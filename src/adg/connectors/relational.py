import importlib
import ipaddress
import socket
from collections.abc import Sequence
from typing import Any

from sqlalchemy import URL, create_engine, inspect, text
from sqlalchemy.engine import Connection

from adg.app.settings import get_settings
from adg.connectors import runtime_engine_cache
from adg.connectors.base import MetadataColumn, MetadataSnapshot, QueryResult
from adg.connectors.errors import ConnectorDependencyError, ConnectorOperationError

_METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("100.100.100.200"),
}


def pinned_scan_databases(config: dict[str, object]) -> list[str] | None:
    """Return the explicit scan list, or None when the caller did not pin one.

    The management service sends ``databases`` from the metadata scan list. An empty
    list is returned as ``[]`` so callers refuse to discover every database on the server.
    """

    if "databases" not in config or config.get("databases") is None:
        return None
    raw = config.get("databases")
    if isinstance(raw, str):
        name = raw.strip()
        return [name] if name else []
    if not isinstance(raw, list):
        raise ConnectorOperationError("metadata_scan_databases_invalid")
    names: list[str] = []
    for item in raw:
        name = str(item).strip()
        if name and name not in names:
            names.append(name)
    return names


class RelationalConnector:
    """Base implementation for SQLAlchemy-backed relational metadata connectors."""

    connector_type = ""
    sqlalchemy_drivername = ""
    dependency_name = ""
    install_extra = ""

    def _require_dependency(self) -> None:
        """Fail early with an install hint when an optional DB driver is missing."""

        try:
            importlib.import_module(self.dependency_name)
        except ModuleNotFoundError as error:
            raise ConnectorDependencyError(
                f"Connector '{self.connector_type}' requires optional extra '{self.install_extra}'"
            ) from error

    def _build_url(self, config: dict[str, object]) -> URL:
        """Translate persisted datasource config into a SQLAlchemy URL."""

        port_value = config.get("port")
        return URL.create(
            drivername=self.sqlalchemy_drivername,
            username=str(config.get("username", "")) or None,
            password=str(config.get("password", "")) or None,
            host=str(config.get("host", "")) or None,
            port=int(str(port_value)) if port_value is not None else None,
            database=str(config.get("database", "")) or None,
        )

    def test_connection(self, config: dict[str, object]) -> None:
        """Open a connection and run a minimal query to validate connectivity."""

        self._require_dependency()
        connection_config = self._validated_connection_config(config)
        try:
            engine = create_engine(
                self._build_url(connection_config),
                connect_args=self._one_shot_connect_args(),
            )
            with engine.connect() as connection:
                connection.exec_driver_sql("select 1")
        except ConnectorDependencyError:
            raise
        except ConnectorOperationError:
            raise
        except Exception as error:
            raise ConnectorOperationError(str(error)) from error

    def scan_metadata(self, config: dict[str, object]) -> MetadataSnapshot:
        """Inspect schemas, tables, views, and columns into the shared snapshot shape."""

        self._require_dependency()
        connection_config = self._validated_connection_config(config)
        pinned = pinned_scan_databases(connection_config)
        configured_database = str(connection_config.get("database", "")).strip()
        try:
            if pinned is not None:
                if not pinned:
                    raise ConnectorOperationError("metadata_scan_databases_empty")
                databases = []
                for database_name in pinned:
                    database_config = {**connection_config, "database": database_name}
                    database_engine = create_engine(
                        self._build_url(database_config),
                        connect_args=self._one_shot_connect_args(),
                    )
                    with database_engine.connect() as connection:
                        databases.append(self._scan_database(connection, database_name))
            elif configured_database:
                engine = create_engine(
                    self._build_url(connection_config),
                    connect_args=self._one_shot_connect_args(),
                )
                with engine.connect() as connection:
                    databases = [self._scan_database(connection, configured_database)]
            else:
                discovery_engine = create_engine(
                    self._build_url(connection_config),
                    connect_args=self._one_shot_connect_args(),
                )
                with discovery_engine.connect() as connection:
                    database_names = self._discover_database_names(connection)
                max_databases = get_settings().metadata_scan_max_databases
                if len(database_names) > max_databases:
                    raise ConnectorOperationError("metadata_scan_database_limit_exceeded")
                databases = []
                for database_name in database_names:
                    database_config = {**connection_config, "database": database_name}
                    database_engine = create_engine(
                        self._build_url(database_config),
                        connect_args=self._one_shot_connect_args(),
                    )
                    with database_engine.connect() as connection:
                        databases.append(self._scan_database(connection, database_name))
        except ConnectorDependencyError:
            raise
        except ConnectorOperationError:
            raise
        except Exception as error:
            raise ConnectorOperationError(str(error)) from error

        return {"databases": databases}

    def _discover_database_names(self, connection: Connection) -> list[str]:
        """Return accessible logical databases when the datasource did not pin one."""

        dialect_name = str(getattr(connection.dialect, "name", "")).lower()
        if dialect_name.startswith("postgres"):
            result = connection.exec_driver_sql(
                """
                SELECT datname
                FROM pg_database
                WHERE datallowconn = true
                  AND datistemplate = false
                ORDER BY datname
                """
            )
            return [str(name) for name in result.scalars().all() if str(name).strip()]
        if dialect_name in {"mysql", "mariadb"}:
            result = connection.exec_driver_sql("SHOW DATABASES")
            system_databases = {"information_schema", "mysql", "performance_schema", "sys"}
            return [
                str(name)
                for name in result.scalars().all()
                if str(name).strip() and str(name).lower() not in system_databases
            ]
        fallback_name = self._connection_database_name(connection)
        return [fallback_name] if fallback_name else ["default"]

    def _connection_database_name(self, connection: Connection) -> str | None:
        """Best-effort database name fallback for dialects without discovery support."""

        direct_name = getattr(connection, "database", None)
        if direct_name:
            return str(direct_name)
        engine = getattr(connection, "engine", None)
        url = getattr(engine, "url", None)
        database_name = getattr(url, "database", None)
        return str(database_name) if database_name else None

    def _scan_database(self, connection: Connection, database_name: str) -> dict[str, object]:
        """Inspect one connected database into ADG's database-first snapshot shape."""

        inspector = inspect(connection)
        schemas: list[dict[str, object]] = []
        for schema_name in inspector.get_schema_names():
            # SQLAlchemy inspectors expose tables and views separately; ADG preserves both.
            tables = [
                self._build_relation_payload(
                    relation_name=table_name,
                    relation_kind="table",
                    schema_name=schema_name,
                    columns=inspector.get_columns(table_name, schema=schema_name),
                )
                for table_name in inspector.get_table_names(schema=schema_name)
            ]
            views = [
                self._build_relation_payload(
                    relation_name=view_name,
                    relation_kind="view",
                    schema_name=schema_name,
                    columns=inspector.get_columns(view_name, schema=schema_name),
                )
                for view_name in inspector.get_view_names(schema=schema_name)
            ]
            schemas.append(
                {
                    "name": schema_name,
                    "tables": tables,
                    "views": views,
                }
            )
        return {"name": database_name, "schemas": schemas}

    def execute_query(self, config: dict[str, object], sql: str, limit: int) -> QueryResult:
        """Execute already-approved SQL and return normalized rows."""

        self._require_dependency()
        connection_config = self._validated_connection_config(config)
        try:
            pool_options: dict[str, Any] = {}
            if connection_config.get("_ext_datasource_id"):
                pool_options["datasource_key"] = str(connection_config["_ext_datasource_id"])
            if connection_config.get("_ext_connection_budget") is not None:
                pool_options["connection_budget"] = int(
                    str(connection_config["_ext_connection_budget"])
                )
            engine = runtime_engine_cache.get_engine(
                self.connector_type,
                self._build_url(connection_config),
                connect_args=self._runtime_connect_args(),
                **pool_options,
            )
            with engine.begin() as connection:
                result = connection.execute(text(sql))
                if result.returns_rows:
                    rows = [dict(row) for row in result.mappings().fetchmany(limit)]
                    columns = [
                        {"name": str(name), "data_type": "unknown"} for name in result.keys()
                    ]
                else:
                    columns = [{"name": "affected_rows", "data_type": "integer"}]
                    rows = [{"affected_rows": result.rowcount}]
        except ConnectorDependencyError:
            raise
        except ConnectorOperationError:
            raise
        except Exception as error:
            raise ConnectorOperationError(str(error)) from error

        return QueryResult(columns=columns, rows=rows)

    def _runtime_connect_args(self) -> dict[str, object]:
        """Return DBAPI timeout options for runtime query connections."""

        settings = get_settings()
        connect_args: dict[str, object] = {
            "connect_timeout": settings.runtime_datasource_connect_timeout_seconds,
        }
        if self.sqlalchemy_drivername.startswith("mysql+"):
            connect_args["read_timeout"] = settings.runtime_datasource_read_timeout_seconds
            connect_args["write_timeout"] = settings.runtime_datasource_write_timeout_seconds
        return connect_args

    def _one_shot_connect_args(self) -> dict[str, object]:
        """Return DBAPI timeout options for non-cached validation and scan engines."""

        return self._runtime_connect_args()

    def _validate_network_boundary(self, config: dict[str, object]) -> None:
        """Reject datasource hosts that should never be contacted by connectors."""

        self._validated_connection_config(config)

    def _validated_connection_config(self, config: dict[str, object]) -> dict[str, object]:
        """Return a connection config whose host has passed network boundary checks."""

        host = str(config.get("host", "")).strip().strip("[]")
        if not host:
            return config
        if self._host_is_allowlisted(host):
            return config
        if host.lower() in {"localhost", "localhost.localdomain"}:
            raise ConnectorOperationError("datasource_network_blocked")

        addresses = self._network_boundary_addresses(host)
        for address in addresses:
            effective_address = self._normalized_boundary_address(address)
            if self._address_is_blocked(address) and not (
                self._host_is_allowlisted(str(address))
                or self._host_is_allowlisted(str(effective_address))
            ):
                raise ConnectorOperationError("datasource_network_blocked")

        if addresses and not self._host_is_ip_literal(host):
            resolved_config = dict(config)
            resolved_config["host"] = str(self._normalized_boundary_address(addresses[0]))
            return resolved_config
        return config

    def _network_boundary_addresses(
        self,
        host: str,
    ) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        """Return literal and DNS-resolved addresses for boundary checks."""

        try:
            return [ipaddress.ip_address(host)]
        except ValueError:
            pass

        try:
            resolved = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as error:
            raise ConnectorOperationError("datasource_network_unresolved") from error

        addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for result in resolved:
            address_text = str(result[4][0])
            try:
                address = ipaddress.ip_address(address_text)
            except ValueError:
                continue
            if address not in addresses:
                addresses.append(address)
        if not addresses:
            raise ConnectorOperationError("datasource_network_unresolved")
        return addresses

    def _address_is_blocked(
        self,
        address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> bool:
        """Return true for address classes connectors must not contact."""

        effective_address = self._normalized_boundary_address(address)
        return (
            effective_address in _METADATA_IPS
            or effective_address.is_loopback
            or effective_address.is_link_local
            or effective_address.is_multicast
            or effective_address.is_unspecified
        )

    def _normalized_boundary_address(
        self,
        address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            return address.ipv4_mapped
        return address

    def _host_is_ip_literal(self, host: str) -> bool:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return False
        return True

    def _host_is_allowlisted(self, host: str) -> bool:
        """Return true when settings explicitly permit an otherwise blocked host."""

        entries = [
            entry.strip()
            for entry in getattr(get_settings(), "datasource_network_allowlist", "").split(",")
            if entry.strip()
        ]
        for entry in entries:
            if host.lower() == entry.lower():
                return True
            try:
                network = ipaddress.ip_network(entry, strict=False)
                address = ipaddress.ip_address(host)
            except ValueError:
                continue
            if address in network:
                return True
        return False

    def _build_relation_payload(
        self,
        *,
        relation_name: str,
        relation_kind: str,
        schema_name: str,
        columns: Sequence[MetadataColumn],
    ) -> dict[str, object]:
        """Normalize one table or view and its columns for snapshot persistence."""

        return {
            "name": relation_name,
            "kind": relation_kind,
            "schema": schema_name,
            "columns": [
                {
                    "name": str(column["name"]),
                    "data_type": str(column["type"]),
                    "nullable": bool(column.get("nullable", True)),
                    "ordinal_position": index,
                    "description": None,
                }
                for index, column in enumerate(columns, start=1)
            ],
        }
