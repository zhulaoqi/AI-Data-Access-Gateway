"""PostgreSQL connector for one database, with schemas flattened to gateway databases.

The connection URL always uses the registered PostgreSQL database. The scan list names
schemas inside that database. System schemas are omitted. Query connections come from the
shared SQLAlchemy pool; each transaction sets its own statement timeout and read-only flag,
then clears them by ending the transaction before the connection returns to the pool.
"""

from typing import Any

from sqlalchemy import URL, create_engine, text
from sqlalchemy.engine import Connection

from adg.connectors.base import MetadataSnapshot, QueryResult
from adg.connectors.errors import ConnectorDependencyError, ConnectorOperationError
from adg.connectors.postgres.adapter import PostgresConnector
from adg.connectors.query_limits import RUNTIME_SOCKET_TIMEOUT_SECONDS
from adg.connectors.relational import pinned_scan_databases
from adg.connectors.runtime_engine_cache import get_engine

_SCHEMA_SQL = text(
    """
    SELECT nspname
    FROM pg_catalog.pg_namespace
    WHERE nspname <> 'information_schema'
      AND nspname <> 'pg_catalog'
      AND nspname <> 'pg_toast'
      AND nspname NOT LIKE 'pg_temp%'
      AND nspname NOT LIKE 'pg_toast_temp%'
    ORDER BY nspname
    """
)
_RELATIONS_SQL = text(
    """
    SELECT table_name, table_type
    FROM information_schema.tables
    WHERE table_schema = :schema
      AND table_type IN ('BASE TABLE', 'VIEW')
    ORDER BY table_name
    """
)
_COLUMNS_SQL = text(
    """
    SELECT table_name, column_name, data_type, is_nullable
    FROM information_schema.columns
    WHERE table_schema = :schema
    ORDER BY table_name, ordinal_position
    """
)


def system_schema(name: str) -> bool:
    lowered = name.lower()
    return lowered in {"information_schema", "pg_catalog", "pg_toast"} or lowered.startswith(
        ("pg_temp", "pg_toast_temp")
    )


class ScopedPostgresConnector(PostgresConnector):
    def _build_url(self, config: dict[str, object]) -> URL:
        url = super()._build_url(config)
        sslmode = str(config.get("sslmode") or "").strip()
        if not sslmode:
            return url
        return url.set(query={**dict(url.query), "sslmode": sslmode})

    def _one_shot_connect_args(self) -> dict[str, object]:
        args = super()._one_shot_connect_args()
        return {**args, "options": "-c statement_timeout=120000"}

    def scan_metadata(self, config: dict[str, object]) -> MetadataSnapshot:
        self._require_dependency()
        checked = self._validated_connection_config(config)
        database = str(checked.get("database") or "").strip()
        if not database:
            raise ConnectorOperationError("postgres_database_required")
        schemas = pinned_scan_databases(checked)
        if schemas is not None and not schemas:
            raise ConnectorOperationError("metadata_scan_databases_empty")
        engine = create_engine(self._build_url(checked), connect_args=self._one_shot_connect_args())
        try:
            with engine.connect() as connection:
                names = schemas if schemas is not None else _schema_names(connection)
                databases = [
                    _scan_schema(self, connection, name)
                    for name in names
                    if not system_schema(name)
                ]
        except ConnectorOperationError:
            raise
        except Exception as error:
            raise ConnectorOperationError(str(error)) from error
        finally:
            engine.dispose()
        return {"databases": databases}

    def execute_query(self, config: dict[str, object], sql: str, limit: int) -> QueryResult:
        self._require_dependency()
        checked = self._validated_connection_config(config)
        if not str(checked.get("database") or "").strip():
            raise ConnectorOperationError("postgres_database_required")
        timeout = checked.get("_ext_timeout_seconds")
        seconds = int(str(timeout)) if timeout else RUNTIME_SOCKET_TIMEOUT_SECONDS
        pool_options: dict[str, Any] = {}
        if checked.get("_ext_datasource_id"):
            pool_options["datasource_key"] = str(checked["_ext_datasource_id"])
        if checked.get("_ext_connection_budget") is not None:
            pool_options["connection_budget"] = int(str(checked["_ext_connection_budget"]))
        try:
            engine = get_engine(
                self.connector_type,
                self._build_url(checked),
                connect_args=self._runtime_connect_args(),
                **pool_options,
            )
            with engine.begin() as connection:
                connection.execute(
                    text("SELECT set_config('statement_timeout', :value, true)"),
                    {"value": f"{seconds}s"},
                )
                connection.execute(text("SET LOCAL transaction_read_only = on"))
                connection.execute(text("SELECT set_config('search_path', '', true)"))
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


def _schema_names(connection: Connection) -> list[str]:
    names = connection.execute(_SCHEMA_SQL).scalars().all()
    return [str(name) for name in names if str(name).strip()]


def _scan_schema(
    connector: ScopedPostgresConnector, connection: Connection, schema: str
) -> dict[str, object]:
    params = {"schema": schema}
    relations = connection.execute(_RELATIONS_SQL, params).mappings().all()
    column_rows = connection.execute(_COLUMNS_SQL, params).mappings().all()
    columns: dict[str, list[dict[str, object]]] = {}
    for row in column_rows:
        columns.setdefault(str(row["table_name"]), []).append(
            {
                "name": str(row["column_name"]),
                "type": str(row["data_type"]),
                "nullable": str(row["is_nullable"]).upper() == "YES",
            }
        )
    tables: list[dict[str, object]] = []
    views: list[dict[str, object]] = []
    for relation in relations:
        name = str(relation["table_name"])
        kind = "view" if str(relation["table_type"]).upper() == "VIEW" else "table"
        payload = connector._build_relation_payload(
            relation_name=name,
            relation_kind=kind,
            schema_name=schema,
            columns=columns.get(name, []),
        )
        (views if kind == "view" else tables).append(payload)
    return {"name": schema, "tables": tables, "views": views}
