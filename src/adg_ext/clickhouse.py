"""ClickHouse connector (PA-2) over the HTTP interface (``clickhouse-connect``).

Every statement runs with ``readonly=1`` and server-side limits; the caller cannot pass query
settings (the guard rejects ``SETTINGS``). Optional per-query hints travel in the config copy
under the ``_ext_*`` keys so the upstream ``MetadataConnector`` signature stays untouched.
"""

import importlib
from collections.abc import Mapping
from datetime import date, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from adg.app.settings import get_settings
from adg.connectors.base import MetadataSnapshot, QueryResult
from adg.connectors.errors import ConnectorDependencyError, ConnectorOperationError
from adg.connectors.relational import RelationalConnector

SYSTEM_DATABASES = ("system", "information_schema", "INFORMATION_SCHEMA")
_VIEW_ENGINES = {"View", "MaterializedView", "LiveView", "WindowView"}


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, bytes | bytearray):
        return bytes(value).decode("utf-8", errors="replace")
    if isinstance(value, list | tuple | set):
        return [_json_safe(v) for v in value]
    if isinstance(value, Mapping):
        return {str(k): _json_safe(v) for k, v in value.items()}
    return str(value)


class ClickHouseConnector:
    """``MetadataConnector`` implementation for ClickHouse."""

    connector_type = "clickhouse"
    default_port = 8123

    def _require_dependency(self) -> Any:
        try:
            return importlib.import_module("clickhouse_connect")
        except ModuleNotFoundError as error:
            raise ConnectorDependencyError(
                "Connector 'clickhouse' requires optional extra 'clickhouse'"
            ) from error

    def _client(self, config: dict[str, object], settings: dict[str, object]) -> Any:
        driver = self._require_dependency()
        checked = RelationalConnector()._validated_connection_config(config)
        runtime = get_settings()
        port = checked.get("port")
        database = str(checked.get("database") or "").strip() or "default"
        try:
            return driver.get_client(
                host=str(checked.get("host", "")),
                port=int(str(port)) if port else self.default_port,
                username=str(checked.get("username", "")) or "default",
                password=str(checked.get("password", "")),
                database=database,
                secure=bool(checked.get("secure", False)),
                connect_timeout=runtime.runtime_datasource_connect_timeout_seconds,
                send_receive_timeout=runtime.runtime_datasource_read_timeout_seconds,
                settings=settings,
                autogenerate_session_id=False,
            )
        except Exception as error:
            raise ConnectorOperationError(str(error)) from error

    def test_connection(self, config: dict[str, object]) -> None:
        client = self._client(config, {"readonly": 1})
        try:
            client.query("SELECT 1")
        except ConnectorOperationError:
            raise
        except Exception as error:
            raise ConnectorOperationError(str(error)) from error
        finally:
            client.close()

    def scan_metadata(self, config: dict[str, object]) -> MetadataSnapshot:
        client = self._client(config, {"readonly": 1})
        configured = str(config.get("database") or "").strip()
        try:
            params: dict[str, object] = {"system": list(SYSTEM_DATABASES)}
            where = "c.database NOT IN {system:Array(String)}"
            if configured:
                where += " AND c.database = {db:String}"
                params["db"] = configured
            rows = client.query(
                "SELECT c.database, c.table, c.name, c.type, c.position, t.engine "
                "FROM system.columns AS c INNER JOIN system.tables AS t "
                "ON c.database = t.database AND c.table = t.name "
                f"WHERE {where} ORDER BY c.database, c.table, c.position",
                parameters=params,
            ).result_rows
            names = client.query(
                "SELECT name FROM system.databases WHERE name NOT IN {system:Array(String)}"
                + (" AND name = {db:String}" if configured else ""),
                parameters=params,
            ).result_rows
        except ConnectorOperationError:
            raise
        except Exception as error:
            raise ConnectorOperationError(str(error)) from error
        finally:
            client.close()
        databases: dict[str, dict[str, dict[str, Any]]] = {str(n[0]): {} for n in names}
        engines: dict[tuple[str, str], str] = {}
        for database, table, column, ctype, position, engine in rows:
            relations = databases.setdefault(str(database), {})
            rel = relations.setdefault(
                str(table),
                {"name": str(table), "kind": "table", "schema": str(database), "columns": []},
            )
            engines[(str(database), str(table))] = str(engine)
            rel["columns"].append(
                {
                    "name": str(column),
                    "data_type": str(ctype),
                    "nullable": str(ctype).startswith("Nullable("),
                    "ordinal_position": int(position),
                    "description": None,
                }
            )
        out: list[dict[str, object]] = []
        for database, relations in databases.items():
            tables = [
                r for k, r in relations.items() if engines[(database, k)] not in _VIEW_ENGINES
            ]
            views = [r for k, r in relations.items() if engines[(database, k)] in _VIEW_ENGINES]
            out.append({"name": database, "tables": tables, "views": views})
        return {"databases": out}

    def execute_query(self, config: dict[str, object], sql: str, limit: int) -> QueryResult:
        timeout = config.get("_ext_timeout_seconds")
        settings: dict[str, object] = {
            "readonly": 1,
            "max_result_rows": int(limit),
            "result_overflow_mode": "break",
        }
        if timeout:
            settings["max_execution_time"] = int(str(timeout))
        client = self._client(config, {})
        try:
            result = client.query(sql, settings=settings)
            names = list(result.column_names)
            types = [t.name for t in result.column_types]
            rows = [
                {n: _json_safe(v) for n, v in zip(names, row, strict=True)}
                for row in result.result_rows[:limit]
            ]
        except ConnectorOperationError:
            raise
        except Exception as error:
            raise ConnectorOperationError(str(error)) from error
        finally:
            client.close()
        columns = [{"name": n, "data_type": t} for n, t in zip(names, types, strict=True)]
        return QueryResult(columns=columns, rows=rows)
