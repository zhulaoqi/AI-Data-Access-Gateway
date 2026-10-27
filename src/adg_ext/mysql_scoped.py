"""MySQL connector whose metadata scan stays inside the databases the account may read.

The upstream scan asks the inspector for every schema the server lists and fails with
``Access denied`` as soon as one of them (``performance_schema``, other tenants' databases) is not
readable. Accounts provisioned by the SQL gateway hold ``SELECT`` on specific databases only.

Relations and columns come from ``information_schema`` rather than ``SHOW CREATE TABLE``: it lists
exactly what the account may see (including column-level grants and views without ``SHOW VIEW``),
so one unreadable object no longer drops every table of the database, and a database is read in two
queries instead of one round trip per table.
"""

import logging
from typing import Any

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError

from adg.connectors.mysql.adapter import MySqlConnector

_ACCESS_DENIED = {1044, 1045, 1142, 1143, 1227}

_LOG = logging.getLogger(__name__)

_SCHEMA_SQL = text(
    "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = :schema"
)
_RELATIONS_SQL = text(
    """
    SELECT TABLE_NAME AS table_name, TABLE_TYPE AS table_type
    FROM information_schema.TABLES
    WHERE TABLE_SCHEMA = :schema
    ORDER BY TABLE_NAME
    """
)
_COLUMNS_SQL = text(
    """
    SELECT
        TABLE_NAME AS table_name,
        COLUMN_NAME AS column_name,
        COLUMN_TYPE AS column_type,
        IS_NULLABLE AS is_nullable
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = :schema
    ORDER BY TABLE_NAME, ORDINAL_POSITION
    """
)


class ScopedMySqlConnector(MySqlConnector):
    def _scan_database(self, connection: Connection, database_name: str) -> dict[str, object]:
        params = {"schema": database_name}
        try:
            if connection.execute(_SCHEMA_SQL, params).first() is None:
                _LOG.warning(
                    "metadata scan: database %s is not visible to the account", database_name
                )
                return {"name": database_name}
            relations = connection.execute(_RELATIONS_SQL, params).mappings().all()
            column_rows = connection.execute(_COLUMNS_SQL, params).mappings().all()
        except DBAPIError as error:
            code: Any = error.orig.args[0] if error.orig and error.orig.args else None
            if code in _ACCESS_DENIED:
                _LOG.warning(
                    "metadata scan: access denied reading database %s (code %s)",
                    database_name,
                    code,
                )
                return {"name": database_name}
            raise
        columns: dict[str, list[dict[str, object]]] = {}
        for row in column_rows:
            columns.setdefault(str(row["table_name"]), []).append(
                {
                    "name": str(row["column_name"]),
                    "type": str(row["column_type"]).upper(),
                    "nullable": str(row["is_nullable"]).upper() == "YES",
                }
            )
        tables: list[dict[str, object]] = []
        views: list[dict[str, object]] = []
        for relation in relations:
            name = str(relation["table_name"])
            kind = "view" if str(relation["table_type"]).upper() == "VIEW" else "table"
            payload = self._build_relation_payload(
                relation_name=name,
                relation_kind=kind,
                schema_name=database_name,
                columns=columns.get(name, []),
            )
            (views if kind == "view" else tables).append(payload)
        # MySQL has no schema level below the database: paths are ``database.table``.
        return {"name": database_name, "tables": tables, "views": views}
