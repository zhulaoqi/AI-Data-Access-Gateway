"""MySQL connector whose metadata scan stays inside the databases the account may read.

The upstream scan asks the inspector for every schema the server lists and fails with
``Access denied`` as soon as one of them (``performance_schema``, other tenants' databases) is not
readable. Accounts provisioned by the SQL gateway hold ``SELECT`` on specific databases only.
"""

from typing import Any

from sqlalchemy import inspect
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError

from adg.connectors.mysql.adapter import MySqlConnector

_ACCESS_DENIED = {1044, 1045, 1142, 1143, 1227}


class ScopedMySqlConnector(MySqlConnector):
    def _scan_database(self, connection: Connection, database_name: str) -> dict[str, object]:
        inspector = inspect(connection)
        try:
            if database_name not in inspector.get_schema_names():
                return {"name": database_name}
            tables = [
                self._build_relation_payload(
                    relation_name=name,
                    relation_kind="table",
                    schema_name=database_name,
                    columns=inspector.get_columns(name, schema=database_name),
                )
                for name in inspector.get_table_names(schema=database_name)
            ]
            views = [
                self._build_relation_payload(
                    relation_name=name,
                    relation_kind="view",
                    schema_name=database_name,
                    columns=inspector.get_columns(name, schema=database_name),
                )
                for name in inspector.get_view_names(schema=database_name)
            ]
        except DBAPIError as error:
            code: Any = error.orig.args[0] if error.orig and error.orig.args else None
            if code in _ACCESS_DENIED:
                return {"name": database_name}
            raise
        # MySQL has no schema level below the database: paths are ``database.table``.
        return {"name": database_name, "tables": tables, "views": views}
