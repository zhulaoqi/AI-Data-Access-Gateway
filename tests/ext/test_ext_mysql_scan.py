from typing import Any, cast

from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError

from adg_ext.mysql_scoped import ScopedMySqlConnector


class _Result:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self._rows = rows

    def first(self) -> dict[str, object] | None:
        return self._rows[0] if self._rows else None

    def mappings(self) -> "_Result":
        return self

    def all(self) -> list[dict[str, object]]:
        return self._rows


class _Connection:
    def __init__(
        self,
        *,
        schemas: list[str],
        relations: list[dict[str, object]],
        columns: list[dict[str, object]],
        denied: bool = False,
    ) -> None:
        self.schemas = schemas
        self.relations = relations
        self.columns = columns
        self.denied = denied

    def execute(self, statement: Any, params: dict[str, object]) -> _Result:
        sql = str(statement)
        if self.denied:
            raise DBAPIError(sql, params, Exception(1142, "SELECT command denied"))
        if "SCHEMATA" in sql:
            return _Result([{"SCHEMA_NAME": s} for s in self.schemas if s == params["schema"]])
        if "information_schema.TABLES" in sql:
            return _Result(self.relations)
        return _Result(self.columns)


def _scan(conn: _Connection, database: str = "dataeye") -> dict[str, Any]:
    return cast(
        dict[str, Any], ScopedMySqlConnector()._scan_database(cast(Connection, conn), database)
    )


def test_reads_tables_views_and_columns_from_information_schema() -> None:
    conn = _Connection(
        schemas=["dataeye"],
        relations=[
            {"table_name": "admin_logs", "table_type": "BASE TABLE"},
            {"table_name": "v_org_source", "table_type": "VIEW"},
        ],
        columns=[
            {
                "table_name": "admin_logs",
                "column_name": "id",
                "column_type": "bigint",
                "is_nullable": "NO",
            },
            {
                "table_name": "admin_logs",
                "column_name": "created_at",
                "column_type": "datetime",
                "is_nullable": "YES",
            },
            {
                "table_name": "v_org_source",
                "column_name": "org_id",
                "column_type": "int",
                "is_nullable": "YES",
            },
        ],
    )

    snapshot = _scan(conn)

    assert snapshot["name"] == "dataeye"
    [table] = snapshot["tables"]
    assert table["name"] == "admin_logs"
    assert table["kind"] == "table"
    assert [(c["name"], c["data_type"], c["nullable"]) for c in table["columns"]] == [
        ("id", "BIGINT", False),
        ("created_at", "DATETIME", True),
    ]
    [view] = snapshot["views"]
    assert view["name"] == "v_org_source"
    assert [c["name"] for c in view["columns"]] == ["org_id"]


def test_invisible_database_keeps_only_the_database_node() -> None:
    snapshot = _scan(_Connection(schemas=[], relations=[], columns=[]))

    assert snapshot == {"name": "dataeye"}


def test_access_denied_keeps_only_the_database_node() -> None:
    snapshot = _scan(_Connection(schemas=["dataeye"], relations=[], columns=[], denied=True))

    assert snapshot == {"name": "dataeye"}
