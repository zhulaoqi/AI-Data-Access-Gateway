import socket

import pytest
from pytest import MonkeyPatch

from adg.connectors.doris import adapter
from adg.connectors.doris.adapter import DorisConnector
from adg.connectors.errors import ConnectorOperationError


@pytest.fixture(autouse=True)
def resolve_test_database_host(monkeypatch: MonkeyPatch) -> None:
    """Keep connector unit tests independent from workstation DNS."""

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("203.0.113.8", 0))
        ],
    )


class FakeResult:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self._rows = rows

    def mappings(self) -> "FakeResult":
        return self

    def all(self) -> list[dict[str, object]]:
        return self._rows


class FakeConnection:
    def __init__(self) -> None:
        self.statements: list[tuple[str, dict[str, object] | None]] = []

    def __enter__(self) -> "FakeConnection":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def execute(
        self,
        statement: object,
        parameters: dict[str, object] | None = None,
    ) -> FakeResult:
        sql = str(statement)
        self.statements.append((sql, parameters))
        if "information_schema.SCHEMATA" in sql:
            return FakeResult(
                [
                    {"schema_name": "analytics"},
                    {"schema_name": "warehouse"},
                ]
            )
        if "information_schema.TABLES" in sql:
            schema = str((parameters or {}).get("schema", "warehouse"))
            if schema == "analytics":
                return FakeResult(
                    [
                        {
                            "table_name": "visits",
                            "table_type": "BASE TABLE",
                            "table_comment": "Web visits.",
                        },
                    ]
                )
            return FakeResult(
                [
                    {
                        "table_name": "orders",
                        "table_type": "BASE TABLE",
                        "table_comment": "Orders imported from Doris.",
                    },
                    {
                        "table_name": "daily_sales",
                        "table_type": "VIEW",
                        "table_comment": "Daily sales rollup.",
                    },
                ]
            )
        if "information_schema.COLUMNS" in sql:
            schema = str((parameters or {}).get("schema", "warehouse"))
            if schema == "analytics":
                return FakeResult(
                    [
                        {
                            "table_name": "visits",
                            "column_name": "id",
                            "data_type": "largeint",
                            "is_nullable": "NO",
                            "ordinal_position": 1,
                            "column_comment": "visit id",
                        },
                    ]
                )
            return FakeResult(
                [
                    {
                        "table_name": "orders",
                        "column_name": "id",
                        "data_type": "largeint",
                        "is_nullable": "NO",
                        "ordinal_position": 1,
                        "column_comment": "primary key",
                    },
                    {
                        "table_name": "orders",
                        "column_name": "created_at",
                        "data_type": "datetimev2",
                        "is_nullable": "YES",
                        "ordinal_position": 2,
                        "column_comment": None,
                    },
                    {
                        "table_name": "daily_sales",
                        "column_name": "total",
                        "data_type": "decimal",
                        "is_nullable": "YES",
                        "ordinal_position": 1,
                        "column_comment": "daily total",
                    },
                ]
            )
        raise AssertionError(f"unexpected SQL: {sql}")


class FakeEngine:
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection

    def connect(self) -> FakeConnection:
        return self.connection


def test_doris_scan_metadata_uses_raw_information_schema(monkeypatch: MonkeyPatch) -> None:
    connection = FakeConnection()

    def fake_create_engine(url: object, **kwargs: object) -> FakeEngine:
        return FakeEngine(connection)

    monkeypatch.setattr(adapter, "create_engine", fake_create_engine, raising=False)
    monkeypatch.setattr(DorisConnector, "_require_dependency", lambda self: None)

    snapshot = DorisConnector().scan_metadata({"database": "warehouse"})

    assert snapshot == {
        "databases": [
            {
                "name": "warehouse",
                "tables": [
                    {
                        "name": "orders",
                        "kind": "table",
                        "description": "Orders imported from Doris.",
                        "columns": [
                            {
                                "name": "id",
                                "data_type": "largeint",
                                "nullable": False,
                                "ordinal_position": 1,
                                "description": "primary key",
                            },
                            {
                                "name": "created_at",
                                "data_type": "datetimev2",
                                "nullable": True,
                                "ordinal_position": 2,
                                "description": None,
                            },
                        ],
                    }
                ],
                "views": [
                    {
                        "name": "daily_sales",
                        "kind": "view",
                        "description": "Daily sales rollup.",
                        "columns": [
                            {
                                "name": "total",
                                "data_type": "decimal",
                                "nullable": True,
                                "ordinal_position": 1,
                                "description": "daily total",
                            },
                        ],
                    }
                ],
            }
        ]
    }
    assert all(parameters == {"schema": "warehouse"} for _, parameters in connection.statements)


def test_doris_scan_metadata_uses_the_pinned_database_list(monkeypatch: MonkeyPatch) -> None:
    connection = FakeConnection()

    def fake_create_engine(url: object, **kwargs: object) -> FakeEngine:
        return FakeEngine(connection)

    monkeypatch.setattr(adapter, "create_engine", fake_create_engine, raising=False)
    monkeypatch.setattr(DorisConnector, "_require_dependency", lambda self: None)

    snapshot = DorisConnector().scan_metadata({"databases": ["analytics"]})

    assert [database["name"] for database in snapshot["databases"]] == ["analytics"]
    assert all("SCHEMATA" not in sql for sql, _parameters in connection.statements)


def test_doris_scan_metadata_discovers_all_accessible_databases_when_database_is_blank(
    monkeypatch: MonkeyPatch,
) -> None:
    connection = FakeConnection()

    def fake_create_engine(url: object, **kwargs: object) -> FakeEngine:
        return FakeEngine(connection)

    monkeypatch.setattr(adapter, "create_engine", fake_create_engine, raising=False)
    monkeypatch.setattr(DorisConnector, "_require_dependency", lambda self: None)

    snapshot = DorisConnector().scan_metadata({})

    assert [database["name"] for database in snapshot["databases"]] == ["analytics", "warehouse"]
    assert snapshot["databases"][0]["tables"] == [
        {
            "name": "visits",
            "kind": "table",
            "description": "Web visits.",
            "columns": [
                {
                    "name": "id",
                    "data_type": "largeint",
                    "nullable": False,
                    "ordinal_position": 1,
                    "description": "visit id",
                }
            ],
        }
    ]


def test_doris_scan_metadata_passes_mysql_wire_timeouts(monkeypatch: MonkeyPatch) -> None:
    connection = FakeConnection()
    captured_kwargs: list[dict[str, object]] = []

    class TimeoutSettingsStub:
        runtime_datasource_connect_timeout_seconds = 8
        runtime_datasource_read_timeout_seconds = 31
        runtime_datasource_write_timeout_seconds = 32
        metadata_scan_max_databases = 25
        datasource_network_allowlist = ""

    def fake_create_engine(url: object, **kwargs: object) -> FakeEngine:
        captured_kwargs.append(kwargs)
        return FakeEngine(connection)

    monkeypatch.setattr(adapter, "get_settings", lambda: TimeoutSettingsStub())
    monkeypatch.setattr(adapter, "create_engine", fake_create_engine, raising=False)
    monkeypatch.setattr(DorisConnector, "_require_dependency", lambda self: None)

    DorisConnector().scan_metadata({"host": "db.internal", "database": "warehouse"})

    assert captured_kwargs == [
        {"connect_args": {"connect_timeout": 8, "read_timeout": 31, "write_timeout": 32}}
    ]


def test_doris_scan_metadata_blocks_dangerous_network_hosts(
    monkeypatch: MonkeyPatch,
) -> None:
    class BoundarySettingsStub:
        runtime_datasource_connect_timeout_seconds = 10
        runtime_datasource_read_timeout_seconds = 120
        runtime_datasource_write_timeout_seconds = 120
        metadata_scan_max_databases = 25
        datasource_network_allowlist = ""

    monkeypatch.setattr(adapter, "get_settings", lambda: BoundarySettingsStub())
    monkeypatch.setattr(DorisConnector, "_require_dependency", lambda self: None)

    with pytest.raises(ConnectorOperationError, match="datasource_network_blocked"):
        DorisConnector().scan_metadata({"host": "169.254.169.254"})


def test_doris_scan_metadata_rejects_database_discovery_over_limit(
    monkeypatch: MonkeyPatch,
) -> None:
    connection = FakeConnection()

    class ScanSettingsStub:
        runtime_datasource_connect_timeout_seconds = 10
        runtime_datasource_read_timeout_seconds = 120
        runtime_datasource_write_timeout_seconds = 120
        metadata_scan_max_databases = 1
        datasource_network_allowlist = ""

    def fake_create_engine(url: object, **kwargs: object) -> FakeEngine:
        return FakeEngine(connection)

    monkeypatch.setattr(adapter, "get_settings", lambda: ScanSettingsStub())
    monkeypatch.setattr(adapter, "create_engine", fake_create_engine, raising=False)
    monkeypatch.setattr(DorisConnector, "_require_dependency", lambda self: None)

    with pytest.raises(ConnectorOperationError, match="metadata_scan_database_limit_exceeded"):
        DorisConnector().scan_metadata({"host": "db.internal"})
