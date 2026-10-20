import socket
from typing import Any, cast

import pytest
from pytest import MonkeyPatch

from adg.connectors import relational, runtime_engine_cache
from adg.connectors.errors import ConnectorOperationError
from adg.connectors.relational import RelationalConnector


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


class FakeScalarResult:
    def __init__(self, values: list[str]) -> None:
        self._values = values

    def all(self) -> list[str]:
        return self._values


class FakeResult:
    def __init__(self, values: list[str]) -> None:
        self._values = values

    def scalars(self) -> FakeScalarResult:
        return FakeScalarResult(self._values)


class FakeDialect:
    name = "postgresql"


class FakeConnection:
    dialect = FakeDialect()

    def __init__(self, database: str | None) -> None:
        self.database = database

    def __enter__(self) -> "FakeConnection":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def exec_driver_sql(self, sql: str) -> FakeResult:
        if sql == "select 1":
            return FakeResult(["1"])
        assert "pg_database" in sql
        return FakeResult(["analytics", "warehouse"])


class FakeEngine:
    def __init__(self, database: str | None) -> None:
        self.database = database

    def connect(self) -> FakeConnection:
        return FakeConnection(self.database)


class FakeInspector:
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection

    def get_schema_names(self) -> list[str]:
        return ["public"]

    def get_table_names(self, schema: str | None = None) -> list[str]:
        assert schema == "public"
        return [f"{self.connection.database}_orders"]

    def get_view_names(self, schema: str | None = None) -> list[str]:
        assert schema == "public"
        return []

    def get_columns(self, table_name: str, schema: str | None = None) -> list[dict[str, object]]:
        assert schema == "public"
        assert table_name.endswith("_orders")
        return [{"name": "id", "type": "integer", "nullable": False}]


class FakePostgresConnector(RelationalConnector):
    connector_type = "fake-postgres"
    sqlalchemy_drivername = "postgresql+psycopg"
    dependency_name = "psycopg"
    install_extra = "postgres"


class FakeMySqlConnector(RelationalConnector):
    connector_type = "fake-mysql"
    sqlalchemy_drivername = "mysql+pymysql"
    dependency_name = "pymysql"
    install_extra = "mysql"


class FakeDmlResult:
    returns_rows = False
    rowcount = 3


class FakeDmlConnection:
    def __init__(self) -> None:
        self.statements: list[str] = []

    def __enter__(self) -> "FakeDmlConnection":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def execute(self, statement: object) -> FakeDmlResult:
        self.statements.append(str(statement))
        return FakeDmlResult()


class FakeDmlEngine:
    def __init__(self) -> None:
        self.connection = FakeDmlConnection()
        self.disposed = False

    def begin(self) -> FakeDmlConnection:
        return self.connection

    def dispose(self) -> None:
        self.disposed = True


def test_relational_scan_metadata_uses_the_pinned_database_list(
    monkeypatch: MonkeyPatch,
) -> None:
    created_databases: list[str | None] = []

    def fake_create_engine(url: object, **kwargs: object) -> FakeEngine:
        database = getattr(url, "database", None)
        created_databases.append(database)
        return FakeEngine(database)

    def fake_inspect(connection: FakeConnection) -> FakeInspector:
        return FakeInspector(connection)

    monkeypatch.setattr(relational, "create_engine", fake_create_engine)
    monkeypatch.setattr(relational, "inspect", fake_inspect)
    monkeypatch.setattr(FakePostgresConnector, "_require_dependency", lambda self: None)

    snapshot = FakePostgresConnector().scan_metadata(
        {"host": "db.internal", "databases": ["analytics"]}
    )
    databases = cast(list[dict[str, Any]], snapshot["databases"])

    assert created_databases == ["analytics"]
    assert [database["name"] for database in databases] == ["analytics"]


def test_relational_scan_metadata_rejects_an_empty_pinned_database_list(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(FakePostgresConnector, "_require_dependency", lambda self: None)

    with pytest.raises(ConnectorOperationError, match="metadata_scan_databases_empty"):
        FakePostgresConnector().scan_metadata({"host": "db.internal", "databases": []})


def test_relational_scan_metadata_discovers_all_accessible_databases_when_database_is_blank(
    monkeypatch: MonkeyPatch,
) -> None:
    created_databases: list[str | None] = []

    def fake_create_engine(url: object, **kwargs: object) -> FakeEngine:
        database = getattr(url, "database", None)
        created_databases.append(database)
        return FakeEngine(database)

    def fake_inspect(connection: FakeConnection) -> FakeInspector:
        return FakeInspector(connection)

    monkeypatch.setattr(relational, "create_engine", fake_create_engine)
    monkeypatch.setattr(relational, "inspect", fake_inspect)
    monkeypatch.setattr(FakePostgresConnector, "_require_dependency", lambda self: None)

    snapshot = FakePostgresConnector().scan_metadata({"host": "db.internal"})
    databases = cast(list[dict[str, Any]], snapshot["databases"])
    schemas = cast(list[dict[str, Any]], databases[0]["schemas"])
    tables = cast(list[dict[str, Any]], schemas[0]["tables"])

    assert created_databases == [None, "analytics", "warehouse"]
    assert [database["name"] for database in databases] == ["analytics", "warehouse"]
    assert tables[0]["name"] == "analytics_orders"


def test_relational_execute_query_returns_affected_rows_for_non_row_statements(
    monkeypatch: MonkeyPatch,
) -> None:
    fake_engine = FakeDmlEngine()

    monkeypatch.setattr(
        runtime_engine_cache,
        "get_engine",
        lambda connector_type, url, connect_args=None: fake_engine,
    )
    monkeypatch.setattr(FakePostgresConnector, "_require_dependency", lambda self: None)

    result = FakePostgresConnector().execute_query(
        {"host": "db.internal"},
        "update public.customers set name = 'Alice' where id = 1",
        100,
    )

    assert fake_engine.connection.statements == [
        "update public.customers set name = 'Alice' where id = 1"
    ]
    assert result.columns == [{"name": "affected_rows", "data_type": "integer"}]
    assert result.rows == [{"affected_rows": 3}]


def test_relational_execute_query_reuses_cached_engine_for_same_config(
    monkeypatch: MonkeyPatch,
) -> None:
    fake_engine = FakeDmlEngine()
    created_urls: list[object] = []

    def fake_create_engine(url: object, **kwargs: object) -> FakeDmlEngine:
        created_urls.append(url)
        return fake_engine

    runtime_engine_cache.dispose_all()
    monkeypatch.setattr(runtime_engine_cache, "create_engine", fake_create_engine)
    monkeypatch.setattr(FakePostgresConnector, "_require_dependency", lambda self: None)

    try:
        connector = FakePostgresConnector()
        config: dict[str, object] = {
            "host": "db.internal",
            "username": "alice",
            "password": "secret",
            "database": "warehouse",
        }
        connector.execute_query(config, "update public.customers set name = 'A'", 100)
        connector.execute_query(config, "update public.customers set name = 'B'", 100)
    finally:
        runtime_engine_cache.dispose_all()

    assert len(created_urls) == 1
    assert fake_engine.connection.statements == [
        "update public.customers set name = 'A'",
        "update public.customers set name = 'B'",
    ]


def test_relational_test_connection_and_scan_metadata_use_one_shot_engines(
    monkeypatch: MonkeyPatch,
) -> None:
    created_databases: list[str | None] = []

    def fail_if_runtime_cache_is_used(
        connector_type: str,
        url: object,
        connect_args: dict[str, object] | None = None,
    ) -> object:
        raise AssertionError("runtime cache must not be used")

    def fake_create_engine(url: object, **kwargs: object) -> FakeEngine:
        database = getattr(url, "database", None)
        created_databases.append(database)
        return FakeEngine(database)

    def fake_inspect(connection: FakeConnection) -> FakeInspector:
        return FakeInspector(connection)

    monkeypatch.setattr(runtime_engine_cache, "get_engine", fail_if_runtime_cache_is_used)
    monkeypatch.setattr(relational, "create_engine", fake_create_engine)
    monkeypatch.setattr(relational, "inspect", fake_inspect)
    monkeypatch.setattr(FakePostgresConnector, "_require_dependency", lambda self: None)

    connector = FakePostgresConnector()
    connector.test_connection({"host": "db.internal", "database": "warehouse"})
    connector.scan_metadata({"host": "db.internal"})

    assert created_databases == ["warehouse", None, "analytics", "warehouse"]


def test_relational_execute_query_passes_postgres_connect_timeout(
    monkeypatch: MonkeyPatch,
) -> None:
    fake_engine = FakeDmlEngine()
    captured_connect_args: list[dict[str, object] | None] = []

    class RuntimeTimeoutSettingsStub:
        runtime_datasource_connect_timeout_seconds = 7
        runtime_datasource_read_timeout_seconds = 45
        runtime_datasource_write_timeout_seconds = 46

    def fake_get_engine(
        connector_type: str,
        url: object,
        connect_args: dict[str, object] | None = None,
    ) -> FakeDmlEngine:
        captured_connect_args.append(connect_args)
        return fake_engine

    monkeypatch.setattr(relational, "get_settings", lambda: RuntimeTimeoutSettingsStub())
    monkeypatch.setattr(runtime_engine_cache, "get_engine", fake_get_engine)
    monkeypatch.setattr(FakePostgresConnector, "_require_dependency", lambda self: None)

    FakePostgresConnector().execute_query(
        {"host": "db.internal"},
        "update public.customers set name = 'Alice' where id = 1",
        100,
    )

    assert captured_connect_args == [{"connect_timeout": 7}]


def test_relational_execute_query_passes_mysql_wire_timeouts(
    monkeypatch: MonkeyPatch,
) -> None:
    fake_engine = FakeDmlEngine()
    captured_connect_args: list[dict[str, object] | None] = []

    class RuntimeTimeoutSettingsStub:
        runtime_datasource_connect_timeout_seconds = 7
        runtime_datasource_read_timeout_seconds = 45
        runtime_datasource_write_timeout_seconds = 46

    def fake_get_engine(
        connector_type: str,
        url: object,
        connect_args: dict[str, object] | None = None,
    ) -> FakeDmlEngine:
        captured_connect_args.append(connect_args)
        return fake_engine

    monkeypatch.setattr(relational, "get_settings", lambda: RuntimeTimeoutSettingsStub())
    monkeypatch.setattr(runtime_engine_cache, "get_engine", fake_get_engine)
    monkeypatch.setattr(FakeMySqlConnector, "_require_dependency", lambda self: None)

    FakeMySqlConnector().execute_query(
        {"host": "db.internal"},
        "update customers set name = 'Alice' where id = 1",
        100,
    )

    assert captured_connect_args == [
        {
            "connect_timeout": 7,
            "read_timeout": 45,
            "write_timeout": 46,
        }
    ]


def test_relational_test_connection_and_scan_metadata_pass_one_shot_timeouts(
    monkeypatch: MonkeyPatch,
) -> None:
    captured_kwargs: list[dict[str, object]] = []

    class TimeoutSettingsStub:
        runtime_datasource_connect_timeout_seconds = 8
        runtime_datasource_read_timeout_seconds = 31
        runtime_datasource_write_timeout_seconds = 32
        metadata_scan_max_databases = 25
        datasource_network_allowlist = ""

    def fake_create_engine(url: object, **kwargs: object) -> FakeEngine:
        captured_kwargs.append(kwargs)
        return FakeEngine(getattr(url, "database", None))

    def fake_inspect(connection: FakeConnection) -> FakeInspector:
        return FakeInspector(connection)

    monkeypatch.setattr(relational, "get_settings", lambda: TimeoutSettingsStub())
    monkeypatch.setattr(relational, "create_engine", fake_create_engine)
    monkeypatch.setattr(relational, "inspect", fake_inspect)
    monkeypatch.setattr(FakeMySqlConnector, "_require_dependency", lambda self: None)

    connector = FakeMySqlConnector()
    connector.test_connection({"host": "db.internal", "database": "warehouse"})
    connector.scan_metadata({"host": "db.internal", "database": "warehouse"})

    assert captured_kwargs == [
        {"connect_args": {"connect_timeout": 8, "read_timeout": 31, "write_timeout": 32}},
        {"connect_args": {"connect_timeout": 8, "read_timeout": 31, "write_timeout": 32}},
    ]


def test_relational_blocks_dangerous_network_hosts_before_connect(
    monkeypatch: MonkeyPatch,
) -> None:
    class BoundarySettingsStub:
        runtime_datasource_connect_timeout_seconds = 10
        runtime_datasource_read_timeout_seconds = 120
        runtime_datasource_write_timeout_seconds = 120
        metadata_scan_max_databases = 25
        datasource_network_allowlist = ""

    monkeypatch.setattr(relational, "get_settings", lambda: BoundarySettingsStub())
    monkeypatch.setattr(FakePostgresConnector, "_require_dependency", lambda self: None)

    for host in ["127.0.0.1", "localhost"]:
        with pytest.raises(ConnectorOperationError, match="datasource_network_blocked"):
            FakePostgresConnector().test_connection({"host": host})


def test_relational_blocks_dns_names_resolving_to_dangerous_addresses(
    monkeypatch: MonkeyPatch,
) -> None:
    class BoundarySettingsStub:
        runtime_datasource_connect_timeout_seconds = 10
        runtime_datasource_read_timeout_seconds = 120
        runtime_datasource_write_timeout_seconds = 120
        metadata_scan_max_databases = 25
        datasource_network_allowlist = ""

    def fake_getaddrinfo(
        host: str,
        port: object,
        type: int = 0,
    ) -> list[tuple[object, object, int, str, tuple[str, int]]]:
        assert host == "metadata.google.internal"
        assert port is None
        assert type == socket.SOCK_STREAM
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                0,
                "",
                ("169.254.169.254", 0),
            )
        ]

    monkeypatch.setattr(relational, "get_settings", lambda: BoundarySettingsStub())
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(FakePostgresConnector, "_require_dependency", lambda self: None)

    with pytest.raises(ConnectorOperationError, match="datasource_network_blocked"):
        FakePostgresConnector().test_connection({"host": "metadata.google.internal"})


def test_relational_fails_closed_when_dns_resolution_fails(
    monkeypatch: MonkeyPatch,
) -> None:
    class BoundarySettingsStub:
        runtime_datasource_connect_timeout_seconds = 10
        runtime_datasource_read_timeout_seconds = 120
        runtime_datasource_write_timeout_seconds = 120
        metadata_scan_max_databases = 25
        datasource_network_allowlist = ""

    def fail_resolution(host: str, port: object, type: int = 0) -> object:
        raise socket.gaierror("temporary lookup failure")

    monkeypatch.setattr(relational, "get_settings", lambda: BoundarySettingsStub())
    monkeypatch.setattr(socket, "getaddrinfo", fail_resolution)
    monkeypatch.setattr(FakePostgresConnector, "_require_dependency", lambda self: None)

    with pytest.raises(ConnectorOperationError, match="datasource_network_unresolved"):
        FakePostgresConnector().test_connection({"host": "db.internal"})


@pytest.mark.parametrize(
    "resolved",
    [
        [],
        [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("not-an-ip", 0))],
    ],
)
def test_relational_fails_closed_when_dns_has_no_usable_address(
    monkeypatch: MonkeyPatch,
    resolved: list[tuple[object, object, int, str, tuple[str, int]]],
) -> None:
    class BoundarySettingsStub:
        datasource_network_allowlist = ""

    monkeypatch.setattr(relational, "get_settings", lambda: BoundarySettingsStub())
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, **kwargs: resolved)

    with pytest.raises(ConnectorOperationError, match="datasource_network_unresolved"):
        FakePostgresConnector()._validated_connection_config({"host": "db.internal"})


def test_relational_blocks_ipv4_mapped_metadata_addresses_before_connect(
    monkeypatch: MonkeyPatch,
) -> None:
    class BoundarySettingsStub:
        runtime_datasource_connect_timeout_seconds = 10
        runtime_datasource_read_timeout_seconds = 120
        runtime_datasource_write_timeout_seconds = 120
        metadata_scan_max_databases = 25
        datasource_network_allowlist = ""

    def fail_if_create_engine_is_called(url: object, **kwargs: object) -> object:
        raise AssertionError("network boundary should block before engine creation")

    monkeypatch.setattr(relational, "get_settings", lambda: BoundarySettingsStub())
    monkeypatch.setattr(relational, "create_engine", fail_if_create_engine_is_called)
    monkeypatch.setattr(FakePostgresConnector, "_require_dependency", lambda self: None)

    with pytest.raises(ConnectorOperationError, match="datasource_network_blocked"):
        FakePostgresConnector().test_connection({"host": "::ffff:100.100.100.200"})


def test_relational_uses_validated_ip_for_resolved_hostname_connections(
    monkeypatch: MonkeyPatch,
) -> None:
    class BoundarySettingsStub:
        runtime_datasource_connect_timeout_seconds = 10
        runtime_datasource_read_timeout_seconds = 120
        runtime_datasource_write_timeout_seconds = 120
        metadata_scan_max_databases = 25
        datasource_network_allowlist = ""

    created_hosts: list[str | None] = []

    def fake_getaddrinfo(
        host: str,
        port: object,
        type: int = 0,
    ) -> list[tuple[object, object, int, str, tuple[str, int]]]:
        assert host == "db.internal"
        assert port is None
        assert type == socket.SOCK_STREAM
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                0,
                "",
                ("10.0.0.8", 0),
            )
        ]

    def fake_create_engine(url: object, **kwargs: object) -> FakeEngine:
        created_hosts.append(getattr(url, "host", None))
        return FakeEngine(getattr(url, "database", None))

    monkeypatch.setattr(relational, "get_settings", lambda: BoundarySettingsStub())
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(relational, "create_engine", fake_create_engine)
    monkeypatch.setattr(FakePostgresConnector, "_require_dependency", lambda self: None)

    FakePostgresConnector().test_connection({"host": "db.internal", "database": "warehouse"})

    assert created_hosts == ["10.0.0.8"]
def test_relational_allows_explicitly_allowlisted_boundary_host(
    monkeypatch: MonkeyPatch,
) -> None:
    class BoundarySettingsStub:
        runtime_datasource_connect_timeout_seconds = 10
        runtime_datasource_read_timeout_seconds = 120
        runtime_datasource_write_timeout_seconds = 120
        metadata_scan_max_databases = 25
        datasource_network_allowlist = "127.0.0.1"

    created_databases: list[str | None] = []

    def fake_create_engine(url: object, **kwargs: object) -> FakeEngine:
        created_databases.append(getattr(url, "database", None))
        return FakeEngine(getattr(url, "database", None))

    monkeypatch.setattr(relational, "get_settings", lambda: BoundarySettingsStub())
    monkeypatch.setattr(relational, "create_engine", fake_create_engine)
    monkeypatch.setattr(FakePostgresConnector, "_require_dependency", lambda self: None)

    FakePostgresConnector().test_connection({"host": "127.0.0.1", "database": "warehouse"})

    assert created_databases == ["warehouse"]


def test_relational_scan_metadata_rejects_database_discovery_over_limit(
    monkeypatch: MonkeyPatch,
) -> None:
    class ScanSettingsStub:
        runtime_datasource_connect_timeout_seconds = 10
        runtime_datasource_read_timeout_seconds = 120
        runtime_datasource_write_timeout_seconds = 120
        metadata_scan_max_databases = 1
        datasource_network_allowlist = ""

    def fake_create_engine(url: object, **kwargs: object) -> FakeEngine:
        return FakeEngine(getattr(url, "database", None))

    monkeypatch.setattr(relational, "get_settings", lambda: ScanSettingsStub())
    monkeypatch.setattr(relational, "create_engine", fake_create_engine)
    monkeypatch.setattr(
        FakePostgresConnector,
        "_discover_database_names",
        lambda self, connection: ["analytics", "warehouse"],
    )
    monkeypatch.setattr(FakePostgresConnector, "_require_dependency", lambda self: None)

    with pytest.raises(ConnectorOperationError, match="metadata_scan_database_limit_exceeded"):
        FakePostgresConnector().scan_metadata({"host": "db.internal"})
