from adg_ext.postgres_scoped import ScopedPostgresConnector, system_schema
from adg_ext.sync import ExtSyncError, connector_target


def test_system_schema_covers_session_temp_schemas() -> None:
    assert system_schema("pg_catalog")
    assert system_schema("PG_TOAST")
    assert system_schema("pg_temp_3")
    assert system_schema("pg_toast_temp_1")
    assert not system_schema("public")


def test_connector_target_requires_the_postgres_database_and_copies_sslmode() -> None:
    try:
        connector_target({"engine": "postgres", "host": "db.internal", "username": "gw"})
    except ExtSyncError as error:
        assert error.status == 422
    else:
        raise AssertionError("missing database must be rejected")

    kind, config = connector_target(
        {
            "engine": "postgres",
            "host": "db.internal",
            "port": 5432,
            "username": "gw",
            "password": "secret",
            "database": "app",
            "databases": ["public"],
            "extra": {"sslmode": "require"},
        }
    )
    assert kind == "postgres"
    assert config["database"] == "app"
    assert config["databases"] == ["public"]
    assert config["sslmode"] == "require"


class _Rows:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self._rows = rows

    def mappings(self) -> "_Rows":
        return self

    def all(self) -> list[dict[str, object]]:
        return self._rows


class _Connection:
    def __enter__(self) -> "_Connection":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, statement: object, params: object = None) -> _Rows:
        sql = str(statement)
        schema = params["schema"] if isinstance(params, dict) else None
        if "information_schema.tables" in sql and schema == "public":
            return _Rows([{"table_name": "orders", "table_type": "BASE TABLE"}])
        if "information_schema.columns" in sql and schema == "public":
            return _Rows(
                [
                    {
                        "table_name": "orders",
                        "column_name": "id",
                        "data_type": "integer",
                        "is_nullable": "NO",
                    }
                ]
            )
        return _Rows([])


class _Engine:
    def __init__(self) -> None:
        self.disposed = False

    def connect(self) -> _Connection:
        return _Connection()

    def dispose(self) -> None:
        self.disposed = True


def test_scan_flattens_one_schema_and_keeps_the_connection_database(monkeypatch) -> None:
    seen: dict[str, object] = {}

    def fake_create_engine(url: object, **_kwargs: object) -> _Engine:
        seen["database"] = url.database
        seen["query"] = dict(url.query)
        return _Engine()

    monkeypatch.setattr("adg_ext.postgres_scoped.create_engine", fake_create_engine)
    connector = ScopedPostgresConnector()
    monkeypatch.setattr(connector, "_require_dependency", lambda: None)
    monkeypatch.setattr(connector, "_validated_connection_config", lambda config: config)

    snapshot = connector.scan_metadata(
        {
            "host": "10.0.0.8",
            "port": 5432,
            "username": "gw",
            "password": "secret",
            "database": "app",
            "databases": ["public", "pg_catalog"],
            "sslmode": "require",
        }
    )

    assert seen["database"] == "app"
    assert seen["query"] == {"sslmode": "require"}
    assert snapshot == {
        "databases": [
            {
                "name": "public",
                "tables": [
                    {
                        "name": "orders",
                        "kind": "table",
                        "schema": "public",
                        "columns": [
                            {
                                "name": "id",
                                "data_type": "integer",
                                "nullable": False,
                                "ordinal_position": 1,
                                "description": None,
                            }
                        ],
                    }
                ],
                "views": [],
            }
        ]
    }
