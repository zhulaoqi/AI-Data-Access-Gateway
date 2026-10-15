"""No identifier or payload the extension writes may outgrow its control-plane column (real MySQL).

SQLite ignores ``String(n)``, so a column that is too narrow only shows up on MySQL, as
``Data too long`` at the worst moment (``audit_events.query_id`` was ``VARCHAR(36)`` for 40
character ids and the fail-closed audit refused every query). Three layers, each on a schema built
the two ways the product can build it (``alembic upgrade head`` = Helm/production,
``Base.metadata.create_all`` = upstream tests/dev):

1. ``GENERATED``: for every value the code generates or accepts, the longest possible value is
   fed in from the *code's own constants*, so growing a limit without growing the column fails.
2. every string column of every model is written with a value of exactly its declared length
   (and every large-text column with a multi-hundred-KB value), in strict SQL mode.
3. the migrated schema equals the model schema (types, lengths, nullability, indexes).
"""

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import (
    Boolean,
    DateTime,
    Engine,
    Integer,
    String,
    Text,
    create_engine,
    insert,
    inspect,
    text,
)
from sqlalchemy.dialects import mysql
from tests.ext_integration.conftest import (
    MYSQL,
    Gateway,
    alembic_upgrade,
    fresh_mysql_database,
)
from tests.ext_integration.test_extint_mysql import provision

from adg.control_plane.models import Base
from adg.shared.ids import uuidv7
from adg_ext import sync

ALEMBIC_DB = "adg_len_alembic"
CREATE_ALL_DB = "adg_len_create_all"
PARITY_MIGRATED_DB = "adg_len_parity_migrated"
PARITY_MODELS_DB = "adg_len_parity_models"


def _url(database: str) -> str:
    return f"mysql+pymysql://root:rootpw@{MYSQL[0]}:{MYSQL[1]}/{database}?charset=utf8mb4"


@pytest.fixture(scope="module", params=["alembic", "create_all"])
def engine(request: pytest.FixtureRequest, engines: None) -> Iterator[Engine]:
    database = ALEMBIC_DB if request.param == "alembic" else CREATE_ALL_DB
    fresh_mysql_database(database)
    if request.param == "alembic":
        alembic_upgrade(_url(database))
    built = create_engine(_url(database))
    if request.param == "create_all":
        Base.metadata.create_all(built)
    yield built
    built.dispose()


def _length(engine: Engine, table: str, column: str) -> int:
    """Character capacity of a VARCHAR column, byte capacity of a TEXT-family column."""

    with engine.connect() as c:
        row = c.execute(
            text(
                "SELECT character_maximum_length FROM information_schema.columns "
                "WHERE table_schema = DATABASE() AND table_name = :t AND column_name = :c"
            ),
            {"t": table, "c": column},
        ).one()
    return int(row[0])


# ---- 1. values the code generates or accepts ----------------------------------------------------

_EVENT_TYPES = (
    "query_execution",
    "metadata_discovery",
    "resource_preview",
    "audit_sql_view",
    "decryption",
    "sql_rejected",
    "permission_rejected",
)
_HELD_VALUES_NOTE = "uuid4 hex form is 36 characters; ids are uuidv7 (36) or qry_ + uuid4 (40)"

# (table, column) -> the longest value that can legally reach it, built from the code's constants
GENERATED: dict[tuple[str, str], str] = {
    ("audit_events", "id"): uuidv7(),
    ("audit_events", "query_id"): f"qry_{uuid4()}",
    ("audit_events", "user_id"): uuidv7(),
    ("audit_events", "api_key_id"): uuidv7(),
    ("audit_events", "datasource_id"): uuidv7(),
    ("audit_events", "event_type"): max(_EVENT_TYPES, key=len),
    ("audit_events", "decision"): "rejected",
    ("decrypt_contexts", "query_id"): f"qry_{uuid4()}",
    ("users", "external_ref"): "gw:user:" + "u" * (sync.MAX_NAME - len("gw:user:")),
    ("users", "name"): "n" * sync.MAX_IDENT,
    ("roles", "name"): "gw:role:" + "r" * (sync.MAX_NAME - len("gw:role:")),
    ("datasources", "name"): "gw:ds:" + "d" * (sync.MAX_NAME - len("gw:ds:")),
    ("api_keys", "name"): "gw:cred:" + "c" * (sync.MAX_NAME - len("gw:cred:")),
    ("api_keys", "key_hash"): "retired:" + uuidv7(),
    ("ext_sync_objects", "name"): "gw:rf:" + "f" * (sync.MAX_NAME - len("gw:rf:")),
    ("ext_sync_objects", "external_id"): "gw:rf:" + "f" * (sync.MAX_NAME - len("gw:rf:")),
    ("ext_sync_objects", "object_type"): max(sync.TYPES, key=len),
    ("ext_sync_objects", "hash"): "h" * 64,
    ("resources", "name"): "t" * sync.MAX_IDENT,
    ("resources", "display_name"): "t" * sync.MAX_IDENT,
    ("resources", "path"): "p" * sync.MAX_PATH,
    ("resource_fields", "name"): "c" * sync.MAX_IDENT,
    ("resource_fields", "data_type"): "T" * sync.MAX_IDENT,
    ("masking_policies", "field_name"): "c" * sync.MAX_IDENT,
    ("ext_role_tables", "resource_id"): uuidv7(),
    ("ext_role_tables", "role_id"): uuidv7(),
    ("ext_row_filter_policies", "resource_id"): uuidv7(),
    ("ext_user_attributes", "user_id"): uuidv7(),
}


def test_every_generated_value_fits_its_column(engine: Engine) -> None:
    too_narrow = []
    for (table, column), value in GENERATED.items():
        capacity = _length(engine, table, column)
        if len(value) > capacity:
            too_narrow.append(f"{table}.{column}: needs {len(value)}, column holds {capacity}")
    assert not too_narrow, too_narrow


def test_the_query_id_format_is_what_the_column_was_sized_for() -> None:
    assert len(f"qry_{uuid4()}") == 40 and len(uuidv7()) == 36, _HELD_VALUES_NOTE


# ---- 2. every string column, written at its declared length ------------------------------------

_BIG_TEXT = 300_000  # bytes into every large-text column: far beyond the 64 KB of MySQL TEXT


def _value(column: Any, n: int) -> Any:
    kind = column.type
    if isinstance(kind, String) and not isinstance(kind, Text):
        # multi-byte characters: the length of a VARCHAR(n) is in characters, not bytes
        return ("字" * n) if n else ""
    if isinstance(kind, Text):
        large = (column.table.name, column.name) in _LARGE_TEXT_COLUMNS
        return "x" * (_BIG_TEXT if large else 60_000)
    if isinstance(kind, DateTime):
        return datetime.now(UTC)
    if isinstance(kind, Boolean):
        return True
    if isinstance(kind, Integer):
        return 1
    raise AssertionError(f"unhandled column type {kind!r} on {column.table.name}.{column.name}")


def _large_text_columns() -> set[tuple[str, str]]:
    return {
        (t.name, c.name)
        for t in Base.metadata.tables.values()
        for c in t.columns
        if isinstance(c.type, Text)
        and isinstance(c.type.dialect_impl(mysql.dialect()), mysql.MEDIUMTEXT)
    }


_LARGE_TEXT_COLUMNS = _large_text_columns()


def test_the_scaling_text_columns_are_large_text_on_mysql() -> None:
    expected = {
        ("audit_events", "resource_ids_json"),
        ("audit_events", "sql_text"),
        ("audit_events", "metadata_json"),
        ("ext_sync_objects", "spec_json"),
        ("ext_role_tables", "allow_json"),
        ("ext_role_tables", "deny_json"),
        ("ext_role_tables", "mask_json"),
        ("ext_row_filter_policies", "where_text"),
        ("ext_row_filter_policies", "params_json"),
        ("ext_user_attributes", "params_json"),
    }
    actual = {
        (t.name, c.name)
        for t in Base.metadata.tables.values()
        for c in t.columns
        if isinstance(c.type, Text)
        and isinstance(c.type.dialect_impl(mysql.dialect()), mysql.MEDIUMTEXT)
    }
    assert actual == expected


def test_every_string_column_accepts_its_declared_maximum(engine: Engine) -> None:
    failures: list[str] = []
    with engine.connect() as conn:
        conn.execute(text("SET FOREIGN_KEY_CHECKS = 0"))
        for table in Base.metadata.sorted_tables:
            conn.execute(table.delete())
            values: dict[str, Any] = {}
            for column in table.columns:
                length = column.type.length if isinstance(column.type, String) else None
                values[column.name] = _value(column, length or 0)
            try:
                conn.execute(insert(table).values(**values))
            except Exception as error:  # noqa: BLE001 - report every table, not just the first
                failures.append(f"{table.name}: {str(error)[:160]}")
            conn.execute(table.delete())
        conn.rollback()
    assert not failures, failures


def test_a_statement_larger_than_64kb_is_audited(engine: Engine) -> None:
    """The audit row carries the SQL twice (original + rewritten) plus the accessed fields."""

    sql = "SELECT " + ", ".join(f"c{i}" for i in range(20_000)) + " FROM shop.orders"
    assert len(sql.encode()) > 100_000
    meta = json.dumps({"phase": "started", "rewritten_sql": sql, "grant": uuidv7()})
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM audit_events"))
        conn.execute(
            text(
                "INSERT INTO audit_events (id, event_type, resource_ids_json, query_id, sql_text,"
                " decision, metadata_json, created_at) VALUES (:id, 'query_execution', '[]',"
                " :q, :sql, 'allowed', :meta, UTC_TIMESTAMP())"
            ),
            {"id": uuidv7(), "q": f"qry_{uuid4()}", "sql": sql, "meta": meta},
        )
        stored = conn.execute(text("SELECT LENGTH(sql_text) FROM audit_events")).scalar_one()
        conn.execute(text("DELETE FROM audit_events"))
    assert stored == len(sql.encode())


def test_query_id_index_survives_the_widening_and_serves_the_audit_filter(
    engine: Engine,
) -> None:
    """``queryId`` is an exact match (``=``, no ``LIKE``), so it must keep using its index."""

    with engine.connect() as conn:
        key_bytes = conn.execute(
            text(
                "SELECT SUM(sub_part IS NOT NULL), MAX(index_name) "
                "FROM information_schema.statistics "
                "WHERE table_schema = DATABASE() AND table_name = 'audit_events' "
                "AND index_name = 'ix_audit_events_query_id'"
            )
        ).one()
        assert key_bytes[1] == "ix_audit_events_query_id"
        assert not key_bytes[0]  # a full-width index, not a prefix index
        plan = (
            conn.execute(
                text("EXPLAIN SELECT id FROM audit_events WHERE query_id = :q"),
                {"q": f"qry_{uuid4()}"},
            )
            .mappings()
            .one()
        )
    # 64 characters x 4 bytes (utf8mb4) = 256 bytes, far below InnoDB's 3072-byte key limit
    assert 64 * 4 < 3072
    assert plan["key"] == "ix_audit_events_query_id"


# ---- 3. the migrated schema is the model schema --------------------------------------------------


def _shape(engine: Engine) -> dict[str, Any]:
    inspector = inspect(engine)
    out: dict[str, Any] = {}
    for table in sorted(inspector.get_table_names()):
        if table == "alembic_version":
            continue
        columns = {
            c["name"]: (
                type(c["type"]).__name__.upper(),
                getattr(c["type"], "length", None),
                bool(c["nullable"]),
            )
            for c in inspector.get_columns(table)
        }
        indexes = sorted(
            (tuple(i["column_names"]), bool(i.get("unique"))) for i in inspector.get_indexes(table)
        )
        out[table] = (columns, indexes)
    return out


# Upstream drift that predates the extension and that no extension code reads or writes: the
# baseline migration adds a UNIQUE (tag, target) index to the two tag-link tables, models do not.
_UPSTREAM_INDEX_DRIFT = {"datasource_tags", "resource_tags"}


def test_alembic_head_and_create_all_build_the_same_schema(engines: None) -> None:
    for database in (PARITY_MIGRATED_DB, PARITY_MODELS_DB):
        fresh_mysql_database(database)
    alembic_upgrade(_url(PARITY_MIGRATED_DB))
    built = create_engine(_url(PARITY_MODELS_DB))
    Base.metadata.create_all(built)
    migrated = create_engine(_url(PARITY_MIGRATED_DB))
    try:
        from_migrations, from_models = _shape(migrated), _shape(built)
    finally:
        built.dispose()
        migrated.dispose()
    assert set(from_migrations) == set(from_models) >= set(Base.metadata.tables)
    for table, (columns, indexes) in from_migrations.items():
        model_columns, model_indexes = from_models[table]
        assert columns == model_columns, table
        if table in _UPSTREAM_INDEX_DRIFT:
            assert set(model_indexes) <= set(indexes), table
        else:
            assert indexes == model_indexes, table


# ---- the same idea through the sync API, on a MySQL control plane --------------------------------


def test_names_of_the_maximum_length_are_stored_and_longer_ones_are_refused(
    gateway_mysql: Gateway, mysql_seed: dict[str, str]
) -> None:
    gw = gateway_mysql
    longest = sync.MAX_NAME
    ds = "gw:ds:" + "d" * (longest - len("gw:ds:"))
    role = "gw:role:" + "r" * (longest - len("gw:role:"))
    row_filter = "gw:rf:" + "f" * (longest - len("gw:rf:"))
    user = "gw:user:" + "u" * (longest - len("gw:user:"))
    cred = "gw:cred:" + "c" * (longest - len("gw:cred:"))
    assert max(map(len, (ds, role, row_filter, user, cred))) == longest

    def ok(response: Any) -> None:
        assert response.status_code == 200, response.text

    ok(
        gw.sync(
            "datasource_account",
            ds,
            {
                "label": "l" * 100_000,  # TEXT columns must hold a long free-text label
                "engine": "mysql",
                "host": MYSQL[0],
                "port": MYSQL[1],
                "database": "shop",
                "username": mysql_seed["user"],
                "password": mysql_seed["password"],
            },
        )
    )
    ok(
        gw.sync(
            "role",
            role,
            {
                "profileName": "p" * 5000,
                "tables": [
                    {
                        "datasource": ds,
                        "database": "shop",
                        "table": "orders",
                        "allow": [f"{c}" for c in ("id", "tenant_id", "phone", "amount")],
                        "deny": ["ssn"],
                        "mask": {},
                    }
                ],
                "operations": {"mode": "read_only"},
                "limits": {"maxConcurrency": 2, "queueSize": 2, "maxRows": 100},
            },
        )
    )
    ok(
        gw.sync(
            "row_filter",
            row_filter,
            {
                "role": role,
                "params": [{"name": "tenant_id", "type": "long", "required": True}],
                "filters": [
                    {
                        "datasource": ds,
                        "database": "shop",
                        "table": "orders",
                        "where": "tenant_id = {{tenant_id}}",
                    }
                ],
            },
        )
    )
    ok(
        gw.sync(
            "user",
            user,
            {
                "grantId": "u" * (longest - len("gw:user:")),
                "principalName": "N" * 1000,  # cosmetic: stored truncated
                "role": role,
                "params": {"tenant_id": 7},
                "expiresAt": 4_102_444_800_000,
            },
        )
    )
    ok(gw.sync("credential", cred, {"user": user, "keyHash": "a" * 64, "expiresAt": None}))
    remote = {
        i["name"]: i["externalId"]
        for i in gw.admin_get("/admin/ext/sync/row_filter?prefix=gw:").json()["items"]
    }
    assert remote[row_filter] == row_filter  # external_id (was VARCHAR(64)) holds the 200 chars

    # one character more is refused with 400 before it reaches a column
    for kind, name in (("role", role + "x"), ("user", user + "x"), ("credential", cred + "x")):
        refused = gw.sync(kind, name, {})
        assert refused.status_code == 400, (kind, refused.text)

    # a grant with the longest name can actually query
    out = gw.client.post(
        "/ext/delegated/query",
        json={
            "grantId": "u" * (longest - len("gw:user:")),
            "sql": "SELECT id FROM shop.orders ORDER BY id",
            "database": "shop",
            "channel": "jdbc",
            "requestId": "q" * 200,
        },
        headers={"X-ADG-API-Key": _entry(gw)},
    )
    assert out.status_code == 200, out.text
    assert out.json()["status"] == "success", out.json()


def _entry(gw: Gateway) -> str:
    from adg.control_plane.services.api_key_service import create_api_key

    with gw.factory() as session:
        create_api_key(session, name="entry", scopes=["entry"], plaintext="adg_entry_key")
        session.commit()
    return "adg_entry_key"


def test_provisioning_helper_still_works_on_the_migrated_schema(
    gateway_mysql: Gateway, mysql_seed: dict[str, str]
) -> None:
    assert provision(gateway_mysql, mysql_seed)
