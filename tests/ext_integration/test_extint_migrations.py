"""The widening migration (``202610150001``) on SQLite and on real MySQL.

Covers the two upgrade paths of a deployment: an empty database straight to ``head`` and a database
that already runs an older revision with data in it (including the revision that shipped the
too-narrow ``audit_events.query_id``), plus repeatability (second ``upgrade head`` is a no-op,
``downgrade -1`` then ``upgrade head`` works).
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, create_engine, inspect, text
from sqlalchemy.exc import DataError
from tests.ext_integration.conftest import (
    MYSQL,
    ROOT,
    alembic_upgrade,
    fresh_mysql_database,
)

from adg.app.settings import get_settings
from adg.shared.ids import uuidv7

OLD = "202610140001"  # shipped the VARCHAR(36) query_id
WIDENING = "202610150001"
HEAD = "202610290001"
BASELINE = "202604260001"  # before the ext tables exist
LONG_REF = "gw:rf:" + "f" * 194  # a row filter's external id is its (200 char) object name


def _fresh_mysql_url() -> str:
    fresh_mysql_database("adg_len_upgrade")
    return f"mysql+pymysql://root:rootpw@{MYSQL[0]}:{MYSQL[1]}/adg_len_upgrade?charset=utf8mb4"


@pytest.fixture
def mysql_url(engines: None) -> str:
    return _fresh_mysql_url()


@pytest.fixture(params=["sqlite", "mysql"])
def url(request: pytest.FixtureRequest, tmp_path: Path) -> str:
    if request.param == "sqlite":
        return f"sqlite:///{tmp_path / 'cp.db'}"
    request.getfixturevalue("engines")
    return _fresh_mysql_url()


def _config(url: str) -> Config:
    config = Config()  # no ini file: env.py would call fileConfig() and silence every other logger
    config.set_main_option("script_location", str(ROOT / "src/adg/control_plane/migrations"))
    config.set_main_option("sqlalchemy.url", url)
    return config


def _current(engine: Engine) -> str | None:
    with engine.connect() as conn:
        row = conn.execute(text("SELECT version_num FROM alembic_version")).first()
    return None if row is None else str(row[0])


def _audit(conn: Any, query_id: str | None, **extra: Any) -> str:
    event_id = uuidv7()
    conn.execute(
        text(
            "INSERT INTO audit_events (id, event_type, resource_ids_json, query_id, sql_text,"
            " decision, metadata_json, created_at) VALUES (:id, 'query_execution', '[]', :q,"
            " :sql, 'allowed', :meta, :at)"
        ),
        {
            "id": event_id,
            "q": query_id,
            "sql": extra.get("sql", "SELECT 1"),
            "meta": extra.get("meta", "{}"),
            "at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S"),
        },
    )
    return event_id


def _sync_object(conn: Any, name: str, external_id: str | None) -> None:
    conn.execute(
        text(
            "INSERT INTO ext_sync_objects (id, object_type, name, hash, spec_json, external_id,"
            " updated_at) VALUES (:id, 'row_filter', :name, :hash, '{}', :ext, :at)"
        ),
        {
            "id": uuidv7(),
            "name": name,
            "hash": "h" * 64,
            "ext": external_id,
            "at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S"),
        },
    )


def _length(engine: Engine, table: str, column: str) -> int | None:
    for c in inspect(engine).get_columns(table):
        if c["name"] == column:
            length: int | None = getattr(c["type"], "length", None)
            return length
    raise AssertionError(f"{table}.{column} not found")


def _constraint_names(engine: Engine, table: str) -> set[str]:
    inspector = inspect(engine)
    return {str(i["name"]) for i in inspector.get_indexes(table)} | {
        str(u["name"]) for u in inspector.get_unique_constraints(table)
    }


def _is_mysql(url: str) -> bool:
    return url.startswith("mysql")


def test_there_is_exactly_one_head_and_capacity_follows_widening() -> None:
    script = ScriptDirectory.from_config(_config("sqlite://"))
    assert script.get_heads() == [HEAD]
    revision = script.get_revision(HEAD)
    assert revision is not None and revision.down_revision == WIDENING


def test_empty_database_upgrades_and_the_upgrade_is_repeatable(url: str) -> None:
    alembic_upgrade(url)
    engine = create_engine(url)
    try:
        assert _current(engine) == HEAD
        assert _length(engine, "audit_events", "query_id") == 64
        assert _length(engine, "ext_sync_objects", "external_id") == 256

        alembic_upgrade(url)  # second run: nothing to do, nothing breaks
        assert _current(engine) == HEAD

        with engine.begin() as conn:  # the values that used to fail
            _audit(conn, f"qry_{uuid4()}")
            _sync_object(conn, LONG_REF, LONG_REF)
            conn.execute(text("DELETE FROM audit_events"))
            conn.execute(text("DELETE FROM ext_sync_objects"))

        command.downgrade(_config(url), "-1")
        get_settings.cache_clear()
        assert _current(engine) == WIDENING
        assert _length(engine, "audit_events", "query_id") == 64
        assert _length(engine, "ext_sync_objects", "external_id") == 256

        alembic_upgrade(url)  # up again after a rollback
        assert _current(engine) == HEAD
        assert _length(engine, "audit_events", "query_id") == 64
    finally:
        engine.dispose()


@pytest.mark.parametrize("start", [BASELINE, OLD])
def test_upgrade_from_an_older_revision_keeps_existing_rows(url: str, start: str) -> None:
    alembic_upgrade(url, start)
    engine = create_engine(url)
    short_query_id = str(uuid4())  # 36 characters: what the old column could hold
    try:
        assert _current(engine) == start
        with engine.begin() as conn:
            kept_event = _audit(conn, short_query_id, sql="SELECT 'old row'", meta='{"a":1}')
            _audit(conn, None)  # rejections carry no query id
            if start == OLD:
                _sync_object(conn, "gw:rf:old", "gw:rf:old")

        if start == OLD and _is_mysql(url):
            # the defect, on the schema that shipped it: strict MySQL refuses the 40 char id
            with pytest.raises(DataError, match="query_id"), engine.begin() as conn:
                _audit(conn, f"qry_{uuid4()}")

        alembic_upgrade(url)
        assert _current(engine) == HEAD

        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT query_id, sql_text, metadata_json FROM audit_events WHERE id = :i"),
                {"i": kept_event},
            ).one()
            assert tuple(row) == (short_query_id, "SELECT 'old row'", '{"a":1}')
            assert conn.execute(text("SELECT COUNT(*) FROM audit_events")).scalar_one() == 2
            if start == OLD:
                kept = conn.execute(text("SELECT external_id FROM ext_sync_objects")).scalars()
                assert list(kept) == ["gw:rf:old"]

        # indexes and constraints survived the ALTER (SQLite rebuilds the table)
        assert "ix_audit_events_query_id" in _constraint_names(engine, "audit_events")
        assert "ix_audit_events_created_at" in _constraint_names(engine, "audit_events")
        assert "uq_ext_sync_type_name" in _constraint_names(engine, "ext_sync_objects")

        new_id = f"qry_{uuid4()}"
        with engine.begin() as conn:
            _audit(conn, new_id)
            _sync_object(conn, LONG_REF, LONG_REF)
        with engine.connect() as conn:
            found = conn.execute(
                text("SELECT COUNT(*) FROM audit_events WHERE query_id = :q"), {"q": new_id}
            ).scalar_one()
        assert found == 1
    finally:
        engine.dispose()


def test_mysql_text_columns_become_mediumtext_and_hold_more_than_64kb(mysql_url: str) -> None:
    url = mysql_url
    alembic_upgrade(url, OLD)
    engine = create_engine(url)
    big = "x" * 200_000
    try:
        with pytest.raises(DataError, match="sql_text"), engine.begin() as conn:
            _audit(conn, None, sql=big)  # TEXT: 64 KB
        alembic_upgrade(url)
        columns = inspect(engine).get_columns("audit_events")
        types = {c["name"]: type(c["type"]).__name__ for c in columns}
        assert types["sql_text"] == types["metadata_json"] == "MEDIUMTEXT"
        with engine.begin() as conn:
            _audit(conn, None, sql=big, meta=big)
            stored = conn.execute(text("SELECT LENGTH(sql_text) FROM audit_events")).scalar_one()
        assert stored == 200_000
    finally:
        engine.dispose()


def test_the_manual_kind_workaround_and_the_migration_agree(mysql_url: str) -> None:
    """``ALTER ... MODIFY query_id VARCHAR(64) NULL`` was applied by hand during the kind check."""

    alembic_upgrade(mysql_url, OLD)
    engine = create_engine(mysql_url)
    try:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE audit_events MODIFY query_id VARCHAR(64) NULL"))
            _audit(conn, f"qry_{uuid4()}")
        alembic_upgrade(mysql_url)
        assert _current(engine) == HEAD
        assert _length(engine, "audit_events", "query_id") == 64
        assert "ix_audit_events_query_id" in _constraint_names(engine, "audit_events")
        with engine.connect() as conn:
            assert conn.execute(text("SELECT COUNT(*) FROM audit_events")).scalar_one() == 1
    finally:
        engine.dispose()
