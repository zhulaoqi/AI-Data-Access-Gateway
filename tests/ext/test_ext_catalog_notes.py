"""Business meanings sync onto MCP descriptions without touching column permissions."""

import hashlib
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from adg.control_plane.db import create_engine_from_url, create_session_factory
from adg.control_plane.models import Base
from adg_ext.catalog_notes import NoteIndex, prefer
from adg_ext.models import ExtCatalogNote, ExtSyncObject
from adg_ext.sync import SyncService

DS = "gw:ds:acc1"
NOTE = "gw:note:acc1"


@pytest.fixture
def session(tmp_path: Path) -> Iterator[Session]:
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'notes.db'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    with factory() as db:
        db.add(
            ExtSyncObject(
                object_type="datasource_account",
                name=DS,
                hash="a" * 64,
                spec_json="{}",
                external_id="executor-ds",
            )
        )
        db.commit()
        yield db


def _put(db: Session, spec: dict[str, object], digest: str) -> None:
    SyncService(db).put("catalog_note", NOTE, digest, spec)
    db.commit()


def test_put_replaces_notes_and_delete_clears_them(session: Session) -> None:
    spec = {
        "datasource": DS,
        "databases": [{"name": "info", "text": "星云业务库"}],
        "tables": [{"database": "info", "name": "audit", "text": "网关审计日志"}],
        "columns": [
            {"database": "info", "table": "audit", "name": "created_at", "text": "创建时间"}
        ],
    }
    _put(session, spec, hashlib.sha256(b"v1").hexdigest())
    _put(
        session,
        {
            "datasource": DS,
            "databases": [{"name": "info", "text": "改后的库说明"}],
            "tables": [],
            "columns": [{"database": "info", "table": "audit", "name": "created_at", "text": "  "}],
        },
        hashlib.sha256(b"v2").hexdigest(),
    )
    rows = list(session.execute(select(ExtCatalogNote)).scalars())
    assert [(row.database_name, row.table_name, row.column_name, row.text) for row in rows] == [
        ("info", "", "", "改后的库说明")
    ]

    SyncService(session).delete("catalog_note", NOTE)
    session.commit()
    assert list(session.execute(select(ExtCatalogNote)).scalars()) == []


def test_business_text_wins_over_the_scanned_comment() -> None:
    notes = NoteIndex(
        [
            ExtCatalogNote(
                datasource_id="executor-ds",
                database_name="info",
                table_name="",
                column_name="",
                text="星云业务库",
            ),
            ExtCatalogNote(
                datasource_id="executor-ds",
                database_name="info",
                table_name="audit",
                column_name="created_at",
                text="创建时间",
            ),
        ]
    )
    assert notes.database("executor-ds", "info") == "星云业务库"
    assert notes.table("executor-ds", "info", "audit") is None
    assert (
        prefer(notes.column("executor-ds", "info", "audit", "created_at"), "列备注") == "创建时间"
    )
    assert prefer(None, "库内备注") == "库内备注"
