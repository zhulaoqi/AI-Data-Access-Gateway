from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from adg.control_plane.services.api_key_service import create_api_key
from adg.shared.security import hash_api_key


def test_migration_creates_the_ext_tables(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'cp.db'}"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    inspector = inspect(create_engine(url))
    tables = set(inspector.get_table_names())
    assert {
        "ext_sync_objects",
        "ext_role_specs",
        "ext_role_tables",
        "ext_row_filter_policies",
        "ext_user_attributes",
        "ext_datasource_capacities",
    } <= tables
    assert "limits_json" in {
        column["name"] for column in inspector.get_columns("ext_user_attributes")
    }
    command.downgrade(config, "202606110001")
    assert "ext_sync_objects" not in set(inspect(create_engine(url)).get_table_names())


def test_api_key_can_be_created_from_an_external_hash(db_session) -> None:
    digest = hash_api_key("gateway-generated-secret")
    record, raw = create_api_key(db_session, name="k", scopes=["runtime"], key_hash=digest)
    assert raw == ""
    assert record.key_hash == digest


def test_external_hash_is_validated_and_exclusive_with_plaintext(db_session) -> None:
    with pytest.raises(ValueError):
        create_api_key(db_session, name="k", scopes=["runtime"], key_hash="abc")
    with pytest.raises(ValueError):
        create_api_key(
            db_session, name="k", scopes=["runtime"], key_hash=hash_api_key("x"), plaintext="x"
        )
    with pytest.raises(ValueError):
        create_api_key(db_session, name="k", scopes=["runtime"], key_hash="G" * 64)
