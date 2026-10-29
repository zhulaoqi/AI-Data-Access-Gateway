from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from alembic import command
from alembic.config import Config
from pytest import MonkeyPatch
from sqlalchemy import create_engine, inspect

from adg.app.settings import get_settings


def migrated_table_names(db_url: str) -> set[str]:
    engine = create_engine(db_url)
    return set(inspect(engine).get_table_names())


def migrated_columns(db_url: str, table_name: str) -> set[str]:
    engine = create_engine(db_url)
    inspector = inspect(engine)
    return {column["name"] for column in inspector.get_columns(table_name)}


def test_initial_migration_creates_foundation_tables(tmp_path: Path) -> None:
    db_path = tmp_path / "control-plane.db"
    db_url = f"sqlite:///{db_path}"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", db_url)

    command.upgrade(config, "head")

    tables = migrated_table_names(db_url)
    assert {
        "api_keys",
        "audit_events",
        "datasources",
        "datasource_tags",
        "field_policies",
        "decrypt_contexts",
        "masking_policies",
        "resources",
        "resource_fields",
        "resource_policies",
        "resource_tags",
        "tags",
        "users",
        "roles",
        "user_roles",
        "org_nodes",
        "alembic_version",
    }.issubset(tables)
    for table_name in tables - {"alembic_version"}:
        column_names = migrated_columns(db_url, table_name)
        assert "tenant_id" not in column_names


def test_directory_tables_exist_after_migration(tmp_path: Path) -> None:
    db_path = tmp_path / "control-plane.db"
    db_url = f"sqlite:///{db_path}"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", db_url)

    command.upgrade(config, "head")

    tables = migrated_table_names(db_url)
    assert "users" in tables
    assert "roles" in tables
    assert "user_roles" in tables
    assert "org_nodes" in tables


def test_api_keys_table_has_user_id_column(tmp_path: Path) -> None:
    db_path = tmp_path / "control-plane.db"
    db_url = f"sqlite:///{db_path}"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", db_url)

    command.upgrade(config, "head")

    columns = migrated_columns(db_url, "api_keys")
    assert "user_id" in columns


def test_datasources_table_has_description_column(tmp_path: Path) -> None:
    db_path = tmp_path / "control-plane.db"
    db_url = f"sqlite:///{db_path}"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", db_url)

    command.upgrade(config, "head")

    columns = migrated_columns(db_url, "datasources")
    assert "description" in columns


def test_resource_policies_table_has_datasource_id_column(tmp_path: Path) -> None:
    db_path = tmp_path / "control-plane.db"
    db_url = f"sqlite:///{db_path}"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", db_url)

    command.upgrade(config, "head")

    columns = migrated_columns(db_url, "resource_policies")
    assert "datasource_id" in columns


def test_migration_uses_database_url_from_environment(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    project_root = Path(__file__).resolve().parents[2]
    configured_db_path = tmp_path / "configured-control-plane.db"
    configured_db_url = f"sqlite:///{configured_db_path}"
    default_db_path = tmp_path / "data" / "adg-control-plane.db"

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ADG_CONTROL_PLANE_DATABASE_URL", configured_db_url)
    default_db_path.parent.mkdir()
    get_settings.cache_clear()

    try:
        config = Config(str(project_root / "alembic.ini"))
        config.set_main_option(
            "script_location",
            str(project_root / "src" / "adg" / "control_plane" / "migrations"),
        )

        command.upgrade(config, "head")
    finally:
        get_settings.cache_clear()

    configured_tables = set(inspect(create_engine(configured_db_url)).get_table_names())
    assert {
        "api_keys",
        "audit_events",
        "datasources",
        "datasource_tags",
        "field_policies",
        "decrypt_contexts",
        "masking_policies",
        "resources",
        "resource_fields",
        "resource_policies",
        "resource_tags",
        "tags",
        "users",
        "roles",
        "user_roles",
        "org_nodes",
        "alembic_version",
    }.issubset(configured_tables)
    assert not default_db_path.exists()


def test_migrations_follow_the_expected_directory_runtime_chain() -> None:
    versions_path = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "adg"
        / "control_plane"
        / "migrations"
        / "versions"
    )
    revision_files = sorted(
        path.name for path in versions_path.glob("*.py") if path.name != "__init__.py"
    )
    assert revision_files == [
        "202604260001_directory_runtime_baseline.py",
        "202604260002_security_hardening_runtime_admin.py",
        "202606090001_datasource_descriptions.py",
        "202606110001_resource_policy_datasource_scope.py",
        "202610140001_ext_tables.py",
        "202610150001_widen_audit_query_id_and_ext_columns.py",
        "202610290001_executor_capacity.py",
    ]

    revisions: dict[str, tuple[str, str | None]] = {}
    for path in sorted(
        versions_path.glob("*.py"),
        key=lambda item: item.name,
    ):
        if path.name == "__init__.py":
            continue
        spec = spec_from_file_location(path.stem, path)
        assert spec is not None
        assert spec.loader is not None
        module = module_from_spec(spec)
        spec.loader.exec_module(module)
        revisions[path.name] = (module.revision, module.down_revision)

    assert revisions == {
        "202604260001_directory_runtime_baseline.py": ("202604260001", None),
        "202604260002_security_hardening_runtime_admin.py": (
            "202604260002",
            "202604260001",
        ),
        "202606090001_datasource_descriptions.py": (
            "202606090001",
            "202604260002",
        ),
        "202606110001_resource_policy_datasource_scope.py": (
            "202606110001",
            "202606090001",
        ),
        "202610140001_ext_tables.py": ("202610140001", "202606110001"),
        "202610150001_widen_audit_query_id_and_ext_columns.py": (
            "202610150001",
            "202610140001",
        ),
        "202610290001_executor_capacity.py": (
            "202610290001",
            "202610150001",
        ),
    }
