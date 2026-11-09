from adg_ext.dryrun import dry_run

# Two tables in one profile. Only the audit log allows created_at. No column catalog is
# sent, which is how the control plane calls dry-run.
SPEC = {
    "scope": {
        "tables": [
            {
                "datasource": "nebula",
                "database": "info",
                "name": "ai_gateway_audit_log",
                "columns": {"allow": ["id", "created_at", "skill_id"]},
            },
            {
                "datasource": "nebula",
                "database": "info",
                "name": "other_table",
                "columns": {"allow": ["id", "name"]},
            },
        ]
    },
    "limits": {"max_rows": 100},
}


def _run(sql: str) -> dict:
    return dry_run({"dialect": "mysql", "datasource": "nebula", "spec": SPEC, "sql": sql})


def test_column_allowed_on_the_queried_table_is_not_rejected_by_other_tables() -> None:
    result = _run(
        "SELECT id, created_at, skill_id FROM info.ai_gateway_audit_log "
        "WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 MINUTE)"
    )
    assert result["allowed"] is True, result["rejectReasons"]


def test_column_missing_on_the_queried_table_is_still_rejected() -> None:
    result = _run("SELECT created_at FROM info.other_table")
    assert result["rejectReasons"] == ["column_not_allowed:created_at"]


def test_table_outside_the_profile_is_still_rejected() -> None:
    result = _run("SELECT id FROM info.missing")
    assert result["rejectReasons"] == ["table_not_accessible:info.missing"]


def test_inaccessible_tables_names_only_the_paths_written_in_sql() -> None:
    from adg.control_plane.models.resource import Resource
    from adg_ext.pipeline import inaccessible_tables

    orders = Resource(
        id="r-orders",
        datasource_id="d",
        kind="relational_table",
        name="orders",
        path="shop.orders",
        display_name="orders",
        status="active",
        metadata_json="{}",
    )
    assert inaccessible_tables(["shop.orders"], [orders], {"r-orders"}) == []
    assert inaccessible_tables(["shop.dim", "shop.no_such_table"], [orders], {"r-orders"}) == [
        "shop.dim",
        "shop.no_such_table",
    ]
    assert inaccessible_tables(["shop.orders"], [orders], set()) == ["shop.orders"]
