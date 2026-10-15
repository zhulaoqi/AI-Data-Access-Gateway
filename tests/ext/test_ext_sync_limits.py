"""Sync input limits that mirror the control-plane column widths (no engine needed)."""

import pytest

from adg_ext import sync
from adg_ext.sync import MAX_DESCRIPTION, MAX_IDENT, MAX_NAME, MAX_PATH, ExtSyncError, fit_snapshot


def test_object_names_are_bounded_by_the_narrowest_native_column() -> None:
    sync.SyncService._check("user", "gw:user:" + "u" * (MAX_NAME - len("gw:user:")))
    for bad in ("gw:user:" + "u" * (MAX_NAME - len("gw:user:") + 1), "user:no-prefix"):
        with pytest.raises(ExtSyncError) as error:
            sync.SyncService._check("user", bad)
        assert error.value.status == 400


def test_name_limit_matches_the_native_columns() -> None:
    from adg.control_plane.models.api_key import ApiKey
    from adg.control_plane.models.datasource import Datasource
    from adg.control_plane.models.directory import Role, User

    for column in (
        Datasource.__table__.c.name,
        Role.__table__.c.name,
        User.__table__.c.external_ref,
        User.__table__.c.name,
        ApiKey.__table__.c.name,
    ):
        assert column.type.length >= MAX_NAME, column  # type: ignore[attr-defined]


def _snapshot(**table: object) -> dict[str, object]:
    relation = {"name": "t", "columns": [{"name": "c", "data_type": "Int64"}], **table}
    return {"databases": [{"name": "shop", "tables": [relation], "schemas": []}]}


def test_a_fitting_catalog_is_unchanged() -> None:
    snapshot = _snapshot()
    assert fit_snapshot(snapshot, "gw:ds:1") == snapshot


def test_long_data_types_and_descriptions_are_truncated_not_fatal() -> None:
    long_type = "Enum8(" + ",".join(f"'v{i}'={i}" for i in range(500)) + ")"
    snapshot = _snapshot(
        description="d" * 100_000,
        columns=[{"name": "c", "data_type": long_type, "description": "x" * 100_000}],
    )
    fitted = fit_snapshot(snapshot, "gw:ds:1")
    table = fitted["databases"][0]["tables"][0]
    assert len(table["columns"][0]["data_type"]) == MAX_IDENT
    assert table["columns"][0]["data_type"] == long_type[:MAX_IDENT]
    assert len(table["description"]) == len(table["columns"][0]["description"]) == MAX_DESCRIPTION


def test_identifiers_that_cannot_be_stored_are_left_out_and_the_rest_kept(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = {
        "databases": [
            {
                "name": "shop",
                "tables": [
                    {"name": "t" * (MAX_IDENT + 1), "columns": []},
                    {"name": "x" * MAX_IDENT, "columns": []},  # path "shop.xxx..." is fine
                    {
                        "name": "ok",
                        "columns": [
                            {"name": "c" * (MAX_IDENT + 1), "data_type": "Int64"},
                            {"name": "fine", "data_type": "Int64"},
                        ],
                    },
                ],
                "views": [],
            },
            {"name": "d" * (MAX_IDENT + 1), "tables": []},
            {"name": "p" * 150, "tables": [{"name": "q" * 190, "columns": []}]},
        ]
    }
    warnings: list[str] = []
    monkeypatch.setattr(sync.logger, "warning", lambda msg, *args: warnings.append(msg % args))
    fitted = fit_snapshot(snapshot, "gw:ds:1")
    names = [d["name"] for d in fitted["databases"]]
    assert names == ["shop", "p" * 150]
    shop = fitted["databases"][0]
    assert [t["name"] for t in shop["tables"]] == ["x" * MAX_IDENT, "ok"]
    assert [c["name"] for c in shop["tables"][1]["columns"]] == ["fine"]
    assert shop["views"] == []
    # 150 + 1 + 190 = 341 <= MAX_PATH: kept; the path limit itself is exercised below
    assert fitted["databases"][1]["tables"][0]["name"] == "q" * 190
    assert len(warnings) == 1 and "exceed the control-plane column widths" in warnings[0]


def test_a_relation_whose_path_exceeds_the_path_column_is_left_out() -> None:
    database = "d" * MAX_IDENT
    schema = "s" * MAX_IDENT
    table = "t" * 150  # 200 + 1 + 200 + 1 + 150 = 552 > 512
    assert len(f"{database}.{schema}.{table}") > MAX_PATH
    snapshot = {
        "databases": [
            {
                "name": database,
                "tables": [],
                "schemas": [{"name": schema, "tables": [{"name": table, "columns": []}]}],
            }
        ]
    }
    # the schema path (401) fits; the relation under it (552) does not
    fitted = fit_snapshot(snapshot, "gw:ds:1")
    assert fitted["databases"][0]["schemas"][0]["name"] == schema
    assert fitted["databases"][0]["schemas"][0]["tables"] == []
