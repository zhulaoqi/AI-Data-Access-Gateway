from adg.policy.runtime import IdentityContext
from adg.visibility_cache import merge_visible


def test_a_sync_replaces_only_the_datasource_it_touched() -> None:
    previous = {
        "roles": ["role-a"],
        "datasources": [
            {"id": "ds-keep", "name": "keep"},
            {"id": "ds-touch", "name": "touch"},
        ],
        "by_datasource": {
            "ds-keep": [{"id": "table-keep"}],
            "ds-touch": [{"id": "table-old"}],
        },
        "tags": [{"id": "tag-keep", "name": "kept"}, {"id": "tag-old", "name": "old"}],
        "tag_names": {"table-keep": ["kept"], "table-old": ["old"]},
    }
    fresh = {
        "roles": ["role-a"],
        "datasources": [{"id": "ds-touch", "name": "touch"}],
        "by_datasource": {"ds-touch": [{"id": "table-new"}]},
        "tags": [{"id": "tag-new", "name": "new"}],
        "tag_names": {"table-new": ["new"]},
    }
    merged = merge_visible(
        previous,
        fresh,
        {"ds-touch"},
        IdentityContext(user_id="user-1", roles=["role-a"]),
        replace=False,
    )
    assert [row["id"] for row in merged["by_datasource"]["ds-keep"]] == ["table-keep"]
    assert [row["id"] for row in merged["by_datasource"]["ds-touch"]] == ["table-new"]
    assert merged["tag_names"] == {"table-keep": ["kept"], "table-new": ["new"]}
    assert {tag["name"] for tag in merged["tags"]} == {"kept", "new"}


def test_a_grant_change_drops_datasources_the_role_no_longer_includes() -> None:
    previous = {
        "roles": ["role-old"],
        "datasources": [
            {"id": "ds-old", "name": "old"},
            {"id": "ds-new", "name": "new"},
        ],
        "by_datasource": {
            "ds-old": [{"id": "table-old"}],
            "ds-new": [{"id": "table-stale"}],
        },
        "tags": [],
        "tag_names": {},
    }
    fresh = {
        "roles": ["role-new"],
        "datasources": [{"id": "ds-new", "name": "new"}],
        "by_datasource": {"ds-new": [{"id": "table-live"}]},
        "tags": [],
        "tag_names": {},
    }
    merged = merge_visible(
        previous,
        fresh,
        {"ds-new"},
        IdentityContext(user_id="user-1", roles=["role-new"]),
        replace=True,
    )
    assert list(merged["by_datasource"]) == ["ds-new"]
    assert merged["by_datasource"]["ds-new"][0]["id"] == "table-live"
    assert merged["roles"] == ["role-new"]
