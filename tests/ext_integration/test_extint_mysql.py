import hashlib
from typing import Any

import pytest

from tests.ext_integration.conftest import MYSQL, Gateway


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def provision(
    gw: Gateway,
    creds: dict[str, str],
    *,
    tenant: int = 7,
    suffix: str = "1",
    limits: dict[str, Any] | None = None,
    operations: dict[str, Any] | None = None,
    filter_where: str | None = "tenant_id = {{tenant_id}}",
    mask: dict[str, str] | None = None,
) -> str:
    """Sync datasource → role → row filter → user → credential; return the plaintext key."""

    ds = "gw:ds:1"
    if (
        gw.client.get(
            "/admin/ext/sync/datasource_account?prefix=gw:", headers={"X-ADG-API-Key": gw.admin}
        ).json()["items"]
        == []
    ):
        r = gw.sync(
            "datasource_account",
            ds,
            {
                "label": "shop",
                "engine": "mysql",
                "dialect": "mysql",
                "host": MYSQL[0],
                "port": MYSQL[1],
                "database": "shop",
                "username": creds["user"],
                "password": creds["password"],
            },
        )
        assert r.status_code == 200, r.text
    role = f"gw:role:p{suffix}:v1"
    r = gw.sync(
        "role",
        role,
        {
            "profileId": f"p{suffix}",
            "profileName": "sales",
            "version": 1,
            "tables": [
                {
                    "datasource": ds,
                    "database": "shop",
                    "table": "orders",
                    "allow": ["id", "tenant_id", "phone", "amount", "created_at"],
                    "deny": ["ssn"],
                    "mask": {"phone": "partial"} if mask is None else mask,
                }
            ],
            "operations": operations or {"mode": "read_only"},
            "limits": limits
            or {
                "maxConcurrency": 2,
                "queueSize": 2,
                "queueTimeoutSeconds": 3,
                "queryTimeoutSeconds": 5,
                "maxRows": 100,
            },
        },
    )
    assert r.status_code == 200, r.text
    if filter_where:
        r = gw.sync(
            "row_filter",
            f"gw:rf:p{suffix}:v1",
            {
                "role": role,
                "params": [{"name": "tenant_id", "type": "long", "required": True}],
                "filters": [
                    {"datasource": ds, "database": "shop", "table": "orders", "where": filter_where}
                ],
            },
        )
        assert r.status_code == 200, r.text
    r = gw.sync(
        "user",
        f"gw:user:g{suffix}",
        {
            "grantId": f"g{suffix}",
            "principalId": "pr1",
            "principalName": "Alice",
            "role": role,
            "kind": "human",
            "channels": ["mcp"],
            "params": {"tenant_id": tenant},
            "expiresAt": 4_102_444_800_000,
        },
    )
    assert r.status_code == 200, r.text
    key = f"adg_key_{suffix}_secret"
    r = gw.sync(
        "credential",
        f"gw:cred:c{suffix}",
        {
            "user": f"gw:user:g{suffix}",
            "channel": "mcp",
            "keyHash": sha(key),
            "keyPrefix": key[:8],
            "expiresAt": 4_102_444_800_000,
        },
    )
    assert r.status_code == 200, r.text
    gw.keys[suffix] = key
    return key


def target(gw: Gateway, key: str) -> tuple[str, list[str]]:
    listing = gw.tool(key, "list_datasources").json()
    datasource_id = listing["datasources"][0]["id"]
    resources = gw.tool(key, "list_resources", datasource_id=datasource_id).json()
    return datasource_id, [r["id"] for r in resources["resources"] if r["name"] == "orders"]


def query(gw: Gateway, key: str, sql: str, limit: int = 100) -> dict[str, Any]:
    ds, ids = target(gw, key)
    r = gw.tool(key, "execute_query", datasource_id=ds, resource_ids=ids, query=sql, limit=limit)
    assert r.status_code == 200, r.text
    return r.json()


def test_row_filter_and_masking_hold_end_to_end(
    gateway: Gateway, mysql_seed: dict[str, str]
) -> None:
    key = provision(gateway, mysql_seed)
    out = query(gateway, key, "SELECT id, phone AS phone, amount FROM shop.orders ORDER BY id")
    assert out["status"] == "success", out
    assert [row["id"] for row in out["rows"]] == [1, 2]  # tenant 7 only
    assert out["rows"][0]["phone"] == "13*******01"  # masked
    assert out["truncated"] is False


def test_closed_column_scope_and_wildcard(gateway: Gateway, mysql_seed: dict[str, str]) -> None:
    key = provision(gateway, mysql_seed)
    out = query(gateway, key, "SELECT * FROM shop.orders")
    assert out["status"] == "rejected"
    assert out["hint"]["allowed_columns"]
    assert "ssn" not in str(out["hint"])
    assert query(gateway, key, "SELECT ssn FROM shop.orders")["reason"].startswith(
        "column_not_allowed"
    )
    assert query(gateway, key, "SELECT id FROM shop.orders WHERE ssn = '111'")["reason"].startswith(
        "column_not_allowed"
    )


def test_masked_column_cannot_be_probed(gateway: Gateway, mysql_seed: dict[str, str]) -> None:
    key = provision(gateway, mysql_seed)
    out = query(gateway, key, "SELECT id FROM shop.orders WHERE phone = '13800000001'")
    assert out["reason"].startswith("masked_column_position_not_allowed")


def test_other_tables_and_unknown_tables_answer_alike(
    gateway: Gateway, mysql_seed: dict[str, str]
) -> None:
    key = provision(gateway, mysql_seed)
    a = query(gateway, key, "SELECT id FROM shop.dim")
    b = query(gateway, key, "SELECT id FROM shop.no_such_table")
    c = query(gateway, key, "SELECT table_name FROM information_schema.tables")
    assert a["reason"] == b["reason"] == "table_not_accessible"
    assert c["status"] == "rejected"


def test_missing_grant_parameter_rejects_instead_of_unfiltered(
    gateway: Gateway, mysql_seed: dict[str, str]
) -> None:
    key = provision(gateway, mysql_seed)
    # the user's params are replaced by an empty set
    r = gateway.sync(
        "user",
        "gw:user:g1",
        {
            "grantId": "g1",
            "principalId": "pr1",
            "principalName": "Alice",
            "role": "gw:role:p1:v1",
            "kind": "human",
            "channels": ["mcp"],
            "params": {},
            "expiresAt": 4_102_444_800_000,
        },
    )
    assert r.status_code == 200
    out = query(gateway, key, "SELECT id FROM shop.orders")
    assert out["status"] == "rejected" and out["reason"].startswith("row_filter_param_missing")


def test_row_cap_marks_truncation(gateway: Gateway, mysql_seed: dict[str, str]) -> None:
    key = provision(
        gateway,
        mysql_seed,
        limits={
            "maxConcurrency": 1,
            "queueSize": 1,
            "queueTimeoutSeconds": 1,
            "queryTimeoutSeconds": 5,
            "maxRows": 1,
        },
    )
    out = query(gateway, key, "SELECT id FROM shop.orders ORDER BY id")
    assert out["status"] == "success"
    assert len(out["rows"]) == 1 and out["truncated"] is True and out["max_rows"] == 1


def test_audit_row_is_committed_before_execution_and_completed(
    gateway: Gateway, mysql_seed: dict[str, str]
) -> None:
    from sqlalchemy import select

    from adg.audit.models import AuditEvent

    key = provision(gateway, mysql_seed)
    out = query(gateway, key, "SELECT id FROM shop.orders")
    assert out["status"] == "success"
    with gateway.factory() as session:
        event = session.execute(
            select(AuditEvent).where(AuditEvent.query_id == out["query_id"])
        ).scalar_one()
        meta = json.loads(event.metadata_json)
    assert meta["phase"] == "completed" and meta["rows"] == 2
    assert "tenant_id = 7" in meta["rewritten_sql"]
    assert meta["grant"]


import json  # noqa: E402
