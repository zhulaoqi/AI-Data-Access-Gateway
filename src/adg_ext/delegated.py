"""Delegated queries for the protocol entry service (PA-6, ``entry`` scope).

The entry service authenticates JDBC clients itself and asks the executor to run a statement on
behalf of a grant. The statement goes through exactly the pipeline of a ``runtime`` query (guard,
row filter, admission, audit); revoked or expired grants are refused here.
"""

import re
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from adg.control_plane.models.directory import User
from adg.control_plane.models.resource import Resource
from adg.gateway_runtime.tools import GatewayRuntimeService
from adg.policy.runtime import load_runtime_identity_for_user
from adg_ext import context as ctxmod
from adg_ext import pipeline
from adg_ext.models import ExtSyncObject
from adg_ext.sync import PREFIX

_CHANNEL = re.compile(r"[a-z][a-z0-9_.-]{0,31}")
MAX_REQUEST_ID = 200  # the audit ``requestId`` filter accepts the same length


class DelegatedError(Exception):
    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


def _grant_user(session: Session, grant_id: str) -> User:
    name = f"{PREFIX}user:{grant_id}"
    user = session.execute(
        select(User).where(User.external_ref == name, User.status == "active")
    ).scalar_one_or_none()
    synced = session.execute(
        select(ExtSyncObject).where(ExtSyncObject.object_type == "user", ExtSyncObject.name == name)
    ).scalar_one_or_none()
    if user is None or synced is None:
        raise DelegatedError(403, "grant_not_active")
    import json

    expires = json.loads(synced.spec_json or "{}").get("expiresAt")
    if expires is not None and datetime.fromtimestamp(int(expires) / 1000, tz=UTC) <= datetime.now(
        UTC
    ):
        raise DelegatedError(403, "grant_expired")
    return user


def run_delegated(session: Session, entry_key_id: str, body: dict[str, Any]) -> dict[str, Any]:
    grant_id = str(body.get("grantId") or "")
    sql = str(body.get("sql") or "")
    request_id = str(body.get("requestId") or "")
    if not grant_id or not sql or not request_id:
        raise DelegatedError(400, "grantId, sql and requestId are required")
    if len(request_id) > MAX_REQUEST_ID:
        raise DelegatedError(400, "requestId_too_long")
    channel = str(body.get("channel") or "jdbc").strip().lower()
    if not _CHANNEL.fullmatch(channel):
        raise DelegatedError(400, "invalid_channel")
    user = _grant_user(session, grant_id)
    identity = load_runtime_identity_for_user(session, user_id=user.id)
    ctx = ctxmod.load(session, user_id=user.id, role_ids=identity.roles)
    if not ctx.scopes:
        raise DelegatedError(403, "grant_has_no_scope")

    database = str(body.get("database") or "").strip().lower()
    resources = [
        r
        for r in session.execute(
            select(Resource).where(Resource.id.in_(list(ctx.scopes)), Resource.status == "active")
        ).scalars()
        if not database or r.path.lower().startswith(database + ".")
    ]
    datasource_ids = sorted({r.datasource_id for r in resources})
    if not datasource_ids:
        raise DelegatedError(404, "database_not_found")
    if len(datasource_ids) > 1:
        raise DelegatedError(409, "datasource_ambiguous")
    datasource_id = datasource_ids[0]

    svc = GatewayRuntimeService(session)
    result = pipeline.run(
        svc,
        identity=identity,
        api_key_id=entry_key_id,
        datasource_id=datasource_id,
        resource_ids=[r.id for r in resources],
        query=sql,
        limit=int(body.get("limit") or 1000),
        event_type="query_execution",
        request_id=request_id,
        audit_extra={
            "channel": channel,
            "request_id": request_id,
            "client_ip": str(body.get("clientIp") or ""),
            "grant_id": grant_id,
        },
    )
    if result is None:
        raise DelegatedError(403, "grant_has_no_scope")
    session.commit()
    return result
