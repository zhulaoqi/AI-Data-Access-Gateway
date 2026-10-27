"""HTTP surface of the extension: sync, dry-run and audit queries (admin), delegated (entry)."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from adg.app.dependencies import (
    AuthenticatedApiKey,
    authenticate_api_key_value,
    require_admin_api_key,
    require_scope,
)
from adg.app.settings import get_settings
from adg.control_plane.db import get_session
from adg_ext import audit_query, blocklist, revocation
from adg_ext import metrics as metrics_text
from adg_ext.config import get_ext_settings
from adg_ext.delegated import DelegatedError, run_delegated
from adg_ext.dryrun import dry_run
from adg_ext.netguard import check_source
from adg_ext.pipeline import get_admission
from adg_ext.redis_share import get_share
from adg_ext.sync import ExtSyncError, SyncService


def require_ext_admin(
    request: Request,
    key: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
) -> AuthenticatedApiKey:
    check_source(request, get_ext_settings().admin_allowed_cidrs)
    return key


def require_entry_key(
    request: Request, session: Annotated[Session, Depends(get_session)]
) -> AuthenticatedApiKey:
    check_source(request, get_ext_settings().entry_allowed_cidrs)
    key = authenticate_api_key_value(
        session,
        request.headers.get(get_settings().api_key_header),
        client_identifier=request.client.host if request.client else None,
    )
    return require_scope(key, "entry", "Entry scope required")


class SyncBody(BaseModel):
    hash: str
    spec: dict[str, Any]


admin_router = APIRouter(
    prefix="/admin/ext", tags=["ext"], dependencies=[Depends(require_ext_admin)]
)
delegated_router = APIRouter(prefix="/ext/delegated", tags=["ext"])
audit_router = APIRouter(
    prefix="/ext/audit", tags=["ext"], dependencies=[Depends(require_ext_admin)]
)


def _fail(error: ExtSyncError) -> HTTPException:
    return HTTPException(status_code=error.status, detail=error.message)


@admin_router.put("/sync/{object_type}/{name}")
def put_object(
    object_type: str,
    name: str,
    body: SyncBody,
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, str]:
    service = SyncService(session)
    try:
        external_id = service.put(object_type, name, body.hash, body.spec)
        session.commit()
    except ExtSyncError as error:
        session.rollback()
        raise _fail(error) from error
    return {"externalId": external_id}


@admin_router.delete("/sync/{object_type}/{name}")
def delete_object(
    object_type: str,
    name: str,
    session: Annotated[Session, Depends(get_session)],
) -> Response:
    service = SyncService(session)
    try:
        external_id = service.external_id_of(object_type, name)
        service.delete(object_type, name)
        session.commit()
    except ExtSyncError as error:
        session.rollback()
        raise _fail(error) from error
    if external_id and object_type in {"user", "credential"}:
        # revocation must also stop requests that are already queued or running
        get_admission().revoke(external_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@admin_router.post("/sync/{object_type}/{name}/reinstate")
def reinstate_object(
    object_type: str,
    name: str,
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, bool]:
    """Lift the tombstone of a revoked credential / deleted user so a new PUT is accepted."""

    try:
        lifted = SyncService(session).reinstate(object_type, name)
        session.commit()
    except ExtSyncError as error:
        session.rollback()
        raise _fail(error) from error
    return {"reinstated": lifted}


@admin_router.post("/sync/datasource_account/{name}/rescan")
def rescan_datasource(
    name: str,
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, int | str]:
    """Re-scan the live catalog of a synced datasource without changing its spec."""

    try:
        counts = SyncService(session).rescan(name)
        session.commit()
    except ExtSyncError as error:
        session.rollback()
        raise _fail(error) from error
    return {"status": "ok", **counts}


@admin_router.get("/sync/{object_type}")
def list_objects(
    object_type: str,
    session: Annotated[Session, Depends(get_session)],
    prefix: Annotated[str, Query()] = "gw:",
) -> dict[str, list[dict[str, str | None]]]:
    try:
        items = SyncService(session).list(object_type, prefix)
    except ExtSyncError as error:
        raise _fail(error) from error
    return {"items": [{"name": i.name, "externalId": i.external_id, "hash": i.hash} for i in items]}


@admin_router.post("/dry-run")
def post_dry_run(body: dict[str, Any]) -> dict[str, Any]:
    return dry_run(body)


@admin_router.get("/metrics")
def metrics() -> dict[str, object]:
    return get_admission().snapshot()


@admin_router.get("/metrics/prometheus")
def metrics_prometheus() -> Response:
    """Prometheus text exposition (0.0.4); admin scope and ``ADG_EXT_ADMIN_ALLOWED_CIDRS`` apply."""

    body = metrics_text.render(
        get_admission(),
        metrics_text.get_query_metrics(),
        revocation.get_cache(),
        blocklist.get_cache(),
    )
    return Response(content=body, media_type=metrics_text.CONTENT_TYPE)


@admin_router.post("/blocklist/refresh")
def refresh_blocklist(force: Annotated[bool, Query()] = False) -> dict[str, object]:
    """Pull the blocklist now (``force`` accepts a snapshot the shrink guard would refuse)."""

    cache = blocklist.get_cache()
    if not cache.enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="blocklist_disabled")
    updated = cache.refresh(force=force)
    return {"updated": updated, "version": cache.version, "entries": cache.size()}


@delegated_router.post("/query")
def delegated_query(
    body: dict[str, Any],
    key: Annotated[AuthenticatedApiKey, Depends(require_entry_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    try:
        return run_delegated(session, key.id, body)
    except DelegatedError as error:
        raise HTTPException(status_code=error.status, detail=error.reason) from error


@delegated_router.delete("/query/{request_id}")
def cancel_delegated_query(
    request_id: str,
    request: Request,
    key: Annotated[AuthenticatedApiKey, Depends(require_entry_key)],
) -> dict[str, int]:
    del key
    forwarded = get_share().forward_cancel(
        request_id,
        request.headers.get("authorization"),
        request.headers.get("x-sqlgw-cancel-hop"),
    )
    if forwarded is not None:
        return {"cancelled": forwarded}
    return {"cancelled": get_admission().revoke(f"req:{request_id}")}


def _audit_fail(error: audit_query.AuditQueryError) -> HTTPException:
    return HTTPException(status_code=error.status, detail=error.reason)


@audit_router.get("/events")
def list_audit_events(
    session: Annotated[Session, Depends(get_session)],
    grant_ids: Annotated[list[str] | None, Query(alias="grantIds")] = None,
    from_: Annotated[str | None, Query(alias="from")] = None,
    to: Annotated[str | None, Query()] = None,
    decision: Annotated[str | None, Query()] = None,
    status_: Annotated[str | None, Query(alias="status")] = None,
    table: Annotated[str | None, Query()] = None,
    reason: Annotated[str | None, Query()] = None,
    query_id: Annotated[str | None, Query(alias="queryId")] = None,
    event_type: Annotated[str | None, Query(alias="eventType")] = None,
    request_id: Annotated[str | None, Query(alias="requestId")] = None,
    channel: Annotated[str | None, Query()] = None,
    datasource_id: Annotated[str | None, Query(alias="datasourceId")] = None,
    include_sql: Annotated[bool, Query(alias="includeSql")] = False,
    limit: Annotated[int | None, Query()] = None,
    offset: Annotated[int, Query()] = 0,
) -> dict[str, Any]:
    try:
        page_limit, page_offset = audit_query.check_page(limit, offset)
        filters = audit_query.build_filters(
            start=from_,
            end=to,
            grant_ids=grant_ids,
            datasource_id=datasource_id,
            decision=decision,
            status=status_,
            table=table,
            reason=reason,
            query_id=query_id,
            event_type=event_type,
            request_id=request_id,
            channel=channel,
        )
        return audit_query.list_events(
            session, filters, page_limit, page_offset, include_sql=include_sql
        )
    except audit_query.AuditQueryError as error:
        raise _audit_fail(error) from error


@audit_router.get("/events/{event_id}")
def get_audit_event(
    event_id: str,
    key: Annotated[AuthenticatedApiKey, Depends(require_ext_admin)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    try:
        return audit_query.event_detail(session, event_id, api_key_id=key.id, user_id=key.user_id)
    except audit_query.AuditQueryError as error:
        raise _audit_fail(error) from error


@audit_router.get("/stats")
def audit_stats(
    session: Annotated[Session, Depends(get_session)],
    from_: Annotated[str | None, Query(alias="from")] = None,
    to: Annotated[str | None, Query()] = None,
) -> dict[str, Any]:
    try:
        return audit_query.stats(session, from_, to)
    except audit_query.AuditQueryError as error:
        raise _audit_fail(error) from error


@audit_router.get("/aggregates")
def audit_aggregates(
    session: Annotated[Session, Depends(get_session)],
    group_by: Annotated[str, Query(alias="groupBy")],
    from_: Annotated[str | None, Query(alias="from")] = None,
    to: Annotated[str | None, Query()] = None,
    near_percent: Annotated[int, Query(alias="nearPercent")] = 90,
) -> dict[str, Any]:
    try:
        return audit_query.aggregates(session, from_, to, group_by, near_percent)
    except audit_query.AuditQueryError as error:
        raise _audit_fail(error) from error
