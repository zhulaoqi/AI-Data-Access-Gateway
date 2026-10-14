"""HTTP surface of the extension: sync and dry-run (admin scope), delegated queries (entry)."""

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
from adg_ext.config import get_ext_settings
from adg_ext.delegated import DelegatedError, run_delegated
from adg_ext.dryrun import dry_run
from adg_ext.netguard import check_source
from adg_ext.pipeline import get_admission
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
    key: Annotated[AuthenticatedApiKey, Depends(require_entry_key)],
) -> dict[str, int]:
    del key
    return {"cancelled": get_admission().revoke(f"req:{request_id}")}
