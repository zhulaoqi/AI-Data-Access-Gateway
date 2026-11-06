from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from adg.app.dependencies import AuthenticatedApiKey, require_admin_api_key
from adg.connectors.errors import ConnectorDependencyError, ConnectorOperationError
from adg.connectors.registry import get_connector_registry
from adg.control_plane.db import get_session
from adg.control_plane.models.datasource import Datasource
from adg.control_plane.models.governance import DatasourceTag, Tag
from adg.control_plane.services.datasource_service import DatasourceService
from adg.control_plane.services.metadata_scan_service import MetadataScanService
from adg.runtime_cache import refresh_catalog, refresh_datasources, refresh_policies
from adg.shared.errors import NotFoundError, ValidationError

router = APIRouter(prefix="/admin/datasources", tags=["admin"])


class DatasourceCreateRequest(BaseModel):
    """Payload for creating a datasource connection definition."""

    name: str
    type: str
    description: str | None = None
    config: dict[str, object]
    status: str = "active"


class DatasourceUpdateRequest(BaseModel):
    """Partial update payload for datasource metadata and connection config."""

    name: str | None = None
    description: str | None = None
    config: dict[str, object] | None = None
    status: str | None = None


def _serialize_datasource(
    datasource: Datasource,
    tags_by_datasource_id: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Return the admin-console datasource representation."""

    return {
        "id": datasource.id,
        "name": datasource.name,
        "type": datasource.type,
        "datasource_kind": datasource.datasource_kind,
        "description": datasource.description,
        "config": datasource.admin_config(),
        "status": datasource.status,
        "created_at": datasource.created_at.isoformat(),
        "updated_at": datasource.updated_at.isoformat(),
        "tags": list((tags_by_datasource_id or {}).get(datasource.id, [])),
    }


@router.get("")
def list_datasources(
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> list[dict[str, Any]]:
    """List datasource records for the admin console."""

    service = DatasourceService(session)
    datasources = service.list_datasources()
    tags_by_datasource_id = _load_datasource_tags(session, [item.id for item in datasources])
    return [_serialize_datasource(item, tags_by_datasource_id) for item in datasources]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_datasource(
    payload: DatasourceCreateRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Create a datasource record without testing the connection immediately."""

    service = DatasourceService(session)
    try:
        datasource = service.create_datasource(
            name=payload.name,
            connector_type=payload.type,
            description=payload.description,
            config=payload.config,
            status=payload.status,
        )
    except ValidationError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)) from error
    session.commit()
    session.refresh(datasource)
    refresh_datasources(session)
    return _serialize_datasource(datasource)


@router.get("/{datasource_id}")
def get_datasource(
    datasource_id: str,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Fetch one datasource by id."""

    service = DatasourceService(session)
    try:
        datasource = service.get_datasource(datasource_id)
    except NotFoundError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error)) from error
    return _serialize_datasource(
        datasource,
        _load_datasource_tags(session, [datasource.id]),
    )


@router.patch("/{datasource_id}")
def update_datasource(
    datasource_id: str,
    payload: DatasourceUpdateRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Patch datasource fields and return the updated record."""

    service = DatasourceService(session)
    try:
        datasource = service.update_datasource(
            datasource_id=datasource_id,
            name=payload.name,
            description=payload.description,
            description_provided="description" in payload.model_fields_set,
            status=payload.status,
            config=payload.config,
        )
    except NotFoundError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error)) from error
    except ValidationError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)) from error
    session.commit()
    session.refresh(datasource)
    refresh_datasources(session)
    return _serialize_datasource(
        datasource,
        _load_datasource_tags(session, [datasource.id]),
    )


@router.delete("/{datasource_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_datasource(
    datasource_id: str,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> Response:
    """Delete a datasource and its scanned metadata snapshots."""

    service = DatasourceService(session)
    try:
        service.delete_datasource(datasource_id)
    except NotFoundError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error)) from error
    session.commit()
    refresh_policies(session)
    refresh_catalog(session, datasource_id)
    refresh_datasources(session)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{datasource_id}/test")
def test_datasource(
    datasource_id: str,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, str]:
    """Validate that the stored datasource config can open a live connection."""

    service = DatasourceService(session)
    try:
        datasource = service.get_datasource(datasource_id)
        connector = get_connector_registry().create(datasource.type)
        connector.test_connection(datasource.config())
    except NotFoundError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error)) from error
    except (ConnectorDependencyError, ConnectorOperationError) as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_connector_error_detail(error),
        ) from error
    return {"status": "ok"}


@router.post("/{datasource_id}/scan")
def scan_datasource(
    datasource_id: str,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, int | str]:
    """Scan live metadata through the connector and replace stored snapshots."""

    datasource_service = DatasourceService(session)
    scan_service = MetadataScanService(session)
    try:
        datasource = datasource_service.get_datasource(datasource_id)
        connector = get_connector_registry().create(datasource.type)
        snapshot = connector.scan_metadata(datasource.config())
        counts = scan_service.replace_snapshot(datasource=datasource, snapshot=snapshot)
    except NotFoundError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error)) from error
    except (ConnectorDependencyError, ConnectorOperationError) as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_connector_error_detail(error),
        ) from error
    session.commit()
    refresh_catalog(session, datasource_id)
    return {"status": "ok", **counts}


def _load_datasource_tags(
    session: Session,
    datasource_ids: list[str],
) -> dict[str, list[dict[str, Any]]]:
    """Load serialized tags for datasource ids keyed by datasource id."""

    if not datasource_ids:
        return {}

    rows = session.execute(
        select(DatasourceTag.datasource_id, Tag)
        .join(Tag, Tag.id == DatasourceTag.tag_id)
        .where(DatasourceTag.datasource_id.in_(datasource_ids))
        .order_by(Tag.name)
    ).all()
    tags_by_datasource_id: dict[str, list[dict[str, Any]]] = {
        item_id: [] for item_id in datasource_ids
    }
    for datasource_id, tag in rows:
        tags_by_datasource_id.setdefault(datasource_id, []).append(_serialize_tag(tag))
    return tags_by_datasource_id


def _serialize_tag(tag: Tag) -> dict[str, Any]:
    """Convert a tag ORM object into a JSON-ready admin payload."""

    return {
        "id": tag.id,
        "name": tag.name,
        "category": tag.category,
        "description": tag.description,
    }

def _connector_error_detail(error: ConnectorDependencyError | ConnectorOperationError) -> str:
    if isinstance(error, ConnectorDependencyError):
        return "Datasource connector dependency is missing. Install the required optional extra."
    return "Datasource connector operation failed. Check datasource connectivity and server logs."
