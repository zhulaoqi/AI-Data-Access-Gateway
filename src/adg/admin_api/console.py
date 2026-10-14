import base64
import json
from datetime import datetime
from typing import Annotated, Any, Literal, cast
from urllib.parse import urlsplit, urlunsplit

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.exc import NoResultFound
from sqlalchemy.orm import Session

from adg.app.dependencies import AuthenticatedApiKey, require_admin_api_key
from adg.app.settings import Settings, get_settings
from adg.audit.models import AuditEvent
from adg.audit.service import AuditService
from adg.control_plane.db import get_session
from adg.control_plane.imports.connectors.registry import get_directory_importer
from adg.control_plane.imports.models import ExcelImportExecution, ExcelImportPreview
from adg.control_plane.imports.pipeline import execute_excel_import, preview_excel_import
from adg.control_plane.models.api_key import ApiKey
from adg.control_plane.models.datasource import Datasource
from adg.control_plane.models.directory import OrgNode, Role, User
from adg.control_plane.models.governance import (
    DatasourceTag,
    FieldPolicy,
    ResourcePolicy,
    ResourceTag,
    Tag,
)
from adg.control_plane.models.masking import MaskingPolicy
from adg.control_plane.models.resource import Resource, ResourceField
from adg.control_plane.services.api_key_service import create_api_key as create_api_key_record
from adg.control_plane.services.directory_service import DirectoryService
from adg.mcp_api.runtime_tools import serialize_runtime_tool_definitions
from adg_ext.config import ext_enabled

router = APIRouter(prefix="/admin", tags=["admin-console"])

PolicySubjectType = Literal["all", "user", "role"]
SERVICE_API_KEY_SCOPES = {"admin", "entry"} if ext_enabled() else {"admin"}


def _page_bounds(
    *,
    settings: Settings,
    limit: int | None,
    offset: int,
) -> tuple[int, int]:
    """Normalize admin list pagination using configured defaults and caps."""

    if offset < 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="offset must be >= 0",
        )
    effective_limit = settings.admin_page_default_limit if limit is None else limit
    if effective_limit < 1:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="limit must be >= 1",
        )
    return min(effective_limit, settings.admin_page_max_limit), offset


def _paginated_response(
    *,
    items: list[dict[str, Any]],
    total: int,
    limit: int,
    offset: int,
) -> dict[str, Any]:
    """Shape one admin list response with stable pagination metadata."""

    return {"items": items, "total": total, "limit": limit, "offset": offset}


def _consume_resource_tree_budget(remaining: int, node_count: int) -> int:
    """Fail closed instead of returning a partial catalog tree."""

    if node_count > remaining:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="resource_tree_node_budget_exceeded",
        )
    return remaining - node_count

class TagRequest(BaseModel):
    """Payload for creating a governance tag."""

    name: str
    category: str | None = None
    description: str | None = None


class TagUpdateRequest(BaseModel):
    """Partial update payload for a governance tag."""

    name: str | None = None
    category: str | None = None
    description: str | None = None


class ResourceUpdateRequest(BaseModel):
    """Editable resource fields exposed by the admin console."""

    display_name: str | None = None
    description: str | None = None
    query_language: str | None = None
    status: str | None = None


class ResourceFieldUpdateRequest(BaseModel):
    """Editable field metadata controlled by operators after metadata scans."""

    description: str | None = None
    status: str | None = None


class ResourceTagRequest(BaseModel):
    """Payload for attaching an existing tag to an existing resource."""

    tag_id: str
    resource_id: str


class DatasourceTagRequest(BaseModel):
    """Payload for attaching an existing tag to an existing datasource."""

    tag_id: str
    datasource_id: str


class ResourcePolicyRequest(BaseModel):
    """Payload for creating a resource-level policy."""

    subject_type: PolicySubjectType
    subject_id: str
    effect: str
    action: str
    datasource_id: str | None = None
    resource_id: str | None = None
    tag_id: str | None = None
    allow_decrypt: bool = False
    status: str = "active"


class ResourcePolicyBatchRequest(BaseModel):
    """Payload for creating resource-level policies for multiple targets."""

    subject_type: PolicySubjectType
    subject_id: str
    effect: str
    action: str
    datasource_ids: list[str] = Field(default_factory=list)
    resource_ids: list[str] = Field(default_factory=list)
    tag_ids: list[str] = Field(default_factory=list)
    allow_decrypt: bool = False
    status: str = "active"


class ResourcePolicyUpdateRequest(BaseModel):
    """Partial update payload for resource-level policies."""

    subject_type: PolicySubjectType | None = None
    subject_id: str | None = None
    effect: str | None = None
    action: str | None = None
    datasource_id: str | None = None
    resource_id: str | None = None
    tag_id: str | None = None
    datasource_ids: list[str] | None = None
    resource_ids: list[str] | None = None
    tag_ids: list[str] | None = None
    allow_decrypt: bool | None = None
    status: str | None = None


class FieldPolicyRequest(BaseModel):
    """Payload for creating a field-level policy."""

    subject_type: PolicySubjectType
    subject_id: str
    effect: str
    resource_id: str
    field_name: str
    action: str
    status: str = "active"


class FieldPolicyUpdateRequest(BaseModel):
    """Partial update payload for field-level policies."""

    subject_type: PolicySubjectType | None = None
    subject_id: str | None = None
    effect: str | None = None
    resource_id: str | None = None
    field_name: str | None = None
    action: str | None = None
    status: str | None = None


class MaskingPolicyRequest(BaseModel):
    """Payload for creating a field masking policy."""

    resource_id: str
    field_name: str
    strategy: str
    config: dict[str, object] = {}
    subject_type: PolicySubjectType | None = None
    subject_id: str | None = None
    status: str = "active"


class MaskingPolicyUpdateRequest(BaseModel):
    """Partial update payload for masking policies."""

    resource_id: str | None = None
    field_name: str | None = None
    strategy: str | None = None
    config: dict[str, object] | None = None
    subject_type: PolicySubjectType | None = None
    subject_id: str | None = None
    status: str | None = None


class ApiKeyCreateRequest(BaseModel):
    """Payload for minting a new API key."""

    name: str
    scopes: list[str]
    expires_at: datetime | None = None
    # SHA-256 of a key generated by the caller (the SQL gateway); no plaintext is returned.
    key_hash: str | None = None


class ApiKeyUpdateRequest(BaseModel):
    """Partial update payload for API key metadata."""

    name: str | None = None
    scopes: list[str] | None = None
    expires_at: datetime | None = None


class UserCreateRequest(BaseModel):
    """Payload for provisioning a directory user and its first runtime key."""

    name: str
    external_ref: str
    org_node_id: str | None = None
    role_ids: list[str] = []


class UserUpdateRequest(BaseModel):
    """Partial update payload for directory users."""

    name: str | None = None
    external_ref: str | None = None
    org_node_id: str | None = None
    role_ids: list[str] | None = None
    status: str | None = None


class RoleCreateRequest(BaseModel):
    """Payload for creating a directory role."""

    name: str
    description: str | None = None
    status: str = "active"


class RoleUpdateRequest(BaseModel):
    """Partial update payload for directory roles."""

    name: str | None = None
    description: str | None = None
    status: str | None = None


class OrgNodeCreateRequest(BaseModel):
    """Payload for creating one organization node inside the directory tree."""

    name: str
    parent_id: str | None = None
    code: str | None = None
    status: str = "active"


class OrgNodeUpdateRequest(BaseModel):
    """Partial update payload for organization nodes."""

    name: str | None = None
    parent_id: str | None = None
    code: str | None = None
    status: str | None = None


class UserExcelImportRequest(BaseModel):
    """Structured row payload used by preview/execute import endpoints."""

    rows: list[dict[str, Any]]
    delimiter: str = "/"


class UserImporterPullRequest(BaseModel):
    """Manual pull request for a third-party directory connector."""

    mode: Literal["preview", "execute"] = "preview"
    config: dict[str, Any] = {}


@router.get("/resources")
def list_resources(
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    datasource_id: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> dict[str, Any]:
    """List resources, optionally filtered by datasource, for admin tables."""

    page_limit, page_offset = _page_bounds(settings=settings, limit=limit, offset=offset)
    conditions = []
    if datasource_id is not None:
        conditions.append(Resource.datasource_id == datasource_id)
    total = int(
        session.execute(select(func.count()).select_from(Resource).where(*conditions)).scalar_one()
    )
    resources = list(
        session.execute(
            select(Resource)
            .where(*conditions)
            .order_by(Resource.path)
            .limit(page_limit)
            .offset(page_offset)
        ).scalars()
    )
    tags_by_resource_id = _load_resource_tags(session, [resource.id for resource in resources])
    return _paginated_response(
        items=[_serialize_resource(resource, tags_by_resource_id) for resource in resources],
        total=total,
        limit=page_limit,
        offset=page_offset,
    )


@router.get("/resource-tree")
def list_resource_tree(
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    datasource_id: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> dict[str, Any]:
    """Return resources and fields as an expandable catalog tree."""

    page_limit, page_offset = _page_bounds(settings=settings, limit=limit, offset=offset)
    conditions = []
    if datasource_id is not None:
        conditions.append(Resource.datasource_id == datasource_id)
    root_conditions = [*conditions, Resource.parent_id.is_(None)]
    total = int(
        session.execute(
            select(func.count()).select_from(Resource).where(*root_conditions)
        ).scalar_one()
    )
    remaining_nodes = settings.admin_resource_tree_max_nodes
    resources = list(
        session.execute(
            select(Resource)
            .where(*root_conditions)
            .order_by(Resource.path)
            .limit(min(page_limit, remaining_nodes + 1))
            .offset(page_offset)
        ).scalars()
    )
    remaining_nodes = _consume_resource_tree_budget(remaining_nodes, len(resources))
    seen_resource_ids = {resource.id for resource in resources}
    parent_ids = set(seen_resource_ids)
    while parent_ids:
        descendants = list(
            session.execute(
                select(Resource)
                .where(Resource.parent_id.in_(parent_ids), *conditions)
                .order_by(Resource.path)
                .limit(remaining_nodes + 1)
            ).scalars()
        )
        new_descendants = [
            resource for resource in descendants if resource.id not in seen_resource_ids
        ]
        if not new_descendants:
            break
        remaining_nodes = _consume_resource_tree_budget(
            remaining_nodes,
            len(new_descendants),
        )
        resources.extend(new_descendants)
        parent_ids = {resource.id for resource in new_descendants}
        seen_resource_ids.update(parent_ids)
    resource_ids = [resource.id for resource in resources]
    fields = []
    if resource_ids:
        fields = list(
            session.execute(
                select(ResourceField)
                .where(ResourceField.resource_id.in_(resource_ids))
                .order_by(ResourceField.ordinal_position)
                .limit(remaining_nodes + 1)
            ).scalars()
        )
        remaining_nodes = _consume_resource_tree_budget(remaining_nodes, len(fields))
    tags_by_resource_id = _load_resource_tags(
        session,
        resource_ids,
        max_rows=remaining_nodes,
    )
    return _paginated_response(
        items=_build_resource_tree(resources, fields, tags_by_resource_id),
        total=total,
        limit=page_limit,
        offset=page_offset,
    )


@router.get("/resources/{resource_id}")
def get_resource(
    resource_id: str,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Fetch one resource by id."""

    resource = _get_by_id(session, Resource, resource_id, "Resource not found")
    return _serialize_resource(resource, _load_resource_tags(session, [resource.id]))


@router.patch("/resources/{resource_id}")
def update_resource(
    resource_id: str,
    payload: ResourceUpdateRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Update resource display metadata controlled by the admin console."""

    resource = _get_by_id(session, Resource, resource_id, "Resource not found")
    _apply_updates(resource, payload.model_dump(exclude_unset=True))
    session.commit()
    session.refresh(resource)
    return _serialize_resource(resource)


@router.delete("/resources/{resource_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_resource(
    resource_id: str,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> Response:
    """Delete a resource and dependent governance, field, and masking rows."""

    resource = _get_by_id(session, Resource, resource_id, "Resource not found")
    session.execute(delete(ResourceField).where(ResourceField.resource_id == resource_id))
    session.execute(delete(ResourceTag).where(ResourceTag.resource_id == resource_id))
    session.execute(delete(ResourcePolicy).where(ResourcePolicy.resource_id == resource_id))
    session.execute(delete(FieldPolicy).where(FieldPolicy.resource_id == resource_id))
    session.execute(delete(MaskingPolicy).where(MaskingPolicy.resource_id == resource_id))
    session.delete(resource)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/resources/{resource_id}/fields")
def list_resource_fields(
    resource_id: str,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> list[dict[str, Any]]:
    """List fields scanned for one resource."""

    fields = session.execute(
        select(ResourceField)
        .where(ResourceField.resource_id == resource_id)
        .order_by(ResourceField.ordinal_position)
    ).scalars()
    return [_serialize_resource_field(field) for field in fields]


@router.patch("/resource-fields/{field_id}")
def update_resource_field(
    field_id: str,
    payload: ResourceFieldUpdateRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Update field-level catalog annotations without changing scanned structure."""

    field = _get_by_id(session, ResourceField, field_id, "Field not found")
    _apply_updates(field, payload.model_dump(exclude_unset=True))
    session.commit()
    session.refresh(field)
    return _serialize_resource_field(field)


@router.get("/tags")
def list_tags(
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> list[dict[str, Any]]:
    """List all governance tags."""

    tags = session.execute(
        select(Tag).order_by(Tag.name)
    ).scalars()
    return [_serialize_tag(tag) for tag in tags]


@router.post("/tags", status_code=status.HTTP_201_CREATED)
def create_tag(
    payload: TagRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Create a governance tag."""

    tag = Tag(**payload.model_dump())
    session.add(tag)
    session.commit()
    session.refresh(tag)
    return _serialize_tag(tag)


@router.get("/tags/{tag_id}")
def get_tag(
    tag_id: str,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Fetch one tag by id."""

    tag = _get_by_id(session, Tag, tag_id, "Tag not found")
    return _serialize_tag(tag)


@router.get("/tags/{tag_id}/catalog")
def get_tag_catalog(
    tag_id: str,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> list[dict[str, Any]]:
    """Return datasource-grouped catalog nodes associated with one governance tag."""

    _require_tag(session, tag_id)
    datasource_ids = list(
        session.execute(
            select(DatasourceTag.datasource_id)
            .where(DatasourceTag.tag_id == tag_id)
            .order_by(DatasourceTag.datasource_id)
        ).scalars()
    )
    tagged_resource_ids = list(
        session.execute(
            select(ResourceTag.resource_id)
            .where(ResourceTag.tag_id == tag_id)
            .order_by(ResourceTag.resource_id)
        ).scalars()
    )
    tagged_resources = (
        list(
            session.execute(
                select(Resource)
                .where(Resource.id.in_(tagged_resource_ids))
                .order_by(Resource.path)
            ).scalars()
        )
        if tagged_resource_ids
        else []
    )
    involved_datasource_ids = sorted(
        {
            *datasource_ids,
            *(resource.datasource_id for resource in tagged_resources),
        }
    )
    if not involved_datasource_ids:
        return []

    datasources = list(
        session.execute(
            select(Datasource)
            .where(Datasource.id.in_(involved_datasource_ids))
            .order_by(Datasource.name)
        ).scalars()
    )
    resources = list(
        session.execute(
            select(Resource)
            .where(Resource.datasource_id.in_(involved_datasource_ids))
            .order_by(Resource.path)
        ).scalars()
    )
    tags_by_datasource_id = _load_datasource_tags(session, involved_datasource_ids)
    tags_by_resource_id = _load_resource_tags(session, [resource.id for resource in resources])
    return _build_tag_catalog_tree(
        datasources=datasources,
        resources=resources,
        tagged_resource_ids=set(tagged_resource_ids),
        tags_by_datasource_id=tags_by_datasource_id,
        tags_by_resource_id=tags_by_resource_id,
    )


@router.patch("/tags/{tag_id}")
def update_tag(
    tag_id: str,
    payload: TagUpdateRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Update tag metadata."""

    tag = _get_by_id(session, Tag, tag_id, "Tag not found")
    _apply_updates(tag, payload.model_dump(exclude_unset=True))
    session.commit()
    session.refresh(tag)
    return _serialize_tag(tag)


@router.delete("/tags/{tag_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_tag(
    tag_id: str,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> Response:
    """Delete a tag and any resource bindings that reference it."""

    session.execute(delete(DatasourceTag).where(DatasourceTag.tag_id == tag_id))
    session.execute(delete(ResourceTag).where(ResourceTag.tag_id == tag_id))
    tag = session.get(Tag, tag_id)
    if tag is not None:
        session.delete(tag)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/resource-tags", status_code=status.HTTP_201_CREATED)
def bind_resource_tag(
    payload: ResourceTagRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Attach a tag to a resource after validating the resource exists."""

    _require_tag(session, payload.tag_id)
    _require_resource(session, payload.resource_id)
    binding = session.execute(
        select(ResourceTag).where(
            ResourceTag.tag_id == payload.tag_id,
            ResourceTag.resource_id == payload.resource_id,
        )
    ).scalar_one_or_none()
    if binding is None:
        binding = ResourceTag(**payload.model_dump())
        session.add(binding)
        session.commit()
        session.refresh(binding)
    return {
        "id": binding.id,
        "tag_id": binding.tag_id,
        "resource_id": binding.resource_id,
    }


@router.delete("/resource-tags", status_code=status.HTTP_204_NO_CONTENT)
def unbind_resource_tag(
    tag_id: str,
    resource_id: str,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> Response:
    """Detach a tag from a resource using the tag/resource pair."""

    session.execute(
        delete(ResourceTag).where(
            ResourceTag.tag_id == tag_id,
            ResourceTag.resource_id == resource_id,
        )
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/datasource-tags", status_code=status.HTTP_201_CREATED)
def bind_datasource_tag(
    payload: DatasourceTagRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Attach a tag to a datasource after validating the datasource exists."""

    _require_tag(session, payload.tag_id)
    _require_datasource(session, payload.datasource_id)
    binding = session.execute(
        select(DatasourceTag).where(
            DatasourceTag.tag_id == payload.tag_id,
            DatasourceTag.datasource_id == payload.datasource_id,
        )
    ).scalar_one_or_none()
    if binding is None:
        binding = DatasourceTag(**payload.model_dump())
        session.add(binding)
        session.commit()
        session.refresh(binding)
    return {
        "id": binding.id,
        "tag_id": binding.tag_id,
        "datasource_id": binding.datasource_id,
    }


@router.delete("/datasource-tags", status_code=status.HTTP_204_NO_CONTENT)
def unbind_datasource_tag(
    tag_id: str,
    datasource_id: str,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> Response:
    """Detach a tag from a datasource using the tag/datasource pair."""

    session.execute(
        delete(DatasourceTag).where(
            DatasourceTag.tag_id == tag_id,
            DatasourceTag.datasource_id == datasource_id,
        )
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/resource-policies")
def list_resource_policies(
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> list[dict[str, Any]]:
    """List resource-level policies grouped by subject for admin management."""

    policies = session.execute(
        select(ResourcePolicy).order_by(
            ResourcePolicy.subject_type,
            ResourcePolicy.subject_id,
            ResourcePolicy.id,
        )
    ).scalars()
    return [
        _serialize_resource_policy_group(group, session)
        for group in _group_resource_policies_by_subject(list(policies))
    ]


@router.post("/resource-policies", status_code=status.HTTP_201_CREATED)
def create_resource_policy(
    payload: ResourcePolicyRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Create a resource-level policy, validating optional resource references."""

    data = payload.model_dump()
    _validate_resource_policy_scope(session, data)
    policy = ResourcePolicy(**data)
    session.add(policy)
    session.commit()
    session.refresh(policy)
    return _serialize_resource_policy(policy, session)


@router.post("/resource-policies/batch", status_code=status.HTTP_201_CREATED)
def create_resource_policies_batch(
    payload: ResourcePolicyBatchRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> list[dict[str, Any]]:
    """Create one resource-level policy for each selected datasource, resource, or tag."""

    target_specs = [
        ("datasource_id", item_id) for item_id in _dedupe_ids(payload.datasource_ids)
    ] + [
        ("resource_id", item_id) for item_id in _dedupe_ids(payload.resource_ids)
    ] + [
        ("tag_id", item_id) for item_id in _dedupe_ids(payload.tag_ids)
    ]
    if not target_specs:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one resource policy target is required",
        )

    common_data = payload.model_dump(
        exclude={"datasource_ids", "resource_ids", "tag_ids"}
    )
    policies: list[ResourcePolicy] = []
    for scope_key, target_id in target_specs:
        data = {
            **common_data,
            "datasource_id": None,
            "resource_id": None,
            "tag_id": None,
            scope_key: target_id,
        }
        _validate_resource_policy_scope(session, data)
        policy = ResourcePolicy(**data)
        session.add(policy)
        policies.append(policy)

    session.commit()
    for policy in policies:
        session.refresh(policy)
    return [_serialize_resource_policy(policy, session) for policy in policies]


@router.get("/resource-policies/{policy_id}")
def get_resource_policy(
    policy_id: str,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Fetch one resource-level policy."""

    if _is_resource_policy_subject_group_id(policy_id):
        policies = _get_resource_policy_subject_group(session, policy_id)
        return _serialize_resource_policy_group(policies, session)
    policy = _get_by_id(session, ResourcePolicy, policy_id, "Policy not found")
    return _serialize_resource_policy(policy, session)


@router.patch("/resource-policies/{policy_id}")
def update_resource_policy(
    policy_id: str,
    payload: ResourcePolicyUpdateRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Update a resource-level policy."""

    if _is_resource_policy_subject_group_id(policy_id):
        return _sync_resource_policy_subject_group(session, policy_id, payload)

    policy = _get_by_id(session, ResourcePolicy, policy_id, "Policy not found")
    data = payload.model_dump(exclude_unset=True)
    data = {
        key: value
        for key, value in data.items()
        if key not in {"datasource_ids", "resource_ids", "tag_ids"}
    }
    if {"datasource_id", "resource_id", "tag_id"}.intersection(data):
        scope_keys = {"datasource_id", "resource_id", "tag_id"}
        merged_scope = {
            "datasource_id": policy.datasource_id,
            "resource_id": policy.resource_id,
            "tag_id": policy.tag_id,
            **{key: value for key, value in data.items() if key in scope_keys},
        }
        _validate_resource_policy_scope(session, merged_scope)
    _apply_updates(policy, data)
    session.commit()
    session.refresh(policy)
    return _serialize_resource_policy(policy, session)


@router.delete("/resource-policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_resource_policy(
    policy_id: str,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> Response:
    """Delete a resource-level policy."""

    if _is_resource_policy_subject_group_id(policy_id):
        policies = _get_resource_policy_subject_group(session, policy_id)
        for policy in policies:
            session.delete(policy)
        session.commit()
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    _delete_by_id(session, ResourcePolicy, policy_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/field-policies")
def list_field_policies(
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> list[dict[str, Any]]:
    """List field-level policies with resource labels for display."""

    policies = session.execute(
        select(FieldPolicy)
    ).scalars()
    return [_serialize_field_policy(policy, session) for policy in policies]


@router.post("/field-policies", status_code=status.HTTP_201_CREATED)
def create_field_policy(
    payload: FieldPolicyRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Create a field-level policy for an existing resource."""

    _require_resource(session, payload.resource_id)
    policy = FieldPolicy(**payload.model_dump())
    session.add(policy)
    session.commit()
    session.refresh(policy)
    return _serialize_field_policy(policy, session)


@router.get("/field-policies/{policy_id}")
def get_field_policy(
    policy_id: str,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Fetch one field-level policy."""

    policy = _get_by_id(session, FieldPolicy, policy_id, "Policy not found")
    return _serialize_field_policy(policy, session)


@router.patch("/field-policies/{policy_id}")
def update_field_policy(
    policy_id: str,
    payload: FieldPolicyUpdateRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Update a field-level policy."""

    policy = _get_by_id(session, FieldPolicy, policy_id, "Policy not found")
    data = payload.model_dump(exclude_unset=True)
    if data.get("resource_id") is not None:
        _require_resource(session, data["resource_id"])
    _apply_updates(policy, data)
    session.commit()
    session.refresh(policy)
    return _serialize_field_policy(policy, session)


@router.delete("/field-policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_field_policy(
    policy_id: str,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> Response:
    """Delete a field-level policy."""

    _delete_by_id(session, FieldPolicy, policy_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/masking-policies")
def list_masking_policies(
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> list[dict[str, Any]]:
    """List masking policies with decoded config and resource labels."""

    policies = session.execute(
        select(MaskingPolicy)
    ).scalars()
    return [_serialize_masking_policy(policy, session) for policy in policies]


@router.post("/masking-policies", status_code=status.HTTP_201_CREATED)
def create_masking_policy(
    payload: MaskingPolicyRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Create a masking policy with compact JSON config storage."""

    _require_resource(session, payload.resource_id)
    data = payload.model_dump()
    config = data.pop("config")
    policy = MaskingPolicy(config_json=json.dumps(config, separators=(",", ":")), **data)
    session.add(policy)
    session.commit()
    session.refresh(policy)
    return _serialize_masking_policy(policy, session)


@router.get("/masking-policies/{policy_id}")
def get_masking_policy(
    policy_id: str,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Fetch one masking policy."""

    policy = _get_by_id(session, MaskingPolicy, policy_id, "Masking policy not found")
    return _serialize_masking_policy(policy, session)


@router.patch("/masking-policies/{policy_id}")
def update_masking_policy(
    policy_id: str,
    payload: MaskingPolicyUpdateRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Update a masking policy and re-encode config when supplied."""

    policy = _get_by_id(session, MaskingPolicy, policy_id, "Masking policy not found")
    data = payload.model_dump(exclude_unset=True)
    if data.get("resource_id") is not None:
        _require_resource(session, data["resource_id"])
    config = data.pop("config", None)
    _apply_updates(policy, data)
    if config is not None:
        policy.config_json = json.dumps(config, separators=(",", ":"))
    session.commit()
    session.refresh(policy)
    return _serialize_masking_policy(policy, session)


@router.delete("/masking-policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_masking_policy(
    policy_id: str,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> Response:
    """Delete a masking policy."""

    _delete_by_id(session, MaskingPolicy, policy_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/users", status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreateRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Create a directory user and return its initial plaintext runtime key once."""

    if payload.org_node_id is not None:
        _require_org_node(session, payload.org_node_id)
    _require_roles(session, payload.role_ids)
    user, plaintext = DirectoryService(session).create_user(
        name=payload.name,
        external_ref=payload.external_ref,
        org_node_id=payload.org_node_id,
        role_ids=payload.role_ids,
    )
    session.commit()
    session.refresh(user)
    return {
        "id": user.id,
        "name": user.name,
        "external_ref": user.external_ref,
        "org_node_id": user.org_node_id,
        "role_ids": list(payload.role_ids),
        "status": user.status,
        "api_key": plaintext,
    }


@router.get("/users")
def list_users(
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> list[dict[str, object]]:
    """List directory users enriched with organization, role, and runtime-key metadata."""

    return [user.to_dict() for user in DirectoryService(session).list_users()]


@router.patch("/users/{user_id}")
def update_user(
    user_id: str,
    payload: UserUpdateRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, object]:
    """Update editable directory user fields used by the admin console."""

    data = payload.model_dump(exclude_unset=True)
    if data.get("org_node_id") is not None:
        _require_org_node(session, str(data["org_node_id"]))
    if data.get("role_ids") is not None:
        _require_roles(session, list(data["role_ids"]))
    try:
        user = DirectoryService(session).update_user(user_id, **data)
    except NoResultFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found") from exc
    session.commit()
    session.refresh(user)
    return next(
        summary.to_dict()
        for summary in DirectoryService(session).list_users()
        if summary.id == user.id
    )


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: str,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> Response:
    """Delete one directory user together with its role links and runtime keys."""

    try:
        DirectoryService(session).delete_user(user_id)
    except NoResultFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found") from exc
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/users/{user_id}/reset-key")
def reset_user_key(
    user_id: str,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Rotate a user's runtime key and return the new plaintext value once."""

    try:
        plaintext = DirectoryService(session).reset_runtime_key(user_id)
    except NoResultFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found") from exc
    session.commit()
    return {"api_key": plaintext}


@router.post("/users/imports/excel/preview")
def preview_users_excel_import(
    payload: UserExcelImportRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Preview normalized user-directory changes from structured Excel rows."""

    try:
        result = preview_excel_import(session, rows=payload.rows, delimiter=payload.delimiter)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return result.to_dict()


@router.post("/users/imports/excel/execute")
def execute_users_excel_import(
    payload: UserExcelImportRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Execute normalized user-directory changes from structured Excel rows."""

    try:
        result = execute_excel_import(session, rows=payload.rows, delimiter=payload.delimiter)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    session.commit()
    return result.to_dict()


@router.post("/users/importers/{platform}/pull")
def pull_import_from_platform(
    platform: str,
    payload: UserImporterPullRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Manually pull one importer batch and run it through preview or execute."""

    try:
        batch = get_directory_importer(platform).fetch(payload.config)
        rows = batch.to_rows()
        result: ExcelImportExecution | ExcelImportPreview
        if payload.mode == "execute":
            result = execute_excel_import(session, rows=rows, delimiter=batch.delimiter)
            session.commit()
        else:
            result = preview_excel_import(session, rows=rows, delimiter=batch.delimiter)
    except ValueError as exc:
        detail = str(exc)
        if detail.startswith("Unsupported importer platform:"):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail) from exc
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc
    return result.to_dict()


@router.get("/roles")
def list_roles(
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> list[dict[str, Any]]:
    """List directory roles for admin assignment UIs."""

    roles = session.execute(select(Role).order_by(Role.name)).scalars()
    return [_serialize_role(role, session=session) for role in roles]


@router.post("/roles", status_code=status.HTTP_201_CREATED)
def create_role(
    payload: RoleCreateRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Create a directory role for user assignment and policy targeting."""

    role = Role(**payload.model_dump())
    session.add(role)
    session.commit()
    session.refresh(role)
    return _serialize_role(role, session=session)


@router.patch("/roles/{role_id}")
def update_role(
    role_id: str,
    payload: RoleUpdateRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Update editable directory role fields used by the admin console."""

    role = _get_by_id(session, Role, role_id, "Role not found")
    _apply_updates(role, payload.model_dump(exclude_unset=True))
    session.commit()
    session.refresh(role)
    return _serialize_role(role, session=session)


@router.get("/roles/{role_id}/users")
def list_role_users(
    role_id: str,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> list[dict[str, Any]]:
    """List all users currently assigned to one directory role."""

    _get_by_id(session, Role, role_id, "Role not found")
    return [summary.to_dict() for summary in DirectoryService(session).list_role_users(role_id)]


@router.delete("/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_role(
    role_id: str,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> Response:
    """Delete a role only after all linked users have been reassigned."""

    try:
        DirectoryService(session).delete_role(role_id)
    except NoResultFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/org-nodes")
def list_org_nodes(
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> list[dict[str, Any]]:
    """List organization nodes ordered by path for admin assignment UIs."""

    return [node.to_dict() for node in DirectoryService(session).list_org_nodes()]


@router.post("/org-nodes", status_code=status.HTTP_201_CREATED)
def create_org_node(
    payload: OrgNodeCreateRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Create one organization node and derive its full path from the parent tree."""

    if payload.parent_id is not None:
        _require_org_node(session, payload.parent_id)
    node = DirectoryService(session).create_org_node(**payload.model_dump())
    session.commit()
    session.refresh(node)
    return _serialize_org_node(node, direct_user_names=[])


@router.patch("/org-nodes/{org_node_id}")
def update_org_node(
    org_node_id: str,
    payload: OrgNodeUpdateRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Update one organization node and cascade path changes through descendants."""

    data = payload.model_dump(exclude_unset=True)
    if data.get("parent_id") is not None:
        _require_org_node(session, str(data["parent_id"]))
    try:
        node = DirectoryService(session).update_org_node(org_node_id, **data)
    except NoResultFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization node not found",
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    session.commit()
    session.refresh(node)
    return _serialize_org_node(node, direct_user_names=[])


@router.delete("/org-nodes/{org_node_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_org_node(
    org_node_id: str,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> Response:
    """Delete an organization node only when it has no child nodes or direct users."""

    try:
        DirectoryService(session).delete_org_node(org_node_id)
    except NoResultFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization node not found",
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/api-keys")
def list_api_keys(
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> list[dict[str, Any]]:
    """List API key metadata without exposing raw key values."""

    keys = session.execute(select(ApiKey).order_by(ApiKey.created_at.desc())).scalars()
    return [_serialize_api_key(key) for key in keys]


@router.get("/api-keys/{api_key_id}")
def get_api_key(
    api_key_id: str,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Fetch one API key metadata record."""

    api_key = _get_by_id(session, ApiKey, api_key_id, "API key not found")
    return _serialize_api_key(api_key)


@router.post("/api-keys", status_code=status.HTTP_201_CREATED)
def create_api_key(
    payload: ApiKeyCreateRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Create an API key and return the raw value exactly once."""

    _validate_service_api_key_scopes(payload.scopes)
    try:
        api_key, plaintext = create_api_key_record(
            session,
            name=payload.name,
            scopes=payload.scopes,
            expires_at=payload.expires_at,
            key_hash=payload.key_hash,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    session.commit()
    session.refresh(api_key)
    return {**_serialize_api_key(api_key), "api_key": plaintext}


@router.patch("/api-keys/{api_key_id}")
def update_api_key(
    api_key_id: str,
    payload: ApiKeyUpdateRequest,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Update API key metadata and status."""

    api_key = _get_by_id(session, ApiKey, api_key_id, "API key not found")
    data = payload.model_dump(exclude_unset=True)
    scopes = data.pop("scopes", None)
    _apply_updates(api_key, data)
    if scopes is not None:
        _validate_service_api_key_scopes(scopes)
        api_key.scopes = json.dumps(scopes, separators=(",", ":"))
    session.commit()
    session.refresh(api_key)
    return _serialize_api_key(api_key)


@router.post("/api-keys/{api_key_id}/revoke")
def revoke_api_key(
    api_key_id: str,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Disable an API key without deleting its audit history reference."""

    api_key = session.get(ApiKey, api_key_id)
    if api_key is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")
    api_key.status = "revoked"
    session.commit()
    session.refresh(api_key)
    return _serialize_api_key(api_key)


@router.get("/audit-events")
def list_audit_events(
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    limit: int | None = None,
    offset: int = 0,
) -> dict[str, Any]:
    """List audit events newest-first for the admin console."""

    page_limit, page_offset = _page_bounds(settings=settings, limit=limit, offset=offset)
    total = int(session.execute(select(func.count()).select_from(AuditEvent)).scalar_one())
    events = list(
        session.execute(
            select(AuditEvent)
            .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
            .limit(page_limit)
            .offset(page_offset)
        ).scalars()
    )
    user_summaries = _load_audit_user_summaries(session, events)
    return _paginated_response(
        items=[_serialize_audit_event_summary(event, user_summaries) for event in events],
        total=total,
        limit=page_limit,
        offset=page_offset,
    )


@router.get("/audit-events/{event_id}/sql")
def get_audit_event_sql(
    event_id: str,
    api_key: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """Return raw SQL for one audit event and audit the detail view separately."""

    event = _get_by_id(session, AuditEvent, event_id, "Audit event not found")
    AuditService(session).record_sql_view(
        api_key_id=api_key.id,
        user_id=api_key.user_id,
        target_event=event,
    )
    session.commit()
    return {
        "id": event.id,
        "sql_text": event.sql_text,
    }


@router.get("/mcp/setup")
def get_mcp_setup(
    request: Request,
    _: Annotated[AuthenticatedApiKey, Depends(require_admin_api_key)],
) -> dict[str, Any]:
    """Return minimal MCP HTTP facade setup information for operators."""

    base_url = _build_mcp_public_base_url(request, get_settings())
    return {
        "server_url": f"{base_url}/mcp",
        "http_tool_url_template": f"{base_url}/api/tools/{{tool_name}}",
        "api_key_header": get_settings().api_key_header,
        "identity_source": "api_key",
        "auth_mode": "key-derived identity",
        "identity_contract": {
            "mode": "derived-from-authenticated-key",
            "caller_supplies_identity": False,
            "payload_scope": "business parameters only",
        },
        "tools": serialize_runtime_tool_definitions(),
    }


def _build_mcp_public_base_url(request: Request, settings: Settings) -> str:
    """Build the externally reachable backend URL for MCP clients."""

    base_url = str(request.base_url).rstrip("/")
    if settings.backend_host_port is None:
        return base_url

    parsed = urlsplit(base_url)
    if not parsed.hostname:
        return base_url

    host = parsed.hostname
    host_part = f"[{host}]" if ":" in host and not host.startswith("[") else host
    port_part = "" if settings.backend_host_port in {80, 443} else f":{settings.backend_host_port}"
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme, f"{host_part}{port_part}", path, "", ""))


def _serialize_resource(
    resource: Resource,
    tags_by_resource_id: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Convert a resource ORM object into a JSON-ready admin payload."""

    return {
        "id": resource.id,
        "datasource_id": resource.datasource_id,
        "parent_id": resource.parent_id,
        "kind": resource.kind,
        "name": resource.name,
        "path": resource.path,
        "display_name": resource.display_name,
        "description": resource.description,
        "query_language": resource.query_language,
        "status": resource.status,
        "scanned_at": resource.scanned_at.isoformat(),
        "tags": list((tags_by_resource_id or {}).get(resource.id, [])),
    }


def _validate_service_api_key_scopes(scopes: list[str]) -> None:
    """Reject runtime scopes on service-key routes and keep the allowed set explicit."""

    normalized = {scope.strip() for scope in scopes if scope and scope.strip()}
    if not normalized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one service API key scope is required",
        )
    unsupported = sorted(normalized.difference(SERVICE_API_KEY_SCOPES))
    if unsupported:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only admin scope is allowed on this page",
        )


def _serialize_resource_field(field: ResourceField) -> dict[str, Any]:
    """Convert a scanned field into an editable admin payload."""

    return {
        "id": field.id,
        "datasource_id": field.datasource_id,
        "resource_id": field.resource_id,
        "name": field.name,
        "data_type": field.data_type,
        "nullable": field.nullable,
        "ordinal_position": field.ordinal_position,
        "description": field.description,
        "status": field.status,
    }


def _serialize_role(role: Role, *, session: Session | None = None) -> dict[str, Any]:
    """Convert a directory role into a JSON-ready admin payload."""

    user_count = 0
    if session is not None:
        user_count = len(DirectoryService(session).list_role_users(role.id))
    return {
        "id": role.id,
        "name": role.name,
        "description": role.description,
        "status": role.status,
        "user_count": user_count,
    }


def _serialize_org_node(
    node: OrgNode,
    *,
    direct_user_names: list[str] | None = None,
) -> dict[str, Any]:
    """Convert an organization node into a JSON-ready admin payload."""

    return {
        "id": node.id,
        "name": node.name,
        "code": node.code,
        "parent_id": node.parent_id,
        "path": node.path,
        "depth": node.depth,
        "status": node.status,
        "direct_user_count": len(direct_user_names or []),
        "direct_user_names": list(direct_user_names or []),
    }


def _build_resource_tree(
    resources: list[Resource],
    fields: list[ResourceField],
    tags_by_resource_id: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Nest resource rows by parent id and attach field leaves to table/view nodes."""

    nodes_by_id: dict[str, dict[str, Any]] = {
        resource.id: {
            "key": f"resource:{resource.id}",
            "type": "resource",
            "id": resource.id,
            "datasource_id": resource.datasource_id,
            "parent_id": resource.parent_id,
            "kind": resource.kind,
            "name": resource.name,
            "path": resource.path,
            "display_name": resource.display_name,
            "description": resource.description,
            "query_language": resource.query_language,
            "status": resource.status,
            "scanned_at": resource.scanned_at.isoformat(),
            "tags": list(tags_by_resource_id.get(resource.id, [])),
            "children": [],
        }
        for resource in resources
    }

    roots: list[dict[str, Any]] = []
    for resource in resources:
        node = nodes_by_id[resource.id]
        if resource.parent_id and resource.parent_id in nodes_by_id:
            cast(list[dict[str, Any]], nodes_by_id[resource.parent_id]["children"]).append(node)
        else:
            roots.append(node)

    for field in fields:
        parent = nodes_by_id.get(field.resource_id)
        if parent is None:
            continue
        cast(list[dict[str, Any]], parent["children"]).append(
            {
                "key": f"field:{field.id}",
                "type": "field",
                "id": field.id,
                "field_id": field.id,
                "resource_id": field.resource_id,
                "datasource_id": field.datasource_id,
                "name": field.name,
                "display_name": field.name,
                "data_type": field.data_type,
                "nullable": field.nullable,
                "ordinal_position": field.ordinal_position,
                "description": field.description,
                "status": field.status,
                "children": [],
            }
        )

    return roots


def _build_tag_catalog_tree(
    *,
    datasources: list[Datasource],
    resources: list[Resource],
    tagged_resource_ids: set[str],
    tags_by_datasource_id: dict[str, list[dict[str, Any]]],
    tags_by_resource_id: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Build a datasource-grouped resource tree pruned to tagged nodes and their ancestors."""

    resources_by_id = {resource.id: resource for resource in resources}
    included_resource_ids: set[str] = set()
    for resource_id in tagged_resource_ids:
        current = resources_by_id.get(resource_id)
        while current is not None and current.id not in included_resource_ids:
            included_resource_ids.add(current.id)
            current = resources_by_id.get(current.parent_id) if current.parent_id else None

    filtered_resources = [
        resource for resource in resources if resource.id in included_resource_ids
    ]
    resource_nodes_by_id: dict[str, dict[str, Any]] = {
        resource.id: {
            "key": f"resource:{resource.id}",
            "type": "resource",
            "id": resource.id,
            "datasource_id": resource.datasource_id,
            "parent_id": resource.parent_id,
            "kind": resource.kind,
            "name": resource.name,
            "path": resource.path,
            "display_name": resource.display_name,
            "description": resource.description,
            "query_language": resource.query_language,
            "status": resource.status,
            "scanned_at": resource.scanned_at.isoformat(),
            "tags": list(tags_by_resource_id.get(resource.id, [])),
            "children": [],
        }
        for resource in filtered_resources
    }
    root_resources_by_datasource_id: dict[str, list[dict[str, Any]]] = {
        datasource.id: [] for datasource in datasources
    }
    for resource in filtered_resources:
        node = resource_nodes_by_id[resource.id]
        if resource.parent_id and resource.parent_id in resource_nodes_by_id:
            parent_children = cast(
                list[dict[str, Any]],
                resource_nodes_by_id[resource.parent_id]["children"],
            )
            parent_children.append(node)
        else:
            root_resources_by_datasource_id.setdefault(resource.datasource_id, []).append(node)

    return [
        {
            "key": f"datasource:{datasource.id}",
            "type": "datasource",
            "id": datasource.id,
            "name": datasource.name,
            "display_name": datasource.name,
            "datasource_type": datasource.type,
            "type_name": datasource.type,
            "datasource_kind": datasource.datasource_kind,
            "status": datasource.status,
            "tags": list(tags_by_datasource_id.get(datasource.id, [])),
            "children": list(root_resources_by_datasource_id.get(datasource.id, [])),
        }
        for datasource in datasources
    ]


def _serialize_tag(tag: Tag) -> dict[str, Any]:
    """Convert a tag ORM object into a JSON-ready admin payload."""

    return {
        "id": tag.id,
        "name": tag.name,
        "category": tag.category,
        "description": tag.description,
    }


def _load_resource_tags(
    session: Session,
    resource_ids: list[str],
    *,
    max_rows: int | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Load serialized tags for resource ids keyed by resource id."""

    if not resource_ids:
        return {}

    query = (
        select(ResourceTag.resource_id, Tag)
        .join(Tag, Tag.id == ResourceTag.tag_id)
        .where(ResourceTag.resource_id.in_(resource_ids))
        .order_by(Tag.name)
    )
    if max_rows is not None:
        query = query.limit(max_rows + 1)
    rows = session.execute(query).all()
    if max_rows is not None:
        _consume_resource_tree_budget(max_rows, len(rows))
    tags_by_resource_id: dict[str, list[dict[str, Any]]] = {item_id: [] for item_id in resource_ids}
    for resource_id, tag in rows:
        tags_by_resource_id.setdefault(resource_id, []).append(_serialize_tag(tag))
    return tags_by_resource_id


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


def _serialize_resource_policy(policy: ResourcePolicy, session: Session) -> dict[str, Any]:
    """Convert a resource policy into a JSON-ready payload with display labels."""

    return {
        "id": policy.id,
        "subject_type": policy.subject_type,
        "subject_id": policy.subject_id,
        "subject_label": _subject_label(session, policy.subject_type, policy.subject_id),
        "effect": policy.effect,
        "action": policy.action,
        "datasource_label": _datasource_label(session, policy.datasource_id),
        "datasource_id": policy.datasource_id,
        "resource_label": _resource_label(session, policy.resource_id),
        "resource_id": policy.resource_id,
        "tag_id": policy.tag_id,
        "tag_name": _tag_name(session, policy.tag_id),
        "allow_decrypt": policy.allow_decrypt,
        "status": policy.status,
    }


def _serialize_resource_policy_group(
    policies: list[ResourcePolicy],
    session: Session,
) -> dict[str, Any]:
    """Convert one subject's resource policies into a grouped admin table row."""

    if not policies:
        raise ValueError("Cannot serialize an empty resource policy group")

    first = policies[0]
    policy_items = [_serialize_resource_policy(policy, session) for policy in policies]
    datasource_ids = _dedupe_optional_ids([item["datasource_id"] for item in policy_items])
    resource_ids = _dedupe_optional_ids([item["resource_id"] for item in policy_items])
    tag_ids = _dedupe_optional_ids([item["tag_id"] for item in policy_items])
    datasource_labels = _dedupe_optional_ids([item["datasource_label"] for item in policy_items])
    resource_labels = _dedupe_optional_ids([item["resource_label"] for item in policy_items])
    tag_names = _dedupe_optional_ids([item["tag_name"] for item in policy_items])

    return {
        "id": _resource_policy_subject_group_id(first.subject_type, first.subject_id),
        "policy_ids": [policy.id for policy in policies],
        "policy_count": len(policies),
        "policy_items": policy_items,
        "subject_type": first.subject_type,
        "subject_id": first.subject_id,
        "subject_label": _subject_label(session, first.subject_type, first.subject_id),
        "effect": _group_scalar([policy.effect for policy in policies]),
        "effect_values": _dedupe_ids([policy.effect for policy in policies]),
        "action": _group_scalar([policy.action for policy in policies]),
        "action_values": _dedupe_ids([policy.action for policy in policies]),
        "datasource_ids": datasource_ids,
        "datasource_count": len(datasource_ids),
        "datasource_id": datasource_ids[0] if len(datasource_ids) == 1 else None,
        "datasource_label": _join_labels(datasource_labels),
        "datasource_labels": datasource_labels,
        "resource_ids": resource_ids,
        "resource_count": len(resource_ids),
        "resource_id": resource_ids[0] if len(resource_ids) == 1 else None,
        "resource_label": _join_labels(resource_labels),
        "resource_labels": resource_labels,
        "tag_ids": tag_ids,
        "tag_count": len(tag_ids),
        "tag_id": tag_ids[0] if len(tag_ids) == 1 else None,
        "tag_name": _join_labels(tag_names),
        "tag_names": tag_names,
        "allow_decrypt": all(policy.allow_decrypt for policy in policies),
        "allow_decrypt_values": sorted({policy.allow_decrypt for policy in policies}),
        "status": _group_scalar([policy.status for policy in policies]),
        "status_values": _dedupe_ids([policy.status for policy in policies]),
    }


def _serialize_field_policy(policy: FieldPolicy, session: Session) -> dict[str, Any]:
    """Convert a field policy into a JSON-ready payload with display labels."""

    return {
        "id": policy.id,
        "subject_type": policy.subject_type,
        "subject_id": policy.subject_id,
        "subject_label": _subject_label(session, policy.subject_type, policy.subject_id),
        "effect": policy.effect,
        "resource_label": _resource_label(session, policy.resource_id),
        "resource_id": policy.resource_id,
        "field_name": policy.field_name,
        "action": policy.action,
        "status": policy.status,
    }


def _serialize_masking_policy(policy: MaskingPolicy, session: Session) -> dict[str, Any]:
    """Convert a masking policy into a JSON-ready payload with decoded config."""

    return {
        "id": policy.id,
        "resource_label": _resource_label(session, policy.resource_id),
        "resource_id": policy.resource_id,
        "field_name": policy.field_name,
        "subject_type": policy.subject_type,
        "subject_id": policy.subject_id,
        "strategy": policy.strategy,
        "config": json.loads(policy.config_json),
        "status": policy.status,
    }


def _serialize_api_key(api_key: ApiKey) -> dict[str, Any]:
    """Return API key metadata safe for repeated display."""

    return {
        "id": api_key.id,
        "name": api_key.name,
        "status": api_key.status,
        "scopes": json.loads(api_key.scopes),
        "expires_at": None if api_key.expires_at is None else api_key.expires_at.isoformat(),
        "created_at": api_key.created_at.isoformat(),
    }


def _serialize_audit_event_summary(
    event: AuditEvent,
    user_summaries: dict[str | None, dict[str, str | None]],
) -> dict[str, Any]:
    """Decode audit JSON fields for the summary list without raw SQL text."""

    user_summary = user_summaries.get(event.user_id, {"user_name": None, "user_org_path": None})
    return {
        "id": event.id,
        "user_id": event.user_id,
        "user_name": user_summary["user_name"],
        "user_org_path": user_summary["user_org_path"],
        "api_key_id": event.api_key_id,
        "event_type": event.event_type,
        "datasource_id": event.datasource_id,
        "resource_ids": event.resource_ids,
        "query_id": event.query_id,
        "decision": event.decision,
        "reason": event.reason,
        "metadata": event.audit_metadata,
        "created_at": event.created_at.isoformat(),
    }


def _load_audit_user_summaries(
    session: Session,
    events: list[AuditEvent],
) -> dict[str | None, dict[str, str | None]]:
    """Resolve audit event user details in batches for one page of events."""

    summaries: dict[str | None, dict[str, str | None]] = {
        None: {"user_name": None, "user_org_path": None}
    }
    user_ids = sorted({event.user_id for event in events if event.user_id is not None})
    if not user_ids:
        return summaries

    users = list(session.execute(select(User).where(User.id.in_(user_ids))).scalars())
    org_node_ids = sorted({user.org_node_id for user in users if user.org_node_id is not None})
    org_paths_by_id: dict[str, str] = {}
    if org_node_ids:
        org_nodes = session.execute(select(OrgNode).where(OrgNode.id.in_(org_node_ids))).scalars()
        org_paths_by_id = {node.id: node.path for node in org_nodes}

    for user in users:
        summaries[user.id] = {
            "user_name": user.name,
            "user_org_path": org_paths_by_id.get(user.org_node_id) if user.org_node_id else None,
        }
    for user_id in user_ids:
        summaries.setdefault(user_id, {"user_name": None, "user_org_path": None})
    return summaries

def _audit_user_summary(session: Session, user_id: str | None) -> dict[str, str | None]:
    """Resolve audit user ids into operator-readable directory details."""

    if user_id is None:
        return {"user_name": None, "user_org_path": None}
    user = session.get(User, user_id)
    if user is None:
        return {"user_name": None, "user_org_path": None}
    org_path = None
    if user.org_node_id:
        org_node = session.get(OrgNode, user.org_node_id)
        org_path = org_node.path if org_node is not None else None
    return {"user_name": user.name, "user_org_path": org_path}


def _resource_label(session: Session, resource_id: str | None) -> str | None:
    """Build a human-readable resource label used by policy and masking tables."""

    if resource_id is None:
        return None
    resource = session.get(Resource, resource_id)
    if resource is None:
        return resource_id
    return f"{resource.display_name or resource.name} / {resource.path}"


def _datasource_label(session: Session, datasource_id: str | None) -> str | None:
    """Resolve one datasource id into its display name when available."""

    if datasource_id is None:
        return None
    datasource = session.get(Datasource, datasource_id)
    return datasource.name if datasource is not None else datasource_id


def _tag_name(session: Session, tag_id: str | None) -> str | None:
    """Resolve one tag id into its display name when available."""

    if tag_id is None:
        return None
    tag = session.get(Tag, tag_id)
    return tag.name if tag is not None else tag_id


def _subject_label(session: Session, subject_type: str, subject_id: str) -> str:
    """Resolve one policy subject into a display label for admin tables."""

    if subject_type == "all":
        return subject_id
    if subject_type == "user":
        user = session.get(User, subject_id)
        if user is not None:
            return user.name
    if subject_type == "role":
        role = session.get(Role, subject_id)
        if role is not None:
            return role.name
    return subject_id


def _get_by_id(session: Session, model: type[Any], item_id: str, detail: str) -> Any:
    """Load one ORM row or raise a FastAPI 404 with the supplied detail."""

    item = session.get(model, item_id)
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)
    return item


def _require_resource(session: Session, resource_id: str) -> Resource:
    """Validate that a referenced resource exists."""

    resource = session.get(Resource, resource_id)
    if resource is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")
    return resource


def _require_datasource(session: Session, datasource_id: str) -> Datasource:
    """Validate that a referenced datasource exists."""

    datasource = session.get(Datasource, datasource_id)
    if datasource is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Datasource not found")
    return datasource


def _validate_resource_policy_scope(session: Session, data: dict[str, Any]) -> None:
    """Validate mutually exclusive datasource, resource, and tag policy scopes."""

    scope_keys = ("datasource_id", "resource_id", "tag_id")
    selected = [key for key in scope_keys if data.get(key) is not None]
    if len(selected) > 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Choose only one resource policy scope",
        )
    if data.get("datasource_id") is not None:
        _require_datasource(session, str(data["datasource_id"]))
    if data.get("resource_id") is not None:
        _require_resource(session, str(data["resource_id"]))
    if data.get("tag_id") is not None:
        _require_tag(session, str(data["tag_id"]))


def _dedupe_ids(item_ids: list[str]) -> list[str]:
    """Return stable unique ids while ignoring empty strings."""

    seen: set[str] = set()
    deduped: list[str] = []
    for item_id in item_ids:
        normalized = item_id.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(normalized)
    return deduped


def _dedupe_optional_ids(item_ids: list[Any]) -> list[str]:
    """Return stable unique string values while ignoring nullish entries."""

    return _dedupe_ids([str(item_id) for item_id in item_ids if item_id is not None])


def _join_labels(labels: list[str]) -> str | None:
    """Join a stable set of labels for grouped admin table columns."""

    return ", ".join(labels) if labels else None


def _group_scalar(values: list[str]) -> str:
    """Return a scalar value for homogeneous groups, or mark mixed groups."""

    unique_values = _dedupe_ids(values)
    if len(unique_values) == 1:
        return unique_values[0]
    return "mixed"


def _resource_policy_subject_group_id(subject_type: str, subject_id: str) -> str:
    """Create an opaque stable id for one subject-level resource policy group."""

    raw = json.dumps([subject_type, subject_id], separators=(",", ":")).encode()
    encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return f"subject:{encoded}"


def _is_resource_policy_subject_group_id(item_id: str) -> bool:
    """Return whether an id points at a grouped subject-level policy row."""

    return item_id.startswith("subject:")


def _decode_resource_policy_subject_group_id(group_id: str) -> tuple[str, str]:
    """Decode one subject-level resource policy group id."""

    if not _is_resource_policy_subject_group_id(group_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found")
    encoded = group_id.removeprefix("subject:")
    padded = encoded + ("=" * (-len(encoded) % 4))
    try:
        decoded = json.loads(base64.urlsafe_b64decode(padded).decode())
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy group not found",
        ) from exc
    if (
        not isinstance(decoded, list)
        or len(decoded) != 2
        or not all(isinstance(item, str) for item in decoded)
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy group not found")
    return decoded[0], decoded[1]


def _group_resource_policies_by_subject(
    policies: list[ResourcePolicy],
) -> list[list[ResourcePolicy]]:
    """Group resource policies by subject while preserving database order."""

    groups: dict[tuple[str, str], list[ResourcePolicy]] = {}
    for policy in policies:
        groups.setdefault((policy.subject_type, policy.subject_id), []).append(policy)
    return list(groups.values())


def _get_resource_policy_subject_group(
    session: Session,
    group_id: str,
) -> list[ResourcePolicy]:
    """Load all resource policies belonging to one grouped subject row."""

    subject_type, subject_id = _decode_resource_policy_subject_group_id(group_id)
    policies = list(
        session.execute(
            select(ResourcePolicy)
            .where(
                ResourcePolicy.subject_type == subject_type,
                ResourcePolicy.subject_id == subject_id,
            )
            .order_by(ResourcePolicy.id)
        ).scalars()
    )
    if not policies:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy group not found")
    return policies


def _resource_policy_target_specs_from_sync_payload(
    data: dict[str, Any],
    existing_policies: list[ResourcePolicy],
) -> list[tuple[str, str]]:
    """Resolve datasource/resource/tag targets from a group sync payload."""

    if any(key in data for key in ("datasource_ids", "resource_ids", "tag_ids")):
        datasource_ids = data.get("datasource_ids") or []
        resource_ids = data.get("resource_ids") or []
        tag_ids = data.get("tag_ids") or []
    elif any(key in data for key in ("datasource_id", "resource_id", "tag_id")):
        datasource_ids = [data["datasource_id"]] if data.get("datasource_id") else []
        resource_ids = [data["resource_id"]] if data.get("resource_id") else []
        tag_ids = [data["tag_id"]] if data.get("tag_id") else []
    else:
        datasource_ids = [
            policy.datasource_id
            for policy in existing_policies
            if policy.datasource_id
        ]
        resource_ids = [policy.resource_id for policy in existing_policies if policy.resource_id]
        tag_ids = [policy.tag_id for policy in existing_policies if policy.tag_id]

    target_specs = [
        ("datasource_id", item_id) for item_id in _dedupe_optional_ids(datasource_ids)
    ] + [
        ("resource_id", item_id) for item_id in _dedupe_optional_ids(resource_ids)
    ] + [
        ("tag_id", item_id) for item_id in _dedupe_optional_ids(tag_ids)
    ]
    if not target_specs:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one resource policy target is required",
        )
    return target_specs


def _sync_resource_policy_subject_group(
    session: Session,
    group_id: str,
    payload: ResourcePolicyUpdateRequest,
) -> dict[str, Any]:
    """Replace one subject's resource policies with the submitted batch scopes."""

    existing_policies = _get_resource_policy_subject_group(session, group_id)
    first = existing_policies[0]
    data = payload.model_dump(exclude_unset=True)
    target_specs = _resource_policy_target_specs_from_sync_payload(data, existing_policies)
    common_data = {
        "subject_type": data.get("subject_type", first.subject_type),
        "subject_id": data.get("subject_id", first.subject_id),
        "effect": data.get("effect", first.effect),
        "action": data.get("action", first.action),
        "allow_decrypt": data.get("allow_decrypt", first.allow_decrypt),
        "status": data.get("status", first.status),
    }

    replacement_policies: list[ResourcePolicy] = []
    for scope_key, target_id in target_specs:
        replacement_data = {
            **common_data,
            "datasource_id": None,
            "resource_id": None,
            "tag_id": None,
            scope_key: target_id,
        }
        _validate_resource_policy_scope(session, replacement_data)
        replacement_policies.append(ResourcePolicy(**replacement_data))

    for policy in existing_policies:
        session.delete(policy)
    for policy in replacement_policies:
        session.add(policy)

    session.commit()
    for policy in replacement_policies:
        session.refresh(policy)
    return _serialize_resource_policy_group(replacement_policies, session)


def _require_org_node(session: Session, org_node_id: str) -> OrgNode:
    """Validate that a referenced organization node exists."""

    org_node = session.get(OrgNode, org_node_id)
    if org_node is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization node not found",
        )
    return org_node


def _require_roles(session: Session, role_ids: list[str]) -> None:
    """Validate that all referenced directory roles exist."""

    for role_id in role_ids:
        if session.get(Role, role_id) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")


def _require_tag(session: Session, tag_id: str) -> Tag:
    """Validate that a referenced tag exists."""

    tag = session.get(Tag, tag_id)
    if tag is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tag not found")
    return tag


def _apply_updates(item: Any, data: dict[str, Any]) -> None:
    """Assign patch payload fields onto an ORM object."""

    for key, value in data.items():
        setattr(item, key, value)


def _delete_by_id(session: Session, model: type[Any], item_id: str) -> None:
    """Delete one ORM row by id and commit the change."""

    item = session.get(model, item_id)
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")
    session.delete(item)
    session.commit()
