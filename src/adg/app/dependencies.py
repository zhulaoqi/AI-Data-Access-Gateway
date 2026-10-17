import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from adg.app.auth_rate_limit import (
    RATE_LIMIT_DETAIL,
    check_auth_rate_limited,
    record_auth_failure,
    record_auth_success,
)
from adg.app.settings import get_settings
from adg.control_plane.db import get_session
from adg.control_plane.models.api_key import ApiKey
from adg.policy.runtime import IdentityContext, load_runtime_identity_for_user
from adg.shared.security import hash_api_key
from adg_ext import enforce as ext_enforce
from adg_ext import revocation as ext_revocation
from adg_ext.config import ext_enabled


@dataclass(frozen=True)
class AuthenticatedApiKey:
    """Minimal authenticated API-key identity shared by request handlers."""

    id: str
    scopes: str
    user_id: str | None = None


@dataclass(frozen=True)
class AuthenticatedRuntimeKey(AuthenticatedApiKey):
    """Runtime-scoped API key with directory identity loaded from the key binding."""

    role_ids: list[str] = field(default_factory=list)
    org_node_id: str | None = None

    @property
    def runtime_identity(self) -> IdentityContext:
        """Return the key-derived runtime identity used by shared tool dispatch."""

        return IdentityContext(
            user_id=self.user_id,
            roles=list(self.role_ids),
            org_node_id=self.org_node_id,
        )


def _normalize_expiration(expires_at: datetime) -> datetime:
    """Treat legacy naive timestamps as UTC before comparing them."""

    if expires_at.tzinfo is None:
        return expires_at.replace(tzinfo=UTC)
    return expires_at


def require_api_key(
    session: Annotated[Session, Depends(get_session)],
    request: Request,
) -> AuthenticatedApiKey:
    """Authenticate a request against active API keys stored in the control plane."""

    raw_api_key = request.headers.get(get_settings().api_key_header)
    return authenticate_api_key_value(
        session,
        raw_api_key,
        client_identifier=_client_identifier_from_request(request),
    )


def authenticate_api_key_value(
    session: Session,
    raw_api_key: str | None,
    client_identifier: str | None = None,
) -> AuthenticatedApiKey:
    """Authenticate one raw API key value against the active control-plane keys."""

    # PA-8: a blocked source is refused before any credential is examined.
    ext_enforce.check_source(session)

    # A shared reverse-proxy peer must never prevent a valid credential from being checked.
    if check_auth_rate_limited(raw_api_key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=RATE_LIMIT_DETAIL,
        )

    if raw_api_key is None or raw_api_key == "":
        ext_enforce.auth_failed(session, "invalid")
        _record_auth_failure_or_raise_rate_limited(raw_api_key, client_identifier)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
        )

    api_key = session.execute(
        select(ApiKey).where(
            ApiKey.status == "active",
            ApiKey.key_hash == hash_api_key(raw_api_key),
        )
    ).scalar_one_or_none()
    if api_key is not None:
        if ext_enabled() and ext_revocation.get_cache().is_revoked(api_key.key_hash):
            ext_enforce.auth_failed(session, "revoked", api_key.user_id)
            _record_auth_failure_or_raise_rate_limited(raw_api_key, client_identifier)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Revoked API key",
            )
        if api_key.expires_at is not None and _normalize_expiration(
            api_key.expires_at
        ) <= datetime.now(UTC):
            ext_enforce.auth_failed(session, "expired", api_key.user_id)
            _record_auth_failure_or_raise_rate_limited(raw_api_key, client_identifier)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Expired API key",
            )
        ext_enforce.check_grant(session, api_key.user_id)
        record_auth_success(raw_api_key)
        return AuthenticatedApiKey(
            id=api_key.id,
            scopes=api_key.scopes,
            user_id=api_key.user_id,
        )

    ext_enforce.auth_failed(
        session, "disabled" if _is_inactive_key(session, raw_api_key) else "invalid"
    )
    _record_auth_failure_or_raise_rate_limited(raw_api_key, client_identifier)
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key",
    )


def _is_inactive_key(session: Session, raw_api_key: str) -> bool:
    """A known key that is no longer active (looked up on a failure, extension only)."""

    if not ext_enabled():
        return False
    return (
        session.execute(
            select(ApiKey.id).where(
                ApiKey.status != "active", ApiKey.key_hash == hash_api_key(raw_api_key)
            )
        ).first()
        is not None
    )


def _record_auth_failure_or_raise_rate_limited(
    raw_api_key: str | None,
    client_identifier: str | None = None,
) -> None:
    """Record one failed authentication and raise 429 when the threshold is reached."""

    if check_auth_rate_limited(raw_api_key, client_identifier) or record_auth_failure(
        raw_api_key,
        client_identifier,
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=RATE_LIMIT_DETAIL,
        )


def _client_identifier_from_request(request: Request) -> str | None:
    if request.client is None:
        return None
    return request.client.host


def require_admin_api_key(
    api_key: Annotated[AuthenticatedApiKey, Depends(require_api_key)],
) -> AuthenticatedApiKey:
    """Require the authenticated API key to carry the admin scope."""

    return require_scope(api_key, "admin", "Admin scope required")


def require_runtime_api_key(
    session: Annotated[Session, Depends(get_session)],
    request: Request,
) -> AuthenticatedRuntimeKey:
    """Require one runtime-scoped API key and load its bound runtime identity."""

    raw_api_key = request.headers.get(get_settings().api_key_header)
    return authenticate_runtime_api_key_value(
        session,
        raw_api_key,
        client_identifier=_client_identifier_from_request(request),
    )


def require_scope(
    api_key: AuthenticatedApiKey,
    scope: str,
    detail: str,
) -> AuthenticatedApiKey:
    """Require one authenticated API key to include a specific scope."""

    if scope not in json.loads(api_key.scopes):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
        )

    return api_key


def authenticate_runtime_api_key_value(
    session: Session,
    raw_api_key: str | None,
    client_identifier: str | None = None,
) -> AuthenticatedRuntimeKey:
    """Authenticate one raw API key value and require the runtime scope."""

    authenticated = require_scope(
        authenticate_api_key_value(session, raw_api_key, client_identifier=client_identifier),
        "runtime",
        "Runtime scope required",
    )
    identity = load_runtime_identity_for_user(session, user_id=authenticated.user_id)
    return AuthenticatedRuntimeKey(
        id=authenticated.id,
        scopes=authenticated.scopes,
        user_id=identity.user_id,
        role_ids=list(identity.role_ids),
        org_node_id=identity.org_node_id,
    )
