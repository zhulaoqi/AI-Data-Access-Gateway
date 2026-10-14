"""Small entry points called from the few patched upstream functions."""

from typing import TYPE_CHECKING

from sqlalchemy.orm import Session

from adg_ext import context as ctxmod
from adg_ext.config import ext_enabled

if TYPE_CHECKING:  # the policy module imports this one
    from adg.policy.runtime import IdentityContext


def context_for(session: Session, identity: "IdentityContext") -> ctxmod.ExtContext:
    """The identity's synced configuration, cached for the lifetime of the request session."""

    cache: dict[tuple[str | None, tuple[str, ...]], ctxmod.ExtContext] = session.info.setdefault(
        "adg_ext_ctx", {}
    )
    key = (identity.user_id, tuple(identity.roles))
    if key not in cache:
        cache[key] = ctxmod.load(session, user_id=identity.user_id, role_ids=identity.roles)
    return cache[key]


def field_denied(
    session: Session, identity: "IdentityContext", resource_id: str, field_name: str
) -> bool | None:
    """True/False when a synced role decides the column's visibility; None = no opinion."""

    if not ext_enabled():
        return None
    allowed = context_for(session, identity).column_allowed(resource_id, field_name)
    return None if allowed is None else not allowed
