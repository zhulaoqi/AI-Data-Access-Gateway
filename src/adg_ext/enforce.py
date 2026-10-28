"""Enforcement of the source blocklist and the auth-failure counters (PA-8).

Called from the patched authentication function (``adg.app.dependencies``), before any credential
is looked at: a blocked source gets the fixed answer ``403 source_blocked`` and a frozen grant gets
``403 grant_frozen`` after its key authenticated. Both are counted for ``/ext/audit/aggregates``,
exported as metrics and written as a sampled audit row (at most one per source and minute per
process, so an attack cannot become a database load). Nothing here ever logs or stores a key.
"""

import logging
import threading
import time
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from adg.app.log_config import kv
from adg_ext import blocklist, clientip
from adg_ext.config import ext_enabled
from adg_ext.riskstats import get_counters
from adg_ext.sync import PREFIX

logger = logging.getLogger(__name__)

_SAMPLE_SECONDS = 60.0
_MAX_SAMPLED = 4096
_sampled: dict[tuple[str, str], float] = {}
_sampled_lock = threading.Lock()


def _should_sample(ip: str, reason: str) -> bool:
    now = time.monotonic()
    with _sampled_lock:
        last = _sampled.get((ip, reason))
        if last is not None and now - last < _SAMPLE_SECONDS:
            return False
        if len(_sampled) >= _MAX_SAMPLED:
            for key in [k for k, v in _sampled.items() if now - v >= _SAMPLE_SECONDS]:
                del _sampled[key]
            if len(_sampled) >= _MAX_SAMPLED:
                return False
        _sampled[(ip, reason)] = now
        return True


def reset_sampling() -> None:
    with _sampled_lock:
        _sampled.clear()


def _audit_sample(
    session: Session | None, ip: str | None, grant_id: str | None, reason: str
) -> None:
    if session is None or not _should_sample(ip or "unknown", reason):
        return
    try:
        from adg.audit.service import AuditService

        AuditService(session).record_event(
            user_id=None,
            api_key_id=None,
            event_type="source_blocked",
            decision="denied",
            datasource_id=None,
            resource_ids=[],
            query_id=None,
            sql_text=None,
            reason=reason,
            metadata={"client_ip": ip or "", "grant_id": grant_id or "", "channel": "gateway"},
        )
        session.commit()
    except Exception:
        session.rollback()
        logger.warning("blocked-attempt audit row not written", exc_info=False)


def _reject(reason: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=reason)


def check_source(session: Session | None = None) -> None:
    """Refuse a blocked source before authentication. A source that cannot be resolved passes."""

    if not ext_enabled():
        return
    cache = blocklist.get_cache()
    if not cache.enabled:
        return
    ip = clientip.current()
    if cache.decide(ip) != blocklist.DENY:
        return
    cache.blocked_total += 1
    get_counters().blocked(ip, None, blocklist.SOURCE_BLOCKED)
    _audit_sample(session, ip, None, blocklist.SOURCE_BLOCKED)
    if _should_sample(ip or "unknown", "log:" + blocklist.SOURCE_BLOCKED):
        logger.warning(kv(event="source_blocked", client=ip, sampled="1/min"))
    raise _reject(blocklist.SOURCE_BLOCKED)


def grant_of_user(session: Session, user_id: str | None) -> str | None:
    """The grant id behind an executor user (``external_ref = gw:user:<grantId>``)."""

    if not user_id:
        return None
    from adg.control_plane.models.directory import User

    ref = session.execute(select(User.external_ref).where(User.id == user_id)).scalar_one_or_none()
    if ref and ref.startswith(f"{PREFIX}user:"):
        return ref[len(f"{PREFIX}user:") :]
    return None


def check_grant(session: Session, user_id: str | None) -> None:
    """Refuse an authenticated key whose grant is frozen."""

    if not ext_enabled():
        return
    cache = blocklist.get_cache()
    if not cache.enabled or not cache.has_frozen():
        return
    grant_id = grant_of_user(session, user_id)
    if grant_id is None or not cache.grant_frozen(grant_id):
        return
    refuse_frozen(session, grant_id)


def refuse_frozen(session: Session | None, grant_id: str) -> None:
    """Count and raise for a frozen grant (used by the delegated path as well)."""

    cache = blocklist.get_cache()
    cache.frozen_total += 1
    ip = clientip.current()
    get_counters().blocked(ip, grant_id, blocklist.GRANT_FROZEN)
    _audit_sample(session, ip, grant_id, blocklist.GRANT_FROZEN)
    if _should_sample(ip or "unknown", "log:" + blocklist.GRANT_FROZEN):
        logger.warning(kv(event="grant_frozen", client=ip, grant=grant_id, sampled="1/min"))
    raise _reject(blocklist.GRANT_FROZEN)


def delegated_check(
    session: Session, grant_id: str, client_ip: str | None
) -> dict[str, Any] | None:
    """For the entry (JDBC) path: the source address and grant come from the request body.

    Returns ``{"reason": ...}`` to refuse, ``None`` to continue.
    """

    if not ext_enabled():
        return None
    cache = blocklist.get_cache()
    if not cache.enabled:
        return None
    ip = clientip.normalize(client_ip)
    if cache.decide(ip) == blocklist.DENY:
        cache.blocked_total += 1
        get_counters().blocked(ip, grant_id, blocklist.SOURCE_BLOCKED)
        _audit_sample(session, ip, grant_id, blocklist.SOURCE_BLOCKED)
        return {"reason": blocklist.SOURCE_BLOCKED}
    if cache.grant_frozen(grant_id):
        cache.frozen_total += 1
        get_counters().blocked(ip, grant_id, blocklist.GRANT_FROZEN)
        _audit_sample(session, ip, grant_id, blocklist.GRANT_FROZEN)
        return {"reason": blocklist.GRANT_FROZEN}
    return None


def auth_failed(session: Session | None, reason: str, user_id: str | None = None) -> None:
    """Count one authentication failure by source address and reason (never the key)."""

    if not ext_enabled():
        return
    grant_id = None
    if session is not None and user_id:
        try:
            grant_id = grant_of_user(session, user_id)
        except Exception:
            grant_id = None
    ip = clientip.current()
    get_counters().auth_failed(ip, grant_id, reason)
    logger.warning(kv(event="auth_failed", reason=reason, client=ip, grant=grant_id))
