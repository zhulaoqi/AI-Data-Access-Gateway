import json
from datetime import datetime

from sqlalchemy.orm import Session

from adg.control_plane.models.api_key import ApiKey
from adg.shared.security import generate_api_key, hash_api_key


def create_api_key(
    session: Session,
    *,
    name: str,
    scopes: list[str],
    expires_at: datetime | None = None,
    plaintext: str | None = None,
    user_id: str | None = None,
    key_hash: str | None = None,
) -> tuple[ApiKey, str]:
    """Create an API key record and return the raw key exactly once to the caller.

    With ``key_hash`` the caller supplies the SHA-256 of a key it generated itself (the SQL
    gateway management service); no plaintext is known here and an empty string is returned.
    """

    if key_hash is not None:
        if plaintext is not None:
            raise ValueError("plaintext and key_hash are mutually exclusive")
        if len(key_hash) != 64 or any(c not in "0123456789abcdef" for c in key_hash):
            raise ValueError("key_hash must be a lowercase SHA-256 hex digest")
        raw_key = ""
    else:
        raw_key = plaintext or generate_api_key()
    api_key = ApiKey(
        name=name,
        key_hash=key_hash if key_hash is not None else hash_api_key(raw_key),
        user_id=user_id,
        status="active",
        scopes=json.dumps(scopes, separators=(",", ":")),
        expires_at=expires_at,
    )
    session.add(api_key)
    session.flush()
    return api_key, raw_key
