import base64
import binascii
import hashlib
import os
from collections.abc import Iterable, Mapping
from typing import Any, Final

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from adg_ext import kdf_cache as ext_kdf

FERNET_ENVELOPE_KIND: Final[str] = "encrypted_secret"
FERNET_ENVELOPE_VERSION: Final[int] = 2
FERNET_KDF_NAME: Final[str] = "pbkdf2-hmac-sha256"
FERNET_KDF_MIN_ITERATIONS: Final[int] = 1_000
FERNET_KDF_MAX_ITERATIONS: Final[int] = 2_000_000
FERNET_SALT_BYTES: Final[int] = 16
FERNET_SALT_ENCODED_LENGTH: Final[int] = 24


def encrypt_fernet_envelope(
    plaintext: bytes,
    *,
    secret: str,
    iterations: int,
) -> dict[str, object]:
    """Encrypt bytes with a randomly salted PBKDF2-derived Fernet key."""

    salt = os.urandom(16)
    key = derive_pbkdf2_fernet_key(secret=secret, salt=salt, iterations=iterations)
    return {
        "kind": FERNET_ENVELOPE_KIND,
        "version": FERNET_ENVELOPE_VERSION,
        "kdf": FERNET_KDF_NAME,
        "salt": base64.urlsafe_b64encode(salt).decode(),
        "iterations": iterations,
        "ciphertext": Fernet(key).encrypt(plaintext).decode(),
    }


def decrypt_fernet_envelope(
    envelope: Mapping[str, object],
    *,
    secret: str,
    legacy_secrets: Iterable[str] = (),
) -> bytes:
    """Decrypt a v2 PBKDF2 envelope or the legacy sha256-derived envelope."""

    version = envelope.get("version")
    if version == FERNET_ENVELOPE_VERSION:
        return _decrypt_v2_envelope(envelope, secret=secret)
    if version is not None:
        raise InvalidToken()
    return decrypt_legacy_fernet_token(
        str(envelope.get("ciphertext", "")),
        secrets=(secret, *legacy_secrets),
    )


def decrypt_legacy_fernet_token(token: str, *, secrets: Iterable[str]) -> bytes:
    """Decrypt a legacy Fernet token derived with sha256(secret)."""

    last_error: InvalidToken | None = None
    for candidate in secrets:
        try:
            return Fernet(derive_legacy_fernet_key(candidate)).decrypt(token.encode())
        except InvalidToken as error:
            last_error = error
    raise last_error or InvalidToken()


def derive_pbkdf2_fernet_key(*, secret: str, salt: bytes, iterations: int) -> bytes:
    """Derive a Fernet-compatible key with PBKDF2-HMAC-SHA256."""

    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    ).derive(secret.encode())
    return base64.urlsafe_b64encode(key)


def derive_legacy_fernet_key(secret: str) -> bytes:
    """Derive the pre-v2 Fernet key from sha256(secret)."""

    return base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())


def _decrypt_v2_envelope(envelope: Mapping[str, object], *, secret: str) -> bytes:
    if envelope.get("kind") != FERNET_ENVELOPE_KIND:
        raise InvalidToken()
    if envelope.get("kdf") != FERNET_KDF_NAME:
        raise InvalidToken()
    ciphertext = envelope.get("ciphertext")
    salt_text = envelope.get("salt")
    iterations = envelope.get("iterations")
    if not isinstance(ciphertext, str):
        raise InvalidToken()
    if not isinstance(salt_text, str):
        raise InvalidToken()
    if (
        not isinstance(iterations, int)
        or isinstance(iterations, bool)
        or not FERNET_KDF_MIN_ITERATIONS <= iterations <= FERNET_KDF_MAX_ITERATIONS
    ):
        raise InvalidToken()
    if len(salt_text) != FERNET_SALT_ENCODED_LENGTH:
        raise InvalidToken()
    try:
        salt = base64.b64decode(
            salt_text.encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (UnicodeEncodeError, ValueError, binascii.Error) as error:
        raise InvalidToken() from error
    if len(salt) != FERNET_SALT_BYTES:
        raise InvalidToken()
    # adg_ext: memoised PBKDF2 output (bounded, expiring, never lowers the iteration count; the
    # Fernet token is still fully verified below). Plain derivation when the extension is off.
    key = ext_kdf.derive_key(
        secret=secret,
        salt=salt,
        iterations=iterations,
        compute=derive_pbkdf2_fernet_key,
    )
    return Fernet(key).decrypt(ciphertext.encode())


def envelope_to_json(envelope: Mapping[str, object]) -> str:
    """Serialize an envelope for text-only database columns."""

    import json

    return json.dumps(dict(envelope), separators=(",", ":"))


def envelope_from_json(value: str) -> dict[str, Any] | None:
    """Parse a serialized envelope, returning None when the value is not JSON object."""

    import json

    try:
        loaded = json.loads(value)
    except json.JSONDecodeError:
        return None
    if not isinstance(loaded, dict):
        return None
    return {str(key): item for key, item in loaded.items()}
