from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ExtSettings(BaseSettings):
    """Environment-driven settings of the extension patches (prefix ``ADG_EXT_``)."""

    model_config = SettingsConfigDict(
        env_prefix="ADG_EXT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Master switch: when off, no extension router, hook or table is active.
    enabled: bool = False

    # Revocation list (PA-6): where the management service publishes revoked credentials.
    revocation_url: str = ""
    revocation_token: str = ""
    revocation_ttl_seconds: float = 5.0
    revocation_timeout_seconds: float = 2.0

    # Optional source restriction for the /admin and /admin/ext surfaces (CIDRs, comma separated).
    admin_allowed_cidrs: str = ""
    # Sources allowed to use the `entry` scope (the JDBC entry service). Empty = no restriction.
    entry_allowed_cidrs: str = ""

    # Admission control (PA-4) defaults; per-grant limits from the role spec override them.
    datasource_max_concurrency: int = 20
    breaker_failure_threshold: int = 5
    breaker_open_seconds: float = 30.0

    # Audit (PA-5): refuse to run a query when its audit record cannot be written.
    audit_fail_closed: bool = True

    # PBKDF2 output cache for datasource secret envelopes (PER-1); see ``adg_ext.kdf_cache``.
    # Size 0 (or TTL 0) disables it. Per process; never persisted or logged.
    kdf_cache_size: int = Field(default=64, ge=0, le=4096)
    kdf_cache_ttl_seconds: float = Field(default=300.0, ge=0.0, le=3600.0)

    # Executor control-plane DB pool (SQLAlchemy). The upstream default is 5 + 10 with a 30 s wait;
    # a request that cannot get a connection within ``..._pool_timeout_seconds`` is answered with
    # HTTP 503 ``admission_pool_exhausted`` (+ ``Retry-After``), not a 30 s hang and a 500.
    control_plane_pool_size: int = Field(default=10, ge=1, le=200)
    control_plane_pool_max_overflow: int = Field(default=30, ge=0, le=400)
    control_plane_pool_timeout_seconds: float = Field(default=5.0, gt=0.0, le=60.0)
    pool_exhausted_retry_after_seconds: int = Field(default=1, ge=1, le=60)

    # API docs pages (``/docs``, ``/redoc``, ``/openapi.json``) of the executor. They need no
    # authentication, so they are off unless explicitly enabled (N05); only effective when the
    # extension itself is enabled.
    enable_docs: bool = False


@lru_cache
def get_ext_settings() -> ExtSettings:
    """Return cached extension settings."""

    return ExtSettings()


def ext_enabled() -> bool:
    """Whether the extension patches are active."""

    return get_ext_settings().enabled
