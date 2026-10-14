from functools import lru_cache

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


@lru_cache
def get_ext_settings() -> ExtSettings:
    """Return cached extension settings."""

    return ExtSettings()


def ext_enabled() -> bool:
    """Whether the extension patches are active."""

    return get_ext_settings().enabled
