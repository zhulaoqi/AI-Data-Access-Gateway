from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from adg.app.apollo import load_apollo
from adg.shared.crypto import FERNET_KDF_MAX_ITERATIONS, FERNET_KDF_MIN_ITERATIONS

DEFAULT_SECRET_KEY = "change-me-to-a-long-random-secret"
DEFAULT_CREDENTIAL_ENCRYPTION_KEY = "change-me-to-a-long-random-credential-key"
DEFAULT_MASKING_ENCRYPTION_KEY = "change-me-to-a-long-random-masking-key"


class Settings(BaseSettings):
    """Environment-driven application configuration."""

    model_config = SettingsConfigDict(
        env_prefix="ADG_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: Literal["local", "test", "production"] = "local"
    service_name: str = "AI Data Access Gateway"
    control_plane_database_url: str = "sqlite:///./data/adg-control-plane.db"
    api_key_header: str = "X-ADG-API-Key"
    mcp_query_api_key_enabled: bool = False
    secret_key: str = Field(default=DEFAULT_SECRET_KEY, min_length=16)
    credential_encryption_key: str = Field(
        default=DEFAULT_CREDENTIAL_ENCRYPTION_KEY,
        min_length=16,
    )
    masking_encryption_key: str = Field(
        default=DEFAULT_MASKING_ENCRYPTION_KEY,
        min_length=16,
    )
    secret_kdf_iterations: int = Field(
        default=390_000,
        ge=FERNET_KDF_MIN_ITERATIONS,
        le=FERNET_KDF_MAX_ITERATIONS,
    )
    metadata_scan_max_databases: int = Field(default=25, ge=1)
    datasource_network_allowlist: str = ""
    log_level: str = "INFO"
    # 非空时日志同时写入该文件（按 200MB 滚动，保留 10 个）；容器里由 docker/start.sh 设置。
    log_file: str = ""
    backend_host_port: int | None = Field(default=None, ge=1, le=65535)
    admin_page_default_limit: int = Field(default=50, ge=1)
    admin_page_max_limit: int = Field(default=500, ge=1)
    admin_resource_tree_max_nodes: int = Field(default=10_000, ge=1)
    sql_execution_mode: Literal["read_only", "dml", "schema", "admin"] = "read_only"
    sql_strict_validation: bool = True
    # False：把 SELECT * / t.* 展开成该表已允许的列。True：直接拒绝。
    # 代码默认拒绝；部署启动脚本目前设为 false，以后要收紧时改回 true。
    sql_reject_wildcard: bool = True
    runtime_datasource_pool_cache_size: int = Field(default=32, ge=1)
    runtime_datasource_pool_idle_ttl_seconds: int = Field(default=300, gt=0)
    runtime_datasource_pool_size: int = Field(default=5, ge=1)
    runtime_datasource_pool_max_overflow: int = Field(default=0, ge=0)
    # 单执行器进程所有运行时数据源池合计的物理连接硬上限。
    runtime_datasource_pool_global_max_connections: int = Field(default=1024, ge=1)
    runtime_datasource_connect_timeout_seconds: int = Field(default=10, gt=0)
    runtime_datasource_read_timeout_seconds: int = Field(default=120, gt=0)
    runtime_datasource_write_timeout_seconds: int = Field(default=120, gt=0)
    runtime_query_max_limit: int = Field(default=1000, ge=1)
    runtime_decrypt_max_values: int = Field(default=100, ge=1)
    auth_rate_limit_enabled: bool = True
    auth_rate_limit_storage: Literal["memory", "redis"] = "memory"
    auth_rate_limit_redis_url: str | None = None
    auth_rate_limit_window_seconds: int = Field(default=60, gt=0)
    auth_rate_limit_max_failures: int = Field(default=10, gt=0)
    auth_rate_limit_block_seconds: int = Field(default=300, gt=0)
    auth_rate_limit_memory_max_buckets: int = Field(default=10_000, ge=2)

    @model_validator(mode="after")
    def validate_production_secrets(self) -> "Settings":
        """Reject placeholder secrets when the service is configured for production use."""

        if self.env == "production" and self.secret_key == DEFAULT_SECRET_KEY:
            raise ValueError("ADG_SECRET_KEY must be set to a unique random value in production.")
        if (
            self.env == "production"
            and self.credential_encryption_key == DEFAULT_CREDENTIAL_ENCRYPTION_KEY
        ):
            raise ValueError(
                "ADG_CREDENTIAL_ENCRYPTION_KEY must be set to a unique random value in production."
            )
        if (
            self.env == "production"
            and self.masking_encryption_key == DEFAULT_MASKING_ENCRYPTION_KEY
        ):
            raise ValueError(
                "ADG_MASKING_ENCRYPTION_KEY must be set to a unique random value in production."
            )
        production_keys = {
            self.secret_key,
            self.credential_encryption_key,
            self.masking_encryption_key,
        }
        if self.env == "production" and len(production_keys) != 3:
            raise ValueError(
                "ADG_SECRET_KEY, ADG_CREDENTIAL_ENCRYPTION_KEY, and "
                "ADG_MASKING_ENCRYPTION_KEY must be different in production."
            )
        if (
            self.auth_rate_limit_enabled
            and self.auth_rate_limit_storage == "redis"
            and not self.auth_rate_limit_redis_url
        ):
            raise ValueError(
                "ADG_AUTH_RATE_LIMIT_REDIS_URL is required when Redis rate limiting is enabled."
            )
        return self


@lru_cache
def get_settings() -> Settings:
    """Return cached settings so dependencies do not rebuild them per request."""

    load_apollo()
    return Settings()
