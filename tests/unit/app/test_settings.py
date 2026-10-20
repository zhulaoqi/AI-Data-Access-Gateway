import pytest
from pytest import MonkeyPatch

from adg.app.settings import Settings


def test_settings_defaults_are_local_friendly() -> None:
    settings = Settings()

    assert settings.env == "local"
    assert settings.service_name == "AI Data Access Gateway"
    assert settings.api_key_header == "X-ADG-API-Key"
    assert settings.mcp_query_api_key_enabled is False
    assert settings.control_plane_database_url.startswith("sqlite:///")
    assert settings.backend_host_port is None
    assert settings.admin_page_default_limit == 50
    assert settings.admin_page_max_limit == 500
    assert settings.admin_resource_tree_max_nodes == 10_000
    assert settings.sql_execution_mode == "read_only"
    assert settings.sql_strict_validation is True
    assert settings.sql_reject_wildcard is True
    assert settings.runtime_datasource_pool_cache_size == 32
    assert settings.runtime_datasource_pool_idle_ttl_seconds == 300
    assert settings.runtime_datasource_pool_size == 5
    assert settings.runtime_datasource_pool_max_overflow == 0
    assert settings.runtime_datasource_connect_timeout_seconds == 10
    assert settings.runtime_datasource_read_timeout_seconds == 120
    assert settings.runtime_datasource_write_timeout_seconds == 120
    assert settings.runtime_query_max_limit == 1000
    assert settings.runtime_decrypt_max_values == 100
    assert settings.masking_encryption_key == "change-me-to-a-long-random-masking-key"
    assert settings.secret_kdf_iterations == 390_000
    assert settings.metadata_scan_max_databases == 25
    assert settings.datasource_network_allowlist == ""
    assert settings.auth_rate_limit_enabled is True
    assert settings.auth_rate_limit_storage == "memory"
    assert settings.auth_rate_limit_redis_url is None
    assert settings.auth_rate_limit_window_seconds == 60
    assert settings.auth_rate_limit_max_failures == 10
    assert settings.auth_rate_limit_block_seconds == 300
    assert settings.auth_rate_limit_memory_max_buckets == 10_000


def test_settings_read_adg_prefixed_environment(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("ADG_ENV", "test")
    monkeypatch.setenv("ADG_CONTROL_PLANE_DATABASE_URL", "sqlite:///./test.db")
    monkeypatch.setenv("ADG_MCP_QUERY_API_KEY_ENABLED", "true")
    monkeypatch.setenv("ADG_SECRET_KEY", "unit-test-secret")
    monkeypatch.setenv("ADG_CREDENTIAL_ENCRYPTION_KEY", "unit-test-credential-key")
    monkeypatch.setenv("ADG_MASKING_ENCRYPTION_KEY", "unit-test-masking-key")
    monkeypatch.setenv("ADG_SECRET_KDF_ITERATIONS", "1200")
    monkeypatch.setenv("ADG_METADATA_SCAN_MAX_DATABASES", "5")
    monkeypatch.setenv("ADG_DATASOURCE_NETWORK_ALLOWLIST", "127.0.0.1,metadata.internal")
    monkeypatch.setenv("ADG_BACKEND_HOST_PORT", "8001")
    monkeypatch.setenv("ADG_ADMIN_PAGE_DEFAULT_LIMIT", "25")
    monkeypatch.setenv("ADG_ADMIN_PAGE_MAX_LIMIT", "250")
    monkeypatch.setenv("ADG_ADMIN_RESOURCE_TREE_MAX_NODES", "2000")
    monkeypatch.setenv("ADG_SQL_EXECUTION_MODE", "dml")
    monkeypatch.setenv("ADG_SQL_STRICT_VALIDATION", "false")
    monkeypatch.setenv("ADG_SQL_REJECT_WILDCARD", "false")
    monkeypatch.setenv("ADG_RUNTIME_DATASOURCE_POOL_CACHE_SIZE", "8")
    monkeypatch.setenv("ADG_RUNTIME_DATASOURCE_POOL_IDLE_TTL_SECONDS", "60")
    monkeypatch.setenv("ADG_RUNTIME_DATASOURCE_POOL_SIZE", "3")
    monkeypatch.setenv("ADG_RUNTIME_DATASOURCE_POOL_MAX_OVERFLOW", "2")
    monkeypatch.setenv("ADG_RUNTIME_DATASOURCE_CONNECT_TIMEOUT_SECONDS", "7")
    monkeypatch.setenv("ADG_RUNTIME_DATASOURCE_READ_TIMEOUT_SECONDS", "45")
    monkeypatch.setenv("ADG_RUNTIME_DATASOURCE_WRITE_TIMEOUT_SECONDS", "46")
    monkeypatch.setenv("ADG_RUNTIME_QUERY_MAX_LIMIT", "250")
    monkeypatch.setenv("ADG_RUNTIME_DECRYPT_MAX_VALUES", "25")
    monkeypatch.setenv("ADG_AUTH_RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("ADG_AUTH_RATE_LIMIT_STORAGE", "redis")
    monkeypatch.setenv("ADG_AUTH_RATE_LIMIT_REDIS_URL", "redis://localhost:6379/2")
    monkeypatch.setenv("ADG_AUTH_RATE_LIMIT_WINDOW_SECONDS", "30")
    monkeypatch.setenv("ADG_AUTH_RATE_LIMIT_MAX_FAILURES", "4")
    monkeypatch.setenv("ADG_AUTH_RATE_LIMIT_BLOCK_SECONDS", "120")
    monkeypatch.setenv("ADG_AUTH_RATE_LIMIT_MEMORY_MAX_BUCKETS", "2000")
    settings = Settings()

    assert settings.env == "test"
    assert settings.control_plane_database_url == "sqlite:///./test.db"
    assert settings.mcp_query_api_key_enabled is True
    assert settings.secret_key == "unit-test-secret"
    assert settings.credential_encryption_key == "unit-test-credential-key"
    assert settings.masking_encryption_key == "unit-test-masking-key"
    assert settings.secret_kdf_iterations == 1200
    assert settings.metadata_scan_max_databases == 5
    assert settings.datasource_network_allowlist == "127.0.0.1,metadata.internal"
    assert settings.backend_host_port == 8001
    assert settings.admin_page_default_limit == 25
    assert settings.admin_page_max_limit == 250
    assert settings.admin_resource_tree_max_nodes == 2000
    assert settings.sql_execution_mode == "dml"
    assert settings.sql_strict_validation is False
    assert settings.sql_reject_wildcard is False
    assert settings.runtime_datasource_pool_cache_size == 8
    assert settings.runtime_datasource_pool_idle_ttl_seconds == 60
    assert settings.runtime_datasource_pool_size == 3
    assert settings.runtime_datasource_pool_max_overflow == 2
    assert settings.runtime_datasource_connect_timeout_seconds == 7
    assert settings.runtime_datasource_read_timeout_seconds == 45
    assert settings.runtime_datasource_write_timeout_seconds == 46
    assert settings.runtime_query_max_limit == 250
    assert settings.runtime_decrypt_max_values == 25
    assert settings.auth_rate_limit_enabled is False
    assert settings.auth_rate_limit_storage == "redis"
    assert settings.auth_rate_limit_redis_url == "redis://localhost:6379/2"
    assert settings.auth_rate_limit_window_seconds == 30
    assert settings.auth_rate_limit_max_failures == 4
    assert settings.auth_rate_limit_block_seconds == 120
    assert settings.auth_rate_limit_memory_max_buckets == 2000


def test_settings_reject_default_secret_key_in_production(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("ADG_ENV", "production")
    monkeypatch.delenv("ADG_SECRET_KEY", raising=False)

    with pytest.raises(ValueError, match="ADG_SECRET_KEY"):
        Settings()


def test_settings_require_credential_encryption_key_in_production(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setenv("ADG_ENV", "production")
    monkeypatch.setenv("ADG_SECRET_KEY", "production-secret-key")
    monkeypatch.delenv("ADG_CREDENTIAL_ENCRYPTION_KEY", raising=False)

    with pytest.raises(ValueError, match="ADG_CREDENTIAL_ENCRYPTION_KEY"):
        Settings()


def test_settings_require_masking_encryption_key_in_production(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setenv("ADG_ENV", "production")
    monkeypatch.setenv("ADG_SECRET_KEY", "production-secret-key")
    monkeypatch.setenv("ADG_CREDENTIAL_ENCRYPTION_KEY", "production-credential-key")
    monkeypatch.delenv("ADG_MASKING_ENCRYPTION_KEY", raising=False)

    with pytest.raises(ValueError, match="ADG_MASKING_ENCRYPTION_KEY"):
        Settings()


def test_settings_reject_reused_production_keys(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("ADG_ENV", "production")
    monkeypatch.setenv("ADG_SECRET_KEY", "shared-production-secret")
    monkeypatch.setenv("ADG_CREDENTIAL_ENCRYPTION_KEY", "shared-production-secret")
    monkeypatch.setenv("ADG_MASKING_ENCRYPTION_KEY", "distinct-production-masking-key")

    with pytest.raises(ValueError, match="must be different"):
        Settings()


def test_settings_allow_missing_redis_url_when_auth_rate_limit_disabled(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setenv("ADG_AUTH_RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("ADG_AUTH_RATE_LIMIT_STORAGE", "redis")
    monkeypatch.delenv("ADG_AUTH_RATE_LIMIT_REDIS_URL", raising=False)

    settings = Settings()

    assert settings.auth_rate_limit_enabled is False
    assert settings.auth_rate_limit_storage == "redis"
    assert settings.auth_rate_limit_redis_url is None
def test_settings_reject_invalid_runtime_pool_values(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("ADG_RUNTIME_DATASOURCE_POOL_CACHE_SIZE", "-1")
    with pytest.raises(ValueError, match="runtime_datasource_pool_cache_size"):
        Settings()

    monkeypatch.delenv("ADG_RUNTIME_DATASOURCE_POOL_CACHE_SIZE")
    monkeypatch.setenv("ADG_RUNTIME_DATASOURCE_POOL_IDLE_TTL_SECONDS", "0")
    with pytest.raises(ValueError, match="runtime_datasource_pool_idle_ttl_seconds"):
        Settings()

    monkeypatch.delenv("ADG_RUNTIME_DATASOURCE_POOL_IDLE_TTL_SECONDS")
    monkeypatch.setenv("ADG_RUNTIME_DATASOURCE_CONNECT_TIMEOUT_SECONDS", "0")
    with pytest.raises(ValueError, match="runtime_datasource_connect_timeout_seconds"):
        Settings()

    monkeypatch.delenv("ADG_RUNTIME_DATASOURCE_CONNECT_TIMEOUT_SECONDS")
    monkeypatch.setenv("ADG_RUNTIME_QUERY_MAX_LIMIT", "0")
    with pytest.raises(ValueError, match="runtime_query_max_limit"):
        Settings()

    monkeypatch.delenv("ADG_RUNTIME_QUERY_MAX_LIMIT")
    monkeypatch.setenv("ADG_RUNTIME_DECRYPT_MAX_VALUES", "0")
    with pytest.raises(ValueError, match="runtime_decrypt_max_values"):
        Settings()

    monkeypatch.delenv("ADG_RUNTIME_DECRYPT_MAX_VALUES")
    monkeypatch.setenv("ADG_SECRET_KDF_ITERATIONS", "999")
    with pytest.raises(ValueError, match="secret_kdf_iterations"):
        Settings()

    monkeypatch.setenv("ADG_SECRET_KDF_ITERATIONS", "2000001")
    with pytest.raises(ValueError, match="secret_kdf_iterations"):
        Settings()

    monkeypatch.delenv("ADG_SECRET_KDF_ITERATIONS")
    monkeypatch.setenv("ADG_METADATA_SCAN_MAX_DATABASES", "0")
    with pytest.raises(ValueError, match="metadata_scan_max_databases"):
        Settings()

    monkeypatch.delenv("ADG_METADATA_SCAN_MAX_DATABASES")
    monkeypatch.setenv("ADG_AUTH_RATE_LIMIT_STORAGE", "sqlite")
    with pytest.raises(ValueError, match="auth_rate_limit_storage"):
        Settings()

    monkeypatch.delenv("ADG_AUTH_RATE_LIMIT_STORAGE")
    monkeypatch.setenv("ADG_AUTH_RATE_LIMIT_WINDOW_SECONDS", "0")
    with pytest.raises(ValueError, match="auth_rate_limit_window_seconds"):
        Settings()

    monkeypatch.delenv("ADG_AUTH_RATE_LIMIT_WINDOW_SECONDS")
    monkeypatch.setenv("ADG_AUTH_RATE_LIMIT_MAX_FAILURES", "0")
    with pytest.raises(ValueError, match="auth_rate_limit_max_failures"):
        Settings()

    monkeypatch.delenv("ADG_AUTH_RATE_LIMIT_MAX_FAILURES")
    monkeypatch.setenv("ADG_AUTH_RATE_LIMIT_BLOCK_SECONDS", "0")
    with pytest.raises(ValueError, match="auth_rate_limit_block_seconds"):
        Settings()

    monkeypatch.delenv("ADG_AUTH_RATE_LIMIT_BLOCK_SECONDS")
    monkeypatch.setenv("ADG_AUTH_RATE_LIMIT_MEMORY_MAX_BUCKETS", "1")
    with pytest.raises(ValueError, match="auth_rate_limit_memory_max_buckets"):
        Settings()

    monkeypatch.delenv("ADG_AUTH_RATE_LIMIT_MEMORY_MAX_BUCKETS")
    monkeypatch.setenv("ADG_AUTH_RATE_LIMIT_STORAGE", "redis")
    monkeypatch.delenv("ADG_AUTH_RATE_LIMIT_REDIS_URL", raising=False)
    with pytest.raises(ValueError, match="ADG_AUTH_RATE_LIMIT_REDIS_URL"):
        Settings()
