"""Real-engine fixtures for the extension: MySQL 8.4 and ClickHouse from ``docker-compose.ext.yml``.

The whole directory is skipped when the engines are neither running nor startable with docker.
"""

import json
import shutil
import socket
import subprocess
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pymysql
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from adg.app.main import create_app
from adg.app.settings import get_settings
from adg.connectors.registry import get_connector_registry
from adg.control_plane.db import create_engine_from_url, create_session_factory
from adg.control_plane.models import Base
from adg.control_plane.services.api_key_service import create_api_key
from adg.shared.security import hash_api_key
from adg_ext import pipeline, revocation
from adg_ext.config import get_ext_settings

ROOT = Path(__file__).resolve().parents[2]
MYSQL = ("127.0.0.1", 33306)
CLICKHOUSE = ("127.0.0.1", 38123)


def _up(addr: tuple[str, int]) -> bool:
    try:
        with socket.create_connection(addr, timeout=1):
            return True
    except OSError:
        return False


@pytest.fixture(scope="session")
def engines() -> None:
    if not (_up(MYSQL) and _up(CLICKHOUSE)):
        if shutil.which("docker") is None:
            pytest.skip("docker is not available")
        subprocess.run(
            ["docker", "compose", "-f", str(ROOT / "docker-compose.ext.yml"), "up", "-d", "--wait"],
            check=False,
            capture_output=True,
        )
    if not (_up(MYSQL) and _up(CLICKHOUSE)):
        pytest.skip("MySQL/ClickHouse test engines are not running")


def mysql_conn(database: str | None = None, user: str = "root", password: str = "rootpw") -> Any:
    for _ in range(30):
        try:
            return pymysql.connect(
                host=MYSQL[0],
                port=MYSQL[1],
                user=user,
                password=password,
                database=database,
                autocommit=True,
            )
        except pymysql.err.OperationalError:
            time.sleep(1)
    raise RuntimeError("mysql not reachable")


@pytest.fixture(scope="session")
def mysql_seed(engines: None) -> dict[str, str]:
    conn = mysql_conn()
    with conn.cursor() as c:
        c.execute("DROP DATABASE IF EXISTS shop")
        c.execute("CREATE DATABASE shop")
        c.execute(
            "CREATE TABLE shop.orders (id BIGINT PRIMARY KEY, tenant_id BIGINT, phone VARCHAR(20),"
            " amount DECIMAL(10,2), ssn VARCHAR(20), created_at DATETIME)"
        )
        c.execute("CREATE TABLE shop.dim (id BIGINT PRIMARY KEY, name VARCHAR(20))")
        rows = [
            (1, 7, "13800000001", "10.50", "111", "2026-10-01 10:00:00"),
            (2, 7, "13800000002", "20.00", "222", "2026-10-02 10:00:00"),
            (3, 8, "13900000003", "30.00", "333", "2026-10-03 10:00:00"),
            (4, 9, "13900000004", "40.00", "444", "2026-10-04 10:00:00"),
        ]
        c.executemany("INSERT INTO shop.orders VALUES (%s,%s,%s,%s,%s,%s)", rows)
        c.execute("INSERT INTO shop.dim VALUES (1,'a')")
        c.execute("SET SESSION cte_max_recursion_depth = 5000")
        c.execute("CREATE TABLE shop.big (id BIGINT PRIMARY KEY)")
        c.execute(
            "INSERT INTO shop.big SELECT n FROM (WITH RECURSIVE s(n) AS "
            "(SELECT 1 UNION ALL SELECT n+1 FROM s WHERE n < 3000) SELECT n FROM s) t"
        )
        c.execute("DROP USER IF EXISTS 'gw_ro'@'%'")
        c.execute("CREATE USER 'gw_ro'@'%' IDENTIFIED BY 'ropw'")
        c.execute("GRANT SELECT ON shop.* TO 'gw_ro'@'%'")
    conn.close()
    return {"user": "gw_ro", "password": "ropw"}


class Gateway:
    """An ADG app with the extension enabled, plus helpers to sync objects and call tools."""

    def __init__(self, client: TestClient, factory: sessionmaker[Session], admin: str) -> None:
        self.client = client
        self.factory = factory
        self.admin = admin
        self.keys: dict[str, str] = {}

    def sync(self, kind: str, name: str, spec: dict[str, Any], hash_: str | None = None) -> Any:
        digest = hash_ or hash_api_key(json.dumps(spec, sort_keys=True))
        return self.client.put(
            f"/admin/ext/sync/{kind}/{name}",
            json={"hash": digest, "spec": spec},
            headers={"X-ADG-API-Key": self.admin},
        )

    def delete(self, kind: str, name: str) -> Any:
        return self.client.delete(
            f"/admin/ext/sync/{kind}/{name}", headers={"X-ADG-API-Key": self.admin}
        )

    def admin_get(self, path: str) -> Any:
        return self.client.get(path, headers={"X-ADG-API-Key": self.admin})

    def tool(self, key: str, name: str, **payload: Any) -> Any:
        return self.client.post(f"/api/tools/{name}", json=payload, headers={"X-ADG-API-Key": key})


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, engines: None) -> Iterator[Gateway]:
    monkeypatch.setenv("ADG_EXT_ENABLED", "true")
    monkeypatch.setenv("ADG_DATASOURCE_NETWORK_ALLOWLIST", "127.0.0.1")
    monkeypatch.setenv("ADG_RUNTIME_QUERY_MAX_LIMIT", "1000")
    get_settings.cache_clear()
    get_ext_settings.cache_clear()
    pipeline.reset_admission()
    revocation.reset_cache()
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'cp.db'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    admin = "adg_admin_test_key"
    with factory() as session:
        create_api_key(session, name="admin", scopes=["admin"], plaintext=admin)
        session.commit()
    registry = get_connector_registry()
    saved = dict(registry._connectors)
    client = TestClient(create_app(session_factory=factory))
    yield Gateway(client, factory, admin)
    registry._connectors.clear()
    registry._connectors.update(saved)
    get_settings.cache_clear()
    get_ext_settings.cache_clear()
    pipeline.reset_admission()
    revocation.reset_cache()


ProvisionFn = Callable[..., str]


@pytest.fixture(scope="session")
def clickhouse_seed(engines: None) -> dict[str, str]:
    import clickhouse_connect

    client = None
    for _ in range(30):
        try:
            client = clickhouse_connect.get_client(
                host=CLICKHOUSE[0], port=CLICKHOUSE[1], username="root", password="rootpw"
            )
            break
        except Exception:
            time.sleep(1)
    assert client is not None
    client.command("DROP DATABASE IF EXISTS shop")
    client.command("CREATE DATABASE shop")
    client.command(
        "CREATE TABLE shop.orders (id Int64, tenant_id Int64, phone String, amount Decimal(10,2),"
        " ssn String, created_at DateTime) ENGINE = MergeTree ORDER BY id"
    )
    client.command(
        "INSERT INTO shop.orders VALUES (1,7,'13800000001',10.50,'111','2026-10-01 10:00:00'),"
        "(2,7,'13800000002',20.00,'222','2026-10-02 10:00:00'),"
        "(3,8,'13900000003',30.00,'333','2026-10-03 10:00:00'),"
        "(4,9,'13900000004',40.00,'444','2026-10-04 10:00:00')"
    )
    client.command("CREATE TABLE shop.big (id Int64) ENGINE = MergeTree ORDER BY id")
    client.command("INSERT INTO shop.big SELECT number FROM numbers(3000)")
    client.command("DROP USER IF EXISTS gw_ro")
    client.command("CREATE USER gw_ro IDENTIFIED BY 'ropw'")
    client.command("GRANT SELECT ON shop.* TO gw_ro")
    client.command("GRANT SELECT ON system.* TO gw_ro")
    client.close()
    return {"user": "gw_ro", "password": "ropw"}
