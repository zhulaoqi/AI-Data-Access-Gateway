"""Server-side cancellation of a running query (PA-4): ``KILL QUERY`` per engine.

MySQL and StarRocks: find the connection whose running statement carries the request tag (the
``/* grant=..,req=.. */`` comment added by the pipeline) with ``SHOW FULL PROCESSLIST`` and
``KILL QUERY`` it. ClickHouse: ``KILL QUERY WHERE query LIKE '%req=<id>%'`` (the same tag).
The account only needs permission to kill its own queries.
"""

import importlib
import logging
from typing import Any

from adg.connectors.relational import RelationalConnector

logger = logging.getLogger(__name__)


def kill_query(connector_type: str, config: dict[str, object], tag: str) -> bool:
    """Best-effort kill; returns whether a kill was issued. Never raises."""

    try:
        checked = RelationalConnector()._validated_connection_config(config)
        if connector_type in {"mysql", "doris"}:
            return _kill_mysql(checked, tag)
        if connector_type == "clickhouse":
            return _kill_clickhouse(checked, tag)
        if connector_type == "postgres":
            return _kill_postgres(checked, tag)
    except Exception:
        logger.warning("kill query failed for tag %s", tag, exc_info=False)
    return False


def _kill_mysql(config: dict[str, object], tag: str) -> bool:
    pymysql: Any = importlib.import_module("pymysql")
    port = config.get("port")
    connection = pymysql.connect(
        host=str(config.get("host", "")),
        port=int(str(port)) if port else 3306,
        user=str(config.get("username", "")),
        password=str(config.get("password", "")),
        connect_timeout=3,
        read_timeout=5,
        write_timeout=5,
    )
    try:
        with connection.cursor() as cursor:
            cursor.execute("SHOW FULL PROCESSLIST")
            own = connection.thread_id()
            marker = f"req={tag}"
            killed = False
            for row in cursor.fetchall():
                process_id, info = row[0], row[7] if len(row) > 7 else None
                if process_id != own and info and marker in str(info):
                    cursor.execute(f"KILL QUERY {int(process_id)}")
                    killed = True
            return killed
    finally:
        connection.close()


def _kill_clickhouse(config: dict[str, object], tag: str) -> bool:
    driver: Any = importlib.import_module("clickhouse_connect")
    port = config.get("port")
    client = driver.get_client(
        host=str(config.get("host", "")),
        port=int(str(port)) if port else 8123,
        username=str(config.get("username", "")) or "default",
        password=str(config.get("password", "")),
        connect_timeout=3,
        send_receive_timeout=5,
    )
    try:
        client.command(
            "KILL QUERY WHERE query LIKE {pattern:String} AND query NOT LIKE 'KILL%' ASYNC",
            parameters={"pattern": f"%req={tag}%"},
        )
        return True
    finally:
        client.close()


def _kill_postgres(config: dict[str, object], tag: str) -> bool:
    if not tag.isalnum():
        return False
    driver: Any = importlib.import_module("psycopg")
    port = config.get("port")
    kwargs: dict[str, object] = {
        "host": str(config.get("host", "")),
        "port": int(str(port)) if port else 5432,
        "user": str(config.get("username", "")),
        "password": str(config.get("password", "")),
        "dbname": str(config.get("database") or ""),
        "connect_timeout": 3,
    }
    sslmode = str(config.get("sslmode") or "").strip()
    if sslmode:
        kwargs["sslmode"] = sslmode
    connection = driver.connect(**kwargs)
    try:
        connection.autocommit = True
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT pid
                FROM pg_stat_activity
                WHERE pid <> pg_backend_pid()
                  AND usename = current_user
                  AND query LIKE %s
                  AND query NOT LIKE 'SELECT pid FROM pg_stat_activity%%'
                """,
                (f"%req={tag}%",),
            )
            pids = [row[0] for row in cursor.fetchall()]
            for pid in pids:
                cursor.execute("SELECT pg_cancel_backend(%s)", (int(pid),))
            return bool(pids)
    finally:
        connection.close()
