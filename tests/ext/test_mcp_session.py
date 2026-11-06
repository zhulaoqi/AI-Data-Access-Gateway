"""A session created on one replica is served by another via the shared id."""

import anyio
import httpx
from mcp.server.fastmcp import FastMCP

from adg_ext.mcp_session import PublishingSessions, dispatch, install_shared_sessions
from adg_ext.redis_share import MCP_HIT, MCP_MISS, MCP_UNAVAILABLE, Share


class _Manager:
    def __init__(self) -> None:
        self._server_instances: dict[str, object] = {}
        self.calls: list[str] = []

    async def handle_request(self, scope, receive, send) -> None:
        self.calls.append("local")
        if scope.get("method") == "POST" and not _sid(scope):
            self._server_instances["d" * 32] = object()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"", "more_body": False})


def _scope(method: str = "POST", session_id: str | None = None) -> dict:
    headers = []
    if session_id:
        headers.append((b"mcp-session-id", session_id.encode()))
    return {"type": "http", "method": method, "headers": headers}


def _sid(scope: dict) -> str | None:
    for name, value in scope["headers"]:
        if name == b"mcp-session-id":
            return value.decode()
    return None


def _run(function):
    anyio.run(function)


def test_publishing_a_new_session_writes_redis_before_the_response(monkeypatch):
    saved: list[str] = []
    monkeypatch.setattr(Share, "save_mcp_session", lambda self, session_id: saved.append(session_id))
    sessions = PublishingSessions()
    sessions["e" * 32] = object()
    assert saved == ["e" * 32]


def test_known_remote_session_is_served_here(monkeypatch):
    served: list[str] = []

    async def serve(manager, scope, receive, send, session_id):
        served.append(session_id)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

    monkeypatch.setattr("adg_ext.mcp_session.serve_shared_session", serve)
    monkeypatch.setattr(Share, "read_mcp_session", lambda self, session_id: MCP_HIT)
    refreshed: list[str] = []
    monkeypatch.setattr(Share, "save_mcp_session", lambda self, session_id: refreshed.append(session_id))
    manager = _Manager()

    async def scenario():
        sent: list[dict] = []

        async def send(message):
            sent.append(message)

        await dispatch(
            manager,
            manager.handle_request,
            _scope(session_id="f" * 32),
            _receive,
            send,
        )
        assert served == ["f" * 32]
        assert manager.calls == []
        assert refreshed == ["f" * 32]
        assert sent[0]["status"] == 200

    _run(scenario)


def test_redis_outage_retries_instead_of_dropping_the_session(monkeypatch):
    monkeypatch.setattr(Share, "read_mcp_session", lambda self, session_id: MCP_UNAVAILABLE)
    manager = _Manager()

    async def scenario():
        sent: list[dict] = []

        async def send(message):
            sent.append(message)

        await dispatch(manager, manager.handle_request, _scope(session_id="a" * 32), _receive, send)
        assert manager.calls == []
        assert sent[0]["status"] == 503

    _run(scenario)


def test_unknown_session_stays_with_the_sdk(monkeypatch):
    monkeypatch.setattr(Share, "read_mcp_session", lambda self, session_id: MCP_MISS)
    manager = _Manager()

    async def scenario():
        await dispatch(manager, manager.handle_request, _scope(session_id="b" * 32), _receive, _noop_send)
        assert manager.calls == ["local"]

    _run(scenario)


def test_local_session_is_not_looked_up(monkeypatch):
    def fail(self, session_id):
        raise AssertionError("local session must not read redis")

    monkeypatch.setattr(Share, "read_mcp_session", fail)
    seen: list[str] = []
    monkeypatch.setattr(Share, "save_mcp_session", lambda self, session_id: seen.append(session_id))
    manager = _Manager()
    manager._server_instances["c" * 32] = object()

    async def scenario():
        await dispatch(
            manager,
            manager.handle_request,
            _scope(session_id="c" * 32),
            _receive,
            _noop_send,
        )
        assert manager.calls == ["local"]
        assert seen == ["c" * 32]

    _run(scenario)


def test_delete_removes_the_shared_session(monkeypatch):
    cleared: list[str] = []
    monkeypatch.setattr(Share, "read_mcp_session", lambda self, session_id: MCP_MISS)
    monkeypatch.setattr(Share, "clear_mcp_session", lambda self, session_id: cleared.append(session_id))
    manager = _Manager()

    async def scenario():
        await dispatch(
            manager,
            manager.handle_request,
            _scope(method="DELETE", session_id="d" * 32),
            _receive,
            _noop_send,
        )
        assert cleared == ["d" * 32]

    _run(scenario)


def test_another_replica_returns_the_tool_list(monkeypatch):
    store: dict[str, str] = {}

    class _Store:
        def get(self, key: str) -> str | None:
            return store.get(key)

        def set(self, key: str, value: str, ex: int | None = None) -> bool:
            store[key] = value
            return True

        def delete(self, key: str) -> int:
            return 1 if store.pop(key, None) is not None else 0

    monkeypatch.setattr("adg_ext.redis_share.get_client", lambda: _Store())
    gateway = FastMCP("shared-session")

    @gateway.tool()
    def ping() -> str:
        return "pong"

    app = gateway.streamable_http_app()
    manager = gateway.session_manager
    install_shared_sessions(manager)
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "0"},
        },
    }

    async def scenario():
        transport = httpx.ASGITransport(app=app)
        async with manager.run(), httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8000",
        ) as client:
            opened = await client.post("/mcp", headers=headers, json=initialize, timeout=5)
            session_id = opened.headers.get("mcp-session-id")
            assert opened.status_code == 200, opened.text
            assert session_id
            assert any(session_id in key for key in store)
            manager._server_instances.pop(session_id)
            listed = await client.post(
                "/mcp",
                headers={
                    **headers,
                    "mcp-session-id": session_id,
                    "mcp-protocol-version": "2024-11-05",
                },
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                timeout=5,
            )
            assert listed.status_code == 200, listed.text
            assert listed.headers["content-type"].startswith("application/json")
            assert listed.json()["id"] == 2
            assert "ping" in listed.text
            assert "Session not found" not in listed.text
            listen = await client.get(
                "/mcp",
                headers={
                    "Accept": "text/event-stream",
                    "mcp-session-id": session_id,
                    "mcp-protocol-version": "2024-11-05",
                },
                timeout=5,
            )
            assert listen.status_code == 405
            assert session_id in "".join(store)

    anyio.run(scenario)


def test_borrowed_calls_return_together(monkeypatch):
    store: dict[str, str] = {}

    class _Store:
        def get(self, key: str) -> str | None:
            return store.get(key)

        def set(self, key: str, value: str, ex: int | None = None) -> bool:
            store[key] = value
            return True

        def delete(self, key: str) -> int:
            return 1 if store.pop(key, None) is not None else 0

    monkeypatch.setattr("adg_ext.redis_share.get_client", lambda: _Store())
    gateway = FastMCP("shared-session")

    @gateway.tool()
    def ping() -> str:
        return "pong"

    app = gateway.streamable_http_app()
    manager = gateway.session_manager
    install_shared_sessions(manager)
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "0"},
        },
    }

    async def scenario():
        transport = httpx.ASGITransport(app=app)
        async with manager.run(), httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8000",
        ) as client:
            opened = await client.post("/mcp", headers=headers, json=initialize, timeout=5)
            session_id = opened.headers["mcp-session-id"]
            manager._server_instances.pop(session_id)
            call_headers = {
                **headers,
                "mcp-session-id": session_id,
                "mcp-protocol-version": "2024-11-05",
            }

            async def call(request_id: int, results: dict[int, httpx.Response]) -> None:
                results[request_id] = await client.post(
                    "/mcp",
                    headers=call_headers,
                    json={
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "method": "tools/call",
                        "params": {"name": "ping", "arguments": {}},
                    },
                    timeout=5,
                )

            results: dict[int, httpx.Response] = {}
            async with anyio.create_task_group() as tg:
                tg.start_soon(call, 2, results)
                tg.start_soon(call, 3, results)
            for request_id, response in results.items():
                assert response.status_code == 200, response.text
                assert response.headers["content-type"].startswith("application/json")
                assert response.json()["id"] == request_id
                assert "pong" in response.text

    anyio.run(scenario)


def test_delete_on_another_replica_drops_the_shared_id(monkeypatch):
    cleared: list[str] = []
    monkeypatch.setattr(Share, "read_mcp_session", lambda self, session_id: MCP_HIT)
    monkeypatch.setattr(Share, "clear_mcp_session", lambda self, session_id: cleared.append(session_id))

    async def fail(*args, **kwargs):
        raise AssertionError("a delete must not open a borrowed transport")

    monkeypatch.setattr("adg_ext.mcp_session.serve_shared_session", fail)
    manager = _Manager()

    async def scenario():
        sent: list[dict] = []

        async def send(message):
            sent.append(message)

        await dispatch(
            manager,
            manager.handle_request,
            _scope(method="DELETE", session_id="f" * 32),
            _receive,
            send,
        )
        assert cleared == ["f" * 32]
        assert sent[0]["status"] == 200
        assert manager.calls == []

    _run(scenario)


def test_install_is_idempotent():
    manager = _Manager()
    install_shared_sessions(manager)
    first = manager.handle_request
    install_shared_sessions(manager)
    assert manager.handle_request is first
    assert isinstance(manager._server_instances, PublishingSessions)


async def _receive():
    return {"type": "http.request", "body": b"{}", "more_body": False}


async def _noop_send(message):
    return None
