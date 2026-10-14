from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from adg.app.main import create_app


def test_nothing_of_the_extension_is_exposed_when_disabled(
    session_factory: sessionmaker[Session],
) -> None:
    client = TestClient(create_app(session_factory=session_factory))
    assert client.post("/admin/ext/dry-run", json={}).status_code == 404
    assert client.get("/admin/ext/sync/role").status_code == 404
    assert client.post("/ext/delegated/query", json={}).status_code == 404
