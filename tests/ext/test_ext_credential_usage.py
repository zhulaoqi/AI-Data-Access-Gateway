from datetime import UTC, datetime, timedelta

from adg_ext import credential_usage as usage


def setup_function():
    usage.reset()


def test_posts_gateway_credential_once_a_minute():
    sent: list[str] = []
    usage.set_poster(sent.append)
    t0 = datetime(2026, 10, 21, tzinfo=UTC)
    usage.note_named("entry-key", t0)
    usage.note_named("gw:cred:01ARZ3NDEKTSV4RRFFQ69G5FAV", t0)
    usage.note_named("gw:cred:01ARZ3NDEKTSV4RRFFQ69G5FAV", t0 + timedelta(seconds=30))
    assert sent == ["01ARZ3NDEKTSV4RRFFQ69G5FAV"]
    usage.note_named("gw:cred:01ARZ3NDEKTSV4RRFFQ69G5FAV", t0 + timedelta(minutes=1))
    assert sent == ["01ARZ3NDEKTSV4RRFFQ69G5FAV", "01ARZ3NDEKTSV4RRFFQ69G5FAV"]


def test_usage_url_sits_next_to_the_revocation_list():
    assert usage.usage_url("http://admin/api/sql-gateway/revocations") == (
        "http://admin/api/sql-gateway/revocations/usage"
    )
    assert usage.usage_url("http://admin/api/sql-gateway/revocations?x=1") == (
        "http://admin/api/sql-gateway/revocations/usage"
    )
    assert usage.usage_url("") == ""


def test_note_api_key_swallows_lookup_errors():
    class Broken:
        def scalar(self, _query):
            raise RuntimeError("db down")

    usage.note_api_key(Broken(), "key-1")  # type: ignore[arg-type]
