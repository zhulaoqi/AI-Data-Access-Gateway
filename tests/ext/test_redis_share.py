from adg_ext.redis_share import Share, get_client, reset_client


def test_share_is_a_noop_without_redis(monkeypatch):
    monkeypatch.delenv("redis.host", raising=False)
    monkeypatch.delenv("REDIS_HOST", raising=False)
    reset_client()
    assert get_client() is None
    share = Share()
    assert share.try_slot("user:a", 1, "m") is True
    assert share.circuit_open("ds") is False
    assert share.forward_cancel("req", None, None) is None
    share.release_slot("user:a", "m")
    share.note_failure("ds", 5, 30)
    share.note_success("ds")
    share.register_run("req")
    share.clear_run("req")
