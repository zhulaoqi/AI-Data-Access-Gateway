from adg_ext.audience import audience_message, audience_reason, query_identity_message


def test_unrestricted_when_the_grant_has_no_list() -> None:
    assert audience_reason(None, None) is None
    assert audience_reason("", "ou_a") is None


def test_listed_requires_the_caller_to_be_on_it() -> None:
    raw = '{"mode":"listed","openIds":["ou_a"]}'
    assert audience_reason(raw, "ou_a") is None
    assert audience_reason(raw, "ou_b") == "person_not_entitled"
    assert audience_reason(raw, "  ") == "person_required"
    assert audience_reason(raw, None) == "person_required"


def test_rejection_explains_why_instead_of_only_hiding_the_catalog() -> None:
    missing = audience_message("person_required")
    absent = audience_message("person_not_entitled")
    assert "X-GW-Person" in missing and "没有返回库表" in missing
    assert "可见名单" in absent and "没有返回库表" in absent
    assert missing != absent
    query = query_identity_message("person_required")
    assert "email" in query and "没有返回库表" in query
    assert query != missing


def test_directory_mode_requires_an_active_open_id() -> None:
    raw = '{"mode":"directory"}'

    def store(key: str) -> str | None:
        if key == "gw:directory:openid:ou_a":
            return '{"status":"active"}'
        if key == "gw:directory:openid:ou_old":
            return '{"status":"disabled"}'
        return None

    assert audience_reason(raw, None, store) == "person_required"
    assert audience_reason(raw, "ou_a", store) is None
    assert audience_reason(raw, "ou_old", store) == "person_not_in_directory"
    assert audience_reason(raw, "ou_missing", store) == "person_not_in_directory"
    assert "在职" in audience_message("person_not_in_directory")

    def broken(_key: str) -> str | None:
        raise RuntimeError("down")

    assert audience_reason(raw, "ou_a", broken) == "directory_unavailable"


def test_empty_or_broken_list_rejects_everyone() -> None:
    assert audience_reason('{"mode":"listed","openIds":[]}', "ou_a") == "person_not_entitled"
    assert audience_reason("{", "ou_a") == "person_not_entitled"
    assert audience_reason('{"mode":"all"}', "ou_a") == "person_not_entitled"
