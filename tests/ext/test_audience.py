from adg_ext.audience import audience_reason


def test_unrestricted_when_the_grant_has_no_list() -> None:
    assert audience_reason(None, None) is None
    assert audience_reason("", "ou_a") is None


def test_listed_requires_the_caller_to_be_on_it() -> None:
    raw = '{"mode":"listed","openIds":["ou_a"]}'
    assert audience_reason(raw, "ou_a") is None
    assert audience_reason(raw, "ou_b") == "person_not_entitled"
    assert audience_reason(raw, "  ") == "person_required"
    assert audience_reason(raw, None) == "person_required"


def test_empty_or_broken_list_rejects_everyone() -> None:
    assert audience_reason('{"mode":"listed","openIds":[]}', "ou_a") == "person_not_entitled"
    assert audience_reason("{", "ou_a") == "person_not_entitled"
    assert audience_reason('{"mode":"all"}', "ou_a") == "person_not_entitled"
