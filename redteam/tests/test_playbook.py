import json

from redteam.playbook import (
    idor,
    info_leak,
    jwt_none,
    mass_assignment,
    playbook_probes,
    prompt_injection,
    sqli,
    ssrf,
    traversal,
)


def _paths(probes):
    return [p["path"] for p in probes]


def test_idor_enumerates_ids():
    probes = idor("http://t")
    assert all(p["method"] == "GET" for p in probes)
    assert "/agents/1" in _paths(probes)
    assert "/users/2" in _paths(probes)
    assert "/accounts/3" in _paths(probes)
    assert "/api/users/1" in _paths(probes)
    assert "/object/1" in _paths(probes)
    assert len(probes) == 16


def test_jwt_none_sends_alg_none_token():
    probes = jwt_none("http://t")
    assert len(probes) == 2
    for p in probes:
        assert p["method"] == "POST"
        token = json.loads(p["body"])["token"]
        parts = token.split(".")
        # header.payload. with an empty signature => three parts, last empty
        assert len(parts) == 3
        assert parts[2] == ""


def test_ssrf_points_at_internal_hosts():
    probes = ssrf("http://t")
    assert any("127.0.0.1" in p["path"] for p in probes)
    assert any("169.254.169.254" in p["path"] for p in probes)
    assert any("url=" in p["path"] for p in probes)
    assert any("next=" in p["path"] for p in probes)


def test_traversal_uses_encoded_payloads():
    probes = traversal("http://t")
    assert any("../" in p["path"] for p in probes)
    assert any("%2e%2e/" in p["path"] for p in probes)


def test_mass_assignment_injects_privilege_fields():
    probes = mass_assignment("http://t")
    assert any("admin" in p["body"] for p in probes)
    assert any("is_admin" in p["body"] for p in probes)


def test_prompt_injection_has_payloads():
    probes = prompt_injection("http://t")
    assert len(probes) == 4
    assert all(p["method"] == "POST" for p in probes)
    assert any("system prompt" in p["body"] for p in probes)


def test_info_leak_probes_dotfiles():
    probes = info_leak("http://t")
    assert any("/.env" in p["path"] for p in probes)
    assert any("/.git/HEAD" in p["path"] for p in probes)
    assert all(p["method"] == "GET" for p in probes)


def test_sqli_probes_query_params():
    probes = sqli("http://t")
    assert all(p["method"] == "GET" for p in probes)
    assert all("id=" in p["path"] for p in probes)


def test_playbook_probes_merges_all():
    probes = playbook_probes("http://t")
    expected = (
        len(idor("http://t"))
        + len(jwt_none("http://t"))
        + len(ssrf("http://t"))
        + len(traversal("http://t"))
        + len(mass_assignment("http://t"))
        + len(prompt_injection("http://t"))
        + len(info_leak("http://t"))
        + len(sqli("http://t"))
    )
    assert len(probes) == expected
