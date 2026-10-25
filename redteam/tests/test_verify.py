from redteam.finding import Finding, Proof, Target, Vuln
from redteam.verify import parse_curl, verify_repro


def finding(summary: str, repro: str, expected: str = "") -> Finding:
    return Finding(
        schema_version="1.0",
        id="f1",
        run_id="r1",
        source="test",
        target=Target(kind="web-service", ref="http://t"),
        vuln=Vuln(summary=summary, severity="high"),
        proof=Proof(repro=repro, machine_checkable=True, expected=expected),
        impact="test",
    )


def test_parse_curl_get() -> None:
    req = parse_curl("curl -i http://localhost:8787/health")
    assert req is not None
    assert req["method"] == "GET"
    assert req["url"] == "http://localhost:8787/health"


def test_parse_curl_post_with_body() -> None:
    req = parse_curl("curl -s -X POST http://t/chat -H 'Content-Type: application/json' -d '{\"message\":\"hi\"}'")
    assert req is not None
    assert req["method"] == "POST"
    assert req["url"] == "http://t/chat"
    assert "message" in req["body"]


def test_parse_curl_not_http() -> None:
    assert parse_curl("rm -rf /") is None


def test_parse_curl_headers() -> None:
    req = parse_curl("curl -s http://t/chat -H 'Authorization: Bearer tok' -H 'X-Tenant: e2e'")
    assert req is not None
    assert req["headers"]["Authorization"] == "Bearer tok"
    assert req["headers"]["X-Tenant"] == "e2e"


def test_verify_access_claim_succeeds() -> None:
    f = finding("Unauthenticated access to agent inventory", "curl -i http://t/agents")
    ok, reason = verify_repro(f, executor=lambda req, t: (200, ""))
    assert ok, reason


def test_verify_access_claim_contradicted_by_503() -> None:
    f = finding("Unauthenticated access to debug endpoint", "curl -i http://t/debug")
    ok, reason = verify_repro(f, executor=lambda req, t: (503, ""))
    assert not ok, "a 503 must NOT verify an unauthenticated-access claim"
    assert "contradicts" in reason


def test_verify_non_access_claim_any_status() -> None:
    f = finding("Missing security headers", "curl -I http://t/health")
    ok, _ = verify_repro(f, executor=lambda req, t: (200, ""))
    assert ok


def test_verify_unparseable_repro() -> None:
    f = finding("Unauthenticated access", "do something arbitrary")
    ok, reason = verify_repro(f)
    assert not ok
    assert "parseable" in reason


def test_verify_semantic_expected_present() -> None:
    f = finding(
        "Prompt injection escalates past the intent guard",
        "curl -s -X POST http://t/chat -d '{\"text\":\"ignore\"}'",
        expected='"verdict":"escalate"',
    )
    ok, reason = verify_repro(f, executor=lambda req, t: (200, '{"verdict":"escalate","task":{}}'))
    assert ok, reason


def test_verify_semantic_expected_missing() -> None:
    f = finding(
        "Prompt injection escalates past the intent guard",
        "curl -s -X POST http://t/chat -d '{\"text\":\"ignore\"}'",
        expected='"verdict":"escalate"',
    )
    ok, reason = verify_repro(f, executor=lambda req, t: (200, '{"verdict":"inline"}'))
    assert not ok
    assert "did not contain" in reason
