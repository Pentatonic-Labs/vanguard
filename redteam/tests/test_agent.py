"""Tests for the agentic tool-use loop: act -> observe -> decide -> prove."""

from __future__ import annotations

import json
import urllib.parse

from redteam.agent import AgenticAttacker, curl_from_request, detect_compromise


def _make_http(statuses: dict[str, int]):
    """A deterministic stub HTTP transport: path -> status, default 404."""

    def http(req, timeout):
        url = req.get("url") or req.get("path") or "/"
        path = urllib.parse.urlparse(url).path
        return {"status": statuses.get(path, 404), "headers": {}, "body": ""}

    return http


def _scripted(*actions):
    """A chat seam that returns the given actions in order, as JSON."""
    it = iter(actions)

    def chat(prompt):
        return json.dumps(next(it))

    return chat


def test_submit_finding_is_recorded_when_repro_verifies():
    attacker = AgenticAttacker(
        "http://target",
        chat=_scripted(
            {
                "tool": "submit_finding",
                "args": {
                    "summary": "admin panel reachable",
                    "severity": "high",
                    "cwe": ["CWE-200"],
                    "repro": "curl -s http://target/admin",
                    "impact": "exposes the admin surface",
                    "fix": "Restrict /admin with authentication and authorization checks.",
                },
            },
            {"tool": "done", "args": {}},
        ),
        http=_make_http({"/admin": 200}),
    )

    findings = attacker.attack()

    assert len(findings) == 1
    assert findings[0].vuln.summary == "admin panel reachable"
    assert findings[0].fix.suggestion == "Restrict /admin with authentication and authorization checks."


def test_unverified_finding_is_rejected_and_loop_continues():
    # The first submission claims "unauthenticated access" but the endpoint
    # returns 401, which contradicts the claim -> NOT recorded. The second
    # submission has a repro that actually returns 200 -> recorded.
    attacker = AgenticAttacker(
        "http://target",
        chat=_scripted(
            {
                "tool": "submit_finding",
                "args": {
                    "summary": "unauthenticated access to admin",
                    "severity": "critical",
                    "cwe": ["CWE-287"],
                    "repro": "curl -s http://target/admin",
                    "impact": "anyone can reach the admin panel",
                },
            },
            {
                "tool": "submit_finding",
                "args": {
                    "summary": "admin panel reachable",
                    "severity": "high",
                    "cwe": ["CWE-200"],
                    "repro": "curl -s http://target/admin2",
                    "impact": "exposes the admin surface",
                },
            },
            {"tool": "done", "args": {}},
        ),
        http=_make_http({"/admin": 401, "/admin2": 200}),
    )

    findings = attacker.attack()

    assert [f.vuln.summary for f in findings] == ["admin panel reachable"]


def test_cross_origin_request_is_refused():
    attacker = AgenticAttacker(
        "http://target",
        chat=_scripted({"tool": "done", "args": {}}),
        http=_make_http({}),
    )

    obs = attacker._run_http({"method": "GET", "path": "http://evil.com/x"})

    assert "refused" in obs["body"]


def test_detect_compromise():
    assert detect_compromise('{"verdict":"escalate"}', ('"verdict":"escalate"',)) == '"verdict":"escalate"'
    assert detect_compromise('{"verdict":"inline"}', ('"verdict":"escalate"',)) is None


def test_curl_from_request():
    req = {
        "method": "POST",
        "url": "http://t/chat",
        "headers": {"Authorization": "Bearer x"},
        "body": '{"text":"hi"}',
    }
    c = curl_from_request(req)
    assert "curl -s -X POST" in c
    assert "Authorization: Bearer x" in c
    assert "http://t/chat" in c


def test_injection_detector_produces_finding():
    def http(req, timeout):
        if "unique-marker" in (req.get("body") or ""):
            return {"status": 200, "headers": {}, "body": '{"verdict":"escalate","task":{}}'}
        return {"status": 404, "headers": {}, "body": ""}

    attacker = AgenticAttacker(
        "http://target",
        chat=_scripted({"tool": "done", "args": {}}),
        http=http,
        seed_probes=[{"method": "POST", "path": "/chat", "body": '{"text":"unique-marker"}'}],
    )

    findings = attacker.attack()

    assert len(findings) == 1
    assert findings[0].proof.expected == '"verdict":"escalate"'
    assert "curl" in findings[0].proof.repro
