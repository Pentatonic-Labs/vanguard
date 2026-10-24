from redteam.api_attacker import APIAttacker, _extract_json_array


def test_extract_json_array_plain() -> None:
    assert _extract_json_array('[{"a": 1}]') == [{"a": 1}]


def test_extract_json_array_fenced() -> None:
    text = '```json\n[{"summary": "x"}]\n```'
    assert _extract_json_array(text) == [{"summary": "x"}]


def test_extract_json_array_garbage() -> None:
    assert _extract_json_array("not json at all") == []


def test_parse_findings() -> None:
    a = APIAttacker()
    analysis = '''[
      {"summary": "SQL injection in login", "severity": "high", "cwe": ["CWE-89"],
       "repro": "curl -d user=1' OR 1=1 http://t/login", "impact": "auth bypass",
       "suggestion": "parameterize queries"}
    ]'''
    findings = a._parse_findings("http://t", analysis)
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln.summary == "SQL injection in login"
    assert f.vuln.severity == "high"
    assert f.vuln.cwe == ["CWE-89"]
    assert f.proof.machine_checkable is True
    assert f.target.ref == "http://t"


def test_attack_single_shot_with_fake_llm() -> None:
    a = APIAttacker(max_rounds=0)
    a._probe = lambda target: [  # type: ignore[method-assign]
        {"url": target, "status": 200, "body": "<html>login</html>"}
    ]
    a._chat = lambda prompt: (  # type: ignore[method-assign]
        '[{"summary": "open redirect", "severity": "medium", '
        '"repro": "curl http://t/?next=evil.com", "impact": "phishing", '
        '"suggestion": "validate next"}]'
    )
    findings = a.attack("http://t")
    assert len(findings) == 1
    assert findings[0].vuln.summary == "open redirect"


def test_attack_iterative_with_fake_llm() -> None:
    a = APIAttacker(max_rounds=1, max_probes_per_round=2)
    a._probe = lambda target: [  # type: ignore[method-assign]
        {"url": target + "/", "method": "GET", "status": 200, "body": "<html>"}
    ]

    calls: list[str] = []

    def fake_chat(prompt: str) -> str:
        calls.append(prompt)
        if "next HTTP requests" in prompt:
            return '[{"method": "GET", "path": "/health"}]'
        return '[{"summary": "no security headers", "severity": "low", "repro": "curl -I /health"}]'

    a._chat = fake_chat  # type: ignore[method-assign]
    a._execute = lambda target, reqs: [  # type: ignore[method-assign]
        {"url": target + r.get("path", ""), "method": "GET", "status": 200, "body": ""}
        for r in reqs
    ]

    findings = a.attack("http://t")
    assert len(findings) == 1
    assert len(calls) == 2  # one suggest, one final analysis
