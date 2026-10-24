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


def test_attack_end_to_end_with_fake_llm() -> None:
    a = APIAttacker()
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
