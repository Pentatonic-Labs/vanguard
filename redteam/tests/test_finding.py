from redteam.finding import Finding, Fix, Proof, Target, Vuln


def _sample_finding() -> Finding:
    return Finding(
        schema_version="1.0",
        id="11111111-1111-1111-1111-111111111111",
        run_id="22222222-2222-2222-2222-222222222222",
        source="redteam-agent",
        target=Target(kind="web-service", ref="https://replica.internal/svc", asset_id="asset-1"),
        vuln=Vuln(
            cwe=["CWE-89"],
            summary="SQL injection in /search",
            severity="critical",
            reachability="confirmed",
            cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ),
        proof=Proof(
            repro="curl 'https://replica.internal/search?q=%27%20OR%201=1--'",
            machine_checkable=True,
            artifact="sha256:abc",
            evidence=["HTTP 500 with SQL error"],
        ),
        impact="Full database read.",
        fix=Fix(suggestion="Parameterize the query."),
        references=["https://example.com/advisory"],
    )


def test_finding_round_trip() -> None:
    original = _sample_finding()
    restored = Finding.from_dict(original.to_dict())
    assert restored == original


def test_to_dict_matches_schema_shape() -> None:
    d = _sample_finding().to_dict()
    assert d["schema_version"] == "1.0"
    assert d["target"]["kind"] == "web-service"
    assert d["proof"]["machine_checkable"] is True
    assert d["vuln"]["cwe"] == ["CWE-89"]


def test_to_dict_omits_empty_optionals() -> None:
    f = Finding(
        schema_version="1.0",
        id="1",
        run_id="2",
        source="s",
        target=Target(kind="code", ref="repo/x"),
        vuln=Vuln(cwe=["CWE-79"], summary="xss", severity="medium", reachability="potential"),
        proof=Proof(repro="run me", machine_checkable=True),
        impact="minor",
    )
    d = f.to_dict()
    assert "fix" not in d
    assert "references" not in d
    assert "asset_id" not in d["target"]
    assert "cvss" not in d["vuln"]
    assert "artifact" not in d["proof"]
    assert "evidence" not in d["proof"]
