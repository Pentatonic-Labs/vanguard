from redteam.finding import Finding, Proof, Target, Vuln
from redteam.proof import validate_finding


def _finding(repro: str, machine_checkable: bool) -> Finding:
    return Finding(
        schema_version="1.0",
        id="1",
        run_id="2",
        source="s",
        target=Target(kind="code", ref="x"),
        vuln=Vuln(cwe=["CWE-89"], summary="s", severity="high", reachability="confirmed"),
        proof=Proof(repro=repro, machine_checkable=machine_checkable),
        impact="i",
    )


def test_accepts_proven_finding() -> None:
    assert validate_finding(_finding("curl ...", True)) is True


def test_rejects_empty_repro() -> None:
    assert validate_finding(_finding("", True)) is False
    assert validate_finding(_finding("   ", True)) is False


def test_rejects_uncheckable() -> None:
    assert validate_finding(_finding("curl ...", False)) is False
