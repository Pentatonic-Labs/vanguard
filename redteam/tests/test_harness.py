import pytest

from redteam.attacker import NoopAttacker
from redteam.attestation import AttestationError, sign_target
from redteam.finding import Finding, Proof, Target, Vuln
from redteam.harness import Harness, HarnessError
from redteam.sandbox import Sandbox

KEY = b"operator-secret-key"
TARGET = "https://replica.internal/svc"


def _sandbox() -> Sandbox:
    return Sandbox(
        isolation="box",
        device="box-01",
        egress_allowlist=["replica.internal"],
        replica_seed="fake-v1",
    )


def _claim(target: str) -> dict:
    return {"target": target, "signature": sign_target(target, KEY)}


def _finding(repro: str, machine_checkable: bool = True) -> Finding:
    return Finding(
        schema_version="1.0",
        id="1",
        run_id="2",
        source="redteam-agent",
        target=Target(kind="web-service", ref=TARGET),
        vuln=Vuln(cwe=["CWE-89"], summary="s", severity="high", reachability="confirmed"),
        proof=Proof(repro=repro, machine_checkable=machine_checkable),
        impact="i",
    )


class FakeAttacker:
    def __init__(self, findings: list[Finding]) -> None:
        self._findings = findings

    def attack(self, target: str) -> list[Finding]:
        return list(self._findings)


def test_run_returns_only_proven_findings() -> None:
    proven = _finding("curl ...", True)
    unproven = _finding("", True)
    harness = Harness(operator_key=KEY, inventory_claim=_claim(TARGET), sandbox=_sandbox())
    result = harness.run(TARGET, FakeAttacker([proven, unproven]))
    assert result.findings == [proven]
    assert result.leads == [unproven]
    assert any(e["event"] == "proof-gate" for e in result.audit_log)


def test_run_rejects_unattested_target() -> None:
    harness = Harness(operator_key=KEY, inventory_claim=_claim(TARGET), sandbox=_sandbox())
    with pytest.raises(AttestationError):
        harness.run("https://replica.internal/other", NoopAttacker())


def test_run_rejects_invalid_sandbox() -> None:
    harness = Harness(
        operator_key=KEY,
        inventory_claim=_claim(TARGET),
        sandbox=Sandbox(isolation="mig"),
    )
    with pytest.raises(HarnessError):
        harness.run(TARGET, NoopAttacker())


def test_noop_attacker_returns_empty() -> None:
    harness = Harness(operator_key=KEY, inventory_claim=_claim(TARGET), sandbox=_sandbox())
    result = harness.run(TARGET, NoopAttacker())
    assert result.findings == []
    assert result.leads == []
