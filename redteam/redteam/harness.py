"""The red-team harness run loop: attestation -> attacker -> proof gate."""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .attacker import Attacker
from .attestation import AttestationError, authorize_target
from .finding import Finding
from .proof import validate_finding
from .sandbox import Sandbox


class HarnessError(Exception):
    """Raised when a run cannot start (e.g. an unsafe sandbox)."""


@dataclass
class RunResult:
    run_id: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    leads: list[Finding] = field(default_factory=list)
    audit_log: list[dict[str, Any]] = field(default_factory=list)


class Harness:
    """Coordinates a red-team run: authorize, run the attacker, gate the findings."""

    def __init__(
        self,
        *,
        operator_key: bytes,
        inventory_claim: dict[str, Any],
        sandbox: Sandbox,
    ) -> None:
        self._operator_key = operator_key
        self._inventory_claim = inventory_claim
        self._sandbox = sandbox

    def run(
        self,
        target: str,
        attacker: Attacker,
        verify: Callable[[Finding], tuple[bool, str]] | None = None,
    ) -> RunResult:
        """Run the attacker against the target and return only proven findings.

        When `verify` is provided, each structurally-valid finding's repro is
        re-executed and must support the claim; unverified claims are downgraded
        to leads.
        """
        audit: list[dict[str, Any]] = []
        run_id = str(uuid.uuid4())

        problems = self._sandbox.validate()
        if problems:
            audit.append(self._event("sandbox-invalid", problems=problems))
            raise HarnessError("sandbox is not safe to run: " + "; ".join(problems))

        try:
            authorize_target(target, self._inventory_claim, self._operator_key)
        except AttestationError as exc:
            audit.append(self._event("attestation-failed", target=target, reason=str(exc)))
            raise
        audit.append(self._event("attestation-passed", target=target))

        claims = attacker.attack(target)
        audit.append(self._event("attacker-finished", claim_count=len(claims)))

        findings: list[Finding] = []
        leads: list[Finding] = []
        for claim in claims:
            if not validate_finding(claim):
                leads.append(claim)
                continue
            if verify is None:
                findings.append(claim)
                continue
            verified, reason = verify(claim)
            audit.append(self._event("verify", id=claim.id, verified=verified, reason=reason))
            if verified:
                findings.append(claim)
            else:
                leads.append(claim)
        audit.append(self._event("proof-gate", finding_count=len(findings), lead_count=len(leads)))

        return RunResult(
            run_id=run_id,
            target=target,
            findings=findings,
            leads=leads,
            audit_log=audit,
        )

    def _event(self, kind: str, **extra: Any) -> dict[str, Any]:
        return {"timestamp": time.time(), "event": kind, **extra}
