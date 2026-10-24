"""The proof gate: no unproven findings."""

from __future__ import annotations

from .finding import Finding


def validate_finding(finding: Finding) -> bool:
    """True when the finding carries a machine-checkable PoC.

    A finding is proven only if its reproduction procedure is non-empty AND
    ``machine_checkable`` is exactly True. Everything else is a lead, never a
    reported finding.
    """
    has_repro = bool(finding.proof.repro and finding.proof.repro.strip())
    return has_repro and finding.proof.machine_checkable is True
