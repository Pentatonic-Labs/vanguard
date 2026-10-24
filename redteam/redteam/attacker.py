"""The pluggable attacker slot."""

from __future__ import annotations

from typing import Protocol

from .finding import Finding


class Attacker(Protocol):
    """A pluggable attacker: given a target reference, return raw findings.

    The returned findings may be unproven claims; the harness's proof gate is
    what separates findings from leads.
    """

    def attack(self, target: str) -> list[Finding]:
        """Probe the target and return findings."""
        ...


class NoopAttacker:
    """Reference attacker stub that finds nothing (find-and-report mode)."""

    def attack(self, target: str) -> list[Finding]:
        return []
