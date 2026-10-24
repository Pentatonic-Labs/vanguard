"""Minimal harness skeleton.

The harness hosts a pluggable attacker (a model) against an ephemeral replica
of a target, with a bounded toolset and a "prove it" proof gate.
"""

from __future__ import annotations


class Harness:
    """Coordinates a single red-team run against a target replica."""

    def __init__(self, target: str) -> None:
        self.target = target

    def run(self) -> None:
        """Placeholder: run the attacker against the target."""
        raise NotImplementedError
