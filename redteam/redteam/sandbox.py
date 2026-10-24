"""Sandbox configuration and validation, per docs/sandbox-spec.md."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Sandbox:
    isolation: str = "box"  # "box" | "card"; MIG is not a valid isolation boundary
    device: str = ""  # dedicated card/box identifier
    container_image: str = ""
    egress_allowlist: list[str] = field(default_factory=list)
    replica_seed: str = ""  # fake-data seed; must be present
    ephemeral: bool = True
    fake_secrets: bool = True

    def validate(self) -> list[str]:
        """Return a list of spec violations; empty means the sandbox is valid."""
        problems: list[str] = []
        if self.isolation not in ("box", "card"):
            problems.append(
                f"isolation must be 'box' or 'card' (got {self.isolation!r}); "
                "MIG is not an isolation boundary on DGX Spark or RTX PRO 6000"
            )
        if not self.device:
            problems.append("a dedicated device/box identifier is required")
        if not self.egress_allowlist:
            problems.append("an egress allowlist is required (default-deny network)")
        if not self.replica_seed:
            problems.append("an ephemeral replica seed (fake data) is required")
        if not self.ephemeral:
            problems.append("the replica must be ephemeral")
        if not self.fake_secrets:
            problems.append("fake-secrets policy must be enabled (never production credentials)")
        return problems
