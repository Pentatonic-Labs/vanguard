"""The Vanguard finding model, mirroring findings/schema.json."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Target:
    kind: str
    ref: str
    asset_id: str = ""


@dataclass
class Vuln:
    cwe: list[str] = field(default_factory=list)
    summary: str = ""
    severity: str = "info"
    reachability: str = "unknown"
    cvss: str = ""


@dataclass
class Proof:
    repro: str = ""
    machine_checkable: bool = True
    artifact: str = ""
    evidence: list[str] = field(default_factory=list)


@dataclass
class Fix:
    suggestion: str = ""
    patch_ref: str = ""
    test_ref: str = ""


@dataclass
class Finding:
    schema_version: str
    id: str
    run_id: str
    source: str
    target: Target
    vuln: Vuln
    proof: Proof
    impact: str
    fix: Fix = field(default_factory=Fix)
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the shape defined by findings/schema.json."""
        data: dict[str, Any] = {
            "schema_version": self.schema_version,
            "id": self.id,
            "run_id": self.run_id,
            "source": self.source,
            "target": _compact(
                {
                    "kind": self.target.kind,
                    "ref": self.target.ref,
                    "asset_id": self.target.asset_id,
                }
            ),
            "vuln": _compact(
                {
                    "cwe": self.vuln.cwe,
                    "summary": self.vuln.summary,
                    "severity": self.vuln.severity,
                    "cvss": self.vuln.cvss,
                    "reachability": self.vuln.reachability,
                }
            ),
            "proof": _compact(
                {
                    "repro": self.proof.repro,
                    "machine_checkable": self.proof.machine_checkable,
                    "artifact": self.proof.artifact,
                    "evidence": self.proof.evidence,
                }
            ),
            "impact": self.impact,
        }
        fix = _compact(
            {
                "suggestion": self.fix.suggestion,
                "patch_ref": self.fix.patch_ref,
                "test_ref": self.fix.test_ref,
            }
        )
        if fix:
            data["fix"] = fix
        if self.references:
            data["references"] = self.references
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """Parse from the shape defined by findings/schema.json."""
        target = data["target"]
        vuln = data["vuln"]
        proof = data["proof"]
        fix = data.get("fix", {})
        return cls(
            schema_version=data["schema_version"],
            id=data["id"],
            run_id=data["run_id"],
            source=data["source"],
            target=Target(
                kind=target["kind"],
                ref=target["ref"],
                asset_id=target.get("asset_id", ""),
            ),
            vuln=Vuln(
                cwe=vuln.get("cwe", []),
                summary=vuln.get("summary", ""),
                severity=vuln.get("severity", "info"),
                cvss=vuln.get("cvss", ""),
                reachability=vuln.get("reachability", "unknown"),
            ),
            proof=Proof(
                repro=proof["repro"],
                machine_checkable=proof.get("machine_checkable", True),
                artifact=proof.get("artifact", ""),
                evidence=proof.get("evidence", []),
            ),
            impact=data["impact"],
            fix=Fix(
                suggestion=fix.get("suggestion", ""),
                patch_ref=fix.get("patch_ref", ""),
                test_ref=fix.get("test_ref", ""),
            ),
            references=data.get("references", []),
        )


def _compact(mapping: dict[str, Any]) -> dict[str, Any]:
    """Drop empty optional fields so output conforms to additionalProperties:false."""
    return {k: v for k, v in mapping.items() if v not in ("", [], None)}
