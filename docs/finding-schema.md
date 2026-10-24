# Vanguard Finding Schema

The standalone, versioned schema for a Vanguard **finding**: a security weakness in your
own stack that the red-team harness has *proven*, not merely claimed.

A finding is produced by the proactive red-team loop and consumed by the `fixer` and by
`cvm-core` (where it becomes a continuously re-scanned signal). The schema is deliberately
self-contained so it can be adopted independently of the Vanguard engine.

## The proof gate (the core rule)

A finding MUST carry a **machine-checkable proof**. Concretely:

- `proof.repro` is **required** — a single command or script that reproduces the flaw.
- `proof.machine_checkable` is **required** and MUST be `true` (enforced with `const: true`).

A report that cannot be reproduced by machine is not a finding; it is a *lead*, and it is
quarantined rather than reported. This rule exists to stop an LLM attacker from
hallucinating vulnerabilities: **no PoC, no finding.**

## Schema

- Canonical `$id`: `https://pentatonic.com/vanguard/schemas/finding.schema.json`
- Dialect: JSON Schema draft 2020-12
- Version: `1.0`
- Strictness: `additionalProperties: false` at every level — unknown fields are rejected.

## Field reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | string | yes | Schema version (`1.0`). |
| `id` | uuid | yes | Stable unique identifier for this finding. |
| `run_id` | uuid | yes | Identifier of the red-team run that produced it. |
| `source` | string | yes | Producer, e.g. `redteam-agent`. |
| `target` | object | yes | What the finding is about. |
| `target.kind` | enum | yes | `web-service` \| `container` \| `code` \| `infra` \| `saas-config`. |
| `target.ref` | string | yes | Reference to the target: purl, CPE, URL, or path. |
| `target.asset_id` | string | no | Inventory asset that owns this target. |
| `vuln` | object | yes | The vulnerability itself. |
| `vuln.cwe` | string[] | yes | One or more `CWE-` identifiers. |
| `vuln.summary` | string | yes | One-line description. |
| `vuln.severity` | enum | yes | `critical` \| `high` \| `medium` \| `low` \| `info`. |
| `vuln.cvss` | string | no | CVSS v3.1 vector string or base score. |
| `vuln.reachability` | enum | yes | `confirmed` \| `potential` \| `not-reachable` \| `unknown`. |
| `proof` | object | yes | The proof. **Gate enforced here.** |
| `proof.repro` | string | yes | One command/script that reproduces the flaw. |
| `proof.artifact` | string | no | SHA-256 of the PoC artifact. |
| `proof.evidence` | string[] | no | Log lines, HTTP responses, etc. |
| `proof.machine_checkable` | boolean | yes | MUST be `true`. |
| `impact` | string | yes | Business/technical impact. |
| `fix` | object | no | Proposed remediation. |
| `fix.suggestion` | string | no | Human-readable remediation. |
| `fix.patch_ref` | string | no | Commit/PR reference for the patch. |
| `fix.test_ref` | string | no | Reference to the regression test. |
| `references` | uri[] | no | External references (CVE, advisory URLs). |

## Interop

The finding schema does not replace existing standards; it layers on top of them:

- **Vulnerability records → OSV.** When a finding corresponds to a known CVE, the
  `references` array carries the CVE/OSV identifier, and `cvm-core` links the finding to
  the OSV record rather than duplicating its data.
- **Code findings → SARIF.** A `code` finding can be exported to SARIF for consumption by
  code-scanning UIs; the finding is the source of truth, SARIF is a rendering.
- **Inventory → CycloneDX.** `target.ref` uses purls and CPEs that resolve against the
  CycloneDX/SPDX SBOM produced by `inventory`.

## Example

```json
{
  "schema_version": "1.0",
  "id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  "run_id": "6ba7b811-9dad-11d1-80b4-00c04fd430c8",
  "source": "redteam-agent",
  "target": {
    "kind": "web-service",
    "ref": "pkg:docker/nvidia/tritonserver@sha256:0123456789abcdef",
    "asset_id": "dgx-07"
  },
  "vuln": {
    "cwe": ["CWE-89"],
    "summary": "SQL injection in the /query endpoint via the 'name' parameter.",
    "severity": "critical",
    "cvss": "9.8",
    "reachability": "confirmed"
  },
  "proof": {
    "repro": "curl 'https://replica/query?name=1%27%20OR%20%271%27%3D%271'",
    "artifact": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "evidence": ["HTTP 200 returned rows outside the allowed scope"],
    "machine_checkable": true
  },
  "impact": "Unauthenticated attacker can read the entire database.",
  "fix": {
    "suggestion": "Use parameterized queries in the /query handler.",
    "patch_ref": "https://github.com/Pentatonic-Labs/vanguard/pull/1",
    "test_ref": "tests/test_query_injection.py"
  },
  "references": ["https://cwe.mitre.org/data/definitions/89.html"]
}
```

## Versioning

Schema versions follow `MAJOR.MINOR`. `1.0` is the initial version. Breaking changes
(adding required fields, changing `const` values) bump MAJOR; additive, backward-compatible
changes bump MINOR. `schema_version` is a plain string so future minor versions remain valid.
