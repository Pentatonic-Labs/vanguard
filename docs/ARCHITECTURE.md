# Vanguard — Architecture

> Status: draft v0.1, pre-code. Project: **Pentatonic Vanguard**.
> Scope agreed: narrow wedge (DGX/NVIDIA fleet + autonomous red-team), broadened later via recipes.
> Boundary agreed: three-layer open/closed (see §8).

---

## 1. Positioning

**Problem.** Vulnerability-driven patching is always on the back foot: a flaw must be
found, exploited, and patched before we react. The only way off the back foot is to find
our *own* flaws before attackers do — by continuously red-teaming our own code, services,
and infrastructure.

**Two loops, one system.**

| Loop | Trigger | Speed | Output |
|------|---------|-------|--------|
| Reactive CVM | CVE/KEV/OSV/vendor feed | near-real-time | "this known vuln is in your stack → fix" |
| Proactive red-team | change in code/API/config surface, or on schedule | continuous | "this *unknown* weakness exists → PoC → fix" |

The reactive loop is deterministic software. The proactive loop is an **agent** problem,
and it is the differentiator.

**Wedge.** The v1 target is the NVIDIA fleet stack — DGX Spark (GB10 Grace Blackwell),
RTX PRO 6000 Blackwell workstations, CUDA/cuDNN, NGC base images, Triton/Inference Server,
drivers, firmware. This surface is high-value, opaque, and underserved. Nobody ships a
collector or recipe set for it; we do, and we are the only contributor who can test
against real hardware.

**Open/closed.** Three layers, settled by decision (§8):
1. **Open — the defense:** CVM, scanners, inventory, fixer, recipes, finding schema.
2. **Open — the neutral scaffolding:** sandbox spec, finding schema, "prove it" harness.
3. **Private — the autonomous attacker:** the attacker model and full exploitation
   orchestrator, pluggable, run locally against our own fleet.

---

## 2. System overview

```
                    ┌─────────────────────────── REACTIVE ───────────────────────────┐
 CISA KEV ─┐        │                                                                │
 OSV.dev ──┤        ▼                                                                │
 NVD ──────┼──► ingest ──► normalize ──► queue ──► match(SBOM) ──► triage ──► fixer ─┼─► PR / auto-apply
 vendors ──┘                 (poll 1–15m + webhooks)                                 │
                                                                                     │
                    ┌─────────────────────────── PROACTIVE ──────────────────────────┐
 code/API/config ──► surface change event ──► redteam harness ──► sandbox replica     │
   (on merge/deploy)                          (pluggable attacker)    (ephemeral,      │
                                                                       isolated)       │
                                    │  enumerate → probe → PROVE → document            │
                                    ▼                                                  │
                              finding (PoC-backed) ──► human review ──► fixer ──► PR   │
                                                                                     │
                                    └── feeds back into cvm-core as a watched signal ──┘
```

Everything is event-driven. There is no polling-only bottleneck on the reactive side
(KEV ~5m, OSV ~1m+webhooks, vendor feeds ~15m), and the proactive side triggers on
**change**, not on a timer.

---

## 3. Modules

### 3.1 `cvm-core` — the reactive engine
- **ingest**: adapters for CISA KEV (JSON), OSV.dev (API + repo webhooks), NVD 2.0,
  vendor feeds (Ubuntu USN, RedHat, Debian DSA, Microsoft MSRC), GitHub Advisories.
- **normalize**: one internal vuln record regardless of source. Canonical fields:
  `id`, `purl[]`/`cpe[]`, `affected_range[]`, `severity`, `cvss`, `epss`, `kev`, `exploit_status`.
- **match**: vuln record → SBOM purls → precise ecosystem version-range matching
  (OSV-style), not CPE string matching.
- **triage**: score = `kev` + `epss` + `reachability` + `asset_criticality`.
  Emits one of: `auto-fix`, `propose`, `alert`.

### 3.2 `inventory` — SBOM + the DGX collector
- Continuous SBOM generation (containers, host packages, app dependencies), CycloneDX/SPDX.
- **DGX collector** (the wedge): enumerates installed NVIDIA drivers, CUDA/cuDNN versions,
  NGC container images and their digests, Triton/Inference Server versions, GPU firmware
  and VBIOS, kernel/driver mismatch state. Outputs purls + a hardware manifest.
- SaaS posture (GitHub / Entra / Cloudflare / Linear): read-only API + config checks.
  **No offensive probing against SaaS** — posture review only, by design.

### 3.3 `recipes` — the plugin interface
A recipe is declarative (YAML) and answers four questions: *what to collect, how to
match, how to triage, how to remediate* — plus optionally *how to red-team it*. v1 recipes:
`dgx`, `container`, `python-deps`, `web-service`, `saas-posture`. The engine interprets
recipes; extensibility does not require writing engine code.

### 3.4 `redteam` — the proactive harness
- **harness**: gives an agent a bounded toolset (shell, HTTP client, browser, code read,
  DB read) pointed at a **replica** of a target. Posture: "enumerate attack surface,
  find a weakness, *prove it*, stop and document."
- **attacker slot**: the model itself is a pluggable interface (`Attacker`), swapped per
  deployment. The repo ships with a stub/reference in find-and-report mode; the
  production-capable attacker (local abliterated model) is private.
- **proof gate**: a finding is not accepted unless it carries a reproducible PoC. No
  PoC = no finding; it is quarantined as a *lead*, not reported as a vulnerability.

### 3.5 `fixer` — finding → patch → regression test → PR
- Emits a patch, a regression test that demonstrates the flaw, and a PR.
- Auto-apply only for low-blast-radius changes (dependency bump, image rebuild) gated on
  green CI. Everything else is *propose + human approve*. Infra/kernel/driver changes are
  never auto-applied.
- Every action is audited; the fixer is a privileged committer and is treated as one.

### 3.6 `findings` — the schema (the reusable artifact)
See §5. The schema is deliberately standalone so it can be adopted independent of the engine.

---

## 4. Data flow

**Reactive:** feed → ingest → normalize → queue → match(SBOM) → triage →
`auto-fix`(fixer) / `propose`(PR) / `alert`.

**Proactive:** code/API/config change (merge/deploy hook) → harness spins an ephemeral
replica → attacker enumerates/probes → proof gate → finding → human review → fixer → PR.

**Feedback:** every finding (red-team or CVE) becomes a watched signal in `cvm-core`, so
the same weakness is continuously re-scanned and can't regress silently.

---

## 5. Finding schema

Anti-hallucination is a hard requirement: a finding is a *proven* vulnerability, not a
claim. Sketch:

```json
{
  "schema_version": "1.0",
  "id": "uuid",
  "run_id": "uuid",
  "source": "redteam-agent",
  "target": {
    "kind": "web-service | container | code | infra | saas-config",
    "ref": "purl | cpe | url",
    "asset_id": "..."
  },
  "vuln": {
    "cwe": ["CWE-89"],
    "summary": "...",
    "severity": "critical",
    "cvss": "9.8",
    "reachability": "confirmed"
  },
  "proof": {
    "repro": "one command/script that reproduces the flaw",
    "artifact": "sha256 of PoC artifact",
    "evidence": ["log line", "http response", "..."],
    "machine_checkable": true
  },
  "impact": "...",
  "fix": { "suggestion": "...", "patch_ref": "commit/pr", "test_ref": "regression test" },
  "references": []
}
```

Interop: vuln records map to OSV; code findings can export to SARIF; inventory exports to
CycloneDX. We do not reinvent those wheels; we define only the *red-team finding* layer
that none of them cover.

---

## 6. Sandbox isolation

**Hardware correction (from earlier discussion):** MIG is a data-center-GPU feature
(A100/H100/H200/B200). It is **not** available on DGX Spark (GB10, single-GPU unified
memory) or RTX PRO 6000 Blackwell (workstation). Do not design around MIG.

Realistic isolation for this fleet:

1. **Dedicate a card or a whole box** to the red-team sandbox (we have ~10 Sparks; the
   RTX box has 3 cards). Card/box-level dedication is the isolation boundary that matters.
2. **Containers** via the NVIDIA Container Toolkit for everything the agent can reach.
3. **Egress control**: a proxy allowlist; no default outbound. All agent traffic is logged.
4. **Ephemeral replicas**: target clones seeded with fake data, no real secrets, no prod
   credentials, destroyable per-run. Secrets are injected as mocks, never as prod values.
5. Optional stronger isolation later: gVisor / Firecracker for the agent's own VM.
6. **Target authorization**: the harness refuses to run against anything it cannot prove
   we own (pinned to an allowlisted asset inventory). This is a speed bump, not a
   guarantee — see §11.

---

## 7. Recipe interface

Declarative, interpreted by the engine. Sketch:

```yaml
recipe:
  id: dgx-firmware
  version: 1
  target_kinds: [infra]
  collect:
    - nvidia_drivers
    - cuda_runtime
    - ngc_images
    - gpu_firmware
  match:
    source: [cve, osv, vendor:nvidia]
    purl_prefix: "pkg:generic/nvidia"
  triage:
    kev_weight: high
    epss_threshold: 0.5
  remediate:
    auto_apply: false            # infra — never auto
    propose: "pr"
  redteam:
    enabled: true
    posture: "firmware/driver misconfiguration and version-downgrade attacks"
```

v1: recipes are data + engine interpretation. v2 (community-contributed logic): WASM
sandbox (wasmtime) so untrusted recipe code can't escape. Do not build code plugins in v1.

---

## 8. Repo & org structure (open vs closed)

**Open (public):**
- `cvm-core`, `inventory` (incl. DGX collector), `recipes`, `findings`, `fixer`
- `redteam` harness in **find-and-report** mode + the sandbox spec
- the finding schema and recipe format (published standalone, versioned)

**Private (internal):**
- the production attacker model + full autonomous exploitation orchestrator
- fleet deployment configs, DGX connector secrets, internal asset inventory

The boundary is not "capability vs no capability" — it is "safety rails are the product."
The open project gives anyone the safe container to run *their own* attacker against
*their own* infra. The attacker itself is a pluggable, private slot.

---

## 9. Recommended tech stack

| Layer | Choice | Rationale |
|-------|--------|-----------|
| `cvm-core` / `inventory` / `fixer` | **Go** | single static binary; ecosystem parity with Trivy/Grype/Syft/osv-scanner |
| `redteam` harness | **Python** | LLM/agent tooling (MCP), fast iteration |
| State | **Postgres** | findings, inventory, runs, audit |
| Artifacts | CycloneDX (SBOM), OSV (vulns), own schema (findings) | interop over invention |
| Messaging | Postgres-backed queue in v1 | Kafka/NATS is premature infra |
| Sandbox | containers + NVIDIA Container Toolkit + egress proxy | §6; gVisor/Firecracker later |

---

## 10. v1 scope & non-goals

**In scope:** the five recipes above; DGX collector; reactive CVM end-to-end;
red-team harness with a reference attacker in find-and-report mode; finding schema;
fixer with `auto-fix` limited to dependency/image bumps.

**Non-goals for v1:**
- Broad package/ecosystem coverage beyond shipped recipes (PHP/HTML/etc. come later, by demand)
- Auto-apply of infra/kernel/driver patches
- Offensive probing of SaaS (posture/config-only)
- Shipping a maximally-capable autonomous attacker as open source
- Kafka/NATS, WASM recipe sandbox, gVisor/Firecracker (all v2)

---

## 11. Decisions & open questions

**Resolved (2026-10-24):**

- **Name**: Vanguard — published as "Pentatonic Vanguard" under the `Pentatonic-Labs`
  GitHub org (kept separate from the commercial `Pentatonic-Ltd` org).
- **License**: Apache-2.0.
- **Finding schema**: standalone, with OSV/SARIF/CycloneDX interop.
- **Target authorization**: attestation gate from day one — a signed inventory claim, not
  a self-asserted string; hardened further post-v1.
- **Publish the sandbox spec as a standalone standard**: yes ("Red Team Sandbox Spec").
- **Stack**: Go (`cvm-core`/`inventory`/`fixer`), Python (`redteam` harness), Postgres.
- **Scheduling**: reactive CVM is CPU-only and always-on; red-team runs are GPU-bursty,
  triggered on merge/deploy plus a nightly sweep (§6).

**Still open:**

1. Repo slug under the org (defaulted to `vanguard`; trivially renamable).
2. CI/deploy credential model: GitHub App vs scoped PAT (flag only — not blocking v1).

---

## 12. Next steps (proposed)

1. Decide the five open questions (§11).
2. Scaffold the repo (Go core + Python harness) with the module layout in §3.
3. Ship `inventory` + DGX collector first — it is the wedge, it is testable on real
   hardware, and every other module depends on it.
4. Then `cvm-core` (reactive loop) end-to-end, then `redteam` harness, then `fixer`.
