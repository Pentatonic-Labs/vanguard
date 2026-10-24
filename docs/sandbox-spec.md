# Red Team Sandbox Spec

**Status:** Draft v0.1 (proposed standard)
**Project:** Pentatonic Vanguard
**License:** Apache-2.0

This document is a standalone, adoptable specification for safely running an autonomous
red-team agent against infrastructure you own. It defines the minimum safety properties a
sandbox MUST provide before an autonomous attacker is permitted to run, and the lifecycle
and audit requirements that make a run trustworthy and reviewable.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD
NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

---

## 1. Purpose and scope

An autonomous red-team agent is a model that actively probes a target — enumerating
attack surface, sending crafted requests, attempting exploitation — in order to find
weaknesses before an adversary does. Because the agent is *autonomous*, the sandbox is
not a convenience; it is the security boundary that makes the activity safe to automate.

This spec covers:

- The isolation model an agent MUST run inside.
- How a target MUST be authorized before the agent may touch it.
- The proof gate a finding MUST pass before it is reported as a vulnerability.
- The run lifecycle and audit trail.

This spec does **not** define:

- How the attacker model itself is built, chosen, or prompted.
- How fixes are applied (that is the fixer's job, out of scope here).
- Offensive probing of SaaS or third-party systems (which is prohibited; see §9).

**Audience.** Anyone operating an autonomous red-team loop, and anyone implementing a
sandbox that claims to comply with this spec.

---

## 2. Terminology

- **Operator** — the human or team that owns the target and authorizes the run.
- **Harness** — the software that provisions the sandbox, runs the attacker, enforces the
  proof gate, and records the audit trail.
- **Attacker** — the autonomous model (the pluggable component) that enumerates and probes
  the target.
- **Target** — the system under test: a codebase, web service, container image, or
  infrastructure configuration.
- **Replica** — an ephemeral copy of the target that the attacker is actually pointed at.
- **Finding** — a vulnerability claim that has passed the proof gate (§6).
- **Lead** — an unproven vulnerability claim, quarantined and never reported as a finding.

---

## 3. Threat model

The sandbox exists to contain two things:

1. **The attacker's actions** — the agent is autonomous and may attempt anything it can
   reach. The sandbox MUST constrain *blast radius*, not intent.
2. **The attacker's escape** — if the agent (or the model driving it) is compromised or
   misbehaves, the sandbox MUST limit what it can reach outside the replica.

What the sandbox protects against:

- An agent probing or exploiting the production target instead of the replica.
- An agent reaching other hosts, services, or the internet.
- An agent reading real secrets, credentials, or production data.
- A finding that is a hallucination or a claim without evidence.

What the sandbox does **not** protect against, by itself:

- A fully **escaped attacker** (a compromised model/runtime that breaks out of its
  container and gains host privileges). The container boundary is one layer, not a
  guarantee. Operators MUST assume an escape is possible and design the blast-radius
  controls (§4.1, §4.3) so that even an escaped agent lands in an isolated environment
  with no credentials and no egress.
- The **attacker model being malicious in ways a sandbox cannot see** (e.g., exfiltrating
  findings it was allowed to read). The audit trail (§8) detects this after the fact; the
  data-minimization rule (§4.4) limits its impact.
- **Operator misconfiguration** (e.g., pointing the agent at production). Authorization
  (§5) is a gate, but a gate is only as good as the inventory it checks against.

The spec treats the sandbox as defense-in-depth: no single control is assumed to hold;
each layer reduces blast radius if the previous one fails.

---

## 4. Isolation model

### 4.1 Hardware isolation (no MIG)

Autonomous red-team runs are GPU-bursty: the attacker model and, when red-teaming a
model-serving stack, the replica itself need a GPU.

- **MIG is not available** on DGX Spark (GB10, single-GPU unified memory) or RTX PRO 6000
  Blackwell (workstation). A compliant implementation MUST NOT rely on MIG for isolation.
- Hardware isolation MUST be **card-level or box-level dedication**: a run MUST be given a
  dedicated GPU card, or a dedicated whole box, that is not shared with production
  workloads for the duration of the run.
- The dedicated device MUST be attached only to the sandbox environment (see §4.2) and
  MUST be released back to the pool when the run is torn down (§7).
- Where a card must be shared (e.g. small fleets), time-slicing (NVIDIA MPS) MAY be used,
  but only when the card is otherwise idle and never concurrently with production. Box
  dedication is RECOMMENDED over card sharing.

### 4.2 Process and container isolation

- The attacker MUST run inside a container (or a stronger boundary — a VM, gVisor, or
  Firecracker) created for the run.
- The container MUST be created with the NVIDIA Container Toolkit only where a GPU is
  actually required; a code-only or web-service target SHOULD run without GPU access.
- The container MUST run with the least privilege: no host network namespace, a read-only
  root filesystem where possible, a non-root user, and no privileged capabilities.
- The replica MUST run in a separate network namespace from the attacker where the target
  topology allows it, so the attacker reaches the replica only through the intended path.

### 4.3 Network egress control

- The sandbox MUST have an **egress allowlist proxy**. Default-deny: no outbound traffic
  unless explicitly allowed.
- Allowed egress SHOULD be limited to: the replica itself, and any package/tool mirrors
  the attacker needs, pinned by host. Internet access MUST be denied by default and MAY be
  enabled only for explicit, logged destinations.
- All agent network traffic MUST be logged (see §8). DNS MUST resolve only through the
  allowlist proxy.

### 4.4 Ephemeral replicas and secrets

- The attacker MUST be pointed at a **replica** of the target, never at production.
- The replica MUST be ephemeral: created for the run and destroyed at the end of the run.
- The replica MUST be seeded with **fake data**. It MUST NOT contain real secrets,
  credentials, PII, or production data.
- Any secret the replica needs MUST be injected as a **mock** (clearly-fake values), never
  a production value. A compliant harness MUST refuse to start if it detects a production
  credential in the replica.
- Data minimization: the replica SHOULD contain the minimum data needed to exercise the
  target, not a full production clone.

---

## 5. Target authorization (attestation gate)

The harness MUST refuse to run against a target it cannot prove the operator owns. A
self-asserted string ("this is my server") is not authorization.

- The harness MUST maintain an **allowlisted asset inventory** — a signed list of targets
  (by identifier, e.g. purl, CPE, host identity, or repo URL) that the operator owns.
- A target is authorized only if it appears in the inventory **and** the inventory entry is
  covered by a **signature** the harness verifies. The signing key MUST be held by the
  operator, not the attacker.
- The harness MUST verify the target's identity (e.g. host key, repo commit, container
  digest) against the inventory claim before provisioning, and MUST abort the run on any
  mismatch.
- A compliant implementation SHOULD bind the authorization to the specific run (a short-
  lived, signed run grant derived from the inventory claim), so a stolen claim cannot be
  replayed.

This is an attestation gate, not a cryptographic proof of ownership against a determined
adversary who forges inventory entries. Operators MUST treat it as one layer of
defense-in-depth, per §3.

---

## 6. Proof gate

The proof gate is what separates a **finding** from a hallucination. It is the single most
important quality control in the loop.

- A claim MUST NOT be reported as a finding unless it carries a **machine-checkable
  proof of concept (PoC)**.
- A PoC MUST include a reproduction procedure (`repro`) that, when executed against the
  replica, reproduces the weakness deterministically, and one or more evidence artifacts
  (command output, HTTP response, log lines).
- The harness MUST be able to re-run the PoC itself. If the harness cannot reproduce the
  claim, the claim MUST be downgraded to a **lead** and MUST NOT be reported as a finding.
- The finding schema MUST require `proof.repro` and `proof.machine_checkable` (see the
  Vanguard finding schema) for a finding to be valid.
- Unproven claims MUST be quarantined (logged, tagged as leads) rather than silently
  discarded, so they can be reviewed by a human.

Rationale: an autonomous attacker's primary failure mode is confident, plausible output
that is not true. Requiring a reproducible PoC is what makes automation safe to trust.

---

## 7. Run lifecycle

Every run MUST follow the lifecycle below, and each transition MUST be recorded in the
audit trail (§8).

```
authorize ──► provision ──► run ──► prove ──► report ──► destroy
```

1. **Authorize** — verify the target against the signed inventory claim (§5). Abort on
   mismatch.
2. **Provision** — allocate the dedicated card/box (§4.1), create the container(s) (§4.2),
   configure the egress allowlist (§4.3), and build the ephemeral replica with fake
   secrets (§4.4).
3. **Run** — the attacker enumerates and probes the replica. All actions are logged.
4. **Prove** — the harness re-runs each claim's PoC (§6). Claims that reproduce become
   findings; the rest become leads.
5. **Report** — findings and leads are written to the finding store, immutable and
   timestamped.
6. **Destroy** — tear down the replica and container, release the GPU card/box, revoke the
   run's network allowlist entries, and revoke the short-lived run grant (§5). Destruction
   MUST happen even when the run fails, crashes, or times out.

A run MUST be bounded in time; a timeout MUST trigger teardown. An operator MUST be able
to abort a run manually, which MUST trigger the same teardown path.

---

## 8. Audit trail

Every run MUST produce an immutable, tamper-evident audit record covering at minimum:

- The run identity (id, start/end time, operator).
- The authorized target and the inventory claim that authorized it (including the
  signature that was verified).
- The sandbox configuration: device allocation, container image/digest, egress allowlist
  entries, and the replica seed used (fake data, not real values).
- A log of agent actions, including all network requests the agent made.
- The proof-gate outcomes: which claims reproduced and which did not.
- The teardown confirmation.

The audit trail MUST be append-only and SHOULD be signed or hashed so tampering is
detectable. It MUST be retained long enough to review any finding after the fact.

---

## 9. Normative requirements

A conforming implementation MUST:

- Run the attacker in a dedicated GPU card or dedicated box (§4.1), never shared with
  production.
- Contain the attacker in a container or stronger boundary (§4.2).
- Default-deny network egress through an allowlist proxy and log all traffic (§4.3).
- Point the attacker at an ephemeral, fake-data replica, never production (§4.4).
- Authorize targets against a signed, allowlisted inventory claim and abort on mismatch
  (§5).
- Refuse to report a finding without a machine-checkable, re-runnable PoC (§6).
- Follow the full authorize → … → destroy lifecycle, with teardown guaranteed on any
  failure or timeout (§7).
- Produce an immutable audit trail (§8).

A conforming implementation MUST NOT:

- Use MIG as an isolation boundary on DGX Spark or RTX PRO 6000 Blackwell hardware (§4.1).
- Run against production, or inject real credentials into the replica (§4.4, §5).
- Offensively probe third-party systems, SaaS, or any target not in the signed inventory
  (§5).

A conforming implementation SHOULD:

- Dedicate a whole box rather than share a card (§4.1).
- Use a VM or stronger sandbox (gVisor/Firecracker) rather than a plain container (§4.2).
- Bind authorization to a short-lived, signed run grant (§5).
- Sign or hash the audit trail (§8).

---

## 10. Out of scope

- Attacker model selection, prompting, or capability. (The attacker is a pluggable,
  private component; this spec governs the environment around it.)
- Patch generation and application (the fixer).
- Vulnerability-intelligence ingestion (the reactive CVM loop).
- Legal authorization to conduct red-team activity. This spec is a technical safety
  standard; operators remain responsible for obtaining authorization to test the systems
  they point the agent at.

---

## Appendix A. Example run manifest

A conforming run MAY be described by a manifest such as:

```yaml
run:
  id: run_01J...
  operator: alice@example.com
  target:
    kind: web-service
    ref: "https://replica.internal/svc"
    authorized_by: "signed-inventory-claim:sha256:..."
  sandbox:
    device: "box-dgx-spark-03"        # dedicated box; no MIG
    container_image: "vanguard/redteam-harness@sha256:..."
    egress_allowlist: ["replica.internal", "proxy.mirror.internal"]
    replica_seed: "fake-data-v4"       # mocks only, never prod values
  gate:
    proof_required: true
    timeout_minutes: 30
  teardown: "always"                   # on success, failure, crash, or timeout
```
