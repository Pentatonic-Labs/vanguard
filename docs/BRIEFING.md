<p align="center">
  <img alt="Pentatonic Labs" src="https://pentatonic.com/img/lab/pentatonic-labs-white.png" height="32">
</p>

# Vanguard

**Continuous vulnerability management and autonomous red-teaming for NVIDIA DGX / GB10-class systems.**

Vanguard finds weaknesses in *your own* stack before attackers do — and proves them.

---

## The problem

AI infrastructure has a new attack surface. The known CVEs in your base images and
drivers are only part of the risk; the *unknown* weaknesses — especially against the
LLM agents you now run in production — are where a motivated attacker goes next.

Two things are true at once:

1. **Known vulns are a grind.** CISA KEV, OSV, NVD, and vendor feeds are noisy, and
   matching them against your *actual* running stack (correct Debian version ordering,
   reachability, OS scoping) is error-prone manual work.
2. **Unknown vulns are invisible.** Nobody is adversarially probing your own agentic
   services the way an attacker will — patiently, deviously, until something gives.

Vanguard closes both.

## The two loops

| Loop | Question it answers | How |
|------|---------------------|-----|
| **Reactive CVM** | "Which *known* vulns are in my stack right now?" | Ingest KEV / OSV / NVD / vendor → match against installed packages → triage → propose verified fixes |
| **Proactive red-team** | "What *unknown* weaknesses can an attacker find — and prove?" | A frontier-model agent attacks a faithful replica of your own service until it finds a weakness with a machine-checkable proof |

## Why it's different

- **A frontier-model attacker, not a scanner.** The red-team agent *acts, observes, and
  decides the next step* — it doesn't just replay a wordlist. It's told to be devious
  and unrelenting, to enumerate and chain findings, the way a real adversary behaves.
- **Deterministic proof, not model confidence.** The harness — not the model — detects
  compromise and proves it. Every finding re-executes its repro before it's accepted;
  unverified claims are rejected.
- **Semantic proof for agentic attacks.** Prompt-injection and objective-injection
  findings are machine-verified by checking the response *content* (did the agent
  escalate? leak its instructions?), not just an HTTP status code.
- **Hardened by design.** The attacker's toolset is bounded — HTTP to the target only,
  no shell, no filesystem, hard step caps — so it can never escape to anything it
  isn't authorized to touch. Threat model and security policy included.

## What it found on our own stack

Pointing Vanguard at a faithful replica of Pentatonic's own control plane, the
red-team agent machine-proved an **agentic prompt-injection escalation** — where
carefully-phrased input slips past the intent guard and becomes the agent's objective —
and surfaced a **reproducible worker crash** in the authentication path. Both were
filed and are being fixed. (Specifics are internal.)

This is the point: Vanguard found real, non-obvious weaknesses in our *own*
production-grade system — weaknesses a conventional scanner would never have seen.

## Get started

```sh
git clone https://github.com/Pentatonic-Labs/vanguard.git
cd vanguard

# reactive CVM against the machine you're on
go run ./cmd/vanguard scan

# hardware inventory (driver, CUDA, cuDNN, GPU firmware, NGC, Grace/GB10, DPU)
go run ./cmd/vanguard inventory

# proactive red-team against the in-repo demo target
make dogfood        # needs a model key (any OpenAI-compatible endpoint)

# local read-only dashboard
make ui             # http://127.0.0.1:8080
```

Requires Go 1.22+ and Python 3.10+. Apache-2.0.

## Built to be shared

Vanguard is open source so you can run it on *your* systems and *your* projects. It's
bounded, honest, and safe to dogfood — never production, always against a replica.

---

<p align="center"><em>Built by <a href="https://pentatonic.com">Pentatonic Labs</a>.</em></p>
