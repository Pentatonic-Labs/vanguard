<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://pentatonic.com/img/lab/pentatonic-labs-white.png">
  <img alt="Pentatonic Labs" src="https://pentatonic.com/img/lab/pentatonic-labs-black.png" height="36">
</picture>

# Vanguard

![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-ff4c00?style=flat-square)
![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-171717?style=flat-square)

**Continuous vulnerability management and autonomous red-teaming** for NVIDIA
DGX / GB10-class systems and the agentic services that run on them.

Vanguard finds weaknesses in *your own* stack before attackers do — and proves them.
It runs two loops:

| Loop | What it does | Question it answers |
|------|--------------|---------------------|
| **Reactive CVM** | Ingest CISA KEV / OSV / NVD / vendor feeds, match them against your installed packages, triage, and propose verified fixes | "Which *known* vulns are in my stack right now?" |
| **Proactive red-team** | A frontier-model agent attacks a faithful replica of your service and finds weaknesses with machine-checkable proof | "What *unknown* weaknesses can an attacker find — and prove?" |

> A short, shareable overview lives in [`docs/BRIEFING.html`](docs/BRIEFING.html) (and [`docs/BRIEFING.md`](docs/BRIEFING.md)).

## Commands

| Command | What it does |
|---------|--------------|
| `vanguard scan` | Find known CVEs in the packages on this machine and print plain-English fixes |
| `vanguard watch` | Poll on a cadence; alert on **new findings** *and* when a **patch becomes available** |
| `vanguard inventory` | Inventory the NVIDIA/DGX/GB10 hardware: driver, CUDA, cuDNN, GPU firmware/VBIOS, NGC images, Grace/GB10, MIG, DPU |
| `vanguard fix` | Print the exact `apt-get install --only-upgrade` command for every fixable finding (dry-run — never auto-applies) |
| `vanguard posture` | Read-only security-posture checks: local Tailscale/Tailworm exposure, plus GitHub / Entra / Cloudflare / Linear when their tokens are set |
| `vanguard ui` | Open a local read-only dashboard (inventory + findings from both loops) |
| `make dogfood` | Run both loops at once against this box + the in-repo demo target |
| red-team (Python) | Point the frontier-model agentic attacker at a replica of your service |

## Quick start

The reactive loop works out of the box against real data. Run it against the machine
you're on:

```sh
go run ./cmd/vanguard scan
```

It fetches CISA KEV and the OSV export for your OS, matches them against your installed
packages (correct Debian version ordering, OS-release scoping, runtime reachability),
and prints plain-English proposals:

```
CVE-2024-5535 (critical, CVSS 9.8)
  Package: openssl (installed 3.0.13)
  Status: loaded by a running process
  Fix: upgrade openssl to >= 3.0.16
  Action: propose
```

Poll continuously and get alerted on new findings **and** when a patch lands for a
previously-unfixable CVE:

```sh
go run ./cmd/vanguard watch -interval 1h
```

Inventory the hardware:

```sh
go run ./cmd/vanguard inventory
```

Apply fixes (dry-run first, then a reviewable shell script):

```sh
go run ./cmd/vanguard fix                 # prints the apt commands
go run ./cmd/vanguard fix -script fix.sh  # writes them to a script you review, then sudo
```

Open the dashboard:

```sh
go run ./cmd/vanguard ui   # then open http://127.0.0.1:8080
```

Requires Go 1.22+. The first `scan` downloads the OSV export (~800 MB); after that it
is cached (parsed result too).

## Red-teaming your own service

The red-team half attacks a **replica** of your service — never production. The
frontier-model agent acts, observes, and decides the next step, and only reports a
finding once its repro re-executes successfully:

```sh
cd redteam
uv run python demo/run_attack.py http://localhost:3000
```

It ships with an intentionally-vulnerable demo target so you can see the full loop
immediately:

```sh
cd redteam
python3 demo/demo_target.py 3456 &
uv run python demo/run_attack.py http://localhost:3456
```

For your own service, point it at a replica and (optionally) seed the API surface:

```python
from redteam.agent import AgenticAttacker

agent = AgenticAttacker(
    "http://localhost:3000",
    seed_paths=["/", "/login"],
    # seed full request shapes (e.g. an authenticated chat route) with:
    # seed_probes=[{"method": "POST", "path": "/chat", "body": '{"text":"hi"}'}],
    # default_headers={"Authorization": "Bearer <low-priv-token>"},
)
for f in agent.attack():
    print(f.vuln.severity, "-", f.vuln.summary, "— repro:", f.proof.repro)
```

**How the proof works.** Web findings (IDOR, traversal, SSRF…) are verified by
re-executing the repro and checking the status. **Agentic findings** (prompt injection,
objective injection) are verified *semantically*: the harness detects a compromise
signal in the response (e.g. an escalation verdict) and re-runs the repro to confirm
the response contains it. Findings are never accepted on the model's say-so.

### Model config

The attacker is an OpenAI-compatible client. Configure it via env vars, with a sane
default out of the box:

| Env var | Default |
|---------|---------|
| `VANGUARD_MODEL` | `orca/orcacyber-flash-1.0` (DeepSeek V4.1 Flash, abliterated) |
| `VANGUARD_BASE_URL` | `https://api.orcarouter.ai/v1` |
| `VANGUARD_API_KEY` | your key (also reads `ORCAROUTER_API_KEY`, `~/.config/orca/api_key`, then `DEEPSEEK_API_KEY`) |

Any OpenAI-compatible endpoint works — e.g. set `VANGUARD_BASE_URL=https://api.deepseek.com/v1`,
`VANGUARD_MODEL=deepseek-v4-pro`.

The attacker's prompt is deliberately adversarial (devious, unrelenting, enumerating,
chaining), but the *toolset* stays bounded: HTTP to the target only, no shell, no
filesystem, and a hard step cap.

## Install

```sh
go install github.com/Pentatonic-Labs/vanguard/cmd/vanguard@main
# or build a local binary:
#   go build -o vanguard ./cmd/vanguard
```

## Layout

- `cvmcore/` — reactive CVM: ingest → normalize → match → triage, plus `fetch`/`pipeline`
- `inventory/` — SBOM generation, the DGX/GB10 collectors (drivers, firmware, NGC, platform), and runtime reachability
- `fixer/` — manifest-precise fixes with a dry-run verification gate
- `findings/` — the finding schema (with semantic `expected` proof for agentic findings)
- `posture/` — read-only posture checks: SaaS (GitHub / Entra / Cloudflare / Linear) and the local Tailscale node (Tailworm findings)
- `redteam/` — the red-team harness (Python): agentic attacker, playbook, proof gate, sandbox
- `docs/` — architecture, threat model, spec docs, and the briefing note

## Security

This is a security tool; we take it seriously. See [`SECURITY.md`](SECURITY.md) for how to
report a vulnerability in Vanguard itself, and [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md)
for what it trusts and what it does *not* protect against.

## License

Apache-2.0. See [LICENSE](LICENSE).

---

Built by [Pentatonic Labs](https://pentatonic.com).
