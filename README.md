<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://pentatonic.com/img/lab/pentatonic-labs-white.png">
  <img alt="Pentatonic Labs" src="https://pentatonic.com/img/lab/pentatonic-labs-black.png" height="36">
</picture>

# Pentatonic Vanguard

![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-ff4c00?style=flat-square)
![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-171717?style=flat-square)

**Continuous vulnerability management and autonomous red-teaming.** Vanguard finds
weaknesses in *your own* stack before attackers do — and fixes them.

## The two loops

| Loop | Trigger | Question it answers |
|------|---------|---------------------|
| **Reactive CVM** | CVE / CISA KEV / OSV / vendor feeds | "Which *known* vulns are in my stack right now?" |
| **Proactive red-team** | you point it at a replica | "What *unknown* weaknesses can an attacker find — and prove?" |

## Quick start

The reactive loop works out of the box against real data. Run it against the machine
you're on:

```sh
go run ./cmd/vanguard scan
```

It fetches CISA KEV and the OSV export for your OS, matches them against your
installed packages (with correct Debian version ordering and OS-release scoping), and
prints plain-English remediation proposals:

```
CVE-2024-5535 (critical, CVSS 9.8)
  Package: openssl (installed 3.0.13)
  Status: loaded by a running process
  Fix: upgrade openssl to >= 3.0.16
  Action: propose
```

Or poll continuously and report only *new* findings:

```sh
go run ./cmd/vanguard watch -interval 1h
```

Requires Go 1.22+. The first run downloads the OSV export (~800 MB); after that it is
cached (and the parsed result is cached too).

## Red-teaming your own service

The red-team half attacks a **replica** of your service — never production. It uses a
bounded, iterative attacker (an LLM that probes over HTTP and hunts to get in), and a
proof gate that re-executes every finding's repro so unverified claims are downgraded.

```sh
cd redteam
DEEPSEEK_API_KEY=... uv run python - <<'PY'
from redteam.api_attacker import APIAttacker
from redteam.verify import verify_repro

attacker = APIAttacker(seed_paths=["/", "/health", "/login"])
claims = attacker.attack("http://localhost:3000")
for f in claims:
    ok, reason = verify_repro(f)
    print(("VERIFIED " if ok else "DOWNGRADED "), f.vuln.severity, "-", f.vuln.summary)
PY
```

- Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/).
- `DEEPSEEK_API_KEY` (or any OpenAI-compatible endpoint via `APIAttacker(base_url=..., model=...)`).
- The attacker's toolset is bounded: HTTP to the target only, no shell, no filesystem.

## Install

```sh
go install github.com/Pentatonic-Labs/vanguard/cmd/vanguard@main
# or build a local binary:
#   go build -o vanguard ./cmd/vanguard
```

## Layout

- `cvmcore/` — reactive CVM: ingest → normalize → match → triage, plus `fetch`/`pipeline`
- `inventory/` — SBOM generation, the DGX collector, and runtime reachability
- `fixer/` — manifest-precise fixes with a dry-run verification gate
- `findings/` — the finding schema
- `posture/` — read-only SaaS posture checks (GitHub / Entra / Cloudflare / Linear)
- `redteam/` — the red-team harness (Python): attacker, attestation, proof gate, sandbox
- `docs/` — architecture, threat model, and the spec docs

## Security

This is a security tool; we take it seriously. See [`SECURITY.md`](SECURITY.md) for how to
report a vulnerability in Vanguard itself, and [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md)
for what it trusts and what it does *not* protect against.

## License

Apache-2.0. See [LICENSE](LICENSE).

---

Built by [Pentatonic Labs](https://pentatonic.com).
