<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://pentatonic.com/img/lab/pentatonic-labs-white.png">
  <img alt="Pentatonic Labs" src="https://pentatonic.com/img/lab/pentatonic-labs-black.png" height="36">
</picture>

# Pentatonic Vanguard

![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-ff4c00?style=flat-square)
![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-171717?style=flat-square)

**Continuous vulnerability management and autonomous red-teaming for NVIDIA/DGX fleets.**

Vanguard finds weaknesses in *your own* stack before attackers do — and fixes them.

## The two loops

| Loop | Trigger | Question it answers |
|------|---------|---------------------|
| **Reactive CVM** | CVE / CISA KEV / OSV / vendor feeds | "Which known vulns are in my stack right now?" |
| **Proactive red-team** | code/API/config change, or nightly sweep | "What unknown weaknesses can an attacker find — and prove?" |

The reactive loop is deterministic software. The proactive loop is an agent that attacks
an ephemeral replica of your service, **proves** each finding with a reproducible PoC, and
feeds the result back into the fix pipeline.

## Why Vanguard

- **DGX/NVIDIA-first** — a collector for drivers, CUDA/cuDNN, NGC images, Triton/Inference
  Server, and GPU firmware; a surface almost nobody covers.
- **Proof, not vibes** — a finding is only reported if it carries a machine-checkable PoC.
- **Open defense, private attacker** — the CVM, scanners, and fix pipeline are open source;
  the attacker model is a pluggable slot you run against your own fleet.

## Status

Pre-alpha. Architecture and module design live in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). No runnable code yet.

## License

Apache-2.0. See [LICENSE](LICENSE).

---

Built by [Pentatonic Labs](https://pentatonic.com).
