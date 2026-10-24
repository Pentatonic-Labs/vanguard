# Threat model

This document describes what Vanguard trusts, its attack surface, and — just as
important — what it does *not* protect against. It is intended to be read by
anyone deploying or reviewing Vanguard.

## What Vanguard is

Vanguard is a defensive tool for *your own* stack. It ingests vulnerability
feeds, matches them against your software inventory, and proposes (and, in a
narrow, gated set of cases, applies) fixes. It is not an attacker, and the
offensive capability it coordinates is deliberately kept private.

## What it trusts

- **The upstream feeds** (OSV.dev, NVD, CISA KEV, vendor advisories) are treated
  as *untrusted input*. A compromised or malicious feed could supply false or
  malformed data, so every parser must be robust: no panics on malformed input,
  size caps on responses and archives, and fuzz coverage on the parsers.
- **The local host** (output of `nvidia-smi`, `dpkg-query`, `docker`, etc.) is
  trusted as a read-only inventory source.
- **Operator credentials** (`NVD_API_KEY`, `VANGUARD_*_TOKEN`) are read only from
  the environment, never logged, and redacted from every error path.

## Attack surface

1. **Untrusted input parsing** — feeds, package manifests, container/image
   metadata. Mitigations: stdlib-only parsers, response/archive size caps,
   fuzz tests.
2. **Command execution** — the collectors shell out to `nvidia-smi`, `docker`,
   `dpkg-query`, etc., and the fixer's verifier runs build/test/lint commands.
   These must only ever run against the *operator's own, reviewed* code, never
   against attacker-influenced input or untrusted repositories.
3. **Credential handling** — tokens must never reach logs, error messages, or
   committed files.
4. **The red-team harness** — runs an attacker model with a bounded toolset
   against a target. It MUST target an ephemeral replica, never production, and
   it is gated by target attestation (see docs/sandbox-spec.md).

## What it protects against

- Known CVEs present in your installed software (purl/CPE + version-range
  matching, with correct Debian version ordering).
- Missing or weak SaaS posture for GitHub / Entra / Cloudflare / Linear
  (read-only checks).
- (Planned) red-team findings that carry a machine-checkable proof.

## What it does NOT protect against

- **Zero-days** the feeds do not yet know about.
- **Runtime regressions from a fix** that pass the test suite but break in
  production — this is what canary deployment and rollback are for; no dry-run
  can prove a fix is behaviorally identical.
- **A compromised upstream feed** supplying false vulnerability data.
- **The operator's own misconfiguration** — e.g. pointing the harness at a live
  service, or running the verifier against untrusted code.

## Design invariants

- No fix is applied without passing the dry-run gate (isolated copy + build /
  test / lint).
- Auto-apply is **default-deny**: low/medium severity, machine-checkable proof,
  and a dependency-bump suggestion are all required; everything else is
  propose-and-human-approve.
- The red-team attacker is a private, pluggable slot; the open repository ships
  only a `NoopAttacker` stub.

## Open items (known, tracked)

- CPE→package matching is a heuristic first cut (fuzzy vendor/product naming).
- Reachability analysis is a placeholder (`Reachable` is hardcoded false).
- NVD ingestion requires an API key and rate-limit backoff; it degrades
  gracefully (warn-and-skip) when unavailable.
