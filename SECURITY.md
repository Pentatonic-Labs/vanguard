# Security

## Reporting a vulnerability

If you find a security issue in Vanguard itself, please report it privately
rather than opening a public issue:

- Use GitHub's private vulnerability reporting (Security tab → "Report a
  vulnerability") on this repository, or
- Email the maintainers directly.

Please include a description, steps to reproduce, and the affected version(s).
We will acknowledge promptly and coordinate a fix. Reporters who follow
responsible disclosure will be credited.

## Scope — what counts as a Vanguard vulnerability

A report is in scope if it lets an attacker:

- cause Vanguard to give a **wrong verdict** (mark a vulnerable package safe, or
  vice versa), e.g. via a version-comparison or matching bug;
- cause Vanguard to **execute commands or write files** outside its intended
  sandbox (e.g. the fixer's verify gate, the collectors);
- **exfiltrate credentials** Vanguard reads (NVD_API_KEY, VANGUARD_*_TOKEN);
- **escape the red-team sandbox** (see docs/sandbox-spec.md).

## Out of scope

- Bugs in the third-party feeds themselves (OSV.dev, NVD, CISA KEV, vendor
  advisories) — report those upstream.
- Vulnerabilities in the software Vanguard *scans* — those are Vanguard's
  *output*, not its own bugs.
- Misconfiguration of your own deployment (for example, running the red-team
  harness against a live production service instead of a replica).

## What to expect

Vanguard is a defensive tool: it reads vulnerability data and proposes fixes. It
is not an attacker. The two most dangerous components — the red-team attacker
model and the auto-apply path — are deliberately private or gated. See
docs/THREAT-MODEL.md for the full picture.
