# Demo target + dogfood run

An intentionally-vulnerable HTTP service that ships with Vanguard so you can run the
red-team attacker locally without touching a real service. It has three deliberate
flaws matching the technique playbook:

| Flaw | Endpoint | Playbook technique |
|------|----------|--------------------|
| IDOR (leaks PII/SSN, no authz) | `GET /users/<id>` | idor |
| JWT `alg=none` accepted | `POST /login` | jwt_none |
| Arbitrary file read | `GET /files?name=<path>` | traversal |

**DO NOT DEPLOY.** Stdlib only, no dependencies.

```sh
# terminal 1 — start the target on a free port
python3 demo_target.py 3456

# terminal 2 — run the frontier-model agentic attacker against it
cd .. # to redteam/
DEEPSEEK_API_KEY=... uv run python demo/run_attack.py http://localhost:3456 10
```

The attacker seeds its context with the baseline + playbook probes, then acts,
observes, and decides the next step, and only reports a finding whose repro
re-executes successfully. A representative run found the IDOR and the file read with
verified `curl` repros in ~15 seconds.
