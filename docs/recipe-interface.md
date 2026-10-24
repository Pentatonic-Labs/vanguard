# Recipe Interface Specification

A **recipe** is the declarative unit of extensibility in Vanguard. It answers four
questions — *what to collect, how to match, how to triage, how to remediate* — plus,
optionally, *how to red-team it*. Recipes are data, not code: the engine interprets them,
so extending Vanguard does not require editing engine code.

## Document shape and location

- A recipe is a single YAML document. One recipe per file, stored under `recipes/`
  (community contributors may store recipes in any directory and point the engine at it).
- The filename conventionally matches the recipe `id` (e.g. `recipes/dgx-firmware.yaml`).
- The document root is a mapping holding the recipe fields directly.

## Schema reference

### Top-level fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Stable, unique recipe identifier (e.g. `dgx-firmware`, `python-deps`). |
| `version` | int | yes | Recipe format version. Must be `1` in v1. |
| `target_kinds` | list[string] | yes | Which target kinds this recipe applies to. Values are drawn from the finding schema's `target.kind` enum: `web-service`, `container`, `code`, `infra`, `saas-config`. |
| `collect` | list[string] | yes | Named collectors to run. Each name resolves to a registered collector in the `inventory` module (e.g. `nvidia_drivers`, `cuda_runtime`, `ngc_images`, `gpu_firmware`, `pip_packages`). |
| `match` | mapping | yes | How collected inventory is matched against vulnerability sources. See below. |
| `triage` | mapping | yes | How matched findings are scored and escalated. See below. |
| `remediate` | mapping | yes | How the fixer may respond. See below. |
| `redteam` | mapping | no | Whether and how proactive red-teaming applies to this target. See below. |

### `match`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `source` | list[string] | yes | Vulnerability sources to ingest for matching: `cve` (NVD), `osv` (OSV.dev), or a vendor feed such as `vendor:nvidia`, `vendor:ubuntu`. |
| `purl_prefix` | string | yes | Package-URL prefix used to scope matching. Only inventory purls under this prefix are considered against this recipe's sources (e.g. `pkg:generic/nvidia`, `pkg:pypi/`). |

### `triage`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `kev_weight` | enum | yes | How heavily the CISA KEV (known-exploited) signal is weighted in scoring: `low`, `medium`, or `high`. |
| `epss_threshold` | float | yes | Minimum EPSS score (0.0–1.0) required to escalate a match beyond routine reporting. |

### `remediate`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `auto_apply` | bool | yes | Whether the fixer may auto-apply fixes. `false` for infrastructure, kernel, and driver changes; `true` only for low-blast-radius changes (dependency bumps, image rebuilds) gated on green CI. |
| `propose` | enum | yes | What the fixer proposes when it does not auto-apply: `pr` (open a pull request for human approval) or `none` (report only). |

### `redteam`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enabled` | bool | yes (when present) | Whether proactive red-teaming applies to this target. |
| `posture` | string | yes (when `enabled: true`) | Attacker posture passed to the red-team harness for this target (e.g. "version-downgrade attacks", "dependency confusion"). |

## How the engine interprets each field

- **`collect`** → the `inventory` module runs each named collector and emits purls plus a
  hardware/software manifest. Collectors are registered separately; a recipe references
  them by name rather than defining them.
- **`match.source`** → `cvm-core` ingests the listed sources and normalizes them to the
  canonical vulnerability record.
- **`match.purl_prefix`** → `cvm-core` match scopes vulnerability records to inventory
  purls under this prefix, using precise ecosystem version-range matching (OSV-style),
  not CPE string matching.
- **`triage`** → `cvm-core` triage computes `kev_weight` + `epss_threshold` + reachability
  + asset criticality and emits one of `auto-fix`, `propose`, or `alert`.
- **`remediate`** → the `fixer` honors `auto_apply` (only low-blast-radius changes, green
  CI required) and `propose` (PR vs report only).
- **`redteam`** → when `enabled`, the `redteam` harness runs the pluggable attacker
  against an ephemeral replica using the given `posture`. Findings must clear the
  "prove it" proof gate.

## Example recipes

### `dgx-firmware` (infrastructure)

```yaml
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
  auto_apply: false          # infra — never auto
  propose: pr
redteam:
  enabled: true
  posture: "firmware/driver misconfiguration and version-downgrade attacks"
```

### `python-deps` (application dependencies)

```yaml
id: python-deps
version: 1
target_kinds: [code, container]
collect:
  - pip_packages
  - poetry_lock
  - uv_lock
match:
  source: [osv, cve]
  purl_prefix: "pkg:pypi/"
triage:
  kev_weight: medium
  epss_threshold: 0.3
remediate:
  auto_apply: true           # dependency bumps are low-blast-radius
  propose: pr
redteam:
  enabled: true
  posture: "dependency confusion, overly broad version ranges, and reachability of vulnerable functions"
```

## Adding a recipe without editing engine code

1. Create a new YAML file under `recipes/` (or a directory you point the engine at).
2. Give it a unique `id`, set `version: 1`, and declare `target_kinds`.
3. Reference **existing** collectors in `collect` and **existing** sources in `match`.
4. Declare `triage`, `remediate`, and optional `redteam` policy.
5. If you need a collector or source that does not exist yet, register it through the
   collector/source interfaces — but you never modify the core engine to add a recipe.

The engine discovers and validates recipes at load time and runs them without any
engine-side change.

## Versioning and the v1 / v2 boundary

- **v1** — recipes are declarative data only. The engine interprets them; recipes contain
  no executable logic. This is the only supported form in v1.
- **v2** — community-contributed *logic* (custom collectors, matchers, or remediators)
  will run in a WASM sandbox (wasmtime) so untrusted recipe code cannot escape the
  process. **Do not build code plugins in v1.**

## Validation rules

- `id` must be non-empty and unique within a deployment.
- `version` must be `1`.
- `target_kinds` must be a non-empty subset of the `target.kind` enum.
- `kev_weight` must be one of `low`, `medium`, `high`.
- `epss_threshold` must be in the range `0.0`–`1.0`.
- `remediate.propose` must be one of `pr`, `none`.
- `redteam.enabled` must be `true` or `false`; when `true`, `redteam.posture` must be
  non-empty.
