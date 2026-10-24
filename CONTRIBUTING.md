# Contributing to Vanguard

Thanks for contributing. Vanguard is a continuous vulnerability management and
autonomous red-teaming project for NVIDIA/DGX fleets.

## Structure

- `cvmcore/` — reactive CVM engine (Go)
- `inventory/` — SBOM generation + DGX collector (Go)
- `fixer/` — finding → patch → PR (Go)
- `redteam/` — red-team harness (Python)
- `docs/` — architecture and specs

## Before you start

1. Pick or file an issue, and comment that you're taking it.
2. For new target types, add a recipe rather than editing the engine — see the
   recipe interface spec in `docs/`.

## Development

Go (stdlib only for now — no external dependencies):

```sh
gofmt -w .
go vet ./...
go test ./...
```

Python harness:

```sh
cd redteam
pip install -e ".[dev]"
ruff check .
pytest
```

## Commit conventions

- Small, focused commits; one concern per commit.
- Imperative subject line (e.g. `inventory: enumerate NVIDIA driver version`).
- Never `git add -A`; stage only what you changed.

## Adding a recipe

Recipes are declarative (collect / match / triage / remediate / redteam). See
`docs/recipe-interface.md` for the format, and add a fixture test alongside.

## Security

- Do not commit real credentials or secrets.
- Red-team targets must be replicas, never production. See `docs/sandbox-spec.md`.
