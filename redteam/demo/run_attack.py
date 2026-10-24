"""Dogfood the agentic attacker against the demo target.

Usage:
    DEEPSEEK_API_KEY=... uv run python demo/run_attack.py [target] [max_steps]

Findings are written to <repo>/.vanguard/redteam.json (the same store the CVM
scan writes), so `vanguard ui` can display them.
"""
from __future__ import annotations

import json
import pathlib
import sys
import time

from redteam.agent import AgenticAttacker

target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3456"
max_steps = int(sys.argv[2]) if len(sys.argv) > 2 else 10

start = time.time()
agent = AgenticAttacker(target, max_steps=max_steps)
findings = agent.attack()
elapsed = time.time() - start

print(f"\n=== {len(findings)} verified finding(s) in {elapsed:.0f}s ===")
for f in findings:
    print(f"- [{f.vuln.severity}] {f.vuln.summary}")
    print(f"    repro : {f.proof.repro}")
    print(f"    impact: {f.impact}")

# Persist to the shared store so `vanguard ui` can display them.
repo_root = pathlib.Path(__file__).resolve().parents[2]
data_dir = repo_root / ".vanguard"
data_dir.mkdir(parents=True, exist_ok=True)
out = data_dir / "redteam.json"
out.write_text(json.dumps([f.to_dict() for f in findings], indent=2))
print(f"\nfindings written to {out}")
