"""Dogfood the agentic attacker against the demo target.

Usage:
    DEEPSEEK_API_KEY=... uv run python demo/run_attack.py [target] [max_steps]
"""
from __future__ import annotations

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
