"""A real attacker: an LLM-driven HTTP prober with a bounded, iterative toolset.

This is the private, pluggable attacker for authorized red-teaming of your own
services. The toolset is bounded: HTTP requests against the target only (no
other hosts), a fixed method set, truncated bodies, and hard caps on rounds and
requests per round. No shell, no filesystem.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from typing import Any

from .finding import Finding, Fix, Proof, Target, Vuln

_BASELINE_PATHS = ("/", "/health", "/robots.txt")
_ALLOWED_METHODS = {"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"}


class APIAttacker:
    """Iteratively probes a target over HTTP and uses an LLM API to find vulnerabilities."""

    def __init__(
        self,
        *,
        api_key: str = "",
        base_url: str = "https://api.deepseek.com/v1",
        model: str = "deepseek-chat",
        timeout: float = 30.0,
        max_rounds: int = 3,
        max_probes_per_round: int = 6,
        seed_paths: list[str] | None = None,
    ) -> None:
        self._api_key = api_key or os.environ.get("DEEPSEEK_API_KEY", "")
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout = timeout
        self._max_rounds = max_rounds
        self._max_probes_per_round = max_probes_per_round
        self._seed_paths = list(seed_paths) if seed_paths else []
        # _chat is an injectable seam for tests.
        self._chat: Callable[[str], str] = self._call_llm

    def attack(self, target: str) -> list[Finding]:
        """Iteratively probe the target, then return findings from the LLM analysis."""
        probes = self._probe(target)
        for _ in range(self._max_rounds):
            suggested = self._suggest(target, probes)
            if not suggested:
                break
            new = self._execute(target, suggested)
            if not new:
                break
            probes.extend(new)
        analysis = self._chat(self._final_prompt(target, probes))
        return self._parse_findings(target, analysis)

    def _probe(self, target: str) -> list[dict[str, Any]]:
        paths = list(_BASELINE_PATHS) + [p for p in self._seed_paths if p not in _BASELINE_PATHS]
        return self._execute(target, [{"method": "GET", "path": p} for p in paths])

    def _suggest(self, target: str, probes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        prompt = (
            "You are red-teaming a service the operator owns (authorized). "
            f"Target: {target}\n"
            "Probe results so far:\n"
            f"{json.dumps(probes, indent=2)}\n\n"
            f"Suggest up to {self._max_probes_per_round} concrete next HTTP requests "
            "(method, path, optional body) most likely to expose a vulnerability. "
            "Respond with ONLY a JSON array, no prose: "
            '[{"method": "GET|POST", "path": "/...", "body": "..."}]'
        )
        return _extract_json_array(self._chat(prompt))

    def _final_prompt(self, target: str, probes: list[dict[str, Any]]) -> str:
        return (
            "You are a security auditor red-teaming a service the operator owns and is "
            "authorized to test.\n"
            f"Target: {target}\n"
            "All HTTP probe results:\n"
            f"{json.dumps(probes, indent=2)}\n\n"
            "Identify concrete, machine-checkable vulnerabilities. Respond with ONLY a JSON "
            "array, no prose, of findings. Each element must be:\n"
            '{"summary": "...", "severity": "critical|high|medium|low", "cwe": ["CWE-..."], '
            '"repro": "a curl command that proves the issue", "impact": "...", '
            '"suggestion": "..."}'
        )

    def _execute(self, target: str, requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
        base = target.rstrip("/")
        results: list[dict[str, Any]] = []
        for r in requests[: self._max_probes_per_round]:
            if not isinstance(r, dict):
                continue
            method = str(r.get("method", "GET")).upper()
            if method not in _ALLOWED_METHODS:
                continue
            path = str(r.get("path", "/"))
            if not path.startswith("/"):
                path = "/" + path
            url = base + path
            body = str(r.get("body", ""))
            try:
                req = urllib.request.Request(url, data=body.encode() if body else None, method=method)
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                    data = resp.read(4096).decode("utf-8", "replace")
                    results.append(
                        {"url": url, "method": method, "status": resp.status, "body": data[:1500]}
                    )
            except urllib.error.HTTPError as exc:
                results.append({"url": url, "method": method, "status": exc.code, "body": ""})
            except Exception as exc:  # noqa: BLE001 - bounded probe; report any failure
                results.append({"url": url, "method": method, "status": None, "error": str(exc)})
        return results

    def _call_llm(self, prompt: str) -> str:
        if not self._api_key:
            return "[]"
        body = json.dumps(
            {
                "model": self._model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
            }
        ).encode()
        req = urllib.request.Request(
            self._base_url + "/chat/completions",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + self._api_key,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        return data["choices"][0]["message"]["content"]

    def _parse_findings(self, target: str, analysis: str) -> list[Finding]:
        items = _extract_json_array(analysis)
        findings: list[Finding] = []
        for item in items:
            if not isinstance(item, dict) or not item.get("summary"):
                continue
            repro = str(item.get("repro", ""))
            findings.append(
                Finding(
                    schema_version="1.0",
                    id="redteam-" + uuid.uuid4().hex[:12],
                    run_id="",
                    source="llm-http-attacker",
                    target=Target(kind="web-service", ref=target),
                    vuln=Vuln(
                        cwe=list(item.get("cwe", [])),
                        summary=str(item.get("summary", "")),
                        severity=str(item.get("severity", "info")),
                        reachability="confirmed",
                    ),
                    proof=Proof(
                        repro=repro,
                        machine_checkable=bool(repro),
                        evidence=[],
                    ),
                    impact=str(item.get("impact", "")),
                    fix=Fix(suggestion=str(item.get("suggestion", ""))),
                )
            )
        return findings


def _extract_json_array(text: str) -> list[Any]:
    """Extract a JSON array from an LLM response, tolerating markdown fences."""
    text = text.strip()
    if text.startswith("```"):
        _, _, text = text.partition("\n")
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
    start = text.find("[")
    end = text.rfind("]")
    if start < 0 or end <= start:
        return []
    try:
        parsed = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []
