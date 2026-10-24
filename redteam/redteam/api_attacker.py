"""A real attacker: an LLM-driven HTTP prober with a deliberately bounded toolset.

This is the private, pluggable attacker for authorized red-teaming of your own
services. The toolset is HTTP GET against the target only — no shell, no
filesystem, no outbound calls except to the configured LLM API.
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

_PROBE_PATHS = ("/", "/health", "/robots.txt")


class APIAttacker:
    """Probes a target over HTTP and uses an LLM API to identify vulnerabilities."""

    def __init__(
        self,
        *,
        api_key: str = "",
        base_url: str = "https://api.deepseek.com/v1",
        model: str = "deepseek-chat",
        timeout: float = 30.0,
    ) -> None:
        self._api_key = api_key or os.environ.get("DEEPSEEK_API_KEY", "")
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout = timeout
        # _chat is an injectable seam for tests.
        self._chat: Callable[[str], str] = self._call_llm

    def attack(self, target: str) -> list[Finding]:
        """Probe the target and return findings produced by the LLM analysis."""
        probes = self._probe(target)
        analysis = self._chat(self._prompt(target, probes))
        return self._parse_findings(target, analysis)

    def _probe(self, target: str) -> list[dict[str, Any]]:
        base = target.rstrip("/")
        results: list[dict[str, Any]] = []
        for path in _PROBE_PATHS:
            url = base + path
            try:
                with urllib.request.urlopen(url, timeout=self._timeout) as resp:
                    body = resp.read(4096).decode("utf-8", "replace")
                    results.append({"url": url, "status": resp.status, "body": body[:1000]})
            except urllib.error.HTTPError as exc:
                results.append({"url": url, "status": exc.code, "body": ""})
            except Exception as exc:  # noqa: BLE001 - bounded probe; report any failure
                results.append({"url": url, "status": None, "error": str(exc)})
        return results

    def _prompt(self, target: str, probes: list[dict[str, Any]]) -> str:
        return (
            "You are a security auditor red-teaming a service the operator owns and is "
            "authorized to test.\n"
            f"Target: {target}\n"
            "HTTP probe results:\n"
            f"{json.dumps(probes, indent=2)}\n\n"
            "Identify concrete, machine-checkable vulnerabilities. Respond with ONLY a JSON "
            "array, no prose, of findings. Each element must be:\n"
            '{"summary": "...", "severity": "critical|high|medium|low", "cwe": ["CWE-..."], '
            '"repro": "a curl command that proves the issue", "impact": "...", '
            '"suggestion": "..."}'
        )

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
