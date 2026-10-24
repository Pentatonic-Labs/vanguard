"""Agentic red-team attacker: a per-step tool-use loop with a prove-gate.

`APIAttacker` batch-suggests probes and analyses the results at the end. This
module is the *agentic* upgrade: the model acts, observes, and decides the next
single action each step, and its only way to report a finding is ``submit_finding``,
which re-executes the repro and rejects it unless the claim verifies. So the loop
keeps going until it has a PROVEN repro or exhausts its step budget.

The toolset is bounded: HTTP requests against the target only (no other hosts), a
fixed method set, truncated bodies, and hard caps on steps and body size. No shell,
no filesystem.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable
from typing import Any

from .finding import Finding, Proof, Target, Vuln
from .playbook import playbook_probes
from .verify import verify_repro

HttpFn = Callable[[dict[str, Any], float], dict[str, Any]]
ChatFn = Callable[[str], str]

_HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

_BASELINE_PATHS = ["/", "/health", "/healthz", "/metrics", "/.env", "/admin"]

_MAX_BODY = 8192


def _bounded_http(req: dict[str, Any], timeout: float) -> dict[str, Any]:
    """One bounded HTTP request. Returns {status, headers, body}. Never raises."""
    method = str(req.get("method", "GET")).upper()
    url = req.get("url") or req.get("path") or "/"
    headers = {k: str(v) for k, v in (req.get("headers") or {}).items()}
    data = (req.get("body") or "").encode()
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            body = resp.read(_MAX_BODY).decode(errors="replace")
            return {"status": resp.status, "headers": dict(resp.headers), "body": body}
    except urllib.error.HTTPError as e:
        body = e.read(_MAX_BODY).decode(errors="replace")
        return {"status": e.code, "headers": dict(e.headers), "body": body}
    except Exception as exc:  # noqa: BLE001 - bounded probe; report the failure
        return {"status": None, "headers": {}, "body": f"request failed: {exc}"}


TOOLS: list[dict[str, Any]] = [
    {
        "name": "http_request",
        "description": (
            "Send ONE bounded HTTP request to the target. method is one of the "
            "allowed methods; path is an absolute path (e.g. /admin). Returns "
            "status, response headers, and a truncated body."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "enum": _HTTP_METHODS},
                "path": {"type": "string"},
                "headers": {"type": "object"},
                "body": {"type": "string"},
            },
            "required": ["method", "path"],
        },
    },
    {
        "name": "submit_finding",
        "description": (
            "Submit a candidate finding. The `repro` (a curl command) is RE-EXECUTED; "
            "if it does not verify the claim, the finding is NOT recorded and you must "
            "refine or abandon it."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "severity": {"type": "string"},
                "cwe": {"type": "array", "items": {"type": "string"}},
                "repro": {"type": "string", "description": "a curl command proving the issue"},
                "impact": {"type": "string"},
            },
            "required": ["summary", "severity", "repro", "impact"],
        },
    },
    {
        "name": "done",
        "description": "Signal that the run is finished (no further actions).",
        "parameters": {"type": "object", "properties": {}},
    },
]

# Hunch list fed to the model so it is not limited to what it happens to recall.
_HUNCHES = (
    "Technique hunches to probe: IDOR (predictable /users/<n>, /api/me, /object/<id>); "
    "JWT alg=none (POST a token with alg:none and an empty signature); SSRF (url/callback/"
    "next/redirect params pointing at internal hosts); path traversal (/../../etc/passwd); "
    "mass assignment (POST extra fields like role=admin, is_admin=true); prompt injection "
    "(send a user message that tells an agent to ignore its instructions)."
)

_SYSTEM_PROMPT = (
    "You are a red-team security agent probing a target you are AUTHORIZED to test. "
    "Your goal is to find a real weakness AND produce a repro that verifies. "
    "Act one step at a time: send a request, read the observation, then decide the next "
    "single action. You only earn a finding by calling submit_finding with a repro that "
    "re-executes successfully.\n\n"
    + _HUNCHES
    + "\n\n"
    "Respond with ONE action as JSON only, no prose: {\"tool\": <name>, \"args\": {<params>}}."
)


def _extract_json_object(text: str) -> dict[str, Any] | None:
    """Pull the first {...} object out of a model reply. Returns None if absent."""
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        return None


def openai_chat_factory(base_url: str, model: str, api_key: str) -> ChatFn:
    """Build a chat function against any OpenAI-compatible /chat/completions endpoint."""

    def chat(prompt: str) -> str:
        body = json.dumps(
            {"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0.2}
        ).encode()
        req = urllib.request.Request(
            base_url.rstrip("/") + "/chat/completions",
            data=body,
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + api_key},
        )
        with urllib.request.urlopen(req, timeout=120) as r:
            data = json.loads(r.read())
        return data["choices"][0]["message"]["content"]

    return chat


class AgenticAttacker:
    """An LLM agent that attacks a target over HTTP until it has a proven finding."""

    def __init__(
        self,
        target: str,
        chat: ChatFn | None = None,
        http: HttpFn | None = None,
        seed_paths: list[str] | None = None,
        max_steps: int = 30,
        timeout: float = 10.0,
        api_key: str | None = None,
        base_url: str = "https://api.deepseek.com/v1",
        model: str = "deepseek-v4-pro",
    ):
        self._target = target.rstrip("/")
        if chat is None:
            key = api_key or os.environ.get("DEEPSEEK_API_KEY", "")
            chat = openai_chat_factory(base_url, model, key)
        self._chat = chat
        self._http = http or _bounded_http
        self._seed_paths = list(seed_paths or [])
        self._max_steps = max_steps
        self._timeout = timeout
        self._run_id = uuid.uuid4().hex

    # ---- HTTP ----

    def _run_http(self, args: dict[str, Any]) -> dict[str, Any]:
        """Run an http_request tool call. Enforces the target-origin bound."""
        method = str(args.get("method", "GET")).upper()
        path = str(args.get("path", "/"))
        url = urllib.parse.urljoin(self._target + "/", path.lstrip("/"))
        if not self._same_origin(url):
            return {"status": None, "headers": {}, "body": "refused: cross-origin request"}
        req = {
            "method": method,
            "url": url,
            "headers": args.get("headers"),
            "body": args.get("body"),
        }
        return self._http(req, self._timeout)

    def _same_origin(self, url: str) -> bool:
        a = urllib.parse.urlparse(self._target)
        b = urllib.parse.urlparse(url)
        return (b.scheme, b.netloc) == (a.scheme, a.netloc)

    def _status(self, req: dict[str, Any], timeout: float) -> int | None:
        return self._http(req, timeout).get("status")

    # ---- LLM ----

    def _decide(self, history: list[dict[str, Any]]) -> dict[str, Any] | None:
        prompt = (
            _SYSTEM_PROMPT
            + "\n\n"
            + f"Target: {self._target}\n\n"
            + f"Tools:\n{json.dumps(TOOLS)}\n\n"
            + f"History (action -> observation):\n{json.dumps(history, indent=2)}\n\n"
            + "Respond with ONE action as JSON only."
        )
        reply = self._chat(prompt)
        return _extract_json_object(reply)

    # ---- finding ----

    def _build_finding(self, args: dict[str, Any]) -> Finding:
        return Finding(
            schema_version="1.0",
            id="agent-" + uuid.uuid4().hex[:12],
            run_id=self._run_id,
            source="llm-agentic-attacker",
            target=Target(kind="http", ref=self._target),
            vuln=Vuln(
                cwe=list(args.get("cwe") or []),
                summary=str(args.get("summary", "")),
                severity=str(args.get("severity", "info")),
            ),
            proof=Proof(repro=str(args.get("repro", ""))),
            impact=str(args.get("impact", "")),
        )

    # ---- loop ----

    def attack(self) -> list[Finding]:
        """Act -> observe -> decide -> repeat, gating findings on repro verification."""
        history: list[dict[str, Any]] = []

        # Seed observations from the baseline and the deterministic playbook.
        paths = _BASELINE_PATHS + [p for p in self._seed_paths if p not in _BASELINE_PATHS]
        for path in paths:
            req = {"method": "GET", "path": path}
            history.append(
                {"action": {"tool": "http_request", "args": req}, "observation": self._run_http(req)}
            )
        for probe in playbook_probes(self._target):
            history.append(
                {
                    "action": {"tool": "http_request", "args": probe},
                    "observation": self._run_http(probe),
                }
            )

        findings: list[Finding] = []
        for _ in range(self._max_steps):
            action = self._decide(history)
            if not action:
                break
            tool = action.get("tool")
            args = action.get("args") or {}
            if tool == "http_request":
                history.append({"action": action, "observation": self._run_http(args)})
            elif tool == "submit_finding":
                finding = self._build_finding(args)
                ok, reason = verify_repro(finding, executor=self._status)
                if ok:
                    findings.append(finding)
                history.append(
                    {"action": action, "observation": {"proven": ok, "reason": reason}}
                )
            elif tool == "done":
                break
            else:
                history.append({"action": action, "observation": {"error": f"unknown tool {tool!r}"}})
        return findings
