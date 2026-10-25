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
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable
from typing import Any

from .finding import Finding, Fix, Proof, Target, Vuln
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
                "fix": {"type": "string", "description": "plain-English remediation: how the issue should be addressed"},
                "expected": {"type": "string", "description": "for agentic/injection findings: exact text the compromised response must contain (e.g. an escalation verdict, a leaked prompt)"},
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
    "Techniques to hunt with (try ALL of them, then improvise beyond them):\n"
    "- IDOR / broken object-level auth: enumerate predictable ids (/users/1..n, /api/me, "
    "/object/1, /accounts/1) and look for PII or cross-tenant data.\n"
    "- Auth bypass: JWT alg=none or alg=HS256 with an empty/weak secret; missing auth on "
    "admin endpoints; role forging (role=admin, is_admin=true, permissions=all).\n"
    "- SSRF: url/callback/next/redirect/uri/webhook/dest params pointed at 127.0.0.1, "
    "169.254.169.254, or internal hostnames.\n"
    "- Path traversal & LFI: ../..//etc/passwd, ..%2f, %2e%2e/, absolute /etc/passwd, "
    "double-encoding, null bytes.\n"
    "- Mass assignment: inject privilege fields into POST/PUT/PATCH bodies.\n"
    "- Injection: SQLi (' OR 1=1--, ' UNION SELECT), command injection (; id, | whoami, "
    "$(whoami)), template injection ({{7*7}}, ${7*7}).\n"
    "- Header abuse: X-Forwarded-For, X-Original-URL, X-Rewrite-URL, Host header override.\n"
    "- Prompt injection against the target's own agent (ignore instructions, reveal system prompt).\n"
    "- Info leak: /.env, /config, /debug, /.git/HEAD, /actuator, /swagger, /api-docs, "
    "verbose error messages, stack traces.\n"
    "Revisit 404s with different encodings, methods (POST/PUT/PATCH/OPTIONS/HEAD), and headers "
    "before giving up. Chain discoveries: a leaked id enables an IDOR; an IDOR yields PII; "
    "PII enables takeover."
)

_SYSTEM_PROMPT = (
    "You are an adversarial penetration-testing agent. You are simulating a sophisticated, "
    "motivated attacker who is devious, persistent, and does NOT give up: assume the defenders "
    "made mistakes and hunt for them relentlessly.\n\n"
    "The target is a replica you are AUTHORIZED to attack (never production). Within that "
    "authorization, be as devious as a real attacker:\n"
    "- Enumerate aggressively: guess ids, paths, parameters, roles, and verbs.\n"
    "- Chain findings into bigger findings.\n"
    "- Revisit failures with different encodings, methods, and headers before giving up.\n"
    "- Do not be polite or timid. Do not stop at the first finding — keep hunting.\n\n"
    "You only earn a finding by calling submit_finding with a repro that RE-EXECUTES "
    "successfully; unverified claims are rejected, so craft each repro carefully. In "
    "submit_finding, state plainly (a) what the issue is (`summary`, `impact`) and (b) how "
    "to address it (`fix`). For agentic or prompt-injection findings, also set `expected` "
    "to the exact text a compromised response must contain (an escalation verdict, a "
    "leaked prompt), so the proof gate can verify it.\n\n"
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


def _default_api_key() -> str:
    """Resolve the model API key: env vars first, then the local OrcaRouter key file,
    then DEEPSEEK_API_KEY."""
    for src in (os.environ.get("VANGUARD_API_KEY"), os.environ.get("ORCAROUTER_API_KEY")):
        if src:
            return src
    try:
        with open(os.path.expanduser("~/.config/orca/api_key")) as f:
            v = f.read().strip()
        if v:
            return v
    except OSError:
        pass
    return os.environ.get("DEEPSEEK_API_KEY", "")


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
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                data = json.loads(r.read())
        except Exception as exc:  # noqa: BLE001 - a model failure must not crash the run
            print(f"[agent] model call failed: {exc}", file=sys.stderr)
            return json.dumps({"tool": "done", "args": {}})
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
        base_url: str | None = None,
        model: str | None = None,
        default_headers: dict[str, str] | None = None,
        seed_probes: list[dict[str, Any]] | None = None,
    ):
        self._target = target.rstrip("/")
        self._default_headers = dict(default_headers or {})
        self._seed_probes = list(seed_probes or [])
        if chat is None:
            base_url = base_url or os.environ.get("VANGUARD_BASE_URL", "https://api.orcarouter.ai/v1")
            model = model or os.environ.get("VANGUARD_MODEL", "orca/orcacyber-flash-1.0")
            key = api_key or _default_api_key()
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
        headers = dict(self._default_headers)
        headers.update(args.get("headers") or {})
        req = {
            "method": method,
            "url": url,
            "headers": headers or None,
            "body": args.get("body"),
        }
        return self._http(req, self._timeout)

    def _same_origin(self, url: str) -> bool:
        a = urllib.parse.urlparse(self._target)
        b = urllib.parse.urlparse(url)
        return (b.scheme, b.netloc) == (a.scheme, a.netloc)

    def _status(self, req: dict[str, Any], timeout: float) -> tuple[int | None, str]:
        obs = self._http(req, timeout)
        return obs.get("status"), obs.get("body", "")

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
            proof=Proof(repro=str(args.get("repro", "")), expected=str(args.get("expected", ""))),
            impact=str(args.get("impact", "")),
            fix=Fix(suggestion=str(args.get("fix", ""))),
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
        # Operator-provided route seeds (full request shapes, e.g. a chat
        # endpoint the attacker must be pointed at before it can explore it).
        for probe in self._seed_probes:
            history.append(
                {"action": {"tool": "http_request", "args": probe}, "observation": self._run_http(probe)}
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
