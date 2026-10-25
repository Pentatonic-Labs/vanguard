"""Repro verification: re-execute a finding's repro and check it supports the claim.

Two kinds of proof are supported:

* **Status-based** (web vulns): the claim is about access (e.g. "unauthenticated"),
  so a 401/403/503 contradicts it.
* **Semantic** (agentic/injection vulns): the finding names an `expected` fragment
  that a compromised response must contain (a leaked system prompt, an escalation
  verdict, a followed instruction). The repro is re-run and the body is checked.

The repro is always a bounded HTTP request, never an arbitrary shell command.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from .finding import Finding

# Claims about unauthenticated/exposed access are only supported if the request
# actually SUCCEEDED; a 401/403/503 contradicts them.
_ACCESS_CLAIM_KEYWORDS = (
    "unauthenticated",
    "without auth",
    "without authentication",
    "exposed",
    "leaks",
    "discloses",
    "accepts",
    "reachable without",
)

# An executor runs a parsed request and returns (status, body). status is None
# when the request could not be executed.
Executor = Callable[[dict[str, Any], float], tuple[int | None, str]]


def verify_repro(finding: Finding, executor: Executor | None = None, timeout: float = 10.0) -> tuple[bool, str]:
    """Re-run the finding's repro and check it supports the claim.

    Returns (verified, reason). A finding whose repro cannot be parsed or run,
    whose response contradicts the claim, or (for semantic findings) whose
    response does not contain the expected evidence, is not verified.
    """
    req = parse_curl(finding.proof.repro)
    if req is None:
        return False, "repro is not a parseable HTTP request"
    exec_ = executor or execute_request
    status, body = exec_(req, timeout)
    if status is None:
        return False, "repro could not be executed"

    # Semantic proof: the finding claims the response contains specific evidence.
    expected = (finding.proof.expected or "").strip()
    if expected:
        if expected not in body:
            return False, f"repro response did not contain the claimed evidence {expected!r}"
        return True, "response contains the claimed evidence"

    # Status-based proof: access claims are only supported by a 2xx/3xx.
    summary = finding.vuln.summary.lower()
    if any(k in summary for k in _ACCESS_CLAIM_KEYWORDS):
        if 200 <= status < 400:
            return True, f"HTTP {status} supports the access claim"
        return False, f"HTTP {status} contradicts the unauthenticated-access claim"
    return True, f"HTTP {status} observed"


def parse_curl(cmd: str) -> dict[str, Any] | None:
    """Best-effort parse of a curl command into method/url/body/headers."""
    m = re.search(r"(?:-X|--request)\s+(\S+)", cmd)
    method = (m.group(1) if m else "GET").upper()
    b = re.search(r'(?:-d|--data(?:-raw)?)\s+(?:"([^"]*)"|\'([^\']*)\'|(\S+))', cmd)
    body = ""
    if b:
        body = b.group(1) or b.group(2) or b.group(3) or ""
    headers: dict[str, str] = {}
    for hm in re.finditer(r'(?:-H|--header)\s+(?:"([^"]*)"|\'([^\']*)\'|(\S+))', cmd):
        h = hm.group(1) or hm.group(2) or hm.group(3)
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    urls = re.findall(r"https?://\S+", cmd)
    if not urls:
        return None
    return {"method": method, "url": urls[-1].rstrip("\"'"), "body": body, "headers": headers}


def execute_request(req: dict[str, Any], timeout: float = 10.0) -> tuple[int | None, str]:
    """Execute an HTTP request, returning (status, body). Never raises."""
    r = urllib.request.Request(
        req["url"],
        data=req["body"].encode() if req.get("body") else None,
        headers=req.get("headers") or {},
        method=req["method"],
    )
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")
    except Exception:  # noqa: BLE001 - verification must never raise on a bad repro
        return None, ""
