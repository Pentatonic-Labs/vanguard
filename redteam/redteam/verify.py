"""Repro verification: re-execute a finding's repro and check it supports the claim.

An LLM attacker can claim "unauthenticated access" while the endpoint actually
returns 401/403/503. This module re-runs the repro (as a bounded HTTP request,
never an arbitrary shell command) and checks the observed status against the
claim, so unverified claims are downgraded to leads.
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

Executor = Callable[[dict[str, Any], float], int | None]


def verify_repro(finding: Finding, executor: Executor | None = None, timeout: float = 10.0) -> tuple[bool, str]:
    """Re-run the finding's repro and check it supports the claim.

    Returns (verified, reason). A finding whose repro cannot be parsed or run,
    or whose response contradicts the claim, is not verified.
    """
    req = parse_curl(finding.proof.repro)
    if req is None:
        return False, "repro is not a parseable HTTP request"
    exec_ = executor or execute_request
    status = exec_(req, timeout)
    if status is None:
        return False, "repro could not be executed"
    summary = finding.vuln.summary.lower()
    if any(k in summary for k in _ACCESS_CLAIM_KEYWORDS):
        if 200 <= status < 400:
            return True, f"HTTP {status} supports the access claim"
        return False, f"HTTP {status} contradicts the unauthenticated-access claim"
    return True, f"HTTP {status} observed"


def parse_curl(cmd: str) -> dict[str, Any] | None:
    """Best-effort parse of a curl command into method/url/body."""
    m = re.search(r"(?:-X|--request)\s+(\S+)", cmd)
    method = (m.group(1) if m else "GET").upper()
    b = re.search(r'(?:-d|--data(?:-raw)?)\s+(?:"([^"]*)"|\'([^\']*)\'|(\S+))', cmd)
    body = ""
    if b:
        body = b.group(1) or b.group(2) or b.group(3) or ""
    urls = re.findall(r"https?://\S+", cmd)
    if not urls:
        return None
    return {"method": method, "url": urls[-1].rstrip("\"'"), "body": body}


def execute_request(req: dict[str, Any], timeout: float = 10.0) -> int | None:
    """Execute an HTTP request, returning the status code (or None on failure)."""
    try:
        r = urllib.request.Request(
            req["url"],
            data=req["body"].encode() if req["body"] else None,
            method=req["method"],
        )
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:  # noqa: BLE001 - verification must never raise on a bad repro
        return None
