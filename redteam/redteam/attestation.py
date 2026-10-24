"""Target authorization: a signed inventory claim, not a self-asserted string."""

from __future__ import annotations

import hashlib
import hmac
from typing import Any


class AttestationError(Exception):
    """Raised when a target is not authorized to be tested."""


def sign_target(target: str, key: bytes) -> str:
    """Return the HMAC-SHA256 signature over a target, as hex."""
    return hmac.new(key, target.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_claim(claim: Any, key: bytes) -> bool:
    """True if the claim carries a valid signature over its own target."""
    if not isinstance(claim, dict):
        return False
    target = claim.get("target")
    signature = claim.get("signature")
    if not isinstance(target, str) or not target:
        return False
    if not isinstance(signature, str) or not signature:
        return False
    return hmac.compare_digest(signature, sign_target(target, key))


def authorize_target(target: str, claim: dict[str, Any], key: bytes) -> None:
    """Authorize a target against a signed inventory claim.

    Raises AttestationError when the claim is unsigned, its signature is
    invalid, or it does not name this target. A self-asserted string is never
    sufficient authorization.
    """
    if not verify_claim(claim, key):
        raise AttestationError("target is not authorized: unsigned or invalid inventory claim")
    if claim.get("target") != target:
        raise AttestationError(
            f"target {target!r} is not authorized by the inventory claim "
            f"for {claim.get('target')!r}"
        )
