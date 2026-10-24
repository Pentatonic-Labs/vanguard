import pytest

from redteam.attestation import AttestationError, authorize_target, sign_target, verify_claim

KEY = b"operator-secret-key"


def _claim(target: str) -> dict:
    return {"target": target, "signature": sign_target(target, KEY)}


def test_authorizes_signed_target() -> None:
    claim = _claim("https://replica.internal/svc")
    authorize_target("https://replica.internal/svc", claim, KEY)


def test_rejects_unsigned_claim() -> None:
    claim = {"target": "https://replica.internal/svc"}
    with pytest.raises(AttestationError):
        authorize_target("https://replica.internal/svc", claim, KEY)


def test_rejects_wrong_target() -> None:
    claim = _claim("https://replica.internal/a")
    with pytest.raises(AttestationError):
        authorize_target("https://replica.internal/b", claim, KEY)


def test_rejects_wrong_key() -> None:
    claim = _claim("https://replica.internal/svc")
    with pytest.raises(AttestationError):
        authorize_target("https://replica.internal/svc", claim, b"other-key")


def test_verify_claim_rejects_non_dict() -> None:
    assert verify_claim("not-a-claim", KEY) is False
