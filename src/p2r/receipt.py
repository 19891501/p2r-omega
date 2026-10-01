"""Signed receipts for observed execution results."""

from __future__ import annotations

from copy import deepcopy

from .canonical import canonicalize
from .digest import sha256_b64
from .errors import VerifyError


def compute_receipt_digest(receipt: dict) -> str:
    stripped = {key: value for key, value in receipt.items() if key != "receipt_signature"}
    return sha256_b64(canonicalize(stripped))


def sign_receipt(receipt: dict, signer) -> dict:
    result = deepcopy(receipt)
    result.pop("receipt_signature", None)
    result["receipt_signature"] = signer.sign(compute_receipt_digest(result).encode("ascii"))
    return result


def build_receipt(*, payload_digest: str, execution_key: str, effect_identity: str, action_semantics: str, observed_effect, observer_id: str, observer_scope: list[str], observed_at: int, signer) -> dict:
    if action_semantics not in {"idempotent", "at_most_once"}:
        raise VerifyError("ACTION_SEMANTICS_INVALID")
    if signer.signer_id != observer_id:
        raise VerifyError("RECEIPT_SIGNER_OBSERVER_MISMATCH")
    scope = sorted(set(observer_scope))
    receipt = {
        "type": "p2r-receipt/v1",
        "payload_digest": payload_digest,
        "execution_key": execution_key,
        "effect_identity": effect_identity,
        "action_semantics": action_semantics,
        "observed_effect": observed_effect,
        "observer": {"id": observer_id, "scope": scope},
        "observed_at": observed_at,
        "result": "COMPLETED",
    }
    return sign_receipt(receipt, signer)


def verify_receipt(receipt: dict, keyring, observer_scopes: dict[str, list[str]]) -> bool:
    if not isinstance(receipt, dict) or receipt.get("type") != "p2r-receipt/v1":
        raise VerifyError("RECEIPT_TYPE_INVALID")
    sig = receipt.get("receipt_signature")
    if not isinstance(sig, dict):
        raise VerifyError("RECEIPT_NO_SIGNATURE")
    observer = receipt.get("observer", {})
    if not isinstance(observer, dict):
        raise VerifyError("RECEIPT_NO_OBSERVER")
    observer_id = observer.get("id")
    if not isinstance(observer_id, str) or not observer_id:
        raise VerifyError("RECEIPT_NO_OBSERVER")
    if sig.get("alg") != "ed25519":
        raise VerifyError("RECEIPT_ALGORITHM_INVALID")
    if sig.get("signer") != observer_id:
        raise VerifyError("RECEIPT_SIGNER_OBSERVER_MISMATCH")
    try:
        signed_digest = compute_receipt_digest(receipt).encode("ascii")
    except Exception as exc:
        raise VerifyError("RECEIPT_CANONICALIZATION_FAILED", str(exc)) from exc
    if not keyring.verify(observer_id, signed_digest, sig.get("value", "")):
        raise VerifyError("RECEIPT_SIGNATURE_INVALID")

    scope = observer.get("scope", [])
    if not isinstance(scope, list) or any(not isinstance(item, str) for item in scope):
        raise VerifyError("OBSERVER_SCOPE_INVALID")
    if observer_id not in observer_scopes:
        raise VerifyError("OBSERVER_NOT_TRUSTED")
    allowed = set(observer_scopes[observer_id])
    if not set(scope).issubset(allowed):
        raise VerifyError("OBSERVER_SCOPE_NOT_GRANTED")

    if receipt.get("result") != "COMPLETED":
        raise VerifyError("RECEIPT_RESULT_INVALID")
    if receipt.get("action_semantics") not in {"idempotent", "at_most_once"}:
        raise VerifyError("ACTION_SEMANTICS_INVALID")
    for field in ("payload_digest", "execution_key", "effect_identity", "observed_at"):
        if field not in receipt:
            raise VerifyError("RECEIPT_FIELD_MISSING", field)
    return True
