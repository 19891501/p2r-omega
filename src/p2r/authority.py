"""Verification and signing of the detached authority envelope."""

from __future__ import annotations

from copy import deepcopy

from .errors import VerifyError


def _payload_digest_bytes(p2r: dict) -> bytes:
    try:
        alg = p2r["payload_digest"]["alg"]
        value = p2r["payload_digest"]["value"]
    except (KeyError, TypeError):
        raise VerifyError("PAYLOAD_DIGEST_MISSING")
    if alg != "sha-256" or not isinstance(value, str):
        raise VerifyError("PAYLOAD_DIGEST_ALGORITHM_INVALID")
    return value.encode("ascii")


def verify_signatures(p2r: dict, keyring) -> bool:
    authority = p2r.get("authority")
    if not isinstance(authority, dict):
        raise VerifyError("AUTHORITY_MISSING")
    authorized = authority.get("authorized_signers", [])
    if not isinstance(authorized, list) or any(not isinstance(x, str) or not x for x in authorized):
        raise VerifyError("AUTHORITY_SIGNERS_INVALID")
    if len(set(authorized)) != len(authorized):
        raise VerifyError("AUTHORITY_SIGNERS_DUPLICATE")
    authorized_set = set(authorized)
    threshold_value = authority.get("threshold", 1)
    if isinstance(threshold_value, bool) or not isinstance(threshold_value, int):
        raise VerifyError("AUTHORITY_BAD_THRESHOLD")
    threshold = threshold_value
    if not (1 <= threshold <= len(authorized_set)):
        raise VerifyError("AUTHORITY_BAD_THRESHOLD")

    digest = _payload_digest_bytes(p2r)
    signatures = p2r.get("signatures", [])
    if not isinstance(signatures, list):
        raise VerifyError("SIGNATURES_INVALID")
    seen: set[str] = set()
    good = 0
    for sig in signatures:
        if not isinstance(sig, dict):
            continue
        signer = sig.get("signer")
        if signer in seen or signer not in authorized_set:
            continue
        if sig.get("alg") != "ed25519":
            continue
        if keyring.verify(signer, digest, sig.get("value", "")):
            seen.add(signer)
            good += 1
    if good < threshold:
        raise VerifyError("SIGNATURE_THRESHOLD_NOT_MET")
    return True


def sign_payload(p2r: dict, signer, *, require_sealed: bool = True) -> dict:
    """Append one detached Ed25519 signature to a sealed P2R object."""
    from .digest import compute_payload_digest

    result = deepcopy(p2r)
    actual = result.get("payload_digest", {}).get("value")
    if require_sealed and actual != compute_payload_digest(result):
        raise VerifyError("PAYLOAD_NOT_SEALED")
    if result.get("payload_digest", {}).get("alg") != "sha-256":
        raise VerifyError("PAYLOAD_DIGEST_ALGORITHM_INVALID")
    signatures = list(result.get("signatures", []))
    signatures.append(signer.sign(actual.encode("ascii")))
    result["signatures"] = signatures
    return result
