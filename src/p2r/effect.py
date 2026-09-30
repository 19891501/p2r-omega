"""Stable identity for the exact authorized effect and execution attempt."""

from .canonical import canonicalize
from .digest import sha256_b64
from .errors import VerifyError


def _effect(p2r: dict) -> tuple[dict, dict]:
    authority = p2r.get("authority")
    effect = p2r.get("effect")
    if not isinstance(authority, dict) or not isinstance(effect, dict):
        raise VerifyError("EFFECT_SHAPE_INVALID")
    required_authority = ("principal", "nonce")
    if any(key not in authority for key in required_authority):
        raise VerifyError("AUTHORITY_EFFECT_FIELDS_MISSING")
    required_effect = ("profile", "rule", "argument", "idempotency_key")
    if any(key not in effect for key in required_effect):
        raise VerifyError("EFFECT_FIELDS_MISSING")
    return authority, effect


def effect_identity(p2r: dict) -> str:
    authority, effect = _effect(p2r)
    return sha256_b64(canonicalize({
        "actor_id": authority["principal"],
        "operation": effect["profile"],
        "rule": effect["rule"],
        "parameters": effect["argument"],
        "idempotency_key": effect["idempotency_key"],
    }))


def execution_key(p2r: dict) -> str:
    authority, _ = _effect(p2r)
    return sha256_b64(canonicalize({
        "effect_identity": effect_identity(p2r),
        "nonce_scope": authority.get("nonce_scope", "global"),
        "nonce": authority["nonce"],
    }))
