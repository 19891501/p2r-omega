"""Fail-closed P2R object verification."""

from .authority import verify_signatures
from .decision import verify_decision, verify_execution_policy
from .digest import compute_payload_digest
from .effect import effect_identity, execution_key
from .errors import VerifyError
from .intent import verify_intent
from .provenance import verify_provenance
from .universe import resolve_and_verify


def _shape(p2r: dict) -> None:
    if not isinstance(p2r, dict):
        raise VerifyError("P2R_NOT_OBJECT")
    if p2r.get("type") != "p2r/v1":
        raise VerifyError("P2R_TYPE_INVALID")
    required = ("world", "intent", "decision", "authority", "effect", "execution_policy")
    missing = [key for key in required if key not in p2r]
    if missing:
        raise VerifyError("P2R_FIELD_MISSING", ",".join(missing))


def verify_object(p2r: dict, ctx) -> bool:
    _shape(p2r)
    digest_block = p2r.get("payload_digest")
    if not isinstance(digest_block, dict):
        raise VerifyError("PAYLOAD_DIGEST_MISSING")
    actual = digest_block.get("value")
    if set(digest_block.keys()) != {"alg", "value"}:
        raise VerifyError("PAYLOAD_DIGEST_SHAPE_INVALID")
    if digest_block.get("alg") != "sha-256" or not isinstance(actual, str):
        raise VerifyError("PAYLOAD_DIGEST_ALGORITHM_INVALID")
    recomputed = compute_payload_digest(p2r)
    if recomputed != actual:
        raise VerifyError("PAYLOAD_DIGEST_MISMATCH")

    universe = resolve_and_verify(p2r, ctx.universe_resolver)
    verify_provenance(p2r, universe)
    verify_intent(p2r)
    verify_decision(p2r)
    verify_execution_policy(p2r)
    verify_signatures(p2r, ctx.keyring)

    # Force the identities through the same parser used by the registry/executor.
    effect_identity(p2r)
    execution_key(p2r)
    return True
