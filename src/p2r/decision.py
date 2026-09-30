"""Decision status verification and fail-closed policy checks."""

from .errors import VerifyError

VALID_STATUSES = {"VERIFIED", "UNKNOWN", "CONFLICT"}


def verify_decision(p2r: dict) -> bool:
    decision = p2r.get("decision")
    if not isinstance(decision, dict):
        raise VerifyError("DECISION_MISSING")
    status = decision.get("status")
    if status not in VALID_STATUSES:
        raise VerifyError("DECISION_STATUS_INVALID")

    policy = p2r.get("execution_policy", {})
    if not isinstance(policy, dict):
        raise VerifyError("EXECUTION_POLICY_INVALID")
    required = policy.get("require_decision_status", "VERIFIED")
    if required not in VALID_STATUSES:
        raise VerifyError("EXECUTION_POLICY_STATUS_INVALID")
    if status != required:
        raise VerifyError("DECISION_STATUS_REJECTED")
    return True


def verify_execution_policy(p2r: dict) -> dict:
    policy = p2r.get("execution_policy", {})
    if not isinstance(policy, dict):
        raise VerifyError("EXECUTION_POLICY_INVALID")
    on_same_effect = policy.get("on_same_effect", "deny")
    if on_same_effect not in {"allow_new_attempt", "deny"}:
        raise VerifyError("EXECUTION_POLICY_SAME_EFFECT_INVALID")
    required = policy.get("require_decision_status", "VERIFIED")
    if required not in VALID_STATUSES:
        raise VerifyError("EXECUTION_POLICY_STATUS_INVALID")
    timeout = policy.get("reservation_timeout_seconds", 300)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 0:
        raise VerifyError("EXECUTION_POLICY_TIMEOUT_INVALID")
    return {
        "require_decision_status": required,
        "on_same_effect": on_same_effect,
        "reservation_timeout_seconds": timeout,
    }
