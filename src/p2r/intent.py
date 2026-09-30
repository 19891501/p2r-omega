"""Signed structured-intent interpretation."""

import json

from .errors import VerifyError

VALID_PROFILES = {"literal-structured-intent-v1"}


def interpret(content: str, profile: str):
    if profile == "literal-structured-intent-v1":
        if not isinstance(content, str):
            raise VerifyError("INTENT_CONTENT_INVALID")
        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            raise VerifyError("INTENT_CONTENT_INVALID", str(exc)) from exc
    raise VerifyError("UNKNOWN_INTENT_PROFILE")


def verify_intent(p2r: dict) -> bool:
    intent = p2r.get("intent")
    if not isinstance(intent, dict):
        raise VerifyError("INTENT_MISSING")
    profile = intent.get("profile")
    if profile not in VALID_PROFILES:
        raise VerifyError("UNKNOWN_INTENT_PROFILE")
    expected = interpret(intent.get("content"), profile)
    if expected != intent.get("structured_goal"):
        raise VerifyError("INTENT_MISMATCH")
    return True
