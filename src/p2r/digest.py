"""Hashing and sealing helpers."""

import base64
import hashlib
from copy import deepcopy

from .canonical import canonicalize


def sha256_b64(data: bytes) -> str:
    """SHA-256 encoded as URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")


def compute_payload_digest(p2r: dict) -> str:
    """Hash the P2R payload while excluding digest and detached signatures."""
    stripped = {
        key: value
        for key, value in p2r.items()
        if key not in ("payload_digest", "signatures")
    }
    return sha256_b64(canonicalize(stripped))


def seal(p2r: dict) -> dict:
    """Return a fresh unsigned P2R payload with a correct payload digest."""
    payload = deepcopy({
        key: value
        for key, value in p2r.items()
        if key not in ("payload_digest", "signatures")
    })
    payload["payload_digest"] = {
        "alg": "sha-256",
        "value": compute_payload_digest(payload),
    }
    return payload
