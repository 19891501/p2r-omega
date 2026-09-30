"""Deterministic canonicalization used by every P2R-Ω digest/signature."""

import json
from typing import Any


def _utf16_key(value: str) -> bytes:
    return value.encode("utf-16-be", errors="strict")


def canonicalize(value: Any) -> bytes:
    """Serialize the supported JSON subset deterministically.

    Canonical V1 deliberately forbids floats. Objects are sorted by their
    UTF-16 code-unit encoding, matching the ordering convention used by JCS.
    """
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, int):
        return str(value).encode("ascii")
    if isinstance(value, float):
        raise TypeError("floats not permitted in canonical payloads")
    if isinstance(value, str):
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    if isinstance(value, (list, tuple)):
        return b"[" + b",".join(canonicalize(item) for item in value) + b"]"
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("canonical object keys must be strings")
        items = sorted(value.items(), key=lambda item: _utf16_key(item[0]))
        return b"{" + b",".join(
            canonicalize(key) + b":" + canonicalize(item)
            for key, item in items
        ) + b"}"
    raise TypeError(f"unsupported canonical type: {type(value).__name__}")
