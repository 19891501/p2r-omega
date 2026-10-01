"""Second, small verifier. It does not import p2r."""

from __future__ import annotations

import base64
import hashlib
import json
import re

_ARRAY_INDEX = re.compile(r"^(0|[1-9][0-9]*)$")


def _string(value: str) -> bytes:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return raw.replace("\u2028".encode("utf-8"), b"\\u2028").replace(
        "\u2029".encode("utf-8"), b"\\u2029"
    )


def canonicalize(value) -> bytes:
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, int):
        return str(value).encode("ascii")
    if isinstance(value, float):
        raise TypeError("float")
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (list, tuple)):
        return b"[" + b",".join(canonicalize(item) for item in value) + b"]"
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("key")
        items = sorted(value.items(), key=lambda item: item[0].encode("utf-16-be"))
        body = b",".join(canonicalize(key) + b":" + canonicalize(item) for key, item in items)
        return b"{" + body + b"}"
    raise TypeError(type(value).__name__)


def sha256_b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")


def payload_digest(obj: dict) -> str:
    stripped = {key: value for key, value in obj.items() if key not in ("payload_digest", "signatures")}
    return sha256_b64(canonicalize(stripped))


def _decode(raw: str) -> str:
    out = []
    i = 0
    while i < len(raw):
        if raw[i] != "~":
            out.append(raw[i])
            i += 1
            continue
        if i + 1 >= len(raw) or raw[i + 1] not in "01":
            raise ValueError("INVALID")
        out.append("/" if raw[i + 1] == "1" else "~")
        i += 2
    return "".join(out)


def pointer(value, path: str):
    if not isinstance(path, str) or (not path.startswith("/") and path != ""):
        raise ValueError("INVALID")
    if path == "":
        return value
    current = value
    for raw in path.split("/")[1:]:
        try:
            token = _decode(raw)
        except ValueError:
            raise
        if isinstance(current, list):
            if _ARRAY_INDEX.fullmatch(token) is None:
                raise ValueError("INVALID")
            if not current or len(token) > len(str(len(current) - 1)):
                raise LookupError("NOT_FOUND")
            index = int(token)
            if index >= len(current):
                raise LookupError("NOT_FOUND")
            current = current[index]
        elif isinstance(current, dict):
            if token not in current:
                raise LookupError("NOT_FOUND")
            current = current[token]
        else:
            raise LookupError("NOT_FOUND")
    return current


def manifest_root(universe: list[dict]) -> str:
    items = [dict(item) for item in universe]
    ids = []
    for item in items:
        evidence_id = item.get("evidence_id")
        if not isinstance(evidence_id, str) or not evidence_id:
            raise ValueError("BAD_ID")
        ids.append(evidence_id)
    if len(ids) != len(set(ids)):
        raise ValueError("DUP")
    items.sort(key=lambda item: item["evidence_id"].encode("utf-8"))
    nodes = [hashlib.sha256(b"\x00" + canonicalize(item)).digest() for item in items]
    if not nodes:
        return sha256_b64(b"\x02")
    while len(nodes) > 1:
        if len(nodes) % 2:
            nodes.append(nodes[-1])
        nodes = [
            hashlib.sha256(b"\x01" + nodes[i] + nodes[i + 1]).digest()
            for i in range(0, len(nodes), 2)
        ]
    return sha256_b64(nodes[0])


def effect_identity(p2r: dict) -> str:
    authority = p2r["authority"]
    effect = p2r["effect"]
    return sha256_b64(canonicalize({
        "actor_id": authority["principal"],
        "operation": effect["profile"],
        "rule": effect["rule"],
        "parameters": effect["argument"],
        "idempotency_key": effect["idempotency_key"],
    }))


def execution_key(p2r: dict) -> str:
    authority = p2r["authority"]
    scope = authority.get("nonce_scope", "global")
    if scope is None or scope == "":
        scope = "global"
    return sha256_b64(canonicalize({
        "effect_identity": effect_identity(p2r),
        "nonce_scope": scope,
        "nonce": authority["nonce"],
    }))
