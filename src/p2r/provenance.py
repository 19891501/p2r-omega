"""Evidence provenance checks over a resolved universe."""

from __future__ import annotations

import re

from .canonical import canonicalize
from .digest import sha256_b64
from .errors import VerifyError


_ARRAY_INDEX = re.compile(r"^(0|[1-9][0-9]*)$")


def _decode_pointer_token(raw: str) -> str:
    """Decode one RFC 6901 reference token without accepting bad escapes."""
    out: list[str] = []
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch != "~":
            out.append(ch)
            i += 1
            continue
        if i + 1 >= len(raw) or raw[i + 1] not in "01":
            raise VerifyError("PROVENANCE_PATH_INVALID")
        out.append("/" if raw[i + 1] == "1" else "~")
        i += 2
    return "".join(out)


def _json_pointer_get(value, pointer: str):
    if not isinstance(pointer, str) or not pointer.startswith("/") and pointer != "":
        raise VerifyError("PROVENANCE_PATH_INVALID")
    if pointer == "":
        return value
    current = value
    for raw in pointer.split("/")[1:]:
        token = _decode_pointer_token(raw)
        if isinstance(current, list):
            if _ARRAY_INDEX.fullmatch(token) is None:
                raise VerifyError("PROVENANCE_PATH_INVALID")
            # A longer digit string is past the last legal index. Compare
            # lengths before int() so a hostile token cannot force a big
            # conversion. The RFC 6901 grammar is unchanged.
            if not current or len(token) > len(str(len(current) - 1)):
                raise VerifyError("PROVENANCE_PATH_NOT_FOUND")
            index = int(token)
            if index >= len(current):
                raise VerifyError("PROVENANCE_PATH_NOT_FOUND")
            current = current[index]
        elif isinstance(current, dict):
            if token not in current:
                raise VerifyError("PROVENANCE_PATH_NOT_FOUND")
            current = current[token]
        else:
            raise VerifyError("PROVENANCE_PATH_NOT_FOUND")
    return current


def verify_provenance(p2r: dict, universe: list[dict]) -> bool:
    entries = p2r.get("provenance", [])
    if not isinstance(entries, list):
        raise VerifyError("PROVENANCE_INVALID")

    by_id = {item.get("evidence_id"): item for item in universe}
    for entry in entries:
        if not isinstance(entry, dict):
            raise VerifyError("PROVENANCE_ENTRY_INVALID")
        source = entry.get("source")
        if not isinstance(source, dict):
            raise VerifyError("PROVENANCE_SOURCE_INVALID")
        evidence_id = source.get("evidence_id")
        if evidence_id not in by_id:
            raise VerifyError("PROVENANCE_EVIDENCE_ID_MISMATCH")

        span = source.get("span")
        if not isinstance(span, dict):
            raise VerifyError("PROVENANCE_SPAN_INVALID")
        start, end = span.get("start"), span.get("end")
        if (
            not isinstance(start, int)
            or isinstance(start, bool)
            or not isinstance(end, int)
            or isinstance(end, bool)
            or start < 0
            or end <= start
        ):
            raise VerifyError("PROVENANCE_SPAN_INVALID")

        path = entry.get("path")
        value_digest = entry.get("value_digest")
        if not isinstance(value_digest, str):
            raise VerifyError("PROVENANCE_VALUE_DIGEST_INVALID")
        value = _json_pointer_get(by_id[evidence_id], path)
        if sha256_b64(canonicalize(value)) != value_digest:
            raise VerifyError("PROVENANCE_VALUE_DIGEST_MISMATCH")
    return True
