"""Evidence provenance checks over a resolved universe."""

from __future__ import annotations

import re

from .canonical import canonicalize
from .digest import sha256_b64
from .errors import VerifyError

# RFC 6901 array index: "0" or a decimal integer with no leading zero.
_ARRAY_INDEX = re.compile(r"^(0|[1-9][0-9]*)$")


def _json_pointer_get(value, pointer: str):
    if not isinstance(pointer, str) or not pointer.startswith("/") and pointer != "":
        raise VerifyError("PROVENANCE_PATH_INVALID")
    if pointer == "":
        return value
    current = value
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            if _ARRAY_INDEX.fullmatch(token) is None:
                raise VerifyError("PROVENANCE_PATH_INVALID")
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
