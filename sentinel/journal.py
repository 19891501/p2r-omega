"""Hash-chained observation journal. This is not the core registry.

Each line commits to the previous line. A partial edit, a deleted line, a
replaced pin, or a rewritten certificate fails surveillance. Replacing the
whole `.sentinel/` directory has no external witness and is not a continuation.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


class JournalBroken(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def path_for(state_dir: Path) -> Path:
    return state_dir / "journal.jsonl"


def tip_path(state_dir: Path) -> Path:
    return state_dir / "journal.tip"


def file_sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def entry_hash(body: dict) -> str:
    material = {key: value for key, value in body.items() if key != "hash"}
    blob = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


def read(state_dir: Path) -> list[dict]:
    path = path_for(state_dir)
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            row = {"_invalid": True}
        if not isinstance(row, dict):
            row = {"_invalid": True}
        rows.append(row)
    return rows


def verify(rows: list[dict]) -> str:
    prev = GENESIS
    for index, row in enumerate(rows):
        if row.get("_invalid") or row.get("seq") != index or row.get("prev") != prev:
            raise JournalBroken("CHAIN_BROKEN")
        if row.get("hash") != entry_hash(row):
            raise JournalBroken("CHAIN_BROKEN")
        prev = row["hash"]
    return prev


def _read_tip(state_dir: Path) -> str | None:
    path = tip_path(state_dir)
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8").strip()
    return text or None


def _write_tip(state_dir: Path, tip: str) -> None:
    path = tip_path(state_dir)
    path.write_text(tip + "\n", encoding="utf-8")
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def survey(state_dir: Path) -> str | None:
    rows = read(state_dir)
    try:
        tip = verify(rows)
    except JournalBroken as exc:
        return exc.reason
    high = _read_tip(state_dir)
    if not rows and high:
        return "TIP_MISMATCH"
    if rows and high is None:
        return "TIP_MISMATCH"
    if rows and high != tip:
        if high == rows[-1].get("prev"):
            _write_tip(state_dir, tip)
        else:
            return "TIP_MISMATCH"
    if rows and file_sha256(state_dir / "frozen.json") != rows[-1].get("pin"):
        return "PIN_CHANGED"
    for row in rows:
        expected = row.get("certificate_sha256")
        certificate_id = row.get("certificate_id")
        if not certificate_id or not expected:
            continue
        actual = file_sha256(state_dir / "certificates" / f"{certificate_id}.json")
        if actual != expected:
            return "CERTIFICATE_MISMATCH"
    return None


def cache_conflicts(state: dict | None, rows: list[dict]) -> bool:
    if not state or not rows:
        return False
    return state.get("status") == "WATCHING" and rows[-1].get("state") != "WATCHING"


def append(state_dir: Path, entry: dict) -> dict:
    state_dir.mkdir(parents=True, exist_ok=True)
    rows = read(state_dir)
    try:
        tip = verify(rows)
    except JournalBroken as exc:
        raise JournalBroken(exc.reason) from exc
    high = _read_tip(state_dir)
    if high is not None and high != tip:
        raise JournalBroken("TIP_MISMATCH")
    body = dict(entry)
    body.setdefault("at", now())
    body["seq"] = len(rows)
    body["prev"] = tip
    body["hash"] = entry_hash(body)
    line = json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n"
    with path_for(state_dir).open("a", encoding="utf-8") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())
    _write_tip(state_dir, body["hash"])
    return body
