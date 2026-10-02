"""Append-only cycle journal. This is not the core registry."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def path_for(state_dir: Path) -> Path:
    return state_dir / "journal.jsonl"


def append(state_dir: Path, entry: dict) -> dict:
    state_dir.mkdir(parents=True, exist_ok=True)
    body = dict(entry)
    body.setdefault("at", now())
    line = json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n"
    with path_for(state_dir).open("a", encoding="utf-8") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())
    return body


def read(state_dir: Path) -> list[dict]:
    path = path_for(state_dir)
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows
