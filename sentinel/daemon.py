"""Persistent observation cycle. It does not decide, authorize, or execute.

SENTINEL → CORE is read-only. QUARANTINED stays in this journal, not in the
core registry.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

from sentinel.journal import append, now
from sentinel.service import _read_json, _write_json, run_check
from sentinel.snapshot import head_ids, observer_digest, porcelain


def certificate_covers(state: dict | None, commit: str | None, tree: str | None, dirty: bool) -> bool:
    if not state or dirty or not commit or not tree:
        return False
    if state.get("status") == "QUARANTINED":
        return False
    if not state.get("valid_certificate"):
        return False
    return state.get("observed_commit") == commit and state.get("observed_tree") == tree


def replay_due(state: dict | None, now_epoch: float, replay_every: float | None) -> bool:
    if not replay_every:
        return False
    if not state or state.get("last_replay_at") is None:
        return True
    return now_epoch - float(state["last_replay_at"]) >= replay_every


def _look(repo: Path) -> tuple[str | None, str | None, bool]:
    if not (repo / ".git").exists():
        return None, None, True
    try:
        commit, tree = head_ids(repo)
        dirty = bool(porcelain(repo).strip())
    except (OSError, subprocess.CalledProcessError):
        return None, None, True
    return commit, tree, dirty


def _event(cert: dict) -> str:
    if cert.get("snapshot") == "WORKTREE_DIRTY":
        return "WORKTREE_DIRTY"
    if cert.get("quarantine_lifted"):
        return "RESTORED"
    if cert.get("state") == "QUARANTINED":
        return "DRIFT"
    if cert.get("result") == "PASS":
        return "CERTIFIED"
    return "UNKNOWN"


def _entry_from_cert(cert: dict) -> dict:
    replay = cert.get("replay") or {}
    return {
        "certificate_id": cert.get("id"),
        "commit": cert.get("commit"),
        "core_digest": cert.get("observed_digest"),
        "event": _event(cert),
        "replay": replay.get("status"),
        "result": cert.get("result"),
        "snapshot": cert.get("snapshot"),
        "state": cert.get("state"),
        "tree": cert.get("tree"),
    }


def cycle(repo: Path, state_dir: Path, *, replay, replay_every: float | None, now_epoch: float) -> dict:
    repo = repo.resolve()
    state_dir = state_dir.resolve()
    state_dir.mkdir(parents=True, exist_ok=True)
    state = _read_json(state_dir / "state.json") or {}
    commit, tree, dirty = _look(repo)
    observer = state.get("observer_digest")
    same_observer = observer is None or observer == observer_digest()
    if certificate_covers(state, commit, tree, dirty) and same_observer and not replay_due(state, now_epoch, replay_every):
        state["last_seen"] = now()
        state["status"] = "WATCHING"
        _write_json(state_dir / "state.json", state)
        return append(
            state_dir,
            {
                "certificate_id": state.get("valid_certificate"),
                "commit": commit,
                "core_digest": state.get("observed_digest"),
                "event": "UNCHANGED",
                "replay": "SKIPPED",
                "result": "PASS",
                "snapshot": "BOUND",
                "state": "WATCHING",
                "tree": tree,
            },
        )
    previous_replay = state.get("last_replay_at")
    cert = run_check(repo, state_dir, replay=None if dirty else replay, emit_if_unchanged=False)
    fresh = _read_json(state_dir / "state.json") or {}
    ran = (cert.get("replay") or {}).get("status") not in {None, "SKIPPED"}
    fresh["last_replay_at"] = now_epoch if ran else previous_replay
    _write_json(state_dir / "state.json", fresh)
    return append(state_dir, _entry_from_cert(cert))


def run_daemon(
    repo: Path,
    state_dir: Path,
    *,
    interval: float,
    iterations: int | None,
    replay,
    sleep=time.sleep,
    replay_every: float | None = None,
    clock=time.time,
) -> dict:
    last: dict = {}
    count = 0
    while iterations is None or count < iterations:
        last = cycle(repo, state_dir, replay=replay, replay_every=replay_every, now_epoch=clock())
        count += 1
        if iterations is not None and count >= iterations:
            break
        sleep(interval)
    return last
