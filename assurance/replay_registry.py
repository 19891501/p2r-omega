"""Exhaustive bounded exploration of the registry model, replayed on SQLite.

The model (``assurance.model_registry``) does not import p2r. This module is
the only place that applies the same actions to ``p2r.registry.Registry``.
A mismatch is a conflict: the minimal action trace is returned and is
replayable.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
from collections import deque

from p2r.errors import RegistryError
from p2r.registry import Registry

from assurance.model_registry import State, empty, safety, step


def actions_for(keys=("k0", "k1"), effects=("e0", "e1"), nows=(0, 1, 2, 3, 4)):
    policies = ("deny", "allow_new_attempt")
    receipt = {"tag": "r"}
    out = []
    for key in keys:
        for effect in effects:
            for policy in policies:
                for now in nows:
                    out.append(("reserve", key, effect, policy, now))
        for now in nows:
            out.append(("mark_executed", key, now, receipt))
            out.append(("mark_ambiguous", key, now))
        out.append(("abandon", key))
    for now in nows:
        out.append(("recover", now))
    return tuple(out)


def _logical_sqlite(path: str):
    db = sqlite3.connect(path)
    try:
        rows = db.execute(
            "SELECT execution_key, effect_identity, status, receipt_json, updated_at "
            "FROM reservations"
        ).fetchall()
    finally:
        db.close()
    return tuple(sorted(tuple(row) for row in rows))


def _logical_model(state: State):
    return tuple(
        sorted(
            (key, row.effect, row.status, row.receipt, row.updated_at)
            for key, row in state.rows.items()
        )
    )


def _status(path: str, key: str):
    db = sqlite3.connect(path)
    try:
        row = db.execute(
            "SELECT status FROM reservations WHERE execution_key=?",
            (key,),
        ).fetchone()
    finally:
        db.close()
    return None if row is None else row[0]


def _apply_impl(path: str, timeout: int, action: tuple):
    reg = Registry(path, reservation_timeout=timeout)
    kind = action[0]
    try:
        if kind == "reserve":
            _, key, effect, policy, now = action
            decision = reg.reserve(key, effect, policy, now)
            mapping = {
                "NEW": ("NEW",),
                "RETRY": ("RETRY", decision.receipt_json),
                "ALREADY_RESERVED": ("ALREADY_RESERVED", decision.prior_execution_key),
                "RECONCILIATION_REQUIRED": ("RECONCILIATION_REQUIRED", decision.prior_execution_key),
                "EFFECT_IN_PROGRESS": ("EFFECT_IN_PROGRESS", decision.prior_execution_key),
                "EFFECT_ALREADY_EXECUTED": ("EFFECT_ALREADY_EXECUTED",),
            }
            if decision.kind not in mapping:
                outcome = ("ok", ("UNKNOWN_DECISION", decision.kind))
            else:
                outcome = ("ok", mapping[decision.kind])
        elif kind == "mark_executed":
            _, key, now, receipt = action
            reg.mark_executed(key, receipt, now)
            outcome = ("ok", ("MARK_EXECUTED",))
        elif kind == "mark_ambiguous":
            _, key, now = action
            before = _status(path, key)
            reg.mark_ambiguous(key, now)
            if before == "EXECUTED":
                outcome = ("ok", ("MARK_AMBIGUOUS_NOOP",))
            else:
                outcome = ("ok", ("MARK_AMBIGUOUS",))
        elif kind == "abandon":
            reg.abandon_before_dispatch(action[1])
            outcome = ("ok", ("ABANDON",))
        elif kind == "recover":
            changed = reg.recover_stale(action[1])
            outcome = ("ok", ("RECOVER", changed))
        else:
            raise AssertionError(action)
    except RegistryError as exc:
        outcome = ("error", exc.code)
    return outcome


def _checkpoint(path: str) -> bytes:
    db = sqlite3.connect(path)
    try:
        db.execute("PRAGMA wal_checkpoint(FULL)")
    finally:
        db.close()
    with open(path, "rb") as handle:
        return handle.read()


def _restore(path: str, blob: bytes) -> None:
    for suffix in ("", "-wal", "-shm"):
        extra = path + suffix
        if os.path.exists(extra):
            os.remove(extra)
    with open(path, "wb") as handle:
        handle.write(blob)


def explore(timeout: int = 2, keys=("k0", "k1"), effects=("e0", "e1"), nows=(0, 1, 2, 3, 4)):
    """BFS. Returns a JSON-ready dict. Stops recording after the first conflict
    but still finishes the search unless ``stop_on_conflict`` is set via the
    result budget. Conflicts abort the search so the minimal trace is kept.
    """
    catalog = actions_for(keys, effects, nows)
    root = empty(timeout)
    root_key = root.key()
    states = {root_key: root}
    parent = {root_key: None}
    violations = []
    work = tempfile.mkdtemp(prefix="p2r-model-")
    path = os.path.join(work, "reg.db")
    Registry(path, reservation_timeout=timeout)
    blobs = {root_key: _checkpoint(path)}
    queue = deque([root_key])
    edges = 0
    try:
        while queue:
            current_key = queue.popleft()
            current = states[current_key]
            for action in catalog:
                edges += 1
                predicted, nxt = step(current, action)
                found = safety(current, nxt, action, predicted)
                if found:
                    violations.append(
                        {
                            "kind": "SAFETY",
                            "violations": found,
                            "action": _public_action(action),
                            "trace": _trace(parent, current_key) + [_public_action(action)],
                        }
                    )
                    return _result(states, edges, violations, timeout, keys, effects, nows, catalog)
                _restore(path, blobs[current_key])
                observed = _apply_impl(path, timeout, action)
                snap = _logical_sqlite(path)
                model_snap = _logical_model(nxt)
                if observed != predicted or snap != model_snap:
                    violations.append(
                        {
                            "kind": "DIVERGENCE",
                            "action": _public_action(action),
                            "predicted": _jsonable(predicted),
                            "observed": _jsonable(observed),
                            "model_rows": model_snap,
                            "sqlite_rows": snap,
                            "trace": _trace(parent, current_key) + [_public_action(action)],
                        }
                    )
                    return _result(states, edges, violations, timeout, keys, effects, nows, catalog)
                nxt_key = nxt.key()
                if nxt_key not in states:
                    states[nxt_key] = nxt
                    parent[nxt_key] = (current_key, _public_action(action))
                    blobs[nxt_key] = _checkpoint(path)
                    queue.append(nxt_key)
        return _result(states, edges, violations, timeout, keys, effects, nows, catalog)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _public_action(action: tuple):
    if action[0] == "mark_executed":
        return ["mark_executed", action[1], action[2], {"tag": "r"}]
    return list(action)


def _jsonable(value):
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    return value


def _trace(parent, key):
    trace = []
    cursor = key
    while parent[cursor] is not None:
        cursor, action = parent[cursor]
        trace.append(action)
    trace.reverse()
    return trace


def _result(states, edges, violations, timeout, keys, effects, nows, catalog):
    return {
        "states": len(states),
        "edges": edges,
        "actions": len(catalog),
        "timeout": timeout,
        "keys": list(keys),
        "effects": list(effects),
        "nows": list(nows),
        "conflicts": violations,
        "status": "CONFLIT" if violations else "PROUVÉ",
    }


def replay_trace(trace: list, timeout: int = 2) -> list:
    """Re-execute a stored trace against SQLite and return outcomes."""
    work = tempfile.mkdtemp(prefix="p2r-replay-")
    path = os.path.join(work, "reg.db")
    try:
        Registry(path, reservation_timeout=timeout)
        outcomes = []
        for action in trace:
            kind = action[0]
            if kind == "mark_executed":
                parsed = ("mark_executed", action[1], action[2], action[3])
            else:
                parsed = tuple(action)
            outcomes.append(_apply_impl(path, timeout, parsed))
        return outcomes
    finally:
        shutil.rmtree(work, ignore_errors=True)
