"""Independent registry model. SPEC §13–14. Does not import p2r.

ABSENT is the absence of a row. Stored statuses are only
RESERVED, EXECUTED, RESERVED_AMBIGUOUS.

Stale rule, matching the implementation predicate (age > timeout):

    updated_at < now - reservation_timeout

Recovery runs inside ``reserve`` and ``recover`` only. It commits only when
that operation commits. ``abandon`` does not recover: it is an adapter
assertion that no dispatch occurred, not a crash path.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

VALID = {"RESERVED", "EXECUTED", "RESERVED_AMBIGUOUS"}
POLICIES = {"deny", "allow_new_attempt"}


@dataclass(frozen=True)
class Row:
    effect: str
    status: str
    updated_at: int
    receipt: str | None
    seq: int


@dataclass
class State:
    timeout: int
    rows: dict[str, Row]
    seq: int = 0

    def clone(self) -> "State":
        return State(self.timeout, dict(self.rows), self.seq)

    def key(self):
        items = tuple(
            sorted(
                (k, r.effect, r.status, r.updated_at, r.receipt)
                for k, r in self.rows.items()
            )
        )
        return (self.timeout, items)


def empty(timeout: int = 2) -> State:
    return State(timeout, {}, 0)


def dumps_receipt(receipt) -> str:
    return json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _recover(rows: dict[str, Row], now: int, timeout: int) -> dict[str, Row]:
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout < 0:
        raise ValueError("REGISTRY_TIMEOUT_INVALID")
    cutoff = now - timeout
    out = {}
    for key, row in rows.items():
        if row.status == "RESERVED" and row.updated_at < cutoff:
            out[key] = Row(row.effect, "RESERVED_AMBIGUOUS", now, row.receipt, row.seq)
        else:
            out[key] = row
    return out


def _priors(rows: dict[str, Row], effect: str) -> list[tuple[str, Row]]:
    found = [(key, row) for key, row in rows.items() if row.effect == effect]
    found.sort(key=lambda item: (item[1].updated_at, item[1].seq))
    return found


def step(state: State, action: tuple):
    """Return (outcome, new_state).

    outcome is ("ok", payload) or ("error", code). On error, new_state is the
    pre-image (the transaction rolls back, including any stale recovery).
    """
    kind = action[0]
    if kind == "reserve":
        _, key, effect, policy, now = action
        if policy not in POLICIES:
            return ("error", "REGISTRY_POLICY_INVALID"), state
        try:
            recovered = _recover(state.rows, now, state.timeout)
        except ValueError as exc:
            return ("error", str(exc)), state
        rows = dict(recovered)
        row = rows.get(key)
        if row is not None:
            if row.effect != effect:
                return ("error", "REGISTRY_EXECUTION_KEY_COLLISION"), state
            if row.status == "EXECUTED":
                payload = ("RETRY", row.receipt)
            elif row.status == "RESERVED":
                payload = ("ALREADY_RESERVED", key)
            elif row.status == "RESERVED_AMBIGUOUS":
                payload = ("RECONCILIATION_REQUIRED", key)
            else:
                return ("error", "REGISTRY_STATUS_INVALID"), state
            new = state.clone()
            new.rows = rows
            return ("ok", payload), new

        priors = _priors(rows, effect)
        for _, prior in priors:
            if prior.status not in VALID:
                return ("error", "REGISTRY_STATUS_INVALID"), state
        ambiguous = next((k for k, r in priors if r.status == "RESERVED_AMBIGUOUS"), None)
        if ambiguous is not None:
            new = state.clone()
            new.rows = rows
            return ("ok", ("RECONCILIATION_REQUIRED", ambiguous)), new
        reserved = next((k for k, r in priors if r.status == "RESERVED"), None)
        if reserved is not None:
            new = state.clone()
            new.rows = rows
            return ("ok", ("EFFECT_IN_PROGRESS", reserved)), new
        if priors and policy == "deny" and any(r.status == "EXECUTED" for _, r in priors):
            new = state.clone()
            new.rows = rows
            return ("ok", ("EFFECT_ALREADY_EXECUTED",)), new

        seq = state.seq + 1
        rows[key] = Row(effect, "RESERVED", now, None, seq)
        new = state.clone()
        new.rows = rows
        new.seq = seq
        return ("ok", ("NEW",)), new

    if kind == "recover":
        _, now = action
        try:
            recovered = _recover(state.rows, now, state.timeout)
        except ValueError as exc:
            return ("error", str(exc)), state
        changed = sum(
            1
            for key, row in recovered.items()
            if state.rows[key].status != row.status
        )
        new = state.clone()
        new.rows = recovered
        return ("ok", ("RECOVER", changed)), new

    if kind == "mark_executed":
        _, key, now, receipt = action
        row = state.rows.get(key)
        if row is None:
            return ("error", "REGISTRY_RESERVATION_MISSING"), state
        if row.status == "RESERVED_AMBIGUOUS":
            return ("error", "REGISTRY_AMBIGUOUS_CANNOT_EXECUTE"), state
        if row.status != "RESERVED":
            return ("error", "REGISTRY_BAD_TRANSITION"), state
        blob = dumps_receipt(receipt)
        new = state.clone()
        new.rows[key] = Row(row.effect, "EXECUTED", now, blob, row.seq)
        return ("ok", ("MARK_EXECUTED",)), new

    if kind == "mark_ambiguous":
        _, key, now = action
        row = state.rows.get(key)
        if row is None:
            return ("error", "REGISTRY_RESERVATION_MISSING"), state
        if row.status == "EXECUTED":
            return ("ok", ("MARK_AMBIGUOUS_NOOP",)), state
        if row.status != "RESERVED":
            return ("error", "REGISTRY_BAD_TRANSITION"), state
        new = state.clone()
        new.rows[key] = Row(row.effect, "RESERVED_AMBIGUOUS", now, row.receipt, row.seq)
        return ("ok", ("MARK_AMBIGUOUS",)), new

    if kind == "abandon":
        _, key = action
        row = state.rows.get(key)
        if row is None:
            return ("error", "REGISTRY_RESERVATION_MISSING"), state
        if row.status != "RESERVED":
            return ("error", "REGISTRY_CANNOT_ABANDON"), state
        new = state.clone()
        del new.rows[key]
        return ("ok", ("ABANDON",)), new

    raise ValueError(f"unknown action {action!r}")


def safety(before: State, after: State, action: tuple, outcome: tuple) -> list[str]:
    """Local safety monitor. Independent of how ``step`` chooses an outcome.

    It only looks at the before/after rows and the declared outcome.
    """
    violations = []
    if outcome[0] == "error":
        if after.key() != before.key():
            violations.append("ERROR_MUTATED_STATE")
        return violations

    for key, row in before.rows.items():
        aft = after.rows.get(key)
        if row.status == "EXECUTED":
            if (
                aft is None
                or aft.status != "EXECUTED"
                or aft.effect != row.effect
                or aft.receipt != row.receipt
                or aft.seq != row.seq
            ):
                violations.append(f"EXECUTED_NOT_STICKY:{key}")
        elif row.status == "RESERVED_AMBIGUOUS":
            if aft is None or aft.status != "RESERVED_AMBIGUOUS" or aft.effect != row.effect or aft.seq != row.seq:
                violations.append(f"AMBIGUOUS_NOT_STICKY:{key}")

    if action[0] == "reserve" and outcome == ("ok", ("NEW",)):
        key, effect, policy = action[1], action[2], action[3]
        created = after.rows.get(key)
        if created is None or created.status != "RESERVED" or created.effect != effect:
            violations.append("NEW_DID_NOT_RESERVE")
        for other, row in after.rows.items():
            if other == key or row.effect != effect:
                continue
            if row.status == "RESERVED_AMBIGUOUS":
                violations.append(f"NEW_DESPITE_AMBIGUOUS:{other}")
            if row.status == "RESERVED":
                violations.append(f"NEW_DESPITE_RESERVED:{other}")
            if policy == "deny" and row.status == "EXECUTED":
                violations.append(f"NEW_DESPITE_DENY_EXECUTED:{other}")
        if key in before.rows and before.rows[key].status == "RESERVED_AMBIGUOUS":
            violations.append("NEW_FROM_AMBIGUOUS_KEY")
    if action[0] == "abandon" and outcome == ("ok", ("ABANDON",)):
        key = action[1]
        if key in after.rows:
            violations.append("ABANDON_LEFT_ROW")
        if key not in before.rows or before.rows[key].status != "RESERVED":
            violations.append("ABANDON_NOT_FROM_RESERVED")
    return violations
