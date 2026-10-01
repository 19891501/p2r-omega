"""Deterministic crash schedules against the executor.

Each scenario has a stable id. The external action is counted. A schedule is
PROUVÉ when the number of external calls matches the contract and the second
attempt does not silently dispatch again, except CH-08 where the signed
policy explicitly allows a new attempt under a new nonce.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tempfile

from p2r.effect import effect_identity, execution_key
from p2r.errors import ExecutionError, PreDispatchError, RegistryError
from p2r.receipt import build_receipt

from tests.helpers import OBSERVER, context, p2r_base, sign_one


def _invoke(ctx, obj, action, semantics):
    try:
        receipt = execute_call(ctx, obj, action, semantics)
    except ExecutionError as exc:
        return exc.code
    except RegistryError as exc:
        return exc.code
    except Exception as exc:
        return type(exc).__name__
    return "RECEIPT" if isinstance(receipt, dict) else type(receipt).__name__


def execute_call(ctx, obj, action, semantics):
    from p2r.executor import execute

    return execute(obj, ctx, action, semantics)


def _run(schedule):
    work = tempfile.mkdtemp(prefix="p2r-chaos-")
    path = os.path.join(work, "reg.db")
    calls = []

    def action(effect, key):
        calls.append(key)
        return schedule["on_action"](effect, key, calls)

    try:
        t0 = schedule.get("t0", 1_000)
        ctx = context(path, clock_value=t0)
        obj = sign_one(p2r_base(**schedule.get("object", {})))
        if schedule.get("prime") == "kill":
            policy = obj["execution_policy"]["on_same_effect"]
            timeout = obj["execution_policy"]["reservation_timeout_seconds"]
            ctx.registry.reserve(
                execution_key(obj),
                effect_identity(obj),
                policy,
                t0,
                reservation_timeout=timeout,
            )
            first = "KILLED_RESERVED"
        else:
            first = _invoke(ctx, obj, action, schedule.get("semantics", "idempotent"))
        if "mutate" in schedule:
            schedule["mutate"](ctx.registry, obj)
        second_obj = obj
        if schedule.get("second") == "new_nonce":
            fields = {k: v for k, v in schedule.get("object", {}).items() if k != "nonce"}
            second_obj = sign_one(p2r_base(nonce="nonce-2", **fields))
        ctx2 = context(path, clock_value=schedule.get("t1", t0))
        second = _invoke(ctx2, second_obj, action, schedule.get("semantics", "idempotent"))
        return {"first": first, "second": second, "external_calls": len(calls)}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _boom(effect, key, calls):
    raise RuntimeError("dispatch outcome unknown")


def _pre(effect, key, calls):
    raise PreDispatchError("NO_DISPATCH")


def _ok(effect, key, calls):
    return {"settled": True}


def _plant_foreign(registry, obj):
    receipt = build_receipt(
        payload_digest="other-object-digest",
        execution_key=execution_key(obj),
        effect_identity=effect_identity(obj),
        action_semantics="idempotent",
        observed_effect={"settled": True},
        observer_id=OBSERVER.signer_id,
        observer_scope=["effect:transfer", "receipt:issue"],
        observed_at=1_000,
        signer=OBSERVER,
    )
    db = sqlite3.connect(registry.path)
    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            "UPDATE reservations SET receipt_json=? WHERE execution_key=?",
            (json.dumps(receipt), execution_key(obj)),
        )
        db.execute("COMMIT")
    finally:
        db.close()


def _plant_ghost(registry, obj):
    db = sqlite3.connect(registry.path)
    try:
        db.execute(
            "INSERT INTO reservations(execution_key,effect_identity,status,receipt_json,updated_at) "
            "VALUES('ghost-key', ?, 'GHOST', NULL, 1)",
            (effect_identity(obj),),
        )
        db.commit()
    finally:
        db.close()


def schedules():
    return [
        {
            "id": "CH-01",
            "title": "exception pendant le dispatch",
            "on_action": _boom,
            "expect_calls": 1,
            "expect_second": "EFFECT_RECONCILIATION_REQUIRED",
        },
        {
            "id": "CH-02",
            "title": "PreDispatchError : abandon puis nouvelle tentative",
            "on_action": _pre,
            "expect_calls": 2,
            "expect_first": "NO_DISPATCH",
            "expect_second": "NO_DISPATCH",
        },
        {
            "id": "CH-03",
            "title": "succès : le retry ne redispatche pas",
            "on_action": _ok,
            "expect_calls": 1,
            "expect_second": "RECEIPT",
        },
        {
            "id": "CH-04",
            "title": "exception in-process : ambigu immédiat, même si l'horloge recule",
            "on_action": _boom,
            "t0": 1_000,
            "t1": 900,
            "expect_calls": 1,
            "expect_second": "EFFECT_RECONCILIATION_REQUIRED",
            "note": "une exception dans le processus n'est pas un kill : mark_ambiguous est appelé",
        },
        {
            "id": "CH-05",
            "title": "reçu signé d'un autre payload substitué dans SQLite",
            "on_action": _ok,
            "mutate": _plant_foreign,
            "expect_calls": 1,
            "expect_second": "RETRY_RECEIPT_PAYLOAD_MISMATCH",
        },
        {
            "id": "CH-06",
            "title": "timeout après crash : réconciliation, pas un retry silencieux",
            "on_action": _boom,
            "t0": 1_000,
            "t1": 1_000 + 301,
            "expect_calls": 1,
            "expect_second": "EFFECT_RECONCILIATION_REQUIRED",
        },
        {
            "id": "CH-07",
            "title": "autre nonce, politique deny",
            "on_action": _ok,
            "second": "new_nonce",
            "expect_calls": 1,
            "expect_second": "EFFECT_ALREADY_EXECUTED",
        },
        {
            "id": "CH-08",
            "title": "autre nonce, allow_new_attempt signé",
            "on_action": _ok,
            "second": "new_nonce",
            "object": {"on_same_effect": "allow_new_attempt"},
            "expect_calls": 2,
            "expect_second": "RECEIPT",
            "note": "autorisé par la politique signée ; execution_key différente",
        },
        {
            "id": "CH-09",
            "title": "ligne GHOST sur le même effet, autre clé",
            "on_action": _ok,
            "mutate": _plant_ghost,
            "second": "new_nonce",
            "expect_calls": 1,
            "expect_second": "REGISTRY_STATUS_INVALID",
        },
        {
            "id": "CH-10",
            "title": "kill après réservation, reprise dans le timeout",
            "on_action": _ok,
            "prime": "kill",
            "t0": 5_000,
            "t1": 5_010,
            "expect_calls": 0,
            "expect_first": "KILLED_RESERVED",
            "expect_second": "ALREADY_RESERVED",
            "note": "le dispatch du processus tué est hors observation ; le processus vivant ne dispatch pas",
        },
        {
            "id": "CH-11",
            "title": "kill après réservation, reprise après timeout",
            "on_action": _ok,
            "prime": "kill",
            "t0": 5_000,
            "t1": 5_000 + 301,
            "expect_calls": 0,
            "expect_first": "KILLED_RESERVED",
            "expect_second": "EFFECT_RECONCILIATION_REQUIRED",
        },
    ]


def run_all():
    results = []
    failed = []
    for schedule in schedules():
        observed = _run(schedule)
        problem = None
        if observed["external_calls"] != schedule["expect_calls"]:
            problem = f"calls {observed['external_calls']} != {schedule['expect_calls']}"
        if "expect_second" in schedule and observed["second"] != schedule["expect_second"]:
            problem = (problem + "; " if problem else "") + (
                f"second {observed['second']} != {schedule['expect_second']}"
            )
        if "expect_first" in schedule and observed["first"] != schedule["expect_first"]:
            problem = (problem + "; " if problem else "") + (
                f"first {observed['first']} != {schedule['expect_first']}"
            )
        row = {
            "id": schedule["id"],
            "title": schedule["title"],
            "first": observed["first"],
            "second": observed["second"],
            "external_calls": observed["external_calls"],
            "note": schedule.get("note", ""),
            "status": "PROUVÉ" if problem is None else "ÉCHEC",
            "problem": problem,
        }
        results.append(row)
        if problem:
            failed.append(row)
    return {"results": results, "failed": failed, "status": "PROUVÉ" if not failed else "ÉCHEC"}


def ghost_rollback():
    """A corrupt sibling must not commit stale recovery."""
    from p2r.registry import Registry

    work = tempfile.mkdtemp(prefix="p2r-ghost-")
    path = os.path.join(work, "reg.db")
    try:
        reg = Registry(path, reservation_timeout=2)
        assert reg.reserve("k0", "e", "deny", 0).kind == "NEW"
        db = sqlite3.connect(path)
        db.execute(
            "INSERT INTO reservations(execution_key,effect_identity,status,receipt_json,updated_at) "
            "VALUES('ghost','e','GHOST',NULL,0)"
        )
        db.commit()
        db.close()
        try:
            reg.reserve("k1", "e", "deny", 10)
            return {"status": "ÉCHEC", "problem": "ghost reserve was accepted"}
        except RegistryError as exc:
            code = exc.code
        row = reg.get("k0")
        if code != "REGISTRY_STATUS_INVALID":
            return {"status": "ÉCHEC", "problem": code}
        if row["status"] != "RESERVED" or row["updated_at"] != 0:
            return {"status": "ÉCHEC", "problem": f"stale recovery committed: {row}"}
        return {"status": "PROUVÉ", "code": code, "k0": row["status"]}
    finally:
        shutil.rmtree(work, ignore_errors=True)
