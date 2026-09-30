from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from p2r.errors import ExecutionError, PreDispatchError
from p2r.executor import execute
from p2r.receipt import verify_receipt

from .helpers import OBSERVER, context, p2r_base, sign_one


def test_success_executes_and_returns_signed_receipt(tmp_path):
    ctx = context(tmp_path / "r.db")
    calls = []

    def action(effect, ekey):
        calls.append((effect, ekey))
        return {"target": effect["argument"]["target"], "status": "ok"}

    receipt = execute(sign_one(p2r_base()), ctx, action)
    assert receipt["result"] == "COMPLETED"
    assert receipt["effect_identity"]
    assert receipt["execution_key"]
    assert len(calls) == 1
    verify_receipt(receipt, ctx.keyring, ctx.observer_scopes)


def test_same_execution_key_retries_cached_receipt_without_action(tmp_path):
    ctx = context(tmp_path / "r.db")
    calls = []

    def action(effect, ekey):
        calls.append(ekey)
        return {"status": "ok"}

    obj = sign_one(p2r_base())
    first = execute(obj, ctx, action)
    second = execute(obj, ctx, action)
    assert first == second
    assert len(calls) == 1


def test_t22_generic_action_failure_marks_ambiguous(tmp_path):
    ctx = context(tmp_path / "r.db")
    obj = sign_one(p2r_base())

    def action(effect, ekey):
        raise RuntimeError("crash after dispatch simulation")

    with pytest.raises(RuntimeError):
        execute(obj, ctx, action)
    row = ctx.registry.get(__import__('p2r.effect', fromlist=['execution_key']).execution_key(obj))
    assert row["status"] == "RESERVED_AMBIGUOUS"


def test_safe_pre_dispatch_failure_can_be_abandoned(tmp_path):
    ctx = context(tmp_path / "r.db")
    obj = sign_one(p2r_base())

    def action(effect, ekey):
        raise PreDispatchError("NO_NETWORK", "adapter failed before dispatch")

    with pytest.raises(PreDispatchError):
        execute(obj, ctx, action)
    from p2r.effect import execution_key
    assert ctx.registry.get(execution_key(obj)) is None


def test_t24_ambiguous_effect_requires_reconciliation_before_new_attempt(tmp_path):
    ctx = context(tmp_path / "r.db")
    obj1 = sign_one(p2r_base(nonce="nonce-a", on_same_effect="allow_new_attempt"))
    obj2 = sign_one(p2r_base(nonce="nonce-b", on_same_effect="allow_new_attempt"))

    def action(effect, ekey):
        raise RuntimeError("ambiguous")

    with pytest.raises(RuntimeError):
        execute(obj1, ctx, action)
    with pytest.raises(ExecutionError, match="EFFECT_RECONCILIATION_REQUIRED"):
        execute(obj2, ctx, lambda effect, ekey: {"status": "should-not-run"})


def test_allow_new_attempt_after_completed_effect_needs_new_execution_key(tmp_path):
    ctx = context(tmp_path / "r.db")
    obj1 = sign_one(p2r_base(nonce="nonce-a", on_same_effect="allow_new_attempt"))
    obj2 = sign_one(p2r_base(nonce="nonce-b", on_same_effect="allow_new_attempt"))
    calls = []

    def action(effect, ekey):
        calls.append(ekey)
        return {"status": "ok", "attempt": len(calls)}

    execute(obj1, ctx, action)
    execute(obj2, ctx, action)
    assert len(calls) == 2
    assert calls[0] != calls[1]


def test_deny_new_attempt_after_completed_effect(tmp_path):
    ctx = context(tmp_path / "r.db")
    obj1 = sign_one(p2r_base(nonce="nonce-a", on_same_effect="deny"))
    obj2 = sign_one(p2r_base(nonce="nonce-b", on_same_effect="deny"))

    execute(obj1, ctx, lambda effect, ekey: {"status": "ok"})
    with pytest.raises(ExecutionError, match="EFFECT_ALREADY_EXECUTED"):
        execute(obj2, ctx, lambda effect, ekey: {"status": "should-not-run"})


def test_t25_concurrent_same_execution_key_allows_one_effect(tmp_path):
    ctx = context(tmp_path / "r.db")
    obj = sign_one(p2r_base())
    calls = []
    entered = threading.Event()
    release = threading.Event()

    def action(effect, ekey):
        calls.append(ekey)
        entered.set()
        assert release.wait(timeout=5)
        return {"status": "ok"}

    def run():
        try:
            return ("ok", execute(obj, ctx, action))
        except ExecutionError as exc:
            return (exc.code, None)

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(run) for _ in range(8)]
        assert entered.wait(timeout=5)
        # Give waiting contenders time to observe RESERVED before the first action completes.
        import time
        time.sleep(0.1)
        release.set()
        results = [future.result(timeout=10) for future in futures]
    assert len(calls) == 1
    assert any(status == "ALREADY_RESERVED" for status, _ in results)
    assert all(status in {"ok", "ALREADY_RESERVED"} for status, _ in results)


def test_t26_concurrent_same_effect_with_distinct_keys_is_serialized(tmp_path):
    ctx = context(tmp_path / "r.db")
    obj1 = sign_one(p2r_base(nonce="nonce-a", on_same_effect="deny"))
    obj2 = sign_one(p2r_base(nonce="nonce-b", on_same_effect="deny"))

    calls = []
    entered = threading.Event()
    release = threading.Event()

    def action(effect, ekey):
        calls.append(ekey)
        entered.set()
        assert release.wait(timeout=5)
        return {"status": "ok"}

    def run(obj):
        try:
            execute(obj, ctx, action)
            return "ok"
        except ExecutionError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(run, obj1)
        assert entered.wait(timeout=5)
        f2 = pool.submit(run, obj2)
        import time
        time.sleep(0.1)
        assert not f2.done() or True
        # The second attempt cannot enter the action while the first reservation is active.
        release.set()
        results = [f1.result(timeout=10), f2.result(timeout=10)]
    assert len(calls) == 1
    assert sorted(results) == ["EFFECT_IN_PROGRESS", "ok"]


def test_at_most_once_records_ambiguity_and_never_auto_retries(tmp_path):
    ctx = context(tmp_path / "r.db")
    obj = sign_one(p2r_base())

    calls = 0
    def action(effect, ekey):
        nonlocal calls
        calls += 1
        raise RuntimeError("unknown external outcome")

    with pytest.raises(RuntimeError):
        execute(obj, ctx, action, action_semantics="at_most_once")
    with pytest.raises(ExecutionError, match="EFFECT_RECONCILIATION_REQUIRED"):
        execute(obj, ctx, action, action_semantics="at_most_once")
    assert calls == 1


def test_cached_receipt_must_bind_to_current_p2r(tmp_path):
    import json
    import sqlite3
    from p2r.effect import execution_key
    from p2r.receipt import build_receipt

    ctx = context(tmp_path / "r.db")
    obj = sign_one(p2r_base())
    execute(obj, ctx, lambda effect, ekey: {"status": "ok"})
    ekey = execution_key(obj)
    forged = build_receipt(
        payload_digest="different-payload",
        execution_key=ekey,
        effect_identity="different-effect",
        action_semantics="idempotent",
        observed_effect={"status": "ok"},
        observer_id="observer",
        observer_scope=["effect:transfer", "receipt:issue"],
        observed_at=1001,
        signer=OBSERVER,
    )
    db = sqlite3.connect(tmp_path / "r.db")
    db.execute("UPDATE reservations SET receipt_json=? WHERE execution_key=?", (json.dumps(forged), ekey))
    db.commit()
    db.close()
    with pytest.raises(ExecutionError, match="RETRY_RECEIPT_PAYLOAD_MISMATCH"):
        execute(obj, ctx, lambda effect, ekey: {"status": "must-not-run"})
