"""Adversarial campaign. These tests try to break V1 invariants."""

from __future__ import annotations

import json
import random
import sqlite3
import threading
from copy import deepcopy
from multiprocessing import get_context

import pytest

from p2r.authority import sign_payload, verify_signatures
from p2r.canonical import canonicalize
from p2r.decision import verify_decision
from p2r.digest import compute_payload_digest, seal, sha256_b64
from p2r.effect import effect_identity, execution_key
from p2r.errors import ExecutionError, PreDispatchError, RegistryError, VerifyError
from p2r.executor import execute
from p2r.keys import Keyring, LocalSigner
from p2r.provenance import _json_pointer_get, verify_provenance
from p2r.receipt import build_receipt, verify_receipt
from p2r.registry import Registry
from p2r.universe import manifest_root
from p2r.verify import verify_object

from .helpers import ALICE, BOB, OBSERVER, context, copy_obj, keyring_with, p2r_base, sign_one, sign_two, universe
from . import oracle


def _ctx(path, clock=1000):
    return context(path, clock_value=clock)


def _run(obj, path, action, semantics="idempotent", clock=1000):
    return execute(obj, _ctx(path, clock), action, semantics)


def test_canonical_key_order_utf16_not_utf8():
    obj = {"\uffff": 1, "\U0001F600": 2}
    raw = canonicalize(obj)
    assert raw.index("\U0001F600".encode("utf-8")) < raw.index("\uffff".encode("utf-8"))
    again = {"\U0001F600": 2, "\uffff": 1}
    assert canonicalize(again) == raw


def test_canonical_line_separators_match_rfc8785():
    raw = canonicalize("\u2028\u2029")
    assert raw == b'"\\u2028\\u2029"'
    assert b"\xe2\x80\xa8" not in raw


def test_canonical_controls_and_identity_pairs():
    assert canonicalize("\n\t\r\"\\") == b'"\\n\\t\\r\\"\\\\"'
    assert canonicalize("é") != canonicalize("e\u0301")
    assert canonicalize("") == b'""'
    assert canonicalize({}) == b"{}"
    assert canonicalize([]) == b"[]"
    assert canonicalize((1, 2)) == canonicalize([1, 2])
    assert canonicalize(-0) == b"0"
    assert canonicalize(-(10**100)) == b"-" + str(10**100).encode()
    with pytest.raises(TypeError):
        canonicalize(1.0)
    with pytest.raises(TypeError):
        canonicalize({1: 2})
    with pytest.raises(TypeError):
        canonicalize(object())


def test_digest_binds_every_signed_field(tmp_path):
    ctx = _ctx(tmp_path / "d.db")
    base = sign_one(p2r_base())
    digest = base["payload_digest"]["value"]
    mutations = []
    mutated = copy_obj(base)
    mutated["effect"]["argument"]["amount"] = 1
    mutations.append(mutated)
    mutated = copy_obj(base)
    mutated["authority"]["nonce"] = "other"
    mutations.append(mutated)
    mutated = copy_obj(base)
    mutated["decision"]["status"] = "UNKNOWN"
    mutations.append(mutated)
    mutated = copy_obj(base)
    mutated["world"]["manifest_root"]["value"] = "AAAA"
    mutations.append(mutated)
    mutated = copy_obj(base)
    mutated["provenance"][0]["path"] = "/missing"
    mutations.append(mutated)
    mutated = copy_obj(base)
    mutated["execution_policy"]["on_same_effect"] = "allow_new_attempt"
    mutations.append(mutated)
    mutated = copy_obj(base)
    extra = ALICE.sign(digest.encode("ascii"))
    mutated["signatures"].append(extra)
    assert compute_payload_digest(mutated) == digest
    verify_object(mutated, ctx)
    for obj in mutations:
        assert compute_payload_digest(obj) != digest
        with pytest.raises(VerifyError):
            verify_object(obj, ctx)


def test_digest_encoding_rejects_standard_base64_padding(tmp_path):
    obj = sign_one(p2r_base())
    obj["payload_digest"]["value"] = obj["payload_digest"]["value"] + "="
    with pytest.raises(VerifyError, match="PAYLOAD_DIGEST_MISMATCH"):
        verify_object(obj, _ctx(tmp_path / "pad.db"))


@pytest.mark.parametrize("threshold", [0, -1, 2])
def test_threshold_bounds(tmp_path, threshold):
    ctx = _ctx(tmp_path / "t.db")
    obj = sign_one(p2r_base(threshold=threshold, authorized=["alice"]))
    with pytest.raises(VerifyError, match="AUTHORITY_BAD_THRESHOLD"):
        verify_object(obj, ctx)


def test_duplicate_signatures_count_once(tmp_path):
    ctx = _ctx(tmp_path / "s.db")
    obj = p2r_base(threshold=2, authorized=["alice", "bob"])
    obj = sign_payload(obj, ALICE)
    obj = sign_payload(obj, ALICE)
    with pytest.raises(VerifyError, match="SIGNATURE_THRESHOLD_NOT_MET"):
        verify_object(obj, ctx)
    ok = sign_two(p2r_base(threshold=2, authorized=["alice", "bob"]))
    assert verify_object(ok, ctx) is True


def test_foreign_and_wrong_alg_do_not_create_authority(tmp_path):
    ctx = _ctx(tmp_path / "a.db")
    eve = LocalSigner.from_seed("eve", b"\x09" * 32)
    obj = p2r_base()
    digest = obj["payload_digest"]["value"].encode("ascii")
    bad = eve.sign(digest)
    bad["alg"] = "none"
    obj["signatures"] = [bad, {"alg": "ed25519", "signer": "alice", "value": "!!!!"}]
    with pytest.raises(VerifyError, match="SIGNATURE_THRESHOLD_NOT_MET"):
        verify_object(obj, ctx)
    other = sign_one(p2r_base(nonce="nonce-2"))
    obj = sign_one(p2r_base())
    obj["signatures"] = other["signatures"]
    with pytest.raises(VerifyError, match="SIGNATURE_THRESHOLD_NOT_MET"):
        verify_object(obj, ctx)


def test_signature_order_is_irrelevant(tmp_path):
    ctx = _ctx(tmp_path / "o.db")
    forward = sign_two(p2r_base(threshold=2, authorized=["alice", "bob"]))
    backward = sign_payload(sign_payload(p2r_base(threshold=2, authorized=["alice", "bob"]), BOB), ALICE)
    assert verify_object(forward, ctx) is True
    assert verify_object(backward, ctx) is True


def test_universe_shape_and_root_stability():
    assert manifest_root([]) == oracle.manifest_root([])
    one = [{"evidence_id": "a", "n": 1}]
    assert manifest_root(one) == oracle.manifest_root(one)
    for size in (2, 3, 4, 5):
        world = [{"evidence_id": f"id-{i}", "n": i} for i in range(size)]
        shuffled = list(reversed(world))
        assert manifest_root(world) == manifest_root(shuffled)
        assert manifest_root(world) == oracle.manifest_root(world)
    changed = [{"evidence_id": "a", "n": 1}, {"evidence_id": "b", "n": 2}]
    touched = [{"evidence_id": "a", "n": 1}, {"evidence_id": "b", "n": 3}]
    assert manifest_root(changed) != manifest_root(touched)
    with pytest.raises(VerifyError, match="UNIVERSE_EVIDENCE_ID_DUPLICATE"):
        manifest_root([{"evidence_id": "a"}, {"evidence_id": "a"}])
    with pytest.raises(VerifyError, match="UNIVERSE_EVIDENCE_ID_MISSING"):
        manifest_root([{"evidence_id": ""}])


def test_pointer_object_and_array_are_not_confused():
    doc = {
        "a": [10, 20, {"01": 7, "-": 8, "0": 9}],
        "01": 1,
        "-": 2,
        "": {"c": 3},
        "~": 4,
        "/": 5,
        "~1": 6,
        "~/": 7,
        "~0": 8,
        "~01": 9,
    }
    accepted = {
        "": doc,
        "/a/0": 10,
        "/a/1": 20,
        "/a/2/01": 7,
        "/a/2/-": 8,
        "/a/2/0": 9,
        "/01": 1,
        "/-": 2,
        "/~0": 4,
        "/~1": 5,
        "/~01": 6,
        "/~0~1": 7,
        "/~00": 8,
        "/~001": 9,
        "//c": 3,
    }
    rejected = [
        "/a/01", "/a/00", "/a/+1", "/a/-1", "/a/-", "/a/1_0", "/a/1e2", "/a/1.0",
        "/a/0\n", "/a/１", "/a/١", "/a/²",
        "/~~1", "/~2", "/~", "/%7E0", "/%2F", "a/0", "#/a",
    ]
    for path, expected in accepted.items():
        assert _json_pointer_get(doc, path) == expected
        assert oracle.pointer(doc, path) == expected
    for path in rejected:
        with pytest.raises(VerifyError):
            _json_pointer_get(doc, path)
        with pytest.raises((ValueError, LookupError)):
            oracle.pointer(doc, path)
    with pytest.raises(VerifyError, match="PROVENANCE_PATH_NOT_FOUND"):
        _json_pointer_get(doc, "/a/3")
    with pytest.raises(VerifyError, match="PROVENANCE_PATH_NOT_FOUND"):
        _json_pointer_get(doc, "/a/0/nope")
    with pytest.raises(VerifyError, match="PROVENANCE_PATH_NOT_FOUND"):
        _json_pointer_get({"a": None}, "/a/b")
    with pytest.raises(VerifyError, match="PROVENANCE_PATH_NOT_FOUND"):
        _json_pointer_get(doc, "/a/" + ("9" * 20000))


def test_intent_and_decision_fail_closed(tmp_path):
    ctx = _ctx(tmp_path / "i.db")
    obj = p2r_base()
    obj["intent"]["content"] = '{"task":"transfer","target":"acct-1","amount":100,"extra":1}'
    obj.pop("payload_digest", None)
    obj = sign_one(seal(obj))
    with pytest.raises(VerifyError, match="INTENT_MISMATCH"):
        verify_object(obj, ctx)
    spaced = p2r_base()
    goal = spaced["intent"]["structured_goal"]
    spaced["intent"]["content"] = json.dumps(goal, indent=2)
    spaced.pop("payload_digest", None)
    spaced.pop("signatures", None)
    spaced = sign_one(seal(spaced))
    assert verify_object(spaced, ctx) is True
    unknown = sign_one(p2r_base(decision="UNKNOWN"))
    with pytest.raises(VerifyError, match="DECISION_STATUS_REJECTED"):
        verify_object(unknown, ctx)
    conflict = p2r_base(decision="CONFLICT")
    conflict["execution_policy"]["require_decision_status"] = "CONFLICT"
    conflict.pop("payload_digest", None)
    conflict = sign_one(seal(conflict))
    assert verify_object(conflict, _ctx(tmp_path / "c.db")) is True
    with pytest.raises(VerifyError, match="DECISION_STATUS_INVALID"):
        verify_decision({"decision": {"status": "MAYBE"}, "execution_policy": {}})


def test_effect_identity_ignores_nonce_and_binds_parameters():
    base = p2r_base()
    other_nonce = p2r_base(nonce="nonce-2")
    assert effect_identity(base) == effect_identity(other_nonce)
    assert execution_key(base) != execution_key(other_nonce)
    assert effect_identity(base) == oracle.effect_identity(base)
    assert execution_key(base) == oracle.execution_key(base)
    changed = copy_obj(base)
    changed["effect"]["argument"] = {"amount": 101, "currency": "EUR", "target": "acct-1"}
    assert effect_identity(changed) != effect_identity(base)
    for field, value in (
        ("principal", "agent:bob"),
        ("nonce", "nonce-9"),
    ):
        tweaked = copy_obj(base)
        tweaked["authority"][field] = value
        if field == "nonce":
            assert effect_identity(tweaked) == effect_identity(base)
            assert execution_key(tweaked) != execution_key(base)
        else:
            assert effect_identity(tweaked) != effect_identity(base)
    blank = copy_obj(base)
    blank["authority"]["nonce_scope"] = ""
    missing = copy_obj(base)
    missing["authority"].pop("nonce_scope")
    explicit = copy_obj(base)
    explicit["authority"]["nonce_scope"] = None
    assert execution_key(blank) == execution_key(base)
    assert execution_key(missing) == execution_key(base)
    assert execution_key(explicit) == execution_key(base)
    weird = copy_obj(base)
    weird["authority"]["nonce_scope"] = 5
    with pytest.raises(VerifyError, match="AUTHORITY_NONCE_SCOPE_INVALID"):
        execution_key(weird)


def test_same_effect_cannot_reuse_authority_for_a_different_payload(tmp_path):
    calls = []
    first = sign_one(p2r_base())
    second = copy_obj(first)
    second.pop("signatures", None)
    second.pop("payload_digest", None)
    second["intent"]["structured_goal"] = {"task": "transfer", "target": "acct-1", "amount": 100, "note": "x"}
    second["intent"]["content"] = json.dumps(second["intent"]["structured_goal"], separators=(",", ":"))
    second = sign_one(seal(second))
    assert effect_identity(first) == effect_identity(second)
    assert execution_key(first) == execution_key(second)
    assert first["payload_digest"]["value"] != second["payload_digest"]["value"]
    path = tmp_path / "bind.db"
    _run(first, path, lambda effect, key: calls.append(key) or {"ok": True})
    with pytest.raises(ExecutionError, match="RETRY_RECEIPT_PAYLOAD_MISMATCH"):
        _run(second, path, lambda effect, key: calls.append("again") or {"ok": True})
    assert calls == [execution_key(first)]


def test_ghost_status_cannot_open_a_new_attempt(tmp_path):
    path = tmp_path / "ghost.db"
    registry = Registry(path)
    obj = p2r_base()
    db = sqlite3.connect(path)
    db.execute(
        "INSERT INTO reservations(execution_key,effect_identity,status,receipt_json,updated_at) VALUES(?,?,?,?,?)",
        ("ghost", effect_identity(obj), "GHOST", None, 1),
    )
    db.commit()
    db.close()
    with pytest.raises(RegistryError, match="REGISTRY_STATUS_INVALID"):
        registry.reserve(execution_key(obj), effect_identity(obj), "deny", 50)


def test_corrupt_cached_receipt_does_not_redispatch(tmp_path):
    path = tmp_path / "bad.db"
    calls = []
    obj = sign_one(p2r_base())
    _run(obj, path, lambda effect, key: calls.append(1) or {"ok": True})
    db = sqlite3.connect(path)
    db.execute("UPDATE reservations SET receipt_json=? WHERE execution_key=?", ("{not-json", execution_key(obj)))
    db.commit()
    db.close()
    with pytest.raises(ExecutionError, match="RETRY_RECEIPT_INVALID"):
        _run(obj, path, lambda effect, key: calls.append(2) or {"ok": True})
    assert calls == [1]


def test_ambiguous_blocks_until_reconciliation(tmp_path):
    path = tmp_path / "amb.db"
    calls = []

    def action(effect, key):
        calls.append(key)
        raise RuntimeError("dispatch uncertain")

    obj = sign_one(p2r_base())
    with pytest.raises(RuntimeError, match="dispatch uncertain"):
        _run(obj, path, action)
    with pytest.raises(ExecutionError, match="EFFECT_RECONCILIATION_REQUIRED"):
        _run(obj, path, lambda effect, key: calls.append("second"))
    assert len(calls) == 1
    row = Registry(path).get(execution_key(obj))
    assert row["status"] == "RESERVED_AMBIGUOUS"


def test_pre_dispatch_failure_can_be_retried(tmp_path):
    path = tmp_path / "pre.db"
    calls = []
    obj = sign_one(p2r_base())

    def boom(effect, key):
        calls.append("boom")
        raise PreDispatchError("not sent")

    with pytest.raises(PreDispatchError):
        _run(obj, path, boom)
    _run(obj, path, lambda effect, key: calls.append("ok") or {"ok": True})
    assert calls == ["boom", "ok"]


def test_external_success_then_persist_failure_does_not_run_again(tmp_path):
    path = tmp_path / "persist.db"
    calls = []

    class Boom(Registry):
        def mark_executed(self, *args, **kwargs):
            raise RegistryError("REGISTRY_MARK_EXECUTED_FAILED", "disk")

    ctx = _ctx(path)
    ctx.registry = Boom(path)
    obj = sign_one(p2r_base())
    with pytest.raises(RegistryError):
        execute(obj, ctx, lambda effect, key: calls.append(1) or {"done": True})
    assert Registry(path).get(execution_key(obj))["status"] == "RESERVED_AMBIGUOUS"
    with pytest.raises(ExecutionError, match="EFFECT_RECONCILIATION_REQUIRED"):
        _run(obj, path, lambda effect, key: calls.append(2) or {"done": True})
    assert calls == [1]


def test_crash_after_committed_execution_replays_receipt(tmp_path):
    path = tmp_path / "done.db"
    calls = []
    obj = sign_one(p2r_base())
    first = _run(obj, path, lambda effect, key: calls.append(1) or {"done": True})
    second = _run(obj, path, lambda effect, key: calls.append(2) or {"done": True})
    assert first == second
    assert calls == [1]


def test_deny_blocks_new_nonce_for_same_effect(tmp_path):
    path = tmp_path / "deny.db"
    calls = []
    _run(sign_one(p2r_base()), path, lambda effect, key: calls.append(key) or {"ok": True})
    with pytest.raises(ExecutionError, match="EFFECT_ALREADY_EXECUTED"):
        _run(sign_one(p2r_base(nonce="nonce-2")), path, lambda effect, key: calls.append("no") or {"ok": True})
    assert len(calls) == 1


def test_concurrency_same_key_runs_once(tmp_path):
    path = tmp_path / "threads.db"
    Registry(path)
    obj = sign_one(p2r_base())
    calls = []
    errors = []
    ok = []
    barrier = threading.Barrier(100)

    def worker():
        barrier.wait()
        try:
            _run(obj, path, lambda effect, key: calls.append(key) or {"ok": True})
            ok.append(1)
        except ExecutionError as exc:
            errors.append(exc.code)

    threads = [threading.Thread(target=worker) for _ in range(100)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert calls == [execution_key(obj)]
    assert len(ok) + len(errors) == 100
    assert set(errors) <= {"ALREADY_RESERVED"}


def test_concurrency_same_effect_deny_runs_once(tmp_path):
    path = tmp_path / "effect-threads.db"
    Registry(path)
    calls = []
    errors = []
    barrier = threading.Barrier(100)

    def worker(i):
        barrier.wait()
        obj = sign_one(p2r_base(nonce=f"n-{i}"))
        try:
            _run(obj, path, lambda effect, key: calls.append(key) or {"ok": True})
        except ExecutionError as exc:
            errors.append(exc.code)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(100)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(calls) == 1
    assert set(errors) <= {"EFFECT_IN_PROGRESS", "EFFECT_ALREADY_EXECUTED", "ALREADY_RESERVED", "EFFECT_RECONCILIATION_REQUIRED"}


def _process_worker(path, nonce, queue):
    try:
        obj = sign_one(p2r_base(nonce=nonce))
        execute(obj, _ctx(path), lambda effect, key: {"ok": True})
        queue.put("ran")
    except ExecutionError as exc:
        queue.put(exc.code)
    except Exception as exc:
        queue.put(type(exc).__name__)


def test_two_processes_cannot_both_execute(tmp_path):
    path = tmp_path / "procs.db"
    Registry(path)
    queue = get_context("fork").Queue()
    procs = [
        get_context("fork").Process(target=_process_worker, args=(str(path), "nonce-1", queue)),
        get_context("fork").Process(target=_process_worker, args=(str(path), "nonce-2", queue)),
    ]
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join(20)
    results = [queue.get(timeout=5) for _ in procs]
    assert results.count("ran") == 1


def test_receipt_signature_is_not_sufficient(tmp_path):
    ctx = _ctx(tmp_path / "rcpt.db")
    obj = sign_one(p2r_base())
    receipt = build_receipt(
        payload_digest=obj["payload_digest"]["value"],
        execution_key=execution_key(obj),
        effect_identity=effect_identity(obj),
        action_semantics="idempotent",
        observed_effect={"ok": True},
        observer_id="observer",
        observer_scope=["effect:transfer"],
        observed_at=1000,
        signer=OBSERVER,
    )
    assert verify_receipt(receipt, ctx.keyring, ctx.observer_scopes) is True
    stolen = copy_obj(receipt)
    stolen["payload_digest"] = "other"
    with pytest.raises(VerifyError, match="RECEIPT_SIGNATURE_INVALID"):
        verify_receipt(stolen, ctx.keyring, ctx.observer_scopes)
    wide = copy_obj(receipt)
    wide["observer"]["scope"] = ["effect:transfer", "admin"]
    with pytest.raises(VerifyError):
        verify_receipt(wide, ctx.keyring, ctx.observer_scopes)
    eve = LocalSigner.from_seed("eve", b"\x07" * 32)
    kr = keyring_with(ALICE, OBSERVER, eve)
    foreign = build_receipt(
        payload_digest=obj["payload_digest"]["value"],
        execution_key=execution_key(obj),
        effect_identity=effect_identity(obj),
        action_semantics="idempotent",
        observed_effect={"ok": True},
        observer_id="eve",
        observer_scope=[],
        observed_at=1000,
        signer=eve,
    )
    with pytest.raises(VerifyError, match="OBSERVER_NOT_TRUSTED"):
        verify_receipt(foreign, kr, {"observer": ["effect:transfer"]})


def test_replay_across_fresh_registry_is_a_new_local_attempt(tmp_path):
    obj = sign_one(p2r_base())
    calls = []
    _run(obj, tmp_path / "one.db", lambda effect, key: calls.append("one") or {"ok": True})
    _run(obj, tmp_path / "two.db", lambda effect, key: calls.append("two") or {"ok": True})
    assert calls == ["one", "two"]


def test_fuzz_and_properties_do_not_crash_or_diverge():
    rng = random.Random(20261001)
    unexpected = []

    def leaf():
        roll = rng.randrange(8)
        if roll == 0:
            return None
        if roll == 1:
            return rng.choice([True, False])
        if roll == 2:
            return rng.choice([0, -1, 2**63, -10**30, rng.randint(-5, 5)])
        if roll == 3:
            return rng.choice(["", "a", "é", "e\u0301", "\U0001F600", "\n", "\u2028", "~"])
        return rng.randint(0, 3)

    def build(depth=0):
        if depth > 3 or rng.random() < 0.4:
            return leaf()
        if rng.random() < 0.5:
            return [build(depth + 1) for _ in range(rng.randint(0, 3))]
        keys = ["", "a", "b", "01", "-", "\U0001F600", "\uffff"]
        rng.shuffle(keys)
        return {key: build(depth + 1) for key in keys[: rng.randint(0, 4)]}

    for _ in range(2000):
        value = build()
        try:
            left = canonicalize(value)
            right = oracle.canonicalize(value)
        except TypeError:
            with pytest.raises(TypeError):
                oracle.canonicalize(value)
            continue
        except Exception as exc:
            unexpected.append(type(exc).__name__)
            continue
        if left != right:
            unexpected.append("DIFF")
    assert unexpected == []

    doc = {"a": [0, {"01": 1, "b": [2]}], "": 3, "~": 4}
    paths = ["", "/a/0", "/a/1/01", "/a/01", "/a/-", "/~0", "/~", "/nope", "/a/9", "a", "/a/" + "1" * 30]
    for _ in range(200):
        paths.append("/a/" + str(rng.randint(-2, 5)))
    for path in paths:
        ref_code = "OK"
        try:
            ref = _json_pointer_get(doc, path)
        except VerifyError as exc:
            ref_code = exc.code
            ref = None
        try:
            other = oracle.pointer(doc, path)
            other_code = "OK"
        except ValueError:
            other_code = "INVALID"
            other = None
        except LookupError:
            other_code = "NOT_FOUND"
            other = None
        if ref_code == "OK":
            assert other_code == "OK" and other == ref
        elif ref_code == "PROVENANCE_PATH_INVALID":
            assert other_code == "INVALID"
        else:
            assert other_code == "NOT_FOUND"


def test_verify_signatures_alone_does_not_bind_the_body(tmp_path):
    obj = sign_one(p2r_base())
    forged = copy_obj(obj)
    forged["effect"]["argument"]["amount"] = 1
    # The detached signature still matches the old digest text, not the new body.
    assert verify_signatures(forged, keyring_with(ALICE)) is True
    with pytest.raises(VerifyError, match="PAYLOAD_DIGEST_MISMATCH"):
        verify_object(forged, _ctx(tmp_path / "forge.db"))


def test_fuzz_mutated_objects_do_not_verify(tmp_path):
    ctx = _ctx(tmp_path / "fuzz.db")
    base = sign_one(p2r_base())
    rng = random.Random(11)
    unexpected = []
    accepted = []
    for i in range(1000):
        obj = copy_obj(base)
        roll = i % 7
        if roll == 0:
            obj["effect"]["argument"]["amount"] = 1000 + i
        elif roll == 1:
            obj["authority"]["nonce"] = f"n-{rng.randrange(10**9)}"
        elif roll == 2:
            obj["decision"]["status"] = rng.choice(["UNKNOWN", "CONFLICT", "NOPE", ""])
        elif roll == 3:
            obj["provenance"][0]["path"] = "/" + str(rng.randrange(1000))
        elif roll == 4:
            obj["world"]["manifest_root"]["value"] = "deadbeef"
        elif roll == 5:
            obj["signatures"][0]["value"] = "AAAA"
        else:
            obj["authority"]["threshold"] = 0
        try:
            if verify_object(obj, ctx):
                accepted.append(roll)
        except VerifyError:
            pass
        except TypeError:
            pass
        except Exception as exc:
            unexpected.append(type(exc).__name__)
    assert accepted == []
    assert unexpected == []
    value = []
    cursor = value
    for _ in range(2000):
        nxt = []
        cursor.append(nxt)
        cursor = nxt
    with pytest.raises(RecursionError):
        canonicalize(value)


def test_injected_receipt_bindings_do_not_redispatch(tmp_path):
    path = tmp_path / "inject.db"
    obj = sign_one(p2r_base())
    ctx = _ctx(path)
    eid = effect_identity(obj)
    ekey = execution_key(obj)
    calls = []

    def plant(receipt_json):
        db = sqlite3.connect(path)
        db.execute("DELETE FROM reservations")
        db.execute(
            "INSERT INTO reservations(execution_key,effect_identity,status,receipt_json,updated_at) VALUES(?,?,?,?,?)",
            (ekey, eid, "EXECUTED", receipt_json, 1),
        )
        db.commit()
        db.close()

    plant(None)
    with pytest.raises(ExecutionError, match="RETRY_RECEIPT_MISSING"):
        execute(obj, ctx, lambda effect, key: calls.append("missing"))

    other = build_receipt(
        payload_digest=obj["payload_digest"]["value"],
        execution_key=ekey,
        effect_identity="other-effect",
        action_semantics="idempotent",
        observed_effect={"ok": True},
        observer_id="observer",
        observer_scope=["effect:transfer"],
        observed_at=1000,
        signer=OBSERVER,
    )
    plant(json.dumps(other))
    with pytest.raises(ExecutionError, match="RETRY_RECEIPT_EFFECT_MISMATCH"):
        execute(obj, ctx, lambda effect, key: calls.append("effect"))

    rebound = build_receipt(
        payload_digest=obj["payload_digest"]["value"],
        execution_key="other-key",
        effect_identity=eid,
        action_semantics="idempotent",
        observed_effect={"ok": True},
        observer_id="observer",
        observer_scope=["effect:transfer"],
        observed_at=1000,
        signer=OBSERVER,
    )
    plant(json.dumps(rebound))
    with pytest.raises(ExecutionError, match="RETRY_RECEIPT_EXECUTION_KEY_MISMATCH"):
        execute(obj, ctx, lambda effect, key: calls.append("key"))

    semantics = build_receipt(
        payload_digest=obj["payload_digest"]["value"],
        execution_key="other-key",
        effect_identity=eid,
        action_semantics="at_most_once",
        observed_effect={"ok": True},
        observer_id="observer",
        observer_scope=["effect:transfer"],
        observed_at=1000,
        signer=OBSERVER,
    )
    plant(json.dumps(semantics))
    with pytest.raises(ExecutionError, match="RETRY_RECEIPT_EXECUTION_KEY_MISMATCH|ACTION_SEMANTICS_MISMATCH"):
        execute(obj, ctx, lambda effect, key: calls.append("sem"))
    assert calls == []
