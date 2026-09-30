"""Minimal end-to-end demo for P2R-Ω Core."""

from __future__ import annotations

import json
from pathlib import Path

from p2r.authority import sign_payload
from p2r.canonical import canonicalize
from p2r.digest import seal, sha256_b64
from p2r.executor import ExecutionContext, execute
from p2r.keys import Keyring, LocalSigner
from p2r.registry import Registry
from p2r.receipt import verify_receipt
from p2r.universe import StaticUniverseResolver, manifest_root

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "demo.db"
if DB.exists():
    DB.unlink()

ALICE = LocalSigner.from_seed("alice", b"\x01" * 32)
OBSERVER = LocalSigner.from_seed("observer", b"\x03" * 32)
UNIVERSE = [
    {"evidence_id": "ev-1", "kind": "document", "title": "Target account", "amount": 100, "currency": "EUR"},
    {"evidence_id": "ev-2", "kind": "document", "status": "verified", "target": "acct-1"},
]

goal = {"task": "transfer", "target": "acct-1", "amount": 100}
obj = seal({
    "type": "p2r/v1",
    "world": {"discovery": {"query": "acct-1"}, "manifest_root": {"alg": "sha-256", "value": manifest_root(UNIVERSE)}},
    "intent": {
        "profile": "literal-structured-intent-v1",
        "content": json.dumps(goal, ensure_ascii=False, separators=(",", ":")),
        "structured_goal": goal,
    },
    "decision": {"status": "VERIFIED"},
    "authority": {
        "principal": "agent:alice",
        "nonce_scope": "global",
        "nonce": "nonce-demo",
        "authorized_signers": ["alice"],
        "threshold": 1,
    },
    "effect": {
        "profile": "transfer-v1",
        "rule": "transfer",
        "argument": {"amount": 100, "currency": "EUR", "target": "acct-1"},
        "idempotency_key": "idem-demo",
    },
    "execution_policy": {
        "require_decision_status": "VERIFIED",
        "on_same_effect": "deny",
        "reservation_timeout_seconds": 300,
    },
    "provenance": [
        {"path": "/amount", "value_digest": sha256_b64(canonicalize(100)), "source": {"evidence_id": "ev-1", "span": {"start": 1, "end": 5}}},
        {"path": "/target", "value_digest": sha256_b64(canonicalize("acct-1")), "source": {"evidence_id": "ev-2", "span": {"start": 7, "end": 13}}},
    ],
})
obj = sign_payload(obj, ALICE)

keyring = Keyring()
keyring.add("alice", ALICE.public_key())
keyring.add("observer", OBSERVER.public_key())
ctx = ExecutionContext(
    keyring=keyring,
    universe_resolver=StaticUniverseResolver(UNIVERSE),
    registry=Registry(DB),
    observer_signer=OBSERVER,
    observer_scopes={"observer": ["effect:transfer", "receipt:issue"]},
    clock=lambda: 1000,
)

calls = 0

def action(effect, execution_key):
    global calls
    calls += 1
    return {"status": "ok", "target": effect["argument"]["target"], "execution_key": execution_key}

first = execute(obj, ctx, action)
second = execute(obj, ctx, action)
verify_receipt(second, ctx.keyring, ctx.observer_scopes)
print(json.dumps({"effect_calls": calls, "same_cached_receipt": first == second, "result": second["result"]}, indent=2))
