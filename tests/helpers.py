import json
from copy import deepcopy

from p2r.authority import sign_payload
from p2r.canonical import canonicalize
from p2r.digest import seal, sha256_b64
from p2r.executor import ExecutionContext
from p2r.keys import Keyring, LocalSigner
from p2r.registry import Registry
from p2r.universe import StaticUniverseResolver, manifest_root

ALICE = LocalSigner.from_seed("alice", b"\x01" * 32)
BOB = LocalSigner.from_seed("bob", b"\x02" * 32)
OBSERVER = LocalSigner.from_seed("observer", b"\x03" * 32)


def universe():
    return [
        {
            "evidence_id": "ev-1",
            "kind": "document",
            "title": "Target account",
            "amount": 100,
            "currency": "EUR",
        },
        {
            "evidence_id": "ev-2",
            "kind": "document",
            "status": "verified",
            "target": "acct-1",
        },
    ]


def p2r_base(*, threshold=1, authorized=None, decision="VERIFIED", on_same_effect="deny", nonce="nonce-1"):
    world = universe()
    goal = {"task": "transfer", "target": "acct-1", "amount": 100}
    obj = {
        "type": "p2r/v1",
        "world": {
            "discovery": {"query": "acct-1"},
            "manifest_root": {"alg": "sha-256", "value": manifest_root(world)},
        },
        "intent": {
            "profile": "literal-structured-intent-v1",
            "content": json.dumps(goal, separators=(",", ":"), ensure_ascii=False),
            "structured_goal": goal,
        },
        "decision": {"status": decision},
        "authority": {
            "principal": "agent:alice",
            "nonce_scope": "global",
            "nonce": nonce,
            "authorized_signers": authorized or ["alice"],
            "threshold": threshold,
        },
        "effect": {
            "profile": "transfer-v1",
            "rule": "transfer",
            "argument": {"amount": 100, "currency": "EUR", "target": "acct-1"},
            "idempotency_key": "idem-001",
        },
        "execution_policy": {
            "require_decision_status": "VERIFIED",
            "on_same_effect": on_same_effect,
            "reservation_timeout_seconds": 300,
        },
        "provenance": [
            {
                "path": "/amount",
                "value_digest": sha256_b64(canonicalize(100)),
                "source": {"evidence_id": "ev-1", "span": {"start": 1, "end": 5}},
            },
            {
                "path": "/target",
                "value_digest": sha256_b64(canonicalize("acct-1")),
                "source": {"evidence_id": "ev-2", "span": {"start": 7, "end": 13}},
            },
        ],
    }
    return seal(obj)


def sign_one(obj):
    return sign_payload(obj, ALICE)


def sign_two(obj):
    obj = sign_payload(obj, ALICE)
    return sign_payload(obj, BOB)


def keyring_with(*signers):
    kr = Keyring()
    for signer in signers:
        kr.add(signer.signer_id, signer.public_key())
    return kr


def context(path, *, clock_value=1000):
    kr = keyring_with(ALICE, BOB, OBSERVER)
    registry = Registry(path, reservation_timeout=300)
    return ExecutionContext(
        keyring=kr,
        universe_resolver=StaticUniverseResolver(universe()),
        registry=registry,
        observer_signer=OBSERVER,
        observer_scopes={"observer": ["effect:transfer", "receipt:issue"]},
        clock=lambda: clock_value,
    )


def copy_obj(obj):
    return deepcopy(obj)
