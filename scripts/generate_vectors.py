"""Generate deterministic V1 vectors using fixed test-only Ed25519 seeds."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from p2r.authority import sign_payload
from p2r.canonical import canonicalize
from p2r.digest import seal, sha256_b64
from p2r.keys import LocalSigner
from p2r.receipt import build_receipt
from p2r.universe import manifest_root

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "vectors"

ALICE = LocalSigner.from_seed("alice", b"\x01" * 32)
BOB = LocalSigner.from_seed("bob", b"\x02" * 32)
OBSERVER = LocalSigner.from_seed("observer", b"\x03" * 32)

UNIVERSE = [
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


def base_object():
    goal = {"task": "transfer", "target": "acct-1", "amount": 100}
    return seal(
        {
            "type": "p2r/v1",
            "world": {
                "discovery": {"query": "acct-1"},
                "manifest_root": {"alg": "sha-256", "value": manifest_root(UNIVERSE)},
            },
            "intent": {
                "profile": "literal-structured-intent-v1",
                "content": json.dumps(goal, ensure_ascii=False, separators=(",", ":")),
                "structured_goal": goal,
            },
            "decision": {"status": "VERIFIED"},
            "authority": {
                "principal": "agent:alice",
                "nonce_scope": "global",
                "nonce": "nonce-1",
                "authorized_signers": ["alice"],
                "threshold": 1,
            },
            "effect": {
                "profile": "transfer-v1",
                "rule": "transfer",
                "argument": {"amount": 100, "currency": "EUR", "target": "acct-1"},
                "idempotency_key": "idem-001",
            },
            "execution_policy": {
                "require_decision_status": "VERIFIED",
                "on_same_effect": "deny",
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
    )


def write(path: Path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


obj = sign_payload(base_object(), ALICE)
write(VECTORS / "universe.json", UNIVERSE)
write(VECTORS / "keyring.json", {
    "keys": {
        "alice": ALICE.public_key_b64(),
        "bob": BOB.public_key_b64(),
        "observer": OBSERVER.public_key_b64(),
    },
    "test_seed_note": "Private seeds are intentionally not included in distributed vectors.",
})
write(VECTORS / "p2r-valid.json", obj)

tampered = deepcopy(obj)
tampered["effect"]["argument"]["amount"] = 9999
write(VECTORS / "p2r-tampered.json", tampered)

receipt = build_receipt(
    payload_digest=obj["payload_digest"]["value"],
    execution_key="vector-execution-key",
    effect_identity="vector-effect-identity",
    action_semantics="idempotent",
    observed_effect={"status": "ok", "target": "acct-1"},
    observer_id="observer",
    observer_scope=["effect:transfer", "receipt:issue"],
    observed_at=1000,
    signer=OBSERVER,
)
write(VECTORS / "receipt-valid.json", receipt)
print("vectors generated")
