# P2R-Ω Core V1 — Frozen Protocol Specification

## 1. Semantic separation

The protocol keeps these statements distinct:

```text
PROOF ≠ AUTHORITY ≠ EFFECT ≠ EXECUTION ≠ RECEIPT
```

A valid proof is not by itself authority to perform an effect. Authority is not evidence that an effect happened. Execution is not observation until a receipt is created.

## 2. Object envelope

A valid P2R object has these signed payload fields:

```json
{
  "type": "p2r/v1",
  "world": {
    "discovery": {},
    "manifest_root": {"alg": "sha-256", "value": "..."}
  },
  "intent": {
    "profile": "literal-structured-intent-v1",
    "content": "JSON text",
    "structured_goal": {}
  },
  "decision": {"status": "VERIFIED|UNKNOWN|CONFLICT"},
  "authority": {
    "principal": "...",
    "nonce_scope": "global",
    "nonce": "...",
    "authorized_signers": ["..."],
    "threshold": 1
  },
  "effect": {
    "profile": "...",
    "rule": "...",
    "argument": {},
    "idempotency_key": "..."
  },
  "execution_policy": {
    "require_decision_status": "VERIFIED",
    "on_same_effect": "deny|allow_new_attempt",
    "reservation_timeout_seconds": 300
  },
  "provenance": [],
  "payload_digest": {
    "alg": "sha-256",
    "value": "..."
  },
  "signatures": []
}
```

`payload_digest` and `signatures` are detached from the digest. The payload digest therefore commits to all other fields.

The `payload_digest` object itself is restricted to exactly `alg` and `value` in V1.

## 3. Canonicalization

Canonical V1 supports `null`, booleans, integers, strings, arrays/tuples, and objects with string keys.

Floats are rejected. Object keys are sorted by their UTF-16 big-endian code-unit encoding. Strings use RFC 8785 escapes, including U+2028 and U+2029. JSON is emitted without insignificant separators and with UTF-8 bytes.

This is a deliberately narrow deterministic subset rather than an unrestricted JSON canonicalizer.

## 4. Payload digest

```text
payload_digest = BASE64URL_NOPAD(
    SHA256(canonicalize(P2R without payload_digest and signatures))
)
```

`object_id = payload_digest`.

## 5. Authority signatures

Ed25519 signs the ASCII bytes of the payload-digest value.

The verifier:

1. requires at least one authorized signer;
2. requires `1 <= threshold <= number_of_authorized_signers`;
3. rejects duplicate authorized signer IDs;
4. counts each authorized signer at most once;
5. ignores signatures from unauthorized signers;
6. requires `alg == ed25519`;
7. requires the keyring to validate the signature.

## 6. Evidence universe

A resolver turns `world.discovery` into a canonical evidence sequence.

Each evidence object must contain a unique non-empty `evidence_id`.

Evidence is sorted by UTF-8 bytes of `evidence_id` before tree construction.

```text
leaf   = SHA256(0x00 || canonicalize(evidence)).digest()
parent = SHA256(0x01 || left || right).digest()
empty  = SHA256(0x02).digest()
```

An odd node is duplicated at the last position of its level.

The final digest is encoded as URL-safe base64 without padding.

The root returned by the resolver must equal `world.manifest_root.value`.

## 7. Intent

V1 uses only:

```text
literal-structured-intent-v1
```

The `content` string is parsed as JSON. The parsed value must equal `structured_goal` exactly.

## 8. Decision

Allowed statuses are:

```text
VERIFIED
UNKNOWN
CONFLICT
```

Default execution policy requires `VERIFIED`.

An object can explicitly require `UNKNOWN` or `CONFLICT`, but that policy must itself be inside the signed payload.

## 9. Provenance

Every provenance item contains:

```json
{
  "path": "/json/pointer",
  "value_digest": "...",
  "source": {
    "evidence_id": "...",
    "span": {"start": 0, "end": 1}
  }
}
```

The verifier checks:

- evidence ID exists in the resolved universe;
- path exists using RFC 6901 JSON Pointer semantics; reference tokens use RFC 6901 escaping exactly (`~0` for `~`, `~1` for `/`); malformed escapes such as `~`, `~~1`, and `~2` are invalid; array indices must match `0` or `[1-9][0-9]*` (so `01`, `00`, `+1`, `-0`, and `1_0` are invalid); object keys remain ordinary strings, so a key such as `"01"` remains valid;
- value digest matches the current resolved value;
- `start` and `end` are non-negative integers with `end > start`.

V1 does not verify the bytes behind the span. That remains outside the core boundary.

## 10. Effect identity

```text
effect_identity = H({
  actor_id      = authority.principal,
  operation     = effect.profile,
  rule          = effect.rule,
  parameters    = effect.argument,
  idempotency_key = effect.idempotency_key
})
```

The hash input is canonicalized with the same V1 canonicalizer and SHA-256 URL-safe base64 encoding.

## 11. Execution key

```text
execution_key = H({
  effect_identity,
  nonce_scope = authority.nonce_scope || "global",
  nonce       = authority.nonce
})
```

A changed nonce creates a different execution key while leaving `effect_identity` unchanged.

## 12. Action semantics

The caller declares one of:

```text
idempotent
at_most_once
```

This is an adapter/target contract. P2R does not infer it and does not turn it into a claim about an external system.

## 13. Reservation state machine

SQLite stores:

```text
RESERVED
EXECUTED
RESERVED_AMBIGUOUS
```

The key is `execution_key`.

Rules:

- same key + same effect + `EXECUTED` → cached retry;
- same key + `RESERVED` → `ALREADY_RESERVED`;
- same key + `RESERVED_AMBIGUOUS` → reconciliation required;
- different key + same effect + prior ambiguous → reconciliation required;
- different key + same effect + prior reserved → effect in progress;
- different key + same effect + prior executed + policy `deny` → already executed;
- different key + same effect + prior executed + policy `allow_new_attempt` → new reservation;
- same key + different effect → registry collision.

New reservations use `BEGIN IMMEDIATE` so competing writers serialize the registry decision.

## 14. Crash rule

After external dispatch may have started, any unexpected exception transitions `RESERVED` to `RESERVED_AMBIGUOUS`.

Only an explicit adapter-level `PreDispatchError` can be safely abandoned, because only the adapter can assert that no external dispatch occurred.

Stale `RESERVED` entries are converted to `RESERVED_AMBIGUOUS` during recovery according to the signed reservation timeout.

## 15. Receipt

A V1 receipt contains:

```text
type = p2r-receipt/v1
payload_digest
effect_identity
execution_key
action_semantics
observed_effect
observer { id, scope }
observed_at
result = COMPLETED
receipt_signature
```

The receipt digest covers every field except `receipt_signature`.

The signer must equal `observer.id`.

The verifier checks Ed25519 validity, requires the observer id to be present in the trusted scope map, and requires the declared observer scope to be a subset of the scope granted to that observer.

## 16. Retry binding

A cached receipt returned by the executor must satisfy all of:

```text
receipt.payload_digest == current P2R payload_digest
receipt.effect_identity == current effect_identity
receipt.execution_key == current execution_key
receipt.action_semantics == requested action_semantics
```

This prevents a valid observer receipt from a different object being returned as a retry result.

## 17. Non-goals

V1 does not claim:

- distributed consensus;
- multi-host global exactly-once;
- payment settlement;
- blockchain finality;
- truth of arbitrary external source bytes;
- proof that an external effect happened merely because a receipt is signed.

The external effect remains outside the cryptographic boundary once control is delegated to the adapter/target.
