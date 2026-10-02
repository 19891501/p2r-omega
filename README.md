# P2R-Ω Core

**P2R-Ω Core — Proof-to-Realization Object**

P2R-Ω is a small authorization/execution object designed around one security invariant:

```text
PROOF ≠ AUTHORITY ≠ EFFECT ≠ EXECUTION ≠ RECEIPT
```

A proof may be valid while the exact effect, the execution attempt, or the observed result is not. P2R binds the authorized effect to a digest, then uses an execution registry to prevent accidental reuse of the same execution attempt.

## What V1 does

```text
DISCOVERY → UNIVERSE → SELECTION → INTENT → DECISION → AUTHORITY → EFFECT → EXECUTION → RECEIPT
```

The V1 implementation includes:

- deterministic canonicalization for a strict JSON subset;
- SHA-256 payload digests with URL-safe unpadded base64;
- detached Ed25519 authority signatures and threshold verification;
- deterministic evidence-universe root (`H(0x00 || leaf)`, `H(0x01 || left || right)`, `H(0x02)` for empty);
- literal structured-intent verification;
- `VERIFIED | UNKNOWN | CONFLICT` decisions, with fail-closed default;
- provenance checks against the resolved universe;
- strict RFC 6901 JSON Pointer token decoding (`~0` and `~1` only), plus strict array-index grammar (`0` or `[1-9][0-9]*`);
- stable `effect_identity` and `execution_key`;
- SQLite reservation states `RESERVED | EXECUTED | RESERVED_AMBIGUOUS`;
- stale reservation recovery;
- signed execution receipts;
- concurrent execution tests and attack tests;
- deterministic JSON vectors.

## Security boundary

P2R-Ω does **not** claim global exactly-once execution.

The external adapter/target must declare its action semantics:

- `idempotent`: retries with the same execution key are expected to map to the same external outcome;
- `at_most_once`: an ambiguous dispatch is not automatically retried and requires reconciliation.

Core cannot prove what happened inside an external payment provider, API, database, human workflow, or network after control leaves the process.

## Payload identity

```text
payload_digest = SHA256(canonicalize(P2R minus payload_digest and signatures))
object_id      = payload_digest
```

The digest covers every signed payload field, including the world root, intent, decision, authority, effect, execution policy, and provenance. Detached signatures are excluded from the digest so they can be added/removed without changing the object identity.

The implementation rejects additional fields inside `payload_digest` so an apparently “unchecked” field cannot be smuggled into an unsigned sub-object.

## Effect identity

```text
effect_identity = H({
  actor_id,
  operation,
  rule,
  parameters,
  idempotency_key
})
```

The attempt key additionally binds the authority nonce and scope:

```text
execution_key = H({effect_identity, nonce_scope, nonce})
```

Changing the effect changes `effect_identity`. Changing only the nonce changes `execution_key` but not the effect identity.

## Registry state machine

```text
                    ┌───────────────┐
                    │    RESERVED   │
                    └───────┬───────┘
                            │ success
                            ▼
                    ┌───────────────┐
                    │    EXECUTED   │
                    └───────────────┘

RESERVED -- crash / unknown outcome --> RESERVED_AMBIGUOUS
RESERVED -- explicit pre-dispatch abandonment --> deleted

RESERVED_AMBIGUOUS -- any new attempt --> RECONCILIATION_REQUIRED
```

The critical failure case is deliberate:

```text
reserve → external dispatch succeeds → process dies → no receipt persisted
```

On restart the stale reservation becomes `RESERVED_AMBIGUOUS`; P2R refuses a fresh attempt until the external outcome is reconciled.

## Receipt

A receipt is signed by the observer and covers:

- P2R payload digest;
- execution key;
- effect identity;
- action semantics;
- observed effect;
- observer id and scope;
- observation time;
- `COMPLETED` result.

On a cached retry, the executor verifies the receipt cryptographically **and** checks its payload/effect/execution bindings against the current P2R object before returning it.

## Usage

### Install

```bash
python -m pip install -e ".[dev]"
```

### Run all tests

```bash
pytest -q
```

Expected result on this tree: `155 passed`. The bounded registry model is the slow test. The count at `ac81c41`, before `tests/integration/`, was `127 passed` on both that commit and its parent.
Heavier volumes are not repeated on every `pytest`:

```bash
PYTHONPATH=src python -m assurance.campaign
```

That command rewrites `MODEL_REPORT.md`, `GUARANTEE_MATRIX.md`, `SECURITY_CASE.md`, and `RED_TEAM_REPORT.md` from a fresh run. It does not change `src/p2r/`.

### Run the deterministic vectors

```bash
PYTHONPATH=src python scripts/generate_vectors.py
pytest -q tests/test_vectors.py
```

### Run the end-to-end demo

```bash
PYTHONPATH=src python scripts/demo.py
```

The demo creates `demo.db` in the repository root. It demonstrates that one real action invocation produces a signed receipt and a second call with the same execution key returns the cached receipt without invoking the external action again.

## Files

```text
p2r-omega/
├── README.md
├── LICENSE
├── pyproject.toml
├── vectors/
│   ├── README.md
│   ├── keyring.json
│   ├── p2r-valid.json
│   ├── p2r-tampered.json
│   ├── receipt-valid.json
│   └── universe.json
├── scripts/
│   ├── demo.py
│   └── generate_vectors.py
├── src/p2r/
│   ├── __init__.py
│   ├── authority.py
│   ├── canonical.py
│   ├── decision.py
│   ├── digest.py
│   ├── effect.py
│   ├── errors.py
│   ├── executor.py
│   ├── intent.py
│   ├── keys.py
│   ├── provenance.py
│   ├── receipt.py
│   ├── registry.py
│   ├── universe.py
│   └── verify.py
└── tests/
    ├── conftest.py
    ├── helpers.py
    ├── test_attacks.py
    ├── test_canonical.py
    ├── test_decision.py
    ├── test_effect.py
    ├── test_execution.py
    ├── test_integrity.py
    ├── test_intent.py
    ├── test_provenance.py
    ├── test_receipt.py
    ├── test_registry.py
    ├── test_signatures.py
    ├── test_universe.py
    ├── test_vectors.py
    └── test_verify.py
```

## Deliberate non-guarantees

P2R-Ω V1 does not provide distributed consensus, a payment rail, a blockchain, a global idempotency service, source-byte/span truth verification, or a claim that an external effect happened merely because a receipt exists.

Those boundaries are intentional. The object is an authorization + attempt-binding + observed-receipt mechanism, not a replacement for the systems it calls.

## Assurance, outside the core

`src/p2r/` is the frozen protocol. `assurance/` does not add states, caches, or a second execution path. It holds an independent registry model, crash schedules, an RFC 6901 corpus, and the differential oracle runner. The claims those runs support are in `GUARANTEE_MATRIX.md` and `SECURITY_CASE.md`. Anything not listed there as PROUVÉ is not claimed.

Layout around that boundary:

```text
skills/p2r-assurance/   how to run the checks
rules/core-freeze.md    when src/p2r/ may change
agents/assurance.md     replay role, not a second protocol
hooks/                  no hook installed
docs/                   index of the root reports
tests/                  the suite pytest already runs
sentinel/               outside watcher, not an import of the core
```

`python scripts/p2r-sentinel check` certifies one clean git snapshot, and only when the suite passes inside that snapshot. A dirty tree or `--no-replay` stays `UNKNOWN`. `QUARANTINED` in `.sentinel/` is not a registry status. See `docs/SENTINEL.md`.

## Status tags

**PROUVÉ** — deterministic digesting, Ed25519 signatures, threshold counting, universe-root checking, intent/decision/provenance checks, SQLite reservation state machine, signed receipts, concurrency tests, crash/ambiguity tests.

**UNKNOWN** — external-world outcome when dispatch leaves the process boundary; source-byte truth behind provenance spans; distributed multi-host exactly-once semantics.

**CONFLICT** — any decision explicitly marked `CONFLICT`, which is rejected by default by the V1 execution policy.

**ÉCHEC** — any invariant verification failure or forbidden registry transition; failures are raised rather than silently downgraded.
