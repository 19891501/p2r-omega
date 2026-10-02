# P2R-Ω Sentinel

The sentinel watches the frozen core. It is not a second protocol, and `QUARANTINED` is not a registry status.

```text
SNAPSHOT → OBSERVE → REPLAY → CERTIFY → WATCH → INVALIDATE
```

`watch --interval 2` only decides when to look. The certificate is the object.

## One snapshot

A `PASS` is bound to one git commit and one tree id. Digest, imports, effect paths, and replay all run on a detached worktree of that commit. After the replay, the sentinel reads the same commit again. If the worktree bytes or the tree id moved, the result is `FAIL`, not `PASS`.

A dirty worktree is `UNKNOWN` with `SNAPSHOT: WORKTREE_DIRTY`. It is not certified, and it is not a core drift.

```text
OBSERVED_COMMIT: <commit>
TREE: <tree>
CORE_DIGEST: <digest>
REPLAY: 151/151
RESULT: PASS
```

## What is not allowed to authorize a new core

`tests/integration/core_manifest.json` is inside the commit being watched. The sentinel reports whether it agrees. Agreement does not make `PASS`.

The pin is `.sentinel/frozen.json`, seeded from `sentinel/pin.py` (the core digest at `c4d8053`). `accept` may write `.sentinel/authorized.json`. It does not rewrite the pin, `src/p2r/`, or the manifest. The certificate then says `FROZEN: DIVERGED`.

## The sentinel is not invisible

Each certificate file is immutable after it is written. If the sentinel code changes, the next certificate says `PRIOR_PROOF: NOT_CARRIED` and the old id is no longer the valid certificate. The old file is not rewritten. That is not `QUARANTINED`. Core quarantine is only for a failed observation of a snapshot: digest, boundary, hooks, replay, or a snapshot that changed during the replay. The invalidated id is recorded in `.sentinel/state.json` and in the next certificate, not by editing the old one.

## One certificate

```bash
python scripts/p2r-sentinel certify <repo>
```

This is one observation. It is not a subscription and it does not collect payment.

On this repository, `CERTIFIED` still means the frozen core: clean snapshot, digest equal to the pin, one effect path, import boundary intact, replay passed. On a repository with no `src/p2r`, the same command does not apply that pin and does not print `CERTIFIED`. A passing replay is `OBSERVED` / `BASELINE: ESTABLISHED`. A later different tree is `DRIFT`, and the baseline file is left untouched. `PAYMENT: NOT_COLLECTED` until a buyer actually pays.

```bash
python scripts/p2r-sentinel check --no-replay
python scripts/p2r-sentinel check
python scripts/p2r-sentinel daemon
python scripts/p2r-sentinel watch --interval 2
```

`daemon` is the persistent cycle. It sleeps, wakes, and appends `.sentinel/journal.jsonl`. Each line carries the hash of the previous line, the pin file, and the certificate bytes. A wake whose commit and tree are still covered by the valid certificate does not replay and does not mint a new proof. A changed snapshot replays before any new certificate. `QUARANTINED` is written only in that journal and in `.sentinel/`, never in the core registry. The process does not decide, authorize, execute, or edit `src/p2r/`.

Surveillance runs before the fast path. An edited line, a deleted line, a rewritten `frozen.json`, or a rewritten certificate becomes `JOURNAL_BROKEN` / `UNKNOWN`. That is not a core drift and it is not a pass. `state.json` saying `WATCHING` does not hide a quarantine that the chain still records. Replacing the whole `.sentinel/` directory has no external witness; it is a new local history, not a continuation.

`--no-replay` stops at `VERIFIED` / `UNKNOWN`. It does not leave `QUARANTINED`. The sentinel process does not import `p2r`. Replay is a separate pytest process whose cwd is the snapshot, not the live tree.
