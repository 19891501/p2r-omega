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

Each certificate records the digest of the sentinel code that emitted it. If that code changes, the previous certificate stays on disk but `automatically_valid` becomes false and the next certificate says `PRIOR_PROOF: NOT_CARRIED`. That is not `QUARANTINED`. Core quarantine is only for a failed observation of a snapshot: digest, boundary, hooks, replay, or a snapshot that changed during the replay.

## Run

```bash
python scripts/p2r-sentinel check --no-replay
python scripts/p2r-sentinel check
python scripts/p2r-sentinel daemon
python scripts/p2r-sentinel watch --interval 2
```

`daemon` is the persistent cycle. It sleeps, wakes, and appends `.sentinel/journal.jsonl`. A wake whose commit and tree are still covered by the valid certificate does not replay and does not mint a new proof. A changed snapshot replays before any new certificate. `QUARANTINED` is written only in that journal and in `.sentinel/`, never in the core registry. The process does not decide, authorize, execute, or edit `src/p2r/`.

`--no-replay` stops at `VERIFIED` / `UNKNOWN`. It does not leave `QUARANTINED`. The sentinel process does not import `p2r`. Replay is a separate pytest process whose cwd is the snapshot, not the live tree.
