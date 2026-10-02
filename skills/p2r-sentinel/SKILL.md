---
name: p2r-sentinel
description: Certify the frozen P2R-Ω core against one immutable git snapshot. Use when checking core drift, running p2r-sentinel, or deciding whether an older sentinel certificate still carries. Do not use it to change src/p2r or to treat QUARANTINED as a registry status.
---

# P2R sentinel

The sentinel does not import `p2r` and does not call `execute`.

## Run

```bash
python scripts/p2r-sentinel check --no-replay
python scripts/p2r-sentinel check
python scripts/p2r-sentinel watch --interval 2
python scripts/p2r-sentinel status
```

`check` without `--no-replay` runs pytest in a detached worktree of `HEAD`. That is the certificate. `watch` is only the loop.

## Pass

`PASS` requires all of:

- a clean worktree, so `HEAD` is the snapshot
- `OBSERVED_COMMIT` and `TREE` unchanged after replay
- core digest equal to `.sentinel/frozen.json` (seeded from `sentinel/pin.py`, not from the manifest in the commit)
- no forbidden import, one `def execute(` in `src/p2r/executor.py`, no active hook
- replay `N/N` inside that same worktree

If the worktree is dirty, the result is `UNKNOWN`. Do not call that a drift.

## Do not

- edit `src/p2r/` from this skill
- treat `tests/integration/core_manifest.json` as the pin
- reuse a certificate whose sentinel digest differs; that is `PRIOR_PROOF: NOT_CARRIED`, not a core quarantine
- report `--no-replay` as `PASS`
- describe `QUARANTINED` as a core registry status
