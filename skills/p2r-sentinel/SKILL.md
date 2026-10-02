---
name: p2r-sentinel
description: Certify the frozen P2R-Ω core against one immutable git snapshot. Use when checking core drift, running p2r-sentinel, or deciding whether an older sentinel certificate still carries. Do not use it to change src/p2r or to treat QUARANTINED as a registry status.
---

# P2R sentinel

The sentinel does not import `p2r` and does not call `execute`.

## Run

```bash
python scripts/p2r-sentinel certify <repo>
python scripts/p2r-sentinel check --no-replay
python scripts/p2r-sentinel check
python scripts/p2r-sentinel daemon
python scripts/p2r-sentinel watch --interval 2
python scripts/p2r-sentinel status
```

`daemon` is the long-running cycle. It journals `.sentinel/journal.jsonl` as a hash chain. It replays only when the certified snapshot no longer covers HEAD, or when `--replay-every` SECONDS has elapsed. It does not trade, size, or send orders. `watch` remains a short poll.

Before trusting a cached `WATCHING`, the chain, `journal.tip`, `frozen.json`, and the certificate bytes must still match. If they do not, the result is `JOURNAL_BROKEN` / `UNKNOWN`, not `PASS`. A `WATCHING` cache does not erase a `QUARANTINED` line. Replacing all of `.sentinel/` is not a continuation.

`certify <repo>` is one certificate, not a daemon and not a payment. `CERTIFIED` is only for this core: pin, one effect path, import boundary, replay. A repository without `src/p2r` is `SUBJECT: external`. A passing replay there is `OBSERVED`, never `CERTIFIED`. `PAYMENT: NOT_COLLECTED` until money actually moves.

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
- write `QUARANTINED` or a certificate into the core registry
- treat `tests/integration/core_manifest.json` as the pin
- reuse a certificate whose sentinel digest differs; that is `PRIOR_PROOF: NOT_CARRIED`, not a core quarantine
- report `--no-replay` as `PASS`
- report `PASS` when the journal chain, the pin, or a certificate file does not match
- describe `QUARANTINED` or `JOURNAL_BROKEN` as a core registry status
