# P2R-Ω Sentinel

The sentinel watches the frozen core. It is not a second protocol.

```text
OBSERVED → VERIFIED → CERTIFIED → WATCHING
                └─ DRIFT → QUARANTINED
```

`QUARANTINED` is a sentinel state in `.sentinel/`. It is not a registry status and it does not gate `execute`.

## Boundary

`sentinel/` does not import `p2r`. A replay is a separate `pytest` process. The sentinel process never calls `execute` and never opens the registry.

A certificate is `PASS` only when all of these hold:

- the core digest equals the authorized digest
- `src/p2r/` imports none of `skills`, `rules`, `agents`, `hooks`, `docs`, `assurance`, `sentinel`
- the only `def execute(` is `src/p2r/executor.py`
- no active hook is installed
- the replay process passed

Anything missing, including a skipped replay, is `UNKNOWN`. A skipped replay does not leave `QUARANTINED`.

The authorized digest starts as `tests/integration/core_manifest.json`. `accept` can record a different local digest in `.sentinel/authorized.json`. That file is not the core. The certificate then says `FROZEN: DIVERGED`.

## Run

```bash
python scripts/p2r-sentinel check --no-replay
python scripts/p2r-sentinel check
python scripts/p2r-sentinel watch --interval 2
python scripts/p2r-sentinel status
```

`check` without `--no-replay` runs the suite. `watch` re-runs it only when the observed tree changes. An unchanged `WATCHING` state does not emit a new certificate.

Leaving quarantine happens in two ways only: the core bytes return to the authorized digest and a replay passes (`QUARANTINE LIFTED: restored`), or an operator runs `accept` after a passing replay (`QUARANTINE LIFTED: accepted`). `accept` does not edit `src/p2r/` or the manifest.
