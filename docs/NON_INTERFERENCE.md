# P2R-Ω ASSURANCE INTEGRATION

Subject of the check: the layout commit, not this report.

```text
commit: ac81c415e9e1271fbf683cfb912fed34489ec9c8
parent: c3383fba914e3c504bc1387eec6dce63c30c5a2b

CORE_CHANGED: NO
TESTS_CHANGED: NO
ASSURANCE_IMPORTS_IN_CORE: 0
ACTIVE_HOOKS: 0
ALTERNATIVE_EFFECT_PATHS: 0
REPLAY_MISMATCHES: 0
PROTOCOL_REGRESSIONS: 0

VERDICT: PROVEN
```

This verdict was computed locally from those two commits. It is not a claim made from the GitHub page alone.

## What was compared

`git diff --name-status c3383fb ac81c41` is only:

```text
M README.md
A agents/assurance.md
A docs/README.md
A hooks/README.md
A rules/core-freeze.md
A skills/p2r-assurance/SKILL.md
```

`src/p2r/` and `tests/` do not appear. `README.md` is outside `ADD`. It gained a directory index. Its blob changed from `714328751289bfbfe555471a230c5284f22810f74484747b35dad8d21deb553c` to `73c2b3497ab99a7f5b7ce00da65a10dbe52b9dd22660b5146a6a6d029351b4ff`. That is not a protocol change.

`ADD` contains no Python file. `pyproject.toml` packages only `src/`.

## Independent digest

Algorithm, applied to `git show <commit>:<path>` bytes, not to this test:

```text
line = relative_path || NUL || sha256(file)
tree = sha256(lines joined by LF, no trailing LF)
```

| Tree | c3383fb | ac81c41 |
|---|---|---|
| `src/p2r` (15 files) | `33f1f479026ed81def4907ca0296b3af5edab0c5ac2e2da1808deb3f89473ce6` | same |
| `tests` (20 files) | `e8370df7194706dfdc470df7773ef0f0092954e005264adcc937bb576d1e966c` | same |

Per-file core hashes are in `tests/integration/core_manifest.json`. The test recomputes them from the working tree. It does not generate the expected value.

## Other checks

| Check | Observation |
|---|---|
| Imports in `src/p2r` | no `skills`, `rules`, `agents`, `hooks`, `docs`, `assurance`, `importlib`, or `__import__` |
| `def execute` | only `src/p2r/executor.py` |
| Active hooks | no file in `.git/hooks/` without the `.sample` suffix. Samples are present and are not installed hooks. `hooks/README.md` is mode `644` |
| Replay | two fresh registries, same calls: `NEW`, `RETRY`, `EFFECT_ALREADY_EXECUTED`. Results equal |
| pytest `c3383fb` | `127 passed` |
| pytest `ac81c41` | `127 passed` |

## Limit

The proof commit that adds `tests/integration/` is after `ac81c41`. `TESTS_CHANGED: NO` refers to the layout commit. The new test is allowed to exist. It must keep the 20 test files from `ac81c41` byte-identical, and it must keep `src/p2r/` on the digest above.

No Ed25519 identity is claimed for this report. The binding is the two commit ids and the tree digest. A throwaway signature would not add a witness.
