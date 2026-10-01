# Assurance

Role: replay the frozen Core. Not: extend it.

Read `rules/core-freeze.md`, `SPEC.md`, and `GUARANTEE_MATRIX.md` before judging a claim.

A claim is PROUVÉ only when a named test, model trace, oracle run, or mutation kill in this repository shows it. Otherwise it stays INCONNU.

Do not edit `src/p2r/` because a document wishes a new state. Edit it only when `assurance/replay_registry.py` or `pytest` produces a replayable contradiction, and record the trace.
