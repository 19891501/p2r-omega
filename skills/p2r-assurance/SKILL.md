# P2R-Ω assurance

Use this when checking the frozen Core. Do not use it to add protocol states.

## Boundary

`src/p2r/` and `SPEC.md` are the protocol. This skill only runs checks that already exist outside that tree.

## Run

```bash
python -m pip install -e ".[dev]"
pytest -q
PYTHONPATH=src python -m assurance.campaign
PYTHONPATH=src python scripts/mutation_campaign.py
```

`pytest -q` on the tree that introduced this layout expects `127 passed`. The model test is the slow one. The campaign rewrites the four root reports from a fresh run and does not edit `src/p2r/`.

`python scripts/p2r-sentinel check` certifies one git snapshot from outside the core. It does not import `p2r`. A dirty tree or `--no-replay` is not `PASS`. The manifest inside the commit is not the pin.

## Do not

- import `assurance` from `src/p2r/`
- treat a green run as distributed exactly-once or as proof of an external effect
- silence the known surviving mutation `defer reserve lock` by deleting it
