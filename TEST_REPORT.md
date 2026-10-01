# TEST_REPORT

Date: 2026-10-01. Tree under test: `main` after the adversarial campaign, parent `1d16497`.

## Dépôt

`git fetch --all --prune` ne montre qu'une branche, `main`. Aucun commit ailleurs à fusionner. Point de restauration local : `restore/pre-adversarial-2026-10-01` sur `1d16497`.

## Exécution

```text
PYTHONPATH=src python3 -m pytest -q
120 passed in 1.96s
```

Répartition approximative : 88 tests déjà sur `1d16497`, plus la campagne dans `tests/test_campaign.py` (canonisation, digest, quorum, univers, pointeur, intention, effet, registre, crash, concurrence, reçus, fuzz).

Campagne chiffrée à l'intérieur des tests :

| Famille | Volume |
|---|---|
| Canonisation différentielle | 2000 valeurs |
| Objets signés mutés | 1000 rejets |
| Pointeurs | corpus RFC 6901 + 200 chemins |
| Threads, même clé | 100 |
| Threads, même effet, `deny` | 100 |
| Processus | 2 |
| Mutations de code | 16, toutes tuées |

`compileall` n'est pas rejoué à part : pytest importe tout le paquet.

## Ce que le chiffre ne dit pas

120 tests verts ne sont pas une preuve d'absence de bug. Le critère utilisé est : les tests tentent de casser les invariants, et aucun contournement reproductible dans la frontière V1 n'est resté ouvert. Les limites hors frontière sont dans `ATTACK_REPORT.md`.
