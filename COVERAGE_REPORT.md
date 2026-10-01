# COVERAGE_REPORT

Outil : `coverage` 7, `python3 -m coverage run -m pytest`. 120 tests passés pendant la mesure.

```text
Name                    Stmts   Miss  Cover   Missing
-----------------------------------------------------
src/p2r/__init__.py        10      0   100%
src/p2r/authority.py       60     11    82%   14-15, 17, 24, 27, 33, 41, 46, 51, 67, 69
src/p2r/canonical.py       28      0   100%
src/p2r/decision.py        32      6    81%   11, 18, 21, 30, 33, 39
src/p2r/digest.py          13      0   100%
src/p2r/effect.py          28      3    89%   22, 25, 28
src/p2r/errors.py          13      0   100%
src/p2r/executor.py        80      6    92%   40, 42, 47, 83, 112-113
src/p2r/intent.py          23      3    87%   13, 18, 24
src/p2r/keys.py            54      8    85%   21, 23, 31, 38, 45-49, 65, 75
src/p2r/provenance.py      71      5    93%   64, 69, 72, 79, 94
src/p2r/receipt.py         59     13    78%   26, 46, 49, 52, 55, 57, 59, 62-63, 69, 77, 79, 82
src/p2r/registry.py       193     56    71%   37, 46, 65, 81-83, 89, 110, 148-149, 151-156, 170, 172, 174, 181-192, 205, 207-208, 210, 216-227, 240, 248-249, 251-256
src/p2r/universe.py        60     11    82%   37, 70-71, 73, 76-77, 86-90
src/p2r/verify.py          39      4    90%   15, 17, 21, 33
-----------------------------------------------------
TOTAL                     763    126    83%
```

83 % de statements. Les manques sont surtout des branches d'erreur : forme invalide, rollback SQLite, clé absente, sémantique d'action inconnue, registre manquant. Le plus bas est `registry.py` à 71 %, parce que les `except` de panne disque ne sont pas injectés.

Ce pourcentage n'est pas le critère de réussite. Les mutations qui retirent un contrôle de sécurité sont tuées ; voir `MUTATION_REPORT.md`.
