# Frontière

P2R-Ω Core V1 est gelé.

```text
CORE GELÉ                         VALIDATION / ASSURANCE
src/p2r/                         assurance/
SPEC.md                          tests/oracle.py
                                 tests/test_assurance.py
                                 scripts/mutation_campaign.py
```

`assurance/` n'est pas importé par le protocole. Il ne crée pas d'état
`QUARANTINED`, pas de cache d'autorité, pas de paiement, pas de consensus.

Le document APEX décrit un objet plus large. Ses ajouts de machine d'état
(quarantaine, filiation d'exécution comme nouvel état stocké, compilateur de
preuves dans le chemin d'exécution) ne sont pas dans V1. Les pièces qui
peuvent exister sans changer le protocole — modèle, oracle, chaos, matrice de
garanties — sont ici.

Une modification de `src/p2r/` exigerait un invariant cassé, un test de
non-régression, et une phrase dans SPEC.md. Cette campagne n'en a pas produit.
