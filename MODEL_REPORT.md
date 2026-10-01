# MODEL_REPORT

Généré : 2026-10-01T19:19:11Z. Python 3.10.21. Commit au moment de la génération : `cd915caab6e49dedf279b18cb46d8f914a4167d3`.

## Recherche

Modèle indépendant : `assurance/model_registry.py` (n'importe pas `p2r`).
Rejeu : `assurance/replay_registry.py` sur `Registry` SQLite, une arête = un fichier restauré.

Borne : clés ['k0', 'k1'], effets ['e0', 'e1'], `now` [0, 1, 2, 3, 4], timeout 2, 67 actions.

| | |
|---|---|
| États | 761 |
| Arêtes | 50987 |
| Conflits | 0 |
| Statut | PROUVÉ |

Aucun contre-exemple dans cette borne. La trace minimale serait rejouable par `replay_trace` si une divergence apparaissait.

Hors borne, donc INCONNU : trois clés ou plus, plusieurs reçus distincts, horloge non entière, deux processus. La ladder de threads couvre la même clé jusqu'à 64 fils, séparément.

## Oracle

| Surface | Volume | Statut |
|---|---|---|
| Canonisation | 20000 | PROUVÉ |
| Identité d'effet | 5000 | PROUVÉ |
| Univers | 1000 | PROUVÉ |
| Python 3.11 vs ce processus, 2000 valeurs | digest | PROUVÉ |

Python 3.12 et 3.13 ne sont pas installés ici. Ce n'est pas un accord : c'est INCONNU.
