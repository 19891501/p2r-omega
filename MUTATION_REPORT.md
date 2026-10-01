# MUTATION_REPORT

Script : `scripts/mutation_campaign.py`. Chaque mutant est une copie temporaire. L'arbre de travail n'est pas modifié. Suite complète : `pytest -q --tb=no`.

16 tuées, 0 survivantes, 0 mutations non appliquées.

| Mutation | Résultat |
|---|---|
| Comparaison de digest court-circuitée | tuée, 13 échecs |
| Seuil de signature retiré | tuée, 11 échecs |
| Signatures dupliquées comptées | tuée, 5 échecs |
| Indices `/01` acceptés | tuée, 6 échecs |
| Échappements `~` malformés acceptés | tuée, 6 échecs |
| Statut de décision non contrôlé | tuée, 6 échecs |
| Crash abandonné au lieu d'ambigu | tuée, 8 échecs |
| Paramètres d'effet ignorés | tuée, 5 échecs |
| Nonce fixé dans la clé d'exécution | tuée, 10 échecs |
| Scope vide non normalisé | tuée, 4 échecs |
| Observateur hors carte accepté | tuée, 4 échecs |
| Binding de payload au retry retiré | tuée, 5 échecs |
| Doublons d'evidence acceptés | tuée, 4 échecs |
| Statut SQL inconnu accepté | tuée, 4 échecs |
| Tri des clés en UTF-8 | tuée, 6 échecs |
| U+2028 laissé brut | tuée, 5 échecs |

Une mutation tuée veut dire qu'au moins un test échoue. Elle ne mesure pas toutes les lignes. Les branches de rollback SQLite restent peu couvertes et n'ont pas été mutées.
