# MUTATION_REPORT

Script : `scripts/mutation_campaign.py`. Chaque mutant est une copie temporaire. L'arbre de travail n'est pas modifié. Les vecteurs sont copiés avec la suite : sans eux, trois tests de vecteurs échouent pour un fichier manquant et faussent le score.

La recherche de modèle (`tests/test_assurance.py::test_registry_model_matches_sqlite`) est sautée dans ces copies (`P2R_SKIP_MODEL=1`). Elle reste dans `pytest` normal.

Graine de lecture : 17 tuées, 1 survivante connue, 0 mutation non appliquée. Re-jeu du 2026-10-01 après correction de la copie.

| Mutation | Résultat |
|---|---|
| Comparaison de digest court-circuitée | tuée, 11 échecs |
| Seuil de signature retiré | tuée, 8 échecs |
| Signatures dupliquées comptées | tuée, 2 échecs |
| Indices non RFC 6901 acceptés | tuée, 4 échecs |
| Échappements `~` malformés acceptés | tuée, 4 échecs |
| Statut de décision non contrôlé | tuée, 3 échecs |
| Crash abandonné au lieu d'ambigu | tuée, 6 échecs |
| Paramètres d'effet ignorés | tuée, 3 échecs |
| Nonce fixé dans la clé d'exécution | tuée, 9 échecs |
| Scope vide non normalisé | tuée, 2 échecs |
| Observateur hors carte accepté | tuée, 1 échec |
| Binding de payload au retry retiré | tuée, 3 échecs |
| Doublons d'evidence acceptés | tuée, 2 échecs |
| Statut SQL inconnu accepté | tuée, 3 échecs |
| `mark_executed` sur ambigu autorisé | tuée, 1 échec |
| `BEGIN IMMEDIATE` du `reserve` remplacé par `BEGIN` | survivante |
| Tri des clés en UTF-8 | tuée, 3 échecs |
| U+2028 laissé brut | tuée, 3 échecs |

## Survivante

`defer reserve lock` passe 126 tests (le modèle exhaustif est le test sauté).

Ce n'est pas une acceptation silencieuse observée. Deux `reserve` concurrents restent sérialisés par la clé primaire de `execution_key` : le second `INSERT` échoue, il ne devient pas un second `NEW`. La suite ne force pas l'entrelacement qui distinguerait `ALREADY_RESERVED` d'une `REGISTRY_RESERVE_FAILED`. La mutation est donc survivante sur le code d'erreur de course, et non un contre-exemple de double dispatch.

Le rapport précédent annonçait 16/16 sans copier `vectors/`. Les tuées réelles ci-dessus sont celles qui échouent encore une fois les vecteurs présents. Les comptes d'échecs ont baissé d'environ trois, ce qui correspond à ces faux échecs.
