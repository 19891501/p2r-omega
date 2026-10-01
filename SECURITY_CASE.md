# SECURITY_CASE

Les affirmations ci-dessous ne dépassent pas les preuves. Le cœur n'a pas été modifié par cette campagne.

## SC-01 Identité du payload

CLAIM. Muter un champ signé invalide l'identité.
ASSUMPTIONS. Sous-ensemble canonique V1. Pas de flottants.
EVIDENCE. `tests/test_integrity.py`, `tests/test_campaign.py`, oracle canonique (PROUVÉ, n=20000, graine 20261001). Mutation du comparateur de digest : tuée.
LIMITATION. Deux documents distincts pourraient théoriquement partager un SHA-256. Non cherché.
STATUS. PROUVÉ pour le sous-ensemble et l'échantillon.

## SC-02 Autorité

CLAIM. Un quorum exige des signataires autorisés distincts, au moins `threshold`.
ASSUMPTIONS. Ed25519 via la bibliothèque `cryptography`. Le message signé est le texte ASCII du digest, pas le corps recomposé par `verify_signatures` seul.
EVIDENCE. `tests/test_signatures.py`. Mutations : seuil retiré, doublons comptés. Toutes tuées.
LIMITATION. `verify_signatures` sans `verify_object` ne relit pas le corps. Le chemin `execute` appelle `verify_object`. Une signature d'algorithme inconnu est ignorée si le quorum est déjà atteint.
STATUS. PROUVÉ sur `execute` / `verify_object`.

## SC-03 Effet et tentative

CLAIM. Un autre effet change `effect_identity`. Un autre nonce change `execution_key` sans changer l'effet. Le scope vide vaut `global`.
ASSUMPTIONS. Même canoniseur que le digest.
EVIDENCE. Oracle d'identité (PROUVÉ, n=5000). Mutations paramètres / nonce / scope tuées.
LIMITATION. Pas une preuve d'injectivité informationnelle au-delà de SHA-256.
STATUS. PROUVÉ sur l'échantillon et les mutations.

## SC-04 Pas de second dispatch local

CLAIM. Pour une `execution_key`, au plus un `NEW` tant que la ligne n'est pas revenue à ABSENT par `abandon`. `RESERVED_AMBIGUOUS` et `deny` après `EXECUTED` ne produisent pas `NEW`.
ASSUMPTIONS. Un seul registre SQLite. Horloge fournie par l'appelant. `abandon` n'est utilisé que pour affirmer l'absence de dispatch.
EVIDENCE. Modèle contre SQLite : 761 états, 50987 arêtes, PROUVÉ. Chaos CH-01 à CH-11. Ladder : PROUVÉ.
LIMITATION. Borne de deux clés et deux effets. Pas de preuve pour n clés. Pas de preuve inter-hôtes. Remplacer `BEGIN IMMEDIATE` par `BEGIN` dans `reserve` n'est pas tué par la suite : la clé primaire suffit aux tests actuels pour empêcher deux `NEW`. Le code d'erreur sous course forcée est INCONNU.
STATUS. PROUVÉ dans la borne et sur les scénarios nommés. Distribué : INCONNU.

## SC-05 Reçu

CLAIM. Un retry ne rend un reçu que si la signature, l'observateur, le digest, l'effet, la clé d'exécution et la sémantique correspondent.
ASSUMPTIONS. L'observateur est dans la carte de scopes. Le registre peut stocker n'importe quel JSON : ce n'est pas une autorité.
EVIDENCE. CH-05. Mutation « observer hors carte » et « binding de payload » tuées. `tests/test_receipt.py`.
LIMITATION. Le registre brut accepte un reçu non vérifié. Seul `execute` le relit. Le reçu ne prouve pas l'effet externe.
STATUS. PROUVÉ sur le chemin `execute`. Vérité externe : INCONNU.

## SC-06 États impossibles

CLAIM. Un statut hors `RESERVED | EXECUTED | RESERVED_AMBIGUOUS` n'est pas interprété comme une permission d'insérer.
ASSUMPTIONS. L'attaquant écrit dans SQLite mais passe encore par `reserve`.
EVIDENCE. CH-09. `ghost_rollback` : la récupération périmée est annulée avec l'erreur (PROUVÉ). Mutation du contrôle de statut tuée.
LIMITATION. Un attaquant qui peut écrire EXECUTED avec un reçu valide de cet objet peut provoquer un retry. C'est le contenu légitime de la ligne, pas un contournement.
STATUS. PROUVÉ.

## SC-07 Ce qui n'est pas revendiqué

CLAIM. Aucune.
STATUS. INCONNU, volontaire : exactly-once distribué, obéissance du monde extérieur, consensus, paiement, octets sources du span, absence de DoS par profondeur.

## Mesures

Benchmark de ce processus (3.10.21, Linux-6.12.8+-x86_64-with-glibc2.36), n=80. Ce n'est pas une preuve.

| Chemin | p50 µs | p95 µs | p99 µs |
|---|---|---|---|
| canonisation | 231.5 | 294.0 | 540.8 |
| digest | 204.3 | 261.3 | 288.4 |
| verify_object | 536.1 | 593.3 | 1067.3 |
| execute en cache | 1226.3 | 1278.8 | 1403.8 |

Premier passage : 1 appel externe.
