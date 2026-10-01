# ATTACK_REPORT

Frontière inchangée : `PROOF ≠ AUTHORITY ≠ EFFECT ≠ EXECUTION ≠ RECEIPT`. P2R-Ω n'observe pas le monde extérieur et ne promet pas l'exactly-once distribué.

## Corrections dans cette campagne

| Avant | Après | Statut |
|---|---|---|
| `nonce_scope` `""` ou `null` ne valait pas `"global"`, contrairement à `authority.nonce_scope \|\| "global"`. Sous `allow_new_attempt`, deux clés d'exécution pour le même effet. | `""` et `null` valent `"global"`. Un scope non-chaîne est `AUTHORITY_NONCE_SCOPE_INVALID`. | ÉCHEC corrigé |
| Une ligne SQLite au statut `GHOST` pour le même effet laissait `reserve` insérer une nouvelle tentative, même en `deny`. | Statut hors `RESERVED \| EXECUTED \| RESERVED_AMBIGUOUS` → `REGISTRY_STATUS_INVALID`. | ÉCHEC corrigé |
| Un reçu en cache illisible levait `JSONDecodeError`. Pas de second dispatch, mais exception hors `ExecutionError`. | `RETRY_RECEIPT_INVALID`. Toujours aucun second dispatch. | ÉCHEC corrigé |
| Un signataire présent dans le trousseau mais absent de la carte de scopes passait `verify_receipt` avec un scope vide : l'ensemble vide est sous-ensemble de l'ensemble vide. | Identifiant absent de la carte → `OBSERVER_NOT_TRUSTED`. | ÉCHEC corrigé |
| `json.dumps` laissait U+2028 et U+2029 bruts. `JSON.stringify` et RFC 8785 les échappent. Deux canonisateurs divergeaient. Aucun vecteur du dépôt ne contenait ces caractères. | Échappement `\u2028` / `\u2029`. La spec le dit. | CONFLIT corrigé |

## Familles

### A–B. Canonisation et digest — PROUVÉ pour le sous-ensemble testé

Clés triées en UTF-16-BE, pas en UTF-8 : U+1F600 précède U+FFFF. Contrôles, NFC ≠ NFD, entiers négatifs longs, objets vides. Tuples et listes produisent les mêmes octets : la spec l'autorise. Un champ signé muté change le digest et `verify_object` refuse. Ajouter une signature ne change pas le digest.

Floats : `TypeError`, pas `VerifyError`. Refus quand même. INCONNU sur la classe d'erreur, pas une acceptation.

### C. Autorité — PROUVÉ pour le quorum

Seuil 0, négatif, ou supérieur au nombre de signataires : refus. Deux signatures d'Alice ne font pas un seuil de 2. `alg=none` et une signature d'un autre objet ne créent pas d'autorité. L'ordre des signatures n'importe pas.

Lecture restante, non changée : une signature d'algorithme étranger est ignorée, elle n'invalide pas un quorum déjà atteint. Le point 6 de la spec peut se lire plus strictement. Ce n'est pas un contournement du seuil. INCONNU de rédaction.

`verify_signatures` seul ne relit pas le corps. `verify_object` le fait. Appeler l'API basse sans le digest est hors du chemin `execute`.

### D. Univers — PROUVÉ sur 0..5 feuilles

Même ensemble, ordre différent, même racine. Un octet modifié, racine différente. Doublon d'identifiant refusé. Pas de collision structurelle cherchée au-delà de ces tailles : la résistance est celle de SHA-256, pas une recherche exhaustive. INCONNU au-delà de l'échantillon.

### E. Pointeur — PROUVÉ sur le corpus

Objet et tableau ne sont pas confondus (`/items/01` clé vs indice). `~0`, `~1`, `~01`, `~0~1`, `~00`, `~001` décodés de gauche à droite. `~`, `~~1`, `~2` refusés. Indices `01`, `00`, `+1`, `-`, `1_0`, `1e2`, chiffres non ASCII refusés. Indice hors tableau : `PATH_NOT_FOUND`. Indice gigantesque refusé avant `int()`. Descente dans un scalaire ou `null` : erreur, pas une valeur.

### F. Intention et décision — PROUVÉ

JSON d'intention différent de `structured_goal` : refus. Espaces dans le contenu : accepté seulement si l'analyse égale le but, et le digest couvre le texte. `UNKNOWN` refusé par défaut. `CONFLICT` accepté seulement si la politique signée l'exige.

### G. Effet — PROUVÉ

Même effet, nonce différent : même `effect_identity`, autre `execution_key`. Paramètre différent : autre effet. L'oracle indépendant produit les mêmes identifiants après normalisation du scope.

### H–I. Registre et crash — PROUVÉ sur les points exécutés

| Point | Résultat |
|---|---|
| Avant réservation, objet invalide | pas d'action |
| `PreDispatchError` | ligne abandonnée, retry autorisé |
| Exception pendant l'action | `RESERVED_AMBIGUOUS`, pas de second appel |
| Succès externe puis échec de `mark_executed` | ambigu, pas de second appel |
| Après `EXECUTED` | retry du reçu, pas de second appel |
| Reçu cache corrompu, autre effet, autre clé, autre sémantique, digest différent | erreur, pas de second appel |
| Statut SQL inconnu | `REGISTRY_STATUS_INVALID` |
| Timeout | non rejoué comme nouvelle action ; la ligne devient ambiguë |

Deux chemins d'erreur du registre (rollback SQLite forcé, `BEGIN` qui échoue) ne sont pas injectés. Ce n'est pas une seconde exécution observée. INCONNU sur ces branches mortes au sens couverture.

### J–K. Reçu et rejeu — PROUVÉ localement, INCONNU distribué

Signature valide d'un autre payload : refus. Scope plus large que le grant : refus. Observateur hors carte : refus. Un second fichier SQLite exécute à nouveau le même objet signé. C'est la frontière : un registre local neuf n'est pas une mémoire globale. Hors garantie, pas un défaut du binding local.

### L. TOCTOU

L'`execution_key` est calculée avant l'action. Le callback ne peut plus la changer. Une mutation concurrente du dict Python d'entrée par le caller n'est pas un adversaire du protocole. INCONNU côté appelant.

### M–N. Fuzz et propriétés

2000 valeurs : `canonicalize` déterministe et égal à l'oracle, sinon `TypeError` des deux côtés. 1000 objets signés mutés : aucun n'est resté `verify_object` vrai. Aucun `KeyError`, `IndexError`, `UnicodeError`, `OverflowError` ou `sqlite3.Error` inattendu dans ces boucles.

Exception attendue et documentée : une liste imbriquée 2000 fois lève `RecursionError`. La spec ne fixe pas de profondeur. Ce n'est pas une acceptation. Aucun plafond n'a été inventé.

### O. Mutations

16 mutations, 16 tuées. Détail dans `MUTATION_REPORT.md`.

### P. Différentiel

`tests/oracle.py` n'importe pas `p2r`. Aucune divergence sur le corpus après les corrections de scope et d'échappement. Détail dans `DIFFERENTIAL_REPORT.md`.

### Q. Ressources

L'indice géant est borné par la longueur, pas par `int()`. Le digest est recalculé avant les signatures : un objet énorme coûte cher avant le quorum, parce que vérifier le digest exige de le relire. Pas de contournement. La récursion profonde reste non bornée.

## Absent

Pas de SaaS, pas de paiement, pas de blockchain, pas de V2.
