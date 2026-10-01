# P2R-Ω Core 0.1.0

Protocole V1, un registre local. Pas un réseau, pas un paiement, pas une blockchain.

## Binding

Autorisation exacte, effet exact, tentative unique, crash ambigu, reçu signé. Une autorisation ne se réutilise pas en silence pour un autre effet. Une tentative ambiguë bloque jusqu'à réconciliation.

## Cette coupe

- Pointeur RFC 6901 : indices `0` ou `[1-9][0-9]*`, échappements `~0` et `~1` seulement.
- Canonisation : tri UTF-16-BE, échappement U+2028 et U+2029.
- `nonce_scope` vide ou nul vaut `"global"`.
- Statut SQLite inconnu refusé.
- Reçu cache illisible refusé sans second dispatch.
- Observateur absent de la carte de scopes refusé.
- 120 tests, 16 mutations tuées, oracle différentiel sans divergence sur le corpus.

## Hors garantie

Le registre est local. Un autre fichier SQLite peut rejouer le même objet signé. Le reçu n'est pas la preuve que le monde extérieur a fait l'action. Une imbrication de plusieurs milliers de niveaux lève `RecursionError`. Les signatures d'algorithme étranger sont ignorées ; elles ne comptent pas dans le quorum.
