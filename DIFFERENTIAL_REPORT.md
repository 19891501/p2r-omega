# DIFFERENTIAL_REPORT

Oracle : `tests/oracle.py`. Il ne importe pas `p2r`. Il réimplémente la canonisation, le digest, le pointeur, la racine d'univers, `effect_identity` et `execution_key`.

## Résultat

Aucune divergence sur :

- 2000 valeurs aléatoires déterministes (seed `20261001`), y compris Unicode, U+2028, clés vides, tableaux et objets ;
- le corpus de pointeurs (vide, indices, clés `01` et `-`, échappements `~`, chemins illégaux, indice long) ;
- univers de 0 à 5 preuves, ordre inversé ;
- l'objet de référence `p2r_base()` pour l'effet et la clé d'exécution.

En cas de `TypeError` d'un côté, l'autre lève aussi `TypeError`.

## Ce que l'oracle ne prouve pas

Il suit les mêmes règles écrites que la référence, une fois les deux écarts corrigés (scope `|| "global"`, échappement U+2028/U+2029). Il détecte une dérive future entre les deux fichiers. Il ne détecte pas une erreur partagée que les deux coderaient de la même façon.

Le tri UTF-16 n'est pas seulement comparé à l'oracle. Un test fixe l'ordre des octets : la clé U+1F600 précède U+FFFF, ce qu'un tri UTF-8 inverserait.

## Écarts trouvés puis fermés

Avant correction, une canonisation style `JSON.stringify` / RFC 8785 divergeait sur U+2028 et U+2029. Avant correction, un `execution_key` lu avec `||` divergeait sur `""` et `null`. Les deux sont alignés. Les vecteurs existants ne changent pas : ils n'utilisent pas ces chaînes, et leur `nonce_scope` est déjà `"global"`.
