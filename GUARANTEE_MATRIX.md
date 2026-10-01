# GUARANTEE_MATRIX

Statuts : PROUVÉ dans la borne citée, INCONNU hors domaine, CONFLIT si deux lecteurs divergent, ÉCHEC si une acceptation silencieuse est observée.

| Propriété | Statut | Preuve |
|---|---|---|
| Payload signé lié au digest | PROUVÉ | tests d'intégrité, mutation « digest court-circuité » tuée, oracle canonique 20000 cas |
| Seuil d'autorité | PROUVÉ | tests de quorum, mutation du seuil tuée |
| Signataire non autorisé compte pour 0 | PROUVÉ | tests de signatures, mutation des doublons tuée |
| Lien d'effet | PROUVÉ | oracle identité 5000 cas, mutation des paramètres tuée |
| Nonce dans la clé d'exécution | PROUVÉ | même campagne, mutation « nonce fixé » tuée |
| `nonce_scope` vide = `global` | PROUVÉ | spec `||`, tests, mutation tuée |
| Racine d'univers | PROUVÉ | oracle 1000 cas, mutation des doublons tuée |
| Pointeur JSON, profil RFC 6901 | PROUVÉ | corpus `assurance/rfc6901.py`, zéro non-conforme dans le profil |
| Retry local, même `execution_key` | PROUVÉ | modèle 761 états / 50987 arêtes, chaos CH-03 |
| `RESERVED_AMBIGUOUS` bloque un nouveau dispatch | PROUVÉ | modèle, CH-01, CH-06, mutation « abandon au lieu d'ambigu » tuée |
| Kill laissant `RESERVED`, dans le timeout | PROUVÉ | CH-10, un seul détenteur, pas un second appel |
| Kill laissant `RESERVED`, après timeout | PROUVÉ | CH-11, réconciliation, pas `NEW` |
| Politique `deny` sur un autre nonce | PROUVÉ | CH-07 |
| `allow_new_attempt` signé, autre nonce | PROUVÉ comme autorisé | CH-08, deux appels, deux clés |
| Substitution de reçu | PROUVÉ sur `execute` | CH-05 `RETRY_RECEIPT_PAYLOAD_MISMATCH`, mutation du binding tuée |
| Statut SQL inconnu | PROUVÉ | CH-09, rollback GHOST, mutation tuée |
| Concurrence même clé | PROUVÉ jusqu'à 64 fils | 1→1 appel, 2→1 appel, 4→1 appel, 8→1 appel, 16→1 appel, 32→1 appel, 64→1 appel |
| Verrou `BEGIN IMMEDIATE` distingué d'un `BEGIN` différé | INCONNU par les tests | mutation survivante ; la clé primaire empêche deux `NEW`, le code d'erreur de course n'est pas asserté |
| Horloge en arrière | PROUVÉ : pas de second dispatch | CH-04 ; la raison du blocage dépend de l'état déjà écrit |
| Exactly-once distribué | INCONNU | un second fichier SQLite n'a pas la mémoire du premier |
| Vérité de l'effet externe | INCONNU | le reçu est une observation signée, pas le monde |
| Octets derrière le span de provenance | INCONNU | V1 ne les lit pas |
| Collision SHA-256 | INCONNU | non cherchée |
| Python 3.12 / 3.13 | INCONNU | interpréteurs absents |
| Profondeur non bornée | INCONNU comme DoS local | `RecursionError` refuse, n'accepte pas ; aucun plafond ajouté |
