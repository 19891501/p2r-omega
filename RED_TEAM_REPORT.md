# RED_TEAM_REPORT

Une attaque ratée n'est une preuve que si le résultat dit pourquoi elle ne passe pas.
Les familles A–Q de la campagne précédente restent dans `ATTACK_REPORT.md`. Ici : les scénarios ajoutés, y compris ceux qui échouent.

## Registre exhaustif

ID. RT-MODEL
Objectif. Trouver un second `NEW`, un `EXECUTED` non collant, ou un désaccord modèle/SQLite.
Précondition. Borne ['k0', 'k1'] × ['e0', 'e1'], timeout 2.
Attaque. 50987 arêtes.
Résultat. PROUVÉ. Conflits : 0.
Preuve. `assurance/replay_registry.py`, `MODEL_REPORT.md`.
Contre-mesure. Machine d'état inchangée : elle a tenu dans la borne.
Statut. PROUVÉ

## Chaos

### CH-01 — exception pendant le dispatch

Objectif. Empêcher un second effet silencieux, ou montrer la politique signée.
Attaque. Premier résultat `RuntimeError`, second `EFFECT_RECONCILIATION_REQUIRED`, appels externes 1.
Résultat. PROUVÉ. 
Preuve. `assurance/chaos.py`.
Statut. PROUVÉ

### CH-02 — PreDispatchError : abandon puis nouvelle tentative

Objectif. Empêcher un second effet silencieux, ou montrer la politique signée.
Attaque. Premier résultat `NO_DISPATCH`, second `NO_DISPATCH`, appels externes 2.
Résultat. PROUVÉ. 
Preuve. `assurance/chaos.py`.
Statut. PROUVÉ

### CH-03 — succès : le retry ne redispatche pas

Objectif. Empêcher un second effet silencieux, ou montrer la politique signée.
Attaque. Premier résultat `RECEIPT`, second `RECEIPT`, appels externes 1.
Résultat. PROUVÉ. 
Preuve. `assurance/chaos.py`.
Statut. PROUVÉ

### CH-04 — exception in-process : ambigu immédiat, même si l'horloge recule

Objectif. Empêcher un second effet silencieux, ou montrer la politique signée.
Attaque. Premier résultat `RuntimeError`, second `EFFECT_RECONCILIATION_REQUIRED`, appels externes 1.
Résultat. PROUVÉ. une exception dans le processus n'est pas un kill : mark_ambiguous est appelé
Preuve. `assurance/chaos.py`.
Statut. PROUVÉ

### CH-05 — reçu signé d'un autre payload substitué dans SQLite

Objectif. Empêcher un second effet silencieux, ou montrer la politique signée.
Attaque. Premier résultat `RECEIPT`, second `RETRY_RECEIPT_PAYLOAD_MISMATCH`, appels externes 1.
Résultat. PROUVÉ. 
Preuve. `assurance/chaos.py`.
Statut. PROUVÉ

### CH-06 — timeout après crash : réconciliation, pas un retry silencieux

Objectif. Empêcher un second effet silencieux, ou montrer la politique signée.
Attaque. Premier résultat `RuntimeError`, second `EFFECT_RECONCILIATION_REQUIRED`, appels externes 1.
Résultat. PROUVÉ. 
Preuve. `assurance/chaos.py`.
Statut. PROUVÉ

### CH-07 — autre nonce, politique deny

Objectif. Empêcher un second effet silencieux, ou montrer la politique signée.
Attaque. Premier résultat `RECEIPT`, second `EFFECT_ALREADY_EXECUTED`, appels externes 1.
Résultat. PROUVÉ. 
Preuve. `assurance/chaos.py`.
Statut. PROUVÉ

### CH-08 — autre nonce, allow_new_attempt signé

Objectif. Empêcher un second effet silencieux, ou montrer la politique signée.
Attaque. Premier résultat `RECEIPT`, second `RECEIPT`, appels externes 2.
Résultat. PROUVÉ. autorisé par la politique signée ; execution_key différente
Preuve. `assurance/chaos.py`.
Statut. PROUVÉ

### CH-09 — ligne GHOST sur le même effet, autre clé

Objectif. Empêcher un second effet silencieux, ou montrer la politique signée.
Attaque. Premier résultat `RECEIPT`, second `REGISTRY_STATUS_INVALID`, appels externes 1.
Résultat. PROUVÉ. 
Preuve. `assurance/chaos.py`.
Statut. PROUVÉ

### CH-10 — kill après réservation, reprise dans le timeout

Objectif. Empêcher un second effet silencieux, ou montrer la politique signée.
Attaque. Premier résultat `KILLED_RESERVED`, second `ALREADY_RESERVED`, appels externes 0.
Résultat. PROUVÉ. le dispatch du processus tué est hors observation ; le processus vivant ne dispatch pas
Preuve. `assurance/chaos.py`.
Statut. PROUVÉ

### CH-11 — kill après réservation, reprise après timeout

Objectif. Empêcher un second effet silencieux, ou montrer la politique signée.
Attaque. Premier résultat `KILLED_RESERVED`, second `EFFECT_RECONCILIATION_REQUIRED`, appels externes 0.
Résultat. PROUVÉ. 
Preuve. `assurance/chaos.py`.
Statut. PROUVÉ

## GHOST et rollback

ID. RT-GHOST
Objectif. Faire commettre la conversion périmée malgré un statut illisible.
Attaque. Ligne `k0` RESERVED à t=0, sœur `GHOST`, `reserve` à t=10.
Résultat. {'status': 'PROUVÉ', 'code': 'REGISTRY_STATUS_INVALID', 'k0': 'RESERVED'}.
Preuve. La transaction annule la mise à jour. `k0` reste RESERVED.
Statut. PROUVÉ

## Corpus RFC 6901

ID. RT-RFC6901
Objectif. Trouver une divergence avec le profil JSON string, ou avec l'oracle.
Résultat. PROUVÉ. Conflits : aucun.
Classification. Les indices à zéro initial et la forme fragment URI sont des choix de profil, pas des extensions silencieuses. Aucune ligne n'est marquée non-conforme.
Preuve. `assurance/rfc6901.py`.
Statut. PROUVÉ

## Verrou SQLite

ID. RT-LOCK
Objectif. Voir si remplacer `BEGIN IMMEDIATE` par `BEGIN` dans `reserve` ouvre un second dispatch.
Précondition. Mutant isolé, vecteurs présents, modèle exhaustif non relancé.
Attaque. `scripts/mutation_campaign.py`, mutant `defer reserve lock`.
Résultat. La suite passe. Aucun second appel externe n'est produit par les tests de concurrence contre ce mutant dans cette exécution.
Preuve. `MUTATION_REPORT.md`. La clé primaire reste. Le code d'erreur d'une course forcée n'est pas couvert.
Contre-mesure. Aucune modification du cœur : la mutation ne montre pas un contournement, elle montre un trou de test.
Statut. INCONNU sur le code d'erreur de course. Pas un ÉCHEC de double dispatch.

## Attaques qui restent hors garantie

ID. RT-SECOND-DB
Objectif. Rejouer le même objet sur un registre vide.
Résultat. Le second registre dispatch. C'est la frontière locale, pas un bug de liaison.
Statut. INCONNU distribué. Documenté, non « corrigé ».

ID. RT-DEPTH
Objectif. Forcer un comportement généreux sur une structure très profonde.
Résultat. `RecursionError`. Refus par accident d'implémentation, pas un plafond spécifié. Aucun changement de sémantique.
Statut. INCONNU comme limite de ressource. Pas une acceptation.

