# Modèle formel — P2R-Ω Core V1

Ce texte fige les objets et les invariants. Il ne les étend pas.
L'implémentation exécutable du registre est `assurance/model_registry.py`.
Elle n'importe pas `p2r`.

## Objets

| Nom | Définition V1 |
|---|---|
| P2R identity | `object_id = payload_digest = H(canonical(P2R \ {payload_digest, signatures}))` |
| Authority | signataires autorisés, seuil, nonce, `nonce_scope` |
| Universe | racine de manifeste des preuves, triée par `evidence_id` |
| Intent | `literal-structured-intent-v1` : `parse(content) = structured_goal` |
| Decision | `VERIFIED \| UNKNOWN \| CONFLICT`, comparée à la politique signée |
| Effect | `(actor_id, operation, rule, parameters, idempotency_key)` |
| Execution | `execution_key = H(effect_identity, nonce_scope \|\| "global", nonce)` |
| Observation | reçu signé par un observateur de confiance, lié à l'objet |
| Receipt | observation `COMPLETED` dont la signature et les liaisons tiennent |

`H` est SHA-256, encodé en base64url sans padding. `canonical` est le sous-ensemble V1 (pas de flottants, clés triées en UTF-16-BE, échappements RFC 8785 y compris U+2028 et U+2029).

## Invariants logiques

```text
mutation(payload signé) → payload_digest' ≠ payload_digest

effect₁ ≠ effect₂ → effect_identity(effect₁) ≠ effect_identity(effect₂)
    pour le codage canonique injectif du sous-ensemble supporté
    (résistance pratique de SHA-256 ; pas une preuve de collision)

nonce₁ ≠ nonce₂ ∧ même effet → execution_key₁ ≠ execution_key₂
    ∧ effect_identity₁ = effect_identity₂

execution_key identique ∧ statut EXECUTED → reserve ≠ NEW

RESERVED_AMBIGUOUS(e) → reserve(e, *) ≠ NEW

abandon(k) défini seulement si statut(k) = RESERVED

statut(k) = EXECUTED → statut'(k) = EXECUTED ∧ effect'(k) = effect(k) ∧ reçu'(k) = reçu(k)

statut(k) = RESERVED_AMBIGUOUS → la ligne n'est ni supprimée ni exécutée

signataire ∉ authorized_signers → il ne contribue pas au quorum

provenance.evidence_id ∉ universe → rejet

politique mutée → payload_digest invalide (elle est dans le payload signé)

UNKNOWN ∧ require_decision_status = VERIFIED → rejet
```

Ce qui n'est pas un invariant :

```text
reçu signé ⇒ effet externe réel
registre local ⇒ exactly-once sur un autre hôte
span de provenance ⇒ octets sources vérifiés
```

## Machine d'état

États d'une ligne, clé = `execution_key` :

```text
ABSENT  (pas de ligne)
RESERVED
EXECUTED
RESERVED_AMBIGUOUS
```

Transitions qui commit :

```text
reserve
  ABSENT, et aucun frère AMBIGUOUS ou RESERVED,
  et (politique ≠ deny ou aucun frère EXECUTED)
      → RESERVED                          outcome NEW
  même clé EXECUTED                       → inchangé   RETRY(reçu)
  même clé RESERVED                       → inchangé   ALREADY_RESERVED
  même clé AMBIGUOUS                      → inchangé   RECONCILIATION_REQUIRED
  autre clé, frère AMBIGUOUS              → inchangé*  RECONCILIATION_REQUIRED
  autre clé, frère RESERVED               → inchangé*  EFFECT_IN_PROGRESS
  autre clé, frère EXECUTED, deny         → inchangé*  EFFECT_ALREADY_EXECUTED
  autre clé, frère EXECUTED, allow        → RESERVED   NEW
  même clé, autre effet                   → rollback   COLLISION

  * la conversion périmée des autres lignes RESERVED est commitée
    avec la décision, y compris quand la décision n'est pas NEW.

mark_executed
  RESERVED → EXECUTED
  AMBIGUOUS → erreur, rollback
  EXECUTED → erreur, rollback
  ABSENT → erreur

mark_ambiguous
  RESERVED → AMBIGUOUS
  EXECUTED → noop commit
  AMBIGUOUS → erreur
  ABSENT → erreur

abandon
  RESERVED → ABSENT
  sinon erreur
  n'exécute pas la récupération périmée

recover / reserve
  RESERVED ∧ updated_at < now - timeout → AMBIGUOUS
  commit seulement si l'opération commit
```

Prédicat de péremption, tel qu'implémenté : strict `<`.
À âge = timeout, la ligne n'est pas encore ambiguë.

`abandon` n'est pas une reprise de crash. C'est l'assertion de l'adaptateur
qu'aucun dispatch n'a eu lieu (`PreDispatchError`). Un kill qui laisse
`RESERVED` devient `ALREADY_RESERVED` dans la fenêtre, puis
`RESERVED_AMBIGUOUS` après le timeout, jamais un second `NEW`.

## Borne explorée

`assurance/replay_registry.py` parcourt toutes les actions

```text
reserve × {k0,k1} × {e0,e1} × {deny, allow_new_attempt} × now ∈ {0,1,2,3,4}
mark_executed, mark_ambiguous × clés × now
abandon × clés
recover × now
```

avec `timeout = 2`, en largeur d'abord. Chaque arête est rejouée sur un
fichier SQLite neuf restauré depuis l'état parent. Un désaccord arrête la
recherche et conserve la trace minimale.

Hors borne : 3 clés ou plus, horloges non entières, statuts injectés hors
API (couverts à part par le scénario GHOST), concurrence (couverte par la
ladder de threads, pas par le modèle mono-thread).
