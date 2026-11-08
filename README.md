# Permis d'agir

Une page qui répond à la question qu'un client pose avant de laisser un agent n8n toucher sa boîte mail : **qu'est-ce que ce robot peut faire sans me demander ?**

Chaque action du fichier exporté est classée **AUTORISÉ**, **À SURVEILLER**, **BLOQUER** ou **INCONNU**. BLOQUER veut dire : l'effet peut partir sans validation humaine. Le livrable ajoute, devant les actions à risque, l'étape native de n8n « Send and Wait », puis un filtre qui ne continue que si la personne approuve.

Offre pilote : **49 € par workflow**, pour les freelances et les agences qui livrent des automatisations n8n. On lit l'export JSON. On ne demande pas l'accès à l'instance, ni les identifiants.

Ce n'est ni un audit de sécurité, ni un avis juridique, ni une certification AI Act. Le classement est une heuristique. Elle peut se tromper.

Le moteur dessous est [P2R-Ω](#le-moteur--p2r-ω) : il signe le document. Il ne décide pas à la place du classement, et il ne prouve pas qu'un e-mail est vraiment parti.

## Ce que vous recevez

`permis analyse workflow.json -o permis.md` écrit trois fichiers :

- `permis.md` — la page à lire ;
- `permis.json` — le même contenu, canonique, que l'on peut signer ;
- `permis.workflow.json` — le brouillon à réimporter dans n8n.

Avec `--signer clef.json`, le JSON porte un reçu. Le client le vérifie avec `permis verifier permis.json`.

## Exemple

Fichier de démonstration : `tests/fixtures/permis/relance.json` (une relance de factures écrite pour les tests, pas un modèle n8n). Extrait du permis :

| Verdict | Effet | Nœud | Action | Qui décide | Validation humaine avant ? | Statut preuve |
|---|---|---|---|---|---|---|
| BLOQUER | ENVOI EXTERNE | Envoyer au client | gmail : destinataire calculé | règle fixe, contenu produit par une IA | non | PROUVÉ |
| INCONNU | ENVOI EXTERNE | Alerter le juridique | gmail : envoi à user@example.com | règle fixe, contenu produit par une IA | non | PROUVÉ |
| INCONNU | CODE | Mettre en forme | code : exécute du code arbitraire | règle fixe, contenu produit par une IA | non | INCONNU |
| À SURVEILLER | ÉCRITURE | Mettre à jour la facture | googleSheets : update | règle fixe, contenu produit par une IA | non | PROUVÉ |
| AUTORISÉ | LECTURE | Lire factures | googleSheets : lecture (opération par défaut) | règle fixe | non | INCONNU |

L'adresse `user@example.com` est **INCONNU** : le fichier ne dit pas si c'est vous ou un client. L'adresse calculée depuis la feuille (`{{ ... Email }}`) est **BLOQUER** : un envoi part sans validation, vers une cible non prouvée.

Le brouillon ajoute, avant ces deux envois, un nœud Gmail `sendAndWait` (approuver / refuser) puis un nœud IF sur `data.approved`. La relecture du brouillon ne laisse plus d'effet BLOQUER sur cet exemple. Le code arbitraire reste INCONNU : on ne devine pas ce qu'il fait.

## Limites

Elles sont recopiées en bas de chaque permis. En bref :

- Analyse du fichier seulement. Pas les comptes connectés, pas les droits OAuth, pas l'historique d'exécution.
- Le classement est une heuristique. Un GET est traité comme une lecture (certains GET modifient le serveur). Un POST est une écriture. Slack est traité comme un envoi interne : un canal partagé avec un client ne se voit pas.
- Un export peut contenir des secrets en clair (clé, jeton, mot de passe, URL de webhook). Ceux qui sont reconnus sont signalés **sans la valeur**, et retirés du brouillon. Un format non reconnu peut rester : relisez le fichier avant de le transmettre.
- Send and Wait, dans n8n, reprend l'exécution aussi sur un refus (`data.approved = false`). Le brouillon ajoute donc un IF, sortie vraie seulement. Cela ne ferme pas un outil branché sur l'agent, un sous-workflow, une autre branche, ni un clic « exécuter ce nœud ».
- Le filtre suppose que la sortie 0 du IF est la branche vraie, comme aujourd'hui dans n8n.
- Une adresse e-mail fixe ne distingue pas « à moi » de « à un client ».
- Le reçu signe **ce document**. Le mot `COMPLETED` imposé par le reçu p2r veut dire que l'observation a été enregistrée, pas que le workflow a réussi, ni qu'un e-mail est parti.
- Le brouillon est à importer et à tester. Remplacez `approbateur@exemple.invalid`. Le compte Gmail de l'approbation n'est pas deviné : s'il existe déjà une référence Gmail (id et nom, sans secret), elle est reprise, sinon il faut la choisir dans n8n.

L'étape est ajoutée devant un envoi externe, une suppression, ou un appel de sous-workflow, sauf si tous les chemins du flux principal passent déjà par un tel filtre. Une écriture ou du code ne la reçoivent que lorsque **l'IA décide elle-même** (nœud outil). Une mise à jour de feuille en aval de l'agent reste « à surveiller », et un outil d'agent reste contournable : le permis le dit au lieu de le masquer.

## Comment lancer

Python 3.11 ou plus. Aucune dépendance au-delà de celles du dépôt (`cryptography`, déjà requise par le moteur).

```bash
python -m pip install -e ".[dev]"
permis analyse workflow.json -o permis.md
```

Sans installation :

```bash
PYTHONPATH=src python -m permis analyse workflow.json -o permis.md
```

Signer, puis vérifier :

```bash
permis clef -o clef.json --signer-id lhassan
permis analyse workflow.json -o permis.md --signer clef.json
permis verifier permis.json --clef publique.json --workflow workflow.json
```

`permis clef` écrit la graine privée dans `clef.json` (ne le versionnez pas, ne l'envoyez pas) et affiche la clef publique. Recopiez cette clef publique dans `publique.json` :

```json
{"signer_id": "lhassan", "public_key": "<valeur affichée>"}
```

Sans `--clef`, `permis verifier` contrôle seulement que le JSON n'a pas changé depuis la signature faite avec la clef qu'il contient : cela ne dit pas *qui* a signé. Avec `--clef`, la clef publique transmise à part doit être la même. Lui passer le fichier privé fonctionne, et la commande prévient qu'elle n'a utilisé que la partie publique.

Alias anglais des commandes : `analyze`, `verify`.

Les tests :

```bash
pytest -q
```

Sur cet arbre : **185 passed** (les 167 tests du moteur, plus ceux de Permis d'agir).

## English

**Agent Permit — what your n8n agent can do without asking, on one page.**

```bash
permis analyse workflow.json -o permis.md
permis verifier permis.json --clef public.json
```

You get every action found in the export, who decides it (a fixed rule or the AI), whether a human approval actually blocks a refusal, and a verdict: ALLOWED / WATCH / BLOCK / UNKNOWN. A draft workflow inserts n8n's Send and Wait step plus an IF on `data.approved` before risky effects. A fixed email address is UNKNOWN: the file cannot tell you from a client. A calculated address is not proof of who receives it either.

Pilot: €49 per workflow. Not a security audit, not legal advice, not an AI Act certification. The optional receipt signs the document. It does not prove the classification is right, and `COMPLETED` does not mean the workflow ran.

## Le moteur : P2R-Ω

Permis d'agir observe un fichier et, si on le demande, enferme cette observation dans un reçu du moteur. Le moteur reste le protocole gelé dans `src/p2r/`. Il ne gagne pas un état, un cache, ni un second chemin d'exécution.

**P2R-Ω Core — Proof-to-Realization Object**

P2R-Ω is a small authorization/execution object designed around one security invariant:

```text
PROOF ≠ AUTHORITY ≠ EFFECT ≠ EXECUTION ≠ RECEIPT
```

A proof may be valid while the exact effect, the execution attempt, or the observed result is not. P2R binds the authorized effect to a digest, then uses an execution registry to prevent accidental reuse of the same execution attempt.

### What V1 does

```text
DISCOVERY → UNIVERSE → SELECTION → INTENT → DECISION → AUTHORITY → EFFECT → EXECUTION → RECEIPT
```

The V1 implementation includes:

- deterministic canonicalization for a strict JSON subset;
- SHA-256 payload digests with URL-safe unpadded base64;
- detached Ed25519 authority signatures and threshold verification;
- deterministic evidence-universe root (`H(0x00 || leaf)`, `H(0x01 || left || right)`, `H(0x02)` for empty);
- literal structured-intent verification;
- `VERIFIED | UNKNOWN | CONFLICT` decisions, with fail-closed default;
- provenance checks against the resolved universe;
- strict RFC 6901 JSON Pointer token decoding (`~0` and `~1` only), plus strict array-index grammar (`0` or `[1-9][0-9]*`);
- stable `effect_identity` and `execution_key`;
- SQLite reservation states `RESERVED | EXECUTED | RESERVED_AMBIGUOUS`;
- stale reservation recovery;
- signed execution receipts;
- concurrent execution tests and attack tests;
- deterministic JSON vectors.

Permis d'agir uses the canonical form, the digest, `effect_identity`, `execution_key`, and the signed receipt. The "effect" in that receipt is the observation of the document, with `action_semantics: at_most_once`. It is not an authorization to run the n8n workflow.

### Security boundary

P2R-Ω does **not** claim global exactly-once execution.

The external adapter/target must declare its action semantics:

- `idempotent`: retries with the same execution key are expected to map to the same external outcome;
- `at_most_once`: an ambiguous dispatch is not automatically retried and requires reconciliation.

Core cannot prove what happened inside an external payment provider, API, database, human workflow, or network after control leaves the process.

### Payload identity

```text
payload_digest = SHA256(canonicalize(P2R minus payload_digest and signatures))
object_id      = payload_digest
```

The digest covers every signed payload field, including the world root, intent, decision, authority, effect, execution policy, and provenance. Detached signatures are excluded from the digest so they can be added/removed without changing the object identity.

The implementation rejects additional fields inside `payload_digest` so an apparently “unchecked” field cannot be smuggled into an unsigned sub-object.

### Effect identity

```text
effect_identity = H({
  actor_id,
  operation,
  rule,
  parameters,
  idempotency_key
})
```

The attempt key additionally binds the authority nonce and scope:

```text
execution_key = H({effect_identity, nonce_scope, nonce})
```

Changing the effect changes `effect_identity`. Changing only the nonce changes `execution_key` but not the effect identity.

### Registry state machine

```text
                    ┌───────────────┐
                    │    RESERVED   │
                    └───────┬───────┘
                            │ success
                            ▼
                    ┌───────────────┐
                    │    EXECUTED   │
                    └───────────────┘

RESERVED -- crash / unknown outcome --> RESERVED_AMBIGUOUS
RESERVED -- explicit pre-dispatch abandonment --> deleted

RESERVED_AMBIGUOUS -- any new attempt --> RECONCILIATION_REQUIRED
```

The critical failure case is deliberate:

```text
reserve → external dispatch succeeds → process dies → no receipt persisted
```

On restart the stale reservation becomes `RESERVED_AMBIGUOUS`; P2R refuses a fresh attempt until the external outcome is reconciled.

### Receipt

A receipt is signed by the observer and covers:

- P2R payload digest;
- execution key;
- effect identity;
- action semantics;
- observed effect;
- observer id and scope;
- observation time;
- `COMPLETED` result.

On a cached retry, the executor verifies the receipt cryptographically **and** checks its payload/effect/execution bindings against the current P2R object before returning it.

For a Permis, that `COMPLETED` result means the observation was recorded. It does not mean an external effect happened.

### Run the deterministic vectors

```bash
PYTHONPATH=src python scripts/generate_vectors.py
pytest -q tests/test_vectors.py
```

### Run the end-to-end demo

```bash
PYTHONPATH=src python scripts/demo.py
```

The demo creates `demo.db` in the repository root. It demonstrates that one real action invocation produces a signed receipt and a second call with the same execution key returns the cached receipt without invoking the external action again.

Heavier volumes are not repeated on every `pytest`:

```bash
PYTHONPATH=src python -m assurance.campaign
```

That command rewrites `MODEL_REPORT.md`, `GUARANTEE_MATRIX.md`, `SECURITY_CASE.md`, and `RED_TEAM_REPORT.md` from a fresh run. It does not change `src/p2r/`.

### Files

```text
p2r-omega/
├── README.md
├── LICENSE
├── pyproject.toml
├── src/permis/          Permis d'agir (produit)
├── src/p2r/             protocole gelé
├── tests/               pytest, dont tests/test_permis.py
├── tests/fixtures/permis/
├── vectors/
├── scripts/
├── assurance/           hors protocole
└── sentinel/            observateur externe, pas un import du cœur
```

### Deliberate non-guarantees

P2R-Ω V1 does not provide distributed consensus, a payment rail, a blockchain, a global idempotency service, source-byte/span truth verification, or a claim that an external effect happened merely because a receipt exists.

Those boundaries are intentional. The object is an authorization + attempt-binding + observed-receipt mechanism, not a replacement for the systems it calls.

### Assurance, outside the core

`src/p2r/` is the frozen protocol. `assurance/` does not add states, caches, or a second execution path. It holds an independent registry model, crash schedules, an RFC 6901 corpus, and the differential oracle runner. The claims those runs support are in `GUARANTEE_MATRIX.md` and `SECURITY_CASE.md`. Anything not listed there as PROUVÉ is not claimed.

`python scripts/p2r-sentinel certify <repo>` is one certificate. On this repository that can be `CERTIFIED`. On a repository without `src/p2r` it is an external observation, not a core certification, and it does not collect payment. `python scripts/p2r-sentinel daemon` repeats the local cycle and appends `.sentinel/journal.jsonl`. It does not write the core registry. A dirty tree or `--no-replay` stays `UNKNOWN`. `QUARANTINED` in `.sentinel/` is not a registry status. See `docs/SENTINEL.md`.

### Status tags

**PROUVÉ** — deterministic digesting, Ed25519 signatures, threshold counting, universe-root checking, intent/decision/provenance checks, SQLite reservation state machine, signed receipts, concurrency tests, crash/ambiguity tests.

**UNKNOWN** — external-world outcome when dispatch leaves the process boundary; source-byte truth behind provenance spans; distributed multi-host exactly-once semantics. The same word, in a Permis, means the n8n file does not determine the verdict.

**CONFLICT** — any decision explicitly marked `CONFLICT`, which is rejected by default by the V1 execution policy. In a Permis, two fields of the same node disagree (for example a draft resource with a send operation).

**ÉCHEC** — any invariant verification failure or forbidden registry transition; failures are raised rather than silently downgraded.
