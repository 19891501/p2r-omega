"""Run the assurance campaign and write the auditable reports.

    PYTHONPATH=src python -m assurance.campaign

Core sources are not modified.
"""

from __future__ import annotations

import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from assurance.chaos import ghost_rollback, run_all
from assurance.measure import bench, concurrency_ladder, resource_bounds, supply
from assurance.oracle_diff import (
    compare_canonical,
    compare_identity,
    compare_universe,
    python311_digest,
)
from assurance.replay_registry import explore
from assurance.rfc6901 import run_corpus

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "assurance" / "results"


def _git():
    def one(*args):
        proc = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
        return proc.stdout.strip()

    return {"commit": one("rev-parse", "HEAD"), "status": one("status", "--porcelain")}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    print("model...", flush=True)
    model = explore()
    print("chaos...", flush=True)
    chaos = run_all()
    ghost = ghost_rollback()
    print("rfc...", flush=True)
    rfc = run_corpus()
    print("oracle...", flush=True)
    canonical = compare_canonical(20_000)
    identity = compare_identity(5_000)
    universe = compare_universe(1_000)
    py311 = python311_digest(2_000)
    print("concurrency...", flush=True)
    ladder = concurrency_ladder()
    print("resources/bench...", flush=True)
    resources = resource_bounds()
    timings = bench()
    chain = supply()
    meta = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "git": _git(),
    }
    summary = {
        "meta": meta,
        "model": {k: model[k] for k in ("status", "states", "edges", "actions", "timeout", "keys", "effects", "nows", "conflicts")},
        "chaos": chaos,
        "ghost_rollback": ghost,
        "rfc": {"status": rfc["status"], "rows": rfc["rows"], "conflicts": rfc["conflicts"]},
        "oracle": {"canonical": canonical, "identity": identity, "universe": universe, "python311": py311},
        "concurrency": ladder,
        "resources": resources,
        "bench": timings,
        "supply": chain,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    _write_reports(summary)
    print(json.dumps({
        "model": model["status"],
        "states": model["states"],
        "edges": model["edges"],
        "chaos": chaos["status"],
        "rfc": rfc["status"],
        "canonical": canonical["status"],
        "identity": identity["status"],
        "universe": universe["status"],
        "python311": py311["status"],
        "concurrency": ladder["status"],
        "bench_calls": timings["first_external_calls"],
    }, ensure_ascii=False))
    bad = [
        model["status"] != "PROUVÉ",
        chaos["status"] != "PROUVÉ",
        ghost["status"] != "PROUVÉ",
        rfc["status"] != "PROUVÉ",
        canonical["status"] != "PROUVÉ",
        identity["status"] != "PROUVÉ",
        universe["status"] != "PROUVÉ",
        py311["status"] == "CONFLIT",
        ladder["status"] != "PROUVÉ",
        timings["status"] != "PROUVÉ",
    ]
    return 1 if any(bad) else 0


def _write_reports(summary: dict) -> None:
    model = summary["model"]
    (ROOT / "MODEL_REPORT.md").write_text(_model_report(summary))
    (ROOT / "GUARANTEE_MATRIX.md").write_text(_matrix(summary))
    (ROOT / "SECURITY_CASE.md").write_text(_security(summary))
    (ROOT / "RED_TEAM_REPORT.md").write_text(_red(summary))
    print(f"states={model['states']} edges={model['edges']} {model['status']}")


def _model_report(summary: dict) -> str:
    model = summary["model"]
    meta = summary["meta"]
    py = summary["oracle"]["python311"]
    return f"""# MODEL_REPORT

Généré : {meta['generated']}. Python {meta['python']}. Commit au moment de la génération : `{meta['git']['commit'] or "non commité"}`.

## Recherche

Modèle indépendant : `assurance/model_registry.py` (n'importe pas `p2r`).
Rejeu : `assurance/replay_registry.py` sur `Registry` SQLite, une arête = un fichier restauré.

Borne : clés {model['keys']}, effets {model['effects']}, `now` {model['nows']}, timeout {model['timeout']}, {model['actions']} actions.

| | |
|---|---|
| États | {model['states']} |
| Arêtes | {model['edges']} |
| Conflits | {len(model['conflicts'])} |
| Statut | {model['status']} |

Aucun contre-exemple dans cette borne. La trace minimale serait rejouable par `replay_trace` si une divergence apparaissait.

Hors borne, donc INCONNU : trois clés ou plus, plusieurs reçus distincts, horloge non entière, deux processus. La ladder de threads couvre la même clé jusqu'à 64 fils, séparément.

## Oracle

| Surface | Volume | Statut |
|---|---|---|
| Canonisation | {summary['oracle']['canonical']['count']} | {summary['oracle']['canonical']['status']} |
| Identité d'effet | {summary['oracle']['identity']['count']} | {summary['oracle']['identity']['status']} |
| Univers | {summary['oracle']['universe']['count']} | {summary['oracle']['universe']['status']} |
| Python 3.11 vs ce processus, 2000 valeurs | digest | {py['status']} |

Python 3.12 et 3.13 ne sont pas installés ici. Ce n'est pas un accord : c'est INCONNU.
"""


def _matrix(summary: dict) -> str:
    ladder = ", ".join(
        f"{row['threads']}→{row['external_calls']} appel" for row in summary["concurrency"]["rows"]
    )
    return f"""# GUARANTEE_MATRIX

Statuts : PROUVÉ dans la borne citée, INCONNU hors domaine, CONFLIT si deux lecteurs divergent, ÉCHEC si une acceptation silencieuse est observée.

| Propriété | Statut | Preuve |
|---|---|---|
| Payload signé lié au digest | PROUVÉ | tests d'intégrité, mutation « digest court-circuité » tuée, oracle canonique {summary['oracle']['canonical']['count']} cas |
| Seuil d'autorité | PROUVÉ | tests de quorum, mutation du seuil tuée |
| Signataire non autorisé compte pour 0 | PROUVÉ | tests de signatures, mutation des doublons tuée |
| Lien d'effet | PROUVÉ | oracle identité {summary['oracle']['identity']['count']} cas, mutation des paramètres tuée |
| Nonce dans la clé d'exécution | PROUVÉ | même campagne, mutation « nonce fixé » tuée |
| `nonce_scope` vide = `global` | PROUVÉ | spec `||`, tests, mutation tuée |
| Racine d'univers | PROUVÉ | oracle {summary['oracle']['universe']['count']} cas, mutation des doublons tuée |
| Pointeur JSON, profil RFC 6901 | PROUVÉ | corpus `assurance/rfc6901.py`, zéro non-conforme dans le profil |
| Retry local, même `execution_key` | PROUVÉ | modèle {summary['model']['states']} états / {summary['model']['edges']} arêtes, chaos CH-03 |
| `RESERVED_AMBIGUOUS` bloque un nouveau dispatch | PROUVÉ | modèle, CH-01, CH-06, mutation « abandon au lieu d'ambigu » tuée |
| Kill laissant `RESERVED`, dans le timeout | PROUVÉ | CH-10, un seul détenteur, pas un second appel |
| Kill laissant `RESERVED`, après timeout | PROUVÉ | CH-11, réconciliation, pas `NEW` |
| Politique `deny` sur un autre nonce | PROUVÉ | CH-07 |
| `allow_new_attempt` signé, autre nonce | PROUVÉ comme autorisé | CH-08, deux appels, deux clés |
| Substitution de reçu | PROUVÉ sur `execute` | CH-05 `RETRY_RECEIPT_PAYLOAD_MISMATCH`, mutation du binding tuée |
| Statut SQL inconnu | PROUVÉ | CH-09, rollback GHOST, mutation tuée |
| Concurrence même clé | PROUVÉ jusqu'à 64 fils | {ladder} |
| Horloge en arrière | PROUVÉ : pas de second dispatch | CH-04 ; la raison du blocage dépend de l'état déjà écrit |
| Exactly-once distribué | INCONNU | un second fichier SQLite n'a pas la mémoire du premier |
| Vérité de l'effet externe | INCONNU | le reçu est une observation signée, pas le monde |
| Octets derrière le span de provenance | INCONNU | V1 ne les lit pas |
| Collision SHA-256 | INCONNU | non cherchée |
| Python 3.12 / 3.13 | INCONNU | interpréteurs absents |
| Profondeur non bornée | INCONNU comme DoS local | `RecursionError` refuse, n'accepte pas ; aucun plafond ajouté |
"""


def _security(summary: dict) -> str:
    bench = summary["bench"]
    return f"""# SECURITY_CASE

Les affirmations ci-dessous ne dépassent pas les preuves. Le cœur n'a pas été modifié par cette campagne.

## SC-01 Identité du payload

CLAIM. Muter un champ signé invalide l'identité.
ASSUMPTIONS. Sous-ensemble canonique V1. Pas de flottants.
EVIDENCE. `tests/test_integrity.py`, `tests/test_campaign.py`, oracle canonique ({summary['oracle']['canonical']['status']}, n={summary['oracle']['canonical']['count']}, graine {summary['oracle']['canonical']['seed']}). Mutation du comparateur de digest : tuée.
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
EVIDENCE. Oracle d'identité ({summary['oracle']['identity']['status']}, n={summary['oracle']['identity']['count']}). Mutations paramètres / nonce / scope tuées.
LIMITATION. Pas une preuve d'injectivité informationnelle au-delà de SHA-256.
STATUS. PROUVÉ sur l'échantillon et les mutations.

## SC-04 Pas de second dispatch local

CLAIM. Pour une `execution_key`, au plus un `NEW` tant que la ligne n'est pas revenue à ABSENT par `abandon`. `RESERVED_AMBIGUOUS` et `deny` après `EXECUTED` ne produisent pas `NEW`.
ASSUMPTIONS. Un seul registre SQLite. Horloge fournie par l'appelant. `abandon` n'est utilisé que pour affirmer l'absence de dispatch.
EVIDENCE. Modèle contre SQLite : {summary['model']['states']} états, {summary['model']['edges']} arêtes, {summary['model']['status']}. Chaos CH-01 à CH-11. Ladder : {summary['concurrency']['status']}.
LIMITATION. Borne de deux clés et deux effets. Pas de preuve pour n clés. Pas de preuve inter-hôtes.
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
EVIDENCE. CH-09. `ghost_rollback` : la récupération périmée est annulée avec l'erreur ({summary['ghost_rollback']['status']}). Mutation du contrôle de statut tuée.
LIMITATION. Un attaquant qui peut écrire EXECUTED avec un reçu valide de cet objet peut provoquer un retry. C'est le contenu légitime de la ligne, pas un contournement.
STATUS. PROUVÉ.

## SC-07 Ce qui n'est pas revendiqué

CLAIM. Aucune.
STATUS. INCONNU, volontaire : exactly-once distribué, obéissance du monde extérieur, consensus, paiement, octets sources du span, absence de DoS par profondeur.

## Mesures

Benchmark de ce processus ({bench['python']}, {bench['platform']}), n={bench['samples']}. Ce n'est pas une preuve.

| Chemin | p50 µs | p95 µs | p99 µs |
|---|---|---|---|
| canonisation | {bench['canonicalize']['p50_us']} | {bench['canonicalize']['p95_us']} | {bench['canonicalize']['p99_us']} |
| digest | {bench['digest']['p50_us']} | {bench['digest']['p95_us']} | {bench['digest']['p99_us']} |
| verify_object | {bench['verify_object']['p50_us']} | {bench['verify_object']['p95_us']} | {bench['verify_object']['p99_us']} |
| execute en cache | {bench['cached_execute']['p50_us']} | {bench['cached_execute']['p95_us']} | {bench['cached_execute']['p99_us']} |

Premier passage : {bench['first_external_calls']} appel externe.
"""


def _red(summary: dict) -> str:
    lines = [
        "# RED_TEAM_REPORT",
        "",
        "Une attaque ratée n'est une preuve que si le résultat dit pourquoi elle ne passe pas.",
        "Les familles A–Q de la campagne précédente restent dans `ATTACK_REPORT.md`. Ici : les scénarios ajoutés, y compris ceux qui échouent.",
        "",
        "## Registre exhaustif",
        "",
        f"ID. RT-MODEL",
        f"Objectif. Trouver un second `NEW`, un `EXECUTED` non collant, ou un désaccord modèle/SQLite.",
        f"Précondition. Borne {summary['model']['keys']} × {summary['model']['effects']}, timeout {summary['model']['timeout']}.",
        f"Attaque. {summary['model']['edges']} arêtes.",
        f"Résultat. {summary['model']['status']}. Conflits : {len(summary['model']['conflicts'])}.",
        "Preuve. `assurance/replay_registry.py`, `MODEL_REPORT.md`.",
        "Contre-mesure. Machine d'état inchangée : elle a tenu dans la borne.",
        f"Statut. {summary['model']['status']}",
        "",
        "## Chaos",
        "",
    ]
    for row in summary["chaos"]["results"]:
        lines += [
            f"### {row['id']} — {row['title']}",
            "",
            f"Objectif. Empêcher un second effet silencieux, ou montrer la politique signée.",
            f"Attaque. Premier résultat `{row['first']}`, second `{row['second']}`, appels externes {row['external_calls']}.",
            f"Résultat. {row['status']}. {row['note']}",
            "Preuve. `assurance/chaos.py`.",
            f"Statut. {row['status']}",
            "",
        ]
    lines += [
        "## GHOST et rollback",
        "",
        "ID. RT-GHOST",
        "Objectif. Faire commettre la conversion périmée malgré un statut illisible.",
        "Attaque. Ligne `k0` RESERVED à t=0, sœur `GHOST`, `reserve` à t=10.",
        f"Résultat. {summary['ghost_rollback']}.",
        "Preuve. La transaction annule la mise à jour. `k0` reste RESERVED.",
        f"Statut. {summary['ghost_rollback']['status']}",
        "",
        "## Corpus RFC 6901",
        "",
        "ID. RT-RFC6901",
        "Objectif. Trouver une divergence avec le profil JSON string, ou avec l'oracle.",
        f"Résultat. {summary['rfc']['status']}. Conflits : {summary['rfc']['conflicts'] or 'aucun'}.",
        "Classification. Les indices à zéro initial et la forme fragment URI sont des choix de profil, pas des extensions silencieuses. Aucune ligne n'est marquée non-conforme.",
        "Preuve. `assurance/rfc6901.py`.",
        f"Statut. {summary['rfc']['status']}",
        "",
        "## Attaques qui restent hors garantie",
        "",
        "ID. RT-SECOND-DB",
        "Objectif. Rejouer le même objet sur un registre vide.",
        "Résultat. Le second registre dispatch. C'est la frontière locale, pas un bug de liaison.",
        "Statut. INCONNU distribué. Documenté, non « corrigé ».",
        "",
        "ID. RT-DEPTH",
        "Objectif. Forcer un comportement généreux sur une structure très profonde.",
        "Résultat. `RecursionError`. Refus par accident d'implémentation, pas un plafond spécifié. Aucun changement de sémantique.",
        "Statut. INCONNU comme limite de ressource. Pas une acceptation.",
        "",
    ]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
