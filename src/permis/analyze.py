"""Assemble le Permis à partir d'un export n8n."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from p2r.digest import sha256_b64

from permis.classify import classify_node, is_agent, short_type, skipped
from permis.errors import PermisError
from permis.graph import flux_status, propagate, reachable_from, tool_owners
from permis.patch import APPROVER, insert_approvals
from permis.report import static_limits
from permis.secrets import (
    display_name,
    find_secrets,
    name_masks,
    pattern_hit,
    redact_values,
    replace_named,
    scrub,
)
from permis.sign import PERMIS_TYPE
from permis.workflow import dump_bytes, load_bytes

_ORDER = {"BLOQUER": 0, "INCONNU": 1, "À SURVEILLER": 2, "AUTORISÉ": 3}
_TOOL_BYPASS = {"ENVOI EXTERNE", "IRRÉVERSIBLE", "ÉCRITURE", "CODE", "SOUS-WORKFLOW"}


@dataclass
class Analysis:
    permis: dict
    corrected: dict | None
    corrected_bytes: bytes | None


def analyze_path(path: Path, *, correct: bool = True) -> Analysis:
    raw = Path(path).read_bytes()
    try:
        workflow = load_bytes(raw)
    except PermisError:
        raise
    except OSError as exc:
        raise PermisError("FICHIER_ILLISIBLE", "Fichier introuvable ou illisible.") from exc
    return analyze_workflow(
        workflow,
        filename=Path(path).name,
        file_sha256=sha256_b64(raw),
        correct=correct,
    )


def analyze_workflow(workflow: dict, *, filename: str, file_sha256: str, correct: bool) -> Analysis:
    if pattern_hit(filename):
        filename = "fichier masqué"
    masks = name_masks(workflow)
    rows, agents, extra_limits = _inspect(workflow, masks)
    secrets = _public_secrets(find_secrets(workflow), masks)
    correction = None
    corrected = None
    corrected_bytes = None
    if correct:
        corrected, meta = insert_approvals(workflow, rows)
        corrected = replace_named(corrected, masks)
        corrected = redact_values(corrected)
        corrected_bytes = dump_bytes(corrected)
        reread_rows, _, _ = _inspect(corrected, {})
        correction = _correction(meta, masks, corrected, reread_rows, sha256_b64(corrected_bytes))
        bypasses = _bypasses(rows)
        correction["bypasses"] = _scrub_obj(replace_named(bypasses, masks))
    permis = _document(
        workflow=workflow,
        filename=filename,
        file_sha256=file_sha256,
        agents=agents,
        rows=rows,
        secrets=secrets,
        correction=correction,
        extra_limits=extra_limits,
    )
    return Analysis(permis, corrected, corrected_bytes)


def _document(*, workflow, filename, file_sha256, agents, rows, secrets, correction, extra_limits) -> dict:
    public_rows = []
    for row in rows:
        public = {key: value for key, value in row.items() if key != "noeud_source"}
        public_rows.append(_scrub_obj(public))
    summary = {key: 0 for key in _ORDER}
    for row in public_rows:
        summary[row["verdict"]] += 1
    limits = static_limits()
    seen = set(limits)
    for item in extra_limits:
        if item not in seen:
            limits.append(item)
            seen.add(item)
    name = workflow.get("name") if isinstance(workflow.get("name"), str) and workflow.get("name") else filename
    if pattern_hit(name):
        name = "workflow masqué"
    else:
        name = scrub(name).replace("|", "/").replace("\n", " ")
    node_count = len(workflow.get("nodes") or [])
    permis = {
        "type": PERMIS_TYPE,
        "workflow": {
            "name": name,
            "filename": filename,
            "sha256": file_sha256,
            "nodes": node_count,
            "agents": [_scrub_obj(agent) for agent in agents],
        },
        "summary": summary,
        "rows": public_rows,
        "secrets": secrets,
        "correction": correction,
        "limits": limits,
    }
    _reject_floats(permis)
    return permis


def _inspect(workflow: dict, masks: dict[str, str]) -> tuple[list[dict], list[str], list[str]]:
    raw_nodes = workflow.get("nodes") if isinstance(workflow.get("nodes"), list) else []
    nodes: dict[str, dict] = {}
    extras: list[str] = []
    seen: set[str] = set()
    for node in raw_nodes:
        if not isinstance(node, dict) or not isinstance(node.get("name"), str):
            extras.append("Un nœud sans nom a été ignoré.")
            continue
        name = node["name"]
        if name in seen:
            extras.append("Plusieurs nœuds portent le même nom : le dernier seul est lu, les liens sont ambigus.")
        seen.add(name)
        nodes[name] = node
    connections = workflow.get("connections") if isinstance(workflow.get("connections"), dict) else {}
    owners = tool_owners(connections, nodes)
    arrivals = propagate(nodes, connections)
    agents = [name for name, node in nodes.items() if is_agent(node)]
    reachable = reachable_from(agents, connections)
    rows = []
    saw_subflow = False
    for name, node in nodes.items():
        if short_type(node) in {"executeWorkflow", "executeWorkflowTrigger"}:
            saw_subflow = True
        if skipped(node):
            continue
        classified = classify_node(node)
        flux, unfiltered = flux_status(name, arrivals)
        tool = name in owners
        if tool:
            who = f"IA « {display_name(owners[name], masks)} » (outil : l'IA décide quand et quoi)"
            validation = "non"
        else:
            who = "règle fixe, contenu produit par une IA" if name in reachable else "règle fixe"
            validation = flux
        who = scrub(who)
        verdict = _verdict(classified, who, validation)
        rows.append(
            {
                "verdict": verdict,
                "effet": classified["effet"],
                "noeud": display_name(name, masks),
                "noeud_source": name,
                "action": classified["action"],
                "qui_decide": who,
                "validation_humaine": validation,
                "flux_principal": flux,
                "preuve": classified["preuve"],
                "note": _note(classified, who, validation, unfiltered, tool),
            }
        )
    rows.sort(key=lambda row: (_ORDER[row["verdict"]], row["noeud"]))
    if saw_subflow:
        extras.append("Un sous-workflow est appelé. Son contenu n'est pas dans ce fichier.")
    settings = workflow.get("settings")
    if isinstance(settings, dict) and settings.get("errorWorkflow"):
        extras.append("Un workflow d'erreur est configuré. Son contenu n'est pas dans ce fichier.")
    if workflow.get("pinData"):
        extras.append(
            "Des données épinglées (pinData) sont présentes. Le permis ne les recopie pas. "
            "Le workflow corrigé les conserve, secrets reconnus retirés."
        )
    agents_public = [scrub(display_name(name, masks)) for name in agents]
    return rows, agents_public, extras


def _verdict(classified: dict, who: str, validation: str) -> str:
    effet = classified["effet"]
    mode = classified["destinataire"]
    risky = effet in {"ENVOI EXTERNE", "IRRÉVERSIBLE"} or (
        effet in {"ÉCRITURE", "CODE"} and who.startswith("IA")
    )
    if effet == "LECTURE":
        return "AUTORISÉ"
    if effet == "VALIDATION":
        return "À SURVEILLER"
    if risky and validation != "oui" and "IA" in who:
        if effet == "ENVOI EXTERNE" and mode in {"litteral", "mixte"}:
            return "INCONNU"
        if effet == "ENVOI EXTERNE" and mode == "absent" and not who.startswith("IA"):
            return "INCONNU"
        return "BLOQUER"
    if effet in {"CODE", "INCONNU", "SOUS-WORKFLOW"}:
        return "INCONNU"
    return "À SURVEILLER"


def _note(classified: dict, who: str, validation: str, unfiltered: bool, tool: bool) -> str:
    effet = classified["effet"]
    mode = classified["destinataire"]
    notes = []
    if effet == "ENVOI EXTERNE":
        if mode == "litteral":
            notes.append(
                "relation destinataire : INCONNU — adresse fixe, le fichier ne distingue pas un envoi à vous-même d'un envoi à un client"
            )
        elif mode == "expression":
            notes.append("relation destinataire : INCONNU — adresse calculée, probable tiers, non prouvé")
        elif mode == "mixte":
            notes.append("relation destinataire : INCONNU — adresses de formes différentes")
        elif mode == "absent" and who.startswith("IA"):
            notes.append("aucun destinataire dans le nœud : l'IA peut le choisir")
        elif mode == "absent":
            notes.append("destinataire absent du nœud")
    if tool and effet in _TOOL_BYPASS:
        notes.append("outil d'agent : un Send and Wait sur le flux principal ne bloque pas cet appel")
    if unfiltered and validation != "oui":
        notes.append("une attente humaine est en amont, sans filtre sur data.approved : un refus peut continuer")
    if effet == "CODE":
        notes.append("le code peut faire autre chose que ce que le graphe montre")
    if effet == "SOUS-WORKFLOW":
        notes.append("le workflow appelé n'a pas été lu")
    if effet == "VALIDATION":
        notes.append(f"message d'approbation : remplacez le destinataire s'il vaut encore {APPROVER}")
    if validation == "sans objet" and effet in {"ENVOI EXTERNE", "IRRÉVERSIBLE"}:
        notes.append("aucun lien entrant : ne part pas avec le flux, sauf exécution manuelle du nœud")
    return " ".join(notes)


def _bypasses(rows: list[dict]) -> list[dict]:
    found = []
    for row in rows:
        if row["qui_decide"].startswith("IA") and row["effet"] in _TOOL_BYPASS:
            found.append(
                {
                    "node": row["noeud"],
                    "reason": "outil d'agent : l'étape ajoutée sur le flux principal ne couvre pas cet appel",
                }
            )
    return found


def _correction(meta: dict, masks: dict, corrected: dict, reread_rows: list[dict], digest: str) -> dict:
    public_meta = _scrub_obj(replace_named(meta, masks))
    summary = {key: 0 for key in _ORDER}
    still = []
    for row in reread_rows:
        summary[row["verdict"]] += 1
        if row["verdict"] == "BLOQUER":
            still.append(row["noeud"])
    public_meta["reread"] = summary
    public_meta["still_blocking"] = [scrub(name) for name in still]
    public_meta["secrets_restants"] = len(find_secrets(corrected))
    public_meta["corrected_sha256"] = digest
    return public_meta


def _public_secrets(secrets: list[dict], masks: dict) -> list[dict]:
    cleaned = []
    for item in secrets:
        node = item["node"]
        if isinstance(node, str):
            node = display_name(node, masks) if node in masks else scrub(node)
        cleaned.append(
            {
                "node": node,
                "path": scrub(item["path"]),
                "kind": item["kind"],
                "length": item["length"],
            }
        )
    return cleaned


def _scrub_obj(value):
    if isinstance(value, str):
        return scrub(value)
    if isinstance(value, list):
        return [_scrub_obj(item) for item in value]
    if isinstance(value, dict):
        return {key: _scrub_obj(item) for key, item in value.items()}
    return value


def _reject_floats(value, path: str = "") -> None:
    if isinstance(value, float):
        raise PermisError("NOMBRE_NON_ENTIER", f"Nombre à virgule dans le permis ({path}).")
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_floats(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_floats(item, f"{path}[{index}]")
