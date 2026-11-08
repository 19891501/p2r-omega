"""Insère l'approbation native n8n (Send and Wait) puis un filtre.

Le filtre est indispensable : avec le type de réponse « approval », n8n
reprend l'exécution aussi quand la personne refuse, en renvoyant
`data.approved = false`. Sans IF sur la sortie vraie, l'effet part quand même.

Cela ne coupe pas un outil branché sur l'agent, ni un sous-workflow.
"""

from __future__ import annotations

import hashlib
from copy import deepcopy

from permis.secrets import pattern_hit

APPROVER = "approbateur@exemple.invalid"
STICKY_NAME = "Permis d'agir — lire avant d'importer"

_RISKY_EFFECTS = {"ENVOI EXTERNE", "IRRÉVERSIBLE", "SOUS-WORKFLOW"}
_TOOL_EFFECTS = {"ÉCRITURE", "CODE"}


def _uuid(label: str) -> str:
    digest = hashlib.sha256(label.encode("utf-8")).hexdigest()
    return f"{digest[:8]}-{digest[8:12]}-4{digest[13:16]}-a{digest[17:20]}-{digest[20:32]}"


def _coords(node: dict) -> tuple[int, int]:
    position = node.get("position")
    if (
        isinstance(position, list)
        and len(position) >= 2
        and all(isinstance(item, (int, float)) and not isinstance(item, bool) for item in position[:2])
    ):
        return int(position[0]), int(position[1])
    return 0, 0


def _unique(existing: set[str], base: str) -> str:
    name = base[:80]
    if name not in existing:
        existing.add(name)
        return name
    index = 2
    while True:
        candidate = f"{base[:72]} ({index})"
        if candidate not in existing:
            existing.add(candidate)
            return candidate
        index += 1


def _gmail_credential(workflow: dict) -> dict | None:
    nodes = workflow.get("nodes")
    if not isinstance(nodes, list):
        return None
    for node in nodes:
        if not isinstance(node, dict):
            continue
        credentials = node.get("credentials")
        if not isinstance(credentials, dict):
            continue
        gmail = credentials.get("gmailOAuth2")
        if not isinstance(gmail, dict):
            continue
        identifier = gmail.get("id")
        label = gmail.get("name")
        if isinstance(identifier, str) and isinstance(label, str) and identifier and label:
            if pattern_hit(identifier) or pattern_hit(label):
                continue
            return {"gmailOAuth2": {"id": identifier, "name": label}}
    return None


def needs_main_gate(row: dict) -> bool:
    """Vrai si le flux principal devrait être arrêté avant cet effet.

    `flux_principal` ignore le contournement par outil : un outil déjà précédé
    d'un filtre ne reçoit pas une deuxième étape à chaque relance.
    """
    if row.get("flux_principal") == "oui":
        return False
    effet = row.get("effet")
    if effet in _RISKY_EFFECTS:
        return True
    decides = row.get("qui_decide") or ""
    return effet in _TOOL_EFFECTS and decides.startswith("IA")


def _has_main_incoming(connections: dict, target: str) -> bool:
    if not isinstance(connections, dict):
        return False
    for by_type in connections.values():
        if not isinstance(by_type, dict):
            continue
        for group in by_type.get("main") or []:
            for link in group or []:
                if isinstance(link, dict) and link.get("node") == target:
                    return True
    return False


def _retarget(connections: dict, target: str, approval: str) -> int:
    moved = 0
    for by_type in connections.values():
        if not isinstance(by_type, dict):
            continue
        groups = by_type.get("main")
        if not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, list):
                continue
            for link in group:
                if isinstance(link, dict) and link.get("node") == target:
                    link["node"] = approval
                    link["type"] = "main"
                    link["index"] = 0
                    moved += 1
    return moved


def insert_approvals(workflow: dict, rows: list[dict]) -> tuple[dict, dict]:
    """Copie le workflow et ajoute les étapes. N'enlève pas encore les secrets."""
    corrected = deepcopy(workflow)
    nodes = corrected.get("nodes")
    connections = corrected.get("connections")
    if not isinstance(nodes, list) or not isinstance(connections, dict):
        corrected["nodes"] = nodes if isinstance(nodes, list) else []
        corrected["connections"] = connections if isinstance(connections, dict) else {}
        nodes = corrected["nodes"]
        connections = corrected["connections"]

    by_name = {}
    for node in nodes:
        if isinstance(node, dict) and isinstance(node.get("name"), str):
            by_name[node["name"]] = node
    existing = set(by_name)
    credential = _gmail_credential(corrected)
    inserted = []
    not_applied = []
    already = []
    for row in rows:
        if row.get("flux_principal") == "oui" and (
            row.get("effet") in _RISKY_EFFECTS
            or (row.get("effet") in _TOOL_EFFECTS and (row.get("qui_decide") or "").startswith("IA"))
        ):
            already.append(row["noeud_source"])

    targets = [row for row in rows if needs_main_gate(row)]
    for row in targets:
        target = row["noeud_source"]
        if target not in by_name or not _has_main_incoming(connections, target):
            not_applied.append(
                {
                    "node": target,
                    "reason": "aucun flux principal entrant : une exécution manuelle du nœud, ou un lien qui n'est pas de type main, ne passe pas par une étape ajoutée ici",
                }
            )
            continue
        approval = _unique(existing, f"Permis — approuver avant « {target} »")
        filt = _unique(existing, f"Permis — filtre avant « {target} »")
        refused = _unique(existing, f"Permis — refus avant « {target} »")
        x, y = _coords(by_name[target])
        _retarget(connections, target, approval)
        nodes.extend(
            [
                _approval_node(approval, target, x, y, credential),
                _filter_node(filt, target, x, y),
                _noop_node(refused, x, y),
            ]
        )
        connections[approval] = {"main": [[{"node": filt, "type": "main", "index": 0}]]}
        connections[filt] = {
            "main": [
                [{"node": target, "type": "main", "index": 0}],
                [{"node": refused, "type": "main", "index": 0}],
            ]
        }
        inserted.append({"before": target, "approval": approval, "filter": filt, "refusal": refused})

    _upsert_sticky(nodes, existing, inserted, not_applied)
    meta = {"inserted": inserted, "not_applied": not_applied, "already_gated": already}
    return corrected, meta


def _approval_node(name: str, target: str, x: int, y: int, credential: dict | None) -> dict:
    node = {
        "parameters": {
            "resource": "message",
            "operation": "sendAndWait",
            "sendTo": APPROVER,
            "subject": "Permis d'agir — approbation requise",
            "message": (
                "Une action à risque va s'exécuter dans ce workflow. "
                "Approuvez seulement si vous acceptez cet effet. "
                f"Remplacez l'adresse {APPROVER} par la personne qui doit décider. "
                "Un refus doit s'arrêter sur le filtre suivant. "
                "Cette étape peut être contournée par un outil d'agent, un sous-workflow ou une exécution manuelle."
            ),
            "responseType": "approval",
            "approvalOptions": {
                "values": {
                    "approvalType": "double",
                    "approveLabel": "Approuver",
                    "disapproveLabel": "Refuser",
                    "buttonApprovalStyle": "primary",
                    "buttonDisapprovalStyle": "secondary",
                }
            },
            "options": {},
        },
        "type": "n8n-nodes-base.gmail",
        "typeVersion": 2.1,
        "position": [x - 420, y],
        "id": _uuid(f"approval:{target}"),
        "name": name,
        "webhookId": _uuid(f"webhook:{target}"),
        "notes": (
            "Inséré par Permis d'agir. Send and Wait reprend aussi sur un refus : "
            "le nœud IF suivant ne laisse passer que la sortie vraie (data.approved)."
        ),
    }
    if credential:
        node["credentials"] = credential
    return node


def _filter_node(name: str, target: str, x: int, y: int) -> dict:
    return {
        "parameters": {
            "conditions": {
                "options": {
                    "caseSensitive": True,
                    "leftValue": "",
                    "typeValidation": "strict",
                    "version": 2,
                },
                "conditions": [
                    {
                        "id": _uuid(f"cond:{target}"),
                        "leftValue": "={{ $json.data.approved }}",
                        "rightValue": True,
                        "operator": {"type": "boolean", "operation": "true", "singleValue": True},
                    }
                ],
                "combinator": "and",
            },
            "options": {},
        },
        "type": "n8n-nodes-base.if",
        "typeVersion": 2.2,
        "position": [x - 200, y],
        "id": _uuid(f"filter:{target}"),
        "name": name,
    }


def _noop_node(name: str, x: int, y: int) -> dict:
    return {
        "parameters": {},
        "type": "n8n-nodes-base.noOp",
        "typeVersion": 1,
        "position": [x - 200, y + 180],
        "id": _uuid(f"noop:{name}"),
        "name": name,
    }


def _upsert_sticky(nodes: list, existing: set[str], inserted: list, not_applied: list) -> None:
    lines = [
        "## Permis d'agir",
        "Fichier modifié automatiquement. À importer et à tester, pas à mettre en production tel quel.",
        f"Remplacez {APPROVER} par la personne qui approuve.",
        "Send and Wait seul ne bloque pas un refus : le filtre data.approved (sortie 0) est là pour ça.",
        "Cela ne ferme pas un outil d'agent, un sous-workflow, ni une exécution manuelle du nœud.",
        "Les secrets reconnus ont été retirés : ressaisissez-les dans n8n, ne les collez pas dans une note.",
    ]
    if inserted:
        lines.append("Étapes ajoutées avant : " + ", ".join(item["before"] for item in inserted) + ".")
    if not_applied:
        lines.append("Sans étape ajoutée : " + ", ".join(item["node"] for item in not_applied) + ".")
    content = "\n".join(lines)
    for node in nodes:
        if isinstance(node, dict) and node.get("name") == STICKY_NAME:
            params = node.setdefault("parameters", {})
            if isinstance(params, dict):
                params["content"] = content
            return
    nodes.append(
        {
            "parameters": {"content": content, "height": 280, "width": 460},
            "type": "n8n-nodes-base.stickyNote",
            "typeVersion": 1,
            "position": [-520, -220],
            "id": _uuid("sticky:permis"),
            "name": STICKY_NAME,
        }
    )
    existing.add(STICKY_NAME)
