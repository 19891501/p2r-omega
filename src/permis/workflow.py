"""Lecture d'un export n8n. Un fichier, un workflow."""

from __future__ import annotations

import json

from permis.errors import PermisError


def load_bytes(raw: bytes) -> dict:
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeError as exc:
        raise PermisError("FICHIER_ILLISIBLE", "Le fichier n'est pas de l'UTF-8.") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PermisError("JSON_INVALIDE", "Le fichier n'est pas du JSON.") from exc
    return unwrap(data)


def unwrap(data):
    if isinstance(data, list):
        if len(data) != 1:
            raise PermisError("PLUSIEURS_WORKFLOWS", "Un fichier doit contenir un seul workflow.")
        data = data[0]
    if not isinstance(data, dict):
        raise PermisError("JSON_INVALIDE", "Un objet JSON est attendu.")
    wrapper_name = data.get("name") if isinstance(data.get("name"), str) else None
    workflow = data
    if "nodes" not in workflow and isinstance(workflow.get("workflow"), dict):
        workflow = workflow["workflow"]
    if isinstance(workflow, dict) and "nodes" not in workflow and isinstance(workflow.get("workflow"), dict):
        workflow = workflow["workflow"]
    if not isinstance(workflow, dict) or not isinstance(workflow.get("nodes"), list):
        raise PermisError("FICHIER_SANS_NOEUDS", "Pas de liste de nœuds dans ce fichier.")
    if "name" not in workflow and wrapper_name:
        workflow = dict(workflow)
        workflow["name"] = wrapper_name
    return workflow


def dump_bytes(workflow: dict) -> bytes:
    return (json.dumps(workflow, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")
