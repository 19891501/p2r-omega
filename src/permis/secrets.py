"""Repère des secrets en clair et ne les recopie jamais.

La détection est volontairement incomplète : un mot de passe dans une phrase
quelconque, sans nom de champ reconnaissable ni préfixe connu, peut passer.
"""

from __future__ import annotations

import re
from typing import Any

PLACEHOLDER = "***PERMIS_SECRET_RETIRE***"

# Préfixes et formes que l'on sait reconnaître sans lire le nom du champ.
_VALUE_PATTERNS = (
    re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{10,}"),
    re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{10,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"glpat-[A-Za-z0-9\-]{10,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
    re.compile(r"hooks\.slack\.com/services/[A-Za-z0-9+/_\-]{4,}(?:/[A-Za-z0-9+/_\-]+)+"),
    re.compile(r"discord(?:app)?\.com/api/webhooks/[A-Za-z0-9_\-]{4,}/[A-Za-z0-9_\-]{4,}"),
    re.compile(r"https?://[^\s/@:]{1,64}:[^\s/@]{4,}@"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{12,}"),
)

_SENSITIVE_KEY = re.compile(
    r"(api[_-]?key|client[_-]?secret|secret|password|passwd|token|"
    r"authorization|private[_-]?key|access[_-]?key|bearer)",
    re.IGNORECASE,
)

# Ces clefs portent un nom technique, pas une valeur à masquer.
_KEY_NAME_OK = {"id", "name", "type", "typeversion", "position", "webhookid"}


def pattern_hit(text: str) -> bool:
    if not isinstance(text, str) or text == PLACEHOLDER:
        return False
    return any(pattern.search(text) for pattern in _VALUE_PATTERNS)


def scrub(text: str) -> str:
    """Si une forme connue apparaît, la chaîne entière est remplacée.

    Un remplacement partiel laisserait la fin d'un jeton dans le texte.
    """
    if not isinstance(text, str):
        return text
    if pattern_hit(text):
        return "***"
    return text


def _sensitive_key(key: str | None) -> bool:
    if not key or key.lower() in _KEY_NAME_OK:
        return False
    return _SENSITIVE_KEY.search(key) is not None


def _expression_without_literal(text: str) -> bool:
    stripped = text.strip()
    if not (stripped.startswith("=") or "{{" in stripped):
        return False
    return not pattern_hit(text)


def is_hardcoded_secret(key: str | None, value: str) -> bool:
    """Vrai si la valeur ne doit pas être imprimée.

    Une expression n8n (`={{ ... }}`) n'est un secret que si un littéral
    reconnaissable y est collé. Un champ nommé comme un secret, avec une
    valeur courte ou un placeholder, n'est pas signalé.
    """
    if not isinstance(value, str) or value == PLACEHOLDER:
        return False
    if pattern_hit(value):
        return True
    if not _sensitive_key(key):
        return False
    if _expression_without_literal(value):
        return False
    stripped = value.strip()
    if len(stripped) < 8:
        return False
    if stripped.lower() in {"changeme", "password", "secret", "token", "placeholder"}:
        return False
    return True


def _segment(key: str) -> str:
    return "***" if pattern_hit(key) else key


def find_secrets(workflow: Any) -> list[dict]:
    """Liste {node, path, kind, length}. Jamais la valeur."""
    found: list[dict] = []

    def walk(value: Any, path: str, node: str | None, key: str | None) -> None:
        if isinstance(value, dict):
            for child_key, child in value.items():
                if not isinstance(child_key, str):
                    continue
                walk(child, f"{path}/{_segment(child_key)}", node, child_key)
            return
        if isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{path}/{index}", node, key)
            return
        if isinstance(value, str) and is_hardcoded_secret(key, value):
            kind = "nom de nœud" if key == "name" else "champ" if _sensitive_key(key) else "motif"
            found.append(
                {
                    "node": node,
                    "path": path or "/",
                    "kind": kind,
                    "length": len(value),
                }
            )

    if isinstance(workflow, dict):
        nodes = workflow.get("nodes")
        if isinstance(nodes, list):
            for index, node in enumerate(nodes):
                label = None
                if isinstance(node, dict) and isinstance(node.get("name"), str):
                    label = "***" if pattern_hit(node["name"]) else node["name"]
                walk(node, f"/nodes/{index}", label, None)
        for top_key, top_value in workflow.items():
            if top_key == "nodes":
                continue
            walk(top_value, f"/{_segment(top_key)}", None, top_key)
    found.sort(key=lambda item: (item["node"] or "", item["path"], item["kind"]))
    return found


def name_masks(workflow: dict) -> dict[str, str]:
    """Renomme les nœuds dont le nom est lui-même un secret."""
    masks: dict[str, str] = {}
    nodes = workflow.get("nodes")
    if not isinstance(nodes, list):
        return masks
    index = 1
    for node in nodes:
        if not isinstance(node, dict):
            continue
        name = node.get("name")
        if isinstance(name, str) and pattern_hit(name) and name not in masks:
            masks[name] = f"nœud masqué {index}"
            index += 1
    return masks


def replace_named(value: Any, masks: dict[str, str]) -> Any:
    """Remplace les noms-secrets partout, clefs de connexion comprises."""
    if not masks:
        return value
    ordered = sorted(masks, key=len, reverse=True)

    def sub(text: str) -> str:
        for old in ordered:
            text = text.replace(old, masks[old])
        return text

    def walk(item: Any) -> Any:
        if isinstance(item, str):
            return sub(item)
        if isinstance(item, list):
            return [walk(child) for child in item]
        if isinstance(item, dict):
            return {sub(key) if isinstance(key, str) else key: walk(child) for key, child in item.items()}
        return item

    return walk(value)


def redact_values(value: Any, key: str | None = None) -> Any:
    """Remplace chaque secret restant par un placeholder, sans garder la valeur."""
    if isinstance(value, dict):
        return {
            child_key: redact_values(child, child_key if isinstance(child_key, str) else None)
            for child_key, child in value.items()
        }
    if isinstance(value, list):
        return [redact_values(child, key) for child in value]
    if isinstance(value, str) and is_hardcoded_secret(key, value):
        return PLACEHOLDER
    return value


def display_name(name: str, masks: dict[str, str]) -> str:
    return masks.get(name, name)
