"""Chemins du flux principal et barrière d'approbation.

Send and Wait met le workflow en attente, puis le reprend aussi bien sur un
refus que sur un accord : le nœud seul n'est donc pas une barrière.
Elle est confirmée seulement si un IF (sortie 0) filtre `data.approved`
après cette attente. Tout autre chemin qui atteint l'effet laisse la
barrière ouverte.
"""

from __future__ import annotations

import json

from permis.classify import is_agent


def _links(bucket) -> list[str]:
    found = []
    if not isinstance(bucket, list):
        return found
    for group in bucket:
        for link in group or []:
            if isinstance(link, dict) and isinstance(link.get("node"), str):
                found.append(link["node"])
    return found


def main_adjacency(connections: dict) -> tuple[dict[str, list[tuple[int, str]]], set[str]]:
    adjacent: dict[str, list[tuple[int, str]]] = {}
    incoming: set[str] = set()
    if not isinstance(connections, dict):
        return adjacent, incoming
    for source, by_type in connections.items():
        if not isinstance(by_type, dict):
            continue
        outs: list[tuple[int, str]] = []
        groups = by_type.get("main")
        if isinstance(groups, list):
            for index, group in enumerate(groups):
                for link in group or []:
                    if isinstance(link, dict) and isinstance(link.get("node"), str):
                        outs.append((index, link["node"]))
                        incoming.add(link["node"])
        adjacent[source] = outs
    return adjacent, incoming


def tool_owners(connections: dict, nodes: dict[str, dict]) -> dict[str, str]:
    """Nom d'outil → nom de l'agent. Les deux sens d'export sont acceptés."""
    owners: dict[str, str] = {}
    if not isinstance(connections, dict):
        return owners
    for source, by_type in connections.items():
        if not isinstance(by_type, dict):
            continue
        for dest in _links(by_type.get("ai_tool")):
            source_agent = is_agent(nodes.get(source))
            dest_agent = is_agent(nodes.get(dest))
            if dest_agent and not source_agent:
                owners[source] = dest
            elif source_agent and not dest_agent:
                owners[dest] = source
            elif not source_agent:
                owners[source] = dest
    return owners


def _blob(node: dict) -> str:
    try:
        return json.dumps(node.get("parameters") or {}, ensure_ascii=False, default=str).lower()
    except TypeError:
        return ""


def is_human_wait(node: dict) -> bool:
    params = node.get("parameters") if isinstance(node.get("parameters"), dict) else {}
    if params.get("operation") == "sendAndWait":
        return True
    raw = node.get("type")
    short = raw.split(".")[-1] if isinstance(raw, str) else ""
    resume = params.get("resume")
    return short == "wait" and resume not in (None, "timeInterval", "specificTime")


def is_approval_filter(node: dict) -> bool:
    """IF ou Filter dont la condition cite le booléen renvoyé par Send and Wait.

    On ne traite pas le mot « approve » dans un texte libre : cela classerait
    comme fermé un filtre qui ne bloque pas le refus.
    """
    raw = node.get("type")
    short = raw.split(".")[-1] if isinstance(raw, str) else ""
    if short not in {"if", "filter"}:
        return False
    return "data.approved" in _blob(node) or '"approved"' in _blob(node)


def propagate(nodes: dict[str, dict], connections: dict) -> dict[str, list[tuple[bool, bool]]]:
    """Pour chaque nœud, les états (barrière confirmée, attente non filtrée) à l'arrivée."""
    adjacent, incoming = main_adjacency(connections)
    names = set(nodes)
    roots = [name for name in nodes if name not in incoming] or list(nodes)
    arrivals: dict[str, list[tuple[bool, bool]]] = {name: [] for name in names}
    seen: set[tuple[str, bool, bool]] = set()
    stack = [(root, False, False) for root in roots]
    while stack:
        current, gated, armed = stack.pop()
        mark = (current, gated, armed)
        if mark in seen or current not in names:
            continue
        seen.add(mark)
        node = nodes[current]
        leave_armed = True if is_human_wait(node) else armed
        filtering = is_approval_filter(node)
        for output_index, nxt in adjacent.get(current, []):
            next_gated, next_armed = gated, leave_armed
            if filtering:
                if output_index == 0 and leave_armed:
                    next_gated, next_armed = True, False
                else:
                    next_gated, next_armed = False, False
            if nxt in names:
                arrivals[nxt].append((next_gated, next_armed))
            stack.append((nxt, next_gated, next_armed))
    return arrivals


def reachable_from(starts: list[str], connections: dict) -> set[str]:
    adjacent, _ = main_adjacency(connections)
    seen: set[str] = set()
    stack = list(starts)
    while stack:
        current = stack.pop()
        for _, nxt in adjacent.get(current, []):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def flux_status(name: str, arrivals: dict[str, list[tuple[bool, bool]]]) -> tuple[str, bool]:
    """(oui|non|sans objet, attente humaine sans filtre sur ce nœud)."""
    states = arrivals.get(name) or []
    if not states:
        return "sans objet", False
    confirmed = all(gated for gated, _ in states)
    unfiltered = any(armed and not gated for gated, armed in states)
    return ("oui" if confirmed else "non"), unfiltered
