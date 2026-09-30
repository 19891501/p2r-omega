"""Canonical evidence universes and domain-separated manifest roots."""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from typing import Protocol, Sequence

from .canonical import canonicalize
from .digest import sha256_b64
from .errors import VerifyError


class UniverseResolver(Protocol):
    def resolve(self, discovery: dict) -> Sequence[dict]:
        ...


def _leaf(evidence: dict) -> bytes:
    return sha256(b"\x00" + canonicalize(evidence)).digest()


def _parent(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right).digest()


def manifest_root(universe: Sequence[dict]) -> str:
    """Return the deterministic Merkle-style root of an evidence universe.

    Evidence is canonicalized by unique ``evidence_id`` ordering. An empty
    universe has the explicit domain-separated root H(0x02).
    """
    items = [deepcopy(item) for item in universe]
    ids: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            raise VerifyError("UNIVERSE_EVIDENCE_INVALID")
        evidence_id = item.get("evidence_id")
        if not isinstance(evidence_id, str) or not evidence_id:
            raise VerifyError("UNIVERSE_EVIDENCE_ID_MISSING")
        ids.append(evidence_id)
    if len(ids) != len(set(ids)):
        raise VerifyError("UNIVERSE_EVIDENCE_ID_DUPLICATE")

    items.sort(key=lambda item: item["evidence_id"].encode("utf-8"))
    nodes = [_leaf(item) for item in items]
    if not nodes:
        return sha256_b64(b"\x02")
    while len(nodes) > 1:
        if len(nodes) % 2:
            nodes.append(nodes[-1])
        nodes = [_parent(nodes[i], nodes[i + 1]) for i in range(0, len(nodes), 2)]
    return sha256_b64(nodes[0])


class StaticUniverseResolver:
    """Deterministic test/dev resolver returning one fixed evidence universe."""

    def __init__(self, universe: Sequence[dict]):
        self._universe = deepcopy(list(universe))

    def resolve(self, discovery: dict) -> list[dict]:
        return deepcopy(self._universe)


def resolve_and_verify(p2r: dict, resolver: UniverseResolver) -> list[dict]:
    try:
        world = p2r["world"]
        root = world["manifest_root"]
    except (KeyError, TypeError):
        raise VerifyError("WORLD_MANIFEST_MISSING")
    if not isinstance(root, dict) or root.get("alg") != "sha-256" or not isinstance(root.get("value"), str):
        raise VerifyError("WORLD_MANIFEST_INVALID")
    try:
        universe = list(resolver.resolve(world.get("discovery", {})))
    except Exception as exc:
        raise VerifyError("UNIVERSE_RESOLUTION_FAILED", str(exc)) from exc
    actual = manifest_root(universe)
    if root["value"] != actual:
        raise VerifyError("WORLD_MANIFEST_MISMATCH")
    return universe


def verify_universe(expected, actual) -> bool:
    """Compatibility helper: compare a root (value or object) to evidence."""
    expected_value = expected.get("value") if isinstance(expected, dict) else expected
    actual_value = actual if isinstance(actual, str) else manifest_root(actual)
    if expected_value != actual_value:
        raise VerifyError("WORLD_MANIFEST_MISMATCH")
    return True
