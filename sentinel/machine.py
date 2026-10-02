"""Sentinel state. These names are not core registry statuses."""

from __future__ import annotations

from sentinel.boundary import AUTHORIZED_EFFECT


def split_paths(paths: list[str]) -> tuple[list[str], list[str]]:
    authorized = [path for path in paths if path == AUTHORIZED_EFFECT]
    alternate = [path for path in paths if path != AUTHORIZED_EFFECT]
    return authorized, alternate


def static_ok(import_violations: list[str], paths: list[str], hooks: list[str]) -> bool:
    authorized, alternate = split_paths(paths)
    return not import_violations and not hooks and not alternate and authorized == [AUTHORIZED_EFFECT]


def result_of(
    *,
    baseline_known: bool,
    digest_match: bool,
    boundary_ok: bool,
    replay_status: str,
    snapshot_bound: bool = True,
    snapshot_ok: bool = True,
) -> str:
    if not snapshot_bound:
        return "UNKNOWN"
    if not snapshot_ok:
        return "FAIL"
    if not baseline_known:
        return "UNKNOWN"
    if not digest_match or not boundary_ok:
        return "FAIL"
    if replay_status == "PASS":
        return "PASS"
    if replay_status == "FAIL":
        return "FAIL"
    return "UNKNOWN"


def settle(previous: str | None, result: str, baseline_known: bool, snapshot_bound: bool = True) -> tuple[str, list[str]]:
    if not snapshot_bound:
        return "OBSERVED", ["OBSERVED"]
    if not baseline_known:
        return "OBSERVED", ["OBSERVED"]
    if result == "PASS":
        return "WATCHING", ["OBSERVED", "VERIFIED", "CERTIFIED", "WATCHING"]
    if result == "FAIL":
        return "QUARANTINED", ["OBSERVED", "DRIFT", "QUARANTINED"]
    if previous == "QUARANTINED":
        return "QUARANTINED", ["OBSERVED", "VERIFIED"]
    return "VERIFIED", ["OBSERVED", "VERIFIED"]
