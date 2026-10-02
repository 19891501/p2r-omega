"""One observation, one certificate. This does not decide, authorize, or execute.

A repository without src/p2r is an external subject. It is not compared to the
frozen P2R core, and a passing replay is not a P2R certification.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from sentinel.boundary import tree_digest
from sentinel.snapshot import acquire, head_ids, release


def _git_bytes(repo: Path, spec: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), "show", spec])


def tracked_files(repo: Path, tree: str) -> dict[str, str]:
    listed = subprocess.check_output(
        ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", tree],
        text=True,
    ).splitlines()
    files = {}
    for rel in listed:
        if rel:
            files[rel] = hashlib.sha256(_git_bytes(repo, f"{tree}:{rel}")).hexdigest()
    return files


def disk_files(root: Path, names: list[str]) -> dict[str, str]:
    files = {}
    for rel in names:
        path = root / rel
        if not path.is_file():
            return {}
        files[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return files


def origin_of(repo: Path) -> str:
    try:
        url = subprocess.check_output(
            ["git", "-C", str(repo), "remote", "get-url", "origin"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return "none"
    return url or "none"


def render_certificate(row: dict) -> str:
    lines = [
        "P2R-Ω CERTIFICATE",
        "",
        f"COMMIT: {row.get('commit') or 'UNKNOWN'}",
        f"TREE: {row.get('tree') or 'UNKNOWN'}",
        f"CORE DIGEST: {row.get('digest') or 'UNKNOWN'}",
        f"REPLAY: {row.get('replay') or 'UNKNOWN'}",
        f"IMPORT BOUNDARY: {row.get('boundary') or 'UNKNOWN'}",
        f"EFFECT PATH: {row.get('effects') or 'UNKNOWN'}",
        f"STATUS: {row.get('status') or 'UNKNOWN'}",
        f"SUBJECT: {row.get('subject') or 'UNKNOWN'}",
        f"BASELINE: {row.get('baseline') or 'UNKNOWN'}",
        f"ORIGIN: {row.get('origin') or 'none'}",
        "PAYMENT: NOT_COLLECTED",
    ]
    if row.get("reason"):
        lines.extend(["", f"REASON: {row['reason']}"])
    return "\n".join(lines) + "\n"


def _certificate_id(row: dict) -> str:
    body = {key: row[key] for key in sorted(row) if key not in {"id", "text"}}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _store(state_dir: Path, row: dict) -> dict:
    from sentinel.service import _write_json

    text = render_certificate(row)
    row = dict(row)
    row["text"] = text
    row["id"] = _certificate_id(row)
    state_dir.mkdir(parents=True, exist_ok=True)
    _write_json(state_dir / "certificates" / f"{row['id']}.json", row)
    (state_dir / "latest.txt").write_text(text)
    returned = dict(row)
    if row["status"] in {"CERTIFIED", "OBSERVED"}:
        returned["result"] = "PASS"
    elif row["status"] in {"QUARANTINED", "DRIFT", "REPLAY_FAILED"}:
        returned["result"] = "FAIL"
    else:
        returned["result"] = "UNKNOWN"
    return returned


def _p2r_row(cert: dict, origin: str) -> dict:
    violations = cert.get("import_violations") or []
    authorized = cert.get("authorized_paths") or []
    alternate = cert.get("alternate_paths") or []
    replay = (cert.get("replay") or {}).get("status") or "UNKNOWN"
    boundary = "PASS" if not violations else "FAIL"
    if alternate:
        effects = f"{len(authorized)}+{len(alternate)}"
    else:
        effects = str(len(authorized))
    passed = (
        cert.get("result") == "PASS"
        and boundary == "PASS"
        and authorized == ["src/p2r/executor.py"]
        and not alternate
        and replay == "PASS"
    )
    if passed:
        status = "CERTIFIED"
        baseline = "UNCHANGED"
    elif cert.get("result") == "UNKNOWN" or not cert.get("snapshot") or cert.get("snapshot") != "BOUND":
        status = "UNKNOWN"
        baseline = "UNKNOWN"
    elif cert.get("state") == "QUARANTINED" or cert.get("result") == "FAIL":
        status = "QUARANTINED"
        baseline = "DRIFT"
    else:
        status = cert.get("state") or "UNKNOWN"
        baseline = "UNKNOWN"
    return {
        "baseline": baseline,
        "boundary": boundary,
        "commit": cert.get("commit"),
        "digest": cert.get("observed_digest"),
        "effects": effects,
        "origin": origin,
        "reason": None if status == "CERTIFIED" or cert.get("snapshot") == "BOUND" else cert.get("snapshot"),
        "replay": replay,
        "status": status,
        "subject": "p2r",
        "tree": cert.get("tree"),
    }


def _external(repo: Path, state_dir: Path, replay) -> dict:
    from sentinel.service import _read_json, _write_json

    origin = origin_of(repo)
    snap = acquire(repo)
    try:
        if not snap.bound or snap.path is None or snap.tree is None:
            return _store(
                state_dir,
                {
                    "baseline": "UNKNOWN",
                    "boundary": "NOT_CHECKED",
                    "commit": snap.commit,
                    "digest": None,
                    "effects": "NOT_CHECKED",
                    "origin": origin,
                    "reason": snap.reason or "SNAPSHOT_FAILED",
                    "replay": "SKIPPED",
                    "status": "UNKNOWN",
                    "subject": "external",
                    "tree": snap.tree,
                },
            )
        files = tracked_files(repo, snap.tree)
        digest = tree_digest(files)
        reason = None
        if tree_digest(disk_files(snap.path, list(files))) != digest:
            reason = "SNAPSHOT_MUTATED"
        if replay is None:
            replay_status = "SKIPPED"
        else:
            replay_status = (replay(snap.path) or {}).get("status") or "UNKNOWN"
        if reason is None:
            try:
                tree_now = head_ids(repo)[1]
            except (subprocess.CalledProcessError, FileNotFoundError, OSError):
                tree_now = None
            if tree_now != snap.tree or tree_digest(disk_files(snap.path, list(files))) != digest:
                reason = "SNAPSHOT_MUTATED"
    finally:
        release(snap)
    prior = _read_json(state_dir / "subject.json")
    if reason is not None or replay_status != "PASS":
        status = "UNKNOWN" if (replay_status == "SKIPPED" or reason) else "REPLAY_FAILED"
        if reason == "SNAPSHOT_MUTATED":
            status = "UNKNOWN"
        baseline = "UNKNOWN"
    elif prior is None:
        _write_json(
            state_dir / "subject.json",
            {"commit": snap.commit, "digest": digest, "source": "observation", "tree": snap.tree},
        )
        status = "OBSERVED"
        baseline = "ESTABLISHED"
    elif prior.get("digest") == digest:
        status = "OBSERVED"
        baseline = "UNCHANGED"
    else:
        status = "DRIFT"
        baseline = "DRIFT"
    return _store(
        state_dir,
        {
            "baseline": baseline,
            "boundary": "NOT_CHECKED",
            "commit": snap.commit,
            "digest": digest,
            "effects": "NOT_CHECKED",
            "origin": origin,
            "reason": reason,
            "replay": replay_status,
            "status": status,
            "subject": "external",
            "tree": snap.tree,
        },
    )


def run_certify(repo: Path, state_dir: Path, replay) -> dict:
    repo = repo.resolve()
    state_dir = state_dir.resolve()
    if (repo / "src" / "p2r").is_dir():
        from sentinel.service import run_check

        cert = run_check(repo, state_dir, replay=replay, emit_if_unchanged=True)
        row = _store(state_dir, _p2r_row(cert, origin_of(repo)))
        row["core_result"] = cert.get("result")
        return row
    return _external(repo, state_dir, replay)
