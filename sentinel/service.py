"""Run the sentinel. The process does not import p2r.

Replay, when requested, is a separate pytest process.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from sentinel.boundary import (
    core_files,
    effect_paths,
    forbidden_imports,
    frozen_digest,
    head_commit,
    installed_hooks,
    tree_digest,
)
from sentinel.machine import result_of, settle, split_paths, static_ok


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def _read_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text())


def parse_pytest(text: str, code: int) -> dict:
    def last(pattern: str) -> int:
        found = re.findall(pattern, text)
        return int(found[-1]) if found else 0

    passed = last(r"(\d+) passed")
    failed = last(r"(\d+) failed")
    errors = last(r"(\d+) error")
    total = passed + failed + errors
    if code == 0 and failed == 0 and errors == 0 and passed > 0:
        status = "PASS"
    elif failed or errors or code not in (0, None):
        status = "FAIL"
    else:
        status = "UNKNOWN"
    return {"status": status, "passed": passed, "failed": failed, "errors": errors, "total": total, "detail": text.strip()[-500:]}


def pytest_replay(repo: Path, timeout: float = 180) -> dict:
    env = os.environ.copy()
    src = str((repo / "src").resolve())
    current = env.get("PYTHONPATH")
    env["PYTHONPATH"] = src if not current else src + os.pathsep + current
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--tb=no"],
            cwd=repo,
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"status": "FAIL", "passed": 0, "failed": None, "errors": None, "total": None, "detail": "timeout"}
    except FileNotFoundError as exc:
        return {"status": "UNKNOWN", "passed": None, "failed": None, "errors": None, "total": None, "detail": str(exc)}
    return parse_pytest((proc.stdout or "") + "\n" + (proc.stderr or ""), proc.returncode)


def _baseline(repo: Path, state_dir: Path) -> tuple[str | None, str]:
    local = _read_json(state_dir / "authorized.json")
    if local and isinstance(local.get("digest"), str):
        return local["digest"], "local"
    return frozen_digest(repo), "manifest"


def _render(cert: dict) -> str:
    replay = cert["replay"]
    if replay["status"] == "SKIPPED":
        replay_line = "SKIPPED"
    elif replay["status"] == "UNKNOWN" or not replay.get("total"):
        replay_line = "UNKNOWN"
    else:
        replay_line = f"{replay['passed']}/{replay['total']}"
    observed = cert["observed_digest"] or "UNKNOWN"
    authorized = cert["authorized_digest"] or "UNKNOWN"
    if not cert["baseline_known"]:
        core_status = "UNKNOWN"
    elif cert["digest_match"]:
        core_status = "UNCHANGED"
    else:
        core_status = "CHANGED"
    lines = [
        "P2R-Ω SENTINEL",
        "",
        f"id: {cert.get('id', 'UNKNOWN')}",
        "",
        f"commit: {cert['commit'] or 'UNKNOWN'}",
        "",
        "CORE:",
        f"{authorized} → {observed}",
        f"STATUS: {core_status}",
        "",
        "IMPORT BOUNDARY:",
        f"{len(cert['import_violations'])} violations",
        "",
        "EFFECT PATH:",
        f"{len(cert['authorized_paths'])} authorized " + ("path" if len(cert["authorized_paths"]) == 1 else "paths"),
        f"{len(cert['alternate_paths'])} alternate paths",
        "",
        "REPLAY:",
        replay_line,
        "",
        "RESULT:",
        cert["result"],
        "",
        "TRACE:",
        " → ".join(cert["trace"]),
        "",
        f"STATE: {cert['state']}",
    ]
    if cert["state"] == "QUARANTINED":
        lines.extend(["", "DRIFT DETECTED"])
        if not cert["digest_match"]:
            lines.append("Core identity changed")
        if cert["previous_certificate_invalidated"]:
            lines.append("Previous certificate invalidated")
        if cert["alternate_paths"]:
            lines.append("New effect path detected")
        if cert["import_violations"]:
            lines.append("Import boundary violated")
        if cert["hooks"]:
            lines.append("Active hook detected")
        if replay["status"] == "FAIL":
            lines.append("Replay failed")
        lines.append("STATUS = QUARANTINED")
    if cert.get("quarantine_lifted"):
        lines.extend(["", f"QUARANTINE LIFTED: {cert['lift_reason']}"])
    if cert["authorized_source"] == "local" and cert["frozen_digest"] and cert["authorized_digest"] != cert["frozen_digest"]:
        lines.extend(["", "FROZEN: DIVERGED"])
    elif cert["frozen_digest"] and cert["observed_digest"] == cert["frozen_digest"]:
        lines.extend(["", "FROZEN: MATCH"])
    return "\n".join(lines) + "\n"


def _certificate_id(payload: dict) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(body).hexdigest()


def run_check(
    repo: Path,
    state_dir: Path,
    *,
    replay=None,
    emit_if_unchanged: bool = True,
    accepting: bool = False,
) -> dict:
    repo = repo.resolve()
    state_dir = state_dir.resolve()
    state_dir.mkdir(parents=True, exist_ok=True)
    previous = _read_json(state_dir / "state.json") or {}
    files = core_files(repo)
    observed = tree_digest(files) if files else None
    authorized, source = _baseline(repo, state_dir)
    frozen = frozen_digest(repo)
    violations = forbidden_imports(repo)
    paths = effect_paths(repo)
    authorized_paths, alternate = split_paths(paths)
    hooks = installed_hooks(repo)
    boundary_ok = static_ok(violations, paths, hooks)
    if replay is None:
        replay_out = {"status": "SKIPPED", "passed": None, "failed": None, "errors": None, "total": None, "detail": "not run"}
    else:
        replay_out = replay()
    digest_match = authorized is not None and observed == authorized
    result = result_of(
        baseline_known=authorized is not None,
        digest_match=digest_match,
        boundary_ok=boundary_ok,
        replay_status=replay_out["status"],
    )
    state_name, trace = settle(previous.get("status"), result, authorized is not None)
    same_view = (
        previous.get("status") == "WATCHING"
        and state_name == "WATCHING"
        and previous.get("observed_digest") == observed
        and previous.get("observed_commit") == head_commit(repo)
        and previous.get("valid_certificate")
    )
    if same_view and not emit_if_unchanged:
        previous["last_seen"] = _now()
        _write_json(state_dir / "state.json", previous)
        latest = _read_json(state_dir / "certificates" / f"{previous['valid_certificate']}.json")
        return latest or previous

    lifted = previous.get("status") == "QUARANTINED" and state_name == "WATCHING"
    invalidated = state_name == "QUARANTINED" and previous.get("status") != "QUARANTINED" and bool(previous.get("valid_certificate"))
    lift_reason = None
    if lifted:
        lift_reason = "accepted" if accepting or previous.get("accepting") else "restored"
    commit = head_commit(repo)
    payload = {
        "alternate_paths": alternate,
        "authorized_digest": authorized,
        "authorized_paths": authorized_paths,
        "authorized_source": source,
        "baseline_known": authorized is not None,
        "commit": commit,
        "digest_match": digest_match,
        "frozen_digest": frozen,
        "hooks": hooks,
        "import_violations": violations,
        "issued_at": _now(),
        "lift_reason": lift_reason,
        "observed_digest": observed,
        "previous_certificate_invalidated": invalidated,
        "quarantine_lifted": lifted,
        "replay": {key: replay_out.get(key) for key in ("status", "passed", "failed", "errors", "total")},
        "result": result,
        "state": state_name,
        "trace": trace,
    }
    payload["replay"]["detail"] = replay_out.get("detail")
    stable = dict(payload)
    stable["replay"] = {key: payload["replay"][key] for key in ("status", "passed", "failed", "errors", "total")}
    cert_id = _certificate_id(stable)
    payload["id"] = cert_id
    text = _render(payload)
    payload["text"] = text
    _write_json(state_dir / "certificates" / f"{cert_id}.json", payload)
    (state_dir / "certificates" / f"{cert_id}.txt").write_text(text)
    (state_dir / "latest.txt").write_text(text)
    invalidated_ids = list(previous.get("invalidated_certificates") or [])
    valid_id = previous.get("valid_certificate")
    if invalidated and valid_id:
        invalidated_ids.append(valid_id)
        valid_id = None
        prior = _read_json(state_dir / "certificates" / f"{invalidated_ids[-1]}.json")
        if prior is not None:
            prior["valid"] = False
            prior["invalidated_at"] = payload["issued_at"]
            _write_json(state_dir / "certificates" / f"{prior['id']}.json", prior)
    if result == "PASS":
        valid_id = cert_id
    elif state_name == "QUARANTINED":
        valid_id = None
    state = {
        "accepting": False,
        "authorized_digest": authorized,
        "authorized_source": source,
        "frozen_digest": frozen,
        "invalidated_certificates": invalidated_ids,
        "last_seen": payload["issued_at"],
        "observed_commit": commit,
        "observed_digest": observed,
        "status": state_name,
        "valid_certificate": valid_id,
    }
    _write_json(state_dir / "state.json", state)
    return payload


def watch(repo: Path, state_dir: Path, *, interval: float, iterations: int | None, replay, sleep=time.sleep) -> dict:
    last = {}
    count = 0
    while iterations is None or count < iterations:
        last = run_check(repo, state_dir, replay=replay, emit_if_unchanged=False)
        count += 1
        if iterations is not None and count >= iterations:
            break
        sleep(interval)
    return last


def accept(repo: Path, state_dir: Path, *, replay) -> dict:
    if replay is None:
        raise RuntimeError("accept refuses to certify without a replay")
    first = run_check(repo, state_dir, replay=replay, emit_if_unchanged=True)
    if not static_ok(first["import_violations"], first["authorized_paths"] + first["alternate_paths"], first["hooks"]):
        raise RuntimeError("accept refuses a broken boundary")
    if first["replay"]["status"] != "PASS":
        raise RuntimeError("accept refuses without a passing replay")
    _write_json(
        state_dir / "authorized.json",
        {
            "accepted_at": _now(),
            "commit": first["commit"],
            "digest": first["observed_digest"],
            "frozen_digest": first["frozen_digest"],
        },
    )
    state = _read_json(state_dir / "state.json") or {}
    state["accepting"] = True
    _write_json(state_dir / "state.json", state)
    return run_check(repo, state_dir, replay=replay, emit_if_unchanged=True, accepting=True)


def _state_dir(repo: Path, explicit: str | None) -> Path:
    return Path(explicit) if explicit else repo / ".sentinel"


def _replay_from_args(args):
    if getattr(args, "no_replay", False):
        return None
    timeout = getattr(args, "timeout", 180)
    return lambda: pytest_replay(args.repo_path, timeout=timeout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="p2r-sentinel")
    parser.add_argument("--repo", default=".")
    parser.add_argument("--state-dir", default=None)
    sub = parser.add_subparsers(dest="cmd", required=True)

    check = sub.add_parser("check")
    check.add_argument("--no-replay", action="store_true")
    check.add_argument("--timeout", type=float, default=180)

    watch_cmd = sub.add_parser("watch")
    watch_cmd.add_argument("--interval", type=float, default=2)
    watch_cmd.add_argument("--iterations", type=int, default=None)
    watch_cmd.add_argument("--no-replay", action="store_true")
    watch_cmd.add_argument("--detach", action="store_true")
    watch_cmd.add_argument("--timeout", type=float, default=180)

    sub.add_parser("status")

    accept_cmd = sub.add_parser("accept")
    accept_cmd.add_argument("--timeout", type=float, default=180)

    args = parser.parse_args(argv)
    args.repo_path = Path(args.repo).resolve()
    state_dir = _state_dir(args.repo_path, args.state_dir)
    try:
        if args.cmd == "status":
            text = (state_dir / "latest.txt").read_text() if (state_dir / "latest.txt").is_file() else "STATE: ABSENT\n"
            sys.stdout.write(text)
            return 0
        if args.cmd == "check":
            cert = run_check(args.repo_path, state_dir, replay=_replay_from_args(args))
        elif args.cmd == "watch":
            if args.detach:
                state_dir.mkdir(parents=True, exist_ok=True)
                pid = os.fork()
                if pid > 0:
                    (state_dir / "pid").write_text(str(pid) + "\n")
                    sys.stdout.write(f"{pid}\n")
                    return 0
                try:
                    os.setsid()
                except OSError:
                    pass
                try:
                    cert = watch(
                        args.repo_path,
                        state_dir,
                        interval=args.interval,
                        iterations=args.iterations,
                        replay=_replay_from_args(args),
                    )
                    os._exit(0 if cert.get("result") != "FAIL" else 1)
                except Exception:
                    os._exit(1)
            cert = watch(
                args.repo_path,
                state_dir,
                interval=args.interval,
                iterations=args.iterations,
                replay=_replay_from_args(args),
            )
        else:
            cert = accept(args.repo_path, state_dir, replay=_replay_from_args(args))
    except RuntimeError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 1
    sys.stdout.write(cert.get("text") or "")
    result = cert.get("result")
    if result == "PASS":
        return 0
    if result == "FAIL":
        return 1
    return 3
