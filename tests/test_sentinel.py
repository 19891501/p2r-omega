"""The sentinel watches the core from outside it."""

from __future__ import annotations

import ast
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinel.boundary import core_files, frozen_digest, tree_digest
from sentinel.service import accept, main, parse_pytest, run_check, watch

EXECUTOR = 'def execute(p2r, ctx, action, action_semantics="idempotent"):\n    return None\n'


def _passed(count=4):
    return {"status": "PASS", "passed": count, "failed": 0, "errors": 0, "total": count, "detail": ""}


def _seal(repo: Path) -> str:
    files = core_files(repo)
    digest = tree_digest(files)
    path = repo / "tests" / "integration" / "core_manifest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"src_p2r_tree": digest, "src_p2r_files": files}) + "\n")
    return digest


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "src" / "p2r").mkdir(parents=True)
    (repo / "src" / "p2r" / "executor.py").write_text(EXECUTOR)
    (repo / "src" / "p2r" / "__init__.py").write_text("")
    (repo / "hooks").mkdir()
    (repo / "hooks" / "README.md").write_text("no hook\n")
    _seal(repo)
    return repo


def test_package_does_not_import_core():
    for path in (ROOT / "sentinel").rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(not alias.name == "p2r" and not alias.name.startswith("p2r.") for alias in node.names)
            if isinstance(node, ast.ImportFrom):
                assert not (node.module == "p2r" or (node.module or "").startswith("p2r."))


def test_real_digest_matches_frozen_manifest():
    files = core_files(ROOT)
    assert tree_digest(files) == frozen_digest(ROOT)
    assert files["src/p2r/executor.py"]


def test_real_boundary_without_replay_is_not_a_pass(tmp_path):
    cert = run_check(ROOT, tmp_path / "state", replay=None)
    assert cert["digest_match"] is True
    assert cert["import_violations"] == []
    assert cert["authorized_paths"] == ["src/p2r/executor.py"]
    assert cert["alternate_paths"] == []
    assert cert["hooks"] == []
    assert cert["result"] == "UNKNOWN"
    assert cert["state"] == "VERIFIED"
    assert "FROZEN: MATCH" in cert["text"]
    assert "STATUS: UNCHANGED" in cert["text"]


def test_replay_pass_ends_watching(tmp_path):
    repo = _repo(tmp_path)
    cert = run_check(repo, tmp_path / "state", replay=lambda: _passed())
    assert cert["result"] == "PASS"
    assert cert["state"] == "WATCHING"
    assert cert["trace"] == ["OBSERVED", "VERIFIED", "CERTIFIED", "WATCHING"]
    assert "4/4" in cert["text"]
    state = json.loads((tmp_path / "state" / "state.json").read_text())
    assert state["valid_certificate"] == cert["id"]
    assert state["status"] == "WATCHING"


def test_identity_drift_quarantines_and_invalidates(tmp_path):
    repo = _repo(tmp_path)
    state = tmp_path / "state"
    first = run_check(repo, state, replay=lambda: _passed())
    path = repo / "src" / "p2r" / "executor.py"
    path.write_text(EXECUTOR + "\n")
    second = run_check(repo, state, replay=lambda: _passed())
    assert second["result"] == "FAIL"
    assert second["state"] == "QUARANTINED"
    assert second["digest_match"] is False
    assert "DRIFT DETECTED" in second["text"]
    assert "Core identity changed" in second["text"]
    assert "Previous certificate invalidated" in second["text"]
    assert "STATUS = QUARANTINED" in second["text"]
    assert "4/4" in second["text"]
    stored = json.loads((state / "certificates" / f"{first['id']}.json").read_text())
    assert stored["valid"] is False
    current = json.loads((state / "state.json").read_text())
    assert current["valid_certificate"] is None
    assert first["id"] in current["invalidated_certificates"]


def test_skipped_replay_does_not_lift_quarantine(tmp_path):
    repo = _repo(tmp_path)
    state = tmp_path / "state"
    path = repo / "src" / "p2r" / "executor.py"
    original = path.read_text()
    run_check(repo, state, replay=lambda: _passed())
    path.write_text(original + "\n")
    run_check(repo, state, replay=lambda: _passed())
    path.write_text(original)
    quiet = run_check(repo, state, replay=None)
    assert quiet["digest_match"] is True
    assert quiet["state"] == "QUARANTINED"
    assert quiet["result"] == "UNKNOWN"


def test_restored_bytes_lift_quarantine_only_with_replay(tmp_path):
    repo = _repo(tmp_path)
    state = tmp_path / "state"
    path = repo / "src" / "p2r" / "executor.py"
    original = path.read_text()
    run_check(repo, state, replay=lambda: _passed())
    path.write_text(original + "\n")
    run_check(repo, state, replay=lambda: _passed())
    path.write_text(original)
    restored = run_check(repo, state, replay=lambda: _passed())
    assert restored["result"] == "PASS"
    assert restored["state"] == "WATCHING"
    assert restored["quarantine_lifted"] is True
    assert restored["lift_reason"] == "restored"
    assert "FROZEN: MATCH" in restored["text"]


def test_second_execute_is_an_alternate_path(tmp_path):
    repo = _repo(tmp_path)
    (repo / "src" / "p2r" / "other.py").write_text("def execute(x):\n    return x\n")
    _seal(repo)
    cert = run_check(repo, tmp_path / "state", replay=lambda: _passed())
    assert cert["alternate_paths"] == ["src/p2r/other.py"]
    assert cert["result"] == "FAIL"
    assert "New effect path detected" in cert["text"]


def test_import_violation(tmp_path):
    repo = _repo(tmp_path)
    (repo / "src" / "p2r" / "bridge.py").write_text("import sentinel\n")
    _seal(repo)
    cert = run_check(repo, tmp_path / "state", replay=lambda: _passed())
    assert cert["import_violations"] == ["src/p2r/bridge.py:sentinel"]
    assert cert["state"] == "QUARANTINED"
    assert "Import boundary violated" in cert["text"]


def test_active_hook(tmp_path):
    repo = _repo(tmp_path)
    hook = repo / "hooks" / "pre-commit.sh"
    hook.write_text("#!/bin/sh\n")
    cert = run_check(repo, tmp_path / "state", replay=lambda: _passed())
    assert cert["hooks"] == ["hooks/pre-commit.sh"]
    assert "Active hook detected" in cert["text"]


def test_replay_failure_quarantines_matching_digest(tmp_path):
    repo = _repo(tmp_path)

    def replay():
        return {"status": "FAIL", "passed": 3, "failed": 1, "errors": 0, "total": 4, "detail": "1 failed, 3 passed"}

    cert = run_check(repo, tmp_path / "state", replay=replay)
    assert cert["digest_match"] is True
    assert cert["result"] == "FAIL"
    assert cert["state"] == "QUARANTINED"
    assert "Replay failed" in cert["text"]
    assert "3/4" in cert["text"]


def test_new_digest_stays_quarantined_until_accept(tmp_path):
    repo = _repo(tmp_path)
    state = tmp_path / "state"
    manifest = (repo / "tests" / "integration" / "core_manifest.json").read_bytes()
    core = (repo / "src" / "p2r" / "executor.py").read_bytes()
    (repo / "src" / "p2r" / "executor.py").write_text(EXECUTOR + "# accepted elsewhere\n")
    drifted = run_check(repo, state, replay=lambda: _passed())
    assert drifted["state"] == "QUARANTINED"
    accepted = accept(repo, state, replay=lambda: _passed())
    assert accepted["result"] == "PASS"
    assert accepted["state"] == "WATCHING"
    assert accepted["lift_reason"] == "accepted"
    assert accepted["authorized_source"] == "local"
    assert "FROZEN: DIVERGED" in accepted["text"]
    assert (repo / "tests" / "integration" / "core_manifest.json").read_bytes() == manifest
    assert (repo / "src" / "p2r" / "executor.py").read_bytes() != core


def test_accept_refuses_a_broken_boundary(tmp_path):
    repo = _repo(tmp_path)
    (repo / "src" / "p2r" / "bridge.py").write_text("from sentinel import service\n")
    _seal(repo)
    try:
        accept(repo, tmp_path / "state", replay=lambda: _passed())
    except RuntimeError as exc:
        assert "broken boundary" in str(exc)
    else:
        raise AssertionError("accept certified a broken boundary")


def test_missing_baseline_is_unknown(tmp_path):
    repo = _repo(tmp_path)
    (repo / "tests" / "integration" / "core_manifest.json").unlink()
    cert = run_check(repo, tmp_path / "state", replay=lambda: _passed())
    assert cert["result"] == "UNKNOWN"
    assert cert["state"] == "OBSERVED"
    assert cert["baseline_known"] is False


def test_watch_emits_one_certificate_while_stable(tmp_path):
    repo = _repo(tmp_path)
    state = tmp_path / "state"
    watch(repo, state, interval=0, iterations=2, replay=lambda: _passed(), sleep=lambda _seconds: None)
    certificates = list((state / "certificates").glob("*.json"))
    assert len(certificates) == 1
    assert json.loads((state / "state.json").read_text())["status"] == "WATCHING"


def test_watch_sees_a_later_drift(tmp_path):
    repo = _repo(tmp_path)
    state = tmp_path / "state"
    mutated = {"done": False}

    def sleep(_seconds):
        if not mutated["done"]:
            (repo / "src" / "p2r" / "executor.py").write_text(EXECUTOR + "\n")
            mutated["done"] = True

    last = watch(repo, state, interval=0, iterations=2, replay=lambda: _passed(), sleep=sleep)
    assert last["state"] == "QUARANTINED"
    assert mutated["done"] is True


def test_pytest_summary_parser():
    assert parse_pytest("133 passed in 41.47s\n", 0)["status"] == "PASS"
    assert parse_pytest("133 passed in 41.47s\n", 0)["passed"] == 133
    failed = parse_pytest("1 failed, 132 passed in 2s\n", 1)
    assert failed["status"] == "FAIL"
    assert (failed["passed"], failed["total"]) == (132, 133)
    assert parse_pytest("", 2)["status"] == "FAIL"


def test_detach_runs_one_iteration(tmp_path):
    repo = _repo(tmp_path)
    state = tmp_path / "state"
    code = main(
        [
            "--repo",
            str(repo),
            "--state-dir",
            str(state),
            "watch",
            "--detach",
            "--iterations",
            "1",
            "--no-replay",
        ]
    )
    assert code == 0
    pid = int((state / "pid").read_text().strip())
    os.waitpid(pid, 0)
    assert (state / "latest.txt").is_file()
    assert "RESULT:\nUNKNOWN" in (state / "latest.txt").read_text()
