"""The sentinel watches the core from outside it."""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinel.boundary import core_files, frozen_digest, tree_digest
from sentinel.pin import FROZEN_CORE_DIGEST
from sentinel.service import accept, main, parse_pytest, run_check, watch
from sentinel.snapshot import core_from_tree, head_ids

EXECUTOR = 'def execute(p2r, ctx, action, action_semantics="idempotent"):\n    return None\n'


def _passed(count=4):
    return {"status": "PASS", "passed": count, "failed": 0, "errors": 0, "total": count, "detail": ""}


def _git(repo: Path, *args: str) -> None:
    subprocess.check_call(
        ["git", "-C", str(repo), "-c", "user.email=sentinel@example.com", "-c", "user.name=sentinel", *args],
        stdout=subprocess.DEVNULL,
    )


def _commit(repo: Path, message: str = "fixture") -> None:
    if not (repo / ".git").exists():
        _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    dirty = subprocess.run(
        ["git", "-C", str(repo), "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    if dirty.strip():
        _git(repo, "commit", "-q", "-m", message)


def _bind(repo: Path, state: Path) -> None:
    state.mkdir(parents=True, exist_ok=True)
    if (state / "frozen.json").exists():
        return
    _commit(repo)
    _commit_id, tree = head_ids(repo)
    digest = tree_digest(core_from_tree(repo, tree))
    (state / "frozen.json").write_text(json.dumps({"digest": digest, "source": "test"}) + "\n")


def observe(repo: Path, state: Path, **kwargs):
    _bind(repo, state)
    return run_check(repo, state, **kwargs)


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
    _commit(repo)
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
    _commit_id, tree = head_ids(ROOT)
    files = core_from_tree(ROOT, tree)
    assert tree_digest(files) == FROZEN_CORE_DIGEST
    assert tree_digest(files) == frozen_digest(ROOT)
    assert files["src/p2r/executor.py"]


def test_real_boundary_without_replay_is_not_a_pass(tmp_path):
    cert = run_check(ROOT, tmp_path / "state", replay=None)
    assert cert["result"] == "UNKNOWN"
    assert cert["result"] != "PASS"
    if cert["snapshot"] == "WORKTREE_DIRTY":
        assert cert["state"] == "OBSERVED"
        assert "CORE_DIGEST: UNKNOWN" in cert["text"]
        return
    assert cert["digest_match"] is True
    assert cert["import_violations"] == []
    assert cert["authorized_paths"] == ["src/p2r/executor.py"]
    assert cert["alternate_paths"] == []
    assert cert["hooks"] == []
    assert cert["state"] == "VERIFIED"
    assert cert["tree"]
    assert "OBSERVED_COMMIT:" in cert["text"]
    assert "FROZEN: MATCH" in cert["text"]
    assert "STATUS: UNCHANGED" in cert["text"]


def test_replay_pass_ends_watching(tmp_path):
    repo = _repo(tmp_path)
    cert = observe(repo, tmp_path / "state", replay=lambda: _passed())
    assert cert["result"] == "PASS"
    assert cert["state"] == "WATCHING"
    assert cert["trace"] == ["OBSERVED", "VERIFIED", "CERTIFIED", "WATCHING"]
    assert "4/4" in cert["text"]
    assert cert["snapshot"] == "BOUND"
    assert cert["commit"]
    assert cert["tree"]
    assert f"OBSERVED_COMMIT: {cert['commit']}" in cert["text"]
    assert f"TREE: {cert['tree']}" in cert["text"]
    assert f"CORE_DIGEST: {cert['observed_digest']}" in cert["text"]
    state = json.loads((tmp_path / "state" / "state.json").read_text())
    assert state["valid_certificate"] == cert["id"]
    assert state["status"] == "WATCHING"


def test_identity_drift_quarantines_and_invalidates(tmp_path):
    repo = _repo(tmp_path)
    state = tmp_path / "state"
    first = observe(repo, state, replay=lambda: _passed())
    issued = (state / "certificates" / f"{first['id']}.json").read_bytes()
    path = repo / "src" / "p2r" / "executor.py"
    path.write_text(EXECUTOR + "\n")
    _commit(repo, "drift")
    second = observe(repo, state, replay=lambda: _passed())
    assert second["result"] == "FAIL"
    assert second["state"] == "QUARANTINED"
    assert second["digest_match"] is False
    assert "DRIFT DETECTED" in second["text"]
    assert "Core identity changed" in second["text"]
    assert "Previous certificate invalidated" in second["text"]
    assert "STATUS = QUARANTINED" in second["text"]
    assert "4/4" in second["text"]
    stored = json.loads(issued)
    assert stored["valid"] is True
    current = json.loads((state / "state.json").read_text())
    assert current["valid_certificate"] is None
    assert first["id"] in current["invalidated_certificates"]
    assert second["previous_certificate_invalidated"] is True
    assert (state / "certificates" / f"{first['id']}.json").read_bytes() == issued


def test_skipped_replay_does_not_lift_quarantine(tmp_path):
    repo = _repo(tmp_path)
    state = tmp_path / "state"
    path = repo / "src" / "p2r" / "executor.py"
    original = path.read_text()
    observe(repo, state, replay=lambda: _passed())
    path.write_text(original + "\n")
    _commit(repo, "drift")
    observe(repo, state, replay=lambda: _passed())
    path.write_text(original)
    _commit(repo, "restore")
    quiet = observe(repo, state, replay=None)
    assert quiet["digest_match"] is True
    assert quiet["state"] == "QUARANTINED"
    assert quiet["result"] == "UNKNOWN"


def test_restored_bytes_lift_quarantine_only_with_replay(tmp_path):
    repo = _repo(tmp_path)
    state = tmp_path / "state"
    path = repo / "src" / "p2r" / "executor.py"
    original = path.read_text()
    observe(repo, state, replay=lambda: _passed())
    path.write_text(original + "\n")
    _commit(repo, "drift")
    observe(repo, state, replay=lambda: _passed())
    path.write_text(original)
    _commit(repo, "restore")
    restored = observe(repo, state, replay=lambda: _passed())
    assert restored["result"] == "PASS"
    assert restored["state"] == "WATCHING"
    assert restored["quarantine_lifted"] is True
    assert restored["lift_reason"] == "restored"
    assert "FROZEN: MATCH" in restored["text"]


def test_second_execute_is_an_alternate_path(tmp_path):
    repo = _repo(tmp_path)
    (repo / "src" / "p2r" / "other.py").write_text("def execute(x):\n    return x\n")
    _seal(repo)
    cert = observe(repo, tmp_path / "state", replay=lambda: _passed())
    assert cert["alternate_paths"] == ["src/p2r/other.py"]
    assert cert["result"] == "FAIL"
    assert "New effect path detected" in cert["text"]


def test_import_violation(tmp_path):
    repo = _repo(tmp_path)
    (repo / "src" / "p2r" / "bridge.py").write_text("import sentinel\n")
    _seal(repo)
    cert = observe(repo, tmp_path / "state", replay=lambda: _passed())
    assert cert["import_violations"] == ["src/p2r/bridge.py:sentinel"]
    assert cert["state"] == "QUARANTINED"
    assert "Import boundary violated" in cert["text"]


def test_active_hook(tmp_path):
    repo = _repo(tmp_path)
    hook = repo / "hooks" / "pre-commit.sh"
    hook.write_text("#!/bin/sh\n")
    cert = observe(repo, tmp_path / "state", replay=lambda: _passed())
    assert cert["hooks"] == ["hooks/pre-commit.sh"]
    assert "Active hook detected" in cert["text"]


def test_replay_failure_quarantines_matching_digest(tmp_path):
    repo = _repo(tmp_path)

    def replay():
        return {"status": "FAIL", "passed": 3, "failed": 1, "errors": 0, "total": 4, "detail": "1 failed, 3 passed"}

    cert = observe(repo, tmp_path / "state", replay=replay)
    assert cert["digest_match"] is True
    assert cert["result"] == "FAIL"
    assert cert["state"] == "QUARANTINED"
    assert "Replay failed" in cert["text"]
    assert "3/4" in cert["text"]


def test_new_digest_stays_quarantined_until_accept(tmp_path):
    repo = _repo(tmp_path)
    state = tmp_path / "state"
    manifest = (repo / "tests" / "integration" / "core_manifest.json").read_bytes()
    frozen_before = None
    core = (repo / "src" / "p2r" / "executor.py").read_bytes()
    observe(repo, state, replay=lambda: _passed())
    frozen_before = (state / "frozen.json").read_bytes()
    (repo / "src" / "p2r" / "executor.py").write_text(EXECUTOR + "# accepted elsewhere\n")
    _commit(repo, "accept-me")
    drifted = observe(repo, state, replay=lambda: _passed())
    assert drifted["state"] == "QUARANTINED"
    accepted = accept(repo, state, replay=lambda: _passed())
    assert accepted["result"] == "PASS"
    assert accepted["state"] == "WATCHING"
    assert accepted["lift_reason"] == "accepted"
    assert accepted["authorized_source"] == "local"
    assert "FROZEN: DIVERGED" in accepted["text"]
    assert (repo / "tests" / "integration" / "core_manifest.json").read_bytes() == manifest
    assert (state / "frozen.json").read_bytes() == frozen_before
    assert (repo / "src" / "p2r" / "executor.py").read_bytes() != core


def test_accept_refuses_a_broken_boundary(tmp_path):
    repo = _repo(tmp_path)
    state = tmp_path / "state"
    (repo / "src" / "p2r" / "bridge.py").write_text("from sentinel import service\n")
    _seal(repo)
    _commit(repo, "bad-import")
    _bind(repo, state)
    try:
        accept(repo, state, replay=lambda: _passed())
    except RuntimeError as exc:
        assert "broken boundary" in str(exc)
    else:
        raise AssertionError("accept certified a broken boundary")


def test_manifest_does_not_move_the_pin(tmp_path):
    repo = _repo(tmp_path)
    state = tmp_path / "state"
    observe(repo, state, replay=lambda: _passed())
    (repo / "src" / "p2r" / "executor.py").write_text(EXECUTOR + "# moved\n")
    _seal(repo)
    _commit(repo, "manifest-follows-core")
    cert = observe(repo, state, replay=lambda: _passed())
    assert cert["manifest_agreement"] == "YES"
    assert cert["digest_match"] is False
    assert cert["result"] == "FAIL"
    assert cert["state"] == "QUARANTINED"
    assert "FROZEN: DIVERGED" in cert["text"]
    assert "MANIFEST_AGREES: YES" in cert["text"]


def test_watch_emits_one_certificate_while_stable(tmp_path):
    repo = _repo(tmp_path)
    state = tmp_path / "state"
    _bind(repo, state)
    watch(repo, state, interval=0, iterations=2, replay=lambda: _passed(), sleep=lambda _seconds: None)
    certificates = list((state / "certificates").glob("*.json"))
    assert len(certificates) == 1
    assert json.loads((state / "state.json").read_text())["status"] == "WATCHING"


def test_watch_sees_a_later_drift(tmp_path):
    repo = _repo(tmp_path)
    state = tmp_path / "state"
    mutated = {"done": False}

    _bind(repo, state)

    def sleep(_seconds):
        if not mutated["done"]:
            (repo / "src" / "p2r" / "executor.py").write_text(EXECUTOR + "\n")
            _commit(repo, "drift")
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
    _bind(repo, state)
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


def test_dirty_worktree_is_not_a_certificate(tmp_path):
    repo = _repo(tmp_path)
    state = tmp_path / "state"
    _bind(repo, state)
    (repo / "src" / "p2r" / "executor.py").write_text(EXECUTOR + "\n")
    cert = observe(repo, state, replay=lambda: _passed())
    assert cert["result"] == "UNKNOWN"
    assert cert["snapshot"] == "WORKTREE_DIRTY"
    assert cert["state"] == "OBSERVED"
    assert "CORE_DIGEST: UNKNOWN" in cert["text"]


def test_live_edit_during_replay_does_not_enter_the_certificate(tmp_path):
    repo = _repo(tmp_path)
    state = tmp_path / "state"
    seen = {}

    def replay(snapshot):
        seen["snapshot"] = snapshot
        assert snapshot != repo
        assert (snapshot / "src" / "p2r" / "executor.py").read_text() == EXECUTOR
        (repo / "src" / "p2r" / "executor.py").write_text(EXECUTOR + "# live\n")
        return _passed()

    cert = observe(repo, state, replay=replay)
    assert cert["result"] == "PASS"
    assert cert["snapshot"] == "BOUND"
    assert seen["snapshot"] != repo
    assert cert["observed_digest"] != tree_digest(core_files(repo))


def test_snapshot_mutation_is_not_a_pass(tmp_path):
    repo = _repo(tmp_path)
    state = tmp_path / "state"

    def replay(snapshot):
        (snapshot / "src" / "p2r" / "executor.py").write_text(EXECUTOR + "# mutated\n")
        return _passed()

    cert = observe(repo, state, replay=replay)
    assert cert["result"] == "FAIL"
    assert cert["state"] == "QUARANTINED"
    assert cert["snapshot_error"] == "SNAPSHOT_MUTATED"
    assert "Snapshot changed during replay" in cert["text"]


def test_observer_change_does_not_carry_the_previous_proof(tmp_path):
    repo = _repo(tmp_path)
    state = tmp_path / "state"
    first = observe(repo, state, replay=lambda: _passed(), observer="observer-a")
    issued = (state / "certificates" / f"{first['id']}.json").read_bytes()
    second = observe(repo, state, replay=lambda: _passed(), observer="observer-b")
    assert second["result"] == "PASS"
    assert second["state"] == "WATCHING"
    assert second["prior_proof"] == "NOT_CARRIED"
    assert "PRIOR_PROOF: NOT_CARRIED" in second["text"]
    assert (state / "certificates" / f"{first['id']}.json").read_bytes() == issued


def test_replay_is_not_due_while_the_certificate_covers():
    from sentinel.daemon import certificate_covers, replay_due

    covered = {
        "status": "WATCHING",
        "valid_certificate": "abc",
        "observed_commit": "c",
        "observed_tree": "t",
    }
    assert certificate_covers(covered, "c", "t", dirty=False) is True
    assert certificate_covers(covered, "c", "t", dirty=True) is False
    assert certificate_covers({**covered, "status": "QUARANTINED"}, "c", "t", dirty=False) is False
    assert replay_due({"last_replay_at": 10}, 15, None) is False
    assert replay_due({"last_replay_at": 10}, 15, 10) is False
    assert replay_due({"last_replay_at": 10}, 20, 10) is True


def test_daemon_replays_once_then_journals_unchanged(tmp_path):
    from sentinel.daemon import run_daemon
    from sentinel.journal import read

    repo = _repo(tmp_path)
    state = tmp_path / "state"
    _bind(repo, state)
    calls = {"n": 0}

    def replay(_snapshot):
        calls["n"] += 1
        return _passed()

    last = run_daemon(repo, state, interval=0, iterations=2, replay=replay, sleep=lambda _seconds: None)
    rows = read(state)
    assert calls["n"] == 1
    assert [row["event"] for row in rows] == ["CERTIFIED", "UNCHANGED"]
    assert rows[0]["certificate_id"] == rows[1]["certificate_id"]
    assert rows[0]["result"] == "PASS"
    assert last["event"] == "UNCHANGED"
    assert last["replay"] == "SKIPPED"
    assert json.loads((state / "state.json").read_text())["status"] == "WATCHING"
    assert list(repo.rglob("*.db")) == []


def test_daemon_dirty_view_does_not_drop_the_certificate(tmp_path):
    from sentinel.daemon import cycle
    from sentinel.journal import read

    repo = _repo(tmp_path)
    state = tmp_path / "state"
    _bind(repo, state)
    calls = {"n": 0}
    path = repo / "src" / "p2r" / "executor.py"
    original = path.read_text()

    def replay(_snapshot):
        calls["n"] += 1
        return _passed()

    first = cycle(repo, state, replay=replay, replay_every=None, now_epoch=1)
    path.write_text(original + "\n")
    dirty = cycle(repo, state, replay=replay, replay_every=None, now_epoch=2)
    path.write_text(original)
    resumed = cycle(repo, state, replay=replay, replay_every=None, now_epoch=3)
    assert first["event"] == "CERTIFIED"
    assert dirty["event"] == "WORKTREE_DIRTY"
    assert dirty["result"] == "UNKNOWN"
    assert resumed["event"] == "UNCHANGED"
    assert resumed["certificate_id"] == first["certificate_id"]
    assert calls["n"] == 1
    rows = read(state)
    assert rows[0]["event"] == "CERTIFIED"
    assert [row["event"] for row in rows] == ["CERTIFIED", "WORKTREE_DIRTY", "UNCHANGED"]


def test_daemon_drift_quarantines_without_writing_the_core(tmp_path):
    from sentinel.daemon import cycle

    repo = _repo(tmp_path)
    state = tmp_path / "state"
    _bind(repo, state)
    path = repo / "src" / "p2r" / "executor.py"
    original = path.read_bytes()

    def replay(_snapshot):
        return _passed()

    cycle(repo, state, replay=replay, replay_every=None, now_epoch=1)
    path.write_bytes(original + b"\n")
    _commit(repo, "drift")
    drifted_bytes = path.read_bytes()
    drifted = cycle(repo, state, replay=replay, replay_every=None, now_epoch=2)
    assert path.read_bytes() == drifted_bytes
    assert drifted["event"] == "DRIFT"
    assert drifted["state"] == "QUARANTINED"
    assert drifted["result"] == "FAIL"
    assert list(repo.rglob("*.db")) == []
    stored = json.loads((state / "state.json").read_text())
    assert stored["valid_certificate"] is None
    path.write_bytes(original)
    _commit(repo, "restore")
    restored = cycle(repo, state, replay=replay, replay_every=None, now_epoch=3)
    assert restored["event"] == "RESTORED"
    assert restored["state"] == "WATCHING"
    assert restored["result"] == "PASS"
    assert path.read_bytes() == original


def test_journal_is_a_hash_chain(tmp_path):
    from sentinel.journal import GENESIS, append, entry_hash, survey

    state = tmp_path / "state"
    first = append(state, {"event": "CERTIFIED", "pin": None})
    second = append(state, {"event": "UNCHANGED", "pin": None})
    assert first["seq"] == 0 and first["prev"] == GENESIS
    assert second["seq"] == 1 and second["prev"] == first["hash"]
    assert first["hash"] == entry_hash(first)
    assert survey(state) is None


def test_edited_or_truncated_journal_is_not_a_pass(tmp_path):
    from sentinel.daemon import cycle
    from sentinel.journal import path_for

    repo = _repo(tmp_path)
    state = tmp_path / "state"
    _bind(repo, state)
    calls = {"n": 0}

    def replay(_snapshot):
        calls["n"] += 1
        return _passed()

    cycle(repo, state, replay=replay, replay_every=None, now_epoch=1)
    journal = path_for(state)
    original = journal.read_bytes()
    lines = journal.read_text().splitlines()
    row = json.loads(lines[0])
    row["event"] = "UNCHANGED"
    lines[0] = json.dumps(row, sort_keys=True, separators=(",", ":"))
    journal.write_text("\n".join(lines) + "\n")
    broken = cycle(repo, state, replay=replay, replay_every=None, now_epoch=2)
    assert broken["event"] == "JOURNAL_BROKEN"
    assert broken["reason"] == "CHAIN_BROKEN"
    assert broken["result"] == "UNKNOWN"
    assert calls["n"] == 1
    assert journal.read_bytes() == ("\n".join(lines) + "\n").encode()
    journal.write_bytes(original)
    resumed = cycle(repo, state, replay=replay, replay_every=None, now_epoch=3)
    assert resumed["event"] == "CERTIFIED"
    assert calls["n"] == 2
    kept = journal.read_text().splitlines()[0]
    journal.write_text(kept + "\n")
    removed = cycle(repo, state, replay=replay, replay_every=None, now_epoch=4)
    assert removed["reason"] == "TIP_MISMATCH"
    assert calls["n"] == 2


def test_pin_or_certificate_edit_does_not_recertify(tmp_path):
    from sentinel.daemon import cycle

    repo = _repo(tmp_path)
    state = tmp_path / "state"
    _bind(repo, state)
    calls = {"n": 0}

    def replay(_snapshot):
        calls["n"] += 1
        return _passed()

    first = cycle(repo, state, replay=replay, replay_every=None, now_epoch=1)
    certificate = state / "certificates" / f"{first['certificate_id']}.json"
    certificate.write_text(certificate.read_text().replace("PASS", "FAIL", 1))
    edited = cycle(repo, state, replay=replay, replay_every=None, now_epoch=2)
    assert edited["event"] == "JOURNAL_BROKEN"
    assert edited["reason"] == "CERTIFICATE_MISMATCH"
    assert edited["result"] == "UNKNOWN"
    assert calls["n"] == 1

    other = tmp_path / "other"
    _bind(repo, other)
    cycle(repo, other, replay=replay, replay_every=None, now_epoch=3)
    pin = other / "frozen.json"
    pin.write_text(pin.read_text().replace("test", "swapped"))
    swapped = cycle(repo, other, replay=replay, replay_every=None, now_epoch=4)
    assert swapped["reason"] == "PIN_CHANGED"
    assert calls["n"] == 2


def test_pin_or_certificate_edit_does_not_recertify(tmp_path):
    from sentinel.daemon import cycle

    repo = _repo(tmp_path)
    state = tmp_path / "state"
    _bind(repo, state)
    calls = {"n": 0}

    def replay(_snapshot):
        calls["n"] += 1
        return _passed()

    first = cycle(repo, state, replay=replay, replay_every=None, now_epoch=1)
    pin = state / "frozen.json"
    pin.write_text(pin.read_text().replace("test", "swapped"))
    swapped = cycle(repo, state, replay=replay, replay_every=None, now_epoch=2)
    assert swapped["event"] == "JOURNAL_BROKEN"
    assert swapped["reason"] == "PIN_CHANGED"
    assert calls["n"] == 1
    pin.write_text(pin.read_text().replace("swapped", "test"))
    certificate = state / "certificates" / f"{first['certificate_id']}.json"
    certificate.write_text(certificate.read_text().replace("PASS", "FAIL", 1))
    edited = cycle(repo, state, replay=replay, replay_every=None, now_epoch=3)
    assert edited["reason"] == "CERTIFICATE_MISMATCH"
    assert edited["result"] == "UNKNOWN"
    assert calls["n"] == 1


def test_watching_cannot_hide_a_quarantine(tmp_path):
    from sentinel.daemon import cycle

    repo = _repo(tmp_path)
    state = tmp_path / "state"
    _bind(repo, state)
    path = repo / "src" / "p2r" / "executor.py"
    calls = {"n": 0}

    def replay(_snapshot):
        calls["n"] += 1
        return _passed()

    cycle(repo, state, replay=replay, replay_every=None, now_epoch=1)
    path.write_text(path.read_text() + "\n")
    _commit(repo, "drift")
    cycle(repo, state, replay=replay, replay_every=None, now_epoch=2)
    cached = json.loads((state / "state.json").read_text())
    cached["status"] = "WATCHING"
    cached["valid_certificate"] = "forged"
    (state / "state.json").write_text(json.dumps(cached))
    seen = calls["n"]
    hidden = cycle(repo, state, replay=replay, replay_every=None, now_epoch=3)
    assert calls["n"] == seen + 1
    assert hidden["event"] == "DRIFT"
    assert hidden["state"] == "QUARANTINED"
    assert hidden["result"] == "FAIL"
    assert json.loads((state / "state.json").read_text())["valid_certificate"] is None
