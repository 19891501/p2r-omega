"""Bind an observation to one git commit and tree. Does not import p2r."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path

from sentinel.boundary import tree_digest


def _git(repo: Path, *args: str, text: bool = True):
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=text,
    )


def head_ids(repo: Path) -> tuple[str, str]:
    commit = _git(repo, "rev-parse", "HEAD").stdout.strip()
    tree = _git(repo, "rev-parse", f"{commit}^{{tree}}").stdout.strip()
    return commit, tree


def porcelain(repo: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "status", "--porcelain"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def core_from_tree(repo: Path, tree: str) -> dict[str, str]:
    listed = _git(repo, "ls-tree", "-r", "--name-only", tree, "src/p2r").stdout.splitlines()
    files = {}
    for rel in listed:
        if not rel.endswith(".py"):
            continue
        blob = subprocess.check_output(["git", "-C", str(repo), "show", f"{tree}:{rel}"])
        files[rel] = hashlib.sha256(blob).hexdigest()
    return files


def observer_digest() -> str:
    import sentinel

    root = Path(sentinel.__file__).resolve().parent
    files = {}
    for path in sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts):
        files[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return tree_digest(files)


class Snapshot:
    def __init__(self, bound: bool, reason: str | None, commit: str | None, tree: str | None, path: Path | None, repo: Path):
        self.bound = bound
        self.reason = reason
        self.commit = commit
        self.tree = tree
        self.path = path
        self.repo = repo


def acquire(repo: Path) -> Snapshot:
    if not (repo / ".git").exists():
        return Snapshot(False, "NOT_A_REPOSITORY", None, None, None, repo)
    try:
        commit, tree = head_ids(repo)
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return Snapshot(False, "HEAD_UNREADABLE", None, None, None, repo)
    try:
        dirty = porcelain(repo)
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return Snapshot(False, "HEAD_UNREADABLE", commit, tree, None, repo)
    if dirty.strip():
        return Snapshot(False, "WORKTREE_DIRTY", commit, tree, None, repo)
    path = Path(tempfile.mkdtemp(prefix="p2r-snap-"))
    try:
        subprocess.run(
            ["git", "-C", str(repo), "worktree", "add", "--detach", "--quiet", str(path), commit],
            check=True,
            capture_output=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        shutil.rmtree(path, ignore_errors=True)
        return Snapshot(False, "SNAPSHOT_FAILED", commit, tree, None, repo)
    return Snapshot(True, None, commit, tree, path, repo)


def release(snap: Snapshot) -> None:
    if snap.path is None:
        return
    subprocess.run(
        ["git", "-C", str(snap.repo), "worktree", "remove", "--force", str(snap.path)],
        capture_output=True,
    )
    if snap.path.exists():
        shutil.rmtree(snap.path, ignore_errors=True)
    subprocess.run(["git", "-C", str(snap.repo), "worktree", "prune"], capture_output=True)


def confirm(snap: Snapshot, digest: str) -> str | None:
    if not snap.bound or snap.commit is None or snap.tree is None or snap.path is None:
        return snap.reason or "SNAPSHOT_FAILED"
    try:
        tree_now = _git(snap.repo, "rev-parse", f"{snap.commit}^{{tree}}").stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return "TREE_UNREADABLE"
    if tree_now != snap.tree:
        return "TREE_CHANGED"
    try:
        files = core_from_tree(snap.repo, snap.tree)
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return "TREE_UNREADABLE"
    if tree_digest(files) != digest:
        return "TREE_DIGEST_CHANGED"
    from sentinel.boundary import core_files

    if tree_digest(core_files(snap.path)) != digest:
        return "SNAPSHOT_MUTATED"
    return None


def covers_head(snap: Snapshot) -> bool:
    if snap.commit is None:
        return False
    try:
        head_now = _git(snap.repo, "rev-parse", "HEAD").stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return False
    return head_now == snap.commit
