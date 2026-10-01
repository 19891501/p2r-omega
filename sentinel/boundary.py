"""Observe the core from files and git. This module does not import p2r."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
from pathlib import Path

FORBIDDEN_MODULES = (
    "skills",
    "rules",
    "agents",
    "hooks",
    "docs",
    "assurance",
    "sentinel",
)
AUTHORIZED_EFFECT = "src/p2r/executor.py"


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def core_files(repo: Path) -> dict[str, str]:
    base = repo / "src" / "p2r"
    if not base.is_dir():
        return {}
    files = {}
    for path in sorted(p for p in base.rglob("*.py") if p.is_file() and "__pycache__" not in p.parts):
        files["src/p2r/" + path.relative_to(base).as_posix()] = file_digest(path)
    return files


def tree_digest(files: dict[str, str]) -> str:
    body = "\n".join(f"{rel}\0{files[rel]}" for rel in sorted(files)).encode()
    return hashlib.sha256(body).hexdigest()


def frozen_digest(repo: Path) -> str | None:
    path = repo / "tests" / "integration" / "core_manifest.json"
    if not path.is_file():
        return None
    value = json.loads(path.read_text()).get("src_p2r_tree")
    return value if isinstance(value, str) else None


def forbidden_imports(repo: Path, names: tuple[str, ...] = FORBIDDEN_MODULES) -> list[str]:
    hits = []
    base = repo / "src" / "p2r"
    if not base.is_dir():
        return hits
    for path in sorted(p for p in base.rglob("*.py") if "__pycache__" not in p.parts):
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError as exc:
            hits.append(f"{path.relative_to(repo)}:SYNTAX:{exc.lineno}")
            continue
        modules: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
            elif isinstance(node, ast.Call):
                func = node.func
                name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
                if name in {"__import__", "import_module"} and node.args and isinstance(node.args[0], ast.Constant):
                    if isinstance(node.args[0].value, str):
                        modules.append(node.args[0].value)
        relative = path.relative_to(repo).as_posix()
        for module in modules:
            for forbidden in names:
                if module == forbidden or module.startswith(forbidden + ".") or module.startswith(forbidden + "/"):
                    hits.append(f"{relative}:{module}")
    return hits


def effect_paths(repo: Path) -> list[str]:
    base = repo / "src" / "p2r"
    if not base.is_dir():
        return []
    found = []
    for path in sorted(p for p in base.rglob("*.py") if "__pycache__" not in p.parts):
        if "def execute(" in path.read_text():
            found.append(path.relative_to(repo).as_posix())
    return found


def installed_hooks(repo: Path) -> list[str]:
    found = []
    git_hooks = repo / ".git" / "hooks"
    if git_hooks.is_dir():
        for path in sorted(git_hooks.iterdir()):
            if path.is_file() and not path.name.endswith(".sample"):
                found.append(path.relative_to(repo).as_posix())
    project = repo / "hooks"
    if project.is_dir():
        for path in sorted(p for p in project.rglob("*") if p.is_file()):
            if path.suffix in {".py", ".sh", ".js"} or os.access(path, os.X_OK):
                found.append(path.relative_to(repo).as_posix())
    return found


def head_commit(repo: Path) -> str | None:
    if not (repo / ".git").exists():
        return None
    try:
        text = subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return None
    return text or None
