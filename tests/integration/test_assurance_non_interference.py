"""Non-interference of the assurance layout with the frozen core.

The expected digest is tests/integration/core_manifest.json. That file was
built from git blobs of c3383fb and ac81c41, not from this module.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path

from p2r.registry import Registry

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = json.loads((Path(__file__).parent / "core_manifest.json").read_text())
ADD = ("skills", "rules", "agents", "hooks", "docs")
FORBIDDEN = (
    "skills",
    "rules",
    "agents",
    "hooks",
    "docs",
    "assurance",
)


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def current_core_files() -> dict[str, str]:
    files = {}
    base = ROOT / "src" / "p2r"
    for path in sorted(p for p in base.rglob("*") if p.is_file() and p.suffix == ".py"):
        files["src/p2r/" + path.relative_to(base).as_posix()] = _file_digest(path)
    return files


def frozen_core_digest() -> str:
    return MANIFEST["src_p2r_tree"]


def current_core_digest() -> str:
    files = current_core_files()
    body = "\n".join(f"{rel}\0{digest}" for rel, digest in files.items()).encode()
    return hashlib.sha256(body).hexdigest()


def forbidden_imports(rel_root: str, names: tuple[str, ...]) -> list[str]:
    hits = []
    for path in sorted((ROOT / rel_root).rglob("*.py")):
        tree = ast.parse(path.read_text())
        modules = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
            elif isinstance(node, ast.Call):
                func = node.func
                name = None
                if isinstance(func, ast.Name):
                    name = func.id
                elif isinstance(func, ast.Attribute):
                    name = func.attr
                if name in {"__import__", "import_module"} and node.args and isinstance(node.args[0], ast.Constant):
                    if isinstance(node.args[0].value, str):
                        modules.append(node.args[0].value)
        for module in modules:
            for forbidden in names:
                if module == forbidden or module.startswith(forbidden + ".") or module.startswith(forbidden + "/"):
                    hits.append(f"{path.relative_to(ROOT)}:{module}")
    return hits


def discover_installed_hooks() -> list[str]:
    found = []
    git_hooks = ROOT / ".git" / "hooks"
    if git_hooks.is_dir():
        for path in sorted(git_hooks.iterdir()):
            if path.is_file() and not path.name.endswith(".sample"):
                found.append(str(path.relative_to(ROOT)))
    project = ROOT / "hooks"
    for path in sorted(p for p in project.rglob("*") if p.is_file()):
        if path.suffix in {".py", ".sh", ".js"} or os.access(path, os.X_OK):
            found.append(str(path.relative_to(ROOT)))
    return found


def replay(path: Path):
    registry = Registry(path, reservation_timeout=2)
    first = registry.reserve("k", "e", "deny", 0)
    registry.mark_executed("k", {"n": 1}, 1)
    retry = registry.reserve("k", "e", "deny", 2)
    other = registry.reserve("k2", "e", "deny", 3)
    row = registry.get("k")
    return (first.kind, retry.kind, retry.receipt_json, other.kind, row["status"], row["effect_identity"])


def test_core_tree_unchanged():
    assert current_core_digest() == frozen_core_digest()
    assert current_core_files() == MANIFEST["src_p2r_files"]


def test_tests_present_at_add_are_unchanged():
    current = {}
    for rel, _digest in MANIFEST["tests_files_at_add"].items():
        path = ROOT / rel
        assert path.is_file(), rel
        current[rel] = _file_digest(path)
    assert current == MANIFEST["tests_files_at_add"]


def test_no_assurance_import_from_core():
    assert forbidden_imports("src/p2r", FORBIDDEN) == []


def test_no_executable_hooks():
    assert discover_installed_hooks() == []


def test_no_alternative_effect_path():
    python_files = [path for name in ADD for path in (ROOT / name).rglob("*.py")]
    assert python_files == []
    definitions = []
    for path in sorted((ROOT / "src" / "p2r").rglob("*.py")):
        if "def execute(" in path.read_text():
            definitions.append(path.relative_to(ROOT).as_posix())
    assert definitions == ["src/p2r/executor.py"]


def test_replay_is_deterministic(tmp_path):
    first = replay(tmp_path / "a.db")
    second = replay(tmp_path / "b.db")
    assert first == second
    assert first == ("NEW", "RETRY", '{"n":1}', "EFFECT_ALREADY_EXECUTED", "EXECUTED", "e")
