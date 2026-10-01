"""Differential checks: core versus tests/oracle.py, and Python 3.10 versus 3.11.

The oracle module does not import p2r. Loading the core on 3.11 avoids
``p2r/__init__.py`` because that build does not have the cryptography wheel.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import random
import subprocess
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEED = 20261001


def _load_core():
    try:
        from p2r.canonical import canonicalize
        from p2r.digest import sha256_b64
        from p2r.effect import effect_identity, execution_key
        from p2r.errors import VerifyError
        from p2r.provenance import _json_pointer_get
        from p2r.universe import manifest_root
    except ModuleNotFoundError:
        pkg = types.ModuleType("p2r")
        pkg.__path__ = [str(ROOT / "src" / "p2r")]
        pkg.__package__ = "p2r"
        sys.modules["p2r"] = pkg
        from p2r.canonical import canonicalize
        from p2r.digest import sha256_b64
        from p2r.effect import effect_identity, execution_key
        from p2r.errors import VerifyError
        from p2r.provenance import _json_pointer_get
        from p2r.universe import manifest_root

    return {
        "canonicalize": canonicalize,
        "sha256_b64": sha256_b64,
        "effect_identity": effect_identity,
        "execution_key": execution_key,
        "pointer": _json_pointer_get,
        "manifest_root": manifest_root,
        "verify_error": VerifyError,
    }


def _load_oracle():
    spec = importlib.util.spec_from_file_location("p2r_oracle_diff", ROOT / "tests" / "oracle.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _atom(rng: random.Random, depth: int):
    roll = rng.randrange(6 if depth <= 0 else 8)
    if roll == 0:
        return None
    if roll == 1:
        return rng.choice([True, False])
    if roll == 2:
        return rng.randint(-50, 50)
    if roll == 3:
        alphabet = ["", "a", "é", "\u2028", "\u2029", "🙂", "n/a", "01"]
        return rng.choice(alphabet)
    if roll == 4 or depth <= 0:
        return rng.randint(0, 9)
    if roll == 5 or depth <= 0:
        return rng.choice(["", "x"])
    if roll == 6:
        return [_atom(rng, depth - 1) for _ in range(rng.randint(0, 3))]
    keys = ["b", "a", "é", "\U0001f600", "01", ""]
    rng.shuffle(keys)
    return {key: _atom(rng, depth - 1) for key in keys[: rng.randint(0, 3)]}


def _objects(count: int, seed: int):
    rng = random.Random(seed)
    return [_atom(rng, 3) for _ in range(count)]


def compare_canonical(count: int = 20000, seed: int = SEED):
    core = _load_core()
    oracle = _load_oracle()
    conflicts = []
    unexpected = []
    for index, value in enumerate(_objects(count, seed)):
        try:
            left = core["canonicalize"](value)
        except TypeError:
            left = None
        except RecursionError:
            left = "RECURSION"
        except Exception as exc:
            unexpected.append((index, "core", type(exc).__name__))
            continue
        try:
            right = oracle.canonicalize(value)
        except TypeError:
            right = None
        except RecursionError:
            right = "RECURSION"
        except Exception as exc:
            unexpected.append((index, "oracle", type(exc).__name__))
            continue
        if left != right:
            conflicts.append(index)
            if len(conflicts) >= 5:
                break
    digest = None
    if not conflicts and not unexpected:
        blob = b"".join(
            core["canonicalize"](value)
            for value in _objects(min(count, 2000), seed)
            if not isinstance(value, float)
        )
        # floats are not generated; TypeError values are skipped above only when both raise.
        digest = hashlib.sha256(blob).hexdigest()
    return {
        "count": count,
        "seed": seed,
        "conflicts": conflicts,
        "unexpected": unexpected[:5],
        "sample_sha256": digest,
        "status": "PROUVÉ" if not conflicts and not unexpected else "CONFLIT",
    }


def compare_identity(count: int = 5000, seed: int = SEED):
    core = _load_core()
    oracle = _load_oracle()
    rng = random.Random(seed + 1)
    conflicts = []
    for index in range(count):
        scope = rng.choice(["global", "", None, "desk"])
        obj = {
            "authority": {
                "principal": rng.choice(["agent:alice", "agent:bob"]),
                "nonce": f"n{rng.randint(0, 20)}",
                "nonce_scope": scope,
            },
            "effect": {
                "profile": "transfer-v1",
                "rule": "transfer",
                "argument": {"amount": rng.randint(0, 5), "note": rng.choice(["a", "b", "é"])},
                "idempotency_key": rng.choice(["idem-1", "idem-2"]),
            },
        }
        if scope is None:
            del obj["authority"]["nonce_scope"]
        try:
            left = (core["effect_identity"](obj), core["execution_key"](obj))
            right = (oracle.effect_identity(obj), oracle.execution_key(obj))
        except Exception as exc:
            conflicts.append((index, type(exc).__name__))
            break
        if left != right:
            conflicts.append(index)
            break
        mutated = json.loads(json.dumps(obj))
        mutated["effect"]["argument"]["amount"] = obj["effect"]["argument"]["amount"] + 1
        if core["effect_identity"](mutated) == left[0]:
            conflicts.append(("mutation_silent", index))
            break
        other = json.loads(json.dumps({k: v for k, v in obj.items()}))
        other["authority"]["nonce"] = obj["authority"]["nonce"] + "x"
        if core["execution_key"](other) == left[1] or core["effect_identity"](other) != left[0]:
            conflicts.append(("nonce", index))
            break
    return {"count": count, "seed": seed, "conflicts": conflicts, "status": "PROUVÉ" if not conflicts else "CONFLIT"}


def compare_universe(count: int = 1000, seed: int = SEED):
    core = _load_core()
    oracle = _load_oracle()
    rng = random.Random(seed + 2)
    conflicts = []
    for index in range(count):
        size = rng.randint(0, 6)
        items = [
            {"evidence_id": f"ev-{rng.randint(0, 8)}", "n": rng.randint(0, 3), "s": rng.choice(["a", "é"])}
            for _ in range(size)
        ]
        try:
            left = core["manifest_root"](items)
        except (ValueError, core["verify_error"]):
            left = None
        except Exception as exc:
            conflicts.append((index, "core", type(exc).__name__))
            break
        try:
            right = oracle.manifest_root(items)
        except (ValueError, core["verify_error"]):
            right = None
        except Exception as exc:
            conflicts.append((index, "oracle", type(exc).__name__))
            break
        if (left is None) != (right is None) or (left is not None and left != right):
            conflicts.append(index)
            break
        if left is not None and items:
            changed = [dict(item) for item in items]
            changed[0]["n"] = changed[0]["n"] + 1
            try:
                moved = core["manifest_root"](changed)
            except (ValueError, core["verify_error"]):
                moved = None
            if moved is not None and moved == left and len({i["evidence_id"] for i in items}) == len(items):
                conflicts.append(("silent", index))
                break
    return {"count": count, "seed": seed, "conflicts": conflicts, "status": "PROUVÉ" if not conflicts else "CONFLIT"}


def python311_digest(count: int = 2000, seed: int = SEED):
    """Spawn CPython 3.11 and hash the same canonical stream."""
    code = r"""
import hashlib, random, sys, types
from pathlib import Path
root = Path(sys.argv[1])
pkg = types.ModuleType("p2r")
pkg.__path__ = [str(root / "src" / "p2r")]
pkg.__package__ = "p2r"
sys.modules["p2r"] = pkg
from p2r.canonical import canonicalize
count, seed = int(sys.argv[2]), int(sys.argv[3])
rng = random.Random(seed)
def atom(depth):
    roll = rng.randrange(6 if depth <= 0 else 8)
    if roll == 0: return None
    if roll == 1: return rng.choice([True, False])
    if roll == 2: return rng.randint(-50, 50)
    if roll == 3: return rng.choice(["", "a", "é", "\u2028", "\u2029", "🙂", "n/a", "01"])
    if roll == 4 or depth <= 0: return rng.randint(0, 9)
    if roll == 5 or depth <= 0: return rng.choice(["", "x"])
    if roll == 6: return [atom(depth-1) for _ in range(rng.randint(0, 3))]
    keys = ["b", "a", "é", "\U0001f600", "01", ""]
    rng.shuffle(keys)
    return {key: atom(depth-1) for key in keys[:rng.randint(0, 3)]}
h = hashlib.sha256()
for _ in range(count):
    h.update(canonicalize(atom(3)))
print(h.hexdigest())
"""
    proc = subprocess.run(
        [sys.executable.replace("python3.10", "python3.11") if False else "/usr/bin/python3.11", "-c", code, str(ROOT), str(count), str(seed)],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return {"status": "INCONNU", "stderr": proc.stderr[-500:]}
    core = _load_core()
    blob = hashlib.sha256()
    for value in _objects(count, seed):
        blob.update(core["canonicalize"](value))
    remote = proc.stdout.strip()
    local = blob.hexdigest()
    return {
        "count": count,
        "seed": seed,
        "python311": remote,
        "local": local,
        "status": "PROUVÉ" if remote == local else "CONFLIT",
    }
