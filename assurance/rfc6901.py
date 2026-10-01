"""Explicit RFC 6901 corpus for the V1 JSON-string profile.

Classifications:

- conforme: required by RFC 6901 JSON String Representation and accepted or
  rejected the same way by the core;
- profil: the V1 profile states a narrower choice that RFC 6901 allows
  (array-index grammar, no URI fragment);
- non-conforme: a real disagreement with the RFC inside the chosen profile;
- ambiguë: the RFC does not decide.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

CORPUS = [
    ("empty document", "", {"a": 1}, "value", "conforme"),
    ("slash key", "/a", {"a": 1}, "value", "conforme"),
    ("nested", "/a/b", {"a": {"b": 2}}, "value", "conforme"),
    ("tilde escape", "/a~1b", {"a/b": 3}, "value", "conforme"),
    ("tilde0", "/m~0n", {"m~n": 4}, "value", "conforme"),
    ("left to right ~01", "/~01", {"~1": 5}, "value", "conforme"),
    ("array 0", "/0", ["z"], "value", "conforme"),
    ("array 1", "/1", ["z", "y"], "value", "conforme"),
    ("array leading zero", "/01", ["z", "y"], "invalid", "profil"),
    ("object key 01", "/01", {"01": 7}, "value", "conforme"),
    ("missing", "/nope", {"a": 1}, "missing", "conforme"),
    ("bad escape tilde", "/~", {"~": 1}, "invalid", "conforme"),
    ("bad escape ~2", "/~2", {"~2": 1}, "invalid", "conforme"),
    ("bad escape ~~1", "/~~1", {"~/": 1, "~~1": 1}, "invalid", "conforme"),
    ("index past end", "/2", ["z"], "missing", "conforme"),
    ("giant index", "/" + "9" * 80, ["z"], "missing", "conforme"),
    ("empty token", "/", {"": 8}, "value", "conforme"),
    ("uri fragment form", "#/a", {"a": 1}, "invalid", "profil"),
    ("no leading slash", "a", {"a": 1}, "invalid", "conforme"),
    ("minus not an index", "/-", ["z"], "invalid", "conforme"),
    ("plus not an index", "/+1", [0, 1], "invalid", "conforme"),
    ("unicode digit", "/１", ["z", "y"], "invalid", "profil"),
    ("scalar descent", "/a/b", {"a": 1}, "missing", "conforme"),
    ("~0~1 chain", "/~0~1", {"~/": 9}, "value", "conforme"),
]


def _load_core_pointer():
    import sys
    import types

    pkg = types.ModuleType("p2r")
    root = Path(__file__).resolve().parents[1] / "src" / "p2r"
    pkg.__path__ = [str(root)]
    pkg.__package__ = "p2r"
    sys.modules.setdefault("p2r", pkg)
    from p2r.provenance import _json_pointer_get
    from p2r.errors import VerifyError

    return _json_pointer_get, VerifyError


def _load_oracle_pointer():
    path = Path(__file__).resolve().parents[1] / "tests" / "oracle.py"
    spec = importlib.util.spec_from_file_location("p2r_oracle_rfc", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.pointer


def classify_one(pointer, document, expected, core_get, verify_error, oracle_get):
    def run(fn, invalid_type, missing_type):
        try:
            return "value", fn(document, pointer)
        except missing_type:
            return "missing", None
        except invalid_type:
            return "invalid", None
        except Exception as exc:
            return "unexpected:" + type(exc).__name__, exc

    core_kind, core_val = run(core_get, verify_error, verify_error)
    # core uses one error type for both; distinguish by code if present
    if core_kind != "value":
        try:
            core_get(document, pointer)
        except verify_error as exc:
            if exc.code == "PROVENANCE_PATH_NOT_FOUND":
                core_kind = "missing"
            elif exc.code == "PROVENANCE_PATH_INVALID":
                core_kind = "invalid"
            else:
                core_kind = "unexpected:" + exc.code
    oracle_kind, oracle_val = run(oracle_get, ValueError, LookupError)
    return core_kind, core_val, oracle_kind, oracle_val


def run_corpus():
    core_get, verify_error = _load_core_pointer()
    oracle_get = _load_oracle_pointer()
    rows = []
    conflicts = []
    for name, pointer, document, expected, rfc_class in CORPUS:
        core_kind, core_val, oracle_kind, oracle_val = classify_one(
            pointer, document, expected, core_get, verify_error, oracle_get
        )
        match = core_kind == expected == oracle_kind and (
            expected != "value" or core_val == oracle_val
        )
        status = "PROUVÉ" if match else "CONFLIT"
        if not match:
            conflicts.append(name)
        rows.append(
            {
                "name": name,
                "pointer": pointer,
                "expected": expected,
                "core": core_kind,
                "oracle": oracle_kind,
                "rfc": rfc_class,
                "status": status,
            }
        )
    non = [row for row in rows if row["rfc"] == "non-conforme"]
    return {
        "rows": rows,
        "conflicts": conflicts,
        "non_conforme": non,
        "status": "PROUVÉ" if not conflicts else "CONFLIT",
    }
