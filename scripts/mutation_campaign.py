"""Apply one-off source mutations and record whether the suite kills them.

This script never edits the working tree. Each mutant is a temp copy.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Deferred BEGIN still loses the second INSERT on the primary key, so the
# suite observes no second dispatch. It does not prove the error code under
# a forced interleaving. Kept visible; not treated as a new silent bypass.
KNOWN_SURVIVORS = {"defer reserve lock"}

MUTATIONS = [
    ("skip payload digest compare", "src/p2r/verify.py", 'if recomputed != actual:', 'if False and recomputed != actual:'),
    ("drop signature threshold", "src/p2r/authority.py", 'if good < threshold:', 'if False and good < threshold:'),
    ("count duplicate signers", "src/p2r/authority.py", 'if signer in seen or signer not in authorized_set:', 'if signer not in authorized_set:'),
    ("accept non-rfc array indexes", "src/p2r/provenance.py", 'if _ARRAY_INDEX.fullmatch(token) is None:', 'if False and _ARRAY_INDEX.fullmatch(token) is None:'),
    ("accept malformed tilde escapes", "src/p2r/provenance.py", 'if i + 1 >= len(raw) or raw[i + 1] not in "01":', 'if False and (i + 1 >= len(raw) or raw[i + 1] not in "01"):'),
    ("accept any decision status", "src/p2r/decision.py", 'if status != required:', 'if False and status != required:'),
    ("abandon instead of ambiguous", "src/p2r/executor.py", 'ctx.registry.mark_ambiguous(ekey, ctx.now)', 'ctx.registry.abandon_before_dispatch(ekey)'),
    ("ignore effect parameters", "src/p2r/effect.py", '"parameters": effect["argument"],', '"parameters": None,'),
    ("ignore nonce in execution key", "src/p2r/effect.py", '"nonce": authority["nonce"],', '"nonce": "fixed",'),
    ("ignore empty nonce scope", "src/p2r/effect.py", 'if scope is None or scope == "":', 'if scope is None and scope == "":'),
    ("accept unlisted observer", "src/p2r/receipt.py", 'if observer_id not in observer_scopes:', 'if False and observer_id not in observer_scopes:'),
    ("skip retry payload binding", "src/p2r/executor.py", 'if cached.get("payload_digest") != p2r["payload_digest"]["value"]:', 'if False and cached.get("payload_digest") != p2r["payload_digest"]["value"]:'),
    ("accept duplicate evidence ids", "src/p2r/universe.py", 'if len(ids) != len(set(ids)):', 'if False and len(ids) != len(set(ids)):'),
    ("accept unknown registry status", "src/p2r/registry.py", 'if prior["status"] not in VALID_STATUSES:', 'if False and prior["status"] not in VALID_STATUSES:'),
    ("seal ambiguous reservation", "src/p2r/registry.py", 'if row["status"] == "RESERVED_AMBIGUOUS":\n                raise RegistryError("REGISTRY_AMBIGUOUS_CANNOT_EXECUTE")', 'if False and row["status"] == "RESERVED_AMBIGUOUS":\n                raise RegistryError("REGISTRY_AMBIGUOUS_CANNOT_EXECUTE")'),
    ("defer reserve lock", "src/p2r/registry.py", 'db.execute("BEGIN IMMEDIATE")\n            self._recover_stale_locked(db, now, reservation_timeout)', 'db.execute("BEGIN")\n            self._recover_stale_locked(db, now, reservation_timeout)'),
    ("sort object keys as utf-8", "src/p2r/canonical.py", 'return value.encode("utf-16-be", errors="strict")', 'return value.encode("utf-8")'),
    ("leave u+2028 raw", "src/p2r/canonical.py", 'return raw.replace("\\u2028".encode("utf-8"), b"\\\\u2028").replace(\n        "\\u2029".encode("utf-8"), b"\\\\u2029"\n    )', 'return raw'),
]


def main() -> int:
    survived = []
    killed = []
    broken = []
    for name, rel, old, new in MUTATIONS:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            shutil.copytree(ROOT / "src", work / "src")
            shutil.copytree(ROOT / "tests", work / "tests")
            shutil.copytree(ROOT / "vectors", work / "vectors")
            if (ROOT / "assurance").exists():
                shutil.copytree(
                    ROOT / "assurance",
                    work / "assurance",
                    ignore=shutil.ignore_patterns("results", "__pycache__"),
                )
            target = work / rel
            text = target.read_text()
            if old not in text:
                broken.append(name)
                print(f"BROKEN\t{name}")
                continue
            target.write_text(text.replace(old, new, 1))
            env = {k: v for k, v in __import__("os").environ.items()}
            env["PYTHONPATH"] = str(work / "src")
            env["P2R_SKIP_MODEL"] = "1"
            proc = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", "--tb=no", "tests"],
                cwd=work,
                env=env,
                capture_output=True,
                text=True,
            )
            line = (proc.stdout.strip().splitlines() or proc.stderr.strip().splitlines() or ["no output"])[-1]
            if proc.returncode == 0:
                survived.append((name, line))
                print(f"SURVIVED\t{name}\t{line}")
            else:
                killed.append((name, line))
                print(f"KILLED\t{name}\t{line}")
    print(f"SUMMARY killed={len(killed)} survived={len(survived)} broken={len(broken)}")
    unexpected = [name for name, _line in survived if name not in KNOWN_SURVIVORS]
    return 1 if unexpected or broken else 0


if __name__ == "__main__":
    raise SystemExit(main())
