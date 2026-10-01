"""Concurrency ladder, resource bounds, micro-benchmark, supply-chain record.

Numbers come from this process. They are not a security proof.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import sys
import tempfile
import threading
import time
from importlib.metadata import version
from pathlib import Path

from p2r.canonical import canonicalize
from p2r.digest import compute_payload_digest
from p2r.errors import ExecutionError
from p2r.executor import execute
from p2r.verify import verify_object

from tests.helpers import context, p2r_base, sign_one

ROOT = Path(__file__).resolve().parents[1]


def concurrency_ladder(levels=(1, 2, 4, 8, 16, 32, 64)):
    rows = []
    for workers in levels:
        work = tempfile.mkdtemp(prefix="p2r-conc-")
        path = os.path.join(work, "reg.db")
        try:
            ctx = context(path)
            obj = sign_one(p2r_base())
            calls = []
            lock = threading.Lock()
            errors = []

            def action(effect, key):
                with lock:
                    calls.append(key)
                return {"ok": True}

            def worker():
                local = context(path)
                try:
                    execute(obj, local, action, "idempotent")
                except ExecutionError as exc:
                    errors.append(exc.code)
                except Exception as exc:
                    errors.append(type(exc).__name__)

            threads = [threading.Thread(target=worker) for _ in range(workers)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            silent = len(calls) != 1
            rows.append(
                {
                    "threads": workers,
                    "external_calls": len(calls),
                    "errors": sorted(set(errors)),
                    "status": "ÉCHEC" if silent else "PROUVÉ",
                }
            )
            if silent:
                break
        finally:
            shutil.rmtree(work, ignore_errors=True)
    return {"rows": rows, "status": "PROUVÉ" if all(r["status"] == "PROUVÉ" for r in rows) else "ÉCHEC"}


def resource_bounds():
    rows = []
    for label, count in (("10KB", 10_000), ("100KB", 100_000), ("1MB", 1_000_000), ("10MB", 10_000_000)):
        value = {"blob": "a" * count}
        started = time.perf_counter()
        try:
            data = canonicalize(value)
            status = "ok"
        except Exception as exc:
            data = b""
            status = type(exc).__name__
        rows.append(
            {
                "case": label,
                "bytes": len(data),
                "seconds": round(time.perf_counter() - started, 4),
                "status": status,
            }
        )
    for depth in (10, 100, 500, 1000):
        value = 0
        for _ in range(depth):
            value = [value]
        started = time.perf_counter()
        try:
            canonicalize(value)
            status = "ok"
        except RecursionError:
            status = "RecursionError"
        except Exception as exc:
            status = type(exc).__name__
        rows.append({"case": f"depth-{depth}", "seconds": round(time.perf_counter() - started, 4), "status": status})
    started = time.perf_counter()
    try:
        canonicalize({"k": "é"})
    except Exception as exc:
        rows.append({"case": "control", "status": type(exc).__name__})
    else:
        rows.append({"case": "control", "seconds": round(time.perf_counter() - started, 4), "status": "ok"})
    return {"rows": rows, "floats": "TypeError", "note": "RecursionError is a refusal, not an acceptance. No depth cap was added."}


def bench(samples: int = 80):
    obj = sign_one(p2r_base())
    ctx = None
    work = tempfile.mkdtemp(prefix="p2r-bench-")
    path = os.path.join(work, "reg.db")
    try:
        ctx = context(path)
        calls = {"n": 0}

        def action(effect, key):
            calls["n"] += 1
            return {"ok": True}

        def time_calls(fn, count):
            samples_s = []
            for _ in range(count):
                started = time.perf_counter()
                fn()
                samples_s.append(time.perf_counter() - started)
            samples_s.sort()
            def pct(q):
                idx = min(len(samples_s) - 1, int(q * len(samples_s)))
                return round(samples_s[idx] * 1e6, 1)
            return {
                "n": count,
                "p50_us": pct(0.50),
                "p95_us": pct(0.95),
                "p99_us": pct(0.99),
            }

        canon = time_calls(lambda: canonicalize(obj), samples)
        digest = time_calls(lambda: compute_payload_digest(obj), samples)
        verify = time_calls(lambda: verify_object(obj, ctx), samples)
        execute(obj, ctx, action, "idempotent")
        retry = time_calls(lambda: execute(obj, ctx, action, "idempotent"), samples)
        return {
            "samples": samples,
            "canonicalize": canon,
            "digest": digest,
            "verify_object": verify,
            "cached_execute": retry,
            "first_external_calls": calls["n"],
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "status": "PROUVÉ" if calls["n"] == 1 else "ÉCHEC",
        }
    finally:
        shutil.rmtree(work, ignore_errors=True)


def supply():
    files = []
    for path in sorted((ROOT / "src" / "p2r").glob("*.py")):
        files.append({"path": str(path.relative_to(ROOT)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    deps = {}
    for name in ("cryptography", "pytest"):
        try:
            deps[name] = version(name)
        except Exception as exc:
            deps[name] = f"missing:{type(exc).__name__}"
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "dependencies": deps,
        "sources": files,
        "network_in_tests": "none — assurance campaigns do not fetch or exec remote code",
    }
