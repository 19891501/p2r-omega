"""SQLite reservation registry with fail-closed recovery semantics."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from .errors import RegistryError

SCHEMA = """
CREATE TABLE IF NOT EXISTS reservations (
    execution_key TEXT PRIMARY KEY,
    effect_identity TEXT NOT NULL,
    status TEXT NOT NULL,
    receipt_json TEXT,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reservations_effect_identity
ON reservations(effect_identity);
"""

VALID_STATUSES = {"RESERVED", "EXECUTED", "RESERVED_AMBIGUOUS"}


@dataclass(frozen=True)
class ReserveDecision:
    kind: str
    receipt_json: str | None = None
    prior_execution_key: str | None = None


class Registry:
    def __init__(self, path="p2r.db", reservation_timeout: int = 300):
        if not isinstance(reservation_timeout, int) or reservation_timeout < 0:
            raise ValueError("reservation_timeout must be a non-negative integer")
        self.path = str(path)
        self.reservation_timeout = reservation_timeout
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self):
        if self.path == ":memory:":
            raise RegistryError("REGISTRY_MEMORY_UNSUPPORTED", "Use a file-backed SQLite path for concurrent/restart semantics")
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def _initialize(self):
        db = self._connect()
        try:
            db.executescript(SCHEMA)
            db.execute("PRAGMA synchronous=FULL")
        finally:
            db.close()

    def _recover_stale_locked(self, db, now: int, timeout: int | None = None) -> int:
        timeout_value = self.reservation_timeout if timeout is None else timeout
        if not isinstance(timeout_value, int) or isinstance(timeout_value, bool) or timeout_value < 0:
            raise RegistryError("REGISTRY_TIMEOUT_INVALID")
        cutoff = now - timeout_value
        cursor = db.execute(
            "UPDATE reservations SET status='RESERVED_AMBIGUOUS', updated_at=? "
            "WHERE status='RESERVED' AND updated_at < ?",
            (now, cutoff),
        )
        return cursor.rowcount

    def recover_stale(self, now: int, timeout: int | None = None) -> int:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            changed = self._recover_stale_locked(db, now, timeout)
            db.execute("COMMIT")
            return changed
        except Exception:
            db.execute("ROLLBACK")
            raise
        finally:
            db.close()

    def reserve(self, execution_key, effect_identity, policy, now, reservation_timeout: int | None = None):
        if policy not in {"allow_new_attempt", "deny"}:
            raise RegistryError("REGISTRY_POLICY_INVALID")
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            self._recover_stale_locked(db, now, reservation_timeout)

            row = db.execute(
                "SELECT * FROM reservations WHERE execution_key=?",
                (execution_key,),
            ).fetchone()
            if row is not None:
                if row["effect_identity"] != effect_identity:
                    raise RegistryError("REGISTRY_EXECUTION_KEY_COLLISION")
                status = row["status"]
                if status == "EXECUTED":
                    result = ReserveDecision("RETRY", row["receipt_json"])
                elif status == "RESERVED":
                    result = ReserveDecision("ALREADY_RESERVED", prior_execution_key=execution_key)
                elif status == "RESERVED_AMBIGUOUS":
                    result = ReserveDecision("RECONCILIATION_REQUIRED", prior_execution_key=execution_key)
                else:
                    raise RegistryError("REGISTRY_STATUS_INVALID")
                db.execute("COMMIT")
                return result

            rows = db.execute(
                "SELECT execution_key,status,receipt_json FROM reservations "
                "WHERE effect_identity=? ORDER BY updated_at ASC",
                (effect_identity,),
            ).fetchall()

            for prior in rows:
                if prior["status"] not in VALID_STATUSES:
                    raise RegistryError("REGISTRY_STATUS_INVALID")

            for prior in rows:
                if prior["status"] == "RESERVED_AMBIGUOUS":
                    db.execute("COMMIT")
                    return ReserveDecision("RECONCILIATION_REQUIRED", prior_execution_key=prior["execution_key"])
            for prior in rows:
                if prior["status"] == "RESERVED":
                    db.execute("COMMIT")
                    return ReserveDecision("EFFECT_IN_PROGRESS", prior_execution_key=prior["execution_key"])
            if rows and policy == "deny":
                executed = next((r for r in rows if r["status"] == "EXECUTED"), None)
                if executed is not None:
                    db.execute("COMMIT")
                    return ReserveDecision("EFFECT_ALREADY_EXECUTED", prior_execution_key=None)

            db.execute(
                "INSERT INTO reservations(execution_key,effect_identity,status,receipt_json,updated_at) "
                "VALUES(?,?,?,?,?)",
                (execution_key, effect_identity, "RESERVED", None, now),
            )
            db.execute("COMMIT")
            return ReserveDecision("NEW")
        except RegistryError:
            try:
                db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except Exception as exc:
            try:
                db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise RegistryError("REGISTRY_RESERVE_FAILED", str(exc)) from exc
        finally:
            db.close()

    def mark_executed(self, execution_key, receipt, now):
        receipt_json = json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT status FROM reservations WHERE execution_key=?",
                (execution_key,),
            ).fetchone()
            if row is None:
                raise RegistryError("REGISTRY_RESERVATION_MISSING")
            if row["status"] == "RESERVED_AMBIGUOUS":
                raise RegistryError("REGISTRY_AMBIGUOUS_CANNOT_EXECUTE")
            if row["status"] != "RESERVED":
                raise RegistryError("REGISTRY_BAD_TRANSITION")
            db.execute(
                "UPDATE reservations SET status='EXECUTED', receipt_json=?, updated_at=? "
                "WHERE execution_key=?",
                (receipt_json, now, execution_key),
            )
            db.execute("COMMIT")
        except RegistryError:
            try:
                db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except Exception as exc:
            try:
                db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise RegistryError("REGISTRY_MARK_EXECUTED_FAILED", str(exc)) from exc
        finally:
            db.close()

    def mark_ambiguous(self, execution_key, now):
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT status FROM reservations WHERE execution_key=?",
                (execution_key,),
            ).fetchone()
            if row is None:
                raise RegistryError("REGISTRY_RESERVATION_MISSING")
            if row["status"] == "EXECUTED":
                db.execute("COMMIT")
                return
            if row["status"] != "RESERVED":
                raise RegistryError("REGISTRY_BAD_TRANSITION")
            db.execute(
                "UPDATE reservations SET status='RESERVED_AMBIGUOUS', updated_at=? WHERE execution_key=?",
                (now, execution_key),
            )
            db.execute("COMMIT")
        except RegistryError:
            try:
                db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except Exception as exc:
            try:
                db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise RegistryError("REGISTRY_MARK_AMBIGUOUS_FAILED", str(exc)) from exc
        finally:
            db.close()

    def abandon_before_dispatch(self, execution_key):
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT status FROM reservations WHERE execution_key=?",
                (execution_key,),
            ).fetchone()
            if row is None:
                raise RegistryError("REGISTRY_RESERVATION_MISSING")
            if row["status"] != "RESERVED":
                raise RegistryError("REGISTRY_CANNOT_ABANDON")
            db.execute("DELETE FROM reservations WHERE execution_key=?", (execution_key,))
            db.execute("COMMIT")
        except RegistryError:
            try:
                db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except Exception as exc:
            try:
                db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise RegistryError("REGISTRY_ABANDON_FAILED", str(exc)) from exc
        finally:
            db.close()

    def get(self, execution_key):
        db = self._connect()
        try:
            row = db.execute("SELECT * FROM reservations WHERE execution_key=?", (execution_key,)).fetchone()
            return dict(row) if row else None
        finally:
            db.close()
