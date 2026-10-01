import json

import pytest

from p2r.errors import RegistryError
from p2r.registry import Registry


def test_new_reservation_is_created(tmp_path):
    reg = Registry(tmp_path / "r.db")
    result = reg.reserve("k1", "e1", "deny", 100)
    assert result.kind == "NEW"
    assert reg.get("k1")["status"] == "RESERVED"


def test_same_execution_key_reserved_is_blocked(tmp_path):
    reg = Registry(tmp_path / "r.db")
    reg.reserve("k1", "e1", "deny", 100)
    result = reg.reserve("k1", "e1", "deny", 101)
    assert result.kind == "ALREADY_RESERVED"


def test_same_execution_key_executed_returns_retry(tmp_path):
    reg = Registry(tmp_path / "r.db")
    reg.reserve("k1", "e1", "deny", 100)
    receipt = {"type": "p2r-receipt/v1", "result": "COMPLETED"}
    reg.mark_executed("k1", receipt, 101)
    result = reg.reserve("k1", "e1", "deny", 102)
    assert result.kind == "RETRY"
    assert json.loads(result.receipt_json) == receipt


def test_different_effect_under_same_execution_key_is_a_collision(tmp_path):
    reg = Registry(tmp_path / "r.db")
    reg.reserve("k1", "e1", "deny", 100)
    with pytest.raises(RegistryError, match="REGISTRY_EXECUTION_KEY_COLLISION"):
        reg.reserve("k1", "e2", "deny", 101)


def test_same_effect_deny_after_execution(tmp_path):
    reg = Registry(tmp_path / "r.db")
    reg.reserve("k1", "e1", "deny", 100)
    reg.mark_executed("k1", {"type": "p2r-receipt/v1", "result": "COMPLETED"}, 101)
    assert reg.reserve("k2", "e1", "deny", 102).kind == "EFFECT_ALREADY_EXECUTED"


def test_same_effect_allow_new_attempt_after_execution(tmp_path):
    reg = Registry(tmp_path / "r.db")
    reg.reserve("k1", "e1", "deny", 100)
    reg.mark_executed("k1", {"type": "p2r-receipt/v1", "result": "COMPLETED"}, 101)
    assert reg.reserve("k2", "e1", "allow_new_attempt", 102).kind == "NEW"


def test_t23_stale_reserved_becomes_ambiguous_and_t24_blocks_new_attempt(tmp_path):
    reg = Registry(tmp_path / "r.db", reservation_timeout=10)
    reg.reserve("k1", "e1", "deny", 100)
    assert reg.recover_stale(111) == 1
    assert reg.get("k1")["status"] == "RESERVED_AMBIGUOUS"
    assert reg.reserve("k2", "e1", "allow_new_attempt", 112).kind == "RECONCILIATION_REQUIRED"


def test_ambiguous_original_key_also_requires_reconciliation(tmp_path):
    reg = Registry(tmp_path / "r.db")
    reg.reserve("k1", "e1", "deny", 100)
    reg.mark_ambiguous("k1", 101)
    assert reg.reserve("k1", "e1", "deny", 102).kind == "RECONCILIATION_REQUIRED"


def test_abandon_before_dispatch_removes_only_reserved(tmp_path):
    reg = Registry(tmp_path / "r.db")
    reg.reserve("k1", "e1", "deny", 100)
    reg.abandon_before_dispatch("k1")
    assert reg.get("k1") is None


def test_mark_executed_cannot_seal_ambiguous(tmp_path):
    reg = Registry(tmp_path / "r.db")
    reg.reserve("k1", "e1", "deny", 100)
    reg.mark_ambiguous("k1", 101)
    with pytest.raises(RegistryError, match="REGISTRY_AMBIGUOUS_CANNOT_EXECUTE"):
        reg.mark_executed("k1", {"type": "p2r-receipt/v1"}, 102)
    assert reg.get("k1")["status"] == "RESERVED_AMBIGUOUS"
    assert reg.get("k1")["receipt_json"] is None


def test_mark_ambiguous_does_not_reopen_executed(tmp_path):
    reg = Registry(tmp_path / "r.db")
    reg.reserve("k1", "e1", "deny", 100)
    reg.mark_executed("k1", {"type": "p2r-receipt/v1", "result": "COMPLETED"}, 101)
    reg.mark_ambiguous("k1", 102)
    row = reg.get("k1")
    assert row["status"] == "EXECUTED"
    assert row["updated_at"] == 101


def test_abandon_cannot_delete_ambiguous(tmp_path):
    reg = Registry(tmp_path / "r.db")
    reg.reserve("k1", "e1", "deny", 100)
    reg.mark_ambiguous("k1", 101)
    with pytest.raises(RegistryError, match="REGISTRY_CANNOT_ABANDON"):
        reg.abandon_before_dispatch("k1")
