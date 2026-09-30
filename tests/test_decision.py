import pytest

from p2r.decision import verify_decision, verify_execution_policy
from p2r.errors import VerifyError

from .helpers import copy_obj, p2r_base


def test_t14_verified_passes():
    assert verify_decision(p2r_base()) is True


def test_t15_unknown_is_blocked_by_default():
    obj = copy_obj(p2r_base())
    obj["decision"]["status"] = "UNKNOWN"
    with pytest.raises(VerifyError, match="DECISION_STATUS_REJECTED"):
        verify_decision(obj)


def test_t20_unknown_can_be_explicitly_required():
    obj = copy_obj(p2r_base())
    obj["decision"]["status"] = "UNKNOWN"
    obj["execution_policy"]["require_decision_status"] = "UNKNOWN"
    assert verify_decision(obj) is True


def test_t20_unknown_policy_value_must_be_valid():
    obj = copy_obj(p2r_base())
    obj["execution_policy"]["require_decision_status"] = "NOT_A_STATUS"
    with pytest.raises(VerifyError, match="EXECUTION_POLICY_STATUS_INVALID"):
        verify_execution_policy(obj)
