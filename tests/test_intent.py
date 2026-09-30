import json

import pytest

from p2r.errors import VerifyError
from p2r.intent import interpret, verify_intent

from .helpers import copy_obj, p2r_base


def test_t12_literal_intent_verifies():
    assert verify_intent(p2r_base()) is True


def test_t13_intent_content_mutation_is_detected():
    obj = copy_obj(p2r_base())
    obj["intent"]["content"] = json.dumps({"task": "other"})
    with pytest.raises(VerifyError, match="INTENT_MISMATCH"):
        verify_intent(obj)


def test_t13_unknown_profile_is_rejected():
    obj = copy_obj(p2r_base())
    obj["intent"]["profile"] = "other-v1"
    with pytest.raises(VerifyError, match="UNKNOWN_INTENT_PROFILE"):
        verify_intent(obj)


def test_t12_invalid_json_is_rejected():
    obj = copy_obj(p2r_base())
    obj["intent"]["content"] = "{bad"
    with pytest.raises(VerifyError, match="INTENT_CONTENT_INVALID"):
        interpret(obj["intent"]["content"], obj["intent"]["profile"])
