import pytest

from p2r.errors import VerifyError
from p2r.verify import verify_object

from .helpers import context, copy_obj, p2r_base, sign_one


def test_complete_object_verifies(tmp_path):
    ctx = context(tmp_path / "registry.db")
    assert verify_object(sign_one(p2r_base()), ctx) is True


def test_missing_digest_fails_closed(tmp_path):
    ctx = context(tmp_path / "registry.db")
    obj = p2r_base()
    obj.pop("payload_digest")
    with pytest.raises(VerifyError, match="PAYLOAD_DIGEST_MISSING"):
        verify_object(obj, ctx)


def test_t28_execution_policy_mutation_invalidates_signed_payload(tmp_path):
    ctx = context(tmp_path / "registry.db")
    obj = sign_one(p2r_base())
    obj["execution_policy"]["on_same_effect"] = "allow_new_attempt"
    with pytest.raises(VerifyError, match="PAYLOAD_DIGEST_MISMATCH"):
        verify_object(obj, ctx)


def test_t29_authority_threshold_mutation_invalidates_signed_payload(tmp_path):
    ctx = context(tmp_path / "registry.db")
    obj = sign_one(p2r_base())
    obj["authority"]["threshold"] = 2
    with pytest.raises(VerifyError, match="PAYLOAD_DIGEST_MISMATCH"):
        verify_object(obj, ctx)


def test_t30_provenance_mutation_invalidates_signed_payload(tmp_path):
    ctx = context(tmp_path / "registry.db")
    obj = sign_one(p2r_base())
    obj["provenance"][0]["source"]["span"]["end"] = 99
    with pytest.raises(VerifyError, match="PAYLOAD_DIGEST_MISMATCH"):
        verify_object(obj, ctx)


def test_unknown_decision_requires_explicitly_resealed_and_resigned_object(tmp_path):
    ctx = context(tmp_path / "registry.db")
    obj = p2r_base(decision="UNKNOWN")
    with pytest.raises(VerifyError, match="DECISION_STATUS_REJECTED"):
        verify_object(sign_one(obj), ctx)
