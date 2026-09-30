from copy import deepcopy

import pytest

from p2r.authority import sign_payload
from p2r.digest import compute_payload_digest, seal
from p2r.errors import VerifyError
from p2r.keys import LocalSigner
from p2r.verify import verify_object

from .helpers import ALICE, BOB, context, p2r_base, sign_one


def test_attack_1_payload_tampering_fails(tmp_path):
    ctx = context(tmp_path / "r.db")
    obj = sign_one(p2r_base())
    obj["effect"]["argument"]["amount"] = 9999
    with pytest.raises(VerifyError, match="PAYLOAD_DIGEST_MISMATCH"):
        verify_object(obj, ctx)


def test_attack_2_injected_signature_does_not_change_payload_digest():
    obj = sign_one(p2r_base())
    digest = obj["payload_digest"]["value"]
    eve = LocalSigner.from_seed("eve", b"\x04" * 32)
    obj["signatures"].append(eve.sign(digest.encode("ascii")))
    assert compute_payload_digest(obj) == digest


def test_attack_3_replacing_signature_with_unauthorized_signer_fails(tmp_path):
    ctx = context(tmp_path / "r.db")
    obj = sign_one(p2r_base())
    eve = LocalSigner.from_seed("eve", b"\x04" * 32)
    obj["signatures"] = [eve.sign(obj["payload_digest"]["value"].encode("ascii"))]
    with pytest.raises(VerifyError, match="SIGNATURE_THRESHOLD_NOT_MET"):
        verify_object(obj, ctx)


def test_attack_4_mutating_decision_without_resigning_fails(tmp_path):
    ctx = context(tmp_path / "r.db")
    obj = sign_one(p2r_base())
    obj["decision"]["status"] = "CONFLICT"
    with pytest.raises(VerifyError, match="PAYLOAD_DIGEST_MISMATCH"):
        verify_object(obj, ctx)


def test_attack_5_mutating_manifest_root_without_resigning_fails(tmp_path):
    ctx = context(tmp_path / "r.db")
    obj = sign_one(p2r_base())
    obj["world"]["manifest_root"]["value"] = "bad"
    with pytest.raises(VerifyError, match="PAYLOAD_DIGEST_MISMATCH"):
        verify_object(obj, ctx)


def test_attack_6_extra_uncovered_fields_inside_digest_block_fail(tmp_path):
    ctx = context(tmp_path / "r.db")
    obj = sign_one(p2r_base())
    obj["payload_digest"]["unchecked"] = "attacker"
    with pytest.raises(VerifyError, match="PAYLOAD_DIGEST_SHAPE_INVALID"):
        verify_object(obj, ctx)


def test_attack_7_reseal_and_sign_after_payload_change_is_a_new_object(tmp_path):
    ctx = context(tmp_path / "r.db")
    obj = p2r_base()
    obj["effect"]["argument"]["amount"] = 101
    changed = seal(obj)
    changed = sign_payload(changed, ALICE)
    assert changed["payload_digest"]["value"] != p2r_base()["payload_digest"]["value"]
    assert verify_object(changed, ctx) is True


def test_attack_8_signature_order_does_not_change_payload_digest(tmp_path):
    ctx = context(tmp_path / "r.db")
    obj = p2r_base(threshold=2, authorized=["alice", "bob"])
    signed = sign_payload(sign_payload(obj, ALICE), BOB)
    reversed_signatures = deepcopy(signed)
    reversed_signatures["signatures"].reverse()
    assert verify_object(reversed_signatures, ctx) is True
