from copy import deepcopy

import pytest

from p2r.authority import verify_signatures
from p2r.errors import VerifyError
from p2r.keys import Keyring, LocalSigner

from .helpers import ALICE, BOB, keyring_with, p2r_base, sign_one, sign_two


def test_t4_real_ed25519_signature_verifies():
    obj = sign_one(p2r_base())
    assert verify_signatures(obj, keyring_with(ALICE)) is True


def test_t5_invalid_signature_is_rejected():
    obj = sign_one(p2r_base())
    obj["signatures"][0]["value"] = "A" * len(obj["signatures"][0]["value"])
    with pytest.raises(VerifyError, match="SIGNATURE_THRESHOLD_NOT_MET"):
        verify_signatures(obj, keyring_with(ALICE))


def test_t6_quorum_two_is_satisfied():
    obj = sign_two(p2r_base(threshold=2, authorized=["alice", "bob"]))
    assert verify_signatures(obj, keyring_with(ALICE, BOB)) is True


def test_t7_quorum_two_is_not_satisfied_by_one_signature():
    obj = sign_one(p2r_base(threshold=2, authorized=["alice", "bob"]))
    with pytest.raises(VerifyError, match="SIGNATURE_THRESHOLD_NOT_MET"):
        verify_signatures(obj, keyring_with(ALICE, BOB))


def test_t8_duplicate_same_signer_does_not_double_count():
    obj = sign_one(p2r_base(threshold=2, authorized=["alice", "bob"]))
    obj["signatures"].append(deepcopy(obj["signatures"][0]))
    with pytest.raises(VerifyError, match="SIGNATURE_THRESHOLD_NOT_MET"):
        verify_signatures(obj, keyring_with(ALICE, BOB))


def test_t8_unauthorized_signer_does_not_count():
    eve = LocalSigner.from_seed("eve", b"\x04" * 32)
    obj = sign_one(p2r_base(threshold=2, authorized=["alice", "bob"]))
    obj["signatures"].append(eve.sign(obj["payload_digest"]["value"].encode("ascii")))
    with pytest.raises(VerifyError, match="SIGNATURE_THRESHOLD_NOT_MET"):
        verify_signatures(obj, keyring_with(ALICE, BOB, eve))


def test_t9_zero_threshold_is_invalid():
    obj = sign_one(p2r_base(threshold=0))
    with pytest.raises(VerifyError, match="AUTHORITY_BAD_THRESHOLD"):
        verify_signatures(obj, keyring_with(ALICE))


def test_t17_threshold_above_authorized_is_invalid():
    obj = sign_one(p2r_base(threshold=2, authorized=["alice"]))
    with pytest.raises(VerifyError, match="AUTHORITY_BAD_THRESHOLD"):
        verify_signatures(obj, keyring_with(ALICE))


def test_t9_duplicate_authorized_signers_are_invalid():
    obj = sign_one(p2r_base(threshold=1, authorized=["alice", "alice"]))
    with pytest.raises(VerifyError, match="AUTHORITY_SIGNERS_DUPLICATE"):
        verify_signatures(obj, keyring_with(ALICE))
