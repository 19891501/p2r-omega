from copy import deepcopy

import pytest

from p2r.errors import VerifyError
from p2r.receipt import build_receipt, compute_receipt_digest, verify_receipt

from .helpers import ALICE, OBSERVER, keyring_with


def make_receipt():
    return build_receipt(
        payload_digest="abc123",
        execution_key="ekey",
        effect_identity="eid",
        action_semantics="idempotent",
        observed_effect={"target": "acct-1", "status": "ok"},
        observer_id="observer",
        observer_scope=["receipt:issue"],
        observed_at=1000,
        signer=OBSERVER,
    )


def test_t18_valid_receipt_verifies():
    receipt = make_receipt()
    assert verify_receipt(receipt, keyring_with(OBSERVER), {"observer": ["receipt:issue"]}) is True


def test_t19_receipt_mutation_is_rejected():
    receipt = make_receipt()
    receipt["observed_effect"]["status"] = "tampered"
    with pytest.raises(VerifyError, match="RECEIPT_SIGNATURE_INVALID"):
        verify_receipt(receipt, keyring_with(OBSERVER), {"observer": ["receipt:issue"]})


def test_t18_signer_observer_mismatch_is_rejected():
    with pytest.raises(VerifyError, match="RECEIPT_SIGNER_OBSERVER_MISMATCH"):
        build_receipt(
            payload_digest="abc",
            execution_key="ekey",
            effect_identity="eid",
            action_semantics="idempotent",
            observed_effect={},
            observer_id="observer",
            observer_scope=[],
            observed_at=1,
            signer=ALICE,
        )


def test_t18_observer_scope_excess_is_rejected():
    receipt = make_receipt()
    with pytest.raises(VerifyError, match="OBSERVER_SCOPE_NOT_GRANTED"):
        verify_receipt(receipt, keyring_with(OBSERVER), {"observer": []})


def test_t27_receipt_result_mutation_is_rejected():
    receipt = make_receipt()
    receipt["result"] = "FAILED"
    with pytest.raises(VerifyError, match="RECEIPT_SIGNATURE_INVALID"):
        verify_receipt(receipt, keyring_with(OBSERVER), {"observer": ["receipt:issue"]})


def test_receipt_digest_excludes_only_signature():
    receipt = make_receipt()
    before = compute_receipt_digest(receipt)
    copy = deepcopy(receipt)
    copy["receipt_signature"]["value"] = "different"
    assert compute_receipt_digest(copy) == before
