import pytest

from p2r.canonical import canonicalize
from p2r.digest import sha256_b64
from p2r.errors import VerifyError
from p2r.provenance import verify_provenance

from .helpers import copy_obj, p2r_base, universe


def test_t21_valid_provenance_passes():
    assert verify_provenance(p2r_base(), universe()) is True


def test_t21_wrong_evidence_id_is_rejected():
    obj = copy_obj(p2r_base())
    obj["provenance"][0]["source"]["evidence_id"] = "missing"
    with pytest.raises(VerifyError, match="PROVENANCE_EVIDENCE_ID_MISMATCH"):
        verify_provenance(obj, universe())


def test_t21_wrong_path_is_rejected():
    obj = copy_obj(p2r_base())
    obj["provenance"][0]["path"] = "/does-not-exist"
    with pytest.raises(VerifyError, match="PROVENANCE_PATH_NOT_FOUND"):
        verify_provenance(obj, universe())


def test_t21_wrong_value_digest_is_rejected():
    obj = copy_obj(p2r_base())
    obj["provenance"][0]["value_digest"] = sha256_b64(canonicalize(101))
    with pytest.raises(VerifyError, match="PROVENANCE_VALUE_DIGEST_MISMATCH"):
        verify_provenance(obj, universe())


def test_t30_invalid_span_is_rejected():
    obj = copy_obj(p2r_base())
    obj["provenance"][0]["source"]["span"] = {"start": 5, "end": 5}
    with pytest.raises(VerifyError, match="PROVENANCE_SPAN_INVALID"):
        verify_provenance(obj, universe())


def test_t21_array_index_follows_rfc6901():
    evidence = {"evidence_id": "ev-arr", "items": [10, 20]}
    base = {
        "provenance": [{
            "path": "/items/1",
            "value_digest": sha256_b64(canonicalize(20)),
            "source": {"evidence_id": "ev-arr", "span": {"start": 0, "end": 1}},
        }]
    }
    assert verify_provenance(base, [evidence]) is True

    zero = copy_obj(base)
    zero["provenance"][0]["path"] = "/items/0"
    zero["provenance"][0]["value_digest"] = sha256_b64(canonicalize(10))
    assert verify_provenance(zero, [evidence]) is True

    missing = copy_obj(base)
    missing["provenance"][0]["path"] = "/items/2"
    with pytest.raises(VerifyError, match="PROVENANCE_PATH_NOT_FOUND"):
        verify_provenance(missing, [evidence])

    for bad in ("/items/01", "/items/00", "/items/+1", "/items/-0", "/items/1_0"):
        obj = copy_obj(base)
        obj["provenance"][0]["path"] = bad
        with pytest.raises(VerifyError, match="PROVENANCE_PATH_INVALID"):
            verify_provenance(obj, [evidence])

    keyed = {"evidence_id": "ev-key", "01": 7}
    assert verify_provenance({
        "provenance": [{
            "path": "/01",
            "value_digest": sha256_b64(canonicalize(7)),
            "source": {"evidence_id": "ev-key", "span": {"start": 0, "end": 1}},
        }]
    }, [keyed]) is True
