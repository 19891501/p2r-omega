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
