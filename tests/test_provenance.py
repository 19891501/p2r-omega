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

    for bad in ("/items/01", "/items/00", "/items/+1", "/items/-0", "/items/1_0"):
        obj = copy_obj(base)
        obj["provenance"][0]["path"] = bad
        with pytest.raises(VerifyError, match="PROVENANCE_PATH_INVALID"):
            verify_provenance(obj, [evidence])


def test_t21_array_index_past_end_is_not_found():
    evidence = {"evidence_id": "ev-arr", "items": [10, 20]}
    obj = {
        "provenance": [{
            "path": "/items/2",
            "value_digest": sha256_b64(canonicalize(10)),
            "source": {"evidence_id": "ev-arr", "span": {"start": 0, "end": 1}},
        }]
    }
    with pytest.raises(VerifyError, match="PROVENANCE_PATH_NOT_FOUND"):
        verify_provenance(obj, [evidence])


def test_t21_oversized_array_index_is_not_found_before_int():
    evidence = {"evidence_id": "ev-arr", "items": [10, 20]}
    obj = {
        "provenance": [{
            "path": "/items/" + ("9" * 100_000),
            "value_digest": sha256_b64(canonicalize(10)),
            "source": {"evidence_id": "ev-arr", "span": {"start": 0, "end": 1}},
        }]
    }
    with pytest.raises(VerifyError, match="PROVENANCE_PATH_NOT_FOUND"):
        verify_provenance(obj, [evidence])


def test_t21_object_key_with_leading_zero_remains_valid():
    evidence = {"evidence_id": "ev-key", "items": {"01": 20}}
    obj = {
        "provenance": [{
            "path": "/items/01",
            "value_digest": sha256_b64(canonicalize(20)),
            "source": {"evidence_id": "ev-key", "span": {"start": 0, "end": 1}},
        }]
    }
    assert verify_provenance(obj, [evidence]) is True


def test_rfc6901_tilde_escapes_are_exact_and_left_to_right():
    evidence = {
        "evidence_id": "ev-tilde",
        "a": {
            "~": 10,
            "/": 20,
            "~1": 30,
            "~/": 40,
            "~0": 50,
            "~01": 60,
        },
    }
    cases = {
        "/a/~0": (10, "/a/~0"),
        "/a/~1": (20, "/a/~1"),
        "/a/~01": (30, "/a/~01"),
        "/a/~0~1": (40, "/a/~0~1"),
        "/a/~00": (50, "/a/~00"),
        "/a/~001": (60, "/a/~001"),
    }
    for path, (expected, _) in cases.items():
        obj = {
            "provenance": [{
                "path": path,
                "value_digest": sha256_b64(canonicalize(expected)),
                "source": {"evidence_id": "ev-tilde", "span": {"start": 0, "end": 1}},
            }]
        }
        assert verify_provenance(obj, [evidence]) is True


def test_invalid_rfc6901_tilde_escapes_are_rejected():
    evidence = {"evidence_id": "ev-tilde-invalid", "a": {"~": 10, "~/": 20, "~2": 30}}
    base = {
        "provenance": [{
            "path": "/a/~0",
            "value_digest": sha256_b64(canonicalize(10)),
            "source": {"evidence_id": "ev-tilde-invalid", "span": {"start": 0, "end": 1}},
        }]
    }
    for bad in ("/a/~", "/a/~~1", "/a/~2"):
        obj = copy_obj(base)
        obj["provenance"][0]["path"] = bad
        with pytest.raises(VerifyError, match="PROVENANCE_PATH_INVALID"):
            verify_provenance(obj, [evidence])
