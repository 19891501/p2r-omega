from p2r.digest import compute_payload_digest, seal

from .helpers import p2r_base, sign_one


def test_t2_digest_stable():
    obj = p2r_base()
    assert compute_payload_digest(obj) == obj["payload_digest"]["value"]


def test_t2_signatures_are_detached_from_payload_digest():
    obj = sign_one(p2r_base())
    digest = compute_payload_digest(obj)
    obj["signatures"].append(obj["signatures"][0].copy())
    assert compute_payload_digest(obj) == digest


def test_t3_payload_mutation_changes_digest():
    obj = p2r_base()
    original = obj["payload_digest"]["value"]
    obj["effect"]["argument"]["amount"] = 101
    assert compute_payload_digest(obj) != original
