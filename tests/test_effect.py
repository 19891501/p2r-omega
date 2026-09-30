from copy import deepcopy

from p2r.effect import effect_identity, execution_key

from .helpers import p2r_base


def test_effect_identity_is_stable():
    obj = p2r_base()
    assert effect_identity(obj) == effect_identity(deepcopy(obj))


def test_effect_change_changes_identity():
    obj = p2r_base()
    a = effect_identity(obj)
    obj["effect"]["argument"]["amount"] = 101
    assert effect_identity(obj) != a


def test_nonce_change_changes_execution_key_but_not_effect_identity():
    obj = p2r_base(nonce="nonce-a")
    a = effect_identity(obj)
    ka = execution_key(obj)
    obj["authority"]["nonce"] = "nonce-b"
    assert effect_identity(obj) == a
    assert execution_key(obj) != ka
