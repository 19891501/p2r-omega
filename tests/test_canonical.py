import pytest

from p2r.canonical import canonicalize


def test_t1_dict_order_is_deterministic():
    assert canonicalize({"b": 2, "a": 1}) == canonicalize({"a": 1, "b": 2})


def test_t1_nested_values_are_deterministic():
    left = {"z": [1, True, None, {"x": "é"}], "a": "ok"}
    right = {"a": "ok", "z": [1, True, None, {"x": "é"}]}
    assert canonicalize(left) == canonicalize(right)


def test_t1_utf16_key_ordering_is_used():
    actual = canonicalize({"\U00010000": 2, "\ue000": 1})
    assert actual == ('{"\U00010000":2,"\ue000":1}').encode("utf-8")


def test_t1_float_is_rejected():
    with pytest.raises(TypeError):
        canonicalize(1.0)


def test_t1_unsupported_type_is_rejected():
    with pytest.raises(TypeError):
        canonicalize({"x": object()})


def test_t1_non_string_keys_are_rejected():
    with pytest.raises(TypeError):
        canonicalize({1: "x"})
