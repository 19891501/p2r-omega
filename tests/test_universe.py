import pytest

from p2r.errors import VerifyError
from p2r.universe import manifest_root, resolve_and_verify, StaticUniverseResolver

from .helpers import p2r_base, universe


def test_t10_universe_root_is_order_independent():
    items = universe()
    assert manifest_root(items) == manifest_root(list(reversed(items)))


def test_t11_universe_mutation_changes_root():
    items = universe()
    root = manifest_root(items)
    items[0]["amount"] = 101
    assert manifest_root(items) != root


def test_t11_empty_universe_has_defined_root():
    assert isinstance(manifest_root([]), str) and manifest_root([])


def test_t11_expected_world_root_must_match_resolver():
    obj = p2r_base()
    bad = StaticUniverseResolver([{**universe()[0], "amount": 999}, universe()[1]])
    with pytest.raises(VerifyError, match="WORLD_MANIFEST_MISMATCH"):
        resolve_and_verify(obj, bad)
