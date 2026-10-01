"""Fast assurance checks. The exhaustive model run lives here too.

The 40s model exploration is the differential proof for the registry.
Heavier oracle volumes, the concurrency ladder, and benchmarks are
``python -m assurance.campaign``.
"""

import os

import pytest

from assurance.chaos import ghost_rollback, run_all
from assurance.oracle_diff import compare_canonical, compare_identity, compare_universe
from assurance.replay_registry import explore
from assurance.rfc6901 import run_corpus


def test_registry_model_matches_sqlite():
    if os.environ.get("P2R_SKIP_MODEL") == "1":
        pytest.skip("bounded model exploration is slow; skipped inside mutation copies")
    result = explore()
    assert result["conflicts"] == []
    assert result["status"] == "PROUVÉ"
    assert result["states"] >= 100
    assert result["edges"] >= result["states"]


def test_chaos_schedules_fail_closed():
    result = run_all()
    assert result["failed"] == []
    assert result["status"] == "PROUVÉ"


def test_corrupt_sibling_does_not_commit_stale_recovery():
    assert ghost_rollback()["status"] == "PROUVÉ"


def test_rfc6901_corpus_matches_oracle():
    result = run_corpus()
    assert result["conflicts"] == []
    assert result["non_conforme"] == []


def test_oracle_samples_agree():
    assert compare_canonical(400)["status"] == "PROUVÉ"
    assert compare_identity(200)["status"] == "PROUVÉ"
    assert compare_universe(80)["status"] == "PROUVÉ"
