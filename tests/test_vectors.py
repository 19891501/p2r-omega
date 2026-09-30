import json
from pathlib import Path

import pytest

from p2r.errors import VerifyError
from p2r.executor import ExecutionContext
from p2r.keys import Keyring
from p2r.receipt import verify_receipt
from p2r.universe import StaticUniverseResolver
from p2r.verify import verify_object

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    return json.loads((ROOT / "vectors" / name).read_text(encoding="utf-8"))


def ctx_for_vectors(tmp_path):
    keys = load("keyring.json")["keys"]
    kr = Keyring()
    for signer_id, encoded in keys.items():
        kr.add_public_b64(signer_id, encoded)
    return ExecutionContext(
        keyring=kr,
        universe_resolver=StaticUniverseResolver(load("universe.json")),
        registry=None,
        observer_signer=None,
        observer_scopes={"observer": ["effect:transfer", "receipt:issue"]},
        clock=lambda: 1000,
    )


def test_vector_valid_p2r_verifies(tmp_path):
    assert verify_object(load("p2r-valid.json"), ctx_for_vectors(tmp_path)) is True


def test_vector_tampered_p2r_fails(tmp_path):
    with pytest.raises(VerifyError, match="PAYLOAD_DIGEST_MISMATCH"):
        verify_object(load("p2r-tampered.json"), ctx_for_vectors(tmp_path))


def test_vector_receipt_verifies(tmp_path):
    ctx = ctx_for_vectors(tmp_path)
    assert verify_receipt(load("receipt-valid.json"), ctx.keyring, ctx.observer_scopes) is True
