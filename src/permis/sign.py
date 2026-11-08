"""Reçu p2r sur un Permis.

Le reçu signe l'observation (le document). `result: COMPLETED` est exigé par
la primitive de reçu : ici cela veut dire que l'observation a été enregistrée,
pas que le workflow n8n a été exécuté, ni que le classement est vrai.

`action_semantics: at_most_once` est le champ obligatoire le plus proche :
ce reçu n'est pas une autorisation à rejouer un effet.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from p2r.canonical import canonicalize
from p2r.digest import sha256_b64
from p2r.effect import effect_identity, execution_key
from p2r.errors import VerifyError
from p2r.keys import LocalSigner, b64d
from p2r.receipt import build_receipt, verify_receipt

from permis.errors import PermisError

OBSERVER_SCOPE = ["permis:observation"]
PERMIS_TYPE = "permis-d-agir/v1"


def permis_digest(permis: dict) -> str:
    return sha256_b64(canonicalize(permis))


def _pseudo(permis: dict, signer_id: str, digest: str) -> dict:
    return {
        "authority": {
            "principal": signer_id,
            "nonce": digest,
            "nonce_scope": "permis-d-agir",
        },
        "effect": {
            "profile": "permis-d-agir/observer",
            "rule": "observation",
            "argument": {
                "workflow_sha256": permis["workflow"]["sha256"],
                "summary": permis["summary"],
            },
            "idempotency_key": digest,
        },
    }


def sign_envelope(permis: dict, signer: LocalSigner, observed_at: int) -> dict:
    if not isinstance(observed_at, int) or isinstance(observed_at, bool):
        raise PermisError("HORODATAGE_INVALIDE", "L'horodatage du reçu doit être un entier (secondes).")
    digest = permis_digest(permis)
    pseudo = _pseudo(permis, signer.signer_id, digest)
    receipt = build_receipt(
        payload_digest=digest,
        execution_key=execution_key(pseudo),
        effect_identity=effect_identity(pseudo),
        action_semantics="at_most_once",
        observed_effect={
            "type": PERMIS_TYPE,
            "workflow_sha256": permis["workflow"]["sha256"],
            "summary": permis["summary"],
        },
        observer_id=signer.signer_id,
        observer_scope=list(OBSERVER_SCOPE),
        observed_at=observed_at,
        signer=signer,
    )
    return {
        "permis": permis,
        "preuve": {
            "alg": "ed25519",
            "public_key": signer.public_key_b64(),
            "signer_id": signer.signer_id,
            "permis_digest": digest,
            "receipt": receipt,
        },
    }


def unsigned_envelope(permis: dict) -> dict:
    return {"permis": permis, "preuve": None}


@dataclass
class VerifyResult:
    ok: bool
    identity_pinned: bool
    signer_id: str | None
    digest: str | None
    summary: dict | None
    workflow_name: str | None
    reason: str | None


def _fail(reason: str, **kwargs) -> VerifyResult:
    return VerifyResult(False, False, kwargs.get("signer_id"), kwargs.get("digest"), kwargs.get("summary"), kwargs.get("workflow_name"), reason)


def verify_envelope(envelope: dict, pinned: tuple[str, str] | None = None) -> VerifyResult:
    """Vérifie le reçu. `pinned` est (signer_id, public_key) transmis à part."""
    if not isinstance(envelope, dict):
        return _fail("ENVELOPPE_INVALIDE")
    permis = envelope.get("permis")
    preuve = envelope.get("preuve")
    if not isinstance(permis, dict) or permis.get("type") != PERMIS_TYPE:
        return _fail("PERMIS_TYPE_INVALIDE")
    name = None
    workflow = permis.get("workflow")
    if isinstance(workflow, dict) and isinstance(workflow.get("name"), str):
        name = workflow["name"]
    summary = permis.get("summary") if isinstance(permis.get("summary"), dict) else None
    if preuve is None:
        return _fail("NON_SIGNE", summary=summary, workflow_name=name)
    if not isinstance(preuve, dict):
        return _fail("PREUVE_INVALIDE", summary=summary, workflow_name=name)
    signer_id = preuve.get("signer_id")
    public_key = preuve.get("public_key")
    if not isinstance(signer_id, str) or not signer_id or not isinstance(public_key, str) or not public_key:
        return _fail("PREUVE_SANS_CLEF", summary=summary, workflow_name=name)
    try:
        actual = permis_digest(permis)
    except (TypeError, ValueError) as exc:
        return _fail(f"CANONIQUE:{exc}", signer_id=signer_id, summary=summary, workflow_name=name)
    if preuve.get("permis_digest") != actual:
        return _fail("PREUVE_DIGEST", signer_id=signer_id, digest=actual, summary=summary, workflow_name=name)
    receipt = preuve.get("receipt")
    if not isinstance(receipt, dict):
        return _fail("RECU_ABSENT", signer_id=signer_id, digest=actual, summary=summary, workflow_name=name)
    if receipt.get("payload_digest") != actual:
        return _fail("RECU_DIGEST", signer_id=signer_id, digest=actual, summary=summary, workflow_name=name)
    if pinned is not None:
        pinned_id, pinned_key = pinned
        if pinned_id != signer_id or pinned_key != public_key:
            return _fail("CLEF_DIFFERENTE", signer_id=signer_id, digest=actual, summary=summary, workflow_name=name)
    try:
        pseudo = _pseudo(permis, signer_id, actual)
        if receipt.get("effect_identity") != effect_identity(pseudo):
            return _fail("EFFET_DIFFERENT", signer_id=signer_id, digest=actual, summary=summary, workflow_name=name)
        if receipt.get("execution_key") != execution_key(pseudo):
            return _fail("CLE_EXECUTION_DIFFERENTE", signer_id=signer_id, digest=actual, summary=summary, workflow_name=name)
    except (TypeError, ValueError, VerifyError) as exc:
        code = getattr(exc, "code", "EFFET_ILLISIBLE")
        return _fail(code, signer_id=signer_id, digest=actual, summary=summary, workflow_name=name)
    observed = receipt.get("observed_effect")
    if not isinstance(observed, dict) or observed.get("type") != PERMIS_TYPE:
        return _fail("EFFET_OBSERVE_INVALIDE", signer_id=signer_id, digest=actual, summary=summary, workflow_name=name)
    if observed.get("workflow_sha256") != permis.get("workflow", {}).get("sha256"):
        return _fail("WORKFLOW_DIGEST", signer_id=signer_id, digest=actual, summary=summary, workflow_name=name)
    if observed.get("summary") != summary:
        return _fail("RESUME_DIFFERENT", signer_id=signer_id, digest=actual, summary=summary, workflow_name=name)
    if receipt.get("action_semantics") != "at_most_once":
        return _fail("SEMANTIQUE_INVALIDE", signer_id=signer_id, digest=actual, summary=summary, workflow_name=name)
    keyring_ok = _verify_signature(receipt, signer_id, public_key)
    if keyring_ok is not None:
        return _fail(keyring_ok, signer_id=signer_id, digest=actual, summary=summary, workflow_name=name)
    return VerifyResult(
        True,
        pinned is not None,
        signer_id,
        actual,
        summary,
        name,
        None,
    )


def _verify_signature(receipt: dict, signer_id: str, public_key: str) -> str | None:
    from p2r.keys import Keyring

    observer = receipt.get("observer")
    if not isinstance(observer, dict) or set(observer.get("scope") or []) != set(OBSERVER_SCOPE):
        return "PORTEE_INVALIDE"
    keyring = Keyring()
    try:
        keyring.add_public_b64(signer_id, public_key)
        verify_receipt(receipt, keyring, {signer_id: list(OBSERVER_SCOPE)})
    except (VerifyError, ValueError, TypeError) as exc:
        return getattr(exc, "code", "RECU_INVALIDE")
    return None


def load_signer(path: Path) -> LocalSigner:
    data = _read_key_file(path)
    signer_id = data.get("signer_id")
    seed = data.get("seed_b64")
    if not isinstance(signer_id, str) or not signer_id or not isinstance(seed, str):
        raise PermisError("CLEF_INVALIDE", "Le fichier de clef doit contenir signer_id et seed_b64.")
    try:
        return LocalSigner.from_seed(signer_id, b64d(seed))
    except ValueError as exc:
        raise PermisError("CLEF_INVALIDE", "La graine n'est pas une clef Ed25519 de 32 octets.") from exc


def load_pin(path: Path) -> tuple[tuple[str, str], bool]:
    """Retourne ((signer_id, public_key), fichier_contient_la_graine)."""
    data = _read_key_file(path)
    signer_id = data.get("signer_id")
    if not isinstance(signer_id, str) or not signer_id:
        raise PermisError("CLEF_INVALIDE", "signer_id manquant dans le fichier de clef.")
    private = isinstance(data.get("seed_b64"), str)
    derived = None
    if private:
        derived = load_signer(path).public_key_b64()
    public = data.get("public_key")
    if isinstance(public, str) and public:
        if derived is not None and derived != public:
            raise PermisError("CLEF_INCOHERENTE", "La clef publique ne correspond pas à la graine.")
        return (signer_id, public), private
    if derived is None:
        raise PermisError("CLEF_INVALIDE", "Ni public_key ni seed_b64 dans le fichier.")
    return (signer_id, derived), private


def write_private_key(path: Path, signer_id: str) -> LocalSigner:
    signer = LocalSigner(signer_id)
    payload = {"signer_id": signer_id, "seed_b64": _seed_b64(signer)}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return signer


def _seed_b64(signer: LocalSigner) -> str:
    from cryptography.hazmat.primitives import serialization

    from p2r.keys import b64e

    raw = signer.private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return b64e(raw)


def _read_key_file(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PermisError("CLEF_ILLISIBLE", "Fichier de clef illisible.") from exc
    if not isinstance(data, dict):
        raise PermisError("CLEF_INVALIDE", "La clef doit être un objet JSON.")
    return data
