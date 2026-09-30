"""Ed25519 signing and verification with URL-safe base64 encoding."""

from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64d(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("invalid base64 value")
    if any(ch.isspace() for ch in value):
        raise ValueError("whitespace not permitted")
    padding = "=" * (-len(value) % 4)
    return base64.b64decode(value + padding, altchars=b"-_", validate=True)


class LocalSigner:
    def __init__(self, signer_id: str, private_key: Ed25519PrivateKey | None = None):
        if not signer_id:
            raise ValueError("signer_id required")
        self.signer_id = signer_id
        self.private_key = private_key or Ed25519PrivateKey.generate()

    @classmethod
    def from_seed(cls, signer_id: str, seed: bytes) -> "LocalSigner":
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be 32 bytes")
        return cls(signer_id, Ed25519PrivateKey.from_private_bytes(seed))

    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    def public_key_b64(self) -> str:
        raw = self.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return b64e(raw)

    def sign(self, payload: bytes) -> dict:
        return {
            "alg": "ed25519",
            "signer": self.signer_id,
            "value": b64e(self.private_key.sign(payload)),
        }


class Keyring:
    def __init__(self):
        self.keys: dict[str, Ed25519PublicKey] = {}

    def add(self, signer_id: str, public_key: Ed25519PublicKey) -> None:
        if not signer_id:
            raise ValueError("signer_id required")
        self.keys[signer_id] = public_key

    def add_public_b64(self, signer_id: str, encoded: str) -> None:
        raw = b64d(encoded)
        self.add(signer_id, Ed25519PublicKey.from_public_bytes(raw))

    def verify(self, signer_id: str, payload: bytes, signature: str) -> bool:
        key = self.keys.get(signer_id)
        if key is None:
            return False
        try:
            raw = b64d(signature)
            if len(raw) != 64:
                return False
            key.verify(raw, payload)
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False
