"""The Anamika bundle format, version 1, in Python.

A port of contracts/bundle/reference.py (anamika-control-plane). The bytes must
match that file's vectors.json exactly; tests/test_bundle.py replays every
vector, so a drift here fails CI instead of failing a job in production.

Differences from the reference, all on purpose:
  * seal() draws a random nonce unless one is given (fixed nonces are for the
    test vectors only; reusing one under a key breaks AES-GCM).
  * open_() raises BundleError, never a bare cryptography exception, so callers
    can map every failure to one error code without a message that could echo data.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"ANAM"
VERSION = 1
NONCE_LEN = 12
LABELS = ("input", "manifest", "output", "summary")


class BundleError(ValueError):
    """An object failed to parse or authenticate. The message never contains data."""


def derive(k_user: bytes, label: str) -> bytes:
    """k_<label> = HKDF-SHA256(K_user, salt="", info="anamika/v1 <label>", 32)."""
    if len(k_user) != 32:
        raise BundleError("K_user must be 32 bytes")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=f"anamika/v1 {label}".encode()).derive(k_user)


def vault_key(vault_master: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=b"anamika/v1 vault").derive(vault_master)


@dataclass(frozen=True)
class Keys:
    """The four keys derived from K_user. Held in memory only; repr hides them."""

    input: bytes
    manifest: bytes
    output: bytes
    summary: bytes

    @classmethod
    def from_user_key(cls, k_user: bytes) -> "Keys":
        return cls(**{label: derive(k_user, label) for label in LABELS})

    def __repr__(self) -> str:  # a stray log of a Keys object must not print key bytes
        return "Keys(<redacted>)"


def part_name(n: int) -> str:
    return f"part-{n:05d}"


def aad_manifest(job: str) -> str:
    return f"anamika/v1|{job}|manifest"


def aad_input(job: str, n: int, total: int) -> str:
    return f"anamika/v1|{job}|input|{part_name(n)}|of-{total:05d}"


def aad_output(job: str, n: int, total: int) -> str:
    return f"anamika/v1|{job}|apply|output|{part_name(n)}|of-{total:05d}"


def aad_summary(job: str, phase: str, what: str) -> str:
    """phase is "measure" or "apply"; what is "summary" or "histogram"."""
    return f"anamika/v1|{job}|{phase}|{what}"


def aad_vault(vault_id: str, version: int) -> str:
    return f"anamika/v1|vault|{vault_id}|v{version}"


def seal(key: bytes, plaintext: bytes, aad: str, nonce: bytes | None = None) -> bytes:
    nonce = os.urandom(NONCE_LEN) if nonce is None else nonce
    if len(nonce) != NONCE_LEN:
        raise BundleError("nonce must be 12 bytes")
    return MAGIC + bytes([VERSION]) + nonce + AESGCM(key).encrypt(nonce, plaintext, aad.encode())


def open_(key: bytes, blob: bytes, aad: str) -> bytes:
    # 4 magic + 1 version + 12 nonce + 16 tag is the smallest valid object.
    if len(blob) < 5 + NONCE_LEN + 16 or blob[:4] != MAGIC:
        raise BundleError("not an Anamika object")
    if blob[4] != VERSION:
        raise BundleError(f"unsupported version {blob[4]}")
    nonce = blob[5 : 5 + NONCE_LEN]
    try:
        return AESGCM(key).decrypt(nonce, blob[5 + NONCE_LEN :], aad.encode())
    except InvalidTag:
        raise BundleError("authentication failed") from None


def wrap(public_key, key: bytes, label: str) -> bytes:
    return public_key.encrypt(
        key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=label.encode())
    )


def unwrap(private_key, wrapped: bytes, label: str) -> bytes:
    return private_key.decrypt(
        wrapped, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=label.encode())
    )
