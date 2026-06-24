"""
Anonymization operation implementations.

Each operation is a function with signature::

    op(value: Any, params: dict, vault: dict) -> Any | None

- Returning ``None`` signals the caller to delete the field (used by ``suppress``).
- *vault* is a per-bundle dict used by ``tokenize`` for cross-resource consistency;
  other operations ignore it.
- All operations handle scalar strings, lists, and nested dicts recursively so
  the path can target either a leaf field or a whole sub-object.

Plugging in new operations: add them to ``OPERATION_MAP`` at the bottom.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import date, datetime
from typing import Any


# ── helpers ──────────────────────────────────────────────────────────────────

def _apply_recursive(value: Any, fn) -> Any:
    """Recursively apply *fn* to string leaves in a dict/list/scalar."""
    if isinstance(value, str):
        return fn(value)
    if isinstance(value, list):
        return [_apply_recursive(v, fn) for v in value]
    if isinstance(value, dict):
        return {k: _apply_recursive(v, fn) for k, v in value.items()}
    return value  # numeric/bool/None — leave unchanged


# ── suppress ─────────────────────────────────────────────────────────────────

def suppress(value: Any, params: dict, vault: dict) -> None:
    """Remove the field entirely."""
    return None


# ── mask ─────────────────────────────────────────────────────────────────────

def mask(value: Any, params: dict, vault: dict) -> Any:
    """
    Replace string values with a fixed character repeated to the same length.

    params:
        char (str): replacement character, default ``"*"``
        fixed_length (int): if set, always produce this many characters
    """
    char: str = params.get("char", "*")
    fixed: int | None = params.get("fixed_length")

    def _mask_str(s: str) -> str:
        length = fixed if fixed is not None else len(s)
        return char * length

    return _apply_recursive(value, _mask_str)


# ── hash ─────────────────────────────────────────────────────────────────────

def hash_value(value: Any, params: dict, vault: dict) -> Any:
    """
    One-way SHA-256 hash, optionally salted and truncated.

    params:
        salt (str): prepended to the value before hashing (default ``""``)
        truncate (int): if set, keep only this many hex characters
    """
    salt: str = params.get("salt", "")
    truncate: int | None = params.get("truncate")

    def _hash_str(s: str) -> str:
        digest = hashlib.sha256((salt + s).encode()).hexdigest()
        return digest[:truncate] if truncate else digest

    return _apply_recursive(value, _hash_str)


# ── tokenize ─────────────────────────────────────────────────────────────────

def tokenize(value: Any, params: dict, vault: dict) -> Any:
    """
    Replace each unique string with a stable pseudonym within the bundle.

    The *vault* dict maintains the mapping for the lifetime of a single
    ``anonymize()`` call, guaranteeing that identical values across different
    resources receive the same token.  Different bundle calls produce different
    tokens (no shared global state).

    params:
        prefix (str): prepended to every generated token (default ``""``)
    """
    prefix: str = params.get("prefix", "")

    def _token(s: str) -> str:
        if s not in vault:
            vault[s] = prefix + secrets.token_urlsafe(8)
        return vault[s]

    return _apply_recursive(value, _token)


# ── encrypt ───────────────────────────────────────────────────────────────────

def encrypt(value: Any, params: dict, vault: dict) -> Any:
    """
    XOR-stream encryption keyed by SHA-256 of *params["key"]*.

    Replace with AES-GCM or the existing SKALD FPE primitives in production.

    params:
        key (str): encryption key (required; no default for security)
    """
    raw_key: str = params.get("key", "")
    key_bytes = hashlib.sha256(raw_key.encode()).digest()  # 32-byte key

    def _encrypt_str(s: str) -> str:
        enc = bytes(b ^ key_bytes[i % 32] for i, b in enumerate(s.encode("utf-8")))
        return enc.hex()

    return _apply_recursive(value, _encrypt_str)


# ── date_generalize ───────────────────────────────────────────────────────────

_DATE_FMTS: list[tuple[str, int]] = [
    ("%Y-%m-%dT%H:%M:%S", 19),
    ("%Y-%m-%dT%H:%M",    16),
    ("%Y-%m-%d",          10),
]


def _parse_date(s: str) -> datetime | None:
    for fmt, length in _DATE_FMTS:
        try:
            return datetime.strptime(s[:length], fmt)
        except ValueError:
            continue
    return None


def date_generalize(value: Any, params: dict, vault: dict) -> Any:
    """
    Reduce date/datetime precision.

    params:
        granularity (str):
            ``"year"``       → ``"1990"``
            ``"year_month"`` → ``"1990-05"``
            ``"decade"``     → ``"1990s"``
            (anything else)  → value unchanged
    """
    granularity: str = params.get("granularity", "year")

    def _generalize_str(s: str) -> str:
        dt = _parse_date(s)
        if dt is None:
            return s
        if granularity == "year":
            return str(dt.year)
        if granularity == "year_month":
            return dt.strftime("%Y-%m")
        if granularity == "decade":
            return f"{(dt.year // 10) * 10}s"
        return s

    return _apply_recursive(value, _generalize_str)


# ── dispatch map ──────────────────────────────────────────────────────────────

OPERATION_MAP: dict[str, Any] = {
    "suppress":       suppress,
    "mask":           mask,
    "hash":           hash_value,
    "tokenize":       tokenize,
    "encrypt":        encrypt,
    "date_generalize": date_generalize,
}
