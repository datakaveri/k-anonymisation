"""Turn the manifest's saved keys and vaults into what skald_core takes.

The manifest says which saved key protects which column (`keys`: slot, column, kind) and which token
vaults the job reads or writes (`vaults`). The bytes arrive from KBS at slots key-NN. This module only
maps and checks; it never stores anything. Columns the manifest does not list get a fresh per-job key
made on the driver (sk.generate_keys), exactly as SKALD does.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .errors import JobError
from .kbs import KeyStore, KeyUnavailable

# skald_core's key sizes (KeyKind::len): a salt is 32 bytes, an AES or FPE key 16.
_LEN = {"hmac_salt": 32, "aes_key": 16, "fpe_key": 16}


def saved_keys(manifest: Dict[str, Any], store: KeyStore) -> Dict[str, Dict[str, bytes]]:
    """{kind: {column: bytes}} for the saved keys the manifest lists.

    KBS releases 32-byte resources. An AES or FPE key needs 16 bytes, so the first 16 are used (the
    registry's key material is uniformly random, so any prefix is as good as the whole).
    """
    header = {c for t in manifest["tables"] for c in t["header"]}
    out: Dict[str, Dict[str, bytes]] = {}
    seen = set()
    for k in manifest.get("keys", []):
        kind, col = k["kind"], k["column"]
        if kind == "vault_key":
            continue  # a vault's key is listed under `vaults`, not used on a column
        if kind not in _LEN or col not in header or (kind, col) in seen:
            raise JobError("MANIFEST_INVALID")
        seen.add((kind, col))
        try:
            raw = store.slot(k["slot"])
        except KeyUnavailable:
            raise JobError("KEY_UNAVAILABLE") from None
        out.setdefault(kind, {})[col] = raw[: _LEN[kind]]
    return out


def vault_specs(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The manifest's vaults, checked: one per column, a known mode, a slot."""
    specs = manifest.get("vaults", [])
    cols = [v["column"] for v in specs]
    if len(set(cols)) != len(cols):
        raise JobError("MANIFEST_INVALID")
    return specs
