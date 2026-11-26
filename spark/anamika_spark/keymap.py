"""Turn the manifest's saved keys and vaults into what skald_core takes.

The manifest says which saved key protects which column (`keys`: slot, column, kind) and which token
vaults the job reads or writes (`vaults`). The bytes arrive from KBS at slots key-NN. This module only
maps and checks; it never stores anything. Columns the manifest does not list get the contract's per-job
key, derived from K_user (bundle.job_key), not a random one: measure and apply are separate Spark jobs and
must hash a quasi-identifier identically, and so must every executor.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .errors import JobError
from .kbs import KeyStore, KeyUnavailable

# skald_core's key sizes (KeyKind::len): a salt is 32 bytes, an AES or FPE key 16. Key material is 32 bytes
# everywhere in the contract (derived, saved, released), so a 16-byte user takes the FIRST 16 bytes.
_LEN = {"hmac_salt": 32, "aes_key": 16, "fpe_key": 16}


def _merged_column(entry: Dict[str, Any], jp, header) -> Optional[str]:
    """The column of the (merged) table a manifest entry names. A single-table bundle: the column itself.
    A multi-table one: `table` + `column` as the user knows them, resolved through the join plan."""
    if jp is None or len(jp.tables) == 1:
        return entry["column"] if entry["column"] in header else None
    return jp.resolve(entry.get("table"), entry["column"])


def saved_keys(manifest: Dict[str, Any], store: KeyStore, jp=None) -> Dict[str, Dict[str, bytes]]:
    """{kind: {merged column: bytes}} for the saved keys the manifest lists.

    KBS releases 32-byte resources. An AES or FPE key needs 16 bytes, so the first 16 are used, as
    contracts/bundle/README.md prescribes ("an application that needs a shorter key takes the first N bytes").
    """
    header = {c for t in manifest["tables"] for c in t["header"]}
    out: Dict[str, Dict[str, bytes]] = {}
    seen = set()
    for k in manifest.get("keys", []):
        kind = k["kind"]
        if kind == "vault_key":
            continue  # a vault's key is listed under `vaults`, not used on a column
        col = _merged_column(k, jp, header)
        if kind not in _LEN or col is None or (kind, col) in seen:
            raise JobError("MANIFEST_INVALID")
        seen.add((kind, col))
        try:
            raw = store.slot(k["slot"])
        except KeyUnavailable:
            raise JobError("KEY_UNAVAILABLE") from None
        out.setdefault(kind, {})[col] = raw[: _LEN[kind]]
    return out


def vault_specs(manifest: Dict[str, Any], jp=None) -> List[Dict[str, Any]]:
    """The manifest's vaults, checked: one per column, a known mode, a slot. `column` is returned as the
    merged table's column (a multi-table bundle names it by table and column)."""
    header = {c for t in manifest["tables"] for c in t["header"]}
    specs = []
    for v in manifest.get("vaults", []):
        col = _merged_column(v, jp, header)
        if col is None:
            raise JobError("MANIFEST_INVALID")
        specs.append({**v, "column": col})
    cols = [v["column"] for v in specs]
    if len(set(cols)) != len(cols):
        raise JobError("MANIFEST_INVALID")
    return specs


def job_keys(plan, manifest: Dict[str, Any], store: KeyStore, jp=None) -> Dict[str, Dict[str, bytes]]:
    """Every key the plan needs, {kind: {column: bytes}}: saved keys from KBS slots override, the rest are
    derived per job from K_user (contract: info "anamika/v1 job-key <kind> <name>", name = the column, or
    "<table>/<column>" of the column's origin when the bundle has several tables: JoinPlan.key_name).

    The result is complete, so sk.generate_keys has nothing left to invent; nothing here is random.
    """
    keys = saved_keys(manifest, store, jp)
    for kind, col in plan.required_keys():
        if col in keys.get(kind, {}):
            continue
        name = jp.key_name(col) if jp is not None and col in jp.columns else col
        keys.setdefault(kind, {})[col] = store.job_key(kind, name)[: _LEN[kind]]  # first 16 for AES/FPE
    return keys
