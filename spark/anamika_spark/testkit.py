"""Pack, run and open bundles locally: for tests and the benchmark wrapper, not for production.

pack_rows() is a small Python port of what the browser and the `anamika-bundle` CLI do (cut a CSV
into parts at row boundaries with a real CSV parser, seal each part and the manifest), so a job can
be exercised end to end without them. Synthetic data only.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from typing import Any, Dict, List, Optional

from . import bundle
from .io import JobIO, LocalDirStore
from .kbs import FakeKbs

K_USER = bytes(range(32))


def read_csv_rows(data: bytes):
    """(header, rows) of a CSV with a header, parsed by a real CSV parser."""
    reader = csv.reader(io.StringIO(data.decode("utf-8"), newline=""))
    header = next(reader)
    return header, [r for r in reader]


def pack_rows(root, job: str, csv_bytes: bytes, config: Dict[str, Any], *, parts: int = 3, k_user: bytes = K_USER,
              keys: Optional[List[Dict[str, str]]] = None, vaults: Optional[List[Dict[str, Any]]] = None,
              ner: bool = False, table: str = "data", application: str = "kanon") -> LocalDirStore:
    """Write staging/{job}/manifest.enc and part-NNNNN.enc under `root`; returns the store."""
    header, rows = read_csv_rows(csv_bytes)
    store = LocalDirStore(root)
    ks = bundle.Keys.from_user_key(k_user)
    per = max(1, -(-len(rows) // parts))
    chunks = [rows[i:i + per] for i in range(0, len(rows), per)] or [[]]
    entries = []
    for n, chunk in enumerate(chunks):
        buf = io.StringIO()
        csv.writer(buf, lineterminator="\n").writerows(chunk)
        plain = buf.getvalue().encode()
        entries.append({"part": n, "rows": len(chunk), "plaintext_bytes": len(plain),
                        "plaintext_sha256": hashlib.sha256(plain).hexdigest()})
        store.put(f"staging/{job}/{bundle.part_name(n)}.enc",
                  bundle.seal(ks.input, plain, bundle.aad_input(job, n, len(chunks))))
    manifest: Dict[str, Any] = {"bundle_version": 1, "job_id": job, "application": application, "kind": "rows",
                                "source_format": "csv", "part_count": len(chunks), "config": config,
                                "tables": [{"name": table, "header": header, "parts": entries}],
                                "created_by": "anamika-spark-testkit/0.1.0"}
    if keys:
        manifest["keys"] = keys
    if vaults:
        manifest["vaults"] = vaults
    if ner:
        manifest["ner"] = {"required": True}
    store.put(f"staging/{job}/manifest.enc",
              bundle.seal(ks.manifest, json.dumps(manifest).encode(), bundle.aad_manifest(job)))
    return store


def pack_tables(root, job: str, tables: Dict[str, bytes], config: Dict[str, Any], *, parts: int = 3,
                k_user: bytes = K_USER, keys: Optional[List[Dict[str, str]]] = None, vaults: Optional[List[Dict[str, Any]]] = None,
                source_format: str = "xlsx", application: str = "kanon") -> LocalDirStore:
    """pack_rows for a multi-table bundle: `tables` is {name: CSV bytes with a header row}, each cut into
    `parts` parts; part numbers run across the tables in order (the contract's global numbering)."""
    store = LocalDirStore(root)
    ks = bundle.Keys.from_user_key(k_user)
    cut = []
    for name, csv_bytes in tables.items():
        header, rows = read_csv_rows(csv_bytes)
        per = max(1, -(-len(rows) // parts))
        cut.append((name, header, [rows[i:i + per] for i in range(0, len(rows), per)] or [[]]))
    total = sum(len(c) for _, _, c in cut)
    n, manifest_tables = 0, []
    for name, header, chunks in cut:
        entries = []
        for chunk in chunks:
            buf = io.StringIO()
            csv.writer(buf, lineterminator="\n").writerows(chunk)
            plain = buf.getvalue().encode()
            entries.append({"part": n, "rows": len(chunk), "plaintext_bytes": len(plain),
                            "plaintext_sha256": hashlib.sha256(plain).hexdigest()})
            store.put(f"staging/{job}/{bundle.part_name(n)}.enc", bundle.seal(ks.input, plain, bundle.aad_input(job, n, total)))
            n += 1
        manifest_tables.append({"name": name, "header": header, "parts": entries})
    manifest: Dict[str, Any] = {"bundle_version": 1, "job_id": job, "application": application, "kind": "rows",
                                "source_format": source_format, "part_count": total, "config": config,
                                "tables": manifest_tables, "created_by": "anamika-spark-testkit/0.1.0"}
    if keys:
        manifest["keys"] = keys
    if vaults:
        manifest["vaults"] = vaults
    store.put(f"staging/{job}/manifest.enc",
              bundle.seal(ks.manifest, json.dumps(manifest).encode(), bundle.aad_manifest(job)))
    return store


def fake_kbs(job: str, k_user: bytes = K_USER, **slots: bytes) -> FakeKbs:
    """A KBS holding K_user and any key-NN slots given as key_00=..., key_01=..."""
    kbs = FakeKbs()
    kbs.put(job, "user-key", k_user)
    for name, value in slots.items():
        kbs.put(job, name.replace("_", "-"), value)
    return kbs


def read_result(store, job: str, k_user: bytes = K_USER):
    """Open apply/summary.enc and every output part: (summary, header, csv bytes with header, per-part plaintexts)."""
    jio = JobIO(store, job, bundle.Keys.from_user_key(k_user))
    summary = jio.read_summary("apply")
    n = summary["part_count"]
    plains = [jio.read_output(i, n) for i in range(n)]
    header = summary["tables"][0]["header"] if summary.get("tables") else []
    buf = io.StringIO()
    csv.writer(buf, lineterminator="\n").writerow(header)
    return summary, header, buf.getvalue().encode() + b"".join(plains), plains


def read_tables(store, job: str, k_user: bytes = K_USER):
    """{table name: CSV bytes with header} from a result's summary: each table's parts, in part order."""
    jio = JobIO(store, job, bundle.Keys.from_user_key(k_user))
    summary = jio.read_summary("apply")
    n = summary["part_count"]
    out = {}
    for t in summary["tables"]:
        buf = io.StringIO()
        csv.writer(buf, lineterminator="\n").writerow(t["header"])
        out[t["name"]] = buf.getvalue().encode() + b"".join(jio.read_output(p["part"], n) for p in t["parts"])
    return out
