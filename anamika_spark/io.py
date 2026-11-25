"""Encrypted reads and writes of a job's objects in Blob.

Layout (contracts/bundle/README.md):

    staging/{job}/manifest.enc  part-00000.enc ...
                  measure/histogram.enc  measure/summary.enc  measure/status.json
                  apply/part-NNNNN.enc   apply/summary.enc    apply/status.json
    vaults/{vault_id}/v{version}.enc      (token vaults; path prefix is configurable)

Vendored from anamika-ray (the store classes are identical, so both should later move to one
shared `anamika-bundle` package); the JobIO half is rows- and phase-oriented here.

BlobStore is the only thing that touches storage. AzureBlobStore is the
production one; LocalDirStore is a directory fake used by tests and local runs.
JobIO adds the crypto: every object is opened or sealed with the right key and
AAD, so a part cannot be swapped, replayed from another job or read under the
wrong role.

A failure while reading raises IoError with a short code, never a message that
could carry data.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol

from . import bundle
from .bundle import BundleError, Keys

_PART = re.compile(r"^part-(\d{5})\.enc$")


class IoError(RuntimeError):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}{': ' + detail if detail else ''}")
        self.code = code


class BlobStore(Protocol):
    def get(self, path: str) -> bytes: ...
    def put(self, path: str, data: bytes, content_type: str = "application/octet-stream") -> None: ...
    def list(self, prefix: str) -> List[str]:
        """Object paths under prefix (full paths, sorted), not directories."""
    def delete(self, path: str) -> None: ...


class LocalDirStore:
    """A directory acting as the container. Writes are atomic (temp file + rename), like a blob PUT."""

    def __init__(self, root):
        self.root = Path(root)

    def _p(self, path: str) -> Path:
        p = (self.root / path).resolve()
        if self.root.resolve() not in p.parents:
            raise IoError("BAD_PATH")
        return p

    def get(self, path: str) -> bytes:
        try:
            return self._p(path).read_bytes()
        except FileNotFoundError:
            raise IoError("NOT_FOUND", path) from None

    def put(self, path: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        p = self._p(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=".put-")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.replace(tmp, p)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def delete(self, path: str) -> None:
        self._p(path).unlink(missing_ok=True)

    def list(self, prefix: str) -> List[str]:
        base = self._p(prefix) if prefix else self.root
        if not base.exists():
            return []
        root = self.root.resolve()
        return sorted(p.relative_to(root).as_posix() for p in base.rglob("*") if p.is_file() and not p.name.startswith(".put-"))


class AzureBlobStore:
    """A Blob container through azure-storage-blob and the pod's managed identity.

    `container_url` is https://<account>.blob.core.windows.net/<container>. Not
    exercised by the unit tests (no network); the interface above is, through
    LocalDirStore, and the SDK calls here are the plain get/put/list ones.
    """

    def __init__(self, container_url: str, credential=None):
        from azure.identity import DefaultAzureCredential  # type: ignore
        from azure.storage.blob import ContainerClient  # type: ignore

        self._c = ContainerClient.from_container_url(container_url, credential=credential or DefaultAzureCredential())

    def get(self, path: str) -> bytes:
        from azure.core.exceptions import ResourceNotFoundError  # type: ignore

        try:
            return self._c.download_blob(path).readall()
        except ResourceNotFoundError:
            raise IoError("NOT_FOUND", path) from None

    def put(self, path: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        from azure.storage.blob import ContentSettings  # type: ignore

        self._c.upload_blob(path, data, overwrite=True, content_settings=ContentSettings(content_type=content_type))

    def delete(self, path: str) -> None:
        from azure.core.exceptions import ResourceNotFoundError  # type: ignore

        try:
            self._c.delete_blob(path)
        except ResourceNotFoundError:
            pass

    def list(self, prefix: str) -> List[str]:
        return sorted(b.name for b in self._c.list_blobs(name_starts_with=prefix))


def store_from_spec(spec: Dict[str, str]) -> BlobStore:
    """Rebuild a store inside a worker from a small picklable description."""
    if spec["kind"] == "local":
        return LocalDirStore(spec["root"])
    if spec["kind"] == "azure":
        return AzureBlobStore(spec["url"])
    raise IoError("BAD_STORE")


_REQUIRED = ("bundle_version", "job_id", "application", "kind", "source_format", "part_count", "config")


def validate_manifest(m: Any, job: str) -> Dict[str, Any]:
    """The checks a runtime needs before trusting a manifest (the JSON Schema is the full definition).

    job_id is compared with our own job on top of the AAD, so a manifest copied
    between jobs fails loudly even if someone re-sealed it.
    """
    if not isinstance(m, dict) or any(k not in m for k in _REQUIRED):
        raise IoError("MANIFEST_INVALID")
    if m["bundle_version"] != 1 or m["job_id"] != job:
        raise IoError("MANIFEST_INVALID")
    if not isinstance(m["part_count"], int) or not 1 <= m["part_count"] <= 99999 or not isinstance(m["config"], dict):
        raise IoError("MANIFEST_INVALID")
    if m["kind"] == "rows":
        tables = m.get("tables")
        if not isinstance(tables, list) or not tables or "files" in m:
            raise IoError("MANIFEST_INVALID")
        numbers = []
        for t in tables:
            if not isinstance(t, dict) or not isinstance(t.get("header"), list) or not t["header"] or not isinstance(t.get("parts"), list):
                raise IoError("MANIFEST_INVALID")
            for p in t["parts"]:
                if not isinstance(p, dict) or any(k not in p for k in ("part", "rows", "plaintext_bytes", "plaintext_sha256")):
                    raise IoError("MANIFEST_INVALID")
                numbers.append(p["part"])
        # Part numbers are global across tables and must cover 0..N-1 exactly once.
        if sorted(numbers) != list(range(m["part_count"])):
            raise IoError("MANIFEST_INVALID")
    elif m["kind"] == "files":
        raise IoError("INVALID_INPUT")  # files belong to Ray; Spark runs rows only
    else:
        raise IoError("MANIFEST_INVALID")
    return m


def _json(body: Dict[str, Any]) -> bytes:
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode()


class JobIO:
    """One job's objects. `keys` is only needed for the roles actually used (a worker holds input+output)."""

    def __init__(self, store: BlobStore, job: str, keys: Keys):
        self.store, self.job, self.keys = store, job, keys
        self.root = f"staging/{job}"

    # -- reading -----------------------------------------------------------
    def read_manifest(self) -> Dict[str, Any]:
        raw = self.store.get(f"{self.root}/manifest.enc")
        try:
            plain = bundle.open_(self.keys.manifest, raw, bundle.aad_manifest(self.job))
            return validate_manifest(json.loads(plain), self.job)
        except (BundleError, ValueError):
            raise IoError("MANIFEST_INVALID") from None

    def list_parts(self) -> List[int]:
        """Part numbers present under staging/{job}/ (top level only)."""
        found = []
        for name in self.store.list(self.root + "/"):
            rel = name[len(self.root) + 1 :]
            m = _PART.match(rel)
            if m and "/" not in rel:
                found.append(int(m.group(1)))
        return sorted(found)

    def read_part(self, n: int, total: int) -> bytes:
        raw = self.store.get(f"{self.root}/{bundle.part_name(n)}.enc")
        try:
            return bundle.open_(self.keys.input, raw, bundle.aad_input(self.job, n, total))
        except BundleError:
            raise IoError("PARTS_MISMATCH", bundle.part_name(n)) from None  # swapped, altered or replayed part

    # -- writing outputs ---------------------------------------------------
    # Outputs are first sealed under apply/pending/ and only moved to their final names once the
    # final k check has passed (publish_output). Numbering is by input part, so N is fixed up front
    # and the sealed bytes can be copied as they are.
    def write_pending(self, n: int, total: int, plaintext: bytes) -> None:
        self.store.put(f"{self.root}/apply/pending/{bundle.part_name(n)}.enc",
                       bundle.seal(self.keys.output, plaintext, bundle.aad_output(self.job, n, total)))

    def publish_output(self, n: int) -> None:
        raw = self.store.get(f"{self.root}/apply/pending/{bundle.part_name(n)}.enc")
        self.store.put(f"{self.root}/apply/{bundle.part_name(n)}.enc", raw)
        self.store.delete(f"{self.root}/apply/pending/{bundle.part_name(n)}.enc")

    def discard_phase(self, phase: str) -> None:
        """Remove everything a phase wrote (a failed run must leave no half result; a retry starts clean)."""
        for name in self.store.list(f"{self.root}/{phase}/"):
            self.store.delete(name)

    def write_summary(self, phase: str, summary: Dict[str, Any]) -> None:
        self.store.put(f"{self.root}/{phase}/summary.enc",
                       bundle.seal(self.keys.summary, _json(summary), bundle.aad_summary(self.job, phase, "summary")))

    def write_histogram(self, body: bytes) -> None:
        self.store.put(f"{self.root}/measure/histogram.enc",
                       bundle.seal(self.keys.summary, body, bundle.aad_summary(self.job, "measure", "histogram")))

    def read_histogram(self) -> bytes:
        try:
            return bundle.open_(self.keys.summary, self.store.get(f"{self.root}/measure/histogram.enc"),
                                bundle.aad_summary(self.job, "measure", "histogram"))
        except (BundleError, IoError):
            raise IoError("PARTS_MISMATCH", "histogram") from None  # barrier object missing or altered

    def write_status(self, phase: str, ok: bool, code: Optional[str] = None) -> None:
        """The one plaintext object. Never data, column names or file names; only ok and a short code."""
        body: Dict[str, Any] = {"ok": ok}
        if not ok:
            body["code"] = code or "JOB_FAILED"
        self.store.put(f"{self.root}/{phase}/status.json", json.dumps(body).encode(), "application/json")

    # -- reading results back (tests, and the owner's tooling) --------------
    def read_output(self, n: int, total: int) -> bytes:
        raw = self.store.get(f"{self.root}/apply/{bundle.part_name(n)}.enc")
        try:
            return bundle.open_(self.keys.output, raw, bundle.aad_output(self.job, n, total))
        except BundleError:
            raise IoError("PART_INVALID", bundle.part_name(n)) from None

    def read_summary(self, phase: str) -> Dict[str, Any]:
        raw = self.store.get(f"{self.root}/{phase}/summary.enc")
        try:
            return json.loads(bundle.open_(self.keys.summary, raw, bundle.aad_summary(self.job, phase, "summary")))
        except (BundleError, ValueError):
            raise IoError("SUMMARY_INVALID") from None


# -- token vaults ------------------------------------------------------------
def vault_path(vault_id: str, version: int, prefix: str = "vaults") -> str:
    if not re.match(r"^[A-Za-z0-9-]{1,64}$", vault_id):  # becomes part of a blob path
        raise IoError("INVALID_INPUT", "vault id")
    return f"{prefix}/{vault_id}/v{version}.enc"


def read_vault(store: BlobStore, vault_master: bytes, vault_id: str, version: int, prefix: str = "vaults") -> Dict[str, Any]:
    """Open vault version `version`. Version 0 is the empty vault and has no object."""
    if version == 0:
        return {"vault_id": vault_id, "version": 0, "entries": {}}
    try:
        raw = store.get(vault_path(vault_id, version, prefix))
        body = json.loads(bundle.open_(bundle.vault_key(vault_master), raw, bundle.aad_vault(vault_id, version)))
    except (BundleError, ValueError, IoError):
        raise IoError("INVALID_INPUT", "vault") from None
    if not isinstance(body, dict) or not isinstance(body.get("entries"), dict):
        raise IoError("INVALID_INPUT", "vault")
    return body


def write_vault(store: BlobStore, vault_master: bytes, vault_id: str, version: int, column: str,
                entries: Dict[str, str], prefix: str = "vaults") -> None:
    """Commit a NEW vault version. Never overwrites: a version that exists means two jobs forked the vault
    (the AO's lock should prevent that), and silently replacing it would lose tokens."""
    path = vault_path(vault_id, version, prefix)
    try:
        store.get(path)
    except IoError:
        pass
    else:
        raise IoError("INVALID_INPUT", "vault version exists")
    body = _json({"vault_id": vault_id, "version": version, "column": column, "entries": entries})
    store.put(path, bundle.seal(bundle.vault_key(vault_master), body, bundle.aad_vault(vault_id, version)))
