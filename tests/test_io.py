"""Blob IO: manifest checks, part reads, pending-then-publish outputs, vault versions."""

import json

import pytest

from anamika_spark import bundle
from anamika_spark.io import IoError, JobIO, LocalDirStore, read_vault, validate_manifest, write_vault
from anamika_spark.testkit import K_USER, pack_rows

JOB = "job-io-0001"
KEYS = bundle.Keys.from_user_key(K_USER)
CSV = b"a,b\n1,x\n2,y\n3,z\n4,w\n"


def test_read_manifest_and_parts(tmp_path):
    store = pack_rows(tmp_path, JOB, CSV, {"data_type": "t"}, parts=2)
    io = JobIO(store, JOB, KEYS)
    m = io.read_manifest()
    assert m["part_count"] == 2 and m["tables"][0]["header"] == ["a", "b"]
    assert io.list_parts() == [0, 1]
    assert io.read_part(0, 2) == b"1,x\n2,y\n"


def test_swapped_part_is_parts_mismatch(tmp_path):
    store = pack_rows(tmp_path, JOB, CSV, {"data_type": "t"}, parts=2)
    a, b = (store.get(f"staging/{JOB}/part-0000{i}.enc") for i in (0, 1))
    store.put(f"staging/{JOB}/part-00000.enc", b)
    store.put(f"staging/{JOB}/part-00001.enc", a)
    with pytest.raises(IoError) as e:
        JobIO(store, JOB, KEYS).read_part(0, 2)
    assert e.value.code == "PARTS_MISMATCH"


def test_manifest_of_another_job_is_refused(tmp_path):
    store = pack_rows(tmp_path, JOB, CSV, {"data_type": "t"})
    # Copy job A's manifest under job B: the AAD fails.
    other = "job-io-0002"
    store.put(f"staging/{other}/manifest.enc", store.get(f"staging/{JOB}/manifest.enc"))
    with pytest.raises(IoError) as e:
        JobIO(store, other, KEYS).read_manifest()
    assert e.value.code == "MANIFEST_INVALID"


def test_validate_manifest_rejects_gaps_and_files(tmp_path):
    base = {"bundle_version": 1, "job_id": JOB, "application": "kanon", "kind": "rows", "source_format": "csv",
            "part_count": 2, "config": {}, "tables": [{"name": "t", "header": ["a"], "parts": [
                {"part": 0, "rows": 1, "plaintext_bytes": 1, "plaintext_sha256": "0" * 64}]}]}
    with pytest.raises(IoError) as e:
        validate_manifest(base, JOB)  # part 1 missing from the table
    assert e.value.code == "MANIFEST_INVALID"
    files = {**base, "kind": "files", "files": []}
    files.pop("tables")
    with pytest.raises(IoError) as e:
        validate_manifest(files, JOB)
    assert e.value.code == "INVALID_INPUT"  # Ray's work, not Spark's


def test_pending_then_publish_and_discard(tmp_path):
    store = LocalDirStore(tmp_path)
    io = JobIO(store, JOB, KEYS)
    io.write_pending(0, 1, b"hello\n")
    assert store.list(f"staging/{JOB}/apply/") == [f"staging/{JOB}/apply/pending/part-00000.enc"]
    io.publish_output(0)
    assert io.read_output(0, 1) == b"hello\n"
    assert not store.list(f"staging/{JOB}/apply/pending/")
    io.write_status("apply", False, "K_CHECK_FAILED")
    assert json.loads(store.get(f"staging/{JOB}/apply/status.json")) == {"ok": False, "code": "K_CHECK_FAILED"}
    io.discard_phase("apply")
    assert not store.list(f"staging/{JOB}/apply/")


def test_vault_versions_are_never_overwritten(tmp_path):
    store, master = LocalDirStore(tmp_path), b"m" * 32
    assert read_vault(store, master, "v1", 0)["entries"] == {}
    write_vault(store, master, "v1", 1, "mrn", {"M1": "T-1"})
    assert read_vault(store, master, "v1", 1)["entries"] == {"M1": "T-1"}
    with pytest.raises(IoError):
        write_vault(store, master, "v1", 1, "mrn", {"M1": "other"})
    with pytest.raises(IoError):
        read_vault(store, b"x" * 32, "v1", 1)  # wrong vault key
    raw = store.get("vaults/v1/v1.enc")
    assert b"M1" not in raw and b"T-1" not in raw
