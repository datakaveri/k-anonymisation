"""Flow B for the Spark job: the owner's encrypted bundle is in THEIR container (anonymous read), results go to
our staging. Two different directories, so reading the input from staging/{job}/ or writing next to the owner's
data fails these tests. Output must equal the flow A run of the same case byte for byte."""

import shutil
import sys
import types

import pytest

import corpus
from anamika_spark.io import AnonymousBlobStore, IoError, input_spec_from_env, split_container_url, with_input
from anamika_spark.job import run_job
from anamika_spark.testkit import read_result
from helpers import setup_case

CASE = [c for c in corpus.CASES if c not in ("preprocess_only", "pass1_grid")][0]


def test_input_from_owner_container_output_to_staging(spark, tmp_path):
    job, store, kbs = setup_case(tmp_path / "flow_a", CASE)
    assert run_job(job, "all", {"kind": "local", "root": str(tmp_path / "flow_a")}, kbs, spark=spark)["ok"]
    _, _, want, _ = read_result(store, job)

    work = tmp_path / "packing"
    job_b, _, kbs_b = setup_case(work, CASE)
    assert job_b == job
    owner = tmp_path / "owner"
    shutil.copytree(work / "staging" / job, owner / "2026-11")
    before = sorted(p.relative_to(owner).as_posix() for p in owner.rglob("*") if p.is_file())
    ours = tmp_path / "ours"
    spec = {"kind": "local", "root": str(ours), "input": {"kind": "local", "root": str(owner), "prefix": "2026-11"}}
    assert run_job(job, "all", spec, kbs_b, spark=spark)["ok"]

    from anamika_spark.io import LocalDirStore

    _, _, got, _ = read_result(LocalDirStore(ours), job)
    assert got == want
    assert sorted(p.relative_to(owner).as_posix() for p in owner.rglob("*") if p.is_file()) == before
    assert not (ours / "staging" / job / "manifest.enc").exists()


def test_missing_input_in_owner_container_fails_closed(spark, tmp_path):
    work = tmp_path / "packing"
    job, _, kbs = setup_case(work, CASE)
    owner = tmp_path / "owner"
    shutil.copytree(work / "staging" / job, owner / "2026-11")
    spec = {"kind": "local", "root": str(tmp_path / "ours"), "input": {"kind": "local", "root": str(owner), "prefix": "elsewhere"}}
    assert run_job(job, "all", spec, kbs, spark=spark)["ok"] is False


def test_env_mapping():
    base = {"kind": "azure", "url": "https://stg.blob.core.windows.net/anamika"}
    env = {"ANAMIKA_INPUT_URL": "https://owner.blob.core.windows.net/patients/2026-11/", "ANAMIKA_INPUT_ANONYMOUS": "1"}
    assert with_input(base, env)["input"] == {"kind": "azure-anon", "url": "https://owner.blob.core.windows.net/patients", "prefix": "2026-11"}
    assert with_input(base, {}) == base
    # A credential-bearing input is not implemented: fail closed instead of falling back to the VM identity.
    with pytest.raises(IoError):
        input_spec_from_env({"ANAMIKA_INPUT_URL": env["ANAMIKA_INPUT_URL"]})
    assert split_container_url("https://o.blob.core.windows.net/c") == ("https://o.blob.core.windows.net/c", "")
    for bad in ("https://o.blob.core.windows.net/c/../x/", "https://o.blob.core.windows.net/", "http://x"):
        with pytest.raises(IoError):
            split_container_url(bad)


def test_anonymous_store_has_no_credential_and_is_read_only(monkeypatch):
    seen = {}

    class FakeClient:
        @classmethod
        def from_container_url(cls, url, credential=None, **kw):
            seen.update(url=url, credential=credential, kw=kw)
            return cls()

    mod = types.ModuleType("azure.storage.blob")
    mod.ContainerClient = FakeClient
    for name in ("azure", "azure.storage"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    monkeypatch.setitem(sys.modules, "azure.storage.blob", mod)
    s = AnonymousBlobStore("https://owner.blob.core.windows.net/patients")
    assert seen["credential"] is None and "sas_token" not in seen["kw"]
    for call in (lambda: s.put("x", b"y"), lambda: s.delete("x")):
        with pytest.raises(IoError) as e:
            call()
        assert e.value.code == "READ_ONLY"
    with pytest.raises(IoError):  # a SAS smuggled into the URL would silently become a credential
        AnonymousBlobStore("https://owner.blob.core.windows.net/patients?sv=2024&sig=x")
