"""Saved keys and token vaults: reuse across jobs, the vault commit rules, and what a missing token does."""

import copy
import csv
import io
import json

import corpus
from anamika_spark import bundle
from anamika_spark.io import read_vault
from anamika_spark.testkit import K_USER, fake_kbs, pack_rows, read_result
from helpers import run, status

CASE = "basic_pass2"
MASTER = bytes(range(100, 132))     # a vault key as KBS releases it (32 bytes)


def config():
    cfg = copy.deepcopy(corpus.case_config(CASE))
    cfg["tabular"]["tokenization"] = [{"column": "diagnosis", "prefix": "D-", "digits": 4}]
    return cfg


def make(root, job, *, vaults=None, saved=True, vault_slot_data=MASTER):
    listed, slots = corpus.case_keys(CASE)
    n = len(listed)
    store = pack_rows(root, job, corpus.case_data(CASE), config(), parts=3, keys=listed if saved else None,
                      vaults=[{**v, "slot": f"key-{n:02d}"} for v in vaults] if vaults else None)
    kbs = fake_kbs(job, **(slots if saved else {}), **({f"key_{n:02d}": vault_slot_data} if vaults else {}))
    return store, kbs


def output_rows(store, job):
    _, header, data, _ = read_result(store, job)
    return list(csv.reader(io.StringIO(data.decode())))


def test_tokens_are_consistent_and_a_vault_version_is_committed(spark, tmp_path):
    job = "j-vault-write"
    store, kbs = make(tmp_path, job, vaults=[{"vault_id": "vlt-1", "column": "diagnosis", "mode": "write", "base_version": 0}])
    r = run(spark, tmp_path, job, kbs, "all")
    assert r["ok"], r
    rows = output_rows(store, job)
    col = rows[0].index("diagnosis")
    tokens = [r_[col] for r_ in rows[1:]]
    assert all(t.startswith("D-") and len(t) == 6 for t in tokens)
    vault = read_vault(store, MASTER, "vlt-1", 1)
    assert vault["version"] == 1 and vault["column"] == "diagnosis"
    assert set(vault["entries"].values()) >= set(tokens)
    assert len(set(vault["entries"].values())) == len(vault["entries"]), "one token per value"
    raw = store.get("vaults/vlt-1/v1.enc")
    assert b"Hypertension" not in raw
    # The vault is never part of the job's output.
    assert not [p for p in store.list(f"staging/{job}/") if "vlt-1" in p]


def test_a_second_job_reuses_the_vault_and_the_saved_keys(spark, tmp_path):
    a, b = "j-vault-first", "j-vault-second"
    store, kbs = make(tmp_path, a, vaults=[{"vault_id": "vlt-2", "column": "diagnosis", "mode": "write", "base_version": 0}])
    assert run(spark, tmp_path, a, kbs, "all")["ok"]
    store_b, kbs_b = make(tmp_path, b, vaults=[{"vault_id": "vlt-2", "column": "diagnosis", "mode": "read", "base_version": 1}])
    assert run(spark, tmp_path, b, kbs_b, "all")["ok"]
    assert read_result(store, a)[2] == read_result(store_b, b)[2], "same data, same saved keys, same vault: same output"
    # Reading never writes a new version.
    assert not store_b.list("vaults/vlt-2/v2.enc")


def test_write_mode_extends_the_vault_to_the_next_version(spark, tmp_path):
    a, b = "j-vault-v1", "j-vault-v2"
    store, kbs = make(tmp_path, a, vaults=[{"vault_id": "vlt-3", "column": "diagnosis", "mode": "write", "base_version": 0}])
    assert run(spark, tmp_path, a, kbs, "all")["ok"]
    _, kbs_b = make(tmp_path, b, vaults=[{"vault_id": "vlt-3", "column": "diagnosis", "mode": "write", "base_version": 1}])
    assert run(spark, tmp_path, b, kbs_b, "all")["ok"]
    assert read_vault(store, MASTER, "vlt-3", 2)["entries"] == read_vault(store, MASTER, "vlt-3", 1)["entries"]


def test_read_mode_with_an_unknown_value_fails_with_token_missing(spark, tmp_path):
    a, b = "j-vault-seed", "j-vault-short"
    store, kbs = make(tmp_path, a, vaults=[{"vault_id": "vlt-4", "column": "diagnosis", "mode": "write", "base_version": 0}])
    assert run(spark, tmp_path, a, kbs, "all")["ok"]
    from anamika_spark.io import write_vault

    # Version 2 holds only one value, so reading it cannot cover the data.
    write_vault(store, MASTER, "vlt-4", 2, "diagnosis", {"Asthma": "D-0001"})
    store_b, kbs_b = make(tmp_path, b, vaults=[{"vault_id": "vlt-4", "column": "diagnosis", "mode": "read", "base_version": 2}])
    r = run(spark, tmp_path, b, kbs_b, "all")
    assert r == {"ok": False, "code": "TOKEN_MISSING"}
    assert status(store_b, b, "apply") == {"ok": False, "code": "TOKEN_MISSING"}


def test_a_failed_job_does_not_commit_a_vault_version(spark, tmp_path):
    job = "j-vault-fail"
    store, kbs = make(tmp_path, job, vaults=[{"vault_id": "vlt-5", "column": "diagnosis", "mode": "write", "base_version": 0}])
    store.put(f"staging/{job}/part-00001.enc", store.get(f"staging/{job}/part-00000.enc"))
    assert not run(spark, tmp_path, job, kbs, "all")["ok"]
    assert not store.list("vaults/")


def test_measure_never_commits_a_vault(spark, tmp_path):
    job = "j-vault-measure"
    store, kbs = make(tmp_path, job, vaults=[{"vault_id": "vlt-6", "column": "diagnosis", "mode": "write", "base_version": 0}])
    assert run(spark, tmp_path, job, kbs, "measure")["ok"]
    assert not store.list("vaults/")


def test_wrong_vault_key_is_invalid_input(spark, tmp_path):
    a, b = "j-vault-ok", "j-vault-wrongkey"
    store, kbs = make(tmp_path, a, vaults=[{"vault_id": "vlt-7", "column": "diagnosis", "mode": "write", "base_version": 0}])
    assert run(spark, tmp_path, a, kbs, "all")["ok"]
    _, kbs_b = make(tmp_path, b, vaults=[{"vault_id": "vlt-7", "column": "diagnosis", "mode": "read", "base_version": 1}],
                    vault_slot_data=bytes(32))
    assert run(spark, tmp_path, b, kbs_b, "all")["code"] == "INVALID_INPUT"


def test_saved_keys_give_the_same_pseudonym_in_two_jobs_and_per_job_keys_do_not(spark, tmp_path):
    outs = {}
    for tag, saved in (("a", True), ("b", True), ("c", False), ("d", False)):
        job = f"j-keys-{tag}"
        store, kbs = make(tmp_path, job, saved=saved)
        assert run(spark, tmp_path, job, kbs, "all")["ok"]
        rows = output_rows(store, job)
        outs[tag] = {c: [r[rows[0].index(c)] for r in rows[1:]] for c in ("id", "email", "phone")}
    assert outs["a"] == outs["b"]
    for c in ("id", "email"):
        assert outs["c"][c] != outs["d"][c], "keys generated per job differ between jobs"
        assert outs["c"][c] != outs["a"][c]
