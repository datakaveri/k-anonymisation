"""Per-job keys are derived from K_user (contracts/bundle/README.md, "Column keys and token vaults").

Why it matters: explore_k runs measure and apply as two separate Spark jobs. If a hashed quasi-identifier got a
random key in each, measure would histogram different cells from the ones apply generalises.
"""

import copy
import json

import corpus
import pytest
from anamika_spark import bundle
from anamika_spark.io import JobIO
from anamika_spark.kbs import KeyStore
from anamika_spark.testkit import K_USER, fake_kbs, pack_rows, read_result
from helpers import run

# One vector shared with workloads/ray in anamika-control-plane (tests/test_kbs.py there): both must give this hex.
# K_user = bytes(range(32)), kind "hmac_salt", name "regno".
SHARED_VECTOR = "e137bd0f483f538f32cc2c6b8a1a82ce9c4a3ee25b1fe642424abe46ec4308d7"


def test_shared_cross_repo_vector():
    assert bundle.job_key(K_USER, "hmac_salt", "regno").hex() == SHARED_VECTOR


def test_key_is_32_bytes_and_depends_on_kind_name_and_k_user():
    a = bundle.job_key(K_USER, "hmac_salt", "id")
    assert len(a) == 32
    assert a != bundle.job_key(K_USER, "hmac_salt", "email")
    assert a != bundle.job_key(K_USER, "aes_key", "id")
    assert a != bundle.job_key(bytes(range(1, 33)), "hmac_salt", "id")
    assert a == bundle.job_key(K_USER, "hmac_salt", "id")


def test_two_k_users_get_different_keys_through_the_keystore():
    ka = KeyStore(fake_kbs("j-aaaaa", k_user=K_USER), "j-aaaaa")
    kb = KeyStore(fake_kbs("j-bbbbb", k_user=bytes(range(1, 33))), "j-bbbbb")
    assert ka.job_key("hmac_salt", "id") != kb.job_key("hmac_salt", "id")


def hashed_qi_config():
    """blood is both hashed and a quasi-identifier: its generalisation cells depend on the hash."""
    cfg = copy.deepcopy(corpus.case_config("basic_pass2"))
    t = cfg["tabular"]
    t["hashing_with_salt"] = ["id", "blood"]
    del t["categorical_hierarchies"]["blood"]
    return cfg


def pack(tmp_path, job, cfg):
    return pack_rows(tmp_path, job, corpus.case_data("basic_pass2"), cfg, parts=3)


def test_explore_k_measure_then_apply_equals_all_with_a_hashed_quasi_identifier(spark, tmp_path):
    cfg = hashed_qi_config()
    # `all`, grid only (pass1): the reference grid.
    ref_cfg = copy.deepcopy(cfg)
    ref_cfg["tabular"]["pass"] = "pass1"
    store = pack(tmp_path, "j-ref-grid", ref_cfg)
    assert run(spark, tmp_path, "j-ref-grid", fake_kbs("j-ref-grid"), "all")["ok"]
    ref_grid = JobIO(store, "j-ref-grid", bundle.Keys.from_user_key(K_USER)).read_summary("apply")["extra"]["grid"]

    # measure: a separate job with its own driver and no state from any other.
    store = pack(tmp_path, "j-hq-m", cfg)
    assert run(spark, tmp_path, "j-hq-m", fake_kbs("j-hq-m"), "measure")["ok"]
    grid = JobIO(store, "j-hq-m", bundle.Keys.from_user_key(K_USER)).read_summary("measure")["grid"]
    strip = lambda g: [{k: v for k, v in c.items() if k != "id"} for c in g]  # noqa: E731
    assert strip(grid) == strip(ref_grid)

    cell = next(c for c in grid if c["feasible"])
    # apply (same job id, as in production) must equal `all` run with that cell's k and limit.
    assert run(spark, tmp_path, "j-hq-m", fake_kbs("j-hq-m"), "apply", choice=cell["id"])["ok"]
    got = read_result(store, "j-hq-m")[2]
    all_cfg = copy.deepcopy(cfg)
    all_cfg["tabular"]["k_anonymize"]["k"] = cell["k"]
    all_cfg["tabular"]["suppression_limit"] = cell["suppression_limit"]
    store = pack(tmp_path, "j-hq-all", all_cfg)
    assert run(spark, tmp_path, "j-hq-all", fake_kbs("j-hq-all"), "all")["ok"]
    assert got == read_result(store, "j-hq-all")[2]


def test_different_k_user_hashes_a_quasi_identifier_differently(spark, tmp_path):
    cfg = hashed_qi_config()
    other = bytes(range(1, 33))
    outs = []
    for job, ku in (("j-hk-a", K_USER), ("j-hk-b", other)):
        store = pack_rows(tmp_path, job, corpus.case_data("basic_pass2"), cfg, parts=2, k_user=ku)
        assert run(spark, tmp_path, job, fake_kbs(job, k_user=ku), "all")["ok"]
        outs.append(read_result(store, job, ku)[2])
    assert outs[0] != outs[1]


def test_a_saved_key_overrides_the_derived_one(spark, tmp_path):
    listed, slots = corpus.case_keys("basic_pass2")
    cfg = copy.deepcopy(corpus.case_config("basic_pass2"))
    outs = {}
    for tag, saved in (("s", True), ("d", False)):
        job = f"j-ov-{tag}"
        store = pack_rows(tmp_path, job, corpus.case_data("basic_pass2"), cfg, parts=2, keys=listed if saved else None)
        assert run(spark, tmp_path, job, fake_kbs(job, **(slots if saved else {})), "all")["ok"]
        outs[tag] = read_result(store, job)[2]
    assert outs["s"] != outs["d"]
    assert outs["s"] == corpus.expected("basic_pass2")[0]  # saved keys are the CLI's, so the CLI's bytes
