"""Every way an object can be wrong must end in a status code, and nothing may be published."""

import json

import pytest

from anamika_spark import bundle
from anamika_spark.kbs import FakeKbs
from anamika_spark.testkit import K_USER, fake_kbs, pack_rows
from helpers import run, setup_case, status

CASE = "original_flow"


def assert_failed(store, job, code):
    assert status(store, job, "apply") == {"ok": False, "code": code}
    assert [p for p in store.list(f"staging/{job}/apply/")] == [f"staging/{job}/apply/status.json"], "only status.json may exist"


def reseal_manifest(store, job, edit):
    ks = bundle.Keys.from_user_key(K_USER)
    m = json.loads(bundle.open_(ks.manifest, store.get(f"staging/{job}/manifest.enc"), bundle.aad_manifest(job)))
    edit(m)
    store.put(f"staging/{job}/manifest.enc", bundle.seal(ks.manifest, json.dumps(m).encode(), bundle.aad_manifest(job)))


def test_swapped_parts(spark, tmp_path):
    job, store, kbs = setup_case(tmp_path, CASE, tag="sw")
    a, b = store.get(f"staging/{job}/part-00000.enc"), store.get(f"staging/{job}/part-00001.enc")
    store.put(f"staging/{job}/part-00000.enc", b)
    store.put(f"staging/{job}/part-00001.enc", a)
    assert run(spark, tmp_path, job, kbs, "all") == {"ok": False, "code": "PARTS_MISMATCH"}
    assert_failed(store, job, "PARTS_MISMATCH")


def test_part_from_another_job(spark, tmp_path):
    job, store, kbs = setup_case(tmp_path, CASE, tag="aj")
    other = pack_rows(tmp_path, "j-other-job", b"a,b\n1,2\n", {}, parts=1)
    store.put(f"staging/{job}/part-00002.enc", other.get("staging/j-other-job/part-00000.enc"))
    assert run(spark, tmp_path, job, kbs, "all")["code"] == "PARTS_MISMATCH"
    assert_failed(store, job, "PARTS_MISMATCH")


def test_flipped_bit_in_a_part(spark, tmp_path):
    job, store, kbs = setup_case(tmp_path, CASE, tag="fb")
    raw = bytearray(store.get(f"staging/{job}/part-00001.enc"))
    raw[40] ^= 1
    store.put(f"staging/{job}/part-00001.enc", bytes(raw))
    assert run(spark, tmp_path, job, kbs, "all")["code"] == "PARTS_MISMATCH"
    assert_failed(store, job, "PARTS_MISMATCH")


def test_missing_part(spark, tmp_path):
    job, store, kbs = setup_case(tmp_path, CASE, tag="mp")
    store.delete(f"staging/{job}/part-00001.enc")
    assert run(spark, tmp_path, job, kbs, "all")["code"] == "PARTS_MISMATCH"
    assert_failed(store, job, "PARTS_MISMATCH")


def test_extra_part(spark, tmp_path):
    job, store, kbs = setup_case(tmp_path, CASE, tag="ep")
    store.put(f"staging/{job}/part-00003.enc", store.get(f"staging/{job}/part-00002.enc"))
    assert run(spark, tmp_path, job, kbs, "all")["code"] == "PARTS_MISMATCH"
    assert_failed(store, job, "PARTS_MISMATCH")


def test_manifest_of_another_job(spark, tmp_path):
    job, store, kbs = setup_case(tmp_path, CASE, tag="mj")
    other, ostore, _ = setup_case(tmp_path, "basic_pass2", tag="oj")
    store.put(f"staging/{job}/manifest.enc", ostore.get(f"staging/{other}/manifest.enc"))
    assert run(spark, tmp_path, job, kbs, "all")["code"] == "MANIFEST_INVALID"
    assert_failed(store, job, "MANIFEST_INVALID")


def test_resealed_manifest_naming_another_job(spark, tmp_path):
    job, store, kbs = setup_case(tmp_path, CASE, tag="rj")
    reseal_manifest(store, job, lambda m: m.update(job_id="j-someone-else"))
    assert run(spark, tmp_path, job, kbs, "all")["code"] == "MANIFEST_INVALID"
    assert_failed(store, job, "MANIFEST_INVALID")


def test_wrong_user_key_cannot_open_the_manifest(spark, tmp_path):
    job, store, _ = setup_case(tmp_path, CASE, tag="uk")
    kbs = fake_kbs(job, k_user=bytes(32))
    assert run(spark, tmp_path, job, kbs, "all")["code"] == "MANIFEST_INVALID"
    assert_failed(store, job, "MANIFEST_INVALID")


def test_manifest_row_count_that_does_not_match_the_part(spark, tmp_path):
    job, store, kbs = setup_case(tmp_path, CASE, tag="rc")
    reseal_manifest(store, job, lambda m: m["tables"][0]["parts"][1].update(rows=1))
    assert run(spark, tmp_path, job, kbs, "all")["code"] == "PARTS_MISMATCH"
    assert_failed(store, job, "PARTS_MISMATCH")


def test_manifest_digest_that_does_not_match_the_part(spark, tmp_path):
    job, store, kbs = setup_case(tmp_path, CASE, tag="dg")
    reseal_manifest(store, job, lambda m: m["tables"][0]["parts"][0].update(plaintext_sha256="0" * 64))
    assert run(spark, tmp_path, job, kbs, "all")["code"] == "PARTS_MISMATCH"
    assert_failed(store, job, "PARTS_MISMATCH")


def test_no_user_key(spark, tmp_path):
    job, store, _ = setup_case(tmp_path, CASE, tag="nk")
    assert run(spark, tmp_path, job, FakeKbs(), "all") == {"ok": False, "code": "KEY_UNAVAILABLE"}
    assert status(store, job, "apply") == {"ok": False, "code": "KEY_UNAVAILABLE"}


def test_saved_key_slot_not_released(spark, tmp_path):
    job, store, kbs = setup_case(tmp_path, CASE, tag="sk")
    del kbs.resources[(job, "key-00")]
    assert run(spark, tmp_path, job, kbs, "all")["code"] == "KEY_UNAVAILABLE"
    assert_failed(store, job, "KEY_UNAVAILABLE")


def test_multi_table_bundles_are_refused(spark, tmp_path):
    job, store, kbs = setup_case(tmp_path, CASE, tag="mt")
    def split(m):  # a valid two-table manifest: the last part moves to a second table
        t = m["tables"][0]
        m["tables"].append({"name": "t2", "header": t["header"], "parts": [t["parts"].pop()]})

    reseal_manifest(store, job, split)
    assert run(spark, tmp_path, job, kbs, "all") == {"ok": False, "code": "INVALID_INPUT"}
    assert_failed(store, job, "INVALID_INPUT")


def test_files_bundles_are_refused(spark, tmp_path):
    job, store, kbs = setup_case(tmp_path, CASE, tag="fl")

    def to_files(m):
        m.pop("tables")
        m.update(kind="files", files=[{"part": i, "path": f"f{i}", "plaintext_bytes": 0, "plaintext_sha256": "0" * 64} for i in range(3)])

    reseal_manifest(store, job, to_files)
    assert run(spark, tmp_path, job, kbs, "all")["code"] == "INVALID_INPUT"


def test_unsupported_application_and_bad_config(spark, tmp_path):
    job, store, kbs = setup_case(tmp_path, CASE, tag="ap")
    reseal_manifest(store, job, lambda m: m.update(application="dp"))
    assert run(spark, tmp_path, job, kbs, "all")["code"] == "INVALID_INPUT"
    job2, store2, kbs2 = setup_case(tmp_path, CASE, tag="bc")
    reseal_manifest(store2, job2, lambda m: m["config"]["tabular"].update(k_anonymize={"k": "five"}))
    assert run(spark, tmp_path, job2, kbs2, "all")["code"] == "INVALID_INPUT"
    assert_failed(store2, job2, "INVALID_INPUT")


def test_a_failed_job_leaves_a_clean_retry(spark, tmp_path):
    job, store, kbs = setup_case(tmp_path, CASE, tag="rt")
    good = store.get(f"staging/{job}/part-00001.enc")
    store.put(f"staging/{job}/part-00001.enc", store.get(f"staging/{job}/part-00000.enc"))
    assert not run(spark, tmp_path, job, kbs, "all")["ok"]
    store.put(f"staging/{job}/part-00001.enc", good)
    assert run(spark, tmp_path, job, kbs, "all")["ok"]
    assert status(store, job, "apply") == {"ok": True}
