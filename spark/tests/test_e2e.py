"""End to end in Spark local mode: pack a conformance case with the bundle code, run the job against a
local-directory blob store and a fake KBS, decrypt the output and compare it with the CLI's recorded
output (SKALD/conformance/expected). Same code path as a cluster; only the master differs.

Output equality is BYTE for byte, not row-set: parts are cut in file order and each executor keeps row
order inside a part, so concatenating the parts in part order gives the CLI's row order.
"""

import json

import pytest

import corpus
import refs
from anamika_spark import job as jobmod
from anamika_spark.io import JobIO
from anamika_spark.testkit import K_USER, read_result
from anamika_spark import bundle
from helpers import run, setup_case, status, validator

CASES = corpus.CASES
HAS_QI = [c for c in CASES if c not in ("preprocess_only",)]
APPLY_CASES = [c for c in HAS_QI if c != "pass1_grid"]


def _strip_id(cells):
    return [{k: v for k, v in c.items() if k != "id"} for c in cells]


@pytest.mark.parametrize("case", CASES)
def test_phase_all_equals_cli(spark, tmp_path, case):
    job, store, kbs = setup_case(tmp_path, case)
    r = run(spark, tmp_path, job, kbs, "all")
    assert r["ok"], r
    assert status(store, job, "apply") == {"ok": True}
    exp_bytes, exp = corpus.expected(case)
    summary, header, got, _ = read_result(store, job)
    validator("bundle-summary").validate(summary)
    if exp["pass"] == "pass1":
        # SKALD's pass 1 writes only the grid; here it rides in the summary and no output part exists.
        assert summary["part_count"] == 0
        assert _strip_id(summary["extra"]["grid"]) == exp["parameter_grid"]
        return
    assert got == exp_bytes
    if "final_rf" in exp:
        assert summary["extra"]["generalization_node"] == exp["final_rf"]
        assert summary["suppressed"] == exp["removed_records"]
        assert summary["rows_in"] == exp["anonymisation_summary"]["total_records"]
        assert summary["k"] == exp["anonymisation_summary"]["k"]
        assert summary["extra"]["min_class_size"] >= summary["k"]
    assert summary["rows_out"] == summary["rows_in"] - summary["suppressed"]


@pytest.mark.parametrize("parts", [1, 2, 7])
def test_part_count_does_not_change_the_output(spark, tmp_path, parts):
    case = "original_flow"
    job, store, kbs = setup_case(tmp_path, case, parts=parts, tag=f"p{parts}")
    assert run(spark, tmp_path, job, kbs, "all")["ok"]
    assert read_result(store, job)[2] == corpus.expected(case)[0]


@pytest.mark.skipif(refs.cli_binary() is None, reason="no skald_pipeline binary (set SKALD_BIN)")
@pytest.mark.parametrize("case", APPLY_CASES)
def test_measure_then_apply_equals_cli(spark, tmp_path, case):
    """explore_k: two jobs (two VMs in production). The user picks a grid cell; the apply job's output must be
    what the CLI writes for that cell's k and suppression limit. The grid's cells are fixed (k in 5/10/50/100,
    limit in 0/0.01/0.1), so the reference is the CLI run live with that k and limit."""
    job, store, kbs = setup_case(tmp_path, case, tag="x")
    r = run(spark, tmp_path, job, kbs, "measure")
    assert r["ok"], r
    assert status(store, job, "measure") == {"ok": True}
    assert not store.list(f"staging/{job}/apply/")  # the barrier: nothing of apply exists yet
    jio = JobIO(store, job, bundle.Keys.from_user_key(K_USER))
    m = jio.read_summary("measure")
    assert set(m) == {"summary_version", "grid", "extra"} and m["summary_version"] == 1
    assert all(isinstance(c["id"], str) and 0 < len(c["id"]) <= 200 for c in m["grid"])
    assert len({c["id"] for c in m["grid"]}) == len(m["grid"])
    feasible = [c for c in m["grid"] if c["feasible"]]
    assert feasible, "every corpus case has a feasible cell"
    for cell in (feasible[0], feasible[-1]):
        rc, expected = refs.cli_for_cell(case, cell["k"], cell["suppression_limit"])
        assert rc == 0
        r = run(spark, tmp_path, job, kbs, "apply", choice=cell["id"])
        assert r["ok"], r
        summary, _, got, _ = read_result(store, job)
        validator("bundle-summary").validate(summary)
        assert got == expected
        assert summary["extra"]["choice"] == cell["id"] and summary["k"] == cell["k"]


def test_measure_grid_equals_cli_grid(spark, tmp_path):
    job, store, kbs = setup_case(tmp_path, "pass1_grid")
    assert run(spark, tmp_path, job, kbs, "measure")["ok"]
    m = JobIO(store, job, bundle.Keys.from_user_key(K_USER)).read_summary("measure")
    assert _strip_id(m["grid"]) == corpus.expected("pass1_grid")[1]["parameter_grid"]


def test_apply_refuses_an_unknown_or_infeasible_choice(spark, tmp_path):
    job, store, kbs = setup_case(tmp_path, "original_flow", tag="c")
    assert run(spark, tmp_path, job, kbs, "measure")["ok"]
    infeasible = next(c["id"] for c in JobIO(store, job, bundle.Keys.from_user_key(K_USER)).read_summary("measure")["grid"]
                      if not c["feasible"])
    for bad in ("nope", infeasible):
        r = run(spark, tmp_path, job, kbs, "apply", choice=bad)
        assert r == {"ok": False, "code": "INVALID_INPUT"}
        assert status(store, job, "apply") == {"ok": False, "code": "INVALID_INPUT"}
        assert not [p for p in store.list(f"staging/{job}/apply/") if p.endswith(".enc")]
    assert run(spark, tmp_path, job, kbs, "apply")["code"] == "INVALID_INPUT"  # no choice at all


def test_apply_without_measure_fails_closed(spark, tmp_path):
    job, store, kbs = setup_case(tmp_path, "original_flow", tag="nm")
    r = run(spark, tmp_path, job, kbs, "apply", choice="k5-s0.05")
    assert r["ok"] is False and r["code"] == "PARTS_MISMATCH"


def test_measure_with_nothing_to_measure_is_invalid_input(spark, tmp_path):
    job, store, kbs = setup_case(tmp_path, "preprocess_only", tag="m")
    assert run(spark, tmp_path, job, kbs, "measure") == {"ok": False, "code": "INVALID_INPUT"}


def test_a_retry_starts_clean(spark, tmp_path):
    job, store, kbs = setup_case(tmp_path, "original_flow", tag="r")
    store.put(f"staging/{job}/apply/part-00009.enc", b"stale")
    store.put(f"staging/{job}/apply/status.json", b'{"ok":false,"code":"X"}')
    assert run(spark, tmp_path, job, kbs, "all")["ok"]
    assert status(store, job, "apply") == {"ok": True}
    assert not any(p.endswith("part-00009.enc") for p in store.list(f"staging/{job}/apply/"))


def test_final_k_check_fails_closed(spark, tmp_path, monkeypatch):
    """If the written rows do not meet k nothing is published: no output, no summary, status says why."""
    from skald_core import SkaldError

    job, store, kbs = setup_case(tmp_path, "original_flow", tag="k")
    monkeypatch.setattr(jobmod, "_verify", lambda tally, k: tally.verify(10_000))
    r = run(spark, tmp_path, job, kbs, "all")
    assert r == {"ok": False, "code": "K_CHECK_FAILED"}
    assert status(store, job, "apply") == {"ok": False, "code": "K_CHECK_FAILED"}
    assert [p for p in store.list(f"staging/{job}/apply/")] == [f"staging/{job}/apply/status.json"]


def test_every_output_object_is_sealed_and_summary_is_schema_valid(spark, tmp_path):
    job, store, kbs = setup_case(tmp_path, "basic_pass2", tag="s")
    assert run(spark, tmp_path, job, kbs, "all")["ok"]
    for name in store.list(f"staging/{job}/apply/"):
        if name.endswith(".enc"):
            raw = store.get(name)
            assert raw[:5] == b"ANAM\x01" and b"Hypertension" not in raw and b"P10" not in raw
    summary, _, _, plains = read_result(store, job)
    for p, plain in zip(summary["tables"][0]["parts"], plains):
        import hashlib

        assert p["plaintext_bytes"] == len(plain) and p["plaintext_sha256"] == hashlib.sha256(plain).hexdigest()
    assert [p["part"] for p in summary["tables"][0]["parts"]] == list(range(summary["part_count"]))


def test_no_row_content_in_driver_logs(spark, tmp_path, caplog):
    job, store, kbs = setup_case(tmp_path, "basic_pass2", tag="l")
    with caplog.at_level("DEBUG"):
        run(spark, tmp_path, job, kbs, "all")
        # A failing run too: a bad manifest must not echo anything either.
        store.put(f"staging/{job}/part-00001.enc", store.get(f"staging/{job}/part-00000.enc"))
        run(spark, tmp_path, job, kbs, "all")
    text = "\n".join(r.getMessage() for r in caplog.records)
    for needle in ("Rahul", "rahul.nair", "P1000", "Hypertension", "560100"):
        assert needle not in text
