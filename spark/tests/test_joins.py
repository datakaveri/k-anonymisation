"""Multi-table bundles: SKALD's sheet joins on Spark, against the command line's recorded output.

The join corpus (SKALD/conformance/cases/join_*) is a workbook per case; the CLI's recorded output is the
joined, anonymised table (anonymized.csv) and, with restore_sheets, one CSV per restored sheet
(sheet.<name>.csv). The bundle holds each sheet as a table. Equality is BYTE for byte: the joined table
needs the CLI's row order, which is what a distributed join has to be made to reproduce.
"""

import copy
import csv
import io
import json
import sys

import pytest

import corpus
import refs  # noqa: F401 - keeps the sys.path setup in one place
from conftest import CORPUS
from anamika_spark import bundle, joins
from anamika_spark.errors import JobError
from anamika_spark.job import run_job
from anamika_spark.kbs import KeyStore
from anamika_spark.testkit import K_USER, fake_kbs, pack_tables, read_result, read_tables
from helpers import job_id, run, status, validator

sys.path.insert(0, str(CORPUS))
from xlsx_min import read_xlsx  # noqa: E402

JOIN_CASES = corpus.JOIN_CASES
RESTORING = [c for c in JOIN_CASES if corpus.case_config(c)["tabular"].get("restore_sheets")]
FLAT = [c for c in JOIN_CASES if c not in RESTORING]


def sheets(case):
    """{sheet: CSV bytes with header} of the case's workbook."""
    out = {}
    for name, rows in read_xlsx(CORPUS / "cases" / case / "data.xlsx"):
        buf = io.StringIO()
        csv.writer(buf, lineterminator="\n").writerows(rows)
        out[name] = buf.getvalue().encode()
    return out


def plan_of(case):
    tables = [(n, next(csv.reader(io.StringIO(b.decode())))) for n, b in sheets(case).items()]
    return joins.plan_tables(tables, joins.parse_sheet_joins(corpus.case_config(case)["tabular"]))


def keys_of(case, jp):
    """The corpus's test keys as saved keys, each filed under the table and column the user would know it by."""
    listed, slots = corpus.case_keys(case)
    for e in listed:
        if e["column"] in jp.columns:
            e["table"] = jp.origins[jp.columns.index(e["column"])][0]
    return [e for e in listed if "table" in e], slots


def setup(root, case, *, parts=3, tag=""):
    job = job_id(case, tag)
    jp = plan_of(case)
    listed, slots = keys_of(case, jp)
    store = pack_tables(root, job, sheets(case), corpus.case_config(case), parts=parts, keys=listed)
    return job, store, fake_kbs(job, **slots)


def expected_sheet(case, name):
    return (CORPUS / "expected" / case / f"sheet.{name}.csv").read_bytes()


def expected_table(case):
    return (CORPUS / "expected" / case / "anonymized.csv").read_bytes()


@pytest.mark.parametrize("case", JOIN_CASES)
def test_phase_all_equals_cli(spark, tmp_path, case):
    job, store, kbs = setup(tmp_path, case)
    r = run(spark, tmp_path, job, kbs, "all")
    assert r["ok"], r
    assert status(store, job, "apply") == {"ok": True}
    summary = None
    if case in RESTORING:
        got = read_tables(store, job)
        want = {n: expected_sheet(case, n) for n in got}
        assert sorted(got) == sorted(n for n in sheets(case) if (CORPUS / "expected" / case / f"sheet.{n}.csv").exists())
        assert got == want
    else:
        summary, header, got, _ = read_result(store, job)
        assert got == expected_table(case)
    summary = summary or __import__("anamika_spark.testkit", fromlist=["x"]).JobIO(
        store, job, bundle.Keys.from_user_key(K_USER)).read_summary("apply")
    validator("bundle-summary").validate(summary)
    exp = json.loads((CORPUS / "expected" / case / "status.json").read_text())["outputs"]
    if "removed_records" in exp:
        assert summary["suppressed"] == exp["removed_records"]
        assert summary["rows_in"] == exp["anonymisation_summary"]["total_records"]
    assert [t["name"] for t in summary["tables"]] == (list(got) if case in RESTORING else [plan_of(case).root])


@pytest.mark.parametrize("parts", [1, 3, 7])
@pytest.mark.parametrize("case", ["join_star_restore", "join_outer_flat", "join_right_qi"])
def test_part_count_does_not_change_the_output(spark, tmp_path, case, parts):
    """The input cut into 1, 3 or 7 parts per table: the file order the join has to reproduce does not move."""
    job, store, kbs = setup(tmp_path, case, parts=parts, tag=f"p{parts}")
    assert run(spark, tmp_path, job, kbs, "all")["ok"]
    if case in RESTORING:
        assert read_tables(store, job) == {n: expected_sheet(case, n) for n in read_tables(store, job)}
    else:
        assert read_result(store, job)[2] == expected_table(case)


def test_the_summary_lists_one_table_per_sheet_with_global_part_numbers(spark, tmp_path):
    case = "join_star_restore"
    job, store, kbs = setup(tmp_path, case)
    assert run(spark, tmp_path, job, kbs, "all")["ok"]
    from anamika_spark.io import JobIO

    s = JobIO(store, job, bundle.Keys.from_user_key(K_USER)).read_summary("apply")
    assert [t["name"] for t in s["tables"]] == ["patients", "visits", "hospitals"]
    assert [t["header"] for t in s["tables"]][1] == ["id", "visit_id", "visit_date", "diagnosis", "note"]
    numbers = [p["part"] for t in s["tables"] for p in t["parts"]]
    assert numbers == list(range(s["part_count"]))  # contiguous, across the tables, in table order
    assert s["extra"]["joined_rows"] == s["rows_out"] == 99 and s["extra"]["tables_in"] == 3
    assert not [n for n in store.list(f"staging/{job}/apply/") if "pending" in n]  # nothing left half-published


# ---------------------------------------------------------------- keys
def test_per_job_keys_are_named_table_slash_column(spark, tmp_path):
    """No saved keys: the job derives "<table>/<column>" of each column's origin. Reproduced by hand, the
    saved key of the same bytes under that name gives the same output; under the bare column it does not."""
    case = "join_inner_collide"
    jp = plan_of(case)
    assert jp.key_name("id") == "patients/id" and jp.key_name("note_y") == "visits/note"
    assert jp.key_name("note_x") == "patients/note" and jp.key_name("diagnosis") == "visits/diagnosis"

    def result(tag, listed, slots):
        job = job_id(case, tag)
        store = pack_tables(tmp_path, job, sheets(case), corpus.case_config(case), keys=listed)
        assert run(spark, tmp_path, job, fake_kbs(job, **slots), "all")["ok"]
        return read_tables(store, job)

    derived = result("d", [], {})
    mirrored = {"key_00": bundle.job_key(K_USER, "hmac_salt", "patients/id")}
    same = result("m", [{"slot": "key-00", "table": "patients", "column": "id", "kind": "hmac_salt"}], mirrored)
    assert derived == same
    bare = {"key_00": bundle.job_key(K_USER, "hmac_salt", "id")}
    other = result("b", [{"slot": "key-00", "table": "patients", "column": "id", "kind": "hmac_salt"}], bare)
    assert other["patients"] != derived["patients"]
    # A join key is ONE key for every sheet: a visit's id is the pseudonym of a patient in the patient sheet.
    rows = lambda t: list(csv.reader(io.StringIO(derived[t].decode())))[1:]  # noqa: E731
    assert rows("visits") and {r[0] for r in rows("visits")} <= {r[0] for r in rows("patients")}


def test_saved_key_by_either_sheet_finds_the_merged_column_but_not_both():
    jp = plan_of("join_inner_collide")
    assert jp.resolve("patients", "id") == "id" and jp.resolve("visits", "id") == "id"
    assert jp.resolve("visits", "note") == "note_y" and jp.resolve("patients", "note") == "note_x"
    assert jp.resolve("visits", "nope") is None and jp.resolve("nope", "id") is None
    assert jp.resolve(None, "visit_id") == "visit_id"  # a bare column is accepted when it is a merged column


def test_two_saved_keys_for_one_merged_column_are_refused(spark, tmp_path):
    case = "join_inner_collide"
    job = job_id(case, "dup")
    listed = [{"slot": "key-00", "table": "patients", "column": "id", "kind": "hmac_salt"},
              {"slot": "key-01", "table": "visits", "column": "id", "kind": "hmac_salt"}]
    pack_tables(tmp_path, job, sheets(case), corpus.case_config(case), keys=listed)
    r = run(spark, tmp_path, job, fake_kbs(job, key_00=bytes(32), key_01=bytes(range(32))), "all")
    assert r == {"ok": False, "code": "MANIFEST_INVALID"}


# ---------------------------------------------------------------- the plan, no Spark
def test_columns_and_provenance_follow_merge_two():
    jp = plan_of("join_star_restore")
    assert jp.columns == ["id", "name", "phone", "age", "pin", "gender", "blood", "hospital", "note_x",
                          "visit_id", "visit_date", "diagnosis", "note_y", "district", "beds"]
    assert jp.root == "patients" and jp.mode == "joins"
    assert [sc.sheet for sc in jp.restore] == ["patients", "visits", "hospitals"]
    visits = dict(jp.restore[1].columns)
    assert visits == {"id": "id", "visit_id": "visit_id", "visit_date": "visit_date", "diagnosis": "diagnosis", "note_y": "note"}
    assert dict(jp.restore[2].columns) == {"hospital": "hospital", "district": "district", "beds": "beds"}
    cross = plan_of("join_cross")
    assert cross.columns[7] == "hospital_x" and "hospital_y" in cross.columns


def test_a_plan_that_cannot_match_the_cli_is_refused():
    t = [("a", ["x", "y"]), ("b", ["p", "q"])]
    with pytest.raises(JobError):  # no shared column: the CLI pastes them side by side by row position
        joins.plan_tables(t, [])
    with pytest.raises(JobError):
        joins.plan_tables(t, [joins.SheetJoin("a", "zzz", ("x",))])
    with pytest.raises(JobError):
        joins.plan_tables(t, [joins.SheetJoin("a", "b", ("x",))])  # x is not in b
    with pytest.raises(JobError):
        joins.plan_tables([("a", ["x", "x"]), ("b", ["x"])], [joins.SheetJoin("a", "b", ("x",))])
    for bad in ({"sheet_joins": [{"left": "a", "right": "b"}]}, {"sheet_joins": [{"left": "a", "right": "b", "on": ["x"], "how": "sideways"}]},
                {"sheet_joins": ["a"]}):
        with pytest.raises(JobError):
            joins.parse_sheet_joins(bad)
    assert joins.parse_sheet_joins({"sheet_joins": [{"left": "a", "right": "b", "on": "x"}]}) == [joins.SheetJoin("a", "b", ("x",), "left")]


def test_refused_bundles_end_in_invalid_input(spark, tmp_path):
    job = job_id("noshared", "")
    cfg = copy.deepcopy(corpus.case_config("join_concat"))
    pack_tables(tmp_path, job, {"a": b"x,y\n1,2\n", "b": b"p,q\n3,4\n"}, cfg)
    assert run(spark, tmp_path, job, fake_kbs(job), "all") == {"ok": False, "code": "INVALID_INPUT"}


# ---------------------------------------------------------------- explore_k over a join
def test_measure_then_apply_over_a_join_equals_all(spark, tmp_path):
    case = "join_right_qi"
    job, store, kbs = setup(tmp_path, case, tag="x")
    r = run(spark, tmp_path, job, kbs, "measure")
    assert r["ok"], r
    assert not store.list(f"staging/{job}/apply/")
    from anamika_spark.io import JobIO

    grid = JobIO(store, job, bundle.Keys.from_user_key(K_USER)).read_summary("measure")["grid"]
    cell = [c for c in grid if c["feasible"]][0]
    r = run(spark, tmp_path, job, kbs, "apply", choice=cell["id"])
    assert r["ok"], r
    got = read_tables(store, job)

    cfg = copy.deepcopy(corpus.case_config(case))
    sec = cfg["tabular"]
    sec["k_anonymize"] = {"k": cell["k"]}
    sec["suppression_limit"] = cell["suppression_limit"]
    ref_job = job_id(case, "ref")
    listed, slots = keys_of(case, plan_of(case))
    ref_store = pack_tables(tmp_path, ref_job, sheets(case), cfg, keys=listed)
    assert run(spark, tmp_path, ref_job, fake_kbs(ref_job, **slots), "all")["ok"]
    assert read_tables(ref_store, ref_job) == got
