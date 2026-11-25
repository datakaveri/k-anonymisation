"""NER inside the job: free text is redacted on the executors before anything else sees it."""

import copy
import csv
import io

import pytest

pytest.importorskip("anamika_ner")

import corpus
from anamika_spark.ner import NerSettings
from anamika_spark.testkit import fake_kbs, pack_rows, read_result
from fake_ner import FakeEngine, make_models
from helpers import run, status


def data():
    rows = list(csv.reader(io.StringIO(corpus.case_data("preprocess_only").decode())))
    head, body = rows[0], rows[1:]
    note = head.index("note")
    for i, r in enumerate(body):
        r[note] = f"Alice met Bob, case {i}"
    buf = io.StringIO()
    csv.writer(buf, lineterminator="\n").writerows([head] + body)
    return buf.getvalue().encode()


def config():
    cfg = copy.deepcopy(corpus.case_config("preprocess_only"))
    sec = cfg[cfg["data_type"]]
    sec.pop("masking", None)          # the free-text step, not masking, handles this column
    sec["free_text_anonymization"] = {"enabled": True, "columns": ["note"]}
    return cfg


def make(tmp_path, job, *, ner_required=True):
    listed, slots = corpus.case_keys("preprocess_only")
    store = pack_rows(tmp_path, job, data(), config(), parts=3, keys=listed, ner=ner_required)
    return store, fake_kbs(job, **slots)


def test_free_text_is_redacted(spark, tmp_path):
    d, pin = make_models(tmp_path)
    job = "j-ner-on"
    store, kbs = make(tmp_path, job)
    r = run(spark, tmp_path, job, kbs, "all", ner=NerSettings(str(d), pin, engine_factory=FakeEngine))
    assert r["ok"], r
    summary, header, got, _ = read_result(store, job)
    rows = list(csv.reader(io.StringIO(got.decode())))
    note = rows[0].index("note")
    assert [r_[note] for r_ in rows[1:4]] == [f"[PERSON] met [PERSON], case {i}" for i in range(3)]
    assert b"Alice" not in got and b"Bob" not in got
    assert summary["extra"]["ner"] is True


def test_manifest_asking_for_ner_without_a_model_fails(spark, tmp_path):
    job = "j-ner-nomodel"
    store, kbs = make(tmp_path, job)
    assert run(spark, tmp_path, job, kbs, "all") == {"ok": False, "code": "INVALID_INPUT"}
    assert status(store, job, "apply") == {"ok": False, "code": "INVALID_INPUT"}


def test_no_ner_when_the_manifest_does_not_ask(spark, tmp_path):
    job = "j-ner-off"
    store, kbs = make(tmp_path, job, ner_required=False)
    assert run(spark, tmp_path, job, kbs, "all")["ok"]
    assert b"Alice met Bob" in read_result(store, job)[2]  # untouched: the AO's word alone never turns NER on or off


def test_a_model_that_does_not_match_its_pin_is_refused(spark, tmp_path):
    d, _ = make_models(tmp_path)
    job = "j-ner-badpin"
    store, kbs = make(tmp_path, job)
    r = run(spark, tmp_path, job, kbs, "all", ner=NerSettings(str(d), "0" * 64, engine_factory=FakeEngine))
    assert r["ok"] is False
    assert not [p for p in store.list(f"staging/{job}/apply/") if p.endswith(".enc")]
