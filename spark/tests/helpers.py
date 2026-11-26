import json
from pathlib import Path

import corpus
from anamika_spark.job import run_job
from anamika_spark.testkit import fake_kbs, pack_rows, read_result

CONTRACT = Path(__file__).resolve().parents[3] / "anamika-control-plane" / "contracts" / "schemas"


def job_id(name, tag=""):
    return ("j-" + name + tag).replace("_", "-")


def setup_case(root, case, *, parts=3, tag=""):
    job = job_id(case, tag)
    listed, slots = corpus.case_keys(case)
    store = pack_rows(root, job, corpus.case_data(case), corpus.case_config(case), parts=parts, keys=listed)
    return job, store, fake_kbs(job, **slots)


def run(spark, root, job, kbs, phase, choice=None, **kw):
    return run_job(job, phase, {"kind": "local", "root": str(root)}, kbs, spark=spark, choice=choice, **kw)


def status(store, job, phase):
    return json.loads(store.get(f"staging/{job}/{phase}/status.json"))


def validator(name):
    from jsonschema import Draft202012Validator

    return Draft202012Validator(json.loads((CONTRACT / f"{name}.schema.json").read_text()))
