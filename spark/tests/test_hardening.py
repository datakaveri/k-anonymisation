"""R1/R2 as tests: the session is configured as the review demands, and a finished job leaves neither
keys nor row content in Spark's local directory."""

import glob
import os
import re
from pathlib import Path

import corpus
from helpers import run, setup_case

DEPLOY = Path(__file__).resolve().parent.parent / "deploy"


def test_session_settings(spark):
    conf = dict(spark.sparkContext.getConf().getAll())
    assert conf["spark.ui.enabled"] == "false"
    assert conf["spark.eventLog.enabled"] == "false"
    assert conf["spark.io.encryption.enabled"] == "true"


def test_image_conf_has_the_r1_and_r2_settings():
    kv = dict(re.findall(r"^(\S+)\s+(\S+)\s*$", (DEPLOY / "spark-defaults.conf").read_text(), re.M))
    assert kv["spark.authenticate"] == "true"
    assert kv["spark.authenticate.secret.file"] == "/run/anamika/spark-secret"
    assert kv["spark.network.crypto.enabled"] == "true" and kv["spark.io.encryption.enabled"] == "true"
    assert kv["spark.ui.enabled"] == "false" and kv["spark.eventLog.enabled"] == "false"
    assert "spark.authenticate.secret" not in kv, "the secret itself must never be in a conf file"


def test_template_variables_are_documented():
    text = (DEPLOY / "sparkapplication.template.yaml").read_text()
    used = set(re.findall(r"\$\{([A-Z_0-9]+)\}", text))
    header = text.split("apiVersion:")[0]
    undocumented = {v for v in used if v not in header}
    assert not undocumented, undocumented
    assert "kata-remote" in text and "spark.authenticate" in text and "IMAGE_DIGEST" in used


def test_no_keys_or_rows_in_spark_local_dir(spark, tmp_path):
    local = spark.sparkContext.getConf().get("spark.local.dir")
    job, store, kbs = setup_case(tmp_path, "basic_pass2", tag="d")
    assert run(spark, tmp_path, job, kbs, "all")["ok"]
    _, slots = corpus.case_keys("basic_pass2")
    needles = [v[:16] for v in slots.values()] + [v.hex()[:32].encode() for v in slots.values()]
    needles += [b"Hypertension", b"rahul.nair0@example.org", b"Rahul Nair", b"P1000"]
    hits, seen = [], 0
    for path in glob.glob(os.path.join(local, "**", "*"), recursive=True):
        if os.path.isfile(path):
            seen += 1
            data = Path(path).read_bytes()
            hits += [(os.path.basename(path), n[:6]) for n in needles if n in data]
    assert seen > 0, "the scan looked at nothing"
    assert not hits, hits
