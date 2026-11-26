#!/usr/bin/env python3
"""SKALD harness `external` engine: pack a CSV into a bundle, run the Spark job in local mode, unpack.

    python3 SKALD/bench/harness.py --rows 100000 --engines cli,external --external-name anamika-spark \
        --external-cmd ".venv-skald/bin/python spark/bench/spark_external.py {input} {output}"

    python3 spark/bench/spark_external.py --corpus        # every conformance case vs the recorded CLI output

What it does: the harness's config and fixed test keys (SKALD/bench/harness.py CONFIG and KEYS) become the
manifest and key slots, the CSV is cut into parts and sealed with the bundle code, `run_job(phase=all)`
runs with Spark `local[2]`, and the decrypted output parts are written to {output} as one CSV with the
header, so the harness can compare its digest with the CLI's.

Timings go to stderr as one JSON line (pack, job, unpack). They are LOCAL, DEBUG-grade numbers on a small
shared machine with a 1 GB driver and say nothing about the cluster benchmark: they show that the
pipeline works and where the fixed costs are (JVM start, packing).
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKALD = Path(os.environ.get("SKALD_DIR", ROOT.parent / "k-anonymisation" / "SKALD"))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SKALD / "bench"))
# Python workers need this package and the same interpreter (skald_core lives in this venv).
os.environ["PYTHONPATH"] = os.pathsep.join(filter(None, [str(ROOT), os.environ.get("PYTHONPATH")]))
os.environ.setdefault("PYSPARK_PYTHON", sys.executable)
os.environ.setdefault("PYSPARK_DRIVER_PYTHON", sys.executable)

KINDS = {"tabular_hash_salts.json": "hmac_salt", "symmetric_keys.json": "aes_key", "fpe_encrypt_keys.json": "fpe_key"}


def run_bundle(csv_bytes: bytes, config: dict, key_files: dict, parts: int, spark, workdir: str, job: str):
    """key_files: {harness file name: {column: hex}}. Returns (output csv bytes, timings dict)."""
    from anamika_spark.job import run_job
    from anamika_spark.testkit import fake_kbs, pack_rows, read_result

    t0 = time.perf_counter()
    listed, slots = [], {}
    for fn, body in key_files.items():
        for col, hexkey in body.items():
            i = len(listed)
            listed.append({"slot": f"key-{i:02d}", "column": col, "kind": KINDS[fn]})
            raw = bytes.fromhex(hexkey)
            slots[f"key_{i:02d}"] = raw + bytes(32 - len(raw))  # KBS resources are 32 bytes; AES/FPE use the prefix
    store = pack_rows(workdir, job, csv_bytes, config, parts=parts, keys=listed)
    kbs = fake_kbs(job, **slots)
    t1 = time.perf_counter()
    result = run_job(job, "all", {"kind": "local", "root": workdir}, kbs, spark=spark)
    t2 = time.perf_counter()
    if not result["ok"]:
        raise SystemExit(f"job failed: {result['code']}")
    _, _, out, _ = read_result(store, job)
    t3 = time.perf_counter()
    return out, {"pack_s": round(t1 - t0, 2), "job_s": round(t2 - t1, 2), "unpack_s": round(t3 - t2, 2)}


def main(argv):
    from anamika_spark.session import build_session

    master = os.environ.get("ANAMIKA_SPARK_MASTER", "local[2]")
    spark = build_session({"ANAMIKA_DRIVER_MEMORY": os.environ.get("ANAMIKA_DRIVER_MEMORY", "1g")}, master=master)
    if argv[0] == "--corpus":
        return corpus(spark)
    import harness  # SKALD/bench/harness.py: the same CONFIG and KEYS the CLI engine uses

    data, output = argv[0], argv[1]
    csv_bytes = Path(data).read_bytes()
    rows = csv_bytes.count(b"\n") - 1
    parts = max(2, min(64, rows // 12500))
    with tempfile.TemporaryDirectory(prefix="anamika-spark-bench-") as wd:
        out, timings = run_bundle(csv_bytes, harness.CONFIG, harness.KEYS, parts, spark, wd, "j-bench-external")
    Path(output).write_bytes(out)
    print(json.dumps({"engine": "anamika-spark", "master": master, "rows": rows, "parts": parts, **timings}), file=sys.stderr)
    return 0


def corpus(spark):
    """Every conformance case through the bundle and Spark, byte-compared with the recorded CLI output."""
    cases = SKALD / "conformance"
    ok = True
    print(f"{'case':28} {'rows':>6} {'pack_s':>7} {'job_s':>7} {'unpack_s':>9}  equal")
    for name in sorted(os.listdir(cases / "cases")):
        cfg = json.loads((cases / "cases" / name / "config.json").read_text())
        exp = cases / "expected" / name / "anonymized.csv"
        if not exp.exists():  # pass1: grid only, no anonymised file to compare (the tests cover the grid)
            continue
        keys = {fn: json.loads((cases / "cases" / name / "testkeys" / fn).read_text()) for fn in KINDS}
        data = (cases / "cases" / name / "data.csv").read_bytes()
        with tempfile.TemporaryDirectory(prefix="anamika-spark-corpus-") as wd:
            out, t = run_bundle(data, cfg, keys, 3, spark, wd, "j-corpus-" + name.replace("_", "-"))
        same, nrows = out == exp.read_bytes(), data.count(b"\n") - 1
        ok &= same
        print(f"{name:28} {nrows:>6} {t['pack_s']:>7} {t['job_s']:>7} {t['unpack_s']:>9}  {same}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
