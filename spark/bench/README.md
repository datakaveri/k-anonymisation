# Benchmark hook

`spark_external.py` plugs the job into SKALD's harness (`SKALD/bench/harness.py`, engine `external`):

```
export SKALD_BIN=.../skald_pipeline
.venv-skald/bin/python k-anonymisation/SKALD/bench/harness.py --rows 100000 --engines cli,batch,external \
    --batches 8 --external-name anamika-spark \
    --external-cmd ".venv-skald/bin/python spark/bench/spark_external.py {input} {output}"
.venv-skald/bin/python spark/bench/spark_external.py --corpus     # conformance corpus, byte compare
```

It packs the CSV into a bundle (the harness's CONFIG and fixed test keys become manifest and key slots), runs
`run_job(phase=all)` in Spark `local[2]` with a fake KBS and a local-directory store, and unpacks the output.

## Result (this machine, 2026-11-26)

Conformance corpus: all 9 cases that write a file are byte-identical to the CLI's recorded output
(pass1_grid writes only a grid; the test suite compares that).

100,000 synthetic rows, 8 parts, harness config (k=10):

| engine | wall_s | rows/s | peak RSS MB | min class | rows_digest |
|---|---|---|---|---|---|
| cli (debug build) | 21.6 | 4629 | 104 | 10 | 308e0f9d2055... |
| batch (skald_core, 1 process) | 19.5 | 5141 | 328 | 10 | 308e0f9d2055... |
| anamika-spark local[2] | 23.9 | 4182 | 354 | 10 | 308e0f9d2055... |

The three digests are identical. Spark wall time split: pack 0.3 s, job 18.6 s, unpack 0.05 s.

**These are NOT the benchmark.** The CLI is a debug build, the machine is shared with ~2 GB free RAM, Spark ran
with `local[2]` and a 1 GB driver, and storage is a local directory. They show the pipeline is correct and that
the fixed costs (JVM start, a few seconds) are small next to the work; the real matrix (cluster, kata-remote,
Blob, release builds) is a separate run.
