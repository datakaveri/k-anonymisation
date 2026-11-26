# spark/ (anamika-spark)

The Spark k-anonymity job of the Anamika keys-only architecture: SKALD's Rust core (`skald_core`) on PySpark,
reading and writing the encrypted bundle in Blob. Lives in the k-anonymisation repo as `spark/`, beside `SKALD/` (the Python package is still `anamika_spark`); the AO and
Co-ordinator launch it (see `deploy/README.md`), the Ray image does the file jobs.

```
python -m anamika_spark.run     # env: ANAMIKA_JOB, ANAMIKA_PHASE, ANAMIKA_STORE_URL | ANAMIKA_STORE_DIR, ...
```

## What it does

Phases (one Spark job each; the AO chooses): `all` (measure then apply), or with explore_k `measure` then,
after the user approves a cell, `apply`.

1. Driver: fetch `K_user` and key slots from the CDH, decrypt `manifest.enc`, check `job_id`, list parts
   (must be exactly `0..N-1`), refuse multi-table or non-`kanon` bundles.
2. Executors: each takes some part numbers, fetches them from Blob, decrypts with `k_input`, checks the
   manifest's length, SHA-256 and row count, parses (all strings), optionally redacts free text (NER), and
   preprocesses with the saved keys (per-job keys for other columns are generated on the driver and broadcast).
   Tokenised columns follow SKALD's recipe: distinct values to the driver, tokens issued there, vault broadcast.
3. Stats (executor partials, driver merge) -> model -> histogram (partials, merge). `measure` writes
   `measure/histogram.enc` (stats + histogram bytes, `k_summary`) and `measure/summary.enc`
   (`{summary_version, grid:[{id, ...SKALD cell}], extra}`) and stops.
4. `apply` (or `all`): pick the node (the chosen cell's `generalization_node`; the config's explicit node for
   `pass2`; else OLA-2 search), generalise, merge tallies, `decide(k)`, finish, write each part, then the
   **final k check over the CSV exactly as written** (fail closed with `K_CHECK_FAILED`).
5. Commit: outputs sealed under `apply/pending/`, then moved to `apply/part-NNNNN.enc`, then `summary.enc`,
   then any vault version, then `status.json` last. Failure deletes the phase directory and writes
   `{"ok": false, "code": ...}`. A retry clears the directory first.

Output part `n` is the anonymised input part `n` (a part may be empty after suppression), so `N` is the input
`part_count` and the summary's `tables[0].parts` lists rows, bytes and SHA-256 per part.

Cell ids are `k{k}-s{suppression_limit}` (derived, opaque to everyone else). `apply` recomputes the grid from the
stored histogram and looks the id up, so the AO's plaintext choice string is the only thing it trusts from
outside, and an unknown or infeasible id is `INVALID_INPUT`.

## Codes

`INVALID_INPUT` (config, multi-table, files, unknown choice, wrong vault key), `MANIFEST_INVALID`,
`PARTS_MISMATCH` (missing/extra/swapped/altered part, manifest digest or row count, missing histogram),
`KEY_UNAVAILABLE`, `K_CHECK_FAILED`, `TOKEN_MISSING` (read-only vault lacks a value), else `JOB_FAILED`.
Executor failures cross Spark as `ANAMIKA_CODE=<CODE>` only, so a library error can never carry a row.

## Tests

```
cd k-anonymisation/spark && ../../.venv-skald/bin/python -m pytest tests -q
```

Spark `local[2]`, 1 GB driver. Corpus tests use `../SKALD` (same repo; `SKALD_DIR` overrides); the CLI-reference tests need a
`skald_pipeline` binary (`SKALD_BIN`, or `SKALD/target/{release,debug}`), the NER tests need `anamika_ner`
(`ANAMIKA_NER_SRC`). Absent pieces skip, not fail.

## Vendored code

`bundle.py`, `kbs.py`, `logscrub.py` and the store classes in `io.py` are vendored from `anamika-control-plane` `workloads/ray` (`anamika_ray`) and pass the same
`vectors.json`. Both should later depend on one shared `anamika-bundle` Python package so the copies cannot drift.

## Benchmark

`bench/spark_external.py` plugs into SKALD's harness `external` engine; see `bench/README.md`.
