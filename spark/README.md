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
   (must be exactly `0..N-1`), refuse non-`kanon` bundles. Several tables are merged first, see "Several tables".
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

## Several tables

A bundle with several tables (a multi-sheet workbook) is merged the way SKALD's command line merges it
(`joins.py`, which says what mirrors what), anonymised as one table, and with `restore_sheets: true` split back
into one output table per input sheet. The result is byte-identical to the CLI's for the same input
(`SKALD/conformance/cases/join_*`, recorded from the CLI; `tests/test_joins.py`, at 1, 3 and 7 parts per table).

* `sheet_joins` (`left`, `right`, `on`, `how` = left/right/inner/outer/cross): pandas `merge` semantics. Without it:
  tables with the same columns are stacked; otherwise each next table is joined (left) on the columns it shares.
  Tables with nothing in common are refused (`INVALID_INPUT`): the CLI pastes them by row position.
* Row order is carried by an id column (part number << 32 | row) and each join step sorts by (left id, right id),
  unmatched right rows last, then numbers the result again. Nothing is collected on the driver.
* Key names for a multi-table bundle are `"<table>/<column>"` of the merged column's origin (`JoinPlan.key_name`):
  `patients/id`, `visits/note` for a renamed `note_y`. A join column shared by two sheets is one merged column and so
  one key, named after the left sheet. A manifest `keys` / `vaults` entry names `table` + `column` as the user knows
  them and resolves through the plan (`visits/id` finds the merged `id`); two entries for one merged column are refused.
  SKALD's own key files name the merged column (`id`), so equivalence runs hand the CLI's keys in as saved keys.
* The split reads the anonymised table: each sheet keeps its own columns under their original names (a column a
  technique removed, e.g. `suppress`, reads as empty, as in SKALD), rows are de-duplicated on the anonymised values,
  first occurrence first. Output parts are numbered across the sheets in sheet order; a sheet gets as many parts as
  its rows need (rows per part as in the merged table), some possibly empty.
* Summary: `tables` lists the sheets; `rows_in` / `rows_out` / `suppressed` count the merged table (what k-anonymity
  saw); `extra.joined_rows` repeats that. Without `restore_sheets` the one output table is the merged table, named
  after the first join's left sheet.
* NER (`free_text_anonymization`) runs after the merge, on the merged columns. A quoted value with a line break
  survives the split here; the CLI's restore reads line by line and would break it.

## Codes

`INVALID_INPUT` (config, tables that cannot be merged, files, unknown choice, wrong vault key), `MANIFEST_INVALID`,
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
