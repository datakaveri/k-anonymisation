# SKALD

Streaming k-anonymization pipeline built in Rust.
Implements the OLA-1 / OLA-2 lattice algorithms for optimal generalization with minimal information loss.

---

## What it does

1. Reads one table: a CSV, JSON (array of flat objects) or Excel file (`.xlsx`/`.xls`, including multi-sheet workbooks joined into one table), or a PostgreSQL table or query
2. Transforms identifier columns: suppress, keyed hash, mask, encrypt (AES-SIV or format-preserving FF1), charcloak, tokenise
3. Optionally reads a pre-sanitized file produced by a free-text anonymization step
4. Computes k-anonymous generalizations of the quasi-identifiers with the OLA-2 lattice search, optionally with distinct l-diversity on sensitive columns (t-closeness is not implemented)
5. Writes the anonymized output, a run summary (equivalence classes, DM\*, suppressed records) and a structured `status.json` to `output/`

Nested JSON documents and FHIR bundles go through a separate per-document flow: path rules decide what each field becomes, anything unmatched is removed, and k-anonymity does not apply.

Key material (keys, salts, token vaults) is written to a separate key directory. Its holders can reverse tokenised and encrypted columns; see [Reverse operations](#reverse-operations-authorized-recovery).

---

## Quick start — Docker (recommended)

```bash
# 1. Add your input file (exactly one of .csv / .json / .xlsx / .xls)
cp your_dataset.csv data/

# 2. Add your config (see Config Schema below)
cp your_config.json config/config.json

# 3. Build and run
docker compose up --build

# 4. Read results
cat output/status.json
cat output/pipeline.log        # full timestamped trace
```

Exit code `0` = success, `1` = error. All detail is in `output/status.json`.

**Running on a different dataset:** with no flags, `data/` must hold exactly **one** input file (otherwise `DATA_AMBIGUOUS_INPUT`), and the first `.json` in `config/` by name is used. To switch datasets without moving files around, name both explicitly with `--config` and `--data` (see [Command line](#command-line)).

---

## Quick start — local Rust

```bash
# Prerequisites: Rust toolchain (https://rustup.rs)

# Run pipeline
cargo run --manifest-path SKALD/Cargo.toml --release --bin skald_pipeline

# Run tests
cargo test --manifest-path SKALD/Cargo.toml

# End-to-end matrix: every input shape, single- and two-pass (needs openpyxl)
python scripts/e2e_matrix.py
```

## Command line

Every path the pipeline uses can be named at run time, so one binary serves any
number of datasets:

```
skald_pipeline [OPTIONS]

  -c, --config <PATH>   Config JSON file, or a directory to search   [SKALD_CONFIG]
  -d, --data <PATH>     Input directory, or a single input file      [SKALD_DATA]
  -o, --output <DIR>    Results and logs — the release               [SKALD_OUTPUT]
  -k, --keys <DIR>      Key material (vaults, keys, salts)           [SKALD_KEYS]
      --chunks <DIR>    Scratch directory for chunked CSV            [SKALD_CHUNKS]
  -r, --root <DIR>      Base directory the defaults hang off         [SKALD_ROOT]
  -h, --help            Print help
  -V, --version         Print version
```

Resolution order for each path is **flag → environment variable → default under
`--root`**, and `--root` itself defaults to the working directory. With no flags
and no variables the layout is `./config`, `./data`, `./chunks`, `./output`
and `./keys`.

```bash
# Pick one of several bundled configs
./skald_pipeline --config config/config_pass1.json

# A config and an input from anywhere on the filesystem
./skald_pipeline --config /etc/skald/live.json --data /mnt/export/patients.csv

# Keep each run's results apart
./skald_pipeline --config /etc/skald/live.json --output /var/skald/runs/2026-08-20

# The same, from the environment — suits cron and systemd units
SKALD_CONFIG=/etc/skald/live.json SKALD_DATA=/mnt/export/patients.csv skald_pipeline
```

`--config` accepts a directory as well as a file; a directory is searched for
its first `*.json`, which is what happens by default. `--data` likewise accepts
either a directory to scan or a single file to read.

Key material — `symmetric_keys.json`, `fpe_encrypt_keys.json`,
`token_vault.json`, and the nested-JSON / FHIR salts and vaults — lives in its own
directory: `--keys`, else `SKALD_KEYS`, else `key_directory` in the config, else
`<root>/keys`. Files are created owner-only (0600, directory 0700). The key
directory may not be the output directory or inside it, and a run refuses to
start while key files from SKALD < 4.0 are still in the output directory
(`KEY_MATERIAL_IN_OUTPUT`) — move them to the key directory. **Ship the output
directory; never ship the key directory**: it reverses every tokenised and
encrypted column.

---

## Build a standalone RHEL 7 bundle

A Docker-based packaging command extracts the statically linked x86_64 binary
and the configs into a portable directory:

```bash
bash scripts/package_rhel7.sh
```

The bundle is written to `dist/skald-rhel7/`, holding the binary, a `run.sh`
wrapper, a `README.txt`, and `config/`, `data/` and `output/` directories. Give
the recipient the bundle, place exactly one input file in `data/`, and run:

```bash
./run.sh                                     # first config in config/
./run.sh --config config/config_pass1.json   # choose among the bundled configs
./run.sh --config /etc/skald/live.json       # a config from outside the bundle
```

Ship as many configs as the recipient needs — every argument after the output
directory is copied into the bundle, and each may be a file or a directory of
`*.json`:

```bash
bash scripts/package_rhel7.sh dist/my-dataset /path/to/my_dataset.json
bash scripts/package_rhel7.sh dist/all-datasets config/
```

The binary is statically linked against musl, so it does not depend on the
recipient's RHEL 7 glibc version — and nothing else is installed on the host,
including no PostgreSQL client: the connector below speaks the wire protocol
directly and its TLS trust store is compiled in.

---

## PostgreSQL input and output

A config can read its rows straight from PostgreSQL instead of from a file, and
load the anonymized result back into a table. Both are optional and independent:
a config with neither section behaves exactly as it always has, and the files
under `output/` are written either way — the database sink is an additional
destination, never a replacement.

```jsonc
{
  "data_type": "health",
  "health": {
    "input": {
      "type": "postgres",
      "host": "db.internal",
      "port": 5432,
      "database": "health",
      "user": "skald",
      "password_env": "SKALD_PG_PASSWORD",   // names the variable, not the secret
      "sslmode": "verify-full",
      "table": "public.patients"             // or "query": "SELECT … WHERE …"
    },
    "output_sink": {
      "type": "postgres",                    // connection omitted → reuse the input's
      "table": "anonymized.patients",
      "mode": "replace"
    }
    // … the usual suppress / hashing / quasi_identifiers / k_anonymize fields
  }
}
```

```bash
SKALD_PG_PASSWORD=… ./skald_pipeline --config /etc/skald/live.json
```

### `input`

| Field | Meaning |
|---|---|
| `type` | `"file"` (default) or `"postgres"` |
| `dsn` | A libpq URI or key/value string. Discrete fields below override it |
| `host`, `port`, `database`, `user` | Connection details; `PGHOST`/`PGPORT`/`PGDATABASE`/`PGUSER` fill in anything unset |
| `password` / `password_env` | The password, or the name of the variable holding it. `PGPASSWORD` is not read implicitly |
| `sslmode` | `disable`, `prefer`, `require`, `verify-ca` (needs `sslrootcert`), `verify-full` (default) — libpq's meanings |
| `sslrootcert` | PEM bundle to verify against. Absent → the Mozilla root program's CAs, compiled in |
| `connect_timeout_seconds`, `application_name` | Passed to the driver |
| `table` | Read this whole table — mutually exclusive with `query` |
| `columns`, `limit` | Narrow a `table` read |
| `query` | A `SELECT` to read instead of a table |

`prefer` and `require` encrypt the connection but do **not** authenticate the
server — the same trade libpq makes. Use `verify-full` where a man in the middle
matters.

Two deliberate departures from stock rustls, both to match libpq so a working
`psql` connection string carries over unchanged:

- **`verify-ca` tolerates a name mismatch.** The chain must be trusted; the name
  on the certificate need not match the host dialled. `verify-full` still checks
  it.
- **A certificate named in `sslrootcert` is trusted as itself.** rustls rejects a
  `CA:TRUE` certificate presented as a server certificate — which is exactly what
  a self-signed PostgreSQL server certificate is, and those are common on
  internal networks. When the certificate the server presents is byte-identical
  to one in `sslrootcert`, it is accepted: naming that exact file is a stronger
  statement of intent than a chain check. Expired certificates are still refused,
  and pinning never applies to the built-in Mozilla roots.

### `output_sink`

| Field | Meaning |
|---|---|
| `type` | `"none"` (default) or `"postgres"` |
| `connection` / inline fields | Omit entirely to reuse the input's connection |
| `table` | Destination, `table` or `schema.table` (required) |
| `mode` | `create` (default), `append`, `truncate`, `replace` |
| `create_schema` | `CREATE SCHEMA IF NOT EXISTS` first. Default `true` |
| `empty_as_null` | Empty fields load as SQL `NULL`. Default `true` |

| Mode | Before loading |
|---|---|
| `append` | Nothing — the table must already exist |
| `create` | `CREATE TABLE IF NOT EXISTS` with every column `text` |
| `truncate` | Create if absent, then `TRUNCATE` |
| `replace` | `DROP TABLE IF EXISTS`, then create |

`truncate` and `replace` destroy rows already in the destination; both are
logged at WARN before anything happens. The DDL and the load share one
transaction, so a failed load leaves the destination as it was rather than half
populated.

### How it works, and what it changes

Both directions stream through `COPY … (FORMAT csv)`. The server does the CSV
quoting and the text conversion of every type it knows; the client only moves
bytes, so nothing larger than a buffer is ever held in memory. Reads are wrapped
as:

```sql
COPY (SELECT replace(replace("col"::text, E'\r', ' '), E'\n', ' ') AS "col", …
      FROM (<your query>) AS skald_source)
TO STDOUT WITH (FORMAT csv, HEADER true)
```

Two consequences worth knowing:

- **Every value arrives as text.** Generalized output is text anyway (`[22-30]`),
  so `create`/`replace` build all-`text` tables.
- **CR and LF inside values become spaces**, so every row is one line in the
  staged CSV. This is the one place the connector alters the data, and it is
  logged.

Credentials never reach the log: connections are reported as
`user@host:port/database sslmode=…` and nothing else.

Staged input lands in `chunks/_pg_input.csv`, which — like everything in
`chunks/` — is deleted at the start of the next run.

**Precedence.** When more than one input is configured, the most specific wins,
and every override is logged: the free-text anonymization handoff first, then a
file named with `--data`, then a `postgres` input, then the data directory scan.

---

## Config schema

Place a single JSON file in `config/`. Full example:

```json
{
  "data_type": "my_dataset",
  "my_dataset": {
    "output_path":        "anonymized.csv",
    "key_directory":      "keys",

    "suppress":           ["name", "email"],
    "hashing_with_salt":  ["national_id"],
    "masking": [
      { "column": "phone", "masking_char": "*", "characters_to_mask": [1,2,3] }
    ],
    "encrypt": [
      "account_number",
      { "national_id": { "format_preserving": true } }
    ],
    "charcloak":          [],
    "tokenization": [
      { "column": "patient_id", "prefix": "TK-", "digits": 8 }
    ],
    "free_text_anonymization": {
      "enabled": false,
      "columns": [],
      "staged_input_path": "work/sanitized_input.csv"
    },

    "quasi_identifiers": {
      "numerical": [
        { "column": "age" },
        { "column": "zipcode" }
      ],
      "categorical": [
        { "column": "gender" },
        { "column": "blood_group" }
      ]
    },
    "categorical_hierarchies": {
      "blood_group": {
        "A+": ["A", "*"],
        "A-": ["A", "*"],
        "O+": ["O", "*"],
        "*":  ["Other", "*"]
      }
    },
    "size": {
      "age":     2,
      "zipcode": 100
    },
    "k_anonymize":      { "k": 15 },
    "suppression_limit": 0.05,
    "l_diversity":      { "l": 2, "sensitive_attributes": ["diagnosis"] },

    "flow_mode": "auto",
    "compute_parameter_grid": true,
    "sheet_joins": [
      { "left": "patients", "right": "visits", "on": "patient_id", "how": "left" }
    ],
    "restore_sheets": false
  }
}
```

### Key fields

| Field | Type | Description |
|---|---|---|
| `pass` | `"pass1"` \| `"pass2"` \| `"no_bounds"` | `pass1` returns the parameter grid and stops; `pass2` anonymizes with the k chosen from it; `no_bounds` (default) does both in one run. See [Two-pass flow](#two-pass-flow--pass1-then-pass2). |
| `k_anonymize.k` | int ≥ 1 | Minimum group size for k-anonymity. Not needed for `pass1`. |
| `suppression_limit` | float 0.0–1.0 | Max fraction of records allowed to be suppressed (published as `*` or removed). Compared in whole records: `⌊σ·N⌋`. Exceeding it fails the run (`SUPPRESSION_LIMIT_EXCEEDED`) and removes the output. |
| `size.<column>` | int ≥ 1 | Required for every numerical QI without `qi_constraints`/`fixed_bins`: the **factor** each lattice step multiplies the bin width by (not the width itself). For `qi_constraints`, the number of parts each interval splits into per level. |
| `fixed_bins.<column>` | `[{"from","to"}]` | Fixed integer bins for a numerical QI (one level, excluded from the lattice search). Values outside every bin are written as `*`. |
| `l_diversity` | `{"l": int, "sensitive_attributes": [col,…]}` | Every published class — including the `*` class of suppressed rows — must hold at least `l` distinct values of each listed column (distinct l-diversity). Enforced by OLA-2 and on the written output. |
| `key_directory` | string | Where key material is stored (see [Command line](#command-line)); `--keys` / `SKALD_KEYS` take precedence. Default `<root>/keys`. |
| `quasi_identifiers.numerical` | array | Numerical columns used as quasi-identifiers |
| `quasi_identifiers.categorical` | array | Categorical columns used as quasi-identifiers |
| `categorical_hierarchies.<column>` | object | Per-value generalization ladder for a categorical QI: `{ "<leaf value>": ["<level 2>", "<level 3>", ...] }`. A `"*"` key is a catch-all for values not otherwise listed. Columns with no entry here suppress straight to `"*"` at any level ≥ 2. OLA-2 groups values by these same labels, so the ladder is also what decides the column's generalization levels. |
| `flow_mode` | `"auto"` \| `"original"` \| `"direct"` | Which OLA search strategy to use (see [Flow modes](#flow-modes--direct-vs-original) below). Default `"auto"`. |
| `compute_parameter_grid` | bool | When true (default), `pass1` and `no_bounds` compute the k × suppression_limit parameter grid in one shared lattice search (multi-combination OLA-2). `pass2` never computes it. |
| `generalization_node` | object | `pass2` only. A grid cell's `generalization_node` from the `pass1` output, copied verbatim (`{ "<QI column>": <level>, ... }`). When set, `pass2` generalizes straight to that node and skips OLA-1, the histogram and OLA-2. It must name every QI and nothing else. |
| `sheet_joins` | array | Config-driven join steps for multi-sheet Excel input: `{ "left": "<sheet>", "right": "<sheet>", "on": "<col>" \| ["<col>", ...], "how": "left"\|"right"\|"inner"\|"outer"\|"cross" }`. If omitted, sheets with a shared column are auto-joined; sheets with no shared columns are concatenated by row position. Only used when the input file is `.xlsx`/`.xls`. |
| `restore_sheets` | bool | When true, also write the anonymized result back as a multi-sheet `.xlsx` mirroring the original input sheets (see [Restoring per-sheet output](#restoring-per-sheet-output-restore_sheets)). Default `false`. Only takes effect when sheets were merged via explicit `sheet_joins` (or there was only one sheet). |
| `free_text_anonymization.enabled` | bool | When true, the pipeline expects a staged sanitized input file to be provided by the TEE before SKALD runs. |
| `free_text_anonymization.columns` | array | Free-text columns selected in the UI for the upstream anonymizer. SKALD only validates that the list is present when the feature is enabled. |
| `free_text_anonymization.staged_input_path` | string | Path to the sanitized input file that the TEE/GDA stage writes. When enabled, SKALD reads this file instead of scanning `data/`. Relative paths are resolved from the repo root. |
| `clean_output` | bool | When true, delete leftover files from a previous run out of `output/` before this run starts. Default `false` — leftovers are reported in the log but kept (see [Leftovers between runs](#leftovers-between-runs)). The active log and anything named like key material (`keys`, `vault`, `salt`) are never removed. |

**The config is checked strictly.** Every key in the section must be one SKALD
reads (keys starting with `_` are comments): a misspelt key used to be ignored
and silently disabled the technique it named. `k` must be a whole number ≥ 1,
quasi-identifiers require `k_anonymize` (except in `pass1`), technique lists must
contain column names, and `hashing_without_salt` and a non-empty legacy `fpe`
are refused. See `CHANGELOG.md` for the full list.

### Two-pass flow — pass1 then pass2

1. **`pass1`** builds the histogram and runs one multi-combination OLA-2 search over the k ∈ {5, 10, 50, 100} × suppression_limit ∈ {0, 0.01, 0.1} grid. It returns `parameter_grid` in `status.json` and writes `output/parameter_grid.txt`. Each cell holds the best node for that (k, σ), as `best_node` (in QI order) and as `generalization_node` (keyed by column), plus its DM\*, number of equivalence classes and suppressed records.
2. **`pass2`** then runs one of two ways:
   - **A grid cell was picked:** put the cell's `k` in `k_anonymize.k`, its `suppression_limit`, and its `generalization_node` in the config. `pass2` generalizes straight to that node, with no OLA-1, histogram or OLA-2. `status.json` reports `"flow": "CHOSEN_NODE"`.
   - **The user chose their own k / σ:** leave `generalization_node` out. `pass2` runs OLA-1 and OLA-2 for that k and σ as usual.

Either way, `pass2` measures the suppression it actually wrote. Writing more than `suppression_limit` allows is an error (`SUPPRESSION_LIMIT_EXCEEDED`), and the output is removed. With a `generalization_node` that only happens when the data changed after `pass1`, so rerun `pass1`.

---

## Output files

| File | Description |
|---|---|
| `output/status.json` | Structured result payload (see below) |
| `output/pipeline.log` | Timestamped, phase-tagged execution trace |
| `output/<output_path>` | Anonymized CSV (name set in config) |
| `output/equivalence_class_stats.json` | EC size distribution |
| `output/top_ola2_nodes.json` | Top-ranked generalization nodes from OLA-2 |
| `keys/token_vault.json` | Token↔value mapping (if tokenization used) — key material, never ship |
| `keys/symmetric_keys.json`, `keys/fpe_encrypt_keys.json` | Encryption keys (if `encrypt` used) — key material, never ship |
| `output/<output_path stem>.xlsx` | Anonymized multi-sheet workbook (if `restore_sheets: true` and applicable — see [Restoring per-sheet output](#restoring-per-sheet-output-restore_sheets)) |
| `output/<output_path stem>.xlsx` / `.json` | Anonymized result in the input's own format (always written for JSON/Excel input — see [Matching the input format](#matching-the-input-format)) |

Rows that fail k (or l) are published with `*` in every QI column only when,
together, they reach k (and are l-diverse); otherwise they are removed, because a
handful of `*` rows singles out exactly the outliers they were meant to hide.
`status.json` reports `suppressed_records` and `removed_records`.

### How the input format is detected

From the file's **contents**, not its name. A `.xlsx` renamed `.csv` is still
read as a workbook, and a `.json` renamed `.csv` is still read as JSON.

This matters because the two failure modes are not equally visible. A misnamed
workbook fails loudly — it is binary, so the CSV reader dies on the first
non-UTF-8 byte. Misnamed JSON is valid UTF-8, so it would sail past that guard,
be parsed as delimited text, and yield garbage columns with no error at all.

Detection uses leading bytes: `PK\x03\x04` (or the OLE2 signature for legacy
`.xls`) means Excel; a first non-whitespace byte of `[` or `{` means JSON;
anything else is treated as CSV. When the name and contents disagree the
contents win and the run logs it:

```
[input] FORMAT MISMATCH: 'records.json.csv' is named like csv but its contents
        are json — reading it as json. The extension is a hint only; fix the
        producer so the name matches.
```

### Matching the input format

Every run writes the anonymized result back in the format it received, with no
configuration required:

| Input | Extra file written |
|---|---|
| `.csv` | none — the CSV output already matches |
| `.json` | `output/<output_path stem>.json` — array of objects |
| `.xlsx` / `.xls` | `output/<output_path stem>.xlsx` — **one** worksheet holding the anonymized table |

The flat CSV is always written too, and `status.json` keeps pointing at it as
`final_output_path`; the converted file is reported alongside as
`format_matched_output_path` — that is the field a downstream uploader should
read. Unlike `restore_sheets`, a failure here fails the run rather than silently
leaving only the CSV: a run handed `.xlsx` should not quietly return a CSV.

This deliberately does **not** rebuild the original sheet layout — a multi-sheet
input comes back as a single sheet. Use [`restore_sheets`](#restoring-per-sheet-output-restore_sheets)
for per-sheet reconstruction.

Both write to the same `<output_path stem>.xlsx`, so when they are enabled
together `restore_sheets` wins: the per-sheet workbook already satisfies "same
format as the input", and flattening it to one sheet would be a downgrade.
`format_matched_output_path` then simply points at the restored workbook.

JSON output keeps the input file's key order, minus suppressed columns.

### Leftovers between runs

`output/` is never wiped automatically, so results from an earlier run stay put
unless this run happens to write the same filename. Running the schools demo
(`output_path: generalized_schools.csv`) and then a patient dataset
(`output_path: generalized_test.csv`) leaves **both** in `output/` — the schools
files are stale, not part of the second run.

Each run logs any such leftovers under the `cleanup` phase:

```
[INFO ] [cleanup] output/ holds 2 file(s) from an earlier run that this run will not
                  overwrite — they are NOT part of these results:
                  generalized_schools.csv, generalized_schools.xlsx.
                  Set "clean_output": true to remove them.
```

Set `"clean_output": true` in the config to have them removed automatically, or
clear `output/` yourself between runs. Key material (`*keys*.json`) and the
active log are never removed either way.

`chunks/` is different: it is pure scratch (chunk splits, plus `_converted.csv`
for JSON/Excel input, which holds **un-anonymized** source data), so it is
emptied at the start of every run with no opt-in needed.

### `status.json` — success

```json
{
  "status": "success",
  "phase":  "done",
  "outputs": {
    "total_records":           50000,
    "final_rf":                [2, 100],
    "lowest_dm_star":          1234.5,
    "num_equivalence_classes": 312,
    "chunk_count":             4,
    "final_output_path":       "output/anonymized.csv",
    "flow":                    "DIRECT_Z",
    "n_approx":                50000,
    "equivalence_space":       48000,
    "n_log2_n":                793157.4,
    "restored_workbook_path":  null,
    "suppressed_records":      120,
    "removed_records":         0,
    "anonymisation_summary":   { "k": 15, "l": 2, "num_equivalence_classes": 312, "dm_star": 1234, "...": "..." },
    "preprocessing":           { "hashing_with_salt:national_id": 50000 }
  },
  "log_file": "output/pipeline.log"
}
```

### `status.json` — error

```json
{
  "status": "error",
  "error": {
    "code":             "DATA_COLUMN_MISSING",
    "message":          "A quasi-identifier column was not found in the CSV header",
    "details":          "age",
    "suggested_fix":    "Column names are case-sensitive — verify they match the config exactly.",
    "http_status_code": 422
  },
  "log_file": "output/pipeline.log"
}
```

---

## Error codes

| HTTP | Code | Meaning |
|---|---|---|
| 400 | `CONFIG_NOT_FOUND` | No JSON file in `config/` |
| 400 | `CONFIG_PARSE_ERROR` | Config JSON is malformed |
| 400 | `CONFIG_MISSING_FIELD` | Required field absent |
| 400 | `CONFIG_INVALID_VALUE` | Field value out of range |
| 400 | `CLI_INVALID_ARGUMENT` | Unknown flag, missing flag value, or a stray path — run `--help` |
| 400 | `DB_CONFIG_INVALID` | Malformed `input`/`output_sink`: no connection, no table/query, bad mode or sslmode |
| 400 | `ENV_VAR_MISSING` | Config references `${VAR}` and it isn't set — export it or write `${VAR:-default}` |
| 422 | `DATA_DIR_MISSING` | `data/` directory not found |
| 422 | `DATA_NO_CSV` | No CSV, JSON, or Excel file in `data/` |
| 422 | `DATA_AMBIGUOUS_INPUT` | More than one input file in `data/` |
| 422 | `DATA_EMPTY` | Input file is empty |
| 422 | `DATA_JSON_INVALID` | JSON input isn't a top-level array of flat objects |
| 422 | `DATA_XLSX_INVALID` | Excel workbook unreadable, or `sheet_joins` names an unknown sheet/column |
| 422 | `DATA_COLUMN_MISSING` | QI column not in CSV header |
| 422 | `PREPROCESS_COLUMN_MISSING` | Preprocessing target column not found |
| 422 | `PREPROCESS_CONFIG_INVALID` | Malformed preprocessing entry |
| 422 | `ANON_INFEASIBLE` | k-anonymity unsatisfiable — raise `suppression_limit` or lower `k` |
| 400 | `CONFIG_UNKNOWN_KEY` | The config has a key SKALD does not read (often a typo) — fix it, or prefix it with `_` to keep it as a comment |
| 422 | `DATA_MALFORMED_ROW` | A CSV row's field count differs from the header, a quoted field is never closed, or the file is not UTF-8 |
| 422 | `LATTICE_TOO_LARGE` | More than 1,000,000 generalization combinations — fewer QIs or larger size factors |
| 422 | `KEY_MATERIAL_IN_OUTPUT` | Key files are in the output directory, or the key directory is inside it — move them to the key directory |
| 422 | `FPE_VALUE_UNSUPPORTED` / `FPE_DOMAIN_TOO_SMALL` | A value cannot be format-preserving-encrypted safely (non-ASCII letters; fewer than 10⁶ possible values) |
| 422 | `TOKEN_SPACE_EXHAUSTED` | The token vault is ≥ 90% full — raise `digits` |
| 500 | `RNG_UNAVAILABLE` / `ENCRYPTION_FAILED` | The OS random number generator failed, or a key does not match its data |
| 422 | `KEY_MATERIAL_INVALID` | A stored salt is not 64 hex characters (for example a pre-4.0 nested-JSON salt) — move the file away and rerun to generate a new one |
| 422 | `GENERALIZATION_FAILED` | No lattice node satisfies k (same remedy as above), or a categorical QI the ORIGINAL flow does not know — see below |
| 422 | `SUPPRESSION_LIMIT_EXCEEDED` | More records would be suppressed than `suppression_limit` allows — raise it or lower `k`; with a `generalization_node`, the data changed since `pass1`, so rerun `pass1` |
| 422 | `ANON_NO_QIS` | No quasi-identifiers defined |
| 422 | `DB_NO_ROWS` | The configured query returned no rows — nothing to anonymize |
| 500 | `IO_READ_FAILED` | File not found or unreadable |
| 500 | `IO_WRITE_FAILED` | Disk full or output not writable |
| 500 | `IO_PERMISSION_DENIED` | Permission denied |
| 500 | `INTERNAL_ERROR` | Unexpected error — check `output/pipeline.log` |
| 502 | `DB_CONNECT_FAILED` | Could not reach the database — host, credentials, sslmode, `pg_hba.conf`, firewall |
| 502 | `DB_READ_FAILED` | The input query failed on the server |
| 502 | `DB_WRITE_FAILED` | The load failed — nothing was committed |

Every error in `status.json` also carries a `suggested_fix`.

---

## Project layout

```
config/                    Runtime config JSON (volume-mounted)
data/                      Input CSV/JSON/Excel, read-only (volume-mounted)
output/                    Pipeline outputs — the release (volume-mounted)
keys/                      Key material — never ship (volume-mounted)
examples/                  Ready-to-run multi-sheet Excel and PostgreSQL examples
SKALD/
  Cargo.toml               Rust crate manifest
  src/
    bin/skald_pipeline.rs  Binary entry point
    bin/skald_ao.rs        Orchestrator toolkit for the block deployment
    bin/skald_preprocess.rs, skald_crypto.rs, skald_kanon.rs
                           Block workers (see "Block deployment")
    pipeline/
      bootstrap.rs         Config parsing, Logger, error types, CSV utilities
      cli.rs               Flags, SKALD_* variables, path resolution
      pipeline.rs          Orchestrator — phase-tagged logging and the run summary
      multitabular.rs      CSV/JSON/Excel input resolution, multi-sheet joins
      nested_json.rs       Per-document de-identification of nested JSON
      fhir_bundle.rs       Per-bundle de-identification of FHIR bundles
      connectors/          PostgreSQL input and output (COPY, rustls TLS)
      anonymization/       OLA-1, OLA-2, Z-histogram, generalization, l-diversity
      preprocess/          Suppress, hash, mask, encrypt, tokenize
      blocks/              Block runtime: plan, stage, keygen, shards, the three blocks
      entry.rs             Error mapping → structured status.json
  tests/                   Integration and property tests
  benches/                 Criterion benchmarks
docker/                    Per-block images and the orchestrator toolkit image
scripts/
  e2e_matrix.py            End-to-end matrix over every input shape
  package_rhel7.sh         Builds the standalone RHEL 7 bundle
  reverse_tokenization.py  Reverses tokenization using token_vault.json
```

---

## Preprocessing operations

| Operation | Config key | Description |
|---|---|---|
| Column suppression | `suppress` | Drops column entirely from output |
| Salted hashing | `hashing_with_salt` | HMAC-SHA256(key = salt's 32 bytes, value), 64 hex chars; a fresh 32-byte random salt per column per run (not stored). With `"shared_hash_salts": true` the salt is kept per column name in `<key dir>/tabular_hash_salts.json` and reused, so tables run separately against one key directory hash a column alike (joinable); that file then reverses nothing on its own but lets its holder test guesses, so keep it with the other key material |
| Masking | `masking` | Position / regex / character-class masking. Every regex must compile when the config is read (lookaround is not supported) — an entry that could leave values unmasked is refused. A `before` / `after` pattern's `length` masks that many characters next to every occurrence of its `delimiter`, or, as `"all"`, everything on that side of the first occurrence (`{"type": "before", "delimiter": "@", "length": "all"}` turns `name@example.org` into `****@example.org`) |
| Encryption | `encrypt` | AES-SIV (deterministic, authenticated), `ENC1$` + hex |
| Format-preserving encrypt | `encrypt` + `format_preserving: true` | NIST FF1 over the whole value; digits stay digits, letters keep case, punctuation stays put. Values with fewer than 10⁶ possible values of their shape, or with non-ASCII letters, are refused |
| Character cloaking | `charcloak` | Random letter/digit of the same class, any script → ASCII |
| Tokenization | `tokenization` | Random `prefix + digits` token, stable per value, vault in the key directory |

Identifier values are trimmed and Unicode-NFC-normalised before hashing,
tokenisation and encryption. `hashing_without_salt` (unsalted SHA-256 — reversible
by enumerating phone or Aadhaar numbers) and the legacy `fpe` section were
removed in 4.0.

---

## Multi-format / multi-tabular input

`data/` accepts exactly one of:

- **CSV** — used as-is (unchanged behavior).
- **JSON** — a top-level array of flat objects, one per record: `[{"col1": "val"}, ...]`. Column order follows first-seen-key order across records; missing keys are filled with `""`.
- **Excel** (`.xlsx`/`.xls`) — single or multi-sheet. A single-sheet workbook is read directly. Multiple sheets are combined into one table by, in order of precedence:
  1. `sheet_joins` in config, if present — an ordered list of explicit join steps (`left`, `right`, `on`, `how`), applied like a pandas `merge`. Chaining several steps against the same `left` sheet builds a star-schema join.
  2. Same-schema sheets (identical columns) are stacked vertically.
  3. Otherwise, sheets are auto-joined on any shared column names, or concatenated by row position if two sheets share none.

JSON/Excel inputs are normalized into a single CSV under `chunks/` before chunking (`data/` itself is treated as read-only, matching the `:ro` Docker volume mount); a plain CSV input is read directly from `data/` without copying.

### Walkthrough: two-sheet Excel workbook

Say `data/patients.xlsx` has two sheets:

- **`Patients`**: `patient_id, Age, Blood Group, PIN Code`
- **`Visits`**: `patient_id, diagnosis_code`

Join them on `patient_id` with a `sheet_joins` config, and generalize `Blood Group` per a custom hierarchy:

```json
{
  "data_type": "test",
  "test": {
    "output_path": "generalized.csv",
    "output_directory": "output",
    "suppression_limit": 0.2,

    "quasi_identifiers": {
      "categorical": [{ "column": "Blood Group" }],
      "numerical": [
        { "column": "Age",      "encode": false, "type": "int" },
        { "column": "PIN Code", "encode": false, "type": "int" }
      ]
    },
    "categorical_hierarchies": {
      "blood group": {
        "A+": ["A", "*"], "A-": ["A", "*"],
        "B+": ["B", "*"], "B-": ["B", "*"],
        "AB+": ["AB", "*"], "AB-": ["AB", "*"],
        "O+": ["O", "*"], "O-": ["O", "*"],
        "*": ["Other", "*"]
      }
    },
    "size": { "Age": 5, "PIN Code": 100000 },

    "sheet_joins": [
      { "left": "Patients", "right": "Visits", "on": "patient_id", "how": "left" }
    ],

    "k_anonymize": { "k": 2 },
    "restore_sheets": true
  }
}
```

```bash
cp patients.xlsx data/
cp this_config.json config/config.json
docker compose up --build
cat output/status.json   # outputs.sample_generalized_rows shows the joined + generalized rows
```

With `restore_sheets: true`, `output/generalized.xlsx` comes back out with the same two sheets — `Patients` (patient_id, Age, Blood Group, PIN Code) and `Visits` (patient_id, diagnosis_code) — populated with the anonymized values instead of the flat merged CSV.

Two ready-to-run, verified examples (including a 3-sheet star-schema case) live in
[`examples/multitabular/`](examples/multitabular/README.md) — copy either straight into `data/`/`config/`.

Things worth double-checking if it doesn't work:

- `sheet_joins[].left`/`.right` must match the workbook's **sheet names exactly** (case-sensitive) — a typo produces `DATA_XLSX_INVALID` naming the sheets it *did* find.
- `on` must be a column present in **both** sheets — otherwise also `DATA_XLSX_INVALID`.
- With more than two sheets, chain multiple `sheet_joins` steps against the same `left` sheet name to build a star schema (each step's `right` sheet joins onto the running `left` frame).
- If `sheet_joins` is omitted entirely: sheets with identical column sets are stacked as more rows; otherwise SKALD auto-joins on whatever column names the sheets have in common, or concatenates by row position if they share none — explicit `sheet_joins` is more predictable and recommended once you have more than one sheet.

### Restoring per-sheet output (`restore_sheets`)

By default, anonymized output is always one flat CSV, even when the input was multi-sheet Excel — SKALD joins everything into one table before anonymizing, since QI columns can span sheets and equivalence classes have to be computed over the full joined row.

Set `"restore_sheets": true` to also get an anonymized `.xlsx` workbook back, with one sheet per **original input sheet**, restored to its original column names/order (join key columns included in every sheet that needs them). It's written alongside the usual flat CSV, named from the same `output_path` stem (e.g. `output_path: "generalized.csv"` → `output/generalized.xlsx`), and its path is reported at `outputs.restored_workbook_path` in `status.json`.

If a sheet's rows were fanned out by the join (e.g. a patient with several visits), the corresponding restored rows are de-duplicated per sheet — a "Patients" sheet won't repeat the same patient once per visit.

**Scope:** only supported when sheets were merged via an explicit `sheet_joins` config (both example demos use this), or when the input had a single sheet (trivial passthrough). It is **not** supported for the auto-join or same-schema-vertical-concat fallback paths — with `restore_sheets: true` but no `sheet_joins`, SKALD logs why and skips writing the workbook (the flat CSV is unaffected either way; this is purely an additional, best-effort output).

---

## Flow modes — DIRECT vs ORIGINAL

The OLA-2 search can run in two modes, controlled by `flow_mode`:

- **`original`** — the classic path: OLA-1 picks an initial generalization, then OLA-2 binary-searches the lattice using a `SparseHist`.
- **`direct`** — skips OLA-1 and builds a compact scalar `ZHist` (mixed-radix-encoded, ~16 bytes/entry) directly at the finest granularity, then runs OLA-2 on that. Falls back to `original` automatically if the encoding would overflow.
- **`auto`** (default) — pre-scans the input once to estimate record count `N` and each QI's domain size, computes the equivalence space `E = Π(QI domain sizes)`, and picks `direct` when `N·log₂(N) ≤ E`, else `original`.

`output/status.json` reports which flow ran (`outputs.flow`) along with the `n_approx`, `equivalence_space`, and `n_log2_n` values behind the decision.

> **How `qi_constraints` behaves.** The intervals are the *coarse* end of a
> generalization ladder, not the bins the output uses. They are split into finer
> sub-intervals, and OLA-2 picks whichever level satisfies `k`. Use `fixed_bins`
> when the output must use exactly the configured bins.
>
> **Categorical ladders must nest:** values that share a label at one level must
> share one at every coarser level. OLA-2's pruning relies on it, so a ladder
> that does not nest is refused (`CONFIG_INVALID_VALUE`).

---

## Block deployment (orchestrator)

The same pipeline is also available as three separately built and attested
blocks, for an orchestrator (AO) that column-shards a dataset and hands each
shard only to the container that needs it. `skald_pipeline` is unchanged.

| Block | Binary | Does | Secret state |
|---|---|---|---|
| preprocess | `skald_preprocess` | suppress, masking, charcloak, tokenization | token vault, in the key directory |
| crypto | `skald_crypto` | `hashing_with_salt`, `encrypt` | reads keys; never creates one |
| kanon | `skald_kanon` | k-anonymity as `scan` → `solve` → `apply` | none |

`skald_ao` is the orchestrator's toolkit: `plan` (which columns each block
needs, in what order), `stage` (cleaning, suppression, row ids), `keygen`,
`project` / `split` / `stitch`, `solve` and `grid`. Each block runs as
`skald_<block> --manifest <job>/manifest.json` and reports in
`<artifacts_dir>/<shard_id>.status.json`. Build the images with
`docker/build-blocks.sh`.

A job run as blocks releases exactly what `skald_pipeline` releases from the
same data and config — the tests check this byte for byte. Each block calls the
monolith's own code for every technique, and `solve` makes the monolith's class
decision (k, l, removing a `*` class smaller than k, `suppression_limit`) over
the merged histogram before any row is written.

- **Keys:** `skald_ao keygen --config <cfg> --keys <key dir>` writes the salts
  and keys into the key directory, in the monolith's files, and prints column
  names only. Blocks read them through `key_directory` in their manifest. A key
  directory or vault inside a block's `artifacts_dir` is refused.
- **Removed rows:** `kanon apply` writes only the row id and the QI columns,
  and lists the rows it removed in `<shard_id>.removed_rids.json`. Pass every
  such list to `skald_ao stitch --removed`, which drops those rows from every
  column. A row missing a processed column fails the stitch rather than taking
  the staged value.
- **Kept on the orchestrator:** `histogram.json` and the scan artifacts hold
  un-generalised quasi-identifier tuples. They are written owner-only and are
  never released.
- **Cleaning:** the optional `cleaning` section (missing-value tokens,
  whitespace, required and numeric columns, `max_dropped_fraction`) is applied
  by `skald_ao stage` only; `skald_pipeline` ignores it with a warning.

---

## Reverse operations (authorized recovery)

Holders of the key directory can reverse the reversible techniques:

- **Tokenization:** `scripts/reverse_tokenization.py` maps tokens back through `keys/token_vault.json`:

  ```bash
  python scripts/reverse_tokenization.py --input output/anonymized.csv --output recovered.csv --vault keys/token_vault.json
  ```

  It accepts CSV or JSON (by extension) and an optional `--columns` filter, and reports tokens missing from the vault, which are left unchanged.
- **Encryption:** `decrypt_value` and `format_preserving_decrypt` in `skald_ola2::pipeline::preprocess::crypto` reverse `encrypt` with the keys in `keys/symmetric_keys.json` and `keys/fpe_encrypt_keys.json`.

Hashing, masking, charcloak and generalization are one-way.

---

## Benchmarking

Criterion benchmarks of the OLA-2 lattice search:

```bash
cargo bench --manifest-path SKALD/Cargo.toml
```
