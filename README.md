# SKALD

Streaming k-anonymization pipeline built in Rust.
Implements the OLA-1 / OLA-2 lattice algorithms for optimal generalization with minimal information loss.

---

## What it does

1. Reads one input file from `data/` — CSV, JSON (array of flat objects), or Excel (`.xlsx`/`.xls`, including multi-sheet workbooks joined into one table)
2. Applies preprocessing (suppress, hash, mask, encrypt, tokenize)
3. Computes k-anonymous generalizations using OLA-2 lattice search — either the original OLA-1→OLA-2 path or a memory-efficient DIRECT flow, chosen automatically
4. Writes anonymized output and a structured status payload to `output/`

Reverse-operation scripts (`scripts/reverse_*.py`) can recover original values from anonymized output for authorized holders of the generated key/vault files.

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

**Running on a different dataset:** `data/` must contain exactly **one** input file and `config/` exactly **one** `.json` file — before copying in a new pair, clear out the old ones:

```bash
rm -f data/* config/*.json
cp new_dataset.xlsx data/
cp new_config.json config/config.json
docker compose up --build
```

Leaving old files behind causes `DATA_AMBIGUOUS_INPUT` (multiple input files) or, for `config/`, silent use of whichever `.json` file sorts first alphabetically — worth clearing both explicitly every time you switch datasets.

---

## Quick start — local Rust

```bash
# Prerequisites: Rust toolchain (https://rustup.rs)

# Run pipeline
cargo run --manifest-path SKALD/Cargo.toml --release --bin skald_pipeline

# Run tests
cargo test --manifest-path SKALD/Cargo.toml --lib
```

---

## Config schema

Place a single JSON file in `config/`. Full example:

```json
{
  "operations": ["SKALD", "k-anonymity"],
  "data_type": "my_dataset",
  "my_dataset": {
    "output_path":        "anonymized.csv",
    "output_directory":   "output",
    "log_file":           "log.txt",

    "suppress":           ["name", "email"],
    "hashing_with_salt":  ["national_id"],
    "hashing_without_salt": [],
    "masking": [
      { "column": "phone", "masking_char": "*", "characters_to_mask": [1,2,3] }
    ],
    "encrypt": [
      { "column": "account_number" },
      { "column": "national_id", "format_preserving": true }
    ],
    "charcloak":          [],
    "tokenization": [
      { "column": "patient_id", "prefix": "TK-", "digits": 8 }
    ],

    "quasi_identifiers": {
      "numerical": [
        { "column": "age",     "encode": false, "type": "int" },
        { "column": "zipcode", "encode": false, "type": "int" }
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
    "enable_l_diversity": false,

    "flow_mode": "auto",
    "compute_parameter_grid": true,
    "sheet_joins": [
      { "left": "patients", "right": "visits", "on": "patient_id", "how": "left" }
    ]
  }
}
```

### Key fields

| Field | Type | Description |
|---|---|---|
| `k_anonymize.k` | int ≥ 1 | Minimum group size for k-anonymity |
| `suppression_limit` | float 0.0–1.0 | Max fraction of records allowed to be suppressed |
| `size.<column>` | int | Bin width (generalization step) for each numerical QI |
| `quasi_identifiers.numerical` | array | Numerical columns used as quasi-identifiers |
| `quasi_identifiers.categorical` | array | Categorical columns used as quasi-identifiers |
| `categorical_hierarchies.<column>` | object | Per-value generalization ladder for a categorical QI: `{ "<leaf value>": ["<level 2>", "<level 3>", ...] }`. A `"*"` key is a catch-all for values not otherwise listed. Columns with no entry here suppress straight to `"*"` at any level ≥ 2. |
| `flow_mode` | `"auto"` \| `"original"` \| `"direct"` | Which OLA search strategy to use (see [Flow modes](#flow-modes--direct-vs-original) below). Default `"auto"`. |
| `compute_parameter_grid` | bool | When true (default), also compute the k × suppression_limit parameter grid (extra OLA-2 searches). Set `false` in benchmarks to skip it. |
| `sheet_joins` | array | Config-driven join steps for multi-sheet Excel input: `{ "left": "<sheet>", "right": "<sheet>", "on": "<col>" \| ["<col>", ...], "how": "left"\|"right"\|"inner"\|"outer"\|"cross" }`. If omitted, sheets with a shared column are auto-joined; sheets with no shared columns are concatenated by row position. Only used when the input file is `.xlsx`/`.xls`. |

**FPE note:** the legacy `"fpe"` config section (PAN/digits-specific format-preserving encryption) has been removed from the Rust pipeline. General format-preserving encryption is still available via `encrypt` + `"format_preserving": true`. The PAN/digits-specific algorithms remain documented in `SKALD/preprocess.py` (reference implementation) and are invertible via `scripts/reverse_fpe.py` for data already encrypted under the old scheme.

---

## Output files

| File | Description |
|---|---|
| `output/status.json` | Structured result payload (see below) |
| `output/pipeline.log` | Timestamped, phase-tagged execution trace |
| `output/<output_path>` | Anonymized CSV (name set in config) |
| `output/equivalence_class_stats.json` | EC size distribution |
| `output/top_ola2_nodes.json` | Top-ranked generalization nodes from OLA-2 |
| `output/token_vault.json` | Token↔value mapping (if tokenization used) |
| `output/symmetric_keys.json` | Symmetric encryption keys (if `encrypt` used) |

`fpe_keys.json` is only produced by the legacy `SKALD/preprocess.py` reference path (PAN/digits FPE), not the Rust pipeline — see the FPE note under [Config schema](#config-schema).

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
    "n_log2_n":                793157.4
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
| 422 | `ANON_NO_QIS` | No quasi-identifiers defined |
| 500 | `IO_READ_FAILED` | File not found or unreadable |
| 500 | `IO_WRITE_FAILED` | Disk full or output not writable |
| 500 | `IO_PERMISSION_DENIED` | Permission denied |
| 500 | `INTERNAL_ERROR` | Unexpected error — check `output/pipeline.log` |

Full reference with suggested fixes: [`error_codes.txt`](error_codes.txt)

---

## Project layout

```
config/                    Runtime config JSON (volume-mounted)
data/                      Input CSV/JSON/Excel, read-only (volume-mounted)
output/                    Pipeline outputs (volume-mounted)
SKALD/
  Cargo.toml               Rust crate manifest
  preprocess.py            Reference Python implementation of preprocessing transforms
                           (parity spec for the Rust port; backs scripts/reverse_*.py)
  src/
    bin/skald_pipeline.rs  Binary entry point
    pipeline/
      bootstrap.rs         Config parsing, Logger, error types, CSV utilities
      pipeline.rs          Orchestrator — phase-tagged logging with elapsed time
      multitabular.rs      CSV/JSON/Excel input resolution, multi-sheet joins
      anonymization/       OLA-1, OLA-2, Z-histogram, hierarchical generalization
      preprocess/          Suppress, hash, mask, encrypt, tokenize
      pyffx_compat.rs      Pure-Rust pyffx-compatible FPE (HMAC-SHA1 Feistel)
      entry.rs             Error mapping → structured status.json
scripts/
  reverse_encryption.py    Reverses AES-GCM `encrypt` using symmetric_keys.json
  reverse_fpe.py           Reverses format-preserving encryption using fpe_keys.json
  reverse_tokenization.py  Reverses tokenization using token_vault.json
benchmark/
  generate_data.py         Streaming synthetic CSV generator (no RAM limit)
  run_benchmark.sh         Automated benchmark matrix (Rust and Python)
  compare_results.py       Side-by-side comparison report + speedup heatmap
  run_overnight.sh         nohup launcher for overnight runs
```

---

## Preprocessing operations

| Operation | Config key | Description |
|---|---|---|
| Column suppression | `suppress` | Drops column entirely from output |
| Salted hashing | `hashing_with_salt` | FNV-1a with per-column salt |
| Unsalted hashing | `hashing_without_salt` | FNV-1a, deterministic |
| Position masking | `masking` | Replaces specified character positions with mask char |
| Pseudo-encryption | `encrypt` | HMAC-SHA256 keystream XOR, hex-encoded |
| Format-preserving encrypt | `encrypt` + `format_preserving: true` | Preserves character class layout |
| Character cloaking | `charcloak` | Random character within same class (digit/upper/lower) |
| Tokenization | `tokenization` | Stable `prefix + sequential ID`, vault persisted to `output/` |

Legacy PAN/digits-specific FPE (`"format": "pan"|"digits"`) is no longer a Rust config option — see the FPE note under [Config schema](#config-schema). It's still implemented in `SKALD/preprocess.py` and invertible via `scripts/reverse_fpe.py`.

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

    "k_anonymize": { "k": 2 }
  }
}
```

```bash
cp patients.xlsx data/
cp this_config.json config/config.json
docker compose up --build
cat output/status.json   # outputs.sample_generalized_rows shows the joined + generalized rows
```

Two ready-to-run, verified examples (including a 3-sheet star-schema case) live in
[`examples/multitabular/`](examples/multitabular/README.md) — copy either straight into `data/`/`config/`.

Things worth double-checking if it doesn't work:

- `sheet_joins[].left`/`.right` must match the workbook's **sheet names exactly** (case-sensitive) — a typo produces `DATA_XLSX_INVALID` naming the sheets it *did* find.
- `on` must be a column present in **both** sheets — otherwise also `DATA_XLSX_INVALID`.
- With more than two sheets, chain multiple `sheet_joins` steps against the same `left` sheet name to build a star schema (each step's `right` sheet joins onto the running `left` frame).
- If `sheet_joins` is omitted entirely: sheets with identical column sets are stacked as more rows; otherwise SKALD auto-joins on whatever column names the sheets have in common, or concatenates by row position if they share none — explicit `sheet_joins` is more predictable and recommended once you have more than one sheet.

---

## Flow modes — DIRECT vs ORIGINAL

The OLA-2 search can run in two modes, controlled by `flow_mode`:

- **`original`** — the classic path: OLA-1 picks an initial generalization, then OLA-2 binary-searches the lattice using a `SparseHist`.
- **`direct`** — skips OLA-1 and builds a compact scalar `ZHist` (mixed-radix-encoded, ~16 bytes/entry) directly at the finest granularity, then runs OLA-2 on that. Falls back to `original` automatically if the encoding would overflow.
- **`auto`** (default) — pre-scans the input once to estimate record count `N` and each QI's domain size, computes the equivalence space `E = Π(QI domain sizes)`, and picks `direct` when `N·log₂(N) ≤ E`, else `original`.

`output/status.json` reports which flow ran (`outputs.flow`) along with the `n_approx`, `equivalence_space`, and `n_log2_n` values behind the decision.

---

## Reverse operations (authorized recovery)

For authorized re-identification of anonymized output, `scripts/` provides CLIs that invert the forward preprocessing operations using the key/vault files SKALD writes to `output/`:

```bash
python scripts/reverse_encryption.py   --input output/anonymized.csv --output recovered.csv --keys output/symmetric_keys.json
python scripts/reverse_fpe.py          --input output/anonymized.csv --output recovered.csv --keys output/fpe_keys.json
python scripts/reverse_tokenization.py --input output/anonymized.csv --output recovered.csv --vault output/token_vault.json
```

Each accepts CSV or JSON (auto-detected by extension) and an optional `--columns` filter; `reverse_tokenization.py` reports any tokens not found in the vault, which are left unchanged.

---

## Benchmarking

```bash
# Rust branch
bash benchmark/run_benchmark.sh --output benchmark/results_rust.json

# Python (master) branch in VM
bash benchmark/run_benchmark.sh --output benchmark/results_python.json

# Compare
python benchmark/compare_results.py \
    benchmark/results_rust.json \
    benchmark/results_python.json
```
