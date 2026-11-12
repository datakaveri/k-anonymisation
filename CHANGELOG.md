# Changelog

All notable changes to SKALD are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). The version in `SKALD/Cargo.toml`
is the release version; tags are `v<version>`.

## [4.1.0] — unreleased

### Added

- **Block deployment for an orchestrator.** Three separately built and
  attested workers — `skald_preprocess` (suppress, masking, charcloak,
  tokenization), `skald_crypto` (`hashing_with_salt`, `encrypt`) and
  `skald_kanon` (k-anonymity as `scan` → `solve` → `apply`) — plus
  `skald_ao`, the orchestrator's toolkit (`plan`, `stage`, `keygen`,
  `project`, `split`, `stitch`, `solve`, `grid`, `manifest`, `chunks`), and
  per-block images in `docker/`. `skald_pipeline` is unchanged.
  - A job run as blocks releases what the monolith releases from the same
    data and config, checked byte for byte by the tests (both flows,
    l-diversity, removal of a `*` class smaller than k). Every block calls the
    monolith's own code for each technique; `solve` makes the monolith's class
    decision over the merged histogram and enforces `suppression_limit` before
    any row is written.
  - Key material: `skald_ao keygen --keys <dir>` mints keys into the key
    directory, in the monolith's files (`block_hash_salts.json` holds a job's
    salts when `shared_hash_salts` is off). It prints column names only. A
    block never creates a key (`BLOCK_KEY_MISSING`), and refuses a key
    directory or token vault inside its artifacts directory
    (`KEY_MATERIAL_IN_OUTPUT`).
  - `kanon apply` returns only the row id and the QI columns and lists the rows
    it removed; `stitch --removed` drops them from every column, and a row
    missing a processed column fails the stitch (`BLOCK_SHARD_INCOMPLETE`)
    instead of falling back to its staged value.
  - The block manifest is strict: unknown fields are refused.
- **`cleaning`** config section (missing-value tokens, whitespace, required and
  numeric columns, `max_dropped_fraction`), applied by `skald_ao stage`.
  Parsed strictly like the rest of the config; `skald_pipeline` ignores it and
  logs a warning.
- **Regex masking `"length": "all"`:** a `before` / `after` pattern masks
  everything on that side of the first occurrence of its delimiter.

### Changed

- A regex masking `length` that is zero, negative, or neither a whole number
  nor `"all"` is a config error. It used to be clamped to 0, which masked
  nothing.

## [4.0.0] — unreleased

This release fixes privacy and security defects found in an internal review in
October 2026. Several fixes change behaviour on purpose, and some refuse
configurations that used to run, because those runs released data that should
have been protected. Read **Migrating from 3.x** first.

### Migrating from 3.x

1. **Move key material out of `output/`.**
   - Keys, salts and token vaults now live in a separate key directory:
     `--keys`, `SKALD_KEYS`, `key_directory` in the config, default
     `<root>/keys`.
   - The run refuses to start while any of these files are in `output/`
     (`KEY_MATERIAL_IN_OUTPUT`):
     - `symmetric_keys.json`, `fpe_encrypt_keys.json`, `token_vault.json`
     - `nested_json_*`, `fhir_bundle_salts.json`
   - Move them; keep them out of anything you release.
   - If a past release shipped `output/` with these files, treat the tokenised
     and encrypted columns in it as reversible by the recipient.
2. **Fix configs the stricter parser refuses.** Unknown keys
   (`CONFIG_UNKNOWN_KEY`) used to be ignored silently; a misspelt
   `"suppres"` released the column. Also refused now:
   - QIs without `k_anonymize`
   - a non-integer or missing `k`
   - `suppression_limit` outside [0, 1]
   - unknown `pass` or `flow_mode` values
   - non-string column entries
   - non-empty `fpe` or `hashing_without_salt`
   - non-nesting `categorical_hierarchies`

   Keys starting with `_` are treated as comments.
3. **`encrypt` output changed.** Values are now `ENC1$` + hex (AES-SIV). Data
   encrypted by 3.x (XOR keystream) cannot be decrypted with the new code, and
   that scheme is broken. Re-encrypt from source.
4. **Format-preserving `encrypt` output changed.** It is now NIST FF1, over the
   whole value. Values with fewer than 10⁶ possible values of their shape, or
   with letters in a non-ASCII script, are refused in the tabular flow and
   removed in the nested-JSON/FHIR flows.
5. **Suppressed rows may be removed.** Rows that fail k used to be published
   with `*` QIs even when only a handful were suppressed, which singled them
   out. They are now removed when, together, they would form a `*` class
   smaller than k (or not l-diverse). `status.json` reports `removed_records`.
6. **`suppression_limit` is enforced.** Exceeding it is now an error
   everywhere; it used to be only a warning when OLA-2 chose the node.
7. **`hashing_with_salt` output changed.** Every flow now computes
   HMAC-SHA256 keyed by the salt's 32 decoded bytes, where it used to compute
   SHA-256(salt ‖ value); FHIR resource-id pseudonyms change the same way.
   Tokens no longer match those from 3.x or from earlier 4.0.0 builds, so
   rehash anything you join on a hashed column. Existing salt files (64 hex
   characters) keep working as the keys. To recompute a token elsewhere:
   `hmac.new(bytes.fromhex(salt), value.encode(), hashlib.sha256).hexdigest()`.
   Nested-JSON salts from 3.x were derived from the clock and process id, so
   are guessable; they are now refused (`KEY_MATERIAL_INVALID`). Move
   `nested_json_salt.json` away and rerun to generate a new one.
8. **PostgreSQL:**
   - The default `sslmode` is now `verify-full`.
   - `verify-ca` needs `sslrootcert`.
   - `PGPASSWORD` is no longer read implicitly; name the variable with
     `password_env`.
   - `${VAR}` expands only in connection fields.
9. **Container:**
   - Runs as uid 65532.
   - The image tag is `v4.0.0`.
   - Mount `./keys` at `/app/keys`, and make `output` and `keys` writable by
     that uid.

### Security

- **CSV records.** A line break inside a quoted CSV field no longer splits the
  record. Previously the fields after it were published raw, past
  suppression, hashing and generalisation. Misaligned rows are now an error.
- **Config fails closed.** Unknown, misspelt or mistyped keys are refused
  instead of silently disabling a technique or k-anonymity. `"k": 5.0` is 5;
  `"k": "5"` is an error, where it used to mean k = 2.
- **Key directory.** Key material is no longer written into the release
  directory. Files are created owner-only (0600 / 0700).
- **`encrypt`** uses AES-SIV instead of an XOR keystream that one known
  plaintext could reverse.
- **`hashing_with_salt`** is HMAC-SHA256, the standard keyed hash, instead of
  SHA-256 of the salt prepended to the value, which allows length extension.
  A token still resists guessing only while its salt stays secret.
- **Format-preserving encryption** uses NIST FF1 over the whole value instead
  of pyffx per character run. pyffx made one-character runs a Caesar shift and
  turned Aadhaar groups into a 10⁴ codebook.
- **No plaintext pass-through.** Non-ASCII letters are no longer passed
  through by format-preserving encryption, charcloak or class masking.
- **RNG.** Keys, salts and tokens come from the OS CSPRNG with no all-zero
  fallback. The nested-JSON salt is 32 random bytes, no longer clock + PID.
- **Masking fails closed.** A masking regex that cannot compile, a masking
  entry with no step, an unknown class mode, or a step missing from
  `apply_order` is a config error; each used to leave values unmasked.
- **`hashing_without_salt`** (unsalted SHA-256, reversible by enumeration) is
  removed.
- **Suppressed outliers.** These are no longer re-identifiable from a
  `*` class smaller than k.
- **Logs.**
  - QI values (decoded histogram buckets) are no longer written to
    `pipeline.log`.
  - Scratch chunks are deleted at the end of every run.
- **QI column resolution.** A QI column whose name ends in `_scaled` or
  `_encoded` is no longer published ungeneralised.
- **PostgreSQL connector:**
  - `${VAR}` values are never echoed in errors.
  - Errors and `Debug` output are scrubbed of credentials.
  - Channel binding is required with `verify-*`.
- **Dependencies.**
  - `zip` 9 (via `calamine` 0.38 and `rust_xlsxwriter` 0.101) fixes
    RUSTSEC-2026-0367/0368/0369.
  - `calamine` 0.38 fixes RUSTSEC-2026-0436 (a malformed `.xls` file could
    panic or exhaust memory).
  - `rustls` and related crates are updated.
  - `rustls-pemfile` (unmaintained) is replaced.

### Added

- **`l_diversity`**: `{"l": 2, "sensitive_attributes": ["<column>"]}` enforces
  distinct l-diversity in OLA-2 and on the written output.
- **`--keys` / `SKALD_KEYS` / `key_directory`** to place key material.
- **`filename`** (nested JSON): cuts a URL or path down to its file name,
  dropping the host, the storage path and any signed-URL parameters.
- **`shared_hash_salts`** (tabular, off by default): keeps each column's hash
  salt in `<key dir>/tabular_hash_salts.json`, so tables run one at a time
  against the same key directory hash a column alike. Don't run them in
  parallel: two runs that both create a salt for a new column disagree.
- **`decrypt_value` / `format_preserving_decrypt`** in
  `skald_ola2::pipeline::preprocess::crypto`, for reversal tooling.
- **Error codes:**
  - `CONFIG_UNKNOWN_KEY`, `DATA_MALFORMED_ROW`, `LATTICE_TOO_LARGE`
  - `KEY_MATERIAL_IN_OUTPUT`, `RNG_UNAVAILABLE`
  - `FPE_VALUE_UNSUPPORTED`, `FPE_DOMAIN_TOO_SMALL`
  - `ENCRYPTION_FAILED`, `TOKEN_SPACE_EXHAUSTED`
- **Run summary.** Every k-anonymity run logs one summary block, also in
  `status.json` → `outputs.anonymisation_summary`. It holds:
  - k, l, suppression limit, and lattice nodes searched and evaluated;
  - the chosen generalisation per QI, in words;
  - number of classes, DM\*, and class-size min / median / mean / max;
  - classes failing k or l;
  - records suppressed, published as `*`, and removed.

  Per-technique value counts go in `outputs.preprocessing`, and pass1 logs the
  full parameter grid.
- **End-to-end matrix.** `scripts/e2e_matrix.py` runs every input shape in
  single- and two-pass mode in parallel and checks every output.
- **Tests.** Integration tests in `SKALD/tests/`, including property tests of
  the k-anonymity guarantee.
- **Benchmarks.** Criterion benches in `SKALD/benches/`.
- **Repository setup.**
  - CI: fmt, clippy `-D warnings`, test, audit, doc.
  - CodeQL, a release workflow and Dependabot.
  - `rust-toolchain.toml`, `rustfmt.toml`, `clippy.toml`.
- **Documentation.**
  - `CONTRIBUTING.md`, `SECURITY.md`.
  - The Apache-2.0 `LICENSE`.

### Changed

- **`fixed_bins` is honoured.** It used to be parsed and ignored.
- **Exact `suppression_limit`.** Compared in whole records, so exactly the
  limit passes (0.29 × 100 used to reject 29).
- **One parsing rule everywhere.** Numeric QI cells are read the same way by
  every stage: finite, \|v\| ≤ 2^53, rounded. Cells with no bin are written
  as `*`. One `-1e18` used to blur every bin; `inf` overflowed.
- **Categorical QI values** are trimmed and NFC-normalised. Hierarchy leaf keys
  are normalised the same way.
- **Categorical QIs in the ORIGINAL flow.** OLA-1 handles any categorical QI;
  it used to accept only `blood group`, `gender` and `profession`.
- **OLA-2 search.**
  - Tags propagate along lattice links, where the old version rescanned the
    whole lattice for every node. Five QIs went from more than 60 s to 16 s.
  - Lattices above 1,000,000 nodes are refused instead of running out of
    memory.
- **Tokens** are random, not sequential (sequence numbers leaked input order).
  The tabular vault keeps mappings for columns not in the current config.
- **Nested-JSON hashes are full length.** `hashing_with_salt` in the nested
  flow now writes all 64 hex characters of the hash, as the tabular and FHIR
  flows do; it used to keep only the first 16.
- **JSON output keeps the input's key order**; it used to come back
  alphabetised.
- **Release builds** enable `overflow-checks`.
- **Version** is now `4.0.0`; it was `0.1.0` in `Cargo.toml` while tags said 3.x.

### Removed

- `hashing_without_salt` (tabular).
- The legacy `fpe` section (it was already ignored, which released its columns
  in clear).
- The pyffx module and the `sha1`, `cipher` and `ndarray` dependencies.
- `scripts/reverse_encryption.py`, `scripts/reverse_fpe.py` and
  `SKALD/preprocess.py`: Python leftovers that cannot reverse 4.x output.
- The unused `OLA2` struct in `lib.rs`.
- Dead duplicate implementations in `ola.rs`.
- The `_scaled` / `_encoded` column-name suffix handling (a leftover from the
  Python pipeline).

## [3.3] — 2026

Tagged `v3.3`; no GitHub Release was published. See `git log v3..v3.3`.

## [3.0]

Tagged `v3`. Rust rewrite of the pipeline.

## [2.4]

Tagged `v2.4`. Last Python release (`release/skald-2.4`).
