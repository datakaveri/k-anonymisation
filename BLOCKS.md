# SKALD as three blocks

Reference for the Anonymization Orchestrator (AO) integration. The monolithic
`skald_pipeline` binary is unchanged and still works exactly as before; this
describes the split form that the AO drives.

---

## 1. The three blocks

| Block | Operations | Secret state | Runs on | Image |
|---|---|---|---|---|
| `preprocess` | `suppress`, `masking`, `charcloak`, `tokenization` | token vault | the AO, in-TEE | `skald-preprocess` |
| `crypto` | `hashing_with_salt`, `hashing_without_salt`, `encrypt`, FPE | per-column keys | dispatched container | `skald-crypto` |
| `kanon` | `scan` → `solve` → `apply` | none (derived histograms only) | dispatched containers | `skald-kanon` |

Plus `skald-ao`, the orchestrator-side toolkit (planning, key minting,
sharding, stitching), which also carries `skald_preprocess`.

### Why operations fall where they do

The three-way split in the brief left two operations unassigned and put one in
a place worth revisiting:

- **`masking` → preprocess.** Unkeyed, deterministic, no secret state. It has
  nothing in common with the keyed operations and everything in common with
  `charcloak`.
- **FPE → crypto.** The config spells it as an `encrypt` variant, but it is
  keyed, so it belongs with the other key-bearing work whatever the config
  calls it.
- **`tokenization` stays in preprocess, but on the AO.** It needs no key, so it
  reads as preprocessing — but its vault is a *reversible* mapping from token
  back to plaintext. That is the one recoverable artifact the system produces.
  Sending it to a worker would put it outside the boundary the user attested
  before handing over their data, so it stays inside the TEE.
- **`suppress` runs first, and on the AO, before any sharding.** A column
  dropped on the orchestrator never reaches a container at all. Dropping it
  later would produce the same file and a weaker guarantee.

---

## 2. The two invariants column sharding rests on

### Row identity

The AO stamps a reserved `__skald_rid` column onto every row before it splits
anything. Every block preserves row count and row order and passes the rid
through untouched, so the AO stitches column shards back together by rid rather
than by position. Targeting the rid in a config is refused
(`BLOCK_RID_PROTECTED`).

k-anonymization stars out QI values; it never deletes rows. The rid space on
the way out is identical to the one on the way in, which is what makes the
stitch total. `kanon apply` also writes `<shard>.suppressed_rids.json` so the
AO can propagate a starred record into the column shards k-anon never saw, if
job policy requires that.

### The AO owns all key material

A worker never mints a salt or a key. If two row shards of one column were
hashed by two containers that each generated their own salt, the same plaintext
would produce two different digests, the column would be silently destroyed,
and the output would look like ordinary hash output. `skald_ao keygen` mints
the keyset once per job, inside the TEE, and it travels in the block manifest.
A `crypto` worker missing a key it needs fails with `BLOCK_KEY_MISSING` rather
than generating one.

This is also what makes the crypto block safe to fan out across rows.

---

## 3. The block manifest

Every block binary is invoked identically:

```sh
skald_<block> --manifest /job/manifest.json      # or SKALD_MANIFEST=<path>
```

Relative paths resolve against the manifest's own directory, so the AO can
mount a self-contained job directory without caring about the container's
working directory.

```jsonc
{
  "schema_version": 1,
  "job_id": "job-123",
  "shard_id": "crypto_1",
  "block": "preprocess" | "crypto" | "kanon",
  "stage": "scan" | "solve" | "apply",   // kanon only

  "config": "config/job.json",           // the ordinary SKALD job config
  "columns": ["Aadhaar", "Email"],       // what the AO routed here
  "input":  "shards/crypto_1.csv",
  "output": "shards/crypto_1.out.csv",
  "artifacts_dir": "artifacts",
  "row_id_column": "__skald_rid",

  "keys": {                              // crypto only, from `skald_ao keygen`
    "hash_salts":     { "Aadhaar": "<hex>" },
    "symmetric_keys": { "Email":   "<hex>" },
    "fpe_keys":       { }
  },

  "inputs":   [],                        // kanon solve: the scan artifacts
  "solution": "artifacts/solution.json", // kanon apply
  "vault":    "artifacts/token_vault.json"
}
```

One config drives every block. A block applies only the parts of it that touch
columns in `columns`, and reports the rest as `deferred` — that is the AO's
routing decision, not an error. A column listed in `columns` but absent from
the shard CSV *is* an error (`BLOCK_COLUMN_NOT_IN_SHARD`), so a routing bug
surfaces instead of silently skipping work.

Each run writes `<artifacts_dir>/<shard_id>.status.json` and prints the same
document on stdout, in the `status.json` shape the monolith already emits:

```jsonc
{ "status": "success", "phase": "done",
  "outputs": { "applied": ["hash_salted:Aadhaar"], "deferred": [],
               "rows_in": 12000, "rows_out": 12000, "output": "…" } }
```

Exit codes: `0` success, `1` reported error, `2` usage error.

---

## 4. k-anonymity: `scan` → `solve` → `apply`

k-anonymity is the one thing in SKALD that cannot be column sharded. The
guarantee is a property of the whole QI tuple over the whole dataset, so every
QI column has to reach the same place and every row has to be counted. A shard
holding only part of the tuple is rejected with `BLOCK_QI_SHARD_INCOMPLETE`.

It shards well by *rows*:

```
  scan   (map,    per row shard)  → partial histogram + local column stats
  solve  (reduce, exactly once)   → global histogram → OLA-1 → OLA-2 → RF
  apply  (map,    per row shard)  → generalized rows
```

**`scan` keys its histogram on raw values, not bucket indices.** A bucket index
depends on the global column minimum and the global categorical domain, and no
single shard knows either. Raw-value keys are shard-independent, so partial
scans merge by addition and `solve` derives the index space afterwards.

### What this fixes about the two-pass flow

The monolith's `pass1` reads the data, builds a histogram, reports `k_optimal`
and throws the histogram away. `pass2` reads the same data again to rebuild the
same histogram. Under the AO that is not merely wasteful: the raw dataset has
to be held — or re-fetched and re-exposed to workers — across a human decision
point that may take minutes or days.

So `solve` persists the merged histogram as `artifacts/histogram.json`:

```
pass1 :  scan (fan-out)  →  solve   → k_optimal, parameter grid, histogram.json
         ──────── user picks k ────────
pass2 :  solve (inputs: [])          → final_rf, below-k classes
         apply (fan-out)             → generalized shards
```

Pass 2 is a pure re-solve over a derived aggregate. It re-reads no rows and
needs no access to the data at all — verified in
`pass_two_resolves_from_the_persisted_histogram_with_no_data_present`, which
deletes every input file before solving. A job can be re-solved for several
candidate k values at essentially zero cost and zero additional exposure.

Set `pass` to `no_bounds` to run scan → solve → apply in one go with a
pre-chosen k.

### What this fixes about suppression

The monolith counts equivalence classes **per chunk** while generalizing, so a
record whose class is globally far above k is still starred when its own chunk
holds few members of it. With one chunk that is invisible; with the AO fanning
out row shards it corrupts results in proportion to the fan-out.

`solve` computes the below-k set once, globally, and `apply` tests membership
instead of counting locally. Measured on 12,000 rows: 4 shards and 120 shards
both star exactly 10 records, matching the monolith's single-chunk run.

### Label space, not index space

The below-k set holds *generalized label tuples*, not histogram indices, and
the distinction is load-bearing.

OLA-2 models categorical generalization as integer division on the domain
index. What actually gets published comes from the configured
`categorical_hierarchies` — and for a column with no hierarchy, every value
above level 1 collapses to `*`. The two disagree: on the reference dataset
OLA-2 reports 270 equivalence classes while the released table has 99. Since
k-anonymity is a property of the released table, `solve` evaluates the below-k
set over exactly the strings that will be written. `solve` and `apply` share
one `generalize_tuple` function so they cannot drift apart.

A row whose QI values cannot be placed — unparsable, outside every configured
interval, or absent from the categorical domain — never entered the histogram,
so no class can vouch for it. `apply` stars it rather than publish a value
whose class size is unknown.

---

## 5. End-to-end

```sh
CFG=config/job.json; DATA=data/input.csv; JOB=job-123

# ── On the AO, in-TEE ────────────────────────────────────────────────────────
skald_ao plan   --config $CFG --job $JOB --data $DATA --out plan.json
skald_ao keygen --config $CFG --out keys.json
skald_ao stamp  --input $DATA --out staged/staged.csv

# One shard per block group, holding only that group's columns.
skald_ao project --input staged/staged.csv --out shards/pre.csv    --columns "PatientID,Name,DoctorID"
skald_ao project --input staged/staged.csv --out shards/crypto.csv --columns "Aadhaar,Phone,Email"
skald_ao project --input staged/staged.csv --out shards/kanon.csv  --columns "Age,PINCode,Gender,BloodGroup"

skald_preprocess --manifest manifests/preprocess.json          # order 1, on the AO

# ── Dispatched ───────────────────────────────────────────────────────────────
skald_crypto --manifest manifests/crypto.json                  # order 2, fan out freely

skald_ao split --input shards/kanon.csv --out-dir shards/rows --prefix k --rows 100000
skald_kanon --manifest manifests/scan_$i.json                  # order 3, one per row shard
skald_kanon --manifest manifests/solve.json                    #          exactly once
skald_kanon --manifest manifests/apply_$i.json                 #          one per row shard

# ── Back on the AO ───────────────────────────────────────────────────────────
skald_ao stitch --base staged/staged.csv --out output/anonymized.csv \
                --shards "shards/pre.out.csv,shards/crypto.out.csv,shards/rows/k_1.out.csv,…" \
                --routed "PatientID,Name,DoctorID,Aadhaar,Phone,Email,Age,PINCode,Gender,BloodGroup"
```

`--routed` is every column sent to any block. It is what separates the two
reasons a column can be missing from the shards that came back: a routed column
nobody returned was **suppressed** and is dropped; a column never routed is
**passthrough** and its base value is kept. This cannot be inferred from the
shards alone, and guessing either leaks a column the job asked to drop or
deletes one it asked to keep.

`stitch` fails with `BLOCK_SHARD_INCOMPLETE` if any row id is unaccounted for.
A worker that lost rows must not produce output that merely looks shorter.

---

## 6. The plan

`skald_ao plan` answers the three questions the AO cannot answer itself:

```jsonc
{
  "groups": [
    { "block": "preprocess", "order": 1, "runs_on": "orchestrator",
      "columns": ["PatientID", "Name", "DateOfBirth", "HospitalName", "DoctorID"],
      "operations": ["suppress:PatientID", "…", "tokenize:DoctorID"],
      "row_parallel": false,
      "row_parallel_note": "tokenization allocates sequential ids from a shared vault (DoctorID) — …" },
    { "block": "crypto", "order": 2, "runs_on": "container", "row_parallel": true,
      "columns": ["AadhaarNumber", "InsuranceID", "PhoneNumber", "Email"] },
    { "block": "kanon",  "order": 3, "runs_on": "container", "row_parallel": true,
      "columns": ["Age", "PINCode", "Gender", "BloodGroup"],
      "stages": ["scan", "solve", "apply"] }
  ],
  "passthrough_columns": ["Diagnosis", "MedicationPrescribed"],
  "keys_required": { "hash_salts": ["AadhaarNumber", "InsuranceID"],
                     "symmetric_keys": ["Email"], "fpe_keys": [] },
  "multi_block_columns": [],
  "notes": ["…"]
}
```

- **`order`** — groups sharing a number may run concurrently; a higher number
  must not start until every lower one has finished for the columns they share.
- **`row_parallel: false`** — the group must not be split across rows.
  Tokenization is the case that triggers it: two row shards of one tokenized
  column would each start their counter at 1 and mint the same token for
  different values. Column sharding is safe here (each column goes to exactly
  one place); row sharding is not.
- **`multi_block_columns`** — columns touched by more than one block, surfaced
  because this is where a plan is most likely to be misread.

Pass `--data` to have the plan validated against the real header
(`PLAN_COLUMN_MISSING`) and to get `passthrough_columns`.

Conflicts are caught before any container starts: a column that is both
suppressed and a quasi-identifier, or both suppressed and a crypto target,
fails with `PLAN_COLUMN_CONFLICT`. A column that is both a QI and a crypto
target is allowed but produces a note — the crypto group runs first, so k-anon
would generalize digests and numeric ordering would not survive.

---

## 7. Error codes

| Code | Meaning |
|---|---|
| `BLOCK_MANIFEST_INVALID` | Manifest unreadable, malformed, or missing a required field |
| `BLOCK_SCHEMA_MISMATCH` | Manifest `schema_version` this binary does not understand |
| `BLOCK_MISMATCH` | Manifest targets a different block than the binary implements |
| `BLOCK_KEY_MISSING` | Crypto block was not given key material for a routed column |
| `BLOCK_COLUMN_NOT_IN_SHARD` | A routed column is absent from the shard CSV |
| `BLOCK_RID_PROTECTED` | The reserved row-id column was targeted, collided, or lost |
| `BLOCK_QI_SHARD_INCOMPLETE` | A k-anon shard is missing part of the QI tuple |
| `BLOCK_HISTOGRAM_MISSING` | `solve` had neither scan artifacts nor a persisted histogram |
| `BLOCK_HISTOGRAM_MISMATCH` | Persisted histogram was built for a different QI set |
| `BLOCK_SCAN_INCONSISTENT` | Scan artifacts disagree on QI column order or arity |
| `BLOCK_SOLUTION_INCOMPLETE` | `apply` was given a pass-1 solution with no `final_rf` |
| `BLOCK_ARTIFACT_INVALID` | A kanon artifact is not in the expected shape |
| `BLOCK_SHARD_INCOMPLETE` | Stitching found row ids no shard accounted for |
| `PLAN_COLUMN_CONFLICT` | Config assigns a column to blocks that cannot both have it |
| `PLAN_COLUMN_MISSING` | Config targets a column the dataset does not have |

All other codes are the monolith's existing ones, unchanged.

---

## 8. Images

```sh
TAG=v1 REGISTRY=ghcr.io/datakaveri ./docker/build-blocks.sh
```

Each block gets its own image on purpose. A single image with three entrypoints
would give the three blocks one measurement, so the coordinator could not
attest "this container can only hash" separately from "this container can only
generalize". Separate binaries mean separate digests mean separate
measurements — the property the attestation step in the AO flow depends on.

All four images build `FROM scratch`: no shell, no OS, no package manager
(~1.3 MB each). A worker holding one column shard and one key can do nothing
else with them.

---

## 9. Open items

- **`kanon solve` is a single reduce and holds the merged histogram in memory.**
  It is bounded by the number of distinct QI tuples, not by row count, but a
  wide numeric QI range can still make it large. `qi_constraints` and
  `fixed_bins` are the lever; a hard guard that fails with a re-plan hint is not
  yet wired up.
- **Blocks read and write plain CSV.** Fine at current volumes and it keeps one
  dialect end to end, but a columnar format would cut the projection and stitch
  cost substantially at scale.
- **The index-space / label-space divergence is worked around, not resolved.**
  `solve` evaluates suppression in label space, which is correct for the
  released table, but OLA-2 still searches the lattice using integer division
  on categorical domain indices. Its reported class counts therefore describe a
  table that is not the one published. Fixing that properly means teaching
  `merge_histogram` about `categorical_hierarchies`, which changes lattice
  results for existing configs — a deliberate decision, not a refactor.
