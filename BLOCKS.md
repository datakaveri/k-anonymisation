# SKALD as three blocks

Reference for the Anonymization Orchestrator (AO) integration. The monolithic
`skald_pipeline` binary is unchanged and still works exactly as before; this
describes the split form that the AO drives.

---

## 1. The blocks

| Unit | Work | Secret state | Runs on | Container role |
|---|---|---|---|---|
| `stage` | data cleaning, `suppress`, row-id stamping | none | the AO, in-TEE | — |
| `preprocess` | `masking`, `charcloak`, `tokenization` | token vault | dispatched container | `skald-preprocess` |
| `crypto` | `hashing_with_salt`, `hashing_without_salt`, `encrypt`, FPE | per-column keys | dispatched container | `skald-crypto` |
| `kanon` | `scan` → **solve (on the AO)** → `apply` | none (derived histograms only) | dispatched containers | `skald-kanon` |

`skald_ao` is the orchestrator-side toolkit: staging, planning, key minting,
sharding, solving, stitching, and emitting the Co-ordinator's chunk manifest.

### What the AO keeps, and why

Only two kinds of work stay on the orchestrator, and they are there for
different reasons.

**Data cleaning.** Missing-value sentinels normalised to one representation,
whitespace settled, unusable rows dropped. This is not an anonymisation
technique and is deliberately separate from the `preprocess` operations. It is
here because it *decides the row set*: dropping a row shifts every row range in
the chunk manifest, so it has to settle before anything is chunked or the
manifest describes a dataset that no longer exists. It also stops a missing
value reaching k-anonymisation as the literal string `"N/A"`, where it becomes
its own quasi-identifier value and splits equivalence classes that should have
merged.

**Suppression.** A column dropped on the orchestrator never reaches a container
at all. That is a stronger property than dropping it later, and it costs
nothing: the staging pass already has the file open.

Everything else is ordinary column work and belongs in a worker. Masking,
charcloak and tokenisation are dispatched.

### Operations the original three-way split left unplaced

- **`masking` → preprocess.** Unkeyed, deterministic, no secret state — nothing
  in common with the keyed operations, everything in common with `charcloak`.
- **FPE → crypto.** The config spells it as an `encrypt` variant, but it is
  keyed, so it belongs with the other key-bearing work whatever it is called.

### One caveat on tokenisation in a container

Tokenisation keeps a *reversible* vault mapping token back to plaintext. Running
it in a worker means that vault is produced outside the TEE, so it must come
back to the AO as an artifact and be treated as key material, not as output.

It also cannot be split across rows: two shards of one tokenised column each
start their id counter at 1 and mint the same token for different values.
Column sharding is safe — each column goes to exactly one container — so the
planner marks the group `row_parallel: false` whenever a tokenised column is
present, and the AO must give that column a single shard covering all its rows.

If row-parallel tokenisation is ever needed, the fix is a *keyed deterministic*
token (`prefix` + truncated HMAC of the value) rather than a sequential id.
That is stateless and shards freely, at the cost of a vault the AO has to
assemble from the workers' outputs rather than one a single worker owns.

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

**No container waits for the user.** The measure containers run, emit their
partial histograms, and exit. `solve` then runs *on the orchestrator*, because
it never touches a row: it reduces the scan artifacts into a histogram and
searches the lattice over that. The apply containers are not started until a k
has been chosen.

```
measure   N containers, fan out, EXIT          ~seconds
   │      each emits a partial qi_histogram
   ▼
barrier   AO merges → artifacts/histogram.json   no container
   │      AO computes the k × σ table            no container
   ▼
   ⏸      user chooses. Hours, days. Nothing is running.
   │      the table can be recomputed for any axes, free
   ▼
solve     AO, on the histogram alone             ~400 ms
   │
   ▼
apply     N containers, fan out, EXIT           ~seconds
```

This is what the chunk-manifest contract already asks for: the measure phase's
artifact "is small, contains no row data, and is returned to the AO **before
the next phase is planned**".

The alternative — holding a measure container open with a timeout — costs
container-hours per waiting job, needs a timeout policy nobody can set well
(what is the right deadline for a human decision?), and puts a process holding
QI data inside the wait. It also does not avoid a second container start, since
the apply phase needs different containers anyway. The only thing it would save
is the measure container's own startup, which is milliseconds for a 1.3 MB
scratch image.

Two consequences worth stating:

- **Exploring costs nothing.** `skald_ao grid` recomputes the table for any k
  and suppression-limit axes the UI asks for, straight from `histogram.json`.
  A user can change their mind as often as they like.
- **Pinning k skips the measure phase entirely.** When `k` is set in the config
  there is no barrier and the job streams once — which is the trade-off the
  `job-config` schema spells out.

### Cleaning changes what suppression costs

`solve` reports two numbers, not one:

- `suppressed_records` — rows the lattice suppresses to reach k.
- `unplaceable_records` — rows the scan could not place at all, because a
  quasi-identifier did not parse, fell outside every configured interval, or
  was not in the categorical domain. They never entered the histogram, so no
  class vouches for them and `apply` stars them.

`effective_suppression_rate` is the two together over the full row count, and it
is what the user actually loses. The lattice cannot see the second number — it
only knows about rows that reached the histogram — so without reporting it here
the loss would only become visible after the apply phase had already run.

Cleaning is the usual source. Emptying a QI column turns those rows into
unplaceable ones. Putting the QI columns in `cleaning.required_columns` drops
them up front instead, so the row count the user is shown is the row count they
get. `solve` warns when the effective rate exceeds the configured limit.

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
CFG=config/job.json; RAW=data/input.csv; JOB=3f1c9b2e-...

# ── On the AO, in-TEE ────────────────────────────────────────────────────────
# One pass: clean, suppress, stamp row ids. Must finish before anything is
# chunked, because cleaning decides the row set.
skald_ao stage  --config $CFG --input $RAW --out staged.csv --report stage.json

# Plan against the RAW header: the plan is what tells staging what to suppress.
skald_ao plan     --config $CFG --job $JOB --data $RAW --out plan.json
skald_ao keygen   --config $CFG --out keys.json
skald_ao manifest --config $CFG --job $JOB --data $RAW --out manifest.json
skald_ao chunks   --manifest manifest.json --input staged.csv \
                  --out-dir chunks/ --rows 250000

# ── Dispatched: preprocess phase ─────────────────────────────────────────────
skald_preprocess --manifest manifests/preprocess.json   # mask, charcloak, tokenize
skald_crypto     --manifest manifests/crypto.json       # hash, encrypt, FPE

# ── Dispatched: measure phase (barrier) ──────────────────────────────────────
skald_kanon --manifest manifests/scan_$i.json           # one per row shard, then EXIT

# ── Back on the AO: barrier, then the user ───────────────────────────────────
skald_ao solve --config $CFG --artifacts art/ --scans "art/mea_1.scan.json,…"
skald_ao grid  --config $CFG --histogram art/histogram.json \
               --k 5,10,25,50,100 --suppression 0,0.01,0.05
#   ... user chooses k. Nothing is running. ...
skald_ao solve --config $CFG_WITH_K --artifacts art/     # re-solve, no scan, no data

# ── Dispatched: apply phase ──────────────────────────────────────────────────
skald_kanon --manifest manifests/apply_$i.json          # one per row shard

# ── Back on the AO ───────────────────────────────────────────────────────────
skald_ao stitch --base staged.csv --out output/anonymized.csv \
                --shards "…" --routed "…"
```

`--routed` is every column sent to any block. It is what separates the two
reasons a column can be missing from the shards that came back: a routed column
nobody returned was **suppressed** and is dropped; a column never routed is
**passthrough** and its base value is kept. This cannot be inferred from the
shards alone, and guessing either leaks a column the job asked to drop or
deletes one it asked to keep.

`stitch` fails with `BLOCK_SHARD_INCOMPLETE` if any row id is unaccounted for.
A worker that lost rows must not produce output that merely looks shorter.

### Cleaning configuration

```jsonc
"cleaning": {
  "enabled": true,
  "null_tokens": ["", "na", "n/a", "null", "nil", "none", "nan", "-", "?", "unknown"],
  "null_replacement": "",
  "trim": true,
  "collapse_whitespace": true,
  "drop_all_empty_rows": true,
  "required_columns": ["Age"],        // row dropped when these are missing
  "numeric_columns": ["Age", "PINCode"],  // non-numeric becomes missing
  "max_dropped_fraction": 0.05        // refuse the job past this
}
```

Absent means disabled: cleaning changes the row set, so it is never applied to a
job that did not ask for it. `max_dropped_fraction` is the guard — a cleaning
step that discards half the dataset has changed the answer rather than tidied
the input, and `STAGE_TOO_MANY_DROPPED` names the reasons rather than only the
count.

Put the quasi-identifier columns in `required_columns` unless you have a reason
not to. See **Cleaning changes what suppression costs** above.

---

## 6. The Co-ordinator contract

`skald_ao manifest` and `skald_ao chunks` emit a document conforming to
`chunk-manifest.schema.json` in `anamika-control-plane`. SKALD is the
application whose column roles and phase structure that manifest describes, so
deriving it from the same config that drives the blocks keeps one source of
truth rather than having the AO restate SKALD's requirements somewhere they can
drift.

| SKALD | Contract phase |
|---|---|
| `stage` | — (runs before chunking; not a phase) |
| `preprocess` + `crypto` blocks | `preprocess` |
| `kanon scan` | `measure` (barrier, produces `qi_histogram`) |
| `kanon solve` | — (the AO's barrier reduce; not a phase) |
| `kanon apply` | `apply` (consumes `qi_histogram`) |

Two things this deliberately does not do:

- **It never names an image.** Phases carry a `container_role` and the
  Co-ordinator resolves it to a digest. An image reference emitted here would
  be a guess about something this side does not own, and the digest that matters
  is the one the Co-ordinator reports back after attesting.
- **It does not encrypt.** Each chunk's `digest` is the SHA-256 of the chunk
  *plaintext*, as the schema specifies, because the container checks it after
  decrypting. Encryption and delivery are the AO's.

### Known gap: two preprocess roles

SKALD ships `preprocess` and `crypto` as separate images so the crypto block can
be attested separately. The contract cannot express that today:

- `Chunk.phase` is an enum of three names, so a chunk cannot say which of two
  `preprocess` phases it belongs to.
- `/jobs/{job_id}/phases/{phase}/start` is keyed by the same name, so the two
  phases have no distinct address.

**Proposed minimal change:** give `Phase` a unique `id`, and have `Chunk.phase`
and the start endpoint reference that id, leaving `name` as the semantic kind.
Adding an optional field and moving the reference is one breaking change to
`Chunk.phase` rather than a redesign.

```jsonc
// Phase
"id":   { "type": "string", "minLength": 1 },   // unique within the manifest
"name": { "enum": ["preprocess", "measure", "apply"] }   // unchanged, now the kind
// Chunk
"phase": { "type": "string" }   // references Phase.id, was the name enum
```

Until then `skald_ao manifest` emits one `preprocess` phase and one role.
`--split-crypto` emits two and prints why the result will not validate.

## 7. The plan

`skald_ao plan` answers the three questions the AO cannot answer itself:

```jsonc
{
  "groups": [
    { "block": "stage", "order": 0, "runs_on": "orchestrator", "container_role": null,
      "columns": ["Age", "PINCode", "PatientID", "Name", "DateOfBirth"],
      "operations": ["clean:*", "require_non_null:Age", "suppress:PatientID", "…"],
      "row_parallel": false,
      "row_parallel_note": "cleaning decides the row set, so it must complete before the dataset is chunked — …" },
    { "block": "preprocess", "order": 1, "runs_on": "container", "container_role": "skald-preprocess",
      "columns": ["HospitalName", "DoctorID"],
      "operations": ["charcloak:HospitalName", "tokenize:DoctorID"],
      "row_parallel": false,
      "row_parallel_note": "tokenisation allocates sequential ids from a shared vault (DoctorID) — …" },
    { "block": "crypto", "order": 2, "runs_on": "container", "container_role": "skald-crypto",
      "row_parallel": true,
      "columns": ["AadhaarNumber", "InsuranceID", "PhoneNumber", "Email"] },
    { "block": "kanon",  "order": 3, "runs_on": "container", "container_role": "skald-kanon",
      "row_parallel": true,
      "columns": ["Age", "PINCode", "Gender", "BloodGroup"],
      "stages": ["scan", "apply"] }
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

## 8. Error codes

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
| `STAGE_COLUMN_MISSING` | A cleaning or suppression column is not in the input |
| `STAGE_TOO_MANY_DROPPED` | Cleaning would discard more rows than the job allows |

All other codes are the monolith's existing ones, unchanged.

---

## 9. Images

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

## 10. Open items

- **`kanon solve` is a single reduce and holds the merged histogram in memory.**
  It is bounded by the number of distinct QI tuples, not by row count, but a
  wide numeric QI range can still make it large. `qi_constraints` and
  `fixed_bins` are the lever; a hard guard that fails with a re-plan hint is not
  yet wired up.
- **Blocks read and write plain CSV.** Fine at current volumes and it keeps one
  dialect end to end, but a columnar format would cut the projection and stitch
  cost substantially at scale.
- **Row-parallel tokenisation is not supported.** Sequential ids need a single
  shard per tokenised column. The keyed-deterministic alternative is described
  in §1 and is not implemented.
- **The `chunk-manifest` phase-id gap above is unresolved**, so the crypto block
  cannot currently be attested separately under the contract as written.
- **The index-space / label-space divergence is worked around, not resolved.**
  `solve` evaluates suppression in label space, which is correct for the
  released table, but OLA-2 still searches the lattice using integer division
  on categorical domain indices. Its reported class counts therefore describe a
  table that is not the one published. Fixing that properly means teaching
  `merge_histogram` about `categorical_hierarchies`, which changes lattice
  results for existing configs — a deliberate decision, not a refactor.
