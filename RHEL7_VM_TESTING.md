# Testing the SKALD binary on a RHEL 7 VM

**If you are a Claude Code session running on the RHEL 7 VM, read this first —
it is the whole brief.**

---

## The goal

SKALD is a k-anonymisation pipeline. It used to be a Python program with a
Docker runtime; it is now a single statically linked Rust binary, so it can run
on a RHEL 7 host that has nothing installed on it — no Python, no Docker, no
PostgreSQL client, and no dependency on the host's (very old) glibc.

The `redhat7-binary-distribution` branch adds two things to that binary, and
this VM exists to prove both of them work on a real RHEL 7 host:

1. **The config is no longer fixed.** The binary used to insist on
   `./config/<first>.json`, `./data/`, `./output/`. It now takes `--config`,
   `--data`, `--output`, `--chunks` and `--root` flags, with matching `SKALD_*`
   environment variables. One bundle now serves every dataset.
2. **Data can come from, and go back to, PostgreSQL.** A config may read its
   rows from a table or query and load the anonymized result into another
   table, over TLS, instead of using CSV files. Files still work exactly as
   before, and the file outputs are always written regardless.

## What this VM is for — and what it is not for

**Run the binary here. Do not build it here.**

The bundle is built on a developer machine (Docker, Alpine, musl) and copied
across. RHEL 7 went end-of-life in June 2024, so `yum` has no repositories
without a subscription or a vault mirror, and the toolchain the build needs
(Rust ≥ 1.88) is not packageable there. Needing to install nothing on the host
is the entire point of the static binary — if you find yourself running `yum
install` to make the pipeline work, something has gone wrong with the approach,
not with the VM.

---

## VM sizing

The pipeline is **single-threaded**. Extra vCPUs will not make a run faster;
they only keep the OS and I/O out of the way. RAM and disk are what matter.

| Workload | vCPU | RAM | Disk |
|---|---|---|---|
| Smoke test — ≤100k rows, <100 MB input | 2 | 4 GB | 20 GB |
| **Typical — 1–5M rows, 0.5–2 GB input** (start here) | **4** | **8 GB** | **40 GB** |
| Large — 10–50M rows, 5–20 GB input | 4–8 | 16–32 GB | 100–200 GB |

**Why that much disk.** A run holds several copies of the data at once: the
input in `data/`, the RAM-sized splits in `chunks/`, a normalised
`_converted.csv` for JSON/Excel input (or `_pg_input.csv` for a database
input), and the anonymized result in `output/`. Budget **4–5× the input size**,
plus ~10 GB for the OS.

**Why that much RAM.** Chunk size is chosen at run time as 20% of
`MemAvailable`, and the histogram phase is the peak: the DIRECT flow holds
roughly 16 bytes per record, and the ORIGINAL flow holds one entry per distinct
quasi-identifier combination, which is heavier. More RAM means larger chunks and
fewer passes; too little just makes it slower, not wrong.

### The exact VM for a 5–6 GB test

| | |
|---|---|
| **OS** | RHEL 7.9 (the last 7.x — earlier minors are fine except 7.0, see below) |
| **vCPU** | **4** |
| **RAM** | **16 GB** |
| **Disk** | **100 GB, SSD-class** (≥250 MB/s sustained), as one volume mounted where the bundle lives |
| **Swap** | 4 GB |
| **Network** | Outbound TCP 5432 to the PostgreSQL host. Nothing inbound |

Cloud equivalents: AWS `m5.xlarge` + 100 GB gp3 · Azure `Standard_D4s_v3` ·
GCP `n2-standard-4`. On Proxmox/VMware/KVM: 4 vCPU, 16384 MB, 100 GB thin disk
on SSD storage.

**Where the 100 GB goes.** A 6 GB input is on disk several times over during a
run:

| | |
|---|---|
| `data/` — the input itself | 6 GB |
| `chunks/_pg_input.csv` or `_converted.csv` — only for a database, JSON or Excel input | 6 GB |
| `chunks/chunk_*.csv` — the RAM-sized splits, a full copy of the input | 6 GB |
| `output/` — the anonymized result | ~6 GB |
| A second output in the input's format (`.xlsx`/`.json`), when the input was not CSV | ~6 GB |
| OS, logs, the bundle | ~10 GB |

That is ~40 GB at peak for one run, and stale `output/` files are *reported*
rather than deleted unless the config sets `"clean_output": true` — so several
runs accumulate. 100 GB leaves room to iterate without housekeeping between
runs.

**Why 16 GB and not 8.** At ~200 bytes a row, 6 GB is roughly 30 million rows.
The peak is the histogram, and which one is built depends on the data:

- the DIRECT flow holds ~16 bytes per record — ~500 MB here, comfortable;
- the ORIGINAL flow holds one entry per *distinct* quasi-identifier
  combination, at roughly 100–150 bytes each. A few million distinct
  combinations is under a gigabyte; tens of millions is several.

16 GB covers both, and also lets the chunker use its full 10-million-row
chunks instead of splitting the work more finely. **Go to 32 GB** if the run
logs a `Warning: Z-histogram needs ~NNNMB` line, or if the quasi-identifier
columns are high-cardinality (a PIN code plus an exact age plus a district is
already a large space).

**Why only 4 vCPU.** The pipeline is single-threaded — the eighth core would
sit idle. Spend the budget on disk throughput instead: the run reads and writes
tens of gigabytes sequentially, so a slow disk, not the CPU, is what will make
it take all afternoon.

### Other VM settings

- **Disk layout** — put the bundle on the large volume, not on `/`. `chunks/`
  churns hard. ext4 or xfs, either is fine.
- **Do not mount that filesystem `noexec`** — the binary lives there.
- **Swap: 2–4 GB.** A safety net for the histogram peak; the run should never
  actually need it.
- **Clock sync (chrony or ntpd).** Only matters for `sslmode=verify-full`: a
  skewed clock makes valid certificates look expired and the connection fails
  with a confusing TLS error.
- **Network.** Outbound TCP to the PostgreSQL host (usually 5432). Nothing
  inbound is needed — the pipeline is a one-shot batch process with no
  listening socket.
- **SELinux.** Enforcing is fine. If execution is denied after copying the
  bundle in, the file's context is wrong rather than the policy:
  `restorecon -Rv /opt/skald`.
- **No CA bundle needed.** The Mozilla root certificates are compiled into the
  binary. Only a *private* CA needs a file on disk, via `sslrootcert`.
- **A PostgreSQL server is not needed on this VM** — and installing one on EOL
  RHEL 7 is painful. Point the connector at a database that already exists
  (a container on the dev machine, or a shared instance) and make sure the VM
  can reach it.

---

## Setup

### If you cloned the repo onto the VM

Cloning `redhat7-binary-distribution` on the VM is useful — it gives you the
configs, this document, and the packaging script. It does **not** give you a
binary, and building one here is the fallback, not the plan:

- `cargo build` needs Rust ≥ 1.88 (the crate is edition 2024, and `calamine`
  and `rust_xlsxwriter` set the floor). RHEL 7 has no such package; `rustup`
  can install it — RHEL 7's glibc 2.17 is exactly the minimum Rust supports —
  but you also need `gcc` for linking, from repositories that no longer exist
  without a subscription or a vault mirror.
- The result would be a **glibc-linked binary that runs only on this host**,
  which is the opposite of what the bundle is for.

So: build the bundle on the developer machine as below, and use the clone on
the VM only for configs and reference. If you genuinely cannot move a file onto
the VM, building here with `rustup` will work and is worth saying out loud in
the test report, because it means a different binary was tested than the one
that ships.

### Building the bundle

On the **developer machine** (which has Docker):

```bash
# Build a bundle carrying every config the VM should be able to run
bash scripts/package_rhel7.sh dist/skald-rhel7 config/
tar czf skald-rhel7.tar.gz -C dist skald-rhel7
scp skald-rhel7.tar.gz user@rhel7-vm:/tmp/
```

On the **VM**:

```bash
sudo mkdir -p /opt/skald && sudo tar xzf /tmp/skald-rhel7.tar.gz -C /opt/skald --strip-components=1
sudo chown -R "$USER" /opt/skald
cd /opt/skald
./run.sh --help
```

`./run.sh` is a wrapper that changes into the bundle directory first, so the
default `config/`, `data/` and `output/` resolve no matter where you invoke it
from. All flags pass straight through.

---

## Test plan

Work down the list. Each step assumes the ones above it passed.

### 1. It runs at all

```bash
cd /opt/skald
file ./skald_pipeline     # expect: ELF 64-bit … static-pie linked
ldd ./skald_pipeline      # expect: "not a dynamic executable" or "statically linked"
./run.sh --version
```

If `ldd` names any shared library, the wrong binary was shipped — it must be
the musl build out of the Docker builder stage.

### 2. The old fixed-layout behaviour still works

```bash
cp /path/to/input.csv data/
./run.sh
echo "exit=$?"
cat output/status.json
```

Expect exit 0 and `"status": "success"`. This is the regression check: nothing
about the flags may have broken the way the bundle worked before.

### 3. The config is genuinely not fixed

```bash
./run.sh --config config/telangana_ration.json
./run.sh --config /etc/skald/whatever.json --data /mnt/export/patients.csv
./run.sh --output /var/skald/runs/$(date +%F)
SKALD_CONFIG=/etc/skald/whatever.json ./run.sh
```

Check in `output/pipeline.log` that the `config` lines name the file you asked
for. Confirm that key material (`symmetric_keys.json`, `fpe_encrypt_keys.json`)
lands in whichever directory `--output` named — the keys must travel with the
results they reverse, or the output can never be reversed.

### 4. Errors are reported, not guessed at

```bash
./run.sh --nonsense                      # expect exit 1, CLI_INVALID_ARGUMENT
./run.sh --config /does/not/exist.json   # expect exit 1, CONFIG_NOT_FOUND
```

Both must still write `output/status.json` with a code, an HTTP status and a
suggested fix. Exit code 0 means success and 1 means failure, always.

### 5. PostgreSQL, reading

Point a config at a database the VM can reach:

```jsonc
"input": {
  "type": "postgres",
  "host": "db.internal", "port": 5432, "database": "health", "user": "skald",
  "password_env": "SKALD_PG_PASSWORD",
  "sslmode": "require",
  "table": "public.patients"
}
```

```bash
SKALD_PG_PASSWORD='…' ./run.sh --config config/pg.json
```

What to check:

- `pipeline.log` has a `postgres_in` line reading
  `user@host:port/database sslmode=…` — **and no password anywhere in the
  file.** Grep for the password to be sure.
- `chunks/_pg_input.csv` has the expected row count.
- Row counts in `status.json` match `SELECT count(*)` on the source.
- Try `sslmode=verify-full`. If it fails where `require` succeeded, the cause
  is either a certificate whose name does not match the host, a private CA
  (supply it with `sslrootcert`), or VM clock skew.

### 6. PostgreSQL, writing

```jsonc
"output_sink": { "type": "postgres", "table": "anon.patients", "mode": "replace" }
```

- Confirm the table appears with all-`text` columns and the anonymized rows.
- Confirm the files in `output/` were **also** written — the sink is an extra
  destination, never a replacement.
- Try `mode: "append"` against a table that does not exist: it must fail
  cleanly with `DB_CONFIG_INVALID` and say to use `mode: "create"` instead.
- Interrupt a load (Ctrl-C mid-run) and confirm the destination is untouched —
  the DDL and the load share one transaction.

### 7. Scale

Run the largest dataset you actually care about. Watch `free -m` and the disk
during the run; note peak RSS and peak disk. That is the real input for sizing
the production VM.

---

## Things that will trip you up

- **`grep MemAvailable /proc/meminfo` returns nothing.** RHEL 7.0 kernels
  predate that field. The pipeline then assumes 512 MB and makes small chunks:
  correct, but slower. Any RHEL 7.1+ kernel has it.
- **A password in the config file.** Use `"password_env": "VAR_NAME"`, or
  `${VAR}` in any string field. The config names the variable; the deployment
  supplies the value. A missing variable is a loud error, never a silent empty
  string.
- **Newlines in text columns.** The chunker splits on line boundaries, so the
  PostgreSQL reader replaces CR and LF inside values with spaces. This is the
  one place the connector changes the data. It is logged on every run.
- **`truncate` and `replace` destroy rows** in the destination table. Both warn
  before doing anything. Do not point them at a table you care about while
  testing.
- **Only one input file in `data/`.** Two files is an error
  (`DATA_AMBIGUOUS_INPUT`), not a guess.
- **`chunks/` is wiped at the start of every run.** Never leave anything there.

---

## What has already been verified, and what has not

Verified on the developer machine:

- The static musl binary builds and runs end-to-end with relocated `--config`,
  `--data`, `--output` and `--chunks`, and via the `SKALD_*` variables.
- `ldd` reports it statically linked; it runs with no shared libraries.
- The old no-flags layout still works, and all 115 unit tests pass.
- Config parsing, SQL generation, identifier quoting, `${VAR}` expansion and
  the connection-failure path are unit-tested; a refused connection reports
  `DB_CONNECT_FAILED`.

**Not yet verified anywhere — this is what the VM is for:**

- Anything against a **live PostgreSQL server**. No server was reachable from
  the development environment, so every successful read and write path is
  untested: `COPY` streaming, type-to-text conversion, the DDL modes, and TLS
  against a real certificate.
- The **Docker/Alpine build of the bundle**. The musl binary was cross-built
  locally with the host C compiler for `ring`; on Alpine the native gcc targets
  musl, which is the supported path, but that exact build has not been run.
- **RHEL 7 itself.** Nothing in this branch has executed on a RHEL 7 kernel.
