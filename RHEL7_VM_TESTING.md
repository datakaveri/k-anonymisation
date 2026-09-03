# Testing the SKALD binary on a RHEL 7 VM

**If you are a Claude Code session working on this, read this first — it is the
whole brief.** You are most likely running on the *developer machine* and
driving the VM over SSH; see "Getting at the VM" below for why.

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

**Why 32 GB, measured rather than guessed.** A 2.15 GB / 14.4-million-row input
was run on this VM three ways:

| Configuration | Wall clock | Peak RSS | Peak disk |
|---|---|---|---|
| Default (parameter grid on, AUTO → ORIGINAL) | 68.5 min | 9.66 GB | 11.1 GB |
| `compute_parameter_grid: false` | 27.3 min | 9.66 GB | 10.5 GB |
| …plus `flow_mode: "direct"` | 23.5 min | 9.66 GB | 10.4 GB |

All three produced the same answer (479,228 equivalence classes), and all three
peaked at the same memory to within 0.01%.

**Memory tracks distinct quasi-identifier combinations, not rows or file size.**
The base histogram held 13,354,633 buckets for 14,400,000 rows — a mean of 1.1
rows per bucket, because `PINCode` was a quasi-identifier at its full 687,001
values. That works out to ~760 bytes per bucket: a `HashMap<Vec<i64>, i64>` key
allocation plus hashmap overhead and resize headroom.

So a 5–6 GB input with quasi-identifiers this fine-grained wants **32 GB**. With
coarser ones it may need far less — the honest way to find out is to run a
sample of the real data and read the `buckets=` line from `pipeline.log`, then
multiply by 760 bytes.

**Two things that do *not* reduce memory**, despite looking as though they
should:

- `compute_parameter_grid: false` saves 41 of the 68 minutes and nothing at all
  in RAM. Set it anyway — it is the single biggest time saving available — but
  do not size the machine around it.
- `flow_mode: "direct"` saves a further 4 minutes and also nothing in RAM. The
  Z-histogram is compact (~16 bytes per entry), but `pipeline.rs` converts it
  into the `SparseHist` unconditionally to feed the parameter grid, k-optimal
  and the equivalence-class stats, so the large representation gets built
  either way. Worth revisiting in the pipeline itself; not something to plan
  around today.

The lever that *does* work is coarsening the quasi-identifiers — a larger
`size` value for a numerical QI, or removing a high-cardinality column from the
QI set entirely.

**Why only 4 vCPU.** The pipeline is single-threaded — the eighth core would
sit idle. Spend the budget on disk throughput instead: the run reads and writes
tens of gigabytes sequentially, so a slow disk, not the CPU, is what will make
it take all afternoon.

### Azure specifically: do not test on `/mnt`

A default Azure RHEL 7 image partitions far smaller than this workload needs.
The VM this was first tested on came up as:

```
/dev/mapper/rootvg-rootlv  2.0G   /
/dev/mapper/rootvg-homelv  1014M  /home
/dev/sdb1                   32G   /mnt
```

Two problems. `/` and `/home` are far too small to hold even one copy of a 6 GB
input, and `/mnt` — the only roomy filesystem — is the Azure **temporary disk**:
its contents are lost when the VM is deallocated, resized, or moved to another
host. It is fine for scratch and for a throwaway test, and wrong for results
and key material, which cannot be regenerated.

**Attach a managed data disk** (100 GB, Premium SSD) and mount it, rather than
working in `/mnt`:

```bash
sudo mkfs.xfs /dev/sdc
sudo mkdir -p /data && sudo mount /dev/sdc /data
echo "/dev/sdc /data xfs defaults,nofail 0 2" | sudo tee -a /etc/fstab
sudo chown "$USER" /data
```

Then keep the bundle, the input and the output under `/data`. Pointing
`--chunks` at `/mnt` and `--output` at `/data` is a reasonable split — scratch
on the ephemeral disk, results on the durable one:

```bash
./run.sh --config /data/cfg/live.json --data /data/in/patients.csv \
         --output /data/runs/$(date +%F) --chunks /mnt/skald-scratch
```

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

## Getting at the VM

**Modern editor tooling does not run on RHEL 7, and does not need to.**

VS Code Server has required glibc ≥ 2.28 since VS Code 1.86 (January 2024).
RHEL 7 ships glibc 2.17, so Remote-SSH refuses to connect:

```
The remote host does not meet the prerequisites for running VS Code Server
… find GLIBC >= v2.28.0 (but found v2.17.0 instead)
```

The same wall stands in front of Node.js: official Linux builds from Node 18
onward are linked against glibc 2.28, so Claude Code cannot be installed on the
VM from the normal packages either.

**Do not fight this.** Nothing is supposed to be installed on that host — that
is the entire premise of shipping a static binary. Keep the editor and Claude
Code on the developer machine and treat the VM as a machine you send commands
to:

```bash
# From the developer machine
scp skald-rhel7.tar.gz rhel7-vm:/tmp/
ssh rhel7-vm 'cd /opt/skald && ./run.sh --config config/pg.json'
ssh rhel7-vm 'cat /opt/skald/output/status.json'
scp rhel7-vm:/opt/skald/output/pipeline.log ./
```

A Claude Code session on the developer machine can run those `ssh` and `scp`
commands directly, which is the smoothest way to work through the test plan
below: the repo, the git history and the editor stay where the tooling works,
and only the binary and its inputs cross to the VM.

Set up an SSH alias so every command is one word shorter and no password is
retyped:

```
# ~/.ssh/config on the developer machine
Host rhel7-vm
    HostName 10.0.0.42
    User skald
    IdentityFile ~/.ssh/id_ed25519
    ServerAliveInterval 30
```

### If you really need an editor on the VM

Two options, both worse than the above:

- **Pin VS Code to 1.85.2** — the last release whose server runs on glibc 2.17.
  The *client* must be 1.85.2 too (the server version is chosen by the client's
  commit), the Remote-SSH extension must be pinned to a compatible version, and
  auto-update must be off (`"update.mode": "none"`,
  `"extensions.autoUpdate": false`). You are then frozen on a 2024 editor with
  no security updates — acceptable for a short test, not as a working setup.
- **Install Node from the unofficial glibc-217 builds** at
  `unofficial-builds.nodejs.org` (`linux-x64-glibc-217` variants exist for
  Node 20 and 22) and run Claude Code on the VM itself. These are community
  builds, not the official release artifacts — reasonable for a throwaway test
  VM, not something to standardise on.

Neither changes what is being tested. The pipeline binary does not care what
editor is attached to the host.

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
the VM only for configs and reference — or skip the clone entirely and drive
the VM over SSH, as in "Getting at the VM" above. If you genuinely cannot move a file onto
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

Verified on a real RHEL 7.9 host (kernel 3.10.0-1160, glibc 2.17, 4 vCPU,
15 GB RAM) against PostgreSQL 13.14 from Red Hat Software Collections:

- The static binary runs with no shared libraries. (`file` calls it a "shared
  object" — that is `file` misreading a static-PIE image; `ldd` says
  `statically linked`.)
- The fixed layout, `--config`/`--data`/`--output`/`--chunks`, and the `SKALD_*`
  variables all work; key material follows `--output`.
- 50,003 rows read over TLS and 50,003 written back. Every column type came
  through faithfully — `date`, `numeric`, `boolean`, `timestamptz`, `jsonb`,
  `bigint` — NULLs stayed NULL, embedded commas and quotes survived, and an
  embedded newline was replaced with spaces as documented. The source table was
  untouched.
- Sink modes `append`/`create`/`truncate`/`replace` behave as specified;
  `append` to a missing table fails with `DB_CONFIG_INVALID` and creates
  nothing.
- TLS: `disable`, `require`, `verify-ca` and `verify-full` all connect against a
  CA-signed certificate (via both a DNS and an IP SAN), and against a
  self-signed certificate supplied as `sslrootcert`. The wrong CA, no CA, and a
  different pinned certificate are all correctly refused.
- Passwords appear nowhere in `pipeline.log` or `status.json`.

**Still not verified:**

- The **Docker/Alpine build of the bundle**. Everything above ran a musl binary
  cross-built on the developer machine with the host C compiler for `ring`; on
  Alpine the native gcc targets musl, which is the supported path, but that
  exact build has not been run. Build it once with
  `scripts/package_rhel7.sh` and repeat tests 1 and 2 against the result.
- A run at **5–6 GB scale**. The largest measured here was 2.15 GB / 14.4M rows
  (see the sizing table above), which completed successfully in every
  configuration.
