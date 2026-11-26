# Deploying anamika-spark

Templates only. The Co-ordinator (its own repo, not changed from here) renders them later.

| File | What it is |
|---|---|
| `Dockerfile` | one image for driver and executors, < 1 GB target, no models (R4) |
| `spark-defaults.conf` | R1 (`spark.authenticate`, secret file, network + IO encryption) and R2 (UI, event log off); copied into the image |
| `log4j2.properties` | WARN only |
| `sparkapplication.template.yaml` | Spark Operator `SparkApplication`, `runtimeClassName: kata-remote`, init data, memory-backed volumes |
| `main.py` | the `mainApplicationFile` spark-submit needs |

**Flow B egress.** A job whose `ANAMIKA_INPUT_URL` is set reads the data owner's Blob account directly, so its
driver and executors need egress to that endpoint (TCP 443). The per-job NetworkPolicy (same shape as
`workloads/ray/deploy/networkpolicy.yaml` in anamika-control-plane) does not allow it by default: the Co-ordinator
must add one allowlist entry for the host in `ANAMIKA_INPUT_URL` for that job and remove it with the job, never a
`*.blob.core.windows.net` wildcard. Outputs still go to `ANAMIKA_STORE_URL` `staging/{job}/`.

## What the Co-ordinator must provide per job

KBS resources at `anamika/{job}/...` (the AO writes `user-key` and `key-NN`; the Co-ordinator's own policy
controls release, bound to the init data's job id and image digest):

| Resource | Written by | Read by |
|---|---|---|
| `user-key` | AO (K_user, from the wrapped key) | driver only |
| `key-NN` | AO (saved keys, vault keys) | driver only |
| `spark-secret` | **Co-ordinator** (>= 32 random bytes, one per job) | every pod's init step (`python -m anamika_spark.initsecret`) |

`spark-secret` is not in the contract yet: someone has to mint and release it (see "Open points").

## Launching (variables)

Env vars the driver reads (`anamika_spark/run.py`). The Co-ordinator's `Spec` fields map as shown.

| Variable | From | Meaning |
|---|---|---|
| `ANAMIKA_JOB` | `Spec.JobID` | job id |
| `ANAMIKA_PHASE` (or `PHASE`) | `Spec.Phase` | `all` = measure then apply in one job; `measure` and `apply` = the two jobs of explore_k |
| `ANAMIKA_CHOICE` | `Spec.Choice` | the approved grid cell id (apply after explore_k). Opaque: passed back untouched |
| `ANAMIKA_STORE_URL` | `Spec.InputURI`'s container | `https://<account>.blob.core.windows.net/<container>`; objects live under `staging/{job}/` |
| `ANAMIKA_INPUT_URL`, `ANAMIKA_INPUT_ANONYMOUS` | Spec env | flow B only: the owner's `https://.../<container>/<prefix>/` holding `manifest.enc` and the parts, read with no credential when `ANAMIKA_INPUT_ANONYMOUS=1` (the only mode implemented; with a credential the job fails closed). Absent: input is `staging/{job}/` of `ANAMIKA_STORE_URL`. Outputs always go to `ANAMIKA_STORE_URL` |
| `ANAMIKA_KEY_MODE` | | `cdh` (default) or `dir` (files in `ANAMIKA_KEY_DIR`; NOT confidential, development only) |
| `ANAMIKA_SPARK_MASTER` | | `local[*]` for the single-VM path; unset on Kubernetes |
| `ANAMIKA_DRIVER_MEMORY`, `ANAMIKA_LOCAL_DIR` | | local mode only |
| `ANAMIKA_VAULT_PREFIX` | | where `vaults/{vault_id}/v{n}.enc` live; default the container root (workload contract) |
| `ANAMIKA_NER_MODEL_REF`, `ANAMIKA_NER_SHA256`, `ANAMIKA_NER_CACHE` | | only used if the manifest says `ner.required` |

Exit code: 0 only when `status.json` says `{"ok": true}`. The failure code is in `status.json`, never on stderr.

Local mode for small jobs is the same code path: `ANAMIKA_SPARK_MASTER='local[*]'` and no SparkApplication
(run the image with `docker run`, or `python -m anamika_spark.run` in a VM). The size threshold is the AO's call.

Template variables are listed at the top of `sparkapplication.template.yaml`.

## Hardening notes

* **R1** `spark.authenticate=true` with `spark.authenticate.secret.file`; the init step writes the secret
  hex-encoded, mode 0600, on a memory-backed emptyDir. `spark.network.crypto.enabled` encrypts RPC.
* **R2** no UI, no event log, WARN logging, `logscrub` on driver and executors, failure codes only.
* **Keys on executors**: column keys and token vaults reach executors by broadcast. With
  `spark.io.encryption.enabled=true` Spark encrypts spill, shuffle, cached blocks and broadcasts with an
  ephemeral per-application key, and local dirs are tmpfs (`spark.kubernetes.local.dirs.tmpfs`).
  `tests/test_hardening.py` scans the local dir after a job for key bytes and row text.
* **Image size**: `pip install pyspark` is ~490 MB because of jars a k-anonymity job never loads. The
  Dockerfile prunes MLlib, GraphX, Streaming, Connect, Hive, RocksDB (-165 MB); the test suite was run
  against a pruned copy. The image itself has NOT been built on this machine, so the < 1 GB figure
  (~870 MB) is an estimate from the pieces.
* **Spill to disk**: if a job's data exceeds executor RAM it spills to the (encrypted) local dir; size
  executors so a normal job fits in memory plus tmpfs, or mount an encrypted data disk.
