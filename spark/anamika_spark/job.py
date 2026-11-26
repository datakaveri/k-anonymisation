"""The k-anonymity job: SKALD's core on Spark, over the encrypted bundle.

Phases (the AO/Co-ordinator picks one per Spark job):

    all      measure then apply in one job (no user choice between them)
    measure  explore_k: write the encrypted k grid and the histogram, stop (the user then picks a cell)
    apply    explore_k: run with the chosen cell id; the histogram written by `measure` is the input

Driver / executor split (skald_core's documented distributed recipe, see SKALD/python/tests/driver.py):

    executors  read+decrypt parts, preprocess, observe stats / histogram, generalise, tally, finish, write
    driver     merge stats, build the model, merge histograms, search, decide, final k check, summaries

Rows never come to the driver: only small mergeable objects (stats, histogram, tallies) and, when a
job tokenises, the distinct values of the tokenised columns (SKALD's own token recipe needs them in
one place to issue tokens; the driver runs in the same confidential VM).

Commit protocol (the AO must never see a half result): outputs are sealed under apply/pending/, the
final k check runs over the CSV exactly as written, and only then are outputs moved to their names,
then summary.enc, then any vault version, and status.json LAST. Any failure deletes the phase's
objects and writes status {"ok": false, "code": ...}. A retry starts by clearing the phase directory.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import pyarrow as pa
import skald_core as sk

from . import joins, logscrub
from .bundle import Keys
from .errors import JobError, code_of, coded_iter
from .io import IoError, JobIO, input_from_spec, read_vault, store_from_spec, write_vault
from .kbs import KeySource, KeyStore, KeyUnavailable
from .keymap import job_keys, vault_specs
from .ner import NerSettings, ner_columns, redact_batch
from .parts import from_ipc, parse_csv, to_ipc, verify_part, write_csv

log = logging.getLogger("anamika_spark")
RUNTIME = "anamika-spark/0.1.0"
PHASES = ("all", "measure", "apply")


@dataclass
class ExecSpec:
    """Everything an executor needs that is not a secret. Pickled into tasks."""

    job: str
    store: Dict[str, str]
    header: List[str]
    entries: Dict[int, Dict[str, Any]]      # part -> manifest entry (rows, bytes, sha256)
    part_count: int
    plan: Any
    ner_cols: List[str] = field(default_factory=list)
    ner: Optional[NerSettings] = None


def _worker_io(spec: ExecSpec, secrets: Dict[str, bytes]) -> JobIO:
    # An executor holds only the input and output keys; manifest and summary keys stay on the driver.
    return JobIO.from_spec(spec.store, spec.job, Keys(secrets["input"], b"", secrets["output"], b""))


def _merge(a, b):
    a.merge(b)
    return a


# ---------------------------------------------------------------- executor stages
def _read_stage(spec: ExecSpec, bc_io):
    @coded_iter
    def run(it):
        logscrub.install()
        io = _worker_io(spec, bc_io.value)
        for n in it:
            data = io.read_part(n, spec.part_count)
            entry = spec.entries[n]
            verify_part(data, entry)
            batch = parse_csv(data, spec.header)
            if batch.num_rows != entry["rows"]:
                raise JobError("PARTS_MISMATCH")
            if spec.ner_cols:
                batch = redact_batch(batch, spec.ner_cols, spec.ner)
            yield n, to_ipc(batch)

    return run


def _token_values_stage(spec: ExecSpec, bc_pre):
    @coded_iter
    def run(it):
        logscrub.install()
        s = bc_pre.value
        pre = sk.Preprocessor(spec.plan, s["keys"], s["vault"], generate_missing=False, issue_tokens=True)
        acc: Dict[str, set] = {}
        for _, ipc in it:
            for col, vals in pre.token_values(from_ipc(ipc)).items():
                acc.setdefault(col, set()).update(vals)
        yield acc

    return run


def _preprocess_stage(spec: ExecSpec, bc_pre):
    @coded_iter
    def run(it):
        logscrub.install()
        s = bc_pre.value
        pre = sk.Preprocessor(spec.plan, s["keys"], s["vault"] or None)
        for n, ipc in it:
            yield n, to_ipc(pre.apply(from_ipc(ipc)))

    return run


def _observe_stage(plan, model=None):
    """Stats per Spark partition (model None) or histogram per partition."""

    @coded_iter
    def run(it):
        logscrub.install()
        acc = sk.Stats(plan) if model is None else sk.Histogram(model)
        for _, ipc in it:
            batch = from_ipc(ipc)
            acc.observe(batch) if model is None else acc.observe(model, batch)
        yield acc

    return run


def _generalise_stage(gen):
    @coded_iter
    def run(it):
        logscrub.install()
        for n, ipc in it:
            out, tally = gen.apply(from_ipc(ipc))
            yield n, to_ipc(out), tally

    return run


def _write_stage(spec: ExecSpec, bc_io, gen, decision):
    """Finish, serialise, seal under pending/, and tally the CSV exactly as written (the final k check's input)."""

    @coded_iter
    def run(it):
        import hashlib as _h  # noqa: PLC0415 - closure is pickled by value

        logscrub.install()
        io = _worker_io(spec, bc_io.value)
        metas, written = [], None
        for item in it:
            n, ipc = item[0], item[1]
            batch = from_ipc(ipc)
            if gen is not None:
                batch = gen.finish(batch, decision)
            data = write_csv(batch)
            io.write_pending(n, spec.part_count, data)
            if gen is not None:
                t = gen.tally(parse_csv(data, batch.schema.names))
                written = t if written is None else _merge(written, t)
            metas.append({"part": n, "rows": batch.num_rows, "plaintext_bytes": len(data),
                          "plaintext_sha256": _h.sha256(data).hexdigest(), "header": batch.schema.names})
        yield metas, written

    return run


def _publish_stage(spec: ExecSpec):
    @coded_iter
    def run(it):
        io = JobIO.from_spec(spec.store, spec.job, Keys(b"", b"", b"", b""))
        for n in it:
            io.publish_output(n)
        return
        yield  # pragma: no cover - makes this a generator

    return run


# ---------------------------------------------------------------- multi-table stages
def _table_read_stage(spec: ExecSpec, bc_io):
    """mapInArrow: part numbers in, one table's rows out (c0..cN strings, __id = part << 32 | row in part),
    so the order of the file is carried by a column and survives any shuffle."""

    @coded_iter
    def run(it):
        logscrub.install()
        io = _worker_io(spec, bc_io.value)
        names = [f"c{i}" for i in range(len(spec.header))] + [joins.ID]
        for b in it:
            for n in b.column("part").to_pylist():
                data = io.read_part(n, spec.part_count)
                entry = spec.entries[n]
                verify_part(data, entry)
                batch = parse_csv(data, spec.header)
                if batch.num_rows != entry["rows"]:
                    raise JobError("PARTS_MISMATCH")
                ids = pa.array([(n << 32) | i for i in range(batch.num_rows)], pa.int64())
                yield pa.RecordBatch.from_arrays(list(batch.columns) + [ids], names=names)

    return run


def _pack_stage(header: List[str]):
    """mapInArrow over the merged, sorted table: each Spark partition becomes one (partition, rows, ipc)
    row, which is the unit the k-anonymity stages already take (a part: number + Arrow IPC bytes)."""

    @coded_iter
    def run(it):
        from pyspark import TaskContext  # noqa: PLC0415

        batches = [b for b in it if b.num_rows]
        if batches:
            table = pa.Table.from_batches(batches).combine_chunks()
            data = table.select([f"c{i}" for i in range(len(header))]).rename_columns(header)
            out = data.to_batches()[0] if data.num_rows else None
        else:
            out = None
        rows = out.num_rows if out is not None else 0
        yield pa.RecordBatch.from_arrays(
            [pa.array([TaskContext.get().partitionId()], pa.int64()), pa.array([rows], pa.int64()),
             pa.array([to_ipc(out) if out is not None else b""], pa.binary())], names=["pid", "rows", "ipc"])

    return run


def _ner_stage(spec: ExecSpec):
    """NER over the merged table (a multi-table bundle redacts after the join, on the merged columns)."""

    @coded_iter
    def run(it):
        logscrub.install()
        for n, ipc in it:
            yield n, to_ipc(redact_batch(from_ipc(ipc), spec.ner_cols, spec.ner))

    return run


def _finish_stage(gen, decision):
    """Finish each part and keep it as the CSV round trip gives it back (what the final k check tallies and
    what the split reads), with its tally."""

    @coded_iter
    def run(it):
        logscrub.install()
        for item in it:
            batch = from_ipc(item[1])
            if gen is not None:
                batch = gen.finish(batch, decision)
            names = batch.schema.names
            data = write_csv(batch)
            back = parse_csv(data, names) if data else batch
            yield item[0], to_ipc(back), (gen.tally(back) if gen is not None else None), back.num_rows

    return run


def _expand_stage(header: List[str]):
    """mapInArrow: (part, ipc) rows back into table rows with __id = part << 32 | row."""

    @coded_iter
    def run(it):
        names = [f"c{i}" for i in range(len(header))] + [joins.ID]
        for b in it:
            for n, blob in zip(b.column("part").to_pylist(), b.column("ipc").to_pylist()):
                batch = from_ipc(bytes(blob))
                ids = pa.array([(n << 32) | i for i in range(batch.num_rows)], pa.int64())
                yield pa.RecordBatch.from_arrays(list(batch.columns) + [ids], names=names)

    return run


def _write_sheet_stage(spec: ExecSpec, bc_io, offset: int, total: int, width: int):
    """mapInArrow over one split sheet (range-partitioned and sorted by first occurrence): the Spark
    partition index is the sheet's part number; seal it under apply/pending/ and report its digest."""

    @coded_iter
    def run(it):
        import hashlib as _h  # noqa: PLC0415 - closure is pickled by value
        from pyspark import TaskContext  # noqa: PLC0415

        logscrub.install()
        batches = [b for b in it if b.num_rows]
        if not batches:
            return
        table = pa.Table.from_batches(batches).combine_chunks()
        data = write_csv(table.select([f"c{i}" for i in range(width)]).to_batches()[0])
        n = offset + TaskContext.get().partitionId()
        _worker_io(spec, bc_io.value).write_pending(n, total, data)
        yield pa.RecordBatch.from_arrays(
            [pa.array([n], pa.int64()), pa.array([table.num_rows], pa.int64()), pa.array([len(data)], pa.int64()),
             pa.array([_h.sha256(data).hexdigest()], pa.string())], names=["part", "rows", "bytes", "sha"])

    return run


# ---------------------------------------------------------------- driver
def _verify(tally, k: int) -> int:
    """The final check over the written CSV. A seam so a test can force a failure."""
    return tally.verify(k)


def _grid_cells(model, hist) -> List[Dict[str, Any]]:
    """SKALD's Pass 1 cells with an opaque id each (the UI's choice). Ids are derived from (k, suppression
    limit), so `apply` can recompute the same grid from the stored histogram and find the cell."""
    entries = model.parameter_grid(hist)["entries"]
    cells, seen = [], set()
    for e in entries:
        cid = e.get("id") or f"k{e['k']}-s{e['suppression_limit']}"
        while cid in seen:
            cid += "x"
        seen.add(cid)
        cells.append({**e, "id": cid})
    return cells


class Job:
    def __init__(self, job: str, phase: str, store_spec: Dict[str, str], kbs: KeySource, spark, *,
                 choice: Optional[str] = None, ner: Optional[NerSettings] = None, vault_prefix: str = ""):
        self.jp = self.restore = None
        if phase not in PHASES:
            raise JobError("INVALID_INPUT")
        self.job, self.phase, self.store_spec, self.spark = job, phase, store_spec, spark
        self.choice, self.ner, self.vault_prefix = choice, ner, vault_prefix
        self.sc = spark.sparkContext
        self.store = store_from_spec(store_spec)
        self.kstore = KeyStore(kbs, job)
        self.out_dir = "measure" if phase == "measure" else "apply"

    # -- entry --------------------------------------------------------------
    def run(self) -> Dict[str, Any]:
        """Run the phase; returns {"ok", "code", "summary"?}. status.json is always written."""
        try:
            keys = self.kstore.keys
        except KeyUnavailable:
            self._best_effort_status("KEY_UNAVAILABLE")
            return {"ok": False, "code": "KEY_UNAVAILABLE"}
        self.jio = JobIO(self.store, self.job, keys, input_from_spec(self.store_spec))
        try:
            summary = self._run(keys)
        except BaseException as e:  # noqa: BLE001 - every failure must end in a status object
            if isinstance(e, (KeyboardInterrupt, SystemExit)):
                raise
            code = code_of(e)
            log.error("%s failed: %s", self.phase, code)  # code only: messages can quote rows
            self._fail(code)
            return {"ok": False, "code": code}
        self.jio.write_status(self.out_dir, True)  # last: this is what makes the result visible
        return {"ok": True, "code": None, "summary": summary}

    def _fail(self, code: str) -> None:
        try:
            self.jio.discard_phase(self.out_dir)
            self.jio.write_status(self.out_dir, False, code)
        except Exception:  # noqa: BLE001
            self._best_effort_status(code)

    def _best_effort_status(self, code: str) -> None:
        try:
            self.store.put(f"staging/{self.job}/{self.out_dir}/status.json",
                           json.dumps({"ok": False, "code": code}).encode(), "application/json")
        except Exception:  # noqa: BLE001
            pass

    # -- the phase ------------------------------------------------------------
    def _run(self, keys: Keys) -> Dict[str, Any]:
        manifest = self.jio.read_manifest()
        if manifest["application"] != "kanon":
            raise JobError("INVALID_INPUT")
        n = manifest["part_count"]
        if self.jio.list_parts() != list(range(n)):
            raise JobError("PARTS_MISMATCH")  # a part left out or added
        self.jio.discard_phase(self.out_dir)  # a retry's leftovers

        tables = manifest["tables"]
        cfg = manifest["config"]
        plan = sk.Plan(json.dumps(cfg))
        section = cfg.get(cfg.get("data_type", ""), {})
        # Several tables: SKALD's own merge (sheet_joins, else stack, else join on shared columns) and, with
        # restore_sheets, the split back. A single table is its own plan and changes nothing below.
        self.jp = joins.plan_tables([(t["name"], t["header"]) for t in tables], joins.parse_sheet_joins(section))
        self.restore = None
        if len(tables) > 1 and section.get("restore_sheets") is True and self.jp.restore and len(self.jp.restore) > 1:
            self.restore = self.jp.restore  # SKALD skips the split when only one sheet would come out
        qis = plan.has_quasi_identifiers
        if self.phase == "measure" and not qis:
            raise JobError("INVALID_INPUT")
        if self.phase == "apply" and not self.choice and qis and plan.pass_name != "pass2":
            raise JobError("INVALID_INPUT")  # an apply job exists only because a choice was approved

        slices = max(1, min(n, 4 * self.sc.defaultParallelism))
        ner_cols = ner_columns(manifest)
        if ner_cols and self.ner is None:
            raise JobError("INVALID_INPUT")  # the manifest asks for NER and no model is configured
        # Keys: saved ones from the slots, the rest derived from K_user (same on every executor and in both
        # explore_k phases), then broadcast. They are never written by this code; spark.io.encryption
        # (session.py) covers what Spark itself spills. generate_keys only validates completeness.
        skeys = sk.generate_keys(plan, job_keys(plan, manifest, self.kstore, self.jp))
        bc_io = self.sc.broadcast({"input": keys.input, "output": keys.output})
        vaults = self._open_vaults(manifest, plan)
        cached = []
        try:
            if len(tables) == 1:
                table = tables[0]
                spec = ExecSpec(self.job, self.store_spec, table["header"], {p["part"]: p for p in table["parts"]}, n,
                                plan, ner_cols, self.ner)
                raw = self.sc.parallelize(list(range(n)), slices).mapPartitions(_read_stage(spec, bc_io))
            else:
                raw, spec = self._joined(manifest, plan, bc_io, slices, ner_cols, cached)
            vault_state = {c: dict(v["entries"]) for c, v in vaults.items()}
            if plan.tokenized_columns():
                raw = raw.persist(_storage())
                cached.append(raw)
                vault_state = self._issue_tokens(spec, plan, raw, skeys, vaults, vault_state)
            bc_pre = self.sc.broadcast({"keys": skeys, "vault": vault_state})
            pre = raw.mapPartitions(_preprocess_stage(spec, bc_pre)).persist(_storage())
            cached.append(pre)
            if not qis:
                return self._apply(spec, bc_io, pre, None, None, None, manifest, vault_state, vaults, keys)
            return self._measure_and_apply(spec, plan, section, bc_io, pre, manifest, vault_state, vaults, keys, cfg)
        finally:
            for r in cached:
                r.unpersist()

    def _joined(self, manifest, plan, bc_io, slices, ner_cols, cached):
        """The merged table of a multi-table bundle as the pipeline's usual parts RDD (number, Arrow IPC),
        plus an ExecSpec for it. Every table is read as a DataFrame whose rows carry their file position,
        joined as SKALD does (joins.py), numbered by that position, and cut into parts by Spark partition."""
        from pyspark.sql import functions as F  # noqa: PLC0415
        from pyspark.sql.types import BinaryType, LongType, StringType, StructField, StructType  # noqa: PLC0415

        n, jp = manifest["part_count"], self.jp
        frames = {}
        for t in manifest["tables"]:
            spec_t = ExecSpec(self.job, self.store_spec, t["header"], {p["part"]: p for p in t["parts"]}, n, plan)
            schema = StructType([StructField(f"c{i}", StringType()) for i in range(len(t["header"]))]
                                + [StructField(joins.ID, LongType())])
            nums = [(p["part"],) for p in t["parts"]]
            seed = self.spark.createDataFrame(nums, "part long").repartition(max(1, min(len(nums), slices)))
            frames[t["name"]] = seed.mapInArrow(_table_read_stage(spec_t, bc_io), schema)
        merged = joins.join_frames(self.spark, jp, frames, _storage())
        if jp.mode in ("concat",):
            # Stacked tables are unioned, not sorted: put them in file order and number them again.
            merged = merged.orderBy(joins.ID).withColumn(joins.ID, F.monotonically_increasing_id()).persist(_storage())
        total_bytes = sum(p["plaintext_bytes"] for t in manifest["tables"] for p in t["parts"])
        # Parts of about 32 MB of input text, at least one Spark partition per core. A join that fans rows
        # out makes the merged table larger than its inputs; parts then run bigger than that.
        want = max(self.sc.defaultParallelism, -(-total_bytes // (32 << 20)))
        merged = merged.repartitionByRange(want, joins.ID).sortWithinPartitions(joins.ID)
        packed = merged.mapInArrow(_pack_stage(jp.columns), StructType([
            StructField("pid", LongType()), StructField("rows", LongType()), StructField("ipc", BinaryType())]))
        raw = (packed.rdd.filter(lambda r: r.rows > 0).zipWithIndex().map(lambda t: (t[1], bytes(t[0].ipc)))
               .persist(_storage()))
        cached.append(raw)
        parts = raw.count()
        if parts == 0:
            raise JobError("INVALID_INPUT")  # the join produced no rows
        spec = ExecSpec(self.job, self.store_spec, jp.columns, {}, parts, plan, ner_cols, self.ner)
        if ner_cols:
            raw = raw.mapPartitions(_ner_stage(spec)).persist(_storage())
            cached.append(raw)
        return raw, spec

    def _issue_tokens(self, spec, plan, raw, skeys, vaults, vault_state):
        """SKALD's token recipe: gather distinct values, issue on the driver, ship the vault to executors."""
        bc_pre = self.sc.broadcast({"keys": skeys, "vault": vault_state})
        values = raw.mapPartitions(_token_values_stage(spec, bc_pre)).treeReduce(
            lambda a, b: {c: a.get(c, set()) | b.get(c, set()) for c in set(a) | set(b)})
        read_only = {c for c, v in vaults.items() if v["mode"] == "read"}
        drv = sk.Preprocessor(plan, skeys, vault_state or None, generate_missing=False, issue_tokens=True)
        drv.issue_tokens({c: sorted(v) for c, v in values.items() if c not in read_only})
        return drv.vault()

    def _open_vaults(self, manifest, plan) -> Dict[str, Dict[str, Any]]:
        """{column: {spec, entries, master, mode}} for the vaults the manifest lists."""
        out: Dict[str, Dict[str, Any]] = {}
        tokenised = set(plan.tokenized_columns())
        for v in vault_specs(manifest, self.jp):
            if v["column"] not in tokenised:
                raise JobError("MANIFEST_INVALID")
            try:
                master = self.kstore.slot(v["slot"])
            except KeyUnavailable:
                raise JobError("KEY_UNAVAILABLE") from None
            body = read_vault(self.store, master, v["vault_id"], v.get("base_version", 0), self.vault_prefix)
            out[v["column"]] = {"spec": v, "entries": body["entries"], "master": master, "mode": v["mode"]}
        return out

    # -- measure / apply ------------------------------------------------------
    def _measure_and_apply(self, spec, plan, section, bc_io, pre, manifest, vault_state, vaults, keys, cfg):
        sc = self.sc
        if self.phase == "apply":
            body = json.loads(self.jio.read_histogram())
            model = sk.Model(plan, sk.Stats.from_bytes(plan, base64.b64decode(body["stats"])))
            hist = sk.Histogram.from_bytes(base64.b64decode(body["hist"]))
        else:
            stats = pre.mapPartitions(_observe_stage(plan)).treeReduce(_merge)
            model = sk.Model(plan, stats)
            hist = pre.mapPartitions(_observe_stage(plan, model)).treeReduce(_merge)
            if hist.total != stats.rows:
                raise JobError("PARTS_MISMATCH")  # every row must be in exactly one histogram

        if self.phase == "measure" or (self.phase == "all" and plan.pass_name == "pass1"):
            cells = _grid_cells(model, hist)
            if self.phase == "measure":
                return self._write_measure(model, stats, hist, cells)
            return self._write_grid_only(spec, manifest, model, cells)

        node, k = self._choose(plan, section, model, hist)
        gen = sk.Generalizer(model, node)
        gen_rdd = pre.mapPartitions(_generalise_stage(gen)).persist(_storage())
        try:
            tally = gen_rdd.map(lambda x: x[2]).treeReduce(_merge)
            decision = tally.decide(k)
            return self._apply(spec, bc_io, gen_rdd, gen, decision, k, manifest, vault_state, vaults, keys,
                               rows_in=tally.total, node=node)
        finally:
            gen_rdd.unpersist()

    def _choose(self, plan, section, model, hist) -> Tuple[List[int], int]:
        """The generalisation node and the k to apply."""
        if self.choice:
            cell = next((c for c in _grid_cells(model, hist) if c["id"] == self.choice), None)
            if cell is None or not cell.get("feasible", True) or not cell.get("generalization_node"):
                raise JobError("INVALID_INPUT")  # not a cell of this job's grid, or one that cannot be met
            return model.node_from_names(cell["generalization_node"]), int(cell["k"])
        if plan.pass_name == "pass2" and section.get("generalization_node"):
            return model.node_from_names(section["generalization_node"]), plan.k
        best = model.search(hist)["best_rf"]
        if not best:
            raise JobError("INVALID_INPUT")  # no node meets k within the suppression limit
        return best, plan.k

    def _write_measure(self, model, stats, hist, cells) -> Dict[str, Any]:
        body = json.dumps({"v": 1, "stats": base64.b64encode(stats.to_bytes()).decode(),
                           "hist": base64.b64encode(hist.to_bytes()).decode()}).encode()
        self.jio.write_histogram(body)
        summary = {"summary_version": 1, "grid": cells,
                   "extra": {"runtime": RUNTIME, "rows": stats.rows}}
        self.jio.write_summary("measure", summary)
        return summary

    def _write_grid_only(self, spec, manifest, model, cells) -> Dict[str, Any]:
        """`all` with a pass1 config: SKALD's CLI writes only the grid, so there are no output parts."""
        summary = {"summary_version": 1, "job_id": self.job, "kind": "rows", "part_count": 0,
                   "tables": [{"name": self.jp.root, "header": spec.header, "parts": []}],
                   "extra": {"runtime": RUNTIME, "phase": self.phase, "grid": cells}}
        self.jio.write_summary("apply", summary)
        return summary

    def _apply(self, spec, bc_io, rdd, gen, decision, k, manifest, vault_state, vaults, keys, *, rows_in=None, node=None):
        if self.restore:
            return self._apply_restored(spec, bc_io, rdd, gen, decision, k, manifest, vault_state, vaults, keys,
                                        rows_in=rows_in, node=node)
        sc, n = self.sc, spec.part_count
        results = rdd.mapPartitions(_write_stage(spec, bc_io, gen, decision)).collect()
        metas = sorted((m for batch, _ in results for m in batch), key=lambda m: m["part"])
        if [m["part"] for m in metas] != list(range(n)):
            raise JobError("PARTS_MISMATCH")
        min_class = None
        if gen is not None:
            written = None
            for _, t in results:
                if t is not None:
                    written = t if written is None else _merge(written, t)
            min_class = _verify(written, k)  # raises K_CHECK_FAILED: fail closed, nothing is published
        header = metas[0]["header"]
        slices = max(1, min(n, 4 * sc.defaultParallelism))
        sc.parallelize(list(range(n)), slices).mapPartitions(_publish_stage(spec)).count()

        rows_out = sum(m["rows"] for m in metas)
        # Without a k check nothing is suppressed, so the rows read are the rows written (a merged table has
        # no per-part manifest entries to sum).
        total_in = rows_in if rows_in is not None else (sum(e["rows"] for e in spec.entries.values()) or rows_out)
        summary: Dict[str, Any] = {
            "summary_version": 1, "job_id": self.job, "kind": "rows", "part_count": n,
            "rows_in": total_in, "rows_out": rows_out, "suppressed": total_in - rows_out,
            "suppression_rate": (total_in - rows_out) / total_in if total_in else 0,
            "tables": [{"name": self.jp.root, "header": header,
                        "parts": [{k2: m[k2] for k2 in ("part", "rows", "plaintext_bytes", "plaintext_sha256")} for m in metas]}],
            "extra": {"runtime": RUNTIME, "phase": self.phase, "ner": bool(spec.ner_cols)},
        }
        if k is not None:
            summary["k"] = k
            summary["extra"].update(min_class_size=min_class, generalization_node=list(node), decision=decision.summary())
            if self.choice:
                summary["extra"]["choice"] = self.choice
        self.jio.write_summary("apply", summary)
        if self.phase != "measure":
            self._commit_vaults(vaults, vault_state)
        return summary

    def _apply_restored(self, spec, bc_io, rdd, gen, decision, k, manifest, vault_state, vaults, keys, *,
                        rows_in=None, node=None):
        """restore_sheets: anonymise the merged table, then write one output table per input sheet, as SKALD's
        write_restored_workbook does: the sheet's own columns under their original names, rows de-duplicated
        on the anonymised values (a join fans one original row out into several merged rows), each at its
        first occurrence. Output parts are numbered across the sheets in sheet order, so the summary's
        part_count is known before the first one is sealed (every part's AAD contains it)."""
        from pyspark.sql import functions as F  # noqa: PLC0415
        from pyspark.sql.types import LongType, StringType, StructField, StructType  # noqa: PLC0415

        sc, n_j, jp, sheets = self.sc, spec.part_count, self.jp, self.restore
        fin = rdd.mapPartitions(_finish_stage(gen, decision)).persist(_storage())
        try:
            min_class = None
            if gen is not None:
                tally = fin.map(lambda x: x[2]).treeReduce(_merge)
                min_class = _verify(tally, k)  # raises K_CHECK_FAILED before anything is written
            joined_rows = fin.map(lambda x: x[3]).sum()
            # The anonymised table's columns: techniques drop some (suppress), and the split gives a column
            # that is gone an empty value, as SKALD's write_restored_workbook does.
            names = fin.map(lambda x: from_ipc(x[1]).schema.names).first()
            expand = StructType([StructField(f"c{i}", StringType()) for i in range(len(names))]
                                + [StructField(joins.ID, LongType())])
            table = (self.spark.createDataFrame(fin.map(lambda x: (int(x[0]), bytearray(x[1]))), "part long, ipc binary")
                     .mapInArrow(_expand_stage(names), expand))
            per_part = max(1, -(-joined_rows // n_j))
            frames, offset = [], 0
            for sc_cols in sheets:
                df = joins.dedupe_sheet(F, table, sc_cols.columns, names).persist(_storage())
                cached_df = df
                cnt = df.count()
                parts = max(1, min(n_j, -(-cnt // per_part)))
                frames.append((sc_cols, cached_df, cnt, offset, parts))
                offset += parts
            total = offset
            out_schema = StructType([StructField("part", LongType()), StructField("rows", LongType()),
                                     StructField("bytes", LongType()), StructField("sha", StringType())])
            out_spec = ExecSpec(self.job, self.store_spec, [], {}, total, spec.plan)
            written = {}
            try:
                for sc_cols, df, cnt, off, parts in frames:
                    width = len(sc_cols.columns)
                    ranged = df.repartitionByRange(parts, joins.ID).sortWithinPartitions(joins.ID)
                    stage = _write_sheet_stage(out_spec, bc_io, off, total, width)
                    for r in ranged.mapInArrow(stage, out_schema).collect():
                        written[r.part] = {"part": r.part, "rows": r.rows, "plaintext_bytes": r.bytes, "plaintext_sha256": r.sha}
            finally:
                for _, df, *_rest in frames:
                    df.unpersist()
            import hashlib as _h  # noqa: PLC0415

            empty = _h.sha256(b"").hexdigest()
            for p in range(total):  # a part no row fell into is still a part: empty, sealed like the others
                if p not in written:
                    self.jio.write_pending(p, total, b"")
                    written[p] = {"part": p, "rows": 0, "plaintext_bytes": 0, "plaintext_sha256": empty}
            sc.parallelize(list(range(total)), max(1, min(total, 4 * sc.defaultParallelism))).mapPartitions(
                _publish_stage(out_spec)).count()
        finally:
            fin.unpersist()

        total_in = rows_in if rows_in is not None else joined_rows
        suppressed = total_in - joined_rows
        tables = [{"name": c.sheet, "header": [orig for _, orig in c.columns],
                   "parts": [written[p] for p in range(off, off + parts)]} for c, _, _, off, parts in frames]
        summary: Dict[str, Any] = {
            "summary_version": 1, "job_id": self.job, "kind": "rows", "part_count": total,
            "rows_in": total_in, "rows_out": joined_rows, "suppressed": suppressed,
            "suppression_rate": suppressed / total_in if total_in else 0, "tables": tables,
            "extra": {"runtime": RUNTIME, "phase": self.phase, "ner": bool(spec.ner_cols), "joined_rows": joined_rows,
                      "tables_in": len(jp.tables), "restored_from": jp.root},
        }
        if k is not None:
            summary["k"] = k
            summary["extra"].update(min_class_size=min_class, generalization_node=list(node), decision=decision.summary())
            if self.choice:
                summary["extra"]["choice"] = self.choice
        self.jio.write_summary("apply", summary)
        if self.phase != "measure":
            self._commit_vaults(vaults, vault_state)
        return summary

    def _commit_vaults(self, vaults, vault_state) -> None:
        """Write version base+1 of each vault this job was allowed to write (mode write), after the output is complete."""
        for col, v in vaults.items():
            if v["mode"] != "write":
                continue
            spec = v["spec"]
            write_vault(self.store, v["master"], spec["vault_id"], spec.get("base_version", 0) + 1, col,
                        vault_state.get(col, {}), self.vault_prefix)


def _storage():
    from pyspark import StorageLevel  # noqa: PLC0415

    return StorageLevel.MEMORY_AND_DISK


def run_job(job: str, phase: str, store_spec: Dict[str, str], kbs: KeySource, *, spark=None, choice: Optional[str] = None,
            ner: Optional[NerSettings] = None, vault_prefix: str = "") -> Dict[str, Any]:
    """Run one phase of one job and return {"ok", "code", "summary"?}. Never raises for a job failure."""
    logscrub.install()
    if spark is None:
        from .session import build_session  # noqa: PLC0415

        spark = build_session()
    try:
        return Job(job, phase, store_spec, kbs, spark, choice=choice, ner=ner, vault_prefix=vault_prefix).run()
    except JobError as e:  # bad phase
        return {"ok": False, "code": e.code}
