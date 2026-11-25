"""Benchmark harness: single-node SKALD vs SKALD's batch API vs anything else.

    python3 harness.py --rows 20000 --engines cli,batch --batches 8
    python3 harness.py --rows 1000000 --engines cli,batch-mp --batches 64 --workers 8 \
        --out results.jsonl
    python3 harness.py --rows 1000000 --engines external --external-cmd \
        "spark-submit my_job.py {input} {output}" --external-name spark+skald_core

Engines
  cli        the skald_pipeline binary on the whole file (SKALD_BIN or target/release|debug)
  batch      skald_core, one process, N batches in sequence (the driver/executor split
             without parallelism: pickles every object across the split)
  batch-mp   skald_core with a process pool as the executors: preprocess, stats, histogram
             and generalise run in workers; merge, search and decide in the parent
  external   any command that reads {input} and writes an anonymised CSV to {output}
             (datakaveri/anonymization-spark, a Spark + skald_core job, ...). It is
             timed as a black box; supply --external-name to label it.

Every engine runs the same synthetic data and the same config (columns, quasi-
identifiers, k, suppression limit, fixed test keys), so rows can be compared:
`rows_digest` is a SHA-256 of the anonymised rows in file order, and engines that
implement SKALD must agree on it. One JSON line per run is appended to --out and a
table is printed. Synthetic data only: nothing here reads a real file.

Spark and anonymization-spark are not run by this script. Plug them in with
`external`, or add a function to ENGINES; the data generator, config and checks
here are what later phases reuse.
"""
import argparse, csv, hashlib, json, multiprocessing as mp, os, pickle, random, resource
import shutil, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
SKALD = os.path.dirname(HERE)

FIRST = ["Asha", "Ravi", "Meena", "Kiran", "Divya", "Arjun", "Priya", "Suresh", "Anita", "Rahul"]
LAST = ["Kumar", "Sharma", "Reddy", "Iyer", "Nair", "Patel", "Singh", "Das"]
BLOOD = ["A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-"]
DIAG = ["Diabetes", "Hypertension", "Asthma", "Anaemia", "Malaria", "Cancer"]
PINS = [560000 + p for p in (1, 2, 10, 34, 66, 95, 100, 103, 118, 124, 150, 200)]
COLS = ["id", "name", "phone", "email", "age", "pin", "gender", "blood", "diagnosis", "note"]

CONFIG = {
    "data_type": "tabular",
    "tabular": {
        "output_path": "anonymized.csv",
        "suppress": ["name"],
        "hashing_with_salt": ["id"],
        "shared_hash_salts": True,
        "encrypt": ["email", {"phone": {"format_preserving": True}}],
        "quasi_identifiers": {"numerical": [{"column": "age"}, {"column": "pin"}],
                              "categorical": [{"column": "gender"}, {"column": "blood"}]},
        "size": {"age": 2, "pin": 10},
        "categorical_hierarchies": {"blood": {b: [b[:-1], "*"] for b in BLOOD},
                                    "gender": {"M": ["Any"], "F": ["Any"]}},
        "k_anonymize": {"k": 10},
        "suppression_limit": 0.05,
    },
}
KEYS = {"tabular_hash_salts.json": {"id": "11" * 32},
        "symmetric_keys.json": {"email": "33" * 16},
        "fpe_encrypt_keys.json": {"phone": "44" * 16}}


def generate(path, rows, seed=7):
    """Synthetic population, written as CSV. Deterministic in (rows, seed)."""
    r = random.Random(seed)
    with open(path, "w", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(COLS)
        for i in range(rows):
            first, last = r.choice(FIRST), r.choice(LAST)
            w.writerow([f"P{i}", f"{first} {last}", f"9{r.randint(100000000, 999999999)}",
                        f"{first.lower()}.{last.lower()}{i}@example.org", r.randint(18, 90),
                        r.choice(PINS), r.choice("MF"), r.choice(BLOOD), r.choice(DIAG), "stable"])


def digest(rows):
    h = hashlib.sha256()
    for row in rows:
        h.update(("\x1f".join(row) + "\x1e").encode())
    return h.hexdigest()


def read_rows(path):
    with open(path, newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
        return header, list(reader)


def min_class(header, rows, qis):
    """Smallest class of the written rows over the quasi-identifiers."""
    idx = [header.index(q) for q in qis]
    sizes = {}
    for r in rows:
        key = tuple(r[i] for i in idx)
        sizes[key] = sizes.get(key, 0) + 1
    return min(sizes.values()) if sizes else 0


class Timer:
    def __init__(self):
        self.phases = {}

    def __call__(self, name):
        t = self

        class _Ctx:
            def __enter__(self):
                self.t0 = time.perf_counter()

            def __exit__(self, *a):
                t.phases[name] = t.phases.get(name, 0.0) + time.perf_counter() - self.t0
        return _Ctx()


def peak_rss_mb(children=False):
    who = resource.RUSAGE_CHILDREN if children else resource.RUSAGE_SELF
    return resource.getrusage(who).ru_maxrss / 1024


# ── Engines ──────────────────────────────────────────────────────────────────

def engine_cli(args, data, workdir):
    binary = args.skald_bin or next((p for p in (os.path.join(SKALD, "target", "release", "skald_pipeline"),
                                                 os.path.join(SKALD, "target", "debug", "skald_pipeline"))
                                     if os.path.exists(p)), None)
    if not binary:
        raise SystemExit("cli engine: build skald_pipeline or set SKALD_BIN / --skald-bin")
    root = os.path.join(workdir, "cli")
    for d in ("data", "config", "keys"):
        os.makedirs(os.path.join(root, d))
    shutil.copy(data, os.path.join(root, "data", "data.csv"))
    json.dump(CONFIG, open(os.path.join(root, "config", "config.json"), "w"))
    for fn, body in KEYS.items():
        json.dump(body, open(os.path.join(root, "keys", fn), "w"))
    t0 = time.perf_counter()
    p = subprocess.run([binary, "--root", root], capture_output=True, text=True)
    wall = time.perf_counter() - t0
    if p.returncode:
        raise SystemExit(f"cli failed: {p.stdout[-300:]} {p.stderr[-300:]}")
    return {"wall_s": wall, "phases": {}, "peak_rss_mb": peak_rss_mb(children=True),
            "output": os.path.join(root, "output", "anonymized.csv")}


def _batches(data, n):
    import pyarrow as pa, pyarrow.csv as pacsv
    probe = pacsv.read_csv(data)
    types = {c: pa.string() for c in probe.schema.names}
    t = pacsv.read_csv(data, convert_options=pacsv.ConvertOptions(column_types=types, strings_can_be_null=False))
    per = max(1, -(-t.num_rows // n))
    return [b for i in range(0, t.num_rows, per) for b in t.slice(i, per).to_batches()]


def _keys():
    return {"hmac_salt": {"id": bytes.fromhex(KEYS["tabular_hash_salts.json"]["id"])},
            "aes_key": {"email": bytes.fromhex(KEYS["symmetric_keys.json"]["email"])},
            "fpe_key": {"phone": bytes.fromhex(KEYS["fpe_encrypt_keys.json"]["phone"])}}


# Worker functions live at module level so a process pool can pickle them.
_W = {}


def _w_init(plan_json, model_state):
    import skald_core as sk
    _W["plan"] = sk.Plan(plan_json)
    _W["pre"] = sk.Preprocessor(_W["plan"], _keys())
    _W["model"] = pickle.loads(model_state) if model_state else None


def _w_pre_stats(batch_bytes):
    import skald_core as sk
    b = _read(batch_bytes)
    out = _W["pre"].apply(b)
    s = sk.Stats(_W["plan"])
    s.observe(out)
    return _write(out), pickle.dumps(s)


def _write(batch):
    import pyarrow as pa
    sink = pa.BufferOutputStream()
    with pa.ipc.new_stream(sink, batch.schema) as w:
        w.write_batch(batch)
    return sink.getvalue().to_pybytes()


def _read(data):
    import pyarrow as pa
    return pa.ipc.open_stream(pa.py_buffer(data)).read_next_batch()


def _w_hist(batch_bytes):
    import skald_core as sk
    h = sk.Histogram(_W["model"])
    h.observe(_W["model"], _read(batch_bytes))
    return pickle.dumps(h)


def _w_gen(args):
    batch_bytes, node = args
    import skald_core as sk
    g = sk.Generalizer(_W["model"], node)
    out, t = g.apply(_read(batch_bytes))
    return _write(out), pickle.dumps(t)


def _w_finish(args):
    batch_bytes, node, decision = args
    import skald_core as sk
    g = sk.Generalizer(_W["model"], node)
    out = g.finish(_read(batch_bytes), pickle.loads(decision))
    t = g.tally(out)
    return _write(out), pickle.dumps(t)


def _engine_batch(args, data, workdir, parallel):
    import skald_core as sk
    tm = Timer()
    plan_json = json.dumps(CONFIG)
    plan = sk.Plan(plan_json)
    with tm("read"):
        batches = [_write(b) for b in _batches(data, args.batches)]
    pool = mp.get_context("spawn").Pool(args.workers, _w_init, (plan_json, None)) if parallel else None
    run = (lambda f, xs: pool.map(f, xs)) if parallel else None
    if not parallel:
        _w_init(plan_json, None)
        run = lambda f, xs: [f(x) for x in xs]
    try:
        with tm("preprocess+stats"):
            pre = run(_w_pre_stats, batches)
        batches = [p[0] for p in pre]
        stats = sk.Stats(plan)
        with tm("merge_stats"):
            for _, s in pre:
                stats.merge(pickle.loads(s))
        with tm("model"):
            model = sk.Model(plan, stats)
        state = pickle.dumps(model)
        if parallel:
            pool.close(); pool.join()
            pool = mp.get_context("spawn").Pool(args.workers, _w_init, (plan_json, state))
            run = lambda f, xs: pool.map(f, xs)
        else:
            _W["model"] = pickle.loads(state)
        with tm("histogram"):
            hs = run(_w_hist, batches)
        hist = sk.Histogram(model)
        with tm("merge_histogram"):
            for h in hs:
                hist.merge(pickle.loads(h))
        with tm("grid"):
            model.parameter_grid(hist)
        with tm("search"):
            node = model.search(hist)["best_rf"]
        with tm("generalise"):
            gs = run(_w_gen, [(b, node) for b in batches])
        tally = sk.Tally(plan)
        for _, t in gs:
            tally.merge(pickle.loads(t))
        with tm("decide"):
            decision = pickle.dumps(tally.decide())
        with tm("finish+check"):
            fs = run(_w_finish, [(g[0], node, decision) for g in gs])
        check = sk.Tally(plan)
        for _, t in fs:
            check.merge(pickle.loads(t))
        min_k = check.verify()
        out = os.path.join(workdir, "batch.csv")
        with open(out, "w", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            for i, (b, _) in enumerate(fs):
                batch = _read(b)
                if i == 0:
                    w.writerow(batch.schema.names)
                cols = [c.to_pylist() for c in batch.columns]
                w.writerows(zip(*cols))
    finally:
        if pool:
            pool.close(); pool.join()
    return {"wall_s": sum(tm.phases.values()), "phases": tm.phases, "peak_rss_mb": peak_rss_mb(),
            "output": out, "min_class": min_k, "node": node}


def engine_batch(args, data, workdir):
    return _engine_batch(args, data, workdir, parallel=False)


def engine_batch_mp(args, data, workdir):
    r = _engine_batch(args, data, workdir, parallel=True)
    r["peak_rss_mb"] = max(r["peak_rss_mb"], peak_rss_mb(children=True))
    return r


def engine_external(args, data, workdir):
    if not args.external_cmd:
        raise SystemExit("external engine needs --external-cmd")
    out = os.path.join(workdir, "external.csv")
    cmd = args.external_cmd.format(input=data, output=out)
    t0 = time.perf_counter()
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    wall = time.perf_counter() - t0
    if p.returncode:
        raise SystemExit(f"external failed: {p.stderr[-300:]}")
    return {"wall_s": wall, "phases": {}, "peak_rss_mb": peak_rss_mb(children=True), "output": out,
            "name": args.external_name}


ENGINES = {"cli": engine_cli, "batch": engine_batch, "batch-mp": engine_batch_mp, "external": engine_external}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rows", type=int, default=20000)
    ap.add_argument("--engines", default="cli,batch")
    ap.add_argument("--batches", type=int, default=8)
    ap.add_argument("--workers", type=int, default=os.cpu_count())
    ap.add_argument("--skald-bin", default=os.environ.get("SKALD_BIN"))
    ap.add_argument("--external-cmd")
    ap.add_argument("--external-name", default="external")
    ap.add_argument("--out", default=None, help="append one JSON line per run here")
    ap.add_argument("--keep", action="store_true", help="keep the scratch directory")
    args = ap.parse_args()

    workdir = tempfile.mkdtemp(prefix="skald-bench-")
    data = os.path.join(workdir, "data.csv")
    generate(data, args.rows)
    qis = ["age", "pin", "gender", "blood"]
    results = []
    for name in args.engines.split(","):
        # Each engine in its own process so peak memory is its own.
        res = ENGINES[name](args, data, workdir)
        header, rows = read_rows(res["output"])
        res.update(engine=res.get("name") or name, rows_in=args.rows, rows_out=len(rows),
                   rows_per_s=round(args.rows / res["wall_s"]), batches=args.batches if name.startswith("batch") else None,
                   rows_digest=digest(rows), observed_min_class=min_class(header, rows, qis) if all(q in header for q in qis) else None,
                   skald_k=CONFIG["tabular"]["k_anonymize"]["k"])
        res.pop("output")
        results.append(res)
        if args.out:
            with open(args.out, "a") as f:
                f.write(json.dumps(res) + "\n")
    print(f"{'engine':14} {'rows':>9} {'out':>9} {'wall_s':>8} {'rows/s':>9} {'rss_mb':>8} {'min_k':>6}  digest")
    for r in results:
        print(f"{r['engine']:14} {r['rows_in']:>9} {r['rows_out']:>9} {r['wall_s']:>8.2f} {r['rows_per_s']:>9} "
              f"{r['peak_rss_mb']:>8.0f} {str(r['observed_min_class']):>6}  {r['rows_digest'][:12]}")
        for ph, s in r["phases"].items():
            print(f"    {ph:18} {s:8.2f}s")
    digests = {r["rows_digest"] for r in results if r["engine"] in ("cli", "batch", "batch-mp")}
    if len(digests) > 1:
        print("MISMATCH: engines implementing SKALD disagree on the output rows", file=sys.stderr)
        sys.exit(1)
    if not args.keep:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
