"""A reference driver: the calls a Spark job makes, one process, N batches.

Mirrors the executor/driver split: every `for b in batches` is what an executor
does to its partitions, everything between is the driver. Objects cross that
line through `pickle`, as they would when broadcast or collected.
"""
import json
import os
import pickle

import pyarrow as pa
import skald_core as sk

from conftest import CORPUS, load_keys, read_strings, rows_of, split


def wire(x):
    return pickle.loads(pickle.dumps(x))


def run_case(case, n_batches, reverse=False):
    cdir = os.path.join(CORPUS, "cases", case)
    with open(os.path.join(cdir, "config.json")) as f:
        plan = sk.Plan(f.read())
    keys = load_keys(case)
    batches = split(read_strings(os.path.join(cdir, "data.csv")), n_batches)
    order = (lambda xs: list(reversed(xs))) if reverse else (lambda xs: list(xs))

    # Executors: keys passed in, never generated, tokens never minted.
    pre = sk.Preprocessor(plan, keys)
    batches = [pre.apply(b) for b in batches]
    result = {"plan": plan, "grid": None, "node": None, "rows": None, "decision": None}
    if not plan.has_quasi_identifiers:
        result["rows"] = rows_of(batches)
        result["header"] = batches[0].schema.names
        return result

    stats = sk.Stats(plan)
    for b in order(batches):
        s = sk.Stats(plan)
        s.observe(b)
        stats.merge(wire(s))
    model = wire(sk.Model(plan, stats))

    hist = sk.Histogram(model)
    for b in order(batches):
        h = sk.Histogram(model)
        h.observe(model, b)
        hist.merge(wire(h))
    assert hist.total == sum(b.num_rows for b in batches)

    if plan.pass_name != "pass2" and json.loads(plan.config_json)[json.loads(plan.config_json)["data_type"]].get(
            "compute_parameter_grid", True):
        result["grid"] = model.parameter_grid(hist)["entries"]
    if plan.pass_name == "pass1":
        return result

    section = json.loads(plan.config_json)
    section = section[section["data_type"]]
    if plan.pass_name == "pass2" and section.get("generalization_node"):
        node = model.node_from_names(section["generalization_node"])
    else:
        node = model.search(hist)["best_rf"]
    gen = wire(sk.Generalizer(model, node))

    tally = sk.Tally(plan)
    generalised = {}
    for i in order(range(len(batches))):
        out, t = gen.apply(batches[i])
        generalised[i] = out
        tally.merge(wire(t))
    decision = wire(tally.decide())
    finished = [gen.finish(generalised[i], decision) for i in range(len(batches))]

    check = sk.Tally(plan)
    for b in finished:
        check.merge(gen.tally(b))
    result.update(node=node, decision=decision, rows=rows_of(finished), header=finished[0].schema.names,
                  min_class=check.verify())
    return result
