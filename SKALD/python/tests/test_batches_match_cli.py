import json
import os

import pytest
import skald_core as sk

from conftest import CASES, CORPUS, read_strings, rows_of
from driver import run_case


def cli_rows(path):
    t = read_strings(os.path.join(path, "anonymized.csv"))
    return t.schema.names, rows_of(t.to_batches())


def cli_status(path):
    with open(os.path.join(path, "status.json")) as f:
        return json.load(f)["outputs"]


@pytest.mark.parametrize("n", [1, 2, 7, 40])
@pytest.mark.parametrize("case", CASES)
def test_n_batches_give_the_cli_output(case, n, cli_outputs):
    """Histogram each batch, merge, search, generalise, check: the rows, the
    grid and the node are the ones the CLI produces on the whole file."""
    cli = cli_outputs(case)
    out = cli_status(cli)
    got = run_case(case, n)
    if got["grid"] is not None:
        assert got["grid"] == out["parameter_grid"]
    if out["pass"] == "pass1":
        return
    header, rows = cli_rows(cli)
    assert got["header"] == header
    assert got["rows"] == rows
    if got["node"] is not None:
        assert got["node"] == out["final_rf"]
        s = got["decision"].summary()
        assert s["suppressed_records"] == out["suppressed_records"]
        assert s["removed_records"] == out["removed_records"]
        assert s["num_equivalence_classes"] == out["num_equivalence_classes"]
        assert got["min_class"] >= 1


@pytest.mark.parametrize("case", CASES)
def test_merge_order_does_not_matter(case, cli_outputs):
    forward, backward = run_case(case, 5), run_case(case, 5, reverse=True)
    assert forward["rows"] == backward["rows"]
    assert forward["node"] == backward["node"]
    assert forward["grid"] == backward["grid"]


def test_the_final_check_fails_when_k_is_not_met():
    got = run_case("basic_pass2", 3)
    plan = got["plan"]
    gen_rows = got["rows"]
    assert gen_rows
    # Re-tally the written rows against a k far larger than the file was made for.
    import pyarrow as pa
    from conftest import read_strings
    written = read_strings(os.path.join(CORPUS, "expected", "basic_pass2", "anonymized.csv"))
    cfg = json.loads(plan.config_json)
    model_stats = sk.Stats(plan)
    model_stats.observe(read_strings(os.path.join(CORPUS, "cases", "basic_pass2", "data.csv")).to_batches()[0])
    model = sk.Model(plan, model_stats)
    gen = sk.Generalizer(model, model.initial_ri)
    t = gen.tally(written.to_batches()[0])
    assert t.verify() >= cfg["tabular"]["k_anonymize"]["k"]
    with pytest.raises(sk.SkaldError) as e:
        t.verify(k=1000)
    assert e.value.code == "K_CHECK_FAILED"
