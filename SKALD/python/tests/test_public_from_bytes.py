"""`from_bytes` is the public inverse of `to_bytes`.

The Spark job ships stats, histograms, tallies and decisions between phases as
bytes. It used to call the private pickle helpers (`_stats_from_bytes` ...);
these tests pin the public constructors to the same behaviour.
"""
import os

import skald_core as sk

from conftest import CORPUS, read_strings

CASE = "basic_pass2"


def _plan_and_batches():
    cdir = os.path.join(CORPUS, "cases", CASE)
    with open(os.path.join(cdir, "config.json")) as f:
        plan = sk.Plan(f.read())
    return plan, read_strings(os.path.join(cdir, "data.csv")).to_batches()


def test_stats_histogram_tally_decision_round_trip():
    plan, batches = _plan_and_batches()
    assert plan.has_quasi_identifiers

    stats = sk.Stats(plan)
    for b in batches:
        stats.observe(b)
    stats2 = sk.Stats.from_bytes(plan, stats.to_bytes())
    assert stats2.rows == stats.rows
    assert stats2.to_bytes() == stats.to_bytes()

    model = sk.Model(plan, stats2)
    hist = sk.Histogram(model)
    for b in batches:
        hist.observe(model, b)
    hist2 = sk.Histogram.from_bytes(hist.to_bytes())
    assert (hist2.total, len(hist2)) == (hist.total, len(hist))
    assert hist2.to_bytes() == hist.to_bytes()

    node = model.search(hist2)["best_rf"]
    gen = sk.Generalizer(model, node)
    tally = sk.Tally(plan)
    for b in batches:
        _, t = gen.apply(b)
        tally.merge(t)
    tally2 = sk.Tally.from_bytes(plan, tally.to_bytes())
    assert (tally2.total, len(tally2)) == (tally.total, len(tally))

    decision = tally2.decide()
    decision2 = sk.Decision.from_bytes(decision.to_bytes())
    assert decision2.summary() == decision.summary()
    assert decision2.publish_suppressed == decision.publish_suppressed


def test_from_bytes_rejects_garbage():
    plan, _ = _plan_and_batches()
    for call in (lambda: sk.Stats.from_bytes(plan, b"nope"), lambda: sk.Histogram.from_bytes(b"nope"),
                 lambda: sk.Tally.from_bytes(plan, b"nope"), lambda: sk.Decision.from_bytes(b"nope")):
        try:
            call()
        except Exception:
            continue
        raise AssertionError("garbage bytes were accepted")
