"""Reference outputs for cells the corpus did not record: the SKALD CLI run live, if a binary is available."""

import copy
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import corpus
from conftest import CORPUS, SKALD

CANDIDATES = [os.environ.get("SKALD_BIN"), SKALD / "target" / "release" / "skald_pipeline",
              SKALD / "target" / "debug" / "skald_pipeline",
              Path.home() / "k-anonymisation/SKALD/target/debug/skald_pipeline"]


def cli_binary():
    return next((str(p) for p in CANDIDATES if p and Path(p).exists()), None)


def cli_for_cell(case, k, limit):
    """The CLI's anonymized.csv for the case with k and suppression_limit replaced and the explicit
    node/pass removed, i.e. what `search(k, limit)` should give: the grid cell a user chose."""
    cfg = copy.deepcopy(corpus.case_config(case))
    sec = cfg[cfg["data_type"]]
    sec["k_anonymize"] = {**sec.get("k_anonymize", {}), "k": k}
    sec["suppression_limit"] = limit
    sec.pop("generalization_node", None)
    sec.pop("pass", None)
    work = tempfile.mkdtemp(prefix="skald-ref-")
    try:
        for d in ("data", "config"):
            os.makedirs(os.path.join(work, d))
        shutil.copy(CORPUS / "cases" / case / "data.csv", os.path.join(work, "data", "data.csv"))
        json.dump(cfg, open(os.path.join(work, "config", "config.json"), "w"))
        shutil.copytree(CORPUS / "cases" / case / "testkeys", os.path.join(work, "keys"))
        p = subprocess.run([cli_binary(), "--root", work], capture_output=True, text=True)
        out = os.path.join(work, "output", "anonymized.csv")
        return p.returncode, (Path(out).read_bytes() if os.path.exists(out) else None)
    finally:
        shutil.rmtree(work, ignore_errors=True)
