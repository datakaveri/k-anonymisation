"""Shared helpers: the conformance corpus, and the CLI's output to compare with."""
import importlib.util
import json
import os
import shutil
import tempfile

import pyarrow as pa
import pyarrow.csv as pacsv
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
SKALD = os.path.dirname(os.path.dirname(HERE))
CORPUS = os.path.join(SKALD, "conformance")
CASES = sorted(os.listdir(os.path.join(CORPUS, "cases")))


def read_strings(path):
    """A CSV as a pyarrow table of string columns (no type inference, no nulls)."""
    probe = pacsv.read_csv(path, read_options=pacsv.ReadOptions(), convert_options=pacsv.ConvertOptions(
        strings_can_be_null=False))
    types = {n: pa.string() for n in probe.schema.names}
    return pacsv.read_csv(path, convert_options=pacsv.ConvertOptions(column_types=types, strings_can_be_null=False))


def rows_of(batches):
    out = []
    for b in batches:
        cols = [c.to_pylist() for c in b.columns]
        out.extend([list(r) for r in zip(*cols)] if cols else [])
    return out


def split(table, n):
    """`n` roughly equal record batches, in file order."""
    per = max(1, -(-table.num_rows // n))
    return [pa.RecordBatch.from_pylist(table.slice(i, per).to_pylist(), schema=table.schema)
            for i in range(0, table.num_rows, per)]


def load_keys(case):
    d = os.path.join(CORPUS, "cases", case, "testkeys")
    mapping = {"tabular_hash_salts.json": "hmac_salt", "symmetric_keys.json": "aes_key",
               "fpe_encrypt_keys.json": "fpe_key"}
    keys = {}
    for fn, kind in mapping.items():
        with open(os.path.join(d, fn)) as f:
            keys[kind] = {c: bytes.fromhex(h) for c, h in json.load(f).items()}
    return keys


def _cli_binary():
    for cand in (os.environ.get("SKALD_BIN"),
                 os.path.join(SKALD, "target", "release", "skald_pipeline"),
                 os.path.join(SKALD, "target", "debug", "skald_pipeline")):
        if cand and os.path.exists(cand):
            return cand
    return None


@pytest.fixture(scope="session")
def cli_outputs():
    """The CLI's output per case: run live on the whole file when a binary is
    built (SKALD_BIN, or target/{release,debug}), else the corpus's recorded
    4.1.0 output. Either way it is the command line, not a second opinion."""
    binary = _cli_binary()
    if binary is None:
        return lambda case: os.path.join(CORPUS, "expected", case)
    spec = importlib.util.spec_from_file_location("run_cli", os.path.join(CORPUS, "run_cli.py"))
    run_cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(run_cli)
    out = tempfile.mkdtemp(prefix="skald-pytest-cli-")
    for case in CASES:
        assert run_cli.run_case(binary, case, out) == 0, case
    yield lambda case: os.path.join(out, case)
    shutil.rmtree(out, ignore_errors=True)
