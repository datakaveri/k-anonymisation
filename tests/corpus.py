"""The SKALD conformance corpus as bundle inputs, and the CLI's recorded outputs to compare with."""

import json

from conftest import CORPUS

CASES = sorted(p.name for p in (CORPUS / "cases").iterdir())
_KINDS = {"tabular_hash_salts.json": "hmac_salt", "symmetric_keys.json": "aes_key", "fpe_encrypt_keys.json": "fpe_key"}


def case_config(case):
    return json.loads((CORPUS / "cases" / case / "config.json").read_text())


def case_data(case):
    return (CORPUS / "cases" / case / "data.csv").read_bytes()


def case_keys(case):
    """(manifest keys list, {key_NN: 32-byte KBS resource}). The corpus's AES/FPE keys are 16 bytes and a
    KBS resource is 32, so they are padded; keymap.saved_keys takes the 16-byte prefix back."""
    listed, slots = [], {}
    for fn, kind in _KINDS.items():
        for col, hexkey in json.loads((CORPUS / "cases" / case / "testkeys" / fn).read_text()).items():
            i = len(listed)
            listed.append({"slot": f"key-{i:02d}", "column": col, "kind": kind})
            raw = bytes.fromhex(hexkey)
            slots[f"key_{i:02d}"] = raw + bytes(32 - len(raw))
    return listed, slots


def expected(case):
    d = CORPUS / "expected" / case
    out = d / "anonymized.csv"
    return (out.read_bytes() if out.exists() else None), json.loads((d / "status.json").read_text())["outputs"]
