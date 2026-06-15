"""
Reverse format-preserving encryption (FPE) applied by SKALD.

Reads the unified key file — one file covers all FPE modes:

  <output_directory>/fpe_keys.json
  {
    "Pincode":  {"key": "<hex>", "mode": "digits"},
    "PAN_ID":   {"key": "<hex>", "mode": "pan"},
    "District": {"key": "<hex>", "mode": "general"}
  }

Modes
-----
  digits  — digit-only strings (e.g. 411001 → 839204)
  pan     — PAN card format AAAAA9999A
  general — segment-wise: uppercase/lowercase/digit runs encrypted separately
             (used by encrypt_columns with format_preserving: true)

Backward-compat: if a value in the key file is a plain hex string (old format)
it is treated as mode=digits.

Usage
-----
    python scripts/reverse_fpe.py \\
        --input  output/anonymized.csv   (or .json) \\
        --output recovered/fpe_decrypted.csv (or .json) \\
        --keys   skald_output/fpe_keys.json \\
        --columns Pincode District          # omit to decrypt ALL columns in key file
"""

import argparse
import hashlib
import hmac as hmac_mod
import json
import re
import string
import sys

import pandas as pd


def _read(path: str) -> pd.DataFrame:
    if path.lower().endswith(".json"):
        with open(path) as f:
            data = json.load(f)
        return pd.DataFrame(data if isinstance(data, list) else [data])
    return pd.read_csv(path)


def _write(df: pd.DataFrame, path: str):
    if path.lower().endswith(".json"):
        df.to_json(path, orient="records", indent=2)
    else:
        df.to_csv(path, index=False)


# ── Key derivation (mirrors preprocess.py _derive_key) ───────────────────────

def _derive_key(master_key: str, context: str) -> bytes:
    h = hmac_mod.new(master_key.encode(), context.encode(), hashlib.sha256)
    return h.digest()[:16]


def _get_pyffx():
    try:
        import pyffx
        return pyffx
    except ImportError:
        raise RuntimeError("pyffx is required:  pip install pyffx")


# ── PAN ───────────────────────────────────────────────────────────────────────

def _fpe_pan_decrypt(value: str, master_key: str) -> str:
    pan = str(value)
    if not re.fullmatch(r"[A-Z]{5}[0-9]{4}[A-Z]", pan):
        return pan
    pyffx = _get_pyffx()
    c5 = pyffx.String(pyffx.FFX(_derive_key(master_key, "pan_letters")), alphabet=string.ascii_uppercase, length=5)
    c4 = pyffx.String(pyffx.FFX(_derive_key(master_key, "pan_digits")),  alphabet=string.digits,          length=4)
    c1 = pyffx.String(pyffx.FFX(_derive_key(master_key, "pan_suffix")),  alphabet=string.ascii_uppercase, length=1)
    return c5.decrypt(pan[:5]) + c4.decrypt(pan[5:9]) + c1.decrypt(pan[9])


# ── Digits ────────────────────────────────────────────────────────────────────

def _fpe_digits_decrypt(value: str, master_key: str) -> str:
    raw = str(value)
    if not raw.isdigit():
        return raw
    pyffx = _get_pyffx()
    key = _derive_key(master_key, f"digits_len_{len(raw)}")
    return pyffx.String(pyffx.FFX(key), alphabet=string.digits, length=len(raw)).decrypt(raw)


# ── General segment-wise ──────────────────────────────────────────────────────

def _fpe_general_decrypt(value: str, master_key: str, column_name: str) -> str:
    pyffx = _get_pyffx()
    out, text, i = [], str(value), 0
    while i < len(text):
        ch = text[i]
        if ch.isupper():   cls, alphabet = "upper", string.ascii_uppercase
        elif ch.islower(): cls, alphabet = "lower", string.ascii_lowercase
        elif ch.isdigit(): cls, alphabet = "digit", string.digits
        else:
            out.append(ch); i += 1; continue

        j = i + 1
        while j < len(text):
            nxt = text[j]
            if cls == "upper" and nxt.isupper(): j += 1; continue
            if cls == "lower" and nxt.islower(): j += 1; continue
            if cls == "digit" and nxt.isdigit(): j += 1; continue
            break

        segment = text[i:j]
        key = _derive_key(master_key, f"{column_name}:{cls}:{len(segment)}")
        out.append(pyffx.String(pyffx.FFX(key), alphabet=alphabet, length=len(segment)).decrypt(segment))
        i = j
    return "".join(out)


# ── Dispatch ──────────────────────────────────────────────────────────────────

def _decrypt_value(value, master_key: str, mode: str, col: str):
    if pd.isna(value) or str(value).strip() == "":
        return value
    v = str(value)
    if mode == "pan":
        return _fpe_pan_decrypt(v, master_key)
    if mode == "digits":
        return _fpe_digits_decrypt(v, master_key)
    return _fpe_general_decrypt(v, master_key, col)  # "general"


# ── Main ──────────────────────────────────────────────────────────────────────

def reverse_fpe(input_csv: str, output_csv: str, key_file: str, columns: list):
    with open(key_file) as f:
        raw_map = json.load(f)

    # Normalise to {col: {"key": hex, "mode": str}}
    key_map = {}
    for col, val in raw_map.items():
        if isinstance(val, dict):
            key_map[col] = val
        else:
            key_map[col] = {"key": val, "mode": "digits"}  # backward-compat

    cols_to_decrypt = [c for c in (columns or list(key_map.keys())) if c in key_map]
    missing = [c for c in (columns or []) if c not in key_map]
    if missing:
        print(f"[WARN] No key found for: {missing}", file=sys.stderr)

    df = _read(input_csv)

    for col in cols_to_decrypt:
        if col not in df.columns:
            print(f"[WARN] '{col}' not in CSV — skipping", file=sys.stderr)
            continue
        entry = key_map[col]
        master_key, mode = entry["key"], entry.get("mode", "digits")
        df[col] = df[col].apply(lambda x: _decrypt_value(x, master_key, mode, col))
        print(f"[OK] FPE-decrypted ({mode}): {col}")

    _write(df, output_csv)
    print(f"\nSaved → {output_csv}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Reverse SKALD format-preserving encryption")
    p.add_argument("--input",   required=True,  help="Anonymized CSV or JSON")
    p.add_argument("--output",  required=True,  help="Output CSV or JSON")
    p.add_argument("--keys",    required=True,  help="fpe_keys.json")
    p.add_argument("--columns", nargs="*",     help="Columns to decrypt (default: all in key file)")
    args = p.parse_args()
    reverse_fpe(args.input, args.output, args.keys, args.columns or [])
