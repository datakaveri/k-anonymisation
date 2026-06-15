"""
Reverse AES-GCM encryption applied by SKALD's encrypt_columns()
(config entries with format_preserving: false).

Key file : <output_directory>/symmetric_keys.json
             { "ColumnName": "<base64-encoded-256-bit-AES-key>", ... }

Ciphertext format per cell: base64( nonce[12 bytes] || AES-GCM-ciphertext )

Usage
-----
    python scripts/reverse_encryption.py \\
        --input   output/anonymized.csv   (or .json) \\
        --output  recovered/decrypted.csv (or .json) \\
        --keys    skald_output/symmetric_keys.json \\
        --columns District UPI_ID        # omit to decrypt ALL columns in key file
"""

import argparse
import base64
import json
import sys

import pandas as pd
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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


def load_keys(key_file: str) -> dict:
    with open(key_file) as f:
        raw = json.load(f)
    return {col: base64.b64decode(b64key) for col, b64key in raw.items()}


def decrypt_value(value, aesgcm: AESGCM):
    if pd.isna(value) or str(value).strip() == "":
        return value
    try:
        blob = base64.b64decode(str(value))
        nonce, ciphertext = blob[:12], blob[12:]
        return aesgcm.decrypt(nonce, ciphertext, None).decode()
    except Exception as e:
        return f"DECRYPT_ERROR: {e}"


def reverse_encryption(input_path: str, output_path: str, key_file: str, columns: list):
    keys = load_keys(key_file)
    cols_to_decrypt = [c for c in (columns or list(keys.keys())) if c in keys]

    missing = [c for c in (columns or []) if c not in keys]
    if missing:
        print(f"[WARN] No key found for: {missing}", file=sys.stderr)

    df = _read(input_path)

    for col in cols_to_decrypt:
        if col not in df.columns:
            print(f"[WARN] '{col}' not in file — skipping", file=sys.stderr)
            continue
        aesgcm = AESGCM(keys[col])
        df[col] = df[col].apply(lambda x: decrypt_value(x, aesgcm))
        print(f"[OK] Decrypted: {col}")

    _write(df, output_path)
    print(f"\nSaved → {output_path}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Reverse SKALD AES-GCM encryption")
    p.add_argument("--input",   required=True,  help="Anonymized CSV or JSON")
    p.add_argument("--output",  required=True,  help="Output CSV or JSON")
    p.add_argument("--keys",    required=True,  help="symmetric_keys.json")
    p.add_argument("--columns", nargs="*",      help="Columns to decrypt (default: all in key file)")
    args = p.parse_args()
    reverse_encryption(args.input, args.output, args.keys, args.columns or [])
