"""
Reverse tokenization applied by SKALD's tokenize_columns().

Vault file : <output_directory>/token_vault.json
  {
    "ColumnName": {
      "forward": { "original_value": "TK-00000001", ... },
      "reverse": { "TK-00000001": "original_value", ... }
    }
  }

Usage
-----
    python scripts/reverse_tokenization.py \\
        --input   output/anonymized.csv   (or .json) \\
        --output  recovered/detokenized.csv (or .json) \\
        --vault   skald_output/token_vault.json \\
        --columns Sub_District Customer_ID   # omit to detokenize ALL vaulted columns
"""

import argparse
import json
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


def reverse_tokenization(input_csv: str, output_csv: str, vault_file: str, columns: list):
    with open(vault_file) as f:
        vault = json.load(f)

    cols_to_reverse = [c for c in (columns or list(vault.keys())) if c in vault]
    missing = [c for c in (columns or []) if c not in vault]
    if missing:
        print(f"[WARN] Column(s) not in vault: {missing}", file=sys.stderr)

    df = _read(input_csv)
    total_unresolved = 0

    for col in cols_to_reverse:
        if col not in df.columns:
            print(f"[WARN] '{col}' not in CSV — skipping", file=sys.stderr)
            continue

        reverse_map = vault[col].get("reverse", {})

        unresolved = df[col].apply(
            lambda t: not (pd.isna(t) or str(t).strip() == "") and str(t) not in reverse_map
        ).sum()
        total_unresolved += unresolved

        df[col] = df[col].apply(
            lambda t: t if (pd.isna(t) or str(t).strip() == "")
            else reverse_map.get(str(t), t)
        )
        print(f"[OK] Detokenized: {col}  ({unresolved} unresolved)")

    if total_unresolved:
        print(f"\n[WARN] {total_unresolved} token(s) not in vault — left unchanged", file=sys.stderr)

    _write(df, output_csv)
    print(f"\nSaved → {output_csv}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Reverse SKALD tokenization")
    p.add_argument("--input",   required=True,  help="Anonymized CSV or JSON")
    p.add_argument("--output",  required=True,  help="Output CSV or JSON")
    p.add_argument("--vault",   required=True,  help="token_vault.json")
    p.add_argument("--columns", nargs="*",     help="Columns to detokenize (default: all in vault)")
    args = p.parse_args()
    reverse_tokenization(args.input, args.output, args.vault, args.columns or [])
