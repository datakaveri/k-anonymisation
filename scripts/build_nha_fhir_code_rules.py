"""
Refresh the code-keyed rules in config/nha_fhir.json from NHA's technique sheets.

In the FHIR bundles the original extraction field names survive only as
Observation.code.text ("gps latitude", "nurse remarks"), and the technique
sheets are keyed by those names. This script writes every field name from the
sheets into the config's `code_rules`, one bucket per sheet:

    Suppress.csv          -> code_rules.suppress
    Hash.xlsx             -> code_rules.hashing_with_salt
    Free_Text_Anon.xlsx   -> code_rules.free_text  (already NER-cleaned upstream)

Entries containing `*` or `|` are hand-written safety-net patterns and codings,
not sheet names, so they are kept as they are. Everything else in the config is
left untouched. Run it again whenever NHA revises the sheets.

Usage
-----
    python scripts/build_nha_fhir_code_rules.py \\
        --suppress  "<dir>/Suppress.csv" \\
        --hash      "<dir>/Hash.xlsx" \\
        --free-text "<dir>/Free_Text_Anon.xlsx" \\
        --config    config/nha_fhir.json
"""

import argparse
import csv
import json
import re
import sys

import openpyxl

FIELD_COLUMN = "Our JSON Field"


def normalise(name: str) -> str:
    """Same normalisation SKALD applies to Observation.code.text."""
    return re.sub(r"[^0-9a-z*]+", "_", name.strip().lower()).strip("_")


def read_csv(path: str) -> list[str]:
    with open(path, encoding="utf-8-sig", newline="") as f:
        return [row[FIELD_COLUMN] for row in csv.DictReader(f) if row.get(FIELD_COLUMN)]


def read_xlsx(path: str) -> list[str]:
    rows = openpyxl.load_workbook(path, read_only=True).worksheets[0].iter_rows(values_only=True)
    header = next(rows)
    col = header.index(FIELD_COLUMN)
    return [r[col] for r in rows if r[col]]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--suppress", required=True)
    ap.add_argument("--hash", required=True)
    ap.add_argument("--free-text", required=True)
    ap.add_argument("--config", default="config/nha_fhir.json")
    args = ap.parse_args()

    sheets = {
        "suppress": read_csv(args.suppress),
        "hashing_with_salt": read_xlsx(args.hash),
        "free_text": read_xlsx(args.free_text),
    }
    names = {bucket: sorted({normalise(n) for n in fields} - {""}) for bucket, fields in sheets.items()}

    # A name in two sheets would be resolved by SKALD in favour of the more
    # protective technique; say so rather than let it pass silently.
    seen: dict[str, str] = {}
    for bucket, fields in names.items():
        for n in fields:
            if n in seen:
                print(f"warning: '{n}' is in both {seen[n]} and {bucket}", file=sys.stderr)
            seen[n] = bucket

    with open(args.config, encoding="utf-8") as f:
        config = json.load(f)
    section = config[config["data_type"]]
    code_rules = section.setdefault("code_rules", {})

    for bucket, fields in names.items():
        patterns = [e for e in code_rules.get(bucket, []) if "*" in e or "|" in e]
        code_rules[bucket] = patterns + fields
        print(f"{bucket}: {len(patterns)} pattern(s) kept, {len(fields)} field name(s) from sheet")

    with open(args.config, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
