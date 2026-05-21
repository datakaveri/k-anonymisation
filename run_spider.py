#!/usr/bin/env python3
"""CLI entry point for the SPIDEr synthetic data generation pipeline.

The config file follows the **standard SKALD JSON format** with three
additional top-level keys:

    epsilon          – differential privacy budget
    n_samples        – number of synthetic records to generate
    sensitive_columns – list of columns to treat as sensitive (joint tuple)

Everything else (quasi_identifiers, suppress, k_anonymize, masking …)
uses the same format as any existing SKALD pipeline-config JSON.

Usage:
    python3 run_spider.py --input data/synthetic_profiles.csv \\
                          --config example_spider_config.json  \\
                          --output synthetic.csv

    # override config values from the command line:
    python3 run_spider.py --input data/synthetic_profiles.csv \\
                          --config example_spider_config.json  \\
                          --k 100 --epsilon 0.5 --n-samples 10000 \\
                          --output synthetic.csv
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pipeline.skald_adapter import parse_spider_config
from pipeline.spider import spider_pipeline


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "SPIDEr — Synthetic Private Integrated Data gEneration\n"
            "Combines SKALD (k-anonymity) + Laplace DP + proportional sampling.\n\n"
            "The --config file uses the standard SKALD JSON format plus three\n"
            "extra top-level keys: epsilon, n_samples, sensitive_columns."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--input",  required=True, help="Path to input CSV.")
    parser.add_argument("--config", required=True,
                        help="Path to SPIDEr/SKALD JSON config file.")
    parser.add_argument("--output", default="synthetic.csv",
                        help="Output CSV path (default: synthetic.csv).")

    # Optional overrides — take precedence over values in the config file
    parser.add_argument("--k",         type=int,   help="Override k-anonymity parameter.")
    parser.add_argument("--epsilon",   type=float, help="Override DP epsilon.")
    parser.add_argument("--n-samples", type=int,   dest="n_samples",
                        help="Override number of synthetic records.")
    parser.add_argument("--seed",      type=int,   default=None,
                        help="Random seed for reproducibility.")

    args = parser.parse_args()

    with open(args.config) as f:
        config = json.load(f)

    # parse_spider_config handles all format conversion
    pipeline_kwargs = parse_spider_config(config)

    # CLI flags override config file values
    if args.k:
        pipeline_kwargs["k"] = args.k
    if args.epsilon:
        pipeline_kwargs["epsilon"] = args.epsilon
    if args.n_samples:
        pipeline_kwargs["n_samples"] = args.n_samples

    print(
        f"[SPIDEr] k={pipeline_kwargs['k']}, "
        f"epsilon={pipeline_kwargs['epsilon']}, "
        f"n_samples={pipeline_kwargs['n_samples']}"
    )
    print(f"[SPIDEr] Input: {args.input}")

    synthetic = spider_pipeline(
        data=args.input,
        seed=args.seed,
        **pipeline_kwargs,
    )

    synthetic.to_csv(args.output, index=False)
    print(f"[SPIDEr] Synthetic dataset written → {args.output}  ({len(synthetic)} records)")


if __name__ == "__main__":
    main()
