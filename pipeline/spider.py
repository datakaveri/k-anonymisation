"""SPIDEr pipeline: SKALD + Differential Privacy + Sampling."""
from __future__ import annotations

import os
import tempfile
from typing import Any, Dict, List, Optional, Union

import pandas as pd

from dp.laplace import add_laplace_noise
from synthetic.histogram import compute_histogram, normalize
from synthetic.sampler import generate_synthetic
from pipeline.skald_adapter import build_bins, run_skald


def spider_pipeline(
    data: Union[str, pd.DataFrame],
    k: int,
    epsilon: float,
    n_samples: int,
    quasi_identifiers: Dict[str, Any],
    sensitive_columns: List[str],
    suppression_limit: float = 0.05,
    extra_skald_config: Optional[Dict] = None,
    repo_root: Optional[str] = None,
    seed: Optional[int] = None,
) -> pd.DataFrame:
    """Run the full SPIDEr synthetic data generation pipeline.

    Pipeline steps:
        1. SKALD  — k-anonymize the input data → equivalence class bins.
        2. Histogram — count records per bin.
        3. DP noise — add Laplace noise scaled to epsilon.
        4. Normalize — convert noisy counts to a probability distribution.
        5. Sampling — draw n_samples records proportionally from bins.

    Args:
        data: Path to input CSV or a pandas DataFrame.
        k: k-anonymity threshold. Each bin will have at least k records.
        epsilon: Differential privacy budget. Smaller = stronger privacy.
        n_samples: Number of synthetic records to generate.
        quasi_identifiers: Column config dict. Format per column:
            {
              "Age":        {"kind": "numerical", "dtype": "int"},
              "Income":     {"kind": "numerical", "dtype": "float",
                             "scale": True, "s": 3},
              "Gender":     {"kind": "categorical"},
              "Blood Group":{"kind": "categorical"},
            }
        sensitive_columns: Column names to treat as sensitive attributes.
            These are sampled as joint tuples (never independently).
        suppression_limit: Max fraction of rows SKALD may suppress (0–1).
        extra_skald_config: Optional SKALD preprocessing options, e.g.:
            {"suppress": ["SSN", "Name"], "hashing_with_salt": ["Email"]}
        repo_root: Path to the repository root (where data/, chunks/, output/ live).
            Defaults to the parent directory of this file.
        seed: Optional random seed for DP noise and synthetic sampling.

    Returns:
        DataFrame of n_samples synthetic records.
    """
    if repo_root is None:
        repo_root = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..")
        )

    # Resolve DataFrame input to a temporary CSV
    tmp_csv: Optional[str] = None
    if isinstance(data, pd.DataFrame):
        tmp_csv = os.path.join(repo_root, "_spider_tmp_input.csv")
        data.to_csv(tmp_csv, index=False)
        input_csv = tmp_csv
    else:
        input_csv = os.path.abspath(data)

    try:
        # Step 1: Run SKALD → generalized CSV
        gen_csv, _ = run_skald(
            input_csv=input_csv,
            k=k,
            quasi_identifiers=quasi_identifiers,
            sensitive_columns=sensitive_columns,
            repo_root=repo_root,
            suppression_limit=suppression_limit,
            extra_skald_config=extra_skald_config,
        )
    finally:
        if tmp_csv and os.path.exists(tmp_csv):
            os.unlink(tmp_csv)

    # Step 1b: Build bins from SKALD output
    bins = build_bins(gen_csv, quasi_identifiers, sensitive_columns)

    # Step 2: Histogram
    hist = compute_histogram(bins)

    # Step 3: Laplace noise for differential privacy
    noisy_hist = add_laplace_noise(hist, epsilon=epsilon, seed=seed)

    # Step 4: Normalize to probability distribution
    probs = normalize(noisy_hist)

    # Step 5: Generate synthetic dataset
    synthetic = generate_synthetic(
        bins=bins,
        probs=probs,
        n_samples=n_samples,
        sensitive_cols=sensitive_columns,
        seed=seed,
    )

    return synthetic
