"""Sampling engine for generating synthetic records from privatized bins."""
from __future__ import annotations

import random
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from .bins import Bin


def sample_bin(probs: List[float], rng: Optional[np.random.Generator] = None) -> int:
    """Sample a bin index according to the probability distribution.

    Args:
        probs: Per-bin probability distribution (must sum to 1).
        rng: Optional numpy Generator for reproducibility.

    Returns:
        Sampled bin index.
    """
    p = np.array(probs, dtype=float)
    if rng is not None:
        return int(rng.choice(len(p), p=p))
    return int(np.random.choice(len(p), p=p))


def sample_qi(b: Bin, rng: Optional[np.random.Generator] = None) -> Dict[str, Any]:
    """Sample quasi-identifier values for a bin.

    - Numerical QIs: drawn uniformly within [min, max].
    - Categorical QIs: drawn uniformly from the bin's unique category list.

    Args:
        b: The bin to sample from.
        rng: Optional numpy Generator for reproducibility.

    Returns:
        Dict mapping column name to sampled value.
    """
    qi: Dict[str, Any] = {}

    for col, (lo, hi) in b.qi_ranges.items():
        qi[col] = rng.uniform(lo, hi) if rng is not None else random.uniform(lo, hi)

    for col, cats in b.qi_categories.items():
        if rng is not None:
            qi[col] = str(rng.choice(cats))
        else:
            qi[col] = random.choice(cats)

    return qi


def sample_sensitive(b: Bin) -> Tuple:
    """Sample a joint sensitive-attribute tuple treated as one atomic unit.

    Sensitive attributes are NEVER sampled independently; the full tuple
    is drawn as a single unit to preserve real-world co-occurrence patterns.

    Args:
        b: The bin to sample from.

    Returns:
        A tuple of sensitive attribute values.
    """
    return random.choice(b.sensitive_values)


def generate_synthetic(
    bins: List[Bin],
    probs: List[float],
    n_samples: int,
    sensitive_cols: List[str],
    seed: Optional[int] = None,
) -> pd.DataFrame:
    """Generate n_samples synthetic records from the privatized bin distribution.

    For each record:
      1. Sample a bin proportionally to its DP-noised probability.
      2. Sample QI values from that bin (uniform numeric, categorical choice).
      3. Sample sensitive attributes as a single joint tuple.
      4. Combine into a record.

    Args:
        bins: List of equivalence class bins.
        probs: Per-bin probability distribution (must sum to 1).
        n_samples: Number of synthetic records to generate.
        sensitive_cols: Column names for sensitive attributes, in tuple order.
        seed: Optional random seed.

    Returns:
        DataFrame of n_samples synthetic records.
    """
    rng = np.random.default_rng(seed)
    if seed is not None:
        random.seed(seed)

    records: List[Dict[str, Any]] = []
    for _ in range(n_samples):
        b = bins[sample_bin(probs, rng)]
        qi = sample_qi(b, rng)
        s = sample_sensitive(b)
        s_dict = dict(zip(sensitive_cols, s if isinstance(s, tuple) else (s,)))
        records.append({**qi, **s_dict})

    return pd.DataFrame(records)
