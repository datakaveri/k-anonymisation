"""Histogram construction and normalization utilities."""
from __future__ import annotations

from typing import List

from .bins import Bin


def compute_histogram(bins: List[Bin]) -> List[int]:
    """Return per-bin record counts.

    Args:
        bins: List of equivalence class bins.

    Returns:
        List of counts, one per bin.
    """
    return [b.size for b in bins]


def normalize(hist: List[float]) -> List[float]:
    """Convert counts to a probability distribution summing to 1.0.

    Args:
        hist: Non-negative counts (typically after DP noise + clipping).

    Returns:
        Probability distribution over bins.

    Raises:
        ValueError: If all counts are zero.
    """
    total = sum(hist)
    if total <= 0:
        raise ValueError("Histogram total is zero; cannot normalize.")
    return [h / total for h in hist]
