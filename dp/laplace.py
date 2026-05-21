"""Laplace mechanism for differential privacy."""
from __future__ import annotations

from typing import List, Optional

import numpy as np


def add_laplace_noise(
    counts: List[float],
    epsilon: float,
    seed: Optional[int] = None,
) -> List[float]:
    """Add Laplace noise to histogram counts for epsilon-differential privacy.

    Uses sensitivity=1, which is the correct global L1 sensitivity for
    histogram counting queries (each individual contributes to exactly one bin).

    Args:
        counts: Raw histogram counts.
        epsilon: Privacy budget. Smaller values give stronger privacy guarantees.
        seed: Optional random seed for reproducibility.

    Returns:
        Noisy counts clipped to non-negative values.
    """
    if epsilon <= 0:
        raise ValueError(f"epsilon must be positive, got {epsilon}")

    scale = 1.0 / epsilon
    rng = np.random.default_rng(seed)
    noise = rng.laplace(loc=0.0, scale=scale, size=len(counts))
    return [max(0.0, c + n) for c, n in zip(counts, noise)]
