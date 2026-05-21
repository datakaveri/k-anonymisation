"""Bin data structure representing a k-anonymous equivalence class."""
from __future__ import annotations

import re
from typing import Dict, List, Tuple

import pandas as pd


class Bin:
    """A k-anonymous equivalence class derived from SKALD generalization.

    Attributes:
        rows: Slice of the generalized DataFrame belonging to this bin.
        size: Number of records in this bin.
        qi_ranges: Numerical QI ranges as {col: (min, max)}.
        qi_categories: Categorical QI values as {col: [unique_values]}.
        sensitive_values: Joint sensitive-attribute tuples, one per row.
    """

    def __init__(
        self,
        rows: pd.DataFrame,
        numerical_qi_cols: List[str],
        categorical_qi_cols: List[str],
        sensitive_cols: List[str],
    ) -> None:
        self.rows = rows
        self.size = len(rows)
        self.qi_ranges: Dict[str, Tuple[float, float]] = {}
        self.qi_categories: Dict[str, List[str]] = {}
        self.sensitive_values: List[Tuple] = []

        self._populate_qi_ranges(numerical_qi_cols)
        self._populate_qi_categories(categorical_qi_cols)
        self._populate_sensitive_values(sensitive_cols)

    def _populate_qi_ranges(self, numerical_cols: List[str]) -> None:
        for col in numerical_cols:
            label = str(self.rows[col].iloc[0])
            self.qi_ranges[col] = _parse_range_label(label)

    def _populate_qi_categories(self, categorical_cols: List[str]) -> None:
        for col in categorical_cols:
            self.qi_categories[col] = self.rows[col].dropna().unique().tolist()

    def _populate_sensitive_values(self, sensitive_cols: List[str]) -> None:
        for _, row in self.rows.iterrows():
            self.sensitive_values.append(tuple(row[c] for c in sensitive_cols))

    def __len__(self) -> int:
        return self.size

    def __repr__(self) -> str:
        return (
            f"Bin(size={self.size}, "
            f"ranges={self.qi_ranges}, "
            f"categories={self.qi_categories})"
        )


def _parse_range_label(label: str) -> Tuple[float, float]:
    """Parse a SKALD-produced range label into (lo, hi).

    Handles:
      '[lo-hi)'   — pd.cut interval format, e.g. '[17.0-25.0)'
      '[-lo-hi)'  — negative lower bound, e.g. '[-5.0-0.0)'
      plain float — unsuppressed scalar value, e.g. '40.438'
    """
    label = label.strip()
    m = re.match(r"^\[(-?[0-9.]+)-(-?[0-9.]+)\)$", label)
    if m:
        return float(m.group(1)), float(m.group(2))
    # Plain scalar: treat as a degenerate range [v, v]
    try:
        v = float(label)
        return v, v
    except ValueError:
        raise ValueError(f"Cannot parse SKALD range label: {label!r}")
