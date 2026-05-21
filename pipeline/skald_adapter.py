"""Adapter: run SKALD on raw data and convert the generalized output into Bin objects."""
from __future__ import annotations

import contextlib
import os
import shutil
import tempfile
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import yaml

from SKALD.core import run_pipeline
from synthetic.bins import Bin


@contextlib.contextmanager
def _working_dir(path: str):
    """Context manager that temporarily changes the working directory."""
    old = os.getcwd()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(old)


def _build_yaml_config(
    quasi_identifiers: Dict[str, Any],
    sensitive_columns: List[str],
    k: int,
    output_directory: str,
    suppression_limit: float,
    extra: Optional[Dict],
) -> Dict:
    """Build the flat YAML config dict expected by SKALD's load_config.

    Args:
        quasi_identifiers: {col: {"kind": "numerical"/"categorical", "dtype": ..., ...}}.
        sensitive_columns: Sensitive column names (first is used for l-diversity tracking).
        k: k-anonymity threshold.
        output_directory: Absolute path for SKALD's generalized CSV output.
        suppression_limit: Maximum fraction of rows SKALD may suppress.
        extra: Optional extra SKALD config keys (suppress, masking, hashing, etc.).

    Returns:
        Flat dict ready for yaml.dump, compatible with SKALD's Config Pydantic model.
    """
    numerical: List[Dict] = []
    categorical: List[Dict] = []
    size: Dict[str, int] = {}
    extra = extra or {}

    for col, meta in quasi_identifiers.items():
        kind = meta["kind"]
        if kind == "numerical":
            entry: Dict[str, Any] = {
                "column": col,
                "type": meta.get("dtype", "int"),
            }
            if meta.get("encode"):
                entry["encode"] = True
            if meta.get("scale"):
                entry["scale"] = True
                entry["s"] = int(meta.get("s", 1))
            # size factors must be integers > 1 (SKALD validation)
            size[col] = max(2, int(meta.get("size", 2)))
            numerical.append(entry)
        elif kind == "categorical":
            categorical.append({"column": col})

    return {
        "enable_k_anonymity": True,
        "enable_l_diversity": False,
        "output_path": "generalized.csv",
        "output_directory": output_directory,
        "log_file": "output/skald.log",
        "suppress": extra.get("suppress", []),
        "hashing_with_salt": extra.get("hashing_with_salt", []),
        "hashing_without_salt": extra.get("hashing_without_salt", []),
        "masking": extra.get("masking", []),
        "charcloak": extra.get("charcloak", []),
        "tokenization": extra.get("tokenization", []),
        "fpe": extra.get("fpe", []),
        "encrypt": extra.get("encrypt", []),
        "quasi_identifiers": {
            "numerical": numerical,
            "categorical": categorical,
        },
        "k": k,
        "l": 1,
        "sensitive_parameter": sensitive_columns[0] if sensitive_columns else None,
        "size": size,
        "suppression_limit": suppression_limit,
    }


def parse_spider_config(config: Dict) -> Dict:
    """Parse a SPIDEr config file into keyword args for spider_pipeline().

    The config must follow the **standard SKALD JSON format** with three
    additional top-level SPIDEr keys: ``epsilon``, ``n_samples``, and
    ``sensitive_columns``.  All other keys mirror what you would write in an
    ordinary SKALD pipeline-config JSON.

    Minimal example::

        {
          "epsilon": 1.0,
          "n_samples": 5000,
          "sensitive_columns": ["Disease"],

          "operations": ["SKALD", "k-anonymity"],
          "data_type": "MyDataset",
          "MyDataset": {
            "k_anonymize": {"k": 50},
            "suppression_limit": 0.05,
            "suppress": ["Name", "Email"],
            "quasi_identifiers": {
              "numerical": [{"column": "Age", "type": "int"}],
              "categorical": ["Gender", "Blood Group"]
            },
            "sensitive_parameter": "Disease",
            "size": {"Age": 2}
          }
        }

    Returns a dict of keyword arguments ready to unpack into spider_pipeline().
    """
    dataset = config.get("data_type", "")
    conf: Dict = config.get(dataset, {})

    # ── SPIDEr-specific top-level keys ───────────────────────────────────────
    epsilon = config.get("epsilon")
    n_samples = config.get("n_samples")
    sensitive_columns: List[str] = (
        config.get("sensitive_columns")
        or ([conf["sensitive_parameter"]] if conf.get("sensitive_parameter") else [])
    )

    # ── k and suppression limit (live inside the dataset section) ────────────
    k = conf.get("k_anonymize", {}).get("k") or conf.get("k")
    suppression_limit = float(conf.get("suppression_limit", 0.05))

    # ── quasi-identifiers: convert SKALD list format → internal dict format ──
    qi_conf = conf.get("quasi_identifiers", {})

    numerical_items: List[Dict] = qi_conf.get("numerical", [])
    categorical_items = qi_conf.get("categorical", [])
    size_map: Dict[str, int] = conf.get("size", {})

    quasi_identifiers: Dict[str, Any] = {}
    for item in numerical_items:
        col = item["column"]
        quasi_identifiers[col] = {
            "kind": "numerical",
            "dtype": item.get("type", "int"),
            "encode": bool(item.get("encode", False)),
            "scale": bool(item.get("scale", False)),
            "s": int(item.get("s", 0)),
            "size": max(2, int(size_map.get(col, 2))),
        }
    for item in categorical_items:
        # SKALD accepts either a plain string or {"column": "..."} object
        col = item if isinstance(item, str) else item["column"]
        quasi_identifiers[col] = {"kind": "categorical"}

    # ── preprocessing passthrough (hashing, masking, encryption …) ───────────
    extra_skald_config = {
        k2: conf.get(k2, [])
        for k2 in (
            "suppress", "hashing_with_salt", "hashing_without_salt",
            "masking", "charcloak", "tokenization", "fpe", "encrypt",
        )
    }

    _missing = [f for f, v in [("k", k), ("epsilon", epsilon), ("n_samples", n_samples)]
                if not v]
    if _missing:
        raise ValueError(f"SPIDEr config is missing required fields: {_missing}")
    if not quasi_identifiers:
        raise ValueError("SPIDEr config has no quasi_identifiers defined.")
    if not sensitive_columns:
        raise ValueError(
            "SPIDEr config must include 'sensitive_columns' (top-level) "
            "or 'sensitive_parameter' (inside the dataset section)."
        )

    return dict(
        k=int(k),
        epsilon=float(epsilon),
        n_samples=int(n_samples),
        quasi_identifiers=quasi_identifiers,
        sensitive_columns=sensitive_columns,
        suppression_limit=suppression_limit,
        extra_skald_config=extra_skald_config,
    )


def run_skald(
    input_csv: str,
    k: int,
    quasi_identifiers: Dict[str, Any],
    sensitive_columns: List[str],
    repo_root: str,
    suppression_limit: float = 0.05,
    extra_skald_config: Optional[Dict] = None,
) -> Tuple[str, List[int]]:
    """Run SKALD on the input CSV and return the generalized output path.

    SKALD requires the working directory to contain data/, chunks/, and output/
    subdirectories. This function manages all file placement automatically.

    Args:
        input_csv: Absolute path to the raw input CSV.
        k: k-anonymity parameter.
        quasi_identifiers: Column metadata mapping:
            {col: {"kind": "numerical"/"categorical",
                   "dtype": "int"/"float",   # for numerical
                   "encode": bool,            # optional
                   "scale": bool,             # optional
                   "s": int,                  # scaling exponent (10^s)
                   "size": int}}              # OLA multiplication factor
        sensitive_columns: Sensitive column names.
        repo_root: Absolute path to the repository root (SKALD's working directory).
        suppression_limit: Maximum fraction of rows SKALD may suppress (0–1).
        extra_skald_config: Optional SKALD preprocessing config
            (suppress, masking, hashing_with_salt, etc.).

    Returns:
        (generalized_csv_path, final_rf) where final_rf is the list of bin widths
        chosen by SKALD, one per numerical QI in config order.
    """
    data_dir = os.path.join(repo_root, "data")
    output_dir = os.path.join(repo_root, "output")
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    # SKALD requires exactly one CSV in data/.
    # Resolve paths first so we never delete the file we're about to use.
    abs_input = os.path.abspath(input_csv)
    dest = os.path.join(data_dir, os.path.basename(input_csv))
    abs_dest = os.path.abspath(dest)

    for fname in os.listdir(data_dir):
        if fname.lower().endswith(".csv"):
            fpath = os.path.abspath(os.path.join(data_dir, fname))
            # Keep the input file if it is already sitting in data/
            if fpath != abs_input:
                os.remove(fpath)

    if abs_input != abs_dest:
        shutil.copy2(input_csv, dest)

    # Write YAML config to a temporary file at repo root so relative paths resolve
    cfg = _build_yaml_config(
        quasi_identifiers=quasi_identifiers,
        sensitive_columns=sensitive_columns,
        k=k,
        output_directory=output_dir,
        suppression_limit=suppression_limit,
        extra=extra_skald_config,
    )
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, dir=repo_root
    ) as tmp:
        yaml.dump(cfg, tmp, default_flow_style=False)
        config_path = tmp.name

    try:
        with _working_dir(repo_root):
            # run_pipeline uses relative paths (data/, chunks/, output/)
            # so we must run it from repo_root
            result = run_pipeline(config_path)
            final_rf = result[0]  # (final_rf, elapsed, dm_star, num_eq, stats)
    finally:
        os.unlink(config_path)

    gen_csv = os.path.join(output_dir, "generalized.csv")
    if not os.path.isfile(gen_csv):
        raise FileNotFoundError(
            f"SKALD did not produce expected output: {gen_csv}\n"
            "Check output/skald.log for details."
        )

    return gen_csv, list(final_rf) if final_rf else []


def build_bins(
    generalized_csv: str,
    quasi_identifiers: Dict[str, Any],
    sensitive_columns: List[str],
) -> List[Bin]:
    """Convert SKALD's generalized CSV output into a list of Bin objects.

    Each bin corresponds to one equivalence class in the generalized data.
    Suppressed rows (where any QI column equals "*") are excluded.

    Args:
        generalized_csv: Path to the generalized CSV produced by SKALD.
        quasi_identifiers: Same dict passed to run_skald().
        sensitive_columns: Columns to treat as sensitive attributes.

    Returns:
        List of Bin objects, one per non-suppressed equivalence class.

    Raises:
        ValueError: If all rows were suppressed.
    """
    df = pd.read_csv(generalized_csv)

    numerical_cols = [
        col for col, m in quasi_identifiers.items() if m["kind"] == "numerical"
    ]
    categorical_cols = [
        col for col, m in quasi_identifiers.items() if m["kind"] == "categorical"
    ]
    qi_cols = numerical_cols + categorical_cols

    # Drop suppressed rows (SKALD marks them with "*" in QI columns)
    suppressed_mask = df[qi_cols].apply(lambda s: s.astype(str) == "*").any(axis=1)
    df = df[~suppressed_mask].reset_index(drop=True)

    if df.empty:
        raise ValueError(
            "All rows were suppressed by SKALD. "
            "Try lowering k or increasing suppression_limit."
        )

    bins: List[Bin] = []
    for _, group in df.groupby(qi_cols, sort=False):
        b = Bin(
            rows=group.reset_index(drop=True),
            numerical_qi_cols=numerical_cols,
            categorical_qi_cols=categorical_cols,
            sensitive_cols=sensitive_columns,
        )
        bins.append(b)

    return bins
