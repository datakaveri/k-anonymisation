# SKALD/core.py
import os
import time
import json
import logging
import psutil
import pandas as pd
import numpy as np
from typing import List, Tuple, Optional
import tempfile
import yaml


# ------------------------
# SKALD modules
# ------------------------
from SKALD.generalization_ri import OLA_1
from SKALD.generalization_rf import OLA_2
from SKALD.utils import format_time, log_performance
from SKALD.config_validation import load_config
from SKALD.encoder import  encode_numerical_columns
from SKALD.chunk_processing import process_chunks_for_histograms
from SKALD.generalize_chunk import generalize_single_chunk
from SKALD.build_QI import build_quasi_identifiers
from SKALD.chunking import split_csv_by_ram
from SKALD.preprocess import (
    suppress,
    encrypt_columns,
    hash_columns,
    mask_columns,
    charcloak_columns,
    fpe_encrypt_columns,
    tokenize_columns,
)
from SKALD.SKALDError import SKALDError
from SKALD.logging_config import setup_logging
from SKALD.combine_chunks import combine_generalized_chunks 


logger = logging.getLogger("SKALD")

# ------------------------------------------------------------------
# Error → Fix mapping
# ------------------------------------------------------------------
ERROR_FIXES = {
    "CONFIG_INVALID": "Validate config against schema and ensure required keys exist",
    "DATA_MISSING": "Ensure CSV files exist and are non-empty",
    "ENCODING_FAILED": "Check numerical columns and enable encoding for sparse attributes",
    "PREPROCESSING_FAILED": "Check suppress/hash/mask/encrypt configuration",
    "MEMORY_ERROR": "Enable chunking or reduce dataset size",
    "GENERALIZATION_FAILED": "Check bin widths and quasi-identifier definitions",
    "INTERNAL_ERROR": "Check logs for stack trace"
}


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
def make_json_safe(obj):
    if isinstance(obj, dict):
        return {k: make_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [make_json_safe(v) for v in obj]
    if isinstance(obj, tuple):
        return [make_json_safe(v) for v in obj]
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    return obj


class InlineListDumper(yaml.SafeDumper):
    """YAML dumper that keeps lists inline where possible."""
    pass

def _safe_listdir(path: str) -> List[str]:
    if not os.path.isdir(path):
        raise FileNotFoundError(f"Directory not found: {path}")
    return os.listdir(path)


def _read_csv_safe(path: str) -> pd.DataFrame:
    try:
        return pd.read_csv(path)
    except FileNotFoundError:
        raise
    except pd.errors.EmptyDataError:
        raise ValueError(f"CSV is empty: {path}")
    except Exception as e:
        raise RuntimeError(f"Failed to read CSV '{path}': {e}")


def _ensure_dir(path: str):
    try:
        os.makedirs(path, exist_ok=True)
    except Exception as e:
        raise SKALDError(
            code="INTERNAL_ERROR",
            message="Failed to create directory",
            details=str(e)
        )


def wrap_internal_error(e: Exception) -> SKALDError:
    return SKALDError(
        code="INTERNAL_ERROR",
        message="Unexpected failure in SKALD pipeline",
        details=str(e),
        suggested_fix=ERROR_FIXES["INTERNAL_ERROR"]
    )


# ==================================================================
# CORE PIPELINE
# ==================================================================
def run_pipeline(
    config_path: str
) -> Tuple[object, float, float, int, dict]:

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    log_file = "output/log.txt"
    setup_logging(log_file)
    start_time = time.time()

    # ------------------------------------------------------------------
    # 1. Load config
    # ------------------------------------------------------------------
    try:
        config = load_config(config_path)
        logger.info("Loaded SKALD configuration")    
    except Exception as e:
        logger.error("Failed to load SKALD configuration: %s", str(e))
        raise SKALDError(
            code="CONFIG_INVALID",
            message="Failed to load SKALD configuration",
            details=str(e)
        )

    if config.enable_k_anonymity and (config.k is None or config.k < 1):
        logger.error("Invalid k value: %s", config.k)
        raise SKALDError(
            code="CONFIG_INVALID",
            message="Invalid k value",
            details=f"k={config.k}",
            suggested_fix="Set k >= 1"
        )

    # ------------------------------------------------------------------
    # 2. Validate input data
    # ------------------------------------------------------------------
    data_dir = "data"
    if not os.path.isdir(data_dir):
        logger.error("Data directory not found: %s", data_dir)
        raise SKALDError(
            code="DATA_MISSING",
            message="Data directory not found",
            details=data_dir
        )
    
    csvs = [
        f for f in _safe_listdir(data_dir)
        if f.lower().endswith(".csv") and os.path.getsize(os.path.join(data_dir, f)) > 0
    ]
    logger.info("Loaded data from data directory")
    if not csvs:
        logger.error("No non-empty CSV files found in data directory: %s", data_dir)
        raise SKALDError(
            code="DATA_MISSING",
            message="No non-empty CSV files found",
            details=data_dir
        )

    # ------------------------------------------------------------------
    # 3. Chunking
    # ------------------------------------------------------------------
    try:
        split_csv_by_ram(data_dir)
    except Exception as e:
        raise SKALDError(
            code="MEMORY_ERROR",
            message="Failed to split dataset into chunks",
            details=str(e)
        )

    chunk_dir = "chunks"
    chunk_files = sorted(f for f in _safe_listdir(chunk_dir) if f.endswith(".csv"))
    if not chunk_files:
        logger.error("No chunks generated in directory: %s", chunk_dir)
        raise SKALDError(
            code="DATA_MISSING",
            message="No chunks generated"
        )

    # ------------------------------------------------------------------
    # 4. Preprocessing
    # ------------------------------------------------------------------
    try:
        for fname in chunk_files:
            path = os.path.join(chunk_dir, fname)
            df = _read_csv_safe(path)

            if config.suppress:
                df = suppress(df, config.suppress)
            if config.hashing_with_salt or config.hashing_without_salt:
                df = hash_columns(df, config.hashing_with_salt, config.hashing_without_salt)
            if config.masking:
                df = mask_columns(df, config.masking)
            if config.charcloak:
                df = charcloak_columns(df, config.charcloak)
            if config.tokenization:
                df = tokenize_columns(df, config.tokenization, config.output_directory)
            if config.fpe:
                df = fpe_encrypt_columns(df, config.fpe, config.output_directory)
            if config.encrypt:
                df = encrypt_columns(df, config.encrypt, config.output_directory)

        
            target_dir = (
                config.output_directory
                if not config.enable_k_anonymity
                else chunk_dir
            )

            os.makedirs(target_dir, exist_ok=True)  
            out_path = os.path.join(target_dir, fname)
            tmp = out_path + ".tmp"

            try:
                df.to_csv(tmp, index=False)
                os.replace(tmp, out_path)
            finally:
                if os.path.exists(tmp):
                    os.remove(tmp)
        logger.info("Completed preprocessing on all chunks")
    except SKALDError:
        raise
    except Exception as e:
        logger.error("Preprocessing failed: %s", str(e))
        raise SKALDError(
            code="PREPROCESSING_FAILED",
            message="Preprocessing failed",
            details=str(e)
        )

    # ------------------------------------------------------------------
    # 5. Early exit (no k-anonymity)
    # ------------------------------------------------------------------
    if not config.enable_k_anonymity:
        logger.info("K-anonymity disabled; skipping k-anonymisation")
        combine_generalized_chunks(config.output_directory, config.output_path)        
        return {}, time.time() - start_time, None, None, None

    # ------------------------------------------------------------------
    # 6. Prepare QI info
    # ------------------------------------------------------------------
    categorical_columns = [q.column for q in config.quasi_identifiers.categorical]
    numerical_columns_info = [
        {"column": q.column, "scale": q.scale, "s": q.s, "encode": q.encode, "type": q.type}
        for q in config.quasi_identifiers.numerical
    ]

    # ------------------------------------------------------------------
    # 7. Scale & Encode numericals
    # ------------------------------------------------------------------
    try:
        encoding_maps, dynamic_min_max =encode_numerical_columns(
            chunk_files, chunk_dir, numerical_columns_info
        )
    except Exception as e:
        raise SKALDError(
            code="ENCODING_FAILED",
            message="Numerical encoding failed",
            details=str(e)
        )

    # ------------------------------------------------------------------
    # 8. Build quasi-identifiers
    # ------------------------------------------------------------------
    try:
        quasi_identifiers, _ = build_quasi_identifiers(
            numerical_columns_info,
            categorical_columns,
            encoding_maps,
            dynamic_min_max
        )
    except Exception as e:
        raise SKALDError(
            code="CONFIG_INVALID",
            message="Failed to build quasi-identifiers",
            details=str(e)
        )
    logger.info("Built quasi-identifiers for generalization")
    # ------------------------------------------------------------------
    # 9. OLA-1 (Ri)
    # ------------------------------------------------------------------
    try:
        n = len(chunk_files)
        available_ram = psutil.virtual_memory().available
        max_eq = max(1, available_ram // 32)
        ola_1 = OLA_1(
            quasi_identifiers,
            n,
            max_eq,
            config.size or {}
        )
        ola_1.build_tree()
        ola_1.find_smallest_passing_ri()
        initial_ri = ola_1.get_optimal_ri()
        logger.info("Completed OLA-1; initial Ri: %s", initial_ri)
    except Exception as e:
        raise SKALDError(
            code="GENERALIZATION_FAILED",
            message="OLA_1 failed",
            details=str(e)
        )

    # ------------------------------------------------------------------
    # 10. OLA-2 
    # ------------------------------------------------------------------
    try:
        first_chunk = _read_csv_safe(os.path.join(chunk_dir, chunk_files[0]))
        total_records = len(first_chunk) * len(chunk_files)

        ola_2 = OLA_2(
            quasi_identifiers,
            total_records,
            config.suppression_limit,
            config.size or {},
            config.sensitive_parameter,
            enable_l_diversity=config.enable_l_diversity
        )

        ola_2.build_tree(initial_ri)

        global_hist = process_chunks_for_histograms(
            chunk_files,
            chunk_dir,
            numerical_columns_info,
            encoding_maps,
            ola_2,
            initial_ri
        )
        final_rf = ola_2.get_final_binwidths(
            global_hist,
            config.k,
            config.l if config.enable_l_diversity else 1
        )

        lowest_dm_star = ola_2.lowest_dm_star
        num_eq_classes = ola_2.best_num_eq_classes
        eq_class_stats = ola_2.get_equivalence_class_stats(global_hist, final_rf, config.k)
        top_ola2_nodes = ola_2.get_top_rf_nodes(5)

    except Exception as e:
        logger.exception("OLA_2 failed with exception: %s", e)
        raise SKALDError(
            code="GENERALIZATION_FAILED",
            message="OLA_2 failed",
            details=str(e)
        )

    # ------------------------------------------------------------------
    # 11. Output generalized chunk
    # ------------------------------------------------------------------
    try:
        all_files = sorted([f for f in _safe_listdir(chunk_dir) if f.endswith(".csv")])
        for idx, chunk_file in enumerate(all_files, start=1):
            _ensure_dir(config.output_directory)
            base_name = f"{config.output_path.rstrip('.csv')}_chunk{idx}.csv"
            output_file = os.path.join(config.output_directory, base_name)
            generalize_single_chunk(
                chunk_file,
                chunk_dir,
                output_file,
                numerical_columns_info,
                encoding_maps,
                ola_2,
                final_rf
            )

        combine_generalized_chunks(config.output_directory, config.output_path)

        # Write equivalence class stats separately
        _ensure_dir(config.output_directory)
        stats_path = os.path.join(config.output_directory, "equivalence_class_stats.json")
        with open(stats_path, "w") as f:
            json.dump(make_json_safe(eq_class_stats), f, indent=2)

        top_nodes_path = os.path.join(config.output_directory, "top_ola2_nodes.json")
        with open(top_nodes_path, "w") as f:
            json.dump(make_json_safe(top_ola2_nodes), f, indent=2)
    except Exception as e:
        raise SKALDError(
            code="GENERALIZATION_FAILED",
            message="Failed to generate anonymized output",
            details=str(e)
        )

    elapsed = time.time() - start_time
    log_performance("SKALD full pipeline executed", start_time)

    return final_rf, elapsed, lowest_dm_star, num_eq_classes, eq_class_stats


# ==================================================================
# IN-MEMORY API  (adapter / library use)
# ==================================================================

def _preprocess_df(df: pd.DataFrame, config) -> pd.DataFrame:
    """Apply all configured preprocess steps to a DataFrame in-memory."""
    if config.suppress:
        df = suppress(df, config.suppress)
    if config.hashing_with_salt or config.hashing_without_salt:
        df = hash_columns(df, config.hashing_with_salt, config.hashing_without_salt)
    if config.masking:
        df = mask_columns(df, config.masking)
    if config.charcloak:
        df = charcloak_columns(df, config.charcloak)
    if config.tokenization:
        df = tokenize_columns(df, config.tokenization, config.output_directory)
    if config.fpe:
        df = fpe_encrypt_columns(df, config.fpe, config.output_directory)
    if config.encrypt:
        df = encrypt_columns(df, config.encrypt, config.output_directory)
    return df


def _encode_df_in_memory(
    df: pd.DataFrame,
    numerical_columns_info: list,
) -> tuple:
    """
    Build encoding_maps and dynamic_min_max from a single in-memory DataFrame,
    then apply the same transformations that encode_numerical_columns + chunk
    processing would do from disk.

    Returns (df_processed, encoding_maps, dynamic_min_max).
    """
    import numpy as np

    encoding_maps = {}
    dynamic_min_max = {}
    df = df.copy()

    for info in numerical_columns_info:
        col     = info["column"]
        encode  = bool(info.get("encode", False))
        scale   = bool(info.get("scale", False))
        s       = int(info.get("s", 0)) if scale else 0
        dtype   = info.get("type", "int")

        if col not in df.columns:
            raise KeyError(f"Column '{col}' not found in records")

        raw = df[col].replace(r"^\s*$", np.nan, regex=True)
        numeric = pd.to_numeric(raw, errors="coerce")

        col_min = float(numeric.min())
        col_max = float(numeric.max())
        dynamic_min_max[col] = [col_min, col_max]

        if encode:
            scaled = np.floor(numeric / (10 ** s)).astype("Int64") if scale else numeric.astype("Int64")
            unique_vals = sorted(scaled.dropna().unique().tolist())
            enc_map = {v: i for i, v in enumerate(unique_vals)}
            enc_col = f"{col}_scaled_encoded" if scale else f"{col}_encoded"
            df[enc_col] = scaled.map(enc_map)
            encoding_maps[col] = {"encoding_map": enc_map, "scale": scale, "s": s}
        else:
            df[col] = numeric

    return df, encoding_maps, dynamic_min_max


def run_on_records(records: list, config) -> list:
    """
    Run the full SKALD pipeline on an in-memory list of dicts.

    No file I/O — all steps (preprocess + optional k-anon) execute in RAM.
    The config object is a ``Config`` instance from ``config_validation``.

    Returns a list of dicts with the same keys (minus suppressed columns,
    plus generalized QI columns if k-anon is enabled).
    """
    import numpy as np
    from SKALD.generalization_ri import OLA_1
    from SKALD.generalization_rf import OLA_2
    from SKALD.build_QI import build_quasi_identifiers

    if not records:
        return records

    df = pd.DataFrame(records)

    # ── Preprocess ────────────────────────────────────────────────
    try:
        df = _preprocess_df(df, config)
    except Exception as e:
        raise SKALDError(
            code="PREPROCESSING_FAILED",
            message="Preprocessing failed",
            details=str(e),
        )

    if not config.enable_k_anonymity:
        return df.to_dict(orient="records")

    # ── K-anonymity (in-memory) ───────────────────────────────────
    categorical_columns = [q.column for q in config.quasi_identifiers.categorical]
    numerical_columns_info = [
        {"column": q.column, "scale": q.scale, "s": q.s, "encode": q.encode, "type": q.type}
        for q in config.quasi_identifiers.numerical
    ]

    # Split: rows with any null/empty in a QI column bypass k-anon and pass through unchanged.
    qi_cols = [i["column"] for i in numerical_columns_info] + categorical_columns
    existing_qi_cols = [c for c in qi_cols if c in df.columns]
    null_mask = df[existing_qi_cols].apply(
        lambda col: col.isna() | (col.astype(str).str.strip() == "")
    ).any(axis=1)

    df_skip = df[null_mask].copy()      # rows with incomplete QIs — passed through as-is
    df = df[~null_mask].copy()          # rows eligible for k-anon

    if df.empty:
        logger.warning("All records have null/empty QI values — k-anonymity skipped for entire batch")
        return pd.concat([df, df_skip], ignore_index=True).to_dict(orient="records")

    if null_mask.any():
        logger.info("Skipping k-anonymity for %d record(s) with null/empty QI values", null_mask.sum())

    try:
        df, encoding_maps, dynamic_min_max = _encode_df_in_memory(df, numerical_columns_info)
    except Exception as e:
        raise SKALDError(code="ENCODING_FAILED", message="Numerical encoding failed", details=str(e))

    try:
        quasi_identifiers, _ = build_quasi_identifiers(
            numerical_columns_info, categorical_columns, encoding_maps, dynamic_min_max
        )
    except Exception as e:
        raise SKALDError(code="CONFIG_INVALID", message="Failed to build quasi-identifiers", details=str(e))

    try:
        available_ram = psutil.virtual_memory().available
        max_eq = max(1, available_ram // 32)
        ola_1 = OLA_1(quasi_identifiers, 1, max_eq, config.size or {})
        ola_1.build_tree()
        ola_1.find_smallest_passing_ri()
        initial_ri = ola_1.get_optimal_ri()
    except Exception as e:
        raise SKALDError(code="GENERALIZATION_FAILED", message="OLA_1 failed", details=str(e))

    try:
        ola_2 = OLA_2(
            quasi_identifiers,
            len(df),
            config.suppression_limit,
            config.size or {},
            config.sensitive_parameter,
            enable_l_diversity=config.enable_l_diversity,
        )
        ola_2.build_tree(initial_ri)
        histogram = ola_2.process_chunk(df, initial_ri)
        final_rf = ola_2.get_final_binwidths(histogram, config.k, config.l if config.enable_l_diversity else 1)
    except Exception as e:
        raise SKALDError(code="GENERALIZATION_FAILED", message="OLA_2 failed", details=str(e))

    try:
        s_list = [int(info.get("s", 0)) if info.get("scale") else 0 for info in numerical_columns_info]
        generalized = ola_2.generalize_chunk(df, final_rf, s_list)
        for info in numerical_columns_info:
            base = info["column"]
            for suffix in ("_scaled_encoded", "_scaled", "_encoded"):
                if base + suffix in generalized.columns:
                    generalized.drop(columns=[base + suffix], inplace=True)
    except Exception as e:
        raise SKALDError(code="GENERALIZATION_FAILED", message="Generalization failed", details=str(e))

    # Recombine: generalized rows first, skipped rows appended at the end
    if df_skip.empty:
        return generalized.to_dict(orient="records")
    result = pd.concat([generalized, df_skip], ignore_index=True)
    return result.to_dict(orient="records")


def run_on_records_safe(records: list, config) -> dict:
    """Like run_on_records but always returns a status dict — never raises."""
    try:
        result = run_on_records(records, config)
        return {"status": "success", "records": result}
    except SKALDError as e:
        return {"status": "error", "error": e.to_dict()}
    except Exception as e:
        return {"status": "error", "error": wrap_internal_error(e).to_dict()}


# ==================================================================
# SAFE WRAPPER (UI ENTRY)
# ==================================================================
def run_pipeline_safe(config_path: str) -> dict:
    logger = logging.getLogger("SKALD")

    try:
        rf, elapsed, dm_star, num_eq, eq_stats = run_pipeline(config_path)

        sample_rows = []
        top_ola2_nodes = []
        try:
            cfg = load_config(config_path)

            candidate_paths = []
            if cfg.output_path:
                candidate_paths.append(cfg.output_path)
                if not os.path.isabs(cfg.output_path):
                    candidate_paths.append(
                        os.path.join(cfg.output_directory, os.path.basename(cfg.output_path))
                    )

            for out_csv in candidate_paths:
                if os.path.isfile(out_csv):
                    sample_rows = pd.read_csv(out_csv).head(10).to_dict(orient="records")
                    break

            top_nodes_path = os.path.join(cfg.output_directory, "top_ola2_nodes.json")
            if os.path.isfile(top_nodes_path):
                with open(top_nodes_path, "r") as f:
                    top_ola2_nodes = json.load(f)
        except Exception as e:
            logger.warning("Failed to load sample output/top nodes into status response: %s", e)

        return make_json_safe({
            "status": "success",
            "outputs": {
                "final_bin_widths": rf,
                "elapsed_time_seconds": elapsed,
                "lowest_dm_star": dm_star,
                "num_equivalence_classes": num_eq,
                "equivalence_class_stats": eq_stats,
                "top_ola2_nodes": top_ola2_nodes,
                "sample_generalized_rows": sample_rows
            },
            "log_file": "log.txt"
        })

    except SKALDError as e:
        return {
            "status": "error",
            "error": {
                "code": e.code,
                "message": e.message,
                "details": e.details,
                "suggested_fix": e.suggested_fix or ERROR_FIXES.get(e.code)
            },
            "log_file": "log.txt"
        }

    except Exception as e:
        err = wrap_internal_error(e)
        return {
            "status": "error",
            "error": err.to_dict(),
            "log_file": "log.txt"
        }

# === ENTRY POINT ===
def _entry_main() -> str:
    """
    Prepares config and returns a YAML config PATH.
    Does NOT run the pipeline.
    """

    config_root = "config"

    if not os.path.isdir(config_root):
        raise FileNotFoundError(f"Config directory not found: {config_root}")

    config_files = [
        f for f in os.listdir(config_root)
        if f.endswith(".json")
    ]

    if not config_files:
        raise FileNotFoundError("No config.json found in config/")

    config_path = os.path.join(config_root, config_files[0])
    #print(f"Running SKALD with config: {config_path}")

    with open(config_path, "r") as f:
        config = json.load(f)

    if "operations" not in config or "data_type" not in config:
        raise KeyError("Invalid config JSON")
    operations = config["operations"]
    enable_k_anonymity = False
    if "k-anonymity" in operations:
        enable_k_anonymity = True
    else:
        enable_k_anonymity = False
    dataset = config["data_type"]
    conf = config.get(dataset, {})

    yaml_config = {
        "enable_k_anonymity": enable_k_anonymity,
        "enable_l_diversity": conf.get("enable_l_diversity", False),
        "output_path": conf.get("output_path", "generalized.csv"),
        "output_directory": conf.get("output_directory", "output"),
        "log_file": conf.get("log_file", "log.txt"),
        "suppress": conf.get("suppress", []),
        "hashing_with_salt": conf.get("hashing_with_salt", []),
        "hashing_without_salt": conf.get("hashing_without_salt", []),
        "masking": conf.get("masking", []),
        "charcloak": conf.get("charcloak", []),
        "tokenization": conf.get("tokenization", []),
        "fpe": conf.get("fpe", []),
        "encrypt": conf.get("encrypt", []),
        "quasi_identifiers": conf.get("quasi_identifiers", {}),
        "k": conf.get("k_anonymize", {}).get("k", 1),
        "l": conf.get("l_diversify", {}).get("l", 1),
        "sensitive_parameter": conf.get("sensitive_parameter"),
        "size": conf.get("size", {}),
        "suppression_limit": conf.get("suppression_limit", 0),
    }

    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    )
    yaml.dump(yaml_config, tmp, sort_keys=False)
    tmp.close()

    return tmp.name  


if __name__ == "__main__":
    try:
        config_path = _entry_main()          # ← string
        response = run_pipeline_safe(config_path)

    except SKALDError as e:
        response = {
            "status": "error",
            "error": e.to_dict(),
            "log_file": "log.txt"
        }

    except Exception as e:
        response = {
            "status": "error",
            "error": {
                "code": "INTERNAL_ERROR",
                "message": str(e)
            },
            "log_file": "log.txt"
        }
    status_path = "output/status.json"
    with open(status_path, "w") as f:
        json.dump(make_json_safe(response), f, indent=2)

    #print(json.dumps(make_json_safe(response), indent=2))
    
