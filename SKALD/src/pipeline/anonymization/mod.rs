//! Anonymization module for the SKALD k-anonymity pipeline.
//!
//! This module implements the two-phase Optimal Lattice Anonymization (OLA) algorithm:
//!
//! - **OLA-1** (`ola` submodule): finds the initial generalization node (`ri`) that satisfies
//!   a memory-based equivalence-class constraint using a synthetic tree search.
//! - **OLA-2** (`ola` submodule): binary-searches the full generalization lattice built from
//!   real data to find the node that minimises DM* while satisfying k-anonymity and suppression
//!   constraints.
//! - **Generalization** (`generalization` submodule): applies the chosen generalization factors
//!   to every chunk and writes the anonymized output files, with a two-pass suppression step.
//!
//! Public types and scan helpers are defined here in `mod.rs` and re-exported so callers can use
//! a flat `pipeline::anonymization::*` import surface.

mod ola;
mod generalization;

pub use ola::{
    build_interval_hierarchy,
    find_ola1_initial_ri,
    build_sparse_histogram,
    find_ola2_best_rf,
    find_ola2_best_rf_detailed,
    equivalence_class_stats,
    compute_parameter_grid,
    compute_k_optimal,
    GridEntry,
    IntervalHierarchy,
    Ola2NodeScore,
    Ola2SearchResult,
    QuasiIdentifierLite,
    SparseHist,
};
pub use generalization::generalize_and_write_outputs;

use crate::pipeline::bootstrap::{split_csv_line_basic, validation, PipelineError, RuntimeConfig};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

// ── Shared utility functions ─────────────────────────────────────────────────

/// Strips encoding/scaling suffixes from an internal column name to recover
/// the original human-readable name used in the pipeline configuration.
///
/// Recognized suffixes (checked in priority order):
/// - `_scaled_encoded`
/// - `_encoded`
/// - `_scaled`
///
/// # Arguments
/// * `col` — the potentially-suffixed column name.
///
/// # Returns
/// The base column name with no suffix, or `col` unchanged if none matched.
pub fn base_col_name(col: &str) -> String {
    if let Some(v) = col.strip_suffix("_scaled_encoded") {
        v.to_string()
    } else if let Some(v) = col.strip_suffix("_encoded") {
        v.to_string()
    } else if let Some(v) = col.strip_suffix("_scaled") {
        v.to_string()
    } else {
        col.to_string()
    }
}

/// Scans all chunk CSV files and computes the global (min, max) for each
/// numerical column in a single streaming pass.
///
/// The result is used to populate `QuasiIdentifierLite::min_value` /
/// `max_value` before entering the OLA phases.
///
/// # Arguments
/// * `chunk_paths` — paths to the pre-processed chunk CSV files.
/// * `numerical_columns` — column names to aggregate (must be numeric-valued).
///
/// # Returns
/// A map from column name to `(global_min, global_max)`. Columns with no
/// parseable values yield `(0.0, 0.0)`.
///
/// # Errors
/// Returns [`PipelineError`] if any chunk file cannot be opened or its header
/// is malformed.
pub fn compute_numerical_min_max(
    chunk_paths: &[PathBuf],
    numerical_columns: &[String],
) -> Result<BTreeMap<String, (f64, f64)>, PipelineError> {
    // (min, max) accumulators — one entry per column, updated in a single pass per chunk
    let mut acc: BTreeMap<String, (Option<f64>, Option<f64>)> =
        numerical_columns.iter().map(|c| (c.clone(), (None, None))).collect();

    for chunk_path in chunk_paths {
        let f = fs::File::open(chunk_path)?;
        let r = BufReader::new(f);
        let mut lines = r.lines();
        let header = lines
            .next()
            .ok_or_else(|| validation("ENCODING_FAILED", "Chunk missing header", &chunk_path.display().to_string()))?
            .map_err(|e| validation("ENCODING_FAILED", "Failed reading header", &e.to_string()))?;
        let headers = split_csv_line_basic(&header);

        // Resolve column indices once per chunk (same schema across all chunks)
        let col_indices: Vec<Option<usize>> = numerical_columns
            .iter()
            .map(|col| headers.iter().position(|h| h == col))
            .collect();

        for line in lines {
            let line = line.map_err(|e| validation("GENERALIZATION_FAILED", "Failed reading row", &e.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }
            let fields = split_csv_line_basic(&line);
            for (col_name, col_idx_opt) in numerical_columns.iter().zip(col_indices.iter()) {
                let Some(col_idx) = col_idx_opt else { continue };
                if *col_idx >= fields.len() {
                    continue;
                }
                if let Ok(v) = fields[*col_idx].trim().parse::<f64>() {
                    let entry = acc.get_mut(col_name).unwrap();
                    entry.0 = Some(entry.0.map_or(v, |m: f64| m.min(v)));
                    entry.1 = Some(entry.1.map_or(v, |m: f64| m.max(v)));
                }
            }
        }
    }

    Ok(acc
        .into_iter()
        .map(|(k, (mn, mx))| (k, (mn.unwrap_or(0.0), mx.unwrap_or(0.0))))
        .collect())
}

/// Builds the ordered list of [`QuasiIdentifierLite`] descriptors from the
/// pipeline configuration and the previously computed min/max map.
///
/// Numerical QIs come first (in config order), followed by categorical QIs.
///
/// # Arguments
/// * `cfg` — the validated runtime pipeline configuration.
/// * `dynamic_min_max` — output of [`compute_numerical_min_max`].
///
/// # Returns
/// A non-empty `Vec<QuasiIdentifierLite>`.
///
/// # Errors
/// Returns [`PipelineError`] with code `CONFIG_INVALID` when no QIs are
/// configured (both `numerical_qis` and `categorical_qis` are empty).
pub fn build_quasi_identifiers(
    cfg: &RuntimeConfig,
    dynamic_min_max: &BTreeMap<String, (f64, f64)>,
) -> Result<Vec<QuasiIdentifierLite>, PipelineError> {
    let mut out = Vec::new();

    for qi in &cfg.numerical_qis {
        let (mn, mx) = dynamic_min_max.get(&qi.column).copied().unwrap_or((0.0, 0.0));
        let interval_hierarchy = if let Some(iv) = cfg.qi_interval_constraints.get(&qi.column) {
            let split = cfg.size_factors.get(&qi.column).copied().unwrap_or(2) as usize;
            Some(build_interval_hierarchy(iv.clone(), split))
        } else {
            None
        };
        out.push(QuasiIdentifierLite {
            column_name: qi.column.clone(),
            is_categorical: false,
            min_value: Some(mn),
            max_value: Some(mx),
            interval_hierarchy,
        });
    }

    for c in &cfg.categorical_qis {
        out.push(QuasiIdentifierLite {
            column_name: c.clone(),
            is_categorical: true,
            min_value: None,
            max_value: None,
            interval_hierarchy: None,
        });
    }

    if out.is_empty() {
        return Err(validation("CONFIG_INVALID", "No quasi-identifiers defined", "quasi_identifiers"));
    }

    Ok(out)
}
