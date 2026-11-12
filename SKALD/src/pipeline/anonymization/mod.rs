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

mod generalization;
mod ola;

pub(crate) use generalization::{ClassTally, decide_classes, generalize_cell};
pub use generalization::{
    GeneralizationSummary, LDiversity, generalize_and_write_outputs, generalize_and_write_outputs_with,
};
pub use ola::{
    CategoricalLevels, GRID_K_VALUES, GRID_SUPPRESSION_LIMITS, GridEntry, INVALID_BIN, IntervalHierarchy,
    MAX_LATTICE_NODES, MAX_NUMERIC_QI_MAGNITUDE, NodeTrace, Ola2NodeScore, Ola2SearchResult, ParameterGrid,
    QuasiIdentifierLite, SensitiveSets, SparseHist, ZHist, allowed_suppressions, attach_categorical_levels,
    build_categorical_levels, build_direct_histogram, build_fixed_interval_hierarchy, build_interval_hierarchy,
    build_sensitive_sets, build_sparse_histogram, build_tuple_histogram, build_tuple_sensitive_sets, build_z_histogram,
    categorical_ladder_len, compute_equivalence_space, compute_k_optimal, compute_parameter_grid,
    compute_parameter_grid_for, compute_parameter_grid_z, compute_z_weights, equivalence_class_stats,
    find_ola1_initial_ri, find_ola2_best_rf, find_ola2_best_rf_detailed, find_ola2_best_rf_z_detailed, find_ola2_with,
    l_aware_class_sizes, merge_histogram, merge_z_histogram, normalize_categorical, parse_numeric_qi,
    resolve_qi_columns, scan_chunks_for_flow, within_suppression_limit, z_hist_to_sparse,
};

use crate::pipeline::bootstrap::{PipelineError, RuntimeConfig, open_csv, validation};
use std::collections::BTreeMap;
use std::path::PathBuf;

// ── Shared utility functions ─────────────────────────────────────────────────

/// Scans all chunk CSV files and computes the global (min, max) for each
/// numerical column in a single streaming pass.
///
/// Values are read with [`parse_numeric_qi`], exactly as the histogram and the
/// output step read them, so an unparseable or out-of-range cell (`NA`, `inf`,
/// `-1e18`) cannot stretch the range and blur every other bin.
///
/// # Returns
/// A map from column name to `(global_min, global_max)`. Columns with no
/// parseable values yield `(0.0, 0.0)`.
///
/// # Errors
/// Returns [`PipelineError`] if a chunk cannot be read, lacks a column, or has
/// a row whose width differs from its header.
pub fn compute_numerical_min_max(
    chunk_paths: &[PathBuf],
    numerical_columns: &[String],
) -> Result<BTreeMap<String, (f64, f64)>, PipelineError> {
    let mut acc: Vec<Option<(i64, i64)>> = vec![None; numerical_columns.len()];
    for chunk_path in chunk_paths {
        let (headers, mut records) = open_csv(chunk_path)?;
        let col_indices: Vec<usize> = numerical_columns
            .iter()
            .map(|col| {
                headers.iter().position(|h| h == col).ok_or_else(|| {
                    validation("DATA_COLUMN_MISSING", "Quasi-identifier column not found in CSV header", col)
                })
            })
            .collect::<Result<_, _>>()?;
        while let Some(fields) = records.next_record_of_width(headers.len())? {
            for (slot, &idx) in acc.iter_mut().zip(&col_indices) {
                if let Some(v) = parse_numeric_qi(&fields[idx]) {
                    *slot = Some(slot.map_or((v, v), |(mn, mx)| (mn.min(v), mx.max(v))));
                }
            }
        }
    }
    Ok(numerical_columns
        .iter()
        .zip(acc)
        .map(|(c, mm)| {
            let (mn, mx) = mm.unwrap_or((0, 0));
            (c.clone(), (mn as f64, mx as f64))
        })
        .collect())
}

/// Builds the ordered list of [`QuasiIdentifierLite`] descriptors from the
/// pipeline configuration and the previously computed min/max map.
///
/// Numerical QIs come first (in config order), followed by categorical QIs.
/// A numerical QI's generalisation comes from, in order of precedence:
/// `fixed_bins` (one fixed level, excluded from the lattice search),
/// `qi_constraints` intervals (a multi-level hierarchy), or uniform bins
/// widened by its `size` factor.
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
        let interval_hierarchy = if let Some(bins) = cfg.fixed_bins.get(&qi.column) {
            Some(build_fixed_interval_hierarchy(bins.clone()))
        } else {
            cfg.qi_interval_constraints.get(&qi.column).map(|iv| {
                let split = cfg.size_factors.get(&qi.column).copied().unwrap_or(2).max(2) as usize;
                build_interval_hierarchy(iv.clone(), split)
            })
        };
        out.push(QuasiIdentifierLite {
            column_name: qi.column.clone(),
            is_categorical: false,
            min_value: Some(mn),
            max_value: Some(mx),
            interval_hierarchy,
            categorical_levels: None,
        });
    }

    for c in &cfg.categorical_qis {
        out.push(QuasiIdentifierLite {
            column_name: c.clone(),
            is_categorical: true,
            min_value: None,
            max_value: None,
            interval_hierarchy: None,
            categorical_levels: None,
        });
    }

    if out.is_empty() {
        return Err(validation("CONFIG_INVALID", "No quasi-identifiers defined", "quasi_identifiers"));
    }

    Ok(out)
}
