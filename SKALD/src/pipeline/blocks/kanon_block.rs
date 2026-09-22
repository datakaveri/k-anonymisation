//! Block 3 — k-anonymization, split into `scan` → `solve` → `apply`.
//!
//! k-anonymity is the one thing in SKALD that genuinely cannot be column
//! sharded: the privacy guarantee is a property of the *whole* quasi-identifier
//! tuple over the *whole* dataset, so every QI column has to arrive at the same
//! place, and every row has to be counted. What it *can* be is row sharded, and
//! that is what these three stages express:
//!
//! ```text
//!   scan   (map,    per row shard)  → partial histogram + local column stats
//!   solve  (reduce, exactly once)   → global histogram → OLA-1 → OLA-2 → RF
//!   apply  (map,    per row shard)  → generalized rows, using the solution
//! ```
//!
//! ## What this fixes about the two-pass flow
//!
//! The monolith's `pass1` reads the data, builds a histogram, reports
//! `k_optimal`, and throws the histogram away. `pass2` then reads the same data
//! again to rebuild the same histogram. Under the AO that is not merely
//! wasteful — it means the raw dataset has to be held (or re-fetched, and
//! re-exposed to workers) across a human decision point that can take minutes
//! or days.
//!
//! So `solve` persists the merged histogram as `histogram.json`. `pass1` is
//! `scan` + `solve`. `pass2` is `solve` again against that artifact, with no
//! `scan` and no access to the raw data at all — it is a pure re-solve over a
//! derived aggregate. Only `apply` touches rows again, and only once k is
//! known. A job can be re-solved for several candidate k values at essentially
//! zero cost and zero additional exposure.
//!
//! ## What this fixes about suppression
//!
//! The monolith computes equivalence-class counts *per chunk* during
//! generalization, so a record whose class is globally well above k can still
//! be starred out because its own chunk happened to hold few members of that
//! class. With one process and one chunk that is invisible; with the AO
//! fanning out row shards it would corrupt results in proportion to the fan-out.
//! `solve` therefore computes the below-k classes once, globally, and `apply`
//! tests membership against that set instead of counting locally.

use super::{BlockManifest, BlockReport, Shard};
use crate::pipeline::anonymization::generalization::{
    generalize_categorical_value, generalize_numeric_label,
};
use crate::pipeline::anonymization::{
    base_col_name, build_quasi_identifiers, compute_equivalence_space, compute_k_optimal,
    compute_parameter_grid, compute_parameter_grid_over, equivalence_class_stats, find_ola1_initial_ri,
    find_ola2_best_rf_detailed, merge_histogram, GridEntry, QuasiIdentifierLite, SparseHist,
};
use crate::pipeline::bootstrap::{
    HierarchyMap,
    available_ram_bytes, parse_runtime_config, validation, FlowMode, PipelineError, RuntimeConfig,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

/// A `scan` artifact: one row shard's contribution to the global histogram.
///
/// The histogram is keyed on **raw values**, not on bucket indices. That is the
/// detail that makes distributed scanning work at all: a bucket index depends
/// on the global column minimum and the global categorical domain, neither of
/// which any single shard knows. Raw-value keys are shard-independent, so
/// partial scans merge by simple addition and `solve` derives the index space
/// afterwards from the merged result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardScan {
    pub schema_version: u32,
    pub job_id: String,
    pub shard_id: String,
    pub qi_columns: Vec<String>,
    /// Rows seen, including rows dropped for unparsable QI values.
    pub rows_total: i64,
    /// Rows that contributed a histogram entry.
    pub rows_valid: i64,
    /// Numeric QI column → (min, max) over this shard.
    pub numeric_bounds: BTreeMap<String, (f64, f64)>,
    /// Categorical QI column → the distinct values this shard saw.
    pub categorical_domains: BTreeMap<String, Vec<String>>,
    /// Raw QI value tuple → count. Tuples are in `qi_columns` order.
    pub hist: Vec<(Vec<String>, i64)>,
}

/// A `solve` artifact: everything `apply` needs, and nothing it does not.
///
/// Notably this carries no raw data — only column statistics and the lattice
/// result — so it is the one artifact that is safe to show the user between
/// pass 1 and pass 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Solution {
    pub schema_version: u32,
    pub job_id: String,
    pub pass: String,
    pub qi_columns: Vec<String>,
    pub numeric_bounds: BTreeMap<String, (f64, f64)>,
    pub categorical_domains: BTreeMap<String, Vec<String>>,
    pub total_records: i64,
    pub k: i64,
    pub suppression_limit: f64,
    pub flow: String,
    pub initial_ri: Vec<i64>,
    /// `None` after a pass-1 solve, which stops before the lattice search.
    pub final_rf: Option<Vec<i64>>,
    #[serde(default)]
    pub k_optimal: Option<i64>,
    #[serde(default)]
    pub lowest_dm_star: Option<i64>,
    #[serde(default)]
    pub num_equivalence_classes: Option<i64>,
    #[serde(default)]
    pub equivalence_class_stats: BTreeMap<i64, i64>,
    #[serde(default)]
    pub parameter_grid: Vec<GridEntry>,
    /// Generalized **label** tuples, at `final_rf`, whose global count is
    /// below k. `apply` stars any row landing in one of these.
    ///
    /// Label space, not index space, and the distinction is load-bearing. The
    /// lattice search models categorical generalization as integer division on
    /// the domain index, but what actually gets published comes from the
    /// configured hierarchy — and for a column with no hierarchy every value
    /// above level 1 collapses to `*`. The two disagree, so a class that looks
    /// small to OLA-2 can be published as part of a much larger one. k-anonymity
    /// is a property of the released table, so the below-k set is computed over
    /// exactly the strings that will be written.
    #[serde(default)]
    pub suppressed_classes: Vec<Vec<String>>,
    #[serde(default)]
    pub suppressed_records: i64,
    /// Rows the scan could not place: a quasi-identifier that did not parse,
    /// fell outside every configured interval, or was not in the categorical
    /// domain. They never entered the histogram, so no class vouches for them
    /// and `apply` stars them.
    ///
    /// Reported here because they are real utility loss that the lattice search
    /// cannot see. A cleaning step that empties a QI column produces exactly
    /// this, and without the number the loss only becomes visible after the
    /// apply phase has already run.
    #[serde(default)]
    pub unplaceable_records: i64,
    /// `(suppressed + unplaceable) / rows_total` — what the user actually loses.
    #[serde(default)]
    pub effective_suppression_rate: f64,
}

/// The persisted global histogram, so pass 2 never re-reads raw data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramArtifact {
    pub schema_version: u32,
    pub job_id: String,
    pub qi_columns: Vec<String>,
    pub rows_total: i64,
    pub rows_valid: i64,
    pub numeric_bounds: BTreeMap<String, (f64, f64)>,
    pub categorical_domains: BTreeMap<String, Vec<String>>,
    pub hist: Vec<(Vec<String>, i64)>,
}

/// Recomputes the k x suppression_limit table from a persisted histogram.
///
/// This is the table the user chooses from between the measure and apply
/// phases, and it is a pure function of the histogram: no rows, no containers,
/// milliseconds. That is what makes it reasonable to let a user sit with the
/// numbers, change their mind, and ask for different axes — none of it costs
/// container time, and nothing is held open waiting for them.
pub fn grid_from_histogram(
    config_path: &Path,
    histogram_path: &Path,
    k_values: &[i64],
    supp_values: &[f64],
) -> Result<serde_json::Value, PipelineError> {
    let cfg = parse_runtime_config(config_path)?;
    let agg: HistogramArtifact = read_json(histogram_path)?;
    let qis = build_quasi_identifiers(&cfg, &agg.numeric_bounds)?;
    let cat_domains: Vec<Vec<String>> = qis
        .iter()
        .map(|q| {
            if q.is_categorical {
                agg.categorical_domains.get(&q.column_name).cloned().unwrap_or_default()
            } else {
                Vec::new()
            }
        })
        .collect();
    let (fine, total_records) = raw_hist_to_sparse(&agg, &qis, &agg.qi_columns, &cat_domains)?;
    let initial_ri = vec![1i64; qis.len()];

    let entries = compute_parameter_grid_over(
        &qis,
        &fine,
        &initial_ri,
        &cfg.size_factors,
        total_records,
        k_values,
        supp_values,
    );

    // The suppression count OLA-2 reports is in index space; what a user
    // actually loses is in label space. Recomputing per cell would mean one
    // merge per cell, so the reported count is left as the lattice's own and
    // labelled as such rather than quietly presented as the final figure.
    Ok(json!({
        "job_id": agg.job_id,
        "total_records": total_records,
        "k_values": k_values,
        "suppression_limits": supp_values,
        "cells": entries,
        "note": "suppression_count is the lattice search's own figure, in histogram index                  space. The published figure comes from the solve stage, which evaluates it                  over the generalized labels that actually get written.",
    }))
}

pub fn run(manifest: &BlockManifest) -> Result<BlockReport, PipelineError> {
    let stage = manifest.stage.as_deref().ok_or_else(|| {
        validation(
            "BLOCK_MANIFEST_INVALID",
            "The kanon block needs a 'stage'",
            "one of: scan, solve, apply",
        )
    })?;
    match stage {
        "scan" => run_scan(manifest),
        "solve" => run_solve(manifest),
        "apply" => run_apply(manifest),
        other => Err(validation(
            "BLOCK_MANIFEST_INVALID",
            "Unknown kanon stage",
            &format!("'{other}' — expected scan, solve or apply"),
        )),
    }
}

// ── Stage 1: scan ────────────────────────────────────────────────────────────

fn run_scan(manifest: &BlockManifest) -> Result<BlockReport, PipelineError> {
    let cfg = parse_runtime_config(&manifest.config)?;
    let shard = Shard::read(manifest.input_path()?, &manifest.row_id_column)?;

    let qi_cols = qi_column_names(&cfg);
    if qi_cols.is_empty() {
        return Err(validation(
            "ANON_NO_QIS",
            "No quasi-identifiers configured",
            "kanon scan needs quasi_identifiers in the job config",
        ));
    }

    // Every QI has to be in this shard. Column sharding routes the whole QI
    // group to one place precisely because a partial tuple is not a tuple.
    let idx: Vec<usize> = qi_cols
        .iter()
        .map(|c| {
            shard
                .column_index(c)
                .or_else(|| shard.column_index(&base_col_name(c)))
                .ok_or_else(|| {
                    validation(
                        "BLOCK_QI_SHARD_INCOMPLETE",
                        "A quasi-identifier column is missing from this shard",
                        &format!(
                            "'{c}' not found. k-anonymity is computed over the full QI tuple, so \
                             the orchestrator must route every QI column to the same shard — \
                             split k-anon work by rows, never by QI columns."
                        ),
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let is_cat: Vec<bool> = qi_cols
        .iter()
        .map(|c| cfg.categorical_qis.iter().any(|q| q == c))
        .collect();

    let mut hist: HashMap<Vec<String>, i64> = HashMap::new();
    let mut bounds: BTreeMap<String, (f64, f64)> = BTreeMap::new();
    let mut domains: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut rows_valid: i64 = 0;

    for row in &shard.rows {
        let mut key = Vec::with_capacity(qi_cols.len());
        let mut valid = true;
        for (i, &col_i) in idx.iter().enumerate() {
            let Some(raw) = row.get(col_i).map(|s| s.trim()) else {
                valid = false;
                break;
            };
            if is_cat[i] {
                domains.entry(qi_cols[i].clone()).or_default().insert(raw.to_string());
                key.push(raw.to_string());
            } else {
                let Ok(v) = raw.parse::<f64>() else {
                    valid = false;
                    break;
                };
                // Canonicalise to the rounded integer the downstream stages use,
                // so identical values from different shards collide on merge.
                let r = v.round() as i64;
                let e = bounds.entry(qi_cols[i].clone()).or_insert((v, v));
                e.0 = e.0.min(v);
                e.1 = e.1.max(v);
                key.push(r.to_string());
            }
        }
        if !valid {
            continue;
        }
        *hist.entry(key).or_insert(0) += 1;
        rows_valid += 1;
    }

    let scan = ShardScan {
        schema_version: super::BLOCK_SCHEMA_VERSION,
        job_id: manifest.job_id.clone(),
        shard_id: manifest.shard_id.clone(),
        qi_columns: qi_cols.clone(),
        rows_total: shard.rows.len() as i64,
        rows_valid,
        numeric_bounds: bounds,
        categorical_domains: domains
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect::<Vec<_>>()))
            .collect(),
        hist: {
            let mut v: Vec<(Vec<String>, i64)> = hist.into_iter().collect();
            v.sort_unstable();
            v
        },
    };

    let out = manifest
        .output
        .clone()
        .unwrap_or_else(|| manifest.artifacts_dir.join(format!("{}.scan.json", manifest.shard_id)));
    write_json(&out, &scan)?;

    Ok(BlockReport {
        job_id: manifest.job_id.clone(),
        shard_id: manifest.shard_id.clone(),
        block: "kanon".to_string(),
        stage: Some("scan".to_string()),
        applied: vec![format!("scan:{}", qi_cols.join("+"))],
        deferred: vec![],
        rows_in: scan.rows_total as usize,
        rows_out: scan.rows_valid as usize,
        output: Some(out.display().to_string()),
        artifacts: vec![out.display().to_string()],
        extra: Some(json!({
            "histogram_buckets": scan.hist.len(),
            "rows_dropped_invalid_qi": scan.rows_total - scan.rows_valid,
        })),
    })
}

// ── Stage 2: solve ───────────────────────────────────────────────────────────

fn run_solve(manifest: &BlockManifest) -> Result<BlockReport, PipelineError> {
    let cfg = parse_runtime_config(&manifest.config)?;
    let hist_path = manifest.artifacts_dir.join("histogram.json");

    // Pass 2 re-solves the histogram pass 1 already built. Re-reading raw rows
    // here would defeat the point of splitting the passes.
    let agg = if manifest.inputs.is_empty() {
        if !hist_path.exists() {
            return Err(validation(
                "BLOCK_HISTOGRAM_MISSING",
                "No scan artifacts and no persisted histogram to solve against",
                &format!(
                    "expected 'inputs' in the manifest, or a previous solve's {} — \
                     run the scan stage first",
                    hist_path.display()
                ),
            ));
        }
        read_json::<HistogramArtifact>(&hist_path)?
    } else {
        let agg = merge_scans(manifest, &manifest.inputs)?;
        write_json(&hist_path, &agg)?;
        agg
    };

    let qi_cols = agg.qi_columns.clone();
    let cfg_cols = qi_column_names(&cfg);
    if cfg_cols != qi_cols {
        return Err(validation(
            "BLOCK_HISTOGRAM_MISMATCH",
            "The persisted histogram was built for a different quasi-identifier set",
            &format!("histogram has {qi_cols:?}, config asks for {cfg_cols:?}"),
        ));
    }

    // Global column statistics, now that every shard has been folded in.
    let dynamic_min_max: BTreeMap<String, (f64, f64)> = agg.numeric_bounds.clone();
    let qis = build_quasi_identifiers(&cfg, &dynamic_min_max)?;
    let cat_domains: Vec<Vec<String>> = qis
        .iter()
        .map(|q| {
            if q.is_categorical {
                agg.categorical_domains.get(&q.column_name).cloned().unwrap_or_default()
            } else {
                Vec::new()
            }
        })
        .collect();

    // Fine-grained (ri = 1) index-space histogram, built from raw-value keys.
    let (fine, total_records) = raw_hist_to_sparse(&agg, &qis, &qi_cols, &cat_domains)?;

    // Flow choice mirrors the monolith's rule, but the decision is cheap here:
    // the histogram already exists, so ORIGINAL simply coarsens it instead of
    // re-reading the data at a coarser granularity.
    let e = compute_equivalence_space(&qis, &cat_domains);
    let n = total_records as f64;
    let n_log_n = n * n.log2().max(0.0);
    let use_direct = match cfg.flow_mode {
        FlowMode::Auto => n_log_n <= e,
        FlowMode::Original => false,
        FlowMode::Direct => true,
    };

    let (initial_ri, base) = if use_direct {
        (vec![1i64; qis.len()], fine.clone())
    } else {
        let max_eq = (available_ram_bytes().unwrap_or(32_000_000) / 32) as i64;
        let ri = find_ola1_initial_ri(&qis, 1, max_eq, &cfg.size_factors)?;
        let coarse = merge_histogram(&fine, &qis, &ri);
        (ri, coarse)
    };

    let parameter_grid = if cfg.compute_param_grid {
        compute_parameter_grid(&qis, &base, &initial_ri, &cfg.size_factors, total_records)
    } else {
        vec![]
    };

    let mut solution = Solution {
        schema_version: super::BLOCK_SCHEMA_VERSION,
        job_id: manifest.job_id.clone(),
        pass: cfg.pass.clone(),
        qi_columns: qi_cols.clone(),
        numeric_bounds: dynamic_min_max,
        categorical_domains: agg.categorical_domains.clone(),
        total_records,
        k: cfg.k,
        suppression_limit: cfg.suppression_limit,
        flow: if use_direct { "DIRECT" } else { "ORIGINAL" }.to_string(),
        initial_ri: initial_ri.clone(),
        final_rf: None,
        k_optimal: None,
        lowest_dm_star: None,
        num_equivalence_classes: None,
        equivalence_class_stats: BTreeMap::new(),
        parameter_grid,
        suppressed_classes: vec![],
        suppressed_records: 0,
        unplaceable_records: agg.rows_total - agg.rows_valid,
        effective_suppression_rate: 0.0,
    };

    let mut extra = json!({
        "histogram_buckets": base.len(),
        "equivalence_space": e,
        "n_log2_n": n_log_n,
        "histogram_artifact": hist_path.display().to_string(),
    });

    if cfg.pass == "pass1" {
        // Stop before the lattice search: the user has not chosen k yet. The
        // histogram is on disk, so the eventual pass-2 solve costs one reduce.
        solution.k_optimal =
            Some(compute_k_optimal(&qis, &base, cfg.suppression_limit, total_records));
    } else {
        if cfg.k <= 0 {
            return Err(validation(
                "CONFIG_MISSING_FIELD",
                "k must be set and > 0 for pass2 / no_bounds",
                "add \"k_anonymize\": {\"k\": <value>} to the job config",
            ));
        }
        let ola2 = find_ola2_best_rf_detailed(
            &qis,
            &base,
            &initial_ri,
            &cfg.size_factors,
            cfg.k,
            cfg.suppression_limit,
            total_records,
        )?;

        // Below-k classes, computed once over the global histogram and in the
        // same label space `apply` will write. This is the whole reason the
        // scan artifact keeps raw values: the published label for a row is a
        // function of its raw values, the global column statistics and the
        // chosen RF, none of which a bucket index preserves.
        //
        // The monolith does this count per chunk, which is invisible on one
        // chunk and wrong on many: a record whose class is globally far above
        // k gets starred because its own chunk happened to hold few members of
        // it. Counting here, once, makes the result identical no matter how the
        // orchestrator sharded the rows.
        let mut label_counts: BTreeMap<Vec<String>, i64> = BTreeMap::new();
        for (raw, count) in &agg.hist {
            if let Some(labels) = generalize_tuple(
                raw,
                &qis,
                &cat_domains,
                &cfg.categorical_hierarchies,
                &ola2.best_rf,
            ) {
                *label_counts.entry(labels).or_insert(0) += count;
            }
        }
        let mut suppressed_classes: Vec<Vec<String>> = Vec::new();
        let mut suppressed_records = 0i64;
        if cfg.k > 1 {
            for (key, count) in &label_counts {
                if *count < cfg.k {
                    suppressed_records += *count;
                    suppressed_classes.push(key.clone());
                }
            }
        }
        suppressed_classes.sort_unstable();

        solution.equivalence_class_stats =
            equivalence_class_stats(&fine, &qis, &ola2.best_rf, cfg.k);
        solution.lowest_dm_star = Some(ola2.lowest_dm_star);
        solution.num_equivalence_classes = Some(ola2.num_equivalence_classes);
        solution.suppressed_classes = suppressed_classes;
        solution.suppressed_records = suppressed_records;
        solution.final_rf = Some(ola2.best_rf.clone());

        extra["top_ola2_nodes"] = serde_json::to_value(&ola2.top_nodes).unwrap_or(json!([]));
        extra["node_trace"] = serde_json::to_value(&ola2.node_trace).unwrap_or(json!([]));
        solution.effective_suppression_rate = if agg.rows_total > 0 {
            (suppressed_records + solution.unplaceable_records) as f64 / agg.rows_total as f64
        } else {
            0.0
        };

        extra["published_equivalence_classes"] = json!(label_counts.len());
        extra["suppression_rate"] = json!(if total_records > 0 {
            suppressed_records as f64 / total_records as f64
        } else {
            0.0
        });
        extra["unplaceable_records"] = json!(solution.unplaceable_records);
        extra["effective_suppression_rate"] = json!(solution.effective_suppression_rate);

        // The lattice honours suppression_limit over the rows it can see. Rows
        // it never saw are loss too, and the two together are what the user
        // gets. Saying so here means the number arrives before the apply phase
        // runs rather than after.
        if solution.effective_suppression_rate > cfg.suppression_limit {
            extra["warning"] = json!(format!(
                "Effective suppression is {:.3}%, above the configured limit of {:.3}%. \
                 {} row(s) satisfy the lattice but {} more cannot be placed at all — a \
                 quasi-identifier is empty or out of range in those rows. Cleaning that \
                 empties a QI column is the usual cause; adding the QI columns to \
                 cleaning.required_columns drops those rows up front instead, so the \
                 row count the user is shown is the row count they get.",
                solution.effective_suppression_rate * 100.0,
                cfg.suppression_limit * 100.0,
                suppressed_records,
                solution.unplaceable_records,
            ));
        }
    }

    let out = manifest
        .output
        .clone()
        .unwrap_or_else(|| manifest.artifacts_dir.join("solution.json"));
    write_json(&out, &solution)?;

    Ok(BlockReport {
        job_id: manifest.job_id.clone(),
        shard_id: manifest.shard_id.clone(),
        block: "kanon".to_string(),
        stage: Some("solve".to_string()),
        applied: vec![format!("solve:{}", cfg.pass)],
        deferred: vec![],
        rows_in: total_records as usize,
        rows_out: total_records as usize,
        output: Some(out.display().to_string()),
        artifacts: vec![out.display().to_string(), hist_path.display().to_string()],
        extra: Some(extra),
    })
}

/// Folds every shard scan into one global aggregate.
///
/// Addition is the only reduction needed, which is exactly why `scan` keys on
/// raw values: bucket indices from two shards would not be comparable.
fn merge_scans(manifest: &BlockManifest, paths: &[PathBuf]) -> Result<HistogramArtifact, PipelineError> {
    let mut qi_columns: Option<Vec<String>> = None;
    let mut hist: HashMap<Vec<String>, i64> = HashMap::new();
    let mut bounds: BTreeMap<String, (f64, f64)> = BTreeMap::new();
    let mut domains: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut rows_total = 0i64;
    let mut rows_valid = 0i64;

    for p in paths {
        let s: ShardScan = read_json(p)?;
        match &qi_columns {
            None => qi_columns = Some(s.qi_columns.clone()),
            Some(existing) if *existing != s.qi_columns => {
                return Err(validation(
                    "BLOCK_SCAN_INCONSISTENT",
                    "Scan artifacts disagree on the quasi-identifier column order",
                    &format!("{existing:?} vs {:?} in {}", s.qi_columns, p.display()),
                ));
            }
            _ => {}
        }
        rows_total += s.rows_total;
        rows_valid += s.rows_valid;
        for (col, (lo, hi)) in s.numeric_bounds {
            let e = bounds.entry(col).or_insert((lo, hi));
            e.0 = e.0.min(lo);
            e.1 = e.1.max(hi);
        }
        for (col, vals) in s.categorical_domains {
            domains.entry(col).or_default().extend(vals);
        }
        for (key, count) in s.hist {
            *hist.entry(key).or_insert(0) += count;
        }
    }

    let qi_columns = qi_columns.ok_or_else(|| {
        validation("BLOCK_SCAN_INCONSISTENT", "No scan artifacts were provided", "inputs was empty")
    })?;
    if rows_valid == 0 {
        return Err(validation(
            "GENERALIZATION_FAILED",
            "No valid histogram records across all shards",
            "every row failed quasi-identifier parsing — check QI column names and types",
        ));
    }

    Ok(HistogramArtifact {
        schema_version: super::BLOCK_SCHEMA_VERSION,
        job_id: manifest.job_id.clone(),
        qi_columns,
        rows_total,
        rows_valid,
        numeric_bounds: bounds,
        // Sorted, so the domain index a value maps to is stable across runs —
        // `apply` derives the same index from the same solution file.
        categorical_domains: domains
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect::<Vec<_>>()))
            .collect(),
        hist: {
            let mut v: Vec<(Vec<String>, i64)> = hist.into_iter().collect();
            v.sort_unstable();
            v
        },
    })
}

/// Converts raw-value tuples into the finest-granularity index space OLA-2
/// expects, using the now-global minima and categorical domains.
fn raw_hist_to_sparse(
    agg: &HistogramArtifact,
    qis: &[QuasiIdentifierLite],
    qi_cols: &[String],
    cat_domains: &[Vec<String>],
) -> Result<(SparseHist, i64), PipelineError> {
    let mut out: SparseHist = HashMap::new();
    let mut total = 0i64;

    for (key, count) in &agg.hist {
        if key.len() != qis.len() {
            return Err(validation(
                "BLOCK_SCAN_INCONSISTENT",
                "A histogram key has the wrong arity",
                &format!("key {key:?} against {} quasi-identifiers", qis.len()),
            ));
        }
        let mut idx = Vec::with_capacity(qis.len());
        let mut valid = true;
        for (i, qi) in qis.iter().enumerate() {
            let raw = &key[i];
            if let Some(h) = &qi.interval_hierarchy {
                let Ok(v) = raw.parse::<f64>() else { valid = false; break };
                match h.value_to_fine_index(v.round() as i64) {
                    Some(fi) => idx.push(fi as i64),
                    None => { valid = false; break }
                }
            } else if qi.is_categorical {
                let Some(pos) = cat_domains[i].iter().position(|v| v == raw) else {
                    valid = false;
                    break;
                };
                idx.push(pos as i64);
            } else {
                let Ok(v) = raw.parse::<f64>() else { valid = false; break };
                let mn = qi.min_value.unwrap_or(0.0);
                idx.push((v - mn).floor().max(0.0) as i64);
            }
        }
        if !valid {
            // A value outside every configured interval is dropped here exactly
            // as the monolith drops it while building the histogram.
            continue;
        }
        *out.entry(idx).or_insert(0) += count;
        total += count;
    }

    if out.is_empty() || total <= 0 {
        return Err(validation(
            "GENERALIZATION_FAILED",
            "No valid histogram records produced",
            &format!(
                "none of the {} scanned value tuples fell inside the configured quasi-identifier \
                 ranges — check qi_constraints/fixed_bins against columns {qi_cols:?}",
                agg.hist.len()
            ),
        ));
    }
    Ok((out, total))
}

// ── Stage 3: apply ───────────────────────────────────────────────────────────

fn run_apply(manifest: &BlockManifest) -> Result<BlockReport, PipelineError> {
    let cfg = parse_runtime_config(&manifest.config)?;
    let sol_path = manifest
        .solution
        .clone()
        .unwrap_or_else(|| manifest.artifacts_dir.join("solution.json"));
    let solution: Solution = read_json(&sol_path)?;

    let final_rf = solution.final_rf.clone().ok_or_else(|| {
        validation(
            "BLOCK_SOLUTION_INCOMPLETE",
            "The solution has no final_rf — it came from a pass-1 solve",
            "run the solve stage again with pass=pass2 and a chosen k before applying",
        )
    })?;

    let qis = build_quasi_identifiers(&cfg, &solution.numeric_bounds)?;
    if qis.len() != final_rf.len() {
        return Err(validation(
            "BLOCK_SOLUTION_INCOMPLETE",
            "final_rf does not match the configured quasi-identifiers",
            &format!("{} factors for {} QIs", final_rf.len(), qis.len()),
        ));
    }
    let cat_domains: Vec<Vec<String>> = qis
        .iter()
        .map(|q| {
            if q.is_categorical {
                solution.categorical_domains.get(&q.column_name).cloned().unwrap_or_default()
            } else {
                Vec::new()
            }
        })
        .collect();

    let mut shard = Shard::read(manifest.input_path()?, &manifest.row_id_column)?;
    let rows_in = shard.rows.len();

    let col_idx: Vec<usize> = qis
        .iter()
        .map(|qi| {
            let name = if qi.is_categorical {
                qi.column_name.clone()
            } else {
                base_col_name(&qi.column_name)
            };
            shard.column_index(&name).or_else(|| shard.column_index(&qi.column_name)).ok_or_else(
                || {
                    validation(
                        "BLOCK_QI_SHARD_INCOMPLETE",
                        "A quasi-identifier column is missing from this shard",
                        &format!("'{name}' — kanon apply needs the whole QI tuple"),
                    )
                },
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    let suppressed: BTreeSet<Vec<String>> =
        solution.suppressed_classes.iter().cloned().collect();

    let mut suppressed_rows = 0usize;
    let mut suppressed_rids: Vec<String> = Vec::new();
    let mut unplaceable_rows = 0usize;

    for row in shard.rows.iter_mut() {
        // Generalize first, then decide. The class a row belongs to is defined
        // by the strings that will be published, so the lookup has to happen on
        // the generalized tuple rather than on anything derived from the raw
        // values — see `Solution::suppressed_classes`.
        let raw: Vec<String> = col_idx
            .iter()
            .map(|&ci| row.get(ci).cloned().unwrap_or_default())
            .collect();
        let labels = generalize_tuple(
            &raw,
            &qis,
            &cat_domains,
            &cfg.categorical_hierarchies,
            &final_rf,
        );

        // A row whose quasi-identifiers could not be placed never entered the
        // histogram, so nothing counted it and no class can vouch for it.
        // Star it rather than publish a value whose class size is unknown.
        let star = match &labels {
            None => {
                unplaceable_rows += 1;
                true
            }
            Some(l) => solution.k > 1 && suppressed.contains(l),
        };

        for (i, &ci) in col_idx.iter().enumerate() {
            if ci >= row.len() {
                continue;
            }
            row[ci] = if star {
                "*".to_string()
            } else {
                labels.as_ref().map(|l| l[i].clone()).unwrap_or_else(|| "*".to_string())
            };
        }

        if star {
            suppressed_rows += 1;
            if let Some(ri) = shard.rid_idx {
                if let Some(rid) = row.get(ri) {
                    suppressed_rids.push(rid.clone());
                }
            }
        }
    }

    let out = manifest.output_path();
    shard.write(&out)?;

    // The AO needs this if job policy says a starred record should also be
    // dropped or redacted in the column shards k-anon never saw.
    let mut artifacts = vec![out.display().to_string()];
    if !suppressed_rids.is_empty() {
        let rid_path = manifest
            .artifacts_dir
            .join(format!("{}.suppressed_rids.json", manifest.shard_id));
        write_json(
            &rid_path,
            &json!({
                "job_id": manifest.job_id,
                "shard_id": manifest.shard_id,
                "row_id_column": manifest.row_id_column,
                "suppressed_rids": suppressed_rids,
            }),
        )?;
        artifacts.push(rid_path.display().to_string());
    }

    Ok(BlockReport {
        job_id: manifest.job_id.clone(),
        shard_id: manifest.shard_id.clone(),
        block: "kanon".to_string(),
        stage: Some("apply".to_string()),
        applied: vec![format!("generalize:{}", solution.qi_columns.join("+"))],
        deferred: vec![],
        rows_in,
        rows_out: shard.rows.len(),
        output: Some(out.display().to_string()),
        artifacts,
        extra: Some(json!({
            "final_rf": final_rf,
            "k": solution.k,
            "rows_suppressed": suppressed_rows,
            "rows_unplaceable_qi": unplaceable_rows,
        })),
    })
}

/// Generalizes one quasi-identifier tuple to the strings that will be
/// published, at factors `rf`.
///
/// Returns `None` when any value cannot be placed — unparsable as a number,
/// outside every configured interval, or absent from the categorical domain.
/// Those are exactly the conditions under which the scan stage dropped a row
/// from the histogram, so `None` here and "not counted there" mean the same
/// thing, which is what lets `apply` trust a hit in `suppressed_classes` and
/// distrust a miss.
///
/// `solve` and `apply` both go through this one function. They have to agree
/// character for character: `solve` writes label tuples into the solution and
/// `apply` looks them up, so any divergence would silently stop suppressing.
fn generalize_tuple(
    raw: &[String],
    qis: &[QuasiIdentifierLite],
    cat_domains: &[Vec<String>],
    hierarchies: &HierarchyMap,
    rf: &[i64],
) -> Option<Vec<String>> {
    let mut out = Vec::with_capacity(qis.len());
    for (i, qi) in qis.iter().enumerate() {
        let v = raw.get(i)?.trim();
        let label = if let Some(h) = &qi.interval_hierarchy {
            let fine = h.value_to_fine_index(v.parse::<f64>().ok()?.round() as i64)?;
            let level = (rf[i] as usize).clamp(1, h.num_levels);
            let coarse = h.ancestor_at.get(fine).and_then(|a| a.get(level)).copied()?;
            h.label(level, coarse)
        } else if qi.is_categorical {
            // Presence in the domain is the validity test; the published label
            // then comes from the hierarchy, exactly as the monolith writes it.
            cat_domains[i].iter().position(|d| d == v)?;
            generalize_categorical_value(hierarchies, &qi.column_name, v, rf[i])
        } else {
            let parsed = v.parse::<f64>().ok()?;
            let min = qi.min_value.unwrap_or(0.0).floor() as i64;
            generalize_numeric_label(parsed.round() as i64, min, rf[i].max(1))
        };
        out.push(label);
    }
    Some(out)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// QI column order, numerical first then categorical — the order
/// `build_quasi_identifiers` produces, which every index tuple depends on.
fn qi_column_names(cfg: &RuntimeConfig) -> Vec<String> {
    let mut v: Vec<String> = cfg.numerical_qis.iter().map(|q| q.column.clone()).collect();
    v.extend(cfg.categorical_qis.iter().cloned());
    v
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), PipelineError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(value)?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, body)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, PipelineError> {
    let raw = fs::read_to_string(path).map_err(|e| {
        validation(
            "IO_READ_FAILED",
            "Could not read a kanon artifact",
            &format!("{}: {e}", path.display()),
        )
    })?;
    serde_json::from_str(&raw).map_err(|e| {
        validation(
            "BLOCK_ARTIFACT_INVALID",
            "A kanon artifact is not in the expected shape",
            &format!("{}: {e}", path.display()),
        )
    })
}
