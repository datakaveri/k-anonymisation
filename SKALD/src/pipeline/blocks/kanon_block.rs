//! Block 3 — k-anonymization, split into `scan` → `solve` → `apply`.
//!
//! k-anonymity is the one thing in SKALD that cannot be column sharded: the
//! guarantee is a property of the *whole* quasi-identifier tuple over the
//! *whole* dataset, so every QI column has to arrive at the same place, and
//! every row has to be counted. What it *can* be is row sharded:
//!
//! ```text
//!   scan   (map,    per row shard)  → partial histogram of QI tuples
//!   solve  (reduce, exactly once)   → OLA-1 → OLA-2 → the class decision
//!   apply  (map,    per row shard)  → published labels, `*`, or removed
//! ```
//!
//! ## The same release as the monolith
//!
//! `scan` reads every cell exactly as the monolith does (`parse_numeric_qi`,
//! `normalize_categorical`) and keys its histogram on those canonical values.
//! Canonical values are shard-independent, so partial scans merge by addition,
//! and `solve` then runs the monolith's own steps over the merged tuples:
//! the base histogram, OLA-1, OLA-2 (l-aware when `l_diversity` is set), and
//! the class decision of the output step — classes that fail k (or l) go to
//! the `*` class, which is published only if it would itself pass and is
//! otherwise removed. `suppression_limit` is checked against what will be
//! written, before any row is touched. `apply` writes each row's label through
//! the monolith's `generalize_cell` and looks the label tuple up in the
//! solved classes. A tuple `solve` never counted is an error, not a guess.
//!
//! ## The two-pass flow
//!
//! `solve` persists the merged histogram as `histogram.json`, so pass 2 is a
//! re-solve over that aggregate with no scan and no access to the raw data.
//! The histogram holds un-generalised quasi-identifier tuples (and the
//! sensitive values l-diversity needs): it stays on the orchestrator, inside
//! the TEE, and is written owner-only. It is never released.
//!
//! ## Removed rows
//!
//! Only `apply` drops rows, and only the suppressed records the class decision
//! removed. It lists every dropped row id in `<shard>.removed_rids.json`; the
//! stitch drops those rows from every column shard, so a removed record cannot
//! survive through a column that k-anonymity never saw.

use super::{BlockManifest, BlockReport, Shard};
use crate::pipeline::anonymization::{
    ClassTally, GRID_K_VALUES, GRID_SUPPRESSION_LIMITS, LDiversity, ParameterGrid, QuasiIdentifierLite, SensitiveSets,
    SparseHist, allowed_suppressions, attach_categorical_levels, build_quasi_identifiers, build_tuple_histogram,
    build_tuple_sensitive_sets, compute_equivalence_space, compute_k_optimal, compute_parameter_grid_for,
    compute_z_weights, decide_classes, find_ola1_initial_ri, find_ola2_with, generalize_cell, l_aware_class_sizes,
    merge_histogram, normalize_categorical, parse_numeric_qi,
};
use crate::pipeline::bootstrap::{
    FlowMode, PipelineError, RuntimeConfig, available_ram_bytes, parse_runtime_config, validation,
};
use crate::pipeline::preprocess::crypto::write_secret_file;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

/// One distinct quasi-identifier tuple and the records that hold it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TupleCount {
    /// Canonical QI values, in QI order: a numeric QI as its rounded integer
    /// (empty when the cell has no usable number), a categorical QI trimmed
    /// and NFC-normalised.
    pub qi: Vec<String>,
    pub count: i64,
    /// Per l-diversity sensitive attribute, the distinct normalised values
    /// these records hold, capped at `l`. Empty without l-diversity.
    #[serde(default)]
    pub sensitive: Vec<Vec<String>>,
}

/// A `scan` artifact: one row shard's contribution to the global histogram.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardScan {
    pub schema_version: u32,
    pub job_id: String,
    pub shard_id: String,
    pub qi_columns: Vec<String>,
    pub sensitive_columns: Vec<String>,
    pub l: usize,
    pub rows_total: i64,
    /// Numeric QI column → (min, max) of its parseable values in this shard.
    pub numeric_bounds: BTreeMap<String, (i64, i64)>,
    /// Categorical QI column → the distinct values this shard holds.
    pub categorical_domains: BTreeMap<String, Vec<String>>,
    pub hist: Vec<TupleCount>,
}

/// The persisted global histogram, so pass 2 never re-reads raw data.
///
/// Holds raw (canonicalised) quasi-identifier tuples: key-material-grade
/// sensitivity, kept on the orchestrator and written owner-only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramArtifact {
    pub schema_version: u32,
    pub job_id: String,
    pub qi_columns: Vec<String>,
    pub sensitive_columns: Vec<String>,
    pub l: usize,
    pub rows_total: i64,
    pub numeric_bounds: BTreeMap<String, (i64, i64)>,
    pub categorical_domains: BTreeMap<String, Vec<String>>,
    pub hist: Vec<TupleCount>,
}

/// A `solve` artifact: everything `apply` needs and the run summary, and no
/// raw data — only column bounds, the chosen node and the published label
/// tuples, which are what the release contains anyway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Solution {
    pub schema_version: u32,
    pub job_id: String,
    pub pass: String,
    pub qi_columns: Vec<String>,
    pub sensitive_columns: Vec<String>,
    pub l: usize,
    pub k: i64,
    pub suppression_limit: f64,
    pub numeric_bounds: BTreeMap<String, (i64, i64)>,
    pub total_records: i64,
    pub flow: String,
    pub initial_ri: Vec<i64>,
    /// `None` after a pass-1 solve, which stops before the lattice search.
    pub final_rf: Option<Vec<i64>>,
    #[serde(default)]
    pub k_optimal: Option<i64>,
    #[serde(default)]
    pub parameter_grid: Value,
    /// Published label tuples (QI order): classes that pass k (and l).
    #[serde(default)]
    pub passing_classes: Vec<Vec<String>>,
    /// Label tuples of classes that fail k (or l): their rows are written as
    /// `*`, or removed when `publish_suppressed` is false.
    #[serde(default)]
    pub failing_classes: Vec<Vec<String>>,
    #[serde(default)]
    pub publish_suppressed: bool,
    /// The run summary, measured over the classes `apply` will write — the
    /// same object the monolith reports as `anonymisation_summary`.
    #[serde(default)]
    pub anonymisation_summary: Value,
}

/// Recomputes the k × suppression_limit table from a persisted histogram.
///
/// A pure function of the histogram — no rows, no containers — so the UI can
/// ask for different axes as often as it likes. It searches the same lattice,
/// with the same l-awareness, as a pass-1 solve.
pub fn grid_from_histogram(
    config_path: &Path,
    histogram_path: &Path,
    k_values: &[i64],
    supp_values: &[f64],
) -> Result<Value, PipelineError> {
    let cfg = parse_runtime_config(config_path)?;
    let agg: HistogramArtifact = read_json(histogram_path)?;
    check_histogram_matches(&agg, &cfg)?;
    let p = prepare(&cfg, &agg)?;
    let grid = grid_over(&cfg, &p, k_values, supp_values)?;
    Ok(json!({
        "job_id": agg.job_id,
        "total_records": p.total,
        "k_values": k_values,
        "suppression_limits": supp_values,
        "cells": grid.entries,
        "lattice_size": grid.lattice_size,
        "nodes_merged": grid.nodes_merged,
    }))
}

pub fn run(manifest: &BlockManifest) -> Result<BlockReport, PipelineError> {
    let stage = manifest.stage.as_deref().ok_or_else(|| {
        validation("BLOCK_MANIFEST_INVALID", "The kanon block needs a 'stage'", "one of: scan, solve, apply")
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
        return Err(validation("ANON_NO_QIS", "No quasi-identifiers configured", "kanon scan needs quasi_identifiers"));
    }
    let (sens_cols, l) = sensitive(&cfg);

    // Every QI has to be in this shard. A partial tuple is not a tuple.
    let qi_idx = columns_in_shard(&shard, &qi_cols, "quasi-identifier")?;
    let sens_idx = columns_in_shard(&shard, &sens_cols, "l_diversity sensitive attribute")?;
    let is_cat: Vec<bool> = qi_cols.iter().map(|c| cfg.categorical_qis.contains(c)).collect();

    let mut hist: BTreeMap<Vec<String>, (i64, Vec<Vec<String>>)> = BTreeMap::new();
    let mut bounds: BTreeMap<String, (i64, i64)> = BTreeMap::new();
    let mut domains: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for row in &shard.rows {
        let mut key = Vec::with_capacity(qi_cols.len());
        for (i, &ci) in qi_idx.iter().enumerate() {
            if is_cat[i] {
                let v = normalize_categorical(&row[ci]);
                domains.entry(qi_cols[i].clone()).or_default().insert(v.clone());
                key.push(v);
            } else {
                match parse_numeric_qi(&row[ci]) {
                    Some(v) => {
                        let b = bounds.entry(qi_cols[i].clone()).or_insert((v, v));
                        b.0 = b.0.min(v);
                        b.1 = b.1.max(v);
                        key.push(v.to_string());
                    }
                    // No usable number: the monolith gives this cell no bin and
                    // writes `*`; the empty canonical value does the same.
                    None => key.push(String::new()),
                }
            }
        }
        let entry = hist.entry(key).or_insert_with(|| (0, vec![Vec::new(); sens_cols.len()]));
        entry.0 += 1;
        for (a, &si) in sens_idx.iter().enumerate() {
            add_capped(&mut entry.1[a], normalize_categorical(&row[si]), l);
        }
    }

    let scan = ShardScan {
        schema_version: super::BLOCK_SCHEMA_VERSION,
        job_id: manifest.job_id.clone(),
        shard_id: manifest.shard_id.clone(),
        qi_columns: qi_cols.clone(),
        sensitive_columns: sens_cols,
        l,
        rows_total: shard.rows.len() as i64,
        numeric_bounds: bounds,
        categorical_domains: domains.into_iter().map(|(k, v)| (k, v.into_iter().collect())).collect(),
        hist: hist.into_iter().map(|(qi, (count, sensitive))| TupleCount { qi, count, sensitive }).collect(),
    };

    let out = manifest
        .output
        .clone()
        .unwrap_or_else(|| manifest.artifacts_dir.join(format!("{}.scan.json", manifest.shard_id)));
    // Raw QI tuples: owner-only, like the persisted histogram.
    write_secret_json(&out, &scan)?;

    Ok(BlockReport {
        job_id: manifest.job_id.clone(),
        shard_id: manifest.shard_id.clone(),
        block: "kanon".to_string(),
        stage: Some("scan".to_string()),
        applied: vec![format!("scan:{}", qi_cols.join("+"))],
        deferred: vec![],
        rows_in: scan.rows_total as usize,
        rows_out: scan.rows_total as usize,
        output: Some(out.display().to_string()),
        artifacts: vec![out.display().to_string()],
        extra: Some(json!({ "histogram_buckets": scan.hist.len() })),
    })
}

// ── Stage 2: solve ───────────────────────────────────────────────────────────

/// Everything the lattice search needs, derived from the merged histogram the
/// way the monolith derives it from chunk files.
struct Prepared {
    qis: Vec<QuasiIdentifierLite>,
    initial_ri: Vec<i64>,
    base: SparseHist,
    sensitive: Option<SensitiveSets>,
    total: i64,
    flow: &'static str,
    equivalence_space: f64,
    n_log2_n: f64,
}

fn prepare(cfg: &RuntimeConfig, agg: &HistogramArtifact) -> Result<Prepared, PipelineError> {
    let min_max: BTreeMap<String, (f64, f64)> = cfg
        .numerical_qis
        .iter()
        .map(|q| {
            let (mn, mx) = agg.numeric_bounds.get(&q.column).copied().unwrap_or((0, 0));
            (q.column.clone(), (mn as f64, mx as f64))
        })
        .collect();
    let mut qis = build_quasi_identifiers(cfg, &min_max)?;
    let domains: Vec<Vec<String>> = qis
        .iter()
        .map(|q| {
            if q.is_categorical {
                agg.categorical_domains.get(&q.column_name).cloned().unwrap_or_default()
            } else {
                vec![]
            }
        })
        .collect();
    attach_categorical_levels(&mut qis, &domains, &cfg.categorical_hierarchies)?;

    // The monolith's flow rule. DIRECT and ORIGINAL differ only in the initial
    // coarsening; the Z encoding the monolith uses for DIRECT is a memory
    // layout of the same histogram, so it is not needed here.
    let n = agg.rows_total as f64;
    let n_log2_n = n * n.log2().max(0.0);
    let equivalence_space = compute_equivalence_space(&qis, &domains);
    let use_direct = match cfg.flow_mode {
        FlowMode::Auto => n_log2_n <= equivalence_space,
        FlowMode::Original => false,
        FlowMode::Direct => true,
    } && compute_z_weights(&qis, &domains).is_some();
    let initial_ri = if use_direct {
        vec![1i64; qis.len()]
    } else {
        let max_eq = (available_ram_bytes().unwrap_or(32_000_000) / 32) as i64;
        find_ola1_initial_ri(&qis, 1, max_eq, &cfg.size_factors)?
    };

    let (base, total) =
        build_tuple_histogram(agg.hist.iter().map(|t| (t.qi.as_slice(), t.count)), &qis, &initial_ri, &domains)?;
    if total != agg.rows_total {
        return Err(validation(
            "BLOCK_SCAN_INCONSISTENT",
            "The histogram's tuple counts do not add up to its row count",
            &format!("{total} counted, {} scanned", agg.rows_total),
        ));
    }
    let sensitive = match &cfg.l_diversity {
        Some(l) => Some(build_tuple_sensitive_sets(
            agg.hist.iter().map(|t| (t.qi.as_slice(), t.sensitive.as_slice())),
            &qis,
            &initial_ri,
            &domains,
            l.sensitive_attributes.len(),
            l.l,
        )?),
        None => None,
    };
    Ok(Prepared {
        qis,
        initial_ri,
        base,
        sensitive,
        total,
        flow: if use_direct { "DIRECT" } else { "ORIGINAL" },
        equivalence_space,
        n_log2_n,
    })
}

/// Class sizes at a lattice node, l-aware when l-diversity is configured —
/// exactly what the monolith's OLA-2 and parameter grid score.
fn class_sizes_at<'a>(cfg: &'a RuntimeConfig, p: &'a Prepared) -> impl FnMut(&[i64]) -> Vec<i64> + 'a {
    move |node: &[i64]| match (&p.sensitive, &cfg.l_diversity) {
        (Some(sens), Some(l)) => l_aware_class_sizes(&p.base, sens, &p.qis, node, l.l),
        _ => merge_histogram(&p.base, &p.qis, node).into_values().collect(),
    }
}

fn grid_over(cfg: &RuntimeConfig, p: &Prepared, ks: &[i64], sigmas: &[f64]) -> Result<ParameterGrid, PipelineError> {
    compute_parameter_grid_for(&p.qis, &p.initial_ri, &cfg.size_factors, p.total, ks, sigmas, class_sizes_at(cfg, p))
}

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
                    "expected 'inputs' in the manifest, or a previous solve's {} — run the scan stage first",
                    hist_path.display()
                ),
            ));
        }
        read_json::<HistogramArtifact>(&hist_path)?
    } else {
        let agg = merge_scans(manifest, &manifest.inputs)?;
        write_secret_json(&hist_path, &agg)?;
        agg
    };
    check_histogram_matches(&agg, &cfg)?;
    let p = prepare(&cfg, &agg)?;
    let (sens_cols, l) = sensitive(&cfg);

    let mut solution = Solution {
        schema_version: super::BLOCK_SCHEMA_VERSION,
        job_id: manifest.job_id.clone(),
        pass: cfg.pass.clone(),
        qi_columns: agg.qi_columns.clone(),
        sensitive_columns: sens_cols,
        l,
        k: cfg.k,
        suppression_limit: cfg.suppression_limit,
        numeric_bounds: agg.numeric_bounds.clone(),
        total_records: p.total,
        flow: p.flow.to_string(),
        initial_ri: p.initial_ri.clone(),
        final_rf: None,
        k_optimal: None,
        parameter_grid: Value::Array(vec![]),
        passing_classes: vec![],
        failing_classes: vec![],
        publish_suppressed: true,
        anonymisation_summary: Value::Null,
    };
    let mut extra = json!({
        "histogram_buckets": p.base.len(),
        "equivalence_space": p.equivalence_space,
        "n_log2_n": p.n_log2_n,
        "flow": p.flow,
    });

    // Pass 2 is run after the user has picked from pass 1's grid, so — as in
    // the monolith — the grid is a pass1 / no_bounds output only.
    if cfg.pass != "pass2" && cfg.compute_param_grid {
        let grid = grid_over(&cfg, &p, GRID_K_VALUES, GRID_SUPPRESSION_LIMITS)?;
        solution.parameter_grid = serde_json::to_value(&grid.entries)?;
    }

    if cfg.pass == "pass1" {
        // Stop before the lattice search: the user has not chosen k yet.
        solution.k_optimal = Some(compute_k_optimal(&p.qis, &p.base, cfg.suppression_limit, p.total));
    } else {
        if cfg.k <= 0 {
            return Err(validation(
                "CONFIG_MISSING_FIELD",
                "k must be set and > 0 for pass2 / no_bounds",
                "add \"k_anonymize\": {\"k\": <value>} to the job config",
            ));
        }
        let final_rf = match (&cfg.generalization_node, cfg.pass.as_str()) {
            // A node chosen from the pass-1 grid: the grid already measured it,
            // so the search is skipped, and the class decision below still
            // checks it against suppression_limit — catching a stale node.
            (Some(chosen), "pass2") => {
                extra["generalization_node"] = json!(chosen);
                crate::pipeline::pipeline::resolve_generalization_node(chosen, &p.qis, &cfg)?
            }
            _ => {
                let ola2 = find_ola2_with(
                    &p.qis,
                    &p.initial_ri,
                    &cfg.size_factors,
                    cfg.k,
                    cfg.suppression_limit,
                    p.total,
                    class_sizes_at(&cfg, &p),
                )?;
                extra["lattice_size"] = json!(ola2.lattice_size);
                extra["nodes_evaluated"] = json!(ola2.node_trace.len());
                extra["top_ola2_nodes"] = serde_json::to_value(&ola2.top_nodes)?;
                ola2.best_rf
            }
        };
        decide(&cfg, &p, &agg, &final_rf, &mut solution)?;
        solution.final_rf = Some(final_rf);
        extra["anonymisation_summary"] = solution.anonymisation_summary.clone();
    }

    let out = manifest.output.clone().unwrap_or_else(|| manifest.artifacts_dir.join("solution.json"));
    write_json(&out, &solution)?;

    Ok(BlockReport {
        job_id: manifest.job_id.clone(),
        shard_id: manifest.shard_id.clone(),
        block: "kanon".to_string(),
        stage: Some("solve".to_string()),
        applied: vec![format!("solve:{}", cfg.pass)],
        deferred: vec![],
        rows_in: p.total as usize,
        rows_out: p.total as usize,
        output: Some(out.display().to_string()),
        artifacts: vec![out.display().to_string(), hist_path.display().to_string()],
        extra: Some(extra),
    })
}

/// The output step's class decision, made over the merged histogram before
/// any row is written: label every tuple at `final_rf`, count classes (and
/// sensitive values) globally, and decide which classes publish, which go to
/// `*`, and whether the `*` class is published or removed. Then hold what
/// will be written to `suppression_limit`.
fn decide(
    cfg: &RuntimeConfig,
    p: &Prepared,
    agg: &HistogramArtifact,
    final_rf: &[i64],
    solution: &mut Solution,
) -> Result<(), PipelineError> {
    let l = cfg.l_diversity.as_ref();
    let l_cap = l.map_or(0, |l| l.l);
    let mut classes: BTreeMap<Vec<String>, ClassTally> = BTreeMap::new();
    for t in &agg.hist {
        let labels = label_tuple(&p.qis, &t.qi, final_rf, cfg);
        classes.entry(labels).or_default().add_group(t.count, &t.sensitive, l_cap);
    }
    let (summary, publish_suppressed) = decide_classes(&classes, p.total, cfg.k, l);

    let allowed = allowed_suppressions(cfg.suppression_limit, summary.total_records);
    if summary.suppressed_records > allowed {
        return Err(validation(
            "SUPPRESSION_LIMIT_EXCEEDED",
            "The written output would exceed suppression_limit on this data",
            &format!(
                "{} of {} records suppressed at {:?}; suppression_limit {} allows {}",
                summary.suppressed_records, summary.total_records, final_rf, cfg.suppression_limit, allowed
            ),
        ));
    }

    for (labels, tally) in classes {
        if tally.passes(cfg.k, l) {
            solution.passing_classes.push(labels);
        } else {
            solution.failing_classes.push(labels);
        }
    }
    solution.publish_suppressed = publish_suppressed;
    solution.anonymisation_summary = crate::pipeline::pipeline::summary_json(cfg, &summary);
    Ok(())
}

/// Folds every shard scan into one global aggregate.
fn merge_scans(manifest: &BlockManifest, paths: &[PathBuf]) -> Result<HistogramArtifact, PipelineError> {
    let mut first: Option<ShardScan> = None;
    let mut hist: BTreeMap<Vec<String>, (i64, Vec<Vec<String>>)> = BTreeMap::new();
    let mut bounds: BTreeMap<String, (i64, i64)> = BTreeMap::new();
    let mut domains: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut rows_total = 0i64;

    for path in paths {
        let s: ShardScan = read_json(path)?;
        if s.schema_version != super::BLOCK_SCHEMA_VERSION {
            return Err(validation(
                "BLOCK_SCHEMA_MISMATCH",
                "A scan artifact comes from a different block schema",
                &path.display().to_string(),
            ));
        }
        if let Some(f) = &first
            && (f.qi_columns != s.qi_columns || f.sensitive_columns != s.sensitive_columns || f.l != s.l)
        {
            return Err(validation(
                "BLOCK_SCAN_INCONSISTENT",
                "Scan artifacts disagree on the quasi-identifiers, sensitive attributes or l",
                &path.display().to_string(),
            ));
        }
        rows_total += s.rows_total;
        for (col, (lo, hi)) in &s.numeric_bounds {
            let b = bounds.entry(col.clone()).or_insert((*lo, *hi));
            b.0 = b.0.min(*lo);
            b.1 = b.1.max(*hi);
        }
        for (col, vals) in &s.categorical_domains {
            domains.entry(col.clone()).or_default().extend(vals.iter().cloned());
        }
        for t in &s.hist {
            let entry = hist.entry(t.qi.clone()).or_insert_with(|| (0, vec![Vec::new(); s.sensitive_columns.len()]));
            entry.0 += t.count;
            for (a, vals) in t.sensitive.iter().enumerate() {
                for v in vals {
                    if let Some(dst) = entry.1.get_mut(a) {
                        add_capped(dst, v.clone(), s.l);
                    }
                }
            }
        }
        if first.is_none() {
            first = Some(ShardScan { hist: vec![], ..s });
        }
    }

    let first = first
        .ok_or_else(|| validation("BLOCK_SCAN_INCONSISTENT", "No scan artifacts were provided", "inputs was empty"))?;
    if rows_total == 0 {
        return Err(validation("GENERALIZATION_FAILED", "No records to anonymize", "every scanned shard was empty"));
    }
    Ok(HistogramArtifact {
        schema_version: super::BLOCK_SCHEMA_VERSION,
        job_id: manifest.job_id.clone(),
        qi_columns: first.qi_columns,
        sensitive_columns: first.sensitive_columns,
        l: first.l,
        rows_total,
        numeric_bounds: bounds,
        // Sorted, as the monolith's domain scan is: a value's domain position
        // must not depend on which shard saw it first.
        categorical_domains: domains.into_iter().map(|(k, v)| (k, v.into_iter().collect())).collect(),
        hist: hist.into_iter().map(|(qi, (count, sensitive))| TupleCount { qi, count, sensitive }).collect(),
    })
}

// ── Stage 3: apply ───────────────────────────────────────────────────────────

fn run_apply(manifest: &BlockManifest) -> Result<BlockReport, PipelineError> {
    let cfg = parse_runtime_config(&manifest.config)?;
    let sol_path = manifest.solution.clone().unwrap_or_else(|| manifest.artifacts_dir.join("solution.json"));
    let solution: Solution = read_json(&sol_path)?;

    let final_rf = solution.final_rf.clone().ok_or_else(|| {
        validation(
            "BLOCK_SOLUTION_INCOMPLETE",
            "The solution has no final_rf — it came from a pass-1 solve",
            "run the solve stage again with pass=pass2 and a chosen k before applying",
        )
    })?;
    let (sens_cols, l) = sensitive(&cfg);
    if solution.schema_version != super::BLOCK_SCHEMA_VERSION
        || solution.qi_columns != qi_column_names(&cfg)
        || solution.k != cfg.k
        || solution.l != l
        || solution.sensitive_columns != sens_cols
        || solution.suppression_limit != cfg.suppression_limit
    {
        return Err(validation(
            "BLOCK_SOLUTION_MISMATCH",
            "The solution was computed for a different config",
            "re-run solve with this job's config before applying",
        ));
    }

    let min_max: BTreeMap<String, (f64, f64)> = cfg
        .numerical_qis
        .iter()
        .map(|q| {
            let (mn, mx) = solution.numeric_bounds.get(&q.column).copied().unwrap_or((0, 0));
            (q.column.clone(), (mn as f64, mx as f64))
        })
        .collect();
    let qis = build_quasi_identifiers(&cfg, &min_max)?;
    if qis.len() != final_rf.len() {
        return Err(validation(
            "BLOCK_SOLUTION_INCOMPLETE",
            "final_rf does not match the configured quasi-identifiers",
            &format!("{} factors for {} QIs", final_rf.len(), qis.len()),
        ));
    }

    let shard = Shard::read(manifest.input_path()?, &manifest.row_id_column)?;
    let rows_in = shard.rows.len();
    let rid_idx = shard.rid_idx.ok_or_else(|| {
        validation(
            "BLOCK_RID_PROTECTED",
            "kanon apply needs the row-id column",
            &format!("'{}' — rows it removes are reported by row id", manifest.row_id_column),
        )
    })?;
    let qi_idx = columns_in_shard(&shard, &solution.qi_columns, "quasi-identifier")?;

    let passing: HashSet<&Vec<String>> = solution.passing_classes.iter().collect();
    let failing: HashSet<&Vec<String>> = solution.failing_classes.iter().collect();

    // Only the row id and the QI columns go back: every other column is the
    // business of the block that transformed it, and returning it here would
    // let a stale copy overwrite that block's output at the stitch.
    let mut out_headers = vec![manifest.row_id_column.clone()];
    out_headers.extend(solution.qi_columns.iter().cloned());
    let mut out = Shard { headers: out_headers, rows: Vec::with_capacity(rows_in), rid_idx: Some(0) };
    let mut removed: Vec<String> = Vec::new();
    let mut starred = 0usize;

    for row in &shard.rows {
        let raw: Vec<String> = qi_idx.iter().map(|&i| row[i].clone()).collect();
        let labels = label_tuple(&qis, &raw, &final_rf, &cfg);
        let written = if passing.contains(&labels) {
            labels
        } else if failing.contains(&labels) {
            if !solution.publish_suppressed {
                removed.push(row[rid_idx].clone());
                continue;
            }
            starred += 1;
            vec!["*".to_string(); labels.len()]
        } else {
            return Err(validation(
                "BLOCK_SOLUTION_MISMATCH",
                "A row falls in a class the solve stage never counted",
                &format!(
                    "row id {} — this shard is not part of the data the solution was computed from; \
                     re-run scan and solve over every shard",
                    row[rid_idx]
                ),
            ));
        };
        let mut r = Vec::with_capacity(written.len() + 1);
        r.push(row[rid_idx].clone());
        r.extend(written);
        out.rows.push(r);
    }

    let out_path = manifest.output_path();
    out.write(&out_path)?;

    // Always written, empty or not, so the AO can hand every apply shard's
    // list to the stitch without checking which ones exist.
    let rid_path = manifest.artifacts_dir.join(format!("{}.removed_rids.json", manifest.shard_id));
    write_json(
        &rid_path,
        &json!({
            "job_id": manifest.job_id,
            "shard_id": manifest.shard_id,
            "row_id_column": manifest.row_id_column,
            "removed_rids": removed,
        }),
    )?;

    Ok(BlockReport {
        job_id: manifest.job_id.clone(),
        shard_id: manifest.shard_id.clone(),
        block: "kanon".to_string(),
        stage: Some("apply".to_string()),
        applied: vec![format!("generalize:{}", solution.qi_columns.join("+"))],
        deferred: vec![],
        rows_in,
        rows_out: out.rows.len(),
        output: Some(out_path.display().to_string()),
        artifacts: vec![out_path.display().to_string(), rid_path.display().to_string()],
        extra: Some(json!({
            "final_rf": final_rf,
            "k": solution.k,
            "rows_published_as_star": starred,
            "rows_removed": removed.len(),
        })),
    })
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// The published label of each QI cell at `rf` — the monolith's own writer.
fn label_tuple(qis: &[QuasiIdentifierLite], raw: &[String], rf: &[i64], cfg: &RuntimeConfig) -> Vec<String> {
    qis.iter().enumerate().map(|(i, qi)| generalize_cell(qi, &raw[i], rf[i], &cfg.categorical_hierarchies)).collect()
}

/// QI column order, numerical first then categorical — the order
/// `build_quasi_identifiers` produces, which every index tuple depends on.
fn qi_column_names(cfg: &RuntimeConfig) -> Vec<String> {
    let mut v: Vec<String> = cfg.numerical_qis.iter().map(|q| q.column.clone()).collect();
    v.extend(cfg.categorical_qis.iter().cloned());
    v
}

/// The l-diversity sensitive attributes and l (empty and 0 without it).
fn sensitive(cfg: &RuntimeConfig) -> (Vec<String>, usize) {
    cfg.l_diversity.as_ref().map(|l: &LDiversity| (l.sensitive_attributes.clone(), l.l)).unwrap_or_default()
}

fn check_histogram_matches(agg: &HistogramArtifact, cfg: &RuntimeConfig) -> Result<(), PipelineError> {
    let (sens_cols, l) = sensitive(cfg);
    if agg.qi_columns != qi_column_names(cfg) || agg.sensitive_columns != sens_cols || agg.l != l {
        return Err(validation(
            "BLOCK_HISTOGRAM_MISMATCH",
            "The histogram was built for different quasi-identifiers, sensitive attributes or l",
            &format!("histogram has {:?} / {:?} / l={}", agg.qi_columns, agg.sensitive_columns, agg.l),
        ));
    }
    Ok(())
}

/// Positions of `columns` in the shard, by exact name, as the monolith
/// resolves QI columns: a column silently skipped would be published as is.
fn columns_in_shard(shard: &Shard, columns: &[String], what: &str) -> Result<Vec<usize>, PipelineError> {
    columns
        .iter()
        .map(|c| {
            shard.column_index(c).ok_or_else(|| {
                validation(
                    "BLOCK_QI_SHARD_INCOMPLETE",
                    "A column k-anonymity needs is missing from this shard",
                    &format!(
                        "{what} '{c}' not found. k-anonymity is computed over the full QI tuple (and l-diversity \
                         over its sensitive attributes), so the orchestrator must route all of them to the same \
                         shard — split k-anon work by rows, never by columns."
                    ),
                )
            })
        })
        .collect()
}

/// Adds `v` to `dst` unless present, keeping at most `l` values.
fn add_capped(dst: &mut Vec<String>, v: String, l: usize) {
    if dst.len() < l && !dst.contains(&v) {
        dst.push(v);
    }
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

/// For artifacts that hold un-generalised QI tuples: owner-only.
fn write_secret_json<T: Serialize>(path: &Path, value: &T) -> Result<(), PipelineError> {
    write_secret_file(path, serde_json::to_string_pretty(value)?.as_bytes())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, PipelineError> {
    let raw = fs::read_to_string(path).map_err(|e| {
        validation("IO_READ_FAILED", "Could not read a kanon artifact", &format!("{}: {e}", path.display()))
    })?;
    serde_json::from_str(&raw).map_err(|e| {
        validation(
            "BLOCK_ARTIFACT_INVALID",
            "A kanon artifact is not in the expected shape",
            &format!("{}: {e}", path.display()),
        )
    })
}
