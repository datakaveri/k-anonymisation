use crate::pipeline::anonymization::{
    GRID_K_VALUES, GRID_SUPPRESSION_LIMITS, GeneralizationSummary, GridEntry, QuasiIdentifierLite, SparseHist, ZHist,
    allowed_suppressions, attach_categorical_levels, build_quasi_identifiers, build_sensitive_sets,
    build_sparse_histogram, build_z_histogram, categorical_ladder_len, compute_equivalence_space, compute_k_optimal,
    compute_numerical_min_max, compute_parameter_grid, compute_parameter_grid_for, compute_parameter_grid_z,
    compute_z_weights, find_ola1_initial_ri, find_ola2_best_rf_detailed, find_ola2_best_rf_z_detailed, find_ola2_with,
    generalize_and_write_outputs_with, l_aware_class_sizes, merge_histogram, merge_z_histogram, scan_chunks_for_flow,
    z_hist_to_sparse,
};
use crate::pipeline::bootstrap::{
    FlowMode, Logger, PipelineError, RuntimeConfig, StatusPayload, available_ram_bytes, clear_output_dir,
    clear_scratch_dir, ensure_output_dir, list_json_configs, open_csv, parse_runtime_config, split_csv_file_by_ram,
    stale_output_files,
};
use crate::pipeline::cli::Paths;
use crate::pipeline::connectors::{DataSink, DataSource, postgres as pg};
use crate::pipeline::fhir_bundle;
use crate::pipeline::multitabular::{
    InputFormat, SheetRestorePlan, resolve_pipeline_input, write_output_in_format, write_restored_workbook,
};
use crate::pipeline::nested_json;
use crate::pipeline::preprocess::preprocess_chunks;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Runs the pipeline over the conventional layout under `root` — `config/`,
/// `data/`, `chunks/` and `output/`. Equivalent to running the binary from
/// `root` with no flags.
pub fn run_pipeline(root: &Path) -> Result<StatusPayload, PipelineError> {
    run_pipeline_with(&Paths::from_root(root))
}

pub fn run_pipeline_with(paths: &Paths) -> Result<StatusPayload, PipelineError> {
    let result = run_pipeline_inner(paths);
    // chunks/ holds raw (pass1) or preprocessed-but-not-anonymized rows, the
    // converted input and any staged database extract. None of it may outlive
    // the run, whether the run succeeded or not.
    let _ = clear_scratch_dir(&paths.chunks_dir);
    result
}

fn run_pipeline_inner(paths: &Paths) -> Result<StatusPayload, PipelineError> {
    let output_dir_path = paths.output_dir.clone();
    let log_file = paths.log_file().display().to_string();
    let mut log = Logger::new(&output_dir_path);

    log.info("startup", "SKALD pipeline starting");

    let config_path = match &paths.config_file {
        Some(path) => {
            log.info("config", &format!("Using config named on the command line: {}", path.display()));
            if !path.is_file() {
                return Err(crate::pipeline::bootstrap::validation(
                    "CONFIG_NOT_FOUND",
                    "The config file named on the command line does not exist",
                    &path.display().to_string(),
                ));
            }
            path.clone()
        }
        None => {
            log.info("config", &format!("Searching for a JSON config in {}", paths.config_dir.display()));
            let candidates = list_json_configs(&paths.config_dir)?;
            // A bundle ships one config per dataset, so "the first one" is a
            // choice the run made rather than the only option there was.
            if candidates.len() > 1 {
                let names: Vec<String> =
                    candidates.iter().filter_map(|p| p.file_name().map(|n| n.to_string_lossy().to_string())).collect();
                log.warn(
                    "config",
                    &format!(
                        "{} configs are present ({}) — using the first by name. \
                     Pass --config to choose a different one.",
                        names.len(),
                        names.join(", "),
                    ),
                );
            }
            candidates.into_iter().next().ok_or_else(|| {
                crate::pipeline::bootstrap::validation(
                    "CONFIG_NOT_FOUND",
                    "No JSON config file found",
                    &format!("{} holds no *.json file", paths.config_dir.display()),
                )
            })?
        }
    };
    log.info("config", &format!("Loaded config: {}", config_path.display()));
    let mut cfg = parse_runtime_config(&config_path)?;
    // Keys, salts and tokens all come from the OS RNG; prove it works before
    // any of them is needed, rather than failing half-way through a release.
    crate::pipeline::preprocess::crypto::generate_random_salt_hex()?;
    for warning in &cfg.warnings {
        log.warn("config", warning);
    }

    // Key material (token vaults, symmetric and FPE keys, hash salts) lives in
    // its own directory, never in the release directory. Resolving it here —
    // where both the command line and the config are known — keeps
    // preprocessing from having to guess at it from the chunk paths.
    let key_dir = paths.key_material_dir(cfg.key_directory.as_deref());
    paths
        .check_key_material_dir(&key_dir)
        .map_err(|e| crate::pipeline::bootstrap::validation("KEY_MATERIAL_IN_OUTPUT", &e.message, &e.details))?;
    refuse_key_material_in_output(&output_dir_path, &key_dir)?;
    cfg.output_directory = key_dir.display().to_string();
    log.info("config", &format!("Key material directory: {}", cfg.output_directory));
    // ── Nested-JSON de-identification ───────────────────────────────────────
    // A separate terminal flow, not a stage of the tabular one. These inputs
    // are one document per patient, so there is no cohort to hide a record in
    // and k-anonymity does not apply — see `nested_json`'s module docs. It
    // returns here rather than falling through to chunking, which would only
    // flatten a single subject into a single row and search a lattice over it.
    if cfg.nested_json.enabled {
        return run_nested_json(&mut log, &cfg, paths, &log_file);
    }
    // Same shape of flow for FHIR Bundles, one per patient.
    if cfg.fhir_bundle.enabled {
        return run_fhir_bundle(&mut log, &cfg, paths, &log_file);
    }

    let pass = cfg.pass.clone();
    log.info("config", &format!("pass={}, k={}, suppression_limit={:.3}", pass, cfg.k, cfg.suppression_limit));

    // ── Stale-artifact handling ──────────────────────────────────────────────
    // chunks/ is pure scratch and `_converted.csv` holds un-anonymized source
    // data, so leftovers are always removed. output/ holds deliverables, so
    // stale files are only reported unless the config opts into cleaning —
    // reported either way, since a leftover `generalized_<other>.csv` beside
    // this run's output is easy to mistake for part of this run's results.
    let removed = clear_scratch_dir(&paths.chunks_dir)?;
    if removed > 0 {
        log.info("cleanup", &format!("Removed {removed} stale file(s) from chunks/"));
    }

    let mut will_write = vec![cfg.output_path.clone()];
    if let Some(stem) = Path::new(&cfg.output_path).file_stem() {
        let stem = stem.to_string_lossy().to_string();
        // The input format isn't known yet at this point, so reserve every name
        // the format-matched output could take rather than mis-report one as
        // stale. `<stem>.xlsx` doubles as the restore_sheets workbook.
        will_write.push(format!("{stem}.xlsx"));
        will_write.push(format!("{stem}.json"));
    }
    if cfg.clean_output {
        let cleared = clear_output_dir(&output_dir_path, &will_write)?;
        if !cleared.is_empty() {
            log.info(
                "cleanup",
                &format!(
                    "clean_output=true — removed {} stale file(s) from output/: {}",
                    cleared.len(),
                    cleared.join(", ")
                ),
            );
        }
    } else {
        let stale = stale_output_files(&output_dir_path, &will_write);
        if !stale.is_empty() {
            log.info(
                "cleanup",
                &format!(
                    "output/ holds {} file(s) from an earlier run that this run will not overwrite — \
                 they are NOT part of these results: {}. Set \"clean_output\": true to remove them.",
                    stale.len(),
                    stale.join(", ")
                ),
            );
        }
    }

    // ── Input normalisation (CSV / JSON / multi-sheet Excel → single CSV) ────
    // data/ is mounted read-only in deployment, so JSON/Excel inputs are
    // normalised into chunks/ (read-write scratch) instead; a plain .csv
    // input is returned as-is, still pointing into data/.
    let staged_input_path = stage_input(&mut log, &cfg, paths)?;

    log.info("input", "Resolving input data format (csv/json/xlsx)");
    let resolved =
        resolve_pipeline_input(staged_input_path.as_deref(), &paths.data_dir, &paths.chunks_dir, &cfg.sheet_joins)?;
    if let Some(mismatch) = &resolved.format_mismatch {
        log.info("input", &format!("FORMAT MISMATCH: {mismatch}"));
    }
    log.info("input", &format!("Reading input as {:?}", resolved.format));
    let (input_csv, restore_plan, input_format) = (resolved.csv_path, resolved.restore_plan, resolved.format);

    // ── Chunking (all passes need the raw CSV split) ─────────────────────────
    log.info("chunking", "Splitting CSV into RAM-sized chunks");
    let (chunk_paths, rows_per_chunk) = split_csv_file_by_ram(&input_csv, &paths.chunks_dir)?;
    log.info("chunking", &format!("{} chunk(s), ~{} rows/chunk", chunk_paths.len(), rows_per_chunk));

    // ── Preprocess-only path (no k-anonymity configured) ─────────────────────
    if !cfg.enable_k_anonymity {
        log.info("preprocessing", &format!(
            "k-anonymity disabled — preprocess-only: suppress={}, hash_salt={}, hash={}, mask={}, encrypt={}, charcloak={}, tokenize={}",
            cfg.suppress.len(), cfg.hashing_with_salt.len(), cfg.hashing_without_salt.len(),
            cfg.masking.len(), cfg.encrypt.len(), cfg.charcloak.len(),
            cfg.tokenization.len(),
        ));
        let pre_stats = preprocess_chunks(&chunk_paths, &cfg)?;
        log_preprocess_stats(&mut log, &pre_stats);

        ensure_output_dir(&output_dir_path)?;
        let final_output_path = output_dir_path.join(&cfg.output_path);
        merge_chunks_to_output(&chunk_paths, &final_output_path)?;
        log.info("output", &format!("Preprocess-only output written to {}", final_output_path.display()));

        let restored_workbook_path =
            maybe_write_restored_workbook(&mut log, &cfg, &restore_plan, &output_dir_path, &final_output_path);
        let format_matched_output_path = write_format_matched_output(
            &mut log,
            &cfg,
            input_format,
            &final_output_path,
            restored_workbook_path.as_deref(),
        )?;
        let database_sink = push_to_sink(&mut log, &cfg, &final_output_path)?;

        return Ok(StatusPayload {
            status: "success".to_string(),
            phase: Some("done".to_string()),
            outputs: Some(json!({
                "pass": "preprocess_only",
                "preprocessing": pre_stats,
                "chunk_count": chunk_paths.len(),
                "final_output_path": final_output_path.display().to_string(),
                "format_matched_output_path": format_matched_output_path,
                "sample_generalized_rows": read_csv_sample(&final_output_path.display().to_string(), 10),
                "restored_workbook_path": restored_workbook_path,
                "database_sink": database_sink,
            })),
            error: None,
            log_file: log_file.clone(),
        });
    }

    // ── Preprocessing (pass2 and no_bounds only) ─────────────────────────────
    let mut pre_stats = crate::pipeline::preprocess::PreprocessStats::new();
    if pass != "pass1" {
        log.info("preprocessing", &format!(
            "Running preprocessing: suppress={}, hash_salt={}, hash={}, mask={}, encrypt={}, charcloak={}, tokenize={}",
            cfg.suppress.len(), cfg.hashing_with_salt.len(), cfg.hashing_without_salt.len(),
            cfg.masking.len(), cfg.encrypt.len(), cfg.charcloak.len(),
            cfg.tokenization.len(),
        ));
        pre_stats = preprocess_chunks(&chunk_paths, &cfg)?;
        log_preprocess_stats(&mut log, &pre_stats);
    }

    // ── Min/max scan ─────────────────────────────────────────────────────────
    log.info("min_max_scan", &format!("Computing min/max for {} numerical QI(s)", cfg.numerical_qis.len()));
    let numerical_cols = cfg.numerical_qis.iter().map(|q| q.column.clone()).collect::<Vec<_>>();
    let dynamic_min_max = compute_numerical_min_max(&chunk_paths, &numerical_cols)?;
    log.info("min_max_scan", &format!("Scanned {} column(s)", dynamic_min_max.len()));

    // ── Build QIs ────────────────────────────────────────────────────────────
    log.info(
        "qi_building",
        &format!("Building QIs: {} numerical, {} categorical", cfg.numerical_qis.len(), cfg.categorical_qis.len()),
    );
    let mut qis = build_quasi_identifiers(&cfg, &dynamic_min_max)?;
    let interval_qi_count = qis.iter().filter(|q| q.interval_hierarchy.is_some()).count();
    log.info("qi_building", &format!("{} QI(s) built ({} with interval constraints)", qis.len(), interval_qi_count));

    // ── Pass 2 with a node chosen from the pass-1 grid ───────────────────────
    // The pass-1 grid already measured this node against this data, so OLA-1,
    // the histogram and OLA-2 would only rediscover it. What gets written is
    // still checked against suppression_limit, which catches a stale node.
    if let Some(chosen) = &cfg.generalization_node {
        if pass == "pass2" {
            if cfg.k <= 0 {
                return Err(crate::pipeline::bootstrap::validation(
                    "CONFIG_MISSING_FIELD",
                    "k must be set and > 0 for pass2 / no_bounds",
                    "Add \"k_anonymize\": {\"k\": <value>} to config",
                ));
            }
            let final_rf = resolve_generalization_node(chosen, &qis, &cfg)?;
            log.info(
                "generalization",
                &format!(
                    "Using generalization_node from config {:?} → {:?} — OLA-1, histogram and OLA-2 skipped",
                    chosen, final_rf
                ),
            );
            let out = write_generalized_output(
                &mut log,
                &cfg,
                &chunk_paths,
                &qis,
                &final_rf,
                &output_dir_path,
                &restore_plan,
                input_format,
                None,
            )?;
            log.info("startup", "Pipeline completed successfully");
            return Ok(StatusPayload {
                status: "success".to_string(),
                phase: Some("done".to_string()),
                outputs: Some(json!({
                    "pass": pass,
                    "source_config": cfg.source_json_config.display().to_string(),
                    "output_path": cfg.output_path,
                    "rows_per_chunk": rows_per_chunk,
                    "chunk_count": chunk_paths.len(),
                    "quasi_identifier_count": qis.len(),
                    "interval_qi_count": interval_qi_count,
                    "flow": "CHOSEN_NODE",
                    "generalization_node": chosen,
                    "final_rf": final_rf,
                    "lowest_dm_star": out.summary.dm_star,
                    "num_equivalence_classes": out.summary.num_equivalence_classes,
                    "equivalence_class_stats": out.summary.class_size_counts,
                    "suppressed_records": out.summary.suppressed_records,
                    "removed_records": out.summary.removed_records,
                    "anonymisation_summary": summary_json(&cfg, &out.summary),
                    "preprocessing": pre_stats,
                    "top_ola2_nodes": [],
                    "total_records": out.summary.total_records,
                    "final_output_path": out.final_output_path,
                    "sample_generalized_rows": out.sample_generalized_rows,
                    "parameter_grid": [],
                    "restored_workbook_path": out.restored_workbook_path,
                    "format_matched_output_path": out.format_matched_output_path,
                    "database_sink": out.database_sink,
                })),
                error: None,
                log_file: log_file.clone(),
            });
        }
        log.warn("config", &format!("generalization_node is only used by pass2 — ignored in {pass}"));
    }

    // ── Pre-scan: record count + categorical domains (needed for flow decision) ─
    log.info("pre_scan", "Scanning chunks for flow selection");
    let (n_approx, categorical_domains) = scan_chunks_for_flow(&chunk_paths, &qis)?;
    attach_categorical_levels(&mut qis, &categorical_domains, &cfg.categorical_hierarchies)?;
    for qi in qis.iter().filter(|q| q.is_categorical) {
        if let Some(c) = &qi.categorical_levels {
            log.info(
                "qi_building",
                &format!("  {}: {} generalization level(s) from categorical_hierarchies", qi.column_name, c.num_levels),
            );
        }
    }
    let e = compute_equivalence_space(&qis, &categorical_domains);
    let n_log_n = (n_approx as f64) * (n_approx as f64).log2().max(0.0);

    // Per-QI breakdown so the flow decision is fully traceable
    // categorical_domains is indexed by QI position (same length as qis)
    log.info("flow", "── QI equivalence ranges ──────────────────────────");
    for (i, qi) in qis.iter().enumerate() {
        let (kind, r_qi) = if qi.is_categorical {
            let sz = categorical_domains.get(i).map(|d| d.len()).unwrap_or(0);
            ("categorical", sz as f64)
        } else if let Some(h) = &qi.interval_hierarchy {
            ("interval   ", h.num_at(1) as f64)
        } else {
            let mn = qi.min_value.unwrap_or(0.0);
            let mx = qi.max_value.unwrap_or(0.0);
            ("numerical  ", (mx - mn + 1.0).max(1.0))
        };
        log.info("flow", &format!("  {:20}  type={kind}  R_Qi={r_qi:.0}", qi.column_name));
    }
    log.info("flow", &format!("  {}", "─".repeat(48)));
    log.info("flow", &format!("  E (product)  = {e:.6e}"));
    log.info("flow", &format!("  N            = {n_approx}"));
    log.info("flow", &format!("  N·log₂N      = {n_log_n:.6e}"));
    log.info(
        "flow",
        &format!(
            "  N·log₂N {} E  →  {}",
            if n_log_n <= e { "≤" } else { ">" },
            if n_log_n <= e { "DIRECT eligible" } else { "ORIGINAL eligible" }
        ),
    );
    log.info("flow", "───────────────────────────────────────────────────");

    let use_direct = match cfg.flow_mode {
        FlowMode::Auto => n_log_n <= e,
        FlowMode::Original => false,
        FlowMode::Direct => true,
    };
    let mode_label = match cfg.flow_mode {
        FlowMode::Auto => "AUTO",
        FlowMode::Original => "ORIGINAL (forced)",
        FlowMode::Direct => "DIRECT (forced)",
    };
    log.info(
        "flow",
        &format!(
            "Flow selected: {}  [config flow_mode={}]",
            if use_direct { "DIRECT" } else { "ORIGINAL" },
            mode_label
        ),
    );

    // ── OLA-1 + Sparse Histogram  OR  Z-encoded Direct Histogram ─────────────
    //
    // DIRECT: build Z histogram (sorted compact array, ~16 bytes/entry).
    //         Falls back to ORIGINAL if Z weights overflow i64.
    // ORIGINAL: OLA-1 to find initial coarsening, then SparseHist.
    //
    // After this block, `base_sparse` is always populated (the SparseHist form of
    // the base histogram) and `z_hist_opt` is Some only in the DIRECT path.

    let actual_use_direct = if use_direct {
        match compute_z_weights(&qis, &categorical_domains) {
            Some(_) => true,
            None => {
                log.info("flow", "Z weights overflow i64 — falling back to ORIGINAL flow");
                false
            }
        }
    } else {
        false
    };

    enum BaseHist {
        Sparse(SparseHist),
        Z(ZHist, Vec<i64>),
    }

    let (initial_ri, base, total_records) = if actual_use_direct {
        // DIRECT: RAM constraint log
        let ram = available_ram_bytes().unwrap_or(32_000_000);
        let needed = 16u64.saturating_mul(n_approx as u64);
        if needed > ram / 2 {
            log.info(
                "histogram",
                &format!(
                    "Warning: Z-histogram needs ~{}MB, RAM/2={}MB — proceed anyway (DIRECT forced)",
                    needed / 1_000_000,
                    ram / 2_000_000
                ),
            );
        }
        log.info("z_enc", &format!("Direct Z-histogram over {} chunk(s) — OLA-1 skipped", chunk_paths.len()));
        let weights = compute_z_weights(&qis, &categorical_domains).unwrap();

        // ── Z weight table ────────────────────────────────────────────────────
        log.info("z_enc", "── mixed-radix weights ────────────────────────────────");
        log.info("z_enc", &format!("  {:20}  {:>10}  {:>12}", "QI", "R_Qi", "W_i"));
        log.info("z_enc", &format!("  {}", "─".repeat(46)));
        for (i, qi) in qis.iter().enumerate() {
            let r_qi = if qi.is_categorical {
                categorical_domains.get(i).map(|d| d.len()).unwrap_or(1) as i64
            } else if let Some(h) = &qi.interval_hierarchy {
                h.num_at(1) as i64
            } else {
                let mn = qi.min_value.unwrap_or(0.0);
                let mx = qi.max_value.unwrap_or(0.0);
                (mx - mn + 1.0) as i64
            };
            log.info("z_enc", &format!("  {:20}  {:>10}  {:>12}", qi.column_name, r_qi, weights[i]));
        }
        log.info("z_enc", &format!("  {}", "─".repeat(46)));

        let ri = vec![1i64; qis.len()];
        let (zh, n) = build_z_histogram(&chunk_paths, &qis, &categorical_domains, &weights)?;

        // ── Collapse stats ────────────────────────────────────────────────────
        // n raw Z values sorted → zh.len() unique buckets; compression = n/buckets
        let compression = if !zh.is_empty() { n as f64 / zh.len() as f64 } else { 1.0 };
        log.info(
            "z_enc",
            &format!("{} raw Z values → {} unique buckets (avg {:.1} records/bucket)", n, zh.len(), compression),
        );
        log.info(
            "z_enc",
            &format!(
                "Z array: ~{}KB raw  →  ~{}KB collapsed  ({}× smaller)",
                n * 8 / 1024,
                zh.len() * 16 / 1024,
                if !zh.is_empty() { (n * 8) / (zh.len() as i64 * 16).max(1) } else { 1 }
            ),
        );

        log.info("histogram", &format!("{} valid records, {} histogram buckets (Z-encoded)", n, zh.len()));
        (ri, BaseHist::Z(zh, weights), n)
    } else {
        let max_eq = (available_ram_bytes().unwrap_or(32_000_000) / 32) as i64;
        log.info("ola1", &format!("OLA-1: finding initial RI (max_eq={})", max_eq));
        let ri = find_ola1_initial_ri(&qis, chunk_paths.len() as i64, max_eq, &cfg.size_factors)?;
        log.info("ola1", &format!("Initial RI: {:?}", ri));
        log.info("histogram", &format!("Building sparse histogram over {} chunk(s)", chunk_paths.len()));
        let (hist, n) = build_sparse_histogram(&chunk_paths, &qis, &ri, &categorical_domains)?;
        log.info("histogram", &format!("{} valid records, {} histogram buckets", n, hist.len()));
        (ri, BaseHist::Sparse(hist), n)
    };

    // Convert to SparseHist for diagnostics, parameter grid, pass1, and eq_stats.
    // In DIRECT flow this conversion is only done once here and reused.
    let base_sparse: SparseHist = match &base {
        BaseHist::Sparse(h) => h.clone(),
        BaseHist::Z(zh, w) => z_hist_to_sparse(zh, &qis, w),
    };

    // ── l-diversity: distinct sensitive values per base cell ─────────────────
    let sensitive_sets = match &cfg.l_diversity {
        Some(l) => {
            log.info(
                "l_diversity",
                &format!(
                    "Collecting distinct values of {} sensitive attribute(s) for l={}",
                    l.sensitive_attributes.len(),
                    l.l
                ),
            );
            Some(build_sensitive_sets(
                &chunk_paths,
                &qis,
                &initial_ri,
                &categorical_domains,
                &l.sensitive_attributes,
                l.l,
            )?)
        }
        None => None,
    };

    // ── Histogram diagnostic ─────────────────────────────────────────────────
    let diag_label = if actual_use_direct { "Base Z-histogram (decoded)" } else { "Base histogram" };
    log_histogram_diagnostic(&mut log, "hist_diag", diag_label, &base_sparse);

    // ── Parameter grid (pass1 and no_bounds) ─────────────────────────────────
    // Pass2 is run after the user has already picked from pass1's grid, so
    // recomputing it there would only repeat pass1's work.
    let parameter_grid: Vec<GridEntry> = if pass == "pass2" {
        log.info("parameter_grid", "Skipped in pass2 — the grid is a pass1 output");
        vec![]
    } else if cfg.compute_param_grid {
        log.info("parameter_grid", "Computing k × suppression_limit parameter grid (multi-combination OLA-2)");
        let grid = match (&base, &sensitive_sets, &cfg.l_diversity) {
            (_, Some(sens), Some(l)) => compute_parameter_grid_for(
                &qis,
                &initial_ri,
                &cfg.size_factors,
                total_records,
                GRID_K_VALUES,
                GRID_SUPPRESSION_LIMITS,
                |node| l_aware_class_sizes(&base_sparse, sens, &qis, node, l.l),
            )?,
            (BaseHist::Z(zh, w), _, _) => {
                compute_parameter_grid_z(&qis, zh, w, &initial_ri, &cfg.size_factors, total_records)?
            }
            (BaseHist::Sparse(h), _, _) => {
                compute_parameter_grid(&qis, h, &initial_ri, &cfg.size_factors, total_records)?
            }
        };
        log.info(
            "parameter_grid",
            &format!(
                "{} grid cells ({} feasible) — {} of {} lattice node(s) merged",
                grid.entries.len(),
                grid.entries.iter().filter(|e| e.feasible).count(),
                grid.nodes_merged,
                grid.lattice_size,
            ),
        );
        write_parameter_grid_table(&grid.entries, &output_dir_path);
        log.info(
            "parameter_grid",
            &format!(
                "  {:>5}  {:>6}  {:24}  {:>14}  {:>6}  {:>10}  feasible",
                "k", "sigma", "best_node", "DM*", "ECs", "suppressed"
            ),
        );
        for e in &grid.entries {
            log.info(
                "parameter_grid",
                &format!(
                    "  {:>5}  {:>6.2}  {:24}  {:>14}  {:>6}  {:>10}  {}",
                    e.k,
                    e.suppression_limit,
                    format!("{:?}", e.best_node),
                    e.dm_star,
                    e.num_equivalence_classes,
                    e.suppression_count,
                    if e.feasible { "yes" } else { "no" }
                ),
            );
        }
        grid.entries
    } else {
        log.info("parameter_grid", "Skipped (compute_parameter_grid=false)");
        vec![]
    };

    // ── Pass 1: compute k_optimal and return ─────────────────────────────────
    if pass == "pass1" {
        let k_optimal = compute_k_optimal(&qis, &base_sparse, cfg.suppression_limit, total_records);
        log.info("pass1", &format!("k_optimal={} (suppression_limit={:.3})", k_optimal, cfg.suppression_limit));
        log.info("startup", "Pass 1 complete — awaiting k input");

        return Ok(StatusPayload {
            status: "success".to_string(),
            phase: Some("awaiting_pass2".to_string()),
            outputs: Some(json!({
                "pass": "pass1",
                "k_optimal": k_optimal,
                "total_records": total_records,
                "suppression_limit": cfg.suppression_limit,
                "parameter_grid": parameter_grid,
                "histogram_buckets": base_sparse.len(),
                "initial_ri": initial_ri,
            })),
            error: None,
            log_file: log_file.clone(),
        });
    }

    // ── Pass 2 / no_bounds: validate k, run OLA-2, generalize ────────────────
    if cfg.k <= 0 {
        return Err(crate::pipeline::bootstrap::validation(
            "CONFIG_MISSING_FIELD",
            "k must be set and > 0 for pass2 / no_bounds",
            "Add \"k_anonymize\": {\"k\": <value>} to config",
        ));
    }

    log.info("ola2", &format!("OLA-2: lattice search (k={}, suppression_limit={:.3})", cfg.k, cfg.suppression_limit));
    let ola2 = match (&base, &sensitive_sets, &cfg.l_diversity) {
        (_, Some(sens), Some(l)) => {
            find_ola2_with(&qis, &initial_ri, &cfg.size_factors, cfg.k, cfg.suppression_limit, total_records, |node| {
                l_aware_class_sizes(&base_sparse, sens, &qis, node, l.l)
            })?
        }
        (BaseHist::Z(zh, w), _, _) => find_ola2_best_rf_z_detailed(
            &qis,
            zh,
            w,
            &initial_ri,
            &cfg.size_factors,
            cfg.k,
            cfg.suppression_limit,
            total_records,
        )?,
        (BaseHist::Sparse(h), _, _) => find_ola2_best_rf_detailed(
            &qis,
            h,
            &initial_ri,
            &cfg.size_factors,
            cfg.k,
            cfg.suppression_limit,
            total_records,
        )?,
    };
    let final_rf = ola2.best_rf.clone();
    let lowest_dm_star = ola2.lowest_dm_star;
    let num_equivalence_classes = ola2.num_equivalence_classes;
    log.info("ola2", &format!("Best RF: {:?}, DM*={}, ECs={}", final_rf, lowest_dm_star, num_equivalence_classes));

    // ── OLA-2 node trace (every directly evaluated node) ─────────────────────
    log.info("ola2_trace", &format!("{} nodes evaluated (others inferred via monotonicity)", ola2.node_trace.len()));
    log.info(
        "ola2_trace",
        &format!("  {:30}  {:>10}  {:>14}  {:>5}  {}", "node", "suppressed", "dm_star", "ECs", "verdict"),
    );
    log.info("ola2_trace", &format!("  {}", "─".repeat(75)));
    for t in &ola2.node_trace {
        log.info(
            "ola2_trace",
            &format!(
                "  {:30}  {:>10}  {:>14}  {:>5}  {}",
                format!("{:?}", t.node),
                t.suppression_count,
                t.dm_star,
                t.num_equivalence_classes,
                if t.passes { "PASS ✓" } else { "FAIL ✗" }
            ),
        );
    }
    log.info("ola2_trace", &format!("  {}", "─".repeat(75)));

    // ── Merged histogram at best RF ───────────────────────────────────────────
    let merged_sparse = match &base {
        BaseHist::Z(zh, w) => {
            let merged_z = merge_z_histogram(zh, &qis, w, &final_rf);
            z_hist_to_sparse(&merged_z, &qis, w)
        }
        BaseHist::Sparse(h) => merge_histogram(h, &qis, &final_rf),
    };
    let merged_label = if actual_use_direct {
        format!("Merged Z-histogram at best RF {:?}", final_rf)
    } else {
        format!("Merged histogram at best RF {:?}", final_rf)
    };
    log_histogram_diagnostic(&mut log, "hist_diag", &merged_label, &merged_sparse);

    let out = write_generalized_output(
        &mut log,
        &cfg,
        &chunk_paths,
        &qis,
        &final_rf,
        &output_dir_path,
        &restore_plan,
        input_format,
        Some((ola2.lattice_size, ola2.node_trace.len())),
    )?;
    fs::write(output_dir_path.join("top_ola2_nodes.json"), serde_json::to_string_pretty(&ola2.top_nodes)?)?;
    log.info("output", "Top OLA-2 nodes written");
    log.info("startup", "Pipeline completed successfully");

    Ok(StatusPayload {
        status: "success".to_string(),
        phase: Some("done".to_string()),
        outputs: Some(json!({
            "pass": pass,
            "source_config": cfg.source_json_config.display().to_string(),
            "output_path": cfg.output_path,
            "rows_per_chunk": rows_per_chunk,
            "chunk_count": chunk_paths.len(),
            "quasi_identifier_count": qis.len(),
            "interval_qi_count": interval_qi_count,
            "max_equivalence_classes": serde_json::Value::Null,
            "flow": if actual_use_direct { "DIRECT_Z" } else { "ORIGINAL" },
            "n_approx": n_approx,
            "equivalence_space": e,
            "n_log2_n": n_log_n,
            "initial_ri": initial_ri,
            "final_rf": final_rf,
            "lowest_dm_star": lowest_dm_star,
            "num_equivalence_classes": num_equivalence_classes,
            "equivalence_class_stats": out.summary.class_size_counts,
            "suppressed_records": out.summary.suppressed_records,
            "removed_records": out.summary.removed_records,
            "anonymisation_summary": summary_json(&cfg, &out.summary),
            "preprocessing": pre_stats,
            "lattice_size": ola2.lattice_size,
            "nodes_evaluated": ola2.node_trace.len(),
            "top_ola2_nodes": ola2.top_nodes,
            "total_records": total_records,
            "final_output_path": out.final_output_path,
            "sample_generalized_rows": out.sample_generalized_rows,
            "parameter_grid": parameter_grid,
            "restored_workbook_path": out.restored_workbook_path,
            "format_matched_output_path": out.format_matched_output_path,
            "database_sink": out.database_sink,
        })),
        error: None,
        log_file: log_file.clone(),
    })
}

/// Maps pass2's `generalization_node` onto QI order, and checks that it names
/// every QI, nothing else, and only levels each QI actually has.
pub(crate) fn resolve_generalization_node(
    chosen: &BTreeMap<String, i64>,
    qis: &[QuasiIdentifierLite],
    cfg: &RuntimeConfig,
) -> Result<Vec<i64>, PipelineError> {
    let invalid = |message: &str, details: String| {
        crate::pipeline::bootstrap::validation("CONFIG_INVALID_VALUE", message, &details)
    };
    let names_qi = |col: &str| qis.iter().any(|q| q.column_name == col);
    let unknown: Vec<&str> = chosen.keys().map(String::as_str).filter(|c| !names_qi(c)).collect();
    if !unknown.is_empty() {
        return Err(invalid("generalization_node names columns that are not quasi-identifiers", unknown.join(", ")));
    }

    let mut final_rf = Vec::with_capacity(qis.len());
    for qi in qis {
        let level = chosen
            .get(&qi.column_name)
            .copied()
            .ok_or_else(|| invalid("generalization_node is missing a quasi-identifier", qi.column_name.clone()))?;
        let max_level = if let Some(h) = &qi.interval_hierarchy {
            h.num_levels as i64
        } else if qi.is_categorical {
            categorical_ladder_len(&qi.column_name, &cfg.categorical_hierarchies) as i64 + 2
        } else {
            let (mn, mx) = (qi.min_value.unwrap_or(0.0), qi.max_value.unwrap_or(0.0));
            ((mx.round() - mn.floor() + 1.0) as i64).max(1)
        };
        if level > max_level {
            return Err(invalid(
                "generalization_node level is beyond what this quasi-identifier supports",
                format!("{}: {} (max {})", qi.column_name, level, max_level),
            ));
        }
        final_rf.push(level);
    }
    Ok(final_rf)
}

/// Everything pass 2 writes once the generalization node is known.
struct GeneralizedOutput {
    summary: GeneralizationSummary,
    final_output_path: String,
    sample_generalized_rows: serde_json::Value,
    restored_workbook_path: Option<String>,
    format_matched_output_path: Option<String>,
    database_sink: serde_json::Value,
}

/// Generalizes every chunk to `final_rf`, checks what was actually suppressed
/// against `suppression_limit`, then writes the derived outputs and the sink.
///
/// Exceeding the limit is an error and the written file is removed before
/// anything is derived from it. OLA-2 and the output step read every cell the
/// same way, so for a node OLA-2 chose this cannot happen; for a node taken
/// from the config it means the data changed since pass1.
#[allow(clippy::too_many_arguments)]
fn write_generalized_output(
    log: &mut Logger,
    cfg: &RuntimeConfig,
    chunk_paths: &[PathBuf],
    qis: &[QuasiIdentifierLite],
    final_rf: &[i64],
    output_dir_path: &Path,
    restore_plan: &Option<SheetRestorePlan>,
    input_format: InputFormat,
    search: Option<(usize, usize)>,
) -> Result<GeneralizedOutput, PipelineError> {
    log.info("generalization", &format!("Generalizing and writing output to {}", output_dir_path.display()));
    let summary = generalize_and_write_outputs_with(
        chunk_paths,
        qis,
        final_rf,
        cfg.k,
        cfg.l_diversity.as_ref(),
        output_dir_path,
        &cfg.output_path,
        &cfg.categorical_hierarchies,
    )?;
    let final_output_path = if Path::new(&cfg.output_path).is_absolute() {
        cfg.output_path.clone()
    } else {
        output_dir_path.join(&cfg.output_path).display().to_string()
    };

    let allowed = allowed_suppressions(cfg.suppression_limit, summary.total_records);
    log.info(
        "generalization",
        &format!(
            "Output written: {} record(s), {} suppressed (limit {}), {} removed, {} equivalence class(es), DM*={}",
            summary.total_records,
            summary.suppressed_records,
            allowed,
            summary.removed_records,
            summary.num_equivalence_classes,
            summary.dm_star
        ),
    );
    if summary.removed_records > 0 {
        log.info(
            "generalization",
            &format!(
                "{} suppressed record(s) were removed rather than published with '*': together they form \
             a class smaller than k (or not l-diverse), which would single them out",
                summary.removed_records
            ),
        );
    }
    if summary.suppressed_records > allowed {
        let _ = fs::remove_file(&final_output_path);
        return Err(crate::pipeline::bootstrap::validation(
            "SUPPRESSION_LIMIT_EXCEEDED",
            "The written output exceeds suppression_limit on this data",
            &format!(
                "{} of {} records suppressed at {:?}; suppression_limit {} allows {}",
                summary.suppressed_records, summary.total_records, final_rf, cfg.suppression_limit, allowed
            ),
        ));
    }

    log_run_summary(log, cfg, qis, final_rf, &summary, search);

    ensure_output_dir(output_dir_path)?;
    fs::write(
        output_dir_path.join("equivalence_class_stats.json"),
        serde_json::to_string_pretty(&summary.class_size_counts)?,
    )?;
    log.info("output", "Equivalence class stats written");

    let sample_generalized_rows = read_csv_sample(&final_output_path, 10);
    let restored_workbook_path =
        maybe_write_restored_workbook(log, cfg, restore_plan, output_dir_path, Path::new(&final_output_path));
    let format_matched_output_path = write_format_matched_output(
        log,
        cfg,
        input_format,
        Path::new(&final_output_path),
        restored_workbook_path.as_deref(),
    )?;
    let database_sink = push_to_sink(log, cfg, Path::new(&final_output_path))?;

    Ok(GeneralizedOutput {
        summary,
        final_output_path,
        sample_generalized_rows,
        restored_workbook_path,
        format_matched_output_path,
        database_sink,
    })
}

/// Works out which single file this run should read, staging it first when it
/// has to be fetched.
///
/// Most specific wins, and every override is logged, because "which rows did
/// this run actually anonymize?" is the first question asked of any output:
///
/// 1. the free-text anonymization handoff — already sanitized, so nothing may
///    displace it;
/// 2. a file named with `--data`, which is a deliberate per-run instruction;
/// 3. a `postgres` input section, staged to `chunks/_pg_input.csv`;
/// 4. otherwise `None`, and the data directory is scanned as it always was.
fn stage_input(log: &mut Logger, cfg: &RuntimeConfig, paths: &Paths) -> Result<Option<PathBuf>, PipelineError> {
    let free_text_staged = if cfg.free_text_anonymization.enabled {
        log.info(
            "input",
            &format!("free-text anonymization enabled for {} column(s)", cfg.free_text_anonymization.columns.len()),
        );
        let staged = cfg
            .free_text_anonymization
            .staged_input_path
            .as_ref()
            .map(|p| if p.is_absolute() { p.clone() } else { paths.root.join(p) });
        if staged.is_none() {
            log.warn(
                "input",
                "free_text_anonymization.enabled is set but staged_input_path is missing — falling back to the data directory",
            );
        }
        staged
    } else {
        None
    };

    if let Some(path) = free_text_staged {
        log.info("input", &format!("Using staged input file from {}", path.display()));
        if paths.data_file.is_some() || matches!(cfg.input_source, DataSource::Postgres(_)) {
            log.warn(
                "input",
                "The free-text handoff file takes precedence — it is the sanitized copy, \
                 so the raw input it was derived from is deliberately not re-read",
            );
        }
        return Ok(Some(path));
    }

    if let Some(path) = &paths.data_file {
        log.info("input", &format!("Using input file named on the command line: {}", path.display()));
        if matches!(cfg.input_source, DataSource::Postgres(_)) {
            log.warn("input", "--data names a file, so the config's postgres input is not read this run");
        }
        return Ok(Some(path.clone()));
    }

    match &cfg.input_source {
        DataSource::Files => Ok(None),
        DataSource::Postgres(read) => {
            let staged = paths.chunks_dir.join("_pg_input.csv");
            pg::read_to_csv(read, &staged, log)?;
            Ok(Some(staged))
        }
    }
}

/// Runs the nested-JSON de-identification flow and builds its status payload.
///
/// Reports the census alongside the documents deliberately: with a key space
/// this open-ended, "which paths did this run let through?" is not a detail of
/// the run, it is the run's main safety claim, and the answer has to be
/// somewhere the operator will look.
fn run_nested_json(
    log: &mut Logger,
    cfg: &RuntimeConfig,
    paths: &Paths,
    log_file: &str,
) -> Result<StatusPayload, PipelineError> {
    log.info(
        "nested-json",
        &format!(
            "Nested-JSON de-identification: {} rule(s), default_action={:?} — \
             one document per patient, so the k-anonymity flow is not run",
            cfg.nested_json.rules.len(),
            cfg.nested_json.default_action,
        ),
    );

    let mut nested = cfg.nested_json.clone();
    nested.key_material_dir = PathBuf::from(&cfg.output_directory);
    nested.output_root = paths.output_dir.clone();
    let report = nested_json::run(&nested, &paths.root)?;

    for (name, why) in &report.files_skipped {
        log.warn("nested-json", &format!("skipped {name}: {why}"));
    }
    if report.salt_created {
        log.info(
            "nested-json",
            &format!(
                "Generated a new hash salt at {} — back it up with the run's other key material; \
                 later runs reuse it so their pseudonyms match this run's",
                report.salt_path.display(),
            ),
        );
    }
    if !report.key_files.is_empty() {
        let files: Vec<String> = report.key_files.iter().map(|p| p.display().to_string()).collect();
        log.info(
            "nested-json",
            &format!(
                "Token vault / encryption keys at {} — anyone holding them can recover the original \
                 values, so keep them apart from the released documents",
                files.join(", "),
            ),
        );
    }
    if report.dry_run {
        log.info(
            "nested-json",
            &format!(
                "DRY RUN — {} document(s) examined, none written. {} path(s) seen, {} would be kept. Review {}",
                report.documents_examined,
                report.paths_seen,
                report.paths_kept,
                report.census_path.display(),
            ),
        );
    } else {
        log.info(
            "nested-json",
            &format!(
                "{} document(s) written to {}; {} path(s) seen, {} kept — review {}",
                report.files_written,
                report.output_dir.display(),
                report.paths_seen,
                report.paths_kept,
                report.census_path.display(),
            ),
        );
    }

    Ok(StatusPayload {
        status: "ok".to_string(),
        phase: Some("done".to_string()),
        outputs: Some(json!({
            "mode": if report.dry_run { "nested_json_dry_run" } else { "nested_json_deidentification" },
            "dry_run": report.dry_run,
            "documents_examined": report.documents_examined,
            "documents_written": report.files_written,
            "documents_skipped": report.files_skipped.len(),
            "output_directory": report.output_dir.display().to_string(),
            "key_census": report.census_path.display().to_string(),
            "paths_seen": report.paths_seen,
            "paths_kept": report.paths_kept,
            "k_anonymity_applied": false,
            "hash_salt_created": report.salt_created,
            "key_material_files": report.key_files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        })),
        error: None,
        log_file: log_file.to_string(),
    })
}

/// Runs the FHIR Bundle de-identification flow and builds its status payload.
///
/// Reports the propagation sweep's hits and the dropped resources alongside the
/// census: both are places the policy changed the bundle beyond what its path
/// rules say, and a reviewer needs to see how often that happened.
fn run_fhir_bundle(
    log: &mut Logger,
    cfg: &RuntimeConfig,
    paths: &Paths,
    log_file: &str,
) -> Result<StatusPayload, PipelineError> {
    log.info(
        "fhir-bundle",
        &format!(
            "FHIR Bundle de-identification: {} path rule(s), {} code rule(s), default_action={:?} — \
             one bundle per patient, so the k-anonymity flow is not run",
            cfg.fhir_bundle.rules.len(),
            cfg.fhir_bundle.code_rules.len() + cfg.fhir_bundle.coding_rules.len(),
            cfg.fhir_bundle.default_action,
        ),
    );

    let mut fhir = cfg.fhir_bundle.clone();
    fhir.key_material_dir = PathBuf::from(&cfg.output_directory);
    fhir.output_root = paths.output_dir.clone();
    let report = fhir_bundle::run(&fhir, &paths.root)?;

    for (name, why) in &report.files_skipped {
        log.warn("fhir-bundle", &format!("skipped {name}: {why}"));
    }
    if report.salts_created > 0 {
        log.info(
            "fhir-bundle",
            &format!(
                "Generated {} new column salt(s) in {} ({} column(s) in total) — back it up with the run's \
                 other key material; later runs reuse it so ids and pseudonyms match this run's",
                report.salts_created,
                report.salt_path.display(),
                report.salt_columns,
            ),
        );
    }
    log.info(
        "fhir-bundle",
        &format!(
            "{}{} bundle(s) examined, {} written to {}; {} path(s) seen, {} released as-is; \
             {} resource(s) dropped by code rules, {} leaf value(s) suppressed by the propagation sweep — review {}",
            if report.dry_run { "DRY RUN — " } else { "" },
            report.documents_examined,
            report.files_written,
            report.output_dir.display(),
            report.paths_seen,
            report.paths_kept,
            report.resources_dropped,
            report.propagated,
            report.census_path.display(),
        ),
    );

    Ok(StatusPayload {
        status: "ok".to_string(),
        phase: Some("done".to_string()),
        outputs: Some(json!({
            "mode": if report.dry_run { "fhir_bundle_dry_run" } else { "fhir_bundle_deidentification" },
            "dry_run": report.dry_run,
            "documents_examined": report.documents_examined,
            "documents_written": report.files_written,
            "documents_skipped": report.files_skipped.len(),
            "output_directory": report.output_dir.display().to_string(),
            "key_census": report.census_path.display().to_string(),
            "paths_seen": report.paths_seen,
            "paths_kept": report.paths_kept,
            "resources_dropped": report.resources_dropped,
            "propagation_suppressed": report.propagated,
            "k_anonymity_applied": false,
            "hash_salts_created": report.salts_created,
            "hash_salt_columns": report.salt_columns,
        })),
        error: None,
        log_file: log_file.to_string(),
    })
}

/// Loads the anonymized CSV into the configured database sink, if there is one.
/// The files under `output/` are written and reported either way — the sink is
/// an additional destination, never a replacement for them.
fn push_to_sink(
    log: &mut Logger,
    cfg: &RuntimeConfig,
    final_output_path: &Path,
) -> Result<serde_json::Value, PipelineError> {
    match &cfg.output_sink {
        DataSink::None => Ok(serde_json::Value::Null),
        DataSink::Postgres(write) => {
            let summary = pg::write_from_csv(write, final_output_path, log)?;
            Ok(json!({
                "type": "postgres",
                "table": summary.table,
                "mode": summary.mode.as_str(),
                "rows_loaded": summary.rows,
                "column_count": summary.columns.len(),
            }))
        }
    }
}

/// Writes the anonymized result in whatever format the input arrived as —
/// `.xlsx` in, `.xlsx` out — alongside the flat CSV, which is always produced
/// and stays the canonical output in `status.json`.
///
/// This is unconditional: a caller that hands SKALD a workbook gets a workbook
/// back without having to ask for it. CSV input is a no-op (the CSV output
/// already matches) and logs why.
///
/// Unlike `restore_sheets` this is fatal on failure. A run given `.xlsx` is
/// expected to produce `.xlsx`, so quietly delivering only the CSV would hand a
/// downstream uploader the wrong artifact.
fn write_format_matched_output(
    log: &mut crate::pipeline::bootstrap::Logger,
    cfg: &crate::pipeline::bootstrap::RuntimeConfig,
    input_format: InputFormat,
    final_output_path: &Path,
    restored_workbook_path: Option<&str>,
) -> Result<Option<String>, PipelineError> {
    if input_format == InputFormat::Csv {
        log.info("output_format", "Input was CSV — output already matches, nothing to convert");
        return Ok(None);
    }
    // `restore_sheets` writes to the same `<output_path stem>.xlsx` this would,
    // and a workbook is exactly what match_input asks for — so reuse it rather
    // than overwriting the per-sheet layout with a flattened single sheet.
    if input_format == InputFormat::Excel
        && let Some(existing) = restored_workbook_path
    {
        log.info(
            "output_format",
            &format!("restore_sheets already wrote {existing} — format matched, keeping the per-sheet workbook"),
        );
        return Ok(Some(existing.to_string()));
    }

    let stem = Path::new(&cfg.output_path)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "generalized".to_string());

    match write_output_in_format(final_output_path, input_format, &stem)? {
        Some(path) => {
            log.info(
                "output_format",
                &format!("Input was {:?} — wrote matching output to {}", input_format, path.display()),
            );
            Ok(Some(path.display().to_string()))
        }
        None => Ok(None),
    }
}

/// If `cfg.restore_sheets` is set and a `SheetRestorePlan` was established for
/// this input (multi-sheet Excel joined via explicit `sheet_joins`), writes
/// the anonymized result back out as a multi-sheet `.xlsx` workbook mirroring
/// the original input sheets. Purely additive and non-fatal: on any failure
/// or inapplicable case (no plan, single-sheet plan) it logs why and returns
/// `None` — the primary anonymized CSV output is unaffected either way.
fn maybe_write_restored_workbook(
    log: &mut crate::pipeline::bootstrap::Logger,
    cfg: &crate::pipeline::bootstrap::RuntimeConfig,
    restore_plan: &Option<SheetRestorePlan>,
    output_dir_path: &Path,
    final_output_path: &Path,
) -> Option<String> {
    if !cfg.restore_sheets {
        return None;
    }
    let Some(plan) = restore_plan else {
        log.info(
            "restore_sheets",
            "restore_sheets=true but no sheet restore plan is available for this input \
             (not multi-sheet Excel joined via explicit sheet_joins) — skipping",
        );
        return None;
    };
    if plan.sheets.len() <= 1 {
        log.info("restore_sheets", "restore_sheets=true but input had only one sheet — nothing to split, skipping");
        return None;
    }

    let xlsx_name = Path::new(&cfg.output_path)
        .file_stem()
        .map(|s| format!("{}.xlsx", s.to_string_lossy()))
        .unwrap_or_else(|| "restored.xlsx".to_string());
    let xlsx_path = output_dir_path.join(xlsx_name);

    match write_restored_workbook(final_output_path, plan, &xlsx_path) {
        Ok(()) => {
            log.info("restore_sheets", &format!("Restored {} sheet(s) to {}", plan.sheets.len(), xlsx_path.display()));
            Some(xlsx_path.display().to_string())
        }
        Err(e) => {
            log.info("restore_sheets", &format!("Failed to write restored workbook: {e}"));
            None
        }
    }
}

/// Key-material files earlier versions wrote into the output directory.
const KEY_MATERIAL_FILES: &[&str] = &[
    "symmetric_keys.json",
    "fpe_encrypt_keys.json",
    "fpe_keys.json",
    "token_vault.json",
    crate::pipeline::preprocess::HASH_SALTS_FILE,
    crate::pipeline::preprocess::BLOCK_HASH_SALTS_FILE,
    "nested_json_salt.json",
    "nested_json_token_vault.json",
    "nested_json_symmetric_keys.json",
    "nested_json_fpe_encrypt_keys.json",
    "fhir_bundle_salts.json",
];

/// Refuses to run while key material sits in the release directory.
///
/// Before 4.0 the keys, salts and token vault were written next to the output.
/// Starting without them would silently generate fresh keys — breaking every
/// earlier pseudonym and ciphertext — and leave the old ones beside the next
/// release, so the operator is asked to move them instead.
fn refuse_key_material_in_output(output_dir: &Path, key_dir: &Path) -> Result<(), PipelineError> {
    let found: Vec<&str> = KEY_MATERIAL_FILES.iter().copied().filter(|f| output_dir.join(f).is_file()).collect();
    if found.is_empty() {
        return Ok(());
    }
    Err(crate::pipeline::bootstrap::validation(
        "KEY_MATERIAL_IN_OUTPUT",
        "Key material found in the output directory",
        &format!(
            "move {} from {} to {} (the key directory) and rerun; never ship them with a release",
            found.join(", "),
            output_dir.display(),
            key_dir.display()
        ),
    ))
}

/// Read the first `n` data rows from a CSV and return them as a JSON array
/// of objects keyed by column header. Returns an empty array on any error.
fn read_csv_sample(path: &str, n: usize) -> serde_json::Value {
    let Ok((headers, mut records)) = open_csv(Path::new(path)) else { return json!([]) };
    let mut rows = Vec::with_capacity(n);
    while rows.len() < n {
        let Ok(Some(values)) = records.next_record() else { break };
        let obj: serde_json::Map<String, serde_json::Value> = headers
            .iter()
            .enumerate()
            .map(|(i, h)| (h.clone(), serde_json::Value::String(values.get(i).cloned().unwrap_or_default())))
            .collect();
        rows.push(serde_json::Value::Object(obj));
    }
    serde_json::Value::Array(rows)
}

/// Concatenate chunk CSVs into a single output file (header from first chunk, data from all).
fn merge_chunks_to_output(chunks: &[std::path::PathBuf], out_path: &std::path::Path) -> Result<(), PipelineError> {
    use crate::pipeline::bootstrap::csv_row_to_line;
    use std::io::Write;
    let mut out = std::io::BufWriter::new(fs::File::create(out_path)?);
    let mut header_written = false;
    for chunk in chunks {
        let (header, mut records) = open_csv(chunk)?;
        if !header_written {
            writeln!(out, "{}", csv_row_to_line(&header))?;
            header_written = true;
        }
        while let Some(fields) = records.next_record_of_width(header.len())? {
            writeln!(out, "{}", csv_row_to_line(&fields))?;
        }
    }
    out.flush()?;
    Ok(())
}

/// Logs what each column technique did: counts per technique and column, never values.
fn log_preprocess_stats(log: &mut Logger, stats: &crate::pipeline::preprocess::PreprocessStats) {
    if stats.is_empty() {
        log.info("preprocessing", "Preprocessing complete — no column techniques configured");
        return;
    }
    log.info("preprocessing", "Preprocessing complete — values transformed per technique and column:");
    for (what, n) in stats {
        log.info("preprocessing", &format!("  {what:40} {n}"));
    }
}

/// What one QI's chosen level means, in words.
fn describe_level(qi: &QuasiIdentifierLite, level: i64) -> String {
    if let Some(h) = &qi.interval_hierarchy {
        let l = (level as usize).clamp(1, h.num_levels);
        return format!("interval level {l} of {} ({} interval(s))", h.num_levels, h.num_at(l));
    }
    if qi.is_categorical {
        let of = qi.categorical_levels.as_ref().map_or(String::new(), |c| format!(" of {}", c.num_levels));
        return if level <= 1 {
            format!("level 1{of} (original values)")
        } else {
            format!("level {level}{of} (hierarchy entry {})", level - 2)
        };
    }
    let range = (qi.max_value.unwrap_or(0.0).round() - qi.min_value.unwrap_or(0.0).floor() + 1.0) as i64;
    if level >= range {
        format!("one bin covering the whole range (width {level})")
    } else {
        format!("bins of width {level} starting at {}", qi.bin_origin())
    }
}

/// Min / median / mean / max class size from a size → count histogram.
fn class_size_stats(counts: &BTreeMap<i64, i64>) -> Option<(i64, i64, f64, i64)> {
    let classes: i64 = counts.values().sum();
    if classes == 0 {
        return None;
    }
    let records: i64 = counts.iter().map(|(size, c)| size * c).sum();
    let mut seen = 0;
    let mut median = 0;
    for (size, c) in counts {
        seen += c;
        if seen * 2 >= classes {
            median = *size;
            break;
        }
    }
    Some((*counts.keys().next()?, median, records as f64 / classes as f64, *counts.keys().next_back()?))
}

pub(crate) fn summary_json(cfg: &RuntimeConfig, s: &GeneralizationSummary) -> serde_json::Value {
    let stats = class_size_stats(&s.class_size_counts);
    json!({
        "k": cfg.k,
        "l": cfg.l_diversity.as_ref().map(|l| l.l),
        "sensitive_attributes": cfg.l_diversity.as_ref().map(|l| l.sensitive_attributes.clone()),
        "t_closeness": "not implemented",
        "suppression_limit": cfg.suppression_limit,
        "allowed_suppressions": allowed_suppressions(cfg.suppression_limit, s.total_records),
        "total_records": s.total_records,
        "equivalence_classes": s.num_equivalence_classes,
        "dm_star": s.dm_star,
        "class_size_min": stats.map(|x| x.0),
        "class_size_median": stats.map(|x| x.1),
        "class_size_mean": stats.map(|x| (x.2 * 100.0).round() / 100.0),
        "class_size_max": stats.map(|x| x.3),
        "classes_failing_k": s.classes_failing_k,
        "classes_failing_l": s.classes_failing_l,
        "suppressed_records": s.suppressed_records,
        "published_suppressed_records": s.published_suppressed_records,
        "removed_records": s.removed_records,
    })
}

/// One block with everything needed to judge a run's anonymisation.
fn log_run_summary(
    log: &mut Logger,
    cfg: &RuntimeConfig,
    qis: &[QuasiIdentifierLite],
    final_rf: &[i64],
    s: &GeneralizationSummary,
    search: Option<(usize, usize)>,
) {
    let t = "summary";
    log.info(t, "── Run summary ─────────────────────────────────────────────");
    log.info(
        t,
        &format!(
            "  records: {}   k = {}   suppression_limit = {} (allows {} record(s))",
            s.total_records,
            cfg.k,
            cfg.suppression_limit,
            allowed_suppressions(cfg.suppression_limit, s.total_records)
        ),
    );
    match &cfg.l_diversity {
        Some(l) => log.info(t, &format!("  l-diversity: l = {} on {}", l.l, l.sensitive_attributes.join(", "))),
        None => log.info(t, "  l-diversity: not configured"),
    }
    log.info(t, "  t-closeness: not implemented");
    match search {
        Some((lattice, evaluated)) => {
            log.info(t, &format!("  lattice: {lattice} node(s), {evaluated} evaluated by OLA-2 (the rest inferred)"))
        }
        None => log.info(t, "  lattice: not searched — generalization_node taken from the config"),
    }
    log.info(t, "  generalisation chosen:");
    for (qi, &level) in qis.iter().zip(final_rf) {
        log.info(t, &format!("    {:24} {}", qi.column_name, describe_level(qi, level)));
    }
    log.info(t, &format!("  equivalence classes published: {}", s.num_equivalence_classes));
    log.info(t, &format!("  DM* (sum of squared class sizes): {}", s.dm_star));
    if let Some((min, median, mean, max)) = class_size_stats(&s.class_size_counts) {
        log.info(t, &format!("  class size: min {min}, median {median}, mean {mean:.2}, max {max}"));
    }
    log.info(
        t,
        &format!("  classes below k: {}   classes failing l only: {}", s.classes_failing_k, s.classes_failing_l),
    );
    log.info(
        t,
        &format!(
            "  suppressed records: {} — published with '*': {}, removed: {}",
            s.suppressed_records, s.published_suppressed_records, s.removed_records
        ),
    );
    log.info(t, "────────────────────────────────────────────────────────────");
}

fn write_parameter_grid_table(grid: &[GridEntry], output_dir: &std::path::Path) {
    use std::fmt::Write as FmtWrite;

    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<6}  {:<6}  {:<24}  {:>14}  {:>6}  {:>10}  feasible",
        "k", "supp", "best_node", "dm_star", "ECs", "suppressed"
    );
    let _ = writeln!(out, "{}", "-".repeat(80));

    for e in grid {
        let node_str = format!("{:?}", e.best_node);
        let _ = writeln!(
            out,
            "{:<6}  {:<6.2}  {:<24}  {:>14}  {:>6}  {:>10}  {}",
            e.k,
            e.suppression_limit,
            node_str,
            e.dm_star,
            e.num_equivalence_classes,
            e.suppression_count,
            if e.feasible { "yes" } else { "no" }
        );
    }

    let path = output_dir.join("parameter_grid.txt");
    let _ = fs::write(path, out);
}

/// Log a compact diagnostic for a histogram: bucket count and size distribution.
///
/// `tag`   — log channel (e.g. "hist_diag")
/// `label` — human-readable label for this histogram (e.g. "Base histogram")
fn log_histogram_diagnostic(log: &mut crate::pipeline::bootstrap::Logger, tag: &str, label: &str, hist: &SparseHist) {
    if hist.is_empty() {
        log.info(tag, &format!("{label}: (empty)"));
        return;
    }

    let total: i64 = hist.values().sum();
    let min_c = hist.values().copied().min().unwrap_or(0);
    let max_c = hist.values().copied().max().unwrap_or(0);
    let mean_c = total as f64 / hist.len() as f64;

    // Bucket-size distribution bands
    let bands: &[(i64, i64, &str)] =
        &[(1, 1, "=1"), (2, 4, "2-4"), (5, 9, "5-9"), (10, 49, "10-49"), (50, 99, "50-99"), (100, i64::MAX, "100+")];
    let mut dist_parts: Vec<String> = Vec::new();
    for (lo, hi, label_band) in bands {
        let cnt = hist.values().filter(|&&v| v >= *lo && v <= *hi).count();
        if cnt > 0 {
            dist_parts.push(format!("{label_band}: {cnt}"));
        }
    }

    log.info(tag, &format!("── {label} ──"));
    log.info(
        tag,
        &format!("  buckets={}, total_records={}, min={}, max={}, mean={:.1}", hist.len(), total, min_c, max_c, mean_c),
    );
    log.info(tag, &format!("  size distribution: {}", dist_parts.join("  ")));
    // Bucket keys are deliberately not logged: they are value offsets and
    // domain positions, i.e. the quasi-identifier values of real records.
    log.info(tag, &format!("── end {label} ──"));
}
