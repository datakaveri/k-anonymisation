use crate::pipeline::anonymization::{
    build_quasi_identifiers, build_sparse_histogram, build_z_histogram, compute_equivalence_space,
    compute_k_optimal, compute_numerical_min_max, compute_parameter_grid, compute_z_weights,
    equivalence_class_stats, find_ola1_initial_ri, find_ola2_best_rf_detailed,
    find_ola2_best_rf_z_detailed, generalize_and_write_outputs, merge_histogram,
    merge_z_histogram, scan_chunks_for_flow, z_hist_to_sparse, GridEntry, QuasiIdentifierLite,
    SparseHist, ZHist,
};
use crate::pipeline::bootstrap::{
    available_ram_bytes, ensure_output_dir, find_first_json_config, parse_runtime_config,
    split_csv_file_by_ram, FlowMode, Logger, PipelineError, StatusPayload,
};
use crate::pipeline::multitabular::resolve_input_csv;
use crate::pipeline::preprocess::preprocess_chunks;
use serde_json::json;
use std::fs;
use std::path::Path;

pub fn run_pipeline(root: &Path) -> Result<StatusPayload, PipelineError> {
    let output_dir_path = root.join("output");
    let mut log = Logger::new(&output_dir_path);

    log.info("startup", "SKALD pipeline starting");

    log.info("config", "Searching for JSON config in config/");
    let config_path = find_first_json_config(&root.join("config"))?;
    log.info("config", &format!("Loaded config: {}", config_path.display()));
    let cfg = parse_runtime_config(&config_path)?;
    let pass = cfg.pass.clone();
    log.info("config", &format!(
        "pass={}, k={}, suppression_limit={:.3}",
        pass, cfg.k, cfg.suppression_limit
    ));

    // ── Input normalisation (CSV / JSON / multi-sheet Excel → single CSV) ────
    // data/ is mounted read-only in deployment, so JSON/Excel inputs are
    // normalised into chunks/ (read-write scratch) instead; a plain .csv
    // input is returned as-is, still pointing into data/.
    log.info("input", "Resolving input data format (csv/json/xlsx)");
    let input_csv = resolve_input_csv(&root.join("data"), &root.join("chunks"), &cfg.sheet_joins)?;

    // ── Chunking (all passes need the raw CSV split) ─────────────────────────
    log.info("chunking", "Splitting CSV into RAM-sized chunks");
    let (chunk_paths, rows_per_chunk) = split_csv_file_by_ram(&input_csv, &root.join("chunks"))?;
    log.info("chunking", &format!("{} chunk(s), ~{} rows/chunk", chunk_paths.len(), rows_per_chunk));

    // ── Preprocess-only path (no k-anonymity configured) ─────────────────────
    if !cfg.enable_k_anonymity {
        log.info("preprocessing", &format!(
            "k-anonymity disabled — preprocess-only: suppress={}, hash_salt={}, hash={}, mask={}, encrypt={}, charcloak={}, tokenize={}",
            cfg.suppress.len(), cfg.hashing_with_salt.len(), cfg.hashing_without_salt.len(),
            cfg.masking.len(), cfg.encrypt.len(), cfg.charcloak.len(),
            cfg.tokenization.len(),
        ));
        preprocess_chunks(&chunk_paths, &cfg)?;
        log.info("preprocessing", "Preprocessing complete");

        ensure_output_dir(&output_dir_path)?;
        let final_output_path = output_dir_path.join(&cfg.output_path);
        merge_chunks_to_output(&chunk_paths, &final_output_path)?;
        log.info("output", &format!("Preprocess-only output written to {}", final_output_path.display()));

        return Ok(StatusPayload {
            status: "success".to_string(),
            phase: Some("done".to_string()),
            outputs: Some(json!({
                "pass": "preprocess_only",
                "chunk_count": chunk_paths.len(),
                "final_output_path": final_output_path.display().to_string(),
                "sample_generalized_rows": read_csv_sample(&final_output_path.display().to_string(), 10),
            })),
            error: None,
            log_file: "output/pipeline.log".to_string(),
        });
    }

    // ── Preprocessing (pass2 and no_bounds only) ─────────────────────────────
    if pass != "pass1" {
        log.info("preprocessing", &format!(
            "Running preprocessing: suppress={}, hash_salt={}, hash={}, mask={}, encrypt={}, charcloak={}, tokenize={}",
            cfg.suppress.len(), cfg.hashing_with_salt.len(), cfg.hashing_without_salt.len(),
            cfg.masking.len(), cfg.encrypt.len(), cfg.charcloak.len(),
            cfg.tokenization.len(),
        ));
        preprocess_chunks(&chunk_paths, &cfg)?;
        log.info("preprocessing", "Preprocessing complete");
    }

    // ── Min/max scan ─────────────────────────────────────────────────────────
    log.info("min_max_scan", &format!("Computing min/max for {} numerical QI(s)", cfg.numerical_qis.len()));
    let numerical_cols = cfg.numerical_qis.iter().map(|q| q.column.clone()).collect::<Vec<_>>();
    let dynamic_min_max = compute_numerical_min_max(&chunk_paths, &numerical_cols)?;
    log.info("min_max_scan", &format!("Scanned {} column(s)", dynamic_min_max.len()));

    // ── Build QIs ────────────────────────────────────────────────────────────
    log.info("qi_building", &format!("Building QIs: {} numerical, {} categorical", cfg.numerical_qis.len(), cfg.categorical_qis.len()));
    let qis = build_quasi_identifiers(&cfg, &dynamic_min_max)?;
    let interval_qi_count = qis.iter().filter(|q| q.interval_hierarchy.is_some()).count();
    log.info("qi_building", &format!("{} QI(s) built ({} with interval constraints)", qis.len(), interval_qi_count));

    // ── Pre-scan: record count + categorical domains (needed for flow decision) ─
    log.info("pre_scan", "Scanning chunks for flow selection");
    let (n_approx, categorical_domains) = scan_chunks_for_flow(&chunk_paths, &qis)?;
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
        log.info("flow", &format!(
            "  {:20}  type={kind}  R_Qi={r_qi:.0}",
            qi.column_name
        ));
    }
    log.info("flow", &format!("  {}", "─".repeat(48)));
    log.info("flow", &format!(
        "  E (product)  = {e:.6e}"
    ));
    log.info("flow", &format!(
        "  N            = {n_approx}"
    ));
    log.info("flow", &format!(
        "  N·log₂N      = {n_log_n:.6e}"
    ));
    log.info("flow", &format!(
        "  N·log₂N {} E  →  {}",
        if n_log_n <= e { "≤" } else { ">" },
        if n_log_n <= e { "DIRECT eligible" } else { "ORIGINAL eligible" }
    ));
    log.info("flow", "───────────────────────────────────────────────────");

    let use_direct = match cfg.flow_mode {
        FlowMode::Auto     => n_log_n <= e,
        FlowMode::Original => false,
        FlowMode::Direct   => true,
    };
    let mode_label = match cfg.flow_mode {
        FlowMode::Auto     => "AUTO",
        FlowMode::Original => "ORIGINAL (forced)",
        FlowMode::Direct   => "DIRECT (forced)",
    };
    log.info("flow", &format!(
        "Flow selected: {}  [config flow_mode={}]",
        if use_direct { "DIRECT" } else { "ORIGINAL" },
        mode_label
    ));

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

    enum BaseHist { Sparse(SparseHist), Z(ZHist, Vec<i64>) }

    let (initial_ri, base, total_records) = if actual_use_direct {
        // DIRECT: RAM constraint log
        let ram = available_ram_bytes().unwrap_or(32_000_000);
        let needed = 16u64.saturating_mul(n_approx as u64);
        if needed > ram / 2 {
            log.info("histogram", &format!(
                "Warning: Z-histogram needs ~{}MB, RAM/2={}MB — proceed anyway (DIRECT forced)",
                needed / 1_000_000, ram / 2_000_000
            ));
        }
        log.info("z_enc", &format!(
            "Direct Z-histogram over {} chunk(s) — OLA-1 skipped", chunk_paths.len()
        ));
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
            log.info("z_enc", &format!(
                "  {:20}  {:>10}  {:>12}",
                qi.column_name, r_qi, weights[i]
            ));
        }
        log.info("z_enc", &format!("  {}", "─".repeat(46)));
        log.info("z_enc", &format!("  Z range: [0, {}]", weights[0] * {
            let r = if qis[0].is_categorical {
                categorical_domains.get(0).map(|d| d.len()).unwrap_or(1) as i64
            } else if let Some(h) = &qis[0].interval_hierarchy {
                h.num_at(1) as i64
            } else {
                let mn = qis[0].min_value.unwrap_or(0.0);
                let mx = qis[0].max_value.unwrap_or(0.0);
                (mx - mn + 1.0) as i64
            };
            r
        } - 1));

        let ri = vec![1i64; qis.len()];
        let (zh, n) = build_z_histogram(&chunk_paths, &qis, &categorical_domains, &weights)?;

        // ── Collapse stats ────────────────────────────────────────────────────
        // n raw Z values sorted → zh.len() unique buckets; compression = n/buckets
        let compression = if zh.len() > 0 { n as f64 / zh.len() as f64 } else { 1.0 };
        log.info("z_enc", &format!(
            "{} raw Z values → {} unique buckets (avg {:.1} records/bucket)",
            n, zh.len(), compression
        ));
        log.info("z_enc", &format!(
            "Z array: ~{}KB raw  →  ~{}KB collapsed  ({}× smaller)",
            n * 8 / 1024,
            zh.len() * 16 / 1024,
            if zh.len() > 0 { (n * 8) / (zh.len() as i64 * 16).max(1) } else { 1 }
        ));

        // ── Sample encode: show first 5 unique buckets decoded ────────────────
        log.info("z_enc", "── sample buckets (Z → u-vector → count) ──────────────");
        for &(z, count) in zh.iter().take(5) {
            // decode manually: u_i = z_remaining / W_i
            let mut rem = z;
            let u: Vec<i64> = weights.iter().map(|&w| { let ui = rem / w; rem -= ui * w; ui }).collect();
            // show original-scale values: v_i = u_i + min_i
            let v: Vec<String> = u.iter().enumerate().map(|(i, &ui)| {
                if qis[i].is_categorical {
                    categorical_domains[i].get(ui as usize).cloned().unwrap_or_else(|| format!("cat[{ui}]"))
                } else if qis[i].interval_hierarchy.is_some() {
                    format!("interval_idx={ui}")
                } else {
                    let mn = qis[i].min_value.unwrap_or(0.0) as i64;
                    format!("{}", mn + ui)
                }
            }).collect();
            log.info("z_enc", &format!(
                "  Z={:8}  u={:?}  v=({})  count={}",
                z, u, v.join(", "), count
            ));
        }
        if zh.len() > 5 {
            log.info("z_enc", &format!("  ... ({} more buckets)", zh.len() - 5));
        }
        log.info("z_enc", "── end sample ─────────────────────────────────────────");

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
        BaseHist::Z(zh, w) => z_hist_to_sparse(zh, w),
    };

    // ── Histogram diagnostic ─────────────────────────────────────────────────
    let diag_label = if actual_use_direct { "Base Z-histogram (decoded)" } else { "Base histogram" };
    log_histogram_diagnostic(&mut log, "hist_diag", diag_label, &base_sparse, 10);

    // ── Parameter grid (all passes) ──────────────────────────────────────────
    let parameter_grid = if cfg.compute_param_grid {
        log.info("parameter_grid", "Computing k × suppression_limit parameter grid");
        let grid = compute_parameter_grid(&qis, &base_sparse, &initial_ri, &cfg.size_factors, total_records);
        log.info("parameter_grid", &format!(
            "{} grid cells ({} feasible)",
            grid.len(),
            grid.iter().filter(|e| e.feasible).count()
        ));
        write_parameter_grid_table(&grid, &output_dir_path);
        grid
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
            log_file: "output/pipeline.log".to_string(),
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
    let ola2 = match &base {
        BaseHist::Z(zh, w) => find_ola2_best_rf_z_detailed(
            &qis, zh, w, &initial_ri, &cfg.size_factors, cfg.k, cfg.suppression_limit, total_records,
        )?,
        BaseHist::Sparse(h) => find_ola2_best_rf_detailed(
            &qis, h, &initial_ri, &cfg.size_factors, cfg.k, cfg.suppression_limit, total_records,
        )?,
    };
    let final_rf = ola2.best_rf.clone();
    let lowest_dm_star = ola2.lowest_dm_star;
    let num_equivalence_classes = ola2.num_equivalence_classes;
    log.info("ola2", &format!("Best RF: {:?}, DM*={}, ECs={}", final_rf, lowest_dm_star, num_equivalence_classes));

    // ── OLA-2 node trace (every directly evaluated node) ─────────────────────
    log.info("ola2_trace", &format!("{} nodes evaluated (others inferred via monotonicity)", ola2.node_trace.len()));
    log.info("ola2_trace", &format!("  {:30}  {:>10}  {:>14}  {:>5}  {}", "node", "suppressed", "dm_star", "ECs", "verdict"));
    log.info("ola2_trace", &format!("  {}", "─".repeat(75)));
    for t in &ola2.node_trace {
        log.info("ola2_trace", &format!(
            "  {:30}  {:>10}  {:>14}  {:>5}  {}",
            format!("{:?}", t.node),
            t.suppression_count,
            t.dm_star,
            t.num_equivalence_classes,
            if t.passes { "PASS ✓" } else { "FAIL ✗" }
        ));
    }
    log.info("ola2_trace", &format!("  {}", "─".repeat(75)));

    // ── Merged histogram at best RF ───────────────────────────────────────────
    let merged_sparse = match &base {
        BaseHist::Z(zh, w) => {
            let merged_z = merge_z_histogram(zh, &qis, w, &final_rf);
            z_hist_to_sparse(&merged_z, w)
        }
        BaseHist::Sparse(h) => merge_histogram(h, &qis, &final_rf),
    };
    let merged_label = if actual_use_direct {
        format!("Merged Z-histogram at best RF {:?}", final_rf)
    } else {
        format!("Merged histogram at best RF {:?}", final_rf)
    };
    log_histogram_diagnostic(&mut log, "hist_diag", &merged_label, &merged_sparse, 10);

    log.info("generalization", &format!("Generalizing and writing output to {}", output_dir_path.display()));
    generalize_and_write_outputs(&chunk_paths, &qis, &final_rf, cfg.k, &output_dir_path, &cfg.output_path, &cfg.categorical_hierarchies)?;
    log.info("generalization", "Output written");

    ensure_output_dir(&output_dir_path)?;
    let eq_stats = equivalence_class_stats(&base_sparse, &qis, &final_rf, cfg.k);
    fs::write(
        output_dir_path.join("equivalence_class_stats.json"),
        serde_json::to_string_pretty(&eq_stats)?,
    )?;
    fs::write(
        output_dir_path.join("top_ola2_nodes.json"),
        serde_json::to_string_pretty(&ola2.top_nodes)?,
    )?;

    log.info("output", "Equivalence class stats and top OLA-2 nodes written");
    log.info("startup", "Pipeline completed successfully");

    let final_output_path = if Path::new(&cfg.output_path).is_absolute() {
        cfg.output_path.clone()
    } else {
        output_dir_path.join(&cfg.output_path).display().to_string()
    };
    let sample_generalized_rows = read_csv_sample(&final_output_path, 10);

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
            "equivalence_class_stats": eq_stats,
            "top_ola2_nodes": ola2.top_nodes,
            "total_records": total_records,
            "final_output_path": final_output_path,
            "sample_generalized_rows": sample_generalized_rows,
            "parameter_grid": parameter_grid,
        })),
        error: None,
        log_file: "output/pipeline.log".to_string(),
    })
}

/// Read the first `n` data rows from a CSV and return them as a JSON array
/// of objects keyed by column header. Returns an empty array on any IO error.
fn read_csv_sample(path: &str, n: usize) -> serde_json::Value {
    use std::io::BufRead;
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return json!([]),
    };
    let mut lines = std::io::BufReader::new(file).lines();

    let header_line = match lines.next().and_then(|r| r.ok()) {
        Some(h) => h,
        None => return json!([]),
    };
    let headers: Vec<String> = header_line.split(',').map(|s| s.trim_matches('"').to_string()).collect();

    let mut rows = Vec::with_capacity(n);
    for line in lines.take(n) {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let values: Vec<&str> = line.split(',').collect();
        let obj: serde_json::Map<String, serde_json::Value> = headers
            .iter()
            .enumerate()
            .map(|(i, h)| {
                let v = values.get(i).copied().unwrap_or("").trim_matches('"').to_string();
                (h.clone(), serde_json::Value::String(v))
            })
            .collect();
        rows.push(serde_json::Value::Object(obj));
    }
    serde_json::Value::Array(rows)
}

/// Concatenate chunk CSVs into a single output file (header from first chunk, data from all).
fn merge_chunks_to_output(chunks: &[std::path::PathBuf], out_path: &std::path::Path) -> Result<(), PipelineError> {
    use std::io::{BufRead, Write};
    let mut out = std::io::BufWriter::new(fs::File::create(out_path).map_err(|e| {
        crate::pipeline::bootstrap::validation("IO_ERROR", &e.to_string(), "merge_chunks")
    })?);
    let mut header_written = false;
    for chunk in chunks {
        let f = match fs::File::open(chunk) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let mut lines = std::io::BufReader::new(f).lines();
        if let Some(Ok(header)) = lines.next() {
            if !header_written {
                writeln!(out, "{}", header).ok();
                header_written = true;
            }
        }
        for line in lines {
            if let Ok(l) = line {
                writeln!(out, "{}", l).ok();
            }
        }
    }
    Ok(())
}

fn write_parameter_grid_table(grid: &[GridEntry], output_dir: &std::path::Path) {
    use std::fmt::Write as FmtWrite;

    let mut out = String::new();
    let _ = writeln!(out, "{:<6}  {:<6}  {:<24}  {:>14}  {:>6}  {:>10}  {}",
        "k", "supp", "best_node", "dm_star", "ECs", "suppressed", "feasible");
    let _ = writeln!(out, "{}", "-".repeat(80));

    for e in grid {
        let node_str = format!("{:?}", e.best_node);
        let _ = writeln!(out, "{:<6}  {:<6.2}  {:<24}  {:>14}  {:>6}  {:>10}  {}",
            e.k, e.suppression_limit, node_str, e.dm_star,
            e.num_equivalence_classes, e.suppression_count,
            if e.feasible { "yes" } else { "no" });
    }

    let path = output_dir.join("parameter_grid.txt");
    let _ = fs::write(path, out);
}

/// Log a compact diagnostic for a histogram: bucket-size distribution and top-N buckets.
///
/// `tag`   — log channel (e.g. "hist_diag")
/// `label` — human-readable label for this histogram (e.g. "Base histogram")
/// `top_n` — how many top-by-count buckets to show
fn log_histogram_diagnostic(
    log: &mut crate::pipeline::bootstrap::Logger,
    tag: &str,
    label: &str,
    hist: &SparseHist,
    top_n: usize,
) {
    if hist.is_empty() {
        log.info(tag, &format!("{label}: (empty)"));
        return;
    }

    let total: i64 = hist.values().sum();
    let min_c = hist.values().copied().min().unwrap_or(0);
    let max_c = hist.values().copied().max().unwrap_or(0);
    let mean_c = total as f64 / hist.len() as f64;

    // Bucket-size distribution bands
    let bands: &[(i64, i64, &str)] = &[
        (1,  1,   "=1"),
        (2,  4,   "2-4"),
        (5,  9,   "5-9"),
        (10, 49,  "10-49"),
        (50, 99,  "50-99"),
        (100, i64::MAX, "100+"),
    ];
    let mut dist_parts: Vec<String> = Vec::new();
    for (lo, hi, label_band) in bands {
        let cnt = hist.values().filter(|&&v| v >= *lo && v <= *hi).count();
        if cnt > 0 {
            dist_parts.push(format!("{label_band}: {cnt}"));
        }
    }

    log.info(tag, &format!("── {label} ──"));
    log.info(tag, &format!("  buckets={}, total_records={}, min={}, max={}, mean={:.1}", hist.len(), total, min_c, max_c, mean_c));
    log.info(tag, &format!("  size distribution: {}", dist_parts.join("  ")));

    // Top-N buckets by count
    let mut sorted: Vec<(&Vec<i64>, i64)> = hist.iter().map(|(k, &v)| (k, v)).collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    log.info(tag, &format!("  top {} buckets (key_tuple → count):", top_n.min(sorted.len())));
    for (key, count) in sorted.iter().take(top_n) {
        log.info(tag, &format!("    {:?}  →  {}", key, count));
    }
    log.info(tag, &format!("── end {label} ──"));
}

