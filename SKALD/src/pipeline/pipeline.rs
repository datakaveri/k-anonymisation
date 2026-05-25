use crate::pipeline::anonymization::{
    build_quasi_identifiers, build_sparse_histogram, compute_k_optimal, compute_numerical_min_max,
    compute_parameter_grid, equivalence_class_stats, find_ola1_initial_ri,
    find_ola2_best_rf_detailed, generalize_and_write_outputs, GridEntry,
};
use crate::pipeline::bootstrap::{
    available_ram_bytes, ensure_output_dir, find_first_json_config, parse_runtime_config,
    split_csv_by_ram, Logger, PipelineError, StatusPayload,
};
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

    // ── Chunking (all passes need the raw CSV split) ─────────────────────────
    log.info("chunking", "Splitting CSV into RAM-sized chunks");
    let (chunk_paths, rows_per_chunk) = split_csv_by_ram(&root.join("data"), &root.join("chunks"))?;
    log.info("chunking", &format!("{} chunk(s), ~{} rows/chunk", chunk_paths.len(), rows_per_chunk));

    // ── Preprocess-only path (no k-anonymity configured) ─────────────────────
    if !cfg.enable_k_anonymity {
        log.info("preprocessing", &format!(
            "k-anonymity disabled — preprocess-only: suppress={}, hash_salt={}, hash={}, mask={}, encrypt={}, charcloak={}, tokenize={}, fpe={}",
            cfg.suppress.len(), cfg.hashing_with_salt.len(), cfg.hashing_without_salt.len(),
            cfg.masking.len(), cfg.encrypt.len(), cfg.charcloak.len(),
            cfg.tokenization.len(), cfg.fpe.len(),
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
            "Running preprocessing: suppress={}, hash_salt={}, hash={}, mask={}, encrypt={}, charcloak={}, tokenize={}, fpe={}",
            cfg.suppress.len(), cfg.hashing_with_salt.len(), cfg.hashing_without_salt.len(),
            cfg.masking.len(), cfg.encrypt.len(), cfg.charcloak.len(),
            cfg.tokenization.len(), cfg.fpe.len(),
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

    // ── OLA-1 ────────────────────────────────────────────────────────────────
    let max_eq = (available_ram_bytes().unwrap_or(32_000_000) / 32) as i64;
    log.info("ola1", &format!("OLA-1: finding initial RI (max_eq={})", max_eq));
    let initial_ri = find_ola1_initial_ri(&qis, chunk_paths.len() as i64, max_eq, &cfg.size_factors)?;
    log.info("ola1", &format!("Initial RI: {:?}", initial_ri));

    // ── Sparse histogram ─────────────────────────────────────────────────────
    log.info("histogram", &format!("Building sparse histogram over {} chunk(s)", chunk_paths.len()));
    let (base_hist, total_records) = build_sparse_histogram(&chunk_paths, &qis, &initial_ri)?;
    log.info("histogram", &format!("{} total records, {} histogram buckets", total_records, base_hist.len()));

    // ── Parameter grid (all passes) ──────────────────────────────────────────
    log.info("parameter_grid", "Computing k × suppression_limit parameter grid");
    let parameter_grid = compute_parameter_grid(&qis, &base_hist, &initial_ri, &cfg.size_factors, total_records);
    log.info("parameter_grid", &format!(
        "{} grid cells ({} feasible)",
        parameter_grid.len(),
        parameter_grid.iter().filter(|e| e.feasible).count()
    ));
    write_parameter_grid_table(&parameter_grid, &output_dir_path);

    // ── Pass 1: compute k_optimal and return ─────────────────────────────────
    if pass == "pass1" {
        let k_optimal = compute_k_optimal(&qis, &base_hist, cfg.suppression_limit, total_records);
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
                "histogram_buckets": base_hist.len(),
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
    let ola2 = find_ola2_best_rf_detailed(
        &qis, &base_hist, &initial_ri, &cfg.size_factors, cfg.k, cfg.suppression_limit, total_records,
    )?;
    let final_rf = ola2.best_rf.clone();
    let lowest_dm_star = ola2.lowest_dm_star;
    let num_equivalence_classes = ola2.num_equivalence_classes;
    log.info("ola2", &format!("Best RF: {:?}, DM*={}, ECs={}", final_rf, lowest_dm_star, num_equivalence_classes));

    log.info("generalization", &format!("Generalizing and writing output to {}", output_dir_path.display()));
    generalize_and_write_outputs(&chunk_paths, &qis, &final_rf, cfg.k, &output_dir_path, &cfg.output_path)?;
    log.info("generalization", "Output written");

    ensure_output_dir(&output_dir_path)?;
    let eq_stats = equivalence_class_stats(&base_hist, &qis, &final_rf, cfg.k);
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
            "max_equivalence_classes": max_eq,
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

