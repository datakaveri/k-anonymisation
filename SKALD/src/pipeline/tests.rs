use super::anonymization::{
    GRID_K_VALUES, GRID_SUPPRESSION_LIMITS, QuasiIdentifierLite, attach_categorical_levels, build_categorical_levels,
    build_direct_histogram, build_interval_hierarchy, build_quasi_identifiers, build_sparse_histogram,
    build_z_histogram, compute_equivalence_space, compute_numerical_min_max, compute_parameter_grid,
    compute_parameter_grid_for, compute_parameter_grid_z, compute_z_weights, find_ola1_initial_ri, find_ola2_best_rf,
    find_ola2_best_rf_detailed, find_ola2_best_rf_z_detailed, generalize_and_write_outputs, merge_histogram,
    merge_z_histogram, scan_chunks_for_flow, z_hist_to_sparse,
};
use super::bootstrap::{
    FlowMode, HierarchyMap, PipelineError, clear_output_dir, clear_scratch_dir, csv_quote_field, csv_row_to_line,
    find_first_json_config, parse_runtime_config, split_csv_by_ram, split_csv_line_basic, stale_output_files,
};
use super::multitabular::{InputFormat, resolve_input_csv, write_output_in_format};
use super::pipeline::run_pipeline;
use super::preprocess::preprocess_chunks;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn mk_temp_dir(prefix: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).expect("time error").as_nanos();
    p.push(format!("{prefix}_{nanos}"));
    fs::create_dir_all(&p).expect("create temp dir");
    p
}

#[test]
fn parse_runtime_config_reads_basic_fields() {
    let d = mk_temp_dir("skald_cfg_parse");
    let cfg_path = d.join("cfg.json");
    fs::write(
        &cfg_path,
        r#"{
          "data_type":"T",
          "T":{
            "output_path":"x.csv",
            "output_directory":"out",
            "suppression_limit":0.2,
            "k_anonymize":{"k":3},
            "suppress":["drop_me"],
            "quasi_identifiers":{
              "numerical":[{"column":"Age","encode":false,"scale":false,"s":0,"type":"int"}],
              "categorical":[{"column":"Gender"}]
            },
            "size":{"Age":2}
          }
        }"#,
    )
    .expect("write cfg");

    let cfg = parse_runtime_config(&cfg_path).expect("parse cfg");
    assert_eq!(cfg.output_path, "x.csv");
    assert_eq!(cfg.output_directory, "out");
    assert_eq!(cfg.k, 3);
    assert_eq!(cfg.suppress, vec!["drop_me".to_string()]);
    assert_eq!(cfg.numerical_qis.len(), 1);
    assert_eq!(cfg.categorical_qis, vec!["Gender".to_string()]);

    let _ = fs::remove_dir_all(d);
}

#[test]
fn parse_runtime_config_reads_free_text_handoff() {
    let d = mk_temp_dir("skald_free_text_cfg");
    let cfg_path = d.join("cfg.json");
    fs::write(
        &cfg_path,
        r#"{
          "data_type":"T",
          "T":{
            "output_path":"x.csv",
            "free_text_anonymization":{
              "enabled":true,
              "columns":["Narrative"],
              "staged_input_path":"work/sanitized.csv"
            }
          }
        }"#,
    )
    .expect("write cfg");

    let cfg = parse_runtime_config(&cfg_path).expect("parse cfg");
    assert!(cfg.free_text_anonymization.enabled);
    assert_eq!(cfg.free_text_anonymization.columns, vec!["Narrative".to_string()]);
    assert_eq!(
        cfg.free_text_anonymization.staged_input_path.as_ref().and_then(|p| p.to_str()),
        Some("work/sanitized.csv")
    );

    let _ = fs::remove_dir_all(d);
}

#[test]
fn split_csv_by_ram_creates_multiple_chunks() {
    let root = mk_temp_dir("skald_chunk_split");
    let data = root.join("data");
    let chunks = root.join("chunks");
    fs::create_dir_all(&data).expect("data dir");

    let mut content = String::from("a,b\n");
    for i in 0..2505 {
        content.push_str(&format!("{i},{i}\n"));
    }
    fs::write(data.join("only.csv"), content).expect("write csv");

    let (out, _rows_per_chunk) = split_csv_by_ram(&data, &chunks).expect("split");
    assert!(!out.is_empty());
    assert!(chunks.join("chunk_1.csv").exists());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn preprocess_suppress_removes_column() {
    let root = mk_temp_dir("skald_preprocess_suppress");
    let chunk = root.join("chunk_1.csv");
    fs::write(&chunk, "a,b,c\n1,2,3\n").expect("write chunk");

    let cfg_path = root.join("cfg.json");
    fs::write(
        &cfg_path,
        r#"{"data_type":"T","T":{"output_path":"x.csv","output_directory":"output","suppress":["b"],"k_anonymize":{"k":2},"quasi_identifiers":{"numerical":[{"column":"a","encode":false,"scale":false,"s":0,"type":"int"}],"categorical":[]}}}"#,
    )
    .expect("write cfg");

    let cfg = parse_runtime_config(&cfg_path).expect("parse");
    preprocess_chunks(std::slice::from_ref(&chunk), &cfg).expect("preprocess");
    let after = fs::read_to_string(&chunk).expect("read chunk");
    assert!(after.lines().next().unwrap_or("").starts_with("a,c"));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn generalize_marks_only_qi_columns() {
    let root = mk_temp_dir("skald_generalize_mark_qi");
    let chunks = root.join("chunks");
    let outdir = root.join("output");
    fs::create_dir_all(&chunks).expect("chunks dir");
    fs::create_dir_all(&outdir).expect("output dir");

    let chunk1 = chunks.join("chunk_1.csv");
    fs::write(&chunk1, "Age,Name\n20,Alice\n20,Bob\n21,Carol\n").expect("write chunk");

    let qis = vec![QuasiIdentifierLite {
        column_name: "Age".to_string(),
        is_categorical: false,
        min_value: Some(20.0),
        max_value: Some(21.0),
        interval_hierarchy: None,
        categorical_levels: None,
    }];

    generalize_and_write_outputs(std::slice::from_ref(&chunk1), &qis, &[1], 2, &outdir, "final.csv", &HashMap::new())
        .expect("generalize");

    // Carol's class has 1 < k = 2 records, so she is suppressed — and since she
    // would be the only `*` row, publishing her would single her out: she is
    // removed instead. Alice and Bob are published with their real class.
    let body = fs::read_to_string(outdir.join("final.csv")).expect("read final");
    assert_eq!(body, "Age,Name\n[20-20],Alice\n[20-20],Bob\n");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn run_pipeline_smoke_success() {
    let root = mk_temp_dir("skald_run_smoke");
    fs::create_dir_all(root.join("config")).expect("config dir");
    fs::create_dir_all(root.join("data")).expect("data dir");

    fs::write(
        root.join("config").join("pipeline.json"),
        r#"{
          "data_type":"T",
          "T":{
            "output_path":"final.csv",
            "output_directory":"output",
            "suppression_limit":1.0,
            "k_anonymize":{"k":2},
            "quasi_identifiers":{
              "numerical":[{"column":"Age","encode":false,"scale":false,"s":0,"type":"int"}],
              "categorical":[]
            },
            "size":{"Age":2}
          }
        }"#,
    )
    .expect("write cfg");

    fs::write(root.join("data").join("d.csv"), "Age,Name\n20,Alice\n20,Bob\n21,Carol\n").expect("write data");

    let status = run_pipeline(&root).expect("run pipeline");
    assert_eq!(status.status, "success");

    let outputs = status.outputs.expect("outputs");
    let out_path = outputs.get("final_output_path").and_then(|v| v.as_str()).expect("final output path");
    assert!(PathBuf::from(out_path).exists());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn run_pipeline_can_consume_staged_input_file() {
    let root = mk_temp_dir("skald_staged_input");
    fs::create_dir_all(root.join("config")).expect("config dir");
    fs::create_dir_all(root.join("chunks")).expect("chunks dir");
    fs::create_dir_all(root.join("work")).expect("work dir");

    fs::write(
        root.join("work").join("sanitized.csv"),
        "Age,Narrative\n20,redacted one\n20,redacted two\n21,redacted three\n",
    )
    .expect("write staged input");

    fs::write(
        root.join("config").join("pipeline.json"),
        r#"{
          "data_type":"T",
          "T":{
            "output_path":"final.csv",
            "output_directory":"output",
            "suppression_limit":1.0,
            "k_anonymize":{"k":2},
            "free_text_anonymization":{
              "enabled":true,
              "columns":["Narrative"],
              "staged_input_path":"work/sanitized.csv"
            },
            "quasi_identifiers":{
              "numerical":[{"column":"Age","encode":false,"scale":false,"s":0,"type":"int"}],
              "categorical":[]
            },
            "size":{"Age":2}
          }
        }"#,
    )
    .expect("write cfg");

    let status = run_pipeline(&root).expect("run pipeline");
    assert_eq!(status.status, "success");

    let outputs = status.outputs.expect("outputs");
    let csv = outputs.get("final_output_path").and_then(|v| v.as_str()).expect("final output");
    assert!(PathBuf::from(csv).exists());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn ola1_scales_initial_ri_when_estimated_eq_too_high() {
    let qis = vec![
        QuasiIdentifierLite {
            column_name: "Age".to_string(),
            is_categorical: false,
            min_value: Some(0.0),
            max_value: Some(99.0),
            interval_hierarchy: None,
            categorical_levels: None,
        },
        QuasiIdentifierLite {
            column_name: "Zip".to_string(),
            is_categorical: false,
            min_value: Some(10000.0),
            max_value: Some(10099.0),
            interval_hierarchy: None,
            categorical_levels: None,
        },
    ];
    let mut size = HashMap::new();
    size.insert("Age".to_string(), 2);
    size.insert("Zip".to_string(), 2);
    let ri = find_ola1_initial_ri(&qis, 1, 400, &size).expect("ola1");
    assert_eq!(ri.len(), 2);
    assert!(ri[0] > 1 || ri[1] > 1);
}

#[test]
fn ola2_picks_rf_that_meets_suppression_limit() {
    let qis = vec![QuasiIdentifierLite {
        column_name: "Age".to_string(),
        is_categorical: false,
        min_value: Some(0.0),
        max_value: Some(3.0),
        interval_hierarchy: None,
        categorical_levels: None,
    }];

    let mut hist = HashMap::new();
    hist.insert(vec![0], 1);
    hist.insert(vec![1], 1);
    hist.insert(vec![2], 1);
    hist.insert(vec![3], 1);

    let mut size = HashMap::new();
    size.insert("Age".to_string(), 2);

    let (rf, _dm, _eq) = find_ola2_best_rf(&qis, &hist, &[1], &size, 2, 0.0, 4).expect("ola2");
    assert_eq!(rf, vec![2]);
}

#[test]
fn finds_first_json_config() {
    let root = mk_temp_dir("skald_cfg_find");
    fs::create_dir_all(&root).expect("dir");
    fs::write(root.join("b.json"), "{}").expect("write b");
    fs::write(root.join("a.json"), "{}").expect("write a");
    let p = find_first_json_config(&root).expect("find cfg");
    assert_eq!(p.file_name().and_then(|n| n.to_str()), Some("a.json"));
    let _ = fs::remove_dir_all(root);
}

// ── Hybrid flow validation tests ──────────────────────────────────────────────

/// Helper: write a single-chunk CSV and return its path.
fn write_chunk(dir: &Path, content: &str) -> PathBuf {
    let p = dir.join("chunk_1.csv");
    fs::write(&p, content).expect("write chunk");
    p
}

/// Both `build_sparse_histogram` (with ri=[1,1]) and `build_direct_histogram`
/// must produce identical bucket counts for the same dataset.
#[test]
fn direct_and_original_histograms_are_equivalent() {
    let d = mk_temp_dir("skald_hist_equiv");
    let chunk =
        write_chunk(&d, "Age,Zip\n20,10001\n20,10002\n21,10001\n21,10002\n22,10003\n22,10003\n23,10000\n23,10000\n");
    let chunks = vec![chunk];

    let qis = vec![
        QuasiIdentifierLite {
            column_name: "Age".to_string(),
            is_categorical: false,
            min_value: Some(20.0),
            max_value: Some(23.0),
            interval_hierarchy: None,
            categorical_levels: None,
        },
        QuasiIdentifierLite {
            column_name: "Zip".to_string(),
            is_categorical: false,
            min_value: Some(10000.0),
            max_value: Some(10003.0),
            interval_hierarchy: None,
            categorical_levels: None,
        },
    ];

    let (_n, cat_domains) = scan_chunks_for_flow(&chunks, &qis).expect("scan");

    let ri_1 = vec![1i64, 1i64];
    let (hist_orig, n_orig) = build_sparse_histogram(&chunks, &qis, &ri_1, &cat_domains).expect("build_sparse");
    let (hist_direct, n_direct) = build_direct_histogram(&chunks, &qis, &cat_domains).expect("build_direct");

    assert_eq!(n_orig, n_direct, "record counts must match");
    assert_eq!(hist_orig.len(), hist_direct.len(), "bucket counts must match");

    // Every key present in original must have the same count in direct
    for (k, v) in &hist_orig {
        let dv = hist_direct.get(k).copied().unwrap_or(0);
        assert_eq!(*v, dv, "count mismatch for key {:?}", k);
    }

    let _ = fs::remove_dir_all(d);
}

/// OLA-2 produces the same best_rf, dm_star, and equivalence class count
/// regardless of which flow was used to build the histogram (as long as both
/// histograms have the same semantic granularity).
#[test]
fn ola2_result_is_identical_for_both_flows() {
    let d = mk_temp_dir("skald_ola2_equiv");
    let chunk = write_chunk(&d, "Age,Zip\n20,100\n20,101\n21,100\n21,101\n22,102\n22,102\n23,103\n23,103\n");
    let chunks = vec![chunk];

    let qis = vec![
        QuasiIdentifierLite {
            column_name: "Age".to_string(),
            is_categorical: false,
            min_value: Some(20.0),
            max_value: Some(23.0),
            interval_hierarchy: None,
            categorical_levels: None,
        },
        QuasiIdentifierLite {
            column_name: "Zip".to_string(),
            is_categorical: false,
            min_value: Some(100.0),
            max_value: Some(103.0),
            interval_hierarchy: None,
            categorical_levels: None,
        },
    ];

    let mut size = HashMap::new();
    size.insert("Age".to_string(), 2);
    size.insert("Zip".to_string(), 2);

    let (_n, cat_domains) = scan_chunks_for_flow(&chunks, &qis).expect("scan");

    let ri = vec![1i64, 1i64];
    let (hist_orig, n_orig) = build_sparse_histogram(&chunks, &qis, &ri, &cat_domains).expect("orig");
    let (hist_direct, n_direct) = build_direct_histogram(&chunks, &qis, &cat_domains).expect("direct");

    let ola2_orig = find_ola2_best_rf_detailed(&qis, &hist_orig, &ri, &size, 2, 0.0, n_orig).expect("ola2 orig");
    let ola2_direct =
        find_ola2_best_rf_detailed(&qis, &hist_direct, &ri, &size, 2, 0.0, n_direct).expect("ola2 direct");

    assert_eq!(ola2_orig.best_rf, ola2_direct.best_rf, "best_rf must match");
    assert_eq!(ola2_orig.lowest_dm_star, ola2_direct.lowest_dm_star, "dm_star must match");
    assert_eq!(ola2_orig.num_equivalence_classes, ola2_direct.num_equivalence_classes, "EC count must match");

    let _ = fs::remove_dir_all(d);
}

/// compute_equivalence_space for a single numerical QI [0,99] = 100.
#[test]
fn equivalence_space_numerical() {
    let qis = vec![QuasiIdentifierLite {
        column_name: "Age".to_string(),
        is_categorical: false,
        min_value: Some(0.0),
        max_value: Some(99.0),
        interval_hierarchy: None,
        categorical_levels: None,
    }];
    let cat_domains: Vec<Vec<String>> = vec![vec![]];
    let e = compute_equivalence_space(&qis, &cat_domains);
    assert!((e - 100.0).abs() < 1e-9, "expected 100, got {}", e);
}

/// compute_equivalence_space for a single categorical QI with 5 values = 5.
#[test]
fn equivalence_space_categorical() {
    let qis = vec![QuasiIdentifierLite {
        column_name: "Gender".to_string(),
        is_categorical: true,
        min_value: None,
        max_value: None,
        interval_hierarchy: None,
        categorical_levels: None,
    }];
    let cat_domains = vec![vec!["M".to_string(), "F".to_string(), "X".to_string(), "NB".to_string(), "U".to_string()]];
    let e = compute_equivalence_space(&qis, &cat_domains);
    assert!((e - 5.0).abs() < 1e-9, "expected 5, got {}", e);
}

/// flow_mode=ORIGINAL is parsed from config and reported as Original variant.
#[test]
fn flow_mode_parsed_from_config() {
    let d = mk_temp_dir("skald_flow_parse");
    let cfg_path = d.join("cfg.json");
    fs::write(
        &cfg_path,
        r#"{"data_type":"T","T":{"flow_mode":"ORIGINAL","k_anonymize":{"k":2},"quasi_identifiers":{"numerical":[{"column":"Age","type":"int","encode":false,"scale":false,"s":0}]}}}"#,
    ).expect("write cfg");

    let cfg = parse_runtime_config(&cfg_path).expect("parse");
    assert_eq!(cfg.flow_mode, FlowMode::Original);
    let _ = fs::remove_dir_all(d);
}

/// flow_mode=DIRECT is parsed correctly.
#[test]
fn flow_mode_direct_parsed() {
    let d = mk_temp_dir("skald_flow_direct");
    let cfg_path = d.join("cfg.json");
    fs::write(
        &cfg_path,
        r#"{"data_type":"T","T":{"flow_mode":"direct","k_anonymize":{"k":2},"quasi_identifiers":{"numerical":[{"column":"Age","type":"int","encode":false,"scale":false,"s":0}]}}}"#,
    ).expect("write cfg");

    let cfg = parse_runtime_config(&cfg_path).expect("parse");
    assert_eq!(cfg.flow_mode, FlowMode::Direct);
    let _ = fs::remove_dir_all(d);
}

// ── Z-encoding tests ──────────────────────────────────────────────────────────

/// compute_z_weights: numeric QIs reserve Z coordinate 0 for cells with no
/// bin, so ranges 3 and 4 become radices 4 and 5, and the weights [5, 1].
#[test]
fn z_weights_correct_two_qi() {
    let qis = vec![
        QuasiIdentifierLite {
            column_name: "A".to_string(),
            is_categorical: false,
            min_value: Some(0.0),
            max_value: Some(2.0),
            interval_hierarchy: None,
            categorical_levels: None,
        },
        QuasiIdentifierLite {
            column_name: "B".to_string(),
            is_categorical: false,
            min_value: Some(0.0),
            max_value: Some(3.0),
            interval_hierarchy: None,
            categorical_levels: None,
        },
    ];
    let cat_domains: Vec<Vec<String>> = vec![vec![], vec![]];
    let w = compute_z_weights(&qis, &cat_domains).expect("weights");
    // radix_A = 3+1, radix_B = 4+1  →  W_A = 5 (product of radices after A), W_B = 1
    assert_eq!(w, vec![5, 1]);
}

/// Z-histogram: two identical records produce one bucket with count 2.
#[test]
fn z_histogram_deduplicates_equal_records() {
    let d = mk_temp_dir("skald_z_dedup");
    let chunk = write_chunk(&d, "Age,Zip\n20,100\n20,100\n21,101\n");
    let chunks = vec![chunk];
    let qis = vec![
        QuasiIdentifierLite {
            column_name: "Age".to_string(),
            is_categorical: false,
            min_value: Some(20.0),
            max_value: Some(21.0),
            interval_hierarchy: None,
            categorical_levels: None,
        },
        QuasiIdentifierLite {
            column_name: "Zip".to_string(),
            is_categorical: false,
            min_value: Some(100.0),
            max_value: Some(101.0),
            interval_hierarchy: None,
            categorical_levels: None,
        },
    ];
    let (_n, cat_domains) = scan_chunks_for_flow(&chunks, &qis).expect("scan");
    let weights = compute_z_weights(&qis, &cat_domains).expect("weights");
    let (zh, n) = build_z_histogram(&chunks, &qis, &cat_domains, &weights).expect("z_hist");

    assert_eq!(n, 3);
    // Numeric coordinates are offset+1 (0 = no bin), radices 3 and 3, weights [3, 1].
    // (20,100) → u=(1,1) → Z = 1*3 + 1 = 4, appears twice
    // (21,101) → u=(2,2) → Z = 2*3 + 2 = 8, appears once
    assert_eq!(zh.len(), 2, "two distinct buckets");
    let (z4, c4) = zh[0];
    let (z8, c8) = zh[1];
    assert_eq!(z4, 4);
    assert_eq!(c4, 2);
    assert_eq!(z8, 8);
    assert_eq!(c8, 1);

    let _ = fs::remove_dir_all(d);
}

/// z_hist_to_sparse produces keys matching what build_direct_histogram would produce.
#[test]
fn z_hist_to_sparse_matches_direct_histogram() {
    let d = mk_temp_dir("skald_z_sparse_match");
    let chunk = write_chunk(&d, "Age,Zip\n20,100\n20,101\n21,100\n21,101\n22,102\n22,102\n");
    let chunks = vec![chunk];
    let qis = vec![
        QuasiIdentifierLite {
            column_name: "Age".to_string(),
            is_categorical: false,
            min_value: Some(20.0),
            max_value: Some(22.0),
            interval_hierarchy: None,
            categorical_levels: None,
        },
        QuasiIdentifierLite {
            column_name: "Zip".to_string(),
            is_categorical: false,
            min_value: Some(100.0),
            max_value: Some(102.0),
            interval_hierarchy: None,
            categorical_levels: None,
        },
    ];
    let (_n, cat_domains) = scan_chunks_for_flow(&chunks, &qis).expect("scan");
    let weights = compute_z_weights(&qis, &cat_domains).expect("weights");

    let (zh, n_z) = build_z_histogram(&chunks, &qis, &cat_domains, &weights).expect("z_hist");
    let (direct, n_d) = build_direct_histogram(&chunks, &qis, &cat_domains).expect("direct");

    assert_eq!(n_z, n_d);
    let sparse = z_hist_to_sparse(&zh, &qis, &weights);
    assert_eq!(sparse.len(), direct.len(), "bucket count must match");
    for (k, v) in &direct {
        let sv = sparse.get(k).copied().unwrap_or(0);
        assert_eq!(*v, sv, "count mismatch for key {:?}", k);
    }
    let _ = fs::remove_dir_all(d);
}

/// merge_z_histogram produces the same result as merge_histogram on equivalent data.
#[test]
fn merge_z_histogram_matches_merge_sparse() {
    let d = mk_temp_dir("skald_z_merge");
    let chunk = write_chunk(&d, "Age,Zip\n20,100\n20,101\n21,100\n21,101\n22,102\n22,102\n23,103\n23,103\n");
    let chunks = vec![chunk];
    let qis = vec![
        QuasiIdentifierLite {
            column_name: "Age".to_string(),
            is_categorical: false,
            min_value: Some(20.0),
            max_value: Some(23.0),
            interval_hierarchy: None,
            categorical_levels: None,
        },
        QuasiIdentifierLite {
            column_name: "Zip".to_string(),
            is_categorical: false,
            min_value: Some(100.0),
            max_value: Some(103.0),
            interval_hierarchy: None,
            categorical_levels: None,
        },
    ];
    let (_n, cat_domains) = scan_chunks_for_flow(&chunks, &qis).expect("scan");
    let weights = compute_z_weights(&qis, &cat_domains).expect("weights");

    let (zh, _) = build_z_histogram(&chunks, &qis, &cat_domains, &weights).expect("z_hist");
    let sparse = z_hist_to_sparse(&zh, &qis, &weights);

    let node = vec![2i64, 2i64];
    let merged_z = z_hist_to_sparse(&merge_z_histogram(&zh, &qis, &weights, &node), &qis, &weights);

    use super::anonymization::merge_histogram;
    let merged_s = merge_histogram(&sparse, &qis, &node);

    assert_eq!(merged_z.len(), merged_s.len(), "merged bucket count must match");
    for (k, v) in &merged_s {
        let zv = merged_z.get(k).copied().unwrap_or(0);
        assert_eq!(*v, zv, "count mismatch after merge at {:?}", k);
    }
    let _ = fs::remove_dir_all(d);
}

/// OLA-2 Z and OLA-2 Sparse produce identical best_rf, dm_star, ECs.
#[test]
fn ola2_z_result_matches_sparse_result() {
    let d = mk_temp_dir("skald_ola2_z_match");
    let chunk = write_chunk(&d, "Age,Zip\n20,100\n20,101\n21,100\n21,101\n22,102\n22,102\n23,103\n23,103\n");
    let chunks = vec![chunk];
    let qis = vec![
        QuasiIdentifierLite {
            column_name: "Age".to_string(),
            is_categorical: false,
            min_value: Some(20.0),
            max_value: Some(23.0),
            interval_hierarchy: None,
            categorical_levels: None,
        },
        QuasiIdentifierLite {
            column_name: "Zip".to_string(),
            is_categorical: false,
            min_value: Some(100.0),
            max_value: Some(103.0),
            interval_hierarchy: None,
            categorical_levels: None,
        },
    ];
    let mut size = HashMap::new();
    size.insert("Age".to_string(), 2i64);
    size.insert("Zip".to_string(), 2i64);
    let (_n, cat_domains) = scan_chunks_for_flow(&chunks, &qis).expect("scan");
    let weights = compute_z_weights(&qis, &cat_domains).expect("weights");
    let ri = vec![1i64, 1i64];

    let (zh, n_z) = build_z_histogram(&chunks, &qis, &cat_domains, &weights).expect("z_hist");
    let sparse = z_hist_to_sparse(&zh, &qis, &weights);

    let r_z = find_ola2_best_rf_z_detailed(&qis, &zh, &weights, &ri, &size, 2, 0.0, n_z).expect("ola2_z");
    let r_s = find_ola2_best_rf_detailed(&qis, &sparse, &ri, &size, 2, 0.0, n_z).expect("ola2_sparse");

    assert_eq!(r_z.best_rf, r_s.best_rf, "best_rf must match");
    assert_eq!(r_z.lowest_dm_star, r_s.lowest_dm_star, "dm_star must match");
    assert_eq!(r_z.num_equivalence_classes, r_s.num_equivalence_classes, "ECs must match");
    let _ = fs::remove_dir_all(d);
}

/// Omitting flow_mode defaults to Auto.
#[test]
fn flow_mode_defaults_to_auto() {
    let d = mk_temp_dir("skald_flow_auto");
    let cfg_path = d.join("cfg.json");
    fs::write(
        &cfg_path,
        r#"{"data_type":"T","T":{"k_anonymize":{"k":2},"quasi_identifiers":{"numerical":[{"column":"Age","type":"int","encode":false,"scale":false,"s":0}]}}}"#,
    ).expect("write cfg");

    let cfg = parse_runtime_config(&cfg_path).expect("parse");
    assert_eq!(cfg.flow_mode, FlowMode::Auto);
    let _ = fs::remove_dir_all(d);
}

// ── CSV quoting round-trip ────────────────────────────────────────────────────

#[test]
fn csv_quote_field_no_quotes_needed() {
    assert_eq!(csv_quote_field("Hypertension"), "Hypertension");
    assert_eq!(csv_quote_field(""), "");
    assert_eq!(csv_quote_field("42"), "42");
}

#[test]
fn csv_quote_field_wraps_commas() {
    assert_eq!(csv_quote_field("House 42, MG Road, Mumbai"), "\"House 42, MG Road, Mumbai\"");
}

#[test]
fn csv_quote_field_escapes_embedded_quotes() {
    assert_eq!(csv_quote_field("say \"hi\""), "\"say \"\"hi\"\"\"");
}

#[test]
fn csv_row_to_line_roundtrip_with_commas_in_field() {
    let row = vec!["C001".to_string(), "House 42, MG Road, Mumbai".to_string(), "Hypertension".to_string()];
    let line = csv_row_to_line(&row);
    let parsed = split_csv_line_basic(&line);
    assert_eq!(parsed, row, "round-trip must recover original fields");
}

#[test]
fn preprocess_preserves_fields_with_commas() {
    let d = mk_temp_dir("skald_preprocess_csv_comma");
    let chunks_dir = d.join("chunks");
    fs::create_dir_all(&chunks_dir).unwrap();
    let chunk = chunks_dir.join("chunk_1.csv");
    fs::write(&chunk, "ID,Address,Disease\n1,\"House 42, MG Road\",Diabetes\n2,\"Flat 7, Park Ave\",Hypertension\n")
        .expect("write chunk");

    let cfg_path = d.join("cfg.json");
    fs::write(&cfg_path, r#"{"data_type":"T","T":{"quasi_identifiers":{"numerical":[]}}}"#).expect("write cfg");
    let cfg = parse_runtime_config(&cfg_path).expect("parse cfg");

    preprocess_chunks(std::slice::from_ref(&chunk), &cfg).expect("preprocess");

    let out = fs::read_to_string(&chunk).expect("read output");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3, "header + 2 data rows");
    let row1 = split_csv_line_basic(lines[1]);
    assert_eq!(row1[1], "House 42, MG Road", "address field must round-trip through preprocess");
    let row2 = split_csv_line_basic(lines[2]);
    assert_eq!(row2[1], "Flat 7, Park Ave", "address field must round-trip through preprocess");
    let _ = fs::remove_dir_all(d);
}

#[test]
fn clear_scratch_dir_removes_stale_chunks_and_converted_csv() {
    let d = mk_temp_dir("skald_clear_scratch");
    let chunks = d.join("chunks");
    fs::create_dir_all(&chunks).expect("chunks dir");
    fs::write(chunks.join("chunk_1.csv"), "a,b\n1,2\n").expect("write chunk");
    fs::write(chunks.join("chunk_2.csv"), "a,b\n3,4\n").expect("write chunk");
    // _converted.csv holds un-anonymized source data — must not survive a run
    fs::write(chunks.join("_converted.csv"), "school_id,school_type\n1,Primary\n").expect("write converted");

    let removed = clear_scratch_dir(&chunks).expect("clear scratch");

    assert_eq!(removed, 3);
    assert!(!chunks.join("_converted.csv").exists());
    assert!(!chunks.join("chunk_1.csv").exists());
    assert!(chunks.is_dir(), "directory itself is kept");

    // Missing directory is not an error
    assert_eq!(clear_scratch_dir(&d.join("nope")).expect("absent dir"), 0);

    let _ = fs::remove_dir_all(d);
}

#[test]
fn stale_output_files_reports_only_leftovers_from_earlier_runs() {
    let d = mk_temp_dir("skald_stale_output");
    let out = d.join("output");
    fs::create_dir_all(&out).expect("output dir");
    for name in [
        "generalized_schools.csv",  // leftover from an earlier run
        "generalized_schools.xlsx", // leftover from an earlier run
        "generalized_test.csv",     // this run writes it
        "status.json",              // rewritten every run
        "pipeline.log",             // the log being written right now
        "symmetric_keys.json",      // key material
    ] {
        fs::write(out.join(name), "x").expect("write file");
    }

    let will_write = vec!["generalized_test.csv".to_string()];
    let stale = stale_output_files(&out, &will_write);

    assert_eq!(stale, vec!["generalized_schools.csv".to_string(), "generalized_schools.xlsx".to_string()]);

    let _ = fs::remove_dir_all(d);
}

#[test]
fn clear_output_dir_removes_leftovers_but_keeps_keys_and_log() {
    let d = mk_temp_dir("skald_clear_output");
    let out = d.join("output");
    fs::create_dir_all(&out).expect("output dir");
    for name in ["generalized_schools.csv", "pipeline.log", "symmetric_keys.json", "fpe_encrypt_keys.json"] {
        fs::write(out.join(name), "x").expect("write file");
    }

    let removed = clear_output_dir(&out, &["generalized_test.csv".to_string()]).expect("clear output");

    assert_eq!(removed, vec!["generalized_schools.csv".to_string()]);
    assert!(!out.join("generalized_schools.csv").exists());
    assert!(out.join("pipeline.log").exists(), "active log must survive");
    assert!(out.join("symmetric_keys.json").exists(), "key material must survive");
    assert!(out.join("fpe_encrypt_keys.json").exists(), "key material must survive");

    let _ = fs::remove_dir_all(d);
}

#[test]
fn clean_output_defaults_to_false_and_parses_from_config() {
    let d = mk_temp_dir("skald_clean_output_cfg");
    fs::create_dir_all(&d).expect("dir");

    let default_path = d.join("default.json");
    fs::write(&default_path, r#"{"data_type":"T","T":{"output_path":"x.csv"}}"#).expect("write cfg");
    assert!(!parse_runtime_config(&default_path).expect("parse cfg").clean_output);

    let enabled_path = d.join("enabled.json");
    fs::write(&enabled_path, r#"{"data_type":"T","T":{"output_path":"x.csv","clean_output":true}}"#)
        .expect("write cfg");
    assert!(parse_runtime_config(&enabled_path).expect("parse cfg").clean_output);

    let _ = fs::remove_dir_all(d);
}

#[test]
fn xlsx_input_yields_xlsx_output_with_no_config_opt_in() {
    let root = mk_temp_dir("skald_xlsx_roundtrip");
    fs::create_dir_all(root.join("config")).expect("config dir");
    fs::create_dir_all(root.join("data")).expect("data dir");

    // A single-sheet workbook, so no sheet_joins / restore_sheets are involved —
    // the .xlsx output must come purely from echoing the input format.
    let mut wb = rust_xlsxwriter::Workbook::new();
    {
        let ws = wb.add_worksheet();
        for (c, h) in ["Age", "Name"].iter().enumerate() {
            ws.write_string(0, c as u16, *h).expect("header");
        }
        for (r, (age, name)) in [("20", "Alice"), ("20", "Bob"), ("21", "Carol")].iter().enumerate() {
            ws.write_string(r as u32 + 1, 0, *age).expect("age");
            ws.write_string(r as u32 + 1, 1, *name).expect("name");
        }
    }
    wb.save(root.join("data").join("in.xlsx")).expect("save xlsx");

    fs::write(
        root.join("config").join("pipeline.json"),
        r#"{
          "data_type":"T",
          "T":{
            "output_path":"final.csv",
            "output_directory":"output",
            "suppression_limit":1.0,
            "k_anonymize":{"k":2},
            "quasi_identifiers":{
              "numerical":[{"column":"Age","encode":false,"scale":false,"s":0,"type":"int"}],
              "categorical":[]
            },
            "size":{"Age":2}
          }
        }"#,
    )
    .expect("write cfg");

    let status = run_pipeline(&root).expect("run pipeline");
    assert_eq!(status.status, "success");

    let outputs = status.outputs.expect("outputs");
    let matched = outputs
        .get("format_matched_output_path")
        .and_then(|v| v.as_str())
        .expect("xlsx input must report a format-matched output without any config flag");
    assert!(matched.ends_with(".xlsx"), "got {matched}");
    assert!(PathBuf::from(matched).exists());

    // The flat CSV is still written and remains the canonical output
    let csv = outputs.get("final_output_path").and_then(|v| v.as_str()).expect("final output");
    assert!(csv.ends_with(".csv"));
    assert!(PathBuf::from(csv).exists());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn csv_input_reports_no_format_matched_output() {
    let root = mk_temp_dir("skald_csv_no_convert");
    fs::create_dir_all(root.join("config")).expect("config dir");
    fs::create_dir_all(root.join("data")).expect("data dir");

    fs::write(root.join("data").join("d.csv"), "Age,Name\n20,Alice\n20,Bob\n21,Carol\n").expect("write data");
    fs::write(
        root.join("config").join("pipeline.json"),
        r#"{
          "data_type":"T",
          "T":{
            "output_path":"final.csv",
            "output_directory":"output",
            "suppression_limit":1.0,
            "k_anonymize":{"k":2},
            "quasi_identifiers":{
              "numerical":[{"column":"Age","encode":false,"scale":false,"s":0,"type":"int"}],
              "categorical":[]
            },
            "size":{"Age":2}
          }
        }"#,
    )
    .expect("write cfg");

    let status = run_pipeline(&root).expect("run pipeline");
    let outputs = status.outputs.expect("outputs");
    assert!(
        outputs.get("format_matched_output_path").map(|v| v.is_null()).unwrap_or(true),
        "CSV in / CSV out needs no conversion"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn write_output_in_format_echoes_input_format() {
    let d = mk_temp_dir("skald_format_echo");
    let csv = d.join("generalized.csv");
    fs::write(&csv, "Age,City\n[20-29],\"Pune, MH\"\n[30-39],Delhi\n").expect("write csv");

    // CSV in → nothing to convert
    assert_eq!(write_output_in_format(&csv, InputFormat::Csv, "generalized").expect("csv"), None);

    // JSON in → array of objects, keys in the table's column order, values escaped
    let json_path = write_output_in_format(&csv, InputFormat::Json, "generalized").expect("json").expect("path");
    assert_eq!(json_path, d.join("generalized.json"));
    let parsed: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&json_path).expect("read json")).expect("parse json");
    let records = parsed.as_array().expect("array");
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["Age"], "[20-29]");
    assert_eq!(records[0]["City"], "Pune, MH", "comma inside a quoted field must survive");
    let key_order: Vec<&str> = fs::read_to_string(&json_path)
        .expect("read json")
        .lines()
        .nth(1)
        .map(|l| if l.find("\"Age\"") < l.find("\"City\"") { vec!["Age", "City"] } else { vec!["City", "Age"] })
        .expect("first record line");
    assert_eq!(key_order, vec!["Age", "City"], "keys follow column order, not alphabetical");

    // Excel in → a real xlsx (zip container)
    let xlsx_path = write_output_in_format(&csv, InputFormat::Excel, "generalized").expect("xlsx").expect("path");
    assert_eq!(xlsx_path, d.join("generalized.xlsx"));
    let bytes = fs::read(&xlsx_path).expect("read xlsx");
    assert_eq!(&bytes[..2], b"PK", "xlsx must be a zip container");

    let _ = fs::remove_dir_all(d);
}

#[test]
fn resolve_input_csv_reports_the_format_it_found() {
    let d = mk_temp_dir("skald_input_format");
    let data = d.join("data");
    let chunks = d.join("chunks");
    fs::create_dir_all(&data).expect("data dir");

    fs::write(data.join("in.csv"), "a,b\n1,2\n").expect("write csv");
    let r = resolve_input_csv(&data, &chunks, &[]).expect("resolve csv");
    assert_eq!(r.format, InputFormat::Csv);
    assert!(r.format_mismatch.is_none());
    assert_eq!(r.csv_path, data.join("in.csv"), "plain CSV is used in place, not copied");

    fs::remove_file(data.join("in.csv")).expect("rm csv");
    fs::write(data.join("in.json"), r#"[{"a":"1","b":"2"}]"#).expect("write json");
    let r = resolve_input_csv(&data, &chunks, &[]).expect("resolve json");
    assert_eq!(r.format, InputFormat::Json);
    assert_eq!(r.csv_path, chunks.join("_converted.csv"), "JSON is normalised into scratch");

    let _ = fs::remove_dir_all(d);
}

#[test]
fn json_misnamed_as_csv_is_read_as_json_not_parsed_as_text() {
    // The TEE decrypt step appends .csv to every dataset, so
    // `records.json.enc` lands as `records.json.csv`. JSON is valid UTF-8, so
    // it slips past the CSV reader's only guard and would be parsed as
    // delimited text — garbage columns, no error, a plausible-looking result.
    let d = mk_temp_dir("skald_sniff_json");
    let data = d.join("data");
    let chunks = d.join("chunks");
    fs::create_dir_all(&data).expect("data dir");
    fs::write(data.join("records.json.csv"), r#"[{"Age":"20","City":"Pune"},{"Age":"21","City":"Delhi"}]"#)
        .expect("write json");

    let r = resolve_input_csv(&data, &chunks, &[]).expect("resolve");

    assert_eq!(r.format, InputFormat::Json, "content wins over the .csv extension");
    let mismatch = r.format_mismatch.expect("the name/content disagreement must be reported");
    assert!(mismatch.contains("records.json.csv") && mismatch.contains("json"), "got: {mismatch}");

    // Parsed as records, not as one column of raw JSON text
    let converted = fs::read_to_string(&r.csv_path).expect("read converted");
    assert_eq!(converted.lines().next(), Some("Age,City"));
    assert_eq!(converted.lines().count(), 3, "header + 2 records");

    let _ = fs::remove_dir_all(d);
}

#[test]
fn xlsx_misnamed_as_csv_reaches_the_excel_reader() {
    let d = mk_temp_dir("skald_sniff_xlsx");
    let data = d.join("data");
    let chunks = d.join("chunks");
    fs::create_dir_all(&data).expect("data dir");

    let mut wb = rust_xlsxwriter::Workbook::new();
    {
        let ws = wb.add_worksheet();
        ws.write_string(0, 0, "Age").expect("header");
        ws.write_string(1, 0, "20").expect("cell");
    }
    wb.save(data.join("dataset.xlsx.csv")).expect("save xlsx");

    let r = resolve_input_csv(&data, &chunks, &[]).expect("resolve");

    assert_eq!(r.format, InputFormat::Excel);
    assert!(r.format_mismatch.is_some());
    assert_eq!(fs::read_to_string(&r.csv_path).expect("read converted").lines().next(), Some("Age"));

    let _ = fs::remove_dir_all(d);
}

#[test]
fn sniff_leaves_genuine_csv_alone() {
    let d = mk_temp_dir("skald_sniff_csv");
    let data = d.join("data");
    let chunks = d.join("chunks");
    fs::create_dir_all(&data).expect("data dir");
    // A leading bracket inside a quoted field must not be mistaken for JSON
    fs::write(data.join("in.csv"), "\"[bracketed]\",b\n1,2\n").expect("write csv");

    let r = resolve_input_csv(&data, &chunks, &[]).expect("resolve");

    assert_eq!(r.format, InputFormat::Csv);
    assert!(r.format_mismatch.is_none(), "no mismatch for a correctly named CSV");

    let _ = fs::remove_dir_all(d);
}

#[test]
fn categorical_hierarchy_key_lookup_is_case_insensitive() {
    // Config keys are lowercased at parse and column names lowercased at
    // lookup, so a producer sending "BloodGroup" verbatim still resolves.
    let d = mk_temp_dir("skald_hier_case");
    let cfg_path = d.join("cfg.json");
    fs::write(&cfg_path, r#"{"data_type":"T","T":{"categorical_hierarchies":{"BloodGroup":{"A+":["A","*"]}}}}"#)
        .expect("write cfg");

    let cfg = parse_runtime_config(&cfg_path).expect("parse cfg");
    assert!(cfg.categorical_hierarchies.contains_key("bloodgroup"), "config key must normalise");
    assert!(!cfg.categorical_hierarchies.contains_key("BloodGroup"));

    let _ = fs::remove_dir_all(d);
}

// ── Multi-combination OLA-2 parameter grid ───────────────────────────────────

fn blood_group_hierarchy() -> HierarchyMap {
    let mut col = HashMap::new();
    for (leaf, group) in [
        ("A+", "A"),
        ("A-", "A"),
        ("B+", "B"),
        ("B-", "B"),
        ("AB+", "AB"),
        ("AB-", "AB"),
        ("O+", "O"),
        ("O-", "O"),
        ("*", "Other"),
    ] {
        col.insert(leaf.to_string(), vec![group.to_string(), "*".to_string()]);
    }
    let mut h = HashMap::new();
    h.insert("blood group".to_string(), col);
    h
}

/// Deterministic people table: skewed Age 20–69, PIN 100–199, 8 blood groups.
fn synthetic_people_csv(n: usize) -> String {
    const GROUPS: [&str; 8] = ["A+", "A-", "AB+", "AB-", "B+", "B-", "O+", "O-"];
    let mut x: u64 = 0x5eed;
    let mut next = || {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        x >> 33
    };
    let mut out = String::from("Age,PIN,Blood Group,Name\n");
    // Pin the numeric ranges so min/max do not depend on the draw.
    out.push_str("20,100,O+,first\n69,199,A+,last\n");
    for i in 0..n {
        let age = 20 + (next() % 50) * (next() % 50) / 49;
        let pin = 100 + next() % 100;
        let group = GROUPS[(next() % 8) as usize];
        out.push_str(&format!("{age},{pin},{group},p{i}\n"));
    }
    out
}

/// Config over `synthetic_people_csv`; `fields` is spliced into the section.
fn people_config(fields: &str) -> String {
    format!(
        r#"{{
      "data_type":"T",
      "T":{{
        "output_path":"final.csv",
        "output_directory":"output",
        "quasi_identifiers":{{
          "numerical":[{{"column":"Age","type":"int"}},{{"column":"PIN","type":"int"}}],
          "categorical":[{{"column":"Blood Group"}}]
        }},
        "qi_constraints":{{"PIN":{{"intervals":[{{"from":100,"to":149}},{{"from":150,"to":199}}]}}}},
        "size":{{"Age":2,"PIN":2}},
        "categorical_hierarchies":{{"blood group":{{
          "A+":["A","*"],"A-":["A","*"],"B+":["B","*"],"B-":["B","*"],
          "AB+":["AB","*"],"AB-":["AB","*"],"O+":["O","*"],"O-":["O","*"],"*":["Other","*"]
        }}}},
        {fields}
      }}
    }}"#
    )
}

/// QIs for `synthetic_people_csv` built the way the pipeline builds them,
/// with categorical levels attached.
fn people_qis(dir: &Path, chunks: &[PathBuf]) -> (Vec<QuasiIdentifierLite>, Vec<Vec<String>>) {
    let cfg_path = dir.join("cfg.json");
    fs::write(&cfg_path, people_config(r#""k_anonymize":{"k":2}"#)).expect("write cfg");
    let cfg = parse_runtime_config(&cfg_path).expect("parse cfg");
    let min_max = compute_numerical_min_max(chunks, &["Age".to_string(), "PIN".to_string()]).expect("min/max");
    let mut qis = build_quasi_identifiers(&cfg, &min_max).expect("qis");
    let (_n, domains) = scan_chunks_for_flow(chunks, &qis).expect("scan");
    attach_categorical_levels(&mut qis, &domains, &cfg.categorical_hierarchies).expect("categorical levels");
    (qis, domains)
}

#[test]
fn categorical_levels_follow_the_configured_hierarchy() {
    let domain: Vec<String> =
        ["A+", "A-", "AB+", "AB-", "B+", "B-", "O+", "O-"].iter().map(|s| s.to_string()).collect();

    let levels = build_categorical_levels("Blood Group", &domain, &blood_group_hierarchy());
    assert_eq!(levels.num_levels, 3, "raw → ABO group → *");
    assert_eq!(levels.group_at[1], vec![0, 1, 2, 3, 4, 5, 6, 7]);
    // AB+ and AB- share a group, apart from A — unlike alphabetical position / level.
    assert_eq!(levels.group_at[2], vec![0, 0, 1, 1, 2, 2, 3, 3]);
    assert_eq!(levels.group_at[3], vec![0; 8]);

    let flat = build_categorical_levels("Blood Group", &domain, &HashMap::new());
    assert_eq!(flat.num_levels, 2, "no hierarchy: raw → *");
    assert_eq!(flat.group_at[2], vec![0; 8]);
}

/// The worked example in "Multi-Combination OLA-2" (SKALD internal docs):
/// 20 records, Age on 3 interval levels × Gender on 2, k ∈ {2,5,10,15},
/// σ ∈ {0%,5%,10%}. Checks the final best-node table from its Figure 7.
#[test]
fn parameter_grid_reproduces_the_worked_example() {
    let d = mk_temp_dir("skald_grid_example");
    let mut csv = String::from("Age,Gender\n");
    for (age, gender, n) in [(0, "F", 2), (0, "M", 1), (1, "F", 8), (1, "M", 7), (2, "F", 1), (2, "M", 1)] {
        for _ in 0..n {
            csv.push_str(&format!("{age},{gender}\n"));
        }
    }
    let chunks = vec![write_chunk(&d, &csv)];
    let mut qis = vec![
        QuasiIdentifierLite {
            column_name: "Age".to_string(),
            is_categorical: false,
            min_value: Some(0.0),
            max_value: Some(2.0),
            interval_hierarchy: Some(build_interval_hierarchy(vec![(0, 3), (4, 7)], 2)),
            categorical_levels: None,
        },
        QuasiIdentifierLite {
            column_name: "Gender".to_string(),
            is_categorical: true,
            min_value: None,
            max_value: None,
            interval_hierarchy: None,
            categorical_levels: None,
        },
    ];
    let (_n, domains) = scan_chunks_for_flow(&chunks, &qis).expect("scan");
    attach_categorical_levels(&mut qis, &domains, &HashMap::new()).expect("categorical levels");
    let (hist, n) = build_direct_histogram(&chunks, &qis, &domains).expect("hist");
    assert_eq!(n, 20);

    let ks = [2, 5, 10, 15];
    let sigmas = [0.0, 0.05, 0.10];
    let grid = compute_parameter_grid_for(&qis, &[1, 1], &HashMap::new(), n, &ks, &sigmas, |node| {
        merge_histogram(&hist, &qis, node).into_values().collect()
    })
    .expect("grid");

    let expected: [((i64, f64), [i64; 2], i64); 12] = [
        ((2, 0.0), [3, 1], 202),
        ((2, 0.05), [3, 1], 202),
        ((2, 0.10), [2, 1], 164),
        ((5, 0.0), [3, 1], 202),
        ((5, 0.05), [3, 1], 202),
        ((5, 0.10), [2, 1], 164),
        ((10, 0.0), [3, 2], 400),
        ((10, 0.05), [3, 2], 400),
        ((10, 0.10), [2, 2], 324),
        ((15, 0.0), [3, 2], 400),
        ((15, 0.05), [3, 2], 400),
        ((15, 0.10), [2, 2], 324),
    ];
    assert_eq!(grid.entries.len(), 12);
    for (entry, ((k, sigma), node, dm)) in grid.entries.iter().zip(expected) {
        assert_eq!((entry.k, entry.suppression_limit), (k, sigma));
        assert!(entry.feasible, "k={k} σ={sigma}");
        assert_eq!(entry.best_node, node.to_vec(), "k={k} σ={sigma}");
        assert_eq!(entry.dm_star, dm, "k={k} σ={sigma}");
    }
    assert_eq!(grid.lattice_size, 6);
    assert!(grid.nodes_merged <= 6, "each node merged at most once, got {}", grid.nodes_merged);

    let independent_merges: usize = ks
        .iter()
        .flat_map(|&k| sigmas.iter().map(move |&s| (k, s)))
        .map(|(k, s)| {
            find_ola2_best_rf_detailed(&qis, &hist, &[1, 1], &HashMap::new(), k, s, n).map_or(0, |r| r.node_trace.len())
        })
        .sum();
    assert!(grid.nodes_merged < independent_merges, "{} vs {}", grid.nodes_merged, independent_merges);

    let _ = fs::remove_dir_all(d);
}

/// One multi-combination search must give every cell exactly what a separate
/// OLA-2 run for that (k, σ) gives, on a lattice mixing a uniform numeric, an
/// interval and a categorical QI — for both histogram representations.
#[test]
fn parameter_grid_matches_independent_ola2_runs() {
    let d = mk_temp_dir("skald_grid_vs_ola2");
    let chunks = vec![write_chunk(&d, &synthetic_people_csv(600))];
    let (qis, domains) = people_qis(&d, &chunks);
    let mut size = HashMap::new();
    size.insert("Age".to_string(), 2);
    size.insert("PIN".to_string(), 2);
    let ri = vec![1i64; qis.len()];
    let (hist, n) = build_direct_histogram(&chunks, &qis, &domains).expect("hist");

    let check = |ks: &[i64], sigmas: &[f64], entries: &[super::anonymization::GridEntry]| {
        let mut feasible = 0;
        for (entry, (k, sigma)) in entries.iter().zip(ks.iter().flat_map(|&k| sigmas.iter().map(move |&s| (k, s)))) {
            assert_eq!((entry.k, entry.suppression_limit), (k, sigma));
            match find_ola2_best_rf_detailed(&qis, &hist, &ri, &size, k, sigma, n) {
                Ok(r) => {
                    feasible += 1;
                    assert!(entry.feasible, "k={k} σ={sigma}");
                    assert_eq!(entry.best_node, r.best_rf, "k={k} σ={sigma}");
                    assert_eq!(entry.dm_star, r.lowest_dm_star, "k={k} σ={sigma}");
                    assert_eq!(entry.num_equivalence_classes, r.num_equivalence_classes, "k={k} σ={sigma}");
                    assert_eq!(entry.suppression_count, r.top_nodes[0].suppression_count, "k={k} σ={sigma}");
                    let named: Vec<(String, i64)> = entry.generalization_node.clone().into_iter().collect();
                    assert_eq!(named.len(), qis.len());
                }
                Err(_) => assert!(!entry.feasible, "k={k} σ={sigma} should be infeasible"),
            }
        }
        feasible
    };

    let ks = [2, 5, 10, 25, 400]; // 400 exceeds every class even at the top node
    let sigmas = [0.0, 0.02, 0.1];
    let grid = compute_parameter_grid_for(&qis, &ri, &size, n, &ks, &sigmas, |node| {
        merge_histogram(&hist, &qis, node).into_values().collect()
    })
    .expect("grid");
    let feasible = check(&ks, &sigmas, &grid.entries);
    assert!(feasible > 3 && feasible < 15, "want a mix of feasible and infeasible cells, got {feasible}");
    assert!(grid.nodes_merged < grid.lattice_size, "{} of {}", grid.nodes_merged, grid.lattice_size);

    // The pipeline's fixed grid, through both histogram representations.
    let sparse_grid = compute_parameter_grid(&qis, &hist, &ri, &size, n).expect("grid");
    check(GRID_K_VALUES, GRID_SUPPRESSION_LIMITS, &sparse_grid.entries);
    let weights = compute_z_weights(&qis, &domains).expect("weights");
    let (zh, zn) = build_z_histogram(&chunks, &qis, &domains, &weights).expect("z hist");
    let z_grid = compute_parameter_grid_z(&qis, &zh, &weights, &ri, &size, zn).expect("grid");
    for (z, s) in z_grid.entries.iter().zip(&sparse_grid.entries) {
        assert_eq!(
            (z.feasible, &z.best_node, z.dm_star, z.suppression_count),
            (s.feasible, &s.best_node, s.dm_star, s.suppression_count)
        );
    }

    let _ = fs::remove_dir_all(d);
}

/// The classes OLA-2 scores must be the classes the output step writes — for
/// categorical QIs (grouped by the configured hierarchy) and for numeric QIs
/// in the ORIGINAL flow, whose base histogram starts at OLA-1's width ri > 1.
#[test]
fn merged_histogram_matches_written_output() {
    let d = mk_temp_dir("skald_merge_vs_output");
    let chunks = vec![write_chunk(&d, &synthetic_people_csv(400))];
    let (qis, domains) = people_qis(&d, &chunks);
    let out = d.join("out");
    let k = 5;

    let ri = vec![2, 1, 1]; // Age starts at width 2, as OLA-1 can choose
    let (hist, _n) = build_sparse_histogram(&chunks, &qis, &ri, &domains).expect("hist");
    for node in [vec![2, 1, 1], vec![4, 3, 2], vec![8, 5, 2], vec![16, 2, 3], vec![50, 6, 1]] {
        let mut sizes: Vec<i64> = merge_histogram(&hist, &qis, &node).into_values().collect();
        let summary =
            generalize_and_write_outputs(&chunks, &qis, &node, k, &out, "final.csv", &blood_group_hierarchy())
                .expect("generalize");

        let suppressed: i64 = sizes.iter().filter(|&&c| c < k).sum();
        sizes.retain(|&c| c >= k);
        let mut written: Vec<i64> = summary
            .class_size_counts
            .iter()
            .flat_map(|(&size, &count)| std::iter::repeat_n(size, count as usize))
            .collect();
        sizes.sort_unstable();
        written.sort_unstable();
        assert_eq!(sizes, written, "class sizes at {node:?}");
        assert_eq!(suppressed, summary.suppressed_records, "suppressed at {node:?}");
    }

    let _ = fs::remove_dir_all(d);
}

/// A class spread over several chunks is judged on its total size, not its
/// size inside each chunk.
#[test]
fn generalization_counts_classes_across_chunks() {
    let d = mk_temp_dir("skald_cross_chunk");
    let c1 = d.join("chunk_1.csv");
    let c2 = d.join("chunk_2.csv");
    fs::write(&c1, "Age,Name\n20,Alice\n21,Bob\n").expect("chunk 1");
    fs::write(&c2, "Age,Name\n20,Carol\n30,Dan\n").expect("chunk 2");
    let qis = vec![QuasiIdentifierLite {
        column_name: "Age".to_string(),
        is_categorical: false,
        min_value: Some(20.0),
        max_value: Some(30.0),
        interval_hierarchy: None,
        categorical_levels: None,
    }];

    let summary =
        generalize_and_write_outputs(&[c1, c2], &qis, &[1], 2, &d, "final.csv", &HashMap::new()).expect("generalize");

    let body = fs::read_to_string(d.join("final.csv")).expect("read final");
    assert_eq!(body, "Age,Name\n[20-20],Alice\n*,Bob\n[20-20],Carol\n*,Dan\n");
    assert_eq!(summary.total_records, 4);
    assert_eq!(summary.suppressed_records, 2);
    assert_eq!(summary.num_equivalence_classes, 1);

    let _ = fs::remove_dir_all(d);
}

fn run_people_pipeline(root: &Path, fields: &str) -> Result<super::bootstrap::StatusPayload, PipelineError> {
    fs::write(root.join("config").join("pipeline.json"), people_config(fields)).expect("write cfg");
    run_pipeline(root)
}

fn people_root(prefix: &str) -> PathBuf {
    let root = mk_temp_dir(prefix);
    fs::create_dir_all(root.join("config")).expect("config dir");
    fs::create_dir_all(root.join("data")).expect("data dir");
    fs::write(root.join("data").join("people.csv"), synthetic_people_csv(800)).expect("write data");
    root
}

/// Pass 1 returns the grid; pass 2 given one of its cells as
/// `generalization_node` writes exactly what pass 2 running OLA-2 for that
/// cell's (k, σ) writes.
#[test]
fn pass2_with_grid_node_matches_pass2_running_ola2() {
    for flow in ["direct", "original"] {
        let root = people_root("skald_pass2_node");

        let pass1 =
            run_people_pipeline(&root, &format!(r#""pass":"pass1","flow_mode":"{flow}","suppression_limit":0.01"#))
                .expect("pass1");
        let outputs = pass1.outputs.expect("pass1 outputs");
        let grid = outputs["parameter_grid"].as_array().expect("grid").clone();
        assert_eq!(grid.len(), GRID_K_VALUES.len() * GRID_SUPPRESSION_LIMITS.len(), "{flow}");
        let cell = grid
            .iter()
            .find(|c| c["feasible"] == true && c["k"] == 10 && c["suppression_limit"].as_f64() == Some(0.01))
            .unwrap_or_else(|| panic!("{flow}: k=10 σ=0.01 should be feasible"))
            .clone();
        let node = cell["generalization_node"].to_string();

        let chosen = run_people_pipeline(&root, &format!(
            r#""pass":"pass2","flow_mode":"{flow}","suppression_limit":0.01,"k_anonymize":{{"k":10}},"generalization_node":{node}"#
        )).expect("pass2 with node");
        let chosen_out = chosen.outputs.expect("outputs");
        assert_eq!(chosen_out["flow"], "CHOSEN_NODE", "{flow}");
        assert_eq!(chosen_out["final_rf"], cell["best_node"], "{flow}");
        assert_eq!(chosen_out["lowest_dm_star"], cell["dm_star"], "{flow}");
        assert_eq!(chosen_out["suppressed_records"], cell["suppression_count"], "{flow}");
        let chosen_csv = fs::read_to_string(root.join("output").join("final.csv")).expect("read chosen");

        let searched = run_people_pipeline(
            &root,
            &format!(r#""pass":"pass2","flow_mode":"{flow}","suppression_limit":0.01,"k_anonymize":{{"k":10}}"#),
        )
        .expect("pass2 with OLA-2");
        let searched_out = searched.outputs.expect("outputs");
        assert_eq!(searched_out["final_rf"], cell["best_node"], "{flow}");
        assert_eq!(searched_out["parameter_grid"], serde_json::json!([]), "{flow}: pass2 skips the grid");
        let searched_csv = fs::read_to_string(root.join("output").join("final.csv")).expect("read searched");
        assert_eq!(chosen_csv, searched_csv, "{flow}");

        let _ = fs::remove_dir_all(root);
    }
}

#[test]
fn pass2_rejects_a_node_that_breaks_the_suppression_limit() {
    let root = people_root("skald_pass2_stale");
    let err = run_people_pipeline(
        &root,
        r#""pass":"pass2","suppression_limit":0.0,"k_anonymize":{"k":10},
           "generalization_node":{"Age":1,"PIN":1,"Blood Group":1}"#,
    )
    .expect_err("finest node cannot meet k=10 with no suppression");
    match err {
        PipelineError::Validation { code, .. } => assert_eq!(code, "SUPPRESSION_LIMIT_EXCEEDED"),
        other => panic!("unexpected error {other:?}"),
    }
    assert!(!root.join("output").join("final.csv").exists(), "a rejected output must not be left behind");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn pass2_rejects_a_node_that_does_not_fit_the_qis() {
    let root = people_root("skald_pass2_bad_node");
    for node in [
        r#"{"Age":2,"PIN":1}"#,                            // QI missing
        r#"{"Age":2,"PIN":1,"Blood Group":1,"Gender":1}"#, // not a QI
        r#"{"Age":2,"PIN":99,"Blood Group":1}"#,           // PIN has 6 levels
        r#"{"Age":2,"PIN":1,"Blood Group":5}"#,            // ladder of 2 → at most 4
    ] {
        let err = run_people_pipeline(
            &root,
            &format!(r#""pass":"pass2","suppression_limit":1.0,"k_anonymize":{{"k":2}},"generalization_node":{node}"#),
        )
        .expect_err(node);
        match err {
            PipelineError::Validation { code, .. } => assert_eq!(code, "CONFIG_INVALID_VALUE", "{node}"),
            other => panic!("{node}: unexpected error {other:?}"),
        }
    }
    let _ = fs::remove_dir_all(root);
}
