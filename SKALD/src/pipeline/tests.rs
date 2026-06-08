use super::anonymization::{
    build_direct_histogram, build_sparse_histogram, build_z_histogram, compute_equivalence_space,
    compute_z_weights, find_ola1_initial_ri, find_ola2_best_rf, find_ola2_best_rf_detailed,
    find_ola2_best_rf_z_detailed, generalize_and_write_outputs, merge_z_histogram,
    scan_chunks_for_flow, z_hist_to_sparse, QuasiIdentifierLite,
};
use super::bootstrap::{find_first_json_config, parse_runtime_config, split_csv_by_ram, FlowMode};
use super::pipeline::run_pipeline;
use super::preprocess::preprocess_chunks;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn mk_temp_dir(prefix: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time error")
        .as_nanos();
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
    assert!(out.len() >= 1);
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
        r#"{"data_type":"T","T":{"output_path":"x.csv","output_directory":"output","suppress":["b"],"quasi_identifiers":{"numerical":[{"column":"a","encode":false,"scale":false,"s":0,"type":"int"}],"categorical":[]}}}"#,
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
    fs::write(
        &chunk1,
        "Age,Name\n20,Alice\n20,Bob\n21,Carol\n",
    )
    .expect("write chunk");

    let qis = vec![QuasiIdentifierLite {
        column_name: "Age".to_string(),
        is_categorical: false,
        min_value: Some(20.0),
        max_value: Some(21.0),
        interval_hierarchy: None,
    }];

    generalize_and_write_outputs(
        std::slice::from_ref(&chunk1),
        &qis,
        &[1],
        2,
        &outdir,
        "final.csv",
    )
    .expect("generalize");

    let body = fs::read_to_string(outdir.join("final.csv")).expect("read final");
    assert!(body.lines().any(|l| l == "*,Carol"));

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

    fs::write(root.join("data").join("d.csv"), "Age,Name\n20,Alice\n20,Bob\n21,Carol\n")
        .expect("write data");

    let status = run_pipeline(&root).expect("run pipeline");
    assert_eq!(status.status, "success");

    let outputs = status.outputs.expect("outputs");
    let out_path = outputs
        .get("final_output_path")
        .and_then(|v| v.as_str())
        .expect("final output path");
    assert!(PathBuf::from(out_path).exists());

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
        },
        QuasiIdentifierLite {
            column_name: "Zip".to_string(),
            is_categorical: false,
            min_value: Some(10000.0),
            max_value: Some(10099.0),
            interval_hierarchy: None,
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
fn write_chunk(dir: &PathBuf, content: &str) -> PathBuf {
    let p = dir.join("chunk_1.csv");
    fs::write(&p, content).expect("write chunk");
    p
}

/// Both `build_sparse_histogram` (with ri=[1,1]) and `build_direct_histogram`
/// must produce identical bucket counts for the same dataset.
#[test]
fn direct_and_original_histograms_are_equivalent() {
    let d = mk_temp_dir("skald_hist_equiv");
    let chunk = write_chunk(
        &d,
        "Age,Zip\n20,10001\n20,10002\n21,10001\n21,10002\n22,10003\n22,10003\n23,10000\n23,10000\n",
    );
    let chunks = vec![chunk];

    let qis = vec![
        QuasiIdentifierLite { column_name: "Age".to_string(), is_categorical: false,
            min_value: Some(20.0), max_value: Some(23.0), interval_hierarchy: None },
        QuasiIdentifierLite { column_name: "Zip".to_string(), is_categorical: false,
            min_value: Some(10000.0), max_value: Some(10003.0), interval_hierarchy: None },
    ];

    let (_n, cat_domains) = scan_chunks_for_flow(&chunks, &qis).expect("scan");

    let ri_1 = vec![1i64, 1i64];
    let (hist_orig, n_orig) = build_sparse_histogram(&chunks, &qis, &ri_1, &cat_domains)
        .expect("build_sparse");
    let (hist_direct, n_direct) = build_direct_histogram(&chunks, &qis, &cat_domains)
        .expect("build_direct");

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
    let chunk = write_chunk(
        &d,
        "Age,Zip\n20,100\n20,101\n21,100\n21,101\n22,102\n22,102\n23,103\n23,103\n",
    );
    let chunks = vec![chunk];

    let qis = vec![
        QuasiIdentifierLite { column_name: "Age".to_string(), is_categorical: false,
            min_value: Some(20.0), max_value: Some(23.0), interval_hierarchy: None },
        QuasiIdentifierLite { column_name: "Zip".to_string(), is_categorical: false,
            min_value: Some(100.0), max_value: Some(103.0), interval_hierarchy: None },
    ];

    let mut size = HashMap::new();
    size.insert("Age".to_string(), 2);
    size.insert("Zip".to_string(), 2);

    let (_n, cat_domains) = scan_chunks_for_flow(&chunks, &qis).expect("scan");

    let ri = vec![1i64, 1i64];
    let (hist_orig, n_orig) = build_sparse_histogram(&chunks, &qis, &ri, &cat_domains).expect("orig");
    let (hist_direct, n_direct) = build_direct_histogram(&chunks, &qis, &cat_domains).expect("direct");

    let ola2_orig = find_ola2_best_rf_detailed(&qis, &hist_orig, &ri, &size, 2, 0.0, n_orig)
        .expect("ola2 orig");
    let ola2_direct = find_ola2_best_rf_detailed(&qis, &hist_direct, &ri, &size, 2, 0.0, n_direct)
        .expect("ola2 direct");

    assert_eq!(ola2_orig.best_rf, ola2_direct.best_rf, "best_rf must match");
    assert_eq!(ola2_orig.lowest_dm_star, ola2_direct.lowest_dm_star, "dm_star must match");
    assert_eq!(
        ola2_orig.num_equivalence_classes, ola2_direct.num_equivalence_classes,
        "EC count must match"
    );

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
    }];
    let cat_domains = vec![vec![
        "M".to_string(), "F".to_string(), "X".to_string(), "NB".to_string(), "U".to_string(),
    ]];
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
        r#"{"data_type":"T","T":{"flow_mode":"ORIGINAL","quasi_identifiers":{"numerical":[{"column":"Age","type":"int","encode":false,"scale":false,"s":0}]}}}"#,
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
        r#"{"data_type":"T","T":{"flow_mode":"direct","quasi_identifiers":{"numerical":[{"column":"Age","type":"int","encode":false,"scale":false,"s":0}]}}}"#,
    ).expect("write cfg");

    let cfg = parse_runtime_config(&cfg_path).expect("parse");
    assert_eq!(cfg.flow_mode, FlowMode::Direct);
    let _ = fs::remove_dir_all(d);
}

// ── Z-encoding tests ──────────────────────────────────────────────────────────

/// compute_z_weights: weights for [R=3, R=4] should be [4, 1].
#[test]
fn z_weights_correct_two_qi() {
    let qis = vec![
        QuasiIdentifierLite { column_name: "A".to_string(), is_categorical: false,
            min_value: Some(0.0), max_value: Some(2.0), interval_hierarchy: None },
        QuasiIdentifierLite { column_name: "B".to_string(), is_categorical: false,
            min_value: Some(0.0), max_value: Some(3.0), interval_hierarchy: None },
    ];
    let cat_domains: Vec<Vec<String>> = vec![vec![], vec![]];
    let w = compute_z_weights(&qis, &cat_domains).expect("weights");
    // R_A=3, R_B=4  →  W_A=4 (product of ranges after A), W_B=1
    assert_eq!(w, vec![4, 1]);
}

/// Z-histogram: two identical records produce one bucket with count 2.
#[test]
fn z_histogram_deduplicates_equal_records() {
    let d = mk_temp_dir("skald_z_dedup");
    let chunk = write_chunk(&d, "Age,Zip\n20,100\n20,100\n21,101\n");
    let chunks = vec![chunk];
    let qis = vec![
        QuasiIdentifierLite { column_name: "Age".to_string(), is_categorical: false,
            min_value: Some(20.0), max_value: Some(21.0), interval_hierarchy: None },
        QuasiIdentifierLite { column_name: "Zip".to_string(), is_categorical: false,
            min_value: Some(100.0), max_value: Some(101.0), interval_hierarchy: None },
    ];
    let (_n, cat_domains) = scan_chunks_for_flow(&chunks, &qis).expect("scan");
    let weights = compute_z_weights(&qis, &cat_domains).expect("weights");
    let (zh, n) = build_z_histogram(&chunks, &qis, &cat_domains, &weights).expect("z_hist");

    assert_eq!(n, 3);
    // (20,100) → u=(0,0) → Z=0, appears twice
    // (21,101) → u=(1,1) → Z = 1*W0 + 1*W1 = 1*2 + 1*1 = 3, appears once
    assert_eq!(zh.len(), 2, "two distinct buckets");
    let (z0, c0) = zh[0];
    let (z3, c3) = zh[1];
    assert_eq!(z0, 0);
    assert_eq!(c0, 2);
    assert_eq!(z3, 3);
    assert_eq!(c3, 1);

    let _ = fs::remove_dir_all(d);
}

/// z_hist_to_sparse produces keys matching what build_direct_histogram would produce.
#[test]
fn z_hist_to_sparse_matches_direct_histogram() {
    let d = mk_temp_dir("skald_z_sparse_match");
    let chunk = write_chunk(&d, "Age,Zip\n20,100\n20,101\n21,100\n21,101\n22,102\n22,102\n");
    let chunks = vec![chunk];
    let qis = vec![
        QuasiIdentifierLite { column_name: "Age".to_string(), is_categorical: false,
            min_value: Some(20.0), max_value: Some(22.0), interval_hierarchy: None },
        QuasiIdentifierLite { column_name: "Zip".to_string(), is_categorical: false,
            min_value: Some(100.0), max_value: Some(102.0), interval_hierarchy: None },
    ];
    let (_n, cat_domains) = scan_chunks_for_flow(&chunks, &qis).expect("scan");
    let weights = compute_z_weights(&qis, &cat_domains).expect("weights");

    let (zh, n_z) = build_z_histogram(&chunks, &qis, &cat_domains, &weights).expect("z_hist");
    let (direct, n_d) = build_direct_histogram(&chunks, &qis, &cat_domains).expect("direct");

    assert_eq!(n_z, n_d);
    let sparse = z_hist_to_sparse(&zh, &weights);
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
    let chunk = write_chunk(
        &d,
        "Age,Zip\n20,100\n20,101\n21,100\n21,101\n22,102\n22,102\n23,103\n23,103\n",
    );
    let chunks = vec![chunk];
    let qis = vec![
        QuasiIdentifierLite { column_name: "Age".to_string(), is_categorical: false,
            min_value: Some(20.0), max_value: Some(23.0), interval_hierarchy: None },
        QuasiIdentifierLite { column_name: "Zip".to_string(), is_categorical: false,
            min_value: Some(100.0), max_value: Some(103.0), interval_hierarchy: None },
    ];
    let (_n, cat_domains) = scan_chunks_for_flow(&chunks, &qis).expect("scan");
    let weights = compute_z_weights(&qis, &cat_domains).expect("weights");

    let (zh, _) = build_z_histogram(&chunks, &qis, &cat_domains, &weights).expect("z_hist");
    let sparse = z_hist_to_sparse(&zh, &weights);

    let node = vec![2i64, 2i64];
    let merged_z = z_hist_to_sparse(&merge_z_histogram(&zh, &qis, &weights, &node), &weights);

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
    let chunk = write_chunk(
        &d,
        "Age,Zip\n20,100\n20,101\n21,100\n21,101\n22,102\n22,102\n23,103\n23,103\n",
    );
    let chunks = vec![chunk];
    let qis = vec![
        QuasiIdentifierLite { column_name: "Age".to_string(), is_categorical: false,
            min_value: Some(20.0), max_value: Some(23.0), interval_hierarchy: None },
        QuasiIdentifierLite { column_name: "Zip".to_string(), is_categorical: false,
            min_value: Some(100.0), max_value: Some(103.0), interval_hierarchy: None },
    ];
    let mut size = HashMap::new();
    size.insert("Age".to_string(), 2i64);
    size.insert("Zip".to_string(), 2i64);
    let (_n, cat_domains) = scan_chunks_for_flow(&chunks, &qis).expect("scan");
    let weights = compute_z_weights(&qis, &cat_domains).expect("weights");
    let ri = vec![1i64, 1i64];

    let (zh, n_z) = build_z_histogram(&chunks, &qis, &cat_domains, &weights).expect("z_hist");
    let sparse = z_hist_to_sparse(&zh, &weights);

    let r_z = find_ola2_best_rf_z_detailed(&qis, &zh, &weights, &ri, &size, 2, 0.0, n_z)
        .expect("ola2_z");
    let r_s = find_ola2_best_rf_detailed(&qis, &sparse, &ri, &size, 2, 0.0, n_z)
        .expect("ola2_sparse");

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
        r#"{"data_type":"T","T":{"quasi_identifiers":{"numerical":[{"column":"Age","type":"int","encode":false,"scale":false,"s":0}]}}}"#,
    ).expect("write cfg");

    let cfg = parse_runtime_config(&cfg_path).expect("parse");
    assert_eq!(cfg.flow_mode, FlowMode::Auto);
    let _ = fs::remove_dir_all(d);
}
