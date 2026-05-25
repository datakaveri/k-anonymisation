use super::anonymization::{
    find_ola1_initial_ri, find_ola2_best_rf, generalize_and_write_outputs, QuasiIdentifierLite,
};
use super::bootstrap::{find_first_json_config, parse_runtime_config, split_csv_by_ram};
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
