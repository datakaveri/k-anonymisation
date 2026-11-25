//! The batch API, driven the way a distributed job drives it, must give the
//! rows, the grid and the node the command line gives on the whole file —
//! whatever the number of batches and the order they are merged in.
//!
//! Expected values are `conformance/expected`, recorded from the 4.1.0 binary.

use serde_json::Value;
use skald_ola2::batch::{
    Decision, Generalizer, Histogram, KeyKind, KeyMaterial, KeyPolicy, MemoryVault, Model, Plan, Preprocessor, Stats,
    Table, Tally, TokenPolicy,
};
use std::fs;
use std::path::{Path, PathBuf};

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("conformance")
}

fn split(t: &Table, n: usize) -> Vec<Table> {
    let per = t.rows.len().div_ceil(n).max(1);
    t.rows
        .chunks(per)
        .enumerate()
        .map(|(i, rows)| Table::new(t.headers.clone(), rows.to_vec(), format!("batch {i}")))
        .collect()
}

fn read_keys(dir: &Path) -> KeyMaterial {
    let mut keys = KeyMaterial::new();
    for (file, kind) in [
        ("tabular_hash_salts.json", KeyKind::HmacSalt),
        ("symmetric_keys.json", KeyKind::AesKey),
        ("fpe_encrypt_keys.json", KeyKind::FpeKey),
    ] {
        let v: Value = serde_json::from_str(&fs::read_to_string(dir.join(file)).unwrap()).unwrap();
        for (col, hex) in v.as_object().unwrap() {
            keys.insert_hex(kind, col, hex.as_str().unwrap()).unwrap();
        }
    }
    keys
}

struct Outcome {
    rows: Vec<Vec<String>>,
    headers: Vec<String>,
    decision: Option<Decision>,
    node: Option<Vec<i64>>,
    grid: Option<Value>,
    verified_min_class: Option<i64>,
}

/// Runs a case through the API in `n` batches. `reverse` merges the per-batch
/// reports back to front, to show the order does not matter.
fn run(case: &str, n: usize, reverse: bool) -> Outcome {
    let dir = corpus().join("cases").join(case);
    let plan = Plan::from_json(&fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    let cfg = &plan.cfg;
    let batches = split(&Table::from_csv_file(&dir.join("data.csv")).unwrap(), n);

    // Executors preprocess with keys they were given and may not generate.
    let mut pre = Preprocessor::new(
        cfg,
        read_keys(&dir.join("testkeys")),
        KeyPolicy::Require,
        MemoryVault::new(),
        TokenPolicy::LookupOnly,
    )
    .unwrap();
    let mut batches: Vec<Table> = batches
        .into_iter()
        .map(|mut b| {
            pre.apply(&mut b).unwrap();
            b
        })
        .collect();
    if !plan.has_quasi_identifiers() {
        return Outcome {
            rows: batches.iter().flat_map(|b| b.rows.clone()).collect(),
            headers: batches[0].headers.clone(),
            decision: None,
            node: None,
            grid: None,
            verified_min_class: None,
        };
    }

    let order = |len: usize| -> Vec<usize> { if reverse { (0..len).rev().collect() } else { (0..len).collect() } };

    let cols = plan.qi_columns();
    let mut stats = Stats::new(&cols);
    for i in order(batches.len()) {
        let mut s = Stats::new(&cols);
        s.observe(&cols, &batches[i]).unwrap();
        // Over the wire and back, as a Spark job sends it.
        let s: Stats = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        stats.merge(&s).unwrap();
    }
    let model = Model::build(cfg, &stats, None).unwrap();

    let mut hist = model.new_histogram();
    for i in order(batches.len()) {
        let mut h = model.new_histogram();
        h.observe(&model, &batches[i]).unwrap();
        hist.merge(&Histogram::from_bytes(&h.to_bytes()).unwrap()).unwrap();
    }

    let grid = (cfg.pass != "pass2" && cfg.compute_param_grid)
        .then(|| serde_json::to_value(model.parameter_grid(&hist).unwrap().entries).unwrap());
    if cfg.pass == "pass1" {
        return Outcome { rows: vec![], headers: vec![], decision: None, node: None, grid, verified_min_class: None };
    }
    let node = match &cfg.generalization_node {
        Some(chosen) if cfg.pass == "pass2" => model.node_from_names(chosen).unwrap(),
        _ => model.search(&hist, cfg.k, cfg.suppression_limit).unwrap().best_rf,
    };

    let g = Generalizer::new(&model.qis, &node, &cfg.categorical_hierarchies, cfg.l_diversity.as_ref()).unwrap();
    let mut tally = Tally::new(cfg.l_diversity.as_ref());
    for i in order(batches.len()) {
        let t = g.apply(&mut batches[i]).unwrap();
        tally.merge(&Tally::from_bytes(&t.to_bytes()).unwrap());
    }
    let decision = Decision::from_bytes(&tally.decide(cfg.k, cfg.l_diversity.as_ref()).to_bytes()).unwrap();
    for b in &mut batches {
        g.finish(b, &decision).unwrap();
    }

    // The final check, on the rows as written.
    let mut out = Tally::new(cfg.l_diversity.as_ref());
    for b in &batches {
        out.merge(&g.tally(b).unwrap());
    }
    let verified_min_class = Some(out.verify(cfg.k, cfg.l_diversity.as_ref()).unwrap());

    Outcome {
        rows: batches.iter().flat_map(|b| b.rows.clone()).collect(),
        headers: batches[0].headers.clone(),
        decision: Some(decision),
        node: Some(node),
        grid,
        verified_min_class,
    }
}

fn cases() -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(corpus().join("cases"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into())
        .collect();
    v.sort();
    v
}

fn check(case: &str, n: usize, reverse: bool) {
    let got = run(case, n, reverse);
    let exp = corpus().join("expected").join(case);
    let status: Value = serde_json::from_str(&fs::read_to_string(exp.join("status.json")).unwrap()).unwrap();
    let outputs = &status["outputs"];
    let label = format!("{case}, {n} batch(es), reverse={reverse}");

    if let Some(grid) = &got.grid {
        assert_eq!(grid, &outputs["parameter_grid"], "{label}: parameter grid");
    }
    if outputs["pass"] == "pass1" {
        return;
    }
    if exp.join("anonymized.csv").exists() {
        let want = Table::from_csv_file(&exp.join("anonymized.csv")).unwrap();
        assert_eq!(got.headers, want.headers, "{label}: headers");
        assert_eq!(got.rows, want.rows, "{label}: rows");
    }
    if let (Some(node), Some(d)) = (&got.node, &got.decision) {
        assert_eq!(&serde_json::to_value(node).unwrap(), &outputs["final_rf"], "{label}: node");
        assert_eq!(d.summary.suppressed_records, outputs["suppressed_records"].as_i64().unwrap(), "{label}");
        assert_eq!(d.summary.removed_records, outputs["removed_records"].as_i64().unwrap(), "{label}");
        let want: Value =
            serde_json::from_str(&fs::read_to_string(exp.join("equivalence_class_stats.json")).unwrap()).unwrap();
        assert_eq!(serde_json::to_value(&d.summary.class_size_counts).unwrap(), want, "{label}: class sizes");
        assert!(got.verified_min_class.unwrap() >= 1, "{label}: final k check");
    }
}

#[test]
fn any_number_of_batches_gives_the_command_lines_output() {
    for case in cases() {
        for n in [1, 2, 7, 40] {
            check(&case, n, false);
        }
    }
}

#[test]
fn merge_order_does_not_matter() {
    for case in cases() {
        check(&case, 5, true);
    }
}

#[test]
fn the_final_check_catches_an_output_that_is_not_k_anonymous() {
    let dir = corpus().join("cases/basic_pass2");
    let plan = Plan::from_json(&fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    let cols = plan.qi_columns();
    let mut stats = Stats::new(&cols);
    stats.observe(&cols, &Table::from_csv_file(&dir.join("data.csv")).unwrap()).unwrap();
    let model = Model::build(&plan.cfg, &stats, None).unwrap();
    let g = Generalizer::new(&model.qis, &model.initial_ri, &plan.cfg.categorical_hierarchies, None).unwrap();

    // The file the command line wrote tallies as k-anonymous...
    let written = Table::from_csv_file(&corpus().join("expected/basic_pass2/anonymized.csv")).unwrap();
    let t = g.tally(&written).unwrap();
    assert!(t.verify(plan.cfg.k, None).unwrap() >= plan.cfg.k);
    // ...and fails against a larger k than it was made for.
    assert!(t.verify(1000, None).is_err());
}
