//! Tests for the block runtime.
//!
//! The properties worth pinning down here are the ones that only break when
//! work is split up — a single-process run cannot exhibit them, so nothing else
//! in the suite would catch a regression.

use super::plan::{build_plan, generate_keys};
use super::shard::{project_columns, split_rows, stamp_row_ids, stitch_columns};
use super::{BlockKeys, BlockManifest, Shard, DEFAULT_ROW_ID_COLUMN};
use crate::pipeline::bootstrap::parse_runtime_config;
use std::fs;
use std::path::{Path, PathBuf};

// ── Fixtures ─────────────────────────────────────────────────────────────────

fn tmp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("skald_block_tests/{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

const CSV: &str = "\
id,name,secret,age,city
1,Asha,AAA111,34,Pune
2,Ravi,BBB222,41,Pune
3,Meena,CCC333,34,Delhi
4,Kabir,DDD444,29,Delhi
";

fn write_csv(dir: &Path) -> PathBuf {
    let p = dir.join("in.csv");
    fs::write(&p, CSV).unwrap();
    p
}

fn config_json(dir: &Path, body: &str) -> PathBuf {
    let p = dir.join("cfg.json");
    fs::write(&p, body).unwrap();
    p
}

const CFG: &str = r#"{
  "data_type": "t",
  "t": {
    "pass": "no_bounds",
    "output_path": "out.csv",
    "suppression_limit": 0.5,
    "flow_mode": "direct",
    "suppress": ["name"],
    "hashing_with_salt": ["secret"],
    "quasi_identifiers": {
      "numerical": [{"column": "age", "type": "int"}],
      "categorical": [{"column": "city"}]
    },
    "size": {"age": 2},
    "compute_parameter_grid": false,
    "k_anonymize": {"k": 2}
  }
}"#;

fn manifest(dir: &Path, body: serde_json::Value) -> PathBuf {
    let p = dir.join("manifest.json");
    fs::write(&p, serde_json::to_string_pretty(&body).unwrap()).unwrap();
    p
}

// ── Sharding round trip ──────────────────────────────────────────────────────

#[test]
fn stamp_project_stitch_round_trips_without_touching_the_data() {
    let d = tmp("round_trip");
    let input = write_csv(&d);
    let staged = d.join("staged.csv");
    let rows = stamp_row_ids(&input, &staged, DEFAULT_ROW_ID_COLUMN).unwrap();
    assert_eq!(rows, 4);

    let a = d.join("a.csv");
    let b = d.join("b.csv");
    project_columns(&staged, &a, &["name".into(), "secret".into()], DEFAULT_ROW_ID_COLUMN).unwrap();
    project_columns(&staged, &b, &["age".into(), "city".into()], DEFAULT_ROW_ID_COLUMN).unwrap();

    let out = d.join("out.csv");
    stitch_columns(
        &staged,
        &[a, b],
        &["name".into(), "secret".into(), "age".into(), "city".into()],
        &out,
        DEFAULT_ROW_ID_COLUMN,
    )
    .unwrap();

    // Columns come back in the base order, the row id is gone, values intact.
    let got = fs::read_to_string(&out).unwrap();
    assert_eq!(got, CSV);
}

#[test]
fn a_projected_shard_carries_only_the_columns_it_was_given() {
    let d = tmp("projection_is_a_boundary");
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();

    let shard = d.join("crypto.csv");
    project_columns(&staged, &shard, &["secret".into()], DEFAULT_ROW_ID_COLUMN).unwrap();

    let body = fs::read_to_string(&shard).unwrap();
    // This is the privacy claim made concrete: a worker handed this file cannot
    // see the other columns however it misbehaves.
    assert!(body.contains("AAA111"));
    for leaked in ["Asha", "Pune", "34"] {
        assert!(!body.contains(leaked), "shard leaked '{leaked}':\n{body}");
    }
}

#[test]
fn stitching_drops_a_suppressed_column_but_keeps_a_passthrough_one() {
    let d = tmp("suppressed_vs_passthrough");
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();

    // A shard that was given `name` and `secret` and returned only `secret` —
    // i.e. `name` was suppressed. `city` was never routed anywhere.
    let shard = d.join("pre.out.csv");
    fs::write(
        &shard,
        "__skald_rid,secret\n0,x\n1,x\n2,x\n3,x\n",
    )
    .unwrap();

    let out = d.join("out.csv");
    stitch_columns(
        &staged,
        &[shard],
        &["name".into(), "secret".into()],
        &out,
        DEFAULT_ROW_ID_COLUMN,
    )
    .unwrap();

    let header = fs::read_to_string(&out).unwrap().lines().next().unwrap().to_string();
    assert_eq!(header, "id,secret,age,city");
}

#[test]
fn stitching_refuses_to_silently_lose_rows() {
    let d = tmp("lost_rows");
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();

    // A worker that came back two rows short.
    let shard = d.join("short.csv");
    fs::write(&shard, "__skald_rid,secret\n0,x\n1,x\n").unwrap();

    let err = stitch_columns(
        &staged,
        &[shard],
        &["secret".into()],
        &d.join("out.csv"),
        DEFAULT_ROW_ID_COLUMN,
    )
    .unwrap_err();
    assert!(format!("{err}").contains("BLOCK_SHARD_INCOMPLETE"), "{err}");
}

#[test]
fn stamping_refuses_input_that_already_uses_the_reserved_name() {
    let d = tmp("rid_collision");
    let p = d.join("in.csv");
    fs::write(&p, "__skald_rid,a\n1,2\n").unwrap();
    let err = stamp_row_ids(&p, &d.join("out.csv"), DEFAULT_ROW_ID_COLUMN).unwrap_err();
    assert!(format!("{err}").contains("BLOCK_RID_PROTECTED"), "{err}");
}

#[test]
fn splitting_repeats_the_header_in_every_row_shard() {
    let d = tmp("split_rows");
    let shards = split_rows(&write_csv(&d), &d.join("s"), "s", 2).unwrap();
    assert_eq!(shards.len(), 2);
    for s in &shards {
        let body = fs::read_to_string(s).unwrap();
        assert!(body.starts_with("id,name,secret,age,city\n"), "{body}");
        assert_eq!(body.lines().count(), 3);
    }
}

// ── Crypto block ─────────────────────────────────────────────────────────────

#[test]
fn the_crypto_block_refuses_to_run_without_orchestrator_supplied_keys() {
    let d = tmp("missing_key");
    let cfg = config_json(&d, CFG);
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();
    let shard = d.join("shard.csv");
    project_columns(&staged, &shard, &["secret".into()], DEFAULT_ROW_ID_COLUMN).unwrap();

    let m = manifest(
        &d,
        serde_json::json!({
            "schema_version": 1, "job_id": "j", "shard_id": "s", "block": "crypto",
            "config": cfg, "input": shard, "artifacts_dir": d.join("art"),
            "columns": ["secret"]
        }),
    );
    let err = super::crypto_block::run(&BlockManifest::load(&m).unwrap()).unwrap_err();
    // Generating one here would look like success and destroy the column across
    // shards, so the only safe behaviour is to stop.
    assert!(format!("{err}").contains("BLOCK_KEY_MISSING"), "{err}");
}

#[test]
fn one_salt_hashes_the_same_value_identically_in_every_shard() {
    let d = tmp("salt_consistency");
    let cfg = config_json(&d, CFG);
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();
    let whole = d.join("whole.csv");
    project_columns(&staged, &whole, &["secret".into()], DEFAULT_ROW_ID_COLUMN).unwrap();

    let keys = generate_keys(&parse_runtime_config(&cfg).unwrap()).unwrap();
    let row_shards = split_rows(&whole, &d.join("rows"), "r", 2).unwrap();

    let mut digests = Vec::new();
    for (i, s) in row_shards.iter().enumerate() {
        let out = d.join(format!("r{i}.out.csv"));
        let m = manifest_at(
            &d,
            &format!("m{i}.json"),
            serde_json::json!({
                "schema_version": 1, "job_id": "j", "shard_id": format!("r{i}"),
                "block": "crypto", "config": cfg, "input": s, "output": out,
                "artifacts_dir": d.join("art"), "columns": ["secret"],
                "keys": serde_json::to_value(&keys).unwrap()
            }),
        );
        super::crypto_block::run(&BlockManifest::load(&m).unwrap()).unwrap();
        let shard = Shard::read(&out, DEFAULT_ROW_ID_COLUMN).unwrap();
        let ci = shard.column_index("secret").unwrap();
        digests.extend(shard.rows.iter().map(|r| r[ci].clone()));
    }

    // Four distinct inputs under one salt: four distinct 64-hex digests, and
    // none of them the plaintext.
    assert_eq!(digests.len(), 4);
    assert!(digests.iter().all(|d| d.len() == 64 && d.chars().all(|c| c.is_ascii_hexdigit())));
    let unique: std::collections::BTreeSet<_> = digests.iter().collect();
    assert_eq!(unique.len(), 4);

    // The point of the test: rerunning shard 0 with the same key reproduces it.
    let out0 = d.join("r0.out.csv");
    let again = d.join("r0.again.csv");
    let m = manifest_at(
        &d,
        "again.json",
        serde_json::json!({
            "schema_version": 1, "job_id": "j", "shard_id": "again", "block": "crypto",
            "config": cfg, "input": row_shards[0].clone(), "output": again,
            "artifacts_dir": d.join("art"), "columns": ["secret"],
            "keys": serde_json::to_value(&keys).unwrap()
        }),
    );
    super::crypto_block::run(&BlockManifest::load(&m).unwrap()).unwrap();
    assert_eq!(fs::read_to_string(&out0).unwrap(), fs::read_to_string(&again).unwrap());
}

#[test]
fn a_column_routed_elsewhere_is_deferred_not_failed() {
    let d = tmp("deferred");
    let cfg = config_json(&d, CFG);
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();
    let shard = d.join("other.csv");
    project_columns(&staged, &shard, &["age".into()], DEFAULT_ROW_ID_COLUMN).unwrap();

    let m = manifest(
        &d,
        serde_json::json!({
            "schema_version": 1, "job_id": "j", "shard_id": "s", "block": "crypto",
            "config": cfg, "input": shard, "output": d.join("o.csv"),
            "artifacts_dir": d.join("art"), "columns": ["age"],
            "keys": {"hash_salts": {}}
        }),
    );
    // `secret` belongs to another shard — that is the orchestrator's routing
    // decision, not an error, and no key is needed for work not done here.
    let report = super::crypto_block::run(&BlockManifest::load(&m).unwrap()).unwrap();
    assert!(report.applied.is_empty());
    assert_eq!(report.deferred, vec!["hash_salted:secret"]);
}

// ── Preprocess block ─────────────────────────────────────────────────────────

#[test]
fn preprocess_suppresses_a_column_and_leaves_the_row_id_alone() {
    let d = tmp("suppress");
    let cfg = config_json(&d, CFG);
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();
    let shard = d.join("pre.csv");
    project_columns(&staged, &shard, &["name".into()], DEFAULT_ROW_ID_COLUMN).unwrap();

    let out = d.join("pre.out.csv");
    let m = manifest(
        &d,
        serde_json::json!({
            "schema_version": 1, "job_id": "j", "shard_id": "pre", "block": "preprocess",
            "config": cfg, "input": shard, "output": out,
            "artifacts_dir": d.join("art"), "columns": ["name"]
        }),
    );
    let report = super::preprocess_block::run(&BlockManifest::load(&m).unwrap()).unwrap();
    assert_eq!(report.applied, vec!["suppress:name"]);
    assert_eq!(report.rows_in, report.rows_out);
    assert_eq!(fs::read_to_string(&out).unwrap(), "__skald_rid\n0\n1\n2\n3\n");
}

#[test]
fn preprocess_refuses_a_config_that_targets_the_row_id() {
    let d = tmp("rid_protected");
    let cfg = config_json(
        &d,
        &CFG.replace(r#""suppress": ["name"]"#, r#""suppress": ["__skald_rid"]"#),
    );
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();

    let m = manifest(
        &d,
        serde_json::json!({
            "schema_version": 1, "job_id": "j", "shard_id": "pre", "block": "preprocess",
            "config": cfg, "input": staged, "output": d.join("o.csv"),
            "artifacts_dir": d.join("art")
        }),
    );
    let err = super::preprocess_block::run(&BlockManifest::load(&m).unwrap()).unwrap_err();
    assert!(format!("{err}").contains("BLOCK_RID_PROTECTED"), "{err}");
}

// ── k-anon ───────────────────────────────────────────────────────────────────

#[test]
fn scan_then_solve_gives_the_same_answer_however_the_rows_were_split() {
    let d = tmp("shard_invariance");
    let cfg = config_json(&d, CFG);
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();
    let qi = d.join("qi.csv");
    project_columns(&staged, &qi, &["age".into(), "city".into()], DEFAULT_ROW_ID_COLUMN).unwrap();

    // The property that matters: how the orchestrator chose to split the rows
    // must not be observable in the result.
    let one = solve_with_shard_size(&d, &cfg, &qi, 4, "one");
    let many = solve_with_shard_size(&d, &cfg, &qi, 1, "many");
    assert_eq!(one.total_records, many.total_records);
    assert_eq!(one.final_rf, many.final_rf);
    assert_eq!(one.suppressed_records, many.suppressed_records);
    assert_eq!(one.suppressed_classes, many.suppressed_classes);
    assert_eq!(one.numeric_bounds, many.numeric_bounds);
    assert_eq!(one.categorical_domains, many.categorical_domains);
}

fn solve_with_shard_size(
    d: &Path,
    cfg: &Path,
    qi: &Path,
    rows: usize,
    tag: &str,
) -> super::kanon_block::Solution {
    let art = d.join(format!("art_{tag}"));
    let shards = split_rows(qi, &d.join(format!("rows_{tag}")), tag, rows).unwrap();
    let mut scans = Vec::new();
    for (i, s) in shards.iter().enumerate() {
        let m = manifest_at(
            d,
            &format!("{tag}_scan{i}.json"),
            serde_json::json!({
                "schema_version": 1, "job_id": "j", "shard_id": format!("{tag}_{i}"),
                "block": "kanon", "stage": "scan", "config": cfg,
                "input": s, "artifacts_dir": art
            }),
        );
        super::kanon_block::run(&BlockManifest::load(&m).unwrap()).unwrap();
        scans.push(art.join(format!("{tag}_{i}.scan.json")));
    }
    let m = manifest_at(
        d,
        &format!("{tag}_solve.json"),
        serde_json::json!({
            "schema_version": 1, "job_id": "j", "shard_id": "solve", "block": "kanon",
            "stage": "solve", "config": cfg, "artifacts_dir": art, "inputs": scans
        }),
    );
    super::kanon_block::run(&BlockManifest::load(&m).unwrap()).unwrap();
    serde_json::from_str(&fs::read_to_string(art.join("solution.json")).unwrap()).unwrap()
}

#[test]
fn pass_two_resolves_from_the_persisted_histogram_with_no_data_present() {
    let d = tmp("two_pass");
    let p1 = config_json(&d, &CFG.replace(r#""pass": "no_bounds""#, r#""pass": "pass1""#));
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();
    let qi = d.join("qi.csv");
    project_columns(&staged, &qi, &["age".into(), "city".into()], DEFAULT_ROW_ID_COLUMN).unwrap();
    let art = d.join("art");

    let m = manifest_at(
        &d,
        "scan.json",
        serde_json::json!({
            "schema_version": 1, "job_id": "j", "shard_id": "s0", "block": "kanon",
            "stage": "scan", "config": p1, "input": qi.clone(), "artifacts_dir": art
        }),
    );
    super::kanon_block::run(&BlockManifest::load(&m).unwrap()).unwrap();

    let m = manifest_at(
        &d,
        "solve1.json",
        serde_json::json!({
            "schema_version": 1, "job_id": "j", "shard_id": "solve", "block": "kanon",
            "stage": "solve", "config": p1, "artifacts_dir": art,
            "inputs": [art.join("s0.scan.json")]
        }),
    );
    super::kanon_block::run(&BlockManifest::load(&m).unwrap()).unwrap();
    let s1: super::kanon_block::Solution =
        serde_json::from_str(&fs::read_to_string(art.join("solution.json")).unwrap()).unwrap();
    assert!(s1.k_optimal.is_some(), "pass1 should report k_optimal");
    assert!(s1.final_rf.is_none(), "pass1 stops before the lattice search");
    assert!(art.join("histogram.json").exists());

    // Everything the scan read is now gone. Pass 2 must still solve.
    fs::remove_file(&qi).unwrap();
    fs::remove_file(&staged).unwrap();
    fs::remove_file(art.join("s0.scan.json")).unwrap();

    let p2 = config_json(&d, CFG); // no_bounds + k=2
    let m = manifest_at(
        &d,
        "solve2.json",
        serde_json::json!({
            "schema_version": 1, "job_id": "j", "shard_id": "solve", "block": "kanon",
            "stage": "solve", "config": p2, "artifacts_dir": art, "inputs": []
        }),
    );
    super::kanon_block::run(&BlockManifest::load(&m).unwrap()).unwrap();
    let s2: super::kanon_block::Solution =
        serde_json::from_str(&fs::read_to_string(art.join("solution.json")).unwrap()).unwrap();
    assert!(s2.final_rf.is_some(), "pass2 should produce a generalization node");
    assert_eq!(s2.total_records, s1.total_records);
}

#[test]
fn solving_without_scans_or_a_histogram_says_what_to_run_first() {
    let d = tmp("no_histogram");
    let cfg = config_json(&d, CFG);
    let m = manifest(
        &d,
        serde_json::json!({
            "schema_version": 1, "job_id": "j", "shard_id": "solve", "block": "kanon",
            "stage": "solve", "config": cfg, "artifacts_dir": d.join("art"), "inputs": []
        }),
    );
    let err = super::kanon_block::run(&BlockManifest::load(&m).unwrap()).unwrap_err();
    assert!(format!("{err}").contains("BLOCK_HISTOGRAM_MISSING"), "{err}");
}

#[test]
fn applying_a_pass_one_solution_is_refused() {
    let d = tmp("pass1_apply");
    let p1 = config_json(&d, &CFG.replace(r#""pass": "no_bounds""#, r#""pass": "pass1""#));
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();
    let qi = d.join("qi.csv");
    project_columns(&staged, &qi, &["age".into(), "city".into()], DEFAULT_ROW_ID_COLUMN).unwrap();
    let art = d.join("art");

    for (name, extra) in [
        ("scan.json", serde_json::json!({"stage": "scan", "input": qi.clone()})),
        ("solve.json", serde_json::json!({"stage": "solve", "inputs": [art.join("s0.scan.json")]})),
    ] {
        let mut body = serde_json::json!({
            "schema_version": 1, "job_id": "j", "shard_id": "s0", "block": "kanon",
            "config": p1, "artifacts_dir": art
        });
        for (k, v) in extra.as_object().unwrap() {
            body[k] = v.clone();
        }
        let m = manifest_at(&d, name, body);
        super::kanon_block::run(&BlockManifest::load(&m).unwrap()).unwrap();
    }

    let m = manifest_at(
        &d,
        "apply.json",
        serde_json::json!({
            "schema_version": 1, "job_id": "j", "shard_id": "s0", "block": "kanon",
            "stage": "apply", "config": p1, "input": qi, "output": d.join("o.csv"),
            "artifacts_dir": art
        }),
    );
    let err = super::kanon_block::run(&BlockManifest::load(&m).unwrap()).unwrap_err();
    assert!(format!("{err}").contains("BLOCK_SOLUTION_INCOMPLETE"), "{err}");
}

#[test]
fn scanning_a_shard_missing_a_quasi_identifier_explains_the_routing_rule() {
    let d = tmp("split_qis");
    let cfg = config_json(&d, CFG);
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();
    // Only half the QI tuple — a column-sharding mistake the block must catch.
    let half = d.join("half.csv");
    project_columns(&staged, &half, &["age".into()], DEFAULT_ROW_ID_COLUMN).unwrap();

    let m = manifest(
        &d,
        serde_json::json!({
            "schema_version": 1, "job_id": "j", "shard_id": "s", "block": "kanon",
            "stage": "scan", "config": cfg, "input": half, "artifacts_dir": d.join("art")
        }),
    );
    let err = super::kanon_block::run(&BlockManifest::load(&m).unwrap()).unwrap_err();
    assert!(format!("{err}").contains("BLOCK_QI_SHARD_INCOMPLETE"), "{err}");
}

// ── Planner ──────────────────────────────────────────────────────────────────

#[test]
fn the_plan_routes_each_column_to_exactly_one_block() {
    let d = tmp("plan");
    let cfg = config_json(&d, CFG);
    let header: Vec<String> =
        "id,name,secret,age,city".split(',').map(str::to_string).collect();
    let plan = build_plan(&cfg, "job-1", Some(&header)).unwrap();

    let by_block = |b: &str| {
        plan.groups.iter().find(|g| g.block == b).map(|g| g.columns.clone()).unwrap_or_default()
    };
    assert_eq!(by_block("preprocess"), vec!["name"]);
    assert_eq!(by_block("crypto"), vec!["secret"]);
    assert_eq!(by_block("kanon"), vec!["age", "city"]);
    assert_eq!(plan.passthrough_columns, vec!["id"]);
    assert_eq!(plan.keys_required.hash_salts, vec!["secret"]);
    assert!(plan.multi_block_columns.is_empty());

    // Ordering is what the orchestrator schedules on.
    let order = |b: &str| plan.groups.iter().find(|g| g.block == b).unwrap().order;
    assert!(order("preprocess") < order("crypto"));
    assert!(order("crypto") < order("kanon"));
}

#[test]
fn a_tokenized_column_is_marked_not_row_parallel() {
    let d = tmp("token_serial");
    let cfg = config_json(
        &d,
        &CFG.replace(
            r#""suppress": ["name"]"#,
            r#""suppress": ["name"], "tokenization": [{"column": "city", "prefix": "C-"}]"#,
        ),
    );
    let plan = build_plan(&cfg, "j", None).unwrap();
    let pre = plan.groups.iter().find(|g| g.block == "preprocess").unwrap();
    // Two shards of one tokenized column would each start their counter at 1
    // and mint the same token for different values.
    assert!(!pre.row_parallel);
    assert!(pre.row_parallel_note.as_ref().unwrap().contains("vault"));
}

#[test]
fn suppressing_a_quasi_identifier_is_caught_before_any_container_starts() {
    let d = tmp("conflict");
    let cfg = config_json(&d, &CFG.replace(r#""suppress": ["name"]"#, r#""suppress": ["age"]"#));
    let err = build_plan(&cfg, "j", None).unwrap_err();
    assert!(format!("{err}").contains("PLAN_COLUMN_CONFLICT"), "{err}");
}

#[test]
fn a_config_naming_a_column_the_data_lacks_fails_planning() {
    let d = tmp("missing_col");
    let cfg = config_json(&d, CFG);
    let header: Vec<String> = "id,age,city".split(',').map(str::to_string).collect();
    let err = build_plan(&cfg, "j", Some(&header)).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("PLAN_COLUMN_MISSING"), "{msg}");
    assert!(msg.contains("name") && msg.contains("secret"), "{msg}");
}

#[test]
fn keygen_covers_exactly_what_the_plan_says_is_required() {
    let d = tmp("keygen");
    let cfg = config_json(
        &d,
        &CFG.replace(
            r#""hashing_with_salt": ["secret"]"#,
            r#""hashing_with_salt": ["secret"], "encrypt": ["name"]"#,
        ),
    );
    let parsed = parse_runtime_config(&cfg).unwrap();
    let keys: BlockKeys = generate_keys(&parsed).unwrap();
    assert!(keys.hash_salts.contains_key("secret"));
    assert!(keys.symmetric_keys.contains_key("name"));
    assert!(keys.fpe_keys.is_empty());
    // Fresh material per call — nothing is derived from the config.
    let again = generate_keys(&parsed).unwrap();
    assert_ne!(keys.hash_salts["secret"], again.hash_salts["secret"]);
}

// ── Manifest ─────────────────────────────────────────────────────────────────

#[test]
fn manifest_paths_resolve_against_the_manifest_directory() {
    let d = tmp("manifest_paths");
    fs::create_dir_all(d.join("job")).unwrap();
    let m = d.join("job/manifest.json");
    fs::write(
        &m,
        r#"{"schema_version":1,"job_id":"j","block":"crypto","config":"../cfg.json",
            "input":"in.csv","artifacts_dir":"art"}"#,
    )
    .unwrap();
    let loaded = BlockManifest::load(&m).unwrap();
    assert_eq!(loaded.config, d.join("job/../cfg.json"));
    assert_eq!(loaded.input.unwrap(), d.join("job/in.csv"));
    assert_eq!(loaded.artifacts_dir, d.join("job/art"));
    assert_eq!(loaded.shard_id, "shard_0");
    assert_eq!(loaded.row_id_column, DEFAULT_ROW_ID_COLUMN);
}

#[test]
fn a_manifest_from_a_future_schema_is_refused_rather_than_guessed_at() {
    let d = tmp("schema");
    let m = d.join("manifest.json");
    fs::write(&m, r#"{"schema_version":99,"job_id":"j","block":"crypto","config":"c.json"}"#)
        .unwrap();
    let err = BlockManifest::load(&m).unwrap_err();
    assert!(format!("{err}").contains("BLOCK_SCHEMA_MISMATCH"), "{err}");
}

fn manifest_at(dir: &Path, name: &str, body: serde_json::Value) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, serde_json::to_string_pretty(&body).unwrap()).unwrap();
    p
}
