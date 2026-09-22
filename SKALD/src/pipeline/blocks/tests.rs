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
    // Suppression is the orchestrator's: a dropped column reaches no container.
    assert_eq!(by_block("stage"), vec!["name"]);
    assert_eq!(by_block("crypto"), vec!["secret"]);
    assert_eq!(by_block("kanon"), vec!["age", "city"]);
    assert_eq!(plan.passthrough_columns, vec!["id"]);
    assert_eq!(plan.keys_required.hash_salts, vec!["secret"]);
    assert!(plan.multi_block_columns.is_empty());

    // Ordering is what the orchestrator schedules on.
    let order = |b: &str| plan.groups.iter().find(|g| g.block == b).unwrap().order;
    assert!(order("stage") < order("crypto"));
    assert!(order("crypto") < order("kanon"));
}

#[test]
fn only_the_staging_group_runs_on_the_orchestrator() {
    let d = tmp("placement");
    let cfg = config_json(
        &d,
        &CFG.replace(
            r#""suppress": ["name"]"#,
            r#""suppress": ["name"], "charcloak": ["city"]"#,
        ),
    );
    let plan = build_plan(&cfg, "j", None).unwrap();
    for g in &plan.groups {
        let expected = if g.block == "stage" { "orchestrator" } else { "container" };
        assert_eq!(g.runs_on, expected, "block {} runs on the wrong side", g.block);
    }
    // Masking, charcloak and tokenisation are ordinary column transforms and
    // belong in a worker, not on the orchestrator.
    let pre = plan.groups.iter().find(|g| g.block == "preprocess").unwrap();
    assert_eq!(pre.runs_on, "container");
    assert_eq!(pre.operations, vec!["charcloak:city"]);
    assert!(!pre.operations.iter().any(|o| o.starts_with("suppress")));
}

#[test]
fn the_plan_names_container_roles_and_never_images() {
    let d = tmp("roles");
    let cfg = config_json(&d, CFG);
    let plan = build_plan(&cfg, "j", None).unwrap();
    let json = serde_json::to_string(&plan).unwrap();
    // Resolution is the Co-ordinator's business; an image reference emitted
    // here would be a guess about something this side does not own.
    assert!(!json.contains("ghcr.io"), "plan named an image: {json}");
    assert!(!json.contains("sha256:"), "plan named a digest: {json}");
    for g in plan.groups.iter().filter(|g| g.runs_on == "container") {
        assert!(g.container_role.is_some(), "{} has no container_role", g.block);
    }
    assert!(plan.groups.iter().find(|g| g.block == "stage").unwrap().container_role.is_none());
}

#[test]
fn solve_is_not_planned_as_a_container_stage() {
    let d = tmp("solve_placement");
    let cfg = config_json(&d, CFG);
    let plan = build_plan(&cfg, "j", None).unwrap();
    let kanon = plan.groups.iter().find(|g| g.block == "kanon").unwrap();
    // Solve reduces a histogram, never rows. Dispatching it would mean a
    // container held open across the user's choice of k for no benefit.
    assert!(!kanon.stages.contains(&"solve".to_string()), "{:?}", kanon.stages);
    assert_eq!(kanon.stages, vec!["scan", "apply"]);
    assert!(plan.notes.iter().any(|n| n.contains("runs on the orchestrator")));
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

// ── Staging: cleaning, suppression, row ids ──────────────────────────────────

const DIRTY: &str = "\
id,name,age,city
1, Asha ,34,Pune
2,N/A,41,  New   Delhi
3,Meena,n/a,Delhi
,,,\u{20}
5,Kabir,notanumber,Pune
";

const CLEAN_CFG: &str = r#"{
  "data_type": "t",
  "t": {
    "pass": "no_bounds",
    "output_path": "out.csv",
    "suppression_limit": 0.5,
    "flow_mode": "direct",
    "suppress": ["name"],
    "cleaning": {
      "enabled": true,
      "numeric_columns": ["age"],
      "required_columns": ["age"]
    },
    "quasi_identifiers": {
      "numerical": [{"column": "age", "type": "int"}],
      "categorical": [{"column": "city"}]
    },
    "size": {"age": 2},
    "compute_parameter_grid": false,
    "k_anonymize": {"k": 2}
  }
}"#;

#[test]
fn staging_normalises_missing_values_trims_and_collapses_whitespace() {
    let d = tmp("cleaning");
    let input = d.join("dirty.csv");
    fs::write(&input, DIRTY).unwrap();
    let cfg = config_json(&d, &CLEAN_CFG.replace(r#""required_columns": ["age"]"#, r#""required_columns": []"#));
    let out = d.join("staged.csv");

    let report = super::stage::stage(&cfg, &input, &out, DEFAULT_ROW_ID_COLUMN, false).unwrap();
    let body = fs::read_to_string(&out).unwrap();

    // " Asha " trimmed; "  New   Delhi" trimmed and internally collapsed.
    assert!(body.contains("0,1,Asha,34,Pune"), "{body}");
    assert!(body.contains("1,2,,41,New Delhi"), "{body}");
    // "N/A" and "n/a" both became the missing-value representation, so they can
    // no longer key their own equivalence class downstream.
    assert!(!body.contains("N/A") && !body.contains("n/a"), "{body}");
    // "notanumber" in a numeric column is missing data in disguise.
    assert!(body.contains("3,5,Kabir,,Pune"), "{body}");
    assert_eq!(report.non_numeric.get("age"), Some(&1));
    assert!(report.nulls_normalised.get("name").is_some());
    assert!(report.whitespace_fixed.get("city").is_some());
    // The all-empty row is gone; the rest survive.
    assert_eq!(report.rows_in, 5);
    assert_eq!(report.rows_out, 4);
    assert_eq!(report.dropped_by_reason.get("all_fields_empty"), Some(&1));
}

#[test]
fn staging_drops_rows_missing_a_required_column() {
    let d = tmp("required");
    let input = d.join("dirty.csv");
    fs::write(&input, DIRTY).unwrap();
    let cfg = config_json(&d, CLEAN_CFG);
    let out = d.join("staged.csv");

    let report = super::stage::stage(&cfg, &input, &out, DEFAULT_ROW_ID_COLUMN, false).unwrap();
    // Rows 3 (age "n/a"), 4 (empty) and 5 (age "notanumber") all lose `age`.
    assert_eq!(report.rows_out, 2);
    // Row 4 is empty throughout and goes first; rows 3 and 5 lose `age` to
    // the missing-value and numeric-coercion rules respectively.
    assert_eq!(report.dropped_by_reason.get("required_column_empty:age"), Some(&2));
    assert_eq!(report.dropped_by_reason.get("all_fields_empty"), Some(&1));
}

#[test]
fn staging_refuses_to_quietly_discard_most_of_the_dataset() {
    let d = tmp("too_many_dropped");
    let input = d.join("dirty.csv");
    fs::write(&input, DIRTY).unwrap();
    let cfg = config_json(
        &d,
        &CLEAN_CFG.replace(
            r#""required_columns": ["age"]"#,
            r#""required_columns": ["age"], "max_dropped_fraction": 0.2"#,
        ),
    );
    let err = super::stage::stage(&cfg, &input, &d.join("o.csv"), DEFAULT_ROW_ID_COLUMN, false)
        .unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("STAGE_TOO_MANY_DROPPED"), "{msg}");
    // The message has to say what was dropped, not only how much.
    assert!(msg.contains("required_column_empty:age"), "{msg}");
    assert!(!d.join("o.csv").exists(), "a refused stage must leave no output");
}

#[test]
fn staging_suppresses_columns_and_stamps_dense_row_ids() {
    let d = tmp("stage_suppress");
    let input = d.join("dirty.csv");
    fs::write(&input, DIRTY).unwrap();
    let cfg = config_json(&d, CLEAN_CFG);
    let out = d.join("staged.csv");

    let report = super::stage::stage(&cfg, &input, &out, DEFAULT_ROW_ID_COLUMN, true).unwrap();
    assert_eq!(report.columns_suppressed, vec!["name"]);
    assert_eq!(report.columns_out, vec!["__skald_rid", "id", "age", "city"]);

    let body = fs::read_to_string(&out).unwrap();
    assert!(!body.contains("Asha") && !body.contains("Kabir"), "suppressed column survived:\n{body}");
    // Ids are assigned after cleaning, so they are dense over the rows that
    // actually exist rather than over the rows the input happened to have.
    let ids: Vec<&str> = body.lines().skip(1).map(|l| l.split(',').next().unwrap()).collect();
    assert_eq!(ids, vec!["0", "1"]);
}

#[test]
fn staging_without_a_cleaning_section_only_suppresses_and_stamps() {
    let d = tmp("no_cleaning");
    let input = d.join("dirty.csv");
    fs::write(&input, DIRTY).unwrap();
    let cfg = config_json(&d, CFG); // no "cleaning" key at all
    let out = d.join("staged.csv");

    let report = super::stage::stage(&cfg, &input, &out, DEFAULT_ROW_ID_COLUMN, false).unwrap();
    // Cleaning changes the row set, so it is never applied to a job that did
    // not ask for it.
    assert!(!report.cleaning_enabled);
    assert_eq!(report.rows_in, report.rows_out);
    assert!(fs::read_to_string(&out).unwrap().contains("N/A"));
}

#[test]
fn staging_fails_on_a_cleaning_column_the_data_lacks() {
    let d = tmp("clean_missing_col");
    let input = d.join("dirty.csv");
    fs::write(&input, DIRTY).unwrap();
    let cfg = config_json(&d, &CLEAN_CFG.replace(r#""numeric_columns": ["age"]"#, r#""numeric_columns": ["nope"]"#));
    let err = super::stage::stage(&cfg, &input, &d.join("o.csv"), DEFAULT_ROW_ID_COLUMN, false)
        .unwrap_err();
    assert!(format!("{err}").contains("STAGE_COLUMN_MISSING"), "{err}");
}

#[test]
fn solve_counts_rows_no_class_can_vouch_for_before_apply_runs() {
    let d = tmp("unplaceable");
    let cfg = config_json(&d, CFG);
    // One row whose `age` is empty — what cleaning produces from "N/A" when the
    // column is not in required_columns. It never enters the histogram, so the
    // lattice cannot see it, but `apply` will star it.
    let input = d.join("in.csv");
    fs::write(
        &input,
        "id,name,secret,age,city\n1,A,X,34,Pune\n2,B,Y,34,Pune\n3,C,Z,,Delhi\n",
    )
    .unwrap();
    let staged = d.join("staged.csv");
    stamp_row_ids(&input, &staged, DEFAULT_ROW_ID_COLUMN).unwrap();
    let qi = d.join("qi.csv");
    project_columns(&staged, &qi, &["age".into(), "city".into()], DEFAULT_ROW_ID_COLUMN).unwrap();
    let art = d.join("art");

    for (name, extra) in [
        ("scan.json", serde_json::json!({"stage": "scan", "input": qi.clone()})),
        ("solve.json", serde_json::json!({"stage": "solve", "inputs": [art.join("s0.scan.json")]})),
    ] {
        let mut m = serde_json::json!({
            "schema_version": 1, "job_id": "j", "shard_id": "s0", "block": "kanon",
            "config": cfg, "artifacts_dir": art
        });
        for (k, v) in extra.as_object().unwrap() {
            m[k] = v.clone();
        }
        super::kanon_block::run(&BlockManifest::load(&manifest_at(&d, name, m)).unwrap()).unwrap();
    }

    let sol: super::kanon_block::Solution =
        serde_json::from_str(&fs::read_to_string(art.join("solution.json")).unwrap()).unwrap();
    assert_eq!(sol.unplaceable_records, 1);
    assert_eq!(sol.total_records, 2, "the unplaceable row is not in the histogram");

    // The prediction has to hold against what apply actually does, or the
    // number shown to the user before the phase runs is worth nothing.
    let out = d.join("applied.csv");
    let m = manifest_at(
        &d,
        "apply.json",
        serde_json::json!({
            "schema_version": 1, "job_id": "j", "shard_id": "s0", "block": "kanon",
            "stage": "apply", "config": cfg, "input": qi, "output": out,
            "solution": art.join("solution.json"), "artifacts_dir": art
        }),
    );
    let report = super::kanon_block::run(&BlockManifest::load(&m).unwrap()).unwrap();
    let starred = report.extra.as_ref().unwrap()["rows_suppressed"].as_i64().unwrap();
    assert_eq!(starred, sol.suppressed_records + sol.unplaceable_records);
}

// ── Parameter grid ───────────────────────────────────────────────────────────

#[test]
fn the_grid_is_recomputed_from_the_histogram_over_caller_chosen_axes() {
    let d = tmp("grid");
    let cfg = config_json(&d, CFG);
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();
    let qi = d.join("qi.csv");
    project_columns(&staged, &qi, &["age".into(), "city".into()], DEFAULT_ROW_ID_COLUMN).unwrap();
    let art = d.join("art");

    for (name, body) in [
        ("scan.json", serde_json::json!({"stage": "scan", "input": qi.clone()})),
        ("solve.json", serde_json::json!({"stage": "solve", "inputs": [art.join("s0.scan.json")]})),
    ] {
        let mut m = serde_json::json!({
            "schema_version": 1, "job_id": "j", "shard_id": "s0", "block": "kanon",
            "config": cfg, "artifacts_dir": art
        });
        for (k, v) in body.as_object().unwrap() {
            m[k] = v.clone();
        }
        super::kanon_block::run(&BlockManifest::load(&manifest_at(&d, name, m)).unwrap()).unwrap();
    }

    // The raw data is irrelevant from here on — the table is a function of the
    // histogram, which is why a user can sit with it for as long as they like.
    fs::remove_file(&qi).unwrap();
    fs::remove_file(&staged).unwrap();

    let table = super::kanon_block::grid_from_histogram(
        &cfg,
        &art.join("histogram.json"),
        &[2, 3],
        &[0.0, 0.5],
    )
    .unwrap();
    assert_eq!(table["cells"].as_array().unwrap().len(), 4);
    assert_eq!(table["total_records"], 4);
    assert_eq!(table["k_values"], serde_json::json!([2, 3]));
}

// ── Chunk manifest ───────────────────────────────────────────────────────────

#[test]
fn the_chunk_manifest_matches_the_coordinator_contract() {
    let d = tmp("contract");
    let cfg = config_json(&d, CFG);
    let header: Vec<String> = "id,name,secret,age,city".split(',').map(str::to_string).collect();
    let plan = build_plan(&cfg, "3f1c9b2e-5a47-4d18-9e30-8b6a1d4c7f20", Some(&header)).unwrap();
    let doc = super::contract::manifest_skeleton(&plan, &cfg, false).unwrap();

    assert_eq!(doc["manifest_version"], 1);
    assert_eq!(doc["application"], "kanon");

    // Every column the config touches is classified; the contract wants a
    // column nobody classified to be an error, not a silent leak.
    let pre = doc["column_roles"]["preprocess"].as_array().unwrap();
    assert!(pre.iter().any(|p| p["column"] == "name" && p["operation"] == "suppress"));
    assert!(pre.iter().any(|p| p["column"] == "secret" && p["operation"] == "hash_salted"));
    assert_eq!(doc["column_roles"]["passthrough"], serde_json::json!(["id"]));

    // k is pinned here, so there is no measure phase and the job streams once.
    let phases = doc["phases"].as_array().unwrap();
    let names: Vec<&str> = phases.iter().map(|p| p["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["preprocess", "apply"]);
    assert_eq!(doc["parameters"]["k"], 2);
    for p in phases {
        // Roles, never images.
        let role = p["container_role"].as_str().unwrap();
        assert!(!role.contains('/') && !role.contains(':'), "role looks like an image: {role}");
    }
}

#[test]
fn omitting_k_puts_a_measure_barrier_in_front_of_apply() {
    let d = tmp("contract_measure");
    let cfg = config_json(&d, &CFG.replace(r#""pass": "no_bounds""#, r#""pass": "pass1""#));
    let plan = build_plan(&cfg, "j", None).unwrap();
    let doc = super::contract::manifest_skeleton(&plan, &cfg, false).unwrap();

    let phases = doc["phases"].as_array().unwrap();
    let measure = phases.iter().find(|p| p["name"] == "measure").unwrap();
    assert_eq!(measure["barrier"], true);
    assert_eq!(measure["columns"], "quasi_identifiers");
    assert_eq!(measure["produces"], "qi_histogram");

    let apply = phases.iter().find(|p| p["name"] == "apply").unwrap();
    assert_eq!(apply["consumes"], "qi_histogram");
    assert_eq!(apply["barrier"], false);
    assert_eq!(doc["parameters"]["k"], serde_json::Value::Null);
}

#[test]
fn chunks_cover_every_row_exactly_once_per_phase() {
    let d = tmp("chunks");
    let cfg = config_json(&d, &CFG.replace(r#""pass": "no_bounds""#, r#""pass": "pass1""#));
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();
    let plan = build_plan(&cfg, "j", None).unwrap();
    let doc = super::contract::manifest_skeleton(&plan, &cfg, false).unwrap();

    let entries =
        super::contract::materialise_chunks(&doc, &staged, &d.join("c"), 3, DEFAULT_ROW_ID_COLUMN)
            .unwrap();

    for phase in ["preprocess", "measure", "apply"] {
        let mut ranges: Vec<(u64, u64)> =
            entries.iter().filter(|c| c.phase == phase).map(|c| (c.rows.start, c.rows.end)).collect();
        ranges.sort_unstable();
        // Disjoint and covering: that is what makes the apply outputs safely
        // concatenable, and for DP it is a privacy property rather than only
        // bookkeeping.
        assert_eq!(ranges, vec![(0, 3), (3, 4)], "phase {phase}");
    }

    // The measure phase sees only the QI columns; apply sees everything.
    let measure = entries.iter().find(|c| c.phase == "measure").unwrap();
    let body = fs::read_to_string(&measure.path).unwrap();
    assert!(!body.contains("secret"), "measure chunk carried a non-QI column:\n{body}");
    assert!(body.starts_with("__skald_rid,age,city\n"), "{body}");

    // Digests are over the plaintext, and differ per projection of the same rows.
    let apply = entries.iter().find(|c| c.phase == "apply" && c.rows.start == 0).unwrap();
    let mea0 = entries.iter().find(|c| c.phase == "measure" && c.rows.start == 0).unwrap();
    assert_ne!(apply.digest, mea0.digest);
    for c in &entries {
        assert_eq!(c.digest.len(), 64);
        assert!(c.digest.chars().all(|ch| ch.is_ascii_hexdigit()));
    }
}

fn manifest_at(dir: &Path, name: &str, body: serde_json::Value) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, serde_json::to_string_pretty(&body).unwrap()).unwrap();
    p
}
