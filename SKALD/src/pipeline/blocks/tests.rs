//! Tests for the block runtime.
//!
//! The properties worth pinning down here are the ones that only break when
//! work is split up — a single-process run cannot exhibit them — and the one
//! that matters most: a job run as blocks releases exactly what the monolith
//! releases from the same data and config.

use super::plan::{build_plan, generate_keys};
use super::shard::{project_columns, read_removed_rids, split_rows, stamp_row_ids, stitch_columns};
use super::{BLOCK_SCHEMA_VERSION, BlockManifest, DEFAULT_ROW_ID_COLUMN, Shard};
use crate::pipeline::bootstrap::parse_runtime_config;
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

// ── Fixtures ─────────────────────────────────────────────────────────────────

fn tmp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("skald_block_tests_{}/{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

const CSV: &str = "\
id,name,secret,age,city
1,TESTNAME A,SEC0001,34,Testpur
2,TESTNAME B,SEC0002,41,Testpur
3,TESTNAME C,SEC0003,34,Demonagar
4,TESTNAME D,SEC0004,29,Demonagar
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
      "numerical": [{"column": "age"}],
      "categorical": [{"column": "city"}]
    },
    "size": {"age": 2},
    "compute_parameter_grid": false,
    "k_anonymize": {"k": 2}
  }
}"#;

/// A manifest at `dir/name`, with the schema version filled in.
fn manifest_at(dir: &Path, name: &str, mut body: Value) -> PathBuf {
    body["schema_version"] = json!(BLOCK_SCHEMA_VERSION);
    let p = dir.join(name);
    fs::write(&p, serde_json::to_string_pretty(&body).unwrap()).unwrap();
    p
}

fn manifest(dir: &Path, body: Value) -> PathBuf {
    manifest_at(dir, "manifest.json", body)
}

fn load(p: &Path) -> BlockManifest {
    BlockManifest::load(p).unwrap()
}

fn err_code(e: crate::pipeline::bootstrap::PipelineError) -> String {
    format!("{e}")
}

// ── Sharding round trip ──────────────────────────────────────────────────────

#[test]
fn stamp_project_stitch_round_trips_without_touching_the_data() {
    let d = tmp("round_trip");
    let staged = d.join("staged.csv");
    assert_eq!(stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap(), 4);

    let a = d.join("a.csv");
    let b = d.join("b.csv");
    project_columns(&staged, &a, &["name".into(), "secret".into()], DEFAULT_ROW_ID_COLUMN).unwrap();
    project_columns(&staged, &b, &["age".into(), "city".into()], DEFAULT_ROW_ID_COLUMN).unwrap();

    let out = d.join("out.csv");
    let routed: Vec<String> = ["name", "secret", "age", "city"].map(String::from).to_vec();
    stitch_columns(&staged, &[a, b], &routed, &[], &out, DEFAULT_ROW_ID_COLUMN).unwrap();
    // Columns come back in the base order, the row id is gone, values intact.
    assert_eq!(fs::read_to_string(&out).unwrap(), CSV);
}

#[test]
fn a_quoted_line_break_stays_inside_its_record_through_every_helper() {
    let d = tmp("quoted_newline");
    let input = d.join("in.csv");
    fs::write(&input, "id,note,age\n1,\"two\nlines\",34\n2,plain,41\n").unwrap();
    let staged = d.join("staged.csv");
    // Reading physical lines would make three records of two, and shift the
    // note's second line into `age` — past every column technique.
    assert_eq!(stamp_row_ids(&input, &staged, DEFAULT_ROW_ID_COLUMN).unwrap(), 2);
    let shard = d.join("age.csv");
    assert_eq!(project_columns(&staged, &shard, &["age".into()], DEFAULT_ROW_ID_COLUMN).unwrap(), 2);
    assert_eq!(fs::read_to_string(&shard).unwrap(), "__skald_rid,age\n0,34\n1,41\n");
    let parts = split_rows(&staged, &d.join("rows"), "r", 1).unwrap();
    assert_eq!(parts.len(), 2);
    assert!(fs::read_to_string(&parts[0]).unwrap().contains("\"two\nlines\""));
}

#[test]
fn a_misaligned_row_is_an_error_not_a_padded_row() {
    let d = tmp("misaligned");
    let input = d.join("in.csv");
    fs::write(&input, "id,age\n1,34\n2\n").unwrap();
    let e = stamp_row_ids(&input, &d.join("s.csv"), DEFAULT_ROW_ID_COLUMN).unwrap_err();
    assert!(err_code(e).contains("DATA_MALFORMED_ROW"));
}

#[test]
fn a_projected_shard_carries_only_the_columns_it_was_given() {
    let d = tmp("projection_is_a_boundary");
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();
    let shard = d.join("crypto.csv");
    project_columns(&staged, &shard, &["secret".into()], DEFAULT_ROW_ID_COLUMN).unwrap();

    let body = fs::read_to_string(&shard).unwrap();
    // A worker handed this file cannot see the other columns however it
    // misbehaves.
    assert!(body.contains("SEC0001"));
    for leaked in ["TESTNAME", "Testpur", "34"] {
        assert!(!body.contains(leaked), "shard leaked '{leaked}':\n{body}");
    }
}

#[test]
fn stitching_drops_a_suppressed_column_but_keeps_a_passthrough_one() {
    let d = tmp("suppressed_vs_passthrough");
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();
    // A shard given `name` and `secret` that returned only `secret` — `name`
    // was suppressed. `age` and `city` were never routed anywhere.
    let shard = d.join("pre.out.csv");
    fs::write(&shard, "__skald_rid,secret\n0,x\n1,x\n2,x\n3,x\n").unwrap();
    let out = d.join("out.csv");
    stitch_columns(&staged, &[shard], &["name".into(), "secret".into()], &[], &out, DEFAULT_ROW_ID_COLUMN).unwrap();
    let header = fs::read_to_string(&out).unwrap().lines().next().unwrap().to_string();
    assert_eq!(header, "id,secret,age,city");
}

#[test]
fn stitching_refuses_to_silently_lose_rows() {
    let d = tmp("lost_rows");
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();
    let shard = d.join("short.csv");
    fs::write(&shard, "__skald_rid,secret\n0,x\n1,x\n").unwrap();
    let out = d.join("out.csv");
    let e = stitch_columns(&staged, &[shard], &["secret".into()], &[], &out, DEFAULT_ROW_ID_COLUMN).unwrap_err();
    assert!(err_code(e).contains("BLOCK_SHARD_INCOMPLETE"));
    assert!(!out.exists(), "a refused stitch must leave no output");
}

#[test]
fn a_row_one_shard_lost_never_falls_back_to_its_staged_value() {
    let d = tmp("partial_patch");
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();
    // Every row comes back from the crypto shard, but the kanon shard lost row
    // 3. Filling its `age` from the staged file would publish the raw QI.
    let crypto = d.join("crypto.csv");
    fs::write(&crypto, "__skald_rid,secret\n0,h0\n1,h1\n2,h2\n3,h3\n").unwrap();
    let kanon = d.join("kanon.csv");
    fs::write(&kanon, "__skald_rid,age,city\n0,*,*\n1,*,*\n2,*,*\n").unwrap();
    let routed: Vec<String> = ["secret", "age", "city"].map(String::from).to_vec();
    let e =
        stitch_columns(&staged, &[crypto, kanon], &routed, &[], &d.join("o.csv"), DEFAULT_ROW_ID_COLUMN).unwrap_err();
    let msg = err_code(e);
    assert!(msg.contains("BLOCK_SHARD_INCOMPLETE") && msg.contains("age"), "{msg}");
}

#[test]
fn a_removed_row_is_dropped_from_every_column_shard() {
    let d = tmp("removed_rows");
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();
    let crypto = d.join("crypto.csv");
    fs::write(&crypto, "__skald_rid,secret\n0,h0\n1,h1\n2,h2\n3,h3\n").unwrap();
    // kanon apply removed row 3 and said so.
    let kanon = d.join("kanon.csv");
    fs::write(&kanon, "__skald_rid,age,city\n0,a,c\n1,a,c\n2,a,c\n").unwrap();
    let removed = d.join("k.removed_rids.json");
    fs::write(&removed, r#"{"removed_rids": ["3"]}"#).unwrap();
    let rids = read_removed_rids(&[removed]).unwrap();
    let routed: Vec<String> = ["secret", "age", "city"].map(String::from).to_vec();
    let out = d.join("o.csv");
    assert_eq!(stitch_columns(&staged, &[crypto, kanon], &routed, &rids, &out, DEFAULT_ROW_ID_COLUMN).unwrap(), 3);
    let body = fs::read_to_string(&out).unwrap();
    // Neither the hashed column nor the passthrough columns of the removed
    // record survive.
    assert!(!body.contains("h3") && !body.contains("TESTNAME D") && !body.contains("\n4,"), "{body}");
}

#[test]
fn stamping_refuses_input_that_already_uses_the_reserved_name() {
    let d = tmp("rid_collision");
    let p = d.join("in.csv");
    fs::write(&p, "__skald_rid,a\n1,2\n").unwrap();
    let e = stamp_row_ids(&p, &d.join("out.csv"), DEFAULT_ROW_ID_COLUMN).unwrap_err();
    assert!(err_code(e).contains("BLOCK_RID_PROTECTED"));
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

// ── Key material ─────────────────────────────────────────────────────────────

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
        json!({"job_id": "j", "shard_id": "s", "block": "crypto", "config": cfg, "input": shard,
               "artifacts_dir": d.join("art"), "columns": ["secret"]}),
    );
    // Generating one here would look like success and destroy the column across
    // shards, so the only safe behaviour is to stop.
    let e = super::crypto_block::run(&load(&m)).unwrap_err();
    assert!(err_code(e).contains("BLOCK_KEY_MISSING"));
}

#[test]
fn a_placeholder_key_is_refused_rather_than_used() {
    let d = tmp("weak_key");
    let cfg = config_json(&d, &CFG.replace(r#""hashing_with_salt": ["secret"]"#, r#""encrypt": ["secret"]"#));
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();
    let m = manifest(
        &d,
        json!({"job_id": "j", "block": "crypto", "config": cfg, "input": staged,
               "artifacts_dir": d.join("art"), "keys": {"symmetric_keys": {"secret": "x"}}}),
    );
    let e = super::crypto_block::run(&load(&m)).unwrap_err();
    assert!(err_code(e).contains("KEY_MATERIAL_INVALID"));
}

#[test]
fn one_salt_hashes_the_same_value_identically_in_every_shard() {
    let d = tmp("salt_consistency");
    let cfg = config_json(&d, CFG);
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();
    let whole = d.join("whole.csv");
    project_columns(&staged, &whole, &["secret".into()], DEFAULT_ROW_ID_COLUMN).unwrap();
    let keys = d.join("keys");
    generate_keys(&parse_runtime_config(&cfg).unwrap(), &keys).unwrap();

    let run = |input: &Path, tag: &str| -> Vec<String> {
        let out = d.join(format!("{tag}.out.csv"));
        let m = manifest_at(
            &d,
            &format!("{tag}.json"),
            json!({"job_id": "j", "shard_id": tag, "block": "crypto", "config": cfg, "input": input,
                   "output": out, "artifacts_dir": d.join("art"), "columns": ["secret"], "key_directory": keys}),
        );
        super::crypto_block::run(&load(&m)).unwrap();
        let shard = Shard::read(&out, DEFAULT_ROW_ID_COLUMN).unwrap();
        let ci = shard.column_index("secret").unwrap();
        shard.rows.iter().map(|r| r[ci].clone()).collect()
    };
    let whole_digests = run(&whole, "whole");
    let split: Vec<String> = split_rows(&whole, &d.join("rows"), "r", 2)
        .unwrap()
        .iter()
        .enumerate()
        .flat_map(|(i, s)| run(s, &format!("r{i}")))
        .collect();
    // Four distinct inputs under one salt: four distinct 64-hex digests, none
    // the plaintext — and however the rows were split, the same digests.
    assert_eq!(whole_digests, split);
    assert!(whole_digests.iter().all(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit())));
    assert_eq!(whole_digests.iter().collect::<std::collections::BTreeSet<_>>().len(), 4);
}

#[test]
fn keygen_writes_the_key_directory_and_reports_names_only() {
    let d = tmp("keygen");
    let cfg = config_json(
        &d,
        &CFG.replace(
            r#""hashing_with_salt": ["secret"]"#,
            r#""hashing_with_salt": ["secret"], "encrypt": ["city", {"age": {"format_preserving": true}}]"#,
        ),
    );
    let parsed = parse_runtime_config(&cfg).unwrap();
    let keys = d.join("keys");
    let report = generate_keys(&parsed, &keys).unwrap();
    assert_eq!(report.hash_salts, vec!["secret"]);
    assert_eq!(report.symmetric_keys, vec!["city"]);
    assert_eq!(report.fpe_keys, vec!["age"]);
    let shown = serde_json::to_string(&report).unwrap();
    let salt_file: Value =
        serde_json::from_str(&fs::read_to_string(keys.join("block_hash_salts.json")).unwrap()).unwrap();
    let salt = salt_file["secret"].as_str().unwrap();
    assert_eq!(salt.len(), 64);
    assert!(!shown.contains(salt), "keygen reported a key: {shown}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(keys.join("symmetric_keys.json")).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "key file readable by others: {mode:o}");
    }

    // Encryption keys are kept, like the monolith's; a per-job salt is not.
    let sym = fs::read_to_string(keys.join("symmetric_keys.json")).unwrap();
    let again = generate_keys(&parsed, &keys).unwrap();
    assert_eq!(fs::read_to_string(keys.join("symmetric_keys.json")).unwrap(), sym);
    assert!(again.minted.iter().all(|m| m.starts_with("hash_salts:")), "{:?}", again.minted);
    let salt2: Value = serde_json::from_str(&fs::read_to_string(keys.join("block_hash_salts.json")).unwrap()).unwrap();
    assert_ne!(salt2["secret"].as_str().unwrap(), salt);
}

#[test]
fn a_key_directory_among_the_artifacts_is_refused() {
    let d = tmp("keys_in_artifacts");
    let cfg = config_json(&d, CFG);
    for (field, path) in [("key_directory", "art/keys"), ("vault", "art/token_vault.json")] {
        let m = manifest(
            &d,
            json!({"job_id": "j", "block": "preprocess", "config": cfg, "input": "in.csv",
                   "artifacts_dir": "art", field: path}),
        );
        let e = BlockManifest::load(&m).unwrap_err();
        assert!(err_code(e).contains("KEY_MATERIAL_IN_OUTPUT"), "{field}");
    }
}

#[test]
fn tokenization_keeps_its_vault_in_the_key_directory() {
    let d = tmp("vault_location");
    let cfg = config_json(
        &d,
        &CFG.replace(r#""suppress": ["name"]"#, r#""tokenization": [{"column": "name", "prefix": "N-"}]"#),
    );
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();
    let shard = d.join("pre.csv");
    project_columns(&staged, &shard, &["name".into()], DEFAULT_ROW_ID_COLUMN).unwrap();
    let art = d.join("art");

    // Without a key directory there is nowhere safe for the vault.
    let m = manifest(
        &d,
        json!({"job_id": "j", "block": "preprocess", "config": cfg, "input": shard, "artifacts_dir": art}),
    );
    assert!(err_code(super::preprocess_block::run(&load(&m)).unwrap_err()).contains("BLOCK_KEY_MISSING"));

    let keys = d.join("keys");
    let m = manifest(
        &d,
        json!({"job_id": "j", "block": "preprocess", "config": cfg, "input": shard, "artifacts_dir": art,
               "key_directory": keys}),
    );
    super::preprocess_block::run(&load(&m)).unwrap();
    assert!(keys.join("token_vault.json").is_file());
    for entry in fs::read_dir(&art).unwrap() {
        let body = fs::read_to_string(entry.unwrap().path()).unwrap();
        assert!(!body.contains("TESTNAME") || !body.contains("N-"), "an artifact maps tokens back to names");
        assert!(!body.contains("\"forward\""), "the vault leaked into the artifacts");
    }
    let out = fs::read_to_string(art.join("shard_0.out.csv")).unwrap();
    assert!(!out.contains("TESTNAME"), "{out}");
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
        json!({"job_id": "j", "block": "crypto", "config": cfg, "input": shard, "output": d.join("o.csv"),
               "artifacts_dir": d.join("art"), "columns": ["age"]}),
    );
    // `secret` belongs to another shard — the orchestrator's routing decision,
    // not an error, and no key is needed for work not done here.
    let report = super::crypto_block::run(&load(&m)).unwrap();
    assert!(report.applied.is_empty());
    assert_eq!(report.deferred, vec!["hashing_with_salt:secret"]);
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
        json!({"job_id": "j", "shard_id": "pre", "block": "preprocess", "config": cfg, "input": shard,
               "output": out, "artifacts_dir": d.join("art"), "columns": ["name"]}),
    );
    let report = super::preprocess_block::run(&load(&m)).unwrap();
    assert_eq!(report.applied, vec!["suppress:name"]);
    assert_eq!(report.rows_in, report.rows_out);
    assert_eq!(fs::read_to_string(&out).unwrap(), "__skald_rid\n0\n1\n2\n3\n");
}

#[test]
fn preprocess_refuses_a_config_that_targets_the_row_id() {
    let d = tmp("rid_protected");
    let cfg = config_json(&d, &CFG.replace(r#""suppress": ["name"]"#, r#""suppress": ["__skald_rid"]"#));
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();
    let m = manifest(
        &d,
        json!({"job_id": "j", "block": "preprocess", "config": cfg, "input": staged, "output": d.join("o.csv"),
               "artifacts_dir": d.join("art")}),
    );
    let e = super::preprocess_block::run(&load(&m)).unwrap_err();
    assert!(err_code(e).contains("BLOCK_RID_PROTECTED"));
}

// ── k-anon stages ────────────────────────────────────────────────────────────

/// Runs scan on `rows`-row shards of `qi`, then solve; returns the solution.
fn solve_with_shard_size(d: &Path, cfg: &Path, qi: &Path, rows: usize, tag: &str) -> super::kanon_block::Solution {
    let art = d.join(format!("art_{tag}"));
    let shards = split_rows(qi, &d.join(format!("rows_{tag}")), tag, rows).unwrap();
    let mut scans = Vec::new();
    for (i, s) in shards.iter().enumerate() {
        let m = manifest_at(
            d,
            &format!("{tag}_scan{i}.json"),
            json!({"job_id": "j", "shard_id": format!("{tag}_{i}"), "block": "kanon", "stage": "scan",
                   "config": cfg, "input": s, "artifacts_dir": art}),
        );
        super::kanon_block::run(&load(&m)).unwrap();
        scans.push(art.join(format!("{tag}_{i}.scan.json")));
    }
    let m = manifest_at(
        d,
        &format!("{tag}_solve.json"),
        json!({"job_id": "j", "shard_id": "solve", "block": "kanon", "stage": "solve", "config": cfg,
               "artifacts_dir": art, "inputs": scans}),
    );
    super::kanon_block::run(&load(&m)).unwrap();
    serde_json::from_str(&fs::read_to_string(art.join("solution.json")).unwrap()).unwrap()
}

fn qi_shard(d: &Path) -> PathBuf {
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();
    let qi = d.join("qi.csv");
    project_columns(&staged, &qi, &["age".into(), "city".into()], DEFAULT_ROW_ID_COLUMN).unwrap();
    qi
}

#[test]
fn scan_then_solve_gives_the_same_answer_however_the_rows_were_split() {
    let d = tmp("shard_invariance");
    let cfg = config_json(&d, CFG);
    let qi = qi_shard(&d);
    let one = solve_with_shard_size(&d, &cfg, &qi, 4, "one");
    let many = solve_with_shard_size(&d, &cfg, &qi, 1, "many");
    assert_eq!(one.total_records, many.total_records);
    assert_eq!(one.final_rf, many.final_rf);
    assert_eq!(one.passing_classes, many.passing_classes);
    assert_eq!(one.failing_classes, many.failing_classes);
    assert_eq!(one.publish_suppressed, many.publish_suppressed);
    assert_eq!(one.numeric_bounds, many.numeric_bounds);
    assert_eq!(one.anonymisation_summary, many.anonymisation_summary);
}

#[test]
fn pass_two_resolves_from_the_persisted_histogram_with_no_data_present() {
    let d = tmp("two_pass");
    let p1 = config_json(&d, &CFG.replace(r#""pass": "no_bounds""#, r#""pass": "pass1""#));
    let qi = qi_shard(&d);
    let art = d.join("art");
    let m = manifest_at(
        &d,
        "scan.json",
        json!({"job_id": "j", "shard_id": "s0", "block": "kanon", "stage": "scan", "config": p1, "input": qi,
               "artifacts_dir": art}),
    );
    super::kanon_block::run(&load(&m)).unwrap();
    let m = manifest_at(
        &d,
        "solve1.json",
        json!({"job_id": "j", "block": "kanon", "stage": "solve", "config": p1, "artifacts_dir": art,
               "inputs": [art.join("s0.scan.json")]}),
    );
    super::kanon_block::run(&load(&m)).unwrap();
    let s1: super::kanon_block::Solution =
        serde_json::from_str(&fs::read_to_string(art.join("solution.json")).unwrap()).unwrap();
    assert!(s1.k_optimal.is_some(), "pass1 should report k_optimal");
    assert!(s1.final_rf.is_none(), "pass1 stops before the lattice search");
    let hist = art.join("histogram.json");
    assert!(hist.exists());
    #[cfg(unix)]
    {
        // Un-generalised QI tuples: owner-only, like key material.
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&hist).unwrap().permissions().mode() & 0o077, 0);
    }

    // Everything the scan read is now gone. Pass 2 must still solve.
    fs::remove_file(&qi).unwrap();
    fs::remove_file(art.join("s0.scan.json")).unwrap();
    let p2 = config_json(&d, CFG);
    let m = manifest_at(
        &d,
        "solve2.json",
        json!({"job_id": "j", "block": "kanon", "stage": "solve", "config": p2, "artifacts_dir": art, "inputs": []}),
    );
    super::kanon_block::run(&load(&m)).unwrap();
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
        json!({"job_id": "j", "block": "kanon", "stage": "solve", "config": cfg, "artifacts_dir": d.join("art"),
               "inputs": []}),
    );
    assert!(err_code(super::kanon_block::run(&load(&m)).unwrap_err()).contains("BLOCK_HISTOGRAM_MISSING"));
}

/// Scans `qi` as one shard and solves it under `cfg`; returns the artifacts dir.
fn scan_and_solve(d: &Path, cfg: &Path, qi: &Path) -> PathBuf {
    let art = d.join("art");
    let m = manifest_at(
        d,
        "scan.json",
        json!({"job_id": "j", "shard_id": "s0", "block": "kanon", "stage": "scan", "config": cfg, "input": qi,
               "artifacts_dir": art}),
    );
    super::kanon_block::run(&load(&m)).unwrap();
    let m = manifest_at(
        d,
        "solve.json",
        json!({"job_id": "j", "block": "kanon", "stage": "solve", "config": cfg, "artifacts_dir": art,
               "inputs": [art.join("s0.scan.json")]}),
    );
    super::kanon_block::run(&load(&m)).unwrap();
    art
}

fn apply(d: &Path, cfg: &Path, input: &Path, art: &Path) -> Result<super::BlockReport, String> {
    let m = manifest_at(
        d,
        "apply.json",
        json!({"job_id": "j", "shard_id": "a0", "block": "kanon", "stage": "apply", "config": cfg,
               "input": input, "output": d.join("applied.csv"), "artifacts_dir": art}),
    );
    super::kanon_block::run(&load(&m)).map_err(err_code)
}

#[test]
fn applying_a_pass_one_solution_is_refused() {
    let d = tmp("pass1_apply");
    let p1 = config_json(&d, &CFG.replace(r#""pass": "no_bounds""#, r#""pass": "pass1""#));
    let qi = qi_shard(&d);
    let art = scan_and_solve(&d, &p1, &qi);
    assert!(apply(&d, &p1, &qi, &art).unwrap_err().contains("BLOCK_SOLUTION_INCOMPLETE"));
}

#[test]
fn applying_a_solution_from_another_config_is_refused() {
    let d = tmp("stale_solution");
    let cfg = config_json(&d, CFG);
    let qi = qi_shard(&d);
    let art = scan_and_solve(&d, &cfg, &qi);
    let k3 = d.join("k3.json");
    fs::write(&k3, CFG.replace(r#""k": 2"#, r#""k": 3"#)).unwrap();
    assert!(apply(&d, &k3, &qi, &art).unwrap_err().contains("BLOCK_SOLUTION_MISMATCH"));
}

#[test]
fn a_row_the_scan_never_counted_is_refused_at_apply() {
    let d = tmp("unseen_row");
    let cfg = config_json(&d, CFG);
    let qi = qi_shard(&d);
    let art = scan_and_solve(&d, &cfg, &qi);
    // A shard that was not part of the scan, with an age far outside every
    // scanned bucket: its class has no verdict, so it must not be published on
    // a guess.
    let other = d.join("other.csv");
    fs::write(&other, "__skald_rid,age,city\n9,100000,Testpur\n").unwrap();
    assert!(apply(&d, &cfg, &other, &art).unwrap_err().contains("BLOCK_SOLUTION_MISMATCH"));
}

#[test]
fn apply_returns_only_the_row_id_and_the_quasi_identifiers() {
    let d = tmp("apply_columns");
    let cfg = config_json(&d, CFG);
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();
    let qi = qi_shard(&d);
    let art = scan_and_solve(&d, &cfg, &qi);
    // Even handed every staged column (the contract's apply phase reads "all"),
    // it must not return them: a stale copy would overwrite another block's
    // output at the stitch.
    apply(&d, &cfg, &staged, &art).unwrap();
    let out = fs::read_to_string(d.join("applied.csv")).unwrap();
    assert!(out.starts_with("__skald_rid,age,city\n"), "{out}");
    assert!(!out.contains("SEC0001") && !out.contains("TESTNAME"), "{out}");
    assert!(art.join("a0.removed_rids.json").is_file());
}

#[test]
fn scanning_a_shard_missing_a_quasi_identifier_explains_the_routing_rule() {
    let d = tmp("split_qis");
    let cfg = config_json(&d, CFG);
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();
    let half = d.join("half.csv");
    project_columns(&staged, &half, &["age".into()], DEFAULT_ROW_ID_COLUMN).unwrap();
    let m = manifest(
        &d,
        json!({"job_id": "j", "block": "kanon", "stage": "scan", "config": cfg, "input": half,
               "artifacts_dir": d.join("art")}),
    );
    assert!(err_code(super::kanon_block::run(&load(&m)).unwrap_err()).contains("BLOCK_QI_SHARD_INCOMPLETE"));
}

#[test]
fn a_stale_generalization_node_is_caught_before_any_row_is_written() {
    let d = tmp("stale_node");
    // Keeping every value distinct suppresses most of this data at k=2.
    let cfg = config_json(
        &d,
        &CFG.replace(r#""pass": "no_bounds""#, r#""pass": "pass2""#)
            .replace(r#""suppression_limit": 0.5"#, r#""suppression_limit": 0.0"#)
            .replace(r#""k_anonymize""#, r#""generalization_node": {"age": 1, "city": 1}, "k_anonymize""#),
    );
    let qi = qi_shard(&d);
    let art = d.join("art");
    let m = manifest_at(
        &d,
        "scan.json",
        json!({"job_id": "j", "shard_id": "s0", "block": "kanon", "stage": "scan", "config": cfg, "input": qi,
               "artifacts_dir": art}),
    );
    super::kanon_block::run(&load(&m)).unwrap();
    let m = manifest_at(
        &d,
        "solve.json",
        json!({"job_id": "j", "block": "kanon", "stage": "solve", "config": cfg, "artifacts_dir": art,
               "inputs": [art.join("s0.scan.json")]}),
    );
    let e = super::kanon_block::run(&load(&m)).unwrap_err();
    assert!(err_code(e).contains("SUPPRESSION_LIMIT_EXCEEDED"));
    assert!(!art.join("solution.json").exists());
}

// ── Monolith parity ──────────────────────────────────────────────────────────

/// Runs the monolith over `csv` with `section`, returning the released file.
/// `keys` is copied in first, so the monolith reads the salts and keys keygen
/// wrote for the block run.
fn run_monolith(dir: &Path, csv: &str, section: &Value, keys: &Path) -> String {
    let root = dir.join("mono");
    for d in ["config", "data", "chunks", "output"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    fs::write(root.join("config/c.json"), json!({"data_type": "t", "t": section}).to_string()).unwrap();
    fs::write(root.join("data/in.csv"), csv).unwrap();
    let mono_keys = root.join("keys");
    fs::create_dir_all(&mono_keys).unwrap();
    for e in fs::read_dir(keys).unwrap() {
        let p = e.unwrap().path();
        fs::copy(&p, mono_keys.join(p.file_name().unwrap())).unwrap();
    }
    crate::pipeline::pipeline::run_pipeline(&root).unwrap();
    fs::read_to_string(root.join("output").join(section["output_path"].as_str().unwrap())).unwrap()
}

/// Runs the same job the way an orchestrator would: plan, keygen, stage, one
/// projection per group, `rows`-row shards fanned out, kanon scan → solve →
/// apply, then one stitch. Returns the released file and the solution.
fn run_blocks(dir: &Path, csv: &str, section: &Value, rows: usize) -> (String, super::kanon_block::Solution) {
    let rid = DEFAULT_ROW_ID_COLUMN;
    let cfg = dir.join("cfg.json");
    fs::write(&cfg, json!({"data_type": "t", "t": section}).to_string()).unwrap();
    let input = dir.join("in.csv");
    fs::write(&input, csv).unwrap();
    let header: Vec<String> = csv.lines().next().unwrap().split(',').map(str::to_string).collect();
    let plan = build_plan(&cfg, "j", Some(&header)).unwrap();
    let keys = dir.join("keys");
    generate_keys(&parse_runtime_config(&cfg).unwrap(), &keys).unwrap();
    let staged = dir.join("staged.csv");
    super::stage::stage(&cfg, &input, &staged, rid, true).unwrap();

    let art = dir.join("art");
    let mut outputs = Vec::new();
    let mut routed = Vec::new();
    let mut removed = Vec::new();
    let mut solution = None;
    for g in plan.groups.iter().filter(|g| g.block != "stage") {
        let proj = dir.join(format!("{}.csv", g.block));
        let cols: Vec<String> = g.columns.iter().chain(&g.read_columns).cloned().collect();
        project_columns(&staged, &proj, &cols, rid).unwrap();
        routed.extend(g.columns.iter().cloned());
        let shards = split_rows(&proj, &dir.join(format!("rows_{}", g.block)), &g.block, rows).unwrap();
        let run = |name: String, body: Value| {
            let m = manifest_at(dir, &format!("{name}.json"), body);
            let block = match g.block.as_str() {
                "preprocess" => super::preprocess_block::run,
                "crypto" => super::crypto_block::run,
                _ => super::kanon_block::run,
            };
            block(&load(&m)).unwrap_or_else(|e| panic!("{name}: {e}"));
        };
        if g.block != "kanon" {
            for (i, s) in shards.iter().enumerate() {
                let out = art.join(format!("{}_{i}.out.csv", g.block));
                run(
                    format!("{}_{i}", g.block),
                    json!({"job_id": "j", "shard_id": format!("{}_{i}", g.block), "block": g.block, "config": cfg,
                           "input": s, "output": out, "artifacts_dir": art, "columns": g.columns,
                           "key_directory": keys}),
                );
                outputs.push(out);
            }
            continue;
        }
        let mut scans = Vec::new();
        for (i, s) in shards.iter().enumerate() {
            run(
                format!("scan_{i}"),
                json!({"job_id": "j", "shard_id": format!("k{i}"), "block": "kanon", "stage": "scan",
                       "config": cfg, "input": s, "artifacts_dir": art}),
            );
            scans.push(art.join(format!("k{i}.scan.json")));
        }
        run(
            "solve".to_string(),
            json!({"job_id": "j", "block": "kanon", "stage": "solve", "config": cfg, "artifacts_dir": art,
                   "inputs": scans}),
        );
        for (i, s) in shards.iter().enumerate() {
            let out = art.join(format!("k{i}.out.csv"));
            run(
                format!("apply_{i}"),
                json!({"job_id": "j", "shard_id": format!("k{i}"), "block": "kanon", "stage": "apply",
                       "config": cfg, "input": s, "output": out, "artifacts_dir": art}),
            );
            outputs.push(out);
            removed.push(art.join(format!("k{i}.removed_rids.json")));
        }
        solution = Some(serde_json::from_str(&fs::read_to_string(art.join("solution.json")).unwrap()).unwrap());
    }
    let out = dir.join("released.csv");
    stitch_columns(&staged, &outputs, &routed, &read_removed_rids(&removed).unwrap(), &out, rid).unwrap();

    // Nothing among the artifacts is key material.
    for name in ["salt", "keys", "vault"] {
        let hit = fs::read_dir(&art).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().contains(name));
        assert!(!hit, "a key file landed among the artifacts");
    }
    (fs::read_to_string(&out).unwrap(), solution.expect("kanon group planned"))
}

/// A synthetic population with clusters, outliers and messy cells (blank and
/// non-numeric ages, an out-of-range zip, padded categorical values).
fn population() -> String {
    let mut s = String::from("Id,Name,Email,Phone,Age,Zip,Gender,Diagnosis,Notes\n");
    let genders = ["M", "F", " M", "F "];
    let diagnoses = ["D1", "D2", "D3"];
    for i in 0..90u32 {
        let age = match i {
            7 => String::new(),
            13 => "abc".to_string(),
            _ => (20 + (i * 7) % 45).to_string(),
        };
        let zip = if i == 21 { "1e30".to_string() } else { (56000 + (i % 6) * 10).to_string() };
        s.push_str(&format!(
            "{i},TESTNAME {i},user{i}@example.org,90000{:05},{age},{zip},{},{},note {i}\n",
            i,
            genders[(i % 4) as usize],
            diagnoses[(i % 3) as usize]
        ));
    }
    // Two outliers no class can absorb at a fine level.
    s.push_str("90,TESTNAME 90,user90@example.org,9000000090,99,99999,X,D1,note 90\n");
    s.push_str("91,TESTNAME 91,user91@example.org,9000000091,98,99998,X,D2,note 91\n");
    s
}

fn parity_section(flow: &str) -> Value {
    json!({
        "output_path": "released.csv",
        "flow_mode": flow,
        "suppression_limit": 0.2,
        "suppress": ["Notes"],
        "hashing_with_salt": ["Name"],
        "shared_hash_salts": true,
        "encrypt": ["Phone"],
        "masking": [{"column": "Email", "masking_char": "*",
                     "regex_patterns": [{"type": "before", "delimiter": "@", "length": "all"}]}],
        "quasi_identifiers": {
            "numerical": [{"column": "Age"}, {"column": "Zip"}],
            "categorical": [{"column": "Gender"}]
        },
        "categorical_hierarchies": {"Gender": {"M": ["Any"], "F": ["Any"], "X": ["Any"]}},
        "size": {"Age": 2, "Zip": 10},
        "compute_parameter_grid": false,
        "k_anonymize": {"k": 4}
    })
}

fn assert_parity(tag: &str, csv: &str, section: Value, rows: usize) -> super::kanon_block::Solution {
    let d = tmp(tag);
    let (blocks, solution) = run_blocks(&d, csv, &section, rows);
    if section.get("hashing_with_salt").is_some() {
        assert_techniques_applied(&blocks);
    }
    let mono = run_monolith(&d, csv, &section, &d.join("keys"));
    assert_eq!(blocks, mono, "{tag}: the block run released something other than the monolith");
    solution
}

/// The parity runs only mean something if every technique actually fired.
fn assert_techniques_applied(released: &str) {
    assert!(!released.contains("TESTNAME"), "names were not hashed");
    assert!(released.contains("ENC1$"), "phones were not encrypted");
    assert!(released.contains("****@example.org"), "emails were not masked");
    assert!(!released.contains("note "), "the suppressed column survived");
    assert!(released.contains(",*,"), "no QI cell was suppressed or left without a bin");
}

#[test]
fn blocks_release_what_the_monolith_releases_direct_flow() {
    let sol = assert_parity("parity_direct", &population(), parity_section("direct"), 17);
    assert_eq!(sol.flow, "DIRECT");
}

#[test]
fn blocks_release_what_the_monolith_releases_original_flow() {
    let sol = assert_parity("parity_original", &population(), parity_section("original"), 23);
    assert_eq!(sol.flow, "ORIGINAL");
}

#[test]
fn blocks_release_what_the_monolith_releases_with_l_diversity() {
    let mut section = parity_section("auto");
    section["l_diversity"] = json!({"l": 2, "sensitive_attributes": ["Diagnosis"]});
    let sol = assert_parity("parity_l", &population(), section, 11);
    assert_eq!(sol.anonymisation_summary["l"], 2);
}

#[test]
fn blocks_fail_the_same_classes_on_l_as_the_monolith() {
    // City A: six records, one diagnosis — large enough for k, not l-diverse.
    // City B: six records, two diagnoses. At the chosen node A fails l, and the
    // `*` class it would form is itself not l-diverse, so it is removed.
    let mut csv = String::from("Id,City,Diagnosis\n");
    for i in 0..12 {
        let (city, diag) = if i < 6 { ("A", "D1") } else { ("B", if i % 2 == 0 { "D1" } else { "D2" }) };
        csv.push_str(&format!("{i},{city},{diag}\n"));
    }
    let section = json!({
        "output_path": "released.csv",
        "pass": "pass2",
        "generalization_node": {"City": 1},
        "suppression_limit": 0.5,
        "quasi_identifiers": {"categorical": [{"column": "City"}]},
        "l_diversity": {"l": 2, "sensitive_attributes": ["Diagnosis"]},
        "compute_parameter_grid": false,
        "k_anonymize": {"k": 3}
    });
    let sol = assert_parity("parity_l_fails", &csv, section, 5);
    assert_eq!(sol.anonymisation_summary["classes_failing_l"], 1, "{}", sol.anonymisation_summary);
    assert_eq!(sol.anonymisation_summary["removed_records"], 6, "{}", sol.anonymisation_summary);
}

#[test]
fn blocks_remove_a_star_class_smaller_than_k_as_the_monolith_does() {
    // Ten of A, ten of B, one C: keeping values distinct suppresses only the C,
    // which alone would be a `*` class of one — so it is removed, not starred.
    let mut csv = String::from("Id,City\n");
    for i in 0..21 {
        csv.push_str(&format!(
            "{i},{}\n",
            if i < 10 {
                "A"
            } else if i < 20 {
                "B"
            } else {
                "C"
            }
        ));
    }
    let section = json!({
        "output_path": "released.csv",
        "suppression_limit": 0.1,
        "quasi_identifiers": {"categorical": [{"column": "City"}]},
        "compute_parameter_grid": false,
        "k_anonymize": {"k": 5}
    });
    let sol = assert_parity("parity_removal", &csv, section, 4);
    assert!(!sol.publish_suppressed);
    assert_eq!(sol.anonymisation_summary["removed_records"], 1);
}

// ── Planner ──────────────────────────────────────────────────────────────────

#[test]
fn the_plan_routes_each_column_to_exactly_one_block() {
    let d = tmp("plan");
    let cfg = config_json(&d, CFG);
    let header: Vec<String> = "id,name,secret,age,city".split(',').map(str::to_string).collect();
    let plan = build_plan(&cfg, "job-1", Some(&header)).unwrap();
    let by_block = |b: &str| plan.groups.iter().find(|g| g.block == b).map(|g| g.columns.clone()).unwrap_or_default();
    // Suppression is the orchestrator's: a dropped column reaches no container.
    assert_eq!(by_block("stage"), vec!["name"]);
    assert_eq!(by_block("crypto"), vec!["secret"]);
    assert_eq!(by_block("kanon"), vec!["age", "city"]);
    assert_eq!(plan.passthrough_columns, vec!["id"]);
    assert_eq!(plan.keys_required.hash_salts, vec!["secret"]);
    assert!(plan.multi_block_columns.is_empty());
    let order = |b: &str| plan.groups.iter().find(|g| g.block == b).unwrap().order;
    assert!(order("stage") < order("crypto"));
    assert!(order("crypto") < order("kanon"));
}

#[test]
fn l_diversity_routes_its_sensitive_attributes_to_kanon_read_only() {
    let d = tmp("plan_l");
    let cfg = config_json(
        &d,
        &CFG.replace(
            r#""k_anonymize""#,
            r#""l_diversity": {"l": 2, "sensitive_attributes": ["secret"]}, "k_anonymize""#,
        )
        .replace(r#""hashing_with_salt": ["secret"],"#, ""),
    );
    let plan = build_plan(&cfg, "j", None).unwrap();
    let kanon = plan.groups.iter().find(|g| g.block == "kanon").unwrap();
    assert_eq!(kanon.columns, vec!["age", "city"]);
    assert_eq!(kanon.read_columns, vec!["secret"]);
}

#[test]
fn only_the_staging_group_runs_on_the_orchestrator() {
    let d = tmp("placement");
    let cfg =
        config_json(&d, &CFG.replace(r#""suppress": ["name"]"#, r#""suppress": ["name"], "charcloak": ["city"]"#));
    let plan = build_plan(&cfg, "j", None).unwrap();
    for g in &plan.groups {
        let expected = if g.block == "stage" { "orchestrator" } else { "container" };
        assert_eq!(g.runs_on, expected, "block {} runs on the wrong side", g.block);
    }
    let pre = plan.groups.iter().find(|g| g.block == "preprocess").unwrap();
    assert_eq!(pre.operations, vec!["charcloak:city"]);
}

#[test]
fn the_plan_names_container_roles_and_never_images() {
    let d = tmp("roles");
    let cfg = config_json(&d, CFG);
    let plan = build_plan(&cfg, "j", None).unwrap();
    let text = serde_json::to_string(&plan).unwrap();
    assert!(!text.contains("ghcr.io") && !text.contains("sha256:"), "{text}");
    for g in plan.groups.iter().filter(|g| g.runs_on == "container") {
        assert!(g.container_role.is_some(), "{} has no container_role", g.block);
    }
}

#[test]
fn solve_is_not_planned_as_a_container_stage() {
    let d = tmp("solve_placement");
    let cfg = config_json(&d, CFG);
    let plan = build_plan(&cfg, "j", None).unwrap();
    let kanon = plan.groups.iter().find(|g| g.block == "kanon").unwrap();
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
    assert!(!pre.row_parallel);
    assert!(pre.row_parallel_note.as_ref().unwrap().contains("vault"));
}

#[test]
fn suppressing_a_quasi_identifier_is_caught_before_any_container_starts() {
    let d = tmp("conflict");
    let cfg = config_json(&d, &CFG.replace(r#""suppress": ["name"]"#, r#""suppress": ["age"]"#));
    assert!(err_code(build_plan(&cfg, "j", None).unwrap_err()).contains("PLAN_COLUMN_CONFLICT"));
}

#[test]
fn a_config_naming_a_column_the_data_lacks_fails_planning() {
    let d = tmp("missing_col");
    let cfg = config_json(&d, CFG);
    let header: Vec<String> = "id,age,city".split(',').map(str::to_string).collect();
    let msg = err_code(build_plan(&cfg, "j", Some(&header)).unwrap_err());
    assert!(msg.contains("PLAN_COLUMN_MISSING") && msg.contains("name") && msg.contains("secret"), "{msg}");
}

// ── Manifest ─────────────────────────────────────────────────────────────────

#[test]
fn manifest_paths_resolve_against_the_manifest_directory() {
    let d = tmp("manifest_paths");
    fs::create_dir_all(d.join("job")).unwrap();
    let m = manifest_at(
        &d.join("job"),
        "manifest.json",
        json!({"job_id": "j", "block": "crypto", "config": "../cfg.json", "input": "in.csv", "artifacts_dir": "art",
               "key_directory": "../keys"}),
    );
    let loaded = load(&m);
    assert_eq!(loaded.config, d.join("cfg.json"));
    assert_eq!(loaded.input.unwrap(), d.join("job/in.csv"));
    assert_eq!(loaded.artifacts_dir, d.join("job/art"));
    assert_eq!(loaded.key_directory.unwrap(), d.join("keys"));
    assert_eq!(loaded.shard_id, "shard_0");
    assert_eq!(loaded.row_id_column, DEFAULT_ROW_ID_COLUMN);
}

#[test]
fn a_manifest_from_another_schema_or_with_an_unknown_field_is_refused() {
    let d = tmp("schema");
    let m = d.join("manifest.json");
    fs::write(&m, r#"{"schema_version":1,"job_id":"j","block":"crypto","config":"c.json"}"#).unwrap();
    assert!(err_code(BlockManifest::load(&m).unwrap_err()).contains("BLOCK_SCHEMA_MISMATCH"));
    fs::write(
        &m,
        format!(
            r#"{{"schema_version":{BLOCK_SCHEMA_VERSION},"job_id":"j","block":"crypto","config":"c.json","kees":{{}}}}"#
        ),
    )
    .unwrap();
    assert!(err_code(BlockManifest::load(&m).unwrap_err()).contains("BLOCK_MANIFEST_INVALID"));
}

#[test]
fn the_debug_form_of_keys_names_columns_only() {
    let mut k = super::BlockKeys::default();
    k.hash_salts.insert("secret".into(), "ab".repeat(32));
    let shown = format!("{k:?}");
    assert!(shown.contains("secret") && !shown.contains("abab"), "{shown}");
}

// ── Staging: cleaning, suppression, row ids ──────────────────────────────────

const DIRTY: &str = "\
id,name,age,city
1, TESTNAME A ,34,Testpur
2,N/A,41,  New   Testpur
3,TESTNAME C,n/a,Demonagar
,,,\u{20}
5,TESTNAME E,notanumber,Testpur
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
      "numerical": [{"column": "age"}],
      "categorical": [{"column": "city"}]
    },
    "size": {"age": 2},
    "compute_parameter_grid": false,
    "k_anonymize": {"k": 2}
  }
}"#;

#[test]
fn the_cleaning_section_is_parsed_strictly() {
    let d = tmp("cleaning_parse");
    for (bad, code) in [
        (r#""required_columns": ["age"], "requird": true"#, "CONFIG_UNKNOWN_KEY"),
        (r#""required_columns": ["age"], "max_dropped_fraction": 1.5"#, "CONFIG_INVALID_VALUE"),
        (r#""required_columns": ["age"], "trim": "yes""#, "CONFIG_INVALID_VALUE"),
        (r#""required_columns": [3]"#, "CONFIG_INVALID_VALUE"),
    ] {
        let cfg = config_json(&d, &CLEAN_CFG.replace(r#""required_columns": ["age"]"#, bad));
        let e = parse_runtime_config(&cfg).unwrap_err();
        assert!(err_code(e).contains(code), "{bad}");
    }
    // The monolith does not clean, and says so rather than ignoring it quietly.
    let cfg = config_json(&d, CLEAN_CFG);
    let parsed = parse_runtime_config(&cfg).unwrap();
    assert!(parsed.cleaning.enabled);
    assert!(parsed.warnings.iter().any(|w| w.contains("cleaning")), "{:?}", parsed.warnings);
}

#[test]
fn staging_normalises_missing_values_trims_and_collapses_whitespace() {
    let d = tmp("cleaning");
    let input = d.join("dirty.csv");
    fs::write(&input, DIRTY).unwrap();
    let cfg = config_json(&d, &CLEAN_CFG.replace(r#""required_columns": ["age"]"#, r#""required_columns": []"#));
    let out = d.join("staged.csv");
    let report = super::stage::stage(&cfg, &input, &out, DEFAULT_ROW_ID_COLUMN, false).unwrap();
    let body = fs::read_to_string(&out).unwrap();
    assert!(body.contains("0,1,TESTNAME A,34,Testpur"), "{body}");
    assert!(body.contains("1,2,,41,New Testpur"), "{body}");
    assert!(!body.contains("N/A") && !body.contains("n/a"), "{body}");
    assert!(body.contains("3,5,TESTNAME E,,Testpur"), "{body}");
    assert_eq!(report.non_numeric.get("age"), Some(&1));
    assert!(report.nulls_normalised.contains_key("name"));
    assert!(report.whitespace_fixed.contains_key("city"));
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
    let report = super::stage::stage(&cfg, &input, &d.join("staged.csv"), DEFAULT_ROW_ID_COLUMN, false).unwrap();
    assert_eq!(report.rows_out, 2);
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
        &CLEAN_CFG
            .replace(r#""required_columns": ["age"]"#, r#""required_columns": ["age"], "max_dropped_fraction": 0.2"#),
    );
    let msg = err_code(super::stage::stage(&cfg, &input, &d.join("o.csv"), DEFAULT_ROW_ID_COLUMN, false).unwrap_err());
    assert!(msg.contains("STAGE_TOO_MANY_DROPPED") && msg.contains("required_column_empty:age"), "{msg}");
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
    assert!(!body.contains("TESTNAME"), "suppressed column survived:\n{body}");
    let ids: Vec<&str> = body.lines().skip(1).map(|l| l.split(',').next().unwrap()).collect();
    assert_eq!(ids, vec!["0", "1"]);
}

#[test]
fn staging_without_a_cleaning_section_only_suppresses_and_stamps() {
    let d = tmp("no_cleaning");
    let input = d.join("dirty.csv");
    fs::write(&input, DIRTY).unwrap();
    let cfg = config_json(&d, CFG);
    let out = d.join("staged.csv");
    let report = super::stage::stage(&cfg, &input, &out, DEFAULT_ROW_ID_COLUMN, false).unwrap();
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
    let e = super::stage::stage(&cfg, &input, &d.join("o.csv"), DEFAULT_ROW_ID_COLUMN, false).unwrap_err();
    assert!(err_code(e).contains("STAGE_COLUMN_MISSING"));
}

// ── Parameter grid ───────────────────────────────────────────────────────────

#[test]
fn the_grid_is_recomputed_from_the_histogram_over_caller_chosen_axes() {
    let d = tmp("grid");
    let cfg = config_json(&d, CFG);
    let qi = qi_shard(&d);
    let art = scan_and_solve(&d, &cfg, &qi);
    fs::remove_file(&qi).unwrap();
    let table =
        super::kanon_block::grid_from_histogram(&cfg, &art.join("histogram.json"), &[2, 3], &[0.0, 0.5]).unwrap();
    assert_eq!(table["cells"].as_array().unwrap().len(), 4);
    assert_eq!(table["total_records"], 4);
    assert_eq!(table["k_values"], json!([2, 3]));
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
    let pre = doc["column_roles"]["preprocess"].as_array().unwrap();
    assert!(pre.iter().any(|p| p["column"] == "name" && p["operation"] == "suppress"));
    assert!(pre.iter().any(|p| p["column"] == "secret" && p["operation"] == "hash_salted"));
    assert_eq!(doc["column_roles"]["passthrough"], json!(["id"]));
    let phases = doc["phases"].as_array().unwrap();
    let names: Vec<&str> = phases.iter().map(|p| p["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["preprocess", "apply"]);
    assert_eq!(doc["parameters"]["k"], 2);
    for p in phases {
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
    assert_eq!(doc["parameters"]["k"], Value::Null);
}

#[test]
fn chunks_cover_every_row_exactly_once_per_phase() {
    let d = tmp("chunks");
    let cfg = config_json(&d, &CFG.replace(r#""pass": "no_bounds""#, r#""pass": "pass1""#));
    let staged = d.join("staged.csv");
    stamp_row_ids(&write_csv(&d), &staged, DEFAULT_ROW_ID_COLUMN).unwrap();
    let plan = build_plan(&cfg, "j", None).unwrap();
    let doc = super::contract::manifest_skeleton(&plan, &cfg, false).unwrap();
    let entries = super::contract::materialise_chunks(&doc, &staged, &d.join("c"), 3, DEFAULT_ROW_ID_COLUMN).unwrap();
    for phase in ["preprocess", "measure", "apply"] {
        let mut ranges: Vec<(u64, u64)> =
            entries.iter().filter(|c| c.phase == phase).map(|c| (c.rows.start, c.rows.end)).collect();
        ranges.sort_unstable();
        assert_eq!(ranges, vec![(0, 3), (3, 4)], "phase {phase}");
    }
    let measure = entries.iter().find(|c| c.phase == "measure").unwrap();
    let body = fs::read_to_string(&measure.path).unwrap();
    assert!(!body.contains("SEC0001"), "measure chunk carried a non-QI column:\n{body}");
    assert!(body.starts_with("__skald_rid,age,city\n"), "{body}");
    let apply = entries.iter().find(|c| c.phase == "apply" && c.rows.start == 0).unwrap();
    let mea0 = entries.iter().find(|c| c.phase == "measure" && c.rows.start == 0).unwrap();
    assert_ne!(apply.digest, mea0.digest);
    assert!(entries.iter().all(|c| c.digest.len() == 64 && c.digest.chars().all(|ch| ch.is_ascii_hexdigit())));
}
