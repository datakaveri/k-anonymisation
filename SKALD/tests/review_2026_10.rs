//! Privacy and correctness tests for the 4.0.0 fixes.
//!
//! Three kinds of test live here:
//!
//! - **Properties** (`prop_*`) — the k-anonymity guarantee as the README states
//!   it, checked over generated inputs. Expected to pass.
//! - **Behaviour pins** (`pins_*`) — document what the code does today at an
//!   edge case. Expected to pass; a change here is a behaviour change worth
//!   noticing.
//! - **Defect regressions** (`defect_*`) — each asserts the correct behaviour
//!   for one fixed defect, labelled with its internal finding id. Each failed
//!   before its fix.

use proptest::prelude::*;
use serde_json::{Value, json};
use skald_ola2::pipeline::anonymization::{
    QuasiIdentifierLite, SparseHist, find_ola2_best_rf_detailed, generalize_and_write_outputs,
};
use skald_ola2::pipeline::bootstrap::{HierarchyMap, PipelineError, split_csv_line_basic};
use skald_ola2::pipeline::pipeline::run_pipeline;
use skald_ola2::pipeline::preprocess::crypto::format_preserving_encrypt;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

// ── Harness ──────────────────────────────────────────────────────────────────

static NEXT_ROOT: AtomicUsize = AtomicUsize::new(0);

fn fresh_root(tag: &str) -> PathBuf {
    let n = NEXT_ROOT.fetch_add(1, Ordering::SeqCst);
    let root = std::env::temp_dir().join(format!("skald-review-{}-{tag}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    for d in ["config", "data", "chunks", "output"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    root
}

/// A finished run: the pipeline's result plus the raw text of the main output.
struct Run {
    result: Result<Value, String>,
    output: Option<String>,
    root: PathBuf,
}

impl Run {
    fn error_code(&self) -> Option<String> {
        self.result.as_ref().err().cloned()
    }
    fn outputs(&self) -> Value {
        self.result.as_ref().ok().cloned().unwrap_or(Value::Null)
    }
    /// Output rows as the pipeline itself splits them, header first.
    fn rows(&self) -> Vec<Vec<String>> {
        self.output.as_deref().unwrap_or("").lines().map(split_csv_line_basic).collect()
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Writes `csv` and `section` under a fresh root and runs the pipeline on it.
fn run_raw(tag: &str, csv: &str, section: Value) -> Run {
    let root = fresh_root(tag);
    let output_path = section.get("output_path").and_then(Value::as_str).unwrap_or("generalized.csv").to_string();
    fs::write(root.join("config/c.json"), json!({"data_type": "t", "t": section}).to_string()).unwrap();
    fs::write(root.join("data/in.csv"), csv).unwrap();
    let result = match run_pipeline(&root) {
        Ok(status) => Ok(status.outputs.unwrap_or(Value::Null)),
        Err(PipelineError::Validation { code, .. }) => Err(code.to_string()),
        Err(e) => Err(format!("OTHER: {e}")),
    };
    let output = fs::read_to_string(root.join("output").join(&output_path)).ok();
    Run { result, output, root }
}

fn to_csv(header: &[&str], rows: &[Vec<String>]) -> String {
    let mut s = header.join(",");
    s.push('\n');
    for r in rows {
        s.push_str(&r.join(","));
        s.push('\n');
    }
    s
}

/// Class sizes over the named QI columns of the output.
fn class_sizes(rows: &[Vec<String>], qi_cols: &[&str]) -> BTreeMap<Vec<String>, usize> {
    let header = &rows[0];
    let idx: Vec<usize> = qi_cols
        .iter()
        .map(|c| header.iter().position(|h| h == c).unwrap_or_else(|| panic!("{c} not in {header:?}")))
        .collect();
    let mut out = BTreeMap::new();
    for r in &rows[1..] {
        let key: Vec<String> = idx.iter().map(|&i| r.get(i).cloned().unwrap_or_default()).collect();
        *out.entry(key).or_insert(0) += 1;
    }
    out
}

/// The guarantee, checked on what was actually written: every published class
/// — including the class of fully suppressed (`*`) rows — has at least k
/// records; suppressed rows that would form a smaller `*` class are removed;
/// and published-`*` plus removed rows stay within `suppression_limit`.
fn assert_k_anonymous(run: &Run, qi_cols: &[&str], k: usize, sigma: f64, n: usize) -> Result<(), TestCaseError> {
    let rows = run.rows();
    let removed = run.outputs()["removed_records"].as_u64().unwrap_or(0) as usize;
    prop_assert_eq!(rows.len() - 1 + removed, n, "rows lost or invented");
    let star: Vec<String> = qi_cols.iter().map(|_| "*".to_string()).collect();
    let sizes = class_sizes(&rows, qi_cols);
    for (key, size) in &sizes {
        prop_assert!(*size >= k, "class {:?} has {} < k={} records", key, size, k);
    }
    let suppressed = sizes.get(&star).copied().unwrap_or(0) + removed;
    prop_assert!(suppressed as f64 <= sigma * n as f64 + 1e-9, "{} suppressed > limit {} × {}", suppressed, sigma, n);
    Ok(())
}

fn section(k: Value, sigma: f64) -> Value {
    json!({
        "suppression_limit": sigma,
        "quasi_identifiers": {
            "numerical": [{"column": "Age"}, {"column": "Zip"}],
            "categorical": [{"column": "Gender"}]
        },
        "categorical_hierarchies": {"Gender": {"M": ["Any"], "F": ["Any"], "X": ["Any"]}},
        "size": {"Age": 2, "Zip": 10},
        "k_anonymize": {"k": k},
        "compute_parameter_grid": false
    })
}

const HDR: [&str; 5] = ["Id", "Age", "Zip", "Gender", "Diagnosis"];
const QI: [&str; 3] = ["Age", "Zip", "Gender"];

// ── Q2: properties ───────────────────────────────────────────────────────────

fn clean_row() -> impl Strategy<Value = (u8, u8, u8, u8)> {
    (0u8..100, 0u8..6, 0u8..3, 0u8..5)
}

fn render_clean(rows: &[(u8, u8, u8, u8)]) -> Vec<Vec<String>> {
    rows.iter()
        .enumerate()
        .map(|(i, &(age, zip, g, d))| {
            vec![
                format!("P{i}"),
                age.to_string(),
                (560_000 + 17 * zip as u32).to_string(),
                ["M", "F", "X"][g as usize].to_string(),
                format!("D{d}"),
            ]
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 96, ..ProptestConfig::default() })]

    /// Clean integer / categorical data: every published class is ≥ k and the
    /// suppressed rows stay within the limit. An infeasible (k, σ) must fail
    /// closed — an error and no output file.
    #[test]
    fn prop_output_is_k_anonymous_clean(
        rows in prop::collection::vec(clean_row(), 1..80),
        k in 1usize..12,
        sigma in prop::sample::select(vec![0.0, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0]),
    ) {
        let data = render_clean(&rows);
        let run = run_raw("prop-clean", &to_csv(&HDR, &data), section(json!(k), sigma));
        match &run.result {
            Ok(_) => assert_k_anonymous(&run, &QI, k, sigma, data.len())?,
            Err(code) => {
                prop_assert!(code == "GENERALIZATION_FAILED" || code == "ANON_INFEASIBLE", "unexpected {}", code);
                prop_assert!(run.output.is_none(), "failed run left an output file");
            }
        }
    }

    /// Messy values the README does not rule out: fractional ages, surrounding
    /// whitespace and case variants in the categorical QI. k-anonymity of the
    /// output must still hold; the suppression limit is checked separately in
    /// `prop_suppression_limit_messy`.
    #[test]
    fn prop_output_is_k_anonymous_messy(
        rows in prop::collection::vec((0u16..1000, 0u8..3, 0u8..6, 0u8..5), 1..80),
        k in 1usize..8,
        sigma in prop::sample::select(vec![0.05, 0.1, 0.25, 0.5]),
    ) {
        let data: Vec<Vec<String>> = rows.iter().enumerate().map(|(i, &(age10, zip, g, d))| vec![
            format!("P{i}"),
            format!("{:.1}", age10 as f64 / 10.0),
            (560_000 + zip as u32).to_string(),
            ["M", " M", "m", "F", "F ", "X"][g as usize].to_string(),
            format!("D{d}"),
        ]).collect();
        let run = run_raw("prop-messy", &to_csv(&HDR, &data), section(json!(k), sigma));
        if run.result.is_ok() {
            for (key, size) in class_sizes(&run.rows(), &QI) {
                prop_assert!(size >= k, "class {:?} has {} < k={}", key, size, k);
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 96, ..ProptestConfig::default() })]

    /// Q4/C-6: on messy values OLA-2's histogram and the output
    /// step bin rows differently, so the output can suppress more than
    /// `suppression_limit` while the run still reports success.
    #[test]
    fn prop_suppression_limit_messy(
        rows in prop::collection::vec((0u16..1000, 0u8..6, 0u8..5), 1..80),
        k in 2usize..6,
        sigma in prop::sample::select(vec![0.05, 0.1, 0.25]),
    ) {
        let data: Vec<Vec<String>> = rows.iter().enumerate().map(|(i, &(age10, g, d))| vec![
            format!("P{i}"),
            format!("{:.1}", 20.5 + age10 as f64 / 10.0),
            "560001".to_string(),
            ["M", " M", "m", "F", "F ", "X"][g as usize].to_string(),
            format!("D{d}"),
        ]).collect();
        let run = run_raw("prop-limit", &to_csv(&HDR, &data), section(json!(k), sigma));
        if run.result.is_ok() {
            assert_k_anonymous(&run, &QI, k, sigma, data.len())?;
        }
    }
}

// ── Q1: chunk-wise processing ────────────────────────────────────────────────

fn numeric_qi(name: &str, min: f64, max: f64) -> QuasiIdentifierLite {
    QuasiIdentifierLite {
        column_name: name.to_string(),
        is_categorical: false,
        min_value: Some(min),
        max_value: Some(max),
        interval_hierarchy: None,
        categorical_levels: None,
    }
}

/// One class, three records in each of two chunks, k = 5. Counted per chunk
/// (as on master / v3.3) every record is suppressed; counted globally none is.
#[test]
fn pins_suppression_counts_classes_across_chunks() {
    let root = fresh_root("two-chunks");
    let a = root.join("chunks/chunk_1.csv");
    let b = root.join("chunks/chunk_2.csv");
    fs::write(&a, "Age,Diagnosis\n30,x\n31,y\n30,z\n").unwrap();
    fs::write(&b, "Age,Diagnosis\n31,x\n30,y\n31,z\n").unwrap();
    let qis = vec![numeric_qi("Age", 30.0, 31.0)];
    let summary =
        generalize_and_write_outputs(&[a, b], &qis, &[2], 5, &root.join("output"), "out.csv", &HierarchyMap::new())
            .unwrap();
    let out = fs::read_to_string(root.join("output/out.csv")).unwrap();
    let _ = fs::remove_dir_all(&root);
    assert_eq!(summary.suppressed_records, 0, "{out}");
    assert_eq!(out.matches("[30-31]").count(), 6, "{out}");
}

/// The node is chosen once from a histogram over every chunk and applied to
/// all of them, so no two output rows can carry different generalisations of
/// the same QI.
#[test]
fn pins_one_generalisation_node_for_the_whole_dataset() {
    let data: Vec<Vec<String>> = (0..300)
        .map(|i| {
            vec![format!("P{i}"), (20 + i % 50).to_string(), "560001".into(), ["M", "F"][i % 2].into(), "d".into()]
        })
        .collect();
    let run = run_raw("one-node", &to_csv(&HDR, &data), section(json!(5), 0.05));
    let widths: std::collections::BTreeSet<i64> = run.rows()[1..]
        .iter()
        .filter(|r| r[1] != "*")
        .map(|r| {
            let (lo, hi) = r[1].trim_matches(['[', ']']).split_once('-').unwrap();
            hi.parse::<i64>().unwrap() - lo.parse::<i64>().unwrap() + 1
        })
        .collect();
    assert_eq!(widths.len(), 1, "Age bins of different widths in one release: {widths:?}");
}

// ── Q8: edge-case pins ───────────────────────────────────────────────────────

#[test]
fn pins_single_row_fails_closed() {
    let run = run_raw("one-row", "Id,Age,Zip,Gender,Diagnosis\nP0,30,560001,M,d\n", section(json!(5), 0.0));
    assert_eq!(run.error_code().as_deref(), Some("GENERALIZATION_FAILED"));
    assert!(run.output.is_none());
}

#[test]
fn pins_k_larger_than_n_suppresses_everything_when_allowed() {
    let data: Vec<Vec<String>> =
        (0..20).map(|i| vec![format!("P{i}"), "30".into(), "560001".into(), "M".into(), "d".into()]).collect();
    let run = run_raw("k-gt-n", &to_csv(&HDR, &data), section(json!(50), 1.0));
    // All 20 fail k, and 20 `*` rows would themselves be a class below k = 50,
    // so they are removed rather than published.
    assert_eq!(run.rows().len(), 1, "only the header should remain");
    assert_eq!(run.outputs()["removed_records"], json!(20));
    let closed = run_raw("k-gt-n-0", &to_csv(&HDR, &data), section(json!(50), 0.0));
    assert_eq!(closed.error_code().as_deref(), Some("GENERALIZATION_FAILED"));
}

#[test]
fn pins_qi_header_with_trailing_space_fails_closed() {
    let run = run_raw("hdr-ws", "Id,Age ,Zip,Gender,Diagnosis\nP0,30,560001,M,d\n", section(json!(1), 0.0));
    assert_eq!(run.error_code().as_deref(), Some("DATA_COLUMN_MISSING"));
}

#[test]
fn pins_identifier_header_with_trailing_space_fails_closed() {
    let mut s = section(json!(1), 0.0);
    s["hashing_with_salt"] = json!(["Id"]);
    let run = run_raw("id-ws", "Id ,Age,Zip,Gender,Diagnosis\nP0,30,560001,M,d\n", s);
    assert_eq!(run.error_code().as_deref(), Some("PREPROCESS_COLUMN_MISSING"));
}

/// The hierarchy lookup rule: the *column* key is trimmed and lower-cased on
/// both sides; the *value* is trimmed and NFC-normalised on both sides but
/// stays case-sensitive; a miss falls back to the `"*"` row, then to `"*"`.
#[test]
fn pins_hierarchy_column_key_folds_case_value_key_does_not() {
    let rows: Vec<Vec<String>> = ["M", "m", " M", "F"]
        .iter()
        .flat_map(|g| {
            (0..6).map(move |i| vec![format!("P{i}"), "30".into(), "560001".into(), g.to_string(), "d".into()])
        })
        .collect();
    let mut s = section(json!(5), 0.0);
    s["categorical_hierarchies"] = json!({" GENDER ": {"M": ["Person"], "F": ["Person"]}});
    s["pass"] = json!("pass2");
    s["generalization_node"] = json!({"Age": 1, "Zip": 1, "Gender": 2});
    let run = run_raw("hier-case", &to_csv(&HDR, &rows), s);
    let g: BTreeMap<String, usize> = run.rows()[1..].iter().fold(BTreeMap::new(), |mut m, r| {
        *m.entry(r[3].clone()).or_insert(0) += 1;
        m
    });
    assert_eq!(g.get("Person"), Some(&18), "{g:?}"); // "M", " M" and "F"
    assert_eq!(g.get("*"), Some(&6), "{g:?}"); // "m" missed the ladder
}

// ── Defect regressions ──────────────────────────────────────────────────────

/// P-1: a newline inside a quoted field splits the record. Fields after the
/// newline land in one quoted cell and skip suppression, hashing and
/// generalisation.
#[test]
fn defect_quoted_newline_leaks_identifiers() {
    let mut csv = String::from("Note,Name,Aadhaar,Age,Zip,Gender\n");
    for i in 0..50 {
        csv.push_str(&format!("n,P{i},{},{},560001,M\n", 100_000_000_000u64 + i, 20 + i % 10));
    }
    csv.push_str("\"has\nnewline\",Zed,999988887777,33,560001,F\n");
    let mut s = section(json!(5), 0.1);
    s["suppress"] = json!(["Name"]);
    s["hashing_with_salt"] = json!(["Aadhaar"]);
    s["quasi_identifiers"] =
        json!({"numerical": [{"column": "Age"}, {"column": "Zip"}], "categorical": [{"column": "Gender"}]});
    let run = run_raw("newline", &csv, s);
    let out = run.output.clone().unwrap_or_default();
    assert!(!out.contains("999988887777"), "raw Aadhaar in output:\n{out}");
    assert!(!out.contains("Zed"), "suppressed Name in output:\n{out}");
}

/// P-2: `"k": 5.0` (or `"5"`) is not an i64, so k silently becomes 2.
#[test]
fn defect_float_k_is_not_downgraded() {
    for k in [json!(5.0), json!("5")] {
        let data: Vec<Vec<String>> = (0..60)
            .map(|i| {
                vec![
                    format!("P{i}"),
                    (20 + (i * 7) % 40).to_string(),
                    "560001".into(),
                    ["M", "F"][i % 2].into(),
                    "d".into(),
                ]
            })
            .collect();
        let run = run_raw("float-k", &to_csv(&HDR, &data), section(k.clone(), 0.0));
        if let Err(code) = &run.result {
            assert!(code.starts_with("CONFIG"), "k={k}: {code}");
            continue;
        }
        let small: Vec<_> = class_sizes(&run.rows(), &QI).into_iter().filter(|(_, n)| *n < 5).collect();
        assert!(small.is_empty(), "k={k} published classes below 5: {small:?}");
    }
}

/// P-3: QIs configured but the `k_anonymize` block missing or misspelt → the
/// run "succeeds" as preprocess-only and publishes the QIs untouched.
#[test]
fn defect_missing_k_anonymize_fails_closed() {
    let mut s = section(json!(5), 0.0);
    let k = s.as_object_mut().unwrap().remove("k_anonymize").unwrap();
    s["k_anonymity"] = k; // the typo
    let data: Vec<Vec<String>> =
        (0..30).map(|i| vec![format!("P{i}"), (20 + i).to_string(), "560001".into(), "M".into(), "d".into()]).collect();
    let run = run_raw("no-k", &to_csv(&HDR, &data), s);
    assert!(run.result.is_err(), "ran as {:?} and wrote:\n{:?}", run.outputs()["pass"], run.output);
}

/// P-4: a numeric QI whose column name ends in `_scaled` / `_encoded` is
/// located by its full name for OLA but by its suffix-stripped name for
/// output, so it is published raw and left out of the class key.
#[test]
fn defect_suffixed_qi_column_is_generalised() {
    let mut csv = String::from("Id,Income_scaled,Gender\n");
    for i in 0..100 {
        csv.push_str(&format!("P{i},{},{}\n", 10_000 + i * 397, ["M", "F"][i % 2]));
    }
    let mut s = section(json!(5), 0.05);
    s["quasi_identifiers"] = json!({"numerical": [{"column": "Income_scaled"}], "categorical": [{"column": "Gender"}]});
    s["size"] = json!({"Income": 10});
    let run = run_raw("scaled", &csv, s);
    if run.result.is_err() {
        return; // failing closed is an acceptable fix
    }
    let small: usize = class_sizes(&run.rows(), &["Income_scaled", "Gender"])
        .into_iter()
        .filter(|(k, n)| *n < 5 && k[0] != "*")
        .map(|(_, n)| n)
        .sum();
    assert_eq!(small, 0, "rows published in classes below k:\n{}", run.output.as_deref().unwrap_or(""));
}

/// P-5: suppressed rows keep every non-QI column. When fewer than k rows are
/// suppressed, the `*` group is itself a class below k: an attacker who knows
/// the target is in the release and matches no published class learns the
/// target's sensitive value.
#[test]
fn defect_outlier_is_not_reidentifiable() {
    let mut data = Vec::new();
    for age in [25, 35, 45, 55] {
        for g in ["M", "F"] {
            for i in 0..10 {
                data.push(vec![
                    format!("P{}", data.len()),
                    (age + i % 4).to_string(),
                    "560001".into(),
                    g.into(),
                    format!("D{}", i % 4),
                ]);
            }
        }
    }
    data.push(vec!["Alice".into(), "99".into(), "560001".into(), "F".into(), "HIV".into()]);
    let run = run_raw("outlier", &to_csv(&HDR, &data), section(json!(5), 0.02));
    let rows = run.rows();
    let starred: Vec<&Vec<String>> = rows[1..].iter().filter(|r| r[1] == "*").collect();
    assert!(
        starred.is_empty() || starred.len() >= 5,
        "{} suppressed row(s) published with Diagnosis: {:?}",
        starred.len(),
        starred.iter().map(|r| &r[4]).collect::<Vec<_>>()
    );
}

/// P-6 / Q4: suppression exactly at the limit must pass. 0.29 × 100 is
/// 28.999… in f64, so 29 suppressed records fail a 29 % limit and OLA-2
/// over-generalises.
#[test]
fn defect_suppression_exactly_at_limit_passes() {
    let mut hist: SparseHist = HashMap::new();
    hist.insert(vec![0], 71);
    for i in 0..29 {
        hist.insert(vec![100 + 10 * i], 1);
    }
    let qis = vec![numeric_qi("Age", 0.0, 999.0)];
    let sizes: HashMap<String, i64> = [("Age".to_string(), 1000)].into();
    let r = find_ola2_best_rf_detailed(&qis, &hist, &[1], &sizes, 5, 0.29, 100).unwrap();
    assert_eq!(r.best_rf, vec![1], "29/100 suppressed should satisfy suppression_limit 0.29");
}

/// P-7: the pyffx construction encrypted each character-class run on its
/// own, and a one-character run degenerated to a key-dependent constant
/// shift: one known pair revealed every value. FF1 over the whole value must
/// refuse domains below 10^6 and must not shift digits by a constant.
#[test]
fn defect_single_char_fpe_is_not_a_shift() {
    for v in ["5", "A", "12345"] {
        let err = format_preserving_encrypt(v, "k1", "c").expect_err(v);
        assert!(matches!(err, PipelineError::Validation { code: "FPE_DOMAIN_TOO_SMALL", .. }), "{v}: {err:?}");
    }
    for key in ["k1", "another key", "0707070707070707"] {
        let shifts: std::collections::BTreeSet<u32> = (0..10u32)
            .map(|d| {
                let c = format_preserving_encrypt(&format!("{d}00000"), key, "c").unwrap();
                (c.as_bytes()[0] as u32 + 10 - b'0' as u32 - d) % 10
            })
            .collect();
        assert!(shifts.len() > 1, "every leading digit shifted by the same amount {shifts:?}");
    }
}

/// P-8: non-FPE `encrypt` XORs every value with the same keystream, so one
/// known plaintext decrypts the column.
#[test]
fn defect_encrypt_resists_known_plaintext() {
    let names = ["Alice Kumar", "Ravi Shankar", "Lakshmi Devi"];
    let mut csv = String::from("Name,Age\n");
    for i in 0..15 {
        csv.push_str(&format!("{},{}\n", names[i % 3], 30 + i % 2));
    }
    let s = json!({
        "suppression_limit": 0.0, "encrypt": ["Name"],
        "quasi_identifiers": {"numerical": [{"column": "Age"}]}, "size": {"Age": 2},
        "k_anonymize": {"k": 1}, "compute_parameter_grid": false
    });
    let run = run_raw("mtp", &csv, s);
    let rows = run.rows();
    let ct = |i: usize| hex::decode(rows[i][0].trim_start_matches("ENC1$")).unwrap();
    let keystream: Vec<u8> = ct(1).iter().zip(names[0].as_bytes()).map(|(c, p)| c ^ p).collect();
    let recovered: Vec<u8> = ct(2).iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
    assert_ne!(String::from_utf8_lossy(&recovered), names[1][..recovered.len()], "decrypted row 2 from row 1");
}

/// P-9: format-preserving encryption passes every non-ASCII character through,
/// so names in Indic scripts are published verbatim.
#[test]
fn defect_fpe_encrypts_non_ascii() {
    let mut csv = String::from("Name,Age\n");
    for i in 0..10 {
        csv.push_str(&format!("राम प्रसाद,{}\n", 30 + i % 2));
    }
    let s = json!({
        "suppression_limit": 0.0, "encrypt": [{"Name": {"format_preserving": true}}],
        "quasi_identifiers": {"numerical": [{"column": "Age"}]}, "size": {"Age": 2},
        "k_anonymize": {"k": 1}, "compute_parameter_grid": false
    });
    let run = run_raw("fpe-utf8", &csv, s);
    assert!(!run.output.as_deref().unwrap_or("").contains("राम"), "Devanagari name published in plaintext");
    assert_eq!(run.error_code().as_deref(), Some("FPE_VALUE_UNSUPPORTED"), "must fail closed");
}

/// P-10: `fixed_bins` is parsed and documented but the live QI builder never
/// reads it, so the column is binned uniformly instead.
#[test]
fn defect_fixed_bins_are_applied() {
    let data: Vec<Vec<String>> = (0..200)
        .map(|i| {
            vec![format!("P{i}"), (20 + i % 40).to_string(), "560001".into(), ["M", "F"][i % 2].into(), "d".into()]
        })
        .collect();
    let mut s = section(json!(5), 0.05);
    s["fixed_bins"] = json!({"Age": [{"from": 0, "to": 39}, {"from": 40, "to": 120}]});
    let run = run_raw("fixed-bins", &to_csv(&HDR, &data), s);
    for r in &run.rows()[1..] {
        assert!(["[0-39]", "[40-120]", "*"].contains(&r[1].as_str()), "Age label {:?} is not a fixed bin", r[1]);
    }
}

// ── Regressions for the remaining fixes ──────────────────────────────────────

/// P-18: with `l_diversity`, a class whose sensitive values are all the same
/// is not published — the homogeneity attack from the review's Q9.
#[test]
fn l_diversity_blocks_the_homogeneity_attack() {
    let mut data = Vec::new();
    for age in [25, 35, 45, 55] {
        for g in ["M", "F"] {
            for i in 0..10 {
                data.push(vec![
                    format!("P{}", data.len()),
                    (age + i % 4).to_string(),
                    "560001".into(),
                    g.into(),
                    format!("D{}", i % 4),
                ]);
            }
        }
    }
    for j in 0..5 {
        data.push(vec![format!("Bob{j}"), (62 + j % 2).to_string(), "560099".into(), "M".into(), "Cancer".into()]);
    }
    let mut s = section(json!(5), 0.05);
    s["l_diversity"] = json!({"l": 2, "sensitive_attributes": ["Diagnosis"]});
    let run = run_raw("l-div", &to_csv(&HDR, &data), s);
    assert!(run.result.is_ok(), "{:?}", run.result);
    let rows = run.rows();
    let mut by_class: BTreeMap<Vec<String>, std::collections::BTreeSet<String>> = BTreeMap::new();
    for r in &rows[1..] {
        by_class.entry(vec![r[1].clone(), r[2].clone(), r[3].clone()]).or_default().insert(r[4].clone());
    }
    for (class, diagnoses) in &by_class {
        assert!(diagnoses.len() >= 2, "class {class:?} discloses its only diagnosis {diagnoses:?}");
    }
}

/// P-19: a masking regex the engine cannot compile used to leave the value
/// unmasked; it must stop the run instead.
#[test]
fn masking_with_an_unsupported_regex_fails_closed() {
    let mut s = section(json!(2), 0.1);
    s["masking"] = json!([{"column": "Id", "regex_patterns": [{"regex": "(?<=\\d{4})\\d"}]}]);
    let run = run_raw("mask-regex", "Id,Age,Zip,Gender,Diagnosis\n123456789012,30,560001,M,d\n", s);
    assert_eq!(run.error_code().as_deref(), Some("PREPROCESS_CONFIG_INVALID"));
    assert!(run.output.is_none());
}

/// C-9: OLA-2's tagging assumes a ladder never splits a group it merged.
#[test]
fn a_non_nesting_hierarchy_is_refused() {
    let data: Vec<Vec<String>> = (0..20)
        .map(|i| vec![format!("P{i}"), "30".into(), "560001".into(), ["A", "B"][i % 2].into(), "d".into()])
        .collect();
    let mut s = section(json!(2), 0.1);
    s["categorical_hierarchies"] = json!({"Gender": {"A": ["X", "P"], "B": ["X", "Q"]}});
    let run = run_raw("nesting", &to_csv(&HDR, &data), s);
    assert_eq!(run.error_code().as_deref(), Some("CONFIG_INVALID_VALUE"));
}

/// C-7 / C-8: one extreme or non-finite value used to stretch the range so
/// far that f64 could not tell ages apart (84% suppressed) or overflowed i64.
#[test]
fn extreme_numeric_values_have_no_bin_and_do_not_blur_the_others() {
    for bad in ["-1e18", "inf", "NaN", "1e308"] {
        let mut data: Vec<Vec<String>> = (0..200)
            .map(|i| {
                vec![format!("P{i}"), (20 + i % 40).to_string(), "560001".into(), ["M", "F"][i % 2].into(), "d".into()]
            })
            .collect();
        data[0][1] = bad.to_string();
        let run = run_raw("extreme", &to_csv(&HDR, &data), section(json!(5), 0.05));
        assert!(run.result.is_ok(), "{bad}: {:?}", run.result);
        let suppressed = run.outputs()["suppressed_records"].as_i64().unwrap();
        assert!(suppressed <= 10, "{bad}: {suppressed} suppressed");
        assert!(!run.output.as_deref().unwrap().contains(bad), "{bad} published");
    }
}

/// C-11: a lattice too large to search fails fast instead of hanging.
#[test]
fn an_oversized_lattice_fails_fast() {
    let cols: Vec<String> = (0..8).map(|i| format!("Q{i}")).collect();
    let mut csv = cols.join(",") + "\n";
    for r in 0..50 {
        csv += &cols
            .iter()
            .enumerate()
            .map(|(i, _)| ((r * 37 + i * 101) % 1000).to_string())
            .collect::<Vec<_>>()
            .join(",");
        csv += "\n";
    }
    let s = json!({
        "suppression_limit": 0.05,
        "quasi_identifiers": {"numerical": cols.iter().map(|c| json!({"column": c})).collect::<Vec<_>>()},
        "size": cols.iter().map(|c| (c.clone(), json!(2))).collect::<serde_json::Map<_, _>>(),
        "k_anonymize": {"k": 5}, "compute_parameter_grid": false
    });
    let t = std::time::Instant::now();
    let run = run_raw("lattice", &csv, s);
    assert_eq!(run.error_code().as_deref(), Some("LATTICE_TOO_LARGE"));
    assert!(t.elapsed().as_secs() < 10, "took {:?}", t.elapsed());
}

/// P-2: a misspelt technique key used to be ignored, releasing the column.
#[test]
fn an_unknown_config_key_is_refused() {
    let mut s = section(json!(2), 0.1);
    s["suppres"] = json!(["Id"]);
    let run = run_raw("typo", "Id,Age,Zip,Gender,Diagnosis\nP0,30,560001,M,d\n", s);
    assert_eq!(run.error_code().as_deref(), Some("CONFIG_UNKNOWN_KEY"));
    assert!(run.output.is_none());
}

/// P-14: unsalted SHA-256 of an identifier can be reversed by enumeration.
#[test]
fn hashing_without_salt_is_refused() {
    let mut s = section(json!(2), 0.1);
    s["hashing_without_salt"] = json!(["Id"]);
    let run = run_raw("unsalted", "Id,Age,Zip,Gender,Diagnosis\nP0,30,560001,M,d\n", s);
    assert_eq!(run.error_code().as_deref(), Some("CONFIG_INVALID_VALUE"));
}

/// P-4 / P-11: key material goes to its own directory, owner-only, never
/// beside the release; leftovers in the release directory stop the run.
#[test]
fn key_material_stays_out_of_the_release_directory() {
    let data: Vec<Vec<String>> = (0..20)
        .map(|i| vec![format!("P{i}"), (30 + i % 2).to_string(), "560001".into(), "M".into(), "d".into()])
        .collect();
    let mut s = section(json!(2), 0.1);
    s["encrypt"] = json!(["Id"]);
    s["tokenization"] = json!([{"column": "Diagnosis"}]);
    let root = fresh_root("keys");
    fs::write(root.join("config/c.json"), json!({"data_type": "t", "t": s}).to_string()).unwrap();
    fs::write(root.join("data/in.csv"), to_csv(&HDR, &data)).unwrap();
    run_pipeline(&root).expect("run");
    let output: Vec<String> =
        fs::read_dir(root.join("output")).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    assert!(!output.iter().any(|n| n.contains("keys") || n.contains("vault") || n.contains("salt")), "{output:?}");
    for f in ["symmetric_keys.json", "token_vault.json"] {
        let path = root.join("keys").join(f);
        assert!(path.is_file(), "{f} missing from keys/");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600, "{f}");
        }
    }
    assert!(!fs::read_dir(root.join("chunks")).unwrap().any(|_| true), "scratch left behind");

    // A pre-4.0 layout with keys beside the output is refused, not silently re-keyed.
    fs::rename(root.join("keys/symmetric_keys.json"), root.join("output/symmetric_keys.json")).unwrap();
    let err = run_pipeline(&root).expect_err("keys in output/ must stop the run");
    assert!(matches!(err, PipelineError::Validation { code: "KEY_MATERIAL_IN_OUTPUT", .. }), "{err:?}");
    let _ = fs::remove_dir_all(&root);
}
