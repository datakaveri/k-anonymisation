//! The orchestrator's staging pass: clean, suppress, stamp — in one read.
//!
//! Everything here runs on the AO, inside the TEE, before a single byte is
//! chunked or dispatched. The three steps are folded into one pass over the
//! file because they are all row-level work on the full dataset and a large
//! input should be read once, not three times.
//!
//! ## Why each step is here rather than in a container
//!
//! **Cleaning** decides the row set. Dropping a row shifts every row range in
//! the chunk manifest, so it has to happen before chunking or the manifest
//! describes a dataset that no longer exists. It is also the step that stops a
//! missing value reaching k-anonymisation as the literal string `"N/A"`, where
//! it becomes its own quasi-identifier value and splits equivalence classes
//! that should have merged.
//!
//! **Suppression** drops whole columns. Doing it here means those columns never
//! reach any container at all — a stronger property than dropping them later,
//! and free, since the file is already open.
//!
//! **Row-id stamping** has to come last, after cleaning has settled which rows
//! exist, so the ids are dense and every downstream shard agrees on them.

use super::DEFAULT_ROW_ID_COLUMN;
use crate::pipeline::bootstrap::{
    csv_row_to_line, parse_runtime_config, split_csv_line_basic, validation, CleaningConfig,
    PipelineError,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

/// What staging did, in enough detail for the AO to show a user why their row
/// count changed.
#[derive(Debug, Default, Serialize)]
pub struct StageReport {
    pub rows_in: usize,
    pub rows_out: usize,
    pub rows_dropped: usize,
    /// Why rows were dropped, by reason.
    pub dropped_by_reason: BTreeMap<String, usize>,
    /// Per-column count of values rewritten to the missing-value representation.
    pub nulls_normalised: BTreeMap<String, usize>,
    /// Per-column count of values that were trimmed or had whitespace collapsed.
    pub whitespace_fixed: BTreeMap<String, usize>,
    /// Per-column count of values dropped for not parsing as a number.
    pub non_numeric: BTreeMap<String, usize>,
    pub columns_suppressed: Vec<String>,
    pub columns_out: Vec<String>,
    pub row_id_column: String,
    pub cleaning_enabled: bool,
}

/// Cleans, suppresses and stamps `input` into `output`.
///
/// Returns the report. Fails with `STAGE_TOO_MANY_DROPPED` if cleaning would
/// discard more than `max_dropped_fraction` of the rows — at that point the
/// step has changed the answer rather than tidied the input, and the user
/// should see that before a job runs on it.
pub fn stage(
    config_path: &Path,
    input: &Path,
    output: &Path,
    rid_col: &str,
    suppress: bool,
) -> Result<StageReport, PipelineError> {
    let cfg = parse_runtime_config(config_path)?;
    let clean = &cfg.cleaning;

    let file = fs::File::open(input).map_err(|e| {
        validation("IO_READ_FAILED", "Could not open the input", &format!("{}: {e}", input.display()))
    })?;
    let mut lines = BufReader::new(file).lines();
    let header_line = lines
        .next()
        .ok_or_else(|| validation("DATA_EMPTY", "Input has no header row", &input.display().to_string()))?
        .map_err(|e| validation("IO_READ_FAILED", "Failed reading header", &e.to_string()))?;
    let headers = split_csv_line_basic(&header_line);

    if headers.iter().any(|h| h == rid_col) {
        return Err(validation(
            "BLOCK_RID_PROTECTED",
            "The input already has a column with the reserved row-id name",
            &format!("rename '{rid_col}' in the source data, or configure a different row_id_column"),
        ));
    }

    // Column sets are resolved once, against the real header, so a config that
    // names a column the data lacks fails here rather than per row.
    let resolve = |cols: &[String], what: &str| -> Result<Vec<usize>, PipelineError> {
        cols.iter()
            .map(|c| {
                headers.iter().position(|h| h == c).ok_or_else(|| {
                    validation(
                        "STAGE_COLUMN_MISSING",
                        "A column named in the config is not in the input",
                        &format!("'{c}' ({what})"),
                    )
                })
            })
            .collect()
    };
    let required_idx = if clean.enabled { resolve(&clean.required_columns, "cleaning.required_columns")? } else { vec![] };
    let numeric_idx = if clean.enabled { resolve(&clean.numeric_columns, "cleaning.numeric_columns")? } else { vec![] };
    let suppress_idx = if suppress { resolve(&cfg.suppress, "suppress")? } else { vec![] };

    let keep: Vec<usize> = (0..headers.len()).filter(|i| !suppress_idx.contains(i)).collect();
    let mut out_headers: Vec<String> = keep.iter().map(|&i| headers[i].clone()).collect();
    out_headers.insert(0, rid_col.to_string());

    let mut report = StageReport {
        columns_suppressed: suppress_idx.iter().map(|&i| headers[i].clone()).collect(),
        columns_out: out_headers.clone(),
        row_id_column: rid_col.to_string(),
        cleaning_enabled: clean.enabled,
        ..Default::default()
    };

    if let Some(p) = output.parent() {
        fs::create_dir_all(p)?;
    }
    let tmp = output.with_extension("csv.tmp");
    let mut w = BufWriter::new(fs::File::create(&tmp)?);
    w.write_all(csv_row_to_line(&out_headers).as_bytes())?;
    w.write_all(b"\n")?;

    let mut rid = 0usize;
    for line in lines {
        let line = line.map_err(|e| validation("IO_READ_FAILED", "Failed reading row", &e.to_string()))?;
        if line.trim().is_empty() {
            continue;
        }
        report.rows_in += 1;
        let mut row = split_csv_line_basic(&line);
        row.resize(headers.len(), String::new());

        if clean.enabled {
            if let Some(reason) = clean_row(&mut row, &headers, clean, &required_idx, &numeric_idx, &mut report) {
                report.rows_dropped += 1;
                *report.dropped_by_reason.entry(reason).or_insert(0) += 1;
                continue;
            }
        }

        let mut out: Vec<String> = keep.iter().map(|&i| row[i].clone()).collect();
        out.insert(0, rid.to_string());
        w.write_all(csv_row_to_line(&out).as_bytes())?;
        w.write_all(b"\n")?;
        rid += 1;
    }
    w.flush()?;
    report.rows_out = rid;

    // Checked after the pass so the report explains *what* was dropped, not
    // just that too much was.
    if report.rows_in > 0 {
        let fraction = report.rows_dropped as f64 / report.rows_in as f64;
        if fraction > clean.max_dropped_fraction {
            let _ = fs::remove_file(&tmp);
            return Err(validation(
                "STAGE_TOO_MANY_DROPPED",
                "Cleaning would discard more of the dataset than the job allows",
                &format!(
                    "{} of {} rows ({:.1}%) dropped, limit is {:.1}% — reasons: {}. \
                     Either the data is not what the config expects or the limit is too tight.",
                    report.rows_dropped,
                    report.rows_in,
                    fraction * 100.0,
                    clean.max_dropped_fraction * 100.0,
                    report
                        .dropped_by_reason
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }
    }

    fs::rename(&tmp, output)?;
    Ok(report)
}

/// Cleans one row in place. Returns `Some(reason)` if the row should be dropped.
fn clean_row(
    row: &mut [String],
    headers: &[String],
    clean: &CleaningConfig,
    required_idx: &[usize],
    numeric_idx: &[usize],
    report: &mut StageReport,
) -> Option<String> {
    for (i, field) in row.iter_mut().enumerate() {
        let original = field.clone();

        if clean.trim {
            let t = field.trim();
            if t.len() != field.len() {
                *field = t.to_string();
            }
        }
        if clean.collapse_whitespace && field.contains(|c: char| c.is_whitespace()) {
            let collapsed = field.split_whitespace().collect::<Vec<_>>().join(" ");
            if collapsed != *field {
                *field = collapsed;
            }
        }
        if *field != original {
            *report.whitespace_fixed.entry(headers[i].clone()).or_insert(0) += 1;
        }

        // Sentinel comparison is case-insensitive on the already-trimmed value,
        // so "N/A", "n/a" and " NA " all land on the same representation.
        if clean.null_tokens.iter().any(|t| t == &field.to_lowercase()) {
            if *field != clean.null_replacement {
                *report.nulls_normalised.entry(headers[i].clone()).or_insert(0) += 1;
            }
            *field = clean.null_replacement.clone();
        }
    }

    // A value that should be a number but is not is missing data wearing a
    // disguise; treating it as a literal would let it key its own equivalence
    // class downstream.
    for &i in numeric_idx {
        let v = &row[i];
        if v.is_empty() || v == &clean.null_replacement {
            continue;
        }
        if v.trim().parse::<f64>().is_err() {
            *report.non_numeric.entry(headers[i].clone()).or_insert(0) += 1;
            row[i] = clean.null_replacement.clone();
        }
    }

    let is_missing = |v: &String| v.is_empty() || v == &clean.null_replacement;

    if clean.drop_all_empty_rows && row.iter().all(is_missing) {
        return Some("all_fields_empty".to_string());
    }
    for &i in required_idx {
        if is_missing(&row[i]) {
            return Some(format!("required_column_empty:{}", headers[i]));
        }
    }
    None
}

/// The row-id column name a job uses, defaulting to the reserved one.
pub fn row_id_column(explicit: Option<&str>) -> String {
    explicit.unwrap_or(DEFAULT_ROW_ID_COLUMN).to_string()
}
