//! Sharding helpers for the orchestrator: stamp, project, split, stitch.
//!
//! The AO could write these itself, but the CSV dialect has to match the one
//! the blocks parse with exactly — quoting, embedded commas and line breaks,
//! blank-line handling — and a mismatch here shows up as silently shifted
//! columns rather than as an error. Every reader here is the pipeline's own
//! record reader: a quoted field may span lines, and a row whose width differs
//! from its header is an error.
//!
//! ```text
//!   stamp_row_ids   input.csv                       → staged.csv (+ __skald_rid)
//!   project_columns staged.csv, [cols]              → group shard (rid + cols)
//!   split_rows      group shard, n                  → row shards for fan-out
//!   stitch_columns  staged.csv, [processed shards],
//!                   [removed rids]                  → final output
//! ```
//!
//! `stitch_columns` joins on the rid rather than on row position, drops every
//! row k-anonymity removed, and refuses a result in which a processed column
//! is missing for any surviving row — the stitch would otherwise fall back to
//! the staged (unprocessed) value for it.

use crate::pipeline::bootstrap::{PipelineError, csv_row_to_line, open_csv, validation};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

fn create(path: &Path) -> Result<BufWriter<fs::File>, PipelineError> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    Ok(BufWriter::new(fs::File::create(path)?))
}

fn write_row(w: &mut BufWriter<fs::File>, row: &[String]) -> Result<(), PipelineError> {
    w.write_all(csv_row_to_line(row).as_bytes())?;
    w.write_all(b"\n")?;
    Ok(())
}

/// Copies `input` to `output` with a reserved row-id column prepended.
///
/// Returns the number of data rows stamped.
pub fn stamp_row_ids(input: &Path, output: &Path, rid_col: &str) -> Result<usize, PipelineError> {
    let (mut headers, mut records) = open_csv(input)?;
    if headers.iter().any(|h| h == rid_col) {
        return Err(validation(
            "BLOCK_RID_PROTECTED",
            "The input already has a column with the reserved row-id name",
            &format!("rename '{rid_col}' in the source data, or configure a different row_id_column"),
        ));
    }
    let width = headers.len();
    headers.insert(0, rid_col.to_string());

    let mut w = create(output)?;
    write_row(&mut w, &headers)?;
    let mut n = 0usize;
    while let Some(mut row) = records.next_record_of_width(width)? {
        row.insert(0, n.to_string());
        write_row(&mut w, &row)?;
        n += 1;
    }
    w.flush()?;
    Ok(n)
}

/// Writes a shard holding only the row-id column and `columns`.
///
/// This is the operation that makes the privacy claim concrete: a container
/// handed this file cannot see the columns that were left out, whatever it
/// does. A requested column that is absent is an error rather than a silent
/// omission, because a block would then skip its work and report success.
pub fn project_columns(input: &Path, output: &Path, columns: &[String], rid_col: &str) -> Result<usize, PipelineError> {
    let (headers, mut records) = open_csv(input)?;
    let mut keep: Vec<usize> = Vec::new();
    if let Some(i) = headers.iter().position(|h| h == rid_col) {
        keep.push(i);
    }
    for c in columns {
        let i = headers.iter().position(|h| h == c).ok_or_else(|| {
            validation(
                "PLAN_COLUMN_MISSING",
                "Cannot project a column that is not in the staged input",
                &format!("'{c}' — check the plan against the dataset header"),
            )
        })?;
        if !keep.contains(&i) {
            keep.push(i);
        }
    }

    let mut w = create(output)?;
    write_row(&mut w, &keep.iter().map(|&i| headers[i].clone()).collect::<Vec<_>>())?;
    let mut n = 0usize;
    while let Some(row) = records.next_record_of_width(headers.len())? {
        write_row(&mut w, &keep.iter().map(|&i| row[i].clone()).collect::<Vec<_>>())?;
        n += 1;
    }
    w.flush()?;
    Ok(n)
}

/// Splits a shard into row shards of at most `rows_per_shard` rows each,
/// repeating the header in every one. Returns the shard paths in order.
pub fn split_rows(
    input: &Path,
    out_dir: &Path,
    prefix: &str,
    rows_per_shard: usize,
) -> Result<Vec<PathBuf>, PipelineError> {
    if rows_per_shard == 0 {
        return Err(validation("CONFIG_INVALID_VALUE", "rows_per_shard must be greater than zero", "pass --rows <n>"));
    }
    fs::create_dir_all(out_dir)?;
    let (headers, mut records) = open_csv(input)?;

    let mut paths = Vec::new();
    let mut rows = 0usize;
    let mut path = out_dir.join(format!("{prefix}_1.csv"));
    let mut w = create(&path)?;
    write_row(&mut w, &headers)?;
    while let Some(row) = records.next_record_of_width(headers.len())? {
        if rows > 0 && rows.is_multiple_of(rows_per_shard) {
            w.flush()?;
            paths.push(path);
            path = out_dir.join(format!("{prefix}_{}.csv", paths.len() + 1));
            w = create(&path)?;
            write_row(&mut w, &headers)?;
        }
        write_row(&mut w, &row)?;
        rows += 1;
    }
    w.flush()?;
    paths.push(path);
    Ok(paths)
}

/// Reads the row ids `kanon apply` removed, from its `*.removed_rids.json`
/// artifacts.
pub fn read_removed_rids(paths: &[PathBuf]) -> Result<Vec<String>, PipelineError> {
    let mut out = Vec::new();
    for p in paths {
        let v: serde_json::Value = serde_json::from_str(&fs::read_to_string(p).map_err(|e| {
            validation("IO_READ_FAILED", "Could not read a removed-rows artifact", &format!("{}: {e}", p.display()))
        })?)?;
        let rids = v.get("removed_rids").and_then(serde_json::Value::as_array).ok_or_else(|| {
            validation(
                "BLOCK_ARTIFACT_INVALID",
                "A removed-rows artifact has no removed_rids list",
                &p.display().to_string(),
            )
        })?;
        for r in rids {
            out.push(
                r.as_str()
                    .ok_or_else(|| {
                        validation(
                            "BLOCK_ARTIFACT_INVALID",
                            "removed_rids holds a non-string",
                            &p.display().to_string(),
                        )
                    })?
                    .to_string(),
            );
        }
    }
    Ok(out)
}

/// Rebuilds one dataset from processed column shards.
///
/// `base` supplies the column order and the authoritative row set; each shard
/// overwrites the columns it carries, matched by row id. Pass shards in plan
/// order: when two shards carry the same column for the same row (one block's
/// output fed the next), the later one is the final value.
///
/// `routed` is the set of columns the orchestrator sent out to *any* block —
/// it is what separates the two reasons a column can be missing from the
/// shards that came back. A routed column nobody returned was suppressed, so
/// it is dropped from the output. A column that was never routed is
/// passthrough: it stayed on the orchestrator and its base value is kept.
///
/// `removed` lists the row ids `kanon apply` removed; those rows are left out
/// of the output entirely, whatever other shards returned for them.
///
/// Every column a shard returned must come back for every row that survives:
/// otherwise that row would be written with its staged, unprocessed value.
pub fn stitch_columns(
    base: &Path,
    shards: &[PathBuf],
    routed: &[String],
    removed: &[String],
    output: &Path,
    rid_col: &str,
) -> Result<usize, PipelineError> {
    let (base_headers, mut base_records) = open_csv(base)?;
    let base_rid = base_headers.iter().position(|h| h == rid_col).ok_or_else(|| {
        validation(
            "BLOCK_RID_PROTECTED",
            "The staged input has no row-id column to stitch on",
            &format!("expected '{rid_col}' — stamp row ids before sharding"),
        )
    })?;
    let removed: HashSet<&str> = removed.iter().map(String::as_str).collect();

    // rid → column name → value, accumulated across every shard.
    let mut patches: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut returned: Vec<String> = Vec::new();

    for shard in shards {
        let (headers, mut records) = open_csv(shard)?;
        let rid_i = headers.iter().position(|h| h == rid_col).ok_or_else(|| {
            validation(
                "BLOCK_RID_PROTECTED",
                "A processed shard came back without its row-id column",
                &format!("{} — the block must pass '{rid_col}' through untouched", shard.display()),
            )
        })?;
        for h in headers.iter().filter(|h| *h != rid_col) {
            if !returned.contains(h) {
                returned.push(h.clone());
            }
        }
        while let Some(row) = records.next_record_of_width(headers.len())? {
            let entry = patches.entry(row[rid_i].clone()).or_default();
            for (i, h) in headers.iter().enumerate() {
                if i != rid_i {
                    entry.insert(h.clone(), row[i].clone());
                }
            }
        }
    }

    let out_headers: Vec<String> = base_headers
        .iter()
        .enumerate()
        .filter(|(i, h)| {
            // Kept when a shard returned it, or when it was never routed out.
            *i != base_rid && (returned.iter().any(|r| r == *h) || !routed.iter().any(|r| r == *h))
        })
        .map(|(_, h)| h.clone())
        .collect();
    let base_idx: Vec<usize> =
        out_headers.iter().map(|h| base_headers.iter().position(|b| b == h).unwrap_or(usize::MAX)).collect();

    let tmp = output.with_extension("csv.tmp");
    let mut w = create(&tmp)?;
    write_row(&mut w, &out_headers)?;

    let mut n = 0usize;
    let mut incomplete: Vec<String> = Vec::new();
    let mut incomplete_rows = 0usize;
    while let Some(row) = base_records.next_record_of_width(base_headers.len())? {
        let rid = &row[base_rid];
        if removed.contains(rid.as_str()) {
            continue;
        }
        let patch = patches.get(rid);
        let mut out = Vec::with_capacity(out_headers.len());
        let mut missing = false;
        for (h, &bi) in out_headers.iter().zip(&base_idx) {
            match patch.and_then(|p| p.get(h)) {
                Some(v) => out.push(v.clone()),
                None if returned.contains(h) => {
                    missing = true;
                    if !incomplete.contains(h) {
                        incomplete.push(h.clone());
                    }
                    out.push(String::new());
                }
                None => out.push(row.get(bi).cloned().unwrap_or_default()),
            }
        }
        if missing {
            incomplete_rows += 1;
            continue;
        }
        write_row(&mut w, &out)?;
        n += 1;
    }
    w.flush()?;
    drop(w);

    // A worker that lost rows must not produce output that merely looks
    // shorter, or that quietly carries the staged value for its column — the
    // AO needs to see this as a failed shard.
    if incomplete_rows > 0 {
        let _ = fs::remove_file(&tmp);
        return Err(validation(
            "BLOCK_SHARD_INCOMPLETE",
            "Some rows came back without a processed value for a column",
            &format!(
                "{incomplete_rows} row(s) missing column(s) {} — a block dropped rows, a shard is missing from the \
                 stitch, or a removed-rows list was not passed",
                incomplete.join(", ")
            ),
        ));
    }
    fs::rename(&tmp, output)?;
    Ok(n)
}
