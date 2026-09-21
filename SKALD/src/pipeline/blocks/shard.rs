//! Sharding helpers for the orchestrator: stamp, project, split, stitch.
//!
//! The AO could write these itself, but the CSV dialect has to match the one
//! the blocks parse with exactly — quoting, embedded commas, blank-line
//! handling — and a mismatch here shows up as silently shifted columns rather
//! than as an error. Shipping them alongside the blocks keeps one dialect.
//!
//! The lifecycle these four functions describe is the whole column-sharding
//! story:
//!
//! ```text
//!   stamp_row_ids   input.csv                       → staged.csv (+ __skald_rid)
//!   project_columns staged.csv, [cols]              → group shard (rid + cols)
//!   split_rows      group shard, n                  → row shards for fan-out
//!   stitch_columns  staged.csv, [processed shards]  → final output
//! ```
//!
//! `stitch_columns` joins on the rid rather than on row position. Position
//! would work today, because every block preserves row order — but it would
//! break the first time a block is allowed to reorder or filter, and it gives
//! no way to detect a shard that came back short.

use crate::pipeline::bootstrap::{csv_row_to_line, split_csv_line_basic, validation, PipelineError};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

/// Copies `input` to `output` with a reserved row-id column prepended.
///
/// Returns the number of data rows stamped.
pub fn stamp_row_ids(input: &Path, output: &Path, rid_col: &str) -> Result<usize, PipelineError> {
    let file = fs::File::open(input).map_err(|e| {
        validation("IO_READ_FAILED", "Could not open input", &format!("{}: {e}", input.display()))
    })?;
    let mut lines = BufReader::new(file).lines();
    let header_line = lines
        .next()
        .ok_or_else(|| validation("DATA_EMPTY", "Input has no header row", &input.display().to_string()))?
        .map_err(|e| validation("IO_READ_FAILED", "Failed reading header", &e.to_string()))?;
    let mut headers = split_csv_line_basic(&header_line);

    if headers.iter().any(|h| h == rid_col) {
        return Err(validation(
            "BLOCK_RID_PROTECTED",
            "The input already has a column with the reserved row-id name",
            &format!("rename '{rid_col}' in the source data, or configure a different row_id_column"),
        ));
    }
    headers.insert(0, rid_col.to_string());

    if let Some(p) = output.parent() {
        fs::create_dir_all(p)?;
    }
    let mut w = BufWriter::new(fs::File::create(output)?);
    w.write_all(csv_row_to_line(&headers).as_bytes())?;
    w.write_all(b"\n")?;

    let mut n = 0usize;
    for line in lines {
        let line = line.map_err(|e| validation("IO_READ_FAILED", "Failed reading row", &e.to_string()))?;
        if line.trim().is_empty() {
            continue;
        }
        let mut row = split_csv_line_basic(&line);
        row.insert(0, n.to_string());
        w.write_all(csv_row_to_line(&row).as_bytes())?;
        w.write_all(b"\n")?;
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
pub fn project_columns(
    input: &Path,
    output: &Path,
    columns: &[String],
    rid_col: &str,
) -> Result<usize, PipelineError> {
    let file = fs::File::open(input).map_err(|e| {
        validation("IO_READ_FAILED", "Could not open staged input", &format!("{}: {e}", input.display()))
    })?;
    let mut lines = BufReader::new(file).lines();
    let header_line = lines
        .next()
        .ok_or_else(|| validation("DATA_EMPTY", "Staged input has no header", &input.display().to_string()))?
        .map_err(|e| validation("IO_READ_FAILED", "Failed reading header", &e.to_string()))?;
    let headers = split_csv_line_basic(&header_line);

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

    if let Some(p) = output.parent() {
        fs::create_dir_all(p)?;
    }
    let mut w = BufWriter::new(fs::File::create(output)?);
    let out_header: Vec<String> = keep.iter().map(|&i| headers[i].clone()).collect();
    w.write_all(csv_row_to_line(&out_header).as_bytes())?;
    w.write_all(b"\n")?;

    let mut n = 0usize;
    for line in lines {
        let line = line.map_err(|e| validation("IO_READ_FAILED", "Failed reading row", &e.to_string()))?;
        if line.trim().is_empty() {
            continue;
        }
        let row = split_csv_line_basic(&line);
        let out: Vec<String> = keep.iter().map(|&i| row.get(i).cloned().unwrap_or_default()).collect();
        w.write_all(csv_row_to_line(&out).as_bytes())?;
        w.write_all(b"\n")?;
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
        return Err(validation(
            "CONFIG_INVALID_VALUE",
            "rows_per_shard must be greater than zero",
            "pass --rows <n>",
        ));
    }
    fs::create_dir_all(out_dir)?;
    let file = fs::File::open(input).map_err(|e| {
        validation("IO_READ_FAILED", "Could not open shard", &format!("{}: {e}", input.display()))
    })?;
    let mut lines = BufReader::new(file).lines();
    let header = lines
        .next()
        .ok_or_else(|| validation("DATA_EMPTY", "Shard has no header", &input.display().to_string()))?
        .map_err(|e| validation("IO_READ_FAILED", "Failed reading header", &e.to_string()))?;

    let mut paths = Vec::new();
    let mut idx = 1usize;
    let mut rows = 0usize;
    let mut path = out_dir.join(format!("{prefix}_{idx}.csv"));
    let mut w = BufWriter::new(fs::File::create(&path)?);
    w.write_all(header.as_bytes())?;
    w.write_all(b"\n")?;

    for line in lines {
        let line = line.map_err(|e| validation("IO_READ_FAILED", "Failed reading row", &e.to_string()))?;
        if line.trim().is_empty() {
            continue;
        }
        if rows > 0 && rows % rows_per_shard == 0 {
            w.flush()?;
            paths.push(path.clone());
            idx += 1;
            path = out_dir.join(format!("{prefix}_{idx}.csv"));
            w = BufWriter::new(fs::File::create(&path)?);
            w.write_all(header.as_bytes())?;
            w.write_all(b"\n")?;
        }
        w.write_all(line.as_bytes())?;
        w.write_all(b"\n")?;
        rows += 1;
    }
    w.flush()?;
    paths.push(path);
    Ok(paths)
}

/// Rebuilds one dataset from processed column shards.
///
/// `base` supplies the column order and the authoritative row set; each shard
/// overwrites the columns it carries, matched by row id.
///
/// `routed` is the set of columns the orchestrator sent out to *any* block —
/// it is what separates the two reasons a column can be missing from the
/// shards that came back. A routed column nobody returned was suppressed, so
/// it is dropped from the output. A column that was never routed is
/// passthrough: it stayed on the orchestrator and its base value is kept.
/// Inferring this from the shards alone is not possible, and guessing wrong
/// either leaks a column the job asked to drop or silently deletes one it
/// asked to keep.
pub fn stitch_columns(
    base: &Path,
    shards: &[PathBuf],
    routed: &[String],
    output: &Path,
    rid_col: &str,
) -> Result<usize, PipelineError> {
    let base_file = fs::File::open(base).map_err(|e| {
        validation("IO_READ_FAILED", "Could not open the staged input", &format!("{}: {e}", base.display()))
    })?;
    let mut base_lines = BufReader::new(base_file).lines();
    let base_header_line = base_lines
        .next()
        .ok_or_else(|| validation("DATA_EMPTY", "Staged input has no header", &base.display().to_string()))?
        .map_err(|e| validation("IO_READ_FAILED", "Failed reading header", &e.to_string()))?;
    let base_headers = split_csv_line_basic(&base_header_line);
    let base_rid = base_headers.iter().position(|h| h == rid_col).ok_or_else(|| {
        validation(
            "BLOCK_RID_PROTECTED",
            "The staged input has no row-id column to stitch on",
            &format!("expected '{rid_col}' — stamp row ids before sharding"),
        )
    })?;

    // rid → column name → value, accumulated across every shard.
    let mut patches: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut returned: Vec<String> = Vec::new();

    for shard in shards {
        let f = fs::File::open(shard).map_err(|e| {
            validation("IO_READ_FAILED", "Could not open a processed shard", &format!("{}: {e}", shard.display()))
        })?;
        let mut lines = BufReader::new(f).lines();
        let hl = lines
            .next()
            .ok_or_else(|| validation("DATA_EMPTY", "Processed shard has no header", &shard.display().to_string()))?
            .map_err(|e| validation("IO_READ_FAILED", "Failed reading shard header", &e.to_string()))?;
        let headers = split_csv_line_basic(&hl);
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

        for line in lines {
            let line = line.map_err(|e| validation("IO_READ_FAILED", "Failed reading shard row", &e.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }
            let row = split_csv_line_basic(&line);
            let Some(rid) = row.get(rid_i) else { continue };
            let entry = patches.entry(rid.clone()).or_default();
            for (i, h) in headers.iter().enumerate() {
                if i == rid_i {
                    continue;
                }
                entry.insert(h.clone(), row.get(i).cloned().unwrap_or_default());
            }
        }
    }

    let out_headers: Vec<String> = base_headers
        .iter()
        .enumerate()
        .filter(|(i, h)| {
            if *i == base_rid {
                return false;
            }
            // Kept when a shard returned it, or when it was never routed out.
            returned.iter().any(|r| r == *h) || !routed.iter().any(|r| r == *h)
        })
        .map(|(_, h)| h.clone())
        .collect();

    if let Some(p) = output.parent() {
        fs::create_dir_all(p)?;
    }
    let mut w = BufWriter::new(fs::File::create(output)?);
    w.write_all(csv_row_to_line(&out_headers).as_bytes())?;
    w.write_all(b"\n")?;

    let mut n = 0usize;
    let mut unmatched = 0usize;
    for line in base_lines {
        let line = line.map_err(|e| validation("IO_READ_FAILED", "Failed reading base row", &e.to_string()))?;
        if line.trim().is_empty() {
            continue;
        }
        let row = split_csv_line_basic(&line);
        let Some(rid) = row.get(base_rid) else { continue };
        let patch = patches.get(rid);
        if patch.is_none() && !shards.is_empty() {
            unmatched += 1;
        }
        let mut out = Vec::with_capacity(out_headers.len());
        for h in &out_headers {
            let v = patch
                .and_then(|p| p.get(h).cloned())
                .or_else(|| base_headers.iter().position(|b| b == h).and_then(|i| row.get(i).cloned()))
                .unwrap_or_default();
            out.push(v);
        }
        w.write_all(csv_row_to_line(&out).as_bytes())?;
        w.write_all(b"\n")?;
        n += 1;
    }
    w.flush()?;

    // A worker that lost rows must not produce output that merely looks
    // shorter — the AO needs to see this as a failed shard, not a smaller one.
    if unmatched > 0 {
        return Err(validation(
            "BLOCK_SHARD_INCOMPLETE",
            "Some rows were not accounted for by any processed shard",
            &format!(
                "{unmatched} of {n} row ids appear in the staged input but in no shard output —                  a block dropped rows, or a shard is missing from the stitch"
            ),
        ));
    }
    Ok(n)
}
