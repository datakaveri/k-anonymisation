//! Multi-tabular input support: normalises JSON and multi-sheet Excel inputs
//! into a single CSV (`data/_converted.csv`) so the existing CSV-based chunker
//! (`bootstrap::split_csv_by_ram`) needs no changes.
//!
//! Ported from the pre-Rust-migration Python prototype (`SKALD/chunking.py` on
//! `multitabular-support`): JSON array-of-objects → CSV, and multi-sheet Excel
//! workbooks merged either via an explicit `sheet_joins` config (star-schema
//! joins, e.g. Education's School master ← amenities/snapshot on `school_id`)
//! or, when that's absent, auto-detected shared-column joins as a fallback.

use crate::pipeline::bootstrap::{csv_row_to_line, io_err, validation, PipelineError};
use calamine::{open_workbook_auto, Data, Range, Reader};
use rust_xlsxwriter::Workbook;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

/// A minimal in-memory table: ordered column names + row-major string cells.
/// Empty string represents a missing/null value (mirrors pandas' NaN → "").
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Sheet {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

/// One explicit join step for a multi-sheet Excel workbook — mirrors the
/// Python `SheetJoin` pydantic model. Chaining several steps onto the same
/// `left` sheet builds a star schema.
#[derive(Debug, Clone, PartialEq)]
pub struct SheetJoinSpec {
    pub left: String,
    pub right: String,
    pub on: Vec<String>,
    pub how: String,
}

const ALLOWED_HOW: [&str; 5] = ["left", "right", "inner", "outer", "cross"];

/// Parse the optional `sheet_joins` array from a config section. Structural
/// validation only (shape of the config) — sheet/column existence against the
/// actual workbook is checked later in `apply_sheet_joins`, once the file is read.
pub fn parse_sheet_joins(section: &Value) -> Result<Vec<SheetJoinSpec>, PipelineError> {
    let Some(arr) = section.get("sheet_joins").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };

    let mut specs = Vec::with_capacity(arr.len());
    for (idx, entry) in arr.iter().enumerate() {
        let step_no = idx + 1;
        let obj = entry.as_object().ok_or_else(|| {
            validation(
                "CONFIG_INVALID_VALUE",
                "Invalid sheet_joins entry",
                &format!("step {step_no}: each entry must be a JSON object with 'left', 'right', 'on'"),
            )
        })?;

        let left = obj
            .get("left")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                validation(
                    "CONFIG_INVALID_VALUE",
                    "sheet_joins entry missing 'left'",
                    &format!("step {step_no}"),
                )
            })?;
        let right = obj
            .get("right")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                validation(
                    "CONFIG_INVALID_VALUE",
                    "sheet_joins entry missing 'right'",
                    &format!("step {step_no}"),
                )
            })?;

        let on: Vec<String> = match obj.get("on") {
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
            _ => Vec::new(),
        };
        if on.is_empty() {
            return Err(validation(
                "CONFIG_INVALID_VALUE",
                "sheet_joins 'on' must list at least one join column",
                &format!("step {step_no} ('{left}' -> '{right}')"),
            ));
        }

        let how = obj.get("how").and_then(Value::as_str).unwrap_or("left").to_string();
        if !ALLOWED_HOW.contains(&how.as_str()) {
            return Err(validation(
                "CONFIG_INVALID_VALUE",
                "Invalid sheet_joins 'how'",
                &format!("step {step_no}: '{how}' — must be one of {ALLOWED_HOW:?}"),
            ));
        }

        specs.push(SheetJoinSpec { left, right, on, how });
    }
    Ok(specs)
}

// ── JSON input ───────────────────────────────────────────────────────────────

/// Reads a JSON array-of-objects file into a `Sheet`; missing keys per-record
/// fill as "".
///
/// Note that columns come out **alphabetised**, not in the input file's key
/// order: `serde_json::Value::Object` is a `BTreeMap` unless the crate's
/// `preserve_order` feature is on, so the original ordering is already gone by
/// the time this function sees the records. Only cosmetic — every column is
/// still present, and each row stays aligned to the header — but it does mean
/// JSON in / JSON out does not round-trip column order.
pub fn read_json_sheet(path: &Path) -> Result<Sheet, PipelineError> {
    let raw = fs::read_to_string(path).map_err(|e| io_err("read JSON file", &path.display().to_string(), e))?;
    let value: Value = serde_json::from_str(&raw)?;
    let Value::Array(items) = value else {
        return Err(validation(
            "DATA_JSON_INVALID",
            "JSON input must be a top-level array of objects",
            &path.display().to_string(),
        ));
    };
    if items.is_empty() {
        return Err(validation("DATA_EMPTY", "JSON file contains no records", &path.display().to_string()));
    }

    let mut columns: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for item in &items {
        let obj = item.as_object().ok_or_else(|| {
            validation(
                "DATA_JSON_INVALID",
                "Each JSON record must be an object",
                &path.display().to_string(),
            )
        })?;
        for key in obj.keys() {
            if seen.insert(key.clone()) {
                columns.push(key.clone());
            }
        }
    }

    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|item| {
            let obj = item.as_object().expect("validated above");
            columns
                .iter()
                .map(|c| obj.get(c).map(json_scalar_to_string).unwrap_or_default())
                .collect()
        })
        .collect();

    Ok(Sheet { columns, rows })
}

fn json_scalar_to_string(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::Bool(b) => if *b { "True" } else { "False" }.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

// ── Excel input ──────────────────────────────────────────────────────────────

/// Reads every sheet of an .xlsx/.xls workbook into `Sheet`s, in workbook order.
pub fn read_xlsx_sheets(path: &Path) -> Result<Vec<(String, Sheet)>, PipelineError> {
    let mut workbook = open_workbook_auto(path).map_err(|e| {
        validation(
            "DATA_XLSX_INVALID",
            "Failed to open Excel workbook",
            &format!("{}: {e}", path.display()),
        )
    })?;

    let sheet_names = workbook.sheet_names();
    if sheet_names.is_empty() {
        return Err(validation(
            "DATA_XLSX_INVALID",
            "Excel workbook has no sheets",
            &path.display().to_string(),
        ));
    }

    let mut out = Vec::with_capacity(sheet_names.len());
    for name in sheet_names {
        let range = workbook.worksheet_range(&name).map_err(|e| {
            validation(
                "DATA_XLSX_INVALID",
                "Failed to read Excel sheet",
                &format!("'{name}' in {}: {e}", path.display()),
            )
        })?;
        out.push((name.clone(), range_to_sheet(&range)));
    }
    Ok(out)
}

fn range_to_sheet(range: &Range<Data>) -> Sheet {
    let mut rows_iter = range.rows();
    let columns: Vec<String> = match rows_iter.next() {
        Some(header) => header.iter().map(cell_to_string).collect(),
        None => return Sheet::default(),
    };
    let ncols = columns.len();
    let rows: Vec<Vec<String>> = rows_iter
        .map(|r| {
            let mut v: Vec<String> = r.iter().map(cell_to_string).collect();
            v.resize(ncols, String::new());
            v.truncate(ncols);
            v
        })
        .collect();
    Sheet { columns, rows }
}

fn cell_to_string(cell: &Data) -> String {
    match cell {
        Data::Empty => String::new(),
        Data::String(s) => s.clone(),
        Data::Float(f) => {
            if f.fract() == 0.0 && f.abs() < 1e15 {
                format!("{}", *f as i64)
            } else {
                f.to_string()
            }
        }
        Data::Int(i) => i.to_string(),
        Data::Bool(b) => if *b { "True" } else { "False" }.to_string(),
        Data::DateTime(dt) => dt.to_string(),
        Data::DateTimeIso(s) | Data::DurationIso(s) => s.clone(),
        Data::Error(e) => format!("#ERR:{e:?}"),
    }
}

// ── Join engine ──────────────────────────────────────────────────────────────

fn column_index(sheet: &Sheet, name: &str) -> Option<usize> {
    sheet.columns.iter().position(|c| c == name)
}

/// Hash-joins two sheets on `on`, matching `pandas.DataFrame.merge` semantics
/// for how ∈ {left, right, inner, outer, cross}: duplicate keys on either side
/// produce one output row per matching pair, and overlapping non-key column
/// names are suffixed `_x` (left) / `_y` (right) exactly as pandas does.
///
/// Callers must have already validated that every column in `on` exists in
/// both `left` and `right` — this is an internal invariant, not re-checked here.
fn merge_two(left: &Sheet, right: &Sheet, on: &[String], how: &str) -> Sheet {
    if how == "cross" {
        return cross_join(left, right);
    }

    let left_on_idx: Vec<usize> = on.iter().map(|c| column_index(left, c).expect("validated by caller")).collect();
    let right_on_idx: Vec<usize> = on.iter().map(|c| column_index(right, c).expect("validated by caller")).collect();
    let right_nonkey_idx: Vec<usize> = (0..right.columns.len()).filter(|i| !right_on_idx.contains(i)).collect();

    let right_nonkey_names: HashSet<&str> = right_nonkey_idx.iter().map(|&i| right.columns[i].as_str()).collect();
    let mut out_columns: Vec<String> = left
        .columns
        .iter()
        .map(|c| if right_nonkey_names.contains(c.as_str()) { format!("{c}_x") } else { c.clone() })
        .collect();
    let left_names: HashSet<&str> = left.columns.iter().map(String::as_str).collect();
    for &i in &right_nonkey_idx {
        let name = &right.columns[i];
        out_columns.push(if left_names.contains(name.as_str()) { format!("{name}_y") } else { name.clone() });
    }

    let mut right_index: HashMap<Vec<String>, Vec<usize>> = HashMap::new();
    for (ridx, row) in right.rows.iter().enumerate() {
        let key: Vec<String> = right_on_idx.iter().map(|&i| row[i].clone()).collect();
        right_index.entry(key).or_default().push(ridx);
    }

    let mut out_rows: Vec<Vec<String>> = Vec::new();
    let mut matched_right: HashSet<usize> = HashSet::new();

    for lrow in &left.rows {
        let key: Vec<String> = left_on_idx.iter().map(|&i| lrow[i].clone()).collect();
        match right_index.get(&key) {
            Some(matches) => {
                for &ridx in matches {
                    matched_right.insert(ridx);
                    let rrow = &right.rows[ridx];
                    let mut out_row = lrow.clone();
                    for &i in &right_nonkey_idx {
                        out_row.push(rrow[i].clone());
                    }
                    out_rows.push(out_row);
                }
            }
            None => {
                if how == "left" || how == "outer" {
                    let mut out_row = lrow.clone();
                    out_row.extend(std::iter::repeat(String::new()).take(right_nonkey_idx.len()));
                    out_rows.push(out_row);
                }
                // how == "inner" | "right": an unmatched left row contributes nothing.
            }
        }
    }

    if how == "right" || how == "outer" {
        for (ridx, rrow) in right.rows.iter().enumerate() {
            if matched_right.contains(&ridx) {
                continue;
            }
            let mut out_row = vec![String::new(); left.columns.len()];
            for (pos, &i) in left_on_idx.iter().enumerate() {
                out_row[i] = rrow[right_on_idx[pos]].clone();
            }
            for &i in &right_nonkey_idx {
                out_row.push(rrow[i].clone());
            }
            out_rows.push(out_row);
        }
    }

    Sheet { columns: out_columns, rows: out_rows }
}

fn cross_join(left: &Sheet, right: &Sheet) -> Sheet {
    let right_names: HashSet<&str> = right.columns.iter().map(String::as_str).collect();
    let left_names: HashSet<&str> = left.columns.iter().map(String::as_str).collect();
    let mut out_columns: Vec<String> = left
        .columns
        .iter()
        .map(|c| if right_names.contains(c.as_str()) { format!("{c}_x") } else { c.clone() })
        .collect();
    out_columns.extend(
        right
            .columns
            .iter()
            .map(|c| if left_names.contains(c.as_str()) { format!("{c}_y") } else { c.clone() }),
    );

    let mut out_rows = Vec::with_capacity(left.rows.len().saturating_mul(right.rows.len()));
    for lrow in &left.rows {
        for rrow in &right.rows {
            let mut row = lrow.clone();
            row.extend(rrow.iter().cloned());
            out_rows.push(row);
        }
    }
    Sheet { columns: out_columns, rows: out_rows }
}

/// Applies config-driven join steps in order — mirrors Python's
/// `_apply_sheet_joins`. Each step merges `right` into the running frame for
/// `left` and writes the result back under `left`'s name, so chaining several
/// steps onto one base sheet builds a star schema. The final frame returned is
/// the first step's `left`.
///
/// Fails loudly on any unknown sheet name or missing join column — these
/// depend on the actual workbook contents, so they can only be checked here,
/// not at config-parse time.
pub fn apply_sheet_joins(
    sheets: &[(String, Sheet)],
    joins: &[SheetJoinSpec],
    source_name: &str,
) -> Result<Sheet, PipelineError> {
    let mut frames: HashMap<String, Sheet> = sheets.iter().cloned().collect();
    let available: Vec<&str> = sheets.iter().map(|(n, _)| n.as_str()).collect();
    let mut root: Option<String> = None;

    for (idx, step) in joins.iter().enumerate() {
        let step_no = idx + 1;
        let left = frames.get(&step.left).cloned().ok_or_else(|| {
            validation(
                "DATA_XLSX_INVALID",
                "sheet_joins references an unknown sheet",
                &format!(
                    "step {step_no}: left sheet '{}' not found in workbook '{source_name}'. Available: {available:?}",
                    step.left
                ),
            )
        })?;
        let right = frames.get(&step.right).cloned().ok_or_else(|| {
            validation(
                "DATA_XLSX_INVALID",
                "sheet_joins references an unknown sheet",
                &format!(
                    "step {step_no}: right sheet '{}' not found in workbook '{source_name}'. Available: {available:?}",
                    step.right
                ),
            )
        })?;

        let missing_left: Vec<&str> = step.on.iter().filter(|c| !left.columns.contains(c)).map(String::as_str).collect();
        let missing_right: Vec<&str> = step.on.iter().filter(|c| !right.columns.contains(c)).map(String::as_str).collect();
        if !missing_left.is_empty() || !missing_right.is_empty() {
            return Err(validation(
                "DATA_XLSX_INVALID",
                "sheet_joins join column(s) missing from sheet",
                &format!(
                    "step {step_no}: '{}' missing {missing_left:?}, '{}' missing {missing_right:?}",
                    step.left, step.right
                ),
            ));
        }

        let merged = merge_two(&left, &right, &step.on, &step.how);
        frames.insert(step.left.clone(), merged);
        if root.is_none() {
            root = Some(step.left.clone());
        }
    }

    let root = root.ok_or_else(|| {
        validation("CONFIG_INVALID_VALUE", "sheet_joins must contain at least one step", source_name)
    })?;
    Ok(frames.remove(&root).expect("root sheet always present in frames"))
}

// ── Restoring per-sheet output after anonymization ──────────────────────────
//
// To write anonymized results back out as one workbook per original sheet, we
// need to know, for every column in the merged table, which original sheet
// (and original column name) it came from. `TrackedSheet` shadows `merge_two`
// /`apply_sheet_joins` with a parallel `origins` vector (same length and
// index order as `sheet.columns`) that carries this provenance through the
// same join steps. Restoring is only supported for the explicit `sheet_joins`
// path — auto-join and same-schema vertical concat don't track it (see
// `merge_excel_sheets`).

/// Which original sheet + column a single merged-table column came from.
#[derive(Debug, Clone, PartialEq)]
pub struct ColumnOrigin {
    pub sheet: String,
    pub original_name: String,
}

#[derive(Debug, Clone)]
struct TrackedSheet {
    sheet: Sheet,
    /// Parallel to `sheet.columns` — origins[i] describes sheet.columns[i].
    origins: Vec<ColumnOrigin>,
}

fn seed_tracked(name: &str, sheet: Sheet) -> TrackedSheet {
    let origins = sheet
        .columns
        .iter()
        .map(|c| ColumnOrigin { sheet: name.to_string(), original_name: c.clone() })
        .collect();
    TrackedSheet { sheet, origins }
}

/// Same join as `merge_two`, but also produces the provenance vector for the
/// result. Relies on `merge_two`'s column ordering being exactly
/// `left.columns` (unchanged) followed by `right`'s non-key columns in order
/// (or, for `how == "cross"`, all of `right.columns`) — see `merge_two`.
fn merge_two_tracked(left: &TrackedSheet, right: &TrackedSheet, on: &[String], how: &str) -> TrackedSheet {
    let merged = merge_two(&left.sheet, &right.sheet, on, how);

    let mut origins = left.origins.clone();
    if how == "cross" {
        origins.extend(right.origins.iter().cloned());
    } else {
        let right_on_idx: HashSet<usize> = on.iter().filter_map(|c| column_index(&right.sheet, c)).collect();
        origins.extend(
            right
                .origins
                .iter()
                .enumerate()
                .filter(|(i, _)| !right_on_idx.contains(i))
                .map(|(_, o)| o.clone()),
        );
    }

    TrackedSheet { sheet: merged, origins }
}

/// Provenance-tracking twin of `apply_sheet_joins` — identical join logic and
/// error handling, but threads `TrackedSheet` instead of `Sheet` so the caller
/// can build a `SheetRestorePlan` from the result.
fn apply_sheet_joins_tracked(
    sheets: &[(String, Sheet)],
    joins: &[SheetJoinSpec],
    source_name: &str,
) -> Result<TrackedSheet, PipelineError> {
    let mut frames: HashMap<String, TrackedSheet> = sheets
        .iter()
        .cloned()
        .map(|(name, sheet)| {
            let tracked = seed_tracked(&name, sheet);
            (name, tracked)
        })
        .collect();
    let available: Vec<&str> = sheets.iter().map(|(n, _)| n.as_str()).collect();
    let mut root: Option<String> = None;

    for (idx, step) in joins.iter().enumerate() {
        let step_no = idx + 1;
        let left = frames.get(&step.left).cloned().ok_or_else(|| {
            validation(
                "DATA_XLSX_INVALID",
                "sheet_joins references an unknown sheet",
                &format!(
                    "step {step_no}: left sheet '{}' not found in workbook '{source_name}'. Available: {available:?}",
                    step.left
                ),
            )
        })?;
        let right = frames.get(&step.right).cloned().ok_or_else(|| {
            validation(
                "DATA_XLSX_INVALID",
                "sheet_joins references an unknown sheet",
                &format!(
                    "step {step_no}: right sheet '{}' not found in workbook '{source_name}'. Available: {available:?}",
                    step.right
                ),
            )
        })?;

        let missing_left: Vec<&str> = step.on.iter().filter(|c| !left.sheet.columns.contains(c)).map(String::as_str).collect();
        let missing_right: Vec<&str> = step.on.iter().filter(|c| !right.sheet.columns.contains(c)).map(String::as_str).collect();
        if !missing_left.is_empty() || !missing_right.is_empty() {
            return Err(validation(
                "DATA_XLSX_INVALID",
                "sheet_joins join column(s) missing from sheet",
                &format!(
                    "step {step_no}: '{}' missing {missing_left:?}, '{}' missing {missing_right:?}",
                    step.left, step.right
                ),
            ));
        }

        let merged = merge_two_tracked(&left, &right, &step.on, &step.how);
        frames.insert(step.left.clone(), merged);
        if root.is_none() {
            root = Some(step.left.clone());
        }
    }

    let root = root.ok_or_else(|| {
        validation("CONFIG_INVALID_VALUE", "sheet_joins must contain at least one step", source_name)
    })?;
    Ok(frames.remove(&root).expect("root sheet always present in frames"))
}

/// One original sheet's reconstruction recipe: ordered
/// `(merged_table_column_name, original_column_name)` pairs.
#[derive(Debug, Clone, PartialEq)]
pub struct SheetColumnPlan {
    pub sheet_name: String,
    pub columns: Vec<(String, String)>,
}

/// Recipe for splitting the final anonymized table back into one sheet per
/// original input sheet.
#[derive(Debug, Clone, PartialEq)]
pub struct SheetRestorePlan {
    pub sheets: Vec<SheetColumnPlan>,
}

/// Builds a `SheetRestorePlan` from the original (pre-join) sheets and the
/// final merged table's provenance. Iterates each original sheet's own column
/// order (not the merged table's) so restored sheets look like the input.
///
/// A join-key column's provenance is dropped by `merge_two_tracked` for the
/// `right` side (it's a duplicate of `left`'s copy), but it always survives
/// unrenamed in the merged table under its original name — so any original
/// column whose name matches a merged-table column name exactly, even without
/// a direct origin entry, is treated as a passthrough shared key.
fn build_restore_plan(
    original_sheets: &[(String, Sheet)],
    final_columns: &[String],
    final_origins: &[ColumnOrigin],
) -> SheetRestorePlan {
    let mut origin_lookup: HashMap<(String, String), String> = HashMap::new();
    for (i, o) in final_origins.iter().enumerate() {
        origin_lookup.insert((o.sheet.clone(), o.original_name.clone()), final_columns[i].clone());
    }
    let final_name_set: HashSet<&str> = final_columns.iter().map(String::as_str).collect();

    let mut sheets = Vec::new();
    for (sheet_name, sheet) in original_sheets {
        let mut columns = Vec::new();
        for col in &sheet.columns {
            let final_name = origin_lookup
                .get(&(sheet_name.clone(), col.clone()))
                .cloned()
                .or_else(|| final_name_set.contains(col.as_str()).then(|| col.clone()));
            if let Some(final_name) = final_name {
                columns.push((final_name, col.clone()));
            }
        }
        if !columns.is_empty() {
            sheets.push(SheetColumnPlan { sheet_name: sheet_name.clone(), columns });
        }
    }
    SheetRestorePlan { sheets }
}

/// Fallback merge when no `sheet_joins` config is provided: merges sheets
/// sequentially on auto-detected shared columns, falling back to a horizontal
/// concat by row position when two adjacent sheets share no columns at all.
/// Mirrors Python's `_auto_join_sheets`.
pub fn auto_join_sheets(sheets: &[(String, Sheet)]) -> Sheet {
    let mut iter = sheets.iter();
    let (_, first) = iter.next().expect("auto_join_sheets requires at least one sheet");
    let mut acc = first.clone();
    for (_, right) in iter {
        let common: Vec<String> = acc.columns.iter().filter(|c| right.columns.contains(c)).cloned().collect();
        acc = if common.is_empty() { horizontal_concat(&acc, right) } else { merge_two(&acc, right, &common, "left") };
    }
    acc
}

fn horizontal_concat(left: &Sheet, right: &Sheet) -> Sheet {
    let n = left.rows.len().max(right.rows.len());
    let mut columns = left.columns.clone();
    columns.extend(right.columns.iter().cloned());
    let mut rows = Vec::with_capacity(n);
    for i in 0..n {
        let mut row: Vec<String> = left.rows.get(i).cloned().unwrap_or_else(|| vec![String::new(); left.columns.len()]);
        row.extend(right.rows.get(i).cloned().unwrap_or_else(|| vec![String::new(); right.columns.len()]));
        rows.push(row);
    }
    Sheet { columns, rows }
}

/// True when every sheet has the same set of column names (order-independent).
fn same_schema(sheets: &[(String, Sheet)]) -> bool {
    let mut sets = sheets.iter().map(|(_, s)| {
        let mut v: Vec<&str> = s.columns.iter().map(String::as_str).collect();
        v.sort_unstable();
        v
    });
    let first = match sets.next() {
        Some(s) => s,
        None => return true,
    };
    sets.all(|s| s == first)
}

/// Stacks same-schema sheets vertically (row-union), realigning column order
/// per sheet in case it differs while the column *set* matches.
fn vertical_concat(sheets: &[(String, Sheet)]) -> Sheet {
    let columns = sheets[0].1.columns.clone();
    let mut rows = Vec::new();
    for (_, sheet) in sheets {
        if sheet.columns == columns {
            rows.extend(sheet.rows.iter().cloned());
        } else {
            let idx_map: Vec<usize> = columns
                .iter()
                .map(|c| sheet.columns.iter().position(|x| x == c).expect("same_schema guarantees membership"))
                .collect();
            for r in &sheet.rows {
                rows.push(idx_map.iter().map(|&i| r[i].clone()).collect());
            }
        }
    }
    Sheet { columns, rows }
}

/// Top-level Excel-sheet merge dispatcher — mirrors the branch structure of
/// Python's `split_csv_by_ram` Excel-handling block:
/// single sheet → use as-is; `sheet_joins` present → config-driven join;
/// else same-schema → vertical concat; else → auto-detected joins.
///
/// Also returns a `SheetRestorePlan` when one can be established — currently
/// only for the single-sheet and explicit-`sheet_joins` cases. Auto-detected
/// joins and same-schema vertical concat return `None`: the former isn't
/// tracked (would need the same provenance threading as `sheet_joins`, not
/// yet done since neither has been requested), and the latter has no
/// meaningful per-column restore (every sheet already shares one schema).
pub fn merge_excel_sheets(
    sheets: Vec<(String, Sheet)>,
    sheet_joins: &[SheetJoinSpec],
    source_name: &str,
) -> Result<(Sheet, Option<SheetRestorePlan>), PipelineError> {
    if sheets.len() == 1 {
        let (name, sheet) = sheets.into_iter().next().expect("len == 1");
        let plan = SheetRestorePlan {
            sheets: vec![SheetColumnPlan {
                sheet_name: name,
                columns: sheet.columns.iter().map(|c| (c.clone(), c.clone())).collect(),
            }],
        };
        return Ok((sheet, Some(plan)));
    }
    if !sheet_joins.is_empty() {
        let tracked = apply_sheet_joins_tracked(&sheets, sheet_joins, source_name)?;
        let plan = build_restore_plan(&sheets, &tracked.sheet.columns, &tracked.origins);
        return Ok((tracked.sheet, Some(plan)));
    }
    if same_schema(&sheets) {
        return Ok((vertical_concat(&sheets), None));
    }
    Ok((auto_join_sheets(&sheets), None))
}

// ── Top-level input resolution ───────────────────────────────────────────────

/// Detects the single input data file in `data_dir` (.csv / .json / .xlsx / .xls)
/// and returns the path to a single CSV ready for chunking, plus a
/// `SheetRestorePlan` when the input was multi-sheet Excel and a plan could be
/// established (see `merge_excel_sheets`) — `None` for CSV/JSON input, single-
/// sheet Excel with nothing to restore beyond itself, or a merge strategy that
/// doesn't track provenance.
///
/// `data_dir` is treated as read-only (it's mounted `:ro` in docker-compose) and
/// is never written to. A plain `.csv` input is returned as-is, pointing back
/// into `data_dir`. JSON or Excel input is normalised into
/// `chunks_dir/_converted.csv` instead — `chunks_dir` is the pipeline's own
/// read-write scratch space — and that path is returned.
///
/// Also reports which format the input actually was, so the run can echo that
/// format back on output.
///
/// The reader is chosen from the file's **contents**, not its name — see
/// [`sniff_format`]. A `.json` file misnamed `.csv` is otherwise valid UTF-8, so
/// it would sail past the CSV reader's only guard and be parsed as delimited
/// text: garbage columns, no error, a plausible-looking result. Routing on
/// content makes that impossible; a name/content disagreement is reported in
/// [`ResolvedInput::format_mismatch`] for the caller to log.
pub fn resolve_input_csv(
    data_dir: &Path,
    chunks_dir: &Path,
    sheet_joins: &[SheetJoinSpec],
) -> Result<ResolvedInput, PipelineError> {
    if !data_dir.is_dir() {
        return Err(validation("DATA_DIR_MISSING", "Data directory not found", &data_dir.display().to_string()));
    }

    let mut csvs = Vec::new();
    let mut jsons = Vec::new();
    let mut excels = Vec::new();
    for entry in fs::read_dir(data_dir)? {
        let path = entry?.path();
        if !path.is_file() {
            continue;
        }
        match path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase().as_str() {
            "csv" => csvs.push(path),
            "json" => jsons.push(path),
            "xlsx" | "xls" => excels.push(path),
            _ => {}
        }
    }

    let total = csvs.len() + jsons.len() + excels.len();
    if total == 0 {
        return Err(validation(
            "DATA_NO_CSV",
            "No CSV, JSON, or Excel file found in data/",
            &data_dir.display().to_string(),
        ));
    }
    if total > 1 {
        let found: Vec<String> = csvs
            .iter()
            .chain(jsons.iter())
            .chain(excels.iter())
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .collect();
        return Err(validation(
            "DATA_AMBIGUOUS_INPUT",
            "More than one input data file found in data/",
            &format!("Expected exactly one .csv/.json/.xlsx file. Found: {found:?}"),
        ));
    }

    // Exactly one candidate at this point; its extension is only a hint.
    let input_path = csvs.into_iter().chain(jsons).chain(excels).next().expect("total == 1 checked above");
    let declared = format_from_extension(&input_path).unwrap_or(InputFormat::Csv);
    let sniffed = sniff_format(&input_path)?;
    let format = sniffed.unwrap_or(declared);

    let format_mismatch = sniffed.filter(|&s| s != declared).map(|s| {
        format!(
            "'{}' is named like {} but its contents are {} — reading it as {}. \
             The extension is a hint only; fix the producer so the name matches.",
            input_path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
            declared.extension(),
            s.extension(),
            s.extension(),
        )
    });

    let (csv_path, restore_plan) = match format {
        InputFormat::Json => {
            fs::create_dir_all(chunks_dir)?;
            let converted_path = chunks_dir.join("_converted.csv");
            let sheet = read_json_sheet(&input_path)?;
            write_sheet_csv(&sheet, &converted_path)?;
            (converted_path, None)
        }
        InputFormat::Excel => {
            fs::create_dir_all(chunks_dir)?;
            let converted_path = chunks_dir.join("_converted.csv");
            let sheets = read_xlsx_sheets(&input_path)?;
            let source_name = input_path.file_name().and_then(|n| n.to_str()).unwrap_or("input").to_string();
            let (merged, plan) = merge_excel_sheets(sheets, sheet_joins, &source_name)?;
            write_sheet_csv(&merged, &converted_path)?;
            (converted_path, plan)
        }
        // Sole CSV input: used in place, still under (read-only) data_dir.
        InputFormat::Csv => (input_path, None),
    };

    Ok(ResolvedInput { csv_path, restore_plan, format, format_mismatch })
}

/// What [`resolve_input_csv`] worked out about the run's input.
#[derive(Debug)]
pub struct ResolvedInput {
    /// A single CSV ready for chunking — the input itself when it was already
    /// CSV, otherwise the normalised `chunks_dir/_converted.csv`.
    pub csv_path: PathBuf,
    /// Per-sheet provenance, when the input was multi-sheet Excel merged via
    /// explicit `sheet_joins`. `None` otherwise.
    pub restore_plan: Option<SheetRestorePlan>,
    /// The format actually detected, which the run echoes back on output.
    pub format: InputFormat,
    /// Set when the file's extension disagreed with its contents; the caller
    /// logs it. Content wins, so this is a warning, not an error.
    pub format_mismatch: Option<String>,
}

/// Maps a path's extension to a format. `None` for anything unrecognised.
fn format_from_extension(path: &Path) -> Option<InputFormat> {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase().as_str() {
        "csv" => Some(InputFormat::Csv),
        "json" => Some(InputFormat::Json),
        "xlsx" | "xls" => Some(InputFormat::Excel),
        _ => None,
    }
}

/// Identifies a file's format from its leading bytes, ignoring its name.
///
/// Recognises the two formats that are unambiguous at the head of the stream:
/// `.xlsx`/`.xls` (a zip container, `PK\x03\x04`) and JSON (first non-whitespace
/// byte is `[` or `{`, which no CSV header row can start with unquoted).
/// Returns `None` for anything else — including CSV, which has no signature and
/// is what the caller falls back to.
pub fn sniff_format(path: &Path) -> Result<Option<InputFormat>, PipelineError> {
    use std::io::Read;

    let mut file = fs::File::open(path).map_err(|e| io_err("open input file", &path.display().to_string(), e))?;
    let mut head = [0u8; 64];
    let read = file
        .read(&mut head)
        .map_err(|e| io_err("read input file header", &path.display().to_string(), e))?;
    let head = &head[..read];

    if head.starts_with(b"PK\x03\x04") {
        return Ok(Some(InputFormat::Excel));
    }
    // Legacy .xls (OLE2 compound file) — recognised so a misnamed one reaches
    // calamine and fails with a real message rather than as broken CSV.
    if head.starts_with(&[0xD0, 0xCF, 0x11, 0xE0]) {
        return Ok(Some(InputFormat::Excel));
    }
    match head.iter().find(|b| !b.is_ascii_whitespace()) {
        Some(b'[') | Some(b'{') => Ok(Some(InputFormat::Json)),
        _ => Ok(None),
    }
}

// ── Echoing the input format back on output ─────────────────────────────────

/// Which of the supported input formats a run was actually given. Drives
/// `output_format: "match_input"`, where the anonymized result is written back
/// in the same format it arrived in rather than always as a flat CSV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputFormat {
    Csv,
    Json,
    Excel,
}

impl InputFormat {
    /// File extension this format is written back as.
    pub fn extension(self) -> &'static str {
        match self {
            InputFormat::Csv => "csv",
            InputFormat::Json => "json",
            InputFormat::Excel => "xlsx",
        }
    }
}

/// Rewrites the final anonymized CSV into `format`, next to it in the same
/// directory, and returns the new file's path.
///
/// Unlike [`write_restored_workbook`] this does not reconstruct the original
/// sheet layout — the anonymized table is written as-is, as a single worksheet
/// (Excel) or a flat array of objects (JSON). It only echoes the *container
/// format* back, so a caller that handed in `.xlsx` gets `.xlsx` out.
///
/// Returns `Ok(None)` for [`InputFormat::Csv`], where the CSV already is the
/// requested format and there is nothing to convert.
pub fn write_output_in_format(
    final_csv_path: &Path,
    format: InputFormat,
    output_path_stem: &str,
) -> Result<Option<PathBuf>, PipelineError> {
    if format == InputFormat::Csv {
        return Ok(None);
    }
    let out_path = final_csv_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("{output_path_stem}.{}", format.extension()));

    let (columns, rows) = read_csv_table(final_csv_path)?;
    match format {
        InputFormat::Json => write_json_table(&columns, &rows, &out_path)?,
        InputFormat::Excel => write_single_sheet_workbook(&columns, &rows, &out_path)?,
        InputFormat::Csv => unreachable!("returned above"),
    }
    Ok(Some(out_path))
}

/// Reads a CSV written by this pipeline back into (header, rows).
fn read_csv_table(path: &Path) -> Result<(Vec<String>, Vec<Vec<String>>), PipelineError> {
    let content = fs::read_to_string(path)
        .map_err(|e| io_err("read final generalized CSV", &path.display().to_string(), e))?;
    let mut lines = content.lines();
    let columns = match lines.next() {
        Some(h) => parse_csv_line(h),
        None => {
            return Err(validation(
                "IO_READ_FAILED",
                "Generalized output is empty — nothing to convert",
                &path.display().to_string(),
            ))
        }
    };
    let rows = lines.filter(|l| !l.is_empty()).map(parse_csv_line).collect();
    Ok((columns, rows))
}

/// Writes the table as a JSON array of objects, mirroring the shape
/// `read_json_sheet` accepts on input so a run can round-trip.
///
/// Written key-by-key rather than through `serde_json::Map`, which is a
/// `BTreeMap` and would alphabetise the fields — this keeps each record's keys
/// in the table's own column order. Values are escaped by `serde_json`.
fn write_json_table(columns: &[String], rows: &[Vec<String>], path: &Path) -> Result<(), PipelineError> {
    let file = fs::File::create(path).map_err(|e| io_err("create JSON output", &path.display().to_string(), e))?;
    let mut w = BufWriter::new(file);

    let write_all = |w: &mut BufWriter<fs::File>, b: &[u8]| -> Result<(), PipelineError> {
        w.write_all(b).map_err(|e| io_err("write JSON output", &path.display().to_string(), e))
    };

    write_all(&mut w, b"[\n")?;
    for (r, row) in rows.iter().enumerate() {
        if r > 0 {
            write_all(&mut w, b",\n")?;
        }
        write_all(&mut w, b"  {")?;
        for (c, column) in columns.iter().enumerate() {
            if c > 0 {
                write_all(&mut w, b", ")?;
            }
            let key = serde_json::to_string(column)?;
            let value = serde_json::to_string(row.get(c).map(String::as_str).unwrap_or(""))?;
            write_all(&mut w, format!("{key}: {value}").as_bytes())?;
        }
        write_all(&mut w, b"}")?;
    }
    write_all(&mut w, b"\n]\n")?;

    w.flush().map_err(|e| io_err("flush JSON output", &path.display().to_string(), e))?;
    Ok(())
}

/// Writes the table as a one-worksheet `.xlsx`. Sheet structure from a
/// multi-sheet input is deliberately not reconstructed here — that is what
/// `restore_sheets` is for.
fn write_single_sheet_workbook(
    columns: &[String],
    rows: &[Vec<String>],
    path: &Path,
) -> Result<(), PipelineError> {
    let mut workbook = Workbook::new();
    let worksheet = workbook.add_worksheet();

    for (c, name) in columns.iter().enumerate() {
        worksheet
            .write_string(0, c as u16, name)
            .map_err(|e| validation("IO_WRITE_FAILED", "Failed writing xlsx header", &e.to_string()))?;
    }
    for (r, row) in rows.iter().enumerate() {
        for (c, value) in row.iter().enumerate() {
            worksheet
                .write_string(r as u32 + 1, c as u16, value)
                .map_err(|e| validation("IO_WRITE_FAILED", "Failed writing xlsx row", &e.to_string()))?;
        }
    }

    workbook.save(path).map_err(|e| {
        validation("IO_WRITE_FAILED", "Failed to save xlsx output", &format!("{}: {e}", path.display()))
    })?;
    Ok(())
}

fn write_sheet_csv(sheet: &Sheet, path: &Path) -> Result<(), PipelineError> {
    let file = fs::File::create(path).map_err(|e| io_err("create converted CSV", &path.display().to_string(), e))?;
    let mut writer = BufWriter::new(file);
    let write_row = |w: &mut BufWriter<fs::File>, fields: &[String]| -> std::io::Result<()> {
        w.write_all(csv_row_to_line(fields).as_bytes())?;
        w.write_all(b"\n")
    };
    write_row(&mut writer, &sheet.columns).map_err(|e| io_err("write converted CSV header", &path.display().to_string(), e))?;
    for row in &sheet.rows {
        write_row(&mut writer, row).map_err(|e| io_err("write converted CSV row", &path.display().to_string(), e))?;
    }
    writer.flush().map_err(|e| io_err("flush converted CSV", &path.display().to_string(), e))?;
    Ok(())
}

// ── Writing anonymized output back as per-sheet workbook ────────────────────

/// Parses one RFC-4180 CSV line, inverting `csv_row_to_line`/`csv_quote_field`
/// (handles quoted fields containing embedded commas or quotes). Operates
/// line-by-line, so a quoted field spanning multiple lines would not round-trip
/// — not a concern here since SKALD's own writer only ever quotes to escape
/// commas/quotes, never raw newlines.
fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut chars = line.chars().peekable();
    let mut in_quotes = false;
    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
        } else if c == '"' {
            in_quotes = true;
        } else if c == ',' {
            fields.push(std::mem::take(&mut field));
        } else {
            field.push(c);
        }
    }
    fields.push(field);
    fields
}

/// Reads the final anonymized CSV and, per `plan`, splits it back into one
/// worksheet per original input sheet — each restored to its original column
/// names and order, with the shared join key(s) carried into every sheet that
/// needs them. Rows are de-duplicated per sheet (by that sheet's own projected
/// column values) since a join can fan a single original row for e.g. a
/// one-sheet-to-many-rows relationship out across multiple merged rows.
pub fn write_restored_workbook(
    final_csv_path: &Path,
    plan: &SheetRestorePlan,
    xlsx_path: &Path,
) -> Result<(), PipelineError> {
    let content = fs::read_to_string(final_csv_path)
        .map_err(|e| io_err("read final generalized CSV", &final_csv_path.display().to_string(), e))?;
    let mut lines = content.lines();
    let header = match lines.next() {
        Some(h) => parse_csv_line(h),
        None => {
            return Err(validation(
                "IO_READ_FAILED",
                "Generalized output is empty — nothing to restore",
                &final_csv_path.display().to_string(),
            ))
        }
    };
    let col_idx: HashMap<&str, usize> = header.iter().enumerate().map(|(i, h)| (h.as_str(), i)).collect();
    let rows: Vec<Vec<String>> = lines.filter(|l| !l.is_empty()).map(parse_csv_line).collect();

    let mut workbook = Workbook::new();
    for sheet_plan in &plan.sheets {
        let worksheet = workbook.add_worksheet();
        worksheet.set_name(&sheet_plan.sheet_name).map_err(|e| {
            validation("IO_WRITE_FAILED", "Invalid sheet name for xlsx output", &format!("'{}': {e}", sheet_plan.sheet_name))
        })?;

        for (c, (_, original_name)) in sheet_plan.columns.iter().enumerate() {
            worksheet
                .write_string(0, c as u16, original_name)
                .map_err(|e| validation("IO_WRITE_FAILED", "Failed writing xlsx header", &e.to_string()))?;
        }

        let col_positions: Vec<Option<usize>> =
            sheet_plan.columns.iter().map(|(final_name, _)| col_idx.get(final_name.as_str()).copied()).collect();

        let mut seen: HashSet<Vec<String>> = HashSet::new();
        let mut out_row = 1u32;
        for row in &rows {
            let projected: Vec<String> =
                col_positions.iter().map(|pos| pos.and_then(|i| row.get(i)).cloned().unwrap_or_default()).collect();
            if seen.insert(projected.clone()) {
                for (c, value) in projected.iter().enumerate() {
                    worksheet
                        .write_string(out_row, c as u16, value)
                        .map_err(|e| validation("IO_WRITE_FAILED", "Failed writing xlsx row", &e.to_string()))?;
                }
                out_row += 1;
            }
        }
    }

    workbook.save(xlsx_path).map_err(|e| {
        validation("IO_WRITE_FAILED", "Failed to save restored xlsx workbook", &format!("{}: {e}", xlsx_path.display()))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sheet(columns: &[&str], rows: &[&[&str]]) -> Sheet {
        Sheet {
            columns: columns.iter().map(|s| s.to_string()).collect(),
            rows: rows.iter().map(|r| r.iter().map(|s| s.to_string()).collect()).collect(),
        }
    }

    #[test]
    fn config_driven_star_schema_join() {
        let master = sheet(&["school_id", "school_type"], &[&["1", "P"], &["2", "S"]]);
        let amenities = sheet(&["school_id", "toilets"], &[&["1", "4"], &["2", "6"]]);
        let snapshot = sheet(&["school_id", "enrolment"], &[&["1", "100"], &["2", "200"]]);
        let sheets = vec![
            ("School master".to_string(), master),
            ("School amenities".to_string(), amenities),
            ("School snapshot".to_string(), snapshot),
        ];
        let joins = vec![
            SheetJoinSpec { left: "School master".into(), right: "School amenities".into(), on: vec!["school_id".into()], how: "left".into() },
            SheetJoinSpec { left: "School master".into(), right: "School snapshot".into(), on: vec!["school_id".into()], how: "left".into() },
        ];
        let out = apply_sheet_joins(&sheets, &joins, "edu.xlsx").unwrap();
        assert_eq!(out.columns, vec!["school_id", "school_type", "toilets", "enrolment"]);
        assert_eq!(out.rows.len(), 2);
        assert_eq!(out.rows[0], vec!["1", "P", "4", "100"]);
    }

    #[test]
    fn auto_detect_fallback_merges_on_shared_columns() {
        let master = sheet(&["school_id", "school_type"], &[&["1", "P"], &["2", "S"]]);
        let amenities = sheet(&["school_id", "toilets"], &[&["1", "4"], &["2", "6"]]);
        let out = auto_join_sheets(&[("m".to_string(), master), ("a".to_string(), amenities)]);
        assert_eq!(out.columns, vec!["school_id", "school_type", "toilets"]);
        assert_eq!(out.rows.len(), 2);
    }

    #[test]
    fn auto_detect_horizontal_concat_when_no_shared_columns() {
        let left = sheet(&["a"], &[&["1"], &["2"]]);
        let right = sheet(&["b"], &[&["x"], &["y"]]);
        let out = auto_join_sheets(&[("l".to_string(), left), ("r".to_string(), right)]);
        assert_eq!(out.columns, vec!["a", "b"]);
        assert_eq!(out.rows, vec![vec!["1", "x"], vec!["2", "y"]]);
    }

    #[test]
    fn same_schema_sheets_concat_vertically() {
        let a = sheet(&["id", "val"], &[&["1", "x"]]);
        let b = sheet(&["id", "val"], &[&["2", "y"]]);
        let sheets = vec![("a".to_string(), a), ("b".to_string(), b)];
        assert!(same_schema(&sheets));
        let out = vertical_concat(&sheets);
        assert_eq!(out.rows, vec![vec!["1", "x"], vec!["2", "y"]]);
    }

    #[test]
    fn merge_two_left_join_keeps_unmatched_left_rows() {
        let left = sheet(&["id", "a"], &[&["1", "x"], &["2", "y"]]);
        let right = sheet(&["id", "b"], &[&["1", "p"]]);
        let out = merge_two(&left, &right, &["id".to_string()], "left");
        assert_eq!(out.rows, vec![vec!["1", "x", "p"], vec!["2", "y", ""]]);
    }

    #[test]
    fn merge_two_inner_join_drops_unmatched_rows() {
        let left = sheet(&["id", "a"], &[&["1", "x"], &["2", "y"]]);
        let right = sheet(&["id", "b"], &[&["1", "p"]]);
        let out = merge_two(&left, &right, &["id".to_string()], "inner");
        assert_eq!(out.rows, vec![vec!["1", "x", "p"]]);
    }

    #[test]
    fn merge_two_outer_join_keeps_both_sides_unmatched() {
        let left = sheet(&["id", "a"], &[&["1", "x"], &["2", "y"]]);
        let right = sheet(&["id", "b"], &[&["1", "p"], &["3", "q"]]);
        let out = merge_two(&left, &right, &["id".to_string()], "outer");
        assert_eq!(out.rows.len(), 3);
        assert!(out.rows.contains(&vec!["1".to_string(), "x".to_string(), "p".to_string()]));
        assert!(out.rows.contains(&vec!["2".to_string(), "y".to_string(), "".to_string()]));
        assert!(out.rows.contains(&vec!["3".to_string(), "".to_string(), "q".to_string()]));
    }

    #[test]
    fn merge_two_duplicate_keys_produce_cartesian_rows() {
        let left = sheet(&["id", "a"], &[&["1", "x"], &["1", "y"]]);
        let right = sheet(&["id", "b"], &[&["1", "p"], &["1", "q"]]);
        let out = merge_two(&left, &right, &["id".to_string()], "left");
        assert_eq!(out.rows.len(), 4);
    }

    #[test]
    fn merge_two_suffixes_colliding_nonkey_columns() {
        let left = sheet(&["id", "name"], &[&["1", "left-name"]]);
        let right = sheet(&["id", "name"], &[&["1", "right-name"]]);
        let out = merge_two(&left, &right, &["id".to_string()], "left");
        assert_eq!(out.columns, vec!["id", "name_x", "name_y"]);
        assert_eq!(out.rows, vec![vec!["1", "left-name", "right-name"]]);
    }

    #[test]
    fn apply_sheet_joins_rejects_unknown_sheet() {
        let sheets = vec![("A".to_string(), sheet(&["id"], &[&["1"]]))];
        let joins = vec![SheetJoinSpec { left: "A".into(), right: "Nope".into(), on: vec!["id".into()], how: "left".into() }];
        let err = apply_sheet_joins(&sheets, &joins, "wb.xlsx").unwrap_err();
        assert!(matches!(err, PipelineError::Validation { code: "DATA_XLSX_INVALID", .. }));
    }

    #[test]
    fn apply_sheet_joins_rejects_missing_join_column() {
        let sheets = vec![
            ("A".to_string(), sheet(&["id"], &[&["1"]])),
            ("B".to_string(), sheet(&["other"], &[&["1"]])),
        ];
        let joins = vec![SheetJoinSpec { left: "A".into(), right: "B".into(), on: vec!["id".into()], how: "left".into() }];
        let err = apply_sheet_joins(&sheets, &joins, "wb.xlsx").unwrap_err();
        assert!(matches!(err, PipelineError::Validation { code: "DATA_XLSX_INVALID", .. }));
    }

    #[test]
    fn parse_sheet_joins_defaults_how_to_left_and_coerces_string_on() {
        let cfg = serde_json::json!({
            "sheet_joins": [
                {"left": "A", "right": "B", "on": "id"}
            ]
        });
        let specs = parse_sheet_joins(&cfg).unwrap();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].on, vec!["id".to_string()]);
        assert_eq!(specs[0].how, "left");
    }

    #[test]
    fn parse_sheet_joins_rejects_invalid_how() {
        let cfg = serde_json::json!({
            "sheet_joins": [
                {"left": "A", "right": "B", "on": ["id"], "how": "sideways"}
            ]
        });
        assert!(parse_sheet_joins(&cfg).is_err());
    }

    #[test]
    fn parse_sheet_joins_absent_returns_empty() {
        let cfg = serde_json::json!({});
        assert_eq!(parse_sheet_joins(&cfg).unwrap(), Vec::new());
    }

    #[test]
    fn read_json_sheet_unions_keys_and_fills_missing() {
        let dir = std::env::temp_dir().join(format!("skald_json_test_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("in.json");
        fs::write(&path, r#"[{"a": 1, "b": "x"}, {"a": 2, "c": true}]"#).unwrap();
        let sheet = read_json_sheet(&path).unwrap();
        assert_eq!(sheet.columns, vec!["a", "b", "c"]);
        assert_eq!(sheet.rows, vec![vec!["1", "x", ""], vec!["2", "", "True"]]);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_json_sheet_rejects_non_array_top_level() {
        let dir = std::env::temp_dir().join(format!("skald_json_test2_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("in.json");
        fs::write(&path, r#"{"a": 1}"#).unwrap();
        let err = read_json_sheet(&path).unwrap_err();
        assert!(matches!(err, PipelineError::Validation { code: "DATA_JSON_INVALID", .. }));
        fs::remove_dir_all(&dir).ok();
    }

    // ── Sheet restore plan ───────────────────────────────────────────────────

    #[test]
    fn restore_plan_two_sheet_join_recovers_original_columns() {
        let patients = sheet(&["patient_id", "Age", "Blood Group"], &[&["1", "23", "A+"]]);
        let visits = sheet(&["patient_id", "diagnosis_code"], &[&["1", "D1"]]);
        let sheets = vec![("Patients".to_string(), patients), ("Visits".to_string(), visits)];
        let joins =
            vec![SheetJoinSpec { left: "Patients".into(), right: "Visits".into(), on: vec!["patient_id".into()], how: "left".into() }];

        let (merged, plan) = merge_excel_sheets(sheets, &joins, "patients.xlsx").unwrap();
        assert_eq!(merged.columns, vec!["patient_id", "Age", "Blood Group", "diagnosis_code"]);

        let plan = plan.expect("sheet_joins path always yields a plan");
        let patients_plan = plan.sheets.iter().find(|s| s.sheet_name == "Patients").unwrap();
        assert_eq!(
            patients_plan.columns,
            vec![
                ("patient_id".to_string(), "patient_id".to_string()),
                ("Age".to_string(), "Age".to_string()),
                ("Blood Group".to_string(), "Blood Group".to_string()),
            ]
        );
        let visits_plan = plan.sheets.iter().find(|s| s.sheet_name == "Visits").unwrap();
        assert_eq!(
            visits_plan.columns,
            vec![("patient_id".to_string(), "patient_id".to_string()), ("diagnosis_code".to_string(), "diagnosis_code".to_string())]
        );
    }

    #[test]
    fn restore_plan_star_schema_tracks_all_three_sheets() {
        let master = sheet(&["school_id", "school_type"], &[&["1", "P"]]);
        let amenities = sheet(&["school_id", "toilets"], &[&["1", "4"]]);
        let snapshot = sheet(&["school_id", "enrolment"], &[&["1", "100"]]);
        let sheets = vec![
            ("School master".to_string(), master),
            ("School amenities".to_string(), amenities),
            ("School snapshot".to_string(), snapshot),
        ];
        let joins = vec![
            SheetJoinSpec { left: "School master".into(), right: "School amenities".into(), on: vec!["school_id".into()], how: "left".into() },
            SheetJoinSpec { left: "School master".into(), right: "School snapshot".into(), on: vec!["school_id".into()], how: "left".into() },
        ];

        let (merged, plan) = merge_excel_sheets(sheets, &joins, "schools.xlsx").unwrap();
        assert_eq!(merged.columns, vec!["school_id", "school_type", "toilets", "enrolment"]);

        let plan = plan.unwrap();
        assert_eq!(plan.sheets.len(), 3);
        let amenities_plan = plan.sheets.iter().find(|s| s.sheet_name == "School amenities").unwrap();
        assert_eq!(
            amenities_plan.columns,
            vec![("school_id".to_string(), "school_id".to_string()), ("toilets".to_string(), "toilets".to_string())]
        );
        let snapshot_plan = plan.sheets.iter().find(|s| s.sheet_name == "School snapshot").unwrap();
        assert_eq!(
            snapshot_plan.columns,
            vec![("school_id".to_string(), "school_id".to_string()), ("enrolment".to_string(), "enrolment".to_string())]
        );
    }

    #[test]
    fn restore_plan_tracks_renamed_colliding_columns() {
        // Both sheets have a non-key "name" column — merge_two suffixes them _x/_y.
        // The restore plan must map each sheet back to ITS OWN "name", not the other's.
        let left = sheet(&["id", "name"], &[&["1", "left-name"]]);
        let right = sheet(&["id", "name"], &[&["1", "right-name"]]);
        let sheets = vec![("Left".to_string(), left), ("Right".to_string(), right)];
        let joins = vec![SheetJoinSpec { left: "Left".into(), right: "Right".into(), on: vec!["id".into()], how: "left".into() }];

        let (merged, plan) = merge_excel_sheets(sheets, &joins, "wb.xlsx").unwrap();
        assert_eq!(merged.columns, vec!["id", "name_x", "name_y"]);

        let plan = plan.unwrap();
        let left_plan = plan.sheets.iter().find(|s| s.sheet_name == "Left").unwrap();
        assert_eq!(left_plan.columns, vec![("id".to_string(), "id".to_string()), ("name_x".to_string(), "name".to_string())]);
        let right_plan = plan.sheets.iter().find(|s| s.sheet_name == "Right").unwrap();
        assert_eq!(right_plan.columns, vec![("id".to_string(), "id".to_string()), ("name_y".to_string(), "name".to_string())]);
    }

    #[test]
    fn restore_plan_single_sheet_is_identity() {
        let only = sheet(&["a", "b"], &[&["1", "2"]]);
        let sheets = vec![("Only".to_string(), only)];
        let (merged, plan) = merge_excel_sheets(sheets, &[], "wb.xlsx").unwrap();
        assert_eq!(merged.columns, vec!["a", "b"]);
        let plan = plan.unwrap();
        assert_eq!(plan.sheets.len(), 1);
        assert_eq!(plan.sheets[0].columns, vec![("a".to_string(), "a".to_string()), ("b".to_string(), "b".to_string())]);
    }

    #[test]
    fn restore_plan_absent_for_auto_join_and_vertical_concat() {
        let master = sheet(&["id", "a"], &[&["1", "x"]]);
        let other = sheet(&["id", "b"], &[&["1", "y"]]);
        let sheets = vec![("M".to_string(), master), ("O".to_string(), other)];
        let (_, plan) = merge_excel_sheets(sheets, &[], "wb.xlsx").unwrap();
        assert!(plan.is_none(), "auto-join fallback should not produce a restore plan");

        let a = sheet(&["id", "val"], &[&["1", "x"]]);
        let b = sheet(&["id", "val"], &[&["2", "y"]]);
        let sheets = vec![("A".to_string(), a), ("B".to_string(), b)];
        let (_, plan) = merge_excel_sheets(sheets, &[], "wb.xlsx").unwrap();
        assert!(plan.is_none(), "same-schema vertical concat should not produce a restore plan");
    }

    #[test]
    fn parse_csv_line_roundtrips_quoted_commas_and_quotes() {
        let line = r#"1,"House 42, MG Road","She said ""hi""",plain"#;
        assert_eq!(parse_csv_line(line), vec!["1", "House 42, MG Road", "She said \"hi\"", "plain"]);
    }

    #[test]
    fn write_restored_workbook_splits_and_dedupes_rows() {
        let dir = std::env::temp_dir().join(format!("skald_restore_test_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let csv_path = dir.join("generalized.csv");
        // Patient 1 has two visits, so the joined+generalized table fans out to two
        // rows sharing identical Patients-side values (patient_id, Age, Blood Group)
        // but distinct Visits-side values (diagnosis_code).
        fs::write(&csv_path, "patient_id,Age,Blood Group,diagnosis_code\n1,[20-30),A,D1\n1,[20-30),A,D2\n").unwrap();

        let plan = SheetRestorePlan {
            sheets: vec![
                SheetColumnPlan {
                    sheet_name: "Patients".to_string(),
                    columns: vec![
                        ("patient_id".to_string(), "patient_id".to_string()),
                        ("Age".to_string(), "Age".to_string()),
                        ("Blood Group".to_string(), "Blood Group".to_string()),
                    ],
                },
                SheetColumnPlan {
                    sheet_name: "Visits".to_string(),
                    columns: vec![
                        ("patient_id".to_string(), "patient_id".to_string()),
                        ("diagnosis_code".to_string(), "diagnosis_code".to_string()),
                    ],
                },
            ],
        };
        let xlsx_path = dir.join("restored.xlsx");
        write_restored_workbook(&csv_path, &plan, &xlsx_path).unwrap();

        let sheets = read_xlsx_sheets(&xlsx_path).unwrap();
        let patients = &sheets.iter().find(|(n, _)| n == "Patients").unwrap().1;
        assert_eq!(patients.columns, vec!["patient_id", "Age", "Blood Group"]);
        assert_eq!(patients.rows, vec![vec!["1", "[20-30)", "A"]], "duplicate Patients-side row should collapse to one");

        let visits = &sheets.iter().find(|(n, _)| n == "Visits").unwrap().1;
        assert_eq!(visits.columns, vec!["patient_id", "diagnosis_code"]);
        assert_eq!(visits.rows, vec![vec!["1", "D1"], vec!["1", "D2"]], "distinct Visits-side rows should both survive");

        fs::remove_dir_all(&dir).ok();
    }
}
