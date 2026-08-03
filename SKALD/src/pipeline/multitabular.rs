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
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufWriter, Write};
use std::path::Path;

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

/// Reads a JSON array-of-objects file into a `Sheet`. Column order is the
/// union of keys in first-seen order across records (mirrors
/// `pandas.DataFrame(list_of_dicts)`); missing keys per-record fill as "".
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
pub fn merge_excel_sheets(
    sheets: Vec<(String, Sheet)>,
    sheet_joins: &[SheetJoinSpec],
    source_name: &str,
) -> Result<Sheet, PipelineError> {
    if sheets.len() == 1 {
        return Ok(sheets.into_iter().next().expect("len == 1").1);
    }
    if !sheet_joins.is_empty() {
        return apply_sheet_joins(&sheets, sheet_joins, source_name);
    }
    if same_schema(&sheets) {
        return Ok(vertical_concat(&sheets));
    }
    Ok(auto_join_sheets(&sheets))
}

// ── Top-level input resolution ───────────────────────────────────────────────

/// Detects the single input data file in `data_dir` (.csv / .json / .xlsx / .xls)
/// and returns the path to a single CSV ready for chunking.
///
/// `data_dir` is treated as read-only (it's mounted `:ro` in docker-compose) and
/// is never written to. A plain `.csv` input is returned as-is, pointing back
/// into `data_dir`. JSON or Excel input is normalised into
/// `chunks_dir/_converted.csv` instead — `chunks_dir` is the pipeline's own
/// read-write scratch space — and that path is returned.
pub fn resolve_input_csv(
    data_dir: &Path,
    chunks_dir: &Path,
    sheet_joins: &[SheetJoinSpec],
) -> Result<std::path::PathBuf, PipelineError> {
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

    if !jsons.is_empty() {
        fs::create_dir_all(chunks_dir)?;
        let converted_path = chunks_dir.join("_converted.csv");
        let sheet = read_json_sheet(&jsons[0])?;
        write_sheet_csv(&sheet, &converted_path)?;
        return Ok(converted_path);
    }
    if !excels.is_empty() {
        fs::create_dir_all(chunks_dir)?;
        let converted_path = chunks_dir.join("_converted.csv");
        let sheets = read_xlsx_sheets(&excels[0])?;
        let source_name = excels[0].file_name().and_then(|n| n.to_str()).unwrap_or("input").to_string();
        let merged = merge_excel_sheets(sheets, sheet_joins, &source_name)?;
        write_sheet_csv(&merged, &converted_path)?;
        return Ok(converted_path);
    }

    // Sole .csv input: return it as-is, still under (read-only) data_dir.
    Ok(csvs.remove(0))
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
}
