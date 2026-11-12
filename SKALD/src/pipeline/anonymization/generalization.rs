//! Generalization and output writing for the SKALD anonymization pipeline.
//!
//! Applies the generalization factors chosen by OLA-2 to every chunk CSV file
//! and produces anonymized output files.
//!
//! ## Two-pass approach
//! 1. **Pass 1** — generalize every row of every chunk and write it to a
//!    per-chunk temporary file, accumulating equivalence-class record counts
//!    (and, with l-diversity, distinct sensitive values) across the whole
//!    dataset.
//! 2. **Pass 2** — re-read the temp files in order and handle every record
//!    whose class has fewer than `k` members (or fewer than `l` distinct values
//!    of a sensitive attribute), writing straight into the final CSV.
//!
//! Counts must span every chunk before anything is suppressed: a class split
//! across chunks can be large enough overall yet small inside each chunk.
//!
//! ## What happens to a failing record
//! Its QI cells become `*`. All such records together form one more class,
//! "everything suppressed", which an attacker can single out just like any
//! other: a lone suppressed outlier is re-identified by being the only record
//! that matches no published class. So suppressed records are published only
//! when that `*` class itself has at least `k` records (and is l-diverse);
//! otherwise they are removed from the output altogether.

use super::{QuasiIdentifierLite, normalize_categorical, parse_numeric_qi, resolve_qi_columns};
use crate::pipeline::bootstrap::{CsvRecords, HierarchyMap, PipelineError, csv_row_to_line, open_csv, validation};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

// ── Value-level generalization helpers ───────────────────────────────────────

/// Formats a numerical value as the closed interval label `[start-end]` for
/// the bucket it falls into.
///
/// # Arguments
/// * `value` — the (rounded) integer value to generalize.
/// * `min_val` — the global minimum of this QI column (used as bucket origin).
/// * `step` — bucket width (must be ≥ 1; clamped internally).
fn generalize_numeric_label(value: i64, min_val: i64, step: i64) -> String {
    let step = step.max(1);
    let bucket_start = min_val + (value - min_val).div_euclid(step) * step;
    let bucket_end = bucket_start.saturating_add(step - 1);
    format!("[{}-{}]", bucket_start, bucket_end)
}

/// Maps a categorical value to its generalized form at the given level using the
/// runtime hierarchy map loaded from config.
///
/// `level <= 1` always returns the original value. For `level >= 2` the function
/// looks up `column_name` (case-insensitive) in `hierarchies`, then looks up
/// `value` within that column map (falling back to the `"*"` catch-all row if
/// the exact value is absent). The generalized string is taken from index
/// `level - 2` of the levels list, defaulting to `"*"` if the index is out of
/// range. Columns absent from the hierarchy are returned unchanged at level 1
/// and suppressed to `"*"` at higher levels.
///
/// `value` must already be normalised ([`normalize_categorical`]); hierarchy
/// leaf keys are normalised the same way when the config is parsed.
pub(super) fn generalize_categorical_label(
    hierarchies: &HierarchyMap,
    column_name: &str,
    value: &str,
    level: i64,
) -> String {
    if level <= 1 {
        return value.to_string();
    }
    let key = column_name.trim().to_lowercase();
    if let Some(col_map) = hierarchies.get(&key) {
        let row = col_map.get(value).or_else(|| col_map.get("*"));
        if let Some(levels) = row {
            let idx = (level - 2) as usize;
            return levels.get(idx).cloned().unwrap_or_else(|| "*".to_string());
        }
    }
    "*".to_string()
}

/// The written form of one QI cell at `level`. Cells with no bin — an
/// unusable number, a value outside every interval — are written as `*`.
fn generalize_cell(qi: &QuasiIdentifierLite, raw: &str, level: i64, hierarchies: &HierarchyMap) -> String {
    if let Some(h) = &qi.interval_hierarchy {
        let level = (level as usize).clamp(1, h.num_levels);
        return parse_numeric_qi(raw)
            .and_then(|v| h.value_to_fine_index(v))
            .map_or_else(|| "*".to_string(), |fi| h.label(level, h.ancestor_at[fi][level]));
    }
    if qi.is_categorical {
        return generalize_categorical_label(hierarchies, &qi.column_name, &normalize_categorical(raw), level);
    }
    parse_numeric_qi(raw).map_or_else(|| "*".to_string(), |v| generalize_numeric_label(v, qi.bin_origin(), level))
}

// ── Main output function ──────────────────────────────────────────────────────

/// l-diversity requirement checked on the written output: every published
/// class must hold at least `l` distinct values of each sensitive attribute.
#[derive(Debug, Clone)]
pub struct LDiversity {
    pub l: usize,
    pub sensitive_attributes: Vec<String>,
}

/// What the generalization step actually wrote, measured on the output itself.
#[derive(Debug, Clone, Default)]
pub struct GeneralizationSummary {
    /// Data rows read.
    pub total_records: i64,
    /// Rows in classes that failed k (or l): published with `*` QIs, or removed.
    pub suppressed_records: i64,
    /// Of `suppressed_records`, how many were removed from the output because
    /// the `*` class they would form is itself too small (or not l-diverse).
    pub removed_records: i64,
    /// Published classes (not counting the `*` class of suppressed rows).
    pub num_equivalence_classes: i64,
    /// Σ size² over published classes.
    pub dm_star: i64,
    /// Class size → number of classes of that size, for published classes.
    pub class_size_counts: BTreeMap<i64, i64>,
    /// Classes (before suppression) with fewer than k records.
    pub classes_failing_k: i64,
    /// Classes with at least k records that failed l-diversity.
    pub classes_failing_l: i64,
    /// Of `suppressed_records`, how many were published with `*` QIs.
    pub published_suppressed_records: i64,
}

/// One class while counting: its size, and up to `l` distinct values of each
/// sensitive attribute.
#[derive(Default)]
struct ClassTally {
    size: i64,
    sensitive: Vec<Vec<String>>,
}

impl ClassTally {
    /// Counts one record with these sensitive values (one per attribute).
    fn add(&mut self, values: &[String], l: usize) {
        self.size += 1;
        for (a, v) in values.iter().enumerate() {
            self.note(a, v, l);
        }
    }

    /// Folds another class into this one.
    fn absorb(&mut self, other: &ClassTally, l: usize) {
        self.size += other.size;
        for (a, values) in other.sensitive.iter().enumerate() {
            for v in values {
                self.note(a, v, l);
            }
        }
    }

    fn note(&mut self, attribute: usize, value: &str, l: usize) {
        if self.sensitive.len() <= attribute {
            self.sensitive.resize(attribute + 1, Vec::new());
        }
        let seen = &mut self.sensitive[attribute];
        if seen.len() < l && !seen.iter().any(|s| s == value) {
            seen.push(value.to_string());
        }
    }

    fn passes(&self, k: i64, l: Option<&LDiversity>) -> bool {
        self.size >= k
            && l.is_none_or(|l| {
                self.sensitive.len() == l.sensitive_attributes.len() && self.sensitive.iter().all(|s| s.len() >= l.l)
            })
    }
}

/// Applies the chosen generalization factors to all chunks and writes the final
/// anonymized CSV. See [`generalize_and_write_outputs_with`].
pub fn generalize_and_write_outputs(
    chunk_paths: &[PathBuf],
    qis: &[QuasiIdentifierLite],
    final_rf: &[i64],
    k: i64,
    output_dir: &Path,
    output_path: &str,
    hierarchies: &HierarchyMap,
) -> Result<GeneralizationSummary, PipelineError> {
    generalize_and_write_outputs_with(chunk_paths, qis, final_rf, k, None, output_dir, output_path, hierarchies)
}

/// Applies the chosen generalization factors to all chunks and writes the final
/// anonymized CSV, enforcing k-anonymity (and l-diversity when `l` is given)
/// on what is written.
///
/// Every chunk is generalized into a temporary file first, so that class sizes
/// are counted over the whole dataset; the temp files are then suppressed and
/// concatenated into a single file at `output_dir / output_path` (or
/// `output_path` if it is absolute), and removed — on failure too.
///
/// # Errors
/// Returns [`PipelineError`] if any file I/O fails, lengths mismatch, a QI or
/// sensitive column is absent from a chunk header, or a row's width differs
/// from its header.
#[allow(clippy::too_many_arguments)]
pub fn generalize_and_write_outputs_with(
    chunk_paths: &[PathBuf],
    qis: &[QuasiIdentifierLite],
    final_rf: &[i64],
    k: i64,
    l: Option<&LDiversity>,
    output_dir: &Path,
    output_path: &str,
    hierarchies: &HierarchyMap,
) -> Result<GeneralizationSummary, PipelineError> {
    if final_rf.len() != qis.len() {
        return Err(validation("GENERALIZATION_FAILED", "final_rf length mismatch", "generalization"));
    }
    if chunk_paths.is_empty() {
        return Err(validation("GENERALIZATION_FAILED", "no chunks provided", "generalization"));
    }
    fs::create_dir_all(output_dir)?;
    let tmp_paths: Vec<PathBuf> =
        (0..chunk_paths.len()).map(|i| output_dir.join(format!("_gen_tmp_{i}.csv"))).collect();
    let result = write_outputs(chunk_paths, &tmp_paths, qis, final_rf, k, l, output_dir, output_path, hierarchies);
    // The temp files hold generalized but not yet suppressed rows: never leave
    // them behind, whether or not the run succeeded.
    for tmp in &tmp_paths {
        let _ = fs::remove_file(tmp);
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn write_outputs(
    chunk_paths: &[PathBuf],
    tmp_paths: &[PathBuf],
    qis: &[QuasiIdentifierLite],
    final_rf: &[i64],
    k: i64,
    l: Option<&LDiversity>,
    output_dir: &Path,
    output_path: &str,
    hierarchies: &HierarchyMap,
) -> Result<GeneralizationSummary, PipelineError> {
    let l_cap = l.map_or(0, |l| l.l);
    let mut headers: Option<Vec<String>> = None;
    let mut qi_idx: Vec<usize> = Vec::new();
    let mut sens_idx: Vec<usize> = Vec::new();

    // --- Pass 1: generalize every chunk into a temp file, counting classes globally ---
    let mut classes: BTreeMap<Vec<String>, ClassTally> = BTreeMap::new();
    let mut total_records = 0_i64;

    for (chunk, tmp_path) in chunk_paths.iter().zip(tmp_paths) {
        let (header, mut records) = open_csv(chunk)?;
        match &headers {
            None => {
                qi_idx = resolve_qi_columns(&header, qis)?;
                if let Some(l) = l {
                    sens_idx = l
                        .sensitive_attributes
                        .iter()
                        .map(|c| {
                            header.iter().position(|h| h == c).ok_or_else(|| {
                                validation(
                                    "DATA_COLUMN_MISSING",
                                    "l_diversity sensitive attribute not found in CSV header",
                                    c,
                                )
                            })
                        })
                        .collect::<Result<_, _>>()?;
                }
                headers = Some(header.clone());
            }
            Some(first) if *first != header => {
                return Err(validation("GENERALIZATION_FAILED", "chunk headers differ", &chunk.display().to_string()));
            }
            Some(_) => {}
        }

        let mut w = BufWriter::new(fs::File::create(tmp_path)?);
        while let Some(mut fields) = records.next_record_of_width(header.len())? {
            for (qi_pos, qi) in qis.iter().enumerate() {
                let i = qi_idx[qi_pos];
                fields[i] = generalize_cell(qi, &fields[i], final_rf[qi_pos], hierarchies);
            }
            let key: Vec<String> = qi_idx.iter().map(|&i| fields[i].clone()).collect();
            let sensitive: Vec<String> = sens_idx.iter().map(|&i| normalize_categorical(&fields[i])).collect();
            classes.entry(key).or_default().add(&sensitive, l_cap);
            total_records += 1;

            w.write_all(csv_row_to_line(&fields).as_bytes())?;
            w.write_all(b"\n")?;
        }
        w.flush()?;
    }
    let headers = headers.unwrap_or_default();

    // Every failing class goes into the `*` class; publish it only if it would
    // itself pass, otherwise its records are removed.
    let mut star = ClassTally::default();
    let mut summary = GeneralizationSummary { total_records, ..Default::default() };
    for tally in classes.values() {
        if tally.passes(k, l) {
            summary.num_equivalence_classes += 1;
            summary.dm_star = summary.dm_star.saturating_add(tally.size.saturating_mul(tally.size));
            *summary.class_size_counts.entry(tally.size).or_insert(0) += 1;
        } else {
            if tally.size < k {
                summary.classes_failing_k += 1;
            } else {
                summary.classes_failing_l += 1;
            }
            summary.suppressed_records += tally.size;
            star.absorb(tally, l_cap);
        }
    }
    let publish_suppressed = star.size == 0 || star.passes(k, l);
    if publish_suppressed {
        summary.published_suppressed_records = star.size;
    } else {
        summary.removed_records = star.size;
    }

    // --- Pass 2: suppress or remove failing records, writing straight into the final file ---
    let final_path =
        if Path::new(output_path).is_absolute() { PathBuf::from(output_path) } else { output_dir.join(output_path) };
    let mut final_writer = BufWriter::new(fs::File::create(&final_path)?);
    final_writer.write_all(csv_row_to_line(&headers).as_bytes())?;
    final_writer.write_all(b"\n")?;

    for tmp_path in tmp_paths {
        // Temp files hold data rows only — no header record to skip.
        let mut records = CsvRecords::new(BufReader::new(fs::File::open(tmp_path)?), &tmp_path.display().to_string());
        while let Some(mut fields) = records.next_record_of_width(headers.len())? {
            let key: Vec<String> = qi_idx.iter().map(|&i| fields[i].clone()).collect();
            if !classes.get(&key).is_some_and(|t| t.passes(k, l)) {
                if !publish_suppressed {
                    continue;
                }
                for &i in &qi_idx {
                    fields[i] = "*".to_string();
                }
            }
            final_writer.write_all(csv_row_to_line(&fields).as_bytes())?;
            final_writer.write_all(b"\n")?;
        }
    }
    final_writer.flush()?;
    Ok(summary)
}
