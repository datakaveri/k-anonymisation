//! Generalization and output writing for the SKALD anonymization pipeline.
//!
//! Applies the generalization factors chosen by OLA-2 to every chunk CSV file
//! and produces anonymized output files.
//!
//! ## Two-pass approach
//! 1. **Pass 1** — generalize each row in-place and write to a temporary file,
//!    simultaneously accumulating per-equivalence-class record counts.
//! 2. **Pass 2** — re-read the temp file and suppress (replace QI values with
//!    `"*"`) any record whose equivalence class has fewer than `k` members.
//!
//! After all per-chunk output files are written they are merged into a single
//! final CSV and the intermediates are deleted.

use crate::pipeline::bootstrap::{csv_row_to_line, split_csv_line_basic, validation, PipelineError};
use super::{QuasiIdentifierLite, base_col_name};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

// ── Value-level generalization helpers ───────────────────────────────────────

/// Formats a numerical value as the closed interval label `[start-end]` for
/// the bucket it falls into.
///
/// # Arguments
/// * `value` — the (rounded) integer value to generalize.
/// * `min_val` — the global minimum of this QI column (used as bucket origin).
/// * `step` — bucket width (must be ≥ 1; clamped internally).
///
/// # Returns
/// A string of the form `"[bucket_start-bucket_end]"`.
fn generalize_numeric_label(value: i64, min_val: i64, step: i64) -> String {
    let bucket_start = min_val + ((value - min_val) / step.max(1)) * step.max(1);
    let bucket_end = bucket_start + step.max(1) - 1;
    format!("[{}-{}]", bucket_start, bucket_end)
}

/// Maps a categorical value to its generalized form at the given level.
///
/// Supported columns and their hierarchies:
///
/// | Column | Level 1 | Level 2 | Level 3 | Level 4 |
/// |--------|---------|---------|---------|---------|
/// | `blood group` | exact | ABO letter | `*` | — |
/// | `gender` | exact | `*` | — | — |
/// | `profession` | exact | sector | super-sector | `*` |
///
/// Any unknown column is returned unchanged.
///
/// # Arguments
/// * `column_name` — the QI column name (case-insensitive).
/// * `value` — the original cell value.
/// * `level` — the generalization level (clamped to ≥ 1).
fn generalize_categorical_value(column_name: &str, value: &str, level: i64) -> String {
    let key = column_name.trim().to_lowercase();
    let lvl = level.max(1);
    match key.as_str() {
        "blood group" => {
            if lvl <= 1 {
                value.to_string()
            } else if lvl == 2 {
                match value {
                    "A+" | "A-" => "A".to_string(),
                    "B+" | "B-" => "B".to_string(),
                    "AB+" | "AB-" => "AB".to_string(),
                    "O+" | "O-" => "O".to_string(),
                    _ => "Other".to_string(),
                }
            } else {
                "*".to_string()
            }
        }
        "gender" => {
            if lvl <= 1 {
                value.to_string()
            } else {
                "*".to_string()
            }
        }
        "profession" => {
            if lvl <= 1 {
                value.to_string()
            } else if lvl == 2 {
                match value {
                    "Medical Specialists" | "Allied Health" | "Nursing" | "Healthcare Support" => "Healthcare".to_string(),
                    "K-12 Education Teacher" | "Higher Education Teacher" | "Supplemental Education Teacher" | "University Professor" => "Education".to_string(),
                    "Performing Arts" | "Visual & Media Arts" | "Design" | "Mixed Media Artist" => "Creative".to_string(),
                    "Traditional Engineering" | "Software Engineering" | "Data & Analytics" | "AI & Machine Learning" => "Engineering".to_string(),
                    _ => "Other".to_string(),
                }
            } else if lvl == 3 {
                match value {
                    "Medical Specialists"
                    | "Allied Health"
                    | "Nursing"
                    | "Healthcare Support"
                    | "K-12 Education Teacher"
                    | "Higher Education Teacher"
                    | "Supplemental Education Teacher"
                    | "University Professor" => "Service Sector".to_string(),
                    "Performing Arts"
                    | "Visual & Media Arts"
                    | "Design"
                    | "Mixed Media Artist"
                    | "Traditional Engineering"
                    | "Software Engineering"
                    | "Data & Analytics"
                    | "AI & Machine Learning" => "Non-Service".to_string(),
                    _ => "Other".to_string(),
                }
            } else {
                "*".to_string()
            }
        }
        _ => value.to_string(),
    }
}

/// Generates the output filename for a single generalized chunk.
///
/// # Arguments
/// * `output_path` — the final merged output path (may end with `.csv`).
/// * `idx` — 1-based chunk index.
///
/// # Returns
/// `"<output_path_without_extension>_chunk<idx>.csv"`.
fn generalized_chunk_name(output_path: &str, idx: usize) -> String {
    let base = output_path.trim_end_matches(".csv");
    format!("{base}_chunk{idx}.csv")
}

// ── Main output function ──────────────────────────────────────────────────────

/// Applies the chosen generalization factors to all chunks and writes the final
/// anonymized CSV.
///
/// For each chunk the function performs two passes (see module-level doc).
/// After all chunks are processed their outputs are concatenated into a single
/// file at `output_dir / output_path` (or `output_path` if it is absolute), and
/// the per-chunk intermediates are removed.
///
/// # Arguments
/// * `chunk_paths` — pre-processed chunk CSV files.
/// * `qis` — quasi-identifier descriptors (same order and length as `final_rf`).
/// * `final_rf` — generalization factors selected by OLA-2.
/// * `k` — k-anonymity threshold; equivalence classes smaller than `k` are suppressed.
/// * `output_dir` — directory where output files are written (created if absent).
/// * `output_path` — filename (or absolute path) for the merged output CSV.
///
/// # Errors
/// Returns [`PipelineError`] if any file I/O fails, lengths mismatch, or a
/// required column is absent from the chunk header.
pub fn generalize_and_write_outputs(
    chunk_paths: &[PathBuf],
    qis: &[QuasiIdentifierLite],
    final_rf: &[i64],
    k: i64,
    output_dir: &Path,
    output_path: &str,
) -> Result<(), PipelineError> {
    if final_rf.len() != qis.len() {
        return Err(validation("GENERALIZATION_FAILED", "final_rf length mismatch", "generalization"));
    }
    fs::create_dir_all(output_dir)?;

    // Resolve column layout from first chunk header (uniform schema across all chunks)
    let (headers, qi_src_indices, qi_output_idx) = {
        let first = chunk_paths
            .first()
            .ok_or_else(|| validation("GENERALIZATION_FAILED", "no chunks provided", "generalization"))?;
        let f = fs::File::open(first)?;
        let mut lines = BufReader::new(f).lines();
        let header = lines
            .next()
            .ok_or_else(|| validation("GENERALIZATION_FAILED", "chunk missing header", &first.display().to_string()))?
            .map_err(|e| validation("GENERALIZATION_FAILED", "failed reading header", &e.to_string()))?;
        let headers = split_csv_line_basic(&header);

        // Source column index for each QI (may differ from output index for numerical)
        let qi_src: Vec<Option<usize>> = qis
            .iter()
            .map(|qi| {
                if qi.is_categorical {
                    headers.iter().position(|h| h == &qi.column_name)
                } else {
                    let src = base_col_name(&qi.column_name);
                    headers.iter().position(|h| h == &src)
                }
            })
            .collect();

        // Output QI column indices (used for EC suppression key)
        let qi_out: Vec<usize> = qis
            .iter()
            .filter_map(|qi| {
                let col = if qi.is_categorical { qi.column_name.clone() } else { base_col_name(&qi.column_name) };
                headers.iter().position(|h| h == &col)
            })
            .collect();

        (headers, qi_src, qi_out)
    };

    // Use global min from qi.min_value (computed across all chunks by compute_numerical_min_max)
    let global_mins: Vec<i64> = qis.iter().map(|qi| qi.min_value.unwrap_or(0.0).floor() as i64).collect();

    let mut output_chunk_paths = Vec::new();

    for (chunk_idx, chunk) in chunk_paths.iter().enumerate() {
        // --- Pass 1: generalize each row, write to temp file, accumulate EC counts ---
        let tmp_path = output_dir.join(format!("_gen_tmp_{chunk_idx}.csv"));
        let mut class_counts: BTreeMap<Vec<String>, i64> = BTreeMap::new();

        {
            let f = fs::File::open(chunk)?;
            let mut lines = BufReader::new(f).lines();
            let _ = lines.next(); // skip header

            let mut w = BufWriter::new(fs::File::create(&tmp_path)?);
            w.write_all(csv_row_to_line(&headers).as_bytes())?;
            w.write_all(b"\n")?;

            for line in lines {
                let line = line.map_err(|e| {
                    validation("GENERALIZATION_FAILED", "failed reading chunk row", &e.to_string())
                })?;
                if line.trim().is_empty() {
                    continue;
                }
                let mut fields = split_csv_line_basic(&line);

                // Apply generalization in-place
                for ((qi, bw), src_idx_opt) in qis.iter().zip(final_rf.iter()).zip(qi_src_indices.iter()) {
                    let Some(src_idx) = src_idx_opt else { continue };
                    if *src_idx >= fields.len() {
                        continue;
                    }
                    if qi.is_categorical {
                        let v = fields[*src_idx].clone();
                        fields[*src_idx] = generalize_categorical_value(&qi.column_name, &v, *bw);
                    } else {
                        if let Ok(v) = fields[*src_idx].trim().parse::<f64>() {
                            let qi_pos = qis.iter().position(|q| std::ptr::eq(q, qi)).unwrap_or(0);
                            fields[*src_idx] =
                                generalize_numeric_label(v.round() as i64, global_mins[qi_pos], (*bw).max(1));
                        }
                    }
                }

                // Accumulate EC key (generalized QI values only)
                if !qi_output_idx.is_empty() && k > 1 {
                    let key: Vec<String> =
                        qi_output_idx.iter().map(|&i| fields.get(i).cloned().unwrap_or_default()).collect();
                    *class_counts.entry(key).or_insert(0) += 1;
                }

                w.write_all(csv_row_to_line(&fields).as_bytes())?;
                w.write_all(b"\n")?;
            }
            w.flush()?;
        }

        // --- Pass 2: apply suppression using EC counts, write final chunk output ---
        let out_name = generalized_chunk_name(output_path, chunk_idx + 1);
        let out_path = output_dir.join(out_name);
        {
            let f = fs::File::open(&tmp_path)?;
            let mut lines = BufReader::new(f).lines();
            let _ = lines.next(); // skip header written by pass 1

            let mut w = BufWriter::new(fs::File::create(&out_path)?);
            w.write_all(csv_row_to_line(&headers).as_bytes())?;
            w.write_all(b"\n")?;

            for line in lines {
                let line = line.map_err(|e| {
                    validation("GENERALIZATION_FAILED", "failed reading temp chunk", &e.to_string())
                })?;
                if line.trim().is_empty() {
                    continue;
                }
                let mut fields = split_csv_line_basic(&line);

                if !qi_output_idx.is_empty() && k > 1 {
                    let key: Vec<String> =
                        qi_output_idx.iter().map(|&i| fields.get(i).cloned().unwrap_or_default()).collect();
                    if class_counts.get(&key).copied().unwrap_or(0) < k {
                        for &i in &qi_output_idx {
                            if i < fields.len() {
                                fields[i] = "*".to_string();
                            }
                        }
                    }
                }

                w.write_all(csv_row_to_line(&fields).as_bytes())?;
                w.write_all(b"\n")?;
            }
            w.flush()?;
        }

        let _ = fs::remove_file(&tmp_path);
        output_chunk_paths.push(out_path);
    }

    // Merge chunk outputs into single final file
    let final_path = if Path::new(output_path).is_absolute() {
        PathBuf::from(output_path)
    } else {
        output_dir.join(output_path)
    };
    let mut final_writer = BufWriter::new(fs::File::create(&final_path)?);
    for (i, p) in output_chunk_paths.iter().enumerate() {
        let f = fs::File::open(p)?;
        let r = BufReader::new(f);
        for (line_no, line) in r.lines().enumerate() {
            let line = line.map_err(|e| {
                validation("GENERALIZATION_FAILED", "failed reading generalized chunk", &e.to_string())
            })?;
            if i > 0 && line_no == 0 {
                continue; // skip repeated header
            }
            final_writer.write_all(line.as_bytes())?;
            final_writer.write_all(b"\n")?;
        }
    }
    final_writer.flush()?;
    for p in output_chunk_paths {
        let _ = fs::remove_file(p);
    }

    Ok(())
}
