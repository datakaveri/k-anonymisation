//! Emits a `chunk-manifest` document for the Co-ordinator.
//!
//! The manifest is the AO→Co-ordinator contract from `anamika-control-plane`
//! (`contracts/schemas/chunk-manifest.schema.json`). SKALD is the application
//! whose column roles and phase structure it describes, so producing it here
//! keeps one source of truth: the same config that drives the blocks derives
//! the manifest, rather than the AO restating SKALD's requirements in a second
//! place that can drift.
//!
//! Two things this deliberately does **not** do:
//!
//! - **It never names an image.** Phases carry a `container_role` and the
//!   Co-ordinator resolves it. An image reference emitted here would be a guess
//!   about something this side does not own, and the digest that matters is the
//!   one the Co-ordinator reports back after attesting.
//!
//! - **It does not encrypt.** The `digest` on each chunk is the SHA-256 of the
//!   chunk *plaintext*, as the schema specifies, because the container checks it
//!   after decrypting. Encryption and delivery are the AO's.

use super::plan::JobPlan;
use crate::pipeline::bootstrap::{
    csv_row_to_line, parse_runtime_config, split_csv_line_basic, validation, PipelineError,
    RuntimeConfig,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

pub const MANIFEST_VERSION: u32 = 1;

/// A chunk of one phase: a row range, the file holding that phase's column
/// projection of it, and the plaintext digest the container will verify.
#[derive(Debug, Clone, Serialize)]
pub struct ChunkEntry {
    pub chunk_id: String,
    pub phase: String,
    pub rows: RowRange,
    pub byte_size: u64,
    pub digest: String,
    /// Where this chunk's plaintext was written. Not part of the contract —
    /// the AO encrypts and delivers it, and strips this before sending.
    #[serde(skip_serializing)]
    pub path: PathBuf,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct RowRange {
    pub start: u64,
    pub end: u64,
}

/// Builds the manifest's static half: version, roles, parameters, phases.
///
/// `chunks` is filled by [`materialise_chunks`], which needs the staged data.
/// Split in two because planning is a decision and chunking is work, and the
/// orchestrator may well want to see the first before committing to the second.
pub fn manifest_skeleton(
    plan: &JobPlan,
    config_path: &Path,
    split_crypto: bool,
) -> Result<Value, PipelineError> {
    let cfg = parse_runtime_config(config_path)?;

    let doc = json!({
        "manifest_version": MANIFEST_VERSION,
        "job_id": plan.job_id,
        "application": "kanon",
        "column_roles": column_roles(&cfg, plan),
        "parameters": {
            // Null means "the measure phase derives it", which is exactly what
            // pass1 does. A pinned k skips the measure phase entirely.
            "k": if cfg.pass == "pass1" || cfg.k <= 0 { Value::Null } else { json!(cfg.k) },
            "suppression_limit": cfg.suppression_limit,
        },
        "phases": phases(&cfg, split_crypto),
        "chunks": [],
        "retry_policy": { "max_attempts_per_chunk": 3, "on_exhausted": "abort_job" },
    });

    Ok(doc)
}

/// Why a `--split-crypto` manifest does not conform, for the caller to print.
///
/// Kept out of the document itself: the schema sets `additionalProperties:
/// false`, so a note added to the manifest would make it fail validation for a
/// second and unrelated reason, which is exactly the kind of noise that gets a
/// real error dismissed.
pub const SPLIT_CRYPTO_WARNING: &str = "\
--split-crypto emits TWO phases named 'preprocess', one per container role, so the crypto
block can be attested separately from the masking/tokenisation block.

The contract as written cannot express that, and the resulting manifest will NOT validate:

  * Chunk.phase is an enum of three names, so a chunk cannot say which of the two
    preprocess phases it belongs to.
  * The Co-ordinator's /jobs/{job_id}/phases/{phase}/start is keyed by the same name,
    so the two phases have no distinct address to be started at.

The minimal contract change is to give Phase a unique `id` and have Chunk.phase and the
start endpoint reference that id instead of the name, leaving `name` as the semantic kind.
See BLOCKS.md. Until then, drop --split-crypto and run one preprocess role that does both.";

fn column_roles(cfg: &RuntimeConfig, plan: &JobPlan) -> Value {
    let mut qis = Vec::new();
    for q in &cfg.numerical_qis {
        qis.push(json!({
            "column": q.column,
            "kind": "numerical",
            "dtype": if q.dtype == "float" { "float" } else { "int" },
            "hierarchy_id": Value::Null,
        }));
    }
    for c in &cfg.categorical_qis {
        qis.push(json!({
            "column": c,
            "kind": "categorical",
            "dtype": "string",
            // A hierarchy is only referenced when one is actually configured;
            // naming one that does not exist would let the measure and apply
            // phases disagree about what they generalised against.
            "hierarchy_id": if cfg.categorical_hierarchies.contains_key(&c.trim().to_lowercase()) {
                json!(format!("{}_v1", c.trim().to_lowercase().replace(' ', "_")))
            } else {
                Value::Null
            },
        }));
    }

    // Every operation, in the contract's vocabulary. Suppression is listed even
    // though the AO performs it during staging: the contract asks for a complete
    // classification, and a column nobody classified is meant to be an error
    // rather than a silent leak.
    let mut preprocess = Vec::new();
    let mut push = |col: &str, op: &str| preprocess.push(json!({ "column": col, "operation": op }));
    for c in &cfg.suppress {
        push(c, "suppress");
    }
    for c in &cfg.hashing_with_salt {
        push(c, "hash_salted");
    }
    for c in &cfg.hashing_without_salt {
        push(c, "hash_unsalted");
    }
    for m in &cfg.masking {
        if let Some(c) = m.get("column").and_then(Value::as_str) {
            push(c, "mask");
        }
    }
    for c in &cfg.charcloak {
        push(c, "charcloak");
    }
    for t in &cfg.tokenization {
        if let Some(c) = t.get("column").and_then(Value::as_str) {
            push(c, "tokenize");
        }
    }
    for e in &cfg.encrypt {
        let (col, fpe) = match e {
            Value::String(s) => (s.clone(), false),
            Value::Object(o) => {
                let col = o
                    .get("column")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .or_else(|| o.keys().next().cloned())
                    .unwrap_or_default();
                let fpe = o
                    .get("format_preserving")
                    .and_then(Value::as_bool)
                    .or_else(|| o.values().next()?.get("format_preserving")?.as_bool())
                    .unwrap_or(false);
                (col, fpe)
            }
            _ => continue,
        };
        if !col.is_empty() {
            push(&col, if fpe { "fpe" } else { "encrypt" });
        }
    }

    json!({
        "quasi_identifiers": qis,
        "sensitive": Vec::<String>::new(),
        "preprocess": preprocess,
        "passthrough": plan.passthrough_columns,
    })
}

fn phases(cfg: &RuntimeConfig, split_crypto: bool) -> Value {
    let mut out = Vec::new();
    let has_pre = !cfg.masking.is_empty() || !cfg.charcloak.is_empty() || !cfg.tokenization.is_empty();
    let has_crypto = !cfg.hashing_with_salt.is_empty()
        || !cfg.hashing_without_salt.is_empty()
        || !cfg.encrypt.is_empty();

    if split_crypto {
        if has_pre {
            out.push(phase("preprocess", false, "preprocess", "skald-preprocess", None, None));
        }
        if has_crypto {
            out.push(phase("preprocess", false, "preprocess", "skald-crypto", None, None));
        }
    } else if has_pre || has_crypto {
        // One role doing both. This is what the contract can express today.
        out.push(phase("preprocess", false, "preprocess", "skald-preprocess", None, None));
    }

    if cfg.enable_k_anonymity {
        // The measure phase exists only when k has to be derived. A pinned k
        // means the histogram is never needed and the job streams once, which
        // is the trade-off the job-config schema spells out.
        let derive_k = cfg.pass == "pass1" || cfg.k <= 0;
        if derive_k {
            out.push(phase(
                "measure",
                true,
                "quasi_identifiers",
                "skald-kanon",
                None,
                Some("qi_histogram"),
            ));
        }
        out.push(phase(
            "apply",
            false,
            "all",
            "skald-kanon",
            derive_k.then_some("qi_histogram"),
            None,
        ));
    }
    Value::Array(out)
}

fn phase(
    name: &str,
    barrier: bool,
    columns: &str,
    role: &str,
    consumes: Option<&str>,
    produces: Option<&str>,
) -> Value {
    json!({
        "name": name,
        "barrier": barrier,
        "columns": columns,
        "container_role": role,
        "consumes": consumes.map(Value::from).unwrap_or(Value::Null),
        "produces": produces.map(Value::from).unwrap_or(Value::Null),
    })
}

/// Writes each phase's column projection of each row range, hashes the
/// plaintext, and returns the `chunks` array.
///
/// A chunk is never shared between phases: the measure and apply phases read
/// the same rows through different column projections, so they get separate
/// entries over the same range — which is also why the digests differ.
pub fn materialise_chunks(
    manifest: &Value,
    staged: &Path,
    out_dir: &Path,
    rows_per_chunk: usize,
    rid_col: &str,
) -> Result<Vec<ChunkEntry>, PipelineError> {
    if rows_per_chunk == 0 {
        return Err(validation(
            "CONFIG_INVALID_VALUE",
            "rows_per_chunk must be greater than zero",
            "pass --rows <n>",
        ));
    }
    fs::create_dir_all(out_dir)?;

    let roles = manifest.get("column_roles").ok_or_else(|| {
        validation("BLOCK_ARTIFACT_INVALID", "Manifest has no column_roles", "manifest_skeleton first")
    })?;
    let qi_cols: Vec<String> = roles
        .get("quasi_identifiers")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|q| q.get("column")?.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    // Suppression happens during staging, so those columns are already gone
    // from the staged file and must not be projected for.
    let pre_cols: Vec<String> = roles
        .get("preprocess")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter(|p| p.get("operation").and_then(Value::as_str) != Some("suppress"))
                .filter_map(|p| p.get("column")?.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    let phase_names: Vec<String> = manifest
        .get("phases")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|p| p.get("name")?.as_str().map(str::to_string)).collect())
        .unwrap_or_default();

    let file = fs::File::open(staged).map_err(|e| {
        validation("IO_READ_FAILED", "Could not open the staged input", &format!("{}: {e}", staged.display()))
    })?;
    let mut lines = BufReader::new(file).lines();
    let header_line = lines
        .next()
        .ok_or_else(|| validation("DATA_EMPTY", "Staged input has no header", &staged.display().to_string()))?
        .map_err(|e| validation("IO_READ_FAILED", "Failed reading header", &e.to_string()))?;
    let headers = split_csv_line_basic(&header_line);

    // Row ranges are decided once and shared by every phase, so the same range
    // means the same rows whichever phase reads it.
    let mut ranges: Vec<(u64, u64, Vec<Vec<String>>)> = Vec::new();
    let mut buf: Vec<Vec<String>> = Vec::new();
    let mut start = 0u64;
    let mut n = 0u64;
    for line in lines {
        let line = line.map_err(|e| validation("IO_READ_FAILED", "Failed reading row", &e.to_string()))?;
        if line.trim().is_empty() {
            continue;
        }
        buf.push(split_csv_line_basic(&line));
        n += 1;
        if buf.len() == rows_per_chunk {
            ranges.push((start, n, std::mem::take(&mut buf)));
            start = n;
        }
    }
    if !buf.is_empty() {
        ranges.push((start, n, buf));
    }
    if ranges.is_empty() {
        return Err(validation("DATA_EMPTY", "Staged input has no data rows", &staged.display().to_string()));
    }

    let mut out = Vec::new();
    for name in &phase_names {
        let (prefix, cols) = match name.as_str() {
            "preprocess" => ("pre", Some(&pre_cols)),
            "measure" => ("mea", Some(&qi_cols)),
            "apply" => ("app", None), // `columns: "all"`
            other => {
                return Err(validation(
                    "BLOCK_ARTIFACT_INVALID",
                    "Unknown phase name in manifest",
                    other,
                ))
            }
        };
        // Two phases can share a name (--split-crypto), and each still needs
        // distinct chunk ids.
        let seq = out.iter().filter(|c: &&ChunkEntry| c.phase == *name).count() / ranges.len();
        let keep = projection(&headers, cols, rid_col)?;

        for (i, (lo, hi, rows)) in ranges.iter().enumerate() {
            let chunk_id = if seq == 0 {
                format!("{prefix}-{i:04}")
            } else {
                format!("{prefix}{seq}-{i:04}")
            };
            let path = out_dir.join(format!("{chunk_id}.csv"));
            let (bytes, digest) = write_projection(&path, &headers, &keep, rows)?;
            out.push(ChunkEntry {
                chunk_id,
                phase: name.clone(),
                rows: RowRange { start: *lo, end: *hi },
                byte_size: bytes,
                digest,
                path,
            });
        }
    }
    Ok(out)
}

/// Column indices to keep: the row id always, then the phase's columns, or
/// everything when the phase reads `all`.
fn projection(
    headers: &[String],
    cols: Option<&Vec<String>>,
    rid_col: &str,
) -> Result<Vec<usize>, PipelineError> {
    let Some(cols) = cols else {
        return Ok((0..headers.len()).collect());
    };
    let mut keep = Vec::new();
    if let Some(i) = headers.iter().position(|h| h == rid_col) {
        keep.push(i);
    }
    for c in cols {
        let i = headers.iter().position(|h| h == c).ok_or_else(|| {
            validation(
                "PLAN_COLUMN_MISSING",
                "A phase needs a column the staged input does not have",
                &format!("'{c}' — was it suppressed during staging?"),
            )
        })?;
        if !keep.contains(&i) {
            keep.push(i);
        }
    }
    Ok(keep)
}

fn write_projection(
    path: &Path,
    headers: &[String],
    keep: &[usize],
    rows: &[Vec<String>],
) -> Result<(u64, String), PipelineError> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let mut w = BufWriter::new(fs::File::create(path)?);

    let mut emit = |w: &mut BufWriter<fs::File>, line: String| -> Result<(), PipelineError> {
        let b = line.as_bytes();
        hasher.update(b);
        hasher.update(b"\n");
        bytes += b.len() as u64 + 1;
        w.write_all(b)?;
        w.write_all(b"\n")?;
        Ok(())
    };

    let head: Vec<String> = keep.iter().map(|&i| headers[i].clone()).collect();
    emit(&mut w, csv_row_to_line(&head))?;
    for row in rows {
        let projected: Vec<String> =
            keep.iter().map(|&i| row.get(i).cloned().unwrap_or_default()).collect();
        emit(&mut w, csv_row_to_line(&projected))?;
    }
    w.flush()?;
    Ok((bytes, hex::encode(hasher.finalize())))
}
