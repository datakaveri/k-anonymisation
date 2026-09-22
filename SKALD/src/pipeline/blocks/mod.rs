//! Block runtime for the Anonymization Orchestrator (AO) deployment model.
//!
//! The monolithic `skald_pipeline` binary stays exactly as it was. This module
//! carves the same work into three independently pullable, independently
//! attestable units so the AO can column-shard a dataset and hand each shard
//! only to the container that actually needs to see it:
//!
//! | Block | Operations | Secret state | Where it runs |
//! |---|---|---|---|
//! | `preprocess` | suppress, masking, charcloak, tokenize | token vault | on the AO, in-TEE |
//! | `crypto` | salted/unsalted hashing, pseudo-encrypt, FPE | per-column keys | dispatched container |
//! | `kanon` | scan / solve / apply | none (derived histograms only) | dispatched container |
//!
//! ## Why the split falls this way
//!
//! `masking` was unassigned in the original three-way sketch. It is unkeyed,
//! deterministic and holds no secret state, so it belongs with the other
//! stateless redactions in `preprocess` rather than alongside key-bearing
//! operations. FPE is keyed, so it goes to `crypto` even though the config
//! spells it as an `encrypt` variant. Tokenization keeps a *reversible* vault,
//! which is secret material even though no key is involved — it therefore
//! stays inside the TEE with the rest of `preprocess`.
//!
//! ## The two invariants that make column sharding safe
//!
//! 1. **Row identity.** The AO stamps every input row with a reserved
//!    `__skald_rid` column before it splits anything. Every block preserves
//!    row count and row order and passes the rid through untouched, so the AO
//!    can stitch column shards back together by rid rather than by position.
//!    k-anonymization stars out QI values, it never deletes rows, so the rid
//!    space is identical on the way out.
//!
//! 2. **The AO owns all key material.** A worker never mints a salt or a key.
//!    If two row shards of the same column were hashed by two containers that
//!    each generated their own salt, the same plaintext would hash to two
//!    different digests and the column would be silently destroyed. Keys and
//!    salts are minted once by the AO (`skald_ao keygen`) and travel in the
//!    block manifest.
//!
//! ## Manifest
//!
//! Every block binary is invoked the same way:
//!
//! ```text
//! skald_<block> --manifest /job/manifest.json
//! ```
//!
//! Relative paths inside the manifest resolve against the manifest's own
//! directory, so the AO can mount a self-contained job directory and never
//! has to care about the container's working directory.

pub mod contract;
pub mod crypto_block;
pub mod kanon_block;
pub mod plan;
pub mod preprocess_block;
pub mod shard;
pub mod stage;

#[cfg(test)]
mod tests;

use crate::pipeline::bootstrap::{
    http_status_for, suggested_fix_for, validation, ErrorPayload, PipelineError, StatusPayload,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Bumped whenever the manifest or artifact shape changes incompatibly.
/// A block refuses a manifest it does not understand rather than guessing.
pub const BLOCK_SCHEMA_VERSION: u32 = 1;

/// Reserved column the AO stamps onto every row before sharding. Blocks treat
/// it as opaque: they never transform it, never drop it, never reorder it.
pub const DEFAULT_ROW_ID_COLUMN: &str = "__skald_rid";

// ── Key material ─────────────────────────────────────────────────────────────

/// Per-column key material, minted by the AO and shipped in the manifest.
///
/// A `crypto` worker that finds a required entry missing fails with
/// `BLOCK_KEY_MISSING` instead of generating one. That failure is deliberate:
/// a silently self-generated key produces output that looks fine and is
/// unrecoverable, and under row-parallel execution it produces output that is
/// not even self-consistent.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct BlockKeys {
    /// column → hex salt, for `hashing_with_salt`.
    #[serde(default)]
    pub hash_salts: BTreeMap<String, String>,
    /// column → hex key, for `encrypt` entries without `format_preserving`.
    #[serde(default)]
    pub symmetric_keys: BTreeMap<String, String>,
    /// column → hex key, for `encrypt` entries with `format_preserving: true`.
    #[serde(default)]
    pub fpe_keys: BTreeMap<String, String>,
}

impl BlockKeys {
    pub fn is_empty(&self) -> bool {
        self.hash_salts.is_empty() && self.symmetric_keys.is_empty() && self.fpe_keys.is_empty()
    }
}

// ── Manifest ─────────────────────────────────────────────────────────────────

fn default_schema_version() -> u32 {
    BLOCK_SCHEMA_VERSION
}
fn default_shard_id() -> String {
    "shard_0".to_string()
}
fn default_artifacts_dir() -> PathBuf {
    PathBuf::from("artifacts")
}
fn default_row_id_column() -> String {
    DEFAULT_ROW_ID_COLUMN.to_string()
}

/// The single input every block binary takes.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlockManifest {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// Opaque job identifier, echoed into every artifact so the AO can
    /// correlate results without parsing paths.
    pub job_id: String,
    /// Identifies this shard within the job. Artifact filenames derive from it.
    #[serde(default = "default_shard_id")]
    pub shard_id: String,
    /// `"preprocess"` | `"crypto"` | `"kanon"`.
    pub block: String,
    /// `kanon` only: `"scan"` | `"solve"` | `"apply"`.
    #[serde(default)]
    pub stage: Option<String>,
    /// The shard CSV this invocation reads. Not used by `kanon solve`.
    #[serde(default)]
    pub input: Option<PathBuf>,
    /// `kanon solve` only: the scan artifacts to reduce.
    #[serde(default)]
    pub inputs: Vec<PathBuf>,
    /// Where the transformed shard is written. Defaults to
    /// `<artifacts_dir>/<shard_id>.out.csv`.
    #[serde(default)]
    pub output: Option<PathBuf>,
    /// Directory for status, keys, vault and stage artifacts.
    #[serde(default = "default_artifacts_dir")]
    pub artifacts_dir: PathBuf,
    #[serde(default = "default_row_id_column")]
    pub row_id_column: String,
    /// The job's SKALD config JSON — the same file shape the monolith reads.
    /// Blocks apply only the parts of it that touch columns present in the
    /// shard, so one config drives every block without duplication.
    pub config: PathBuf,
    /// Columns the AO routed to this shard. When empty, the block infers the
    /// set from the shard header. Listing them explicitly turns an AO routing
    /// bug into an error instead of a silently skipped operation.
    #[serde(default)]
    pub columns: Vec<String>,
    /// `crypto` only.
    #[serde(default)]
    pub keys: BlockKeys,
    /// `kanon apply` only: the `solution.json` produced by `kanon solve`.
    #[serde(default)]
    pub solution: Option<PathBuf>,
    /// `preprocess` only: shared token vault. Defaults to
    /// `<artifacts_dir>/token_vault.json`.
    #[serde(default)]
    pub vault: Option<PathBuf>,
}

impl BlockManifest {
    /// Loads a manifest and rewrites every relative path in it to be relative
    /// to the manifest's own directory.
    pub fn load(path: &Path) -> Result<Self, PipelineError> {
        let raw = fs::read_to_string(path).map_err(|e| {
            validation(
                "BLOCK_MANIFEST_INVALID",
                "Could not read the block manifest",
                &format!("{}: {e}", path.display()),
            )
        })?;
        let mut m: BlockManifest = serde_json::from_str(&raw).map_err(|e| {
            validation(
                "BLOCK_MANIFEST_INVALID",
                "Block manifest is not valid JSON or is missing a required field",
                &format!("{}: {e}", path.display()),
            )
        })?;

        if m.schema_version != BLOCK_SCHEMA_VERSION {
            return Err(validation(
                "BLOCK_SCHEMA_MISMATCH",
                "Block manifest schema_version is not supported by this binary",
                &format!(
                    "manifest declares {}, this build understands {}",
                    m.schema_version, BLOCK_SCHEMA_VERSION
                ),
            ));
        }

        let base = path.parent().unwrap_or(Path::new(".")).to_path_buf();
        let rel = |p: &Path| -> PathBuf {
            if p.is_absolute() { p.to_path_buf() } else { base.join(p) }
        };
        m.config = rel(&m.config);
        m.artifacts_dir = rel(&m.artifacts_dir);
        m.input = m.input.as_deref().map(rel);
        m.output = m.output.as_deref().map(rel);
        m.solution = m.solution.as_deref().map(rel);
        m.vault = m.vault.as_deref().map(rel);
        m.inputs = m.inputs.iter().map(|p| rel(p)).collect();
        Ok(m)
    }

    pub fn output_path(&self) -> PathBuf {
        self.output
            .clone()
            .unwrap_or_else(|| self.artifacts_dir.join(format!("{}.out.csv", self.shard_id)))
    }

    pub fn input_path(&self) -> Result<&Path, PipelineError> {
        self.input.as_deref().ok_or_else(|| {
            validation(
                "BLOCK_MANIFEST_INVALID",
                "Manifest is missing 'input'",
                &format!("block '{}' reads a shard CSV", self.block),
            )
        })
    }

    pub fn vault_path(&self) -> PathBuf {
        self.vault
            .clone()
            .unwrap_or_else(|| self.artifacts_dir.join("token_vault.json"))
    }

    pub fn status_path(&self) -> PathBuf {
        self.artifacts_dir.join(format!("{}.status.json", self.shard_id))
    }
}

// ── Shard I/O ────────────────────────────────────────────────────────────────

/// A shard held in memory: a header plus its rows, with the rid column located.
pub struct Shard {
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
    /// Index of the rid column in `headers`, when the AO stamped one.
    pub rid_idx: Option<usize>,
}

impl Shard {
    pub fn read(path: &Path, rid_col: &str) -> Result<Self, PipelineError> {
        use crate::pipeline::bootstrap::split_csv_line_basic;
        use std::io::{BufRead, BufReader};

        let file = fs::File::open(path).map_err(|e| {
            validation("IO_READ_FAILED", "Could not open shard", &format!("{}: {e}", path.display()))
        })?;
        let mut lines = BufReader::new(file).lines();
        let header_line = lines
            .next()
            .ok_or_else(|| validation("DATA_EMPTY", "Shard is empty", &path.display().to_string()))?
            .map_err(|e| validation("IO_READ_FAILED", "Failed reading shard header", &e.to_string()))?;
        let headers = split_csv_line_basic(&header_line);
        let rid_idx = headers.iter().position(|h| h == rid_col);

        let mut rows = Vec::new();
        for line in lines {
            let line =
                line.map_err(|e| validation("IO_READ_FAILED", "Failed reading shard row", &e.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }
            rows.push(split_csv_line_basic(&line));
        }
        Ok(Shard { headers, rows, rid_idx })
    }

    pub fn write(&self, path: &Path) -> Result<(), PipelineError> {
        use crate::pipeline::bootstrap::csv_row_to_line;
        use std::io::{BufWriter, Write};

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("csv.tmp");
        let mut w = BufWriter::new(fs::File::create(&tmp)?);
        w.write_all(csv_row_to_line(&self.headers).as_bytes())?;
        w.write_all(b"\n")?;
        for row in &self.rows {
            w.write_all(csv_row_to_line(row).as_bytes())?;
            w.write_all(b"\n")?;
        }
        w.flush()?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn column_index(&self, name: &str) -> Option<usize> {
        self.headers.iter().position(|h| h == name)
    }

    /// True when the block should act on this column at all.
    ///
    /// A column the AO did not route here is skipped, not an error — that is
    /// the whole point of column sharding. A column the AO *did* route here
    /// but that is missing from the CSV is an error, raised by the caller.
    pub fn routed(&self, manifest: &BlockManifest, column: &str) -> bool {
        if manifest.columns.is_empty() {
            return self.column_index(column).is_some();
        }
        manifest.columns.iter().any(|c| c == column)
    }
}

/// Resolves the index of a column the AO explicitly routed to this shard,
/// failing loudly when the shard does not actually carry it.
pub fn required_column_index(
    shard: &Shard,
    column: &str,
    op: &str,
) -> Result<usize, PipelineError> {
    shard.column_index(column).ok_or_else(|| {
        validation(
            "BLOCK_COLUMN_NOT_IN_SHARD",
            "A column routed to this shard is absent from the shard CSV",
            &format!("column '{column}' required by {op}"),
        )
    })
}

// ── Result reporting ─────────────────────────────────────────────────────────

/// What a block did, reported back to the AO in a shape the AO can act on
/// without reading logs.
#[derive(Debug, Default, Serialize)]
pub struct BlockReport {
    pub job_id: String,
    pub shard_id: String,
    pub block: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    /// Operations actually applied, as `"<op>:<column>"`.
    pub applied: Vec<String>,
    /// Operations in the config that this shard does not carry, and so were
    /// left for another shard.
    pub deferred: Vec<String>,
    pub rows_in: usize,
    pub rows_out: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

/// Runs a block body, writes `<artifacts_dir>/<shard_id>.status.json` in the
/// same `StatusPayload` shape the monolith emits, and returns the process exit
/// code. Errors are reported structurally, never as a bare panic, because the
/// AO reads status files to decide whether to retry or fail the job.
pub fn run_block<F>(block_name: &str, body: F) -> i32
where
    F: FnOnce(&BlockManifest) -> Result<BlockReport, PipelineError>,
{
    let manifest_path = match manifest_path_from_args() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("skald_{block_name}: {e}");
            return 2;
        }
    };

    let manifest = match BlockManifest::load(&manifest_path) {
        Ok(m) => m,
        Err(e) => {
            emit_orphan_error(block_name, &manifest_path, &e);
            return 1;
        }
    };

    if manifest.block != block_name {
        let e = validation(
            "BLOCK_MISMATCH",
            "Manifest targets a different block than this binary implements",
            &format!("manifest block='{}', binary='{block_name}'", manifest.block),
        );
        write_status(&manifest, status_for_error(&e));
        eprintln!("skald_{block_name}: {e}");
        return 1;
    }

    let _ = fs::create_dir_all(&manifest.artifacts_dir);

    match body(&manifest) {
        Ok(report) => {
            let payload = StatusPayload {
                status: "success".to_string(),
                phase: Some("done".to_string()),
                outputs: Some(serde_json::to_value(&report).unwrap_or(Value::Null)),
                error: None,
                log_file: manifest.status_path().display().to_string(),
            };
            write_status(&manifest, payload);
            0
        }
        Err(e) => {
            eprintln!("skald_{block_name}: {e}");
            write_status(&manifest, status_for_error(&e));
            1
        }
    }
}

fn manifest_path_from_args() -> Result<PathBuf, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--manifest" | "-m" => {
                return args
                    .get(i + 1)
                    .map(PathBuf::from)
                    .ok_or_else(|| "--manifest needs a path".to_string());
            }
            "--help" | "-h" => {
                return Err("usage: --manifest <path>  (or set SKALD_MANIFEST)".to_string());
            }
            other if !other.starts_with('-') => return Ok(PathBuf::from(other)),
            _ => i += 1,
        }
    }
    if let Ok(p) = std::env::var("SKALD_MANIFEST") {
        return Ok(PathBuf::from(p));
    }
    Err("no manifest given: pass --manifest <path> or set SKALD_MANIFEST".to_string())
}

fn status_for_error(e: &PipelineError) -> StatusPayload {
    let (code, message, details) = match e {
        PipelineError::Validation { code, message, details } => {
            (code.to_string(), message.clone(), details.clone())
        }
        PipelineError::Io(io) => (
            "IO_READ_FAILED".to_string(),
            "An I/O error occurred".to_string(),
            io.to_string(),
        ),
        PipelineError::Json(j) => (
            "CONFIG_PARSE_ERROR".to_string(),
            "Failed to parse JSON".to_string(),
            j.to_string(),
        ),
    };
    StatusPayload {
        status: "error".to_string(),
        phase: None,
        outputs: None,
        error: Some(ErrorPayload {
            suggested_fix: suggested_fix_for(&code).to_string(),
            http_status_code: http_status_for(&code),
            code,
            message,
            details,
        }),
        log_file: String::new(),
    }
}

fn write_status(manifest: &BlockManifest, payload: StatusPayload) {
    let _ = fs::create_dir_all(&manifest.artifacts_dir);
    if let Ok(body) = serde_json::to_string_pretty(&payload) {
        let _ = fs::write(manifest.status_path(), &body);
        println!("{body}");
    }
}

/// The manifest itself failed to load, so there is no `artifacts_dir` to write
/// into. Report on stdout beside the manifest so the AO still gets structure.
fn emit_orphan_error(block: &str, manifest_path: &Path, e: &PipelineError) {
    eprintln!("skald_{block}: {e}");
    let payload = status_for_error(e);
    if let Ok(body) = serde_json::to_string_pretty(&payload) {
        println!("{body}");
        if let Some(dir) = manifest_path.parent() {
            let _ = fs::write(dir.join(format!("{block}.status.json")), body);
        }
    }
}
