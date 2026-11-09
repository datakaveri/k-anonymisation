use crate::pipeline::anonymization::{LDiversity, normalize_categorical};
use crate::pipeline::connectors::{DataSink, DataSource, parse_data_sink, parse_data_source};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug)]
pub enum PipelineError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Validation { code: &'static str, message: String, details: String },
}

impl fmt::Display for PipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PipelineError::Io(e) => write!(f, "I/O error: {e}"),
            PipelineError::Json(e) => write!(f, "JSON error: {e}"),
            PipelineError::Validation { code, message, details } => {
                write!(f, "[{code}] {message}: {details}")
            }
        }
    }
}

impl Error for PipelineError {}

impl From<std::io::Error> for PipelineError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for PipelineError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

/// Per-column categorical generalization hierarchy.
/// `{ "column_name": { "leaf_value": ["level2", "level3", …], "*": ["fallback_level2", …] } }`
pub type HierarchyMap = HashMap<String, HashMap<String, Vec<String>>>;

#[derive(Debug, Clone)]
pub struct FreeTextAnonymizationConfig {
    pub enabled: bool,
    pub columns: Vec<String>,
    /// Optional path to a sanitized input file produced by the free-text
    /// anonymization stage. When present and enabled, the pipeline consumes
    /// this staged file instead of scanning `data/` for the raw input.
    pub staged_input_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub enable_k_anonymity: bool,
    /// "pass1" | "pass2" | "no_bounds"
    pub pass: String,
    /// k is optional — not required for pass1 (0 when absent).
    pub k: i64,
    /// l-diversity requirement on top of k, when configured.
    pub l_diversity: Option<LDiversity>,
    /// `key_directory` from the config, if set. The command line and
    /// `SKALD_KEYS` take precedence (see `cli::Paths::key_material_dir`).
    pub key_directory: Option<String>,
    /// Non-fatal config findings (ignored legacy keys) for the run log.
    pub warnings: Vec<String>,
    pub suppression_limit: f64,
    pub output_path: String,
    pub output_directory: String,
    pub suppress: Vec<String>,
    pub hashing_with_salt: Vec<String>,
    pub hashing_without_salt: Vec<String>,
    /// `shared_hash_salts`: reuse each column's `hashing_with_salt` salt from
    /// `<key dir>/tabular_hash_salts.json`, so the same column name hashes the
    /// same way across tables and runs that share a key directory. Off by
    /// default — a fresh salt per column per run.
    pub shared_hash_salts: bool,
    pub masking: Vec<Value>,
    pub encrypt: Vec<Value>,
    pub charcloak: Vec<String>,
    pub tokenization: Vec<Value>,
    pub numerical_qis: Vec<NumericalQiConfig>,
    pub categorical_qis: Vec<String>,
    pub categorical_hierarchies: HierarchyMap,
    pub size_factors: HashMap<String, i64>,
    pub source_json_config: PathBuf,
    /// Per-column non-uniform interval constraints: column → sorted list of (from, to) intervals
    pub qi_interval_constraints: HashMap<String, Vec<(i64, i64)>>,
    /// Fixed non-uniform bins: column → sorted list of (from, to) intervals.
    /// QIs listed here are excluded from the OLA-2 lattice search (bins are fixed)
    /// but still contribute to equivalence class keys in the histogram.
    pub fixed_bins: HashMap<String, Vec<(i64, i64)>>,
    /// Histogram-construction strategy.
    /// `Auto` applies the N·log₂N vs E decision rule at runtime.
    pub flow_mode: FlowMode,
    /// When true (default), compute the k × suppression_limit parameter grid
    /// in pass1 and no_bounds runs. Pass2 never computes it — pass1 already did.
    pub compute_param_grid: bool,
    /// Pass2 only: the generalization level per QI column, as copied from a
    /// pass1 parameter-grid cell's `generalization_node`. When set, pass2
    /// generalizes straight to this node and skips OLA-1, the histogram and
    /// OLA-2.
    pub generalization_node: Option<BTreeMap<String, i64>>,
    /// Optional, config-driven join keys for multi-sheet Excel inputs.
    /// When empty, sheets are auto-joined on shared column names (see
    /// `multitabular::resolve_input_csv`).
    pub sheet_joins: Vec<crate::pipeline::multitabular::SheetJoinSpec>,
    /// When true, also write the anonymized result back as a multi-sheet
    /// `.xlsx` workbook mirroring the original input sheets (only meaningful
    /// when the input was multi-sheet Excel joined via `sheet_joins`).
    pub restore_sheets: bool,
    /// Optional free-text anonymization handoff.
    pub free_text_anonymization: FreeTextAnonymizationConfig,
    /// Nested-JSON de-identification. When enabled this replaces the tabular
    /// flow outright rather than feeding it — see `nested_json`'s module docs.
    pub nested_json: crate::pipeline::nested_json::NestedJsonConfig,
    /// FHIR Bundle de-identification. Like `nested_json`, replaces the tabular
    /// flow outright — see `fhir_bundle`'s module docs.
    pub fhir_bundle: crate::pipeline::fhir_bundle::FhirBundleConfig,
    /// When true, delete leftover files from a previous run out of `output/`
    /// before this run starts (key material and the active log are kept).
    /// Defaults to false — stale files are only reported, never removed.
    pub clean_output: bool,
    /// Where this run reads its input from. Defaults to the filesystem, which
    /// is what every config written before connectors existed resolves to.
    pub input_source: DataSource,
    /// Where this run pushes its anonymized output, *in addition* to the files
    /// under `output/` — those are written either way.
    pub output_sink: DataSink,
}

/// Controls which histogram-building algorithm SKALD uses.
///
/// - `Auto`: use N·log₂N ≤ E to pick DIRECT (fast) or ORIGINAL (OLA-1 based).
/// - `Original`: always run OLA-1 + sparse histogram (previous behaviour).
/// - `Direct`: always skip OLA-1 and build the finest-granularity histogram directly.
#[derive(Debug, Clone, PartialEq)]
pub enum FlowMode {
    Auto,
    Original,
    Direct,
}

#[derive(Debug, Clone)]
pub struct NumericalQiConfig {
    pub column: String,
    pub scale: bool,
    pub s: i64,
    pub encode: bool,
    pub dtype: String,
}

#[derive(Debug, Serialize)]
pub struct StatusPayload {
    pub status: String,
    /// Pipeline phase at completion — "done" on success, the failing phase name on error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outputs: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorPayload>,
    pub log_file: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorPayload {
    pub code: String,
    pub message: String,
    pub details: String,
    pub suggested_fix: String,
    /// HTTP status code for UI/API consumers to use directly.
    pub http_status_code: u16,
}

/// Structured logger — writes timestamped, levelled lines to both stderr and
/// `<output_dir>/pipeline.log`. File is truncated at construction so each run
/// produces a fresh log. Flushes after every line so partial logs are readable
/// if the pipeline crashes.
pub struct Logger {
    file: Option<BufWriter<fs::File>>,
    start: Instant,
}

impl Logger {
    pub fn new(output_dir: &Path) -> Self {
        let _ = fs::create_dir_all(output_dir);
        let file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(output_dir.join("pipeline.log"))
            .ok()
            .map(BufWriter::new);
        Self { file, start: Instant::now() }
    }

    pub fn info(&mut self, phase: &str, msg: &str) {
        self.emit("INFO ", phase, msg);
    }
    pub fn warn(&mut self, phase: &str, msg: &str) {
        self.emit("WARN ", phase, msg);
    }
    pub fn error(&mut self, phase: &str, msg: &str) {
        self.emit("ERROR", phase, msg);
    }

    fn emit(&mut self, level: &str, phase: &str, msg: &str) {
        let ms = self.start.elapsed().as_millis();
        let line = format!("[+{ms:>6}ms] [{level}] [{phase:<18}] {msg}\n");
        eprint!("{line}");
        if let Some(f) = &mut self.file {
            let _ = f.write_all(line.as_bytes());
            let _ = f.flush();
        }
    }
}

// ── Error-code helpers ───────────────────────────────────────────────────────

/// Human-readable fix hint for every error code — shown directly in the UI.
pub fn suggested_fix_for(code: &str) -> &'static str {
    match code {
        "CONFIG_NOT_FOUND" => {
            "Create a config/ directory and add a JSON configuration file. \
             Refer to the schema reference for the required fields."
        }
        "CONFIG_PARSE_ERROR" => {
            "Validate your config JSON with a linter. \
             Ensure all brackets and quotes are balanced."
        }
        "CONFIG_MISSING_FIELD" => {
            "The config file is missing a required field. \
             Required fields: data_type, quasi_identifiers, k_anonymize, output_path."
        }
        "CONFIG_INVALID" | "CONFIG_INVALID_VALUE" => {
            "Review config field values: k must be ≥ 1, suppression_limit must be \
             0.0–1.0, size factors must be positive integers."
        }
        "DATA_DIR_MISSING" | "DATA_MISSING" => "Create a data/ directory and place exactly one CSV file inside it.",
        "DATA_NO_CSV" => {
            "No CSV, JSON, or Excel file found in data/. \
             Add exactly one .csv, .json, or .xlsx/.xls file."
        }
        "DATA_AMBIGUOUS_INPUT" => {
            "More than one input data file found in data/. \
             Keep exactly one .csv, .json, or .xlsx/.xls file."
        }
        "DATA_EMPTY" => {
            "The input file exists but is empty. \
             Ensure it has a header row and at least one data row."
        }
        "DATA_JSON_INVALID" => {
            "JSON input must be a top-level array of flat objects, one per record. \
             Example: [{\"col1\": \"val\"}, {\"col1\": \"val2\"}]."
        }
        "DATA_XLSX_INVALID" => {
            "The Excel workbook could not be read, or a sheet_joins step \
             referenced an unknown sheet or a column missing from one of the sheets. \
             Verify the workbook opens correctly and that sheet_joins names and \
             'on' columns match the actual sheet headers."
        }
        "DATA_COLUMN_MISSING" => {
            "A quasi-identifier column was not found in the CSV header. \
             Column names are case-sensitive — verify they match exactly."
        }
        "PREPROCESS_COLUMN_MISSING" | "PREPROCESSING_FAILED" => {
            "A preprocessing target column was not found in the CSV header. \
             Check suppress, masking, hashing, tokenization, fpe, encrypt, \
             charcloak, and free-text handoff column names against the actual CSV header."
        }
        "PREPROCESS_CONFIG_INVALID" => {
            "A preprocessing config entry is malformed. \
             Each entry must be an object with a 'column' field and valid parameters."
        }
        "ANON_INFEASIBLE" | "GENERALIZATION_FAILED" => {
            "k-anonymity cannot be satisfied with the current settings. \
             Try: (1) increase suppression_limit (e.g. to 0.05), \
             (2) decrease k, \
             (3) add more records, \
             (4) increase size factors for numerical QIs."
        }
        "SUPPRESSION_LIMIT_EXCEEDED" => {
            "The written output suppressed more records than suppression_limit allows, \
             so no output was kept. With a generalization_node, the input data has \
             probably changed since pass1 — rerun pass1 and pick a node from the \
             fresh grid, or drop generalization_node to let OLA-2 choose."
        }
        "CONFIG_UNKNOWN_KEY" => {
            "The config contains a key SKALD does not read. A misspelt key would \
             silently disable a protection, so unknown keys are refused. Fix the \
             spelling, or prefix the key with '_' to keep it as a comment."
        }
        "DATA_MALFORMED_ROW" => {
            "A CSV row does not have the same number of fields as the header, a quoted \
             field is never closed, or the file is not UTF-8. Fix the input file — \
             misaligned rows would put values in the wrong columns."
        }
        "LATTICE_TOO_LARGE" => {
            "Too many generalization combinations to search. Use fewer \
             quasi-identifiers, larger size factors, or qi_constraints / fixed_bins \
             with fewer levels."
        }
        "KEY_MATERIAL_IN_OUTPUT" => {
            "Key material (keys, salts, token vaults) must not live in the release \
             directory. Move the listed files into the key directory (--keys, \
             SKALD_KEYS or key_directory; default <root>/keys) and rerun."
        }
        "RNG_UNAVAILABLE" => {
            "The operating system's random number generator could not be read, so no \
             key or salt was generated. Run SKALD where /dev/urandom (getrandom) works."
        }
        "FPE_VALUE_UNSUPPORTED" => {
            "Format-preserving encryption only handles ASCII letters and digits; a value \
             contains letters or digits in another script. Use encrypt without \
             format_preserving, tokenization or hashing_with_salt for this column."
        }
        "FPE_DOMAIN_TOO_SMALL" => {
            "A value is too short to format-preserving-encrypt safely (fewer than a \
             million possible values). Use tokenization or hashing_with_salt for this column."
        }
        "ENCRYPTION_FAILED" => {
            "A value could not be encrypted or decrypted. Check that the key files in the \
             key directory belong to this dataset."
        }
        "TOKEN_SPACE_EXHAUSTED" => {
            "The token vault is nearly full for the configured number of digits. \
             Increase tokenization 'digits' for this column."
        }
        "ANON_NO_QIS" => {
            "No quasi-identifiers are defined. \
             Add at least one entry to quasi_identifiers.numerical \
             or quasi_identifiers.categorical in the config."
        }
        "ENCODING_FAILED" => {
            "A data encoding error occurred. \
             Check that numerical QI columns contain only numeric values and no blanks."
        }
        "IO_READ_FAILED" => {
            "A required file could not be read. \
             Check that the file exists and the process has read permissions."
        }
        "IO_WRITE_FAILED" => {
            "A file could not be written. \
             Check disk space and write permissions for the output/ and chunks/ directories."
        }
        "IO_PERMISSION_DENIED" => {
            "Permission denied on a file or directory. \
             Run the pipeline with appropriate filesystem permissions."
        }
        "CLI_INVALID_ARGUMENT" => {
            "The command line could not be understood. \
             Run `skald_pipeline --help` for the accepted flags."
        }
        "DB_CONFIG_INVALID" => {
            "Review the config's 'input' / 'output_sink' section: a postgres input needs \
             a connection (dsn, or database plus host/user) and one of 'table' or 'query'; \
             a postgres sink needs a 'table'."
        }
        "ENV_VAR_MISSING" => {
            "The config references an environment variable with ${VAR} that is not set. \
             Export it before running, or write ${VAR:-default} to supply a fallback."
        }
        "DB_CONNECT_FAILED" => {
            "Could not reach the database. Check host, port, credentials and sslmode, \
             and that this machine is allowed to connect (pg_hba.conf, firewall)."
        }
        "DB_READ_FAILED" => {
            "The input query failed on the server. Verify the table or SELECT is valid \
             and that the connecting user has SELECT on it."
        }
        "DB_WRITE_FAILED" => {
            "The anonymized rows could not be loaded. Verify the destination table's \
             columns match the output, and that the user has INSERT (plus CREATE for \
             mode 'create'/'replace') on the schema. Nothing was committed."
        }
        "DB_NO_ROWS" => {
            "The configured query returned no rows. Check the table name, any WHERE \
             clause, and that the connecting user can see the rows."
        }
        "INTERNAL_ERROR" => {
            "An unexpected internal error occurred. \
             Check output/pipeline.log for a full trace and contact support."
        }
        _ => "Review the pipeline configuration and input data, then retry.",
    }
}

/// HTTP status code for each error code — for UI/API response routing.
pub fn http_status_for(code: &str) -> u16 {
    match code {
        "CONFIG_NOT_FOUND"
        | "CONFIG_PARSE_ERROR"
        | "CONFIG_MISSING_FIELD"
        | "CONFIG_INVALID"
        | "CONFIG_INVALID_VALUE"
        | "CLI_INVALID_ARGUMENT"
        | "CONFIG_UNKNOWN_KEY"
        | "DB_CONFIG_INVALID"
        | "ENV_VAR_MISSING" => 400,

        "DATA_DIR_MISSING"
        | "DATA_MISSING"
        | "DATA_NO_CSV"
        | "DATA_AMBIGUOUS_INPUT"
        | "DATA_EMPTY"
        | "DATA_JSON_INVALID"
        | "DATA_XLSX_INVALID"
        | "DATA_COLUMN_MISSING"
        | "PREPROCESS_COLUMN_MISSING"
        | "PREPROCESSING_FAILED"
        | "PREPROCESS_CONFIG_INVALID"
        | "ANON_INFEASIBLE"
        | "SUPPRESSION_LIMIT_EXCEEDED"
        | "ANON_NO_QIS"
        | "GENERALIZATION_FAILED"
        | "ENCODING_FAILED"
        | "DATA_MALFORMED_ROW"
        | "LATTICE_TOO_LARGE"
        | "KEY_MATERIAL_IN_OUTPUT"
        | "FPE_VALUE_UNSUPPORTED"
        | "FPE_DOMAIN_TOO_SMALL"
        | "TOKEN_SPACE_EXHAUSTED"
        | "DB_NO_ROWS" => 422,

        "RNG_UNAVAILABLE" | "ENCRYPTION_FAILED" => 500,

        "IO_READ_FAILED" | "IO_WRITE_FAILED" | "IO_PERMISSION_DENIED" | "INTERNAL_ERROR" => 500,

        // The database is a dependency this process talks to, not part of it —
        // a caller retrying against a healthy server is the right response.
        "DB_CONNECT_FAILED" | "DB_READ_FAILED" | "DB_WRITE_FAILED" => 502,

        _ => 500,
    }
}

/// Wrap an `std::io::Error` with the operation and file path that caused it,
/// using the appropriate error code based on the IO error kind.
pub fn io_err(operation: &'static str, path: &str, e: std::io::Error) -> PipelineError {
    let code: &'static str = match e.kind() {
        std::io::ErrorKind::NotFound => "IO_READ_FAILED",
        std::io::ErrorKind::PermissionDenied => "IO_PERMISSION_DENIED",
        _ => {
            if operation.starts_with("write") || operation.starts_with("creat") {
                "IO_WRITE_FAILED"
            } else {
                "IO_READ_FAILED"
            }
        }
    };
    PipelineError::Validation { code, message: format!("Failed to {operation}"), details: format!("{path}: {e}") }
}

pub fn validation(code: &'static str, message: &str, details: &str) -> PipelineError {
    PipelineError::Validation { code, message: message.to_string(), details: details.to_string() }
}

pub fn split_csv_line_basic(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes => {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            }
            '"' => in_quotes = true,
            ',' if !in_quotes => {
                fields.push(std::mem::take(&mut field));
            }
            _ => field.push(c),
        }
    }
    fields.push(field);
    fields
}

/// Whether a record is still inside a quoted field after `text`, starting from
/// `in_quotes`. Follows exactly the quoting rules of [`split_csv_line_basic`].
fn quote_state_after(text: &str, mut in_quotes: bool) -> bool {
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '"' {
            continue;
        }
        if in_quotes && chars.peek() == Some(&'"') {
            chars.next();
        } else {
            in_quotes = !in_quotes;
        }
    }
    in_quotes
}

/// Streams CSV records from a reader, keeping a quoted field that spans
/// several physical lines in one record.
///
/// Every CSV reader in the tabular flow must go through this. Reading physical
/// lines instead splits a record whose free-text field holds a line break, and
/// the fragments land in the wrong columns — past suppression, hashing and
/// generalisation, which all address fields by position.
pub struct CsvRecords<R: BufRead> {
    reader: R,
    source: String,
    line_no: usize,
}

impl<R: BufRead> CsvRecords<R> {
    /// `source` names the input in error messages (a path, never data).
    pub fn new(reader: R, source: &str) -> Self {
        Self { reader, source: source.to_string(), line_no: 0 }
    }

    /// Physical line on which the last returned record ended (1-based).
    pub fn line_no(&self) -> usize {
        self.line_no
    }

    /// The next record, or `None` at end of input. Blank lines are skipped.
    pub fn next_record(&mut self) -> Result<Option<Vec<String>>, PipelineError> {
        loop {
            let mut record = String::new();
            let mut in_quotes = false;
            loop {
                let mut line = String::new();
                let n = self.reader.read_line(&mut line).map_err(|e| {
                    validation(
                        "DATA_MALFORMED_ROW",
                        "Failed reading CSV (is it UTF-8?)",
                        &format!("{} after line {}: {e}", self.source, self.line_no),
                    )
                })?;
                if n == 0 {
                    if in_quotes {
                        return Err(validation(
                            "DATA_MALFORMED_ROW",
                            "Unterminated quoted field at end of CSV",
                            &format!("{}: record starting before line {}", self.source, self.line_no),
                        ));
                    }
                    if record.is_empty() {
                        return Ok(None);
                    }
                    break;
                }
                self.line_no += 1;
                in_quotes = quote_state_after(&line, in_quotes);
                record.push_str(&line);
                if !in_quotes {
                    break;
                }
            }
            if record.ends_with('\n') {
                record.pop();
                if record.ends_with('\r') {
                    record.pop();
                }
            }
            if record.trim().is_empty() {
                continue;
            }
            return Ok(Some(split_csv_line_basic(&record)));
        }
    }

    /// Like [`Self::next_record`], but a record whose field count differs
    /// from `width` is an error rather than a silently misaligned row.
    pub fn next_record_of_width(&mut self, width: usize) -> Result<Option<Vec<String>>, PipelineError> {
        let Some(fields) = self.next_record()? else { return Ok(None) };
        if fields.len() != width {
            return Err(validation(
                "DATA_MALFORMED_ROW",
                "CSV row has a different number of fields than the header",
                &format!("{} line {}: {} field(s), header has {}", self.source, self.line_no, fields.len(), width),
            ));
        }
        Ok(Some(fields))
    }
}

/// Opens `path` as CSV and reads its header record.
pub fn open_csv(path: &Path) -> Result<(Vec<String>, CsvRecords<BufReader<fs::File>>), PipelineError> {
    let file = fs::File::open(path).map_err(|e| io_err("open CSV file", &path.display().to_string(), e))?;
    let mut records = CsvRecords::new(BufReader::new(file), &path.display().to_string());
    let header = records
        .next_record()?
        .ok_or_else(|| validation("DATA_EMPTY", "CSV file contains no header row", &path.display().to_string()))?;
    Ok((header, records))
}

/// Quotes a single CSV field per RFC 4180 — wraps in `"..."` and doubles any
/// embedded quotes only when the field contains a comma, quote, or line break.
pub fn csv_quote_field(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Serializes a row of fields to a CSV line, quoting fields as needed.
pub fn csv_row_to_line(fields: &[String]) -> String {
    fields.iter().map(|f| csv_quote_field(f)).collect::<Vec<_>>().join(",")
}

pub fn ensure_output_dir(path: &Path) -> Result<(), PipelineError> {
    fs::create_dir_all(path)?;
    Ok(())
}

/// Every `*.json` in `config_dir`, sorted by name.
///
/// A bundle can ship several configs — one per dataset — so which of them a
/// bare run picks is worth being able to report, not just decide.
pub fn list_json_configs(config_dir: &Path) -> Result<Vec<PathBuf>, PipelineError> {
    if !config_dir.is_dir() {
        return Err(validation("CONFIG_NOT_FOUND", "Config directory not found", &config_dir.display().to_string()));
    }
    let mut files: Vec<PathBuf> = fs::read_dir(config_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    files.sort();
    Ok(files)
}

pub fn find_first_json_config(config_dir: &Path) -> Result<PathBuf, PipelineError> {
    list_json_configs(config_dir)?.into_iter().next().ok_or_else(|| {
        validation("CONFIG_NOT_FOUND", "No JSON config file found in config/", "config/ directory is empty")
    })
}

/// Keys a data_type section may contain. Anything else is refused: a
/// misspelt `"suppres"` or `"k_anonymity"` used to be ignored silently, which
/// disabled the protection the operator thought they had configured.
const KNOWN_SECTION_KEYS: &[&str] = &[
    // output, run control
    "output_path",
    "output_directory",
    "key_directory",
    "pass",
    "clean_output",
    "compute_parameter_grid",
    "flow_mode",
    "generalization_node",
    // k-anonymity
    "k_anonymize",
    "suppression_limit",
    "quasi_identifiers",
    "categorical_hierarchies",
    "size",
    "qi_constraints",
    "fixed_bins",
    "l_diversity",
    // column techniques
    "suppress",
    "hashing_with_salt",
    "hashing_without_salt",
    "shared_hash_salts",
    "masking",
    "encrypt",
    "charcloak",
    "tokenization",
    // inputs and sinks
    "sheet_joins",
    "restore_sheets",
    "free_text_anonymization",
    "input",
    "output_sink",
    // nested JSON / FHIR flows
    "nested_json",
    "fhir_bundle",
    "input_path",
    "dry_run",
    "default_action",
    "keep",
    "free_text",
    "filename",
    "code_rules",
    "propagation",
    "hash_strip_prefixes",
    // annotation only: lists columns deliberately left in clear
    "insensitive_columns",
    // legacy, accepted only when empty
    "fpe",
];

fn check_section_keys(section: &Value, warnings: &mut Vec<String>) -> Result<(), PipelineError> {
    let Some(obj) = section.as_object() else {
        return Err(validation("CONFIG_INVALID", "The data_type section must be a JSON object", ""));
    };
    for (key, value) in obj {
        if key.starts_with('_') {
            continue; // comment
        }
        if key == "enable_l_diversity" {
            return Err(validation(
                "CONFIG_UNKNOWN_KEY",
                "enable_l_diversity is not a SKALD setting",
                "Configure l-diversity with \"l_diversity\": {\"l\": 2, \"sensitive_attributes\": [\"<column>\"]}",
            ));
        }
        if !KNOWN_SECTION_KEYS.contains(&key.as_str()) {
            return Err(validation("CONFIG_UNKNOWN_KEY", "Unknown config key", key));
        }
        if key == "fpe" {
            if value.as_array().is_some_and(|a| !a.is_empty()) {
                return Err(validation(
                    "CONFIG_INVALID_VALUE",
                    "The legacy fpe section is no longer supported, so its columns would be released in clear",
                    "Use \"encrypt\": [{\"<column>\": {\"format_preserving\": true}}]",
                ));
            }
            warnings.push("The empty legacy \"fpe\" key has no effect and can be removed".to_string());
        }
        if key == "output_directory" {
            warnings.push(
                "output_directory no longer decides where key material is stored; use key_directory or --keys"
                    .to_string(),
            );
        }
    }
    Ok(())
}

/// A technique's column list. Every entry must be a string: a non-string
/// entry used to be dropped, leaving that column untouched.
fn string_list(section: &Value, key: &str) -> Result<Vec<String>, PipelineError> {
    match section.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str().map(str::to_string).ok_or_else(|| {
                    validation("CONFIG_INVALID_VALUE", "Expected a list of column names", &format!("{key}: {v}"))
                })
            })
            .collect(),
        Some(other) => {
            Err(validation("CONFIG_INVALID_VALUE", "Expected a list of column names", &format!("{key}: {other}")))
        }
    }
}

/// `"l_diversity": {"l": 2, "sensitive_attributes": ["Diagnosis"]}` — every
/// published class must hold at least `l` distinct values of each sensitive
/// attribute (distinct l-diversity).
fn parse_l_diversity(
    section: &Value,
    numerical_qis: &[NumericalQiConfig],
    categorical_qis: &[String],
    suppress: &[String],
) -> Result<Option<LDiversity>, PipelineError> {
    let Some(block) = section.get("l_diversity") else { return Ok(None) };
    let invalid = |msg: &str| validation("CONFIG_INVALID_VALUE", msg, &block.to_string());
    let l = block
        .get("l")
        .and_then(Value::as_i64)
        .filter(|l| *l >= 1)
        .ok_or_else(|| invalid("l_diversity.l must be a whole number ≥ 1"))? as usize;
    let attrs: Vec<String> = block
        .get("sensitive_attributes")
        .and_then(Value::as_array)
        .and_then(|a| a.iter().map(|v| v.as_str().map(str::to_string)).collect::<Option<Vec<_>>>())
        .filter(|a| !a.is_empty())
        .ok_or_else(|| invalid("l_diversity.sensitive_attributes must be a non-empty list of column names"))?;
    for a in &attrs {
        if numerical_qis.iter().any(|q| &q.column == a) || categorical_qis.contains(a) {
            return Err(invalid(&format!("{a} is both a quasi-identifier and a sensitive attribute")));
        }
        if suppress.contains(a) {
            return Err(invalid(&format!("{a} is suppressed, so it cannot be a sensitive attribute")));
        }
    }
    Ok((l > 1).then_some(LDiversity { l, sensitive_attributes: attrs }))
}

pub fn parse_runtime_config(config_path: &Path) -> Result<RuntimeConfig, PipelineError> {
    let raw = fs::read_to_string(config_path)?;
    let root: Value = serde_json::from_str(&raw)?;

    let data_type = root.get("data_type").and_then(Value::as_str).ok_or_else(|| {
        validation("CONFIG_MISSING_FIELD", "Required field 'data_type' is absent", &config_path.display().to_string())
    })?;

    let section = root.get(data_type).ok_or_else(|| {
        validation(
            "CONFIG_MISSING_FIELD",
            "Config section for data_type not found",
            &format!("No section named '{}' in config", data_type),
        )
    })?;
    let mut warnings = Vec::new();
    check_section_keys(section, &mut warnings)?;

    let output_path = section.get("output_path").and_then(Value::as_str).unwrap_or("generalized.csv").to_string();

    let output_directory = section.get("output_directory").and_then(Value::as_str).unwrap_or("output").to_string();

    let suppress = string_list(section, "suppress")?;

    let hashing_with_salt = string_list(section, "hashing_with_salt")?;

    let hashing_without_salt = string_list(section, "hashing_without_salt")?;

    let shared_hash_salts = match section.get("shared_hash_salts") {
        None | Some(Value::Null) => false,
        Some(v) => v.as_bool().ok_or_else(|| {
            validation("CONFIG_INVALID_VALUE", "shared_hash_salts must be true or false", &format!("got {v}"))
        })?,
    };

    let masking = section.get("masking").and_then(Value::as_array).cloned().unwrap_or_default();

    let encrypt = section.get("encrypt").and_then(Value::as_array).cloned().unwrap_or_default();

    let charcloak = string_list(section, "charcloak")?;

    let tokenization = section.get("tokenization").and_then(Value::as_array).cloned().unwrap_or_default();

    let suppression_limit = match section.get("suppression_limit") {
        None | Some(Value::Null) => 0.0,
        Some(v) => v.as_f64().filter(|s| (0.0..=1.0).contains(s)).ok_or_else(|| {
            validation(
                "CONFIG_INVALID_VALUE",
                "suppression_limit must be a number between 0 and 1",
                &format!("got {v} — it is a fraction of records, e.g. 0.05 for 5%"),
            )
        })?,
    };

    let pass = match section.get("pass") {
        None | Some(Value::Null) => "no_bounds".to_string(),
        Some(Value::String(p)) if ["pass1", "pass2", "no_bounds"].contains(&p.as_str()) => p.clone(),
        Some(other) => {
            return Err(validation(
                "CONFIG_INVALID_VALUE",
                "pass must be \"pass1\", \"pass2\" or \"no_bounds\"",
                &format!("got {other}"),
            ));
        }
    };

    // k is a privacy parameter: it is never defaulted and never coerced from
    // a string. `5.0` is accepted as 5; `5.5`, `"5"`, `0` and a missing `k`
    // inside a present k_anonymize block are errors.
    let k = match section.get("k_anonymize") {
        None => 0,
        Some(block) => {
            let raw = block.get("k").ok_or_else(|| {
                validation(
                    "CONFIG_MISSING_FIELD",
                    "k_anonymize.k is required",
                    "Add \"k_anonymize\": {\"k\": <whole number ≥ 1>}",
                )
            })?;
            raw.as_i64()
                .or_else(|| raw.as_f64().filter(|f| f.fract() == 0.0 && f.abs() < 1e15).map(|f| f as i64))
                .filter(|k| *k >= 1)
                .ok_or_else(|| {
                    validation(
                        "CONFIG_INVALID_VALUE",
                        "k_anonymize.k must be a whole number ≥ 1",
                        &format!("got {raw}"),
                    )
                })?
        }
    };

    // Per-QI non-uniform interval constraints
    // Config shape: "qi_constraints": { "Age": { "intervals": [{"from":1,"to":10}, ...] } }
    let mut qi_interval_constraints: HashMap<String, Vec<(i64, i64)>> = HashMap::new();
    if let Some(obj) = section.get("qi_constraints").and_then(Value::as_object) {
        for (col, constraint) in obj {
            if let Some(arr) = constraint.get("intervals").and_then(Value::as_array) {
                let intervals: Vec<(i64, i64)> = arr
                    .iter()
                    .filter_map(|iv| {
                        let from = iv.get("from")?.as_i64()?;
                        let to = iv.get("to")?.as_i64()?;
                        if to >= from { Some((from, to)) } else { None }
                    })
                    .collect();
                if !intervals.is_empty() {
                    qi_interval_constraints.insert(col.clone(), intervals);
                }
            }
        }
    }

    // Fixed non-uniform bins — QI is excluded from lattice search but keys ECs in histogram.
    // Config shape: "fixed_bins": { "Age": [{"from": 0, "to": 18}, {"from": 19, "to": 35}] }
    let mut fixed_bins: HashMap<String, Vec<(i64, i64)>> = HashMap::new();
    if let Some(obj) = section.get("fixed_bins").and_then(Value::as_object) {
        for (col, arr_val) in obj {
            if let Some(arr) = arr_val.as_array() {
                let intervals: Vec<(i64, i64)> = arr
                    .iter()
                    .filter_map(|iv| {
                        let from = iv.get("from")?.as_i64()?;
                        let to = iv.get("to")?.as_i64()?;
                        if to >= from { Some((from, to)) } else { None }
                    })
                    .collect();
                if !intervals.is_empty() {
                    fixed_bins.insert(col.clone(), intervals);
                }
            }
        }
    }

    let mut numerical_qis = Vec::new();
    let mut categorical_qis = Vec::new();

    if let Some(qis) = section.get("quasi_identifiers") {
        if let Some(nums) = qis.get("numerical").and_then(Value::as_array) {
            for n in nums {
                let column = n.get("column").and_then(Value::as_str).filter(|c| !c.is_empty()).ok_or_else(|| {
                    validation(
                        "CONFIG_INVALID_VALUE",
                        "Every quasi_identifiers.numerical entry needs a \"column\"",
                        &n.to_string(),
                    )
                })?;
                for legacy in ["scale", "s", "encode", "type"] {
                    if n.get(legacy).is_some() {
                        warnings.push(format!(
                            "quasi_identifiers.numerical[{column}].{legacy} has no effect in the Rust pipeline and is ignored"
                        ));
                    }
                }
                numerical_qis.push(NumericalQiConfig {
                    column: column.to_string(),
                    scale: n.get("scale").and_then(Value::as_bool).unwrap_or(false),
                    s: n.get("s").and_then(Value::as_i64).unwrap_or(0),
                    encode: n.get("encode").and_then(Value::as_bool).unwrap_or(false),
                    dtype: n.get("type").and_then(Value::as_str).unwrap_or("int").to_string(),
                });
            }
        }
        if let Some(cats) = qis.get("categorical").and_then(Value::as_array) {
            for c in cats {
                if let Some(col) = c.get("column").and_then(Value::as_str) {
                    categorical_qis.push(col.to_string());
                } else if let Some(col) = c.as_str() {
                    categorical_qis.push(col.to_string());
                }
            }
        }
    }

    let mut categorical_hierarchies: HierarchyMap = HashMap::new();
    if let Some(hier_obj) = section.get("categorical_hierarchies").and_then(Value::as_object) {
        for (col, col_val) in hier_obj {
            if let Some(col_obj) = col_val.as_object() {
                // Leaf keys are normalised exactly as data values are before
                // lookup, so `"M "` in the config matches `"M"` in the data.
                let mut col_map: HashMap<String, Vec<String>> = HashMap::new();
                for (leaf, levels_val) in col_obj {
                    let levels = levels_val
                        .as_array()
                        .and_then(|a| a.iter().map(|v| v.as_str().map(str::to_string)).collect::<Option<Vec<_>>>())
                        .ok_or_else(|| {
                            validation(
                                "CONFIG_INVALID_VALUE",
                                "categorical_hierarchies ladders must be arrays of strings",
                                &format!("{col}.{leaf}"),
                            )
                        })?;
                    let key = if leaf == "*" { leaf.clone() } else { normalize_categorical(leaf) };
                    if col_map.insert(key, levels).is_some() {
                        return Err(validation(
                            "CONFIG_INVALID_VALUE",
                            "categorical_hierarchies has two leaves that differ only by surrounding whitespace or Unicode form",
                            &format!("{col}.{leaf}"),
                        ));
                    }
                }
                if categorical_hierarchies.insert(col.trim().to_lowercase(), col_map).is_some() {
                    return Err(validation(
                        "CONFIG_INVALID_VALUE",
                        "categorical_hierarchies names the same column twice (column keys are case-insensitive)",
                        col,
                    ));
                }
            }
        }
    }

    let mut size_factors = HashMap::new();
    if let Some(obj) = section.get("size").and_then(Value::as_object) {
        for (k, v) in obj {
            let iv = v.as_i64().filter(|f| *f >= 1).ok_or_else(|| {
                validation("CONFIG_INVALID_VALUE", "size factors must be whole numbers ≥ 1", &format!("size.{k} = {v}"))
            })?;
            size_factors.insert(k.clone(), iv);
        }
    }

    let has_k_anonymize = section.get("k_anonymize").is_some();
    let has_qis = !numerical_qis.is_empty() || !categorical_qis.is_empty();
    // Quasi-identifiers with no k_anonymize block used to switch the run to
    // preprocess-only and publish every QI untouched. A config that names QIs
    // means them to be protected.
    if has_qis && !has_k_anonymize && pass != "pass1" {
        return Err(validation(
            "CONFIG_MISSING_FIELD",
            "quasi_identifiers are configured but k_anonymize is missing",
            "Add \"k_anonymize\": {\"k\": <whole number ≥ 1>} (or remove quasi_identifiers for a preprocess-only run)",
        ));
    }
    if !hashing_without_salt.is_empty() {
        return Err(validation(
            "CONFIG_INVALID_VALUE",
            "hashing_without_salt is not supported",
            "Unsalted SHA-256 of an identifier can be reversed by enumerating every possible value \
             (phone and Aadhaar numbers take seconds to hours) — use hashing_with_salt",
        ));
    }
    let l_diversity = parse_l_diversity(section, &numerical_qis, &categorical_qis, &suppress)?;

    let flow_mode = match section.get("flow_mode") {
        None | Some(Value::Null) => FlowMode::Auto,
        Some(Value::String(s)) if s.eq_ignore_ascii_case("auto") => FlowMode::Auto,
        Some(Value::String(s)) if s.eq_ignore_ascii_case("original") => FlowMode::Original,
        Some(Value::String(s)) if s.eq_ignore_ascii_case("direct") => FlowMode::Direct,
        Some(other) => {
            return Err(validation(
                "CONFIG_INVALID_VALUE",
                "flow_mode must be \"auto\", \"original\" or \"direct\"",
                &format!("got {other}"),
            ));
        }
    };

    let sheet_joins = crate::pipeline::multitabular::parse_sheet_joins(section)?;
    let restore_sheets = section.get("restore_sheets").and_then(Value::as_bool).unwrap_or(false);
    let free_text_anonymization = {
        let block = section.get("free_text_anonymization").and_then(Value::as_object).cloned().unwrap_or_default();
        let enabled = block.get("enabled").and_then(Value::as_bool).unwrap_or(false);
        let columns = block
            .get("columns")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect::<Vec<_>>())
            .unwrap_or_default();
        let staged_input_path =
            block.get("staged_input_path").and_then(Value::as_str).filter(|s| !s.trim().is_empty()).map(PathBuf::from);

        if enabled && columns.is_empty() {
            return Err(validation(
                "CONFIG_INVALID_VALUE",
                "free_text_anonymization.enabled requires at least one column",
                "Add one or more entries under free_text_anonymization.columns",
            ));
        }

        FreeTextAnonymizationConfig { enabled, columns, staged_input_path }
    };
    let nested_json = crate::pipeline::nested_json::parse_nested_json(section)?;
    let fhir_bundle = crate::pipeline::fhir_bundle::parse_fhir_bundle(section)?;
    if nested_json.enabled && fhir_bundle.enabled {
        return Err(validation(
            "CONFIG_INVALID_VALUE",
            "nested_json and fhir_bundle are both enabled",
            "They are separate flows over different input shapes — enable one per config",
        ));
    }
    let clean_output = section.get("clean_output").and_then(Value::as_bool).unwrap_or(false);

    let generalization_node = match section.get("generalization_node") {
        None | Some(Value::Null) => None,
        Some(Value::Object(obj)) => {
            let mut node = BTreeMap::new();
            for (col, level) in obj {
                let level = level.as_i64().filter(|l| *l >= 1).ok_or_else(|| {
                    validation(
                        "CONFIG_INVALID_VALUE",
                        "generalization_node levels must be integers ≥ 1",
                        &format!("generalization_node.{col}"),
                    )
                })?;
                node.insert(col.clone(), level);
            }
            Some(node)
        }
        Some(_) => {
            return Err(validation(
                "CONFIG_INVALID_VALUE",
                "generalization_node must be an object of column → level",
                "Copy a parameter_grid cell's generalization_node from the pass1 output",
            ));
        }
    };

    // A sink that names no connection of its own writes back to the database
    // the input was read from — the common "anonymize this table into that one"
    // case, which should not have to repeat the credentials.
    let input_source = parse_data_source(section)?;
    let inherited_connection = match &input_source {
        DataSource::Postgres(read) => Some(read.connection.clone()),
        DataSource::Files => None,
    };
    let output_sink = parse_data_sink(section, inherited_connection.as_ref())?;

    Ok(RuntimeConfig {
        // Pass1 exists to produce the parameter grid, and k is chosen from it
        // afterwards, so pass1 needs QIs but not a k_anonymize block.
        enable_k_anonymity: has_qis,
        pass,
        k,
        l_diversity,
        key_directory: section.get("key_directory").and_then(Value::as_str).map(str::to_string),
        warnings,
        suppression_limit,
        output_path,
        output_directory,
        suppress,
        hashing_with_salt,
        hashing_without_salt,
        shared_hash_salts,
        masking,
        encrypt,
        charcloak,
        tokenization,
        numerical_qis,
        categorical_qis,
        categorical_hierarchies,
        size_factors,
        source_json_config: config_path.to_path_buf(),
        qi_interval_constraints,
        fixed_bins,
        flow_mode,
        compute_param_grid: section.get("compute_parameter_grid").and_then(Value::as_bool).unwrap_or(true),
        generalization_node,
        sheet_joins,
        restore_sheets,
        free_text_anonymization,
        nested_json,
        fhir_bundle,
        clean_output,
        input_source,
        output_sink,
    })
}

/// Files in `output/` a run must never delete: the log it is currently writing,
/// and any key material — removing keys would make output encrypted by an
/// earlier run unrecoverable.
fn is_protected_output(name: &str) -> bool {
    name == "pipeline.log" || name.contains("keys") || name.contains("vault") || name.contains("salt")
}

/// Per-run artifacts every successful run rewrites, so their presence from an
/// earlier run is never surprising and isn't worth reporting.
const ALWAYS_REWRITTEN: [&str; 4] =
    ["status.json", "parameter_grid.txt", "equivalence_class_stats.json", "top_ola2_nodes.json"];

/// Empties the pipeline's scratch directory (`chunks/`).
///
/// `chunks/` holds only derived working files — the RAM-sized chunk splits and
/// the normalised `_converted.csv` for JSON/Excel input. Leftovers from an
/// earlier run are always stale, and `_converted.csv` in particular holds
/// *un-anonymized* source data, so they are removed unconditionally at startup.
/// A missing directory is not an error.
///
/// # Returns
/// The number of files removed.
pub fn clear_scratch_dir(chunks_dir: &Path) -> Result<usize, PipelineError> {
    if !chunks_dir.is_dir() {
        return Ok(0);
    }
    let mut removed = 0;
    for entry in fs::read_dir(chunks_dir)? {
        let path = entry?.path();
        if path.is_file() {
            fs::remove_file(&path).map_err(|e| io_err("remove stale scratch file", &path.display().to_string(), e))?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Names the files already in `output/` that this run will neither overwrite
/// nor delete — i.e. results of an *earlier* run that would otherwise be easy
/// to mistake for this run's output (e.g. `generalized_schools.csv` lingering
/// beside a fresh `generalized_test.csv`).
///
/// `will_write` lists the filenames this run is going to produce; those plus
/// key material, the active log, and the always-rewritten per-run artifacts
/// are excluded. Returns file names, sorted.
pub fn stale_output_files(output_dir: &Path, will_write: &[String]) -> Vec<String> {
    let Ok(entries) = fs::read_dir(output_dir) else {
        return Vec::new();
    };
    let mut stale: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .filter(|name| !is_protected_output(name))
        .filter(|name| !ALWAYS_REWRITTEN.contains(&name.as_str()))
        .filter(|name| !will_write.iter().any(|w| w == name))
        .collect();
    stale.sort();
    stale
}

/// Deletes the files reported by [`stale_output_files`]. Used only when the
/// config sets `clean_output: true` — key material and the active log are
/// never touched.
///
/// # Returns
/// The names of the files removed, sorted.
pub fn clear_output_dir(output_dir: &Path, will_write: &[String]) -> Result<Vec<String>, PipelineError> {
    let stale = stale_output_files(output_dir, will_write);
    for name in &stale {
        let path = output_dir.join(name);
        fs::remove_file(&path).map_err(|e| io_err("remove stale output file", &path.display().to_string(), e))?;
    }
    Ok(stale)
}

pub fn list_non_empty_csvs(data_dir: &Path) -> Result<Vec<PathBuf>, PipelineError> {
    if !data_dir.is_dir() {
        return Err(validation("DATA_DIR_MISSING", "Data directory not found", &data_dir.display().to_string()));
    }
    let mut out: Vec<PathBuf> = fs::read_dir(data_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("csv"))
        .filter(|p| fs::metadata(p).map(|m| m.len() > 0).unwrap_or(false))
        .collect();
    out.sort();
    if out.is_empty() {
        return Err(validation(
            "DATA_NO_CSV",
            "No non-empty CSV files found in data/",
            "Add exactly one CSV file to the data/ directory",
        ));
    }
    Ok(out)
}

/// Read MemAvailable from /proc/meminfo. Returns None on any parse failure.
pub fn available_ram_bytes() -> Option<u64> {
    let raw = fs::read_to_string("/proc/meminfo").ok()?;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            let kb = rest.split_whitespace().next()?.parse::<u64>().ok()?;
            return Some(kb.saturating_mul(1024));
        }
    }
    None
}

/// Sample up to `n` data rows from `path` and return their average byte length.
/// Returns a fallback of 256 bytes if the file can't be read or has no data rows.
fn sample_avg_row_bytes(path: &Path, n: usize) -> usize {
    let Ok(file) = fs::File::open(path) else { return 256 };
    let mut lines = BufReader::new(file).lines();
    lines.next(); // skip header
    let mut total = 0usize;
    let mut count = 0usize;
    for l in lines.take(n).map_while(Result::ok) {
        total += l.len() + 1; // +1 for newline
        count += 1;
    }
    if count == 0 { 256 } else { (total / count).max(1) }
}

/// Compute rows-per-chunk so that one chunk fits comfortably in RAM.
///
/// Target: use at most 20% of available RAM per chunk. The pipeline also holds
/// the sparse histogram and preprocessing buffers simultaneously, so staying
/// well below 50% gives enough headroom on any machine.
///
/// Clamped to [1_000, 10_000_000] so we never make absurdly tiny or huge chunks.
fn compute_rows_per_chunk(avg_row_bytes: usize) -> usize {
    const MIN_ROWS: usize = 1_000;
    const MAX_ROWS: usize = 10_000_000;
    const RAM_FRACTION: f64 = 0.20;

    let ram = available_ram_bytes().unwrap_or(512 * 1024 * 1024); // default 512 MB
    let target = ((ram as f64 * RAM_FRACTION) / avg_row_bytes as f64) as usize;
    target.clamp(MIN_ROWS, MAX_ROWS)
}

/// Convenience wrapper for plain single-CSV input: finds the one non-empty
/// `.csv` in `data_dir` and chunks it. `data_dir` is only ever read, never
/// written — safe under a read-only mount (e.g. docker-compose's `:ro` data
/// volume). JSON/Excel inputs go through `multitabular::resolve_input_csv`
/// first, which writes a normalised CSV into `chunks_dir` instead, then call
/// `split_csv_file_by_ram` directly on that path.
pub fn split_csv_by_ram(data_dir: &Path, chunks_dir: &Path) -> Result<(Vec<PathBuf>, usize), PipelineError> {
    let csvs = list_non_empty_csvs(data_dir)?;
    if csvs.len() != 1 {
        return Err(validation(
            "DATA_NO_CSV",
            "Expected exactly one CSV in data/",
            &format!("found {} CSV files — remove extras or consolidate into one", csvs.len()),
        ));
    }
    split_csv_file_by_ram(&csvs[0], chunks_dir)
}

/// Splits a single known CSV file into RAM-sized chunks under `chunks_dir`.
pub fn split_csv_file_by_ram(input: &Path, chunks_dir: &Path) -> Result<(Vec<PathBuf>, usize), PipelineError> {
    fs::create_dir_all(chunks_dir)?;

    // Sample before opening the streaming reader so we can seek back to the start.
    let avg_row_bytes = sample_avg_row_bytes(input, 200);
    let rows_per_chunk = compute_rows_per_chunk(avg_row_bytes);

    // Records, not lines: a quoted field may hold a line break, and a chunk
    // boundary must never fall inside one. Every row is checked against the
    // header width here, once, so everything downstream can trust positions.
    let (header_fields, mut records) = open_csv(input)?;
    let header = csv_row_to_line(&header_fields);

    let mut chunk_paths = Vec::new();
    let mut chunk_idx = 1usize;
    let mut row_count = 0usize;

    let mut out_path = chunks_dir.join(format!("chunk_{chunk_idx}.csv"));
    let mut writer = BufWriter::new(fs::File::create(&out_path)?);
    writer.write_all(header.as_bytes())?;
    writer.write_all(b"\n")?;

    while let Some(fields) = records.next_record_of_width(header_fields.len())? {
        let line = csv_row_to_line(&fields);
        if row_count > 0 && row_count.is_multiple_of(rows_per_chunk) {
            writer.flush()?;
            chunk_paths.push(out_path.clone());
            chunk_idx += 1;
            out_path = chunks_dir.join(format!("chunk_{chunk_idx}.csv"));
            writer = BufWriter::new(fs::File::create(&out_path)?);
            writer.write_all(header.as_bytes())?;
            writer.write_all(b"\n")?;
        }
        writer.write_all(line.as_bytes())?;
        writer.write_all(b"\n")?;
        row_count += 1;
    }
    writer.flush()?;
    chunk_paths.push(out_path);

    Ok((chunk_paths, rows_per_chunk))
}
