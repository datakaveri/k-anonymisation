use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
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

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub enable_k_anonymity: bool,
    /// "pass1" | "pass2" | "no_bounds"
    pub pass: String,
    /// k is optional — not required for pass1
    pub k: i64,
    pub suppression_limit: f64,
    pub output_path: String,
    pub output_directory: String,
    pub suppress: Vec<String>,
    pub hashing_with_salt: Vec<String>,
    pub hashing_without_salt: Vec<String>,
    pub masking: Vec<Value>,
    pub encrypt: Vec<Value>,
    pub charcloak: Vec<String>,
    pub tokenization: Vec<Value>,
    pub fpe: Vec<Value>,
    pub numerical_qis: Vec<NumericalQiConfig>,
    pub categorical_qis: Vec<String>,
    pub size_factors: HashMap<String, i64>,
    pub source_json_config: PathBuf,
    /// Per-column non-uniform interval constraints: column → sorted list of (from, to) intervals
    pub qi_interval_constraints: HashMap<String, Vec<(i64, i64)>>,
    /// Fixed non-uniform bins: column → sorted list of (from, to) intervals.
    /// QIs listed here are excluded from the OLA-2 lattice search (bins are fixed)
    /// but still contribute to equivalence class keys in the histogram.
    pub fixed_bins: HashMap<String, Vec<(i64, i64)>>,
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
        "CONFIG_NOT_FOUND" =>
            "Create a config/ directory and add a JSON configuration file. \
             Refer to the schema reference for the required fields.",
        "CONFIG_PARSE_ERROR" =>
            "Validate your config JSON with a linter. \
             Ensure all brackets and quotes are balanced.",
        "CONFIG_MISSING_FIELD" =>
            "The config file is missing a required field. \
             Required fields: data_type, quasi_identifiers, k_anonymize, output_path.",
        "CONFIG_INVALID" | "CONFIG_INVALID_VALUE" =>
            "Review config field values: k must be ≥ 1, suppression_limit must be \
             0.0–1.0, size factors must be positive integers.",
        "DATA_DIR_MISSING" | "DATA_MISSING" =>
            "Create a data/ directory and place exactly one CSV file inside it.",
        "DATA_NO_CSV" =>
            "No CSV file found in data/. \
             Add exactly one CSV file with a header row.",
        "DATA_EMPTY" =>
            "The CSV file exists but is empty. \
             Ensure it has a header row and at least one data row.",
        "DATA_COLUMN_MISSING" =>
            "A quasi-identifier column was not found in the CSV header. \
             Column names are case-sensitive — verify they match exactly.",
        "PREPROCESS_COLUMN_MISSING" | "PREPROCESSING_FAILED" =>
            "A preprocessing target column was not found in the CSV header. \
             Check suppress, masking, hashing, tokenization, fpe, encrypt, \
             and charcloak column names against the actual CSV header.",
        "PREPROCESS_CONFIG_INVALID" =>
            "A preprocessing config entry is malformed. \
             Each entry must be an object with a 'column' field and valid parameters.",
        "ANON_INFEASIBLE" | "GENERALIZATION_FAILED" =>
            "k-anonymity cannot be satisfied with the current settings. \
             Try: (1) increase suppression_limit (e.g. to 0.05), \
             (2) decrease k, \
             (3) add more records, \
             (4) increase size factors for numerical QIs.",
        "ANON_NO_QIS" =>
            "No quasi-identifiers are defined. \
             Add at least one entry to quasi_identifiers.numerical \
             or quasi_identifiers.categorical in the config.",
        "ENCODING_FAILED" =>
            "A data encoding error occurred. \
             Check that numerical QI columns contain only numeric values and no blanks.",
        "IO_READ_FAILED" =>
            "A required file could not be read. \
             Check that the file exists and the process has read permissions.",
        "IO_WRITE_FAILED" =>
            "A file could not be written. \
             Check disk space and write permissions for the output/ and chunks/ directories.",
        "IO_PERMISSION_DENIED" =>
            "Permission denied on a file or directory. \
             Run the pipeline with appropriate filesystem permissions.",
        "INTERNAL_ERROR" =>
            "An unexpected internal error occurred. \
             Check output/pipeline.log for a full trace and contact support.",
        _ =>
            "Review the pipeline configuration and input data, then retry.",
    }
}

/// HTTP status code for each error code — for UI/API response routing.
pub fn http_status_for(code: &str) -> u16 {
    match code {
        "CONFIG_NOT_FOUND"
        | "CONFIG_PARSE_ERROR"
        | "CONFIG_MISSING_FIELD"
        | "CONFIG_INVALID"
        | "CONFIG_INVALID_VALUE" => 400,

        "DATA_DIR_MISSING"
        | "DATA_MISSING"
        | "DATA_NO_CSV"
        | "DATA_EMPTY"
        | "DATA_COLUMN_MISSING"
        | "PREPROCESS_COLUMN_MISSING"
        | "PREPROCESSING_FAILED"
        | "PREPROCESS_CONFIG_INVALID"
        | "ANON_INFEASIBLE"
        | "ANON_NO_QIS"
        | "GENERALIZATION_FAILED"
        | "ENCODING_FAILED" => 422,

        "IO_READ_FAILED" | "IO_WRITE_FAILED" | "IO_PERMISSION_DENIED" | "INTERNAL_ERROR" => 500,

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
    PipelineError::Validation {
        code,
        message: format!("Failed to {operation}"),
        details: format!("{path}: {e}"),
    }
}

pub fn validation(code: &'static str, message: &str, details: &str) -> PipelineError {
    PipelineError::Validation {
        code,
        message: message.to_string(),
        details: details.to_string(),
    }
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

/// Encodes a single CSV field value per RFC 4180: wraps in double-quotes when
/// the value contains a comma, double-quote, or newline, and escapes any
/// embedded double-quotes by doubling them.
///
/// This is the counterpart to [`split_csv_line_basic`] — together they form a
/// lossless round-trip for arbitrary field values including street addresses
/// that contain commas.
pub fn csv_quote_field(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Serialises a row of field values into a single CSV line using
/// [`csv_quote_field`] to ensure values with commas or quotes are safely
/// escaped.  Does NOT append a newline.
pub fn csv_row_to_line(fields: &[String]) -> String {
    fields.iter().map(|f| csv_quote_field(f)).collect::<Vec<_>>().join(",")
}

pub fn ensure_output_dir(path: &Path) -> Result<(), PipelineError> {
    fs::create_dir_all(path)?;
    Ok(())
}

pub fn find_first_json_config(config_dir: &Path) -> Result<PathBuf, PipelineError> {
    if !config_dir.is_dir() {
        return Err(validation(
            "CONFIG_NOT_FOUND",
            "Config directory not found",
            &config_dir.display().to_string(),
        ));
    }
    let mut files: Vec<PathBuf> = fs::read_dir(config_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    files.sort();
    files
        .into_iter()
        .next()
        .ok_or_else(|| validation("CONFIG_NOT_FOUND", "No JSON config file found in config/", "config/ directory is empty"))
}

pub fn parse_runtime_config(config_path: &Path) -> Result<RuntimeConfig, PipelineError> {
    let raw = fs::read_to_string(config_path)?;
    let root: Value = serde_json::from_str(&raw)?;

    let data_type = root
        .get("data_type")
        .and_then(Value::as_str)
        .ok_or_else(|| validation("CONFIG_MISSING_FIELD", "Required field 'data_type' is absent", &config_path.display().to_string()))?;

    let section = root.get(data_type).ok_or_else(|| {
        validation(
            "CONFIG_MISSING_FIELD",
            "Config section for data_type not found",
            &format!("No section named '{}' in config", data_type),
        )
    })?;

    let output_path = section
        .get("output_path")
        .and_then(Value::as_str)
        .unwrap_or("generalized.csv")
        .to_string();

    let output_directory = section
        .get("output_directory")
        .and_then(Value::as_str)
        .unwrap_or("output")
        .to_string();

    let suppress = section
        .get("suppress")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let hashing_with_salt = section
        .get("hashing_with_salt")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let hashing_without_salt = section
        .get("hashing_without_salt")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let masking = section
        .get("masking")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let encrypt = section
        .get("encrypt")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let charcloak = section
        .get("charcloak")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let tokenization = section
        .get("tokenization")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let fpe = section
        .get("fpe")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let suppression_limit = section
        .get("suppression_limit")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);

    let pass = section
        .get("pass")
        .and_then(Value::as_str)
        .unwrap_or("no_bounds")
        .to_string();

    let k = section
        .get("k_anonymize")
        .and_then(|v| v.get("k"))
        .and_then(Value::as_i64)
        .unwrap_or(if pass == "pass1" { 0 } else { 2 });

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
                numerical_qis.push(NumericalQiConfig {
                    column: n.get("column").and_then(Value::as_str).unwrap_or("").to_string(),
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

    let mut size_factors = HashMap::new();
    if let Some(obj) = section.get("size").and_then(Value::as_object) {
        for (k, v) in obj {
            if let Some(iv) = v.as_i64() {
                size_factors.insert(k.clone(), iv.max(1));
            }
        }
    }

    let has_k_anonymize = section.get("k_anonymize").is_some();
    let has_qis = !numerical_qis.is_empty() || !categorical_qis.is_empty();

    Ok(RuntimeConfig {
        enable_k_anonymity: has_k_anonymize && has_qis,
        pass,
        k: if k <= 0 { 0 } else { k },
        suppression_limit,
        output_path,
        output_directory,
        suppress,
        hashing_with_salt,
        hashing_without_salt,
        masking,
        encrypt,
        charcloak,
        tokenization,
        fpe,
        numerical_qis,
        categorical_qis,
        size_factors,
        source_json_config: config_path.to_path_buf(),
        qi_interval_constraints,
        fixed_bins,
    })
}

pub fn list_non_empty_csvs(data_dir: &Path) -> Result<Vec<PathBuf>, PipelineError> {
    if !data_dir.is_dir() {
        return Err(validation(
            "DATA_DIR_MISSING",
            "Data directory not found",
            &data_dir.display().to_string(),
        ));
    }
    let mut out: Vec<PathBuf> = fs::read_dir(data_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("csv"))
        .filter(|p| fs::metadata(p).map(|m| m.len() > 0).unwrap_or(false))
        .collect();
    out.sort();
    if out.is_empty() {
        return Err(validation("DATA_NO_CSV", "No non-empty CSV files found in data/", "Add exactly one CSV file to the data/ directory"));
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
    for line in lines.take(n) {
        if let Ok(l) = line {
            total += l.len() + 1; // +1 for newline
            count += 1;
        }
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

pub fn split_csv_by_ram(
    data_dir: &Path,
    chunks_dir: &Path,
) -> Result<(Vec<PathBuf>, usize), PipelineError> {
    fs::create_dir_all(chunks_dir)?;
    let csvs = list_non_empty_csvs(data_dir)?;
    if csvs.len() != 1 {
        return Err(validation(
            "DATA_NO_CSV",
            "Expected exactly one CSV in data/",
            &format!("found {} CSV files — remove extras or consolidate into one", csvs.len()),
        ));
    }
    let input = &csvs[0];

    // Sample before opening the streaming reader so we can seek back to the start.
    let avg_row_bytes = sample_avg_row_bytes(input, 200);
    let rows_per_chunk = compute_rows_per_chunk(avg_row_bytes);

    let file = fs::File::open(input)
        .map_err(|e| io_err("open CSV file", &input.display().to_string(), e))?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    let header = lines
        .next()
        .ok_or_else(|| validation("DATA_EMPTY", "CSV file contains no header row", &input.display().to_string()))?
        .map_err(|e| io_err("read CSV header", &input.display().to_string(), e))?;

    let mut chunk_paths = Vec::new();
    let mut chunk_idx = 1usize;
    let mut row_count = 0usize;

    let mut out_path = chunks_dir.join(format!("chunk_{chunk_idx}.csv"));
    let mut writer = BufWriter::new(fs::File::create(&out_path)?);
    writer.write_all(header.as_bytes())?;
    writer.write_all(b"\n")?;

    for line in lines {
        let line = line.map_err(|e| validation("DATA_MISSING", "Failed reading row", &e.to_string()))?;
        if row_count > 0 && row_count % rows_per_chunk == 0 {
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
