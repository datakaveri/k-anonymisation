//! Pre-processing pipeline for the SKALD anonymization system.
//!
//! Applies a configurable sequence of privacy-enhancing transformations to
//! every input CSV chunk **before** the k-anonymization phase.
//!
//! Supported operations (executed in this fixed order per chunk):
//!
//! | Operation | Config key | Description |
//! |---|---|---|
//! | Column suppression | `suppress` | Drop columns entirely from output |
//! | Salted hashing | `hashing_with_salt` | HMAC-SHA256 keyed by a per-run random salt, or a per-column salt kept in the key directory (`shared_hash_salts`) |
//! | Masking | `masking` | Position / regex / class-based character masking |
//! | CharCloak | `charcloak` | Class-preserving random character replacement |
//! | Tokenization | `tokenization` | Random opaque tokens with vault persistence |
//! | Encryption | `encrypt` | AES-SIV, or NIST FF1 format-preserving encryption |
//!
//! Identifier values are normalised (trimmed, Unicode NFC) before hashing,
//! tokenisation and encryption, so spacing variants get one pseudonym.
//!
//! The `crypto` submodule contains the cryptographic primitives and the
//! `masking` submodule contains configuration parsing and masking logic.

pub mod crypto;
pub(crate) mod masking;

use crate::pipeline::bootstrap::{PipelineError, RuntimeConfig, csv_row_to_line, open_csv, validation};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use crypto::{
    encrypt_value, ensure_private_dir, format_preserving_encrypt, generate_random_salt_hex, hash_key, key_for,
    keyed_hash, normalize_identifier, randomize_preserving_class, read_json_map_string, should_skip_value,
    write_json_pretty,
};

use masking::{
    EncryptConfigLite, MaskingConfigLite, TokenizationConfigLite, apply_masking_value, parse_encrypt_config,
    parse_masking_config, parse_tokenization_config,
};

/// Per-column `hashing_with_salt` salts, in the key directory, when `shared_hash_salts` is on.
pub(crate) const HASH_SALTS_FILE: &str = "tabular_hash_salts.json";
/// Per-column token vaults, in the key directory.
pub(crate) const TOKEN_VAULT_FILE: &str = "token_vault.json";
/// Per-column `encrypt` keys, in the key directory.
pub(crate) const SYMMETRIC_KEYS_FILE: &str = "symmetric_keys.json";
/// Per-column format-preserving `encrypt` keys, in the key directory.
pub(crate) const FPE_KEYS_FILE: &str = "fpe_encrypt_keys.json";
/// Per-job `hashing_with_salt` salts minted by `skald_ao keygen` when
/// `shared_hash_salts` is off: every row shard of a column must hash under one
/// salt, so even a per-run salt has to be written down for the job's duration.
pub(crate) const BLOCK_HASH_SALTS_FILE: &str = "block_hash_salts.json";

/// One column's token mappings, both directions.
pub(crate) struct TokenVault {
    forward: BTreeMap<String, String>,
    reverse: BTreeMap<String, String>,
}

/// Every column's vault, as read from `token_vault.json`: the parsed document
/// (so columns this run does not tokenise are written back untouched) and a
/// [`TokenVault`] for each column this run does tokenise.
pub(crate) struct TokenVaults {
    doc: serde_json::Map<String, Value>,
    pub(crate) columns: BTreeMap<String, TokenVault>,
}

impl TokenVaults {
    /// Reads `path` (absent means empty) and prepares a vault for each column.
    pub(crate) fn load(path: &Path, columns: &[&str]) -> Result<Self, PipelineError> {
        let doc: serde_json::Map<String, Value> = if path.exists() {
            serde_json::from_str::<Value>(&fs::read_to_string(path)?)?.as_object().cloned().unwrap_or_default()
        } else {
            serde_json::Map::new()
        };
        let read_map = |v: Option<&Value>| -> BTreeMap<String, String> {
            v.and_then(Value::as_object)
                .map(|m| m.iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect())
                .unwrap_or_default()
        };
        let mut out = BTreeMap::new();
        for col in columns {
            let existing = doc.get(*col);
            out.insert(
                col.to_string(),
                TokenVault {
                    forward: read_map(existing.and_then(|c| c.get("forward"))),
                    reverse: read_map(existing.and_then(|c| c.get("reverse"))),
                },
            );
        }
        Ok(Self { doc, columns: out })
    }

    /// Writes every column back to `path` as key material (owner-only).
    pub(crate) fn save(mut self, path: &Path) -> Result<(), PipelineError> {
        let as_obj = |m: &BTreeMap<String, String>| {
            m.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect::<serde_json::Map<_, _>>()
        };
        for (col, vault) in &self.columns {
            self.doc.insert(
                col.clone(),
                serde_json::json!({ "forward": as_obj(&vault.forward), "reverse": as_obj(&vault.reverse) }),
            );
        }
        write_json_pretty(path, &Value::Object(self.doc))
    }
}

impl TokenVault {
    /// The token for `value`, issuing a new one if it has none.
    ///
    /// New tokens are random rather than sequential — a counter numbers values
    /// in first-seen order, which leaks the input's order (and its sort key) —
    /// and are checked against every token already issued.
    pub(crate) fn token_for(&mut self, value: &str, cfg: &TokenizationConfigLite) -> Result<String, PipelineError> {
        if let Some(t) = self.forward.get(value) {
            return Ok(t.clone());
        }
        let space = 10u64.saturating_pow(cfg.digits.min(18) as u32);
        if self.reverse.len() as u64 >= space / 10 * 9 {
            return Err(validation("TOKEN_SPACE_EXHAUSTED", "Token vault is nearly full", &cfg.column));
        }
        loop {
            let mut b = [0u8; 8];
            getrandom::getrandom(&mut b).map_err(|e| {
                validation("RNG_UNAVAILABLE", "The operating system's random number generator failed", &e.to_string())
            })?;
            let token = format!("{}{:0width$}", cfg.prefix, u64::from_le_bytes(b) % space, width = cfg.digits);
            if !self.reverse.contains_key(&token) {
                self.forward.insert(value.to_string(), token.clone());
                self.reverse.insert(token.clone(), value.to_string());
                return Ok(token);
            }
        }
    }
}

/// Applies all configured pre-processing transformations to each input chunk
/// and writes the result back in-place (atomic rename via a `.csv.tmp` file).
///
/// A token vault (`token_vault.json`), symmetric key store (`symmetric_keys.json`),
/// and FPE-encrypt key store (`fpe_encrypt_keys.json`) are maintained in
/// `output_directory` so that mappings are consistent across pipeline re-runs.
///
/// # Arguments
/// * `chunks` — paths to the CSV chunk files to transform (modified in-place).
/// * `cfg` — the validated pipeline runtime configuration.
///
/// # Returns
/// `Ok(())` when all chunks have been successfully processed and all key stores
/// have been persisted.
///
/// # Errors
/// Returns [`PipelineError`] if any chunk file cannot be opened/written,
/// a required column is missing, or a config entry is malformed.
pub fn preprocess_chunks(chunks: &[PathBuf], cfg: &RuntimeConfig) -> Result<PreprocessStats, PipelineError> {
    let masking_cfgs: Vec<MaskingConfigLite> =
        cfg.masking.iter().map(parse_masking_config).collect::<Result<Vec<_>, _>>()?;
    let token_cfgs: Vec<TokenizationConfigLite> =
        cfg.tokenization.iter().map(parse_tokenization_config).collect::<Result<Vec<_>, _>>()?;
    let encrypt_cfgs: Vec<EncryptConfigLite> =
        cfg.encrypt.iter().map(parse_encrypt_config).collect::<Result<Vec<_>, _>>()?;

    let out_dir_buf = if Path::new(&cfg.output_directory).is_absolute() {
        PathBuf::from(&cfg.output_directory)
    } else if let Some(first_chunk) = chunks.first() {
        if let Some(chunks_dir) = first_chunk.parent() {
            if let Some(root_dir) = chunks_dir.parent() {
                root_dir.join(&cfg.output_directory)
            } else {
                chunks_dir.join(&cfg.output_directory)
            }
        } else {
            PathBuf::from(&cfg.output_directory)
        }
    } else {
        PathBuf::from(&cfg.output_directory)
    };
    let out_dir = out_dir_buf.as_path();
    ensure_private_dir(out_dir)?;

    // Token vaults: every column ever tokenised, so a run that tokenises fewer
    // columns does not drop earlier mappings when it saves the file back.
    let token_vault_path = out_dir.join(TOKEN_VAULT_FILE);
    let token_columns: Vec<&str> = token_cfgs.iter().map(|t| t.column.as_str()).collect();
    let mut vaults = TokenVaults::load(&token_vault_path, &token_columns)?;

    // Per-column random salts for salted hashing, consistent within a run across
    // all chunks for the same column. By default generated fresh each run and
    // never written (matches Python behavior). With `shared_hash_salts` they are
    // read from and saved to the key directory, keyed by column name, so tables
    // run one at a time against the same key directory hash a column alike.
    let hash_salts_path = out_dir.join(HASH_SALTS_FILE);
    let mut hash_salts: BTreeMap<String, String> =
        if cfg.shared_hash_salts { read_json_map_string(&hash_salts_path)? } else { BTreeMap::new() };
    let hash_salts_loaded = hash_salts.len();

    let symmetric_keys_path = out_dir.join(SYMMETRIC_KEYS_FILE);
    let mut symmetric_keys = read_json_map_string(&symmetric_keys_path)?;

    let fpe_encrypt_keys_path = out_dir.join(FPE_KEYS_FILE);
    let mut fpe_encrypt_keys = read_json_map_string(&fpe_encrypt_keys_path)?;

    let mut stats = PreprocessStats::new();
    for chunk_path in chunks {
        // Records, not lines, and every row as wide as the header: a short row
        // would otherwise skip every technique below and go out in clear.
        let (mut headers, mut records) = open_csv(chunk_path)?;
        let mut rows: Vec<Vec<String>> = Vec::new();
        while let Some(fields) = records.next_record_of_width(headers.len())? {
            rows.push(fields);
        }
        let column = |headers: &[String], col: &str, what: &str| -> Result<usize, PipelineError> {
            headers.iter().position(|h| h == col).ok_or_else(|| {
                validation("PREPROCESS_COLUMN_MISSING", &format!("Column not found in CSV header for {what}"), col)
            })
        };
        // Applies `f` to every non-missing value of column `idx`, naming the
        // column and row (never the value) if it fails.
        let apply = |rows: &mut Vec<Vec<String>>,
                     idx: usize,
                     col: &str,
                     f: &mut dyn FnMut(&str) -> Result<String, PipelineError>|
         -> Result<u64, PipelineError> {
            let mut changed = 0u64;
            for (n, row) in rows.iter_mut().enumerate() {
                if should_skip_value(&row[idx]) {
                    continue;
                }
                changed += 1;
                row[idx] = f(&row[idx]).map_err(|e| match e {
                    PipelineError::Validation { code, message, details } => PipelineError::Validation {
                        code,
                        message,
                        details: format!("{details} (column {col}, data row {} of {})", n + 1, chunk_path.display()),
                    },
                    other => other,
                })?;
            }
            Ok(changed)
        };
        let mut count = |technique: &str, col: &str, n: u64| {
            *stats.entry(format!("{technique}:{col}")).or_insert(0) += n;
        };

        if !cfg.suppress.is_empty() {
            let mut drop_idx = Vec::new();
            for col in &cfg.suppress {
                drop_idx.push(column(&headers, col, "suppression")?);
                count("suppress", col, rows.len() as u64);
            }
            drop_idx.sort_unstable();
            drop_idx.dedup();
            let keep = |i: &usize| !drop_idx.contains(i);
            headers = headers.into_iter().enumerate().filter(|(i, _)| keep(i)).map(|(_, h)| h).collect();
            for row in &mut rows {
                *row = std::mem::take(row).into_iter().enumerate().filter(|(i, _)| keep(i)).map(|(_, v)| v).collect();
            }
        }

        for col in &cfg.hashing_with_salt {
            let idx = column(&headers, col, "salted hashing")?;
            if !hash_salts.contains_key(col) {
                hash_salts.insert(col.clone(), generate_random_salt_hex()?);
            }
            let key = hash_key(&hash_salts[col], &format!("{HASH_SALTS_FILE}: {col}"))?;
            let n = apply(&mut rows, idx, col, &mut |v| Ok(keyed_hash(&key, normalize_identifier(v).as_bytes())))?;
            count("hashing_with_salt", col, n);
        }

        for m in &masking_cfgs {
            let idx = column(&headers, &m.column, "masking")?;
            let n = apply(&mut rows, idx, &m.column, &mut |v| apply_masking_value(v, m, &randomize_preserving_class))?;
            count("masking", &m.column, n);
        }

        for col in &cfg.charcloak {
            let idx = column(&headers, col, "charcloak")?;
            let n = apply(&mut rows, idx, col, &mut |v| randomize_preserving_class(v))?;
            count("charcloak", col, n);
        }

        for tcfg in &token_cfgs {
            let idx = column(&headers, &tcfg.column, "tokenization")?;
            let vault = vaults
                .columns
                .get_mut(&tcfg.column)
                .ok_or_else(|| validation("INTERNAL_ERROR", "Token vault missing for column", &tcfg.column))?;
            let n = apply(&mut rows, idx, &tcfg.column, &mut |v| vault.token_for(&normalize_identifier(v), tcfg))?;
            count("tokenization", &tcfg.column, n);
        }

        for ecfg in &encrypt_cfgs {
            let idx = column(&headers, &ecfg.column, "encryption")?;
            if ecfg.format_preserving {
                let key = key_for(&mut fpe_encrypt_keys, &ecfg.column)?;
                let n = apply(&mut rows, idx, &ecfg.column, &mut |v| {
                    format_preserving_encrypt(&normalize_identifier(v), &key, &ecfg.column)
                })?;
                count("encrypt_fpe", &ecfg.column, n);
            } else {
                let key = key_for(&mut symmetric_keys, &ecfg.column)?;
                let n = apply(&mut rows, idx, &ecfg.column, &mut |v| {
                    encrypt_value(&normalize_identifier(v), &key, &ecfg.column)
                })?;
                count("encrypt", &ecfg.column, n);
            }
        }

        let tmp_path = chunk_path.with_extension("csv.tmp");
        let mut w = BufWriter::new(fs::File::create(&tmp_path)?);
        w.write_all(csv_row_to_line(&headers).as_bytes())?;
        w.write_all(b"\n")?;
        for row in rows {
            w.write_all(csv_row_to_line(&row).as_bytes())?;
            w.write_all(b"\n")?;
        }
        w.flush()?;
        fs::rename(tmp_path, chunk_path)?;
    }

    if !vaults.columns.is_empty() {
        vaults.save(&token_vault_path)?;
    }
    if cfg.shared_hash_salts && hash_salts.len() > hash_salts_loaded {
        write_json_pretty(
            &hash_salts_path,
            &Value::Object(hash_salts.into_iter().map(|(k, v)| (k, Value::String(v))).collect()),
        )?;
    }
    write_json_pretty(
        &symmetric_keys_path,
        &Value::Object(symmetric_keys.into_iter().map(|(k, v)| (k, Value::String(v))).collect()),
    )?;
    write_json_pretty(
        &fpe_encrypt_keys_path,
        &Value::Object(fpe_encrypt_keys.into_iter().map(|(k, v)| (k, Value::String(v))).collect()),
    )?;

    Ok(stats)
}

/// Values each technique transformed, keyed `"<technique>:<column>"`
/// (`suppress` counts the rows whose cell was dropped). Counts only — never values.
pub type PreprocessStats = BTreeMap<String, u64>;
