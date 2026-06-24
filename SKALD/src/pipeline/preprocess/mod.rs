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
//! | Salted hashing | `hashing_with_salt` | SHA-256 with a per-run random salt |
//! | Unsalted hashing | `hashing_without_salt` | Deterministic SHA-256 |
//! | Masking | `masking` | Position / regex / class-based character masking |
//! | CharCloak | `charcloak` | Class-preserving random character replacement |
//! | Tokenization | `tokenization` | Sequential opaque tokens with vault persistence |
//! | FPE | `fpe` | Format-preserving encryption (PAN / digits) |
//! | Encryption | `encrypt` | Pseudo-encryption or format-preserving encryption |
//!
//! The `crypto` submodule contains the cryptographic primitives and the
//! `masking` submodule contains configuration parsing and masking logic.

mod crypto;
mod masking;

use crate::pipeline::bootstrap::{split_csv_line_basic, validation, PipelineError, RuntimeConfig};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use crypto::{
    format_preserving_encrypt_general,
    generate_random_key_hex,
    generate_random_salt_hex,
    hash_hex,
    pseudo_encrypt,
    randomize_preserving_class,
    read_json_map_string,
    should_skip_value,
    write_json_pretty,
};

use masking::{
    apply_masking_value,
    parse_encrypt_config,
    parse_masking_config,
    parse_tokenization_config,
    EncryptConfigLite,
    MaskingConfigLite,
    TokenizationConfigLite,
};

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
pub fn preprocess_chunks(chunks: &[PathBuf], cfg: &RuntimeConfig) -> Result<(), PipelineError> {
    let masking_cfgs: Vec<MaskingConfigLite> = cfg
        .masking
        .iter()
        .map(parse_masking_config)
        .collect::<Result<Vec<_>, _>>()?;
    let token_cfgs: Vec<TokenizationConfigLite> = cfg
        .tokenization
        .iter()
        .map(parse_tokenization_config)
        .collect::<Result<Vec<_>, _>>()?;
    let encrypt_cfgs: Vec<EncryptConfigLite> = cfg.encrypt.iter().map(parse_encrypt_config).collect::<Result<Vec<_>, _>>()?;

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
    fs::create_dir_all(out_dir)?;

    // --- In-memory token vault (replaces JSON-Value traversal per row) ---
    // Keyed by column name → (forward: value→token, reverse: token→value, next sequential id)
    struct InMemVault {
        forward: BTreeMap<String, String>,
        reverse: BTreeMap<String, String>,
        next_id: u64,
    }

    let token_vault_path = out_dir.join("token_vault.json");
    let mut in_mem_vaults: BTreeMap<String, InMemVault> = BTreeMap::new();
    if !token_cfgs.is_empty() {
        let existing: Value = if token_vault_path.exists() {
            serde_json::from_str(&fs::read_to_string(&token_vault_path)?)?
        } else {
            serde_json::json!({})
        };
        for tcfg in &token_cfgs {
            let fwd: BTreeMap<String, String> = existing
                .get(&tcfg.column)
                .and_then(|c| c.get("forward"))
                .and_then(Value::as_object)
                .map(|m| m.iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect())
                .unwrap_or_default();
            let rev: BTreeMap<String, String> = existing
                .get(&tcfg.column)
                .and_then(|c| c.get("reverse"))
                .and_then(Value::as_object)
                .map(|m| m.iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect())
                .unwrap_or_default();
            let next_id = rev.len() as u64 + 1;
            in_mem_vaults.insert(tcfg.column.clone(), InMemVault { forward: fwd, reverse: rev, next_id });
        }
    }

    // Per-column random salts for salted hashing — generated fresh each run (matches Python behavior).
    // Not persisted to disk; consistent within a run across all chunks for the same column.
    let mut hash_salts: BTreeMap<String, String> = BTreeMap::new();

    let symmetric_keys_path = out_dir.join("symmetric_keys.json");
    let mut symmetric_keys = read_json_map_string(&symmetric_keys_path)?;

    let fpe_encrypt_keys_path = out_dir.join("fpe_encrypt_keys.json");
    let mut fpe_encrypt_keys = read_json_map_string(&fpe_encrypt_keys_path)?;

    for chunk_path in chunks {
        let file = fs::File::open(chunk_path)?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        let header_line = lines
            .next()
            .ok_or_else(|| validation("DATA_EMPTY", "Chunk is empty", &chunk_path.display().to_string()))?
            .map_err(|e| validation("IO_READ_FAILED", "Failed reading header", &e.to_string()))?;
        let mut headers = split_csv_line_basic(&header_line);
        let mut rows: Vec<Vec<String>> = Vec::new();
        for line in lines {
            let line = line.map_err(|e| validation("IO_READ_FAILED", "Failed reading row", &e.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }
            rows.push(split_csv_line_basic(&line));
        }

        if !cfg.suppress.is_empty() {
            let mut drop_idx = Vec::new();
            for col in &cfg.suppress {
                if let Some(i) = headers.iter().position(|h| h == col) {
                    drop_idx.push(i);
                } else {
                    return Err(validation("PREPROCESS_COLUMN_MISSING", "Suppression column not found in CSV header", col));
                }
            }
            drop_idx.sort_unstable();
            drop_idx.dedup();
            headers = headers
                .into_iter()
                .enumerate()
                .filter(|(i, _)| !drop_idx.contains(i))
                .map(|(_, h)| h)
                .collect();
            for row in &mut rows {
                *row = row
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| !drop_idx.contains(i))
                    .map(|(_, v)| v.clone())
                    .collect();
            }
        }

        for col in &cfg.hashing_with_salt {
            let idx = headers
                .iter()
                .position(|h| h == col)
                .ok_or_else(|| validation("PREPROCESS_COLUMN_MISSING", "Column not found in CSV header for salted hashing", col))?;
            let salt = hash_salts
                .entry(col.clone())
                .or_insert_with(generate_random_salt_hex)
                .clone();
            for row in &mut rows {
                if idx >= row.len() {
                    continue;
                }
                let v = row[idx].clone();
                if should_skip_value(&v) {
                    continue;
                }
                row[idx] = hash_hex(&format!("{}{}", salt, v));
            }
        }

        for col in &cfg.hashing_without_salt {
            let idx = headers
                .iter()
                .position(|h| h == col)
                .ok_or_else(|| validation("PREPROCESS_COLUMN_MISSING", "Column not found in CSV header for hashing", col))?;
            for row in &mut rows {
                if idx >= row.len() {
                    continue;
                }
                let v = row[idx].clone();
                if should_skip_value(&v) {
                    continue;
                }
                row[idx] = hash_hex(&v);
            }
        }

        for m in &masking_cfgs {
            let idx = headers
                .iter()
                .position(|h| h == &m.column)
                .ok_or_else(|| validation("PREPROCESS_COLUMN_MISSING", "Column not found in CSV header for masking", &m.column))?;
            for row in rows.iter_mut() {
                if idx >= row.len() {
                    continue;
                }
                let v = row[idx].clone();
                if should_skip_value(&v) {
                    continue;
                }
                row[idx] = apply_masking_value(&v, m, &randomize_preserving_class);
            }
        }

        for col in &cfg.charcloak {
            let idx = headers
                .iter()
                .position(|h| h == col)
                .ok_or_else(|| validation("PREPROCESS_COLUMN_MISSING", "Column not found in CSV header for charcloak", col))?;
            for row in rows.iter_mut() {
                if idx >= row.len() {
                    continue;
                }
                let v = row[idx].clone();
                if should_skip_value(&v) {
                    continue;
                }
                row[idx] = randomize_preserving_class(&v);
            }
        }

        for tcfg in &token_cfgs {
            let idx = headers
                .iter()
                .position(|h| h == &tcfg.column)
                .ok_or_else(|| validation("PREPROCESS_COLUMN_MISSING", "Column not found in CSV header for tokenization", &tcfg.column))?;
            let vault = in_mem_vaults
                .get_mut(&tcfg.column)
                .ok_or_else(|| validation("INTERNAL_ERROR", "Token vault missing for column", &tcfg.column))?;

            for row in &mut rows {
                if idx >= row.len() {
                    continue;
                }
                let v = row[idx].clone();
                if should_skip_value(&v) {
                    continue;
                }
                // O(1) lookup in BTreeMap instead of traversing JSON Value tree
                if let Some(tok) = vault.forward.get(&v) {
                    row[idx] = tok.clone();
                } else {
                    // next_id is a simple counter — no collision loop needed
                    let token = format!("{}{:0width$}", tcfg.prefix, vault.next_id, width = tcfg.digits);
                    vault.forward.insert(v.clone(), token.clone());
                    vault.reverse.insert(token.clone(), v);
                    vault.next_id += 1;
                    row[idx] = token;
                }
            }
        }

        for ecfg in &encrypt_cfgs {
            let idx = headers
                .iter()
                .position(|h| h == &ecfg.column)
                .ok_or_else(|| validation("PREPROCESS_COLUMN_MISSING", "Column not found in CSV header for encryption", &ecfg.column))?;

            if ecfg.format_preserving {
                let key = fpe_encrypt_keys
                    .entry(ecfg.column.clone())
                    .or_insert_with(generate_random_key_hex)
                    .clone();
                for row in &mut rows {
                    if idx >= row.len() {
                        continue;
                    }
                    let v = row[idx].clone();
                    if should_skip_value(&v) {
                        continue;
                    }
                    row[idx] = format_preserving_encrypt_general(&v, &key, &ecfg.column);
                }
            } else {
                let key = symmetric_keys
                    .entry(ecfg.column.clone())
                    .or_insert_with(generate_random_key_hex)
                    .clone();
                for row in &mut rows {
                    if idx >= row.len() {
                        continue;
                    }
                    let v = row[idx].clone();
                    if should_skip_value(&v) {
                        continue;
                    }
                    row[idx] = pseudo_encrypt(&v, &key, &ecfg.column);
                }
            }
        }

        let tmp_path = chunk_path.with_extension("csv.tmp");
        let mut w = BufWriter::new(fs::File::create(&tmp_path)?);
        w.write_all(headers.join(",").as_bytes())?;
        w.write_all(b"\n")?;
        for row in rows {
            w.write_all(row.join(",").as_bytes())?;
            w.write_all(b"\n")?;
        }
        w.flush()?;
        fs::rename(tmp_path, chunk_path)?;
    }

    // Serialize in-memory vaults back to the JSON format expected by callers
    if !in_mem_vaults.is_empty() {
        let mut vault_json = serde_json::json!({});
        for (col, vault) in &in_mem_vaults {
            vault_json[col] = serde_json::json!({
                "forward": vault.forward.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect::<serde_json::Map<_, _>>(),
                "reverse": vault.reverse.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect::<serde_json::Map<_, _>>(),
            });
        }
        write_json_pretty(&token_vault_path, &vault_json)?;
    }
    write_json_pretty(
        &symmetric_keys_path,
        &Value::Object(symmetric_keys.into_iter().map(|(k, v)| (k, Value::String(v))).collect()),
    )?;
    write_json_pretty(
        &fpe_encrypt_keys_path,
        &Value::Object(fpe_encrypt_keys.into_iter().map(|(k, v)| (k, Value::String(v))).collect()),
    )?;

    Ok(())
}
