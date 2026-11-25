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
pub mod keys;
pub(crate) mod masking;
pub mod vault;

use crate::batch::Table;
use crate::pipeline::bootstrap::{PipelineError, RuntimeConfig, csv_row_to_line, open_csv, validation};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use crypto::{
    encrypt_value, ensure_private_dir, format_preserving_encrypt, hash_key, keyed_hash, normalize_identifier,
    randomize_preserving_class, read_json_map_string, should_skip_value, write_json_pretty,
};

pub use keys::{KeyKind, KeyMaterial};
pub use vault::{ColumnVault, MemoryVault, TokenVault};

use masking::{
    EncryptConfigLite, MaskingConfigLite, TokenizationConfigLite, apply_masking_value, parse_encrypt_config,
    parse_masking_config, parse_tokenization_config,
};

/// Per-column `hashing_with_salt` salts, in the key directory, when `shared_hash_salts` is on.
pub(crate) const HASH_SALTS_FILE: &str = "tabular_hash_salts.json";

/// Where tokens come from when a value has none yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenPolicy {
    /// Mint a random token and record it in the vault (the command line, and a
    /// driver completing a vault before its executors run).
    Issue,
    /// Only use tokens the vault already holds; a value without one is an
    /// error. Executors must never mint, or two of them would give the same
    /// value two tokens.
    LookupOnly,
}

/// What a missing key does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPolicy {
    /// Generate it from the OS RNG (the command line's behaviour).
    Generate,
    /// Fail with `KEY_MISSING`. Executors must never generate, or each would
    /// hash and encrypt under a different key.
    Require,
}

/// The token for `value` in `cfg.column`: the vault's, or a new random one.
///
/// New tokens are random rather than sequential — a counter numbers values
/// in first-seen order, which leaks the input's order (and its sort key) —
/// and are checked against every token already issued.
fn token_for<V: TokenVault>(
    vault: &mut V,
    policy: TokenPolicy,
    value: &str,
    cfg: &TokenizationConfigLite,
) -> Result<String, PipelineError> {
    if let Some(t) = vault.lookup(&cfg.column, value) {
        return Ok(t);
    }
    if policy == TokenPolicy::LookupOnly {
        return Err(validation(
            "TOKEN_MISSING",
            "A value has no token in the vault and this caller may not issue one",
            &cfg.column,
        ));
    }
    let space = 10u64.saturating_pow(cfg.digits.min(18) as u32);
    if vault.len(&cfg.column) as u64 >= space / 10 * 9 {
        return Err(validation("TOKEN_SPACE_EXHAUSTED", "Token vault is nearly full", &cfg.column));
    }
    loop {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).map_err(|e| {
            validation("RNG_UNAVAILABLE", "The operating system's random number generator failed", &e.to_string())
        })?;
        let token = format!("{}{:0width$}", cfg.prefix, u64::from_le_bytes(b) % space, width = cfg.digits);
        if !vault.token_in_use(&cfg.column, &token) {
            vault.assign(&cfg.column, value, &token)?;
            return Ok(token);
        }
    }
}

/// How far [`Preprocessor::run`] goes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Every technique.
    Full,
    /// Stop where tokenization would start and collect the values it would
    /// tokenise instead.
    CollectTokenValues,
}

/// The pre-processing techniques of one config, applied table by table.
///
/// This is the single implementation: the command line applies it to each
/// chunk file, and library callers apply it to each record batch. Techniques
/// run in a fixed order per table (suppress, salted hashing, masking,
/// charcloak, tokenization, encryption) and a column is transformed the same
/// way whichever table it arrives in, because the keys and the vault are held
/// here, once, for the whole run.
pub struct Preprocessor<V: TokenVault = MemoryVault> {
    suppress: Vec<String>,
    hashing_with_salt: Vec<String>,
    charcloak: Vec<String>,
    masking: Vec<MaskingConfigLite>,
    tokens: Vec<TokenizationConfigLite>,
    encrypt: Vec<EncryptConfigLite>,
    keys: KeyMaterial,
    key_policy: KeyPolicy,
    /// Keys generated by this run, for the caller to persist.
    generated: Vec<(KeyKind, String)>,
    vault: V,
    token_policy: TokenPolicy,
}

impl<V: TokenVault> Preprocessor<V> {
    /// Parses the configured techniques. `keys` holds the keys the caller
    /// owns; `key_policy` says what to do about the rest.
    ///
    /// # Errors
    /// A malformed masking, tokenization or encryption entry.
    pub fn new(
        cfg: &RuntimeConfig,
        keys: KeyMaterial,
        key_policy: KeyPolicy,
        vault: V,
        token_policy: TokenPolicy,
    ) -> Result<Self, PipelineError> {
        Ok(Self {
            suppress: cfg.suppress.clone(),
            hashing_with_salt: cfg.hashing_with_salt.clone(),
            charcloak: cfg.charcloak.clone(),
            masking: cfg.masking.iter().map(parse_masking_config).collect::<Result<_, _>>()?,
            tokens: cfg.tokenization.iter().map(parse_tokenization_config).collect::<Result<_, _>>()?,
            encrypt: cfg.encrypt.iter().map(parse_encrypt_config).collect::<Result<_, _>>()?,
            keys,
            key_policy,
            generated: Vec::new(),
            vault,
            token_policy,
        })
    }

    /// Every key the config needs, as `(kind, column)`.
    pub fn required_keys(&self) -> Vec<(KeyKind, String)> {
        let mut out: Vec<(KeyKind, String)> =
            self.hashing_with_salt.iter().map(|c| (KeyKind::HmacSalt, c.clone())).collect();
        for e in &self.encrypt {
            let kind = if e.format_preserving { KeyKind::FpeKey } else { KeyKind::AesKey };
            out.push((kind, e.column.clone()));
        }
        out
    }

    /// Columns the config tokenises.
    pub fn tokenized_columns(&self) -> Vec<String> {
        self.tokens.iter().map(|t| t.column.clone()).collect()
    }

    /// The vault, for the caller to read or save.
    pub fn vault(&self) -> &V {
        &self.vault
    }

    /// Hands back the keys (including any generated), the vault, and the
    /// `(kind, column)` pairs that were generated.
    pub fn into_parts(self) -> (KeyMaterial, V, Vec<(KeyKind, String)>) {
        (self.keys, self.vault, self.generated)
    }

    /// The key for `(kind, column)`: the caller's, a generated one, or an error.
    fn key(&mut self, kind: KeyKind, column: &str) -> Result<String, PipelineError> {
        if let Some(k) = self.keys.map(kind).get(column) {
            return Ok(k.clone());
        }
        if self.key_policy == KeyPolicy::Require {
            return Err(validation(
                "KEY_MISSING",
                &format!("No {} was passed for this column and this caller may not generate one", kind.as_str()),
                column,
            ));
        }
        self.keys.generate_missing(&[(kind, column.to_string())])?;
        self.generated.push((kind, column.to_string()));
        Ok(self.keys.map(kind)[column].clone())
    }

    /// Applies every technique to `table` in place and returns what each
    /// transformed (counts only).
    ///
    /// # Errors
    /// A configured column missing from the table, a key missing under
    /// [`KeyPolicy::Require`], a token missing under
    /// [`TokenPolicy::LookupOnly`], or a value a technique cannot process
    /// (the error names the column and row, never the value).
    pub fn apply(&mut self, table: &mut Table) -> Result<PreprocessStats, PipelineError> {
        self.run(table, Stage::Full).map(|(stats, _)| stats)
    }

    /// The distinct values this table would tokenise, per column, normalised
    /// as tokenization sees them. A driver collects these from every batch,
    /// issues the missing tokens into the vault, and only then lets executors
    /// run [`Preprocessor::apply`] with [`TokenPolicy::LookupOnly`].
    pub fn token_values(&mut self, table: &mut Table) -> Result<BTreeMap<String, BTreeSet<String>>, PipelineError> {
        self.run(table, Stage::CollectTokenValues).map(|(_, values)| values)
    }

    /// Issues a token for each of `values` that has none, whatever this
    /// preprocessor's own [`TokenPolicy`] is.
    pub fn issue_tokens(&mut self, values: &BTreeMap<String, BTreeSet<String>>) -> Result<(), PipelineError> {
        for t in self.tokens.clone() {
            for v in values.get(&t.column).into_iter().flatten() {
                token_for(&mut self.vault, TokenPolicy::Issue, v, &t)?;
            }
        }
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn run(
        &mut self,
        table: &mut Table,
        stage: Stage,
    ) -> Result<(PreprocessStats, BTreeMap<String, BTreeSet<String>>), PipelineError> {
        let mut stats = PreprocessStats::new();
        let mut collected: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let source = table.source.clone();
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
                        details: format!("{details} (column {col}, data row {} of {source})", n + 1),
                    },
                    other => other,
                })?;
            }
            Ok(changed)
        };
        let mut count = |technique: &str, col: &str, n: u64| {
            *stats.entry(format!("{technique}:{col}")).or_insert(0) += n;
        };
        let (headers, rows) = (&mut table.headers, &mut table.rows);

        if !self.suppress.is_empty() {
            let mut drop_idx = Vec::new();
            for col in &self.suppress {
                drop_idx.push(column(headers, col, "suppression")?);
                count("suppress", col, rows.len() as u64);
            }
            drop_idx.sort_unstable();
            drop_idx.dedup();
            let keep = |i: &usize| !drop_idx.contains(i);
            *headers =
                std::mem::take(headers).into_iter().enumerate().filter(|(i, _)| keep(i)).map(|(_, h)| h).collect();
            for row in rows.iter_mut() {
                *row = std::mem::take(row).into_iter().enumerate().filter(|(i, _)| keep(i)).map(|(_, v)| v).collect();
            }
        }

        for col in self.hashing_with_salt.clone() {
            let idx = column(headers, &col, "salted hashing")?;
            let salt = self.key(KeyKind::HmacSalt, &col)?;
            let key = hash_key(&salt, &format!("{HASH_SALTS_FILE}: {col}"))?;
            let n = apply(rows, idx, &col, &mut |v| Ok(keyed_hash(&key, normalize_identifier(v).as_bytes())))?;
            count("hashing_with_salt", &col, n);
        }

        for m in &self.masking {
            let idx = column(headers, &m.column, "masking")?;
            let n = apply(rows, idx, &m.column, &mut |v| apply_masking_value(v, m, &randomize_preserving_class))?;
            count("masking", &m.column, n);
        }

        for col in &self.charcloak {
            let idx = column(headers, col, "charcloak")?;
            let n = apply(rows, idx, col, &mut |v| randomize_preserving_class(v))?;
            count("charcloak", col, n);
        }

        for tcfg in self.tokens.clone() {
            let idx = column(headers, &tcfg.column, "tokenization")?;
            if stage == Stage::CollectTokenValues {
                let set = collected.entry(tcfg.column.clone()).or_default();
                for row in rows.iter() {
                    if !should_skip_value(&row[idx]) {
                        set.insert(normalize_identifier(&row[idx]));
                    }
                }
                continue;
            }
            let (vault, policy) = (&mut self.vault, self.token_policy);
            let n = apply(rows, idx, &tcfg.column, &mut |v| token_for(vault, policy, &normalize_identifier(v), &tcfg))?;
            count("tokenization", &tcfg.column, n);
        }
        if stage == Stage::CollectTokenValues {
            return Ok((stats, collected));
        }

        for ecfg in self.encrypt.clone() {
            let idx = column(headers, &ecfg.column, "encryption")?;
            if ecfg.format_preserving {
                let key = self.key(KeyKind::FpeKey, &ecfg.column)?;
                let n = apply(rows, idx, &ecfg.column, &mut |v| {
                    format_preserving_encrypt(&normalize_identifier(v), &key, &ecfg.column)
                })?;
                count("encrypt_fpe", &ecfg.column, n);
            } else {
                let key = self.key(KeyKind::AesKey, &ecfg.column)?;
                let n = apply(rows, idx, &ecfg.column, &mut |v| {
                    encrypt_value(&normalize_identifier(v), &key, &ecfg.column)
                })?;
                count("encrypt", &ecfg.column, n);
            }
        }
        Ok((stats, collected))
    }
}

/// Applies all configured pre-processing transformations to each input chunk
/// and writes the result back in-place (atomic rename via a `.csv.tmp` file).
///
/// A token vault (`token_vault.json`), symmetric key store (`symmetric_keys.json`),
/// and FPE-encrypt key store (`fpe_encrypt_keys.json`) are maintained in
/// `output_directory` so that mappings are consistent across pipeline re-runs.
/// The techniques themselves are [`Preprocessor`]'s; this function is the file
/// and key-directory plumbing around it.
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
    let token_vault_path = out_dir.join("token_vault.json");
    let mut vault_json: serde_json::Map<String, Value> = if token_vault_path.exists() {
        serde_json::from_str::<Value>(&fs::read_to_string(&token_vault_path)?)?.as_object().cloned().unwrap_or_default()
    } else {
        serde_json::Map::new()
    };
    let read_map = |v: Option<&Value>| -> BTreeMap<String, String> {
        v.and_then(Value::as_object)
            .map(|m| m.iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect())
            .unwrap_or_default()
    };
    let token_cols: Vec<String> = cfg
        .tokenization
        .iter()
        .map(parse_tokenization_config)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|t| t.column)
        .collect();
    let mut vault = MemoryVault::new();
    for col in &token_cols {
        let existing = vault_json.get(col);
        vault.insert_column(
            col,
            read_map(existing.and_then(|c| c.get("forward"))),
            read_map(existing.and_then(|c| c.get("reverse"))),
        );
    }

    // Per-column random salts for salted hashing, consistent within a run across
    // all chunks for the same column. By default generated fresh each run and
    // never written (matches Python behavior). With `shared_hash_salts` they are
    // read from and saved to the key directory, keyed by column name, so tables
    // run one at a time against the same key directory hash a column alike.
    let hash_salts_path = out_dir.join(HASH_SALTS_FILE);
    let hash_salts: BTreeMap<String, String> =
        if cfg.shared_hash_salts { read_json_map_string(&hash_salts_path)? } else { BTreeMap::new() };
    let hash_salts_loaded = hash_salts.len();

    let symmetric_keys_path = out_dir.join("symmetric_keys.json");
    let fpe_encrypt_keys_path = out_dir.join("fpe_encrypt_keys.json");
    let mut keys = KeyMaterial::new();
    for (col, k) in hash_salts {
        keys.insert_hex(KeyKind::HmacSalt, &col, k);
    }
    for (col, k) in read_json_map_string(&symmetric_keys_path)? {
        keys.insert_hex(KeyKind::AesKey, &col, k);
    }
    for (col, k) in read_json_map_string(&fpe_encrypt_keys_path)? {
        keys.insert_hex(KeyKind::FpeKey, &col, k);
    }

    let mut pre = Preprocessor::new(cfg, keys, KeyPolicy::Generate, vault, TokenPolicy::Issue)?;

    let mut stats = PreprocessStats::new();
    for chunk_path in chunks {
        // Records, not lines, and every row as wide as the header: a short row
        // would otherwise skip every technique below and go out in clear.
        let (headers, mut records) = open_csv(chunk_path)?;
        let mut rows: Vec<Vec<String>> = Vec::new();
        while let Some(fields) = records.next_record_of_width(headers.len())? {
            rows.push(fields);
        }
        let mut table = Table::new(headers, rows, chunk_path.display().to_string());
        for (k, n) in pre.apply(&mut table)? {
            *stats.entry(k).or_insert(0) += n;
        }

        let tmp_path = chunk_path.with_extension("csv.tmp");
        let mut w = BufWriter::new(fs::File::create(&tmp_path)?);
        w.write_all(csv_row_to_line(&table.headers).as_bytes())?;
        w.write_all(b"\n")?;
        for row in &table.rows {
            w.write_all(csv_row_to_line(row).as_bytes())?;
            w.write_all(b"\n")?;
        }
        w.flush()?;
        fs::rename(tmp_path, chunk_path)?;
    }

    let (keys, vault, _generated) = pre.into_parts();
    if !token_cols.is_empty() {
        for col in &token_cols {
            let as_obj = |m: &BTreeMap<String, String>| {
                m.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect::<serde_json::Map<_, _>>()
            };
            let cv = vault.column(col).cloned().unwrap_or_default();
            vault_json.insert(
                col.clone(),
                serde_json::json!({ "forward": as_obj(&cv.forward), "reverse": as_obj(&cv.reverse) }),
            );
        }
        write_json_pretty(&token_vault_path, &Value::Object(vault_json))?;
    }
    let as_obj = |m: &BTreeMap<String, String>| {
        Value::Object(m.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect())
    };
    if cfg.shared_hash_salts && keys.hmac_salt.len() > hash_salts_loaded {
        write_json_pretty(&hash_salts_path, &as_obj(&keys.hmac_salt))?;
    }
    write_json_pretty(&symmetric_keys_path, &as_obj(&keys.aes_key))?;
    write_json_pretty(&fpe_encrypt_keys_path, &as_obj(&keys.fpe_key))?;

    Ok(stats)
}

/// Values each technique transformed, keyed `"<technique>:<column>"`
/// (`suppress` counts the rows whose cell was dropped). Counts only — never values.
pub type PreprocessStats = BTreeMap<String, u64>;

#[cfg(test)]
mod preprocessor_tests {
    use super::*;
    use crate::pipeline::bootstrap::parse_runtime_config_value;

    fn cfg(section: &str) -> RuntimeConfig {
        let root: Value = serde_json::from_str(&format!(r#"{{"data_type":"T","T":{section}}}"#)).unwrap();
        parse_runtime_config_value(&root, Path::new("test.json")).unwrap()
    }

    fn table() -> Table {
        Table::new(
            vec!["name".into(), "phone".into(), "id".into()],
            vec![
                vec!["Asha".into(), "9876543210".into(), "A1".into()],
                vec!["Ravi".into(), "".into(), "B2".into()],
                vec!["Asha".into(), "9876543210".into(), "A1".into()],
            ],
            "t",
        )
    }

    #[test]
    fn keys_passed_in_are_used_and_nothing_is_generated() {
        let c = cfg(r#"{"suppress":["name"],"hashing_with_salt":["id"],"encrypt":["phone"]}"#);
        let mut keys = KeyMaterial::new();
        keys.insert(KeyKind::HmacSalt, "id", &[7u8; 32]).unwrap();
        keys.insert(KeyKind::AesKey, "phone", &[9u8; 16]).unwrap();
        let mut pre =
            Preprocessor::new(&c, keys.clone(), KeyPolicy::Require, MemoryVault::new(), TokenPolicy::Issue).unwrap();
        let (mut a, mut b) = (table(), table());
        pre.apply(&mut a).unwrap();
        pre.apply(&mut b).unwrap();
        assert_eq!(a, b, "same keys, same output");
        assert_eq!(a.headers, ["phone", "id"]);
        assert_eq!(a.rows[0][1], keyed_hash(&[7u8; 32], b"A1"));
        assert_eq!(a.rows[1][0], "", "a missing value stays missing");
        assert!(pre.into_parts().2.is_empty());
    }

    #[test]
    fn a_missing_key_is_an_error_when_generation_is_not_allowed() {
        let c = cfg(r#"{"hashing_with_salt":["id"]}"#);
        let mut pre =
            Preprocessor::new(&c, KeyMaterial::new(), KeyPolicy::Require, MemoryVault::new(), TokenPolicy::Issue)
                .unwrap();
        let err = pre.apply(&mut table()).unwrap_err();
        assert!(matches!(err, PipelineError::Validation { code: "KEY_MISSING", .. }));
        // Generation stays the default and is reported.
        let mut pre =
            Preprocessor::new(&c, KeyMaterial::new(), KeyPolicy::Generate, MemoryVault::new(), TokenPolicy::Issue)
                .unwrap();
        pre.apply(&mut table()).unwrap();
        assert_eq!(pre.into_parts().2, [(KeyKind::HmacSalt, "id".to_string())]);
    }

    #[test]
    fn key_length_is_checked_and_debug_does_not_print_keys() {
        let mut keys = KeyMaterial::new();
        assert!(keys.insert(KeyKind::HmacSalt, "id", &[1u8; 16]).is_err());
        keys.insert(KeyKind::AesKey, "phone", &[0xabu8; 16]).unwrap();
        assert!(!format!("{keys:?}").contains("abab"));
    }

    #[test]
    fn tokens_come_from_the_vault_and_executors_cannot_mint() {
        let c = cfg(r#"{"tokenization":[{"column":"id","prefix":"T-","digits":6}]}"#);
        let mut driver =
            Preprocessor::new(&c, KeyMaterial::new(), KeyPolicy::Require, MemoryVault::new(), TokenPolicy::LookupOnly)
                .unwrap();
        // An executor with an empty vault refuses rather than inventing a token.
        let err = driver.apply(&mut table()).unwrap_err();
        assert!(matches!(err, PipelineError::Validation { code: "TOKEN_MISSING", .. }));
        // The driver collects the values, issues tokens, and then lookup works.
        let values = driver.token_values(&mut table()).unwrap();
        assert_eq!(values["id"].len(), 2);
        driver.issue_tokens(&values).unwrap();
        let mut t = table();
        driver.apply(&mut t).unwrap();
        assert!(t.rows[0][2].starts_with("T-"));
        assert_eq!(t.rows[0][2], t.rows[2][2], "one value, one token");
        assert_ne!(t.rows[0][2], t.rows[1][2]);
        assert_eq!(driver.vault().len("id"), 2);
    }

    #[test]
    fn vault_entries_round_trip_and_stay_a_bijection() {
        let mut v = MemoryVault::new();
        v.load_entries("id", [("A".to_string(), "T1".to_string())]).unwrap();
        assert_eq!(v.lookup("id", "A").as_deref(), Some("T1"));
        assert!(v.assign("id", "B", "T1").is_err());
        assert!(v.assign("id", "A", "T2").is_err());
        v.assign("id", "A", "T1").unwrap();
        v.assign("id", "B", "T2").unwrap();
        assert_eq!(v.entries("id").len(), 2);
        assert!(
            v.load_entries("id", [("A".to_string(), "X".to_string()), ("B".to_string(), "X".to_string())]).is_err()
        );
    }
}
