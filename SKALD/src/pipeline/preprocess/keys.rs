//! Keys and salts handed to preprocessing, by kind and column.
//!
//! Until now every key was generated into a key directory by the run itself.
//! A caller that owns its keys (the Anamika job flow releases them from a key
//! broker; the Spark executors must all use the same ones) passes them in
//! here instead. Generation stays the default: with nothing passed, the
//! missing ones are generated, exactly as before.

use crate::pipeline::bootstrap::{PipelineError, validation};
use std::collections::BTreeMap;
use std::fmt;

/// What a key is for. Each kind has its own length and its own map, so the
/// same column can carry a salt and an encryption key without confusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyKind {
    /// `hashing_with_salt`: the 32-byte HMAC-SHA256 key.
    HmacSalt,
    /// `encrypt` (AES-SIV): the 16-byte master key.
    AesKey,
    /// `encrypt` with `format_preserving` (FF1): the 16-byte master key.
    FpeKey,
}

impl KeyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyKind::HmacSalt => "hmac_salt",
            KeyKind::AesKey => "aes_key",
            KeyKind::FpeKey => "fpe_key",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "hmac_salt" => Some(KeyKind::HmacSalt),
            "aes_key" => Some(KeyKind::AesKey),
            "fpe_key" => Some(KeyKind::FpeKey),
            _ => None,
        }
    }

    /// Length in bytes of a key of this kind.
    pub fn len(self) -> usize {
        match self {
            KeyKind::HmacSalt => 32,
            KeyKind::AesKey | KeyKind::FpeKey => 16,
        }
    }

    pub fn is_empty(self) -> bool {
        false
    }
}

/// Keys by kind, then column. Stored as the lowercase hex the key files and
/// the crypto primitives already use, so a key passed in as bytes and the same
/// key read from a key directory produce identical output.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct KeyMaterial {
    pub(crate) hmac_salt: BTreeMap<String, String>,
    pub(crate) aes_key: BTreeMap<String, String>,
    pub(crate) fpe_key: BTreeMap<String, String>,
}

// Never print key bytes: `{:?}` of a config or an error must be safe to log.
impl fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("hmac_salt", &self.hmac_salt.keys().collect::<Vec<_>>())
            .field("aes_key", &self.aes_key.keys().collect::<Vec<_>>())
            .field("fpe_key", &self.fpe_key.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl KeyMaterial {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn map(&self, kind: KeyKind) -> &BTreeMap<String, String> {
        match kind {
            KeyKind::HmacSalt => &self.hmac_salt,
            KeyKind::AesKey => &self.aes_key,
            KeyKind::FpeKey => &self.fpe_key,
        }
    }

    pub(crate) fn map_mut(&mut self, kind: KeyKind) -> &mut BTreeMap<String, String> {
        match kind {
            KeyKind::HmacSalt => &mut self.hmac_salt,
            KeyKind::AesKey => &mut self.aes_key,
            KeyKind::FpeKey => &mut self.fpe_key,
        }
    }

    /// Sets the key for `column` from raw bytes.
    ///
    /// # Errors
    /// `KEY_MATERIAL_INVALID` when `bytes` is not the length `kind` needs.
    pub fn insert(&mut self, kind: KeyKind, column: &str, bytes: &[u8]) -> Result<(), PipelineError> {
        if bytes.len() != kind.len() {
            return Err(validation(
                "KEY_MATERIAL_INVALID",
                &format!("A {} must be {} bytes (got {})", kind.as_str(), kind.len(), bytes.len()),
                column,
            ));
        }
        self.map_mut(kind).insert(column.to_string(), hex::encode(bytes));
        Ok(())
    }

    /// Sets the key for `column` from the hex string a key file holds.
    pub(crate) fn insert_hex(&mut self, kind: KeyKind, column: &str, hex: String) {
        self.map_mut(kind).insert(column.to_string(), hex);
    }

    /// The key for `column` as raw bytes, if present.
    pub fn bytes(&self, kind: KeyKind, column: &str) -> Option<Vec<u8>> {
        hex::decode(self.map(kind).get(column)?).ok()
    }

    pub fn contains(&self, kind: KeyKind, column: &str) -> bool {
        self.map(kind).contains_key(column)
    }

    /// Columns that have a key of `kind`.
    pub fn columns(&self, kind: KeyKind) -> Vec<String> {
        self.map(kind).keys().cloned().collect()
    }

    /// Generates a key (from the OS RNG) for each `(kind, column)` that has
    /// none, and returns the ones it generated.
    ///
    /// # Errors
    /// `RNG_UNAVAILABLE` when the OS cannot supply randomness.
    pub fn generate_missing(
        &mut self,
        required: &[(KeyKind, String)],
    ) -> Result<Vec<(KeyKind, String)>, PipelineError> {
        use super::crypto::{generate_random_key_hex, generate_random_salt_hex};
        let mut made = Vec::new();
        for (kind, column) in required {
            if self.contains(*kind, column) {
                continue;
            }
            let k = match kind {
                KeyKind::HmacSalt => generate_random_salt_hex()?,
                KeyKind::AesKey | KeyKind::FpeKey => generate_random_key_hex()?,
            };
            self.insert_hex(*kind, column, k);
            made.push((*kind, column.clone()));
        }
        Ok(made)
    }
}
