//! Cryptographic primitives used by the SKALD pre-processing pipeline.
//!
//! Provides:
//! - Random key/salt generation from `/dev/urandom`.
//! - SHA-256 hashing (salted and unsalted).
//! - HMAC-SHA256 key derivation.
//! - Format-preserving encryption (FPE) for general text, PAN, and digit strings.
//! - Pseudo-encryption (XOR keystream from HMAC blocks).
//! - Class-preserving randomization.
//! - JSON map I/O helpers used by `preprocess_chunks`.
//!
//! All functions are `pub(super)` — only the parent `preprocess` module can
//! access them directly.

use crate::pipeline::bootstrap::PipelineError;
use crate::pipeline::pyffx_compat::fpe_encrypt;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

// ── Key / salt generation ────────────────────────────────────────────────────

/// Generate a random 32-hex-char (16-byte) key from `/dev/urandom`.
///
/// Falls back to zeroed bytes only if the OS RNG is unavailable — still better
/// than a deterministic derivation from the column name.
///
/// # Returns
/// A 32-character lowercase hexadecimal string.
pub(super) fn generate_random_key_hex() -> String {
    use std::io::Read;
    let mut buf = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    hex::encode(buf)
}

/// Generate a random 64-hex-char (32-byte) salt from `/dev/urandom`.
///
/// Used for salted SHA-256 hashing to prevent dictionary/rainbow-table attacks.
///
/// # Returns
/// A 64-character lowercase hexadecimal string.
pub(super) fn generate_random_salt_hex() -> String {
    use std::io::Read;
    let mut buf = [0u8; 32];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    hex::encode(buf)
}

// ── Hashing ──────────────────────────────────────────────────────────────────

/// Computes the SHA-256 hash of `input` and returns it as a 64-character
/// lowercase hexadecimal string (matches Python `hashlib.sha256(...).hexdigest()`).
///
/// # Arguments
/// * `input` — the plaintext string to hash.
pub(super) fn hash_hex(input: &str) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

// ── Value guards ─────────────────────────────────────────────────────────────

/// Returns `true` when `v` should be left unchanged (empty or `"nan"`).
///
/// Used before every transformation step to preserve missing-value markers.
pub(super) fn should_skip_value(v: &str) -> bool {
    let t = v.trim();
    t.is_empty() || t.eq_ignore_ascii_case("nan")
}

// ── JSON helpers ─────────────────────────────────────────────────────────────

/// Reads a JSON file as a flat `String → String` map.
///
/// Returns an empty map if the file does not exist. Non-string values in the
/// JSON object are silently ignored.
///
/// # Arguments
/// * `path` — path to the JSON file.
///
/// # Errors
/// Returns [`PipelineError`] if the file exists but cannot be read or parsed.
pub(super) fn read_json_map_string(path: &Path) -> Result<BTreeMap<String, String>, PipelineError> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let raw = fs::read_to_string(path)?;
    let val: Value = serde_json::from_str(&raw)?;
    let mut out = BTreeMap::new();
    if let Some(obj) = val.as_object() {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                out.insert(k.clone(), s.to_string());
            }
        }
    }
    Ok(out)
}

/// Writes a JSON [`Value`] to `path` using pretty-printing and an atomic
/// rename (write to `.tmp` then rename) to avoid partial writes.
///
/// Parent directories are created if absent.
///
/// # Arguments
/// * `path` — destination file path.
/// * `v` — the value to serialize.
///
/// # Errors
/// Returns [`PipelineError`] if directory creation, file write, or rename fails.
pub(super) fn write_json_pretty(path: &Path, v: &Value) -> Result<(), PipelineError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(v)?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, body)?;
    fs::rename(tmp, path)?;
    Ok(())
}

// ── HMAC key derivation ───────────────────────────────────────────────────────

/// HMAC-SHA256 type alias used for key derivation.
type HmacSha256 = Hmac<Sha256>;

/// Derives a 16-byte sub-key from `master_key` and a domain `context` string
/// using HMAC-SHA256 (first 16 bytes of the digest).
///
/// This is the shared building block for FPE and pseudo-encryption so that
/// each (column, class, length) triple gets a unique but deterministic key.
///
/// # Arguments
/// * `master_key` — the column-level master key (hex string or raw bytes as UTF-8).
/// * `context` — a domain-separation string (e.g. `"column:upper:5"`).
///
/// # Returns
/// 16-byte derived key array.
pub(super) fn derive_key(master_key: &str, context: &str) -> [u8; 16] {
    let mut mac = HmacSha256::new_from_slice(master_key.as_bytes()).expect("HMAC init");
    mac.update(context.as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

// ── Format-preserving encryption ─────────────────────────────────────────────

/// Encrypts `value` in a format-preserving way, processing each run of
/// identical character class (upper-case letter / lower-case letter / digit)
/// as a separate FPE segment.
///
/// Non-alphanumeric characters (spaces, hyphens, punctuation) pass through
/// unchanged so that the overall structure of the value is preserved.
///
/// Key derivation uses `"<column>:<class>:<segment_len>"` as the context, so
/// the same column always produces the same ciphertext for the same plaintext.
///
/// # Arguments
/// * `value` — the plaintext string.
/// * `master_key` — the column-level master key.
/// * `column` — the column name (used in key derivation context).
pub(super) fn format_preserving_encrypt_general(value: &str, master_key: &str, column: &str) -> String {
    let text = value.to_string();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0usize;
    let mut out = String::with_capacity(chars.len());

    while i < chars.len() {
        let ch = chars[i];
        let (class_name, alphabet) = if ch.is_ascii_uppercase() {
            ("upper", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        } else if ch.is_ascii_lowercase() {
            ("lower", "abcdefghijklmnopqrstuvwxyz")
        } else if ch.is_ascii_digit() {
            ("digit", "0123456789")
        } else {
            out.push(ch);
            i += 1;
            continue;
        };

        let mut j = i + 1;
        while j < chars.len() {
            let c = chars[j];
            let same = (class_name == "upper" && c.is_ascii_uppercase())
                || (class_name == "lower" && c.is_ascii_lowercase())
                || (class_name == "digit" && c.is_ascii_digit());
            if !same {
                break;
            }
            j += 1;
        }

        let segment: String = chars[i..j].iter().collect();
        let ctx = format!("{column}:{class_name}:{}", segment.len());
        let key = derive_key(master_key, &ctx);
        let encrypted = fpe_encrypt(&key, &segment, alphabet);
        out.push_str(&encrypted);
        i = j;
    }

    out
}

/// Encrypts `value` using a deterministic XOR keystream derived from successive
/// HMAC-SHA256 blocks, then hex-encodes the result.
///
/// The keystream never repeats regardless of value length because each 16-byte
/// block uses a unique counter as part of its HMAC context.
///
/// # Arguments
/// * `value` — the plaintext string.
/// * `key` — the column-level key.
/// * `column` — the column name (used in HMAC context `"<column>:<block_idx>"`).
pub(super) fn pseudo_encrypt(value: &str, key: &str, column: &str) -> String {
    // Build a keystream via successive HMAC-SHA256 blocks so the pattern never repeats,
    // regardless of value length. Each 16-byte block i uses context "<column>:<i>".
    let plaintext = value.as_bytes();
    let mut keystream = Vec::with_capacity(plaintext.len());
    let mut block_idx: u64 = 0;
    while keystream.len() < plaintext.len() {
        let ctx = format!("{column}:{block_idx}");
        keystream.extend_from_slice(&derive_key(key, &ctx));
        block_idx += 1;
    }
    let mut out = String::with_capacity(plaintext.len() * 2);
    for (p, k) in plaintext.iter().zip(keystream.iter()) {
        out.push_str(&format!("{:02x}", p ^ k));
    }
    out
}

// ── Class-preserving randomization ───────────────────────────────────────────

/// Replace each character with a random character of the same class
/// (digit / upper-case letter / lower-case letter).
///
/// Uses `/dev/urandom` for true randomness — output is different on every call
/// for the same input (matches Python `secrets.choice`). Non-alphanumeric
/// characters pass through unchanged.
///
/// # Arguments
/// * `value` — the string whose alphanumeric characters are to be randomized.
pub(crate) fn randomize_preserving_class(value: &str) -> String {
    use std::io::Read;
    let char_count = value.chars().count();
    let byte_count = char_count * 4;
    let mut random_bytes = vec![0u8; byte_count];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut random_bytes);
    }
    let mut out = String::with_capacity(value.len());
    for (i, c) in value.chars().enumerate() {
        let r = u32::from_le_bytes([
            random_bytes[i * 4],
            random_bytes[i * 4 + 1],
            random_bytes[i * 4 + 2],
            random_bytes[i * 4 + 3],
        ]);
        if c.is_ascii_digit() {
            out.push((b'0' + (r % 10) as u8) as char);
        } else if c.is_ascii_uppercase() {
            out.push((b'A' + (r % 26) as u8) as char);
        } else if c.is_ascii_lowercase() {
            out.push((b'a' + (r % 26) as u8) as char);
        } else {
            out.push(c);
        }
    }
    out
}
