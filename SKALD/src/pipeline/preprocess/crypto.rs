//! Cryptographic primitives used by the SKALD pre-processing pipeline.
//!
//! Provides:
//! - Random key/salt generation from the operating system's CSPRNG.
//! - Keyed hashing (HMAC-SHA256) for `hashing_with_salt`.
//! - HMAC-SHA256 key derivation.
//! - Deterministic authenticated encryption (AES-SIV) for `encrypt`.
//! - Format-preserving encryption (NIST FF1) for `encrypt` with
//!   `format_preserving`.
//! - Class-preserving randomization.
//! - Writing key material with owner-only permissions.
//!
//! Primitives the per-document flows (`nested_json`, `fhir_bundle`) also apply
//! are `pub(crate)`, so a technique means the same thing in every flow; the
//! encryption functions are `pub` so their output can be decrypted by tools
//! and tests outside the crate.

use crate::pipeline::bootstrap::{PipelineError, validation};
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use serde_json::Value;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;

// ── Key / salt generation ────────────────────────────────────────────────────

/// `n` bytes from the operating system's CSPRNG, hex-encoded.
///
/// # Errors
/// `RNG_UNAVAILABLE` when the OS cannot supply randomness. There is no
/// fallback: a predictable key or salt is worse than no run at all.
fn random_hex(n: usize) -> Result<String, PipelineError> {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).map_err(|e| {
        validation("RNG_UNAVAILABLE", "The operating system's random number generator failed", &e.to_string())
    })?;
    Ok(hex::encode(buf))
}

/// A random 32-hex-char (16-byte) key.
pub(crate) fn generate_random_key_hex() -> Result<String, PipelineError> {
    random_hex(16)
}

/// A random 64-hex-char (32-byte) salt.
pub(crate) fn generate_random_salt_hex() -> Result<String, PipelineError> {
    random_hex(32)
}

/// The key for `column` in `keys`, generating and storing a new one if absent.
pub(crate) fn key_for(keys: &mut BTreeMap<String, String>, column: &str) -> Result<String, PipelineError> {
    if let Some(k) = keys.get(column) {
        return Ok(k.clone());
    }
    let k = generate_random_key_hex()?;
    keys.insert(column.to_string(), k.clone());
    Ok(k)
}

// ── Hashing ──────────────────────────────────────────────────────────────────

/// The 32-byte HMAC key a stored salt encodes. Salts are written as 64 hex
/// characters; anything else — a hand-edited file, or a salt SKALD < 4.0
/// derived from the clock — is refused rather than hashed under.
///
/// # Errors
/// `KEY_MATERIAL_INVALID` when `salt_hex` is not 64 hex characters.
pub(crate) fn hash_key(salt_hex: &str, owner: &str) -> Result<[u8; 32], PipelineError> {
    let mut key = [0u8; 32];
    hex::decode_to_slice(salt_hex, &mut key).map_err(|_| {
        validation(
            "KEY_MATERIAL_INVALID",
            "A hash salt must be 64 hex characters (32 bytes); move the file away and rerun to generate a new one",
            owner,
        )
    })?;
    Ok(key)
}

/// `hashing_with_salt`: HMAC-SHA256 of `value` under `key`, as 64 lowercase
/// hex characters (Python: `hmac.new(key, value, hashlib.sha256).hexdigest()`).
pub(crate) fn keyed_hash(key: &[u8; 32], value: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(value);
    hex::encode(mac.finalize().into_bytes())
}

// ── Value guards ─────────────────────────────────────────────────────────────

/// Returns `true` when `v` should be left unchanged (empty or `"nan"`).
///
/// Used before every transformation step to preserve missing-value markers.
pub(super) fn should_skip_value(v: &str) -> bool {
    let t = v.trim();
    t.is_empty() || t.eq_ignore_ascii_case("nan")
}

/// Canonical form of an identifier before it is hashed, encrypted or
/// tokenised: surrounding whitespace removed and Unicode NFC. Without it
/// `" 1234"`, `"1234 "` and `"1234"` would get three different pseudonyms.
pub(crate) fn normalize_identifier(v: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    v.trim().nfc().collect()
}

// ── Key material files ───────────────────────────────────────────────────────

/// Reads a JSON file as a flat `String → String` map.
///
/// Returns an empty map if the file does not exist. Non-string values in the
/// JSON object are silently ignored.
///
/// # Errors
/// Returns [`PipelineError`] if the file exists but cannot be read or parsed.
pub(crate) fn read_json_map_string(path: &Path) -> Result<BTreeMap<String, String>, PipelineError> {
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

/// Creates `path` (and parents) and restricts it to its owner (0700 on Unix).
pub(crate) fn ensure_private_dir(path: &Path) -> Result<(), PipelineError> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Writes key material: to a temp file created owner-only (0600 on Unix),
/// synced, then renamed over `path`, whose mode is then set again — so a key
/// file is never readable by others, not even for a moment, and a mode an
/// operator tightened by hand is not undone by the next run.
pub(crate) fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<(), PipelineError> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Writes a JSON [`Value`] holding key material (see [`write_secret_file`]).
pub(crate) fn write_json_pretty(path: &Path, v: &Value) -> Result<(), PipelineError> {
    write_secret_file(path, serde_json::to_string_pretty(v)?.as_bytes())
}

// ── HMAC key derivation ───────────────────────────────────────────────────────

/// HMAC-SHA256 type alias used for key derivation.
type HmacSha256 = Hmac<Sha256>;

/// 32 bytes derived from `master_key` for one purpose, `context`, with
/// HMAC-SHA256. The master key string's bytes are the HMAC key, as they have
/// always been, so existing key files stay valid.
pub(crate) fn derive_key32(master_key: &str, context: &str) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(master_key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(context.as_bytes());
    mac.finalize().into_bytes().into()
}

// ── encrypt: AES-SIV ─────────────────────────────────────────────────────────

const ENC_PREFIX: &str = "ENC1$";

fn siv(master_key: &str) -> aes_siv::siv::Aes128Siv {
    use aes_siv::KeyInit;
    aes_siv::siv::Aes128Siv::new_from_slice(&derive_key32(master_key, "skald/encrypt/aes-siv/v1"))
        .expect("AES-128-SIV takes a 32-byte key")
}

/// Encrypts `value` with AES-SIV, authenticated with `column` as associated
/// data, and returns `ENC1$` + hex.
///
/// Deterministic on purpose — the same value in the same column always gives
/// the same ciphertext, so encrypted columns still join — but unlike the XOR
/// keystream it replaces, one known plaintext reveals nothing about any other
/// value, and a tampered ciphertext fails to decrypt.
pub fn encrypt_value(value: &str, master_key: &str, column: &str) -> Result<String, PipelineError> {
    let ct = siv(master_key)
        .encrypt([column.as_bytes()], value.as_bytes())
        .map_err(|_| validation("ENCRYPTION_FAILED", "AES-SIV encryption failed", column))?;
    Ok(format!("{ENC_PREFIX}{}", hex::encode(ct)))
}

/// Inverse of [`encrypt_value`].
pub fn decrypt_value(ciphertext: &str, master_key: &str, column: &str) -> Result<String, PipelineError> {
    let fail = || validation("ENCRYPTION_FAILED", "Not a valid ciphertext for this column and key", column);
    let raw = hex::decode(ciphertext.strip_prefix(ENC_PREFIX).ok_or_else(fail)?).map_err(|_| fail())?;
    let pt = siv(master_key).decrypt([column.as_bytes()], &raw).map_err(|_| fail())?;
    String::from_utf8(pt).map_err(|_| fail())
}

// ── encrypt + format_preserving: NIST FF1 ───────────────────────────────────
//
// Each ASCII digit or letter position keeps its class (digit, upper, lower);
// everything else that is not a letter or digit (spaces, '-', '@', '.') stays
// in place. The class digits of the WHOLE value form one mixed-radix number,
// which is encrypted as one FF1 numeral string — so `1234 5678 9012` is one
// 12-digit domain, not three 4-digit ones, and equal blocks do not encrypt
// equally. Cycle-walking keeps the result inside the value's own domain.

/// NIST SP 800-38G Rev. 1 minimum domain size.
const FF1_MIN_DOMAIN: u64 = 1_000_000;

#[derive(Clone, Copy, PartialEq)]
enum CharClass {
    Digit,
    Upper,
    Lower,
}

impl CharClass {
    fn of(c: char) -> Option<Self> {
        if c.is_ascii_digit() {
            Some(Self::Digit)
        } else if c.is_ascii_uppercase() {
            Some(Self::Upper)
        } else if c.is_ascii_lowercase() {
            Some(Self::Lower)
        } else {
            None
        }
    }
    fn radix(self) -> u32 {
        if self == Self::Digit { 10 } else { 26 }
    }
    fn index(self, c: char) -> u32 {
        match self {
            Self::Digit => c as u32 - '0' as u32,
            Self::Upper => c as u32 - 'A' as u32,
            Self::Lower => c as u32 - 'a' as u32,
        }
    }
    fn char_at(self, i: u32) -> char {
        let base = match self {
            Self::Digit => b'0',
            Self::Upper => b'A',
            Self::Lower => b'a',
        };
        (base + i as u8) as char
    }
    fn tag(self) -> u8 {
        match self {
            Self::Digit => b'D',
            Self::Upper => b'U',
            Self::Lower => b'L',
        }
    }
}

/// A value split into class positions and literals, plus the FF1 tweak that
/// binds the column and the value's shape.
struct Shape {
    chars: Vec<char>,
    classes: Vec<Option<CharClass>>,
    domain: BigUint,
    tweak: Vec<u8>,
}

fn shape(value: &str, column: &str) -> Result<Shape, PipelineError> {
    let chars: Vec<char> = value.chars().collect();
    let mut classes = Vec::with_capacity(chars.len());
    let mut domain = BigUint::from(1u32);
    let mut tweak = column.as_bytes().to_vec();
    tweak.push(0);
    for &c in &chars {
        let class = CharClass::of(c);
        match class {
            Some(k) => {
                domain *= k.radix();
                tweak.push(k.tag());
            }
            // A letter or digit outside ASCII would otherwise pass through in
            // clear — a Devanagari name published verbatim. Refuse instead.
            None if c.is_alphanumeric() => {
                return Err(validation(
                    "FPE_VALUE_UNSUPPORTED",
                    "Format-preserving encryption only handles ASCII letters and digits",
                    &format!("column {column}: a value contains letters or digits in another script"),
                ));
            }
            None => {
                let mut buf = [0u8; 4];
                tweak.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
        classes.push(class);
    }
    if domain < BigUint::from(FF1_MIN_DOMAIN) {
        return Err(validation(
            "FPE_DOMAIN_TOO_SMALL",
            "Value too short for format-preserving encryption",
            &format!("column {column}: a value has fewer than {FF1_MIN_DOMAIN} possible values of its shape"),
        ));
    }
    Ok(Shape { chars, classes, domain, tweak })
}

impl Shape {
    /// The class positions as one mixed-radix number.
    fn to_number(&self) -> BigUint {
        let mut x = BigUint::from(0u32);
        for (c, class) in self.chars.iter().zip(&self.classes) {
            if let Some(k) = class {
                x = x * k.radix() + k.index(*c);
            }
        }
        x
    }

    /// The value with its class positions replaced by `x`'s mixed-radix digits.
    fn with_number(&self, mut x: BigUint) -> String {
        let mut out = self.chars.clone();
        for (i, class) in self.classes.iter().enumerate().rev() {
            if let Some(k) = class {
                let r = BigUint::from(k.radix());
                let d = (&x % &r).to_u32_digits().first().copied().unwrap_or(0);
                x /= r;
                out[i] = k.char_at(d);
            }
        }
        out.into_iter().collect()
    }

    /// Number of decimal digits FF1 works on: enough for every value below the domain.
    fn width(&self) -> usize {
        (&self.domain - 1u32).to_str_radix(10).len().max(6)
    }
}

fn to_numerals(x: &BigUint, width: usize) -> Vec<u16> {
    let s = x.to_str_radix(10);
    let mut v = vec![0u16; width - s.len()];
    v.extend(s.bytes().map(|b| (b - b'0') as u16));
    v
}

fn from_numerals(v: &[u16]) -> BigUint {
    v.iter().fold(BigUint::from(0u32), |acc, &d| acc * 10u32 + d as u32)
}

fn ff1(master_key: &str) -> fpe::ff1::FF1<aes::Aes256> {
    fpe::ff1::FF1::<aes::Aes256>::new(&derive_key32(master_key, "skald/fpe/ff1/v1"), 10).expect("radix 10 is valid")
}

fn ff1_walk(value: &str, master_key: &str, column: &str, encrypt: bool) -> Result<String, PipelineError> {
    use fpe::ff1::FlexibleNumeralString;
    let shape = shape(value, column)?;
    let ff1 = ff1(master_key);
    let width = shape.width();
    let fail = || validation("ENCRYPTION_FAILED", "Format-preserving encryption failed", column);
    let mut x = shape.to_number();
    // Cycle-walking: FF1 permutes 10^width numbers; re-apply it until the
    // result is back inside the value's domain. Each step lands inside with
    // probability domain / 10^width > 1/10, so this ends quickly.
    loop {
        let ns = FlexibleNumeralString::from(to_numerals(&x, width));
        let out = if encrypt { ff1.encrypt(&shape.tweak, &ns) } else { ff1.decrypt(&shape.tweak, &ns) }
            .map_err(|_| fail())?;
        x = from_numerals(&Vec::<u16>::from(out));
        if x < shape.domain {
            return Ok(shape.with_number(x));
        }
    }
}

/// Encrypts `value` with FF1, preserving its length, every character's class
/// (digit / upper-case / lower-case) and every other character in place.
///
/// # Errors
/// `FPE_VALUE_UNSUPPORTED` for letters or digits outside ASCII;
/// `FPE_DOMAIN_TOO_SMALL` for values with fewer than a million possible
/// values of their shape (a 1-character or 5-digit value would be guessable).
pub fn format_preserving_encrypt(value: &str, master_key: &str, column: &str) -> Result<String, PipelineError> {
    ff1_walk(value, master_key, column, true)
}

/// Inverse of [`format_preserving_encrypt`].
pub fn format_preserving_decrypt(value: &str, master_key: &str, column: &str) -> Result<String, PipelineError> {
    ff1_walk(value, master_key, column, false)
}

// ── Class-preserving randomization ───────────────────────────────────────────

/// Replace each letter or digit with a random one of the same class, keeping
/// case; any other character is kept. Letters and digits in any script are
/// replaced (by ASCII ones), so no original letter survives.
///
/// # Errors
/// `RNG_UNAVAILABLE` when the OS cannot supply randomness.
pub(crate) fn randomize_preserving_class(value: &str) -> Result<String, PipelineError> {
    let chars: Vec<char> = value.chars().collect();
    let mut random_bytes = vec![0u8; chars.len() * 4];
    getrandom::fill(&mut random_bytes).map_err(|e| {
        validation("RNG_UNAVAILABLE", "The operating system's random number generator failed", &e.to_string())
    })?;
    let mut out = String::with_capacity(value.len());
    for (i, c) in chars.into_iter().enumerate() {
        let r = u32::from_le_bytes([
            random_bytes[i * 4],
            random_bytes[i * 4 + 1],
            random_bytes[i * 4 + 2],
            random_bytes[i * 4 + 3],
        ]);
        if c.is_numeric() {
            out.push((b'0' + (r % 10) as u8) as char);
        } else if c.is_alphabetic() && c.is_uppercase() {
            out.push((b'A' + (r % 26) as u8) as char);
        } else if c.is_alphabetic() {
            out.push((b'a' + (r % 26) as u8) as char);
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "00112233445566778899aabbccddeeff";

    /// Pinned against Python's `hmac.new(bytes(range(32)), b"BOCW/UP/1",
    /// hashlib.sha256).hexdigest()`, so a token can be recomputed outside SKALD.
    #[test]
    fn keyed_hash_is_hmac_sha256_under_the_decoded_salt() {
        let salt: String = (0u8..32).map(|b| format!("{b:02x}")).collect();
        let key = hash_key(&salt, "col").unwrap();
        assert_eq!(key, std::array::from_fn::<u8, 32, _>(|i| i as u8));
        assert_eq!(keyed_hash(&key, b"BOCW/UP/1"), "5b4bed85ff61c96ad4d36d61eb290807fe8414d4f3e97abec032405af7d20d25");
    }

    #[test]
    fn a_salt_that_is_not_32_hex_bytes_is_refused() {
        for bad in ["", "test-salt", "00ff", &"g".repeat(64), &"0".repeat(66)] {
            let err = hash_key(bad, "col").unwrap_err();
            assert!(err.to_string().contains("KEY_MATERIAL_INVALID"), "{bad}: {err}");
        }
    }

    #[test]
    fn fpe_round_trips_and_preserves_shape() {
        for v in ["1234 5678 9012", "+91-98765-43210", "ABCDE1234F", "user.name42@example.com"] {
            let ct = format_preserving_encrypt(v, KEY, "col").expect("encrypt");
            assert_ne!(ct, v);
            assert_eq!(ct.len(), v.len());
            for (a, b) in v.chars().zip(ct.chars()) {
                assert_eq!(CharClass::of(a).map(CharClass::tag), CharClass::of(b).map(CharClass::tag), "{v} → {ct}");
                if CharClass::of(a).is_none() {
                    assert_eq!(a, b);
                }
            }
            assert_eq!(format_preserving_decrypt(&ct, KEY, "col").expect("decrypt"), v);
        }
    }

    #[test]
    fn fpe_does_not_encrypt_equal_blocks_equally() {
        let ct = format_preserving_encrypt("1111 2222 1111", KEY, "aadhaar").expect("encrypt");
        let blocks: Vec<&str> = ct.split(' ').collect();
        assert_ne!(blocks[0], blocks[2], "{ct}");
    }

    #[test]
    fn fpe_is_not_a_per_character_shift() {
        // The pyffx construction it replaces shifted every 1-character segment
        // by one key-dependent constant.
        let shifts: std::collections::BTreeSet<u32> = (0..10u32)
            .map(|d| {
                let v = format!("{d}00000");
                let c = format_preserving_encrypt(&v, KEY, "c").expect("encrypt");
                (c.as_bytes()[0] as u32 + 10 - b'0' as u32 - d) % 10
            })
            .collect();
        assert!(shifts.len() > 1, "{shifts:?}");
    }

    #[test]
    fn fpe_refuses_small_domains_and_non_ascii_letters() {
        for v in ["5", "12345", "AB"] {
            let err = format_preserving_encrypt(v, KEY, "c").expect_err(v);
            assert!(matches!(err, PipelineError::Validation { code: "FPE_DOMAIN_TOO_SMALL", .. }), "{v}: {err:?}");
        }
        let err = format_preserving_encrypt("राम प्रसाद", KEY, "c").expect_err("devanagari");
        assert!(
            matches!(err, PipelineError::Validation { code: "FPE_VALUE_UNSUPPORTED", ref details, .. } if !details.contains("राम"))
        );
    }

    #[test]
    fn fpe_depends_on_the_column() {
        let a = format_preserving_encrypt("9876543210", KEY, "a").expect("a");
        let b = format_preserving_encrypt("9876543210", KEY, "b").expect("b");
        assert_ne!(a, b);
    }

    #[test]
    fn encrypt_resists_known_plaintext_and_round_trips() {
        let a = encrypt_value("Alice Kumar", KEY, "Name").expect("a");
        let b = encrypt_value("Ravi Shankar", KEY, "Name").expect("b");
        let raw = |s: &str| hex::decode(s.trim_start_matches(ENC_PREFIX)).unwrap();
        // XOR of the known plaintext with its ciphertext must not decrypt the other value.
        let stream: Vec<u8> = raw(&a).iter().zip(b"Alice Kumar").map(|(c, p)| c ^ p).collect();
        let guess: Vec<u8> = raw(&b).iter().zip(&stream).map(|(c, k)| c ^ k).collect();
        assert_ne!(&guess[..], &b"Ravi Shankar"[..guess.len()]);
        assert_eq!(decrypt_value(&b, KEY, "Name").expect("decrypt"), "Ravi Shankar");
        assert_eq!(encrypt_value("Ravi Shankar", KEY, "Name").expect("again"), b, "deterministic");
        assert!(decrypt_value(&b, KEY, "Other").is_err(), "column is authenticated");
    }

    #[test]
    fn identifiers_are_normalised_before_use() {
        assert_eq!(normalize_identifier(" 1234"), "1234");
        assert_eq!(normalize_identifier("1234 "), "1234");
        assert_eq!(normalize_identifier("E\u{301}"), "É");
    }

    #[test]
    fn charcloak_replaces_letters_in_every_script() {
        let out = randomize_preserving_class("राम Kumar 42").expect("rng");
        assert!(!out.contains('र') && !out.contains("Kumar") && out.contains(' '), "{out}");
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_are_owner_only_even_over_a_world_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("skald-secret-{}", std::process::id()));
        let path = dir.join("keys.json");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&path, "{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_secret_file(&path, b"{\"k\":\"v\"}").unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        let _ = fs::remove_dir_all(&dir);
    }
}
