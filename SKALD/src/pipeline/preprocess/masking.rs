//! Masking configuration parsing and application for the SKALD pre-processing pipeline.
//!
//! This module provides:
//! - Parsed lightweight configuration structs for tokenization, FPE, encryption,
//!   and masking operations.
//! - Regex-based masking helpers that mirror the Python pipeline's logic exactly.
//! - The [`apply_masking_value`] entry point that executes masking steps in the
//!   order specified by `apply_order` in the pipeline configuration.
//!
//! All public items in this module are `pub(super)` — they are accessed only
//! through the parent `preprocess` module.

use crate::pipeline::bootstrap::{validation, PipelineError};
use regex::Regex;
use serde_json::Value;

// ── Tokenization ──────────────────────────────────────────────────────────────

/// Lightweight tokenization configuration parsed from a pipeline config entry.
///
/// Tokenization replaces original values with opaque sequential tokens of the
/// form `<prefix><zero-padded-id>`, preserving a reversible vault mapping.
#[derive(Debug)]
pub(super) struct TokenizationConfigLite {
    /// Target CSV column name.
    pub(super) column: String,
    /// Token prefix string (default: `"TK-"`).
    pub(super) prefix: String,
    /// Number of zero-padded digits in the token suffix (default: `6`).
    pub(super) digits: usize,
}

/// Parses a single tokenization config entry from the pipeline JSON.
///
/// # Arguments
/// * `entry` — a JSON object with keys `"column"` (required), `"prefix"`, `"digits"`.
///
/// # Errors
/// Returns [`PipelineError`] with code `PREPROCESS_CONFIG_INVALID` if the
/// entry is not an object, `"column"` is missing, or `"digits"` is ≤ 0.
pub(super) fn parse_tokenization_config(entry: &Value) -> Result<TokenizationConfigLite, PipelineError> {
    let obj = entry
        .as_object()
        .ok_or_else(|| validation("PREPROCESS_CONFIG_INVALID", "Each tokenization entry must be an object", "tokenization"))?;
    let column = obj
        .get("column")
        .and_then(Value::as_str)
        .ok_or_else(|| validation("PREPROCESS_CONFIG_INVALID", "Tokenization config missing 'column'", "tokenization"))?
        .to_string();
    let prefix = obj.get("prefix").and_then(Value::as_str).unwrap_or("TK-").to_string();
    let digits = obj.get("digits").and_then(Value::as_i64).unwrap_or(6);
    if digits <= 0 {
        return Err(validation("PREPROCESS_CONFIG_INVALID", "tokenization 'digits' must be > 0", &column));
    }
    Ok(TokenizationConfigLite { column, prefix, digits: digits as usize })
}

// ── Symmetric / format-preserving encryption config ──────────────────────────

/// Lightweight encryption configuration parsed from a pipeline config entry.
///
/// Supports both pseudo-encryption (XOR keystream, `format_preserving: false`)
/// and format-preserving general encryption (`format_preserving: true`).
#[derive(Debug)]
pub(super) struct EncryptConfigLite {
    /// Target CSV column name.
    pub(super) column: String,
    /// `true` → use [`format_preserving_encrypt_general`]; `false` → use
    /// [`pseudo_encrypt`] (XOR keystream, hex output with `"ENC$"` prefix).
    pub(super) format_preserving: bool,
}

/// Parses a single encrypt config entry from the pipeline JSON.
///
/// Accepts two forms:
/// - A plain string `"column_name"` → `format_preserving: false`.
/// - An object `{ "column_name": { "format_preserving": true|false } }`.
///
/// # Errors
/// Returns [`PipelineError`] with code `PREPROCESS_CONFIG_INVALID` for
/// malformed entries.
pub(super) fn parse_encrypt_config(entry: &Value) -> Result<EncryptConfigLite, PipelineError> {
    if let Some(col) = entry.as_str() {
        return Ok(EncryptConfigLite { column: col.to_string(), format_preserving: false });
    }
    let obj = entry
        .as_object()
        .ok_or_else(|| validation("PREPROCESS_CONFIG_INVALID", "Encrypt entry must be string or object", "encrypt"))?;
    if obj.len() != 1 {
        return Err(validation("PREPROCESS_CONFIG_INVALID", "Encrypt object entry must contain one column key", "encrypt"));
    }
    let (column, opts) = obj.iter().next().expect("checked len=1");
    let format_preserving = opts
        .as_object()
        .and_then(|m| m.get("format_preserving"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(EncryptConfigLite { column: column.clone(), format_preserving })
}

// ── Regex masking config ──────────────────────────────────────────────────────

/// How many characters a delimiter-anchored pattern masks.
///
/// Parsed from the optional `length` key of a `regex_patterns` entry:
/// - `"length": "all"` → [`MaskLength::All`] — mask every character on the
///   chosen side of the delimiter.
/// - `"length": 4` → [`MaskLength::Count`] — mask exactly that many characters
///   adjacent to the delimiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MaskLength {
    /// Mask the whole side of the delimiter (everything before it, or
    /// everything after it, up to the first occurrence of the delimiter).
    All,
    /// Mask exactly this many characters next to each delimiter occurrence.
    Count(usize),
}

/// Describes how a regex pattern is specified — either as a literal regex string
/// or as a semantic descriptor that is converted to a regex at apply time.
#[derive(Debug, Clone)]
pub(super) enum RegexPatternKind {
    /// A literal regex string provided directly in the config.
    Literal(String),
    /// A semantic descriptor: `type` is one of `"before"`, `"after"`,
    /// `"in_between"`; `delimiter`/`start`/`end` define anchors.
    Derived {
        pattern_type: String,
        delimiter: Option<String>,
        start: Option<String>,
        end: Option<String>,
    },
}

/// Per-pattern masking configuration within a column's `regex_patterns` list.
#[derive(Debug, Clone)]
pub(super) struct RegexPatternConfig {
    /// How the pattern is specified.
    pub(super) kind: RegexPatternKind,
    /// Character used to replace matched text (may override the column default).
    pub(super) masking_char: char,
    /// Optional length for delimiter-anchored masking
    /// (`type=before`/`after` + `length` key): a fixed character count, or
    /// [`MaskLength::All`] for the whole side of the delimiter.
    pub(super) length: Option<MaskLength>,
    /// Optional group-level masking: pairs of `(capture_group_index, "full"|"partial")`.
    pub(super) mask_groups: Vec<(usize, String)>,
    /// Semantic type (`"before"`, `"after"`, `"in_between"`) — stored regardless
    /// of whether a literal `regex` field is also present, so delimiter-length
    /// masking fires even when the kind is `Literal`.
    pub(super) pattern_type: Option<String>,
    /// Delimiter string for `"before"` / `"after"` length masking — stored
    /// alongside `kind` for the same reason.
    pub(super) delimiter: Option<String>,
    /// Start anchor for `"in_between"` patterns (used in derived fallback).
    pub(super) start: Option<String>,
    /// End anchor for `"in_between"` patterns (used in derived fallback).
    pub(super) end: Option<String>,
}

/// Full masking configuration for one CSV column.
///
/// Supports three orthogonal masking steps that can be composed in any order
/// via `apply_order`:
/// 1. **characters** — mask specific 1-based character positions.
/// 2. **regex** — apply one or more regex patterns.
/// 3. **class** — replace each character with a fixed or random character of
///    the same class.
#[derive(Debug)]
pub(super) struct MaskingConfigLite {
    /// Target CSV column name.
    pub(super) column: String,
    /// Default masking character for this column (e.g. `'*'`).
    pub(super) masking_char: char,
    /// 1-based character positions to mask (applied in the `"characters"` step).
    pub(super) characters_to_mask: Vec<usize>,
    /// Regex patterns applied in the `"regex"` step.
    pub(super) regex_patterns: Vec<RegexPatternConfig>,
    /// Ordered list of steps to apply: `"characters"`, `"regex"`, `"class"`.
    pub(super) apply_order: Vec<String>,
    /// Class masking mode: `"random_class"` or `"fixed_class"`, or `None`.
    pub(super) class_masking_mode: Option<String>,
    /// Character used to replace letters in `"fixed_class"` mode (default `'X'`).
    pub(super) class_letter: char,
    /// Character used to replace digits in `"fixed_class"` mode (default `'0'`).
    pub(super) class_digit: char,
}

/// Parses a single masking config entry from the pipeline JSON.
///
/// # Arguments
/// * `entry` — a JSON object with required key `"column"` and optional keys
///   `"masking_char"`, `"characters_to_mask"`, `"regex_patterns"`,
///   `"apply_order"`, `"class_masking_mode"`, `"class_mask_letter"`,
///   `"class_mask_digit"`.
///
/// # Errors
/// Returns [`PipelineError`] with code `PREPROCESS_CONFIG_INVALID` for
/// malformed entries.
pub(super) fn parse_masking_config(entry: &Value) -> Result<MaskingConfigLite, PipelineError> {
    let obj = entry
        .as_object()
        .ok_or_else(|| validation("PREPROCESS_CONFIG_INVALID", "Each masking entry must be an object", "masking"))?;
    let column = obj
        .get("column")
        .and_then(Value::as_str)
        .ok_or_else(|| validation("PREPROCESS_CONFIG_INVALID", "Masking config missing 'column'", "masking"))?
        .to_string();

    let masking_char_s = obj
        .get("masking_char")
        .or_else(|| obj.get("masking_character"))
        .and_then(Value::as_str)
        .unwrap_or("*");
    let masking_char = masking_char_s
        .chars()
        .next()
        .ok_or_else(|| validation("PREPROCESS_CONFIG_INVALID", "masking_char cannot be empty", &column))?;

    // characters_to_mask
    let mut characters_to_mask = Vec::new();
    if let Some(arr) = obj.get("characters_to_mask").and_then(Value::as_array) {
        for v in arr {
            let pos = v.as_i64().ok_or_else(|| {
                validation("PREPROCESS_CONFIG_INVALID", "characters_to_mask must be positive integers", &column)
            })?;
            if pos > 0 {
                characters_to_mask.push(pos as usize);
            }
        }
    }

    // regex_patterns
    let mut regex_patterns: Vec<RegexPatternConfig> = Vec::new();
    if let Some(arr) = obj.get("regex_patterns").and_then(Value::as_array) {
        for pat in arr {
            let pobj = pat.as_object().ok_or_else(|| {
                validation("PREPROCESS_CONFIG_INVALID", "Each regex_patterns entry must be an object", &column)
            })?;

            let pat_masking_char = pobj
                .get("masking_char")
                .and_then(Value::as_str)
                .map(|s| s.chars().next().unwrap_or(masking_char))
                .unwrap_or(masking_char);

            let length = match pobj.get("length") {
                None | Some(Value::Null) => None,
                Some(v) if v.is_i64() || v.is_u64() => {
                    let n = v.as_i64().unwrap_or(0);
                    if n <= 0 {
                        return Err(validation(
                            "PREPROCESS_CONFIG_INVALID",
                            "regex pattern 'length' must be > 0 or the string \"all\"",
                            &column,
                        ));
                    }
                    Some(MaskLength::Count(n as usize))
                }
                Some(Value::String(s)) if s.trim().eq_ignore_ascii_case("all") => Some(MaskLength::All),
                Some(_) => {
                    return Err(validation(
                        "PREPROCESS_CONFIG_INVALID",
                        "regex pattern 'length' must be a positive integer or the string \"all\"",
                        &column,
                    ));
                }
            };

            // mask_groups: {"1": "full", "2": "partial"}
            let mut mask_groups: Vec<(usize, String)> = Vec::new();
            if let Some(mg) = pobj.get("mask_groups").and_then(Value::as_object) {
                for (k, v) in mg {
                    if let (Ok(idx), Some(mode)) = (k.parse::<usize>(), v.as_str()) {
                        mask_groups.push((idx, mode.to_string()));
                    }
                }
            }

            // Extract semantic info unconditionally — needed for length masking and
            // derived fallback even when a literal "regex" field is also present.
            let pattern_type_val = pobj.get("type").and_then(Value::as_str).map(|s| s.to_lowercase());
            let delimiter_val    = pobj.get("delimiter").and_then(Value::as_str).map(|s| s.to_string());
            let start_val        = pobj.get("start").and_then(Value::as_str).map(|s| s.to_string());
            let end_val          = pobj.get("end").and_then(Value::as_str).map(|s| s.to_string());

            let kind = if let Some(r) = pobj.get("regex").and_then(Value::as_str) {
                RegexPatternKind::Literal(r.to_string())
            } else {
                RegexPatternKind::Derived {
                    pattern_type: pattern_type_val.clone().unwrap_or_default(),
                    delimiter: delimiter_val.clone(),
                    start: start_val.clone(),
                    end: end_val.clone(),
                }
            };

            regex_patterns.push(RegexPatternConfig {
                kind,
                masking_char: pat_masking_char,
                length,
                mask_groups,
                pattern_type: pattern_type_val,
                delimiter: delimiter_val,
                start: start_val,
                end: end_val,
            });
        }
    }

    // apply_order — default ["characters", "regex", "class"]
    let apply_order: Vec<String> = obj
        .get("apply_order")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_else(|| vec!["characters".to_string(), "regex".to_string(), "class".to_string()]);

    let class_masking_mode = obj.get("class_masking_mode").and_then(Value::as_str).map(|s| s.to_string());
    let class_letter = obj.get("class_mask_letter").and_then(Value::as_str)
        .unwrap_or("X").chars().next().unwrap_or('X');
    let class_digit  = obj.get("class_mask_digit").and_then(Value::as_str)
        .unwrap_or("0").chars().next().unwrap_or('0');

    Ok(MaskingConfigLite { column, masking_char, characters_to_mask, regex_patterns, apply_order, class_masking_mode, class_letter, class_digit })
}

// ── Regex helpers ─────────────────────────────────────────────────────────────

/// Builds a regex string from a semantic type descriptor — mirrors Python `_derive_regex`.
///
/// Supported `pattern_type` values:
/// - `"before"` + `delimiter` → match everything before the delimiter.
/// - `"after"` + `delimiter` → match everything after the delimiter.
/// - `"in_between"` + `start` + `end` → match text between start and end markers
///   (`end = "$"` anchors to end-of-string).
///
/// Returns an empty string when the type is unknown or required arguments are absent.
///
/// # Arguments
/// * `pattern_type` — one of `"before"`, `"after"`, `"in_between"`.
/// * `delimiter` — delimiter character/string (used for `"before"` / `"after"`).
/// * `start` — start anchor (used for `"in_between"`).
/// * `end` — end anchor (used for `"in_between"`; `"$"` means end-of-string).
pub(super) fn derive_regex(pattern_type: &str, delimiter: Option<&str>, start: Option<&str>, end: Option<&str>) -> String {
    // All patterns use capturing group 1 for the text to mask — avoids lookbehind
    // assertions that the Rust `regex` crate does not support.
    match pattern_type {
        "before" => {
            if let Some(d) = delimiter {
                return format!("^(.+?){}", regex::escape(d));
            }
        }
        "after" => {
            if let Some(d) = delimiter {
                return format!("{}(.+)$", regex::escape(d));
            }
        }
        "in_between" => {
            if let (Some(s), Some(e)) = (start, end) {
                if e == "$" {
                    return format!("{}(.+)$", regex::escape(s));
                }
                return format!("{}(.+?){}", regex::escape(s), regex::escape(e));
            }
        }
        _ => {}
    }
    String::new()
}

/// Applies length-limited masking before or after a delimiter — mirrors Python
/// `_apply_delimiter_length_mask`.
///
/// With [`MaskLength::Count`], every occurrence of `delimiter` is found and
/// `n` characters immediately before (`"before"`) or after (`"after"`) it are
/// masked. With [`MaskLength::All`], only the first occurrence is used and the
/// whole side of it is masked — everything from the start of the value up to
/// the delimiter (`"before"`), or from the delimiter to the end (`"after"`).
///
/// # Arguments
/// * `text` — the original string value.
/// * `pattern_type` — `"before"` or `"after"`.
/// * `delimiter` — the substring that acts as the masking anchor.
/// * `length` — how much to mask on the chosen side of the delimiter.
/// * `mask_char` — the replacement character.
///
/// # Returns
/// `(masked_text, changed)` where `changed` is `true` if any masking occurred.
pub(super) fn apply_delimiter_length_mask(text: &str, pattern_type: &str, delimiter: &str, length: MaskLength, mask_char: char) -> (String, bool) {
    if delimiter.is_empty() || length == MaskLength::Count(0) {
        return (text.to_string(), false);
    }
    let mut chars: Vec<char> = text.chars().collect();
    let text_str = text;
    let mut changed = false;
    let mut search_start = 0usize;

    loop {
        // find delimiter byte offset from search_start
        let Some(byte_idx) = text_str[search_start..].find(delimiter) else { break };
        let abs_byte = search_start + byte_idx;

        // convert byte offset to char offset
        let char_before = text_str[..abs_byte].chars().count();
        let delim_char_len = delimiter.chars().count();

        let (start_ci, end_ci) = if pattern_type == "after" {
            let s = char_before + delim_char_len;
            match length {
                MaskLength::All => (s, chars.len()),
                MaskLength::Count(n) => (s, (s + n).min(chars.len())),
            }
        } else {
            // before
            let e = char_before;
            match length {
                MaskLength::All => (0, e),
                MaskLength::Count(n) => (e.saturating_sub(n), e),
            }
        };

        for i in start_ci..end_ci {
            chars[i] = mask_char;
            changed = true;
        }

        // "all" is anchored to the first occurrence only — masking around every
        // occurrence would swallow the delimiters' surrounding text twice over.
        if length == MaskLength::All { break; }

        search_start = abs_byte + delimiter.len();
        if search_start >= text_str.len() { break; }
    }

    (chars.into_iter().collect(), changed)
}

/// Applies a single [`RegexPatternConfig`] to one string value.
///
/// Processing order:
/// 1. **Delimiter-length masking** — if `length` is set and the pattern is a
///    `before`/`after` type with a delimiter, call
///    [`apply_delimiter_length_mask`] and return immediately if it produced a
///    change. `length: "all"` masks the whole side of the delimiter; on an
///    `in_between` pattern it is a no-op, since the derived regex already
///    masks everything between the two anchors.
/// 2. **Build regex** — from the literal or derived kind.
/// 3. **Compile** — falls back to returning the original value on compile error.
/// 4. **Apply** — group masking via [`apply_regex_group_mask`], or full-match
///    masking with a data-adaptive `in_between` fallback.
///
/// # Arguments
/// * `value` — the original string value.
/// * `pat` — the pattern configuration to apply.
/// * `_column` — the column name (reserved for future diagnostic messages).
pub(super) fn apply_regex_pattern(value: &str, pat: &RegexPatternConfig, _column: &str) -> String {
    let mask_char = pat.masking_char;

    // 1. Delimiter-length masking (fires regardless of kind, uses stored semantic fields)
    if let Some(length) = pat.length {
        let pattern_type = pat.pattern_type.as_deref().unwrap_or("");
        let delimiter    = pat.delimiter.as_deref().unwrap_or("");
        if !delimiter.is_empty() && (pattern_type == "before" || pattern_type == "after") {
            let (result, changed) = apply_delimiter_length_mask(value, pattern_type, delimiter, length, mask_char);
            if changed {
                return result;
            }
        }
    }

    // 2. Build regex string; track whether this is a derived (capturing-group) pattern
    let mut is_derived = matches!(&pat.kind, RegexPatternKind::Derived { .. });
    let regex_str: String = match &pat.kind {
        RegexPatternKind::Literal(r) => r.clone(),
        RegexPatternKind::Derived { pattern_type, delimiter, start, end } => {
            derive_regex(pattern_type, delimiter.as_deref(), start.as_deref(), end.as_deref())
        }
    };

    if regex_str.is_empty() {
        return value.to_string();
    }

    // 3. Compile; when a literal regex fails (e.g. lookbehind), fall back to derived
    let compiled = match Regex::new(&regex_str) {
        Ok(r) => r,
        Err(_) => {
            let pt      = pat.pattern_type.as_deref().unwrap_or("");
            let derived = derive_regex(pt, pat.delimiter.as_deref(), pat.start.as_deref(), pat.end.as_deref());
            if derived.is_empty() {
                return value.to_string();
            }
            match Regex::new(&derived) {
                Ok(r) => { is_derived = true; r }
                Err(_) => return value.to_string(),
            }
        }
    };

    // 4. Apply — explicit group masking, auto group-1 for derived patterns, or full-match
    if !pat.mask_groups.is_empty() {
        apply_regex_group_mask(value, &compiled, &pat.mask_groups, mask_char)
    } else if is_derived {
        // Derived patterns capture exactly what should be masked in group 1
        let auto = [(1usize, "full".to_string())];
        apply_regex_group_mask(value, &compiled, &auto, mask_char)
    } else {
        let mut result = String::with_capacity(value.len());
        let mut last = 0usize;
        for m in compiled.find_iter(value) {
            result.push_str(&value[last..m.start()]);
            result.push_str(&mask_char.to_string().repeat(m.as_str().chars().count()));
            last = m.end();
        }
        result.push_str(&value[last..]);
        result
    }
}

/// Applies group-based masking to all matches of `re` in `value`.
///
/// For each match, specific capture groups are masked according to their mode:
/// - `"full"` — replace every character with `default_mask`.
/// - `"partial"` — keep the first character, replace the rest with `default_mask`.
/// - Any other mode — leave the group unchanged.
///
/// # Arguments
/// * `value` — the original string value.
/// * `re` — pre-compiled regular expression.
/// * `mask_groups` — list of `(capture_group_index, mode)` pairs.
/// * `default_mask` — the masking character.
pub(super) fn apply_regex_group_mask(value: &str, re: &Regex, mask_groups: &[(usize, String)], default_mask: char) -> String {
    re.replace_all(value, |caps: &regex::Captures| {
        let full_match = caps.get(0).map(|m| m.as_str()).unwrap_or("");
        let mut rebuilt = full_match.to_string();
        for (group_idx, mode) in mask_groups {
            if let Some(group_match) = caps.get(*group_idx) {
                let original = group_match.as_str();
                let replacement = match mode.as_str() {
                    "full" => default_mask.to_string().repeat(original.chars().count()),
                    "partial" => {
                        if original.chars().count() <= 1 {
                            original.to_string()
                        } else {
                            let mut chars = original.chars();
                            let first = chars.next().unwrap().to_string();
                            let rest = default_mask.to_string().repeat(original.chars().count() - 1);
                            first + &rest
                        }
                    }
                    _ => original.to_string(),
                };
                rebuilt = rebuilt.replacen(original, &replacement, 1);
            }
        }
        rebuilt
    }).to_string()
}

/// Applies all masking steps configured in `cfg` to `value` in the order
/// specified by `cfg.apply_order`.
///
/// Steps:
/// - `"characters"` — mask characters at specific 1-based positions.
/// - `"regex"` — apply each [`RegexPatternConfig`] in sequence.
/// - `"class"` — replace alphanumeric characters with `random_class` or
///   `fixed_class` substitutes (uses the `randomize_fn` callback so callers
///   can inject the class-preserving randomizer from `crypto`).
///
/// Unknown step names in `apply_order` are silently ignored.
///
/// # Arguments
/// * `value` — the original cell value.
/// * `cfg` — the parsed masking configuration for this column.
/// * `randomize_fn` — callback that implements class-preserving randomization
///   (typically [`super::crypto::randomize_preserving_class`]).
pub(super) fn apply_masking_value(
    value: &str,
    cfg: &MaskingConfigLite,
    randomize_fn: &dyn Fn(&str) -> String,
) -> String {
    let mut masked = value.to_string();

    for step in &cfg.apply_order {
        match step.as_str() {
            "characters" if !cfg.characters_to_mask.is_empty() => {
                let mut chars: Vec<char> = masked.chars().collect();
                for pos in &cfg.characters_to_mask {
                    let idx = pos.saturating_sub(1);
                    if idx < chars.len() {
                        chars[idx] = cfg.masking_char;
                    }
                }
                masked = chars.into_iter().collect();
            }
            "regex" if !cfg.regex_patterns.is_empty() => {
                for pat in &cfg.regex_patterns {
                    masked = apply_regex_pattern(&masked, pat, &cfg.column);
                }
            }
            "class" => {
                masked = match cfg.class_masking_mode.as_deref() {
                    Some("random_class") => randomize_fn(&masked),
                    Some("fixed_class") => {
                        let mut out = String::with_capacity(masked.len());
                        for c in masked.chars() {
                            if c.is_ascii_digit() { out.push(cfg.class_digit); }
                            else if c.is_ascii_alphabetic() { out.push(cfg.class_letter); }
                            else { out.push(c); }
                        }
                        out
                    }
                    _ => masked,
                };
            }
            _ => {}
        }
    }

    masked
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pattern(entry: serde_json::Value) -> RegexPatternConfig {
        let cfg = parse_masking_config(&json!({
            "column": "c",
            "masking_char": "*",
            "regex_patterns": [entry],
        }))
        .expect("config parses");
        cfg.regex_patterns.into_iter().next().expect("one pattern")
    }

    #[test]
    fn length_all_masks_everything_before_the_delimiter() {
        let p = pattern(json!({"type": "before", "delimiter": "@", "length": "all"}));
        assert_eq!(p.length, Some(MaskLength::All));
        assert_eq!(apply_regex_pattern("john.doe@example.com", &p, "c"), "********@example.com");
    }

    #[test]
    fn length_all_masks_everything_after_the_delimiter() {
        let p = pattern(json!({"type": "after", "delimiter": "@", "length": "all"}));
        assert_eq!(apply_regex_pattern("john.doe@example.com", &p, "c"), "john.doe@***********");
    }

    #[test]
    fn length_all_is_anchored_to_the_first_delimiter_occurrence() {
        let p = pattern(json!({"type": "after", "delimiter": "-", "length": "all"}));
        assert_eq!(apply_regex_pattern("AB-CD-EF", &p, "c"), "AB-*****");

        let p = pattern(json!({"type": "before", "delimiter": "-", "length": "all"}));
        assert_eq!(apply_regex_pattern("AB-CD-EF", &p, "c"), "**-CD-EF");
    }

    #[test]
    fn length_all_accepts_mixed_case_and_surrounding_space() {
        let p = pattern(json!({"type": "before", "delimiter": "@", "length": " ALL "}));
        assert_eq!(p.length, Some(MaskLength::All));
    }

    #[test]
    fn numeric_length_still_masks_a_fixed_count_at_every_occurrence() {
        let p = pattern(json!({"type": "after", "delimiter": "-", "length": 1}));
        assert_eq!(p.length, Some(MaskLength::Count(1)));
        assert_eq!(apply_regex_pattern("AB-CD-EF", &p, "c"), "AB-*D-*F");
    }

    #[test]
    fn length_all_leaves_the_value_alone_when_the_delimiter_is_absent() {
        let p = pattern(json!({"type": "before", "delimiter": "@", "length": "all"}));
        assert_eq!(apply_regex_pattern("no-delimiter-here", &p, "c"), "no-delimiter-here");
    }

    #[test]
    fn length_all_on_in_between_falls_through_to_the_derived_regex() {
        let p = pattern(json!({"type": "in_between", "start": "(", "end": ")", "length": "all"}));
        assert_eq!(apply_regex_pattern("call (022) 1234", &p, "c"), "call (***) 1234");
    }

    #[test]
    fn a_bad_length_is_a_config_error() {
        for bad in [json!("half"), json!(0), json!(-3), json!(true)] {
            let err = parse_masking_config(&json!({
                "column": "c",
                "regex_patterns": [{"type": "before", "delimiter": "@", "length": bad}],
            }));
            assert!(err.is_err(), "expected 'length' rejection");
        }
    }
}
