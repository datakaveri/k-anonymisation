//! Per-document de-identification for nested JSON extraction bundles.
//!
//! Built for the NHA claim bundles (BOCW / AROGYAK). **One file is one
//! patient** — a single case's claim documents, shaped as:
//!
//! ```text
//! { case_id, total_documents, total_pages,
//!   pages: [ { document, link, page_number, total_pages,
//!              extracted_data: { …whatever the extractor found on that page… } } ] }
//! ```
//!
//! That one-patient-per-file grain is what makes this a different problem from
//! the rest of SKALD, and why this module does not feed the k-anonymity flow.
//! k-anonymity protects a record by hiding it in a crowd of at least k others
//! sharing its quasi-identifiers; with a single subject per document there is
//! no crowd, so no k, no equivalence classes, and no generalization lattice to
//! search. What protects one of these documents is removing the identifiers it
//! contains and coarsening the quasi-identifiers that remain. So this module is
//! a structure-preserving **redaction pass**: nested JSON in, the same nested
//! JSON out, one output file per input file, with identifying leaves removed,
//! replaced, pseudonymised or coarsened in place.
//!
//! The hard part is not the nesting, it is that `extracted_data` has **no fixed
//! schema** — it is whatever the extraction model read off that page. A census
//! of only the first 5 KB of 50 sample files already turns up 2365 distinct
//! keys, and the tail grows with every new file: `handwritten_notes_3`,
//! `malayalam_text_2`, `lab_serum_bilirubin_direct_method`, `bed_sheet_color`.
//! An open-ended key space cannot be secured by listing the keys to remove,
//! because the next document always brings a key nobody listed. So the policy
//! runs the other way round: **every leaf is suppressed unless a rule keeps
//! it** (`default_action`), and rules are glob patterns over JSON paths rather
//! than literal key names.
//!
//! Each run also writes a **key census** — every path seen across the corpus,
//! how often, and which rule decided its fate. With a key space this size that
//! report is the only practical way to tune the rules; it is how you find the
//! identifying key that no pattern has caught yet.

use crate::pipeline::bootstrap::{PipelineError, io_err, validation};
use crate::pipeline::preprocess::crypto::{
    encrypt_value, format_preserving_encrypt, generate_random_salt_hex, hash_key, key_for, keyed_hash,
    normalize_identifier, randomize_preserving_class, read_json_map_string, write_json_pretty, write_secret_file,
};
use crate::pipeline::preprocess::masking::{
    MaskingConfigLite, TokenizationConfigLite, apply_masking_value, parse_encrypt_config, parse_masking_config,
    parse_tokenization_config,
};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

// ── Policy ───────────────────────────────────────────────────────────────────

/// What the policy does with one leaf value.
///
/// These are the techniques `preprocess` already implements for the tabular
/// flow, addressed by path glob instead of column name — deliberately not a new
/// vocabulary. `Keep` is the one addition, and only because the polarity is
/// inverted here: the tabular flow keeps every column it is not told about,
/// while an open-ended key space has to be default-deny, which means there must
/// be a way to say "this one is allowed".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Allow the value through unchanged. No tabular equivalent — see above.
    Keep,
    /// `suppress`: remove the key from its parent object entirely.
    Suppress,
    /// `masking`: index into `NestedJsonConfig::masking`, which holds specs
    /// parsed by the tabular masker itself. The value is transformed by
    /// `apply_masking_value`, so the `characters_to_mask` / `regex_patterns` /
    /// `class_masking_mode` steps behave exactly as they do for a CSV column —
    /// an entry naming none of them masks nothing, which is why one is required.
    Masking { spec: usize },
    /// `hashing_with_salt`: a stable salted digest, so the same value maps to
    /// the same token everywhere. This is what keeps a case linkable across its
    /// own pages without carrying the resolvable id.
    Hash,
    /// `free_text`: released unchanged because the NER pipeline has already
    /// anonymized it upstream, before the document reached SKALD. Behaves like
    /// `Keep`, but is labelled apart in the census so a reviewer can tell
    /// "cleared by policy" from "trusted to an upstream pass".
    FreeText,
    /// `charcloak`: every letter and digit replaced by a random one of the same
    /// class, punctuation kept — `"9000000002"` → `"4170295836"`. Irreversible
    /// and not stable: the same input gives a different output every time.
    Charcloak,
    /// `tokenization`: index into `NestedJsonConfig::tokenization`. The value
    /// becomes `<prefix><n>`, recorded in the run's token vault under the
    /// entry's pattern, so it can be reversed and the same value always gets
    /// the same token.
    Tokenize { spec: usize },
    /// `encrypt`: reversible, deterministic encryption under a key generated
    /// per pattern and kept with the run's key material. `format_preserving`
    /// keeps each run of digits / upper / lower letters in its class and
    /// length; otherwise the output is hex.
    Encrypt { format_preserving: bool },
    /// `filename`: a URL or path cut down to its last segment, with the query
    /// string and fragment dropped —
    /// `https://host/media/complaint/0000aaaa1111_complaint_00001_00002.jpg?Signature=…`
    /// → `0000aaaa1111_complaint_00001_00002.jpg`. The host, the storage layout
    /// and any signed-URL credentials go; the name itself is released, so a
    /// name that embeds a person (`DISCHARGE ANIL TESTNAME.pdf`) still needs
    /// reviewing. A value with no file name left is suppressed.
    Filename,
}

impl Action {
    /// The config key this action came from, for the census report.
    pub(crate) fn label(&self) -> String {
        match self {
            Action::Keep => "keep".into(),
            Action::FreeText => "free_text".into(),
            Action::Suppress => "suppress".into(),
            Action::Masking { .. } => "masking".into(),
            Action::Hash => "hashing_with_salt".into(),
            Action::Charcloak => "charcloak".into(),
            Action::Tokenize { .. } => "tokenization".into(),
            Action::Encrypt { format_preserving: true } => "encrypt(format_preserving)".into(),
            Action::Encrypt { format_preserving: false } => "encrypt".into(),
            Action::Filename => "filename".into(),
        }
    }
}

/// Parses `default_action`, which can only be one of the two techniques that
/// need no parameters — the fallback applies to paths nobody has named, and
/// masking or generalizing an unknown field is not meaningful.
pub(crate) fn parse_action(raw: &str) -> Option<Action> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "keep" => Some(Action::Keep),
        "suppress" | "drop" => Some(Action::Suppress),
        _ => None,
    }
}

/// One policy rule: a path glob and what to do with the leaves it matches.
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub pattern: String,
    pub action: Action,
    segments: Vec<Segment>,
    spec: Specificity,
}

/// How narrow a pattern is. Ordered so that greater = narrower, and derived
/// `Ord` compares the fields in declaration order.
///
/// This is what lets the config be an unordered set of buckets instead of an
/// ordered list. Order-dependent matching was the source of every policy bug
/// found on real data: `**.*_id` swallowing `case_id`, `**.*age*` banding
/// `total_pages`, `**.*time*` feeding `status_at_time_of_discharge` to a date
/// parser. Under most-specific-wins all three resolve correctly with no
/// thought about placement — `case_id` is narrower than `**.*_id`, and that is
/// the whole rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Specificity {
    /// Negated so fewer `**` segments sorts higher.
    neg_double_stars: i32,
    /// Negated so fewer `*` wildcards sorts higher.
    neg_stars: i32,
    /// Literal (non-wildcard) characters the pattern pins down.
    literal_chars: i32,
    /// A pattern naming more segments is pinning down more of the path.
    segments: i32,
}

/// Tie-break when two equally narrow patterns both match: the more protective
/// action wins. With `suppress` outranking `keep`, an accidental overlap fails
/// closed rather than releasing a value.
pub(crate) fn privacy_rank(a: &Action) -> u8 {
    match a {
        Action::Suppress => 8,
        // Both release part of the value and drop the rest.
        Action::Masking { .. } | Action::Filename => 7,
        Action::Charcloak => 6,
        Action::Hash => 5,
        // Reversible by whoever holds the vault or key, so below the one-way
        // techniques; a token reveals nothing of the value's shape, ciphertext
        // reveals its length (and its format, when format-preserving).
        Action::Tokenize { .. } => 4,
        Action::Encrypt { .. } => 3,
        Action::Keep | Action::FreeText => 1,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    /// `**` — matches zero or more whole path segments.
    DoubleStar,
    /// One segment, possibly containing `*` wildcards.
    Literal(String),
}

impl Rule {
    pub fn new(pattern: &str, action: Action) -> Rule {
        // Census paths print array indices glued to their key (`name[].text`),
        // so accept that spelling too and a row can be pasted back as a rule.
        let normalised = pattern.replace("[]", ".[]").replace("..[]", ".[]");
        let segments: Vec<Segment> = normalised
            .trim_start_matches('.')
            .split('.')
            .map(|s| if s == "**" { Segment::DoubleStar } else { Segment::Literal(s.to_ascii_lowercase()) })
            .collect();
        let spec = Specificity {
            neg_double_stars: -(segments.iter().filter(|s| **s == Segment::DoubleStar).count() as i32),
            neg_stars: -(segments
                .iter()
                .map(|s| match s {
                    Segment::Literal(l) => l.matches('*').count(),
                    Segment::DoubleStar => 0,
                })
                .sum::<usize>() as i32),
            literal_chars: segments
                .iter()
                .map(|s| match s {
                    Segment::Literal(l) => l.chars().filter(|c| *c != '*').count(),
                    Segment::DoubleStar => 0,
                })
                .sum::<usize>() as i32,
            segments: segments.len() as i32,
        };
        Rule { pattern: pattern.to_string(), action, segments, spec }
    }

    fn matches(&self, path: &[String]) -> bool {
        seg_match(&self.segments, path)
    }
}

/// Glob match of pattern segments against path segments. `**` spans any number
/// of segments; `*` inside a segment matches any run of characters within that
/// one segment. Recursive because `**` needs backtracking, and these patterns
/// are a handful of segments long.
fn seg_match(pat: &[Segment], path: &[String]) -> bool {
    match pat.first() {
        None => path.is_empty(),
        Some(Segment::DoubleStar) => (0..=path.len()).any(|skip| seg_match(&pat[1..], &path[skip..])),
        Some(Segment::Literal(lit)) => match path.first() {
            None => false,
            Some(seg) => wildcard_match(lit, seg) && seg_match(&pat[1..], &path[1..]),
        },
    }
}

/// `*`-wildcard match within a single segment. Both sides are lowercased by
/// their constructors, so this is a plain byte comparison.
fn wildcard_match(pat: &str, text: &str) -> bool {
    let parts: Vec<&str> = pat.split('*').collect();
    if parts.len() == 1 {
        return pat == text;
    }
    let first = parts[0];
    if !text.starts_with(first) {
        return false;
    }
    let mut rest = &text[first.len()..];
    let last = parts[parts.len() - 1];
    for m in &parts[1..parts.len() - 1] {
        if m.is_empty() {
            continue;
        }
        match rest.find(m) {
            Some(i) => rest = &rest[i + m.len()..],
            None => return false,
        }
    }
    rest.len() >= last.len() && rest.ends_with(last)
}

// ── Config ───────────────────────────────────────────────────────────────────

/// The nested-JSON policy, read from the same section keys the tabular flow
/// uses (`suppress`, `hashing_with_salt`, `masking`, `size`, `qi_constraints`,
/// `output_path`, `output_directory`) with path globs in place of column names.
#[derive(Debug, Clone)]
pub struct NestedJsonConfig {
    /// Section key `nested_json: true`. Switches this flow on in place of the
    /// tabular one.
    pub enabled: bool,
    /// Section key `input_path`. A `.json` file, or a directory of them. Each
    /// file is one patient and is processed independently.
    pub input_path: Option<PathBuf>,
    /// Section key `output_path`, used as a subdirectory of `output_directory`
    /// because this flow emits one document per input rather than one table.
    pub output_subdir: String,
    /// Section key `default_action`. `suppress` or `keep`; defaults to
    /// `suppress`, since an open-ended key space cannot be default-keep.
    pub default_action: Action,
    /// Every bucket flattened into one set. Matching is most-specific-wins, so
    /// which bucket a pattern came from carries no precedence.
    pub rules: Vec<Rule>,
    /// Section key `dry_run`. Report what the policy would do and write no
    /// documents — the review step before a release.
    pub dry_run: bool,
    /// Populated from the run's `output_directory`. The hash salt lives in
    /// `<key_material_dir>/nested_json_salt.json`, generated on first run, the
    /// same way the tabular flow persists `symmetric_keys.json` — a salt is a
    /// secret and does not belong in a committed config.
    pub key_material_dir: PathBuf,
    /// Root the anonymized documents go under (`<output_root>/<output_path>`).
    /// Set from the run's output directory — never the key material directory.
    pub output_root: PathBuf,
    /// Masking specs, parsed by the tabular masker's own `parse_masking_config`
    /// so nested masking and column masking cannot drift apart.
    pub(crate) masking: Vec<MaskingConfigLite>,
    /// Tokenization specs, parsed by the tabular `parse_tokenization_config`;
    /// `column` holds the path pattern, which also names the vault entry.
    pub(crate) tokenization: Vec<TokenizationConfigLite>,
}

impl Default for NestedJsonConfig {
    fn default() -> Self {
        NestedJsonConfig {
            enabled: false,
            input_path: None,
            output_subdir: "nested_json".to_string(),
            default_action: Action::Suppress,
            rules: Vec::new(),
            dry_run: false,
            key_material_dir: PathBuf::from("keys"),
            output_root: PathBuf::from("output"),
            masking: Vec::new(),
            tokenization: Vec::new(),
        }
    }
}

/// Reads the nested-JSON policy off a config section.
///
/// The section is shaped exactly like a tabular one — same technique keys at
/// the same level — with two differences forced by the data rather than by
/// taste: values are path globs instead of column names, because
/// `extracted_data` has no fixed schema; and `keep` exists, because
/// `default_action` is `suppress` and there must be a way to allow a field.
pub fn parse_nested_json(section: &Value) -> Result<NestedJsonConfig, PipelineError> {
    let mut cfg = NestedJsonConfig {
        enabled: section.get("nested_json").and_then(Value::as_bool).unwrap_or(false),
        ..NestedJsonConfig::default()
    };
    if !cfg.enabled {
        return Ok(cfg);
    }

    cfg.input_path =
        section.get("input_path").and_then(Value::as_str).filter(|s| !s.trim().is_empty()).map(PathBuf::from);
    if let Some(p) = section.get("output_path").and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
        cfg.output_subdir = p.to_string();
    }
    cfg.dry_run = section.get("dry_run").and_then(Value::as_bool).unwrap_or(false);
    if let Some(raw) = section.get("default_action").and_then(Value::as_str) {
        cfg.default_action = parse_action(raw).ok_or_else(|| {
            validation(
                "CONFIG_INVALID_VALUE",
                "Invalid default_action",
                &format!("'{raw}' — must be 'suppress' or 'keep'"),
            )
        })?;
    }

    let (rules, specs) = parse_policy_rules(section)?;
    cfg.rules = rules;
    cfg.masking = specs.masking;
    cfg.tokenization = specs.tokenization;

    if cfg.input_path.is_none() {
        return Err(validation(
            "CONFIG_INVALID_VALUE",
            "nested_json requires 'input_path'",
            "Point it at a .json file or a directory of them",
        ));
    }
    if cfg.rules.is_empty() && cfg.default_action == Action::Suppress {
        return Err(validation(
            "CONFIG_INVALID_VALUE",
            "this policy would suppress every field",
            "default_action is 'suppress' and no patterns were given",
        ));
    }

    Ok(cfg)
}

/// Parameters some rules point into by index, parsed alongside them.
#[derive(Debug, Default)]
pub(crate) struct PolicySpecs {
    pub masking: Vec<MaskingConfigLite>,
    pub(crate) tokenization: Vec<TokenizationConfigLite>,
}

/// Technique keys of the tabular config that no per-document flow applies,
/// with what to use instead. Listing a path under one of these used to be
/// ignored without a word, leaving the path to `default_action` — which with
/// `keep` released the value in clear.
const UNSUPPORTED_TECHNIQUES: [(&str, &str); 2] = [
    (
        "hashing_without_salt",
        "an unsalted hash of a phone number or id is reversed by hashing every candidate — use hashing_with_salt",
    ),
    ("fpe", "use encrypt with {\"<pattern>\": {\"format_preserving\": true}}"),
];

/// Reads the technique buckets every per-document flow shares — `keep`,
/// `suppress`, `hashing_with_salt`, `free_text`, `charcloak`, `masking`,
/// `tokenization`, `encrypt`, `size` and `qi_constraints` — into one rule set.
/// The FHIR bundle flow reads its policy through this too, so a pattern means
/// the same thing in either flow.
pub(crate) fn parse_policy_rules(section: &Value) -> Result<(Vec<Rule>, PolicySpecs), PipelineError> {
    for (key, instead) in UNSUPPORTED_TECHNIQUES {
        let listed = section.get(key).filter(|v| match v {
            Value::Null => false,
            Value::Array(a) => !a.is_empty(),
            _ => true,
        });
        if let Some(listed) = listed {
            return Err(validation(
                "CONFIG_INVALID_VALUE",
                &format!("'{key}' is not applied to nested documents"),
                &format!("{key}: {listed} — {instead}"),
            ));
        }
    }

    let mut rules = Vec::new();
    let mut masking = Vec::new();
    // Techniques that take a plain list of targets, as in the tabular config.
    for (key, action) in [
        ("keep", Action::Keep),
        ("suppress", Action::Suppress),
        ("hashing_with_salt", Action::Hash),
        ("free_text", Action::FreeText),
        ("charcloak", Action::Charcloak),
        ("filename", Action::Filename),
    ] {
        for pattern in string_list(section.get(key), key)? {
            rules.push(Rule::new(&pattern, action.clone()));
        }
    }

    // `masking`: parsed by the tabular masker's own parser, so an entry here
    // means exactly what the same entry means against a CSV column.
    if let Some(entries) = section.get("masking") {
        let arr = entries.as_array().ok_or_else(|| {
            validation("CONFIG_INVALID_VALUE", "masking must be an array of objects", &entries.to_string())
        })?;
        for entry in arr {
            let spec = parse_masking_config(entry)?;
            // An entry naming no step masks nothing and `apply_masking_value`
            // returns the value untouched — silently releasing what the
            // operator believed was masked. Refuse it instead.
            if spec.characters_to_mask.is_empty() && spec.regex_patterns.is_empty() && spec.class_masking_mode.is_none()
            {
                return Err(validation(
                    "PREPROCESS_CONFIG_INVALID",
                    "Masking entry specifies no masking step, so it would mask nothing",
                    &format!(
                        "{}: give it 'characters_to_mask', 'regex_patterns', or \
                         'class_masking_mode' (\"fixed_class\" masks the whole value)",
                        spec.column
                    ),
                ));
            }
            rules.push(Rule::new(&spec.column.clone(), Action::Masking { spec: masking.len() }));
            masking.push(spec);
        }
    }

    // `tokenization` and `encrypt`: the tabular entry formats, unchanged —
    // `{"column", "prefix", "digits"}` and `"pattern"` or
    // `{"pattern": {"format_preserving": bool}}` — with a path glob as the column.
    let mut tokenization = Vec::new();
    for entry in object_list(section.get("tokenization"), "tokenization")? {
        let spec = parse_tokenization_config(entry)?;
        rules.push(Rule::new(&spec.column, Action::Tokenize { spec: tokenization.len() }));
        tokenization.push(spec);
    }
    for entry in object_list(section.get("encrypt"), "encrypt")? {
        let spec = parse_encrypt_config(entry)?;
        rules.push(Rule::new(&spec.column, Action::Encrypt { format_preserving: spec.format_preserving }));
    }

    // Ages and dates are coarsened with `masking` (`characters_to_mask` over
    // the digits to drop). A config still carrying the retired `size` banding
    // or `qi_constraints` `precision` form is refused: ignored, its paths would
    // fall to `default_action` — released in clear under `keep`.
    if let Some((pattern, _)) = section.get("size").and_then(Value::as_object).and_then(|o| o.iter().next()) {
        return Err(validation(
            "CONFIG_INVALID_VALUE",
            "size is not supported for nested documents",
            &format!("{pattern}: mask the value with a 'masking' entry and 'characters_to_mask' instead"),
        ));
    }
    if let Some(obj) = section.get("qi_constraints").and_then(Value::as_object)
        && let Some((pattern, _)) = obj.iter().find(|(_, c)| c.get("precision").is_some())
    {
        return Err(validation(
            "CONFIG_INVALID_VALUE",
            "qi_constraints precision is not supported",
            &format!("{pattern}: mask the date with a 'masking' entry and 'characters_to_mask' instead"),
        ));
    }

    Ok((rules, PolicySpecs { masking, tokenization }))
}

/// A technique bucket holding a list of entries in the tabular format.
fn object_list<'a>(v: Option<&'a Value>, key: &str) -> Result<&'a [Value], PipelineError> {
    match v {
        None => Ok(&[]),
        Some(v) => v
            .as_array()
            .map(Vec::as_slice)
            .ok_or_else(|| validation("CONFIG_INVALID_VALUE", &format!("{key} must be an array"), &v.to_string())),
    }
}

/// A technique bucket holding a list of path globs.
fn string_list(v: Option<&Value>, key: &str) -> Result<Vec<String>, PipelineError> {
    let Some(v) = v else { return Ok(Vec::new()) };
    let arr = v.as_array().ok_or_else(|| {
        validation("CONFIG_INVALID_VALUE", &format!("{key} must be an array of path patterns"), &v.to_string())
    })?;
    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        let pattern = entry.as_str().filter(|s| !s.trim().is_empty()).ok_or_else(|| {
            validation("CONFIG_INVALID_VALUE", &format!("{key} entries must be non-empty strings"), &entry.to_string())
        })?;
        out.push(pattern.to_string());
    }
    Ok(out)
}

// ── Value transforms ─────────────────────────────────────────────────────────

/// `hashing_with_salt`: HMAC-SHA256 under the run's hash key, all 64 hex
/// chars, as in the tabular and FHIR flows, so `hashing` means the same thing
/// in every flow.
pub(crate) fn hash_token(key: &[u8; 32], value: &str) -> String {
    keyed_hash(key, value.as_bytes())
}

/// Applies one action to one leaf. `None` means "remove this key".
///
/// `matched_by` is the pattern that chose `action`; the reversible techniques
/// keep their vault entry and key under it.
fn apply(
    action: &Action,
    value: &Value,
    matched_by: &str,
    cfg: &NestedJsonConfig,
    keys: &mut KeyStore,
) -> Option<Value> {
    let text = match leaf_text(value) {
        Some(t) if !t.trim().is_empty() => t,
        _ => return apply_action(action, value, &cfg.masking, Some(&keys.hash_key)),
    };
    // A value a technique cannot handle — a format-preserving value too short
    // or in a non-ASCII script, a full token vault — is removed (`None`),
    // never released as it was.
    match action {
        Action::Tokenize { spec } => {
            Some(Value::String(keys.token(cfg.tokenization.get(*spec)?, &normalize_identifier(&text))?))
        }
        Action::Encrypt { format_preserving } => {
            Some(Value::String(keys.encrypt(matched_by, *format_preserving, &normalize_identifier(&text))?))
        }
        other => apply_action(other, value, &cfg.masking, Some(&keys.hash_key)),
    }
}

/// A scalar as the text the techniques operate on; `None` for a container.
fn leaf_text(value: &Value) -> Option<String> {
    match value {
        Value::Null => Some(String::new()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

/// [`apply`] for the techniques that need no key material, against a bare
/// list of masking specs, for flows that hold their policy in a config type of
/// their own. `hash_key` is `None` for a flow that hashes under keys of its
/// own; `Hash` then fails closed.
pub(crate) fn apply_action(
    action: &Action,
    value: &Value,
    masking: &[MaskingConfigLite],
    hash_key: Option<&[u8; 32]>,
) -> Option<Value> {
    let Some(as_text) = leaf_text(value) else { return Some(value.clone()) };
    let empty = as_text.trim().is_empty();

    match action {
        Action::Keep | Action::FreeText => Some(value.clone()),
        Action::Suppress => None,
        Action::Masking { spec } => {
            if empty {
                return Some(value.clone());
            }
            let spec = masking.get(*spec)?;
            Some(Value::String(apply_masking_value(&as_text, spec, &randomize_preserving_class).ok()?))
        }
        _ if empty => Some(value.clone()),
        // These need the run's vault and keys, which only [`apply`] holds.
        // Reaching here with a value means a caller bypassed it, so fail
        // closed rather than release the value.
        Action::Tokenize { .. } | Action::Encrypt { .. } => None,
        Action::Hash => Some(Value::String(hash_token(hash_key?, as_text.trim()))),
        Action::Charcloak => Some(Value::String(randomize_preserving_class(&as_text).ok()?)),
        Action::Filename => file_name(&as_text).map(Value::String),
    }
}

/// The last segment of a URL or path, percent-decoded, without its query
/// string or fragment. `None` when nothing is left — a bare host, or a path
/// ending in a separator — so the caller suppresses rather than releases it.
fn file_name(value: &str) -> Option<String> {
    let path = value.trim().split(['?', '#']).next()?;
    // In `scheme://host/...` only what follows the host is a path; a bare
    // `scheme://host` has no file name, and the host is not one.
    let path = match path.split_once("://") {
        Some((_, rest)) => rest.split_once('/').map(|(_, p)| p)?,
        None => path,
    };
    let last = path.rsplit(['/', '\\']).next()?;
    if last.is_empty() {
        return None;
    }
    let bytes = last.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        match (bytes[i], bytes.get(i + 1).copied().and_then(hex), bytes.get(i + 2).copied().and_then(hex)) {
            (b'%', Some(h), Some(l)) => {
                out.push((h * 16 + l) as u8);
                i += 3;
            }
            (b, _, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    let name = String::from_utf8_lossy(&out).trim().to_string();
    (!name.is_empty()).then_some(name)
}

// ── Key material ─────────────────────────────────────────────────────────────

/// Token vault file, beside the salt. Same shape as the tabular
/// `token_vault.json` — `{pattern: {forward, reverse}}` — but a file of its
/// own, because the tabular flow rewrites its vault with only its own columns.
const TOKEN_VAULT_FILE: &str = "nested_json_token_vault.json";
/// `{pattern: hex key}` for `encrypt` entries.
const SYMMETRIC_KEYS_FILE: &str = "nested_json_symmetric_keys.json";
/// `{pattern: hex key}` for `encrypt` entries with `format_preserving: true`.
const FPE_KEYS_FILE: &str = "nested_json_fpe_encrypt_keys.json";

#[derive(Debug, Default)]
struct TokenVault {
    forward: BTreeMap<String, String>,
    reverse: BTreeMap<String, String>,
}

/// The key material one run transforms values under: the hash key, the token
/// vaults and the encryption keys, each keyed by the pattern that selected the
/// value. Loaded from and persisted to the run's key material directory, so a
/// value gets the same token and ciphertext in every run and every document.
#[derive(Debug, Default)]
pub struct KeyStore {
    /// The decoded `nested_json_salt.json` salt: the `hashing_with_salt` HMAC key.
    hash_key: [u8; 32],
    vaults: BTreeMap<String, TokenVault>,
    symmetric: BTreeMap<String, String>,
    fpe: BTreeMap<String, String>,
}

impl KeyStore {
    /// A store holding only a hash key, with empty vaults and no keys yet.
    pub fn with_hash_key(hash_key: [u8; 32]) -> KeyStore {
        KeyStore { hash_key, ..Default::default() }
    }

    /// Reads whatever vault and keys earlier runs left in `dir`.
    fn load(dir: &Path, hash_key: [u8; 32]) -> Result<KeyStore, PipelineError> {
        let mut store = KeyStore::with_hash_key(hash_key);
        store.symmetric = read_json_map_string(&dir.join(SYMMETRIC_KEYS_FILE))?;
        store.fpe = read_json_map_string(&dir.join(FPE_KEYS_FILE))?;
        let vault_path = dir.join(TOKEN_VAULT_FILE);
        if vault_path.is_file() {
            let raw = fs::read_to_string(&vault_path)
                .map_err(|e| io_err("read nested_json token vault", &vault_path.display().to_string(), e))?;
            let v: Value = serde_json::from_str(&raw)?;
            let map = |entry: &Value, side: &str| -> BTreeMap<String, String> {
                entry
                    .get(side)
                    .and_then(Value::as_object)
                    .map(|m| m.iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect())
                    .unwrap_or_default()
            };
            for (pattern, entry) in v.as_object().into_iter().flatten() {
                store.vaults.insert(
                    pattern.clone(),
                    TokenVault { forward: map(entry, "forward"), reverse: map(entry, "reverse") },
                );
            }
        }
        Ok(store)
    }

    /// Generates a key for every `encrypt` pattern that lacks one. Done before
    /// any document is written, so ciphertext never exists without its key
    /// already on disk.
    fn ensure_encrypt_keys(&mut self, rules: &[Rule]) -> Result<(), PipelineError> {
        for rule in rules {
            if let Action::Encrypt { format_preserving } = rule.action {
                let keys = if format_preserving { &mut self.fpe } else { &mut self.symmetric };
                key_for(keys, &rule.pattern)?;
            }
        }
        Ok(())
    }

    /// The vault token for `value`, issuing a new random one on first sight
    /// (a counter would number documents in processing order). `None` when the
    /// vault is nearly full or no randomness is available.
    fn token(&mut self, spec: &TokenizationConfigLite, value: &str) -> Option<String> {
        let vault = self.vaults.entry(spec.column.clone()).or_default();
        if let Some(t) = vault.forward.get(value) {
            return Some(t.clone());
        }
        let space = 10u64.saturating_pow(spec.digits.min(18) as u32);
        if vault.reverse.len() as u64 >= space / 10 * 9 {
            return None;
        }
        let token = loop {
            let mut b = [0u8; 8];
            getrandom::getrandom(&mut b).ok()?;
            // Never hand a token out twice, whatever an edited vault holds.
            let t = format!("{}{:0width$}", spec.prefix, u64::from_le_bytes(b) % space, width = spec.digits);
            if !vault.reverse.contains_key(&t) {
                break t;
            }
        };
        vault.forward.insert(value.to_string(), token.clone());
        vault.reverse.insert(token.clone(), value.to_string());
        Some(token)
    }

    /// `value` encrypted under `pattern`'s key — the tabular primitives, with
    /// the pattern in place of the column name. `None` if it cannot be.
    fn encrypt(&mut self, pattern: &str, format_preserving: bool, value: &str) -> Option<String> {
        let keys = if format_preserving { &mut self.fpe } else { &mut self.symmetric };
        let key = key_for(keys, pattern).ok()?;
        if format_preserving {
            format_preserving_encrypt(value, &key, pattern).ok()
        } else {
            encrypt_value(value, &key, pattern).ok()
        }
    }

    /// Writes every non-empty store to `dir` and returns the files written.
    fn persist(&self, dir: &Path) -> Result<Vec<PathBuf>, PipelineError> {
        let mut written = Vec::new();
        let as_object = |m: &BTreeMap<String, String>| {
            Value::Object(m.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect())
        };
        for (file, keys) in [(SYMMETRIC_KEYS_FILE, &self.symmetric), (FPE_KEYS_FILE, &self.fpe)] {
            if !keys.is_empty() {
                write_json_pretty(&dir.join(file), &as_object(keys))?;
                written.push(dir.join(file));
            }
        }
        if !self.vaults.is_empty() {
            let vault: Map<String, Value> = self
                .vaults
                .iter()
                .map(|(p, v)| {
                    (
                        p.clone(),
                        serde_json::json!({ "forward": as_object(&v.forward), "reverse": as_object(&v.reverse) }),
                    )
                })
                .collect();
            write_json_pretty(&dir.join(TOKEN_VAULT_FILE), &Value::Object(vault))?;
            written.push(dir.join(TOKEN_VAULT_FILE));
        }
        Ok(written)
    }
}

// ── Census ───────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
struct KeyStat {
    seen: usize,
    non_empty: usize,
    action: String,
    matched_by: String,
    example: String,
}

/// One row of the key census report.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyCensusRow {
    pub seen: usize,
    pub non_empty: usize,
    pub action: String,
    pub matched_by: String,
    pub example: String,
}

/// Aggregated census across every document a run processed.
#[derive(Debug, Default)]
pub struct Census {
    stats: BTreeMap<String, KeyStat>,
}

impl Census {
    fn record(&mut self, path: &str, value: &Value, action: &Action, matched_by: &str) {
        self.record_as(path, value, &action.label(), matched_by, matches!(action, Action::Keep));
    }

    /// Records one leaf under an explicit action label. `may_sample` must be
    /// false for anything but a value released as-is — see below.
    pub(crate) fn record_as(&mut self, path: &str, value: &Value, label: &str, matched_by: &str, may_sample: bool) {
        let stat = self.stats.entry(path.to_string()).or_default();
        stat.seen += 1;
        stat.action = label.to_string();
        stat.matched_by = matched_by.to_string();
        let text = match value {
            Value::String(s) => s.clone(),
            Value::Null => String::new(),
            other => other.to_string(),
        };
        if !text.trim().is_empty() {
            stat.non_empty += 1;
            // Only ever sample a value the policy is keeping. An example drawn
            // from a suppressed path would put the exact PII under discussion
            // into a report that then gets shared around to tune the rules.
            if stat.example.is_empty() && may_sample {
                stat.example = text.chars().take(40).collect();
            }
        }
    }

    pub fn rows(&self) -> Vec<(String, KeyCensusRow)> {
        self.stats
            .iter()
            .map(|(k, s)| {
                (
                    k.clone(),
                    KeyCensusRow {
                        seen: s.seen,
                        non_empty: s.non_empty,
                        action: s.action.clone(),
                        matched_by: s.matched_by.clone(),
                        example: s.example.clone(),
                    },
                )
            })
            .collect()
    }

    /// Paths the policy let through unchanged, most frequent first. This is the
    /// review list: everything here is in the released document.
    pub fn kept_paths(&self) -> Vec<(&str, usize)> {
        let mut v: Vec<(&str, usize)> = self
            .stats
            .iter()
            .filter(|(_, s)| s.action == "keep" || s.action == "free_text")
            .map(|(k, s)| (k.as_str(), s.seen))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v
    }
}

/// Writes the census as CSV, most-frequent path first so the keys that matter
/// most to review sit at the top.
pub fn write_census(census: &Census, path: &Path) -> Result<(), PipelineError> {
    use crate::pipeline::bootstrap::csv_row_to_line;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| io_err("create census directory", &parent.display().to_string(), e))?;
    }
    let mut rows = census.rows();
    rows.sort_by(|a, b| b.1.seen.cmp(&a.1.seen).then_with(|| a.0.cmp(&b.0)));

    let mut out = csv_row_to_line(&[
        "path".into(),
        "documents_seen".into(),
        "non_empty".into(),
        "action".into(),
        "matched_by".into(),
        "example_value".into(),
    ]);
    out.push('\n');
    for (p, r) in rows {
        out.push_str(&csv_row_to_line(&[
            p,
            r.seen.to_string(),
            r.non_empty.to_string(),
            r.action,
            r.matched_by,
            r.example,
        ]));
        out.push('\n');
    }
    fs::write(path, out).map_err(|e| io_err("write nested_json census", &path.display().to_string(), e))?;
    Ok(())
}

// ── Document walk ────────────────────────────────────────────────────────────

/// Resolves the action for a path: the **narrowest** matching pattern wins,
/// ties going to the more protective action. Config order is irrelevant.
///
/// A path ending in `[]` is retried without its trailing index segments, so a
/// pattern naming an array of scalars (`**.logos_present`) covers its elements
/// without being written twice. The full path is tried first, so an explicit
/// `**.logos_present.[]` still takes precedence.
fn decide<'a>(cfg: &'a NestedJsonConfig, path: &[String]) -> (&'a Action, &'a str) {
    decide_in(&cfg.rules, &cfg.default_action, path)
}

/// [`decide`] over a bare rule set and fallback. `path` segments must already
/// be lowercased, with array indices as `[]`.
pub(crate) fn decide_in<'a>(rules: &'a [Rule], default: &'a Action, path: &[String]) -> (&'a Action, &'a str) {
    let pick = |p: &[String]| -> Option<&'a Rule> {
        let mut best: Option<&'a Rule> = None;
        for rule in rules {
            if !rule.matches(p) {
                continue;
            }
            let better = match best {
                None => true,
                Some(b) => (rule.spec, privacy_rank(&rule.action)) > (b.spec, privacy_rank(&b.action)),
            };
            if better {
                best = Some(rule);
            }
        }
        best
    };

    if let Some(rule) = pick(path) {
        return (&rule.action, rule.pattern.as_str());
    }
    let trimmed = path.iter().rposition(|s| s != "[]").map(|i| i + 1).unwrap_or(0);
    if trimmed < path.len()
        && let Some(rule) = pick(&path[..trimmed])
    {
        return (&rule.action, rule.pattern.as_str());
    }
    (default, "<default>")
}

/// Renders match segments as a display path: `pages[].extracted_data.patient_name`.
pub(crate) fn display_path(segments: &[String]) -> String {
    let mut out = String::new();
    for seg in segments {
        if seg == "[]" {
            out.push_str("[]");
        } else {
            if !out.is_empty() {
                out.push('.');
            }
            out.push_str(seg);
        }
    }
    out
}

/// Rewrites one document in place, preserving its structure.
///
/// Containers are always walked — a policy decision applies to leaves, never to
/// a whole subtree, so `extracted_data` is never suppressed wholesale by a
/// pattern that happens to match its name. An object that ends up empty because
/// every one of its leaves was suppressed is kept as an empty object rather than
/// removed, so the document's shape (and its page count) survives.
///
/// Array indices are collapsed to `[]` in the path used for matching and for
/// the census, so one rule covers every page and the census does not grow a
/// row per page number.
fn walk(
    value: &Value,
    path: &mut Vec<String>,
    cfg: &NestedJsonConfig,
    keys: &mut KeyStore,
    census: &mut Census,
) -> Option<Value> {
    match value {
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                path.push(k.to_ascii_lowercase());
                let kept = walk(v, path, cfg, keys, census);
                path.pop();
                if let Some(kept) = kept {
                    out.insert(k.clone(), kept);
                }
            }
            Some(Value::Object(out))
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for v in items {
                path.push("[]".to_string());
                let kept = walk(v, path, cfg, keys, census);
                path.pop();
                match kept {
                    Some(kept) => out.push(kept),
                    // Suppressing an object element would shift every later
                    // index and make `page_number` lie, so it is held as null.
                    // A suppressed *scalar* element carries no index anything
                    // else refers to, so it is dropped — otherwise a wholly
                    // suppressed string array becomes `[null, null, null]`,
                    // which still discloses how many values were there.
                    None if v.is_object() || v.is_array() => out.push(Value::Null),
                    None => {}
                }
            }
            Some(Value::Array(out))
        }
        leaf => {
            let (action, matched_by) = decide(cfg, path);
            census.record(&display_path(path), leaf, action, matched_by);
            apply(action, leaf, matched_by, cfg, keys)
        }
    }
}

/// Anonymizes one document. Exposed for tests and for callers holding a parsed
/// document already.
pub fn anonymize_document(doc: &Value, cfg: &NestedJsonConfig, keys: &mut KeyStore, census: &mut Census) -> Value {
    walk(doc, &mut Vec::new(), cfg, keys, census).unwrap_or(Value::Null)
}

// ── Run ──────────────────────────────────────────────────────────────────────

/// What one [`run`] produced.
#[derive(Debug, Default)]
pub struct RunReport {
    pub files_written: usize,
    /// Documents read and run through the policy, whether or not written.
    pub documents_examined: usize,
    /// `(file name, why)` for documents that could not be read or parsed. A
    /// corpus of extraction outputs reliably contains a few duds, and failing
    /// the whole run over one of them would mean no output at all.
    pub files_skipped: Vec<(String, String)>,
    pub paths_seen: usize,
    pub paths_kept: usize,
    pub output_dir: PathBuf,
    pub census_path: PathBuf,
    /// True when this run generated the salt for the first time. Later runs
    /// reuse the persisted one, so their pseudonyms match this run's.
    pub salt_created: bool,
    /// Where the salt lives, so the log can say what to back up.
    pub salt_path: PathBuf,
    /// Token vault and encryption key files this run wrote. Whoever holds them
    /// can reverse `tokenization` and `encrypt`, so the log names them.
    pub key_files: Vec<PathBuf>,
    /// True when the run only reported and wrote no anonymized documents.
    pub dry_run: bool,
}

/// Every `*.json` directly under `dir`, sorted by name for deterministic output.
pub(crate) fn json_files(dir: &Path) -> Result<Vec<PathBuf>, PipelineError> {
    let mut out = Vec::new();
    let entries = fs::read_dir(dir).map_err(|e| io_err("scan nested JSON directory", &dir.display().to_string(), e))?;
    for entry in entries {
        let entry = entry.map_err(|e| io_err("read nested JSON directory entry", &dir.display().to_string(), e))?;
        let path = entry.path();
        let is_json = path.extension().and_then(|e| e.to_str()).is_some_and(|e| e.eq_ignore_ascii_case("json"));
        if path.is_file() && is_json {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// Reads the persisted hash salt, generating and storing it on first run.
///
/// Mirrors how the tabular flow treats `symmetric_keys.json`: key material is
/// read from the run's output directory if present and written back if not, so
/// pseudonyms stay stable across runs without the salt ever being committed to
/// a config file. Returns `(hash key, created_this_run, path)`.
///
/// The salt is 32 bytes from the OS CSPRNG, stored as hex and decoded into
/// the HMAC key. Salts written before 4.0.0 were derived from the clock and
/// the process id and truncated to 64 bits, which an attacker holding one
/// known pseudonym can search; they are refused (`KEY_MATERIAL_INVALID`).
fn load_or_create_salt(dir: &Path) -> Result<([u8; 32], bool, PathBuf), PipelineError> {
    let path = dir.join("nested_json_salt.json");
    if path.is_file() {
        let raw =
            fs::read_to_string(&path).map_err(|e| io_err("read nested_json salt", &path.display().to_string(), e))?;
        let v: Value = serde_json::from_str(&raw)?;
        if let Some(salt) = v.get("hash_salt").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            return Ok((hash_key(salt, &path.display().to_string())?, false, path));
        }
        return Err(validation(
            "CONFIG_INVALID_VALUE",
            "nested_json salt file exists but holds no 'hash_salt'",
            &path.display().to_string(),
        ));
    }

    let salt = generate_random_salt_hex()?;
    let body = serde_json::to_string_pretty(&serde_json::json!({ "hash_salt": salt }))?;
    write_secret_file(&path, body.as_bytes())?;
    Ok((hash_key(&salt, &path.display().to_string())?, true, path))
}

/// Processes every input document independently and writes one anonymized
/// document per input, plus the key census.
pub fn run(cfg: &NestedJsonConfig, root: &Path) -> Result<RunReport, PipelineError> {
    let resolve = |p: &Path| -> PathBuf { if p.is_absolute() { p.to_path_buf() } else { root.join(p) } };

    let input = resolve(cfg.input_path.as_ref().ok_or_else(|| {
        validation(
            "CONFIG_INVALID_VALUE",
            "nested_json.input_path is not set",
            "Set it to a .json file or a directory of them",
        )
    })?);
    // One document per input rather than one table, so `output_path` names a
    // subdirectory of `output_directory` instead of a file.
    let output_dir = resolve(&cfg.output_root).join(&cfg.output_subdir);
    let census_path = output_dir.join("nested_json_census.csv");

    let files = if input.is_dir() {
        json_files(&input)?
    } else if input.is_file() {
        vec![input.clone()]
    } else {
        return Err(validation("DATA_MISSING", "nested_json.input_path does not exist", &input.display().to_string()));
    };
    if files.is_empty() {
        return Err(validation(
            "DATA_EMPTY",
            "No .json files found for nested_json input",
            &input.display().to_string(),
        ));
    }

    let key_dir = resolve(&cfg.key_material_dir);
    let (hash_key, salt_created, salt_path) = load_or_create_salt(&key_dir)?;
    let mut keys = KeyStore::load(&key_dir, hash_key)?;
    keys.ensure_encrypt_keys(&cfg.rules)?;

    if !cfg.dry_run {
        fs::create_dir_all(&output_dir)
            .map_err(|e| io_err("create nested_json output directory", &output_dir.display().to_string(), e))?;
        keys.persist(&key_dir)?;
    }

    let mut census = Census::default();
    let mut report = RunReport {
        output_dir: output_dir.clone(),
        census_path: census_path.clone(),
        salt_created,
        salt_path,
        dry_run: cfg.dry_run,
        ..Default::default()
    };

    for file in &files {
        let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("<unnamed>").to_string();
        let raw = match fs::read_to_string(file) {
            Ok(r) => r,
            Err(e) => {
                report.files_skipped.push((name, format!("unreadable: {e}")));
                continue;
            }
        };
        let doc: Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                report.files_skipped.push((name, format!("invalid JSON: {e}")));
                continue;
            }
        };

        let anon = anonymize_document(&doc, cfg, &mut keys, &mut census);

        // The census is built either way — a dry run's whole purpose is to
        // produce it — but only a real run writes a document.
        if cfg.dry_run {
            report.documents_examined += 1;
            continue;
        }

        let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("document");
        // Named after the input, so a document is traceable to its source
        // bundle without the output directory needing an index.
        let out_path = output_dir.join(format!("{stem}.json"));
        let text = serde_json::to_string_pretty(&anon)?;
        fs::write(&out_path, text)
            .map_err(|e| io_err("write anonymized document", &out_path.display().to_string(), e))?;
        report.files_written += 1;
        report.documents_examined += 1;
    }

    if report.documents_examined == 0 {
        return Err(validation(
            "DATA_EMPTY",
            "nested_json processed no documents",
            &format!("{} file(s) found, all skipped", report.files_skipped.len()),
        ));
    }

    // Tokens issued during the run are only on disk once this lands; a run
    // that fails before here leaves documents whose new tokens cannot be
    // reversed, so its output is not to be released.
    if !cfg.dry_run {
        report.key_files = keys.persist(&key_dir)?;
    }
    write_census(&census, &census_path)?;
    report.paths_seen = census.rows().len();
    report.paths_kept = census.kept_paths().len();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const KEY: [u8; 32] = [7; 32];

    // ── Matching ────────────────────────────────────────────────────────────

    fn path(s: &str) -> Vec<String> {
        // Mirrors how `walk` builds a path: lowercased segments, `[]` for indices.
        s.split('.').map(|p| p.to_ascii_lowercase()).collect()
    }

    #[test]
    fn wildcard_matches_within_a_segment() {
        assert!(wildcard_match("patient_*", "patient_name"));
        assert!(wildcard_match("*name*", "hospital_name_2"));
        assert!(wildcard_match("*name", "patient_name"));
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("exact", "exact"));
        assert!(!wildcard_match("patient_*", "doctor_name"));
        assert!(!wildcard_match("exact", "exactly"));
    }

    #[test]
    fn double_star_spans_segments() {
        let r = Rule::new("**.patient_name", Action::Suppress);
        assert!(r.matches(&path("patient_name")));
        assert!(r.matches(&path("pages.[].extracted_data.patient_name")));
        assert!(!r.matches(&path("pages.[].extracted_data.patient_age")));
    }

    /// The narrowest pattern wins regardless of where it sits, in both
    /// directions — this is what makes the config an unordered set of buckets.
    #[test]
    fn narrowest_pattern_wins_regardless_of_order() {
        for rules in [
            vec![Rule::new("**.hospital_name", Action::Keep), Rule::new("**.*name*", Action::Suppress)],
            vec![Rule::new("**.*name*", Action::Suppress), Rule::new("**.hospital_name", Action::Keep)],
        ] {
            let cfg = NestedJsonConfig { rules, ..Default::default() };
            assert_eq!(decide(&cfg, &path("pages.[].extracted_data.hospital_name")).0, &Action::Keep);
            assert_eq!(decide(&cfg, &path("pages.[].extracted_data.patient_name")).0, &Action::Suppress);
        }
    }

    /// The three ordering bugs the first draft actually shipped, each now
    /// resolved by specificity alone. Written in the *wrong* order on purpose:
    /// under first-match-wins every one of these would fail.
    #[test]
    fn specificity_defuses_the_real_ordering_bugs() {
        let cfg = NestedJsonConfig {
            rules: vec![
                Rule::new("**.*_id", Action::Suppress),
                Rule::new("**.*_number", Action::Suppress),
                Rule::new("**.*age*", Action::Suppress),
                Rule::new("**.*stamp*", Action::Suppress),
                Rule::new("**.*time*", Action::Suppress),
                Rule::new("case_id", Action::Hash),
                Rule::new("total_pages", Action::Keep),
                Rule::new("pages.[].page_number", Action::Keep),
                Rule::new("**.patient_age", Action::Masking { spec: 0 }),
                Rule::new("**.status_at_time_of_discharge", Action::Keep),
            ],
            ..Default::default()
        };
        for (p, want) in [
            ("case_id", Action::Hash),
            ("total_pages", Action::Keep),
            ("pages.[].page_number", Action::Keep),
            ("pages.[].extracted_data.patient_age", Action::Masking { spec: 0 }),
            ("pages.[].extracted_data.status_at_time_of_discharge", Action::Keep),
        ] {
            assert_eq!(decide(&cfg, &path(p)).0, &want, "{p}");
        }
    }

    /// An overlap the config did not disambiguate must fail closed.
    #[test]
    fn equal_specificity_ties_go_to_the_safer_action() {
        for rules in [
            vec![Rule::new("**.*_x", Action::Keep), Rule::new("**.*_x", Action::Suppress)],
            vec![Rule::new("**.*_x", Action::Suppress), Rule::new("**.*_x", Action::Keep)],
        ] {
            let cfg = NestedJsonConfig { rules, ..Default::default() };
            assert_eq!(decide(&cfg, &path("a.b_x")).0, &Action::Suppress);
        }
    }

    #[test]
    fn unmatched_paths_take_the_default() {
        let cfg = NestedJsonConfig { rules: vec![Rule::new("case_id", Action::Keep)], ..Default::default() };
        let (action, by) = decide(&cfg, &path("pages.[].extracted_data.bed_sheet_color"));
        assert_eq!(action, &Action::Suppress);
        assert_eq!(by, "<default>");
    }

    // ── Value transforms ────────────────────────────────────────────────────

    #[test]
    fn hashing_is_stable_and_salt_dependent() {
        assert_eq!(hash_token(&KEY, "BOCW/UP/1"), hash_token(&KEY, "BOCW/UP/1"));
        assert_ne!(hash_token(&KEY, "BOCW/UP/1"), hash_token(&[8; 32], "BOCW/UP/1"));
        assert_eq!(hash_token(&KEY, "x").len(), 64);
    }

    #[test]
    fn empty_values_survive_transforms_unchanged() {
        let cfg = NestedJsonConfig::default();
        for action in [Action::Hash, Action::Charcloak] {
            let got = apply(&action, &json!(""), "", &cfg, &mut KeyStore::with_hash_key(KEY));
            assert_eq!(got, Some(json!("")), "{action:?} should leave an empty value alone");
        }
    }

    // ── Document walk ───────────────────────────────────────────────────────

    fn nha_doc(case: &str, name: &str, age: &str) -> Value {
        json!({
            "case_id": case,
            "total_documents": 1,
            "total_pages": 2,
            "pages": [
                {
                    "document": "Discharge Summary",
                    "link": format!("provider/1/2/forms/attachment/DISCHARGE {name}.pdf"),
                    "page_number": 1,
                    "total_pages": 2,
                    "extracted_data": {
                        "document_type": "discharge_summary",
                        "patient_name": name,
                        "patient_age": age,
                        "patient_gender": "Male",
                        "patient_address": "VILLAGE TESTGAON TEHSIL DEMO",
                        "hospital_name": "EXAMPLE HEART HOSPITAL",
                        "hospital_mobile": "9000000001",
                        "patient_uhid": "90000001",
                        "date_of_admission": "21/04/2025",
                        "final_diagnosis": "CAD",
                        "doctor_signature_present": true,
                        "bed_sheet_color": "white"
                    }
                },
                {
                    "document": "Any other document",
                    "link": "provider/1/2/forms/attachment/LAB.pdf",
                    "page_number": 2,
                    "total_pages": 2,
                    "extracted_data": {
                        "document_type": "investigation_report",
                        "patient_name": name,
                        "lab_hemoglobin": "4.2 gms%",
                        "latitude": "12.3456",
                        "longitude": "76.5432"
                    }
                }
            ]
        })
    }

    fn nha_cfg() -> NestedJsonConfig {
        NestedJsonConfig {
            enabled: true,
            default_action: Action::Suppress,
            rules: vec![
                Rule::new("**.*signature*", Action::Suppress),
                Rule::new("**.*name*", Action::Suppress),
                Rule::new("**.*address*", Action::Suppress),
                Rule::new("**.*mobile*", Action::Suppress),
                Rule::new("**.lat*", Action::Suppress),
                Rule::new("**.long*", Action::Suppress),
                Rule::new("**.link", Action::Suppress),
                Rule::new("case_id", Action::Hash),
                Rule::new("**.patient_uhid", Action::Hash),
                Rule::new("**.patient_age", Action::Masking { spec: 1 }),
                Rule::new("**.date_of_admission", Action::Masking { spec: 0 }),
                Rule::new("total_documents", Action::Keep),
                Rule::new("total_pages", Action::Keep),
                Rule::new("**.document", Action::Keep),
                Rule::new("**.page_number", Action::Keep),
                Rule::new("**.document_type", Action::Keep),
                Rule::new("**.patient_gender", Action::Keep),
                Rule::new("**.final_diagnosis", Action::Keep),
                Rule::new("**.lab_*", Action::Keep),
            ],
            // `21/04/2025` → `**/04/2025`: the day goes, month and year stay.
            // `49Y` → `4*Y`: the age goes, its decade stays.
            masking: vec![
                parse_masking_config(&json!({
                    "column": "**.date_of_admission",
                    "apply_order": ["characters"],
                    "characters_to_mask": [1, 2]
                }))
                .unwrap(),
                parse_masking_config(&json!({
                    "column": "**.patient_age",
                    "apply_order": ["characters"],
                    "characters_to_mask": [2]
                }))
                .unwrap(),
            ],
            ..Default::default()
        }
    }

    fn anon(doc: &Value) -> (Value, Census) {
        let mut census = Census::default();
        let out = anonymize_document(doc, &nha_cfg(), &mut KeyStore::with_hash_key(KEY), &mut census);
        (out, census)
    }

    #[test]
    fn structure_is_preserved() {
        let doc = nha_doc("BOCW/MP/1", "ANIL TESTNAME", "49Y");
        let (out, _) = anon(&doc);
        assert_eq!(out["pages"].as_array().unwrap().len(), 2, "page count must survive");
        assert_eq!(out["total_pages"], json!(2));
        assert!(out["pages"][0]["extracted_data"].is_object());
        assert_eq!(out["pages"][0]["page_number"], json!(1));
        assert_eq!(out["pages"][1]["page_number"], json!(2));
    }

    #[test]
    fn direct_identifiers_are_gone_from_the_whole_document() {
        let doc = nha_doc("BOCW/MP/1", "ANIL TESTNAME", "49Y");
        let (out, _) = anon(&doc);
        let text = serde_json::to_string(&out).unwrap();
        for leaked in [
            "SURESH",          // patient name
            "TESTNAME",        // and via the attachment filename in `link`
            "TESTGAON",        // address
            "9000000001",      // mobile
            "90000001",        // uhid, in the clear
            "12.3456",         // geolocation
            "EXAMPLE HEART",   // hospital name
            "bed_sheet_color", // never named by a rule — the default must catch it
        ] {
            assert!(!text.contains(leaked), "{leaked} survived into the output");
        }
    }

    #[test]
    fn suppressed_keys_are_absent_rather_than_blank() {
        let doc = nha_doc("BOCW/MP/1", "ANIL TESTNAME", "49Y");
        let (out, _) = anon(&doc);
        let ed = out["pages"][0]["extracted_data"].as_object().unwrap();
        assert!(!ed.contains_key("patient_name"));
        assert!(!ed.contains_key("patient_address"));
        assert!(!out["pages"][0].as_object().unwrap().contains_key("link"));
    }

    #[test]
    fn quasi_identifiers_are_coarsened_in_place() {
        let doc = nha_doc("BOCW/MP/1", "ANIL TESTNAME", "49Y");
        let (out, _) = anon(&doc);
        let ed = &out["pages"][0]["extracted_data"];
        assert_eq!(ed["patient_age"], json!("4*Y"));
        assert_eq!(ed["date_of_admission"], json!("**/04/2025"));
        assert_eq!(ed["patient_gender"], json!("Male"), "kept for utility");
        assert_eq!(ed["final_diagnosis"], json!("CAD"));
    }

    #[test]
    fn signatures_are_suppressed_outright() {
        let doc = nha_doc("BOCW/MP/1", "ANIL TESTNAME", "49Y");
        let (out, _) = anon(&doc);
        let ed = out["pages"][0]["extracted_data"].as_object().unwrap();
        assert!(
            !ed.contains_key("doctor_signature_present"),
            "masking cannot be trusted on this corpus's scripts, so signatures go entirely"
        );
    }

    #[test]
    fn hashing_links_a_case_across_documents_without_naming_it() {
        let a = nha_doc("BOCW/MP/1", "ANIL TESTNAME", "49Y");
        let b = nha_doc("BOCW/MP/1", "ANIL TESTNAME", "49Y");
        let c = nha_doc("BOCW/BR/2", "RAM KUMAR", "18 Years");
        let (oa, _) = anon(&a);
        let (ob, _) = anon(&b);
        let (oc, _) = anon(&c);
        assert_eq!(oa["case_id"], ob["case_id"], "same case → same pseudonym");
        assert_ne!(oa["case_id"], oc["case_id"], "different cases stay distinct");
        assert_ne!(oa["case_id"], json!("BOCW/MP/1"), "the original id must not survive");
    }

    #[test]
    fn an_unseen_key_is_suppressed_by_default() {
        // The whole point of default-deny: a key no rule anticipated.
        let mut doc = nha_doc("BOCW/MP/1", "ANIL TESTNAME", "49Y");
        doc["pages"][0]["extracted_data"]["aadhaar_number_scanned_from_card"] = json!("1234 5678 9012");
        let (out, census) = anon(&doc);
        let text = serde_json::to_string(&out).unwrap();
        assert!(!text.contains("1234 5678 9012"));
        let rows: BTreeMap<_, _> = census.rows().into_iter().collect();
        let row = &rows["pages[].extracted_data.aadhaar_number_scanned_from_card"];
        assert_eq!(row.action, "suppress");
        assert_eq!(row.matched_by, "<default>");
    }

    #[test]
    fn census_normalises_page_indices_and_never_samples_suppressed_values() {
        let doc = nha_doc("BOCW/MP/1", "ANIL TESTNAME", "49Y");
        let (_, census) = anon(&doc);
        let rows: BTreeMap<_, _> = census.rows().into_iter().collect();
        // Both pages fold into one census row rather than one per index.
        assert_eq!(rows["pages[].extracted_data.patient_name"].seen, 2);
        assert!(
            rows["pages[].extracted_data.patient_name"].example.is_empty(),
            "a suppressed path must not have its value quoted in the report"
        );
        assert_eq!(rows["pages[].extracted_data.document_type"].example, "discharge_summary");
    }

    // ── Run ─────────────────────────────────────────────────────────────────

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("skald_nested_{tag}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn run_writes_one_document_per_input_plus_a_census() {
        let root = tmpdir("run");
        let input = root.join("in");
        fs::create_dir_all(&input).unwrap();
        fs::write(
            input.join("BOCW_MP_1.json"),
            serde_json::to_string(&nha_doc("BOCW/MP/1", "ANIL TESTNAME", "49Y")).unwrap(),
        )
        .unwrap();
        fs::write(
            input.join("BOCW_BR_2.json"),
            serde_json::to_string(&nha_doc("BOCW/BR/2", "RAM KUMAR", "18 Years")).unwrap(),
        )
        .unwrap();
        fs::write(input.join("broken.json"), "{not json").unwrap();

        let cfg = NestedJsonConfig {
            input_path: Some(PathBuf::from("in")),
            output_subdir: "out".to_string(),
            key_material_dir: PathBuf::from("."),
            output_root: PathBuf::from("."),
            ..nha_cfg()
        };
        let report = run(&cfg, &root).unwrap();

        assert_eq!(report.files_written, 2);
        assert_eq!(report.files_skipped.len(), 1, "the malformed file is skipped, not fatal");
        assert!(root.join("out/BOCW_MP_1.json").is_file());
        assert!(root.join("out/BOCW_BR_2.json").is_file());
        assert!(root.join("out/nested_json_census.csv").is_file());

        let written = fs::read_to_string(root.join("out/BOCW_MP_1.json")).unwrap();
        assert!(!written.contains("SURESH"));
        // Output must still parse as the same shape it went in as.
        let parsed: Value = serde_json::from_str(&written).unwrap();
        assert_eq!(parsed["pages"].as_array().unwrap().len(), 2);

        let census = fs::read_to_string(root.join("out/nested_json_census.csv")).unwrap();
        assert!(census.starts_with("path,documents_seen,non_empty,action,matched_by,example_value"));
        assert!(census.contains("pages[].extracted_data.patient_name"));
    }

    #[test]
    fn run_accepts_a_single_file_as_input() {
        let root = tmpdir("single");
        let file = root.join("one.json");
        fs::write(&file, serde_json::to_string(&nha_doc("BOCW/UP/9", "BABLU", "18 Years")).unwrap()).unwrap();
        let cfg = NestedJsonConfig {
            input_path: Some(PathBuf::from("one.json")),
            output_subdir: "out".to_string(),
            key_material_dir: PathBuf::from("."),
            output_root: PathBuf::from("."),
            ..nha_cfg()
        };
        let report = run(&cfg, &root).unwrap();
        assert_eq!(report.files_written, 1);
        assert!(root.join("out/one.json").is_file());
    }

    #[test]
    fn run_fails_when_every_document_is_unusable() {
        let root = tmpdir("allbad");
        fs::write(root.join("a.json"), "{nope").unwrap();
        let cfg = NestedJsonConfig {
            input_path: Some(PathBuf::from(".")),
            output_subdir: "out".to_string(),
            key_material_dir: PathBuf::from("."),
            output_root: PathBuf::from("."),
            ..nha_cfg()
        };
        let err = run(&cfg, &root).unwrap_err();
        assert!(format!("{err:?}").contains("processed no documents"));
    }

    /// The salt is key material: generated once, persisted, and reused, so a
    /// second run's pseudonyms join to the first run's.
    #[test]
    fn salt_persists_so_pseudonyms_are_stable_across_runs() {
        let root = tmpdir("salt");
        fs::write(root.join("a.json"), serde_json::to_string(&nha_doc("BOCW/MP/1", "ANIL TESTNAME", "49Y")).unwrap())
            .unwrap();
        let cfg = NestedJsonConfig {
            input_path: Some(PathBuf::from("a.json")),
            output_subdir: "out".to_string(),
            key_material_dir: PathBuf::from("keys"),
            output_root: PathBuf::from("output"),
            ..nha_cfg()
        };

        let first = run(&cfg, &root).unwrap();
        assert!(first.salt_created, "the first run creates the salt");
        assert!(root.join("keys/nested_json_salt.json").is_file());
        let a: Value = serde_json::from_str(&fs::read_to_string(root.join("output/out/a.json")).unwrap()).unwrap();

        let second = run(&cfg, &root).unwrap();
        assert!(!second.salt_created, "the second run reuses it");
        let b: Value = serde_json::from_str(&fs::read_to_string(root.join("output/out/a.json")).unwrap()).unwrap();
        assert_eq!(a["case_id"], b["case_id"], "same salt must give the same pseudonym");
        assert_ne!(a["case_id"], json!("BOCW/MP/1"));
    }

    /// The salt is the HMAC key, so it must decode to 32 bytes. A salt SKALD
    /// < 4.0 derived from the clock is refused rather than hashed under.
    #[test]
    fn a_legacy_salt_is_refused() {
        let root = tmpdir("legacy-salt");
        fs::write(root.join("a.json"), serde_json::to_string(&nha_doc("BOCW/MP/1", "ANIL TESTNAME", "49Y")).unwrap())
            .unwrap();
        fs::create_dir_all(root.join("keys")).unwrap();
        fs::write(root.join("keys/nested_json_salt.json"), r#"{"hash_salt": "1a2b3c4d5e6f7a8b"}"#).unwrap();
        let cfg = NestedJsonConfig {
            input_path: Some(PathBuf::from("a.json")),
            output_subdir: "out".to_string(),
            key_material_dir: PathBuf::from("keys"),
            output_root: PathBuf::from("output"),
            ..nha_cfg()
        };
        let err = run(&cfg, &root).unwrap_err();
        assert!(format!("{err:?}").contains("KEY_MATERIAL_INVALID"), "{err:?}");
        assert!(!root.join("output/out/a.json").exists());
    }

    #[test]
    fn dry_run_writes_no_documents_but_still_censuses() {
        let root = tmpdir("dry");
        fs::write(root.join("a.json"), serde_json::to_string(&nha_doc("BOCW/MP/1", "ANIL TESTNAME", "49Y")).unwrap())
            .unwrap();
        let cfg = NestedJsonConfig {
            input_path: Some(PathBuf::from("a.json")),
            output_subdir: "out".to_string(),
            key_material_dir: PathBuf::from("keys"),
            output_root: PathBuf::from("output"),
            dry_run: true,
            ..nha_cfg()
        };
        let report = run(&cfg, &root).unwrap();
        assert!(report.dry_run);
        assert_eq!(report.documents_examined, 1);
        assert_eq!(report.files_written, 0);
        assert!(!root.join("output/out/a.json").exists(), "a dry run must produce no document");
        assert!(root.join("output/out/nested_json_census.csv").is_file(), "but it must produce the census");
    }

    // ── Config ──────────────────────────────────────────────────────────────

    #[test]
    fn config_rejects_a_policy_that_keeps_nothing() {
        let err = parse_nested_json(&json!({"nested_json": true, "input_path": "data/nha"})).unwrap_err();
        assert!(format!("{err:?}").contains("suppress every field"));
    }

    #[test]
    fn config_requires_input_path() {
        let err = parse_nested_json(&json!({"nested_json": true, "keep": ["a"]})).unwrap_err();
        assert!(format!("{err:?}").contains("input_path"));
    }

    #[test]
    fn config_rejects_an_unknown_default_action() {
        let err = parse_nested_json(&json!({
            "nested_json": true, "input_path": "x", "default_action": "shred"
        }))
        .unwrap_err();
        assert!(format!("{err:?}").contains("shred"));
    }

    #[test]
    fn config_rejects_malformed_techniques() {
        let base = |extra: Value| {
            let mut o = json!({"nested_json": true, "input_path": "x"});
            for (k, v) in extra.as_object().unwrap() {
                o[k] = v.clone();
            }
            o
        };
        for (cfg, want) in [
            (base(json!({"keep": "**.a"})), "keep"),
            (base(json!({"masking": [{"masking_char": "*"}]})), "column"),
            (base(json!({"size": {"**.a": 5}})), "size is not supported"),
            (base(json!({"qi_constraints": {"**.d": {"precision": "month"}}})), "characters_to_mask"),
        ] {
            let err = parse_nested_json(&cfg).unwrap_err();
            assert!(format!("{err:?}").contains(want), "expected {want} in {err:?}");
        }
    }

    /// Every technique reads off the same section keys the tabular config uses.
    #[test]
    fn config_reads_the_house_technique_keys() {
        let cfg = parse_nested_json(&json!({
            "nested_json": true,
            "input_path": "data/nha",
            "output_path": "nha",
            "keep": ["**.lab_*"],
            "suppress": ["**.*name*"],
            "hashing_with_salt": ["case_id"],
            "hashing_without_salt": [],
            "masking": [{
                "column": "**.*signature*",
                "masking_char": "#",
                "apply_order": ["class"],
                "class_masking_mode": "fixed_class",
                "class_mask_letter": "X",
                "class_mask_digit": "0"
            }],
            "encrypt": [],
            "charcloak": [],
            "tokenization": [],
            "fpe": [],
            "qi_constraints": {
                // An intervals-only entry is the tabular flow's business, and
                // must not be mistaken for a rule here.
                "**.something": {"intervals": [{"from": 1, "to": 10}]}
            }
        }))
        .unwrap();

        assert!(cfg.enabled);
        assert_eq!(cfg.output_subdir, "nha");
        assert_eq!(cfg.default_action, Action::Suppress);
        for (path_str, want) in [
            ("pages.[].extracted_data.lab_hemoglobin", Action::Keep),
            ("pages.[].extracted_data.patient_name", Action::Suppress),
            ("pages.[].extracted_data.doctor_signature", Action::Masking { spec: 0 }),
            ("case_id", Action::Hash),
            ("pages.[].something", Action::Suppress),
        ] {
            assert_eq!(decide(&cfg, &path(path_str)).0, &want, "{path_str}");
        }
    }

    #[test]
    fn absent_flag_parses_as_disabled() {
        let cfg = parse_nested_json(&json!({"suppress": []})).unwrap();
        assert!(!cfg.enabled);
        let cfg = parse_nested_json(&json!({"nested_json": false, "keep": ["a"]})).unwrap();
        assert!(!cfg.enabled);
    }

    // ── Reversible and randomising techniques ──────────────────────────────

    fn complaints_cfg() -> NestedJsonConfig {
        parse_nested_json(&json!({
            "nested_json": true,
            "input_path": "in",
            "default_action": "suppress",
            "keep": ["[].status"],
            "charcloak": ["[].vehicle_no"],
            "tokenization": [{ "column": "[].citizen.phone", "prefix": "PH-", "digits": 4 }],
            "encrypt": [
                "[].citizen.name",
                { "[].citizen.aadhaar": { "format_preserving": true } }
            ]
        }))
        .unwrap()
    }

    fn complaints() -> Value {
        json!([
            { "status": "Open", "vehicle_no": "HR-26-AB-1234",
              "citizen": { "phone": "9000000002", "name": "test citizen", "aadhaar": "1234 5678 9012" } },
            { "status": "Closed", "vehicle_no": "",
              "citizen": { "phone": "9000000002", "name": "test citizen", "aadhaar": null } },
            { "status": "Open", "vehicle_no": null,
              "citizen": { "phone": "", "name": null, "aadhaar": "" } },
            { "status": "Closed", "vehicle_no": "DL-01-C-7",
              "citizen": { "phone": "9000000003", "name": "Ram", "aadhaar": "2222 3333 4444" } }
        ])
    }

    /// Inverts `encrypt` (AES-SIV) for a pattern's key.
    fn pseudo_decrypt(ciphertext: &str, key: &str, pattern: &str) -> String {
        crate::pipeline::preprocess::crypto::decrypt_value(ciphertext, key, pattern).unwrap()
    }

    #[test]
    fn charcloak_replaces_each_character_within_its_class() {
        let cfg = complaints_cfg();
        let out = anonymize_document(&complaints(), &cfg, &mut KeyStore::with_hash_key(KEY), &mut Census::default());
        let cloaked = out[0]["vehicle_no"].as_str().unwrap();
        assert_ne!(cloaked, "HR-26-AB-1234");
        assert_eq!(cloaked.len(), "HR-26-AB-1234".len());
        for (a, b) in "HR-26-AB-1234".chars().zip(cloaked.chars()) {
            assert_eq!(a.is_ascii_uppercase(), b.is_ascii_uppercase(), "{cloaked}");
            assert_eq!(a.is_ascii_digit(), b.is_ascii_digit(), "{cloaked}");
            if !a.is_ascii_alphanumeric() {
                assert_eq!(a, b, "punctuation is kept");
            }
        }
        assert_eq!(out[1].get("vehicle_no"), Some(&json!("")), "an empty value stays empty");
    }

    #[test]
    fn tokenization_is_stable_and_the_vault_reverses_it() {
        let cfg = complaints_cfg();
        let mut keys = KeyStore::with_hash_key(KEY);
        let out = anonymize_document(&complaints(), &cfg, &mut keys, &mut Census::default());
        let (a, b, c) = (&out[0]["citizen"]["phone"], &out[1]["citizen"]["phone"], &out[3]["citizen"]["phone"]);
        // Tokens are random (a counter would number values in first-seen order),
        // shaped prefix + zero-padded digits, stable per value and reversible.
        let shaped = |t: &Value| {
            t.as_str()
                .is_some_and(|t| t.len() == 7 && t.starts_with("PH-") && t[3..].bytes().all(|b| b.is_ascii_digit()))
        };
        assert!(shaped(a) && shaped(c), "{a} {c}");
        assert_eq!(a, b, "the same phone gets the same token in every record");
        assert_ne!(a, c);
        assert_eq!(out[2]["citizen"].get("phone"), Some(&json!("")), "an empty value is not tokenized");
        let vault = &keys.vaults["[].citizen.phone"];
        assert_eq!(vault.reverse[a.as_str().unwrap()], "9000000002");
        assert_eq!(vault.reverse[c.as_str().unwrap()], "9000000003");
    }

    #[test]
    fn encryption_is_deterministic_and_decrypts_back() {
        let cfg = complaints_cfg();
        let mut keys = KeyStore::with_hash_key(KEY);
        let out = anonymize_document(&complaints(), &cfg, &mut keys, &mut Census::default());

        let name = out[0]["citizen"]["name"].as_str().unwrap();
        assert_ne!(name, "test citizen");
        assert_eq!(out[1]["citizen"]["name"], json!(name), "deterministic, so records still join");
        let key = &keys.symmetric["[].citizen.name"];
        assert_eq!(pseudo_decrypt(name, key, "[].citizen.name"), "test citizen");

        let aadhaar = out[0]["citizen"]["aadhaar"].as_str().unwrap();
        assert_ne!(aadhaar, "1234 5678 9012");
        assert!(
            aadhaar.len() == 14 && aadhaar.split(' ').all(|g| g.len() == 4 && g.bytes().all(|b| b.is_ascii_digit())),
            "format-preserving keeps the digit groups: {aadhaar}"
        );
        let key = &keys.fpe["[].citizen.aadhaar"];
        let plain =
            crate::pipeline::preprocess::crypto::format_preserving_decrypt(aadhaar, key, "[].citizen.aadhaar").unwrap();
        assert_eq!(plain, "1234 5678 9012");
        // Indexing a missing key also yields Null, so check the key survived.
        assert_eq!(out[1]["citizen"].get("aadhaar"), Some(&Value::Null), "null passes through");
        assert_eq!(out[2]["citizen"].get("name"), Some(&Value::Null), "null passes through");
        assert_eq!(out[2]["citizen"].get("aadhaar"), Some(&json!("")), "empty passes through");
    }

    #[test]
    fn census_labels_the_new_techniques() {
        let mut census = Census::default();
        anonymize_document(&complaints(), &complaints_cfg(), &mut KeyStore::with_hash_key(KEY), &mut census);
        let action = |p: &str| census.rows().into_iter().find(|(path, _)| path == p).unwrap().1.action;
        assert_eq!(action("[].vehicle_no"), "charcloak");
        assert_eq!(action("[].citizen.phone"), "tokenization");
        assert_eq!(action("[].citizen.name"), "encrypt");
        assert_eq!(action("[].citizen.aadhaar"), "encrypt(format_preserving)");
    }

    #[test]
    fn run_persists_key_material_and_later_runs_reuse_it() {
        let root = tmpdir("keys");
        fs::create_dir_all(root.join("in")).unwrap();
        fs::write(root.join("in/c.json"), complaints().to_string()).unwrap();
        let cfg = NestedJsonConfig {
            output_subdir: "out".into(),
            key_material_dir: PathBuf::from("."),
            output_root: PathBuf::from("."),
            ..complaints_cfg()
        };

        let first = run(&cfg, &root).unwrap();
        let mut files: Vec<_> = first.key_files.iter().map(|p| p.file_name().unwrap().to_owned()).collect();
        files.sort();
        assert_eq!(files, [FPE_KEYS_FILE, SYMMETRIC_KEYS_FILE, TOKEN_VAULT_FILE]);
        let before = fs::read_to_string(root.join("out/c.json")).unwrap();

        run(&cfg, &root).unwrap();
        let after = fs::read_to_string(root.join("out/c.json")).unwrap();
        let reversible = |doc: &str| {
            let v: Value = serde_json::from_str(doc).unwrap();
            v.as_array().unwrap().iter().map(|r| r["citizen"].clone()).collect::<Vec<_>>()
        };
        assert_eq!(reversible(&before), reversible(&after), "tokens and ciphertext match across runs");
    }

    #[test]
    fn a_dry_run_writes_no_key_material() {
        let root = tmpdir("keys_dry");
        fs::create_dir_all(root.join("in")).unwrap();
        fs::write(root.join("in/c.json"), complaints().to_string()).unwrap();
        let cfg = NestedJsonConfig {
            output_subdir: "out".into(),
            key_material_dir: PathBuf::from("."),
            output_root: PathBuf::from("."),
            dry_run: true,
            ..complaints_cfg()
        };
        let report = run(&cfg, &root).unwrap();
        assert!(report.key_files.is_empty());
        for f in [TOKEN_VAULT_FILE, SYMMETRIC_KEYS_FILE, FPE_KEYS_FILE] {
            assert!(!root.join(f).exists(), "{f}");
        }
    }

    #[test]
    fn techniques_no_nested_flow_applies_are_refused_not_ignored() {
        for key in ["hashing_without_salt", "fpe"] {
            let err = parse_nested_json(&json!({
                "nested_json": true, "input_path": "in", "keep": ["a"], key: ["[].citizen.phone"]
            }))
            .unwrap_err();
            assert!(format!("{err:?}").contains(key), "{err:?}");
        }
        // Empty buckets, as every shipped config carries them, are fine.
        parse_nested_json(&json!({
            "nested_json": true, "input_path": "in", "keep": ["a"], "hashing_without_salt": [], "fpe": []
        }))
        .unwrap();
    }

    #[test]
    fn fhir_bundles_refuse_the_reversible_techniques() {
        for (key, entry) in
            [("tokenization", json!([{ "column": "**.telecom[].value" }])), ("encrypt", json!(["**.telecom[].value"]))]
        {
            let err = crate::pipeline::fhir_bundle::parse_fhir_bundle(&json!({
                "fhir_bundle": true, "input_path": "in", "keep": ["a"], key: entry
            }))
            .unwrap_err();
            assert!(format!("{err:?}").contains("not supported by fhir_bundle"), "{err:?}");
        }
    }

    #[test]
    fn filename_keeps_only_the_last_path_segment() {
        for (input, want) in [
            (
                "https://files.example.org/app/media/complaint/documents/0000aaaa1111_complaint_00001_00002.jpg?AWSAccessKeyId=EXAMPLEKEY&Signature=abc%3D&Expires=1790706636",
                Some("0000aaaa1111_complaint_00001_00002.jpg"),
            ),
            ("https://host/a/DISCHARGE%20SURESH.pdf#page=2", Some("DISCHARGE SURESH.pdf")),
            ("/srv/uploads/scan_01.png", Some("scan_01.png")),
            ("C:\\scans\\scan_02.png", Some("scan_02.png")),
            ("report.pdf", Some("report.pdf")),
            ("https://files.example.org", None),
            ("https://files.example.org/media/", None),
        ] {
            assert_eq!(file_name(input).as_deref(), want, "{input}");
        }
    }

    #[test]
    fn filename_rules_apply_through_the_config() {
        let cfg = parse_nested_json(&json!({
            "nested_json": true, "input_path": "in",
            "filename": ["**.document", "timeline[].documents[]"]
        }))
        .unwrap();
        let doc = json!({
            "documents_details": [
                { "document": "https://fs/x/0000aaaa1111_complaint_00001_00002.jpg?Signature=abc" },
                { "document": null },
                { "document": "https://fs" }
            ],
            "timeline": [{ "documents": ["https://fs/y/0000bbbb2222_documents.jpg?Expires=1"] }]
        });
        let mut census = Census::default();
        let out = anonymize_document(&doc, &cfg, &mut KeyStore::with_hash_key(KEY), &mut census);
        let docs = &out["documents_details"];
        assert_eq!(docs[0]["document"], json!("0000aaaa1111_complaint_00001_00002.jpg"));
        assert_eq!(docs[1].get("document"), Some(&Value::Null), "null passes through");
        assert_eq!(docs[2].get("document"), None, "a bare host is suppressed, not released");
        assert_eq!(out["timeline"][0]["documents"], json!(["0000bbbb2222_documents.jpg"]));
        let row = census.rows().into_iter().find(|(p, _)| p == "documents_details[].document").unwrap().1;
        assert_eq!(row.action, "filename");
    }
}
