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

use crate::pipeline::bootstrap::{io_err, validation, PipelineError};
use crate::pipeline::preprocess::crypto::randomize_preserving_class;
use crate::pipeline::preprocess::masking::{apply_masking_value, parse_masking_config, MaskingConfigLite};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
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
    /// `masking`: index into [`NestedJsonConfig::masking`], which holds specs
    /// parsed by the tabular masker itself. The value is transformed by
    /// `apply_masking_value`, so the `characters_to_mask` / `regex_patterns` /
    /// `class_masking_mode` steps behave exactly as they do for a CSV column —
    /// an entry naming none of them masks nothing, which is why one is required.
    Masking { spec: usize },
    /// `hashing_with_salt`: a stable salted digest, so the same value maps to
    /// the same token everywhere. This is what keeps a case linkable across its
    /// own pages without carrying the resolvable id.
    Hash,
    /// Generalization with a fixed bin width, the `size` of the tabular
    /// config: `"49Y"` with size 5 → `"45-49"`. Bins are fixed rather than
    /// searched because a single-subject document has no lattice to search.
    GeneralizeSize { size: u32 },
    /// Generalization of a date or timestamp to year, or year-month. The one
    /// technique with no tabular counterpart — the tabular flow generalizes
    /// numbers and categorical hierarchies, and never parses a date.
    GeneralizeDate { month: bool },
}

impl Action {
    /// The config key this action came from, for the census report.
    fn label(&self) -> String {
        match self {
            Action::Keep => "keep".into(),
            Action::Suppress => "suppress".into(),
            Action::Masking { .. } => "masking".into(),
            Action::Hash => "hashing_with_salt".into(),
            Action::GeneralizeSize { size } => format!("generalization(size={size})"),
            Action::GeneralizeDate { month } => {
                format!("generalization({})", if *month { "month" } else { "year" })
            }
        }
    }
}

/// Parses `default_action`, which can only be one of the two techniques that
/// need no parameters — the fallback applies to paths nobody has named, and
/// masking or generalizing an unknown field is not meaningful.
fn parse_action(raw: &str) -> Option<Action> {
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
fn privacy_rank(a: &Action) -> u8 {
    match a {
        Action::Suppress => 5,
        Action::Masking { .. } => 4,
        Action::Hash => 3,
        Action::GeneralizeSize { .. } | Action::GeneralizeDate { .. } => 2,
        Action::Keep => 1,
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
        let segments: Vec<Segment> = pattern
            .split('.')
            .map(|s| {
                if s == "**" {
                    Segment::DoubleStar
                } else {
                    Segment::Literal(s.to_ascii_lowercase())
                }
            })
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
    /// Masking specs, parsed by the tabular masker's own `parse_masking_config`
    /// so nested masking and column masking cannot drift apart.
    pub masking: Vec<MaskingConfigLite>,
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
            key_material_dir: PathBuf::from("output"),
            masking: Vec::new(),
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
    let mut cfg = NestedJsonConfig::default();
    cfg.enabled = section.get("nested_json").and_then(Value::as_bool).unwrap_or(false);
    if !cfg.enabled {
        return Ok(cfg);
    }

    cfg.input_path = section
        .get("input_path")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from);
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

    // Techniques that take a plain list of targets, as in the tabular config.
    for (key, action) in [
        ("keep", Action::Keep),
        ("suppress", Action::Suppress),
        ("hashing_with_salt", Action::Hash),
    ] {
        for pattern in string_list(section.get(key), key)? {
            cfg.rules.push(Rule::new(&pattern, action.clone()));
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
            if spec.characters_to_mask.is_empty()
                && spec.regex_patterns.is_empty()
                && spec.class_masking_mode.is_none()
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
            cfg.rules.push(Rule::new(&spec.column.clone(), Action::Masking { spec: cfg.masking.len() }));
            cfg.masking.push(spec);
        }
    }

    // `size`: the generalization bin width per target, as in the tabular config.
    if let Some(obj) = section.get("size").and_then(Value::as_object) {
        for (pattern, v) in obj {
            let size = v.as_u64().filter(|n| *n > 0).ok_or_else(|| {
                validation(
                    "CONFIG_INVALID_VALUE",
                    "size values must be a positive bin width",
                    &format!("{pattern}: {v}"),
                )
            })?;
            cfg.rules.push(Rule::new(pattern, Action::GeneralizeSize { size: size as u32 }));
        }
    }

    // `qi_constraints`: how a given QI is allowed to generalize. The tabular
    // flow reads `intervals` here and ignores anything else, so date precision
    // rides along in the same block instead of needing a key of its own.
    if let Some(obj) = section.get("qi_constraints").and_then(Value::as_object) {
        for (pattern, constraint) in obj {
            let Some(p) = constraint.get("precision") else { continue };
            let month = match p.as_str().map(|s| s.trim().to_ascii_lowercase()).as_deref() {
                Some("month") => true,
                Some("year") => false,
                _ => {
                    return Err(validation(
                        "CONFIG_INVALID_VALUE",
                        "qi_constraints precision must be \"month\" or \"year\"",
                        &format!("{pattern}: {p}"),
                    ))
                }
            };
            cfg.rules.push(Rule::new(pattern, Action::GeneralizeDate { month }));
        }
    }

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

/// A technique bucket holding a list of path globs.
fn string_list(v: Option<&Value>, key: &str) -> Result<Vec<String>, PipelineError> {
    let Some(v) = v else { return Ok(Vec::new()) };
    let arr = v.as_array().ok_or_else(|| {
        validation(
            "CONFIG_INVALID_VALUE",
            &format!("{key} must be an array of path patterns"),
            &v.to_string(),
        )
    })?;
    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        let pattern = entry.as_str().filter(|s| !s.trim().is_empty()).ok_or_else(|| {
            validation(
                "CONFIG_INVALID_VALUE",
                &format!("{key} entries must be non-empty strings"),
                &entry.to_string(),
            )
        })?;
        out.push(pattern.to_string());
    }
    Ok(out)
}

// ── Value transforms ─────────────────────────────────────────────────────────

fn hash_token(salt: &str, value: &str) -> String {
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(value.as_bytes());
    // 16 hex chars is 64 bits — plenty to keep these id spaces collision-free,
    // and short enough to stay readable in a document meant for human review.
    hex::encode(h.finalize())[..16].to_string()
}

/// Pulls the first run of ASCII digits out of a string. Ages in this corpus
/// arrive as `"49Y"`, `"18 Years"`, `"24 Yrs./Male"`, `"2 वर्ष"`, `"25YRS/MALE"`.
fn first_number(s: &str) -> Option<i64> {
    let mut digits = String::new();
    for c in s.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
        } else if !digits.is_empty() {
            break;
        }
    }
    digits.parse().ok()
}

/// `49` with size 5 → `"45-49"`. Values at or above 90 collapse into a single
/// top band: for an age, the 90+ tail is thin enough that a five-year band
/// there comes close to naming the person.
fn generalize_size(value: &str, width: u32) -> Option<String> {
    let age = first_number(value)?;
    if age < 0 {
        return None;
    }
    if age >= 90 {
        return Some("90+".to_string());
    }
    let w = width as i64;
    let lo = (age / w) * w;
    Some(format!("{}-{}", lo, lo + w - 1))
}

const MONTHS: [&str; 12] =
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];

/// Coarsens the date formats this corpus actually contains:
/// `27/10/2024`, `25-4-2025`, `2025-04-21 2:24 pm`, `21-Apr-2025 03:11 PM`,
/// `Oct 29, 2024, 04:57 p.m.`, `21/4/25`.
///
/// Ambiguity is resolved the way Indian health records are written —
/// day-first — except when the first component is unambiguously a 4-digit
/// year. Returns `None` when nothing date-shaped is found, which the caller
/// turns into a redaction rather than a pass-through.
fn date_precision(value: &str, month: bool) -> Option<String> {
    let lower = value.to_ascii_lowercase();

    // Named month anywhere: "21-apr-2025", "oct 29, 2024".
    if let Some((mi, _)) = MONTHS.iter().enumerate().find(|(_, m)| lower.contains(*m)) {
        let year = four_digit_year(&lower)?;
        return Some(if month { format!("{year}-{:02}", mi + 1) } else { year.to_string() });
    }

    // Numeric separators.
    let parts: Vec<&str> = lower
        .split(|c: char| !c.is_ascii_digit())
        .filter(|p| !p.is_empty())
        .collect();
    if parts.len() < 3 {
        // A bare year on its own is still usable.
        return four_digit_year(&lower).map(|y| y.to_string());
    }

    let (y, m) = if parts[0].len() == 4 {
        (parts[0].parse::<i64>().ok()?, parts[1].parse::<i64>().ok()?)
    } else {
        let raw_y = parts[2].parse::<i64>().ok()?;
        let y = if parts[2].len() <= 2 {
            // Two-digit years in this corpus are all 20xx.
            2000 + raw_y
        } else {
            raw_y
        };
        (y, parts[1].parse::<i64>().ok()?)
    };
    if !(1900..=2100).contains(&y) || !(1..=12).contains(&m) {
        return None;
    }
    Some(if month { format!("{y}-{m:02}") } else { y.to_string() })
}

fn four_digit_year(s: &str) -> Option<i64> {
    let bytes: Vec<char> = s.chars().collect();
    for w in bytes.windows(4) {
        if w.iter().all(|c| c.is_ascii_digit()) {
            let y: i64 = w.iter().collect::<String>().parse().ok()?;
            if (1900..=2100).contains(&y) {
                return Some(y);
            }
        }
    }
    None
}

/// Applies one action to one leaf. `None` means "remove this key".
fn apply(action: &Action, value: &Value, cfg: &NestedJsonConfig, salt: &str) -> Option<Value> {
    let as_text = match value {
        Value::Null => String::new(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        _ => return Some(value.clone()),
    };
    let empty = as_text.trim().is_empty();
    // A value that will not parse for its generalization is suppressed, never
    // passed through: an unparsed date is still a date. Not configurable —
    // there is no safe reading of "release the value I could not generalize".
    let fallback = || None;

    match action {
        Action::Keep => Some(value.clone()),
        Action::Suppress => None,
        Action::Masking { spec } => {
            if empty {
                return Some(value.clone());
            }
            let spec = cfg.masking.get(*spec)?;
            Some(Value::String(apply_masking_value(&as_text, spec, &randomize_preserving_class)))
        }
        _ if empty => Some(value.clone()),
        Action::Hash => Some(Value::String(hash_token(salt, as_text.trim()))),
        Action::GeneralizeSize { size } => {
            generalize_size(&as_text, *size).map(Value::String).or_else(fallback)
        }
        Action::GeneralizeDate { month } => {
            date_precision(&as_text, *month).map(Value::String).or_else(fallback)
        }
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
        let stat = self.stats.entry(path.to_string()).or_default();
        stat.seen += 1;
        stat.action = action.label();
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
            if stat.example.is_empty() && matches!(action, Action::Keep) {
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
            .filter(|(_, s)| s.action == "keep")
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
    let pick = |p: &[String]| -> Option<&'a Rule> {
        let mut best: Option<&'a Rule> = None;
        for rule in &cfg.rules {
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
    if trimmed < path.len() {
        if let Some(rule) = pick(&path[..trimmed]) {
            return (&rule.action, rule.pattern.as_str());
        }
    }
    (&cfg.default_action, "<default>")
}

/// Renders match segments as a display path: `pages[].extracted_data.patient_name`.
fn display_path(segments: &[String]) -> String {
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
    salt: &str,
    census: &mut Census,
) -> Option<Value> {
    match value {
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                path.push(k.to_ascii_lowercase());
                let kept = walk(v, path, cfg, salt, census);
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
                let kept = walk(v, path, cfg, salt, census);
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
            apply(action, leaf, cfg, salt)
        }
    }
}

/// Anonymizes one document. Exposed for tests and for callers holding a parsed
/// document already.
pub fn anonymize_document(doc: &Value, cfg: &NestedJsonConfig, salt: &str, census: &mut Census) -> Value {
    walk(doc, &mut Vec::new(), cfg, salt, census).unwrap_or(Value::Null)
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
    /// True when the run only reported and wrote no anonymized documents.
    pub dry_run: bool,
}

/// Every `*.json` directly under `dir`, sorted by name for deterministic output.
fn json_files(dir: &Path) -> Result<Vec<PathBuf>, PipelineError> {
    let mut out = Vec::new();
    let entries =
        fs::read_dir(dir).map_err(|e| io_err("scan nested JSON directory", &dir.display().to_string(), e))?;
    for entry in entries {
        let entry =
            entry.map_err(|e| io_err("read nested JSON directory entry", &dir.display().to_string(), e))?;
        let path = entry.path();
        let is_json = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("json"));
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
/// a config file. Returns `(salt, created_this_run, path)`.
fn load_or_create_salt(dir: &Path) -> Result<(String, bool, PathBuf), PipelineError> {
    let path = dir.join("nested_json_salt.json");
    if path.is_file() {
        let raw = fs::read_to_string(&path)
            .map_err(|e| io_err("read nested_json salt", &path.display().to_string(), e))?;
        let v: Value = serde_json::from_str(&raw)?;
        if let Some(salt) = v.get("hash_salt").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            return Ok((salt.to_string(), false, path));
        }
        return Err(validation(
            "CONFIG_INVALID_VALUE",
            "nested_json salt file exists but holds no 'hash_salt'",
            &path.display().to_string(),
        ));
    }

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let salt = hash_token("skald-nested-json", &format!("{nanos}-{}", std::process::id()));
    fs::create_dir_all(dir)
        .map_err(|e| io_err("create key material directory", &dir.display().to_string(), e))?;
    let body = serde_json::to_string_pretty(&serde_json::json!({ "hash_salt": salt }))?;
    fs::write(&path, body)
        .map_err(|e| io_err("write nested_json salt", &path.display().to_string(), e))?;
    Ok((salt, true, path))
}

/// Processes every input document independently and writes one anonymized
/// document per input, plus the key census.
pub fn run(cfg: &NestedJsonConfig, root: &Path) -> Result<RunReport, PipelineError> {
    let resolve = |p: &Path| -> PathBuf {
        if p.is_absolute() { p.to_path_buf() } else { root.join(p) }
    };

    let input = resolve(cfg.input_path.as_ref().ok_or_else(|| {
        validation(
            "CONFIG_INVALID_VALUE",
            "nested_json.input_path is not set",
            "Set it to a .json file or a directory of them",
        )
    })?);
    // One document per input rather than one table, so `output_path` names a
    // subdirectory of `output_directory` instead of a file.
    let output_dir = resolve(&cfg.key_material_dir).join(&cfg.output_subdir);
    let census_path = output_dir.join("nested_json_census.csv");

    let files = if input.is_dir() {
        json_files(&input)?
    } else if input.is_file() {
        vec![input.clone()]
    } else {
        return Err(validation(
            "DATA_MISSING",
            "nested_json.input_path does not exist",
            &input.display().to_string(),
        ));
    };
    if files.is_empty() {
        return Err(validation(
            "DATA_EMPTY",
            "No .json files found for nested_json input",
            &input.display().to_string(),
        ));
    }

    let (salt, salt_created, salt_path) = load_or_create_salt(&resolve(&cfg.key_material_dir))?;

    if !cfg.dry_run {
        fs::create_dir_all(&output_dir).map_err(|e| {
            io_err("create nested_json output directory", &output_dir.display().to_string(), e)
        })?;
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

        let anon = anonymize_document(&doc, cfg, &salt, &mut census);

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

    write_census(&census, &census_path)?;
    report.paths_seen = census.rows().len();
    report.paths_kept = census.kept_paths().len();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SALT: &str = "test-salt";

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
                Rule::new("**.patient_age", Action::GeneralizeSize { size: 5 }),
                Rule::new("**.timestamp", Action::GeneralizeDate { month: true }),
                Rule::new("**.status_at_time_of_discharge", Action::Keep),
            ],
            ..Default::default()
        };
        for (p, want) in [
            ("case_id", Action::Hash),
            ("total_pages", Action::Keep),
            ("pages.[].page_number", Action::Keep),
            ("pages.[].extracted_data.patient_age", Action::GeneralizeSize { size: 5 }),
            ("pages.[].extracted_data.timestamp", Action::GeneralizeDate { month: true }),
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
    fn generalize_size_parses_the_age_formats_this_corpus_uses() {
        assert_eq!(generalize_size("49Y", 5).unwrap(), "45-49");
        assert_eq!(generalize_size("18 Years", 5).unwrap(), "15-19");
        assert_eq!(generalize_size("24 Yrs./Male", 5).unwrap(), "20-24");
        assert_eq!(generalize_size("25YRS/MALE", 10).unwrap(), "20-29");
        assert_eq!(generalize_size("2 वर्ष", 5).unwrap(), "0-4");
        assert_eq!(generalize_size("94 Years", 5).unwrap(), "90+");
        assert_eq!(generalize_size("illegible", 5), None);
    }

    #[test]
    fn dates_coarsen_across_the_formats_this_corpus_uses() {
        for (input, month, want) in [
            ("27/10/2024", true, "2024-10"),
            ("25/4/2025", true, "2025-04"),
            ("2025-04-21 2:24 pm", true, "2025-04"),
            ("21-Apr-2025 03:11 PM", true, "2025-04"),
            ("Oct 29, 2024, 04:57 p.m.", true, "2024-10"),
            ("21/4/25", true, "2025-04"),
            ("27/10/2024", false, "2024"),
        ] {
            assert_eq!(date_precision(input, month).as_deref(), Some(want), "input {input}");
        }
        assert_eq!(date_precision("illegible", true), None);
    }

    #[test]
    fn hashing_is_stable_and_salt_dependent() {
        assert_eq!(hash_token(SALT, "BOCW/UP/1"), hash_token(SALT, "BOCW/UP/1"));
        assert_ne!(hash_token(SALT, "BOCW/UP/1"), hash_token("other", "BOCW/UP/1"));
        assert_eq!(hash_token(SALT, "x").len(), 16);
    }

    #[test]
    fn empty_values_survive_transforms_unchanged() {
        let cfg = NestedJsonConfig::default();
        for action in [Action::Hash, Action::GeneralizeSize { size: 5 }, Action::GeneralizeDate { month: true }] {
            let got = apply(&action, &json!(""), &cfg, SALT);
            assert_eq!(got, Some(json!("")), "{action:?} should leave an empty value alone");
        }
    }

    #[test]
    fn unparseable_values_are_suppressed_not_passed_through() {
        let cfg = NestedJsonConfig::default();
        for action in [
            Action::GeneralizeDate { month: true },
            Action::GeneralizeSize { size: 5 },
        ] {
            let got = apply(&action, &json!("illegible"), &cfg, SALT);
            assert_eq!(got, None, "{action:?} must drop a value it cannot generalize");
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
                        "patient_address": "GRAM- GAVRI TEHSIL RADH",
                        "hospital_name": "ANANT HEART HOSPITAL",
                        "hospital_mobile": "9111277737",
                        "patient_uhid": "90026049",
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
                        "latitude": "23.2599",
                        "longitude": "77.4126"
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
                Rule::new("**.patient_age", Action::GeneralizeSize { size: 5 }),
                Rule::new("**.date_of_admission", Action::GeneralizeDate { month: true }),
                Rule::new("total_documents", Action::Keep),
                Rule::new("total_pages", Action::Keep),
                Rule::new("**.document", Action::Keep),
                Rule::new("**.page_number", Action::Keep),
                Rule::new("**.document_type", Action::Keep),
                Rule::new("**.patient_gender", Action::Keep),
                Rule::new("**.final_diagnosis", Action::Keep),
                Rule::new("**.lab_*", Action::Keep),
            ],
            ..Default::default()
        }
    }

    fn anon(doc: &Value) -> (Value, Census) {
        let mut census = Census::default();
        let out = anonymize_document(doc, &nha_cfg(), SALT, &mut census);
        (out, census)
    }

    #[test]
    fn structure_is_preserved() {
        let doc = nha_doc("BOCW/MP/1", "SURESH MEENA", "49Y");
        let (out, _) = anon(&doc);
        assert_eq!(out["pages"].as_array().unwrap().len(), 2, "page count must survive");
        assert_eq!(out["total_pages"], json!(2));
        assert!(out["pages"][0]["extracted_data"].is_object());
        assert_eq!(out["pages"][0]["page_number"], json!(1));
        assert_eq!(out["pages"][1]["page_number"], json!(2));
    }

    #[test]
    fn direct_identifiers_are_gone_from_the_whole_document() {
        let doc = nha_doc("BOCW/MP/1", "SURESH MEENA", "49Y");
        let (out, _) = anon(&doc);
        let text = serde_json::to_string(&out).unwrap();
        for leaked in [
            "SURESH",            // patient name
            "MEENA",             // and via the attachment filename in `link`
            "GRAM- GAVRI",       // address
            "9111277737",        // mobile
            "90026049",          // uhid, in the clear
            "23.2599",           // geolocation
            "ANANT HEART",       // hospital name
            "bed_sheet_color",   // never named by a rule — the default must catch it
        ] {
            assert!(!text.contains(leaked), "{leaked} survived into the output");
        }
    }

    #[test]
    fn suppressed_keys_are_absent_rather_than_blank() {
        let doc = nha_doc("BOCW/MP/1", "SURESH MEENA", "49Y");
        let (out, _) = anon(&doc);
        let ed = out["pages"][0]["extracted_data"].as_object().unwrap();
        assert!(!ed.contains_key("patient_name"));
        assert!(!ed.contains_key("patient_address"));
        assert!(!out["pages"][0].as_object().unwrap().contains_key("link"));
    }

    #[test]
    fn quasi_identifiers_are_coarsened_in_place() {
        let doc = nha_doc("BOCW/MP/1", "SURESH MEENA", "49Y");
        let (out, _) = anon(&doc);
        let ed = &out["pages"][0]["extracted_data"];
        assert_eq!(ed["patient_age"], json!("45-49"));
        assert_eq!(ed["date_of_admission"], json!("2025-04"));
        assert_eq!(ed["patient_gender"], json!("Male"), "kept for utility");
        assert_eq!(ed["final_diagnosis"], json!("CAD"));
    }

    #[test]
    fn signatures_are_suppressed_outright() {
        let doc = nha_doc("BOCW/MP/1", "SURESH MEENA", "49Y");
        let (out, _) = anon(&doc);
        let ed = out["pages"][0]["extracted_data"].as_object().unwrap();
        assert!(
            !ed.contains_key("doctor_signature_present"),
            "masking cannot be trusted on this corpus's scripts, so signatures go entirely"
        );
    }

    #[test]
    fn hashing_links_a_case_across_documents_without_naming_it() {
        let a = nha_doc("BOCW/MP/1", "SURESH MEENA", "49Y");
        let b = nha_doc("BOCW/MP/1", "SURESH MEENA", "49Y");
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
        let mut doc = nha_doc("BOCW/MP/1", "SURESH MEENA", "49Y");
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
        let doc = nha_doc("BOCW/MP/1", "SURESH MEENA", "49Y");
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
            serde_json::to_string(&nha_doc("BOCW/MP/1", "SURESH MEENA", "49Y")).unwrap(),
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
        fs::write(
            root.join("a.json"),
            serde_json::to_string(&nha_doc("BOCW/MP/1", "SURESH MEENA", "49Y")).unwrap(),
        )
        .unwrap();
        let cfg = NestedJsonConfig {
            input_path: Some(PathBuf::from("a.json")),
            output_subdir: "out".to_string(),
            key_material_dir: PathBuf::from("keys"),
            ..nha_cfg()
        };

        let first = run(&cfg, &root).unwrap();
        assert!(first.salt_created, "the first run creates the salt");
        assert!(root.join("keys/nested_json_salt.json").is_file());
        let a: Value =
            serde_json::from_str(&fs::read_to_string(root.join("keys/out/a.json")).unwrap()).unwrap();

        let second = run(&cfg, &root).unwrap();
        assert!(!second.salt_created, "the second run reuses it");
        let b: Value =
            serde_json::from_str(&fs::read_to_string(root.join("keys/out/a.json")).unwrap()).unwrap();
        assert_eq!(a["case_id"], b["case_id"], "same salt must give the same pseudonym");
        assert_ne!(a["case_id"], json!("BOCW/MP/1"));
    }

    #[test]
    fn dry_run_writes_no_documents_but_still_censuses() {
        let root = tmpdir("dry");
        fs::write(
            root.join("a.json"),
            serde_json::to_string(&nha_doc("BOCW/MP/1", "SURESH MEENA", "49Y")).unwrap(),
        )
        .unwrap();
        let cfg = NestedJsonConfig {
            input_path: Some(PathBuf::from("a.json")),
            output_subdir: "out".to_string(),
            key_material_dir: PathBuf::from("keys"),
            dry_run: true,
            ..nha_cfg()
        };
        let report = run(&cfg, &root).unwrap();
        assert!(report.dry_run);
        assert_eq!(report.documents_examined, 1);
        assert_eq!(report.files_written, 0);
        assert!(!root.join("keys/out/a.json").exists(), "a dry run must produce no document");
        assert!(
            root.join("keys/out/nested_json_census.csv").is_file(),
            "but it must produce the census"
        );
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
            (base(json!({"size": {"**.a": 0}})), "positive"),
            (base(json!({"qi_constraints": {"**.d": {"precision": "day"}}})), "month"),
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
            "size": {"**.patient_age": 10},
            "qi_constraints": {
                "**.*date*": {"precision": "year"},
                // An intervals-only entry is the tabular flow's business, and
                // must not be mistaken for a date rule here.
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
            ("pages.[].extracted_data.patient_age", Action::GeneralizeSize { size: 10 }),
            ("pages.[].extracted_data.issue_date", Action::GeneralizeDate { month: false }),
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


}
