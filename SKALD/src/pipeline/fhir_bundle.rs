//! Per-bundle de-identification for FHIR R4 Bundles.
//!
//! Built for the NHA claim bundles (BOCW / AROGYAK) after they moved from raw
//! extraction JSON (see `nested_json`) to FHIR. **One bundle is still one
//! patient**, so the reasoning in `nested_json` carries over unchanged: there
//! is no cohort, no k, and this is a structure-preserving redaction pass —
//! one Bundle in, one valid Bundle out.
//!
//! What FHIR changes is everything around the leaves:
//!
//! - **The schema is fixed.** A few hundred element paths instead of an
//!   open-ended key space, so default-deny over FHIR paths
//!   (`Observation.valueQuantity.value`) is precise and reviewable. Rules are
//!   the same globs, buckets and most-specific-wins matching as `nested_json`
//!   — the engine is shared, not copied.
//! - **The old field names survive in one place only:** `Observation.code.text`
//!   (`"gps latitude"`, `"nurse remarks"`). The per-field technique lists are
//!   keyed by those names, so Observations take a second, *code-keyed* rule set
//!   on top of the path rules. A code rule that suppresses drops the whole
//!   Observation — its code alone says what it was.
//! - **Resources reference each other.** Ids are replaced by salted
//!   pseudonyms and every `reference` / `fullUrl` is rewritten to match; a
//!   dropped resource is also removed from whatever pointed at it
//!   (`DiagnosticReport.result[]`).
//! - **The same value is written in several places.** A patient's name sits
//!   in `Patient.name`, in the attachment filename inside
//!   `DocumentReference.content[].attachment.url` (spelled differently), and
//!   in the generated narrative. Path rules handle the places we know about;
//!   a per-bundle **propagation sweep** handles the rest: values read from
//!   identifying paths become needles, and any released leaf containing one is
//!   suppressed and reported. See [`Needles`].
//! - **The output must stay valid FHIR.** Empty objects and arrays are
//!   removed rather than left as `{}` / `null` placeholders (both invalid in
//!   FHIR JSON), a `text` block without its `div` is removed, and a suppressed
//!   primitive takes its `_element` extension sibling with it.

use crate::pipeline::bootstrap::{io_err, validation, PipelineError};
use crate::pipeline::nested_json::{
    apply_action, decide_in, display_path, json_files, parse_action, parse_policy_rules, privacy_rank,
    write_census, Action, Census, Rule,
};
use crate::pipeline::preprocess::crypto::{generate_random_salt_hex, hash_hex};
use crate::pipeline::preprocess::masking::MaskingConfigLite;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

/// The data-absent-reason extension. An element carrying only this says "the
/// source did not have it" and holds no data, so it is always kept.
const DATA_ABSENT_REASON: &str = "http://hl7.org/fhir/StructureDefinition/data-absent-reason";

/// Per-column salt file for this flow, beside the run's other key material.
const SALT_FILE: &str = "fhir_bundle_salts.json";

/// The salt column resource ids are pseudonymised under.
const ID_COLUMN: &str = "<resource id>";

// ── Config ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FhirBundleConfig {
    /// Section key `fhir_bundle: true`. Switches this flow on in place of the
    /// tabular one.
    pub enabled: bool,
    /// Section key `input_path`: a `.json` bundle or a directory of them.
    pub input_path: Option<PathBuf>,
    /// Section key `output_path`, a subdirectory of `output_directory`.
    pub output_subdir: String,
    pub default_action: Action,
    /// Path rules over `ResourceType.element…`, shared engine with `nested_json`.
    pub rules: Vec<Rule>,
    pub masking: Vec<MaskingConfigLite>,
    /// Section key `code_rules`: single-segment globs over the normalised
    /// `Observation.code.text` / `coding[].display`.
    pub code_rules: Vec<Rule>,
    /// Entries of `code_rules` written as `system|code`, matched exactly.
    pub coding_rules: Vec<(String, Action)>,
    /// Section key `propagation.from`: paths whose values become needles.
    pub propagate_from: Vec<Rule>,
    pub propagation_enabled: bool,
    /// Needles shorter than this (after compaction) are ignored.
    pub propagation_min_length: usize,
    /// Section key `hash_strip_prefixes`. Stripped before hashing so
    /// `urn:layerkg:BOCW_BR_…` and `BOCW/BR/…` pseudonymise to the same token.
    pub hash_strip_prefixes: Vec<String>,
    pub dry_run: bool,
    pub key_material_dir: PathBuf,
}

impl Default for FhirBundleConfig {
    fn default() -> Self {
        FhirBundleConfig {
            enabled: false,
            input_path: None,
            output_subdir: "fhir_bundle".to_string(),
            default_action: Action::Suppress,
            rules: Vec::new(),
            masking: Vec::new(),
            code_rules: Vec::new(),
            coding_rules: Vec::new(),
            propagate_from: Vec::new(),
            propagation_enabled: true,
            propagation_min_length: 6,
            hash_strip_prefixes: Vec::new(),
            dry_run: false,
            key_material_dir: PathBuf::from("output"),
        }
    }
}

/// Reads the FHIR bundle policy off a config section. Technique buckets are
/// read by the same parser as `nested_json`, with FHIR paths as the patterns.
pub fn parse_fhir_bundle(section: &Value) -> Result<FhirBundleConfig, PipelineError> {
    let mut cfg = FhirBundleConfig::default();
    cfg.enabled = section.get("fhir_bundle").and_then(Value::as_bool).unwrap_or(false);
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

    // Dates are coarsened with `masking` here, not generalization: FHIR dates
    // are fixed-position ISO 8601, so masking the day and time characters is
    // exact. Refuse the nested-JSON `precision` form rather than silently
    // running a second date technique beside it.
    if let Some(obj) = section.get("qi_constraints").and_then(Value::as_object) {
        if let Some((path, _)) = obj.iter().find(|(_, c)| c.get("precision").is_some()) {
            return Err(validation(
                "CONFIG_INVALID_VALUE",
                "qi_constraints precision is not used by fhir_bundle",
                &format!("{path}: mask FHIR dates with a 'masking' entry and 'characters_to_mask' instead"),
            ));
        }
    }

    let (rules, masking) = parse_policy_rules(section)?;
    cfg.rules = rules;
    cfg.masking = masking;

    if let Some(block) = section.get("code_rules") {
        let obj = block.as_object().ok_or_else(|| {
            validation("CONFIG_INVALID_VALUE", "code_rules must be an object of technique lists", &block.to_string())
        })?;
        for (key, list) in obj {
            let action = match key.as_str() {
                "keep" => Action::Keep,
                "suppress" => Action::Suppress,
                "hashing_with_salt" => Action::Hash,
                "free_text" => Action::FreeText,
                other => {
                    return Err(validation(
                        "CONFIG_INVALID_VALUE",
                        "Unknown code_rules technique",
                        &format!("'{other}' — must be keep, suppress, hashing_with_salt or free_text"),
                    ))
                }
            };
            for entry in str_list(list, &format!("code_rules.{key}"))? {
                if entry.contains('|') {
                    cfg.coding_rules.push((entry.trim().to_ascii_lowercase(), action.clone()));
                } else {
                    cfg.code_rules.push(Rule::new(&normalise_code(&entry), action.clone()));
                }
            }
        }
    }

    if let Some(block) = section.get("propagation") {
        cfg.propagation_enabled = block.get("enabled").and_then(Value::as_bool).unwrap_or(true);
        if let Some(n) = block.get("min_length") {
            cfg.propagation_min_length = n.as_u64().filter(|n| *n >= 3).ok_or_else(|| {
                validation(
                    "CONFIG_INVALID_VALUE",
                    "propagation.min_length must be an integer of at least 3",
                    &n.to_string(),
                )
            })? as usize;
        }
        if let Some(list) = block.get("from") {
            for p in str_list(list, "propagation.from")? {
                cfg.propagate_from.push(Rule::new(&p, Action::Suppress));
            }
        }
    }

    if let Some(list) = section.get("hash_strip_prefixes") {
        cfg.hash_strip_prefixes = str_list(list, "hash_strip_prefixes")?
            .into_iter()
            .map(|p| p.to_ascii_lowercase())
            .collect();
    }

    if cfg.input_path.is_none() {
        return Err(validation(
            "CONFIG_INVALID_VALUE",
            "fhir_bundle requires 'input_path'",
            "Point it at a .json bundle or a directory of them",
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

fn str_list(v: &Value, key: &str) -> Result<Vec<String>, PipelineError> {
    let arr = v.as_array().ok_or_else(|| {
        validation("CONFIG_INVALID_VALUE", &format!("{key} must be an array of strings"), &v.to_string())
    })?;
    arr.iter()
        .map(|e| {
            e.as_str().filter(|s| !s.trim().is_empty()).map(str::to_string).ok_or_else(|| {
                validation("CONFIG_INVALID_VALUE", &format!("{key} entries must be non-empty strings"), &e.to_string())
            })
        })
        .collect()
}

// ── Normalisation ────────────────────────────────────────────────────────────

/// `"Dialysis run-data  Venous Pressure"` → `"dialysis_run_data_venous_pressure"`,
/// the spelling the technique lists use. `*` survives so patterns normalise the
/// same way as the codes they match.
fn normalise_code(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.trim().chars().flat_map(char::to_lowercase) {
        if c.is_alphanumeric() || c == '*' {
            out.push(c);
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string()
}

/// Lowercase alphanumerics only: `"BOCW/BR/2025/R2/1"` and `"BOCW_BR_2025_R2_1"`
/// compact to the same string.
fn compact(s: &str) -> String {
    s.chars().filter(|c| c.is_alphanumeric()).flat_map(char::to_lowercase).collect()
}

/// Decodes `%XX` escapes, so a filename in a URL reads as the name it spells.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Canonical form a value is hashed in, so the same identifier written with
/// different separators or a URN prefix gets one pseudonym.
fn hash_canonical(value: &str, strip_prefixes: &[String]) -> String {
    let mut v = value.trim();
    let lower = v.to_ascii_lowercase();
    for p in strip_prefixes {
        if lower.starts_with(p.as_str()) {
            v = &v[p.len()..];
            break;
        }
    }
    compact(v)
}

/// A salted, UUID-shaped pseudonym for a resource id. Deterministic under the
/// salt, so references can be rewritten without a lookup table and the same
/// source resource keeps one id across runs.
fn pseudo_id(salt: &str, id: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"fhir-id\0");
    h.update(salt.as_bytes());
    h.update(b"\0");
    h.update(id.as_bytes());
    let x = hex::encode(h.finalize());
    let variant = ['8', '9', 'a', 'b'][usize::from_str_radix(&x[16..17], 16).unwrap_or(0) % 4];
    format!("{}-{}-5{}-{}{}-{}", &x[0..8], &x[8..12], &x[13..16], variant, &x[17..20], &x[20..32])
}

/// One salt per column, shared by every bundle in the run and persisted with
/// the run's key material — the same scheme as tabular `hashing_with_salt`
/// (a random 32-byte salt per column, SHA-256 of salt + value), except that
/// the salts are kept so a folder processed in several runs still produces one
/// token per value.
///
/// A *column* is the rule that chose the hash: `Claim.identifier[].value`,
/// `**.meta.source`, `code:aadhaar_number`. Equal values in different columns
/// therefore get unrelated tokens and cannot be joined, while one column's
/// value gets the same token in every bundle — which is what makes a folder of
/// one-patient files linkable as a set.
#[derive(Debug, Default, Clone)]
pub struct Salts {
    by_column: BTreeMap<String, String>,
    created: usize,
}

impl Salts {
    /// The salt for `column`, generated on first use.
    pub fn for_column(&mut self, column: &str) -> String {
        if let Some(s) = self.by_column.get(column) {
            return s.clone();
        }
        let salt = generate_random_salt_hex();
        self.by_column.insert(column.to_string(), salt.clone());
        self.created += 1;
        salt
    }

    fn load(path: &Path) -> Result<Salts, PipelineError> {
        if !path.is_file() {
            return Ok(Salts::default());
        }
        let raw = fs::read_to_string(path).map_err(|e| io_err("read fhir_bundle salts", &path.display().to_string(), e))?;
        let v: Value = serde_json::from_str(&raw)?;
        let obj = v.as_object().ok_or_else(|| {
            validation("CONFIG_INVALID_VALUE", "fhir_bundle salt file must map column to salt", &path.display().to_string())
        })?;
        let mut by_column = BTreeMap::new();
        for (col, salt) in obj {
            let salt = salt.as_str().filter(|s| !s.is_empty()).ok_or_else(|| {
                validation("CONFIG_INVALID_VALUE", "fhir_bundle salt file holds an empty salt", col)
            })?;
            by_column.insert(col.clone(), salt.to_string());
        }
        Ok(Salts { by_column, created: 0 })
    }

    fn save(&self, path: &Path) -> Result<(), PipelineError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| io_err("create key material directory", &parent.display().to_string(), e))?;
        }
        let body = serde_json::to_string_pretty(&self.by_column)?;
        fs::write(path, body).map_err(|e| io_err("write fhir_bundle salts", &path.display().to_string(), e))
    }

    /// Salted hash of a value, as tabular `hashing_with_salt` computes it.
    fn hash(&mut self, column: &str, value: &str) -> String {
        let salt = self.for_column(column);
        hash_hex(&format!("{salt}{value}"))
    }
}

/// The id a reference points at: `urn:uuid:X` or `Type/X`. Contained (`#x`)
/// and absolute references return `None`.
fn reference_target(r: &str) -> Option<&str> {
    if let Some(id) = r.strip_prefix("urn:uuid:") {
        return Some(id);
    }
    if r.contains(':') || r.starts_with('#') {
        return None;
    }
    let mut parts = r.split('/');
    let ty = parts.next()?;
    let id = parts.next()?;
    ty.chars().next().filter(char::is_ascii_uppercase)?;
    Some(id)
}

/// Rewrites a reference onto pseudonymised ids. `None` means it cannot be
/// rewritten safely — an absolute URL can name anything — and is dropped.
fn remap_reference(salt: &str, r: &str) -> Option<String> {
    if r.starts_with('#') {
        return Some(r.to_string());
    }
    if let Some(id) = r.strip_prefix("urn:uuid:") {
        return Some(format!("urn:uuid:{}", pseudo_id(salt, id)));
    }
    let id = reference_target(r)?;
    let ty = r.split('/').next()?;
    Some(format!("{ty}/{}", pseudo_id(salt, id)))
}

// ── Propagation needles ──────────────────────────────────────────────────────

/// Words that say nothing about who a value names. A name token is only a
/// needle if it is not one of these, so a suppressed hospital name does not
/// take every leaf containing "hospital" with it.
const STOPWORDS: &[&str] = &[
    "shri", "smt", "kumari", "baby", "master", "late", "name", "unknown", "illegible", "patient",
    "hospital", "hospitals", "medical", "college", "centre", "center", "research", "private",
    "limited", "government", "india", "general", "institute", "institution", "multispeciality",
    "multispecialty", "speciality", "specialty", "super", "heart", "care", "clinic", "health",
    "nursing", "home", "trust", "memorial", "district", "state", "city", "road", "nagar", "main",
    "near", "opposite", "post", "village", "ward", "block", "sciences", "science", "national",
    "authority", "scheme", "diagnostic", "diagnostics", "laboratory", "pathology", "eye", "kidney",
    "cancer", "children", "mother", "child", "womens", "women", "with", "from", "and", "the",
];

/// Values read from identifying paths in one bundle, in the forms they turn
/// up in elsewhere. Built per bundle — a needle is only meaningful inside the
/// patient's own record.
///
/// Three kinds, because the copies are never exact:
/// - **compact**: the whole value with separators stripped —
///   `BOCW/BR/2025/R2/1010708053` inside `BOCW_BR_2025_R2_1010708053`;
/// - **digit runs** of 6+ digits — the case number alone in a URL path;
/// - **name words** of 4+ letters from values holding no digits —
///   `Patient.name` "KAILA SHI DEVI" against the filename "kailashi devi.pdf",
///   where only the word "devi" survives the respelling.
#[derive(Debug, Default)]
pub struct Needles {
    compact: Vec<(String, String)>,
    digits: Vec<(String, String)>,
    words: Vec<(String, String)>,
}

impl Needles {
    fn add(&mut self, value: &str, source: &str, min_len: usize) {
        let value = value.trim();
        let c = compact(value);
        if c.chars().count() >= min_len {
            self.compact.push((c, source.to_string()));
        }
        for run in value.split(|ch: char| !ch.is_ascii_digit()).filter(|r| r.len() >= 6) {
            self.digits.push((run.to_string(), source.to_string()));
        }
        if !value.chars().any(|ch| ch.is_ascii_digit()) {
            for w in words(value) {
                if w.chars().count() >= 4 && !STOPWORDS.contains(&w.as_str()) {
                    self.words.push((w, source.to_string()));
                }
            }
        }
    }

    /// The source path of the first needle found in `text`, if any.
    fn hit(&self, text: &str) -> Option<&str> {
        let decoded = percent_decode(text);
        let c = compact(&decoded);
        if let Some((_, src)) = self.compact.iter().find(|(n, _)| c.contains(n.as_str())) {
            return Some(src);
        }
        let runs: Vec<&str> = decoded.split(|ch: char| !ch.is_ascii_digit()).filter(|r| !r.is_empty()).collect();
        if let Some((_, src)) = self.digits.iter().find(|(n, _)| runs.iter().any(|r| r.contains(n.as_str()))) {
            return Some(src);
        }
        let ws: HashSet<String> = words(&decoded).collect();
        self.words.iter().find(|(n, _)| ws.contains(n)).map(|(_, src)| src.as_str())
    }
}

fn words(s: &str) -> impl Iterator<Item = String> + '_ {
    s.split(|c: char| !c.is_alphabetic()).filter(|w| !w.is_empty()).map(str::to_lowercase)
}

// ── Pre-pass ─────────────────────────────────────────────────────────────────

/// Calls `f` on every resource in `v`, including contained and nested ones.
fn for_each_resource<'a>(v: &'a Value, f: &mut dyn FnMut(&'a Map<String, Value>)) {
    match v {
        Value::Object(map) => {
            if map.get("resourceType").is_some_and(Value::is_string) {
                f(map);
            }
            for child in map.values() {
                for_each_resource(child, f);
            }
        }
        Value::Array(items) => items.iter().for_each(|c| for_each_resource(c, f)),
        _ => {}
    }
}

/// Every leaf of `v` with its match path, re-rooted at nested resources the
/// same way the main walk does.
fn for_each_leaf<'a>(v: &'a Value, lpath: &mut Vec<String>, dpath: &mut Vec<String>, f: &mut dyn FnMut(&[String], &[String], &'a Value)) {
    match v {
        Value::Object(map) => {
            if let Some(rt) = map.get("resourceType").and_then(Value::as_str) {
                if !lpath.is_empty() {
                    // A nested resource is handled when the outer loop reaches it.
                    return;
                }
                lpath.push(rt.to_ascii_lowercase());
                dpath.push(rt.to_string());
            }
            for (k, child) in map {
                if k == "resourceType" {
                    continue;
                }
                lpath.push(k.to_ascii_lowercase());
                dpath.push(k.clone());
                for_each_leaf(child, lpath, dpath, f);
                lpath.pop();
                dpath.pop();
            }
        }
        Value::Array(items) => {
            for c in items {
                lpath.push("[]".into());
                dpath.push("[]".into());
                for_each_leaf(c, lpath, dpath, f);
                lpath.pop();
                dpath.pop();
            }
        }
        leaf => f(lpath, dpath, leaf),
    }
}

/// The codes an Observation is known by, for the code-keyed rules: the
/// normalised `code.text` and each `coding[].display`, plus `system|code`.
fn observation_codes(res: &Map<String, Value>) -> (Vec<String>, Vec<String>) {
    let mut texts = Vec::new();
    let mut codings = Vec::new();
    if let Some(code) = res.get("code") {
        if let Some(t) = code.get("text").and_then(Value::as_str) {
            texts.push(normalise_code(t));
        }
        for c in code.get("coding").and_then(Value::as_array).into_iter().flatten() {
            if let Some(d) = c.get("display").and_then(Value::as_str) {
                texts.push(normalise_code(d));
            }
            if let (Some(s), Some(k)) = (c.get("system").and_then(Value::as_str), c.get("code").and_then(Value::as_str)) {
                codings.push(format!("{s}|{k}").to_ascii_lowercase());
            }
        }
    }
    texts.retain(|t| !t.is_empty());
    (texts, codings)
}

/// The code rule that governs an Observation: the narrowest matching text
/// glob or an exact coding, the more protective one winning when several
/// match — a code that is suppressed under any of its names is suppressed.
fn code_decision<'a>(cfg: &'a FhirBundleConfig, res: &Map<String, Value>) -> Option<(&'a Action, String)> {
    let (texts, codings) = observation_codes(res);
    let mut best: Option<(&'a Action, String)> = None;
    let mut consider = |action: &'a Action, why: String| {
        let better = match &best {
            None => true,
            Some((b, _)) => privacy_rank(action) > privacy_rank(b),
        };
        if better {
            best = Some((action, why));
        }
    };
    for t in &texts {
        let seg = [t.clone()];
        let (action, by) = decide_in(&cfg.code_rules, &Action::Keep, &seg);
        if by != "<default>" {
            consider(action, format!("code:{by}"));
        }
    }
    for c in &codings {
        if let Some((_, action)) = cfg.coding_rules.iter().find(|(k, _)| k == c) {
            consider(action, format!("coding:{c}"));
        }
    }
    best
}

// ── Walk ─────────────────────────────────────────────────────────────────────

struct Walker<'a> {
    cfg: &'a FhirBundleConfig,
    salts: &'a mut Salts,
    /// The `<resource id>` column's salt, looked up once per bundle.
    id_salt: String,
    census: &'a mut Census,
    /// Original ids of resources a code rule dropped.
    dropped: HashSet<String>,
    needles: Needles,
    /// The code rule governing the Observation being walked, if any.
    code_override: Option<(Action, String)>,
}

impl Walker<'_> {
    /// Walks one value. `None` removes it from its parent.
    fn walk(&mut self, value: &Value, lpath: &mut Vec<String>, dpath: &mut Vec<String>) -> Option<Value> {
        match value {
            Value::Object(map) => self.walk_object(map, lpath, dpath),
            Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    lpath.push("[]".into());
                    dpath.push("[]".into());
                    let kept = self.walk(item, lpath, dpath);
                    lpath.pop();
                    dpath.pop();
                    // FHIR JSON forbids nulls in arrays, and nothing indexes
                    // into these by position, so a removed element is dropped.
                    out.extend(kept);
                }
                (!out.is_empty()).then_some(Value::Array(out))
            }
            leaf => self.leaf(leaf, lpath, dpath),
        }
    }

    fn walk_object(&mut self, map: &Map<String, Value>, lpath: &mut Vec<String>, dpath: &mut Vec<String>) -> Option<Value> {
        // A resource restarts the path at its own type, so `Observation.code`
        // means the same thing in `entry[].resource` and in `contained[]`.
        if let Some(rt) = map.get("resourceType").and_then(Value::as_str) {
            return self.walk_resource(rt, map);
        }

        // Pure structure, no data: "the source did not have this".
        if map.get("url").and_then(Value::as_str) == Some(DATA_ABSENT_REASON) {
            return Some(Value::Object(map.clone()));
        }

        // A reference to a dropped resource goes with it.
        if let Some(target) = map.get("reference").and_then(Value::as_str).and_then(reference_target) {
            if self.dropped.contains(target) {
                self.census.record_as(&display_path(dpath), &Value::Null, "drop_reference", "<dropped resource>", false);
                return None;
            }
        }

        let mut out = Map::new();
        for (k, v) in map {
            if k == "reference" || k == "fullUrl" {
                if let Some(r) = v.as_str() {
                    dpath.push(k.clone());
                    let shown = display_path(dpath);
                    dpath.pop();
                    match remap_reference(&self.id_salt, r) {
                        Some(new) => {
                            self.census.record_as(&shown, v, "pseudonymise_reference", "<structural>", false);
                            out.insert(k.clone(), Value::String(new));
                        }
                        None => self.census.record_as(&shown, v, "suppress", "<unresolvable reference>", false),
                    }
                    continue;
                }
            }
            lpath.push(k.to_ascii_lowercase());
            dpath.push(k.clone());
            // An entry whose resource was dropped is dropped whole, rather than
            // left behind as a bare `fullUrl` pointing at nothing.
            let is_resource = v.get("resourceType").is_some_and(Value::is_string);
            let kept = self.walk(v, lpath, dpath);
            lpath.pop();
            dpath.pop();
            match kept {
                Some(kept) => {
                    out.insert(k.clone(), kept);
                }
                None if is_resource => return None,
                None => {}
            }
        }
        self.tidy(map, out, lpath)
    }

    fn walk_resource(&mut self, rt: &str, map: &Map<String, Value>) -> Option<Value> {
        let id = map.get("id").and_then(Value::as_str);
        if id.is_some_and(|id| self.dropped.contains(id)) {
            return None;
        }
        let saved = std::mem::take(&mut self.code_override);
        if rt == "Observation" {
            self.code_override = code_decision(self.cfg, map).map(|(a, by)| (a.clone(), by));
        }

        let mut lpath = vec![rt.to_ascii_lowercase()];
        let mut dpath = vec![rt.to_string()];
        let mut out = Map::new();
        out.insert("resourceType".into(), Value::String(rt.to_string()));
        for (k, v) in map {
            match k.as_str() {
                "resourceType" => {}
                "id" if v.is_string() => {
                    self.census.record_as(&format!("{rt}.id"), v, "pseudonymise_id", "<structural>", false);
                    out.insert("id".into(), Value::String(pseudo_id(&self.id_salt, v.as_str().unwrap_or_default())));
                }
                _ => {
                    lpath.push(k.to_ascii_lowercase());
                    dpath.push(k.clone());
                    let kept = self.walk(v, &mut lpath, &mut dpath);
                    lpath.pop();
                    dpath.pop();
                    if let Some(kept) = kept {
                        out.insert(k.clone(), kept);
                    }
                }
            }
        }
        self.code_override = saved;
        let tidied = self.tidy(map, out, &lpath)?;
        Some(tidied)
    }

    /// FHIR-validity cleanup of one rewritten object.
    fn tidy(&self, original: &Map<String, Value>, mut out: Map<String, Value>, lpath: &[String]) -> Option<Value> {
        // A primitive removed by policy takes its `_element` sibling with it:
        // that extension can carry the original text of the value.
        for k in original.keys() {
            if !k.starts_with('_') && !out.contains_key(k) {
                out.remove(&format!("_{k}"));
            }
        }
        // Narrative requires its div; `status` alone would be invalid.
        if lpath.last().is_some_and(|s| s == "text") && out.contains_key("status") && !out.contains_key("div") {
            return None;
        }
        (!out.is_empty()).then_some(Value::Object(out))
    }

    fn leaf(&mut self, leaf: &Value, lpath: &[String], dpath: &[String]) -> Option<Value> {
        let shown = display_path(dpath);
        let (action, matched_by) = self.decide(lpath);

        let result = match &action {
            Action::Hash => {
                let text = match leaf {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    _ => String::new(),
                };
                if text.trim().is_empty() {
                    Some(leaf.clone())
                } else {
                    let canonical = hash_canonical(&text, &self.cfg.hash_strip_prefixes);
                    Some(Value::String(self.salts.hash(&matched_by, &canonical)))
                }
            }
            // The salt argument is only read by `Hash`, handled above.
            other => apply_action(other, leaf, &self.cfg.masking, ""),
        };

        // The sweep: a value released as-is must not contain an identifier
        // this same bundle suppressed or pseudonymised somewhere else.
        let released_verbatim = matches!(action, Action::Keep | Action::FreeText);
        if released_verbatim && self.cfg.propagation_enabled {
            if let Some(text) = leaf.as_str() {
                if let Some(src) = self.needles.hit(text) {
                    let by = format!("propagated:{src}");
                    self.census.record_as(&shown, leaf, "suppress", &by, false);
                    return None;
                }
            }
        }

        self.census.record_as(&shown, leaf, &action.label(), &matched_by, matches!(action, Action::Keep));
        result
    }

    fn decide(&self, lpath: &[String]) -> (Action, String) {
        if let Some((action, by)) = &self.code_override {
            // Code-keyed techniques act on the Observation's value; its code,
            // status and the rest stay under the path rules.
            let on_value = lpath.get(1).is_some_and(|s| s.starts_with("value"));
            if on_value && matches!(action, Action::Hash) {
                return (action.clone(), by.clone());
            }
        }
        let (a, by) = decide_in(&self.cfg.rules, &self.cfg.default_action, lpath);
        (a.clone(), by.to_string())
    }
}

/// Anonymizes one Bundle. Exposed for tests and for callers holding a parsed
/// bundle already.
pub fn anonymize_bundle(bundle: &Value, cfg: &FhirBundleConfig, salts: &mut Salts, census: &mut Census) -> Value {
    let mut dropped = HashSet::new();
    for_each_resource(bundle, &mut |res| {
        if res.get("resourceType").and_then(Value::as_str) != Some("Observation") {
            return;
        }
        if let Some((Action::Suppress, by)) = code_decision(cfg, res) {
            let (texts, _) = observation_codes(res);
            let code = texts.first().cloned().unwrap_or_default();
            census.record_as(&format!("Observation[code={code}]"), &Value::Null, "drop_resource", &by, false);
            if let Some(id) = res.get("id").and_then(Value::as_str) {
                dropped.insert(id.to_string());
            }
        }
    });

    let mut needles = Needles::default();
    if cfg.propagation_enabled && !cfg.propagate_from.is_empty() {
        for_each_resource(bundle, &mut |res| {
            let v = Value::Object(res.clone());
            for_each_leaf(&v, &mut Vec::new(), &mut Vec::new(), &mut |lpath, dpath, leaf| {
                let text = match leaf {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    _ => return,
                };
                if cfg.propagate_from.iter().any(|r| decide_in(std::slice::from_ref(r), &Action::Keep, lpath).1 != "<default>") {
                    needles.add(&text, &display_path(dpath), cfg.propagation_min_length);
                }
            });
        });
    }

    let id_salt = salts.for_column(ID_COLUMN);
    let mut w = Walker { cfg, salts, id_salt, census, dropped, needles, code_override: None };
    w.walk(bundle, &mut Vec::new(), &mut Vec::new()).unwrap_or(Value::Null)
}

// ── Run ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct RunReport {
    pub files_written: usize,
    pub documents_examined: usize,
    pub files_skipped: Vec<(String, String)>,
    pub paths_seen: usize,
    pub paths_kept: usize,
    /// Leaves the propagation sweep suppressed across the run.
    pub propagated: usize,
    pub resources_dropped: usize,
    pub output_dir: PathBuf,
    pub census_path: PathBuf,
    /// Columns whose salt this run generated. Zero on a rerun over the same
    /// columns — every salt came from the persisted file.
    pub salts_created: usize,
    pub salt_columns: usize,
    pub salt_path: PathBuf,
    pub dry_run: bool,
}

/// The output file name for one bundle: `<input stem>_anonymised.fhir.json`,
/// so each output sits next to the name of the input it came from.
///
/// NHA input names are case ids (`BOCW_BR_2025_R2_1010708053.fhir.json`), so
/// this carries the case id in clear onto the released file. That is the
/// requested trade-off — traceability for verification — and it means the
/// released folder must be handled as identifying even though its contents
/// are not.
fn output_name(file: &Path) -> String {
    let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("bundle");
    let lower = name.to_ascii_lowercase();
    let stem_len = [".fhir.json", ".json"]
        .iter()
        .find(|ext| lower.ends_with(*ext))
        .map(|ext| name.len() - ext.len())
        .unwrap_or(name.len());
    format!("{}_anonymised.fhir.json", &name[..stem_len])
}

pub fn run(cfg: &FhirBundleConfig, root: &Path) -> Result<RunReport, PipelineError> {
    let resolve = |p: &Path| -> PathBuf { if p.is_absolute() { p.to_path_buf() } else { root.join(p) } };
    let input = resolve(cfg.input_path.as_ref().ok_or_else(|| {
        validation("CONFIG_INVALID_VALUE", "fhir_bundle.input_path is not set", "Set it to a bundle or a directory of them")
    })?);
    let output_dir = resolve(&cfg.key_material_dir).join(&cfg.output_subdir);
    let census_path = output_dir.join("fhir_bundle_census.csv");

    let files = if input.is_dir() {
        json_files(&input)?
    } else if input.is_file() {
        vec![input.clone()]
    } else {
        return Err(validation("DATA_MISSING", "fhir_bundle.input_path does not exist", &input.display().to_string()));
    };
    if files.is_empty() {
        return Err(validation("DATA_EMPTY", "No .json files found for fhir_bundle input", &input.display().to_string()));
    }

    let salt_path = resolve(&cfg.key_material_dir).join(SALT_FILE);
    let mut salts = Salts::load(&salt_path)?;
    if !cfg.dry_run {
        fs::create_dir_all(&output_dir)
            .map_err(|e| io_err("create fhir_bundle output directory", &output_dir.display().to_string(), e))?;
    }

    let mut census = Census::default();
    let mut report = RunReport {
        output_dir: output_dir.clone(),
        census_path: census_path.clone(),
        salt_path: salt_path.clone(),
        dry_run: cfg.dry_run,
        ..Default::default()
    };

    for file in &files {
        let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("<unnamed>").to_string();
        let doc: Value = match fs::read_to_string(file).map_err(|e| format!("unreadable: {e}")).and_then(|raw| {
            serde_json::from_str(&raw).map_err(|e| format!("invalid JSON: {e}"))
        }) {
            Ok(v) => v,
            Err(why) => {
                report.files_skipped.push((name, why));
                continue;
            }
        };
        if doc.get("resourceType").and_then(Value::as_str) != Some("Bundle") {
            report.files_skipped.push((name, "not a FHIR Bundle (resourceType != \"Bundle\")".into()));
            continue;
        }

        let anon = anonymize_bundle(&doc, cfg, &mut salts, &mut census);
        report.documents_examined += 1;
        if cfg.dry_run {
            continue;
        }
        let out_path = output_dir.join(output_name(file));
        let text = serde_json::to_string_pretty(&anon)?;
        fs::write(&out_path, text).map_err(|e| io_err("write anonymized bundle", &out_path.display().to_string(), e))?;
        report.files_written += 1;
    }

    if report.documents_examined == 0 {
        return Err(validation(
            "DATA_EMPTY",
            "fhir_bundle processed no bundles",
            &format!("{} file(s) found, all skipped", report.files_skipped.len()),
        ));
    }

    write_census(&census, &census_path)?;
    // Persisted even on a dry run: the salts are what make a later real run's
    // tokens match whatever the dry run was reviewed against.
    salts.save(&salt_path)?;
    report.salts_created = salts.created;
    report.salt_columns = salts.by_column.len();
    let rows = census.rows();
    report.paths_seen = rows.len();
    report.paths_kept = census.kept_paths().len();
    report.propagated = rows.iter().filter(|(_, r)| r.matched_by.starts_with("propagated:")).map(|(_, r)| r.seen).sum();
    report.resources_dropped = rows.iter().filter(|(_, r)| r.action == "drop_resource").map(|(_, r)| r.seen).sum();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    const SALT: &str = "test-salt";
    const PAT: &str = "d7359bfc-ae18-5eb0-91bd-f1d79277a38b";
    const OBS_HB: &str = "11111111-0000-5000-8000-000000000001";
    const OBS_GPS: &str = "11111111-0000-5000-8000-000000000002";
    const DR: &str = "11111111-0000-5000-8000-000000000003";

    fn dar() -> Value {
        json!({"extension": [{"url": DATA_ABSENT_REASON, "valueCode": "unknown"}]})
    }

    fn entry(res: Value) -> Value {
        json!({"fullUrl": format!("urn:uuid:{}", res["id"].as_str().unwrap()), "resource": res})
    }

    /// Shaped on the real NHA samples, with made-up identities.
    fn bundle() -> Value {
        let meta = json!({"source": "urn:layerkg:BOCW_BR_2025_R2_1010708053",
                          "tag": [{"system": "urn:layerkg:origin", "code": "structure"}]});
        json!({
            "resourceType": "Bundle",
            "type": "collection",
            "entry": [
                entry(json!({"resourceType": "Patient", "id": PAT, "meta": meta, "name": [{"text": "RAVI SHANKAR PRASAD"}], "gender": "male", "birthDate": "1971-05-06"})),
                entry(json!({"resourceType": "Claim", "id": "c1", "meta": meta,
                    "identifier": [{"value": "BOCW/BR/2025/R2/1010708053"}],
                    "patient": {"reference": format!("urn:uuid:{PAT}")},
                    "_status": dar()})),
                entry(json!({"resourceType": "Observation", "id": OBS_HB, "meta": meta, "status": "final",
                    "identifier": [{"system": "urn:layerkg:source-fact", "value": "ca4e9a6bf48e21574d83c1f7"}],
                    "code": {"text": "hemoglobin", "coding": [{"system": "http://loinc.org", "code": "718-7", "display": "Hemoglobin"}]},
                    "subject": {"reference": format!("urn:uuid:{PAT}")},
                    "valueQuantity": {"value": 9.1, "unit": "g/dL"},
                    "performer": [{"extension": [{"url": DATA_ABSENT_REASON, "valueCode": "unknown"}], "display": "Unknown performer"}],
                    "text": {"status": "generated", "div": "<div>Observation — hemoglobin; RAVI 9.1</div>"}})),
                entry(json!({"resourceType": "Observation", "id": OBS_GPS, "meta": meta, "status": "final",
                    "code": {"text": "gps latitude", "coding": [{"system": "http://loinc.org", "code": "42130-5", "display": "Latitude"}]},
                    "subject": {"reference": format!("urn:uuid:{PAT}")},
                    "valueQuantity": {"value": 25.592575, "unit": "°"}})),
                entry(json!({"resourceType": "DiagnosticReport", "id": DR, "status": "final",
                    "code": {"text": "investigation report"},
                    "subject": {"reference": format!("urn:uuid:{PAT}")},
                    "result": [{"reference": format!("urn:uuid:{OBS_HB}")}, {"reference": format!("urn:uuid:{OBS_GPS}")}]})),
                entry(json!({"resourceType": "Organization", "id": "o1", "name": "SREE CHITRA HOSPITAL, KOLLAM", "alias": ["S C HOSPITAL"]})),
                entry(json!({"resourceType": "DocumentReference", "id": "d1", "status": "current",
                    "subject": {"reference": format!("urn:uuid:{PAT}")},
                    "type": {"text": "clinical notes"},
                    "category": [{"text": "In Treatment Photo with Doctor PMAM"}, {"text": "Photo of Ravi at bedside"}],
                    "content": [{"attachment": {"url": "prod/TMS/provider/4667/5887/1010708053/forms/1/attachment/ravi%20shankar.pdf", "title": "page 1"}}]})),
            ]
        })
    }

    fn cfg() -> FhirBundleConfig {
        let mut rules: Vec<Rule> = [
            "Bundle.type", "**.status", "**.meta.tag[].system", "**.meta.tag[].code",
            "**.coding[].system", "**.coding[].code", "**.coding[].display", "**.code.text",
            "**.type.text", "**.category[].text", "Observation.valueQuantity.*", "Patient.gender",
            "DocumentReference.content[].attachment.title",
        ]
        .iter()
        .map(|p| Rule::new(p, Action::Keep))
        .collect();
        for p in ["Patient.name.**", "Organization.name", "Organization.alias", "**.attachment.url", "**.text.div", "**.identifier[].value", "**.identifier[].system"] {
            rules.push(Rule::new(p, Action::Suppress));
        }
        rules.push(Rule::new("Claim.identifier[].value", Action::Hash));
        rules.push(Rule::new("**.meta.source", Action::Hash));
        FhirBundleConfig {
            enabled: true,
            rules,
            code_rules: vec![Rule::new("gps_*", Action::Suppress), Rule::new("nurse_remarks", Action::FreeText)],
            propagate_from: ["Patient.name.**", "Claim.identifier[].value", "Organization.name", "Organization.alias"]
                .iter()
                .map(|p| Rule::new(p, Action::Suppress))
                .collect(),
            hash_strip_prefixes: vec!["urn:layerkg:".into()],
            ..Default::default()
        }
    }

    type CensusRows = BTreeMap<String, crate::pipeline::nested_json::KeyCensusRow>;

    fn anon_in(c: &FhirBundleConfig, b: &Value, salts: &mut Salts) -> (Value, CensusRows) {
        let mut census = Census::default();
        let out = anonymize_bundle(b, c, salts, &mut census);
        (out, census.rows().into_iter().collect())
    }

    fn anon_with(c: &FhirBundleConfig, b: &Value) -> (Value, CensusRows) {
        anon_in(c, b, &mut Salts::default())
    }

    fn anon() -> (Value, CensusRows) {
        anon_with(&cfg(), &bundle())
    }

    fn resource<'a>(out: &'a Value, rt: &str) -> &'a Value {
        out["entry"].as_array().unwrap().iter().map(|e| &e["resource"]).find(|r| r["resourceType"] == rt).unwrap()
    }

    #[test]
    fn identifiers_are_gone_from_the_whole_bundle() {
        let (out, _) = anon();
        let text = serde_json::to_string(&out).unwrap().to_lowercase();
        for leaked in ["ravi", "shankar", "1010708053", "bocw", "sree chitra", "25.59", "ca4e9a6b", PAT, "4667/5887"] {
            assert!(!text.contains(&leaked.to_lowercase()), "{leaked} survived into the output");
        }
    }

    #[test]
    fn ids_and_references_are_pseudonymised_consistently() {
        let mut salts = Salts::default();
        let (out, _) = anon_in(&cfg(), &bundle(), &mut salts);
        let entries = out["entry"].as_array().unwrap();
        for e in entries {
            assert_eq!(e["fullUrl"], json!(format!("urn:uuid:{}", e["resource"]["id"].as_str().unwrap())));
        }
        let patient_id = resource(&out, "Patient")["id"].as_str().unwrap().to_string();
        assert_ne!(patient_id, PAT);
        assert_eq!(patient_id.len(), 36);
        assert_eq!(resource(&out, "Claim")["patient"]["reference"], json!(format!("urn:uuid:{patient_id}")));
        // Deterministic under the id column's salt, so a rerun gives the same ids.
        assert_eq!(pseudo_id(&salts.for_column(ID_COLUMN), PAT), patient_id);
        assert_ne!(pseudo_id("other", PAT), patient_id);
    }

    #[test]
    fn a_code_suppressed_observation_is_dropped_with_its_references() {
        let mut salts = Salts::default();
        let (out, census) = anon_in(&cfg(), &bundle(), &mut salts);
        let entries = out["entry"].as_array().unwrap();
        assert_eq!(entries.len(), 6, "the GPS observation's entry is removed whole");
        let result = resource(&out, "DiagnosticReport")["result"].as_array().unwrap();
        assert_eq!(result.len(), 1, "and the report no longer points at it");
        assert_eq!(result[0]["reference"], json!(format!("urn:uuid:{}", pseudo_id(&salts.for_column(ID_COLUMN), OBS_HB))));
        let row = &census["Observation[code=gps_latitude]"];
        assert_eq!(row.action, "drop_resource");
        assert_eq!(row.matched_by, "code:gps_*");
    }

    /// One salt per column: equal values in one column share a token across
    /// every bundle, while different columns cannot be joined on their tokens.
    #[test]
    fn each_column_hashes_under_its_own_salt_shared_across_bundles() {
        let mut salts = Salts::default();
        let (a, _) = anon_in(&cfg(), &bundle(), &mut salts);
        let (b, _) = anon_in(&cfg(), &bundle(), &mut salts);
        let claim_a = resource(&a, "Claim");
        let token = claim_a["identifier"][0]["value"].as_str().unwrap();
        assert_eq!(token.len(), 64, "SHA-256 hex, as tabular hashing_with_salt");
        assert_eq!(resource(&b, "Claim")["identifier"][0]["value"], json!(token), "same column, same value, same token");
        let canonical = hash_canonical("BOCW/BR/2025/R2/1010708053", &[]);
        let salt = salts.for_column("Claim.identifier[].value");
        assert_eq!(token, hash_hex(&format!("{salt}{canonical}")));
        assert_ne!(claim_a["meta"]["source"], json!(token), "meta.source is another column, so another salt");
        assert_eq!(salts.by_column.len(), 3, "claim id, meta.source and resource ids: {:?}", salts.by_column.keys());
    }

    #[test]
    fn output_is_named_after_the_input_file() {
        for (input, want) in [
            ("BOCW_BR_2025_R2_1010708053.fhir.json", "BOCW_BR_2025_R2_1010708053_anonymised.fhir.json"),
            ("case (1).json", "case (1)_anonymised.fhir.json"),
            ("bundle", "bundle_anonymised.fhir.json"),
        ] {
            assert_eq!(output_name(Path::new(input)), want);
        }
    }

    #[test]
    fn the_sweep_catches_copies_no_path_rule_named() {
        let (out, census) = anon();
        let cats: Vec<&str> = resource(&out, "DocumentReference")["category"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["text"].as_str().unwrap())
            .collect();
        assert_eq!(cats, vec!["In Treatment Photo with Doctor PMAM"], "the category naming the patient is removed");
        let row = &census["DocumentReference.category[].text"];
        assert_eq!(row.matched_by, "propagated:Patient.name[].text");
        assert!(row.example.is_empty() || row.example == "In Treatment Photo with Doctor PMAM");
    }

    #[test]
    fn needles_match_respelled_and_reformatted_copies() {
        let mut n = Needles::default();
        n.add("KAILA SHI DEVI", "Patient.name[].text", 6);
        n.add("BOCW/BR/2025/R2/1010708053", "Claim.identifier[].value", 6);
        assert!(n.hit(".../attachment/kailashi%20devi.pdf").is_some(), "respelled name in a URL");
        assert!(n.hit("urn:layerkg:BOCW_BR_2025_R2_1010708053").is_some(), "other separators");
        assert!(n.hit("provider/4667/5887/1010708053/forms").is_some(), "case number alone");
        assert!(n.hit("Complete blood count").is_none());
        assert!(n.hit("devices").is_none(), "words match whole, not as substrings");
    }

    #[test]
    fn output_stays_valid_fhir_shaped() {
        let (out, _) = anon();
        let obs = resource(&out, "Observation");
        assert!(obs.get("text").is_none(), "a narrative stripped of its div is removed");
        assert!(obs.get("identifier").is_none(), "an identifier array left empty is removed");
        assert_eq!(obs["performer"][0]["extension"][0]["url"], json!(DATA_ABSENT_REASON), "data-absent-reason survives");
        assert!(obs["performer"][0].get("display").is_none());
        assert_eq!(resource(&out, "Claim")["_status"], dar());
        let text = serde_json::to_string(&out).unwrap();
        assert!(!text.contains("{}") && !text.contains("[]") && !text.contains("null"));
    }

    #[test]
    fn a_suppressed_primitive_takes_its_extension_sibling() {
        let mut b = bundle();
        b["entry"][0]["resource"]["name"] = json!([{"text": "X Y"}]);
        b["entry"][0]["resource"]["_gender"] = json!({"extension": [{"url": "http://example.org/original-text", "valueString": "purush"}]});
        let mut c = cfg();
        c.rules.retain(|r| r.pattern != "Patient.gender");
        let (out, _) = anon_with(&c, &b);
        let p = resource(&out, "Patient");
        assert!(p.get("gender").is_none() && p.get("_gender").is_none());
    }

    #[test]
    fn code_hash_rules_pseudonymise_the_observation_value() {
        let mut b = bundle();
        b["entry"].as_array_mut().unwrap().push(entry(json!({"resourceType": "Observation", "id": "u1", "status": "final",
            "code": {"text": "patient uhid"}, "valueString": "90026049"})));
        let mut c = cfg();
        c.rules.push(Rule::new("Observation.valueString", Action::Keep));
        c.code_rules.push(Rule::new("*uhid*", Action::Hash));
        let mut salts = Salts::default();
        let (out, _) = anon_in(&c, &b, &mut salts);
        let obs = out["entry"].as_array().unwrap().iter().map(|e| &e["resource"]).find(|r| r["code"]["text"] == "patient uhid").unwrap();
        let salt = salts.for_column("code:*uhid*");
        assert_eq!(obs["valueString"], json!(hash_hex(&format!("{salt}90026049"))));
    }

    /// FHIR dates are fixed-position ISO 8601, so the tabular masker's
    /// `characters_to_mask` blanks exactly the day and the time.
    #[test]
    fn dates_are_masked_to_the_month_by_position() {
        let c = parse_fhir_bundle(&json!({
            "fhir_bundle": true,
            "input_path": "x",
            "keep": ["Bundle.type"],
            "masking": [{"column": "**.period.start", "masking_char": "*",
                         "apply_order": ["characters"], "characters_to_mask": [9, 10, 12, 13, 15, 16, 18, 19]}]
        }))
        .unwrap();
        let b = json!({"resourceType": "Bundle", "type": "collection", "entry": [entry(json!({
            "resourceType": "Encounter", "id": "e1", "period": {"start": "2025-04-21T10:30:00+05:30"}}))]});
        let (out, census) = anon_with(&c, &b);
        assert_eq!(resource(&out, "Encounter")["period"]["start"], json!("2025-04-**T**:**:**+05:30"));
        assert_eq!(census["Encounter.period.start"].action, "masking");
    }

    #[test]
    fn unknown_paths_are_suppressed_by_default() {
        let mut b = bundle();
        b["entry"][0]["resource"]["maritalStatus"] = json!({"text": "Married"});
        b["entry"][0]["resource"]["extension"] = json!([{"url": "http://example.org/religion", "valueString": "X"}]);
        let (out, census) = anon_with(&cfg(), &b);
        let p = resource(&out, "Patient");
        assert!(p.get("maritalStatus").is_none() && p.get("extension").is_none());
        assert_eq!(census["Patient.maritalStatus.text"].matched_by, "<default>");
    }

    #[test]
    fn code_normalisation_matches_the_technique_list_spelling() {
        assert_eq!(normalise_code("Dialysis run-data  Venous Pressure"), "dialysis_run_data_venous_pressure");
        assert_eq!(normalise_code("post-operative_note_rest_day"), "post_operative_note_rest_day");
        assert_eq!(normalise_code("*_Latitude*"), "*_latitude*");
    }

    #[test]
    fn references_are_remapped_or_dropped() {
        assert_eq!(remap_reference(SALT, "#c1").as_deref(), Some("#c1"));
        assert_eq!(remap_reference(SALT, "Patient/p1"), Some(format!("Patient/{}", pseudo_id(SALT, "p1"))));
        assert_eq!(remap_reference(SALT, "https://hospital.example/Patient/123"), None);
    }

    // ── Config & run ────────────────────────────────────────────────────────

    #[test]
    fn config_parses_code_rules_and_blocks() {
        let c = parse_fhir_bundle(&json!({
            "fhir_bundle": true,
            "input_path": "data/fhir",
            "keep": ["Patient.gender"],
            "hashing_with_salt": ["Claim.identifier[].value"],
            "code_rules": {"suppress": ["GPS Latitude", "http://loinc.org|42130-5"], "free_text": ["nurse_remarks"]},
            "propagation": {"from": ["Patient.name.**"], "min_length": 5},
            "hash_strip_prefixes": ["urn:layerkg:"]
        }))
        .unwrap();
        assert_eq!(c.code_rules.len(), 2);
        assert!(
            c.code_rules.iter().any(|r| r.pattern == "gps_latitude" && r.action == Action::Suppress),
            "code patterns are normalised to the technique-list spelling"
        );
        assert_eq!(c.coding_rules, vec![("http://loinc.org|42130-5".to_string(), Action::Suppress)]);
        assert_eq!(c.propagation_min_length, 5);
        let seg: Vec<String> = ["patient", "gender"].iter().map(|s| s.to_string()).collect();
        assert_eq!(decide_in(&c.rules, &c.default_action, &seg).0, &Action::Keep);
    }

    #[test]
    fn config_rejects_bad_input() {
        for (v, want) in [
            (json!({"fhir_bundle": true, "keep": ["a"]}), "input_path"),
            (json!({"fhir_bundle": true, "input_path": "x"}), "suppress every field"),
            (json!({"fhir_bundle": true, "input_path": "x", "keep": ["a"], "code_rules": {"shred": ["b"]}}), "shred"),
            (
                json!({"fhir_bundle": true, "input_path": "x", "keep": ["a"], "qi_constraints": {"**.date": {"precision": "month"}}}),
                "characters_to_mask",
            ),
        ] {
            let err = parse_fhir_bundle(&v).unwrap_err();
            assert!(format!("{err:?}").contains(want), "expected {want} in {err:?}");
        }
        assert!(!parse_fhir_bundle(&json!({"keep": []})).unwrap().enabled);
    }

    /// The shipped NHA policy, resolved against the decisions that matter. A
    /// refresh of the technique sheets regenerates most of that file, so this
    /// is what catches a regeneration that quietly changes one of them.
    #[test]
    fn shipped_nha_config_resolves_the_load_bearing_paths() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/nha_fhir.json");
        let root: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        let c = parse_fhir_bundle(&root[root["data_type"].as_str().unwrap()]).unwrap();
        let seg = |p: &str| -> Vec<String> {
            p.replace("[]", ".[]").split('.').map(|s| s.to_ascii_lowercase()).collect()
        };
        for (p, want) in [
            ("Claim.identifier[].value", Action::Hash),
            ("Observation.meta.source", Action::Hash),
            ("Patient.identifier[].value", Action::Hash),
            ("Patient.name[].text", Action::Suppress),
            ("Organization.name", Action::Suppress),
            ("DocumentReference.content[].attachment.url", Action::Suppress),
            ("Observation.text.div", Action::Suppress),
            ("Observation.subject.display", Action::Suppress),
            ("Observation.identifier[].value", Action::Suppress),
            ("Observation.code.coding[].display", Action::Keep),
            ("Observation.valueQuantity.value", Action::Keep),
            ("Patient.gender", Action::Keep),
            ("DiagnosticReport.conclusion", Action::FreeText),
            ("Patient.maritalStatus.text", Action::Suppress),
            ("Patient.birthDate", Action::Suppress),
        ] {
            assert_eq!(decide_in(&c.rules, &c.default_action, &seg(p)).0, &want, "{p}");
        }
        for p in [
            "Encounter.period.start",
            "Observation.effectiveDateTime",
            "Procedure.performedPeriod.end",
            "Condition.recordedDate",
            "Claim.created",
            "Bundle.timestamp",
        ] {
            let got = decide_in(&c.rules, &c.default_action, &seg(p)).0;
            assert!(matches!(got, Action::Masking { .. }), "{p} should be masked, got {got:?}");
        }
        let obs = |text: &str| json!({"resourceType": "Observation", "code": {"text": text}});
        for (text, want) in [
            ("gps latitude", Some(Action::Suppress)),
            ("patient mobile number", Some(Action::Suppress)),
            ("case_id", Some(Action::Hash)),
            ("aadhaar_number", Some(Action::Hash)),
            ("nurse remarks", Some(Action::FreeText)),
            ("haemoglobin", None),
            ("blood bank", None),
        ] {
            let got = code_decision(&c, obs(text).as_object().unwrap()).map(|(a, _)| a.clone());
            assert_eq!(got, want, "{text}");
        }
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("skald_fhir_{tag}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn run_writes_pseudonymous_files_and_a_census() {
        let root = tmpdir("run");
        let input = root.join("in");
        fs::create_dir_all(&input).unwrap();
        fs::write(input.join("BOCW_BR_2025_R2_1010708053.fhir.json"), serde_json::to_string(&bundle()).unwrap()).unwrap();
        fs::write(input.join("not_a_bundle.json"), r#"{"resourceType": "Patient"}"#).unwrap();
        fs::write(input.join("broken.json"), "{nope").unwrap();
        let c = FhirBundleConfig {
            input_path: Some(PathBuf::from("in")),
            output_subdir: "out".into(),
            key_material_dir: PathBuf::from("."),
            ..cfg()
        };
        let report = run(&c, &root).unwrap();
        assert_eq!(report.files_written, 1);
        assert_eq!(report.files_skipped.len(), 2);
        assert_eq!(report.resources_dropped, 1);
        assert!(report.propagated >= 1);
        let names: Vec<String> = fs::read_dir(root.join("out")).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        assert!(names.contains(&"fhir_bundle_census.csv".to_string()));
        assert!(names.contains(&"BOCW_BR_2025_R2_1010708053_anonymised.fhir.json".to_string()), "{names:?}");
        assert!(root.join(SALT_FILE).is_file());
    }

    /// A folder is one corpus: every file shares the column salts, and the
    /// salts persist across runs.
    #[test]
    fn a_folder_shares_column_salts_across_files_and_runs() {
        let root = tmpdir("folder");
        let input = root.join("in");
        fs::create_dir_all(&input).unwrap();
        fs::write(input.join("BOCW_BR_2025_R2_1010708053.fhir.json"), serde_json::to_string(&bundle()).unwrap()).unwrap();
        fs::write(input.join("BOCW_BR_2025_R2_1010708053 (1).fhir.json"), serde_json::to_string(&bundle()).unwrap()).unwrap();
        let c = FhirBundleConfig {
            input_path: Some(PathBuf::from("in")),
            output_subdir: "out".into(),
            key_material_dir: PathBuf::from("keys"),
            ..cfg()
        };
        let listing = || -> Vec<String> {
            let mut v: Vec<String> = fs::read_dir(root.join("keys/out"))
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .filter(|n| n.ends_with(".fhir.json"))
                .collect();
            v.sort();
            v
        };

        let first = run(&c, &root).unwrap();
        assert_eq!(first.files_written, 2);
        assert_eq!(first.salts_created, 3);
        let names = listing();
        assert_eq!(
            names,
            vec![
                "BOCW_BR_2025_R2_1010708053 (1)_anonymised.fhir.json".to_string(),
                "BOCW_BR_2025_R2_1010708053_anonymised.fhir.json".to_string(),
            ],
            "each input keeps its own name, so a duplicate export is not overwritten"
        );
        let a: Value = serde_json::from_str(&fs::read_to_string(root.join("keys/out").join(&names[0])).unwrap()).unwrap();
        let b: Value = serde_json::from_str(&fs::read_to_string(root.join("keys/out").join(&names[1])).unwrap()).unwrap();
        assert_eq!(resource(&a, "Claim")["identifier"], resource(&b, "Claim")["identifier"], "one salt per column across files");
        assert_eq!(resource(&a, "Patient")["id"], resource(&b, "Patient")["id"]);

        let second = run(&c, &root).unwrap();
        assert_eq!(second.salts_created, 0, "a rerun reuses the persisted salts");
        assert_eq!(listing(), names, "so it produces the same pseudonyms");
    }

    #[test]
    fn dry_run_writes_no_bundles() {
        let root = tmpdir("dry");
        fs::write(root.join("a.fhir.json"), serde_json::to_string(&bundle()).unwrap()).unwrap();
        let c = FhirBundleConfig {
            input_path: Some(PathBuf::from("a.fhir.json")),
            output_subdir: "out".into(),
            key_material_dir: PathBuf::from("."),
            dry_run: true,
            ..cfg()
        };
        let report = run(&c, &root).unwrap();
        assert_eq!((report.documents_examined, report.files_written), (1, 0));
        let names: Vec<String> = fs::read_dir(root.join("out")).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        assert_eq!(names, vec!["fhir_bundle_census.csv".to_string()]);
    }
}
