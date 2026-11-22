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

use crate::pipeline::bootstrap::{PipelineError, io_err, validation};
use crate::pipeline::nested_json::{
    Action, Census, Predicate, Resolver, Rule, apply_action, decide_at, decide_in, display_path, json_files,
    parse_action, parse_policy_rules, privacy_rank, wildcard_match, write_census,
};
use crate::pipeline::preprocess::crypto::{generate_random_salt_hex, hash_key, keyed_hash, write_secret_file};
use crate::pipeline::preprocess::masking::{MaskingConfigLite, parse_masking_config};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

/// The data-absent-reason extension. An element carrying only this says "the
/// source did not have it" and holds no data, so it is always kept.
const DATA_ABSENT_REASON: &str = "http://hl7.org/fhir/StructureDefinition/data-absent-reason";

/// Per-column salt file for this flow, beside the run's other key material.
const SALT_FILE: &str = "fhir_bundle_salts.json";

/// The salt column resource ids are pseudonymised under.
const ID_COLUMN: &str = "<resource id>";

/// The salt column pseudonymous output file names are keyed under.
const OUTPUT_NAME_COLUMN: &str = "<output name>";

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
    /// Path masking specs, then the `code_rules` masking specs.
    pub(crate) masking: Vec<MaskingConfigLite>,
    /// Section key `code_rules`: code lists, each scoped to resource types.
    pub code_scopes: Vec<CodeScope>,
    /// Section key `drop_resources`: resources removed whole, with every
    /// reference to them.
    pub drop_resources: Vec<ResourceSelector>,
    /// Section key `output_names`.
    pub output_names: OutputNames,
    /// Section key `propagation.from`: paths whose values become needles.
    pub propagate_from: Vec<Rule>,
    pub propagation_enabled: bool,
    /// Needles shorter than this (after compaction) are ignored.
    pub propagation_min_length: usize,
    /// Section key `hash_strip_prefixes`. Stripped before hashing so
    /// `urn:example:CASE_ST_…` and `CASE/ST/…` pseudonymise to the same token.
    pub hash_strip_prefixes: Vec<String>,
    pub dry_run: bool,
    pub key_material_dir: PathBuf,
    /// Root the anonymized bundles go under — the run's output directory,
    /// never the key material directory.
    pub output_root: PathBuf,
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
            code_scopes: Vec::new(),
            drop_resources: Vec::new(),
            output_names: OutputNames::Input,
            propagate_from: Vec::new(),
            propagation_enabled: true,
            propagation_min_length: 6,
            hash_strip_prefixes: Vec::new(),
            dry_run: false,
            key_material_dir: PathBuf::from("keys"),
            output_root: PathBuf::from("output"),
        }
    }
}

impl FhirBundleConfig {
    /// Code rules across every scope, for the log.
    pub fn code_rule_count(&self) -> usize {
        self.code_scopes.iter().map(|s| s.rules.len() + s.codings.len()).sum()
    }
}

/// How output files are named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputNames {
    /// `<input stem>_anonymised.fhir.json`. NHA stems are case ids, so the
    /// released file names identify the case.
    Input,
    /// `<hmac>_anonymised.fhir.json`: the first 32 hex characters of
    /// HMAC-SHA256 of the input stem under the `<output name>` salt in
    /// `fhir_bundle_salts.json`. Whoever holds the salt can map an input to
    /// its output; the released folder alone cannot.
    Pseudonym,
}

/// One block of `code_rules`: code lists and the resource types whose `code`
/// they are read against.
#[derive(Debug, Clone)]
pub struct CodeScope {
    /// Resource types, as written (`Observation`, `Condition`, …).
    pub resources: Vec<String>,
    /// Single-segment globs over the normalised `code.text` and
    /// `code.coding[].display`.
    pub rules: Vec<Rule>,
    /// Entries written as `system|code`, lowercased, matched exactly.
    pub codings: Vec<(String, Action)>,
}

impl CodeScope {
    fn applies_to(&self, rt: &str) -> bool {
        self.resources.iter().any(|r| r == rt)
    }
}

/// A `drop_resources` entry: `Type`, `Type[predicate]`, or a type glob such
/// as `*[meta.security="…|GDIS"]`. The predicate is tested against the
/// resource itself, with the syntax of a path-rule predicate.
#[derive(Debug, Clone)]
pub struct ResourceSelector {
    /// The entry as written, for the census.
    pub text: String,
    /// Lowercased type glob.
    type_glob: String,
    predicate: Option<Predicate>,
}

impl ResourceSelector {
    fn parse(text: &str) -> Result<ResourceSelector, PipelineError> {
        let bad =
            |why: &str| validation("CONFIG_INVALID_VALUE", "Malformed drop_resources entry", &format!("{text}: {why}"));
        let trimmed = text.trim();
        let (ty, rest) = match trimmed.find('[') {
            Some(i) => (&trimmed[..i], Some(&trimmed[i..])),
            None => (trimmed, None),
        };
        if ty.is_empty() || !ty.chars().all(|c| c.is_ascii_alphanumeric() || c == '*') {
            return Err(bad("must start with a resource type (letters, or * as a wildcard)"));
        }
        if ty.eq_ignore_ascii_case("bundle") {
            return Err(bad("the Bundle itself cannot be dropped"));
        }
        let predicate = match rest {
            None => None,
            Some(r) => {
                let body = r
                    .strip_prefix('[')
                    .and_then(|r| r.strip_suffix(']'))
                    .ok_or_else(|| bad("a selector is Type or Type[predicate], with nothing after the closing ']'"))?;
                if body.trim().is_empty() {
                    return Err(bad("empty predicate"));
                }
                Some(Predicate::parse(body).map_err(|why| bad(&why))?)
            }
        };
        Ok(ResourceSelector { text: trimmed.to_string(), type_glob: ty.to_ascii_lowercase(), predicate })
    }

    fn matches(&self, rt: &str, res: &Map<String, Value>, resolve: Option<Resolver>) -> bool {
        wildcard_match(&self.type_glob, &rt.to_ascii_lowercase())
            && self.predicate.as_ref().is_none_or(|p| p.matches_map(res, resolve))
    }
}

/// Reads the FHIR bundle policy off a config section. Technique buckets are
/// read by the same parser as `nested_json`, with FHIR paths as the patterns.
pub fn parse_fhir_bundle(section: &Value) -> Result<FhirBundleConfig, PipelineError> {
    let mut cfg = FhirBundleConfig {
        enabled: section.get("fhir_bundle").and_then(Value::as_bool).unwrap_or(false),
        ..FhirBundleConfig::default()
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
    // Bundles are walked without a token vault or key store, so a reversible
    // technique here would have nowhere to keep its mapping. Refuse it rather
    // than let the rule fall through to suppression unannounced.
    if let Some(rule) = rules.iter().find(|r| matches!(r.action, Action::Tokenize { .. } | Action::Encrypt { .. })) {
        return Err(validation(
            "CONFIG_INVALID_VALUE",
            "tokenization and encrypt are not supported by fhir_bundle",
            &format!("{}: use hashing_with_salt for a stable pseudonym", rule.pattern),
        ));
    }
    cfg.rules = rules;
    cfg.masking = specs.masking;

    if let Some(block) = section.get("code_rules") {
        let blocks: Vec<&Value> = match block {
            Value::Array(a) => a.iter().collect(),
            other => vec![other],
        };
        for b in blocks {
            let scope = parse_code_block(b, &mut cfg.masking)?;
            cfg.code_scopes.push(scope);
        }
    }

    if let Some(list) = section.get("drop_resources") {
        for entry in str_list(list, "drop_resources")? {
            cfg.drop_resources.push(ResourceSelector::parse(&entry)?);
        }
    }

    if let Some(v) = section.get("output_names") {
        cfg.output_names = match v.as_str() {
            Some("input") => OutputNames::Input,
            Some("pseudonym") => OutputNames::Pseudonym,
            _ => {
                return Err(validation(
                    "CONFIG_INVALID_VALUE",
                    "Invalid output_names",
                    &format!("{v} — must be \"input\" or \"pseudonym\""),
                ));
            }
        };
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
                cfg.propagate_from.push(Rule::try_new(&p, Action::Suppress)?);
            }
        }
    }

    if let Some(list) = section.get("hash_strip_prefixes") {
        cfg.hash_strip_prefixes =
            str_list(list, "hash_strip_prefixes")?.into_iter().map(|p| p.to_ascii_lowercase()).collect();
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

/// Reads one `code_rules` block: technique lists of code globs or
/// `system|code` entries, `masking` entries keyed by `code`, and the
/// `resources` the block applies to (default `["Observation"]`).
fn parse_code_block(block: &Value, masking: &mut Vec<MaskingConfigLite>) -> Result<CodeScope, PipelineError> {
    let invalid = |msg: &str, detail: &str| validation("CONFIG_INVALID_VALUE", msg, detail);
    let obj = block.as_object().ok_or_else(|| {
        invalid("code_rules must be an object of technique lists, or a list of them", &block.to_string())
    })?;
    let mut scope = CodeScope { resources: vec!["Observation".to_string()], rules: Vec::new(), codings: Vec::new() };
    if let Some(list) = obj.get("resources") {
        scope.resources = str_list(list, "code_rules.resources")?.into_iter().map(|r| r.trim().to_string()).collect();
        if scope.resources.is_empty() {
            return Err(invalid("code_rules.resources is empty", "list the resource types the codes apply to"));
        }
        if let Some(bad) = scope.resources.iter().find(|r| {
            r.eq_ignore_ascii_case("bundle")
                || !r.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                || !r.chars().all(|c| c.is_ascii_alphanumeric())
        }) {
            return Err(invalid("code_rules.resources entries must be resource type names", bad));
        }
    }
    let observation_only = scope.resources.iter().all(|r| r == "Observation");
    let push = |scope: &mut CodeScope, entry: &str, action: Action| {
        if entry.contains('|') {
            scope.codings.push((entry.trim().to_ascii_lowercase(), action));
        } else {
            scope.rules.push(Rule::new(&normalise_code(entry), action));
        }
    };
    for (key, list) in obj {
        let action = match key.as_str() {
            "resources" => continue,
            "keep" => Action::Keep,
            "suppress" => Action::Suppress,
            "hashing_with_salt" => Action::Hash,
            "free_text" => Action::FreeText,
            "masking" => {
                let entries = list
                    .as_array()
                    .ok_or_else(|| invalid("code_rules.masking must be an array of objects", &list.to_string()))?;
                if !observation_only && !entries.is_empty() {
                    return Err(invalid(
                        "code_rules.masking acts on an Observation's value[x]",
                        "put it in a block whose resources are [\"Observation\"] only",
                    ));
                }
                for e in entries {
                    let mut entry = e
                        .as_object()
                        .cloned()
                        .ok_or_else(|| invalid("code_rules.masking entries must be objects", &e.to_string()))?;
                    if entry.contains_key("column") {
                        return Err(invalid(
                            "code_rules.masking entries name a 'code', not a 'column'",
                            &e.to_string(),
                        ));
                    }
                    let code = entry
                        .remove("code")
                        .and_then(|c| c.as_str().map(str::to_string))
                        .filter(|c| !c.trim().is_empty())
                        .ok_or_else(|| invalid("code_rules.masking entries need a non-empty 'code'", &e.to_string()))?;
                    entry.insert("column".into(), Value::String(format!("code:{code}")));
                    let spec = parse_masking_config(&Value::Object(entry))?;
                    let action = Action::Masking { spec: masking.len() };
                    masking.push(spec);
                    push(&mut scope, &code, action);
                }
                continue;
            }
            other => {
                return Err(invalid(
                    "Unknown code_rules technique",
                    &format!("'{other}' — must be keep, suppress, hashing_with_salt, free_text, masking or resources"),
                ));
            }
        };
        let entries = str_list(list, &format!("code_rules.{key}"))?;
        if !observation_only && matches!(action, Action::Hash | Action::FreeText) && !entries.is_empty() {
            return Err(invalid(
                &format!("code_rules.{key} acts on an Observation's value[x]"),
                "put it in a block whose resources are [\"Observation\"] only; other resources take keep and suppress",
            ));
        }
        for entry in entries {
            push(&mut scope, &entry, action.clone());
        }
    }
    Ok(scope)
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
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(b);
            i += 3;
            continue;
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

/// A keyed, UUID-shaped pseudonym for a resource id: HMAC-SHA256 of
/// `fhir-id\0` + id under the id column's key. Deterministic under the key, so
/// references can be rewritten without a lookup table and the same source
/// resource keeps one id across runs.
fn pseudo_id(key: &[u8; 32], id: &str) -> String {
    let x = keyed_hash(key, &[b"fhir-id\0".as_slice(), id.as_bytes()].concat());
    let variant = ['8', '9', 'a', 'b'][usize::from_str_radix(&x[16..17], 16).unwrap_or(0) % 4];
    format!("{}-{}-5{}-{}{}-{}", &x[0..8], &x[8..12], &x[13..16], variant, &x[17..20], &x[20..32])
}

/// One salt per column, shared by every bundle in the run and persisted with
/// the run's key material — the same scheme as tabular `hashing_with_salt`
/// (a random 32-byte salt per column, the HMAC-SHA256 key), except that
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
    /// Decoded salts: each column's HMAC key. Stored as 64 hex chars.
    by_column: BTreeMap<String, [u8; 32]>,
    created: usize,
}

impl Salts {
    /// The key for `column`, generated on first use.
    pub fn for_column(&mut self, column: &str) -> [u8; 32] {
        if let Some(k) = self.by_column.get(column) {
            return *k;
        }
        // The OS RNG is checked when the run starts, so this cannot fail later,
        // and a fresh salt is always 64 hex chars.
        let key = generate_random_salt_hex().and_then(|s| hash_key(&s, column)).expect("OS RNG checked at startup");
        self.by_column.insert(column.to_string(), key);
        self.created += 1;
        key
    }

    fn load(path: &Path) -> Result<Salts, PipelineError> {
        if !path.is_file() {
            return Ok(Salts::default());
        }
        let raw =
            fs::read_to_string(path).map_err(|e| io_err("read fhir_bundle salts", &path.display().to_string(), e))?;
        let v: Value = serde_json::from_str(&raw)?;
        let obj = v.as_object().ok_or_else(|| {
            validation(
                "CONFIG_INVALID_VALUE",
                "fhir_bundle salt file must map column to salt",
                &path.display().to_string(),
            )
        })?;
        let mut by_column = BTreeMap::new();
        for (col, salt) in obj {
            let salt = salt
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| validation("CONFIG_INVALID_VALUE", "fhir_bundle salt file holds an empty salt", col))?;
            by_column.insert(col.clone(), hash_key(salt, &format!("{}: {col}", path.display()))?);
        }
        Ok(Salts { by_column, created: 0 })
    }

    fn save(&self, path: &Path) -> Result<(), PipelineError> {
        let hex: BTreeMap<&String, String> = self.by_column.iter().map(|(c, k)| (c, hex::encode(k))).collect();
        let body = serde_json::to_string_pretty(&hex)?;
        write_secret_file(path, body.as_bytes())
    }

    /// Keyed hash of a value, as tabular `hashing_with_salt` computes it.
    fn hash(&mut self, column: &str, value: &str) -> String {
        keyed_hash(&self.for_column(column), value.as_bytes())
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
fn remap_reference(key: &[u8; 32], r: &str) -> Option<String> {
    if r.starts_with('#') {
        return Some(r.to_string());
    }
    if let Some(id) = r.strip_prefix("urn:uuid:") {
        return Some(format!("urn:uuid:{}", pseudo_id(key, id)));
    }
    let id = reference_target(r)?;
    let ty = r.split('/').next()?;
    Some(format!("{ty}/{}", pseudo_id(key, id)))
}

// ── Propagation needles ──────────────────────────────────────────────────────

/// Words that say nothing about who a value names. A name token is only a
/// needle if it is not one of these, so a suppressed hospital name does not
/// take every leaf containing "hospital" with it.
const STOPWORDS: &[&str] = &[
    "shri",
    "smt",
    "kumari",
    "baby",
    "master",
    "late",
    "name",
    "unknown",
    "illegible",
    "patient",
    "hospital",
    "hospitals",
    "medical",
    "college",
    "centre",
    "center",
    "research",
    "private",
    "limited",
    "government",
    "india",
    "general",
    "institute",
    "institution",
    "multispeciality",
    "multispecialty",
    "speciality",
    "specialty",
    "super",
    "heart",
    "care",
    "clinic",
    "health",
    "nursing",
    "home",
    "trust",
    "memorial",
    "district",
    "state",
    "city",
    "road",
    "nagar",
    "main",
    "near",
    "opposite",
    "post",
    "village",
    "ward",
    "block",
    "sciences",
    "science",
    "national",
    "authority",
    "scheme",
    "diagnostic",
    "diagnostics",
    "laboratory",
    "pathology",
    "eye",
    "kidney",
    "cancer",
    "children",
    "mother",
    "child",
    "womens",
    "women",
    "with",
    "from",
    "and",
    "the",
];

/// Values read from identifying paths in one bundle, in the forms they turn
/// up in elsewhere. Built per bundle — a needle is only meaningful inside the
/// patient's own record.
///
/// Three kinds, because the copies are never exact:
/// - **compact**: the whole value with separators stripped —
///   `TESTCASE/ST/2025/R0/1000000017` inside `TESTCASE_ST_2025_R0_1000000017`;
/// - **digit runs** of 6+ digits — the case number alone in a URL path;
/// - **name words** of 4+ letters from values holding no digits —
///   `Patient.name` "MALA TI KUMARI" against the filename "malati kumari.pdf",
///   where only the word "kumari" survives the respelling.
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

/// A leaf's position: its match path, display path and the array elements
/// along it (for predicates).
struct LeafAt<'p, 'v> {
    lpath: &'p [String],
    dpath: &'p [String],
    items: &'p [Option<&'v Value>],
}

/// Every leaf of `v` with its position, re-rooted at nested resources the
/// same way the main walk does.
fn for_each_leaf<'v>(
    v: &'v Value,
    lpath: &mut Vec<String>,
    dpath: &mut Vec<String>,
    items: &mut Vec<Option<&'v Value>>,
    f: &mut dyn FnMut(LeafAt<'_, 'v>, &'v Value),
) {
    match v {
        Value::Object(map) => {
            let mut rooted = false;
            if let Some(rt) = map.get("resourceType").and_then(Value::as_str) {
                if !lpath.is_empty() {
                    // A nested resource is handled when the outer loop reaches it.
                    return;
                }
                lpath.push(rt.to_ascii_lowercase());
                dpath.push(rt.to_string());
                items.push(None);
                rooted = true;
            }
            for (k, child) in map {
                if k == "resourceType" {
                    continue;
                }
                lpath.push(k.to_ascii_lowercase());
                dpath.push(k.clone());
                items.push(None);
                for_each_leaf(child, lpath, dpath, items, f);
                lpath.pop();
                dpath.pop();
                items.pop();
            }
            if rooted {
                lpath.pop();
                dpath.pop();
                items.pop();
            }
        }
        Value::Array(elements) => {
            for c in elements {
                lpath.push("[]".into());
                dpath.push("[]".into());
                items.push(Some(c));
                for_each_leaf(c, lpath, dpath, items, f);
                lpath.pop();
                dpath.pop();
                items.pop();
            }
        }
        leaf => f(LeafAt { lpath, dpath, items }, leaf),
    }
}

/// Resource type by id, for resolving references to `Type/id`. Built per
/// bundle from every resource's `id` and every entry's `fullUrl`.
fn reference_index(bundle: &Value) -> HashMap<String, String> {
    let mut index = HashMap::new();
    for_each_resource(bundle, &mut |res| {
        if let (Some(rt), Some(id)) =
            (res.get("resourceType").and_then(Value::as_str), res.get("id").and_then(Value::as_str))
        {
            index.insert(id.to_string(), rt.to_string());
        }
    });
    for e in bundle.get("entry").and_then(Value::as_array).into_iter().flatten() {
        if let (Some(full), Some(rt)) = (
            e.get("fullUrl").and_then(Value::as_str).and_then(reference_target),
            e.get("resource").and_then(|r| r.get("resourceType")).and_then(Value::as_str),
        ) {
            index.entry(full.to_string()).or_insert_with(|| rt.to_string());
        }
    }
    index
}

/// `Type/id` for a reference the bundle can resolve.
fn resolve_in(index: &HashMap<String, String>, r: &str) -> Option<String> {
    let id = reference_target(r)?;
    index.get(id).map(|rt| format!("{rt}/{id}"))
}

/// The codes a resource is known by, for the code-keyed rules: the
/// normalised `code.text` and each `coding[].display`, plus `system|code`.
fn resource_codes(res: &Map<String, Value>) -> (Vec<String>, Vec<String>) {
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
            if let (Some(s), Some(k)) = (c.get("system").and_then(Value::as_str), c.get("code").and_then(Value::as_str))
            {
                codings.push(format!("{s}|{k}").to_ascii_lowercase());
            }
        }
    }
    texts.retain(|t| !t.is_empty());
    (texts, codings)
}

/// The code rule that governs a resource: across every `code_rules` block
/// scoped to its type, the narrowest matching text glob or an exact coding,
/// the more protective one winning when several match — a code that is
/// suppressed under any of its names is suppressed.
fn code_decision<'a>(cfg: &'a FhirBundleConfig, rt: &str, res: &Map<String, Value>) -> Option<(&'a Action, String)> {
    let scopes: Vec<&CodeScope> = cfg.code_scopes.iter().filter(|s| s.applies_to(rt)).collect();
    if scopes.is_empty() {
        return None;
    }
    let (texts, codings) = resource_codes(res);
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
    for scope in scopes {
        for t in &texts {
            let seg = [t.clone()];
            let (action, by) = decide_in(&scope.rules, &Action::Keep, &seg);
            if by != "<default>" {
                consider(action, format!("code:{by}"));
            }
        }
        for c in &codings {
            if let Some((_, action)) = scope.codings.iter().find(|(k, _)| k == c) {
                consider(action, format!("coding:{c}"));
            }
        }
    }
    best
}

// ── Walk ─────────────────────────────────────────────────────────────────────

struct Walker<'a> {
    cfg: &'a FhirBundleConfig,
    salts: &'a mut Salts,
    /// The `<resource id>` column's key, looked up once per bundle.
    id_key: [u8; 32],
    census: &'a mut Census,
    /// Original ids of resources a code rule or `drop_resources` dropped.
    dropped: HashSet<String>,
    /// The dropped resources themselves, so one without an id goes too.
    dropped_at: HashSet<*const Map<String, Value>>,
    needles: Needles,
    /// Resource type by id, for predicates on references.
    refs: HashMap<String, String>,
    /// The code rule governing the Observation being walked, if any.
    code_override: Option<(Action, String)>,
}

/// The match path, display path and array elements of the value being
/// walked, pushed and popped together.
struct Pos<'v> {
    lpath: Vec<String>,
    dpath: Vec<String>,
    items: Vec<Option<&'v Value>>,
}

impl<'v> Pos<'v> {
    fn root(rt: &str) -> Pos<'v> {
        Pos { lpath: vec![rt.to_ascii_lowercase()], dpath: vec![rt.to_string()], items: vec![None] }
    }
    fn push_key(&mut self, k: &str) {
        self.lpath.push(k.to_ascii_lowercase());
        self.dpath.push(k.to_string());
        self.items.push(None);
    }
    fn push_item(&mut self, item: &'v Value) {
        self.lpath.push("[]".into());
        self.dpath.push("[]".into());
        self.items.push(Some(item));
    }
    fn pop(&mut self) {
        self.lpath.pop();
        self.dpath.pop();
        self.items.pop();
    }
}

impl Walker<'_> {
    fn resolve(&self, r: &str) -> Option<String> {
        resolve_in(&self.refs, r)
    }

    /// Walks one value. `None` removes it from its parent.
    fn walk<'v>(&mut self, value: &'v Value, pos: &mut Pos<'v>) -> Option<Value> {
        match value {
            Value::Object(map) => self.walk_object(map, pos),
            Value::Array(elements) => {
                let mut out = Vec::with_capacity(elements.len());
                for item in elements {
                    pos.push_item(item);
                    let kept = self.walk(item, pos);
                    pos.pop();
                    // FHIR JSON forbids nulls in arrays, and nothing indexes
                    // into these by position, so a removed element is dropped.
                    out.extend(kept);
                }
                (!out.is_empty()).then_some(Value::Array(out))
            }
            leaf => self.leaf(leaf, pos),
        }
    }

    fn walk_object<'v>(&mut self, map: &'v Map<String, Value>, pos: &mut Pos<'v>) -> Option<Value> {
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
        if let Some(target) = map.get("reference").and_then(Value::as_str).and_then(reference_target)
            && self.dropped.contains(target)
        {
            self.census.record_as(
                &display_path(&pos.dpath),
                &Value::Null,
                "drop_reference",
                "<dropped resource>",
                false,
            );
            return None;
        }

        let mut out = Map::new();
        for (k, v) in map {
            if (k == "reference" || k == "fullUrl")
                && let Some(r) = v.as_str()
            {
                pos.push_key(k);
                let shown = display_path(&pos.dpath);
                let suppressed_by = if k == "reference" { self.reference_suppressed(pos) } else { None };
                pos.pop();
                if let Some(by) = suppressed_by {
                    self.census.record_as(&shown, v, "suppress", &by, false);
                    continue;
                }
                match remap_reference(&self.id_key, r) {
                    Some(new) => {
                        self.census.record_as(&shown, v, "pseudonymise_reference", "<structural>", false);
                        out.insert(k.clone(), Value::String(new));
                    }
                    None => self.census.record_as(&shown, v, "suppress", "<unresolvable reference>", false),
                }
                continue;
            }
            pos.push_key(k);
            // An entry whose resource was dropped is dropped whole, rather than
            // left behind as a bare `fullUrl` pointing at nothing.
            let is_resource = v.get("resourceType").is_some_and(Value::is_string);
            let kept = self.walk(v, pos);
            pos.pop();
            match kept {
                Some(kept) => {
                    out.insert(k.clone(), kept);
                }
                None if is_resource => return None,
                None => {}
            }
        }
        self.tidy(map, out, &pos.lpath)
    }

    /// Whether a `reference` (its path on top of `pos`) is suppressed by an
    /// explicit rule: on the reference itself, or on the nearest ancestor an
    /// explicit rule names (`Claim.facility`, `Patient.link.**`). A reference
    /// no rule names is pseudonymised, as it always was; so is one whose
    /// nearest explicit rule is anything but `suppress`.
    fn reference_suppressed(&self, pos: &Pos) -> Option<String> {
        let resolve = |r: &str| self.resolve(r);
        for end in (2..=pos.lpath.len()).rev() {
            let (action, by) = decide_at(
                &self.cfg.rules,
                &self.cfg.default_action,
                &pos.lpath[..end],
                &pos.items[..end],
                Some(&resolve),
            );
            if by != "<default>" {
                return (*action == Action::Suppress).then(|| by.to_string());
            }
        }
        None
    }

    fn walk_resource(&mut self, rt: &str, map: &Map<String, Value>) -> Option<Value> {
        let id = map.get("id").and_then(Value::as_str);
        if self.dropped_at.contains(&(map as *const _)) || id.is_some_and(|id| self.dropped.contains(id)) {
            return None;
        }
        let saved = std::mem::take(&mut self.code_override);
        if rt == "Observation" {
            self.code_override = code_decision(self.cfg, rt, map).map(|(a, by)| (a.clone(), by));
        }

        let mut pos = Pos::root(rt);
        let mut out = Map::new();
        out.insert("resourceType".into(), Value::String(rt.to_string()));
        for (k, v) in map {
            match k.as_str() {
                "resourceType" => {}
                "id" if v.is_string() => {
                    self.census.record_as(&format!("{rt}.id"), v, "pseudonymise_id", "<structural>", false);
                    out.insert("id".into(), Value::String(pseudo_id(&self.id_key, v.as_str().unwrap_or_default())));
                }
                _ => {
                    pos.push_key(k);
                    let kept = self.walk(v, &mut pos);
                    pos.pop();
                    if let Some(kept) = kept {
                        out.insert(k.clone(), kept);
                    }
                }
            }
        }
        self.code_override = saved;
        let tidied = self.tidy(map, out, &pos.lpath)?;
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

    fn leaf(&mut self, leaf: &Value, pos: &Pos) -> Option<Value> {
        let shown = display_path(&pos.dpath);
        let (action, matched_by) = self.decide(pos, leaf);

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
            // The key argument is only read by `Hash`, handled above.
            other => apply_action(other, leaf, &self.cfg.masking, None),
        };

        // The sweep: a value released as-is must not contain an identifier
        // this same bundle suppressed or pseudonymised somewhere else.
        let released_verbatim = matches!(action, Action::Keep | Action::FreeText);
        if released_verbatim
            && self.cfg.propagation_enabled
            && let Some(text) = leaf.as_str()
            && let Some(src) = self.needles.hit(text)
        {
            let by = format!("propagated:{src}");
            self.census.record_as(&shown, leaf, "suppress", &by, false);
            return None;
        }

        self.census.record_as(&shown, leaf, &action.label(), &matched_by, matches!(action, Action::Keep));
        result
    }

    fn decide(&self, pos: &Pos, leaf: &Value) -> (Action, String) {
        if let Some((action, by)) = &self.code_override {
            // Code-keyed techniques act on the Observation's value; its code,
            // status and the rest stay under the path rules.
            let on_value = pos.lpath.get(1).is_some_and(|s| s.starts_with("value"));
            if on_value {
                match action {
                    Action::Hash => return (action.clone(), by.clone()),
                    // Masking yields text, which would turn a number or a
                    // boolean into a string FHIR rejects; those are removed.
                    Action::Masking { .. } if leaf.is_string() => return (action.clone(), by.clone()),
                    Action::Masking { .. } => return (Action::Suppress, by.clone()),
                    _ => {}
                }
            }
        }
        let resolve = |r: &str| self.resolve(r);
        let (a, by) = decide_at(&self.cfg.rules, &self.cfg.default_action, &pos.lpath, &pos.items, Some(&resolve));
        (a.clone(), by.to_string())
    }
}

/// Anonymizes one Bundle. Exposed for tests and for callers holding a parsed
/// bundle already.
pub fn anonymize_bundle(bundle: &Value, cfg: &FhirBundleConfig, salts: &mut Salts, census: &mut Census) -> Value {
    let refs = reference_index(bundle);
    let resolve = |r: &str| resolve_in(&refs, r);

    let mut dropped = HashSet::new();
    let mut dropped_at: HashSet<*const Map<String, Value>> = HashSet::new();
    for_each_resource(bundle, &mut |res| {
        let Some(rt) = res.get("resourceType").and_then(Value::as_str) else { return };
        if rt == "Bundle" {
            return;
        }
        let mut drop = |path: String, by: String| {
            census.record_as(&path, &Value::Null, "drop_resource", &by, false);
            dropped_at.insert(res as *const _);
            if let Some(id) = res.get("id").and_then(Value::as_str) {
                dropped.insert(id.to_string());
            }
        };
        if let Some(sel) = cfg.drop_resources.iter().find(|s| s.matches(rt, res, Some(&resolve))) {
            drop(rt.to_string(), format!("drop_resources:{}", sel.text));
            return;
        }
        if let Some((Action::Suppress, by)) = code_decision(cfg, rt, res) {
            let (texts, codings) = resource_codes(res);
            let code = match texts.first() {
                Some(t) => t.clone(),
                // An Observation's census row has always shown its text only.
                None if rt != "Observation" => codings.first().cloned().unwrap_or_default(),
                None => String::new(),
            };
            drop(format!("{rt}[code={code}]"), by);
        }
    });

    let mut needles = Needles::default();
    if cfg.propagation_enabled && !cfg.propagate_from.is_empty() {
        for_each_resource(bundle, &mut |res| {
            let v = Value::Object(res.clone());
            for_each_leaf(&v, &mut Vec::new(), &mut Vec::new(), &mut Vec::new(), &mut |at, leaf| {
                let text = match leaf {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    _ => return,
                };
                if cfg.propagate_from.iter().any(|r| {
                    decide_at(std::slice::from_ref(r), &Action::Keep, at.lpath, at.items, Some(&resolve)).1
                        != "<default>"
                }) {
                    needles.add(&text, &display_path(at.dpath), cfg.propagation_min_length);
                }
            });
        });
    }

    let id_key = salts.for_column(ID_COLUMN);
    let mut w = Walker { cfg, salts, id_key, census, dropped, dropped_at, needles, refs, code_override: None };
    let mut pos = Pos { lpath: Vec::new(), dpath: Vec::new(), items: Vec::new() };
    w.walk(bundle, &mut pos).unwrap_or(Value::Null)
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

/// An input's name without `.fhir.json` / `.json`.
fn input_stem(file: &Path) -> &str {
    let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("bundle");
    let lower = name.to_ascii_lowercase();
    let stem_len = [".fhir.json", ".json"]
        .iter()
        .find(|ext| lower.ends_with(*ext))
        .map(|ext| name.len() - ext.len())
        .unwrap_or(name.len());
    &name[..stem_len]
}

/// The output file name for one bundle: `<input stem>_anonymised.fhir.json`,
/// so each output sits next to the name of the input it came from.
///
/// NHA input names are case ids (`TESTCASE_ST_2025_R0_1000000017.fhir.json`), so
/// this carries the case id in clear onto the released file — traceability
/// for verification, at the cost of a released folder that identifies its
/// cases. `"output_names": "pseudonym"` ([`pseudonymous_output_name`]) avoids it.
fn output_name(file: &Path) -> String {
    format!("{}_anonymised.fhir.json", input_stem(file))
}

/// `<hmac>_anonymised.fhir.json`, the HMAC of the input stem under `key`
/// (see [`OutputNames::Pseudonym`]). The stem is hashed exactly as written, so
/// `X` and `X (1)` stay apart and one does not overwrite the other.
fn pseudonymous_output_name(key: &[u8; 32], file: &Path) -> String {
    let mac = keyed_hash(key, input_stem(file).as_bytes());
    format!("{}_anonymised.fhir.json", &mac[..32])
}

pub fn run(cfg: &FhirBundleConfig, root: &Path) -> Result<RunReport, PipelineError> {
    let resolve = |p: &Path| -> PathBuf { if p.is_absolute() { p.to_path_buf() } else { root.join(p) } };
    let input = resolve(cfg.input_path.as_ref().ok_or_else(|| {
        validation(
            "CONFIG_INVALID_VALUE",
            "fhir_bundle.input_path is not set",
            "Set it to a bundle or a directory of them",
        )
    })?);
    let output_dir = resolve(&cfg.output_root).join(&cfg.output_subdir);
    let census_path = output_dir.join("fhir_bundle_census.csv");

    let files = if input.is_dir() {
        json_files(&input)?
    } else if input.is_file() {
        vec![input.clone()]
    } else {
        return Err(validation("DATA_MISSING", "fhir_bundle.input_path does not exist", &input.display().to_string()));
    };
    if files.is_empty() {
        return Err(validation(
            "DATA_EMPTY",
            "No .json files found for fhir_bundle input",
            &input.display().to_string(),
        ));
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
        let doc: Value = match fs::read_to_string(file)
            .map_err(|e| format!("unreadable: {e}"))
            .and_then(|raw| serde_json::from_str(&raw).map_err(|e| format!("invalid JSON: {e}")))
        {
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
        let out_name = match cfg.output_names {
            OutputNames::Input => output_name(file),
            OutputNames::Pseudonym => pseudonymous_output_name(&salts.for_column(OUTPUT_NAME_COLUMN), file),
        };
        let out_path = output_dir.join(out_name);
        let text = serde_json::to_string_pretty(&anon)?;
        fs::write(&out_path, text)
            .map_err(|e| io_err("write anonymized bundle", &out_path.display().to_string(), e))?;
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

    const KEY: [u8; 32] = [7; 32];
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
        let meta = json!({"source": "urn:example:TESTCASE_ST_2025_R0_1000000017",
                          "tag": [{"system": "urn:example:origin", "code": "structure"}]});
        json!({
            "resourceType": "Bundle",
            "type": "collection",
            "entry": [
                entry(json!({"resourceType": "Patient", "id": PAT, "meta": meta, "name": [{"text": "ARJUN TESTNAME VERMA"}], "gender": "male", "birthDate": "1970-01-01"})),
                entry(json!({"resourceType": "Claim", "id": "c1", "meta": meta,
                    "identifier": [{"value": "TESTCASE/ST/2025/R0/1000000017"}],
                    "patient": {"reference": format!("urn:uuid:{PAT}")},
                    "_status": dar()})),
                entry(json!({"resourceType": "Observation", "id": OBS_HB, "meta": meta, "status": "final",
                    "identifier": [{"system": "urn:example:source-fact", "value": "aaaa1111bbbb2222cccc3333"}],
                    "code": {"text": "hemoglobin", "coding": [{"system": "http://loinc.org", "code": "718-7", "display": "Hemoglobin"}]},
                    "subject": {"reference": format!("urn:uuid:{PAT}")},
                    "valueQuantity": {"value": 9.1, "unit": "g/dL"},
                    "performer": [{"extension": [{"url": DATA_ABSENT_REASON, "valueCode": "unknown"}], "display": "Unknown performer"}],
                    "text": {"status": "generated", "div": "<div>Observation — hemoglobin; ARJUN 9.1</div>"}})),
                entry(json!({"resourceType": "Observation", "id": OBS_GPS, "meta": meta, "status": "final",
                    "code": {"text": "gps latitude", "coding": [{"system": "http://loinc.org", "code": "42130-5", "display": "Latitude"}]},
                    "subject": {"reference": format!("urn:uuid:{PAT}")},
                    "valueQuantity": {"value": 12.345678, "unit": "°"}})),
                entry(json!({"resourceType": "DiagnosticReport", "id": DR, "status": "final",
                    "code": {"text": "investigation report"},
                    "subject": {"reference": format!("urn:uuid:{PAT}")},
                    "result": [{"reference": format!("urn:uuid:{OBS_HB}")}, {"reference": format!("urn:uuid:{OBS_GPS}")}]})),
                entry(json!({"resourceType": "Organization", "id": "o1", "name": "EXAMPLE CARE HOSPITAL, TESTPUR", "alias": ["E C HOSPITAL"]})),
                entry(json!({"resourceType": "DocumentReference", "id": "d1", "status": "current",
                    "subject": {"reference": format!("urn:uuid:{PAT}")},
                    "type": {"text": "clinical notes"},
                    "category": [{"text": "In Treatment Photo with Doctor PMAM"}, {"text": "Photo of Arjun at bedside"}],
                    "content": [{"attachment": {"url": "store/provider/1111/2222/1000000017/forms/1/attachment/arjun%20testname.pdf", "title": "page 1"}}]})),
            ]
        })
    }

    fn cfg() -> FhirBundleConfig {
        let mut rules: Vec<Rule> = [
            "Bundle.type",
            "**.status",
            "**.meta.tag[].system",
            "**.meta.tag[].code",
            "**.coding[].system",
            "**.coding[].code",
            "**.coding[].display",
            "**.code.text",
            "**.type.text",
            "**.category[].text",
            "Observation.valueQuantity.*",
            "Patient.gender",
            "DocumentReference.content[].attachment.title",
        ]
        .iter()
        .map(|p| Rule::new(p, Action::Keep))
        .collect();
        for p in [
            "Patient.name.**",
            "Organization.name",
            "Organization.alias",
            "**.attachment.url",
            "**.text.div",
            "**.identifier[].value",
            "**.identifier[].system",
        ] {
            rules.push(Rule::new(p, Action::Suppress));
        }
        rules.push(Rule::new("Claim.identifier[].value", Action::Hash));
        rules.push(Rule::new("**.meta.source", Action::Hash));
        FhirBundleConfig {
            enabled: true,
            rules,
            code_scopes: vec![CodeScope {
                resources: vec!["Observation".into()],
                rules: vec![Rule::new("gps_*", Action::Suppress), Rule::new("nurse_remarks", Action::FreeText)],
                codings: Vec::new(),
            }],
            propagate_from: ["Patient.name.**", "Claim.identifier[].value", "Organization.name", "Organization.alias"]
                .iter()
                .map(|p| Rule::new(p, Action::Suppress))
                .collect(),
            hash_strip_prefixes: vec!["urn:example:".into()],
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
        for leaked in
            ["arjun", "testname", "1000000017", "testcase", "example care", "12.34", "aaaa1111", PAT, "1111/2222"]
        {
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
        assert_ne!(pseudo_id(&[8; 32], PAT), patient_id);
    }

    #[test]
    fn a_code_suppressed_observation_is_dropped_with_its_references() {
        let mut salts = Salts::default();
        let (out, census) = anon_in(&cfg(), &bundle(), &mut salts);
        let entries = out["entry"].as_array().unwrap();
        assert_eq!(entries.len(), 6, "the GPS observation's entry is removed whole");
        let result = resource(&out, "DiagnosticReport")["result"].as_array().unwrap();
        assert_eq!(result.len(), 1, "and the report no longer points at it");
        assert_eq!(
            result[0]["reference"],
            json!(format!("urn:uuid:{}", pseudo_id(&salts.for_column(ID_COLUMN), OBS_HB)))
        );
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
        assert_eq!(token.len(), 64, "HMAC-SHA256 hex, as tabular hashing_with_salt");
        assert_eq!(
            resource(&b, "Claim")["identifier"][0]["value"],
            json!(token),
            "same column, same value, same token"
        );
        let canonical = hash_canonical("TESTCASE/ST/2025/R0/1000000017", &[]);
        let key = salts.for_column("Claim.identifier[].value");
        assert_eq!(token, keyed_hash(&key, canonical.as_bytes()));
        assert_ne!(claim_a["meta"]["source"], json!(token), "meta.source is another column, so another salt");
        assert_eq!(salts.by_column.len(), 3, "claim id, meta.source and resource ids: {:?}", salts.by_column.keys());
    }

    #[test]
    fn output_is_named_after_the_input_file() {
        for (input, want) in [
            ("TESTCASE_ST_2025_R0_1000000017.fhir.json", "TESTCASE_ST_2025_R0_1000000017_anonymised.fhir.json"),
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
        n.add("MALA TI KUMARI", "Patient.name[].text", 6);
        n.add("TESTCASE/ST/2025/R0/1000000017", "Claim.identifier[].value", 6);
        assert!(n.hit(".../attachment/malati%20kumari.pdf").is_some(), "respelled name in a URL");
        assert!(n.hit("urn:example:TESTCASE_ST_2025_R0_1000000017").is_some(), "other separators");
        assert!(n.hit("provider/1111/2222/1000000017/forms").is_some(), "case number alone");
        assert!(n.hit("Complete blood count").is_none());
        assert!(n.hit("kumarika").is_none(), "words match whole, not as substrings");
    }

    #[test]
    fn output_stays_valid_fhir_shaped() {
        let (out, _) = anon();
        let obs = resource(&out, "Observation");
        assert!(obs.get("text").is_none(), "a narrative stripped of its div is removed");
        assert!(obs.get("identifier").is_none(), "an identifier array left empty is removed");
        assert_eq!(
            obs["performer"][0]["extension"][0]["url"],
            json!(DATA_ABSENT_REASON),
            "data-absent-reason survives"
        );
        assert!(obs["performer"][0].get("display").is_none());
        assert_eq!(resource(&out, "Claim")["_status"], dar());
        let text = serde_json::to_string(&out).unwrap();
        assert!(!text.contains("{}") && !text.contains("[]") && !text.contains("null"));
    }

    #[test]
    fn a_suppressed_primitive_takes_its_extension_sibling() {
        let mut b = bundle();
        b["entry"][0]["resource"]["name"] = json!([{"text": "X Y"}]);
        b["entry"][0]["resource"]["_gender"] =
            json!({"extension": [{"url": "http://example.org/original-text", "valueString": "purush"}]});
        let mut c = cfg();
        c.rules.retain(|r| r.pattern != "Patient.gender");
        let (out, _) = anon_with(&c, &b);
        let p = resource(&out, "Patient");
        assert!(p.get("gender").is_none() && p.get("_gender").is_none());
    }

    #[test]
    fn code_hash_rules_pseudonymise_the_observation_value() {
        let mut b = bundle();
        b["entry"]
            .as_array_mut()
            .unwrap()
            .push(entry(json!({"resourceType": "Observation", "id": "u1", "status": "final",
            "code": {"text": "patient uhid"}, "valueString": "90000001"})));
        let mut c = cfg();
        c.rules.push(Rule::new("Observation.valueString", Action::Keep));
        c.code_scopes[0].rules.push(Rule::new("*uhid*", Action::Hash));
        let mut salts = Salts::default();
        let (out, _) = anon_in(&c, &b, &mut salts);
        let obs = out["entry"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| &e["resource"])
            .find(|r| r["code"]["text"] == "patient uhid")
            .unwrap();
        let key = salts.for_column("code:*uhid*");
        assert_eq!(obs["valueString"], json!(keyed_hash(&key, b"90000001")));
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
        assert_eq!(remap_reference(&KEY, "#c1").as_deref(), Some("#c1"));
        assert_eq!(remap_reference(&KEY, "Patient/p1"), Some(format!("Patient/{}", pseudo_id(&KEY, "p1"))));
        assert_eq!(remap_reference(&KEY, "https://hospital.example/Patient/123"), None);
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
            "hash_strip_prefixes": ["urn:example:"]
        }))
        .unwrap();
        let scope = &c.code_scopes[0];
        assert_eq!(scope.resources, vec!["Observation".to_string()], "an object block is Observation-scoped");
        assert_eq!(scope.rules.len(), 2);
        assert!(
            scope.rules.iter().any(|r| r.pattern == "gps_latitude" && r.action == Action::Suppress),
            "code patterns are normalised to the technique-list spelling"
        );
        assert_eq!(scope.codings, vec![("http://loinc.org|42130-5".to_string(), Action::Suppress)]);
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

    /// The NHA policy, resolved against the decisions that matter. A refresh
    /// of the technique sheets regenerates most of that file, so this is what
    /// catches a regeneration that quietly changes one of them. The policy is
    /// kept out of the repository, so the test only runs where it is present.
    #[test]
    fn local_nha_config_resolves_the_load_bearing_paths() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/nha_fhir.json");
        if !path.is_file() {
            eprintln!("skipped: {} is not present (kept out of the repository)", path.display());
            return;
        }
        let root: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        let c = parse_fhir_bundle(&root[root["data_type"].as_str().unwrap()]).unwrap();
        let seg =
            |p: &str| -> Vec<String> { p.replace("[]", ".[]").split('.').map(|s| s.to_ascii_lowercase()).collect() };
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
            let got = code_decision(&c, "Observation", obs(text).as_object().unwrap()).map(|(a, _)| a.clone());
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
        fs::write(input.join("TESTCASE_ST_2025_R0_1000000017.fhir.json"), serde_json::to_string(&bundle()).unwrap())
            .unwrap();
        fs::write(input.join("not_a_bundle.json"), r#"{"resourceType": "Patient"}"#).unwrap();
        fs::write(input.join("broken.json"), "{nope").unwrap();
        let c = FhirBundleConfig {
            input_path: Some(PathBuf::from("in")),
            output_subdir: "out".into(),
            key_material_dir: PathBuf::from("."),
            output_root: PathBuf::from("."),
            ..cfg()
        };
        let report = run(&c, &root).unwrap();
        assert_eq!(report.files_written, 1);
        assert_eq!(report.files_skipped.len(), 2);
        assert_eq!(report.resources_dropped, 1);
        assert!(report.propagated >= 1);
        let names: Vec<String> =
            fs::read_dir(root.join("out")).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        assert!(names.contains(&"fhir_bundle_census.csv".to_string()));
        assert!(names.contains(&"TESTCASE_ST_2025_R0_1000000017_anonymised.fhir.json".to_string()), "{names:?}");
        assert!(root.join(SALT_FILE).is_file());
    }

    /// A folder is one corpus: every file shares the column salts, and the
    /// salts persist across runs.
    #[test]
    fn a_folder_shares_column_salts_across_files_and_runs() {
        let root = tmpdir("folder");
        let input = root.join("in");
        fs::create_dir_all(&input).unwrap();
        fs::write(input.join("TESTCASE_ST_2025_R0_1000000017.fhir.json"), serde_json::to_string(&bundle()).unwrap())
            .unwrap();
        fs::write(
            input.join("TESTCASE_ST_2025_R0_1000000017 (1).fhir.json"),
            serde_json::to_string(&bundle()).unwrap(),
        )
        .unwrap();
        let c = FhirBundleConfig {
            input_path: Some(PathBuf::from("in")),
            output_subdir: "out".into(),
            key_material_dir: PathBuf::from("keys"),
            output_root: PathBuf::from("output"),
            ..cfg()
        };
        let listing = || -> Vec<String> {
            let mut v: Vec<String> = fs::read_dir(root.join("output/out"))
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
                "TESTCASE_ST_2025_R0_1000000017 (1)_anonymised.fhir.json".to_string(),
                "TESTCASE_ST_2025_R0_1000000017_anonymised.fhir.json".to_string(),
            ],
            "each input keeps its own name, so a duplicate export is not overwritten"
        );
        let a: Value =
            serde_json::from_str(&fs::read_to_string(root.join("output/out").join(&names[0])).unwrap()).unwrap();
        let b: Value =
            serde_json::from_str(&fs::read_to_string(root.join("output/out").join(&names[1])).unwrap()).unwrap();
        assert_eq!(
            resource(&a, "Claim")["identifier"],
            resource(&b, "Claim")["identifier"],
            "one salt per column across files"
        );
        assert_eq!(resource(&a, "Patient")["id"], resource(&b, "Patient")["id"]);

        let second = run(&c, &root).unwrap();
        assert_eq!(second.salts_created, 0, "a rerun reuses the persisted salts");
        assert_eq!(listing(), names, "so it produces the same pseudonyms");
    }

    // ── 4.1: predicates, resource drops, scoped code rules, references ─────

    const CADAVERIC: &str = "http://hl7.org/fhir/StructureDefinition/patient-cadavericDonor";
    const V2_0074: &str = "http://terminology.hl7.org/CodeSystem/v2-0074";

    fn policy(extra: Value) -> FhirBundleConfig {
        let mut section = json!({"fhir_bundle": true, "input_path": "x", "keep": ["Bundle.type", "**.status"]});
        for (k, v) in extra.as_object().unwrap() {
            section[k] = v.clone();
        }
        parse_fhir_bundle(&section).unwrap()
    }

    fn bundle_of(resources: Vec<Value>) -> Value {
        json!({"resourceType": "Bundle", "type": "collection", "entry": resources.into_iter().map(entry).collect::<Vec<_>>()})
    }

    fn resources_of<'a>(out: &'a Value, rt: &str) -> Vec<&'a Value> {
        out["entry"].as_array().unwrap().iter().map(|e| &e["resource"]).filter(|r| r["resourceType"] == rt).collect()
    }

    fn patient_with_identifiers() -> Value {
        json!({"resourceType": "Patient", "id": "p1", "identifier": [
            {"system": "urn:example:aadhaar", "value": "900000000001"},
            {"system": "urn:example:naco-art", "value": "ART-0001-TEST"},
            {"system": "urn:example:uhid", "type": {"coding": [{"system": "http://terminology.hl7.org/CodeSystem/v2-0203", "code": "MR"}]}, "value": "UHID9000001"}
        ]})
    }

    #[test]
    fn an_art_predicate_suppresses_only_naco_identifiers() {
        let c = policy(json!({
            "keep": ["Bundle.type", "Patient.identifier[].system", "Patient.identifier[].type.**"],
            "hashing_with_salt": ["Patient.identifier[].value"],
            "suppress": ["Patient.identifier[system~\"*NACO*\"].**"]
        }));
        let mut salts = Salts::default();
        let (out, census) = anon_in(&c, &bundle_of(vec![patient_with_identifiers()]), &mut salts);
        let ids = resource(&out, "Patient")["identifier"].as_array().unwrap().clone();
        assert_eq!(ids.len(), 2, "the ART identifier is removed whole: {ids:?}");
        let key = salts.for_column("Patient.identifier[].value");
        assert_eq!(ids[0]["system"], json!("urn:example:aadhaar"));
        assert_eq!(ids[0]["value"], json!(keyed_hash(&key, b"900000000001")), "Aadhaar stays hashed");
        assert_eq!(ids[1]["value"], json!(keyed_hash(&key, b"uhid9000001")), "and so does the UHID");
        assert!(!serde_json::to_string(&out).unwrap().contains("ART-0001"));
        // One census path holds all three; the last writer names the rule.
        assert!(census.contains_key("Patient.identifier[].value"));
    }

    #[test]
    fn predicates_reach_nested_codings_and_masking_columns() {
        let c = policy(json!({
            "keep": ["Bundle.type", "Patient.identifier[].system", "Patient.identifier[].type.**"],
            "hashing_with_salt": ["Patient.identifier[].value"],
            "masking": [{"column": "Patient.identifier[type.coding.code=\"MR\"].value",
                         "characters_to_mask": [1, 2, 3, 4], "apply_order": ["characters"]}]
        }));
        let (out, census) = anon_with(&c, &bundle_of(vec![patient_with_identifiers()]));
        let ids = resource(&out, "Patient")["identifier"].as_array().unwrap();
        assert_eq!(ids[2]["value"], json!("****9000001"), "masking.column takes a predicate");
        assert_eq!(ids[0]["value"].as_str().unwrap().len(), 64, "others keep the plain rule");
        assert_eq!(census["Patient.identifier[].value"].seen, 3);
    }

    #[test]
    fn an_organ_donor_extension_is_kept_while_religion_is_suppressed() {
        let c = policy(json!({"keep": ["Bundle.type", format!("Patient.extension[url=\"{CADAVERIC}\"].**")]}));
        let p = json!({"resourceType": "Patient", "id": "p1", "extension": [
            {"url": CADAVERIC, "valueBoolean": true},
            {"url": "http://hl7.org/fhir/StructureDefinition/patient-religion", "valueCodeableConcept": {"text": "TESTFAITH"}}
        ]});
        let (out, _) = anon_with(&c, &bundle_of(vec![p]));
        let ext = resource(&out, "Patient")["extension"].as_array().unwrap();
        assert_eq!(ext, &vec![json!({"url": CADAVERIC, "valueBoolean": true})]);
    }

    #[test]
    fn a_predicate_beats_a_plain_rule_with_fewer_double_stars() {
        // Equal-length plain rules would pick the hash; the predicate rule,
        // though it has a `**`, is narrower by content.
        let c = policy(json!({
            "keep": ["Bundle.type", "Patient.identifier[system~\"*naco*\"].**"],
            "hashing_with_salt": ["Patient.identifier[].value"]
        }));
        let (out, _) = anon_with(&c, &bundle_of(vec![patient_with_identifiers()]));
        assert_eq!(resource(&out, "Patient")["identifier"][1]["value"], json!("ART-0001-TEST"));
        assert_eq!(resource(&out, "Patient")["identifier"][0]["value"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn predicates_work_in_propagation_from() {
        let c = policy(json!({
            "keep": ["Bundle.type", "DocumentReference.description"],
            "propagation": {"from": ["Patient.identifier[system~\"*naco*\"].value"]}
        }));
        let doc =
            json!({"resourceType": "DocumentReference", "id": "d1", "description": "ART card ART-0001-TEST scanned"});
        let other = json!({"resourceType": "DocumentReference", "id": "d2", "description": "UHID9000001 card"});
        let (out, census) = anon_with(&c, &bundle_of(vec![patient_with_identifiers(), doc, other]));
        let descs: Vec<&Value> = resources_of(&out, "DocumentReference").iter().map(|d| &d["description"]).collect();
        assert_eq!(descs, vec![&Value::Null, &json!("UHID9000001 card")], "only the NACO value is a needle");
        assert_eq!(census["DocumentReference.description"].seen, 2);
    }

    fn genetics_bundle() -> Value {
        bundle_of(vec![
            json!({"resourceType": "Patient", "id": "p1"}),
            json!({"resourceType": "DiagnosticReport", "id": "dr-ge", "status": "final",
                   "category": [{"coding": [{"system": V2_0074, "code": "GE"}]}], "code": {"text": "exome"},
                   "subject": {"reference": "urn:uuid:p1"}}),
            json!({"resourceType": "DiagnosticReport", "id": "dr-lab", "status": "final",
                   "category": [{"coding": [{"system": V2_0074, "code": "LAB"}]}], "code": {"text": "cbc"}}),
            json!({"resourceType": "Procedure", "id": "pr1", "status": "completed",
                   "report": [{"reference": "urn:uuid:dr-ge"}, {"reference": "urn:uuid:dr-lab"}]}),
            json!({"resourceType": "MolecularSequence", "id": "ms1", "patient": {"reference": "urn:uuid:p1"}}),
            json!({"resourceType": "Observation", "id": "o-var", "status": "final", "code": {"text": "variant"},
                   "derivedFrom": [{"reference": "urn:uuid:ms1"}]}),
            json!({"resourceType": "Observation", "id": "o-hb", "status": "final", "code": {"text": "hemoglobin"},
                   "derivedFrom": [{"reference": "urn:uuid:dr-lab"}]}),
            json!({"resourceType": "Specimen", "id": "sp-dna", "type": {"coding": [{"code": "DNA"}]}}),
            json!({"resourceType": "Specimen", "id": "sp-bld", "type": {"coding": [{"code": "BLD"}]}}),
            json!({"resourceType": "Media", "id": "m1", "status": "completed"}),
        ])
    }

    fn genetics_policy() -> FhirBundleConfig {
        policy(json!({
            "keep": ["Bundle.type", "**.status", "**.code.text"],
            "drop_resources": [
                "MolecularSequence",
                "Media",
                format!("DiagnosticReport[category.coding=\"{V2_0074}|GE\"]"),
                "Specimen[type.coding.code=\"DNA\"|\"RNA\"]",
                "Observation[derivedFrom.reference~\"MolecularSequence/*\"]"
            ]
        }))
    }

    #[test]
    fn a_ge_diagnostic_report_is_dropped_with_its_references() {
        let mut salts = Salts::default();
        let (out, census) = anon_in(&genetics_policy(), &genetics_bundle(), &mut salts);
        let reports = resources_of(&out, "DiagnosticReport");
        assert_eq!(reports.len(), 1, "only the lab report is left");
        let lab_id = pseudo_id(&salts.for_column(ID_COLUMN), "dr-lab");
        assert_eq!(reports[0]["id"], json!(lab_id));
        assert_eq!(
            resource(&out, "Procedure")["report"],
            json!([{"reference": format!("urn:uuid:{lab_id}")}]),
            "the procedure no longer points at the genetics report"
        );
        let row = &census["DiagnosticReport"];
        assert_eq!(row.action, "drop_resource");
        assert_eq!(row.matched_by, format!("drop_resources:DiagnosticReport[category.coding=\"{V2_0074}|GE\"]"));
    }

    #[test]
    fn resources_are_dropped_by_type_and_by_predicate() {
        let (out, census) = anon_with(&genetics_policy(), &genetics_bundle());
        assert!(resources_of(&out, "MolecularSequence").is_empty(), "no empty shell with a pseudonymous id");
        assert!(resources_of(&out, "Media").is_empty());
        assert_eq!(resources_of(&out, "Specimen").len(), 1, "the DNA specimen goes, blood stays");
        let obs = resources_of(&out, "Observation");
        assert_eq!(obs.len(), 1, "the variant derived from a MolecularSequence goes via its urn:uuid reference");
        assert_eq!(obs[0]["code"]["text"], json!("hemoglobin"));
        assert_eq!(census["Specimen"].seen, 1);
        assert!(!serde_json::to_string(&out).unwrap().contains("ms1"));
        let mut c = Census::default();
        anonymize_bundle(&genetics_bundle(), &genetics_policy(), &mut Salts::default(), &mut c);
        let dropped: usize = c.rows().iter().filter(|(_, r)| r.action == "drop_resource").map(|(_, r)| r.seen).sum();
        assert_eq!(dropped, 5);
    }

    #[test]
    fn a_sensitivity_label_drops_any_resource_type() {
        let c = policy(json!({"keep": ["Bundle.type", "**.code.text"],
            "drop_resources": ["*[meta.security=\"http://terminology.hl7.org/CodeSystem/v3-ActCode|GDIS\"]"]}));
        let b = bundle_of(vec![
            json!({"resourceType": "Condition", "id": "c1", "code": {"text": "x"},
                   "meta": {"security": [{"system": "http://terminology.hl7.org/CodeSystem/v3-ActCode", "code": "GDIS"}]}}),
            json!({"resourceType": "Condition", "id": "c2", "code": {"text": "y"}}),
        ]);
        let (out, _) = anon_with(&c, &b);
        let left = resources_of(&out, "Condition");
        assert_eq!(left.len(), 1);
        assert_eq!(left[0]["code"]["text"], json!("y"));
    }

    #[test]
    fn scoped_code_rules_drop_conditions_and_service_requests() {
        let c = policy(json!({
            "keep": ["Bundle.type", "**.code.text", "**.coding[].*"],
            "code_rules": [
                {"suppress": ["gps_*"]},
                {"resources": ["Condition", "ServiceRequest", "DiagnosticReport"],
                 "suppress": ["*hiv*", "http://hl7.org/fhir/sid/icd-10|B20"]}
            ]
        }));
        let b = bundle_of(vec![
            json!({"resourceType": "Condition", "id": "c1", "code": {"coding": [{"system": "http://hl7.org/fhir/sid/icd-10", "code": "B20"}]}}),
            json!({"resourceType": "Condition", "id": "c2", "code": {"text": "Fracture of radius"}}),
            json!({"resourceType": "ServiceRequest", "id": "s1", "code": {"text": "HIV-1 viral load"}}),
            json!({"resourceType": "DiagnosticReport", "id": "d1", "code": {"text": "HIV screening"}}),
            json!({"resourceType": "Observation", "id": "o1", "code": {"text": "hiv antibody"}}),
            json!({"resourceType": "Observation", "id": "o2", "code": {"text": "gps latitude"}}),
            json!({"resourceType": "Procedure", "id": "x1", "code": {"text": "hiv counselling"}}),
        ]);
        let (out, census) = anon_with(&c, &b);
        assert_eq!(resources_of(&out, "Condition").len(), 1);
        assert!(resources_of(&out, "ServiceRequest").is_empty());
        assert!(resources_of(&out, "DiagnosticReport").is_empty());
        let obs = resources_of(&out, "Observation");
        assert_eq!(obs.len(), 1, "Observations follow the Observation block only");
        assert_eq!(obs[0]["code"]["text"], json!("hiv antibody"));
        assert_eq!(resources_of(&out, "Procedure").len(), 1, "Procedure is in no scope");
        assert_eq!(
            census["Condition[code=http://hl7.org/fhir/sid/icd-10|b20]"].matched_by,
            "coding:http://hl7.org/fhir/sid/icd-10|b20"
        );
        assert_eq!(census["ServiceRequest[code=hiv_1_viral_load]"].matched_by, "code:*hiv*");
    }

    fn dob_observations() -> Value {
        bundle_of(vec![
            json!({"resourceType": "Observation", "id": "o1", "status": "final", "code": {"text": "patient_dob"}, "valueString": "1970-06-15"}),
            json!({"resourceType": "Observation", "id": "o2", "status": "final", "code": {"text": "admission date"}, "valueDateTime": "2025-04-21T10:30:00+05:30"}),
            json!({"resourceType": "Observation", "id": "o3", "status": "final", "code": {"text": "patient_dob"}, "valueQuantity": {"value": 1970, "unit": "a"}}),
            json!({"resourceType": "Observation", "id": "o4", "status": "final", "code": {"text": "hemoglobin"}, "valueString": "1970-06-15"}),
        ])
    }

    #[test]
    fn a_dob_observation_is_masked_to_the_year_by_a_code_rule() {
        let c = policy(json!({
            "keep": ["Bundle.type", "**.status", "**.code.text", "Observation.value*", "Observation.valueQuantity.*"],
            "code_rules": {"masking": [
                {"code": "*_dob", "masking_char": "*", "characters_to_mask": [6, 7, 9, 10], "apply_order": ["characters"]},
                {"code": "admission_date", "characters_to_mask": [9, 10, 12, 13, 15, 16, 18, 19], "apply_order": ["characters"]}
            ]}
        }));
        let (out, census) = anon_with(&c, &dob_observations());
        let obs = resources_of(&out, "Observation");
        assert_eq!(obs[0]["valueString"], json!("1970-**-**"));
        assert_eq!(obs[1]["valueDateTime"], json!("2025-04-**T**:**:**+05:30"), "admission date to the month");
        assert!(obs[2]["valueQuantity"].get("value").is_none(), "a number under a masking code is removed");
        assert_eq!(obs[2]["valueQuantity"]["unit"], json!("a"));
        assert_eq!(obs[3]["valueString"], json!("1970-06-15"), "other codes follow the path rules");
        assert_eq!(census["Observation.valueString"].seen, 2);
        assert_eq!(obs[0]["code"]["text"], json!("patient_dob"), "the code itself is untouched");
    }

    #[test]
    fn explicit_rules_suppress_references() {
        let c = policy(json!({
            "keep": ["Bundle.type", "**.status"],
            "suppress": ["Patient.link.**", "Claim.facility", "Encounter.location[].location.reference"]
        }));
        let b = bundle_of(vec![
            json!({"resourceType": "Patient", "id": "p1", "link": [{"other": {"reference": "urn:uuid:p2"}, "type": "seealso"}]}),
            json!({"resourceType": "Patient", "id": "p2"}),
            json!({"resourceType": "Location", "id": "l1"}),
            json!({"resourceType": "Claim", "id": "c1", "status": "active", "patient": {"reference": "urn:uuid:p1"},
                   "facility": {"reference": "urn:uuid:l1", "display": "TESTWARD"}}),
            json!({"resourceType": "Encounter", "id": "e1", "status": "finished", "subject": {"reference": "urn:uuid:p1"},
                   "location": [{"location": {"reference": "urn:uuid:l1"}}]}),
        ]);
        let mut salts = Salts::default();
        let (out, census) = anon_in(&c, &b, &mut salts);
        let p1 = pseudo_id(&salts.for_column(ID_COLUMN), "p1");
        assert!(resources_of(&out, "Patient")[0].get("link").is_none());
        let claim = resource(&out, "Claim");
        assert!(claim.get("facility").is_none(), "a rule on the parent removes the reference");
        assert_eq!(claim["patient"]["reference"], json!(format!("urn:uuid:{p1}")), "no rule: pseudonymised");
        let enc = resource(&out, "Encounter");
        assert!(enc.get("location").is_none());
        assert_eq!(enc["subject"]["reference"], json!(format!("urn:uuid:{p1}")));
        for e in out["entry"].as_array().unwrap() {
            assert!(e["fullUrl"].as_str().unwrap().starts_with("urn:uuid:"), "fullUrl stays pseudonymised");
        }
        assert_eq!(census["Claim.facility.reference"].matched_by, "Claim.facility");
        assert_eq!(census["Claim.facility.reference"].action, "suppress");
    }

    #[test]
    fn a_reference_under_a_non_suppress_rule_stays_pseudonymised() {
        let c = policy(json!({"keep": ["Bundle.type", "Claim.facility.**"]}));
        let b = bundle_of(vec![json!({"resourceType": "Claim", "id": "c1", "facility": {"reference": "Location/l1"}})]);
        let mut salts = Salts::default();
        let (out, census) = anon_in(&c, &b, &mut salts);
        let want = format!("Location/{}", pseudo_id(&salts.for_column(ID_COLUMN), "l1"));
        assert_eq!(resource(&out, "Claim")["facility"]["reference"], json!(want));
        assert_eq!(census["Claim.facility.reference"].action, "pseudonymise_reference");
    }

    #[test]
    fn output_names_can_be_pseudonymous() {
        let root = tmpdir("pseudo_names");
        let input = root.join("in");
        fs::create_dir_all(&input).unwrap();
        for n in ["TESTCASE_ST_2025_R0_1000000017.fhir.json", "TESTCASE_ST_2025_R0_1000000017 (1).fhir.json"] {
            fs::write(input.join(n), serde_json::to_string(&bundle()).unwrap()).unwrap();
        }
        let c = FhirBundleConfig {
            input_path: Some(PathBuf::from("in")),
            output_subdir: "out".into(),
            key_material_dir: PathBuf::from("keys"),
            output_root: PathBuf::from("output"),
            output_names: OutputNames::Pseudonym,
            ..cfg()
        };
        let listing = || -> Vec<String> {
            let mut v: Vec<String> = fs::read_dir(root.join("output/out"))
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .filter(|n| n.ends_with(".fhir.json"))
                .collect();
            v.sort();
            v
        };
        run(&c, &root).unwrap();
        let names = listing();
        assert_eq!(names.len(), 2, "duplicates keep apart: {names:?}");
        for n in &names {
            assert!(!n.contains("TESTCASE") && !n.contains("1000000017"), "{n}");
            assert_eq!(n.len(), 32 + "_anonymised.fhir.json".len());
        }
        let salts = Salts::load(&root.join("keys").join(SALT_FILE)).unwrap();
        let key = salts.by_column[OUTPUT_NAME_COLUMN];
        let want = format!("{}_anonymised.fhir.json", &keyed_hash(&key, b"TESTCASE_ST_2025_R0_1000000017")[..32]);
        assert!(names.contains(&want), "recomputable from the salt: {want}");
        run(&c, &root).unwrap();
        assert_eq!(listing(), names, "stable across runs");
    }

    #[test]
    fn new_keys_parse_and_default_as_before() {
        let c = policy(json!({}));
        assert_eq!(c.output_names, OutputNames::Input);
        assert!(c.drop_resources.is_empty() && c.code_scopes.is_empty());
        let c =
            policy(json!({"output_names": "pseudonym", "code_rules": {"resources": ["Observation"], "keep": ["x"]}}));
        assert_eq!(c.output_names, OutputNames::Pseudonym);
        assert_eq!(c.code_rule_count(), 1);
    }

    #[test]
    fn malformed_new_syntax_is_a_config_error() {
        let base = |extra: Value| {
            let mut section = json!({"fhir_bundle": true, "input_path": "x", "keep": ["Bundle.type"]});
            for (k, v) in extra.as_object().unwrap() {
                section[k] = v.clone();
            }
            parse_fhir_bundle(&section).map(|_| ()).unwrap_err()
        };
        for (extra, want) in [
            (json!({"suppress": ["Patient.identifier[system~naco].value"]}), "double-quoted"),
            (json!({"suppress": ["Patient.identifier[system:\"x\"].value"]}), "not a field path"),
            (json!({"suppress": ["Patient.identifier[system=\"x].value"]}), "closing ']'"),
            (json!({"suppress": ["Patient.identifier[=\"x\"].value"]}), "field name"),
            (json!({"suppress": ["Patient.identifier[sys tem=\"x\"].value"]}), "not a field path"),
            (json!({"suppress": ["Patient.identifier[system=\"x\"]value"]}), "after ']'"),
            (json!({"suppress": ["Patient.identifier[system=\"x\" use=\"y\"]"]}), "unexpected"),
            (json!({"suppress": ["Patient.identifier[system=\"\\x\"]"]}), "escapes"),
            (json!({"suppress": ["Patient..identifier[system=\"x\"]"]}), "empty path segment"),
            (
                json!({"masking": [{"column": "a[b=\"c\"", "characters_to_mask": [1], "apply_order": ["characters"]}]}),
                "closing",
            ),
            (json!({"propagation": {"from": ["a[b]"]}}), "'=' or '~'"),
            (json!({"drop_resources": ["Bundle"]}), "Bundle itself"),
            (json!({"drop_resources": ["Specimen[type.coding.code=\"DNA\"]x"]}), "nothing after"),
            (json!({"drop_resources": ["Spec-imen"]}), "resource type"),
            (json!({"drop_resources": ["Specimen[]"]}), "empty predicate"),
            (json!({"drop_resources": "Media"}), "array of strings"),
            (json!({"output_names": "hashed"}), "\\\"pseudonym\\\""),
            (
                json!({"code_rules": {"masking": [{"column": "x", "characters_to_mask": [1], "apply_order": ["characters"]}]}}),
                "'code', not a 'column'",
            ),
            (json!({"code_rules": {"masking": [{"code": "x"}]}}), "no masking step"),
            (json!({"code_rules": {"resources": ["Condition"], "hashing_with_salt": ["x"]}}), "value[x]"),
            (
                json!({"code_rules": {"resources": ["Condition", "Observation"], "masking": [{"code": "x", "characters_to_mask": [1], "apply_order": ["characters"]}]}}),
                "value[x]",
            ),
            (json!({"code_rules": {"resources": ["condition"], "suppress": ["x"]}}), "resource type names"),
            (json!({"code_rules": {"resources": [], "suppress": ["x"]}}), "empty"),
            (json!({"code_rules": [{"suppress": ["x"]}, "nope"]}), "list of them"),
        ] {
            let err = format!("{:?}", base(extra.clone()));
            assert!(err.contains(want), "{extra}: expected {want} in {err}");
        }
    }

    #[test]
    fn dry_run_writes_no_bundles() {
        let root = tmpdir("dry");
        fs::write(root.join("a.fhir.json"), serde_json::to_string(&bundle()).unwrap()).unwrap();
        let c = FhirBundleConfig {
            input_path: Some(PathBuf::from("a.fhir.json")),
            output_subdir: "out".into(),
            key_material_dir: PathBuf::from("."),
            output_root: PathBuf::from("."),
            dry_run: true,
            ..cfg()
        };
        let report = run(&c, &root).unwrap();
        assert_eq!((report.documents_examined, report.files_written), (1, 0));
        let names: Vec<String> =
            fs::read_dir(root.join("out")).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        assert_eq!(names, vec!["fhir_bundle_census.csv".to_string()]);
    }
}
