//! Per-document flows (FHIR bundles, nested JSON) as a library call.
//!
//! Neither flow has dataset-wide state that shapes an output. One document is
//! one patient, so there is no cohort, no k, no generalisation lattice: a
//! document is anonymised from the config and the keys alone. What the command
//! line keeps across documents is only (a) the salts and encryption keys, which
//! a caller now passes in, and (b) the key census, a report that sums counts
//! over documents and does not feed back into any output. So there is no
//! measure step: [`DocPlan::apply`] is the whole operation, and workers can run
//! it on any document in any order and get the command line's bytes.
//!
//! Two things the command line does across documents are not offered:
//!
//! - `tokenization` (nested JSON) issues random tokens first-come into a vault
//!   shared by every document, so its output depends on processing order and the
//!   vault must be one object. [`DocPlan::from_json`] refuses such a config.
//! - `charcloak` and random-class masking are random per call by design, so two
//!   runs (CLI or not) differ; they work but cannot be compared byte for byte.
//!
//! Keys are passed in as [`KeyMaterial`] (the same type the tabular flow takes).
//! [`DocPlan::required_keys`] lists what a config needs; a missing key is an
//! error (`KEY_MATERIAL_MISSING`) and nothing is released, never a key invented
//! at random as the command line would do on a first run.

use crate::pipeline::bootstrap::{PipelineError, parse_runtime_config_value, validation};
use crate::pipeline::fhir_bundle::{self, FhirBundleConfig, Salts};
use crate::pipeline::nested_json::{self, Action, Census, FreeTextPass, KeyStore, NestedJsonConfig};
use crate::pipeline::preprocess::{KeyKind, KeyMaterial};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, VecDeque};
use std::path::Path;

/// The key name nested JSON's single `hashing_with_salt` key is filed under
/// (`nested_json_salt.json` holds it as `hash_salt`).
pub const NESTED_HASH_SALT: &str = "hash_salt";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocKind {
    Fhir,
    Nested,
}

/// A validated config for one of the per-document flows.
#[derive(Debug, Clone)]
pub struct DocPlan {
    kind: DocKind,
    fhir: FhirBundleConfig,
    nested: NestedJsonConfig,
    /// The config text, so a plan can be rebuilt on another machine.
    pub json: String,
}

/// One anonymised document.
#[derive(Debug)]
pub struct DocOutput {
    /// The bytes the command line would write for this document.
    pub bytes: Vec<u8>,
    /// Counts and categories only, no values: what the policy did.
    pub audit: Value,
}

/// Cleans a batch of free-text strings; returns one string per input, in order.
pub type Redactor<'a> = &'a mut dyn FnMut(Vec<String>) -> Result<Vec<String>, PipelineError>;

impl DocPlan {
    /// Parses and validates a config the way the command line does.
    ///
    /// # Errors
    /// Any config error the command line would report; `CONFIG_INVALID_VALUE`
    /// when the config selects the other flow, or (nested JSON) uses `tokenization`.
    pub fn from_json(json: &str, kind: DocKind) -> Result<Self, PipelineError> {
        let root: Value = serde_json::from_str(json)?;
        let cfg = parse_runtime_config_value(&root, Path::new("<config>"))?;
        let (want, other) = match kind {
            DocKind::Fhir => (cfg.fhir_bundle.enabled, cfg.nested_json.enabled),
            DocKind::Nested => (cfg.nested_json.enabled, cfg.fhir_bundle.enabled),
        };
        if !want || other {
            return Err(validation(
                "CONFIG_INVALID_VALUE",
                match kind {
                    DocKind::Fhir => "the config does not select the fhir_bundle flow",
                    DocKind::Nested => "the config does not select the nested_json flow",
                },
                "set `fhir_bundle: true` or `nested_json: true` in the data_type's section",
            ));
        }
        if kind == DocKind::Nested
            && let Some(rule) = cfg.nested_json.rules.iter().find(|r| matches!(r.action, Action::Tokenize { .. }))
        {
            return Err(validation(
                "CONFIG_INVALID_VALUE",
                "tokenization needs one vault shared by every document, which per-document workers do not have",
                &format!("{}: use hashing_with_salt for a stable pseudonym", rule.pattern),
            ));
        }
        Ok(Self { kind, fhir: cfg.fhir_bundle, nested: cfg.nested_json, json: json.to_string() })
    }

    pub fn kind(&self) -> DocKind {
        self.kind
    }

    /// Every key the config can use, as `(kind, name)`. Names are the ones the
    /// command line files its keys under: FHIR salt columns (`<resource id>`,
    /// `Claim.identifier[].value`, `code:gps_*` ...), nested JSON's `hash_salt`
    /// and its `encrypt` patterns.
    pub fn required_keys(&self) -> Vec<(KeyKind, String)> {
        match self.kind {
            DocKind::Fhir => {
                fhir_bundle::salt_columns(&self.fhir).into_iter().map(|c| (KeyKind::HmacSalt, c)).collect()
            }
            DocKind::Nested => {
                let mut out = vec![(KeyKind::HmacSalt, NESTED_HASH_SALT.to_string())];
                for r in &self.nested.rules {
                    if let Action::Encrypt { format_preserving } = r.action {
                        let kind = if format_preserving { KeyKind::FpeKey } else { KeyKind::AesKey };
                        if !out.iter().any(|(k, n)| *k == kind && *n == r.pattern) {
                            out.push((kind, r.pattern.clone()));
                        }
                    }
                }
                out
            }
        }
    }

    /// The paths whose released text is `free_text`, as written in the config.
    pub fn free_text_paths(&self) -> Vec<String> {
        let rules = match self.kind {
            DocKind::Fhir => &self.fhir.rules,
            DocKind::Nested => &self.nested.rules,
        };
        let mut out: Vec<String> =
            rules.iter().filter(|r| r.action == Action::FreeText).map(|r| r.pattern.clone()).collect();
        if self.kind == DocKind::Fhir {
            for s in &self.fhir.code_scopes {
                out.extend(
                    s.rules.iter().filter(|r| r.action == Action::FreeText).map(|r| format!("code:{}", r.pattern)),
                );
            }
        }
        out
    }

    fn check_keys(&self, keys: &KeyMaterial) -> Result<(), PipelineError> {
        let missing: Vec<String> = self
            .required_keys()
            .into_iter()
            .filter(|(k, n)| !keys.contains(*k, n))
            .map(|(k, n)| format!("{}:{n}", k.as_str()))
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        // Names only, never key bytes.
        Err(validation("KEY_MATERIAL_MISSING", "a key the config needs was not supplied", &missing.join(", ")))
    }

    /// The file name the command line writes a document under (FHIR:
    /// `<stem>_anonymised.fhir.json`, or a keyed hash of the stem; nested JSON:
    /// `<stem>.json`).
    pub fn output_name(&self, keys: &KeyMaterial, input_name: &str) -> Result<String, PipelineError> {
        match self.kind {
            DocKind::Nested => {
                let stem = Path::new(input_name).file_stem().and_then(|s| s.to_str()).unwrap_or("document");
                Ok(format!("{stem}.json"))
            }
            DocKind::Fhir => {
                self.check_keys(keys)?;
                let mut salts = self.salts(keys)?;
                Ok(fhir_bundle::output_file_name(&self.fhir, &mut salts, input_name))
            }
        }
    }

    fn salts(&self, keys: &KeyMaterial) -> Result<Salts, PipelineError> {
        let mut by_column = BTreeMap::new();
        for col in keys.columns(KeyKind::HmacSalt) {
            let bytes = keys.bytes(KeyKind::HmacSalt, &col).unwrap_or_default();
            let key: [u8; 32] = bytes
                .try_into()
                .map_err(|_| validation("KEY_MATERIAL_INVALID", "an hmac_salt must be 32 bytes", &col))?;
            by_column.insert(col, key);
        }
        Ok(Salts::provided(by_column))
    }

    fn key_store(&self, keys: &KeyMaterial) -> Result<KeyStore, PipelineError> {
        let salt = keys.bytes(KeyKind::HmacSalt, NESTED_HASH_SALT).unwrap_or_default();
        let salt: [u8; 32] = salt
            .try_into()
            .map_err(|_| validation("KEY_MATERIAL_INVALID", "an hmac_salt must be 32 bytes", NESTED_HASH_SALT))?;
        let pick = |kind: KeyKind| -> BTreeMap<String, String> {
            keys.columns(kind).into_iter().filter_map(|c| keys.map(kind).get(&c).map(|h| (c, h.clone()))).collect()
        };
        Ok(KeyStore::with_keys(salt, pick(KeyKind::AesKey), pick(KeyKind::FpeKey)))
    }

    /// Anonymises one document.
    ///
    /// `redact`, if given, is called once with every string the config releases
    /// as `free_text` (in walk order) and must return the cleaned strings; the
    /// document is then built with those. Without it, free text is released as
    /// the command line does, trusting an upstream pass.
    ///
    /// # Errors
    /// `DATA_INVALID_JSON`, `DATA_NOT_FHIR_BUNDLE`, `KEY_MATERIAL_MISSING`,
    /// `KEY_MATERIAL_INVALID`, or whatever `redact` returns.
    pub fn apply(
        &self,
        keys: &KeyMaterial,
        document: &[u8],
        mut redact: Option<Redactor<'_>>,
    ) -> Result<DocOutput, PipelineError> {
        self.check_keys(keys)?;
        let doc: Value = serde_json::from_slice(document)
            .map_err(|_| validation("DATA_INVALID_JSON", "the document is not valid JSON", ""))?;
        if self.kind == DocKind::Fhir && doc.get("resourceType").and_then(Value::as_str) != Some("Bundle") {
            return Err(validation("DATA_NOT_FHIR_BUNDLE", "not a FHIR Bundle (resourceType != \"Bundle\")", ""));
        }

        let run = |pass: FreeTextPass, census: &mut Census| -> Result<(Value, FreeTextPass), PipelineError> {
            match self.kind {
                DocKind::Fhir => {
                    let mut salts = self.salts(keys)?;
                    salts.free_text = pass;
                    let out = fhir_bundle::anonymize_bundle(&doc, &self.fhir, &mut salts, census);
                    let missing = salts.missing();
                    if !missing.is_empty() {
                        return Err(validation(
                            "KEY_MATERIAL_MISSING",
                            "the walk needed a salt that was not supplied",
                            &missing.join(", "),
                        ));
                    }
                    Ok((out, std::mem::take(&mut salts.free_text)))
                }
                DocKind::Nested => {
                    let mut store = self.key_store(keys)?;
                    store.free_text = pass;
                    let out = nested_json::anonymize_document(&doc, &self.nested, &mut store, census);
                    Ok((out, std::mem::take(&mut store.free_text)))
                }
            }
        };

        let mut census = Census::default();
        let out = match redact.as_mut() {
            None => run(FreeTextPass::Off, &mut census)?.0,
            Some(redact) => {
                let (_, collected) = run(FreeTextPass::Collect(Vec::new()), &mut Census::default())?;
                let FreeTextPass::Collect(texts) = collected else { unreachable!("Collect stays Collect") };
                let n = texts.len();
                let cleaned = if texts.is_empty() { Vec::new() } else { redact(texts)? };
                if cleaned.len() != n {
                    return Err(validation("NER_FAILED", "the redactor returned the wrong number of strings", ""));
                }
                run(FreeTextPass::Replace(VecDeque::from(cleaned)), &mut census)?.0
            }
        };

        let bytes = serde_json::to_string_pretty(&out)?.into_bytes();
        Ok(DocOutput { bytes, audit: audit_of(&census) })
    }
}

/// Counts from the census, no values (its `example` column is left out).
fn audit_of(census: &Census) -> Value {
    let rows = census.rows();
    let mut by_action: BTreeMap<String, u64> = BTreeMap::new();
    let (mut leaves, mut propagated, mut dropped) = (0u64, 0u64, 0u64);
    for (_, r) in &rows {
        *by_action.entry(r.action.clone()).or_default() += r.seen as u64;
        leaves += r.seen as u64;
        if r.matched_by.starts_with("propagated:") {
            propagated += r.seen as u64;
        }
        if r.action == "drop_resource" {
            dropped += r.seen as u64;
        }
    }
    let mut m = Map::new();
    m.insert("paths".into(), rows.len().into());
    m.insert("paths_kept".into(), census.kept_paths().len().into());
    m.insert("leaves".into(), leaves.into());
    m.insert("by_action".into(), Value::Object(by_action.into_iter().map(|(k, v)| (k, v.into())).collect()));
    m.insert("propagated".into(), propagated.into());
    m.insert("resources_dropped".into(), dropped.into());
    Value::Object(m)
}

#[cfg(test)]
mod tests {
    //! The library call against the command line's own `run`, over the synthetic
    //! corpus in `conformance/documents`: same config, same keys, same bytes.
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn corpus() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("conformance/documents")
    }

    /// Fixed, distinct key bytes per name: stands in for keys derived from K_user.
    fn key_bytes(kind: KeyKind, name: &str) -> Vec<u8> {
        let seed: u8 = name.bytes().fold(kind.len() as u8, |a, b| a.wrapping_mul(31).wrapping_add(b));
        (0..kind.len()).map(|i| seed.wrapping_add(i as u8)).collect()
    }

    fn keys_for(plan: &DocPlan) -> KeyMaterial {
        let mut keys = KeyMaterial::new();
        for (kind, name) in plan.required_keys() {
            keys.insert(kind, &name, &key_bytes(kind, &name)).unwrap();
        }
        keys
    }

    /// Writes `keys` where the command line reads its own, in its file formats.
    fn write_key_files(plan: &DocPlan, keys: &KeyMaterial, dir: &Path) {
        fs::create_dir_all(dir).unwrap();
        let hex = |kind: KeyKind, name: &str| ::hex::encode(keys.bytes(kind, name).unwrap());
        match plan.kind() {
            DocKind::Fhir => {
                let m: BTreeMap<String, String> = keys
                    .columns(KeyKind::HmacSalt)
                    .into_iter()
                    .map(|c| (c.clone(), hex(KeyKind::HmacSalt, &c)))
                    .collect();
                fs::write(dir.join("fhir_bundle_salts.json"), serde_json::to_string(&m).unwrap()).unwrap();
            }
            DocKind::Nested => {
                let salt = serde_json::json!({ "hash_salt": hex(KeyKind::HmacSalt, NESTED_HASH_SALT) });
                fs::write(dir.join("nested_json_salt.json"), salt.to_string()).unwrap();
                for (kind, file) in [
                    (KeyKind::AesKey, "nested_json_symmetric_keys.json"),
                    (KeyKind::FpeKey, "nested_json_fpe_encrypt_keys.json"),
                ] {
                    let m: BTreeMap<String, String> =
                        keys.columns(kind).into_iter().map(|c| (c.clone(), hex(kind, &c))).collect();
                    if !m.is_empty() {
                        fs::write(dir.join(file), serde_json::to_string(&m).unwrap()).unwrap();
                    }
                }
            }
        }
    }

    /// Runs the command line's flow over `docs`, returns {output file name: bytes}.
    fn cli_outputs(plan: &DocPlan, keys: &KeyMaterial, docs: &Path, tag: &str) -> BTreeMap<String, Vec<u8>> {
        let root = std::env::temp_dir().join(format!("skald_docs_{tag}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        write_key_files(plan, keys, &root.join("keys"));
        let out = root.join("output");
        match plan.kind() {
            DocKind::Fhir => {
                let mut cfg = plan.fhir.clone();
                cfg.input_path = Some(docs.to_path_buf());
                cfg.key_material_dir = root.join("keys");
                cfg.output_root = out.clone();
                fhir_bundle::run(&cfg, &root).unwrap();
            }
            DocKind::Nested => {
                let mut cfg = plan.nested.clone();
                cfg.input_path = Some(docs.to_path_buf());
                cfg.key_material_dir = root.join("keys");
                cfg.output_root = out.clone();
                nested_json::run(&cfg, &root).unwrap();
            }
        }
        let sub = fs::read_dir(&out).unwrap().map(|e| e.unwrap().path()).find(|p| p.is_dir()).unwrap();
        let got = fs::read_dir(&sub)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .map(|p| (p.file_name().unwrap().to_string_lossy().to_string(), fs::read(&p).unwrap()))
            .collect();
        let _ = fs::remove_dir_all(&root);
        got
    }

    fn lib_outputs(plan: &DocPlan, keys: &KeyMaterial, docs: &Path) -> BTreeMap<String, Vec<u8>> {
        let mut files: Vec<PathBuf> = fs::read_dir(docs).unwrap().map(|e| e.unwrap().path()).collect();
        files.sort();
        files
            .iter()
            .map(|f| {
                let name = f.file_name().unwrap().to_string_lossy().to_string();
                let out = plan.apply(keys, &fs::read(f).unwrap(), None).unwrap();
                (plan.output_name(keys, &name).unwrap(), out.bytes)
            })
            .collect()
    }

    fn check(config: &str, kind: DocKind, docs: &str, tag: &str) {
        let plan = DocPlan::from_json(&fs::read_to_string(corpus().join(config)).unwrap(), kind).unwrap();
        let keys = keys_for(&plan);
        let docs = corpus().join(docs);
        let want = cli_outputs(&plan, &keys, &docs, tag);
        assert_eq!(want.len(), 3, "{tag}: the corpus has three documents");
        assert_eq!(lib_outputs(&plan, &keys, &docs), want, "{tag}");
    }

    #[test]
    fn fhir_matches_the_command_line() {
        check("fhir/config.json", DocKind::Fhir, "fhir/docs", "fhir");
    }

    #[test]
    fn fhir_pseudonymous_names_match_the_command_line() {
        check("fhir/config_pseudonym.json", DocKind::Fhir, "fhir/docs", "fhir_pseudonym");
    }

    #[test]
    fn nested_json_matches_the_command_line() {
        check("nested/config.json", DocKind::Nested, "nested/docs", "nested");
    }

    #[test]
    fn documents_do_not_depend_on_each_other() {
        // The property that lets workers take documents in any order.
        let plan =
            DocPlan::from_json(&fs::read_to_string(corpus().join("fhir/config.json")).unwrap(), DocKind::Fhir).unwrap();
        let keys = keys_for(&plan);
        let doc = fs::read(corpus().join("fhir/docs/TESTCASE_ST_2025_R0_1000000001.fhir.json")).unwrap();
        let alone = plan.apply(&keys, &doc, None).unwrap().bytes;
        for other in ["0", "2"] {
            let d =
                fs::read(corpus().join(format!("fhir/docs/TESTCASE_ST_2025_R0_100000000{other}.fhir.json"))).unwrap();
            plan.apply(&keys, &d, None).unwrap();
        }
        assert_eq!(plan.apply(&keys, &doc, None).unwrap().bytes, alone);
    }

    #[test]
    fn a_missing_key_fails_the_document_and_names_the_key() {
        let plan =
            DocPlan::from_json(&fs::read_to_string(corpus().join("fhir/config.json")).unwrap(), DocKind::Fhir).unwrap();
        let mut keys = KeyMaterial::new();
        keys.insert(KeyKind::HmacSalt, "<resource id>", &[1; 32]).unwrap();
        let doc = fs::read(corpus().join("fhir/docs/TESTCASE_ST_2025_R0_1000000000.fhir.json")).unwrap();
        let err = plan.apply(&keys, &doc, None).unwrap_err().to_string();
        assert!(err.contains("KEY_MATERIAL_MISSING") && err.contains("Claim.identifier[].value"), "{err}");
    }

    #[test]
    fn free_text_goes_through_the_redactor_in_walk_order() {
        let plan =
            DocPlan::from_json(&fs::read_to_string(corpus().join("nested/config.json")).unwrap(), DocKind::Nested)
                .unwrap();
        let keys = keys_for(&plan);
        let doc = fs::read(corpus().join("nested/docs/case_1.json")).unwrap();
        let mut seen = Vec::new();
        let mut redact = |texts: Vec<String>| -> Result<Vec<String>, PipelineError> {
            seen.extend(texts.iter().cloned());
            Ok(texts.iter().map(|_| "[REDACTED]".to_string()).collect())
        };
        let out = plan.apply(&keys, &doc, Some(&mut redact)).unwrap();
        assert_eq!(seen.len(), 3, "one nurse_remarks per page");
        assert!(seen.iter().all(|t| t.contains("is stable")));
        let text = String::from_utf8(out.bytes).unwrap();
        assert_eq!(text.matches("[REDACTED]").count(), 3);
        assert!(!text.contains("is stable"));
    }

    #[test]
    fn cleaned_fhir_free_text_is_swept_as_released_not_as_found() {
        // The conclusion names the patient, so the propagation sweep removes it as the command
        // line receives it. A caller that cleans free text first releases the cleaned text,
        // and the sweep must judge that.
        let plan =
            DocPlan::from_json(&fs::read_to_string(corpus().join("fhir/config.json")).unwrap(), DocKind::Fhir).unwrap();
        let keys = keys_for(&plan);
        let doc = fs::read(corpus().join("fhir/docs/TESTCASE_ST_2025_R0_1000000000.fhir.json")).unwrap();
        let plain = String::from_utf8(plan.apply(&keys, &doc, None).unwrap().bytes).unwrap();
        assert!(!plain.contains("Mild anaemia"));
        let mut redact = |t: Vec<String>| -> Result<Vec<String>, PipelineError> {
            Ok(t.iter().map(|s| s.replace("ARJUN", "[PERSON]")).collect())
        };
        let cleaned = String::from_utf8(plan.apply(&keys, &doc, Some(&mut redact)).unwrap().bytes).unwrap();
        assert!(cleaned.contains("Mild anaemia noted for [PERSON]."), "{cleaned}");
    }

    #[test]
    fn tokenization_is_refused_for_nested_json() {
        let mut cfg: Value =
            serde_json::from_str(&fs::read_to_string(corpus().join("nested/config.json")).unwrap()).unwrap();
        cfg["nested"]["tokenization"] = serde_json::json!([{ "column": "**.mobile_number" }]);
        let err = DocPlan::from_json(&cfg.to_string(), DocKind::Nested).unwrap_err().to_string();
        assert!(err.contains("tokenization"), "{err}");
    }
}
