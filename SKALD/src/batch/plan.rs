//! Step 1: the parsed, validated config.

use super::stats::QiColumns;
use crate::pipeline::bootstrap::{PipelineError, RuntimeConfig, parse_runtime_config_value, validation};
use crate::pipeline::preprocess::{KeyKind, KeyMaterial, KeyPolicy, MemoryVault, Preprocessor, TokenPolicy};
use serde_json::Value;
use std::path::Path;

/// A validated config for a tabular k-anonymity run.
#[derive(Debug, Clone)]
pub struct Plan {
    pub cfg: RuntimeConfig,
    /// The config text, so a plan can be rebuilt on another machine.
    pub json: String,
}

impl Plan {
    /// Parses and validates a config given as JSON text — the same
    /// validation the command line applies (`KNOWN_SECTION_KEYS`, value
    /// ranges, required `k`).
    ///
    /// # Errors
    /// Any config error the command line would report; `CONFIG_INVALID_VALUE`
    /// when the config selects the nested-JSON or FHIR flow, which has no
    /// batch form.
    pub fn from_json(json: &str) -> Result<Self, PipelineError> {
        let root: Value = serde_json::from_str(json)?;
        let cfg = parse_runtime_config_value(&root, Path::new("<config>"))?;
        if cfg.nested_json.enabled || cfg.fhir_bundle.enabled {
            return Err(validation(
                "CONFIG_INVALID_VALUE",
                "nested_json and fhir_bundle have no batch form",
                "the batch API serves the tabular flow",
            ));
        }
        Ok(Self { cfg, json: json.to_string() })
    }

    /// Every key the config's techniques need, as `(kind, column)`: what a
    /// caller must supply (or let [`KeyMaterial::generate_missing`] make)
    /// before running executors with [`KeyPolicy::Require`].
    pub fn required_keys(&self) -> Result<Vec<(KeyKind, String)>, PipelineError> {
        let pre = Preprocessor::new(
            &self.cfg,
            KeyMaterial::new(),
            KeyPolicy::Require,
            MemoryVault::new(),
            TokenPolicy::LookupOnly,
        )?;
        Ok(pre.required_keys())
    }

    pub fn qi_columns(&self) -> QiColumns {
        QiColumns::from_config(&self.cfg)
    }

    /// Whether the config asks for k-anonymity (it has quasi-identifiers) or
    /// only column techniques.
    pub fn has_quasi_identifiers(&self) -> bool {
        self.cfg.enable_k_anonymity
    }
}
