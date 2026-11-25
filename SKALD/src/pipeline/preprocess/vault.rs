//! Token vaults: the original → token map tokenization draws on.
//!
//! The vault is a trait so a caller that keeps its vaults somewhere else — the
//! Anamika job flow loads and saves a sealed object per column — can hand
//! SKALD a map it loaded, and take back what the run added, without SKALD
//! knowing where it lives. [`MemoryVault`] is the in-memory implementation and
//! what the command line uses: it is loaded from, and saved back to,
//! `token_vault.json` exactly as before.

use crate::pipeline::bootstrap::{PipelineError, validation};
use std::collections::BTreeMap;

/// One vault per column: maps an original value to its token, both ways.
///
/// `original` is always the value as tokenization sees it — already
/// normalised with `normalize_identifier` — so a vault never has to know the
/// normalisation rules.
pub trait TokenVault {
    /// The token already issued for `original` in `column`, if any.
    fn lookup(&self, column: &str, original: &str) -> Option<String>;

    /// Records `original → token` for `column`.
    ///
    /// # Errors
    /// `TOKEN_CONFLICT` when `token` already stands for a different original in
    /// this column, or `original` already has a different token: a vault must
    /// stay a bijection or detokenisation becomes ambiguous.
    fn assign(&mut self, column: &str, original: &str, token: &str) -> Result<(), PipelineError>;

    /// Whether `token` is already issued in `column` (for any original).
    fn token_in_use(&self, column: &str, token: &str) -> bool;

    /// Number of tokens issued in `column`.
    fn len(&self, column: &str) -> usize;

    fn is_empty(&self, column: &str) -> bool {
        self.len(column) == 0
    }
}

/// One column's mappings, both directions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ColumnVault {
    pub forward: BTreeMap<String, String>,
    pub reverse: BTreeMap<String, String>,
}

/// In-memory vaults, one per column.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryVault {
    columns: BTreeMap<String, ColumnVault>,
}

impl MemoryVault {
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs a column's vault from its `forward` and `reverse` maps, the
    /// shape `token_vault.json` stores.
    pub fn insert_column(
        &mut self,
        column: &str,
        forward: BTreeMap<String, String>,
        reverse: BTreeMap<String, String>,
    ) {
        self.columns.insert(column.to_string(), ColumnVault { forward, reverse });
    }

    /// Installs a column's vault from `original → token` entries (the
    /// `entries` object of an Anamika vault plaintext); the reverse map is
    /// derived.
    ///
    /// # Errors
    /// `TOKEN_CONFLICT` when two originals share a token.
    pub fn load_entries(
        &mut self,
        column: &str,
        entries: impl IntoIterator<Item = (String, String)>,
    ) -> Result<(), PipelineError> {
        let mut col = ColumnVault::default();
        for (original, token) in entries {
            if col.reverse.insert(token.clone(), original.clone()).is_some() {
                return Err(validation("TOKEN_CONFLICT", "Two originals share one token in the vault", column));
            }
            col.forward.insert(original, token);
        }
        self.columns.insert(column.to_string(), col);
        Ok(())
    }

    /// The column's `original → token` entries, for saving the vault back.
    pub fn entries(&self, column: &str) -> BTreeMap<String, String> {
        self.columns.get(column).map(|c| c.forward.clone()).unwrap_or_default()
    }

    pub fn column(&self, column: &str) -> Option<&ColumnVault> {
        self.columns.get(column)
    }

    /// Columns that hold a vault.
    pub fn columns(&self) -> impl Iterator<Item = &String> {
        self.columns.keys()
    }
}

impl TokenVault for MemoryVault {
    fn lookup(&self, column: &str, original: &str) -> Option<String> {
        self.columns.get(column)?.forward.get(original).cloned()
    }

    fn assign(&mut self, column: &str, original: &str, token: &str) -> Result<(), PipelineError> {
        let col = self.columns.entry(column.to_string()).or_default();
        match (col.forward.get(original), col.reverse.get(token)) {
            (Some(t), Some(o)) if t == token && o == original => return Ok(()),
            (None, None) => {}
            _ => return Err(validation("TOKEN_CONFLICT", "The token or the original is already in the vault", column)),
        }
        col.forward.insert(original.to_string(), token.to_string());
        col.reverse.insert(token.to_string(), original.to_string());
        Ok(())
    }

    fn token_in_use(&self, column: &str, token: &str) -> bool {
        self.columns.get(column).is_some_and(|c| c.reverse.contains_key(token))
    }

    fn len(&self, column: &str) -> usize {
        self.columns.get(column).map_or(0, |c| c.reverse.len())
    }
}
