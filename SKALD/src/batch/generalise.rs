//! Third scan: write the chosen node, then enforce k on what is written.
//!
//! Generalising a batch is local, but whether a class is big enough is not: a
//! class split across batches can be large overall and small in each. So the
//! step is in three parts, each usable on its own:
//!
//! 1. [`Generalizer::apply`] rewrites the quasi-identifier cells of a batch and
//!    returns its [`Tally`] of classes.
//! 2. Tallies are merged, and [`Tally::decide`] says which classes fail k (and
//!    l) and whether the rows that fail can be published as `*` or must be
//!    removed.
//! 3. [`Generalizer::finish`] applies the [`Decision`] to each batch.
//!
//! [`Generalizer::tally`] and [`Tally::verify`] are the final check: tally the
//! rows actually written and confirm every class is at least k.

use super::table::Table;
use crate::pipeline::anonymization::{ClassTally, generalize_cell};
use crate::pipeline::anonymization::{
    GeneralizationSummary, LDiversity, QuasiIdentifierLite, normalize_categorical, resolve_qi_columns,
};
use crate::pipeline::bootstrap::{HierarchyMap, PipelineError, validation};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Class sizes (and, with l-diversity, distinct sensitive values) of the rows
/// of one or more batches, keyed by the written quasi-identifier cells.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tally {
    pub(crate) classes: BTreeMap<Vec<String>, ClassTally>,
    pub total: i64,
    l_cap: usize,
}

/// What the whole data set's tally says to do with each class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub summary: GeneralizationSummary,
    /// Classes that fail k (or l): their rows are suppressed or removed.
    failing: BTreeSet<Vec<String>>,
    /// Whether the failing rows are published with `*` quasi-identifiers
    /// (their combined class passes) or removed (it would single them out).
    pub publish_suppressed: bool,
}

impl Tally {
    pub fn new(l: Option<&LDiversity>) -> Self {
        Self { classes: BTreeMap::new(), total: 0, l_cap: l.map_or(0, |l| l.l) }
    }

    /// Folds another tally into this one.
    pub fn merge(&mut self, other: &Tally) {
        self.total += other.total;
        for (key, t) in &other.classes {
            self.classes.entry(key.clone()).or_default().absorb(t, self.l_cap);
        }
    }

    /// Decides every class against `k` (and `l`).
    ///
    /// Every failing class goes into the `*` class; that is published only if
    /// it would itself pass, otherwise its records are removed — a lone
    /// suppressed outlier is re-identified by being the only record that
    /// matches no published class.
    pub fn decide(&self, k: i64, l: Option<&LDiversity>) -> Decision {
        let l_cap = l.map_or(0, |l| l.l);
        let mut star = ClassTally::default();
        let mut failing = BTreeSet::new();
        let mut summary = GeneralizationSummary { total_records: self.total, ..Default::default() };
        for (key, tally) in &self.classes {
            if tally.passes(k, l) {
                summary.num_equivalence_classes += 1;
                summary.dm_star = summary.dm_star.saturating_add(tally.size.saturating_mul(tally.size));
                *summary.class_size_counts.entry(tally.size).or_insert(0) += 1;
            } else {
                if tally.size < k {
                    summary.classes_failing_k += 1;
                } else {
                    summary.classes_failing_l += 1;
                }
                summary.suppressed_records += tally.size;
                star.absorb(tally, l_cap);
                failing.insert(key.clone());
            }
        }
        let publish_suppressed = star.size == 0 || star.passes(k, l);
        if publish_suppressed {
            summary.published_suppressed_records = star.size;
        } else {
            summary.removed_records = star.size;
        }
        Decision { summary, failing, publish_suppressed }
    }

    /// The final check on written rows: every class holds at least `k` rows
    /// (and is l-diverse). Returns the smallest class size.
    ///
    /// # Errors
    /// `K_CHECK_FAILED` naming how many classes are too small.
    pub fn verify(&self, k: i64, l: Option<&LDiversity>) -> Result<i64, PipelineError> {
        let failing = self.classes.values().filter(|t| !t.passes(k, l)).count();
        if failing > 0 {
            return Err(validation(
                "K_CHECK_FAILED",
                "The written output is not k-anonymous",
                &format!(
                    "{failing} of {} classes hold fewer than k={k} rows (or fail l-diversity)",
                    self.classes.len()
                ),
            ));
        }
        Ok(self.classes.values().map(|t| t.size).min().unwrap_or(0))
    }

    /// Number of classes.
    pub fn len(&self) -> usize {
        self.classes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }

    // ── Wire format ──────────────────────────────────────────────────────────

    pub fn to_bytes(&self) -> Vec<u8> {
        #[derive(Serialize)]
        struct Wire<'a> {
            total: i64,
            l_cap: usize,
            classes: Vec<(&'a Vec<String>, &'a ClassTally)>,
        }
        let classes = self.classes.iter().collect();
        serde_json::to_vec(&Wire { total: self.total, l_cap: self.l_cap, classes }).expect("strings always serialise")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PipelineError> {
        #[derive(Deserialize)]
        struct Wire {
            total: i64,
            l_cap: usize,
            classes: Vec<(Vec<String>, ClassTally)>,
        }
        let w: Wire = serde_json::from_slice(bytes)
            .map_err(|_| validation("BATCH_DECODE_FAILED", "Not a tally written by this version", "tally"))?;
        Ok(Self { classes: w.classes.into_iter().collect(), total: w.total, l_cap: w.l_cap })
    }
}

impl Decision {
    /// Failing classes, for sending to executors (usually few).
    pub fn failing_classes(&self) -> &BTreeSet<Vec<String>> {
        &self.failing
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("strings and integers always serialise")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PipelineError> {
        serde_json::from_slice(bytes)
            .map_err(|_| validation("BATCH_DECODE_FAILED", "Not a decision written by this version", "decision"))
    }
}

/// Rewrites batches at one lattice node.
#[derive(Debug, Clone)]
pub struct Generalizer {
    qis: Vec<QuasiIdentifierLite>,
    node: Vec<i64>,
    hierarchies: HierarchyMap,
    l: Option<LDiversity>,
}

impl Generalizer {
    /// # Errors
    /// `GENERALIZATION_FAILED` when `node` does not have one level per QI.
    pub fn new(
        qis: &[QuasiIdentifierLite],
        node: &[i64],
        hierarchies: &HierarchyMap,
        l: Option<&LDiversity>,
    ) -> Result<Self, PipelineError> {
        if node.len() != qis.len() {
            return Err(validation("GENERALIZATION_FAILED", "final_rf length mismatch", "generalization"));
        }
        Ok(Self { qis: qis.to_vec(), node: node.to_vec(), hierarchies: hierarchies.clone(), l: l.cloned() })
    }

    fn sens_idx(&self, table: &Table) -> Result<Vec<usize>, PipelineError> {
        let Some(l) = &self.l else { return Ok(Vec::new()) };
        l.sensitive_attributes
            .iter()
            .map(|c| {
                table.column(c).ok_or_else(|| {
                    validation("DATA_COLUMN_MISSING", "l_diversity sensitive attribute not found in CSV header", c)
                })
            })
            .collect()
    }

    /// Replaces each quasi-identifier cell of `table` with its label at the
    /// node (`*` for a cell with no bin) and returns the batch's tally.
    pub fn apply(&self, table: &mut Table) -> Result<Tally, PipelineError> {
        let qi_idx = resolve_qi_columns(&table.headers, &self.qis)?;
        let sens_idx = self.sens_idx(table)?;
        let mut tally = Tally::new(self.l.as_ref());
        for row in &mut table.rows {
            for (pos, qi) in self.qis.iter().enumerate() {
                let i = qi_idx[pos];
                row[i] = generalize_cell(qi, &row[i], self.node[pos], &self.hierarchies);
            }
            tally.add_row(row, &qi_idx, &sens_idx);
        }
        Ok(tally)
    }

    /// Tally of rows whose quasi-identifiers are already written (the
    /// output of [`Generalizer::finish`]), for the final check.
    pub fn tally(&self, table: &Table) -> Result<Tally, PipelineError> {
        let qi_idx = resolve_qi_columns(&table.headers, &self.qis)?;
        let sens_idx = self.sens_idx(table)?;
        let mut tally = Tally::new(self.l.as_ref());
        for row in &table.rows {
            tally.add_row(row, &qi_idx, &sens_idx);
        }
        Ok(tally)
    }

    /// Applies the decision to a generalised batch: rows of failing classes
    /// get `*` quasi-identifiers, or are removed when the `*` class would
    /// itself be too small.
    pub fn finish(&self, table: &mut Table, decision: &Decision) -> Result<(), PipelineError> {
        let qi_idx = resolve_qi_columns(&table.headers, &self.qis)?;
        let rows = std::mem::take(&mut table.rows);
        for mut row in rows {
            let key: Vec<String> = qi_idx.iter().map(|&i| row[i].clone()).collect();
            if decision.failing.contains(&key) {
                if !decision.publish_suppressed {
                    continue;
                }
                for &i in &qi_idx {
                    row[i] = "*".to_string();
                }
            }
            table.rows.push(row);
        }
        Ok(())
    }
}

impl Tally {
    fn add_row(&mut self, row: &[String], qi_idx: &[usize], sens_idx: &[usize]) {
        let key: Vec<String> = qi_idx.iter().map(|&i| row[i].clone()).collect();
        let sensitive: Vec<String> = sens_idx.iter().map(|&i| normalize_categorical(&row[i])).collect();
        self.classes.entry(key).or_default().add(&sensitive, self.l_cap);
        self.total += 1;
    }
}
