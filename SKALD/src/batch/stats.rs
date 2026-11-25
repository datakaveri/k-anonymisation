//! First scan: everything the model needs to know about the data as a whole.
//!
//! A numeric quasi-identifier's bins start at its global minimum and its range
//! sets how many levels it has; a categorical one's domain fixes its codes. No
//! batch can know those alone, so each batch reports what it saw ([`Stats`])
//! and the reports are merged before the model is built. Merging is
//! order-independent, so batches may be scanned on any executor in any order.

use super::table::Table;
use crate::pipeline::anonymization::{normalize_categorical, parse_numeric_qi};
use crate::pipeline::bootstrap::{PipelineError, RuntimeConfig, validation};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The quasi-identifier columns of a config, numeric first and then
/// categorical — the order the model keeps them in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QiColumns {
    pub numeric: Vec<String>,
    pub categorical: Vec<String>,
}

impl QiColumns {
    pub fn from_config(cfg: &RuntimeConfig) -> Self {
        Self {
            numeric: cfg.numerical_qis.iter().map(|q| q.column.clone()).collect(),
            categorical: cfg.categorical_qis.clone(),
        }
    }
}

/// What one or more batches contain, as far as the model is concerned.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stats {
    /// Data rows seen.
    pub rows: i64,
    /// Per numeric QI: smallest and largest parseable value, `None` while none
    /// has been seen.
    pub numeric: Vec<Option<(i64, i64)>>,
    /// Per categorical QI: every distinct normalised value.
    pub categorical: Vec<BTreeSet<String>>,
}

fn resolve(table: &Table, names: &[String]) -> Result<Vec<usize>, PipelineError> {
    names
        .iter()
        .map(|c| {
            table
                .column(c)
                .ok_or_else(|| validation("DATA_COLUMN_MISSING", "Quasi-identifier column not found in CSV header", c))
        })
        .collect()
}

impl Stats {
    pub fn new(cols: &QiColumns) -> Self {
        Self {
            rows: 0,
            numeric: vec![None; cols.numeric.len()],
            categorical: vec![BTreeSet::new(); cols.categorical.len()],
        }
    }

    /// Adds one batch.
    ///
    /// Numbers are read with `parse_numeric_qi`, exactly as the histogram and
    /// the output step read them, so an unparseable or out-of-range cell
    /// (`NA`, `inf`, `-1e18`) cannot stretch the range and blur every other bin.
    ///
    /// # Errors
    /// `DATA_COLUMN_MISSING` when a quasi-identifier is not a column.
    pub fn observe(&mut self, cols: &QiColumns, table: &Table) -> Result<(), PipelineError> {
        let num_idx = resolve(table, &cols.numeric)?;
        let cat_idx = resolve(table, &cols.categorical)?;
        for row in &table.rows {
            self.rows += 1;
            for (slot, &i) in self.numeric.iter_mut().zip(&num_idx) {
                if let Some(v) = parse_numeric_qi(&row[i]) {
                    *slot = Some(slot.map_or((v, v), |(mn, mx)| (mn.min(v), mx.max(v))));
                }
            }
            for (set, &i) in self.categorical.iter_mut().zip(&cat_idx) {
                // Skip the allocation for a value already seen.
                let v = normalize_categorical(&row[i]);
                if !set.contains(&v) {
                    set.insert(v);
                }
            }
        }
        Ok(())
    }

    /// Folds another report into this one.
    ///
    /// # Errors
    /// `BATCH_SHAPE_MISMATCH` when the two were made for different configs.
    pub fn merge(&mut self, other: &Stats) -> Result<(), PipelineError> {
        if self.numeric.len() != other.numeric.len() || self.categorical.len() != other.categorical.len() {
            return Err(validation(
                "BATCH_SHAPE_MISMATCH",
                "Stats were made for different quasi-identifier lists",
                "merge",
            ));
        }
        self.rows += other.rows;
        for (a, b) in self.numeric.iter_mut().zip(&other.numeric) {
            *a = match (*a, *b) {
                (Some((a0, a1)), Some((b0, b1))) => Some((a0.min(b0), a1.max(b1))),
                (x, None) | (None, x) => x,
            };
        }
        for (a, b) in self.categorical.iter_mut().zip(&other.categorical) {
            a.extend(b.iter().cloned());
        }
        Ok(())
    }

    /// `(min, max)` per numeric column, `(0, 0)` for one with no parseable
    /// value — the shape `build_quasi_identifiers` takes.
    pub fn min_max(&self, cols: &QiColumns) -> BTreeMap<String, (f64, f64)> {
        cols.numeric
            .iter()
            .zip(&self.numeric)
            .map(|(c, mm)| {
                let (mn, mx) = mm.unwrap_or((0, 0));
                (c.clone(), (mn as f64, mx as f64))
            })
            .collect()
    }

    /// Sorted categorical domains, indexed by position in the model's QI list
    /// (numeric QIs hold an empty domain), as `scan_chunks_for_flow` returns.
    pub fn domains(&self) -> Vec<Vec<String>> {
        let mut out = vec![Vec::new(); self.numeric.len()];
        out.extend(self.categorical.iter().map(|s| s.iter().cloned().collect()));
        out
    }
}
