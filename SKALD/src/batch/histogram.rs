//! Second scan: the histogram of rows over the quasi-identifiers.
//!
//! Each batch is binned at the model's finest granularity (`initial_ri`), the
//! per-batch histograms are merged by adding counts, and the search then runs
//! on the merged histogram alone — it never sees a row. Merging is
//! order-independent and associative, so it can be done as a tree.
//!
//! Two representations, chosen by the model's flow: a sorted, run-length
//! encoded array of Z-encoded keys (DIRECT, about 16 bytes per distinct cell)
//! and a map from cell to count (ORIGINAL). With l-diversity each cell also
//! carries up to `l` distinct values of each sensitive attribute.

use super::model::Model;
use super::table::Table;
use crate::pipeline::anonymization::{
    INVALID_BIN, QuasiIdentifierLite, SensitiveSets, SparseHist, ZHist, normalize_categorical, resolve_qi_columns,
    z_hist_to_sparse,
};
use crate::pipeline::bootstrap::{PipelineError, validation};
use std::collections::HashMap;

/// Distinct sensitive values per cell, per attribute, capped at `l`. Strings,
/// not ids, because ids are local to one batch.
pub(crate) type SensCells = HashMap<Vec<i64>, Vec<Vec<String>>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cells {
    /// DIRECT flow: sorted `(z, count)` with strictly increasing `z`.
    Z(ZHist),
    Sparse(SparseHist),
}

/// The merged (or per-batch) histogram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Histogram {
    pub cells: Cells,
    /// Rows counted.
    pub total: i64,
    pub(crate) sens: Option<SensCells>,
    /// The l the sensitive sets are capped at (0 without l-diversity).
    l: usize,
}

// ── Row kernels, shared with the file-based builders in `ola` ────────────────

/// Bins every row of `table` into `hist` at `initial_ri`. Returns rows added.
pub(crate) fn observe_sparse(
    hist: &mut SparseHist,
    qis: &[QuasiIdentifierLite],
    initial_ri: &[i64],
    domains: &[Vec<String>],
    table: &Table,
) -> Result<i64, PipelineError> {
    let idx = resolve_qi_columns(&table.headers, qis)?;
    for row in &table.rows {
        let key = crate::pipeline::anonymization::base_key(qis, row, &idx, initial_ri, domains)?;
        *hist.entry(key).or_insert(0) += 1;
    }
    Ok(table.rows.len() as i64)
}

/// Z-encodes every row of `table` at the finest granularity into `zs`.
pub(crate) fn observe_z(
    zs: &mut Vec<i64>,
    qis: &[QuasiIdentifierLite],
    domains: &[Vec<String>],
    weights: &[i64],
    table: &Table,
) -> Result<(), PipelineError> {
    let idx = resolve_qi_columns(&table.headers, qis)?;
    let ones = vec![1; qis.len()];
    for row in &table.rows {
        let key = crate::pipeline::anonymization::base_key(qis, row, &idx, &ones, domains)?;
        zs.push(crate::pipeline::anonymization::z_of_key(qis, &key, weights));
    }
    Ok(())
}

/// Adds the sensitive values of every row of `table` to `sets`, keyed like
/// the base histogram.
pub(crate) fn observe_sensitive(
    sets: &mut SensCells,
    qis: &[QuasiIdentifierLite],
    initial_ri: &[i64],
    domains: &[Vec<String>],
    sensitive_columns: &[String],
    l: usize,
    table: &Table,
) -> Result<(), PipelineError> {
    let idx = resolve_qi_columns(&table.headers, qis)?;
    let s_idx: Vec<usize> = sensitive_columns
        .iter()
        .map(|c| {
            table.column(c).ok_or_else(|| {
                validation("DATA_COLUMN_MISSING", "l_diversity sensitive attribute not found in CSV header", c)
            })
        })
        .collect::<Result<_, _>>()?;
    for row in &table.rows {
        let key = crate::pipeline::anonymization::base_key(qis, row, &idx, initial_ri, domains)?;
        let cell = sets.entry(key).or_insert_with(|| vec![Vec::new(); sensitive_columns.len()]);
        for (a, &si) in s_idx.iter().enumerate() {
            if cell[a].len() < l {
                let v = normalize_categorical(&row[si]);
                if !cell[a].contains(&v) {
                    cell[a].push(v);
                }
            }
        }
    }
    Ok(())
}

/// Collapses raw Z values into a sorted run-length histogram.
pub(crate) fn collapse_z(mut zs: Vec<i64>) -> ZHist {
    zs.sort_unstable();
    let mut hist = ZHist::new();
    for z in zs {
        match hist.last_mut() {
            Some(last) if last.0 == z => last.1 += 1,
            _ => hist.push((z, 1)),
        }
    }
    hist
}

fn merge_z(a: &ZHist, b: &ZHist) -> ZHist {
    let mut out = ZHist::with_capacity(a.len() + b.len());
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        let take_a = j >= b.len() || (i < a.len() && a[i].0 <= b[j].0);
        let next = if take_a {
            i += 1;
            a[i - 1]
        } else {
            j += 1;
            b[j - 1]
        };
        match out.last_mut() {
            Some(last) if last.0 == next.0 => last.1 += next.1,
            _ => out.push(next),
        }
    }
    out
}

fn union_capped(dst: &mut Vec<String>, src: &[String], l: usize) {
    for v in src {
        if dst.len() >= l {
            return;
        }
        if !dst.contains(v) {
            dst.push(v.clone());
        }
    }
}

impl Histogram {
    pub(crate) fn new(model: &Model) -> Self {
        let cells = if model.weights.is_some() { Cells::Z(ZHist::new()) } else { Cells::Sparse(SparseHist::new()) };
        let l = model.l_diversity.as_ref().map_or(0, |l| l.l);
        Self { cells, total: 0, sens: model.l_diversity.as_ref().map(|_| SensCells::new()), l }
    }

    /// Counts one batch.
    ///
    /// # Errors
    /// A quasi-identifier or sensitive attribute that is not a column.
    pub fn observe(&mut self, model: &Model, table: &Table) -> Result<(), PipelineError> {
        match (&mut self.cells, &model.weights) {
            (Cells::Z(zh), Some(w)) => {
                let mut zs = Vec::with_capacity(table.rows.len());
                observe_z(&mut zs, &model.qis, &model.domains, w, table)?;
                *zh = merge_z(zh, &collapse_z(zs));
            }
            (Cells::Sparse(h), _) => {
                observe_sparse(h, &model.qis, &model.initial_ri, &model.domains, table)?;
            }
            (Cells::Z(_), None) => {
                return Err(validation("BATCH_SHAPE_MISMATCH", "A Z histogram needs the DIRECT model", "histogram"));
            }
        }
        if let (Some(sets), Some(ld)) = (&mut self.sens, &model.l_diversity) {
            observe_sensitive(
                sets,
                &model.qis,
                &model.initial_ri,
                &model.domains,
                &ld.sensitive_attributes,
                ld.l,
                table,
            )?;
        }
        self.total += table.rows.len() as i64;
        Ok(())
    }

    /// Folds another histogram (made from the same model) into this one.
    ///
    /// # Errors
    /// `BATCH_SHAPE_MISMATCH` when the two use different representations.
    pub fn merge(&mut self, other: &Histogram) -> Result<(), PipelineError> {
        match (&mut self.cells, &other.cells) {
            (Cells::Z(a), Cells::Z(b)) => *a = merge_z(a, b),
            (Cells::Sparse(a), Cells::Sparse(b)) => {
                for (k, c) in b {
                    *a.entry(k.clone()).or_insert(0) += c;
                }
            }
            _ => {
                return Err(validation(
                    "BATCH_SHAPE_MISMATCH",
                    "Histograms from different flows cannot merge",
                    "merge",
                ));
            }
        }
        match (&mut self.sens, &other.sens) {
            (Some(a), Some(b)) => {
                for (k, attrs) in b {
                    let cell = a.entry(k.clone()).or_insert_with(|| vec![Vec::new(); attrs.len()]);
                    for (dst, src) in cell.iter_mut().zip(attrs) {
                        union_capped(dst, src, self.l);
                    }
                }
            }
            (None, None) => {}
            _ => {
                return Err(validation("BATCH_SHAPE_MISMATCH", "Only one histogram carries sensitive values", "merge"));
            }
        }
        self.total += other.total;
        Ok(())
    }

    /// Distinct non-empty cells.
    pub fn len(&self) -> usize {
        match &self.cells {
            Cells::Z(z) => z.len(),
            Cells::Sparse(s) => s.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The cells as the sparse map the diagnostics and l-diversity read.
    pub fn to_sparse(&self, model: &Model) -> SparseHist {
        match (&self.cells, &model.weights) {
            (Cells::Sparse(s), _) => s.clone(),
            (Cells::Z(z), Some(w)) => z_hist_to_sparse(z, &model.qis, w),
            (Cells::Z(_), None) => SparseHist::new(),
        }
    }

    /// Sensitive values interned to ids, in the form the search takes.
    pub(crate) fn sensitive_sets(&self) -> Option<SensitiveSets> {
        self.sens.as_ref().map(intern_sensitive)
    }

    // ── Wire format ──────────────────────────────────────────────────────────

    /// Compact binary form for sending between processes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = b"SKH1".to_vec();
        b.extend(self.total.to_le_bytes());
        b.extend((self.l as u64).to_le_bytes());
        match &self.cells {
            Cells::Z(z) => {
                b.push(1);
                b.extend((z.len() as u64).to_le_bytes());
                for (k, c) in z {
                    b.extend(k.to_le_bytes());
                    b.extend(c.to_le_bytes());
                }
            }
            Cells::Sparse(s) => {
                b.push(0);
                let width = s.keys().next().map_or(0, Vec::len);
                b.extend((s.len() as u64).to_le_bytes());
                b.extend((width as u64).to_le_bytes());
                // Sorted, so equal histograms serialise equally.
                let mut entries: Vec<_> = s.iter().collect();
                entries.sort();
                for (key, c) in entries {
                    for v in key {
                        b.extend(v.to_le_bytes());
                    }
                    b.extend(c.to_le_bytes());
                }
            }
        }
        match &self.sens {
            None => b.push(0),
            Some(sens) => {
                b.push(1);
                let mut entries: Vec<_> = sens.iter().collect();
                entries.sort();
                let json = serde_json::to_vec(&entries).expect("strings and integers always serialise");
                b.extend((json.len() as u64).to_le_bytes());
                b.extend(json);
            }
        }
        b
    }

    /// Inverse of [`Histogram::to_bytes`].
    ///
    /// # Errors
    /// `BATCH_DECODE_FAILED` for bytes this crate did not write.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PipelineError> {
        let bad = || validation("BATCH_DECODE_FAILED", "Not a histogram written by this version", "histogram");
        let mut r = Reader { b: bytes, at: 0 };
        if r.take(4).ok_or_else(bad)? != b"SKH1" {
            return Err(bad());
        }
        let total = r.i64().ok_or_else(bad)?;
        let l = r.u64().ok_or_else(bad)? as usize;
        let kind = r.take(1).ok_or_else(bad)?[0];
        let n = r.u64().ok_or_else(bad)? as usize;
        let cells = if kind == 1 {
            let mut z = ZHist::with_capacity(n.min(1 << 24));
            for _ in 0..n {
                z.push((r.i64().ok_or_else(bad)?, r.i64().ok_or_else(bad)?));
            }
            Cells::Z(z)
        } else {
            let width = r.u64().ok_or_else(bad)? as usize;
            let mut s = SparseHist::new();
            for _ in 0..n {
                let key = (0..width).map(|_| r.i64()).collect::<Option<Vec<_>>>().ok_or_else(bad)?;
                s.insert(key, r.i64().ok_or_else(bad)?);
            }
            Cells::Sparse(s)
        };
        let sens = match r.take(1).ok_or_else(bad)?[0] {
            0 => None,
            _ => {
                let len = r.u64().ok_or_else(bad)? as usize;
                let json = r.take(len).ok_or_else(bad)?;
                let entries: Vec<(Vec<i64>, Vec<Vec<String>>)> = serde_json::from_slice(json).map_err(|_| bad())?;
                Some(entries.into_iter().collect())
            }
        };
        Ok(Self { cells, total, sens, l })
    }
}

/// Interns sensitive values to ids (one table per attribute, shared by every
/// cell). Only the number of distinct values per cell matters to the search.
pub(crate) fn intern_sensitive(sens: &SensCells) -> SensitiveSets {
    let mut interned: Vec<HashMap<&str, u32>> = Vec::new();
    let mut out = SensitiveSets::new();
    for (key, attrs) in sens {
        if interned.len() < attrs.len() {
            interned.resize_with(attrs.len(), HashMap::new);
        }
        let cell = attrs
            .iter()
            .enumerate()
            .map(|(a, vals)| {
                vals.iter()
                    .map(|v| {
                        let next = interned[a].len() as u32;
                        *interned[a].entry(v.as_str()).or_insert(next)
                    })
                    .collect()
            })
            .collect();
        out.insert(key.clone(), cell);
    }
    out
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(s)
    }
    fn i64(&mut self) -> Option<i64> {
        Some(i64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
}

/// `INVALID_BIN` is part of the wire contract: a cell with no bin is `-1`.
const _: () = assert!(INVALID_BIN == -1);
