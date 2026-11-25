//! The model: the quasi-identifier lattice built from the merged [`Stats`],
//! plus everything that searches it.
//!
//! Given the same config and the same merged stats, [`Model::build`] produces
//! the same model on every machine, so a driver can build it once and executors
//! can rebuild it from `(config, stats, max_eq)` instead of shipping it.

use super::histogram::Histogram;
use super::stats::{QiColumns, Stats};
use crate::pipeline::anonymization::{
    GRID_K_VALUES, GRID_SUPPRESSION_LIMITS, LDiversity, Ola2SearchResult, ParameterGrid, QuasiIdentifierLite,
    SensitiveSets, SparseHist, attach_categorical_levels, build_quasi_identifiers, categorical_ladder_len,
    compute_equivalence_space, compute_k_optimal, compute_parameter_grid_for, compute_z_weights, find_ola1_initial_ri,
    find_ola2_with, l_aware_class_sizes, merge_histogram, merge_z_histogram,
};
use crate::pipeline::bootstrap::{
    FlowMode, HierarchyMap, PipelineError, RuntimeConfig, available_ram_bytes, validation,
};
use std::collections::{BTreeMap, HashMap};

/// The quasi-identifier model of one run.
#[derive(Debug, Clone)]
pub struct Model {
    /// Quasi-identifiers, numeric first then categorical, with their
    /// hierarchies and categorical levels attached.
    pub qis: Vec<QuasiIdentifierLite>,
    /// Sorted categorical domains by QI position (empty for numeric QIs).
    pub domains: Vec<Vec<String>>,
    /// Data rows the stats covered.
    pub total_rows: i64,
    /// Product of every QI's range (E in the flow decision).
    pub equivalence_space: f64,
    /// N·log₂N of the flow decision.
    pub n_log_n: f64,
    /// Whether the DIRECT flow was asked for (by `flow_mode`, or by `auto`
    /// since N·log₂N ≤ E) before the weights were checked to fit.
    pub direct_requested: bool,
    /// Mixed-radix weights; `Some` means the DIRECT flow (Z-encoded histogram
    /// at the finest granularity).
    pub weights: Option<Vec<i64>>,
    /// Where the lattice search starts: all ones in the DIRECT flow, the OLA-1
    /// result otherwise.
    pub initial_ri: Vec<i64>,
    /// `max_eq` OLA-1 used (`None` in the DIRECT flow). Passing it back to
    /// [`Model::build`] reproduces the model without consulting the machine's
    /// free RAM again.
    pub max_eq: Option<i64>,
    pub size_factors: HashMap<String, i64>,
    pub hierarchies: HierarchyMap,
    pub l_diversity: Option<LDiversity>,
    /// `k` and `suppression_limit` from the config, as defaults.
    pub k: i64,
    pub suppression_limit: f64,
}

impl Model {
    /// The quasi-identifiers alone, from the config and the scanned ranges —
    /// no domains, no levels. Enough to validate a chosen node.
    pub fn qis_only(cfg: &RuntimeConfig, stats: &Stats) -> Result<Vec<QuasiIdentifierLite>, PipelineError> {
        let cols = QiColumns::from_config(cfg);
        build_quasi_identifiers(cfg, &stats.min_max(&cols))
    }

    /// Builds the model and decides the histogram flow.
    ///
    /// `max_eq` is OLA-1's memory bound on equivalence classes; `None` derives
    /// it from the machine's free RAM, which is what the command line does.
    ///
    /// # Errors
    /// No quasi-identifiers; a categorical ladder that does not nest;
    /// `ANON_INFEASIBLE` / `LATTICE_TOO_LARGE` from OLA-1.
    pub fn build(cfg: &RuntimeConfig, stats: &Stats, max_eq: Option<i64>) -> Result<Self, PipelineError> {
        let mut qis = Self::qis_only(cfg, stats)?;
        let domains = stats.domains();
        attach_categorical_levels(&mut qis, &domains, &cfg.categorical_hierarchies)?;

        let n = stats.rows;
        let e = compute_equivalence_space(&qis, &domains);
        let n_log_n = (n as f64) * (n as f64).log2().max(0.0);
        let direct_requested = match cfg.flow_mode {
            FlowMode::Auto => n_log_n <= e,
            FlowMode::Original => false,
            FlowMode::Direct => true,
        };
        // Z weights that overflow i64 fall back to the ORIGINAL flow.
        let weights = if direct_requested { compute_z_weights(&qis, &domains) } else { None };
        let (initial_ri, max_eq) = if weights.is_some() {
            (vec![1i64; qis.len()], None)
        } else {
            let max_eq = max_eq.unwrap_or_else(|| (available_ram_bytes().unwrap_or(32_000_000) / 32) as i64);
            (find_ola1_initial_ri(&qis, 0, max_eq, &cfg.size_factors)?, Some(max_eq))
        };
        Ok(Self {
            qis,
            domains,
            total_rows: n,
            equivalence_space: e,
            n_log_n,
            direct_requested,
            weights,
            initial_ri,
            max_eq,
            size_factors: cfg.size_factors.clone(),
            hierarchies: cfg.categorical_hierarchies.clone(),
            l_diversity: cfg.l_diversity.clone(),
            k: cfg.k,
            suppression_limit: cfg.suppression_limit,
        })
    }

    /// An empty histogram for this model.
    pub fn new_histogram(&self) -> Histogram {
        Histogram::new(self)
    }

    /// Maps a `generalization_node` given by column name (the shape a grid
    /// cell carries) onto QI order, checking that it names every QI, nothing
    /// else, and only levels each QI actually has.
    pub fn node_from_names(&self, chosen: &BTreeMap<String, i64>) -> Result<Vec<i64>, PipelineError> {
        node_from_names(chosen, &self.qis, &self.hierarchies)
    }

    /// The l-diversity view the search needs: the base histogram as a sparse
    /// map and the sensitive values interned.
    fn l_view(&self, hist: &Histogram) -> Result<Option<(SparseHist, SensitiveSets, usize)>, PipelineError> {
        let Some(l) = &self.l_diversity else { return Ok(None) };
        let sparse = hist.to_sparse(self);
        let sens = hist.sensitive_sets().ok_or_else(|| {
            validation(
                "BATCH_SHAPE_MISMATCH",
                "The histogram carries no sensitive values but l-diversity is set",
                "l_diversity",
            )
        })?;
        Ok(Some((sparse, sens, l.l)))
    }

    /// The k × suppression_limit grid: the best node for each of the standard
    /// (k, σ) pairs, found by one multi-combination OLA-2 over the merged
    /// histogram. This is "explore k first": pick a cell, then call
    /// [`Model::search`] or generalise at its node.
    pub fn parameter_grid(&self, hist: &Histogram) -> Result<ParameterGrid, PipelineError> {
        self.parameter_grid_for(hist, GRID_K_VALUES, GRID_SUPPRESSION_LIMITS)
    }

    /// [`Model::parameter_grid`] over caller-chosen k values and limits.
    pub fn parameter_grid_for(
        &self,
        hist: &Histogram,
        ks: &[i64],
        sigmas: &[f64],
    ) -> Result<ParameterGrid, PipelineError> {
        let total = hist.total;
        if let Some((sparse, sens, l)) = self.l_view(hist)? {
            return compute_parameter_grid_for(
                &self.qis,
                &self.initial_ri,
                &self.size_factors,
                total,
                ks,
                sigmas,
                |node| l_aware_class_sizes(&sparse, &sens, &self.qis, node, l),
            );
        }
        compute_parameter_grid_for(&self.qis, &self.initial_ri, &self.size_factors, total, ks, sigmas, |node| {
            self.class_sizes(hist, node)
        })
    }

    /// OLA-2 for one `(k, suppression_limit)` over the merged histogram: the
    /// node with the lowest DM* whose suppression stays within the limit.
    pub fn search(&self, hist: &Histogram, k: i64, suppression_limit: f64) -> Result<Ola2SearchResult, PipelineError> {
        let total = hist.total;
        if let Some((sparse, sens, l)) = self.l_view(hist)? {
            return find_ola2_with(
                &self.qis,
                &self.initial_ri,
                &self.size_factors,
                k,
                suppression_limit,
                total,
                |node| l_aware_class_sizes(&sparse, &sens, &self.qis, node, l),
            );
        }
        find_ola2_with(&self.qis, &self.initial_ri, &self.size_factors, k, suppression_limit, total, |node| {
            self.class_sizes(hist, node)
        })
    }

    /// Largest k whose suppression at the coarsest node stays within
    /// `suppression_limit` (pass 1's `k_optimal`).
    pub fn k_optimal(&self, hist: &Histogram, suppression_limit: f64) -> i64 {
        compute_k_optimal(&self.qis, &hist.to_sparse(self), suppression_limit, hist.total)
    }

    /// Class sizes of the histogram merged to `node`.
    fn class_sizes(&self, hist: &Histogram, node: &[i64]) -> Vec<i64> {
        match (&hist.cells, &self.weights) {
            (super::histogram::Cells::Z(zh), Some(w)) => {
                merge_z_histogram(zh, &self.qis, w, node).into_iter().map(|(_, c)| c).collect()
            }
            (super::histogram::Cells::Sparse(h), _) => merge_histogram(h, &self.qis, node).into_values().collect(),
            // A Z histogram without weights cannot be built; Histogram::new never makes one.
            (super::histogram::Cells::Z(_), None) => Vec::new(),
        }
    }

    /// The histogram merged to `node`, as sparse class keys → sizes (for logs
    /// and diagnostics).
    pub fn merged_sparse(&self, hist: &Histogram, node: &[i64]) -> SparseHist {
        merge_histogram(&hist.to_sparse(self), &self.qis, node)
    }
}

/// See [`Model::node_from_names`].
pub fn node_from_names(
    chosen: &BTreeMap<String, i64>,
    qis: &[QuasiIdentifierLite],
    hierarchies: &HierarchyMap,
) -> Result<Vec<i64>, PipelineError> {
    let invalid = |message: &str, details: String| validation("CONFIG_INVALID_VALUE", message, &details);
    let names_qi = |col: &str| qis.iter().any(|q| q.column_name == col);
    let unknown: Vec<&str> = chosen.keys().map(String::as_str).filter(|c| !names_qi(c)).collect();
    if !unknown.is_empty() {
        return Err(invalid("generalization_node names columns that are not quasi-identifiers", unknown.join(", ")));
    }

    let mut final_rf = Vec::with_capacity(qis.len());
    for qi in qis {
        let level = chosen
            .get(&qi.column_name)
            .copied()
            .ok_or_else(|| invalid("generalization_node is missing a quasi-identifier", qi.column_name.clone()))?;
        let max_level = if let Some(h) = &qi.interval_hierarchy {
            h.num_levels as i64
        } else if qi.is_categorical {
            categorical_ladder_len(&qi.column_name, hierarchies) as i64 + 2
        } else {
            let (mn, mx) = (qi.min_value.unwrap_or(0.0), qi.max_value.unwrap_or(0.0));
            ((mx.round() - mn.floor() + 1.0) as i64).max(1)
        };
        if level > max_level {
            return Err(invalid(
                "generalization_node level is beyond what this quasi-identifier supports",
                format!("{}: {} (max {})", qi.column_name, level, max_level),
            ));
        }
        final_rf.push(level);
    }
    Ok(final_rf)
}
