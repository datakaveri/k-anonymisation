use super::generalization::generalize_categorical_label;
use crate::pipeline::bootstrap::{HierarchyMap, PipelineError, open_csv, validation};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;

// ── Non-uniform interval hierarchy ───────────────────────────────────────────

/// Precomputed halving hierarchy for a single non-uniform-interval QI.
///
/// Levels are 1-indexed: `levels[1]` = finest (all intervals with width ≈ 1),
/// `levels[num_levels]` = coarsest (the user-supplied intervals).
/// `ancestor_at[fine_idx][level]` gives the interval index at `level` for a
/// fine interval originally indexed `fine_idx`.
#[derive(Debug, Clone)]
pub struct IntervalHierarchy {
    pub levels: Vec<Vec<(i64, i64)>>, // 1-indexed; levels[0] is unused
    pub ancestor_at: Vec<Vec<usize>>, // [fine_idx][level] → coarse idx
    pub num_levels: usize,
}

impl IntervalHierarchy {
    /// Map a raw data value to its fine (level-1) interval index.
    /// Returns `None` if the value falls outside all intervals.
    /// Uses binary search — O(log n) per call.
    pub fn value_to_fine_index(&self, value: i64) -> Option<usize> {
        let lv = &self.levels[1];
        let mut lo = 0usize;
        let mut hi = lv.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let (f, t) = lv[mid];
            if value < f {
                hi = mid;
            } else if value > t {
                lo = mid + 1;
            } else {
                return Some(mid);
            }
        }
        None
    }

    /// Number of intervals at `level` (1-indexed).
    pub fn num_at(&self, level: usize) -> usize {
        self.levels.get(level).map(|v| v.len()).unwrap_or(1)
    }

    /// Interval label at `level` for interval index `idx`.
    pub fn label(&self, level: usize, idx: usize) -> String {
        if let Some(lv) = self.levels.get(level)
            && let Some(&(f, t)) = lv.get(idx)
        {
            return if f == t { format!("[{}]", f) } else { format!("[{}-{}]", f, t) };
        }
        "*".to_string()
    }
}

/// Split each interval into `n` roughly-equal parts.
/// The last sub-interval absorbs any remainder so no gap is introduced.
/// Intervals with width < n are left unchanged (cannot be split into n parts).
fn split_intervals_n(intervals: &[(i64, i64)], n: usize) -> Vec<(i64, i64)> {
    let n = n.max(2) as i64;
    let mut out = Vec::new();
    for &(from, to) in intervals {
        let width = to - from + 1;
        if width < n {
            out.push((from, to));
        } else {
            let part = width / n;
            for i in 0..n {
                let f = from + i * part;
                let t = if i == n - 1 { to } else { f + part - 1 };
                out.push((f, t));
            }
        }
    }
    out
}

/// Build a multi-level refinement hierarchy from user-supplied coarse intervals.
///
/// `split_factor` controls how many parts each interval is divided into at each
/// step (2 = halving, 10 = decile split, etc.).  Splitting stops when the minimum
/// interval width would drop below `split_factor`, i.e.
///   `num_splits = floor(log_n(min_width))`
/// giving `num_levels = 1 + num_splits`.
pub fn build_interval_hierarchy(user_intervals: Vec<(i64, i64)>, split_factor: usize) -> IntervalHierarchy {
    let n = split_factor.max(2);
    let min_width = user_intervals.iter().map(|&(f, t)| (t - f + 1).max(1)).min().unwrap_or(1);
    let num_splits =
        if min_width < n as i64 { 0 } else { ((min_width as f64).ln() / (n as f64).ln()).floor() as usize };
    let num_levels = 1 + num_splits;

    // Build from coarsest (user) down to finest, then reverse
    let mut raw: Vec<Vec<(i64, i64)>> = vec![user_intervals];
    for _ in 0..num_splits {
        let prev = raw.last().unwrap().clone();
        raw.push(split_intervals_n(&prev, n));
    }
    raw.reverse(); // raw[0] = finest, raw[num_splits] = coarsest

    // 1-indexed: levels[0] unused, levels[1] = finest, levels[num_levels] = coarsest
    let mut levels: Vec<Vec<(i64, i64)>> = vec![vec![]];
    for lv in raw {
        levels.push(lv);
    }

    let fine_count = levels[1].len();
    // ancestor_at[fine_idx][level] = interval index at that level (binary search per level)
    let mut ancestor_at: Vec<Vec<usize>> = vec![vec![0usize; num_levels + 1]; fine_count];
    for fine_idx in 0..fine_count {
        let (fine_from, _) = levels[1][fine_idx];
        ancestor_at[fine_idx][1] = fine_idx;
        for level in 2..=num_levels {
            let lv = &levels[level];
            let mut lo = 0usize;
            let mut hi = lv.len();
            let mut found = 0usize;
            while lo < hi {
                let mid = lo + (hi - lo) / 2;
                let (f, t) = lv[mid];
                if fine_from < f {
                    hi = mid;
                } else if fine_from > t {
                    lo = mid + 1;
                } else {
                    found = mid;
                    break;
                }
            }
            ancestor_at[fine_idx][level] = found;
        }
    }

    IntervalHierarchy { levels, ancestor_at, num_levels }
}

/// Build a single-level hierarchy from user-supplied fixed bin boundaries.
///
/// The resulting `IntervalHierarchy` has `num_levels = 1`, so `build_tree_levels`
/// will never expand this dimension (max_level = 1, initial = 1 → already at max).
/// The QI participates in equivalence-class keys (histogram includes its bin index)
/// but is excluded from the OLA-2 lattice search.
pub fn build_fixed_interval_hierarchy(mut intervals: Vec<(i64, i64)>) -> IntervalHierarchy {
    intervals.sort_by_key(|&(f, _)| f);
    let fine_count = intervals.len();

    // 1-indexed: levels[0] unused, levels[1] = user's fixed bins (the only level)
    let levels = vec![vec![], intervals];

    // ancestor_at[i][1] = i (each bin maps to itself — no merging)
    let ancestor_at: Vec<Vec<usize>> = (0..fine_count).map(|i| vec![0, i]).collect();

    IntervalHierarchy { levels, ancestor_at, num_levels: 1 }
}

// ── Categorical generalization levels ────────────────────────────────────────

/// How one categorical QI's observed values group together at each
/// generalization level, derived from the same labels the output step writes.
///
/// Levels are 1-indexed: `group_at[1]` keeps every value distinct,
/// `group_at[num_levels]` is the coarsest. `group_at[level][domain_pos]` is the
/// group id of the value at `domain_pos` in the column's sorted domain; ids are
/// assigned in first-seen order, so two levels that group values identically
/// have identical vectors.
#[derive(Debug, Clone)]
pub struct CategoricalLevels {
    pub group_at: Vec<Vec<i64>>, // 1-indexed; group_at[0] is unused
    pub num_levels: usize,
}

/// Number of entries in the longest ladder configured for `column` under
/// `categorical_hierarchies` (0 when the column has none).
///
/// Level `L` (2 ≤ L ≤ len + 1) writes ladder entry `L - 2` and every level
/// beyond that writes `"*"`, so no level above `len + 2` can change the output.
pub fn categorical_ladder_len(column: &str, hierarchies: &HierarchyMap) -> usize {
    hierarchies.get(&column.trim().to_lowercase()).and_then(|m| m.values().map(Vec::len).max()).unwrap_or(0)
}

/// Builds the level → grouping table for one categorical QI over its observed
/// `domain`, by generalizing every value exactly as the output step will.
///
/// OLA-2 previously grouped values by `domain_pos / level`, i.e. alphabetical
/// neighbours, which neither matched the labels written out nor nested across
/// levels. Deriving the grouping from the labels makes the classes OLA-2 counts
/// the classes that actually end up in the output.
pub fn build_categorical_levels(column: &str, domain: &[String], hierarchies: &HierarchyMap) -> CategoricalLevels {
    let top = categorical_ladder_len(column, hierarchies) + 2;
    let mut group_at: Vec<Vec<i64>> = vec![vec![]];
    for level in 1..=top {
        let mut ids: HashMap<String, i64> = HashMap::new();
        let groups = domain
            .iter()
            .map(|v| {
                let label = generalize_categorical_label(hierarchies, column, v, level as i64);
                let next = ids.len() as i64;
                *ids.entry(label).or_insert(next)
            })
            .collect();
        group_at.push(groups);
    }
    // A top level that groups exactly like the one below it only adds lattice
    // nodes with identical equivalence classes.
    while group_at.len() > 2 && group_at[group_at.len() - 1] == group_at[group_at.len() - 2] {
        group_at.pop();
    }
    let num_levels = group_at.len() - 1;
    CategoricalLevels { group_at, num_levels }
}

/// Attaches a [`CategoricalLevels`] table to every categorical QI.
/// `categorical_domains` is indexed by QI position, as returned by
/// [`scan_chunks_for_flow`].
///
/// # Errors
/// `CONFIG_INVALID_VALUE` when a column's ladder does not nest — two values
/// that share a label at one level are split at a coarser one. OLA-2's
/// pass/fail tagging assumes generalising never splits a class, so a
/// non-nesting ladder would make it skip nodes on false inferences.
pub fn attach_categorical_levels(
    qis: &mut [QuasiIdentifierLite],
    categorical_domains: &[Vec<String>],
    hierarchies: &HierarchyMap,
) -> Result<(), PipelineError> {
    for (i, qi) in qis.iter_mut().enumerate() {
        if !qi.is_categorical {
            continue;
        }
        let domain = categorical_domains.get(i).map(Vec::as_slice).unwrap_or(&[]);
        let levels = build_categorical_levels(&qi.column_name, domain, hierarchies);
        check_categorical_nesting(&qi.column_name, domain, hierarchies, &levels)?;
        qi.categorical_levels = Some(levels);
    }
    Ok(())
}

fn check_categorical_nesting(
    column: &str,
    domain: &[String],
    hierarchies: &HierarchyMap,
    levels: &CategoricalLevels,
) -> Result<(), PipelineError> {
    for level in 1..levels.num_levels {
        let mut parent_of: HashMap<i64, usize> = HashMap::new();
        for (pos, &group) in levels.group_at[level].iter().enumerate() {
            let first = *parent_of.entry(group).or_insert(pos);
            if levels.group_at[level + 1][first] != levels.group_at[level + 1][pos] {
                let label =
                    |p: usize, l: usize| generalize_categorical_label(hierarchies, column, &domain[p], l as i64);
                return Err(validation(
                    "CONFIG_INVALID_VALUE",
                    "categorical_hierarchies ladder does not nest",
                    &format!(
                        "{column}: values labelled '{}' at level {level} are split between '{}' and '{}' at level {}",
                        label(pos, level),
                        label(first, level + 1),
                        label(pos, level + 1),
                        level + 1
                    ),
                ));
            }
        }
    }
    Ok(())
}

// ── Value parsing shared by every stage ──────────────────────────────────────
//
// OLA-2 scores the classes it predicts from the histogram; the output step
// counts the classes it actually writes. The two only agree if every stage
// reads a cell the same way, so the rules live here and nowhere else.

/// Largest magnitude a numeric QI value may have. Beyond 2^53 an f64 cannot
/// tell neighbouring integers apart, so bins would silently merge.
pub const MAX_NUMERIC_QI_MAGNITUDE: f64 = 9_007_199_254_740_992.0;

/// Histogram coordinate for a QI cell that has no bin: an unparseable or
/// out-of-range number, or a value outside every configured interval. It is
/// never merged with a real bin, at any level, and the output writes it as `*`.
pub const INVALID_BIN: i64 = -1;

/// Parses a numeric QI cell: trimmed, finite, within ±2^53, rounded to the
/// nearest integer. `None` means the cell has no usable number.
pub fn parse_numeric_qi(raw: &str) -> Option<i64> {
    let v: f64 = raw.trim().parse().ok()?;
    if !v.is_finite() || v.abs() > MAX_NUMERIC_QI_MAGNITUDE {
        return None;
    }
    Some(v.round() as i64)
}

/// Canonical form of a categorical QI value: surrounding whitespace removed and
/// Unicode NFC, so `" M"`, `"M"` and differently composed accents are one value.
pub fn normalize_categorical(raw: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    raw.trim().nfc().collect()
}

/// Whether `suppressed` records fit within `suppression_limit` of `total`.
///
/// Compared in whole records: `0.29 × 100` is `28.999…` in f64, and a float
/// comparison would reject exactly 29.
pub fn within_suppression_limit(suppressed: i64, suppression_limit: f64, total: i64) -> bool {
    suppressed <= allowed_suppressions(suppression_limit, total)
}

/// Most records `suppression_limit` allows out of `total`.
pub fn allowed_suppressions(suppression_limit: f64, total: i64) -> i64 {
    (suppression_limit * total as f64 + 1e-9).floor().max(0.0) as i64
}

// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct QuasiIdentifierLite {
    pub column_name: String,
    pub is_categorical: bool,
    pub min_value: Option<f64>,
    pub max_value: Option<f64>,
    /// Non-None when this QI uses user-defined non-uniform intervals instead of
    /// uniform bin-width generalization.
    pub interval_hierarchy: Option<IntervalHierarchy>,
    /// Set on categorical QIs by [`attach_categorical_levels`] once the domain
    /// is known. When absent, categorical merges fall back to `domain_pos / level`.
    pub categorical_levels: Option<CategoricalLevels>,
}

/// Index of base-histogram coordinate `u` for QI `qi` once generalized to
/// `level` (an interval/categorical level, or a raw bin width for uniform numerics).
#[inline]
fn generalized_index(qi: Option<&QuasiIdentifierLite>, u: i64, level: i64) -> i64 {
    if u == INVALID_BIN {
        return INVALID_BIN;
    }
    if let Some(h) = qi.and_then(|q| q.interval_hierarchy.as_ref()) {
        let l = (level as usize).clamp(1, h.num_levels);
        return h.ancestor_at.get(u as usize).and_then(|a| a.get(l)).copied().unwrap_or(0) as i64;
    }
    if let Some(c) = qi.and_then(|q| q.categorical_levels.as_ref()) {
        let l = (level as usize).clamp(1, c.num_levels);
        return c.group_at[l].get(u as usize).copied().unwrap_or(0);
    }
    if qi.is_some_and(|q| q.is_categorical) {
        // A categorical QI without levels has a single level: its raw values.
        return u;
    }
    u / level.max(1)
}

impl QuasiIdentifierLite {
    fn get_range(&self) -> f64 {
        match (self.min_value, self.max_value) {
            (Some(a), Some(b)) => (b.round() - a.floor() + 1.0).max(1.0),
            _ => 1.0,
        }
    }

    /// Origin of this numeric QI's bins: the floor of its global minimum.
    pub fn bin_origin(&self) -> i64 {
        self.min_value.unwrap_or(0.0).floor() as i64
    }

    /// Base-histogram coordinate of one cell of this QI: a numeric offset from
    /// the bin origin, a fine interval index, or a categorical domain position
    /// (`domain` is the column's sorted, normalised domain). [`INVALID_BIN`]
    /// when the cell has no bin. Categorical values missing from `domain`
    /// cannot happen for a domain scanned from the same data, and are an error.
    pub fn base_coordinate(&self, raw: &str, domain: &[String]) -> Result<i64, PipelineError> {
        if let Some(h) = &self.interval_hierarchy {
            return Ok(parse_numeric_qi(raw).and_then(|v| h.value_to_fine_index(v)).map_or(INVALID_BIN, |i| i as i64));
        }
        if self.is_categorical {
            let v = normalize_categorical(raw);
            return domain.binary_search(&v).map(|p| p as i64).map_err(|_| {
                validation(
                    "GENERALIZATION_FAILED",
                    "Categorical value missing from the scanned domain",
                    &self.column_name,
                )
            });
        }
        Ok(parse_numeric_qi(raw).map_or(INVALID_BIN, |v| v - self.bin_origin()))
    }
}

pub type SparseHist = HashMap<Vec<i64>, i64>;

/// Z-encoded histogram for the DIRECT flow.
/// Entries are (z_value, count), sorted by z_value in ascending order.
/// Every entry has count ≥ 1 and all z_values are strictly increasing.
pub type ZHist = Vec<(i64, i64)>;

#[derive(Debug, Clone, Serialize)]
pub struct Ola2NodeScore {
    pub node: Vec<i64>,
    pub dm_star: i64,
    pub num_equivalence_classes: i64,
    pub suppression_count: i64,
}

/// One entry per node actually evaluated by the OLA-2 binary search.
/// Nodes inferred via monotonicity propagation are NOT included — only nodes
/// that triggered a real `merge_histogram` call.
#[derive(Debug, Clone, Serialize)]
pub struct NodeTrace {
    pub node: Vec<i64>,
    pub suppression_count: i64,
    pub dm_star: i64,
    pub num_equivalence_classes: i64,
    pub passes: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Ola2SearchResult {
    pub best_rf: Vec<i64>,
    pub lowest_dm_star: i64,
    pub num_equivalence_classes: i64,
    pub top_nodes: Vec<Ola2NodeScore>,
    /// Trace of every node directly evaluated (not inferred) during the search.
    pub node_trace: Vec<NodeTrace>,
    /// Nodes in the generalisation lattice that was searched.
    pub lattice_size: usize,
}

fn ceil_div_i64(a: i64, b: i64) -> i64 {
    let aa = a.max(0);
    let bb = b.max(1);
    (aa + bb - 1) / bb
}

/// Number of generalisation levels a categorical QI has (1 when no
/// [`CategoricalLevels`] are attached: the raw values only).
fn categorical_num_levels(qi: &QuasiIdentifierLite) -> i64 {
    qi.categorical_levels.as_ref().map_or(1, |c| c.num_levels as i64)
}

/// Estimated number of equivalence classes at `node`, used by OLA-1 to keep
/// the base histogram within memory.
fn calculate_equivalence_classes_ola1(qis: &[QuasiIdentifierLite], node: &[i64]) -> Result<i64, PipelineError> {
    if node.len() != qis.len() {
        return Err(validation("GENERALIZATION_FAILED", "bin width length mismatch", "OLA-1"));
    }
    let mut classes = 1_i64;
    for (qi, &v) in qis.iter().zip(node) {
        let v = v.max(1);
        let bins = if let Some(h) = &qi.interval_hierarchy {
            h.num_at((v as usize).clamp(1, h.num_levels)) as i64
        } else if let Some(c) = &qi.categorical_levels {
            let l = (v as usize).clamp(1, c.num_levels);
            c.group_at[l].iter().copied().max().map_or(1, |m| m + 1)
        } else if qi.is_categorical {
            1
        } else {
            ceil_div_i64((qi.get_range().ceil() as i64).max(1), v)
        };
        classes = classes.saturating_mul(bins.max(1));
    }
    Ok(classes.max(1))
}

// ── Generalisation lattice ───────────────────────────────────────────────────

/// Ceiling on lattice size. The search keeps every node in memory and may
/// merge the histogram once per node; beyond this it cannot finish in
/// reasonable time or memory, so it fails up front instead of hanging.
pub const MAX_LATTICE_NODES: u128 = 1_000_000;

/// Next generalisation level of one QI after `value`, or `None` at the top.
fn next_level(
    qi: &QuasiIdentifierLite,
    value: i64,
    size_factors: &HashMap<String, i64>,
) -> Result<Option<i64>, PipelineError> {
    if let Some(h) = &qi.interval_hierarchy {
        return Ok((value < h.num_levels as i64).then_some(value + 1));
    }
    if qi.is_categorical {
        return Ok((value < categorical_num_levels(qi)).then_some(value + 1));
    }
    let factor = size_factors.get(&qi.column_name).copied().ok_or_else(|| {
        validation(
            "GENERALIZATION_FAILED",
            "Missing size factor for numeric QI",
            &format!("add \"size\": {{\"{}\": <factor ≥ 2>}} to the config", qi.column_name),
        )
    })?;
    let top = (qi.get_range().ceil() as i64).max(1);
    let next = value.saturating_mul(factor.max(1)).min(top).max(1);
    Ok((next != value).then_some(next))
}

/// Every node reachable from an initial node by generalising one QI one step
/// at a time, grouped by distance from the initial node.
///
/// `succ[i]` holds the nodes one step more general than node `i`, `pred[i]`
/// the nodes one step less general. A node's up-set (everything at least as
/// general in every QI) is exactly what is reachable through `succ`, so
/// predictive tagging can walk the graph instead of scanning the lattice.
pub(crate) struct Lattice {
    pub nodes: Vec<Vec<i64>>,
    pub levels: Vec<Vec<usize>>,
    pub level_of: Vec<usize>,
    pub succ: Vec<Vec<usize>>,
    pub pred: Vec<Vec<usize>>,
}

impl Lattice {
    pub fn build(
        qis: &[QuasiIdentifierLite],
        initial: &[i64],
        size_factors: &HashMap<String, i64>,
    ) -> Result<Self, PipelineError> {
        if qis.len() != initial.len() {
            return Err(validation("GENERALIZATION_FAILED", "initial node length mismatch", "lattice"));
        }
        // Size the lattice before materialising it: it is the product of the
        // per-QI chain lengths.
        let mut size: u128 = 1;
        for (qi, &start) in qis.iter().zip(initial) {
            let mut levels: u128 = 1;
            let mut v = start;
            while let Some(n) = next_level(qi, v, size_factors)? {
                v = n;
                levels += 1;
            }
            size = size.saturating_mul(levels);
        }
        if size > MAX_LATTICE_NODES {
            return Err(validation(
                "LATTICE_TOO_LARGE",
                "The generalisation lattice is too large to search",
                &format!(
                    "{size} nodes (limit {MAX_LATTICE_NODES}) — use fewer quasi-identifiers, larger size factors, \
                     or qi_constraints / fixed_bins with fewer levels"
                ),
            ));
        }

        let mut lat = Lattice {
            nodes: vec![initial.to_vec()],
            levels: vec![vec![0]],
            level_of: vec![0],
            succ: vec![vec![]],
            pred: vec![vec![]],
        };
        let mut index: HashMap<Vec<i64>, usize> = HashMap::from([(initial.to_vec(), 0)]);
        loop {
            let mut next = Vec::new();
            for &at in lat.levels.last().expect("at least one level").clone().iter() {
                for (i, qi) in qis.iter().enumerate() {
                    let Some(v) = next_level(qi, lat.nodes[at][i], size_factors)? else { continue };
                    let mut node = lat.nodes[at].clone();
                    node[i] = v;
                    let id = match index.get(&node) {
                        Some(&id) => id,
                        None => {
                            let id = lat.nodes.len();
                            index.insert(node.clone(), id);
                            lat.nodes.push(node);
                            lat.level_of.push(lat.levels.len());
                            lat.succ.push(vec![]);
                            lat.pred.push(vec![]);
                            next.push(id);
                            id
                        }
                    };
                    lat.succ[at].push(id);
                    lat.pred[id].push(at);
                }
            }
            if next.is_empty() {
                break;
            }
            lat.levels.push(next);
        }
        Ok(lat)
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Settles every unsettled node above (`up`) or below `start` with
    /// `value`, through `settle`, which returns false for nodes already
    /// settled — the walk does not continue past those, since their own
    /// up- or down-set was settled when they were.
    fn propagate(&self, start: usize, up: bool, mut settle: impl FnMut(usize) -> bool) {
        let mut stack = vec![start];
        while let Some(i) = stack.pop() {
            let next = if up { &self.succ[i] } else { &self.pred[i] };
            for &j in next {
                if settle(j) {
                    stack.push(j);
                }
            }
        }
    }
}

pub fn find_ola1_initial_ri(
    qis: &[QuasiIdentifierLite],
    _n_chunks: i64,
    max_eq: i64,
    size_factors: &HashMap<String, i64>,
) -> Result<Vec<i64>, PipelineError> {
    if qis.is_empty() {
        return Err(validation(
            "ANON_NO_QIS",
            "No quasi-identifiers defined — cannot run OLA-1",
            "Add at least one QI to quasi_identifiers in config",
        ));
    }
    if max_eq <= 0 {
        return Err(validation("GENERALIZATION_FAILED", "max_eq must be > 0", "OLA-1"));
    }

    let lattice = Lattice::build(qis, &vec![1_i64; qis.len()], size_factors)?;
    let mut passing = Vec::new();
    for node in &lattice.nodes {
        if calculate_equivalence_classes_ola1(qis, node)? <= max_eq {
            passing.push(node.clone());
        }
    }
    passing.sort();
    passing.into_iter().next().ok_or_else(|| {
        validation(
            "ANON_INFEASIBLE",
            "No generalization satisfies the equivalence class memory constraint (OLA-1)",
            "Increase available RAM, reduce size factors, or reduce the number of QIs",
        )
    })
}

// ── Column resolution ────────────────────────────────────────────────────────

/// Position of every QI column in `header`, by exact name.
///
/// The histogram and the output step must agree on which column a QI is, so
/// both resolve through this function. An unresolved QI is an error: a QI
/// that is silently skipped is published ungeneralised and left out of the
/// class key.
pub fn resolve_qi_columns(header: &[String], qis: &[QuasiIdentifierLite]) -> Result<Vec<usize>, PipelineError> {
    qis.iter()
        .map(|qi| {
            header.iter().position(|h| h == &qi.column_name).ok_or_else(|| {
                validation("DATA_COLUMN_MISSING", "Quasi-identifier column not found in CSV header", &qi.column_name)
            })
        })
        .collect()
}

/// Calls `visit` with every data row of every chunk, after checking each
/// chunk's header resolves the QIs and each row has the header's width.
fn for_each_row(
    chunk_paths: &[PathBuf],
    qis: &[QuasiIdentifierLite],
    mut visit: impl FnMut(&[String], &[usize]) -> Result<(), PipelineError>,
) -> Result<(), PipelineError> {
    if chunk_paths.is_empty() {
        return Err(validation("GENERALIZATION_FAILED", "No chunks provided", "histogram"));
    }
    for chunk in chunk_paths {
        let (header, mut records) = open_csv(chunk)?;
        let col_idx = resolve_qi_columns(&header, qis)?;
        while let Some(fields) = records.next_record_of_width(header.len())? {
            visit(&fields, &col_idx)?;
        }
    }
    Ok(())
}

// ── Flow-selection pre-scan ───────────────────────────────────────────────────

/// Single-pass scan over all chunks that produces the two inputs needed to
/// decide the histogram-building strategy:
///
/// - **total record count**.
/// - **categorical domains** — for each QI position `i`, a sorted `Vec<String>`
///   of every distinct normalised value in that column (see
///   [`normalize_categorical`]). Non-categorical positions hold an empty `Vec`.
pub fn scan_chunks_for_flow(
    chunk_paths: &[PathBuf],
    qis: &[QuasiIdentifierLite],
) -> Result<(i64, Vec<Vec<String>>), PipelineError> {
    let mut cat_sets: Vec<BTreeSet<String>> = vec![BTreeSet::new(); qis.len()];
    let mut total: i64 = 0;
    for_each_row(chunk_paths, qis, |fields, col_idx| {
        total += 1;
        for (i, qi) in qis.iter().enumerate() {
            if qi.is_categorical {
                cat_sets[i].insert(normalize_categorical(&fields[col_idx[i]]));
            }
        }
        Ok(())
    })?;
    let categorical_domains = cat_sets.into_iter().map(|s| s.into_iter().collect()).collect();
    Ok((total, categorical_domains))
}

// ── Equivalence-space computation ─────────────────────────────────────────────

/// Computes the total equivalence space E = Π R_Qi where:
/// - Numerical: R_Qi = max − min + 1
/// - Categorical: R_Qi = domain size
/// - Interval: R_Qi = number of finest-level intervals
///
/// Uses `f64` throughout to avoid overflow for large spaces.
/// Returns `f64::INFINITY` when the product overflows.
pub fn compute_equivalence_space(qis: &[QuasiIdentifierLite], categorical_domains: &[Vec<String>]) -> f64 {
    let mut e: f64 = 1.0;
    for (i, qi) in qis.iter().enumerate() {
        let r = if qi.is_categorical {
            let v = categorical_domains.get(i).map(|d| d.len()).unwrap_or(1);
            (v as f64).max(1.0)
        } else if let Some(h) = &qi.interval_hierarchy {
            h.num_at(1) as f64
        } else {
            qi.get_range()
        };
        e *= r;
        if e.is_infinite() {
            break;
        }
    }
    e
}

// ── Histogram builders ────────────────────────────────────────────────────────

/// Base-histogram key of one row: each QI's [`QuasiIdentifierLite::base_coordinate`],
/// with numeric offsets rounded down to a multiple of that QI's `initial_ri`
/// (the bin start), so `key / width` lands on the bin the output step writes
/// for any lattice width, which is always a multiple of `initial_ri`.
fn base_key(
    qis: &[QuasiIdentifierLite],
    fields: &[String],
    col_idx: &[usize],
    initial_ri: &[i64],
    categorical_domains: &[Vec<String>],
) -> Result<Vec<i64>, PipelineError> {
    let mut key = Vec::with_capacity(qis.len());
    for (i, qi) in qis.iter().enumerate() {
        let c = qi.base_coordinate(&fields[col_idx[i]], &categorical_domains[i])?;
        let numeric = !qi.is_categorical && qi.interval_hierarchy.is_none();
        key.push(if numeric && c != INVALID_BIN {
            let step = initial_ri[i].max(1);
            c / step * step
        } else {
            c
        });
    }
    Ok(key)
}

pub fn build_sparse_histogram(
    chunk_paths: &[PathBuf],
    qis: &[QuasiIdentifierLite],
    initial_ri: &[i64],
    categorical_domains: &[Vec<String>],
) -> Result<(SparseHist, i64), PipelineError> {
    if qis.len() != initial_ri.len() {
        return Err(validation("GENERALIZATION_FAILED", "initial_ri length mismatch", "OLA-2"));
    }
    if categorical_domains.len() != qis.len() {
        return Err(validation(
            "GENERALIZATION_FAILED",
            "categorical_domains length mismatch",
            "build_sparse_histogram",
        ));
    }
    let mut hist: SparseHist = HashMap::new();
    let mut total_records: i64 = 0;
    for_each_row(chunk_paths, qis, |fields, col_idx| {
        *hist.entry(base_key(qis, fields, col_idx, initial_ri, categorical_domains)?).or_insert(0) += 1;
        total_records += 1;
        Ok(())
    })?;
    if total_records == 0 {
        return Err(validation(
            "GENERALIZATION_FAILED",
            "No records to anonymize",
            "the input has a header but no rows",
        ));
    }
    Ok((hist, total_records))
}

/// [`build_sparse_histogram`] over QI value tuples instead of chunk files.
///
/// Each item is one tuple of QI cells in QI order, with the number of records
/// holding it. Every tuple goes through the same `base_key` as a chunk row,
/// so a histogram aggregated elsewhere (the k-anonymity block merges per-shard
/// scans) keys and counts exactly as the monolith's would over the same rows.
pub fn build_tuple_histogram<'a>(
    tuples: impl IntoIterator<Item = (&'a [String], i64)>,
    qis: &[QuasiIdentifierLite],
    initial_ri: &[i64],
    categorical_domains: &[Vec<String>],
) -> Result<(SparseHist, i64), PipelineError> {
    if qis.len() != initial_ri.len() || categorical_domains.len() != qis.len() {
        return Err(validation("GENERALIZATION_FAILED", "length mismatch", "build_tuple_histogram"));
    }
    let identity: Vec<usize> = (0..qis.len()).collect();
    let mut hist: SparseHist = HashMap::new();
    let mut total_records: i64 = 0;
    for (tuple, count) in tuples {
        if tuple.len() != qis.len() {
            return Err(validation("GENERALIZATION_FAILED", "QI tuple has the wrong arity", "build_tuple_histogram"));
        }
        *hist.entry(base_key(qis, tuple, &identity, initial_ri, categorical_domains)?).or_insert(0) += count;
        total_records += count;
    }
    if total_records == 0 {
        return Err(validation(
            "GENERALIZATION_FAILED",
            "No records to anonymize",
            "the input has a header but no rows",
        ));
    }
    Ok((hist, total_records))
}

/// Builds a histogram at the finest possible granularity (`initial_ri = [1,…,1]`),
/// bypassing OLA-1 entirely.
pub fn build_direct_histogram(
    chunk_paths: &[PathBuf],
    qis: &[QuasiIdentifierLite],
    categorical_domains: &[Vec<String>],
) -> Result<(SparseHist, i64), PipelineError> {
    build_sparse_histogram(chunk_paths, qis, &vec![1; qis.len()], categorical_domains)
}

// ── Z-encoding DIRECT flow ────────────────────────────────────────────────────
//
// Z is a mixed-radix scalar that uniquely encodes a (u1, u2, ..., uc) tuple:
//   Z = Σ(i=0..c-1)  u_i · W_i
// where W_i = Π(k=i+1 to c-1) R_Qk  and  W_{c-1} = 1.
//
// For numerical QIs:  u_i = offset + 1  ∈ [0, R_Qi]   (0 = no bin)
// For interval QIs:   u_i = fine_index + 1          (0 = outside every interval)
// For categorical:    u_i = domain_position        ∈ [0, R_Qi − 1]
//
// Numeric and interval QIs reserve 0 for [`INVALID_BIN`], so their radix is
// one more than their range.

/// Radix of QI `i` in Z space.
fn z_radix(qi: &QuasiIdentifierLite, domain_len: usize) -> i64 {
    if qi.is_categorical {
        domain_len.max(1) as i64
    } else if let Some(h) = &qi.interval_hierarchy {
        h.num_at(1) as i64 + 1
    } else {
        qi.get_range() as i64 + 1
    }
}

/// Compute mixed-radix weights W_i = Π(k=i+1 to c-1) R_Qk.
/// Returns `None` if the full Z range overflows `i64`.
pub fn compute_z_weights(qis: &[QuasiIdentifierLite], categorical_domains: &[Vec<String>]) -> Option<Vec<i64>> {
    let c = qis.len();
    let ranges: Vec<i64> =
        qis.iter().enumerate().map(|(i, qi)| z_radix(qi, categorical_domains.get(i).map_or(1, Vec::len))).collect();
    let mut weights = vec![1i64; c];
    for i in (0..c.saturating_sub(1)).rev() {
        weights[i] = weights[i + 1].checked_mul(ranges[i + 1])?;
    }
    // The largest Z must fit too, not just the weights.
    weights.first().map_or(Some(()), |w0| w0.checked_mul(*ranges.first()?).map(|_| ()))?;
    Some(weights)
}

/// Z-space coordinate of a base coordinate (and back).
fn to_z(qi: &QuasiIdentifierLite, coord: i64) -> i64 {
    if qi.is_categorical { coord } else { coord + 1 }
}
fn from_z(qi: &QuasiIdentifierLite, u: i64) -> i64 {
    if qi.is_categorical { u } else { u - 1 }
}

/// Encode a normalized u-vector to a single scalar Z.
#[inline]
fn encode_z(u: &[i64], weights: &[i64]) -> i64 {
    u.iter().zip(weights.iter()).map(|(ui, wi)| ui * wi).sum()
}

/// Decode scalar Z back to a normalized u-vector using the precomputed weights.
#[inline]
fn decode_z(mut z: i64, weights: &[i64]) -> Vec<i64> {
    let mut u = Vec::with_capacity(weights.len());
    for &w in weights {
        let ui = z / w;
        z -= ui * w;
        u.push(ui);
    }
    u
}

/// Sort a Vec<i64> of Z values and RLE-compress into a ZHist.
fn collapse_z_values(mut zs: Vec<i64>) -> ZHist {
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

/// Build a Z-encoded histogram at finest granularity.
///
/// Each record is converted to a single Z scalar via mixed-radix encoding.
/// The result is a sorted, RLE-collapsed `ZHist` using at most 16 bytes/entry
/// versus ~40+ bytes/entry for the equivalent `SparseHist`.
pub fn build_z_histogram(
    chunk_paths: &[PathBuf],
    qis: &[QuasiIdentifierLite],
    categorical_domains: &[Vec<String>],
    weights: &[i64],
) -> Result<(ZHist, i64), PipelineError> {
    if categorical_domains.len() != qis.len() || weights.len() != qis.len() {
        return Err(validation("GENERALIZATION_FAILED", "length mismatch", "build_z_histogram"));
    }
    let ones = vec![1; qis.len()];
    let mut zs: Vec<i64> = Vec::new();
    for_each_row(chunk_paths, qis, |fields, col_idx| {
        let key = base_key(qis, fields, col_idx, &ones, categorical_domains)?;
        let u: Vec<i64> = qis.iter().zip(&key).map(|(qi, &c)| to_z(qi, c)).collect();
        zs.push(encode_z(&u, weights));
        Ok(())
    })?;
    if zs.is_empty() {
        return Err(validation(
            "GENERALIZATION_FAILED",
            "No records to anonymize",
            "the input has a header but no rows",
        ));
    }
    let n = zs.len() as i64;
    Ok((collapse_z_values(zs), n))
}

/// Convert a `ZHist` to a `SparseHist` with the same keys
/// [`build_direct_histogram`] would produce.
pub fn z_hist_to_sparse(hist: &ZHist, qis: &[QuasiIdentifierLite], weights: &[i64]) -> SparseHist {
    hist.iter()
        .map(|&(z, count)| {
            let key = decode_z(z, weights).into_iter().zip(qis).map(|(u, qi)| from_z(qi, u)).collect();
            (key, count)
        })
        .collect()
}

/// Merge a `ZHist` to the generalization level described by `node`.
///
/// Analogous to [`merge_histogram`] but stays in Z space throughout, avoiding
/// the per-entry `Vec` allocation cost of `SparseHist`.
pub fn merge_z_histogram(hist: &ZHist, qis: &[QuasiIdentifierLite], weights: &[i64], node: &[i64]) -> ZHist {
    let mut mapped: Vec<(i64, i64)> = hist
        .iter()
        .map(|&(z, count)| {
            let u = decode_z(z, weights);
            let u_prime: Vec<i64> = u
                .iter()
                .zip(qis)
                .enumerate()
                .map(|(i, (&ui, qi))| to_z(qi, generalized_index(Some(qi), from_z(qi, ui), node[i])))
                .collect();
            (encode_z(&u_prime, weights), count)
        })
        .collect();

    mapped.sort_unstable_by_key(|&(z, _)| z);

    let mut out = ZHist::new();
    for (z, count) in mapped {
        match out.last_mut() {
            Some(last) if last.0 == z => last.1 += count,
            _ => out.push((z, count)),
        }
    }
    out
}

pub fn merge_histogram(hist: &SparseHist, qis: &[QuasiIdentifierLite], node: &[i64]) -> SparseHist {
    let mut merged: SparseHist = HashMap::new();
    for (idx, count) in hist {
        let m: Vec<i64> = idx.iter().enumerate().map(|(i, &v)| generalized_index(qis.get(i), v, node[i])).collect();
        *merged.entry(m).or_insert(0) += *count;
    }
    merged
}

// ── l-diversity ──────────────────────────────────────────────────────────────

/// Distinct sensitive values per base-histogram cell: for each cell, one list
/// per sensitive attribute of interned value ids, capped at `l` (more than `l`
/// distinct values never changes a verdict).
pub type SensitiveSets = HashMap<Vec<i64>, Vec<Vec<u32>>>;

/// Adds the values of `src` to `dst` until `dst` holds `l` distinct values.
fn union_capped(dst: &mut Vec<u32>, src: &[u32], l: usize) {
    for &v in src {
        if dst.len() >= l {
            return;
        }
        if !dst.contains(&v) {
            dst.push(v);
        }
    }
}

/// Collects [`SensitiveSets`] keyed exactly like the base histogram built with
/// the same `initial_ri` (so it pairs with [`build_sparse_histogram`], or with
/// [`z_hist_to_sparse`] when `initial_ri` is all ones).
pub fn build_sensitive_sets(
    chunk_paths: &[PathBuf],
    qis: &[QuasiIdentifierLite],
    initial_ri: &[i64],
    categorical_domains: &[Vec<String>],
    sensitive_columns: &[String],
    l: usize,
) -> Result<SensitiveSets, PipelineError> {
    let mut sets: SensitiveSets = HashMap::new();
    let mut interned: Vec<HashMap<String, u32>> = vec![HashMap::new(); sensitive_columns.len()];
    let mut sens_idx: Option<Vec<usize>> = None;
    for chunk in chunk_paths {
        let (header, mut records) = open_csv(chunk)?;
        let col_idx = resolve_qi_columns(&header, qis)?;
        let s_idx: Vec<usize> = sensitive_columns
            .iter()
            .map(|c| {
                header.iter().position(|h| h == c).ok_or_else(|| {
                    validation("DATA_COLUMN_MISSING", "l_diversity sensitive attribute not found in CSV header", c)
                })
            })
            .collect::<Result<_, _>>()?;
        sens_idx.get_or_insert_with(|| s_idx.clone());
        while let Some(fields) = records.next_record_of_width(header.len())? {
            let key = base_key(qis, &fields, &col_idx, initial_ri, categorical_domains)?;
            let cell = sets.entry(key).or_insert_with(|| vec![Vec::new(); sensitive_columns.len()]);
            for (a, &si) in s_idx.iter().enumerate() {
                let next = interned[a].len() as u32;
                let id = *interned[a].entry(normalize_categorical(&fields[si])).or_insert(next);
                union_capped(&mut cell[a], &[id], l);
            }
        }
    }
    Ok(sets)
}

/// [`build_sensitive_sets`] over QI value tuples instead of chunk files.
///
/// Each item is a QI tuple (QI order) with, per sensitive attribute, the
/// distinct normalised values its records hold. Capping a tuple's values at `l`
/// before they reach here loses nothing: a cell only ever needs to know whether
/// it has reached `l`.
pub fn build_tuple_sensitive_sets<'a>(
    tuples: impl IntoIterator<Item = (&'a [String], &'a [Vec<String>])>,
    qis: &[QuasiIdentifierLite],
    initial_ri: &[i64],
    categorical_domains: &[Vec<String>],
    attributes: usize,
    l: usize,
) -> Result<SensitiveSets, PipelineError> {
    let identity: Vec<usize> = (0..qis.len()).collect();
    let mut sets: SensitiveSets = HashMap::new();
    let mut interned: Vec<HashMap<String, u32>> = vec![HashMap::new(); attributes];
    for (tuple, values) in tuples {
        if tuple.len() != qis.len() || values.len() != attributes {
            return Err(validation(
                "GENERALIZATION_FAILED",
                "QI or sensitive tuple has the wrong arity",
                "build_tuple_sensitive_sets",
            ));
        }
        let key = base_key(qis, tuple, &identity, initial_ri, categorical_domains)?;
        let cell = sets.entry(key).or_insert_with(|| vec![Vec::new(); attributes]);
        for (a, vals) in values.iter().enumerate() {
            for v in vals {
                let next = interned[a].len() as u32;
                let id = *interned[a].entry(normalize_categorical(v)).or_insert(next);
                union_capped(&mut cell[a], &[id], l);
            }
        }
    }
    Ok(sets)
}

/// Class sizes at `node`, with every class that is not l-diverse reported as
/// a negative size: it is suppressed whatever k is.
pub fn l_aware_class_sizes(
    base: &SparseHist,
    sensitive: &SensitiveSets,
    qis: &[QuasiIdentifierLite],
    node: &[i64],
    l: usize,
) -> Vec<i64> {
    let mut classes: HashMap<Vec<i64>, (i64, Vec<Vec<u32>>)> = HashMap::new();
    for (key, &count) in base {
        let class: Vec<i64> = key.iter().enumerate().map(|(i, &v)| generalized_index(qis.get(i), v, node[i])).collect();
        let entry = classes.entry(class).or_insert_with(|| (0, Vec::new()));
        entry.0 += count;
        if let Some(cell) = sensitive.get(key) {
            if entry.1.is_empty() {
                entry.1 = vec![Vec::new(); cell.len()];
            }
            for (dst, src) in entry.1.iter_mut().zip(cell) {
                union_capped(dst, src, l);
            }
        }
    }
    classes
        .into_values()
        .map(|(count, sets)| if !sets.is_empty() && sets.iter().all(|s| s.len() >= l) { count } else { -count })
        .collect()
}

// ── Scoring ──────────────────────────────────────────────────────────────────

/// Suppression, DM* and EC count of one merged node at one k.
#[derive(Debug, Clone, Copy, Default)]
struct KStats {
    suppressed: i64,
    dm_star: i64,
    num_equivalence_classes: i64,
}

/// Scores every k in `ks` in a single pass over a merged node's class sizes.
///
/// A negative size is a class that fails l-diversity (see
/// [`l_aware_class_sizes`]); it is suppressed for every k. DM* is the sum of
/// squared sizes over published classes; suppressed records add nothing to it.
fn k_stats(class_sizes: &[i64], ks: &[i64]) -> Vec<KStats> {
    let mut out = vec![KStats::default(); ks.len()];
    for &c in class_sizes {
        if c == 0 {
            continue;
        }
        for (s, &k) in out.iter_mut().zip(ks) {
            if c < k {
                s.suppressed += c.abs();
            } else {
                s.dm_star = s.dm_star.saturating_add(c.saturating_mul(c));
                s.num_equivalence_classes += 1;
            }
        }
    }
    out
}

fn score(class_sizes: &[i64], k: i64) -> KStats {
    k_stats(class_sizes, &[k])[0]
}

// ── OLA-2 search ─────────────────────────────────────────────────────────────

/// OLA-2 for one (k, suppression_limit) over any histogram representation:
/// `class_sizes_at(node)` merges the histogram to `node` and returns its class
/// sizes (negative for classes that fail l-diversity).
///
/// Binary search over lattice levels with predictive tagging: a passing node
/// tags its whole up-set passing, a failing node its whole down-set failing.
/// That is sound because every QI's levels nest, so generalising never splits
/// a class and suppression never grows. Only evaluated nodes are candidates;
/// the answer is the minimum (DM*, suppressed, −ECs, node) among them, and
/// every minimal passing node is evaluated, so it is the optimum.
pub fn find_ola2_with<F>(
    qis: &[QuasiIdentifierLite],
    initial_ri: &[i64],
    size_factors: &HashMap<String, i64>,
    k: i64,
    suppression_limit: f64,
    total_records: i64,
    mut class_sizes_at: F,
) -> Result<Ola2SearchResult, PipelineError>
where
    F: FnMut(&[i64]) -> Vec<i64>,
{
    if k <= 0 {
        return Err(validation("GENERALIZATION_FAILED", "k must be > 0", "OLA-2"));
    }
    if !(0.0..=1.0).contains(&suppression_limit) {
        return Err(validation("GENERALIZATION_FAILED", "suppression_limit must be in [0,1]", "OLA-2"));
    }
    if total_records <= 0 {
        return Err(validation("GENERALIZATION_FAILED", "total_records must be > 0", "OLA-2"));
    }
    if initial_ri.len() != qis.len() {
        return Err(validation("GENERALIZATION_FAILED", "initial_ri length mismatch", "OLA-2"));
    }
    let lat = Lattice::build(qis, initial_ri, size_factors)?;
    let mut status: Vec<Option<bool>> = vec![None; lat.len()];
    let mut open_per_level: Vec<usize> = lat.levels.iter().map(Vec::len).collect();
    let mut scored: Vec<Ola2NodeScore> = Vec::new();
    let mut node_trace: Vec<NodeTrace> = Vec::new();

    loop {
        let open: Vec<usize> = (0..lat.levels.len()).filter(|&l| open_per_level[l] > 0).collect();
        let Some(&mid_level) = open.get(open.len() / 2) else { break };
        let mut candidates: Vec<usize> =
            lat.levels[mid_level].iter().copied().filter(|&n| status[n].is_none()).collect();
        candidates.sort_by(|&a, &b| lat.nodes[b].cmp(&lat.nodes[a]));
        let at = candidates[candidates.len() / 2];

        let s = score(&class_sizes_at(&lat.nodes[at]), k);
        let passes = within_suppression_limit(s.suppressed, suppression_limit, total_records);
        node_trace.push(NodeTrace {
            node: lat.nodes[at].clone(),
            suppression_count: s.suppressed,
            dm_star: s.dm_star,
            num_equivalence_classes: s.num_equivalence_classes,
            passes,
        });

        status[at] = Some(passes);
        open_per_level[lat.level_of[at]] -= 1;
        lat.propagate(at, passes, |j| {
            if status[j].is_some() {
                return false;
            }
            status[j] = Some(passes);
            open_per_level[lat.level_of[j]] -= 1;
            true
        });
        if passes {
            scored.push(Ola2NodeScore {
                node: lat.nodes[at].clone(),
                dm_star: s.dm_star,
                num_equivalence_classes: s.num_equivalence_classes,
                suppression_count: s.suppressed,
            });
        }
    }

    scored.sort_by(|a, b| {
        (a.dm_star, a.suppression_count, -a.num_equivalence_classes, &a.node).cmp(&(
            b.dm_star,
            b.suppression_count,
            -b.num_equivalence_classes,
            &b.node,
        ))
    });
    scored.truncate(5);
    let best = scored.first().ok_or_else(|| {
        validation(
            "GENERALIZATION_FAILED",
            "No node satisfies k-anonymity constraints",
            "Increase suppression_limit or reduce k",
        )
    })?;
    Ok(Ola2SearchResult {
        best_rf: best.node.clone(),
        lowest_dm_star: best.dm_star,
        num_equivalence_classes: best.num_equivalence_classes,
        top_nodes: scored.clone(),
        node_trace,
        lattice_size: lat.len(),
    })
}

/// OLA-2 lattice search operating entirely on a `ZHist`.
pub fn find_ola2_best_rf_z_detailed(
    qis: &[QuasiIdentifierLite],
    base_hist: &ZHist,
    weights: &[i64],
    initial_ri: &[i64],
    size_factors: &HashMap<String, i64>,
    k: i64,
    suppression_limit: f64,
    total_records: i64,
) -> Result<Ola2SearchResult, PipelineError> {
    find_ola2_with(qis, initial_ri, size_factors, k, suppression_limit, total_records, |node| {
        merge_z_histogram(base_hist, qis, weights, node).into_iter().map(|(_, c)| c).collect()
    })
}

pub fn find_ola2_best_rf(
    qis: &[QuasiIdentifierLite],
    base_hist: &SparseHist,
    initial_ri: &[i64],
    size_factors: &HashMap<String, i64>,
    k: i64,
    suppression_limit: f64,
    total_records: i64,
) -> Result<(Vec<i64>, i64, i64), PipelineError> {
    let detailed =
        find_ola2_best_rf_detailed(qis, base_hist, initial_ri, size_factors, k, suppression_limit, total_records)?;
    Ok((detailed.best_rf, detailed.lowest_dm_star, detailed.num_equivalence_classes))
}

pub fn find_ola2_best_rf_detailed(
    qis: &[QuasiIdentifierLite],
    base_hist: &SparseHist,
    initial_ri: &[i64],
    size_factors: &HashMap<String, i64>,
    k: i64,
    suppression_limit: f64,
    total_records: i64,
) -> Result<Ola2SearchResult, PipelineError> {
    find_ola2_with(qis, initial_ri, size_factors, k, suppression_limit, total_records, |node| {
        merge_histogram(base_hist, qis, node).into_values().collect()
    })
}

// ── Parameter grid ───────────────────────────────────────────────────────────

/// k values the parameter grid covers, easiest first.
pub const GRID_K_VALUES: &[i64] = &[5, 10, 50, 100];
/// Suppression limits the parameter grid covers, strictest first.
pub const GRID_SUPPRESSION_LIMITS: &[f64] = &[0.0, 0.01, 0.1];

/// One cell in the (k × suppression_limit) parameter grid.
#[derive(Debug, Clone, Serialize)]
pub struct GridEntry {
    pub k: i64,
    pub suppression_limit: f64,
    /// Best generalization node found by OLA-2, empty if infeasible.
    pub best_node: Vec<i64>,
    /// `best_node` keyed by QI column name — the shape pass 2 accepts back as
    /// `generalization_node`, so a chosen cell can be copied into the config
    /// verbatim. Empty if infeasible.
    pub generalization_node: BTreeMap<String, i64>,
    pub dm_star: i64,
    pub num_equivalence_classes: i64,
    /// Records suppressed at the best node.
    pub suppression_count: i64,
    pub feasible: bool,
}

/// The parameter grid plus how much of the lattice it had to merge to get there.
#[derive(Debug, Clone, Serialize)]
pub struct ParameterGrid {
    pub entries: Vec<GridEntry>,
    /// Lattice nodes whose histogram was actually merged.
    pub nodes_merged: usize,
    pub lattice_size: usize,
}

/// Parameter grid over a `SparseHist` base histogram.
/// See [`compute_parameter_grid_for`] for the search.
pub fn compute_parameter_grid(
    qis: &[QuasiIdentifierLite],
    base_hist: &SparseHist,
    initial_ri: &[i64],
    size_factors: &HashMap<String, i64>,
    total_records: i64,
) -> Result<ParameterGrid, PipelineError> {
    compute_parameter_grid_for(
        qis,
        initial_ri,
        size_factors,
        total_records,
        GRID_K_VALUES,
        GRID_SUPPRESSION_LIMITS,
        |node| merge_histogram(base_hist, qis, node).into_values().collect(),
    )
}

/// Parameter grid over a `ZHist` base histogram, merging in Z space.
pub fn compute_parameter_grid_z(
    qis: &[QuasiIdentifierLite],
    base_hist: &ZHist,
    weights: &[i64],
    initial_ri: &[i64],
    size_factors: &HashMap<String, i64>,
    total_records: i64,
) -> Result<ParameterGrid, PipelineError> {
    compute_parameter_grid_for(
        qis,
        initial_ri,
        size_factors,
        total_records,
        GRID_K_VALUES,
        GRID_SUPPRESSION_LIMITS,
        |node| merge_z_histogram(base_hist, qis, weights, node).into_iter().map(|(_, c)| c).collect(),
    )
}

/// Multi-combination OLA-2: one lattice search that answers every
/// (k, suppression_limit) cell of the grid at once.
///
/// A node's merged histogram does not depend on k or σ — only the verdict
/// read off it does. So the lattice is built once and every node carries a
/// `ks × sigmas` status matrix:
///
/// - Merging a node (`class_sizes_at`, at most once per node) scores all ks in
///   one pass and settles all of that node's cells.
/// - Each settled cell propagates across the lattice exactly as in single-combo
///   OLA-2: a pass tags the node's up-set passing for that cell, a fail tags
///   its down-set failing.
/// - The next node merged is chosen as in [`find_ola2_with`] — the middle node
///   of the middle level that still has an unsettled cell.
///
/// Each cell's answer is the minimum (DM*, suppressed, −ECs, node) over the
/// nodes that were merged and pass it — the same answers as one OLA-2 run per
/// cell, at a fraction of the merges.
pub fn compute_parameter_grid_for<F>(
    qis: &[QuasiIdentifierLite],
    initial_ri: &[i64],
    size_factors: &HashMap<String, i64>,
    total_records: i64,
    ks: &[i64],
    sigmas: &[f64],
    mut class_sizes_at: F,
) -> Result<ParameterGrid, PipelineError>
where
    F: FnMut(&[i64]) -> Vec<i64>,
{
    let (nk, ns) = (ks.len(), sigmas.len());
    let infeasible = |k: i64, suppression_limit: f64| GridEntry {
        k,
        suppression_limit,
        best_node: vec![],
        generalization_node: BTreeMap::new(),
        dm_star: -1,
        num_equivalence_classes: 0,
        suppression_count: -1,
        feasible: false,
    };
    if total_records <= 0 {
        let entries = ks.iter().flat_map(|&k| sigmas.iter().map(move |&s| infeasible(k, s))).collect();
        return Ok(ParameterGrid { entries, nodes_merged: 0, lattice_size: 0 });
    }
    let lat = Lattice::build(qis, initial_ri, size_factors)?;

    // status[node][ki * ns + si]: None = unsettled, Some(pass)
    let mut status: Vec<Vec<Option<bool>>> = vec![vec![None; nk * ns]; lat.len()];
    let mut stats: Vec<Option<Vec<KStats>>> = vec![None; lat.len()];
    let unsettled = |s: &[Option<bool>]| s.iter().any(Option::is_none);
    let mut nodes_merged = 0usize;

    loop {
        let open_levels: Vec<usize> =
            (0..lat.levels.len()).filter(|&l| lat.levels[l].iter().any(|&n| unsettled(&status[n]))).collect();
        let Some(&mid_level) = open_levels.get(open_levels.len() / 2) else { break };
        let mut candidates: Vec<usize> =
            lat.levels[mid_level].iter().copied().filter(|&n| unsettled(&status[n])).collect();
        candidates.sort_by(|&a, &b| lat.nodes[b].cmp(&lat.nodes[a]));
        let at = candidates[candidates.len() / 2];

        let node_stats = k_stats(&class_sizes_at(&lat.nodes[at]), ks);
        nodes_merged += 1;

        for cell in 0..nk * ns {
            let pass = within_suppression_limit(node_stats[cell / ns].suppressed, sigmas[cell % ns], total_records);
            status[at][cell] = Some(pass);
            lat.propagate(at, pass, |j| {
                if status[j][cell].is_some() {
                    return false;
                }
                status[j][cell] = Some(pass);
                true
            });
        }
        stats[at] = Some(node_stats);
    }

    let mut entries = Vec::with_capacity(nk * ns);
    for (ki, &k) in ks.iter().enumerate() {
        for &suppression_limit in sigmas {
            let best = (0..lat.len())
                .filter_map(|n| stats[n].as_ref().map(|s| (n, s[ki])))
                .filter(|(_, s)| within_suppression_limit(s.suppressed, suppression_limit, total_records))
                .min_by(|(a, sa), (b, sb)| {
                    (sa.dm_star, sa.suppressed, -sa.num_equivalence_classes, &lat.nodes[*a]).cmp(&(
                        sb.dm_star,
                        sb.suppressed,
                        -sb.num_equivalence_classes,
                        &lat.nodes[*b],
                    ))
                });
            entries.push(match best {
                Some((n, s)) => GridEntry {
                    k,
                    suppression_limit,
                    best_node: lat.nodes[n].clone(),
                    generalization_node: qis
                        .iter()
                        .zip(&lat.nodes[n])
                        .map(|(qi, &v)| (qi.column_name.clone(), v))
                        .collect(),
                    dm_star: s.dm_star,
                    num_equivalence_classes: s.num_equivalence_classes,
                    suppression_count: s.suppressed,
                    feasible: true,
                },
                None => infeasible(k, suppression_limit),
            });
        }
    }

    Ok(ParameterGrid { entries, nodes_merged, lattice_size: lat.len() })
}

pub fn equivalence_class_stats(
    hist: &SparseHist,
    qis: &[QuasiIdentifierLite],
    rf: &[i64],
    k: i64,
) -> BTreeMap<i64, i64> {
    let merged = merge_histogram(hist, qis, rf);
    let mut stats = BTreeMap::new();
    for v in merged.values() {
        if *v >= k {
            *stats.entry(*v).or_insert(0) += 1;
        }
    }
    stats
}

/// Compute k_optimal at the coarsest constrained node.
///
/// For interval QIs: coarsest = num_levels (user-defined intervals).
/// For uniform QIs: coarsest = full range collapsed to one bin.
/// For categorical QIs: coarsest = top level of its [`CategoricalLevels`].
///
/// k_optimal = largest k such that the records suppressed (ECs with size < k)
/// at the coarsest node stay within `suppression_limit * total_records`.
pub fn compute_k_optimal(
    qis: &[QuasiIdentifierLite],
    base_hist: &SparseHist,
    suppression_limit: f64,
    total_records: i64,
) -> i64 {
    let coarsest: Vec<i64> = qis
        .iter()
        .map(|qi| {
            if let Some(ref h) = qi.interval_hierarchy {
                h.num_levels as i64
            } else if qi.is_categorical {
                categorical_num_levels(qi)
            } else {
                (qi.get_range().ceil() as i64).max(1)
            }
        })
        .collect();

    let merged = merge_histogram(base_hist, qis, &coarsest);
    let allowed = allowed_suppressions(suppression_limit, total_records);

    let mut sizes: Vec<i64> = merged.values().copied().filter(|&v| v > 0).collect();
    sizes.sort_unstable();

    // Walk sorted sizes: prefix = records already suppressed if k = current size.
    // k_optimal = last size where prefix <= allowed.
    let mut prefix = 0i64;
    let mut k_optimal = 1i64;
    for &s in &sizes {
        if prefix <= allowed {
            k_optimal = s;
        } else {
            break;
        }
        prefix += s;
    }
    k_optimal
}
