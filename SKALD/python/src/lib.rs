//! `skald_core`: SKALD's batch API for Python.
//!
//! Record batches cross the boundary through Arrow's C data interface
//! (`pyarrow.RecordBatch` in and out, nothing copied between Python and Rust).
//! Inside Rust, SKALD's row kernels read cells as text, so a batch is
//! materialised once per call — see `skald_ola2::batch::arrow_io`.
//!
//! Everything a Spark job moves between driver and executors is either a plain
//! Python value or an object that pickles to bytes (`Plan`, `Stats`, `Model`,
//! `Histogram`, `Tally`, `Decision`, `Generalizer`).

// `__reduce__` returns (callable, args) tuples, which are what pickle takes.
#![allow(clippy::type_complexity)]

use arrow_array::RecordBatch;
use arrow_pyarrow::PyArrowType;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use skald_ola2::batch::arrow_io::{batch_from_table, table_from_batch};
use skald_ola2::batch::{
    Decision, Generalizer, Histogram, KeyKind, KeyMaterial, KeyPolicy, MemoryVault, Model, Plan, Preprocessor,
    QiColumns, Stats, Table, Tally, TokenPolicy,
};
use skald_ola2::pipeline::bootstrap::PipelineError;
use std::collections::{BTreeMap, BTreeSet};

pyo3::create_exception!(
    skald_core,
    SkaldError,
    PyValueError,
    "A SKALD validation or data error; `.code` is the stable error code."
);

fn err(e: PipelineError) -> PyErr {
    let (code, text) = match &e {
        PipelineError::Validation { code, .. } => (code.to_string(), e.to_string()),
        PipelineError::Io(_) => ("IO_ERROR".to_string(), e.to_string()),
        PipelineError::Json(_) => ("CONFIG_PARSE_ERROR".to_string(), e.to_string()),
    };
    Python::attach(|py| {
        let exc = SkaldError::new_err(text);
        let _ = exc.value(py).setattr("code", code);
        exc
    })
}

fn to_py_json(py: Python<'_>, v: &impl serde::Serialize) -> PyResult<Py<PyAny>> {
    let text = serde_json::to_string(v).map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(py.import("json")?.call_method1("loads", (text,))?.unbind())
}

fn kind_of(name: &str) -> PyResult<KeyKind> {
    KeyKind::parse(name)
        .ok_or_else(|| PyValueError::new_err(format!("unknown key kind {name:?} (hmac_salt, aes_key or fpe_key)")))
}

fn keys_from_py(d: &Bound<'_, PyDict>) -> PyResult<KeyMaterial> {
    let mut keys = KeyMaterial::new();
    for (kind, cols) in d.iter() {
        let kind = kind_of(&kind.extract::<String>()?)?;
        for (col, bytes) in cols.cast::<PyDict>()?.iter() {
            keys.insert(kind, &col.extract::<String>()?, &bytes.extract::<Vec<u8>>()?).map_err(err)?;
        }
    }
    Ok(keys)
}

fn keys_to_py<'py>(py: Python<'py>, keys: &KeyMaterial) -> PyResult<Bound<'py, PyDict>> {
    let out = PyDict::new(py);
    for kind in [KeyKind::HmacSalt, KeyKind::AesKey, KeyKind::FpeKey] {
        let d = PyDict::new(py);
        for col in keys.columns(kind) {
            if let Some(b) = keys.bytes(kind, &col) {
                d.set_item(col, PyBytes::new(py, &b))?;
            }
        }
        out.set_item(kind.as_str(), d)?;
    }
    Ok(out)
}

/// The keys a config needs, for a driver to load or generate once: returns
/// `existing` plus a fresh key for every one it lacks.
#[pyfunction]
#[pyo3(signature = (plan, existing=None))]
fn generate_keys<'py>(
    py: Python<'py>,
    plan: &PyPlan,
    existing: Option<&Bound<'py, PyDict>>,
) -> PyResult<Bound<'py, PyDict>> {
    let mut keys = match existing {
        Some(d) => keys_from_py(d)?,
        None => KeyMaterial::new(),
    };
    keys.generate_missing(&plan.inner.required_keys().map_err(err)?).map_err(err)?;
    keys_to_py(py, &keys)
}

// ── Plan ─────────────────────────────────────────────────────────────────────

/// A parsed and validated config (the same validation the CLI applies).
#[pyclass(name = "Plan", module = "skald_core")]
struct PyPlan {
    inner: Plan,
}

#[pymethods]
impl PyPlan {
    #[new]
    fn new(config_json: &str) -> PyResult<Self> {
        Ok(Self { inner: Plan::from_json(config_json).map_err(err)? })
    }
    /// The config text; also what pickling stores.
    #[getter]
    fn config_json(&self) -> &str {
        &self.inner.json
    }
    #[getter]
    fn k(&self) -> i64 {
        self.inner.cfg.k
    }
    #[getter]
    fn suppression_limit(&self) -> f64 {
        self.inner.cfg.suppression_limit
    }
    /// `"pass1"`, `"pass2"` or `"no_bounds"`.
    #[getter]
    fn pass_name(&self) -> String {
        self.inner.cfg.pass.clone()
    }
    #[getter]
    fn has_quasi_identifiers(&self) -> bool {
        self.inner.has_quasi_identifiers()
    }
    /// `(numeric_columns, categorical_columns)`.
    fn qi_columns(&self) -> (Vec<String>, Vec<String>) {
        let c = self.inner.qi_columns();
        (c.numeric, c.categorical)
    }
    /// `[(kind, column), ...]` the techniques need.
    fn required_keys(&self) -> PyResult<Vec<(String, String)>> {
        Ok(self.inner.required_keys().map_err(err)?.into_iter().map(|(k, c)| (k.as_str().to_string(), c)).collect())
    }
    fn tokenized_columns(&self) -> PyResult<Vec<String>> {
        Ok(Preprocessor::new(
            &self.inner.cfg,
            KeyMaterial::new(),
            KeyPolicy::Require,
            MemoryVault::new(),
            TokenPolicy::LookupOnly,
        )
        .map_err(err)?
        .tokenized_columns())
    }
    fn __reduce__<'py>(slf: &Bound<'py, Self>) -> PyResult<(Bound<'py, PyAny>, (String,))> {
        Ok((slf.get_type().into_any(), (slf.borrow().inner.json.clone(),)))
    }
}

// ── Preprocessor ─────────────────────────────────────────────────────────────

/// Suppress, hash, mask, charcloak, tokenise and encrypt batches.
///
/// Executors build one per partition from the broadcast `keys` (and `vault`),
/// with the defaults `generate_missing=False, issue_tokens=False`, so a missing
/// key or token is an error rather than a value that differs between executors.
/// `generate_missing=True, issue_tokens=True` is the single-process default.
#[pyclass(name = "Preprocessor", module = "skald_core")]
struct PyPreprocessor {
    inner: Preprocessor<MemoryVault>,
    counts: BTreeMap<String, u64>,
}

#[pymethods]
impl PyPreprocessor {
    #[new]
    #[pyo3(signature = (plan, keys=None, vault=None, generate_missing=false, issue_tokens=false))]
    fn new(
        plan: &PyPlan,
        keys: Option<&Bound<'_, PyDict>>,
        vault: Option<&Bound<'_, PyDict>>,
        generate_missing: bool,
        issue_tokens: bool,
    ) -> PyResult<Self> {
        let keys = match keys {
            Some(d) => keys_from_py(d)?,
            None => KeyMaterial::new(),
        };
        let mut v = MemoryVault::new();
        if let Some(d) = vault {
            for (col, entries) in d.iter() {
                v.load_entries(&col.extract::<String>()?, entries.extract::<BTreeMap<String, String>>()?)
                    .map_err(err)?;
            }
        }
        let inner = Preprocessor::new(
            &plan.inner.cfg,
            keys,
            if generate_missing { KeyPolicy::Generate } else { KeyPolicy::Require },
            v,
            if issue_tokens { TokenPolicy::Issue } else { TokenPolicy::LookupOnly },
        )
        .map_err(err)?;
        Ok(Self { inner, counts: BTreeMap::new() })
    }

    /// Transforms one record batch; returns a batch of string columns.
    fn apply(&mut self, py: Python<'_>, batch: PyArrowType<RecordBatch>) -> PyResult<PyArrowType<RecordBatch>> {
        let mut table = table_from_batch(&batch.0, "batch").map_err(err)?;
        let stats = py.detach(|| self.inner.apply(&mut table)).map_err(err)?;
        for (k, n) in stats {
            *self.counts.entry(k).or_insert(0) += n;
        }
        Ok(PyArrowType(batch_from_table(&table).map_err(err)?))
    }

    /// Driver step 1 of distributed tokenisation: the distinct values this
    /// batch would tokenise, `{column: [value, ...]}`.
    fn token_values(&mut self, batch: PyArrowType<RecordBatch>) -> PyResult<BTreeMap<String, Vec<String>>> {
        let mut table = table_from_batch(&batch.0, "batch").map_err(err)?;
        let values = self.inner.token_values(&mut table).map_err(err)?;
        Ok(values.into_iter().map(|(c, s)| (c, s.into_iter().collect())).collect())
    }

    /// Driver step 2: give every collected value a token (kept if it has one).
    fn issue_tokens(&mut self, values: BTreeMap<String, Vec<String>>) -> PyResult<()> {
        let values: BTreeMap<String, BTreeSet<String>> =
            values.into_iter().map(|(c, v)| (c, v.into_iter().collect())).collect();
        self.inner.issue_tokens(&values).map_err(err)
    }

    /// The vault as `{column: {original: token}}`, to broadcast or to save.
    fn vault(&self) -> BTreeMap<String, BTreeMap<String, String>> {
        let v = self.inner.vault();
        v.columns().map(|c| (c.clone(), v.entries(c))).collect()
    }

    /// All keys in use, in the form `keys=` takes (includes generated ones).
    fn keys<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        keys_to_py(py, self.inner.keys())
    }

    /// `[(kind, column), ...]` generated because none was passed.
    fn generated_keys(&self) -> Vec<(String, String)> {
        self.inner.generated_keys().iter().map(|(k, c)| (k.as_str().to_string(), c.clone())).collect()
    }

    /// Values transformed so far per `"<technique>:<column>"` (counts only).
    fn counts(&self) -> BTreeMap<String, u64> {
        self.counts.clone()
    }
}

// ── Stats ────────────────────────────────────────────────────────────────────

/// What batches contain, as far as the model cares (ranges, domains, rows).
#[pyclass(name = "Stats", module = "skald_core")]
struct PyStats {
    plan: Py<PyPlan>,
    cols: QiColumns,
    inner: Stats,
}

#[pymethods]
impl PyStats {
    #[new]
    fn new(plan: Py<PyPlan>, py: Python<'_>) -> Self {
        let cols = plan.borrow(py).inner.qi_columns();
        Self { inner: Stats::new(&cols), cols, plan }
    }
    fn observe(&mut self, py: Python<'_>, batch: PyArrowType<RecordBatch>) -> PyResult<()> {
        let table = table_from_batch(&batch.0, "batch").map_err(err)?;
        py.detach(|| self.inner.observe(&self.cols, &table)).map_err(err)
    }
    fn merge(&mut self, other: &PyStats) -> PyResult<()> {
        self.inner.merge(&other.inner).map_err(err)
    }
    #[getter]
    fn rows(&self) -> i64 {
        self.inner.rows
    }
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &serde_json::to_vec(&self.inner).expect("stats always serialise"))
    }
    fn __reduce__<'py>(slf: &Bound<'py, Self>) -> PyResult<(Bound<'py, PyAny>, (Py<PyPlan>, Bound<'py, PyBytes>))> {
        let py = slf.py();
        let me = slf.borrow();
        let f = py.import("skald_core")?.getattr("_stats_from_bytes")?;
        Ok((f, (me.plan.clone_ref(py), me.to_bytes(py))))
    }
}

#[pyfunction]
fn _stats_from_bytes(py: Python<'_>, plan: Py<PyPlan>, data: &[u8]) -> PyResult<PyStats> {
    let mut s = PyStats::new(plan, py);
    s.inner = serde_json::from_slice(data).map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(s)
}

// ── Model ────────────────────────────────────────────────────────────────────

/// The lattice and flow decision built from merged stats. Pickles as
/// `(plan, stats, max_eq)` and is rebuilt identically on every executor.
#[pyclass(name = "Model", module = "skald_core")]
struct PyModel {
    plan: Py<PyPlan>,
    stats: Stats,
    inner: Model,
}

fn build_model(py: Python<'_>, plan: Py<PyPlan>, stats: Stats, max_eq: Option<i64>) -> PyResult<PyModel> {
    let inner = {
        let p = plan.borrow(py);
        Model::build(&p.inner.cfg, &stats, max_eq).map_err(err)?
    };
    Ok(PyModel { plan, stats, inner })
}

#[pymethods]
impl PyModel {
    #[new]
    #[pyo3(signature = (plan, stats, max_eq=None))]
    fn new(py: Python<'_>, plan: Py<PyPlan>, stats: &PyStats, max_eq: Option<i64>) -> PyResult<Self> {
        build_model(py, plan, stats.inner.clone(), max_eq)
    }
    #[getter]
    fn plan(&self, py: Python<'_>) -> Py<PyPlan> {
        self.plan.clone_ref(py)
    }
    #[getter]
    fn n_rows(&self) -> i64 {
        self.inner.total_rows
    }
    /// `"DIRECT"` (Z-encoded histogram) or `"ORIGINAL"` (OLA-1 + sparse).
    #[getter]
    fn flow(&self) -> &'static str {
        if self.inner.weights.is_some() { "DIRECT" } else { "ORIGINAL" }
    }
    #[getter]
    fn qi_names(&self) -> Vec<String> {
        self.inner.qis.iter().map(|q| q.column_name.clone()).collect()
    }
    #[getter]
    fn initial_ri(&self) -> Vec<i64> {
        self.inner.initial_ri.clone()
    }
    #[getter]
    fn max_eq(&self) -> Option<i64> {
        self.inner.max_eq
    }

    /// The k × suppression_limit grid, `[{k, suppression_limit, best_node,
    /// generalization_node, dm_star, num_equivalence_classes,
    /// suppression_count, feasible}, ...]`.
    fn parameter_grid(&self, py: Python<'_>, hist: &PyHistogram) -> PyResult<Py<PyAny>> {
        let grid = py.detach(|| self.inner.parameter_grid(&hist.inner)).map_err(err)?;
        let d = PyDict::new(py);
        d.set_item("entries", to_py_json(py, &grid.entries)?)?;
        d.set_item("nodes_merged", grid.nodes_merged)?;
        d.set_item("lattice_size", grid.lattice_size)?;
        Ok(d.into_any().unbind())
    }

    /// OLA-2 for one (k, suppression_limit); defaults come from the config.
    #[pyo3(signature = (hist, k=None, suppression_limit=None))]
    fn search(
        &self,
        py: Python<'_>,
        hist: &PyHistogram,
        k: Option<i64>,
        suppression_limit: Option<f64>,
    ) -> PyResult<Py<PyAny>> {
        let k = k.unwrap_or(self.inner.k);
        let sup = suppression_limit.unwrap_or(self.inner.suppression_limit);
        let r = py.detach(|| self.inner.search(&hist.inner, k, sup)).map_err(err)?;
        to_py_json(py, &r)
    }

    #[pyo3(signature = (hist, suppression_limit=None))]
    fn k_optimal(&self, hist: &PyHistogram, suppression_limit: Option<f64>) -> i64 {
        self.inner.k_optimal(&hist.inner, suppression_limit.unwrap_or(self.inner.suppression_limit))
    }

    /// Maps `{column: level}` (a grid cell's `generalization_node`) to a node.
    fn node_from_names(&self, chosen: BTreeMap<String, i64>) -> PyResult<Vec<i64>> {
        self.inner.node_from_names(&chosen).map_err(err)
    }

    fn __reduce__<'py>(
        slf: &Bound<'py, Self>,
    ) -> PyResult<(Bound<'py, PyAny>, (Py<PyPlan>, Bound<'py, PyBytes>, Option<i64>))> {
        let py = slf.py();
        let me = slf.borrow();
        let f = py.import("skald_core")?.getattr("_model_from_state")?;
        let stats = serde_json::to_vec(&me.stats).expect("stats always serialise");
        Ok((f, (me.plan.clone_ref(py), PyBytes::new(py, &stats), me.inner.max_eq)))
    }
}

#[pyfunction]
fn _model_from_state(py: Python<'_>, plan: Py<PyPlan>, stats: &[u8], max_eq: Option<i64>) -> PyResult<PyModel> {
    let stats = serde_json::from_slice(stats).map_err(|e| PyValueError::new_err(e.to_string()))?;
    build_model(py, plan, stats, max_eq)
}

// ── Histogram ────────────────────────────────────────────────────────────────

/// Counts of rows per quasi-identifier cell; merge per-batch ones, then search.
#[pyclass(name = "Histogram", module = "skald_core")]
struct PyHistogram {
    inner: Histogram,
}

#[pymethods]
impl PyHistogram {
    #[new]
    fn new(model: &PyModel) -> Self {
        Self { inner: model.inner.new_histogram() }
    }
    fn observe(&mut self, py: Python<'_>, model: &PyModel, batch: PyArrowType<RecordBatch>) -> PyResult<()> {
        let table = table_from_batch(&batch.0, "batch").map_err(err)?;
        py.detach(|| self.inner.observe(&model.inner, &table)).map_err(err)
    }
    fn merge(&mut self, other: &PyHistogram) -> PyResult<()> {
        self.inner.merge(&other.inner).map_err(err)
    }
    #[getter]
    fn total(&self) -> i64 {
        self.inner.total
    }
    fn __len__(&self) -> usize {
        self.inner.len()
    }
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.to_bytes())
    }
    fn __reduce__<'py>(slf: &Bound<'py, Self>) -> PyResult<(Bound<'py, PyAny>, (Bound<'py, PyBytes>,))> {
        let py = slf.py();
        Ok((py.import("skald_core")?.getattr("_histogram_from_bytes")?, (slf.borrow().to_bytes(py),)))
    }
}

#[pyfunction]
fn _histogram_from_bytes(data: &[u8]) -> PyResult<PyHistogram> {
    Ok(PyHistogram { inner: Histogram::from_bytes(data).map_err(err)? })
}

// ── Generalizer, Tally, Decision ─────────────────────────────────────────────

/// Rewrites batches at one lattice node. Pickles as `(model, node)`.
#[pyclass(name = "Generalizer", module = "skald_core")]
struct PyGeneralizer {
    model: Py<PyModel>,
    node: Vec<i64>,
    inner: Generalizer,
}

/// Class sizes of the rows of one or more batches.
#[pyclass(name = "Tally", module = "skald_core")]
struct PyTally {
    plan: Py<PyPlan>,
    inner: Tally,
}

/// Which classes fail k (and l) and what to do with their rows.
#[pyclass(name = "Decision", module = "skald_core")]
struct PyDecision {
    inner: Decision,
}

#[pymethods]
impl PyGeneralizer {
    #[new]
    fn new(py: Python<'_>, model: Py<PyModel>, node: Vec<i64>) -> PyResult<Self> {
        let inner = {
            let m = model.borrow(py);
            let p = m.plan.borrow(py);
            Generalizer::new(&m.inner.qis, &node, &m.inner.hierarchies, p.inner.cfg.l_diversity.as_ref())
                .map_err(err)?
        };
        Ok(Self { model, node, inner })
    }

    /// Generalises one batch; returns `(batch, tally)`. The batch is not yet
    /// suppressed: that needs the merged tally's decision.
    fn apply(&self, py: Python<'_>, batch: PyArrowType<RecordBatch>) -> PyResult<(PyArrowType<RecordBatch>, PyTally)> {
        let mut table = table_from_batch(&batch.0, "batch").map_err(err)?;
        let tally = py.detach(|| self.inner.apply(&mut table)).map_err(err)?;
        let plan = self.model.borrow(py).plan.clone_ref(py);
        Ok((PyArrowType(batch_from_table(&table).map_err(err)?), PyTally { plan, inner: tally }))
    }

    /// Applies the decision: failing rows get `*` quasi-identifiers or are removed.
    fn finish(
        &self,
        py: Python<'_>,
        batch: PyArrowType<RecordBatch>,
        decision: &PyDecision,
    ) -> PyResult<PyArrowType<RecordBatch>> {
        let mut table = table_from_batch(&batch.0, "batch").map_err(err)?;
        py.detach(|| self.inner.finish(&mut table, &decision.inner)).map_err(err)?;
        Ok(PyArrowType(batch_from_table(&table).map_err(err)?))
    }

    /// Tally of rows as written (no generalisation), for the final check.
    fn tally(&self, py: Python<'_>, batch: PyArrowType<RecordBatch>) -> PyResult<PyTally> {
        let table: Table = table_from_batch(&batch.0, "batch").map_err(err)?;
        let inner = py.detach(|| self.inner.tally(&table)).map_err(err)?;
        Ok(PyTally { plan: self.model.borrow(py).plan.clone_ref(py), inner })
    }

    #[getter]
    fn node(&self) -> Vec<i64> {
        self.node.clone()
    }

    fn __reduce__<'py>(slf: &Bound<'py, Self>) -> PyResult<(Bound<'py, PyAny>, (Py<PyModel>, Vec<i64>))> {
        let py = slf.py();
        let me = slf.borrow();
        Ok((slf.get_type().into_any(), (me.model.clone_ref(py), me.node.clone())))
    }
}

#[pymethods]
impl PyTally {
    #[new]
    fn new(py: Python<'_>, plan: Py<PyPlan>) -> Self {
        let inner = Tally::new(plan.borrow(py).inner.cfg.l_diversity.as_ref());
        Self { plan, inner }
    }
    fn merge(&mut self, other: &PyTally) {
        self.inner.merge(&other.inner);
    }
    #[getter]
    fn total(&self) -> i64 {
        self.inner.total
    }
    fn __len__(&self) -> usize {
        self.inner.len()
    }

    /// Decides every class against k (default: the config's). Needs the
    /// tallies of the whole data set merged first.
    #[pyo3(signature = (k=None))]
    fn decide(&self, py: Python<'_>, k: Option<i64>) -> PyDecision {
        let p = self.plan.borrow(py);
        PyDecision { inner: self.inner.decide(k.unwrap_or(p.inner.cfg.k), p.inner.cfg.l_diversity.as_ref()) }
    }

    /// The final check: raises `SkaldError` (`K_CHECK_FAILED`) when a class of
    /// written rows is smaller than k; otherwise returns the smallest class size.
    #[pyo3(signature = (k=None))]
    fn verify(&self, py: Python<'_>, k: Option<i64>) -> PyResult<i64> {
        let p = self.plan.borrow(py);
        self.inner.verify(k.unwrap_or(p.inner.cfg.k), p.inner.cfg.l_diversity.as_ref()).map_err(err)
    }

    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.to_bytes())
    }
    fn __reduce__<'py>(slf: &Bound<'py, Self>) -> PyResult<(Bound<'py, PyAny>, (Py<PyPlan>, Bound<'py, PyBytes>))> {
        let py = slf.py();
        let me = slf.borrow();
        Ok((py.import("skald_core")?.getattr("_tally_from_bytes")?, (me.plan.clone_ref(py), me.to_bytes(py))))
    }
}

#[pyfunction]
fn _tally_from_bytes(plan: Py<PyPlan>, data: &[u8]) -> PyResult<PyTally> {
    Ok(PyTally { plan, inner: Tally::from_bytes(data).map_err(err)? })
}

#[pymethods]
impl PyDecision {
    /// Counts measured on the whole data set: `total_records`,
    /// `suppressed_records`, `removed_records`, `num_equivalence_classes`,
    /// `dm_star`, `class_size_counts`, `classes_failing_k`, `classes_failing_l`,
    /// `published_suppressed_records`.
    fn summary<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let s = &self.inner.summary;
        let d = PyDict::new(py);
        d.set_item("total_records", s.total_records)?;
        d.set_item("suppressed_records", s.suppressed_records)?;
        d.set_item("removed_records", s.removed_records)?;
        d.set_item("num_equivalence_classes", s.num_equivalence_classes)?;
        d.set_item("dm_star", s.dm_star)?;
        d.set_item("class_size_counts", s.class_size_counts.clone())?;
        d.set_item("classes_failing_k", s.classes_failing_k)?;
        d.set_item("classes_failing_l", s.classes_failing_l)?;
        d.set_item("published_suppressed_records", s.published_suppressed_records)?;
        Ok(d)
    }
    #[getter]
    fn publish_suppressed(&self) -> bool {
        self.inner.publish_suppressed
    }
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.to_bytes())
    }
    fn __reduce__<'py>(slf: &Bound<'py, Self>) -> PyResult<(Bound<'py, PyAny>, (Bound<'py, PyBytes>,))> {
        let py = slf.py();
        Ok((py.import("skald_core")?.getattr("_decision_from_bytes")?, (slf.borrow().to_bytes(py),)))
    }
}

#[pyfunction]
fn _decision_from_bytes(data: &[u8]) -> PyResult<PyDecision> {
    Ok(PyDecision { inner: Decision::from_bytes(data).map_err(err)? })
}

#[pymodule]
fn skald_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("SkaldError", m.py().get_type::<SkaldError>())?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_class::<PyPlan>()?;
    m.add_class::<PyPreprocessor>()?;
    m.add_class::<PyStats>()?;
    m.add_class::<PyModel>()?;
    m.add_class::<PyHistogram>()?;
    m.add_class::<PyGeneralizer>()?;
    m.add_class::<PyTally>()?;
    m.add_class::<PyDecision>()?;
    m.add_function(wrap_pyfunction!(generate_keys, m)?)?;
    m.add_function(wrap_pyfunction!(_stats_from_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(_model_from_state, m)?)?;
    m.add_function(wrap_pyfunction!(_histogram_from_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(_tally_from_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(_decision_from_bytes, m)?)?;
    Ok(())
}
