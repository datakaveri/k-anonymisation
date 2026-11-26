//! Batch API: SKALD's per-row work and k search, callable one batch at a time.
//!
//! The command line reads files in RAM-sized chunks; a distributed caller (a
//! Spark job) holds the data as batches spread over executors. Both need the
//! same steps in the same order, so they share this one implementation:
//! the command line is a loop over chunk files, the Python wheel a loop over
//! Arrow record batches.
//!
//! The steps, in the order a driver runs them (executors do the per-batch
//! parts; everything marked "merge" or "search" runs on one machine and never
//! sees a row):
//!
//! 1. [`Plan::from_json`] — parse and validate the config.
//! 2. [`Preprocessor::apply`] on every batch — suppress, hash, mask, tokenise,
//!    encrypt (keys and token vault passed in).
//! 3. [`Stats::observe`] on every batch, then [`Stats::merge`] — ranges and
//!    domains of the quasi-identifiers.
//! 4. [`Model::build`] — lattice and flow decision.
//! 5. [`Histogram::observe`] on every batch, then [`Histogram::merge`].
//! 6. [`Model::parameter_grid`] ("explore k") and [`Model::search`] — the node.
//! 7. [`Generalizer::apply`] on every batch, [`Tally::merge`],
//!    [`Tally::decide`], then [`Generalizer::finish`] on every batch.
//! 8. [`Generalizer::tally`] on the written rows and [`Tally::verify`] — the
//!    final k check.
//!
//! FHIR bundles and nested JSON have no such steps: each document is
//! anonymised on its own from the config and the keys, see [`documents`].

#[cfg(feature = "arrow")]
pub mod arrow_io;
pub mod documents;
pub mod generalise;
pub mod histogram;
pub mod model;
pub mod plan;
pub mod stats;
pub mod table;

pub use crate::pipeline::preprocess::{
    KeyKind, KeyMaterial, KeyPolicy, MemoryVault, Preprocessor, TokenPolicy, TokenVault,
};
pub use documents::{DocKind, DocOutput, DocPlan};
pub use generalise::{Decision, Generalizer, Tally};
pub use histogram::{Cells, Histogram};
pub use model::Model;
pub use plan::Plan;
pub use stats::{QiColumns, Stats};
pub use table::Table;
