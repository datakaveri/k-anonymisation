//! Batch API: SKALD's per-row work and k search, callable one batch at a time.
//!
//! The command line reads files in RAM-sized chunks; a distributed caller (a
//! Spark job) holds the data as batches spread over executors. Both need the
//! same steps in the same order, so they share this one implementation:
//! the command line is a loop over chunk files, the Python wheel a loop over
//! Arrow record batches.

pub mod table;

pub use table::Table;
