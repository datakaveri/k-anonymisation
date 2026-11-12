//! Benchmarks behind the scaling claims in the CHANGELOG: how OLA-2's
//! lattice search grows with the number of quasi-identifiers and with the
//! number of distinct histogram cells.
//!
//! Run with `cargo bench --bench ola`. Histograms are synthetic and built in
//! memory, so the numbers measure the search, not CSV I/O.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use skald_ola2::pipeline::anonymization::{QuasiIdentifierLite, SparseHist, find_ola2_best_rf_detailed};
use std::collections::HashMap;
use std::hint::black_box;

/// `q` numeric QIs over 0..=range, with `cells` distinct base cells drawn from
/// a fixed linear-congruential sequence (deterministic across runs).
fn setup(q: usize, range: i64, cells: usize) -> (Vec<QuasiIdentifierLite>, SparseHist, HashMap<String, i64>, i64) {
    let qis: Vec<QuasiIdentifierLite> = (0..q)
        .map(|i| QuasiIdentifierLite {
            column_name: format!("Q{i}"),
            is_categorical: false,
            min_value: Some(0.0),
            max_value: Some(range as f64),
            interval_hierarchy: None,
            categorical_levels: None,
        })
        .collect();
    let mut hist: SparseHist = HashMap::new();
    let mut x: u64 = 0x2545_F491_4F6C_DD1D;
    let mut total = 0;
    for _ in 0..cells {
        let key: Vec<i64> = (0..q)
            .map(|_| {
                x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
                ((x >> 33) as i64) % (range + 1)
            })
            .collect();
        let count = 1 + (x % 7) as i64;
        *hist.entry(key).or_insert(0) += count;
        total += count;
    }
    let sizes = qis.iter().map(|qi| (qi.column_name.clone(), 2)).collect();
    (qis, hist, sizes, total)
}

fn by_qi_count(c: &mut Criterion) {
    let mut g = c.benchmark_group("ola2_by_qi_count");
    g.sample_size(10);
    for q in [2usize, 3, 4, 5] {
        let (qis, hist, sizes, total) = setup(q, 255, 5_000);
        g.bench_with_input(BenchmarkId::from_parameter(q), &q, |b, _| {
            b.iter(|| find_ola2_best_rf_detailed(&qis, &hist, &vec![1; q], &sizes, 5, 0.05, total).unwrap())
        });
    }
    g.finish();
}

fn by_histogram_cells(c: &mut Criterion) {
    let mut g = c.benchmark_group("ola2_by_histogram_cells");
    g.sample_size(10);
    for cells in [1_000usize, 10_000, 100_000] {
        let (qis, hist, sizes, total) = setup(3, 1023, cells);
        g.bench_with_input(BenchmarkId::from_parameter(cells), &cells, |b, _| {
            b.iter(|| black_box(find_ola2_best_rf_detailed(&qis, &hist, &[1, 1, 1], &sizes, 5, 0.05, total).unwrap()))
        });
    }
    g.finish();
}

criterion_group!(benches, by_qi_count, by_histogram_cells);
criterion_main!(benches);
