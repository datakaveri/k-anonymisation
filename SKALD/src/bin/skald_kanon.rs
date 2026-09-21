//! Block 3 worker — k-anonymization, one stage per invocation.
//!
//! `stage` in the manifest selects scan (map), solve (reduce) or apply (map).
fn main() {
    let code = skald_ola2::pipeline::blocks::run_block(
        "kanon",
        skald_ola2::pipeline::blocks::kanon_block::run,
    );
    std::process::exit(code);
}
