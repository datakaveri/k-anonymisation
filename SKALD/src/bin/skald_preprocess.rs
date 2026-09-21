//! Block 1 worker — suppression, masking, charcloak, tokenization.
//!
//! Intended to run on the Anonymization Orchestrator itself: the token vault
//! it maintains is reversible secret state and belongs inside the TEE the user
//! attested. Packaged as its own binary anyway so it has its own image digest
//! and its own measurement.
fn main() {
    let code = skald_ola2::pipeline::blocks::run_block(
        "preprocess",
        skald_ola2::pipeline::blocks::preprocess_block::run,
    );
    std::process::exit(code);
}
