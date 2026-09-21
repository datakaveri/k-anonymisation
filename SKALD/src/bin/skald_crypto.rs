//! Block 2 worker — salted/unsalted hashing, pseudo-encryption, FPE.
//!
//! Dispatched to a container. Reads key material from the manifest and never
//! generates any: two row shards of one column must share one key.
fn main() {
    let code = skald_ola2::pipeline::blocks::run_block(
        "crypto",
        skald_ola2::pipeline::blocks::crypto_block::run,
    );
    std::process::exit(code);
}
