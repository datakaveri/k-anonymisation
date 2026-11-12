//! Block 2 worker — `hashing_with_salt` (HMAC-SHA256) and `encrypt` (AES-SIV,
//! or NIST FF1 when format-preserving).
//!
//! Dispatched to a container. Reads key material from the manifest's key
//! directory (or inline keys) and never generates any: two row shards of one
//! column must share one key.
fn main() {
    let code = skald_ola2::pipeline::blocks::run_block("crypto", skald_ola2::pipeline::blocks::crypto_block::run);
    std::process::exit(code);
}
