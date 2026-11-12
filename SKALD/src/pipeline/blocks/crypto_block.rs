//! Block 2 — crypto: `hashing_with_salt` and `encrypt` (AES-SIV, or NIST FF1
//! when `format_preserving`).
//!
//! Every operation in this block is keyed, and the key is supplied by the
//! orchestrator. That is the whole difference between this block and
//! `preprocess`, and it is why this one is safe to dispatch: a worker that
//! holds a column and a key for that column learns nothing it was not already
//! given, and it holds no state that outlives the shard.
//!
//! The monolith generates salts and keys itself, per run. That is correct when
//! one process sees every row. It is not correct here: two workers handed
//! different row shards of the same column would each mint a salt and the
//! column would end up with two disjoint digest spaces, which looks like
//! ordinary hash output and is unrecoverable. So this block never generates
//! key material — a missing key is a hard failure with `BLOCK_KEY_MISSING`,
//! and `skald_ao keygen` is what fills the gap.
//!
//! Each value goes through the monolith's own functions — identifier
//! normalisation, then `keyed_hash`, [`encrypt_value`] or
//! [`format_preserving_encrypt`] — so a column processed here is
//! byte-for-byte what the monolith writes under the same key.

use super::{BlockKeys, BlockManifest, BlockReport, Shard, apply_to_column, required_column_index};
use crate::pipeline::bootstrap::{PipelineError, RuntimeConfig, parse_runtime_config, validation};
use crate::pipeline::preprocess::HASH_SALTS_FILE;
use crate::pipeline::preprocess::crypto::{
    encrypt_value, format_preserving_encrypt, hash_key, keyed_hash, normalize_identifier,
};
use crate::pipeline::preprocess::masking::{EncryptConfigLite, parse_encrypt_config};
use serde_json::json;
use std::collections::BTreeMap;

pub fn run(manifest: &BlockManifest) -> Result<BlockReport, PipelineError> {
    let cfg = parse_runtime_config(&manifest.config)?;
    let mut shard = Shard::read(manifest.input_path()?, &manifest.row_id_column)?;
    let rows_in = shard.rows.len();
    let keys = resolve_keys(manifest, &cfg)?;

    let mut report = BlockReport {
        job_id: manifest.job_id.clone(),
        shard_id: manifest.shard_id.clone(),
        block: "crypto".to_string(),
        rows_in,
        ..Default::default()
    };
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();

    guard_rid_not_targeted(manifest, &cfg)?;

    // ── Salted hashing: HMAC-SHA256 keyed by the AO's salt ───────────────────
    for col in &cfg.hashing_with_salt {
        if !shard.routed(manifest, col) {
            report.deferred.push(format!("hashing_with_salt:{col}"));
            continue;
        }
        let idx = required_column_index(&shard, col, "salted hashing")?;
        let salt = require_key(&keys.hash_salts, "hash_salts", col)?;
        let key = hash_key(&salt, &format!("{HASH_SALTS_FILE}: {col}"))?;
        let n =
            apply_to_column(&mut shard, idx, col, &mut |v| Ok(keyed_hash(&key, normalize_identifier(v).as_bytes())))?;
        counts.insert(format!("hashing_with_salt:{col}"), n);
        report.applied.push(format!("hashing_with_salt:{col}"));
    }

    // ── Encryption: AES-SIV, or FF1 when format-preserving ───────────────────
    let encrypt_cfgs: Vec<EncryptConfigLite> =
        cfg.encrypt.iter().map(parse_encrypt_config).collect::<Result<Vec<_>, _>>()?;
    for ecfg in &encrypt_cfgs {
        let label = if ecfg.format_preserving { "encrypt_fpe" } else { "encrypt" };
        if !shard.routed(manifest, &ecfg.column) {
            report.deferred.push(format!("{label}:{}", ecfg.column));
            continue;
        }
        let idx = required_column_index(&shard, &ecfg.column, label)?;
        let (store, name) = if ecfg.format_preserving {
            (&keys.fpe_keys, "fpe_keys")
        } else {
            (&keys.symmetric_keys, "symmetric_keys")
        };
        let key = require_key(store, name, &ecfg.column)?;
        let n = apply_to_column(&mut shard, idx, &ecfg.column, &mut |v| {
            let v = normalize_identifier(v);
            if ecfg.format_preserving {
                format_preserving_encrypt(&v, &key, &ecfg.column)
            } else {
                encrypt_value(&v, &key, &ecfg.column)
            }
        })?;
        counts.insert(format!("{label}:{}", ecfg.column), n);
        report.applied.push(format!("{label}:{}", ecfg.column));
    }

    let out = manifest.output_path();
    shard.write(&out)?;
    report.rows_out = shard.rows.len();
    report.output = Some(out.display().to_string());
    report.extra = Some(json!({ "preprocessing": counts }));
    Ok(report)
}

/// The keys for this shard: from the key directory when the manifest names
/// one, else the inline `keys`. Never both — two sources for one key is how a
/// shard ends up hashed under a different salt from its neighbours.
fn resolve_keys(manifest: &BlockManifest, cfg: &RuntimeConfig) -> Result<BlockKeys, PipelineError> {
    match &manifest.key_directory {
        Some(dir) if !manifest.keys.is_empty() => Err(validation(
            "BLOCK_MANIFEST_INVALID",
            "The manifest supplies keys both inline and through a key directory",
            &format!("use one: keys, or key_directory {}", dir.display()),
        )),
        Some(dir) => BlockKeys::from_key_directory(dir, cfg.shared_hash_salts),
        None => Ok(manifest.keys.clone()),
    }
}

fn guard_rid_not_targeted(manifest: &BlockManifest, cfg: &RuntimeConfig) -> Result<(), PipelineError> {
    let rid = &manifest.row_id_column;
    let hit = cfg.hashing_with_salt.iter().any(|c| c == rid)
        || cfg.encrypt.iter().filter_map(|v| parse_encrypt_config(v).ok()).any(|e| &e.column == rid);
    if hit {
        return Err(validation(
            "BLOCK_RID_PROTECTED",
            "The reserved row-id column is targeted by a crypto operation",
            &format!("'{rid}' is the orchestrator's join key — remove it from hashing/encrypt"),
        ));
    }
    Ok(())
}

/// Looks up key material the AO was supposed to provide, and checks its shape.
///
/// Deliberately does not fall back to generating one: see the module header.
/// A salt must be the 64 hex characters keygen writes ([`hash_key`] checks
/// that); an encryption key must be at least 32 hex characters, so a
/// placeholder such as `"x"` is refused rather than used as a key.
fn require_key(map: &BTreeMap<String, String>, store: &str, column: &str) -> Result<String, PipelineError> {
    let key = map.get(column).cloned().ok_or_else(|| {
        validation(
            "BLOCK_KEY_MISSING",
            "The orchestrator did not supply key material for a column routed to this shard",
            &format!(
                "{store}['{column}'] is absent — run `skald_ao keygen` and pass its key directory (or the keys) \
                 in the block manifest. This block never mints its own keys, because two shards of one column \
                 must share one key."
            ),
        )
    })?;
    if store != "hash_salts" && (key.len() < 32 || !key.bytes().all(|b| b.is_ascii_hexdigit())) {
        return Err(validation(
            "KEY_MATERIAL_INVALID",
            "An encryption key is not at least 32 hex characters",
            &format!("{store}['{column}'] — mint keys with `skald_ao keygen`"),
        ));
    }
    Ok(key)
}
