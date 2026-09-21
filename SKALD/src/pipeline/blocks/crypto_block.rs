//! Block 2 — crypto: salted and unsalted hashing, pseudo-encryption, FPE.
//!
//! Every operation in this block is keyed, and the key is supplied by the
//! orchestrator. That is the whole difference between this block and
//! `preprocess`, and it is why this one is safe to dispatch: a worker that
//! holds a column and a key for that column learns nothing it was not already
//! given, and it holds no state that outlives the shard.
//!
//! The monolith generates salts and keys itself, lazily, per run. That is
//! correct when one process sees every row. It is not correct here: two
//! workers handed different row shards of the same column would each mint a
//! salt and the column would end up with two disjoint digest spaces, which
//! looks like ordinary hash output and is unrecoverable. So this block never
//! generates key material — a missing key is a hard failure with
//! `BLOCK_KEY_MISSING`, and `skald_ao keygen` is what fills the gap.

use super::{required_column_index, BlockKeys, BlockManifest, BlockReport, Shard};
use crate::pipeline::bootstrap::{parse_runtime_config, validation, PipelineError};
use crate::pipeline::preprocess::crypto::{
    format_preserving_encrypt_general, hash_hex, pseudo_encrypt, should_skip_value,
};
use crate::pipeline::preprocess::masking::{parse_encrypt_config, EncryptConfigLite};

pub fn run(manifest: &BlockManifest) -> Result<BlockReport, PipelineError> {
    let cfg = parse_runtime_config(&manifest.config)?;
    let input = manifest.input_path()?;
    let mut shard = Shard::read(input, &manifest.row_id_column)?;
    let rows_in = shard.rows.len();

    let mut report = BlockReport {
        job_id: manifest.job_id.clone(),
        shard_id: manifest.shard_id.clone(),
        block: "crypto".to_string(),
        rows_in,
        ..Default::default()
    };

    guard_rid_not_targeted(manifest, &cfg)?;

    // ── Salted hashing ───────────────────────────────────────────────────────
    for col in &cfg.hashing_with_salt {
        if !shard.routed(manifest, col) {
            report.deferred.push(format!("hash_salted:{col}"));
            continue;
        }
        let idx = required_column_index(&shard, col, "salted hashing")?;
        let salt = require_key(&manifest.keys, "hash_salts", col)?;
        for row in shard.rows.iter_mut() {
            let Some(v) = row.get(idx).cloned() else { continue };
            if should_skip_value(&v) {
                continue;
            }
            row[idx] = hash_hex(&format!("{salt}{v}"));
        }
        report.applied.push(format!("hash_salted:{col}"));
    }

    // ── Unsalted hashing ─────────────────────────────────────────────────────
    // Deterministic and keyless, so it needs nothing from the manifest.
    for col in &cfg.hashing_without_salt {
        if !shard.routed(manifest, col) {
            report.deferred.push(format!("hash:{col}"));
            continue;
        }
        let idx = required_column_index(&shard, col, "hashing")?;
        for row in shard.rows.iter_mut() {
            let Some(v) = row.get(idx).cloned() else { continue };
            if should_skip_value(&v) {
                continue;
            }
            row[idx] = hash_hex(&v);
        }
        report.applied.push(format!("hash:{col}"));
    }

    // ── Encryption (pseudo + format-preserving) ──────────────────────────────
    let encrypt_cfgs: Vec<EncryptConfigLite> =
        cfg.encrypt.iter().map(parse_encrypt_config).collect::<Result<Vec<_>, _>>()?;
    for ecfg in &encrypt_cfgs {
        let label = if ecfg.format_preserving { "fpe" } else { "encrypt" };
        if !shard.routed(manifest, &ecfg.column) {
            report.deferred.push(format!("{label}:{}", ecfg.column));
            continue;
        }
        let idx = required_column_index(&shard, &ecfg.column, label)?;
        let store = if ecfg.format_preserving { "fpe_keys" } else { "symmetric_keys" };
        let key = require_key(&manifest.keys, store, &ecfg.column)?;
        for row in shard.rows.iter_mut() {
            let Some(v) = row.get(idx).cloned() else { continue };
            if should_skip_value(&v) {
                continue;
            }
            row[idx] = if ecfg.format_preserving {
                format_preserving_encrypt_general(&v, &key, &ecfg.column)
            } else {
                pseudo_encrypt(&v, &key, &ecfg.column)
            };
        }
        report.applied.push(format!("{label}:{}", ecfg.column));
    }

    let out = manifest.output_path();
    shard.write(&out)?;
    report.rows_out = shard.rows.len();
    report.output = Some(out.display().to_string());
    Ok(report)
}

fn guard_rid_not_targeted(
    manifest: &BlockManifest,
    cfg: &crate::pipeline::bootstrap::RuntimeConfig,
) -> Result<(), PipelineError> {
    let rid = &manifest.row_id_column;
    let hit = cfg.hashing_with_salt.iter().any(|c| c == rid)
        || cfg.hashing_without_salt.iter().any(|c| c == rid)
        || cfg
            .encrypt
            .iter()
            .filter_map(|v| v.get("column").and_then(serde_json::Value::as_str))
            .any(|c| c == rid);
    if hit {
        return Err(validation(
            "BLOCK_RID_PROTECTED",
            "The reserved row-id column is targeted by a crypto operation",
            &format!("'{rid}' is the orchestrator's join key — remove it from hashing/encrypt"),
        ));
    }
    Ok(())
}

/// Looks up key material the AO was supposed to provide.
///
/// Deliberately does not fall back to generating one: see the module header.
fn require_key(keys: &BlockKeys, store: &str, column: &str) -> Result<String, PipelineError> {
    let map = match store {
        "hash_salts" => &keys.hash_salts,
        "symmetric_keys" => &keys.symmetric_keys,
        "fpe_keys" => &keys.fpe_keys,
        _ => unreachable!("unknown key store {store}"),
    };
    map.get(column).cloned().ok_or_else(|| {
        validation(
            "BLOCK_KEY_MISSING",
            "The orchestrator did not supply key material for a column routed to this shard",
            &format!(
                "keys.{store}['{column}'] is absent — run `skald_ao keygen` and pass the \
                 resulting keyset in the block manifest. This block never mints its own keys, \
                 because two shards of one column must share one key."
            ),
        )
    })
}
