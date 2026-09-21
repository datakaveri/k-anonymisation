//! Block 1 — preprocessing: suppression, masking, charcloak, tokenization.
//!
//! Everything here is either irreversible or reversible only through a vault
//! that never leaves the TEE, and none of it needs a key. That is what makes
//! this the block the AO runs on itself rather than dispatching: the token
//! vault is the one piece of recoverable plaintext mapping the system
//! produces, and shipping it to a worker would put it outside the boundary the
//! user attested.
//!
//! Suppression is deliberately the first thing that happens to a dataset. A
//! column dropped on the AO is a column that never reaches any container, so
//! running it before sharding shrinks the attack surface rather than just the
//! file.

use super::{required_column_index, BlockManifest, BlockReport, Shard};
use crate::pipeline::bootstrap::{parse_runtime_config, validation, PipelineError, RuntimeConfig};
use crate::pipeline::preprocess::crypto::{
    randomize_preserving_class, should_skip_value, write_json_pretty,
};
use crate::pipeline::preprocess::masking::{
    apply_masking_value, parse_masking_config, parse_tokenization_config, MaskingConfigLite,
    TokenizationConfigLite,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Forward and reverse token maps for one column, plus the next free id.
struct Vault {
    forward: BTreeMap<String, String>,
    reverse: BTreeMap<String, String>,
    next_id: u64,
}

pub fn run(manifest: &BlockManifest) -> Result<BlockReport, PipelineError> {
    let cfg = parse_runtime_config(&manifest.config)?;
    let input = manifest.input_path()?;
    let mut shard = Shard::read(input, &manifest.row_id_column)?;
    let rows_in = shard.rows.len();

    let mut report = BlockReport {
        job_id: manifest.job_id.clone(),
        shard_id: manifest.shard_id.clone(),
        block: "preprocess".to_string(),
        rows_in,
        ..Default::default()
    };

    guard_rid_not_targeted(manifest, &cfg)?;

    apply_suppression(manifest, &cfg, &mut shard, &mut report)?;
    apply_masking(manifest, &cfg, &mut shard, &mut report)?;
    apply_charcloak(manifest, &cfg, &mut shard, &mut report)?;
    let vault_written = apply_tokenization(manifest, &cfg, &mut shard, &mut report)?;

    let out = manifest.output_path();
    shard.write(&out)?;

    report.rows_out = shard.rows.len();
    report.output = Some(out.display().to_string());
    if vault_written {
        report.artifacts.push(manifest.vault_path().display().to_string());
    }
    Ok(report)
}

/// The rid is the AO's join key. A config that suppresses, masks or tokenizes
/// it would break column stitching in a way that is very hard to see in the
/// output, so it is refused up front.
fn guard_rid_not_targeted(manifest: &BlockManifest, cfg: &RuntimeConfig) -> Result<(), PipelineError> {
    let rid = &manifest.row_id_column;
    let hit = cfg.suppress.iter().any(|c| c == rid)
        || cfg.charcloak.iter().any(|c| c == rid)
        || cfg
            .masking
            .iter()
            .chain(cfg.tokenization.iter())
            .filter_map(|v| v.get("column").and_then(Value::as_str))
            .any(|c| c == rid);
    if hit {
        return Err(validation(
            "BLOCK_RID_PROTECTED",
            "The reserved row-id column is targeted by a preprocessing operation",
            &format!(
                "'{rid}' is how the orchestrator stitches column shards back together — \
                 remove it from suppress/masking/charcloak/tokenization"
            ),
        ));
    }
    Ok(())
}

fn apply_suppression(
    manifest: &BlockManifest,
    cfg: &RuntimeConfig,
    shard: &mut Shard,
    report: &mut BlockReport,
) -> Result<(), PipelineError> {
    let mut drop_idx = Vec::new();
    for col in &cfg.suppress {
        if !shard.routed(manifest, col) {
            report.deferred.push(format!("suppress:{col}"));
            continue;
        }
        // A suppressed column that is already gone is fine — an earlier block
        // or an earlier pass over this shard removed it. Only a column the AO
        // routed here and that is genuinely absent is a routing error, and
        // `routed()` above has already told us the AO meant it for us.
        match shard.column_index(col) {
            Some(i) => {
                drop_idx.push(i);
                report.applied.push(format!("suppress:{col}"));
            }
            None => report.deferred.push(format!("suppress:{col}")),
        }
    }
    if drop_idx.is_empty() {
        return Ok(());
    }
    drop_idx.sort_unstable();
    drop_idx.dedup();

    let keep: Vec<usize> = (0..shard.headers.len()).filter(|i| !drop_idx.contains(i)).collect();
    shard.headers = keep.iter().map(|&i| shard.headers[i].clone()).collect();
    for row in &mut shard.rows {
        *row = keep.iter().map(|&i| row.get(i).cloned().unwrap_or_default()).collect();
    }
    shard.rid_idx = shard.headers.iter().position(|h| h == &manifest.row_id_column);
    Ok(())
}

fn apply_masking(
    manifest: &BlockManifest,
    cfg: &RuntimeConfig,
    shard: &mut Shard,
    report: &mut BlockReport,
) -> Result<(), PipelineError> {
    let cfgs: Vec<MaskingConfigLite> =
        cfg.masking.iter().map(parse_masking_config).collect::<Result<Vec<_>, _>>()?;
    for m in &cfgs {
        if !shard.routed(manifest, &m.column) {
            report.deferred.push(format!("masking:{}", m.column));
            continue;
        }
        let idx = required_column_index(shard, &m.column, "masking")?;
        for row in shard.rows.iter_mut() {
            let Some(v) = row.get(idx).cloned() else { continue };
            if should_skip_value(&v) {
                continue;
            }
            row[idx] = apply_masking_value(&v, m, &randomize_preserving_class);
        }
        report.applied.push(format!("masking:{}", m.column));
    }
    Ok(())
}

fn apply_charcloak(
    manifest: &BlockManifest,
    cfg: &RuntimeConfig,
    shard: &mut Shard,
    report: &mut BlockReport,
) -> Result<(), PipelineError> {
    for col in &cfg.charcloak {
        if !shard.routed(manifest, col) {
            report.deferred.push(format!("charcloak:{col}"));
            continue;
        }
        let idx = required_column_index(shard, col, "charcloak")?;
        for row in shard.rows.iter_mut() {
            let Some(v) = row.get(idx).cloned() else { continue };
            if should_skip_value(&v) {
                continue;
            }
            row[idx] = randomize_preserving_class(&v);
        }
        report.applied.push(format!("charcloak:{col}"));
    }
    Ok(())
}

/// Tokenization is the one operation whose correctness depends on how the AO
/// sharded the data: two shards holding the same column would each allocate
/// ids from their own counter and produce colliding tokens for different
/// values. The planner marks tokenized columns `row_parallel: false` for
/// exactly this reason; here we assume that contract and take the vault
/// read-modify-write serially.
fn apply_tokenization(
    manifest: &BlockManifest,
    cfg: &RuntimeConfig,
    shard: &mut Shard,
    report: &mut BlockReport,
) -> Result<bool, PipelineError> {
    let cfgs: Vec<TokenizationConfigLite> = cfg
        .tokenization
        .iter()
        .map(parse_tokenization_config)
        .collect::<Result<Vec<_>, _>>()?;

    let mine: Vec<&TokenizationConfigLite> =
        cfgs.iter().filter(|t| shard.routed(manifest, &t.column)).collect();
    for t in cfgs.iter().filter(|t| !shard.routed(manifest, &t.column)) {
        report.deferred.push(format!("tokenize:{}", t.column));
    }
    if mine.is_empty() {
        return Ok(false);
    }

    let vault_path = manifest.vault_path();
    let mut vaults = load_vaults(&vault_path, &mine)?;

    for tcfg in mine {
        let idx = required_column_index(shard, &tcfg.column, "tokenization")?;
        let vault = vaults.get_mut(&tcfg.column).expect("vault seeded above");
        for row in shard.rows.iter_mut() {
            let Some(v) = row.get(idx).cloned() else { continue };
            if should_skip_value(&v) {
                continue;
            }
            if let Some(tok) = vault.forward.get(&v) {
                row[idx] = tok.clone();
            } else {
                let token =
                    format!("{}{:0width$}", tcfg.prefix, vault.next_id, width = tcfg.digits);
                vault.forward.insert(v.clone(), token.clone());
                vault.reverse.insert(token.clone(), v);
                vault.next_id += 1;
                row[idx] = token;
            }
        }
        report.applied.push(format!("tokenize:{}", tcfg.column));
    }

    save_vaults(&vault_path, &vaults)?;
    Ok(true)
}

fn load_vaults(
    path: &Path,
    cfgs: &[&TokenizationConfigLite],
) -> Result<BTreeMap<String, Vault>, PipelineError> {
    let existing: Value = if path.exists() {
        serde_json::from_str(&fs::read_to_string(path)?)?
    } else {
        serde_json::json!({})
    };
    let read_map = |col: &str, side: &str| -> BTreeMap<String, String> {
        existing
            .get(col)
            .and_then(|c| c.get(side))
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default()
    };

    let mut out = BTreeMap::new();
    for t in cfgs {
        let forward = read_map(&t.column, "forward");
        let reverse = read_map(&t.column, "reverse");
        let next_id = reverse.len() as u64 + 1;
        out.insert(t.column.clone(), Vault { forward, reverse, next_id });
    }
    Ok(out)
}

/// Merges this shard's additions back into whatever the vault file already
/// holds, so a column processed in several passes does not lose the mappings
/// of the columns it did not touch.
fn save_vaults(path: &Path, vaults: &BTreeMap<String, Vault>) -> Result<(), PipelineError> {
    let mut doc: Value = if path.exists() {
        serde_json::from_str(&fs::read_to_string(path)?)?
    } else {
        serde_json::json!({})
    };
    for (col, v) in vaults {
        doc[col] = serde_json::json!({
            "forward": v.forward.iter().map(|(k, t)| (k.clone(), Value::String(t.clone())))
                .collect::<serde_json::Map<_, _>>(),
            "reverse": v.reverse.iter().map(|(t, k)| (t.clone(), Value::String(k.clone())))
                .collect::<serde_json::Map<_, _>>(),
        });
    }
    write_json_pretty(path, &doc)
}
