//! Block 1 — preprocessing: suppression, masking, charcloak, tokenization.
//!
//! Everything here is either irreversible or reversible only through a vault
//! that never leaves the TEE, and none of it needs a key. That is what makes
//! this the block the AO runs on itself rather than dispatching: the token
//! vault is the one piece of recoverable plaintext mapping the system
//! produces, and shipping it to a worker would put it outside the boundary the
//! user attested. The vault lives in the key directory, never among the
//! artifacts.
//!
//! Suppression is normally done earlier, by the AO's staging pass, so the
//! dropped columns never reach a container; it is supported here as well for
//! an AO that skips staging.
//!
//! Each value goes through the monolith's own functions — masking, class-
//! preserving randomisation, and random tokens checked against every token
//! already issued — in the monolith's order.

use super::{BlockManifest, BlockReport, Shard, apply_to_column, required_column_index};
use crate::pipeline::bootstrap::{PipelineError, RuntimeConfig, parse_runtime_config, validation};
use crate::pipeline::preprocess::TokenVaults;
use crate::pipeline::preprocess::crypto::{normalize_identifier, randomize_preserving_class};
use crate::pipeline::preprocess::masking::{
    MaskingConfigLite, TokenizationConfigLite, apply_masking_value, parse_masking_config, parse_tokenization_config,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub fn run(manifest: &BlockManifest) -> Result<BlockReport, PipelineError> {
    let cfg = parse_runtime_config(&manifest.config)?;
    let mut shard = Shard::read(manifest.input_path()?, &manifest.row_id_column)?;
    let rows_in = shard.rows.len();

    let mut report = BlockReport {
        job_id: manifest.job_id.clone(),
        shard_id: manifest.shard_id.clone(),
        block: "preprocess".to_string(),
        rows_in,
        ..Default::default()
    };
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();

    guard_rid_not_targeted(manifest, &cfg)?;

    apply_suppression(manifest, &cfg, &mut shard, &mut report, &mut counts)?;
    apply_masking(manifest, &cfg, &mut shard, &mut report, &mut counts)?;
    apply_charcloak(manifest, &cfg, &mut shard, &mut report, &mut counts)?;
    apply_tokenization(manifest, &cfg, &mut shard, &mut report, &mut counts)?;

    let out = manifest.output_path();
    shard.write(&out)?;

    report.rows_out = shard.rows.len();
    report.output = Some(out.display().to_string());
    report.extra = Some(json!({ "preprocessing": counts }));
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
    counts: &mut BTreeMap<String, u64>,
) -> Result<(), PipelineError> {
    let mut drop_idx = Vec::new();
    for col in &cfg.suppress {
        if !shard.routed(manifest, col) {
            report.deferred.push(format!("suppress:{col}"));
            continue;
        }
        // A suppressed column that is already gone is fine — the staging pass
        // removed it. Only a column the AO routed here *explicitly* and that is
        // absent is a routing error.
        match shard.column_index(col) {
            Some(i) => {
                drop_idx.push(i);
                counts.insert(format!("suppress:{col}"), shard.rows.len() as u64);
                report.applied.push(format!("suppress:{col}"));
            }
            None if manifest.columns.iter().any(|c| c == col) => {
                return Err(validation(
                    "BLOCK_COLUMN_NOT_IN_SHARD",
                    "A column routed to this shard is absent from the shard CSV",
                    &format!("column '{col}' required by suppression"),
                ));
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
        *row = keep.iter().map(|&i| row[i].clone()).collect();
    }
    shard.rid_idx = shard.headers.iter().position(|h| h == &manifest.row_id_column);
    Ok(())
}

fn apply_masking(
    manifest: &BlockManifest,
    cfg: &RuntimeConfig,
    shard: &mut Shard,
    report: &mut BlockReport,
    counts: &mut BTreeMap<String, u64>,
) -> Result<(), PipelineError> {
    let cfgs: Vec<MaskingConfigLite> = cfg.masking.iter().map(parse_masking_config).collect::<Result<Vec<_>, _>>()?;
    for m in &cfgs {
        if !shard.routed(manifest, &m.column) {
            report.deferred.push(format!("masking:{}", m.column));
            continue;
        }
        let idx = required_column_index(shard, &m.column, "masking")?;
        let n =
            apply_to_column(shard, idx, &m.column, &mut |v| apply_masking_value(v, m, &randomize_preserving_class))?;
        counts.insert(format!("masking:{}", m.column), n);
        report.applied.push(format!("masking:{}", m.column));
    }
    Ok(())
}

fn apply_charcloak(
    manifest: &BlockManifest,
    cfg: &RuntimeConfig,
    shard: &mut Shard,
    report: &mut BlockReport,
    counts: &mut BTreeMap<String, u64>,
) -> Result<(), PipelineError> {
    for col in &cfg.charcloak {
        if !shard.routed(manifest, col) {
            report.deferred.push(format!("charcloak:{col}"));
            continue;
        }
        let idx = required_column_index(shard, col, "charcloak")?;
        let n = apply_to_column(shard, idx, col, &mut |v| randomize_preserving_class(v))?;
        counts.insert(format!("charcloak:{col}"), n);
        report.applied.push(format!("charcloak:{col}"));
    }
    Ok(())
}

/// Tokenization is the one operation whose correctness depends on how the AO
/// sharded the data: tokens are random and each is checked against every
/// token the vault already holds, so two shards tokenising one column at once
/// could each issue the same token for different values. The planner marks
/// tokenised columns `row_parallel: false` for exactly this reason; here the
/// vault is read, extended and written back by this one invocation.
fn apply_tokenization(
    manifest: &BlockManifest,
    cfg: &RuntimeConfig,
    shard: &mut Shard,
    report: &mut BlockReport,
    counts: &mut BTreeMap<String, u64>,
) -> Result<(), PipelineError> {
    let cfgs: Vec<TokenizationConfigLite> =
        cfg.tokenization.iter().map(parse_tokenization_config).collect::<Result<Vec<_>, _>>()?;

    let mine: Vec<&TokenizationConfigLite> = cfgs.iter().filter(|t| shard.routed(manifest, &t.column)).collect();
    for t in cfgs.iter().filter(|t| !shard.routed(manifest, &t.column)) {
        report.deferred.push(format!("tokenization:{}", t.column));
    }
    if mine.is_empty() {
        return Ok(());
    }

    let vault_path = manifest.vault_path()?;
    let columns: Vec<&str> = mine.iter().map(|t| t.column.as_str()).collect();
    let mut vaults = TokenVaults::load(&vault_path, &columns)?;

    for tcfg in mine {
        let idx = required_column_index(shard, &tcfg.column, "tokenization")?;
        let vault = vaults
            .columns
            .get_mut(&tcfg.column)
            .ok_or_else(|| validation("INTERNAL_ERROR", "Token vault missing for column", &tcfg.column))?;
        let n = apply_to_column(shard, idx, &tcfg.column, &mut |v| vault.token_for(&normalize_identifier(v), tcfg))?;
        counts.insert(format!("tokenization:{}", tcfg.column), n);
        report.applied.push(format!("tokenization:{}", tcfg.column));
    }

    // Owner-only, in the key directory. Reported by name only, so the AO knows
    // the vault changed without the path landing among the artifacts.
    vaults.save(&vault_path)?;
    Ok(())
}
