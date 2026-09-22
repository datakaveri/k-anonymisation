//! The planner: turns one job config into a column-wise execution plan.
//!
//! This is what the AO calls first. Given a config saying, say, that columns
//! 3–6 need hashing and columns 1 and 7 need suppressing, it answers three
//! questions the orchestrator cannot answer on its own:
//!
//! - **which columns each block needs to see** — so the AO can project a shard
//!   holding those columns and nothing else;
//! - **what has to happen in what order** when a column is touched by more
//!   than one block (a hashed column that is also a quasi-identifier has to be
//!   hashed before it is generalized, or the generalization is meaningless);
//! - **which groups may be split across rows** — tokenization and k-anon may
//!   not, for opposite reasons, and getting that wrong corrupts output quietly.
//!
//! The plan is data, not instructions: the AO is free to schedule the groups
//! however it likes, as long as it respects `order` and `row_parallel`.

use super::{BlockKeys, BLOCK_SCHEMA_VERSION, DEFAULT_ROW_ID_COLUMN};
use crate::pipeline::bootstrap::{parse_runtime_config, validation, PipelineError, RuntimeConfig};
use crate::pipeline::preprocess::crypto::{generate_random_key_hex, generate_random_salt_hex};
use crate::pipeline::preprocess::masking::{parse_encrypt_config, parse_masking_config, parse_tokenization_config};
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::Path;

/// One dispatchable unit of work: a block, the columns it needs, and the
/// constraints the AO has to honour when scheduling it.
#[derive(Debug, Clone, Serialize)]
pub struct BlockGroup {
    /// `"preprocess"` | `"crypto"` | `"kanon"`.
    pub block: String,
    /// Relative order. Groups sharing a number may run concurrently; a higher
    /// number must not start until every lower one has finished for the columns
    /// they share.
    pub order: u32,
    /// Columns the AO should project into this group's shard, in config order.
    pub columns: Vec<String>,
    /// `"<op>:<column>"` for every operation this group will perform.
    pub operations: Vec<String>,
    /// Whether this group may be split into several row shards run in parallel.
    pub row_parallel: bool,
    /// Why not, when `row_parallel` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_parallel_note: Option<String>,
    /// Where this group is expected to execute.
    pub runs_on: String,
    /// Logical name the Co-ordinator resolves to an image digest.
    ///
    /// Deliberately not an image reference. Resolution is the Co-ordinator's
    /// business, so changing which image a role points at is not a change to
    /// anything the AO emits — and the digest that gets attested is the one the
    /// Co-ordinator reports back, never one this side guessed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_role: Option<String>,
    /// Which phase of the chunk manifest this group belongs to.
    pub phase: String,
    /// `kanon` only.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub stages: Vec<String>,
}

/// Key material the AO must mint before dispatching the crypto group.
#[derive(Debug, Clone, Default, Serialize)]
pub struct KeyRequirements {
    pub hash_salts: Vec<String>,
    pub symmetric_keys: Vec<String>,
    pub fpe_keys: Vec<String>,
}

impl KeyRequirements {
    pub fn is_empty(&self) -> bool {
        self.hash_salts.is_empty() && self.symmetric_keys.is_empty() && self.fpe_keys.is_empty()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct JobPlan {
    pub schema_version: u32,
    pub job_id: String,
    pub config: String,
    pub row_id_column: String,
    pub pass: String,
    pub k: i64,
    pub suppression_limit: f64,
    pub enable_k_anonymity: bool,
    pub groups: Vec<BlockGroup>,
    /// Columns no block touches. The AO carries them through untouched — they
    /// never need to leave the orchestrator.
    pub passthrough_columns: Vec<String>,
    pub keys_required: KeyRequirements,
    /// Columns handled by more than one block, with the order they run in.
    /// Surfaced explicitly because this is where a plan is most likely to be
    /// misread.
    pub multi_block_columns: Vec<MultiBlockColumn>,
    /// Advisory notes for the orchestrator — not errors, but things that change
    /// how the job should be scheduled.
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MultiBlockColumn {
    pub column: String,
    pub blocks: Vec<String>,
}

/// Logical container roles, matching the names the chunk-manifest contract's
/// worked example uses. These are resolved to image digests by the
/// Co-ordinator, not here.
const ROLE_PREPROCESS: &str = "skald-preprocess";
const ROLE_CRYPTO: &str = "skald-crypto";
const ROLE_KANON: &str = "skald-kanon";

/// Builds the plan for a job config.
///
/// `header` is the input dataset's column list when the AO already knows it.
/// Supplying it is what lets the planner catch a config naming a column the
/// data does not have, and what lets it report passthrough columns — without
/// it the plan is still correct, just less informative.
pub fn build_plan(
    config_path: &Path,
    job_id: &str,
    header: Option<&[String]>,
) -> Result<JobPlan, PipelineError> {
    let cfg = parse_runtime_config(config_path)?;
    let mut notes = Vec::new();

    let masking_cols: Vec<String> = cfg
        .masking
        .iter()
        .map(parse_masking_config)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|m| m.column)
        .collect();
    let token_cols: Vec<String> = cfg
        .tokenization
        .iter()
        .map(parse_tokenization_config)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|t| t.column)
        .collect();
    let encrypt_cfgs = cfg
        .encrypt
        .iter()
        .map(parse_encrypt_config)
        .collect::<Result<Vec<_>, _>>()?;
    let (fpe_cols, sym_cols): (Vec<String>, Vec<String>) = {
        let mut f = Vec::new();
        let mut s = Vec::new();
        for e in &encrypt_cfgs {
            if e.format_preserving { f.push(e.column.clone()) } else { s.push(e.column.clone()) }
        }
        (f, s)
    };

    let qi_cols: Vec<String> = cfg
        .numerical_qis
        .iter()
        .map(|q| q.column.clone())
        .chain(cfg.categorical_qis.iter().cloned())
        .collect();

    // ── Group 0: staging, on the AO ──────────────────────────────────────────
    // Cleaning and suppression are the orchestrator's, and for different
    // reasons. Cleaning decides the row set, so it has to settle before
    // anything is chunked or the row ranges in the manifest describe a dataset
    // that no longer exists. Suppression drops whole columns, and doing it here
    // means those columns never reach a container at all.
    //
    // Nothing else stays: masking, charcloak and tokenisation are ordinary
    // column transforms and belong in a worker.
    let mut stage_ops = Vec::new();
    let mut stage_cols: Vec<String> = Vec::new();
    if cfg.cleaning.enabled {
        stage_ops.push("clean:*".to_string());
        for c in &cfg.cleaning.required_columns {
            stage_ops.push(format!("require_non_null:{c}"));
            push_unique(&mut stage_cols, c);
        }
        for c in &cfg.cleaning.numeric_columns {
            stage_ops.push(format!("coerce_numeric:{c}"));
            push_unique(&mut stage_cols, c);
        }
    }
    for c in &cfg.suppress {
        stage_ops.push(format!("suppress:{c}"));
        push_unique(&mut stage_cols, c);
    }

    // ── Group 1: preprocess, dispatched ──────────────────────────────────────
    let mut pre_ops = Vec::new();
    let mut pre_cols: Vec<String> = Vec::new();
    for c in &masking_cols {
        pre_ops.push(format!("masking:{c}"));
        push_unique(&mut pre_cols, c);
    }
    for c in &cfg.charcloak {
        pre_ops.push(format!("charcloak:{c}"));
        push_unique(&mut pre_cols, c);
    }
    for c in &token_cols {
        pre_ops.push(format!("tokenize:{c}"));
        push_unique(&mut pre_cols, c);
    }

    // ── Group 2: crypto, dispatched ──────────────────────────────────────────
    let mut crypto_ops = Vec::new();
    let mut crypto_cols: Vec<String> = Vec::new();
    let mut keys_required = KeyRequirements::default();
    for c in &cfg.hashing_with_salt {
        crypto_ops.push(format!("hash_salted:{c}"));
        push_unique(&mut crypto_cols, c);
        push_unique(&mut keys_required.hash_salts, c);
    }
    for c in &cfg.hashing_without_salt {
        crypto_ops.push(format!("hash:{c}"));
        push_unique(&mut crypto_cols, c);
    }
    for c in &sym_cols {
        crypto_ops.push(format!("encrypt:{c}"));
        push_unique(&mut crypto_cols, c);
        push_unique(&mut keys_required.symmetric_keys, c);
    }
    for c in &fpe_cols {
        crypto_ops.push(format!("fpe:{c}"));
        push_unique(&mut crypto_cols, c);
        push_unique(&mut keys_required.fpe_keys, c);
    }

    // ── Conflict checks ──────────────────────────────────────────────────────
    // A suppressed column is gone by the time anything else runs, so any later
    // reference to it is a config bug the AO should see now rather than as a
    // worker failure ten minutes into the job.
    for c in &cfg.suppress {
        if qi_cols.iter().any(|q| q == c) {
            return Err(validation(
                "PLAN_COLUMN_CONFLICT",
                "A column is both suppressed and used as a quasi-identifier",
                &format!("'{c}' cannot be dropped and generalized — remove it from one of them"),
            ));
        }
        if crypto_cols.iter().any(|x| x == c) {
            return Err(validation(
                "PLAN_COLUMN_CONFLICT",
                "A column is both suppressed and sent to the crypto block",
                &format!("'{c}' is dropped before the crypto block runs — remove it from one of them"),
            ));
        }
        if pre_cols.iter().any(|x| x == c) {
            return Err(validation(
                "PLAN_COLUMN_CONFLICT",
                "A column is both suppressed and sent to the preprocess block",
                &format!(
                    "'{c}' is dropped during staging, before any container runs — \
                     remove it from one of them"
                ),
            ));
        }
    }

    // Cleaning reads columns the staging pass must still have in hand.
    for c in cfg.cleaning.required_columns.iter().chain(cfg.cleaning.numeric_columns.iter()) {
        if cfg.suppress.iter().any(|s| s == c) {
            return Err(validation(
                "PLAN_COLUMN_CONFLICT",
                "A column used by cleaning is also suppressed",
                &format!(
                    "'{c}' — staging cleans before it suppresses, so this works, but the \
                     intent is ambiguous enough to be worth stating explicitly"
                ),
            ));
        }
    }

    // Hashing or encrypting a QI destroys the ordering and the domain the
    // lattice search depends on. It is legal (the values still group), but the
    // result is categorical-by-accident, so the AO is told.
    for c in &qi_cols {
        if crypto_cols.iter().any(|x| x == c) {
            notes.push(format!(
                "Column '{c}' is both a quasi-identifier and a crypto target. The crypto group \
                 runs first, so k-anon will generalize ciphertext/digests — numeric ordering and \
                 interval constraints will not survive. Confirm this is intended."
            ));
        }
        if pre_cols.iter().any(|x| x == c) {
            notes.push(format!(
                "Column '{c}' is both a quasi-identifier and a preprocessing target. \
                 Preprocessing runs first, so k-anon sees the transformed values."
            ));
        }
    }

    // ── Header validation ────────────────────────────────────────────────────
    let mut passthrough = Vec::new();
    if let Some(cols) = header {
        let known: BTreeSet<&String> = cols.iter().collect();
        let mut missing = Vec::new();
        for c in stage_cols.iter().chain(pre_cols.iter()).chain(crypto_cols.iter()).chain(qi_cols.iter()) {
            if !known.contains(c) && c != DEFAULT_ROW_ID_COLUMN {
                push_unique(&mut missing, c);
            }
        }
        if !missing.is_empty() {
            // The most likely cause is passing an already-staged file: planning
            // happens before staging, because the plan is what decides which
            // columns staging suppresses.
            let suppressed_and_missing: Vec<&String> =
                missing.iter().filter(|c| cfg.suppress.contains(c)).collect();
            let hint = if suppressed_and_missing.is_empty() {
                "check the column names against the dataset header — they are case-sensitive"
            } else {
                "these are all suppressed columns, so this looks like a staged file — \
                 plan against the RAW input, since the plan is what tells staging to drop them"
            };
            return Err(validation(
                "PLAN_COLUMN_MISSING",
                "The config targets columns that are not in the dataset",
                &format!("{} — {hint}", missing.join(", ")),
            ));
        }
        let touched: BTreeSet<&String> = stage_cols
            .iter()
            .chain(pre_cols.iter())
            .chain(crypto_cols.iter())
            .chain(qi_cols.iter())
            .collect();
        for c in cols {
            if c != &cfg.output_path && !touched.contains(c) && c != DEFAULT_ROW_ID_COLUMN {
                passthrough.push(c.clone());
            }
        }
    }

    // ── Assemble ─────────────────────────────────────────────────────────────
    let mut groups = Vec::new();

    if !stage_ops.is_empty() {
        groups.push(BlockGroup {
            block: "stage".to_string(),
            order: 0,
            columns: stage_cols.clone(),
            operations: stage_ops,
            // One pass over the whole file on the orchestrator. It could be
            // parallelised, but it has to finish before row ranges exist at
            // all, so there is nothing yet to parallelise against.
            row_parallel: false,
            row_parallel_note: Some(
                "cleaning decides the row set, so it must complete before the dataset is \
                 chunked — there are no row ranges to fan out over until it has"
                    .to_string(),
            ),
            runs_on: "orchestrator".to_string(),
            container_role: None,
            phase: "stage".to_string(),
            stages: vec![],
        });
    }

    if !pre_ops.is_empty() {
        // Tokenisation allocates sequential ids from a shared vault. Two row
        // shards of one tokenised column would each start from their own
        // counter and mint the same token for different values, so the column
        // may be split by column but never by row.
        let tokenized = !token_cols.is_empty();
        groups.push(BlockGroup {
            block: "preprocess".to_string(),
            order: 1,
            columns: pre_cols.clone(),
            operations: pre_ops,
            row_parallel: !tokenized,
            row_parallel_note: tokenized.then(|| {
                format!(
                    "tokenisation allocates sequential ids from a shared vault ({}) — \
                     give each tokenised column a single shard covering all its rows. \
                     The vault comes back as an artifact and belongs in the TEE.",
                    token_cols.join(", ")
                )
            }),
            runs_on: "container".to_string(),
            container_role: Some(ROLE_PREPROCESS.to_string()),
            phase: "preprocess".to_string(),
            stages: vec![],
        });
    }

    if !crypto_ops.is_empty() {
        groups.push(BlockGroup {
            block: "crypto".to_string(),
            order: 2,
            columns: crypto_cols.clone(),
            operations: crypto_ops,
            // Safe to fan out precisely because the AO minted the keys: every
            // shard of a column uses the same salt and the same key.
            row_parallel: true,
            row_parallel_note: None,
            runs_on: "container".to_string(),
            container_role: Some(ROLE_CRYPTO.to_string()),
            phase: "preprocess".to_string(),
            stages: vec![],
        });
    }

    if cfg.enable_k_anonymity && !qi_cols.is_empty() {
        groups.push(BlockGroup {
            block: "kanon".to_string(),
            order: 3,
            // The whole QI tuple, together. This group is the reason column
            // sharding has a floor: k-anonymity over a subset of the QIs is a
            // different (and weaker) guarantee than the one the job asked for.
            columns: qi_cols.clone(),
            operations: qi_cols.iter().map(|c| format!("generalize:{c}")).collect(),
            row_parallel: true,
            row_parallel_note: None,
            runs_on: "container".to_string(),
            container_role: Some(ROLE_KANON.to_string()),
            phase: "measure+apply".to_string(),
            // `solve` is absent on purpose: it reduces scan artifacts and runs
            // on the orchestrator. See the note below.
            stages: if cfg.pass == "pass1" {
                vec!["scan".to_string()]
            } else {
                vec!["scan".to_string(), "apply".to_string()]
            },
        });
        notes.push(
            "kanon row shards fan out for 'scan' (the measure phase) and 'apply'. Never split \
             the QI columns across shards — k-anonymity over part of the tuple is a different \
             and weaker guarantee than the one the job asked for."
                .to_string(),
        );
        notes.push(
            "'solve' runs on the orchestrator, not in a container: it reduces the scan artifacts \
             and searches the lattice over a histogram, never over rows. Keeping it here means no \
             container is held open across the user's choice of k — the measure containers exit \
             at the barrier and the apply containers are not started until the choice is made."
                .to_string(),
        );
        if cfg.pass == "pass1" {
            notes.push(
                "pass1 ends at the measure barrier and persists artifacts/histogram.json. The \
                 k x suppression_limit table comes from `skald_ao grid` against that file, costs \
                 no container time, and can be recomputed for any axes the UI asks for. Pass 2 is \
                 `skald_ao solve` over the same file, then the apply phase."
                    .to_string(),
            );
        }
    } else if !cfg.enable_k_anonymity {
        notes.push("k-anonymity is disabled for this job — no kanon group was planned.".to_string());
    }

    let mut multi_block_columns = Vec::new();
    let all: BTreeSet<&String> = stage_cols
        .iter()
        .chain(pre_cols.iter())
        .chain(crypto_cols.iter())
        .chain(qi_cols.iter())
        .collect();
    for c in all {
        let mut blocks = Vec::new();
        if stage_cols.contains(c) {
            blocks.push("stage".to_string());
        }
        if pre_cols.contains(c) {
            blocks.push("preprocess".to_string());
        }
        if crypto_cols.contains(c) {
            blocks.push("crypto".to_string());
        }
        if qi_cols.contains(c) {
            blocks.push("kanon".to_string());
        }
        if blocks.len() > 1 {
            multi_block_columns.push(MultiBlockColumn { column: c.clone(), blocks });
        }
    }

    Ok(JobPlan {
        schema_version: BLOCK_SCHEMA_VERSION,
        job_id: job_id.to_string(),
        config: config_path.display().to_string(),
        row_id_column: DEFAULT_ROW_ID_COLUMN.to_string(),
        pass: cfg.pass.clone(),
        k: cfg.k,
        suppression_limit: cfg.suppression_limit,
        enable_k_anonymity: cfg.enable_k_anonymity,
        groups,
        passthrough_columns: passthrough,
        keys_required,
        multi_block_columns,
        notes,
    })
}

/// Mints the key material a plan says the crypto block will need.
///
/// This runs on the AO, inside the TEE, exactly once per job. Every row shard
/// of a column then receives the same salt and the same key — which is the
/// property that makes the crypto block safe to fan out, and the reason the
/// crypto block refuses to generate anything itself.
pub fn generate_keys(cfg: &RuntimeConfig) -> Result<BlockKeys, PipelineError> {
    let mut keys = BlockKeys::default();
    for c in &cfg.hashing_with_salt {
        keys.hash_salts.entry(c.clone()).or_insert_with(generate_random_salt_hex);
    }
    for e in cfg.encrypt.iter().map(parse_encrypt_config).collect::<Result<Vec<_>, _>>()? {
        let store = if e.format_preserving { &mut keys.fpe_keys } else { &mut keys.symmetric_keys };
        store.entry(e.column).or_insert_with(generate_random_key_hex);
    }
    Ok(keys)
}

fn push_unique(v: &mut Vec<String>, s: &str) {
    if !v.iter().any(|x| x == s) {
        v.push(s.to_string());
    }
}
