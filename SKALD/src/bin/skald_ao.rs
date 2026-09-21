//! Orchestrator-side toolkit for the Anonymization Orchestrator.
//!
//! The AO owns everything that has to happen once per job and in one place:
//! deciding how to shard, minting key material, stamping row ids, projecting
//! column shards, and stitching the results back together. None of it touches
//! a worker, and all of it runs inside the TEE the user attested.
//!
//! ```text
//!   skald_ao plan    --config <cfg> [--job <id>] [--data <csv>] [--out plan.json]
//!   skald_ao keygen  --config <cfg> [--out keys.json]
//!   skald_ao stamp   --input <csv> --out <staged.csv> [--rid <col>]
//!   skald_ao project --input <staged.csv> --out <shard.csv> --columns a,b,c
//!   skald_ao split   --input <shard.csv> --out-dir <dir> --rows <n> [--prefix p]
//!   skald_ao stitch  --base <staged.csv> --out <final.csv> --shards a.csv,b.csv \
//!                    --routed a,b,c
//! ```
//!
//! Every subcommand prints JSON on stdout and exits non-zero on failure, so the
//! orchestrator can drive it without scraping text.

use skald_ola2::pipeline::blocks::plan::{build_plan, generate_keys};
use skald_ola2::pipeline::blocks::shard::{project_columns, split_rows, stamp_row_ids, stitch_columns};
use skald_ola2::pipeline::blocks::DEFAULT_ROW_ID_COLUMN;
use skald_ola2::pipeline::bootstrap::{parse_runtime_config, split_csv_line_basic, PipelineError};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        eprintln!("{USAGE}");
        std::process::exit(if args.is_empty() { 2 } else { 0 });
    }
    let cmd = args[0].clone();
    let flags = parse_flags(&args[1..]);

    let result = match cmd.as_str() {
        "plan" => cmd_plan(&flags),
        "keygen" => cmd_keygen(&flags),
        "stamp" => cmd_stamp(&flags),
        "project" => cmd_project(&flags),
        "split" => cmd_split(&flags),
        "stitch" => cmd_stitch(&flags),
        other => {
            eprintln!("skald_ao: unknown subcommand '{other}'\n\n{USAGE}");
            std::process::exit(2);
        }
    };

    match result {
        Ok(v) => {
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        }
        Err(e) => {
            eprintln!("skald_ao {cmd}: {e}");
            let (code, message, details) = match &e {
                PipelineError::Validation { code, message, details } => {
                    (code.to_string(), message.clone(), details.clone())
                }
                PipelineError::Io(io) => {
                    ("IO_READ_FAILED".to_string(), "I/O error".to_string(), io.to_string())
                }
                PipelineError::Json(j) => {
                    ("CONFIG_PARSE_ERROR".to_string(), "JSON error".to_string(), j.to_string())
                }
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": "error",
                    "error": { "code": code, "message": message, "details": details }
                }))
                .unwrap_or_default()
            );
            std::process::exit(1);
        }
    }
}

const USAGE: &str = "\
skald_ao — orchestrator-side toolkit for SKALD block execution

  plan    --config <cfg.json> [--job <id>] [--data <input.csv>] [--out <plan.json>]
          Column-wise execution plan: which block sees which columns, in what
          order, and which groups may be row-parallel. Pass --data to have the
          plan validated against the real header and report passthrough columns.

  keygen  --config <cfg.json> [--out <keys.json>]
          Mint the per-column salts and keys the crypto block needs. Run once
          per job, inside the TEE. Workers never generate key material.

  stamp   --input <input.csv> --out <staged.csv> [--rid <col>]
          Prepend the reserved row-id column used to stitch shards back.

  project --input <staged.csv> --out <shard.csv> --columns <a,b,c> [--rid <col>]
          Write a shard holding only the row id and the named columns.

  split   --input <shard.csv> --out-dir <dir> --rows <n> [--prefix <p>]
          Split a shard into row shards for fan-out.

  stitch  --base <staged.csv> --shards <a.csv,b.csv> --routed <a,b,c>
          --out <final.csv> [--rid <col>]
          Rejoin processed column shards on the row id. --routed is every
          column sent to any block: it is what tells a suppressed column apart
          from one that simply stayed on the orchestrator.
";

// ── Subcommands ──────────────────────────────────────────────────────────────

fn cmd_plan(f: &Flags) -> Result<serde_json::Value, PipelineError> {
    let config = f.path("config")?;
    let job_id = f.get("job").cloned().unwrap_or_else(|| "job".to_string());
    let header = match f.get("data") {
        Some(p) => Some(read_header(Path::new(p))?),
        None => None,
    };
    let plan = build_plan(&config, &job_id, header.as_deref())?;
    let value = serde_json::to_value(&plan)?;
    if let Some(out) = f.get("out") {
        write_json(Path::new(out), &value)?;
    }
    Ok(value)
}

fn cmd_keygen(f: &Flags) -> Result<serde_json::Value, PipelineError> {
    let cfg = parse_runtime_config(&f.path("config")?)?;
    let keys = generate_keys(&cfg)?;
    let value = serde_json::to_value(&keys)?;
    if let Some(out) = f.get("out") {
        write_json(Path::new(out), &value)?;
    }
    Ok(value)
}

fn cmd_stamp(f: &Flags) -> Result<serde_json::Value, PipelineError> {
    let rid = f.rid();
    let rows = stamp_row_ids(&f.path("input")?, &f.path("out")?, &rid)?;
    Ok(json!({ "status": "success", "rows": rows, "row_id_column": rid,
               "output": f.get("out") }))
}

fn cmd_project(f: &Flags) -> Result<serde_json::Value, PipelineError> {
    let cols = f.list("columns");
    let rid = f.rid();
    let rows = project_columns(&f.path("input")?, &f.path("out")?, &cols, &rid)?;
    Ok(json!({ "status": "success", "rows": rows, "columns": cols,
               "output": f.get("out") }))
}

fn cmd_split(f: &Flags) -> Result<serde_json::Value, PipelineError> {
    let n: usize = f
        .get("rows")
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000);
    let prefix = f.get("prefix").cloned().unwrap_or_else(|| "shard".to_string());
    let paths = split_rows(&f.path("input")?, &f.path("out-dir")?, &prefix, n)?;
    Ok(json!({
        "status": "success",
        "rows_per_shard": n,
        "shards": paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
    }))
}

fn cmd_stitch(f: &Flags) -> Result<serde_json::Value, PipelineError> {
    let shards: Vec<PathBuf> = f.list("shards").into_iter().map(PathBuf::from).collect();
    let routed = f.list("routed");
    let rid = f.rid();
    let rows = stitch_columns(&f.path("base")?, &shards, &routed, &f.path("out")?, &rid)?;
    Ok(json!({ "status": "success", "rows": rows, "output": f.get("out") }))
}

// ── Flag parsing ─────────────────────────────────────────────────────────────

struct Flags(HashMap<String, String>);

impl Flags {
    fn get(&self, k: &str) -> Option<&String> {
        self.0.get(k)
    }

    fn path(&self, k: &str) -> Result<PathBuf, PipelineError> {
        self.0.get(k).map(PathBuf::from).ok_or_else(|| {
            skald_ola2::pipeline::bootstrap::validation(
                "CONFIG_MISSING_FIELD",
                "A required argument is missing",
                &format!("--{k}"),
            )
        })
    }

    fn list(&self, k: &str) -> Vec<String> {
        self.0
            .get(k)
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn rid(&self) -> String {
        self.0.get("rid").cloned().unwrap_or_else(|| DEFAULT_ROW_ID_COLUMN.to_string())
    }
}

fn parse_flags(args: &[String]) -> Flags {
    let mut map = HashMap::new();
    let mut i = 0;
    while i < args.len() {
        if let Some(name) = args[i].strip_prefix("--") {
            if let Some(v) = args.get(i + 1).filter(|v| !v.starts_with("--")) {
                map.insert(name.to_string(), v.clone());
                i += 2;
                continue;
            }
            map.insert(name.to_string(), "true".to_string());
        }
        i += 1;
    }
    Flags(map)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn read_header(path: &Path) -> Result<Vec<String>, PipelineError> {
    let f = fs::File::open(path).map_err(|e| {
        skald_ola2::pipeline::bootstrap::validation(
            "IO_READ_FAILED",
            "Could not read the dataset header",
            &format!("{}: {e}", path.display()),
        )
    })?;
    let mut lines = BufReader::new(f).lines();
    let line = lines
        .next()
        .ok_or_else(|| {
            skald_ola2::pipeline::bootstrap::validation(
                "DATA_EMPTY",
                "Dataset has no header row",
                &path.display().to_string(),
            )
        })?
        .map_err(|e| {
            skald_ola2::pipeline::bootstrap::validation(
                "IO_READ_FAILED",
                "Failed reading header",
                &e.to_string(),
            )
        })?;
    Ok(split_csv_line_basic(&line))
}

fn write_json(path: &Path, value: &serde_json::Value) -> Result<(), PipelineError> {
    if let Some(p) = path.parent() {
        if !p.as_os_str().is_empty() {
            fs::create_dir_all(p)?;
        }
    }
    fs::write(path, serde_json::to_string_pretty(value)?)?;
    Ok(())
}
