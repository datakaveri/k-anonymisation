use crate::pipeline::bootstrap::{
    http_status_for, suggested_fix_for, ErrorPayload, PipelineError, StatusPayload,
};
use crate::pipeline::cli::{parse_args, CliError, CliOutcome, Paths};
use crate::pipeline::pipeline::run_pipeline_with;
use std::ffi::OsString;
use std::fs;
use std::path::Path;

pub fn main_entry() {
    let argv: Vec<OsString> = std::env::args_os().skip(1).collect();

    match parse_args(argv) {
        Ok(CliOutcome::Message(text)) => print!("{text}"),

        Ok(CliOutcome::Run(paths)) => {
            let status = match run_pipeline_with(&paths) {
                Ok(ok) => ok,
                Err(e) => status_for_error(e, &paths.log_file().display().to_string()),
            };
            finish(&paths, status);
        }

        // The command line is what failed, so the layout it would have selected
        // is unknown — the report goes to the default place, and to stderr,
        // where someone running this by hand will actually see it.
        Err(e) => {
            eprintln!("skald_pipeline: {} — {}", e.message, e.details);
            let paths = Paths::from_root(Path::new("."));
            let status = status_for_cli_error(&e, &paths.log_file().display().to_string());
            finish(&paths, status);
        }
    }
}

/// Writes `status.json` next to the log and sets the process's exit code from
/// it: 0 when the run succeeded, 1 when it did not.
fn finish(paths: &Paths, status: StatusPayload) {
    if let Err(e) = fs::create_dir_all(&paths.output_dir) {
        eprintln!("failed creating output directory {}: {e}", paths.output_dir.display());
        std::process::exit(1);
    }
    let status_path = paths.output_dir.join("status.json");
    match serde_json::to_string_pretty(&status) {
        Ok(body) => {
            if let Err(e) = fs::write(&status_path, body) {
                eprintln!("failed writing {}: {e}", status_path.display());
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("failed serializing status payload: {e}");
            std::process::exit(1);
        }
    }

    if status.status == "error" {
        std::process::exit(1);
    }
}

fn status_for_cli_error(e: &CliError, log_file: &str) -> StatusPayload {
    error_status("CLI_INVALID_ARGUMENT", e.message.clone(), e.details.clone(), log_file)
}

fn status_for_error(e: PipelineError, log_file: &str) -> StatusPayload {
    match e {
        PipelineError::Validation { code, message, details } => {
            error_status(code, message, details, log_file)
        }

        PipelineError::Io(e) => {
            let (code, msg) = match e.kind() {
                std::io::ErrorKind::NotFound => (
                    "IO_READ_FAILED",
                    "A required file or directory was not found",
                ),
                std::io::ErrorKind::PermissionDenied => (
                    "IO_PERMISSION_DENIED",
                    "Permission denied accessing a file or directory",
                ),
                std::io::ErrorKind::WriteZero
                | std::io::ErrorKind::StorageFull => (
                    "IO_WRITE_FAILED",
                    "Failed to write output — disk may be full",
                ),
                _ => ("IO_READ_FAILED", "An unexpected I/O error occurred"),
            };
            error_status(code, msg.to_string(), e.to_string(), log_file)
        }

        PipelineError::Json(e) => error_status(
            "CONFIG_PARSE_ERROR",
            "Failed to parse JSON configuration".to_string(),
            e.to_string(),
            log_file,
        ),
    }
}

fn error_status(code: &str, message: String, details: String, log_file: &str) -> StatusPayload {
    StatusPayload {
        status: "error".to_string(),
        phase: None,
        outputs: None,
        error: Some(ErrorPayload {
            suggested_fix: suggested_fix_for(code).to_string(),
            http_status_code: http_status_for(code),
            code: code.to_string(),
            message,
            details,
        }),
        log_file: log_file.to_string(),
    }
}
