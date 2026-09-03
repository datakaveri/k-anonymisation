//! Runtime layout — where the pipeline reads its config and input from, and
//! where it writes its results.
//!
//! Every path resolves the same way: an explicit command-line flag wins, then
//! the matching `SKALD_*` environment variable, then a default relative to
//! `--root` (itself defaulting to the process's working directory). That keeps
//! the original contract — "run the binary from a directory holding `config/`,
//! `data/` and `output/`" — working untouched, while letting one packaged
//! binary be pointed at a different config and a different input on every run.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Everything the pipeline needs to know about *where* to work.
#[derive(Debug, Clone, PartialEq)]
pub struct Paths {
    /// Base directory the defaults hang off.
    pub root: PathBuf,
    /// A config file named explicitly. `None` → discover the first `*.json`
    /// in [`Paths::config_dir`], which is the historical behaviour.
    pub config_file: Option<PathBuf>,
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    /// A single input file named explicitly, bypassing the `data_dir` scan.
    pub data_file: Option<PathBuf>,
    pub chunks_dir: PathBuf,
    pub output_dir: PathBuf,
    /// True when `output_dir` came from a flag or the environment. The config's
    /// own `output_directory` must not then relocate key material away from the
    /// directory the operator explicitly asked for.
    pub output_dir_explicit: bool,
}

impl Paths {
    /// The historical layout: `config/`, `data/`, `chunks/` and `output/` all
    /// directly under `root`.
    pub fn from_root(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            config_file: None,
            config_dir: root.join("config"),
            data_dir: root.join("data"),
            data_file: None,
            chunks_dir: root.join("chunks"),
            output_dir: root.join("output"),
            output_dir_explicit: false,
        }
    }

    /// Where preprocessing keeps key material (token vault, symmetric keys, FPE
    /// keys). Normally the config's `output_directory`, resolved against `root`
    /// — but an explicit `--output` wins, so relocating the run's outputs takes
    /// the keys with it instead of stranding them under the old root.
    ///
    /// Always absolute. Preprocessing falls back to re-deriving this directory
    /// from the chunk paths when it is given a relative one, which lands the
    /// keys somewhere else entirely as soon as `--chunks` is not a sibling of
    /// the output directory — `--output out --chunks scratch/x` wrote them to
    /// `scratch/out`. Handing over an absolute path removes the guesswork.
    pub fn key_material_dir(&self, config_output_directory: &str) -> PathBuf {
        let chosen = if self.output_dir_explicit {
            self.output_dir.clone()
        } else {
            let configured = Path::new(config_output_directory);
            if configured.is_absolute() {
                configured.to_path_buf()
            } else {
                self.root.join(configured)
            }
        };
        // Purely lexical — no filesystem access, so this works for a directory
        // that does not exist yet.
        std::path::absolute(&chosen).unwrap_or(chosen)
    }

    /// Path of `pipeline.log`, as reported in `status.json`.
    pub fn log_file(&self) -> PathBuf {
        self.output_dir.join("pipeline.log")
    }
}

/// A command line that asked for something other than a pipeline run.
#[derive(Debug, Clone, PartialEq)]
pub enum CliOutcome {
    /// Run the pipeline with this layout.
    Run(Box<Paths>),
    /// Print this text and exit successfully (`--help`, `--version`).
    Message(String),
}

/// A command line that could not be understood. Carries the same two fields the
/// status payload needs, so `entry` can report it exactly like any other error.
#[derive(Debug, Clone, PartialEq)]
pub struct CliError {
    pub message: String,
    pub details: String,
}

impl CliError {
    fn new(message: &str, details: &str) -> Self {
        Self { message: message.to_string(), details: details.to_string() }
    }
}

pub const HELP: &str = "\
skald_pipeline — k-anonymisation and preprocessing pipeline

USAGE:
    skald_pipeline [OPTIONS]

OPTIONS:
    -c, --config <PATH>   Config JSON file, or a directory to search for the
                          first *.json in it        [env: SKALD_CONFIG]
                          (default: <root>/config)
    -d, --data <PATH>     Input directory holding exactly one .csv/.json/.xlsx,
                          or a single input file    [env: SKALD_DATA]
                          (default: <root>/data)
    -o, --output <DIR>    Directory for results, logs and key material
                                                    [env: SKALD_OUTPUT]
                          (default: <root>/output)
        --chunks <DIR>    Scratch directory for chunked CSV
                                                    [env: SKALD_CHUNKS]
                          (default: <root>/chunks)
    -r, --root <DIR>      Base directory the defaults above hang off
                                                    [env: SKALD_ROOT]
                          (default: the working directory)
    -h, --help            Print this help and exit
    -V, --version         Print the version and exit

A command-line flag always wins over the environment variable, which wins over
the default. Postgres input and output are configured in the config JSON itself
(`input` / `output_sink`), not on the command line.

EXIT CODES:
    0  pipeline completed          1  pipeline failed — see output/status.json
";

/// Parses `argv` (already stripped of the program name) against the process
/// environment.
pub fn parse_args<I>(argv: I) -> Result<CliOutcome, CliError>
where
    I: IntoIterator<Item = OsString>,
{
    parse_args_with_env(argv, |key| std::env::var_os(key).map(PathBuf::from))
}

/// Same as [`parse_args`] but with the environment injected, so tests can
/// exercise the precedence rules without mutating process-global state.
pub fn parse_args_with_env<I, F>(argv: I, env: F) -> Result<CliOutcome, CliError>
where
    I: IntoIterator<Item = OsString>,
    F: Fn(&str) -> Option<PathBuf>,
{
    let mut config: Option<PathBuf> = None;
    let mut data: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut chunks: Option<PathBuf> = None;
    let mut root: Option<PathBuf> = None;

    let mut args = argv.into_iter().peekable();
    while let Some(raw) = args.next() {
        let arg = raw.to_string_lossy().into_owned();

        // `--flag=value` is split here so both spellings share one code path.
        let (name, inline_value) = match arg.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n.to_string(), Some(OsString::from(v))),
            _ => (arg.clone(), None),
        };

        let mut take_value = |flag: &str| -> Result<PathBuf, CliError> {
            match inline_value.clone().or_else(|| args.next()) {
                Some(v) if !v.is_empty() => Ok(PathBuf::from(v)),
                _ => Err(CliError::new(
                    "Command-line flag is missing its value",
                    &format!("{flag} expects a path, e.g. `{flag} /srv/skald/config.json`"),
                )),
            }
        };

        match name.as_str() {
            "-c" | "--config" => config = Some(take_value("--config")?),
            "-d" | "--data" => data = Some(take_value("--data")?),
            "-o" | "--output" => output = Some(take_value("--output")?),
            "--chunks" => chunks = Some(take_value("--chunks")?),
            "-r" | "--root" => root = Some(take_value("--root")?),
            "-h" | "--help" => return Ok(CliOutcome::Message(HELP.to_string())),
            "-V" | "--version" => {
                return Ok(CliOutcome::Message(format!(
                    "skald_pipeline {}\n",
                    env!("CARGO_PKG_VERSION")
                )))
            }
            other if other.starts_with('-') => {
                return Err(CliError::new(
                    "Unrecognised command-line flag",
                    &format!("{other} is not a known flag — run `skald_pipeline --help` for the list"),
                ))
            }
            other => {
                return Err(CliError::new(
                    "Unexpected positional argument",
                    &format!(
                        "`{other}` was given with no flag. Name what it is, \
                         e.g. `--config {other}` or `--data {other}`"
                    ),
                ))
            }
        }
    }

    let config = config.or_else(|| env("SKALD_CONFIG"));
    let data = data.or_else(|| env("SKALD_DATA"));
    let output = output.or_else(|| env("SKALD_OUTPUT"));
    let chunks = chunks.or_else(|| env("SKALD_CHUNKS"));
    let root = root.or_else(|| env("SKALD_ROOT")).unwrap_or_else(|| PathBuf::from("."));

    let mut paths = Paths::from_root(&root);

    // A config path may name either the file itself or a directory to search —
    // an operator handing over "the config" means either, and guessing wrong
    // would fail with a confusing "no JSON config found".
    if let Some(path) = config {
        if path.is_dir() {
            paths.config_dir = path;
        } else {
            paths.config_dir = path.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
            paths.config_file = Some(path);
        }
    }

    // Likewise for input: a directory is scanned as before, a file is used directly.
    if let Some(path) = data {
        if path.is_dir() {
            paths.data_dir = path;
        } else {
            paths.data_dir = path.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
            paths.data_file = Some(path);
        }
    }

    if let Some(dir) = output {
        paths.output_dir = dir;
        paths.output_dir_explicit = true;
    }
    if let Some(dir) = chunks {
        paths.chunks_dir = dir;
    }

    Ok(CliOutcome::Run(Box::new(paths)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }

    fn no_env(_: &str) -> Option<PathBuf> {
        None
    }

    fn run(outcome: CliOutcome) -> Paths {
        match outcome {
            CliOutcome::Run(paths) => *paths,
            CliOutcome::Message(text) => panic!("expected a run, got a message: {text}"),
        }
    }

    /// A directory to hang `is_dir()`-sensitive cases off. Unique per test so
    /// the suite stays parallel-safe.
    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("skald_cli_{}_{}", tag, std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn bare_command_line_keeps_the_historical_layout() {
        let paths = run(parse_args_with_env(argv(&[]), no_env).expect("parse"));
        assert_eq!(paths, Paths::from_root(Path::new(".")));
        assert_eq!(paths.config_dir, PathBuf::from("./config"));
        assert_eq!(paths.data_dir, PathBuf::from("./data"));
        assert_eq!(paths.output_dir, PathBuf::from("./output"));
        assert_eq!(paths.chunks_dir, PathBuf::from("./chunks"));
        assert!(paths.config_file.is_none());
        assert!(!paths.output_dir_explicit);
    }

    #[test]
    fn root_moves_every_default_together() {
        let paths = run(parse_args_with_env(argv(&["--root", "/srv/skald"]), no_env).expect("parse"));
        assert_eq!(paths.config_dir, PathBuf::from("/srv/skald/config"));
        assert_eq!(paths.data_dir, PathBuf::from("/srv/skald/data"));
        assert_eq!(paths.output_dir, PathBuf::from("/srv/skald/output"));
        assert_eq!(paths.chunks_dir, PathBuf::from("/srv/skald/chunks"));
    }

    #[test]
    fn config_pointing_at_a_file_names_that_file() {
        let paths = run(parse_args_with_env(argv(&["--config", "/etc/skald/ration.json"]), no_env).expect("parse"));
        assert_eq!(paths.config_file, Some(PathBuf::from("/etc/skald/ration.json")));
        assert_eq!(paths.config_dir, PathBuf::from("/etc/skald"));
    }

    #[test]
    fn config_pointing_at_a_directory_is_searched() {
        let dir = temp_dir("config_dir");
        let paths = run(parse_args_with_env(
            argv(&["--config", dir.to_str().unwrap()]),
            no_env,
        )
        .expect("parse"));
        assert_eq!(paths.config_dir, dir);
        assert!(paths.config_file.is_none(), "a directory must still be searched, not opened");
    }

    #[test]
    fn data_pointing_at_a_file_bypasses_the_directory_scan() {
        let paths = run(parse_args_with_env(argv(&["--data", "/mnt/export/patients.csv"]), no_env).expect("parse"));
        assert_eq!(paths.data_file, Some(PathBuf::from("/mnt/export/patients.csv")));
        assert_eq!(paths.data_dir, PathBuf::from("/mnt/export"));
    }

    #[test]
    fn flags_may_be_written_with_an_equals_sign() {
        let paths = run(parse_args_with_env(argv(&["--output=/var/skald/out"]), no_env).expect("parse"));
        assert_eq!(paths.output_dir, PathBuf::from("/var/skald/out"));
        assert!(paths.output_dir_explicit);
    }

    #[test]
    fn short_flags_are_accepted() {
        let paths = run(parse_args_with_env(
            argv(&["-c", "/a/c.json", "-d", "/b/in.csv", "-o", "/c/out", "-r", "/d"]),
            no_env,
        )
        .expect("parse"));
        assert_eq!(paths.config_file, Some(PathBuf::from("/a/c.json")));
        assert_eq!(paths.data_file, Some(PathBuf::from("/b/in.csv")));
        assert_eq!(paths.output_dir, PathBuf::from("/c/out"));
        assert_eq!(paths.chunks_dir, PathBuf::from("/d/chunks"));
    }

    #[test]
    fn environment_supplies_paths_when_no_flag_does() {
        let env = |key: &str| match key {
            "SKALD_CONFIG" => Some(PathBuf::from("/env/config.json")),
            "SKALD_OUTPUT" => Some(PathBuf::from("/env/out")),
            _ => None,
        };
        let paths = run(parse_args_with_env(argv(&[]), env).expect("parse"));
        assert_eq!(paths.config_file, Some(PathBuf::from("/env/config.json")));
        assert_eq!(paths.output_dir, PathBuf::from("/env/out"));
        assert!(paths.output_dir_explicit);
    }

    #[test]
    fn a_flag_beats_the_environment() {
        let env = |key: &str| match key {
            "SKALD_CONFIG" => Some(PathBuf::from("/env/config.json")),
            _ => None,
        };
        let paths = run(parse_args_with_env(argv(&["--config", "/flag/config.json"]), env).expect("parse"));
        assert_eq!(paths.config_file, Some(PathBuf::from("/flag/config.json")));
    }

    #[test]
    fn a_flag_with_no_value_is_an_error_not_a_silent_default() {
        let err = parse_args_with_env(argv(&["--config"]), no_env).expect_err("must fail");
        assert!(err.details.contains("--config"), "{err:?}");
    }

    #[test]
    fn unknown_flags_and_stray_paths_are_rejected() {
        let unknown = parse_args_with_env(argv(&["--danger"]), no_env).expect_err("must fail");
        assert!(unknown.message.contains("Unrecognised"), "{unknown:?}");

        let positional = parse_args_with_env(argv(&["config.json"]), no_env).expect_err("must fail");
        assert!(positional.details.contains("--config config.json"), "{positional:?}");
    }

    #[test]
    fn help_and_version_ask_for_no_run() {
        assert!(matches!(
            parse_args_with_env(argv(&["--help"]), no_env).expect("parse"),
            CliOutcome::Message(_)
        ));
        match parse_args_with_env(argv(&["-V"]), no_env).expect("parse") {
            CliOutcome::Message(text) => assert!(text.starts_with("skald_pipeline "), "{text}"),
            other => panic!("expected a message, got {other:?}"),
        }
    }

    #[test]
    fn key_material_follows_an_explicit_output_directory() {
        let relocated = run(parse_args_with_env(argv(&["--output", "/var/skald/out"]), no_env).expect("parse"));
        assert_eq!(relocated.key_material_dir("output"), PathBuf::from("/var/skald/out"));
        // …even when the config names some other relative directory, because
        // splitting the keys from the results they decrypt helps nobody.
        assert_eq!(relocated.key_material_dir("keys"), PathBuf::from("/var/skald/out"));
    }

    #[test]
    fn key_material_dir_is_always_absolute() {
        // Preprocessing re-derives a relative key directory from the chunk
        // paths, which put the keys in `<chunks parent>/<relative path>` —
        // `--output selftest/result --chunks selftest/scratch` wrote them to
        // `selftest/selftest/result`. An absolute path is never re-derived.
        for args in [
            vec!["--output", "relative/out"],
            vec!["--root", "relative/root"],
            vec![],
        ] {
            let paths = run(parse_args_with_env(argv(&args), no_env).expect("parse"));
            let dir = paths.key_material_dir("output");
            assert!(dir.is_absolute(), "{args:?} produced a relative key directory: {}", dir.display());
        }
    }

    #[test]
    fn without_an_output_flag_the_config_still_places_key_material() {
        let paths = run(parse_args_with_env(argv(&["--root", "/srv/skald"]), no_env).expect("parse"));
        assert_eq!(paths.key_material_dir("output"), PathBuf::from("/srv/skald/output"));
        assert_eq!(paths.key_material_dir("keys"), PathBuf::from("/srv/skald/keys"));
        assert_eq!(paths.key_material_dir("/secure/keys"), PathBuf::from("/secure/keys"));
    }
}
