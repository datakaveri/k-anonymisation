//! External data connectors — reading a run's input from, and writing its
//! output back to, systems other than the local filesystem.
//!
//! The pipeline core is unchanged by any of this: a connector's only job is to
//! land a single chunk-safe CSV in the scratch directory on the way in, and to
//! load the anonymized CSV somewhere on the way out. Everything between those
//! two points still works on files.
//!
//! Connectors are opt-in. A config with no `input` / `output_sink` section runs
//! exactly as it did before this module existed.

pub mod postgres;

use crate::pipeline::bootstrap::{PipelineError, validation};
use serde_json::Value;
use std::path::PathBuf;

/// Where a run's input comes from.
#[derive(Debug, Clone, PartialEq)]
pub enum DataSource {
    /// Scan the data directory, or use the file named on the command line.
    /// The historical behaviour, and the default.
    Files,
    Postgres(Box<PgRead>),
}

/// Where a run's anonymized output goes, in addition to the files under
/// `output/` — which are always written, connector or not.
#[derive(Debug, Clone, PartialEq)]
pub enum DataSink {
    /// Files only. The default.
    None,
    Postgres(Box<PgWrite>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct PgRead {
    pub connection: PgConnection,
    /// The `SELECT` whose result set is anonymized.
    pub query: String,
    /// How the query was arrived at, for the log — a config `table` or `query`.
    pub origin: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PgWrite {
    pub connection: PgConnection,
    pub table: QualifiedName,
    pub mode: WriteMode,
    /// `CREATE SCHEMA IF NOT EXISTS` before creating the table.
    pub create_schema: bool,
    /// When true (the default) an empty CSV field loads as SQL NULL, matching
    /// the pipeline's own "empty string means missing" convention. When false
    /// empty fields load as empty strings and nothing in the output is NULL.
    pub empty_as_null: bool,
}

/// What to do with the destination table before loading rows into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    /// The table must already exist; rows are appended.
    Append,
    /// `CREATE TABLE IF NOT EXISTS` (all columns `text`), then append. Default.
    Create,
    /// Create if absent, then `TRUNCATE` before loading.
    Truncate,
    /// `DROP TABLE IF EXISTS`, then recreate and load.
    Replace,
}

impl WriteMode {
    fn parse(raw: &str) -> Result<Self, PipelineError> {
        match raw {
            "append" => Ok(Self::Append),
            "create" => Ok(Self::Create),
            "truncate" => Ok(Self::Truncate),
            "replace" => Ok(Self::Replace),
            other => Err(validation(
                "DB_CONFIG_INVALID",
                "Unknown output_sink mode",
                &format!("'{other}' is not a mode — use one of: append, create, truncate, replace"),
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Append => "append",
            Self::Create => "create",
            Self::Truncate => "truncate",
            Self::Replace => "replace",
        }
    }

    /// True for the modes that destroy rows already in the destination table.
    pub fn is_destructive(self) -> bool {
        matches!(self, Self::Truncate | Self::Replace)
    }
}

/// A schema-qualified SQL identifier, validated at parse time so it can be
/// interpolated into a statement safely. Table names arrive from the config,
/// not from the data, but they still never reach the server unquoted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualifiedName {
    parts: Vec<String>,
}

impl QualifiedName {
    pub fn parse(raw: &str, field: &str) -> Result<Self, PipelineError> {
        let parts: Vec<String> = raw.split('.').map(|p| p.trim().to_string()).collect();
        if parts.is_empty() || parts.len() > 2 {
            return Err(validation(
                "DB_CONFIG_INVALID",
                "Malformed table name",
                &format!("{field} = '{raw}' — expected 'table' or 'schema.table'"),
            ));
        }
        for part in &parts {
            if part.is_empty() {
                return Err(validation(
                    "DB_CONFIG_INVALID",
                    "Malformed table name",
                    &format!("{field} = '{raw}' — an empty component is not a valid identifier"),
                ));
            }
            if part.contains('"') || part.contains('\0') {
                return Err(validation(
                    "DB_CONFIG_INVALID",
                    "Illegal character in table name",
                    &format!("{field} = '{raw}' — double quotes and NUL bytes are not allowed"),
                ));
            }
        }
        Ok(Self { parts })
    }

    /// The name as it should appear in a statement — every component quoted, so
    /// mixed case and reserved words work and nothing is interpretable as SQL.
    pub fn quoted(&self) -> String {
        self.parts.iter().map(|p| quote_ident(p)).collect::<Vec<_>>().join(".")
    }

    /// The schema component, when the name was qualified with one.
    pub fn schema(&self) -> Option<&str> {
        if self.parts.len() == 2 { Some(&self.parts[0]) } else { None }
    }
}

impl std::fmt::Display for QualifiedName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.parts.join("."))
    }
}

/// Quotes one SQL identifier, doubling any embedded quote.
pub fn quote_ident(raw: &str) -> String {
    format!("\"{}\"", raw.replace('"', "\"\""))
}

/// Quotes a string literal for a statement that cannot take a bind parameter
/// (`COPY … WITH (NULL '…')` among them).
pub fn quote_literal(raw: &str) -> String {
    format!("'{}'", raw.replace('\'', "''"))
}

/// How to protect the connection to the server. Mirrors libpq's `sslmode`, so
/// an operator can carry the value over from an existing connection string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslMode {
    /// Never use TLS.
    Disable,
    /// Use TLS if the server offers it, plaintext otherwise. No verification.
    Prefer,
    /// Require TLS, but do not verify the server's certificate.
    Require,
    /// Require TLS and verify the certificate chain, but not the hostname.
    VerifyCa,
    /// Require TLS and verify both the chain and the hostname.
    VerifyFull,
}

impl SslMode {
    fn parse(raw: &str) -> Result<Self, PipelineError> {
        match raw {
            "disable" => Ok(Self::Disable),
            "prefer" => Ok(Self::Prefer),
            "require" => Ok(Self::Require),
            "verify-ca" | "verify_ca" => Ok(Self::VerifyCa),
            "verify-full" | "verify_full" => Ok(Self::VerifyFull),
            other => Err(validation(
                "DB_CONFIG_INVALID",
                "Unknown sslmode",
                &format!(
                    "'{other}' is not an sslmode — use one of: \
                     disable, prefer, require, verify-ca, verify-full"
                ),
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disable => "disable",
            Self::Prefer => "prefer",
            Self::Require => "require",
            Self::VerifyCa => "verify-ca",
            Self::VerifyFull => "verify-full",
        }
    }

    pub fn encrypts(self) -> bool {
        !matches!(self, Self::Disable)
    }

    /// True for the modes that prove who the server is (`verify-ca`,
    /// `verify-full`). Only these also require SCRAM channel binding.
    pub fn authenticates_server(self) -> bool {
        matches!(self, Self::VerifyCa | Self::VerifyFull)
    }

    /// The WARN line the connector logs on every connection made in a mode
    /// that does not authenticate the server. `None` for the verify modes.
    pub fn security_warning(self) -> Option<&'static str> {
        match self {
            Self::Disable => Some(
                "sslmode=disable: the connection is NOT encrypted and the server is NOT authenticated — \
                 credentials and data cross the network in plaintext. Use sslmode=verify-full.",
            ),
            Self::Prefer => Some(
                "sslmode=prefer: the server is NOT authenticated — its certificate is not checked and the \
                 connection silently falls back to plaintext if the server does not offer TLS. \
                 Use sslmode=verify-full (with sslrootcert for a private CA).",
            ),
            Self::Require => Some(
                "sslmode=require: the server is NOT authenticated — the connection is encrypted but the \
                 server's certificate is not checked, so a man in the middle is not ruled out. \
                 Use sslmode=verify-full (with sslrootcert for a private CA).",
            ),
            Self::VerifyCa | Self::VerifyFull => None,
        }
    }
}

/// Everything needed to open one server connection.
///
/// `Debug` is implemented by hand: it never prints the DSN or the password,
/// and it scrubs values that came from `${VAR}` expansion (see [`Self::scrub`]).
#[derive(Clone, PartialEq)]
pub struct PgConnection {
    /// A libpq-style URI or key/value string. Discrete fields below override
    /// whatever it sets, so a DSN can supply the defaults and the config the
    /// specifics.
    pub dsn: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub database: Option<String>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub ssl_mode: SslMode,
    /// PEM bundle to verify the server against, for `verify-ca`/`verify-full`.
    /// Absent means the Mozilla root program's CA set.
    pub root_cert: Option<PathBuf>,
    pub connect_timeout_seconds: Option<u64>,
    pub application_name: String,
    /// Every value a `${VAR}` reference expanded to while this connection was
    /// parsed. Kept only so [`Self::scrub`] can keep them out of logs and errors.
    env_values: Vec<String>,
}

const REDACTED: &str = "<redacted>";

/// Values shorter than this are not scrubbed: replacing every "db" or "pg" in
/// a message would mangle it, and a value that short is not a secret.
const MIN_SCRUBBED_LEN: usize = 4;

impl PgConnection {
    /// A one-line description safe to write to the log — never the password,
    /// and never a DSN, which usually carries one.
    pub fn redacted(&self) -> String {
        let host = self
            .host
            .clone()
            .unwrap_or_else(|| if self.dsn.is_some() { "<from dsn>".to_string() } else { "localhost".to_string() });
        let port = self.port.map(|p| p.to_string()).unwrap_or_else(|| "5432".to_string());
        let db = self.database.clone().unwrap_or_else(|| "<from dsn>".to_string());
        let user = self.user.clone().unwrap_or_else(|| "<from dsn/env>".to_string());
        self.scrub(&format!("{user}@{host}:{port}/{db} sslmode={}", self.ssl_mode.as_str()))
    }

    /// `text` with the password and every `${VAR}`-expanded value replaced by
    /// `<redacted>`. Applied to the connection's log line and to connect-time
    /// errors, whose driver and server text can quote the user, database or
    /// host back — so a secret routed into one of those fields stays hidden.
    pub fn scrub(&self, text: &str) -> String {
        let mut secrets: Vec<&str> = self
            .env_values
            .iter()
            .map(String::as_str)
            .chain(self.password.as_deref())
            .filter(|s| s.len() >= MIN_SCRUBBED_LEN)
            .collect();
        // Longest first, so a value that contains another is replaced whole.
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        secrets.iter().fold(text.to_string(), |acc, secret| acc.replace(secret, REDACTED))
    }
}

impl std::fmt::Debug for PgConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scrubbed = |v: &Option<String>| v.as_deref().map(|v| self.scrub(v));
        f.debug_struct("PgConnection")
            .field("dsn", &self.dsn.as_ref().map(|_| REDACTED))
            .field("host", &scrubbed(&self.host))
            .field("port", &self.port)
            .field("database", &scrubbed(&self.database))
            .field("user", &scrubbed(&self.user))
            .field("password", &self.password.as_ref().map(|_| REDACTED))
            .field("ssl_mode", &self.ssl_mode)
            .field("root_cert", &self.root_cert.as_ref().map(|p| self.scrub(&p.display().to_string())))
            .field("connect_timeout_seconds", &self.connect_timeout_seconds)
            .field("application_name", &self.application_name)
            .finish_non_exhaustive()
    }
}

// ── Config parsing ───────────────────────────────────────────────────────────

/// Reads the optional `input` section. Absent, or `"type": "file"`, gives
/// [`DataSource::Files`] — which is what every pre-connector config yields.
pub fn parse_data_source(section: &Value) -> Result<DataSource, PipelineError> {
    let Some(input) = section.get("input") else {
        return Ok(DataSource::Files);
    };
    let obj = input.as_object().ok_or_else(|| {
        validation("DB_CONFIG_INVALID", "'input' must be a JSON object", "e.g. {\"type\": \"postgres\", …}")
    })?;

    match obj.get("type").and_then(Value::as_str).unwrap_or("file") {
        "file" | "files" => Ok(DataSource::Files),
        "postgres" | "postgresql" => Ok(DataSource::Postgres(Box::new(parse_pg_read(input)?))),
        other => Err(validation(
            "DB_CONFIG_INVALID",
            "Unknown input type",
            &format!("input.type = '{other}' — supported types are 'file' and 'postgres'"),
        )),
    }
}

fn parse_pg_read(input: &Value) -> Result<PgRead, PipelineError> {
    let connection = parse_connection(input, "input")?;

    let table = input.get("table").and_then(Value::as_str);
    let query = input.get("query").and_then(Value::as_str);

    let (query, origin) = match (table, query) {
        (Some(_), Some(_)) => {
            return Err(validation(
                "DB_CONFIG_INVALID",
                "input names both 'table' and 'query'",
                "Give one or the other — 'table' to read a whole table, 'query' for a custom SELECT",
            ));
        }
        (None, None) => {
            return Err(validation(
                "DB_CONFIG_INVALID",
                "input is missing 'table' and 'query'",
                "A postgres input needs one of them, e.g. \"table\": \"public.patients\"",
            ));
        }
        (Some(table), None) => {
            let name = QualifiedName::parse(literal(table, "input.table")?, "input.table")?;
            let columns = parse_column_list(input.get("columns"), "input.columns")?;
            let projection = if columns.is_empty() {
                "*".to_string()
            } else {
                columns.iter().map(|c| quote_ident(c)).collect::<Vec<_>>().join(", ")
            };
            let mut sql = format!("SELECT {projection} FROM {}", name.quoted());
            if let Some(limit) = parse_limit(input)? {
                sql.push_str(&format!(" LIMIT {limit}"));
            }
            (sql, format!("table {name}"))
        }
        (None, Some(query)) => {
            let sql = strip_trailing_semicolons(literal(query, "input.query")?);
            if sql.is_empty() {
                return Err(validation(
                    "DB_CONFIG_INVALID",
                    "input.query is empty",
                    "Provide a SELECT statement, or use 'table' instead",
                ));
            }
            (sql, "custom query".to_string())
        }
    };

    Ok(PgRead { connection, query, origin })
}

/// Reads the optional `output_sink` section. `fallback` supplies connection
/// details when the sink omits them — writing back to the database the input
/// came from is the common case and should not need them repeated.
pub fn parse_data_sink(section: &Value, fallback: Option<&PgConnection>) -> Result<DataSink, PipelineError> {
    let Some(sink) = section.get("output_sink") else {
        return Ok(DataSink::None);
    };
    let obj = sink.as_object().ok_or_else(|| {
        validation("DB_CONFIG_INVALID", "'output_sink' must be a JSON object", "e.g. {\"type\": \"postgres\", …}")
    })?;

    match obj.get("type").and_then(Value::as_str).unwrap_or("none") {
        "none" | "file" | "files" => Ok(DataSink::None),
        "postgres" | "postgresql" => {
            let has_own_connection = sink.get("connection").is_some()
                || ["dsn", "host", "database", "user"].iter().any(|k| sink.get(*k).is_some());
            let connection = match (has_own_connection, fallback) {
                (false, Some(inherited)) => inherited.clone(),
                _ => parse_connection(sink, "output_sink")?,
            };

            let table_raw = sink.get("table").and_then(Value::as_str).ok_or_else(|| {
                validation(
                    "DB_CONFIG_INVALID",
                    "output_sink is missing 'table'",
                    "Name the destination, e.g. \"table\": \"anonymized.patients\"",
                )
            })?;
            let table = QualifiedName::parse(literal(table_raw, "output_sink.table")?, "output_sink.table")?;

            let mode = match sink.get("mode").and_then(Value::as_str) {
                Some(raw) => WriteMode::parse(literal(raw, "output_sink.mode")?)?,
                None => WriteMode::Create,
            };

            Ok(DataSink::Postgres(Box::new(PgWrite {
                connection,
                table,
                mode,
                create_schema: sink.get("create_schema").and_then(Value::as_bool).unwrap_or(true),
                empty_as_null: sink.get("empty_as_null").and_then(Value::as_bool).unwrap_or(true),
            })))
        }
        other => Err(validation(
            "DB_CONFIG_INVALID",
            "Unknown output_sink type",
            &format!("output_sink.type = '{other}' — supported types are 'none' and 'postgres'"),
        )),
    }
}

/// Connection details may sit in a nested `connection` object or be inlined
/// beside `table`/`query`. Both spellings are accepted; the nested one wins.
fn parse_connection(owner: &Value, field: &str) -> Result<PgConnection, PipelineError> {
    let conn = owner.get("connection").unwrap_or(owner);

    // `${VAR}` is expanded only in the connection fields read through
    // `str_field`/`expand` below (see EXPANDED_FIELDS); what each reference
    // expanded to is collected so it can be scrubbed from logs and errors.
    let env_values = std::cell::RefCell::new(Vec::new());
    let expand = |raw: &str, key: &str| expand_env_into(raw, &format!("{field}.{key}"), &mut env_values.borrow_mut());
    let str_field = |key: &str| -> Result<Option<String>, PipelineError> {
        match conn.get(key).and_then(Value::as_str) {
            Some(raw) => Ok(Some(expand(raw, key)?)),
            None => Ok(None),
        }
    };

    let port = match conn.get("port") {
        None | Some(Value::Null) => None,
        Some(Value::Number(n)) => {
            let n = n.as_u64().filter(|p| *p > 0 && *p <= u16::MAX as u64).ok_or_else(|| {
                validation("DB_CONFIG_INVALID", "Invalid port", &format!("{field}.port must be 1–65535"))
            })?;
            Some(n as u16)
        }
        Some(Value::String(s)) => {
            // The value is never quoted back: it may have come from a variable.
            Some(expand(s, "port")?.parse::<u16>().ok().filter(|p| *p > 0).ok_or_else(|| {
                validation(
                    "DB_CONFIG_INVALID",
                    "Invalid port",
                    &format!("{field}.port is not a valid port number (after ${{VAR}} expansion)"),
                )
            })?)
        }
        Some(_) => {
            return Err(validation("DB_CONFIG_INVALID", "Invalid port", &format!("{field}.port must be a number")));
        }
    };

    // A password can be given inline (expanded like the other connection fields), or by
    // naming the variable holding it — the form that keeps secrets out of a
    // config file that gets committed or shipped in a bundle.
    let password = match conn.get("password_env").and_then(Value::as_str) {
        Some(var) => Some(read_env_var(var).map_err(|_| {
            validation(
                "DB_CONFIG_INVALID",
                "Password environment variable is not set",
                &format!("{field}.password_env names '{var}', which is unset in this process's environment"),
            )
        })?),
        None => str_field("password")?,
    };

    // Unset means verify-full: the one mode that proves which server this is.
    let ssl_mode = match conn.get("sslmode").or_else(|| conn.get("ssl_mode")).and_then(Value::as_str) {
        Some(raw) => SslMode::parse(literal(raw, &format!("{field}.sslmode"))?)?,
        None => SslMode::VerifyFull,
    };

    let root_cert = conn
        .get("sslrootcert")
        .or_else(|| conn.get("root_cert"))
        .and_then(Value::as_str)
        .map(|raw| expand(raw, "sslrootcert"))
        .transpose()?
        .map(PathBuf::from);

    if root_cert.is_some() && !ssl_mode.encrypts() {
        return Err(validation(
            "DB_CONFIG_INVALID",
            "sslrootcert is set but sslmode disables TLS",
            &format!("{field}: set sslmode to verify-ca or verify-full, or drop sslrootcert"),
        ));
    }

    // verify-ca skips the hostname check, so against the public root set it
    // would accept any server holding any publicly issued certificate.
    if ssl_mode == SslMode::VerifyCa && root_cert.is_none() {
        return Err(validation(
            "DB_CONFIG_INVALID",
            "sslmode=verify-ca needs sslrootcert",
            &format!(
                "{field}: verify-ca trusts only the CA bundle named in sslrootcert — set it, \
                 or use verify-full to check the server against the public CA set"
            ),
        ));
    }

    let connection = PgConnection {
        dsn: str_field("dsn")?.or(str_field("connection_string")?),
        host: str_field("host")?,
        port,
        database: str_field("database")?.or(str_field("dbname")?),
        user: str_field("user")?.or(str_field("username")?),
        password,
        ssl_mode,
        root_cert,
        connect_timeout_seconds: conn.get("connect_timeout_seconds").and_then(Value::as_u64),
        application_name: match conn.get("application_name").and_then(Value::as_str) {
            Some(raw) => literal(raw, &format!("{field}.application_name"))?.to_string(),
            None => "skald".to_string(),
        },
        env_values: env_values.into_inner(),
    };

    if connection.dsn.is_none() && connection.database.is_none() {
        return Err(validation(
            "DB_CONFIG_INVALID",
            "No database named",
            &format!("{field} needs either a 'dsn' or a 'database' (plus host/user as needed)"),
        ));
    }

    Ok(connection)
}

fn parse_column_list(value: Option<&Value>, field: &str) -> Result<Vec<String>, PipelineError> {
    let Some(value) = value else { return Ok(Vec::new()) };
    let arr = value.as_array().ok_or_else(|| {
        validation(
            "DB_CONFIG_INVALID",
            "Column list must be an array",
            &format!("{field} must be an array of column names"),
        )
    })?;
    arr.iter()
        .map(|entry| {
            entry
                .as_str()
                .ok_or_else(|| {
                    validation(
                        "DB_CONFIG_INVALID",
                        "Column name must be a string",
                        &format!("{field} holds a non-string entry"),
                    )
                })
                .and_then(|raw| {
                    let name = literal(raw, field)?.to_string();
                    if name.contains('"') || name.is_empty() {
                        return Err(validation(
                            "DB_CONFIG_INVALID",
                            "Illegal column name",
                            &format!("{field}: '{name}' is empty or contains a double quote"),
                        ));
                    }
                    Ok(name)
                })
        })
        .collect()
}

fn parse_limit(input: &Value) -> Result<Option<u64>, PipelineError> {
    match input.get("limit") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n.as_u64().map(Some).ok_or_else(|| {
            validation("DB_CONFIG_INVALID", "Invalid limit", "input.limit must be a non-negative whole number")
        }),
        Some(_) => Err(validation("DB_CONFIG_INVALID", "Invalid limit", "input.limit must be a number")),
    }
}

/// Trailing semicolons break the `COPY (…) TO STDOUT` wrapper the reader builds,
/// and a config author has no way to know that. Strip them instead of failing.
fn strip_trailing_semicolons(sql: &str) -> String {
    sql.trim().trim_end_matches(|c: char| c == ';' || c.is_whitespace()).to_string()
}

// ── Environment expansion ────────────────────────────────────────────────────

/// The only fields `${VAR}` is expanded in. Everything else — table, query,
/// columns, sslmode, application_name, mode — is literal: a reference there
/// would put an environment secret into a statement, the output, or an error.
const EXPANDED_FIELDS: &str = "dsn, host, port, database, user, password, sslrootcert";

/// Returns `raw` unchanged for a field that is never `${VAR}`-expanded, or an
/// error if it holds a reference — passing `${…}` through verbatim would only
/// fail later and more obscurely.
fn literal<'a>(raw: &'a str, field: &str) -> Result<&'a str, PipelineError> {
    if raw.contains("${") {
        return Err(validation(
            "DB_CONFIG_INVALID",
            "${VAR} expansion is not supported for this field",
            &format!(
                "{field} contains '${{' — environment variables are expanded only in the \
                 connection fields ({EXPANDED_FIELDS})"
            ),
        ));
    }
    Ok(raw)
}

/// Substitutes `${VAR}` and `${VAR:-fallback}` in the connection field named
/// by `field` (used in error messages — the value itself never is).
///
/// This is what keeps credentials out of the config file: the config names the
/// variable, the deployment supplies the value. A `${VAR}` with no fallback and
/// no value is an error rather than an empty string — silently connecting as
/// nobody, to nowhere, produces a far worse message later.
pub fn expand_env(raw: &str, field: &str) -> Result<String, PipelineError> {
    expand_env_into(raw, field, &mut Vec::new())
}

/// [`expand_env`], also pushing each value a variable expanded to onto
/// `substituted` so the caller can scrub it from what it logs.
fn expand_env_into(raw: &str, field: &str, substituted: &mut Vec<String>) -> Result<String, PipelineError> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;

    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find('}').ok_or_else(|| {
            validation(
                "DB_CONFIG_INVALID",
                "Unterminated ${…} in config value",
                &format!("{field} opens a variable reference with '${{' that is never closed with '}}'"),
            )
        })?;
        let reference = &after[..end];
        rest = &after[end + 1..];

        let (name, fallback) = match reference.split_once(":-") {
            Some((name, fallback)) => (name, Some(fallback)),
            None => (reference, None),
        };
        let name = name.trim();
        if name.is_empty() {
            return Err(validation(
                "DB_CONFIG_INVALID",
                "Empty variable name in config value",
                &format!("{field} contains '${{}}' with no variable named inside it"),
            ));
        }

        match (read_env_var(name), fallback) {
            (Ok(value), _) => {
                out.push_str(&value);
                substituted.push(value);
            }
            (Err(_), Some(fallback)) => out.push_str(fallback),
            (Err(_), None) => {
                return Err(validation(
                    "ENV_VAR_MISSING",
                    "Referenced environment variable is not set",
                    &format!(
                        "'{name}' is referenced in {field} but unset in this process's \
                         environment. Export it, or write ${{{name}:-default}} to supply a fallback."
                    ),
                ));
            }
        }
    }

    out.push_str(rest);
    Ok(out)
}

fn read_env_var(name: &str) -> Result<String, std::env::VarError> {
    std::env::var(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn source(section: Value) -> DataSource {
        parse_data_source(&section).expect("parse input section")
    }

    fn pg_source(section: Value) -> PgRead {
        match source(section) {
            DataSource::Postgres(read) => *read,
            DataSource::Files => panic!("expected a postgres source"),
        }
    }

    fn code_of(err: PipelineError) -> String {
        match err {
            PipelineError::Validation { code, .. } => code.to_string(),
            other => panic!("expected a validation error, got {other:?}"),
        }
    }

    // ── Defaults: configs written before connectors existed ──────────────────

    #[test]
    fn a_config_with_no_input_section_still_reads_files() {
        assert_eq!(source(json!({"suppress": ["name"]})), DataSource::Files);
        assert_eq!(source(json!({"input": {"type": "file"}})), DataSource::Files);
    }

    #[test]
    fn a_config_with_no_output_sink_writes_only_files() {
        let sink = parse_data_sink(&json!({"suppress": ["name"]}), None).expect("parse");
        assert_eq!(sink, DataSink::None);
    }

    // ── Reading ──────────────────────────────────────────────────────────────

    #[test]
    fn a_table_becomes_a_select_with_every_identifier_quoted() {
        let read = pg_source(json!({
            "input": {
                "type": "postgres",
                "database": "health",
                "table": "public.ration_members"
            }
        }));
        assert_eq!(read.query, r#"SELECT * FROM "public"."ration_members""#);
        assert_eq!(read.origin, "table public.ration_members");
    }

    #[test]
    fn a_column_list_and_limit_narrow_the_generated_select() {
        let read = pg_source(json!({
            "input": {
                "type": "postgres",
                "database": "health",
                "table": "members",
                "columns": ["uid", "Full Name"],
                "limit": 500
            }
        }));
        assert_eq!(read.query, r#"SELECT "uid", "Full Name" FROM "members" LIMIT 500"#);
    }

    #[test]
    fn a_custom_query_is_taken_as_written_minus_its_semicolon() {
        // The trailing semicolon has to go: the reader wraps the query in
        // `COPY ( … ) TO STDOUT`, where it would be a syntax error.
        let read = pg_source(json!({
            "input": {
                "type": "postgres",
                "database": "health",
                "query": "SELECT a, b FROM t WHERE district = 'Hyderabad';  "
            }
        }));
        assert_eq!(read.query, "SELECT a, b FROM t WHERE district = 'Hyderabad'");
        assert_eq!(read.origin, "custom query");
    }

    #[test]
    fn naming_both_a_table_and_a_query_is_rejected() {
        let err = parse_data_source(&json!({
            "input": {"type": "postgres", "database": "d", "table": "t", "query": "SELECT 1"}
        }))
        .expect_err("must fail");
        assert_eq!(code_of(err), "DB_CONFIG_INVALID");
    }

    #[test]
    fn naming_neither_a_table_nor_a_query_is_rejected() {
        let err = parse_data_source(&json!({"input": {"type": "postgres", "database": "d"}})).expect_err("must fail");
        assert_eq!(code_of(err), "DB_CONFIG_INVALID");
    }

    #[test]
    fn an_unknown_input_type_is_rejected_rather_than_ignored() {
        let err = parse_data_source(&json!({"input": {"type": "mysql", "database": "d"}})).expect_err("must fail");
        assert_eq!(code_of(err), "DB_CONFIG_INVALID");
    }

    #[test]
    fn a_connection_with_neither_dsn_nor_database_is_rejected() {
        let err = parse_data_source(&json!({
            "input": {"type": "postgres", "host": "db.internal", "table": "t"}
        }))
        .expect_err("must fail");
        assert_eq!(code_of(err), "DB_CONFIG_INVALID");
    }

    #[test]
    fn connection_details_may_be_nested_or_inline() {
        let nested = pg_source(json!({
            "input": {
                "type": "postgres",
                "connection": {"host": "db.internal", "port": 6432, "database": "health", "user": "skald"},
                "table": "t"
            }
        }));
        assert_eq!(nested.connection.host.as_deref(), Some("db.internal"));
        assert_eq!(nested.connection.port, Some(6432));
        assert_eq!(nested.connection.user.as_deref(), Some("skald"));

        let inline = pg_source(json!({
            "input": {"type": "postgres", "host": "db.internal", "database": "health", "table": "t"}
        }));
        assert_eq!(inline.connection.host.as_deref(), Some("db.internal"));
    }

    #[test]
    fn sslmode_defaults_to_verify_full_and_accepts_the_libpq_spellings() {
        let default = pg_source(json!({"input": {"type": "postgres", "database": "d", "table": "t"}}));
        assert_eq!(default.connection.ssl_mode, SslMode::VerifyFull);

        for (raw, expected) in [
            ("disable", SslMode::Disable),
            ("prefer", SslMode::Prefer),
            ("require", SslMode::Require),
            ("verify-full", SslMode::VerifyFull),
        ] {
            let read = pg_source(json!({
                "input": {"type": "postgres", "database": "d", "table": "t", "sslmode": raw}
            }));
            assert_eq!(read.connection.ssl_mode, expected, "sslmode={raw}");
        }
        let read = pg_source(json!({
            "input": {
                "type": "postgres", "database": "d", "table": "t",
                "sslmode": "verify-ca", "sslrootcert": "/etc/ssl/ca.pem"
            }
        }));
        assert_eq!(read.connection.ssl_mode, SslMode::VerifyCa);

        let err = parse_data_source(&json!({
            "input": {"type": "postgres", "database": "d", "table": "t", "sslmode": "sometimes"}
        }))
        .expect_err("must fail");
        assert_eq!(code_of(err), "DB_CONFIG_INVALID");
    }

    #[test]
    fn a_root_certificate_with_tls_switched_off_is_a_contradiction() {
        let err = parse_data_source(&json!({
            "input": {
                "type": "postgres", "database": "d", "table": "t",
                "sslmode": "disable", "sslrootcert": "/etc/ssl/ca.pem"
            }
        }))
        .expect_err("must fail");
        assert_eq!(code_of(err), "DB_CONFIG_INVALID");
    }

    #[test]
    fn a_port_given_as_a_string_is_still_a_port() {
        let read = pg_source(json!({
            "input": {"type": "postgres", "database": "d", "table": "t", "port": "5433"}
        }));
        assert_eq!(read.connection.port, Some(5433));

        let err = parse_data_source(&json!({
            "input": {"type": "postgres", "database": "d", "table": "t", "port": 70000}
        }))
        .expect_err("must fail");
        assert_eq!(code_of(err), "DB_CONFIG_INVALID");
    }

    // ── Writing ──────────────────────────────────────────────────────────────

    fn pg_sink(section: Value, fallback: Option<&PgConnection>) -> PgWrite {
        match parse_data_sink(&section, fallback).expect("parse output_sink") {
            DataSink::Postgres(write) => *write,
            DataSink::None => panic!("expected a postgres sink"),
        }
    }

    #[test]
    fn a_sink_with_no_connection_reuses_the_input_connection() {
        let section = json!({
            "input": {"type": "postgres", "database": "health", "host": "db.internal", "table": "raw"},
            "output_sink": {"type": "postgres", "table": "anon.members"}
        });
        let read = pg_source(section.clone());
        let write = pg_sink(section, Some(&read.connection));

        assert_eq!(write.connection, read.connection);
        assert_eq!(write.table.to_string(), "anon.members");
        assert_eq!(write.mode, WriteMode::Create, "create is the safe default");
        assert!(write.create_schema);
        assert!(write.empty_as_null);
    }

    #[test]
    fn a_sink_may_point_at_a_different_server_than_the_input() {
        let inherited = pg_source(json!({
            "input": {"type": "postgres", "database": "health", "host": "source.internal", "table": "raw"}
        }))
        .connection;

        let write = pg_sink(
            json!({
                "output_sink": {
                    "type": "postgres",
                    "connection": {"host": "warehouse.internal", "database": "analytics"},
                    "table": "public.members"
                }
            }),
            Some(&inherited),
        );
        assert_eq!(write.connection.host.as_deref(), Some("warehouse.internal"));
        assert_eq!(write.connection.database.as_deref(), Some("analytics"));
    }

    #[test]
    fn every_write_mode_parses_and_only_two_destroy_rows() {
        for (raw, expected, destructive) in [
            ("append", WriteMode::Append, false),
            ("create", WriteMode::Create, false),
            ("truncate", WriteMode::Truncate, true),
            ("replace", WriteMode::Replace, true),
        ] {
            let write =
                pg_sink(json!({"output_sink": {"type": "postgres", "database": "d", "table": "t", "mode": raw}}), None);
            assert_eq!(write.mode, expected, "mode={raw}");
            assert_eq!(write.mode.is_destructive(), destructive, "mode={raw}");
        }

        let err = parse_data_sink(
            &json!({"output_sink": {"type": "postgres", "database": "d", "table": "t", "mode": "upsert"}}),
            None,
        )
        .expect_err("must fail");
        assert_eq!(code_of(err), "DB_CONFIG_INVALID");
    }

    #[test]
    fn a_sink_without_a_table_is_rejected() {
        let err = parse_data_sink(&json!({"output_sink": {"type": "postgres", "database": "d"}}), None)
            .expect_err("must fail");
        assert_eq!(code_of(err), "DB_CONFIG_INVALID");
    }

    // ── Identifier safety ────────────────────────────────────────────────────

    #[test]
    fn identifiers_are_quoted_and_hostile_ones_refused() {
        let plain = QualifiedName::parse("members", "t").expect("parse");
        assert_eq!(plain.quoted(), r#""members""#);
        assert_eq!(plain.schema(), None);

        let qualified = QualifiedName::parse("anon.Ration Members", "t").expect("parse");
        assert_eq!(qualified.quoted(), r#""anon"."Ration Members""#);
        assert_eq!(qualified.schema(), Some("anon"));

        // A quote in the name is the one character that could break out of the
        // quoting, so it never reaches the server at all.
        for hostile in [r#"t"; DROP TABLE users; --"#, "a.b.c", "", "public."] {
            assert!(QualifiedName::parse(hostile, "t").is_err(), "accepted {hostile:?}");
        }
    }

    #[test]
    fn literals_escape_embedded_quotes() {
        assert_eq!(quote_literal("plain"), "'plain'");
        assert_eq!(quote_literal("it's"), "'it''s'");
    }

    // ── Environment expansion ────────────────────────────────────────────────

    #[test]
    fn a_value_with_no_reference_is_returned_unchanged() {
        assert_eq!(expand_env("db.internal", "input.host").expect("expand"), "db.internal");
        assert_eq!(expand_env("", "input.host").expect("expand"), "");
    }

    #[test]
    fn a_reference_is_replaced_by_the_variables_value() {
        // PATH is set in every environment this runs in, so the success path is
        // testable without mutating the process environment mid-suite.
        let path = std::env::var("PATH").expect("PATH is set");
        assert_eq!(expand_env("${PATH}", "input.host").expect("expand"), path);
        assert_eq!(expand_env("prefix-${PATH}-suffix", "input.host").expect("expand"), format!("prefix-{path}-suffix"));
    }

    #[test]
    fn an_unset_variable_falls_back_when_one_is_offered() {
        assert_eq!(
            expand_env("${SKALD_DEFINITELY_UNSET_VARIABLE:-localhost}", "input.host").expect("expand"),
            "localhost"
        );
    }

    #[test]
    fn an_unset_variable_with_no_fallback_fails_loudly() {
        let err = expand_env("${SKALD_DEFINITELY_UNSET_VARIABLE}", "input.host").expect_err("must fail");
        assert_eq!(code_of(err), "ENV_VAR_MISSING");
    }

    #[test]
    fn a_malformed_reference_is_rejected() {
        assert!(expand_env("${PATH", "input.host").is_err(), "unterminated reference accepted");
        assert!(expand_env("${}", "input.host").is_err(), "empty variable name accepted");
    }

    #[test]
    fn password_env_names_the_variable_rather_than_holding_the_secret() {
        let read = pg_source(json!({
            "input": {
                "type": "postgres", "database": "d", "table": "t",
                "password_env": "PATH"
            }
        }));
        assert_eq!(read.connection.password, std::env::var("PATH").ok());

        let err = parse_data_source(&json!({
            "input": {
                "type": "postgres", "database": "d", "table": "t",
                "password_env": "SKALD_DEFINITELY_UNSET_VARIABLE"
            }
        }))
        .expect_err("must fail");
        assert_eq!(code_of(err), "DB_CONFIG_INVALID");
    }

    #[test]
    fn a_redacted_connection_never_carries_the_password() {
        let read = pg_source(json!({
            "input": {
                "type": "postgres", "host": "db.internal", "database": "health",
                "user": "skald", "password": "hunter2", "table": "t", "sslmode": "verify-full"
            }
        }));
        let line = read.connection.redacted();
        assert!(!line.contains("hunter2"), "password leaked into the log: {line}");
        assert_eq!(line, "skald@db.internal:5432/health sslmode=verify-full");
    }

    // ── ${VAR} is confined to connection fields, and never echoed ────────────

    #[test]
    fn env_references_expand_in_every_connection_field() {
        let path = std::env::var("PATH").expect("PATH is set");
        let read = pg_source(json!({
            "input": {
                "type": "postgres",
                "dsn": "host=${PATH}",
                "host": "${PATH}", "database": "${PATH}", "user": "${PATH}",
                "password": "${PATH}", "sslrootcert": "${PATH}",
                "port": "${SKALD_DEFINITELY_UNSET_VARIABLE:-6432}",
                "table": "t"
            }
        }));
        let c = &read.connection;
        assert_eq!(c.dsn, Some(format!("host={path}")));
        for (name, value) in
            [("host", &c.host), ("database", &c.database), ("user", &c.user), ("password", &c.password)]
        {
            assert_eq!(value.as_deref(), Some(path.as_str()), "{name}");
        }
        assert_eq!(c.root_cert, Some(PathBuf::from(&path)));
        assert_eq!(c.port, Some(6432));
    }

    #[test]
    fn env_references_outside_connection_fields_are_refused_and_not_expanded() {
        let path = std::env::var("PATH").expect("PATH is set");
        let inputs = [
            ("input.table", json!({"type": "postgres", "database": "d", "table": "${PATH}"})),
            ("input.query", json!({"type": "postgres", "database": "d", "query": "SELECT '${PATH}'"})),
            ("input.columns", json!({"type": "postgres", "database": "d", "table": "t", "columns": ["${PATH}"]})),
            ("input.sslmode", json!({"type": "postgres", "database": "d", "table": "t", "sslmode": "${PATH}"})),
            (
                "input.application_name",
                json!({"type": "postgres", "database": "d", "table": "t", "application_name": "${PATH}"}),
            ),
        ];
        let sinks = [
            ("output_sink.table", json!({"type": "postgres", "database": "d", "table": "anon.${PATH}"})),
            ("output_sink.mode", json!({"type": "postgres", "database": "d", "table": "t", "mode": "${PATH}"})),
        ];
        let errors =
            inputs
                .into_iter()
                .map(|(field, input)| (field, parse_data_source(&json!({"input": input})).expect_err(field)))
                .chain(sinks.into_iter().map(|(field, sink)| {
                    (field, parse_data_sink(&json!({"output_sink": sink}), None).expect_err(field))
                }));

        for (field, err) in errors {
            let text = err.to_string();
            assert!(text.starts_with("[DB_CONFIG_INVALID]"), "{field}: {text}");
            assert!(text.contains(&format!("{field} contains '${{'")), "{field} not named: {text}");
            assert!(!text.contains(&path), "{field}: an environment value reached the error: {text}");
        }
    }

    #[test]
    fn a_secret_routed_into_the_port_is_not_quoted_back() {
        let path = std::env::var("PATH").expect("PATH is set");
        let err = parse_data_source(&json!({
            "input": {"type": "postgres", "database": "d", "table": "t", "port": "${PATH}"}
        }))
        .expect_err("must fail");
        let text = err.to_string();
        assert!(!text.contains(&path), "expanded value echoed: {text}");
        assert!(text.contains("input.port is not a valid port number (after ${VAR} expansion)"), "{text}");

        let err = parse_data_source(&json!({
            "input": {"type": "postgres", "database": "d", "table": "t", "port": "0"}
        }))
        .expect_err("port 0 must fail as a string too");
        assert_eq!(code_of(err), "DB_CONFIG_INVALID");
    }

    #[test]
    fn a_malformed_reference_names_the_field_never_the_value() {
        // A literal password that happens to contain `${` must not be echoed.
        for raw in ["hunter2${tail", "hunter2${}"] {
            let text = expand_env(raw, "input.password").expect_err("must fail").to_string();
            assert!(text.contains("input.password"), "{text}");
            assert!(!text.contains("hunter2"), "value echoed: {text}");
        }
        let text = parse_data_source(&json!({
            "input": {"type": "postgres", "database": "d", "table": "t", "dsn": "password=hunter2${x"}
        }))
        .expect_err("must fail")
        .to_string();
        assert!(text.contains("input.dsn") && !text.contains("hunter2"), "{text}");
    }

    // ── TLS and credentials ──────────────────────────────────────────────────

    #[test]
    fn verify_ca_without_a_root_certificate_is_rejected() {
        let err = parse_data_source(&json!({
            "input": {"type": "postgres", "database": "d", "table": "t", "sslmode": "verify-ca"}
        }))
        .expect_err("verify-ca against the public roots would accept any public certificate");
        assert_eq!(code_of(err), "DB_CONFIG_INVALID");
    }

    #[test]
    fn only_the_verify_modes_authenticate_and_every_other_mode_warns() {
        for mode in [SslMode::Disable, SslMode::Prefer, SslMode::Require] {
            assert!(!mode.authenticates_server(), "{}", mode.as_str());
            let warning = mode.security_warning().expect("a warning");
            assert!(warning.contains("server is NOT authenticated"), "{warning}");
        }
        for mode in [SslMode::VerifyCa, SslMode::VerifyFull] {
            assert!(mode.authenticates_server(), "{}", mode.as_str());
            assert_eq!(mode.security_warning(), None);
        }
    }

    #[test]
    fn debug_output_never_shows_the_dsn_or_the_password() {
        let section = json!({
            "input": {
                "type": "postgres", "table": "t", "password": "hunter2",
                "dsn": "postgresql://skald:dsn-s3cret@db.internal/health"
            },
            "output_sink": {"type": "postgres", "table": "anon.t"}
        });
        let source = parse_data_source(&section).expect("parse");
        let DataSource::Postgres(read) = &source else { panic!("expected a postgres source") };
        let sink = parse_data_sink(&section, Some(&read.connection)).expect("parse");
        let DataSink::Postgres(write) = &sink else { panic!("expected a postgres sink") };

        for (what, text) in [
            ("PgConnection", format!("{:?}", read.connection)),
            ("PgRead", format!("{read:?}")),
            ("PgWrite", format!("{write:?}")),
            ("DataSource", format!("{source:?}")),
            ("DataSink", format!("{sink:?}")),
        ] {
            assert!(!text.contains("hunter2"), "{what} printed the password: {text}");
            assert!(!text.contains("dsn-s3cret"), "{what} printed the DSN: {text}");
            assert!(text.contains(r#"dsn: Some("<redacted>")"#), "{what}: {text}");
            assert!(text.contains(r#"password: Some("<redacted>")"#), "{what}: {text}");
        }
        // Pretty-printed output spreads fields over lines but must hide the same things.
        let pretty = format!("{sink:#?}");
        assert!(!pretty.contains("hunter2") && !pretty.contains("dsn-s3cret"), "{pretty}");
    }

    #[test]
    fn values_from_the_environment_are_scrubbed_from_the_log_line_and_debug() {
        let path = std::env::var("PATH").expect("PATH is set");
        let read = pg_source(json!({
            "input": {"type": "postgres", "host": "db.internal", "database": "health", "user": "${PATH}", "table": "t"}
        }));
        assert_eq!(read.connection.user.as_deref(), Some(path.as_str()), "the driver still gets the real value");

        let line = read.connection.redacted();
        assert_eq!(line, "<redacted>@db.internal:5432/health sslmode=verify-full");
        let debug = format!("{:?}", read.connection);
        assert!(!debug.contains(&path), "{debug}");

        // Server text that quotes the user back is scrubbed the same way.
        let server = format!("password authentication failed for user \"{path}\"");
        assert_eq!(read.connection.scrub(&server), "password authentication failed for user \"<redacted>\"");
    }
}
