//! PostgreSQL connector — `COPY`-based streaming in both directions.
//!
//! Reading and writing both go through `COPY … (FORMAT csv)` rather than
//! row-by-row queries. The server does the CSV quoting and the text conversion
//! of every type it knows, the client only moves bytes, and nothing larger than
//! one buffer is ever held in memory — which matters, because the whole point
//! of the pipeline's chunker is that the dataset does not fit in RAM.
//!
//! On the way in, every column is cast to `text` and stripped of CR/LF. The
//! chunker splits the staged CSV on line boundaries, so a newline inside a
//! quoted value — an address column will have them — would corrupt every row
//! after it. Replacing them with spaces is the one place this connector alters
//! the data, and it is logged when the input is staged.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use postgres::{Client, NoTls};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme};

use crate::pipeline::bootstrap::{io_err, validation, Logger, PipelineError};
use crate::pipeline::connectors::{
    quote_ident, quote_literal, PgConnection, PgRead, PgWrite, SslMode, WriteMode,
};

/// What a staging read pulled out of the database.
#[derive(Debug, Clone, PartialEq)]
pub struct ReadSummary {
    pub columns: Vec<String>,
    pub rows: u64,
}

/// What a sink write pushed back into it.
#[derive(Debug, Clone, PartialEq)]
pub struct WriteSummary {
    pub table: String,
    pub columns: Vec<String>,
    pub rows: u64,
    pub mode: WriteMode,
}

// ── Reading ──────────────────────────────────────────────────────────────────

/// Streams the configured query into `dest` as a chunk-safe CSV and returns
/// what was staged. `dest`'s parent directory is created if it does not exist.
pub fn read_to_csv(spec: &PgRead, dest: &Path, log: &mut Logger) -> Result<ReadSummary, PipelineError> {
    log.info(
        "postgres_in",
        &format!("Connecting to {} to read {}", spec.connection.redacted(), spec.origin),
    );
    let mut client = connect(&spec.connection)?;

    let columns = describe_columns(&mut client, &spec.query)?;
    log.info("postgres_in", &format!("{} column(s): {}", columns.len(), columns.join(", ")));

    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }

    let statement = copy_out_statement(&spec.query, &columns);
    let mut file = std::io::BufWriter::new(
        fs::File::create(dest).map_err(|e| io_err("create staged input CSV", &dest.display().to_string(), e))?,
    );

    let mut reader = client.copy_out(&statement).map_err(|e| {
        db_error("DB_READ_FAILED", "COPY out of PostgreSQL failed", &e)
    })?;

    let mut buf = vec![0u8; 64 * 1024];
    let mut newlines: u64 = 0;
    let mut bytes: u64 = 0;
    loop {
        let read = reader
            .read(&mut buf)
            .map_err(|e| io_err("read COPY stream from PostgreSQL", &spec.origin, e))?;
        if read == 0 {
            break;
        }
        newlines += buf[..read].iter().filter(|b| **b == b'\n').count() as u64;
        bytes += read as u64;
        file.write_all(&buf[..read])
            .map_err(|e| io_err("write staged input CSV", &dest.display().to_string(), e))?;
    }
    file.flush().map_err(|e| io_err("flush staged input CSV", &dest.display().to_string(), e))?;

    // Values are newline-free by construction, so every line past the header is
    // exactly one row.
    let rows = newlines.saturating_sub(1);
    if rows == 0 {
        return Err(validation(
            "DB_NO_ROWS",
            "The configured PostgreSQL input returned no rows",
            &format!(
                "{} produced only a header row — there is nothing to anonymize. \
                 Check the table name, any WHERE clause, and that this user can see the rows.",
                spec.origin
            ),
        ));
    }

    log.info(
        "postgres_in",
        &format!("Staged {rows} row(s) ({bytes} bytes) to {}", dest.display()),
    );
    log.info(
        "postgres_in",
        "CR/LF inside text values were replaced with spaces so the row-based chunker stays correct",
    );

    Ok(ReadSummary { columns, rows })
}

/// Asks the server what the query returns, without running it.
fn describe_columns(client: &mut Client, query: &str) -> Result<Vec<String>, PipelineError> {
    let statement = client.prepare(query).map_err(|e| {
        db_error("DB_READ_FAILED", "PostgreSQL rejected the input query", &e)
    })?;

    let columns: Vec<String> = statement.columns().iter().map(|c| c.name().to_string()).collect();
    if columns.is_empty() {
        return Err(validation(
            "DB_CONFIG_INVALID",
            "The input query returns no columns",
            "A SKALD input must be a SELECT that produces at least one column",
        ));
    }

    // A join that returns two columns of the same name would silently collapse
    // once the config addresses columns by name — better to say so here.
    let mut seen = std::collections::HashSet::new();
    let duplicates: Vec<&String> = columns.iter().filter(|c| !seen.insert((*c).clone())).collect();
    if !duplicates.is_empty() {
        return Err(validation(
            "DB_CONFIG_INVALID",
            "The input query returns duplicate column names",
            &format!(
                "{duplicates:?} appear more than once. Alias them in the query \
                 (e.g. SELECT a.id AS a_id, b.id AS b_id) so every column is addressable by name."
            ),
        ));
    }

    Ok(columns)
}

/// Wraps the user's query so the server hands back a CSV the chunker can split:
/// every column cast to `text`, CR and LF replaced with spaces.
fn copy_out_statement(query: &str, columns: &[String]) -> String {
    let projection = columns
        .iter()
        .map(|c| {
            let ident = quote_ident(c);
            format!("replace(replace({ident}::text, E'\\r', ' '), E'\\n', ' ') AS {ident}")
        })
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        "COPY (SELECT {projection} FROM ({query}) AS skald_source) TO STDOUT WITH (FORMAT csv, HEADER true)"
    )
}

// ── Writing ──────────────────────────────────────────────────────────────────

/// Loads the anonymized CSV at `src` into the configured table.
///
/// The DDL and the load share one transaction, so a failed load leaves the
/// destination exactly as it was rather than half-populated — including for
/// `replace`, where the old table is still there if the new one never fills.
pub fn write_from_csv(spec: &PgWrite, src: &Path, log: &mut Logger) -> Result<WriteSummary, PipelineError> {
    let columns = read_csv_header(src)?;
    log.info(
        "postgres_out",
        &format!(
            "Connecting to {} to load {} column(s) into {} (mode={})",
            spec.connection.redacted(),
            columns.len(),
            spec.table,
            spec.mode.as_str()
        ),
    );
    if spec.mode.is_destructive() {
        log.warn(
            "postgres_out",
            &format!(
                "mode={} — existing rows in {} are removed before this run's output is loaded",
                spec.mode.as_str(),
                spec.table
            ),
        );
    }

    let mut client = connect(&spec.connection)?;

    if spec.mode == WriteMode::Append && !table_exists(&mut client, spec)? {
        return Err(validation(
            "DB_CONFIG_INVALID",
            "Destination table does not exist",
            &format!(
                "output_sink.table = '{}' with mode=append, but the table is not there. \
                 Create it first, or use mode 'create' to have SKALD create it.",
                spec.table
            ),
        ));
    }

    let mut tx = client.transaction().map_err(|e| {
        db_error("DB_WRITE_FAILED", "Could not begin a transaction on the destination", &e)
    })?;

    for statement in ddl_statements(spec, &columns) {
        tx.batch_execute(&statement).map_err(|e| {
            db_error("DB_WRITE_FAILED", &format!("Statement failed: {statement}"), &e)
        })?;
    }

    let column_list = columns.iter().map(|c| quote_ident(c)).collect::<Vec<_>>().join(", ");
    // `NULL ''` is COPY's default in CSV mode; naming a marker the pipeline
    // never writes is what makes empty fields load as empty strings instead.
    let null_marker = if spec.empty_as_null { "" } else { "\u{1}skald_no_null\u{1}" };
    let statement = format!(
        "COPY {} ({column_list}) FROM STDIN WITH (FORMAT csv, HEADER true, NULL {})",
        spec.table.quoted(),
        quote_literal(null_marker),
    );

    let rows = {
        let mut writer = tx.copy_in(&statement).map_err(|e| {
            db_error("DB_WRITE_FAILED", "COPY into PostgreSQL was rejected", &e)
        })?;

        let mut file = fs::File::open(src)
            .map_err(|e| io_err("open anonymized CSV for upload", &src.display().to_string(), e))?;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let read = file
                .read(&mut buf)
                .map_err(|e| io_err("read anonymized CSV for upload", &src.display().to_string(), e))?;
            if read == 0 {
                break;
            }
            writer.write_all(&buf[..read]).map_err(|e| {
                io_err("stream anonymized CSV to PostgreSQL", &src.display().to_string(), e)
            })?;
        }
        writer.finish().map_err(|e| {
            db_error("DB_WRITE_FAILED", "PostgreSQL rejected the anonymized rows", &e)
        })?
    };

    tx.commit().map_err(|e| db_error("DB_WRITE_FAILED", "Could not commit the loaded rows", &e))?;

    log.info("postgres_out", &format!("Loaded {rows} row(s) into {}", spec.table));

    Ok(WriteSummary {
        table: spec.table.to_string(),
        columns,
        rows,
        mode: spec.mode,
    })
}

/// The DDL each write mode runs before loading, in order.
fn ddl_statements(spec: &PgWrite, columns: &[String]) -> Vec<String> {
    let table = spec.table.quoted();
    let definition = columns
        .iter()
        .map(|c| format!("{} text", quote_ident(c)))
        .collect::<Vec<_>>()
        .join(", ");

    let mut statements = Vec::new();
    if spec.create_schema {
        if let Some(schema) = spec.table.schema() {
            statements.push(format!("CREATE SCHEMA IF NOT EXISTS {}", quote_ident(schema)));
        }
    }
    match spec.mode {
        WriteMode::Append => {}
        WriteMode::Create => {
            statements.push(format!("CREATE TABLE IF NOT EXISTS {table} ({definition})"));
        }
        WriteMode::Truncate => {
            statements.push(format!("CREATE TABLE IF NOT EXISTS {table} ({definition})"));
            statements.push(format!("TRUNCATE TABLE {table}"));
        }
        WriteMode::Replace => {
            statements.push(format!("DROP TABLE IF EXISTS {table}"));
            statements.push(format!("CREATE TABLE {table} ({definition})"));
        }
    }
    statements
}

fn table_exists(client: &mut Client, spec: &PgWrite) -> Result<bool, PipelineError> {
    // `to_regclass` parses its argument as an identifier, so the quoted form is
    // what has to go in: unquoted, a table created as "Ration Members" would be
    // looked up as `ration members` and reported missing.
    let row = client
        .query_one("SELECT to_regclass($1) IS NOT NULL", &[&spec.table.quoted()])
        .map_err(|e| db_error("DB_WRITE_FAILED", "Could not check whether the destination table exists", &e))?;
    Ok(row.get(0))
}

/// Reads just the header line of a CSV this pipeline wrote, honouring the
/// quoting `bootstrap::csv_row_to_line` applies.
fn read_csv_header(path: &Path) -> Result<Vec<String>, PipelineError> {
    let file = fs::File::open(path)
        .map_err(|e| io_err("open anonymized CSV", &path.display().to_string(), e))?;
    let mut lines = BufReader::new(file).lines();
    let header = lines
        .next()
        .transpose()
        .map_err(|e| io_err("read anonymized CSV header", &path.display().to_string(), e))?
        .ok_or_else(|| {
            validation("DATA_EMPTY", "The anonymized CSV has no header row", &path.display().to_string())
        })?;

    let columns = parse_csv_header(&header);
    if columns.is_empty() {
        return Err(validation(
            "DATA_EMPTY",
            "The anonymized CSV header is empty",
            &path.display().to_string(),
        ));
    }
    Ok(columns)
}

fn parse_csv_header(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                current.push('"');
                chars.next();
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => fields.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    fields.push(current);
    fields.iter().map(|f| f.trim_end_matches('\r').to_string()).collect()
}

// ── Connecting ───────────────────────────────────────────────────────────────

fn connect(conn: &PgConnection) -> Result<Client, PipelineError> {
    let config = build_config(conn)?;

    match conn.ssl_mode {
        SslMode::Disable => config
            .connect(NoTls)
            .map_err(|e| db_error("DB_CONNECT_FAILED", "Could not connect to PostgreSQL", &e)),
        _ => {
            let tls = tokio_postgres_rustls::MakeRustlsConnect::new(build_tls_config(conn)?);
            config.connect(tls).map_err(|e| {
                db_error(
                    "DB_CONNECT_FAILED",
                    &format!("Could not connect to PostgreSQL over TLS (sslmode={})", conn.ssl_mode.as_str()),
                    &e,
                )
            })
        }
    }
}

/// Builds the driver config: DSN first if there is one, then the discrete
/// config fields on top of it, then libpq's `PG*` environment variables for
/// anything still unset. Same precedence an operator expects from `psql`.
fn build_config(conn: &PgConnection) -> Result<postgres::Config, PipelineError> {
    use std::str::FromStr;

    let mut config = match &conn.dsn {
        Some(dsn) => postgres::Config::from_str(dsn).map_err(|e| {
            db_error("DB_CONFIG_INVALID", "Could not parse the PostgreSQL connection string", &e)
        })?,
        None => postgres::Config::new(),
    };

    if let Some(host) = &conn.host {
        config.host(host);
    }
    if let Some(port) = conn.port {
        config.port(port);
    }
    if let Some(database) = &conn.database {
        config.dbname(database);
    }
    if let Some(user) = &conn.user {
        config.user(user);
    }
    if let Some(password) = &conn.password {
        config.password(password);
    }

    if config.get_hosts().is_empty() {
        config.host(&std::env::var("PGHOST").unwrap_or_else(|_| "localhost".to_string()));
    }
    if config.get_ports().is_empty() {
        if let Ok(port) = std::env::var("PGPORT") {
            let port = port.parse::<u16>().map_err(|_| {
                validation("DB_CONFIG_INVALID", "PGPORT is not a valid port number", &port)
            })?;
            config.port(port);
        }
    }
    if config.get_dbname().is_none() {
        if let Ok(dbname) = std::env::var("PGDATABASE") {
            config.dbname(&dbname);
        }
    }
    if config.get_user().is_none() {
        let user = std::env::var("PGUSER").or_else(|_| std::env::var("USER")).map_err(|_| {
            validation(
                "DB_CONFIG_INVALID",
                "No PostgreSQL user named",
                "Set 'user' in the config's connection section, or export PGUSER",
            )
        })?;
        config.user(&user);
    }
    if config.get_password().is_none() {
        if let Ok(password) = std::env::var("PGPASSWORD") {
            config.password(&password);
        }
    }

    config.application_name(&conn.application_name);
    config.ssl_mode(match conn.ssl_mode {
        SslMode::Disable => postgres::config::SslMode::Disable,
        SslMode::Prefer => postgres::config::SslMode::Prefer,
        SslMode::Require | SslMode::VerifyCa | SslMode::VerifyFull => postgres::config::SslMode::Require,
    });
    if let Some(seconds) = conn.connect_timeout_seconds {
        config.connect_timeout(Duration::from_secs(seconds));
    }

    Ok(config)
}

fn build_tls_config(conn: &PgConnection) -> Result<ClientConfig, PipelineError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| {
            validation("DB_CONNECT_FAILED", "Could not initialise TLS", &e.to_string())
        })?;

    let config = match conn.ssl_mode {
        SslMode::Disable => unreachable!("callers check for Disable before building a TLS config"),

        // libpq semantics: `prefer` and `require` encrypt the connection but
        // authenticate nothing, so a man in the middle is not ruled out. That
        // is a deliberate choice an operator makes; `verify-full` is the mode
        // that actually proves who the server is.
        SslMode::Prefer | SslMode::Require => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerification(provider)))
            .with_no_client_auth(),

        SslMode::VerifyCa => {
            let roots = Arc::new(root_store(conn)?);
            let inner = WebPkiServerVerifier::builder_with_provider(roots, provider)
                .build()
                .map_err(|e| {
                    validation("DB_CONNECT_FAILED", "Could not build the certificate verifier", &e.to_string())
                })?;
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(ChainOnlyVerification(inner)))
                .with_no_client_auth()
        }

        SslMode::VerifyFull => builder.with_root_certificates(root_store(conn)?).with_no_client_auth(),
    };

    Ok(config)
}

/// The CAs a server certificate is checked against: the PEM bundle named by
/// `sslrootcert` if there is one, otherwise the Mozilla root program's set.
fn root_store(conn: &PgConnection) -> Result<RootCertStore, PipelineError> {
    let mut roots = RootCertStore::empty();

    let Some(path) = &conn.root_cert else {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        return Ok(roots);
    };

    let pem = fs::read(path).map_err(|e| io_err("read sslrootcert PEM bundle", &path.display().to_string(), e))?;
    let mut cursor = pem.as_slice();
    let mut added = 0usize;
    for cert in rustls_pemfile::certs(&mut cursor) {
        let cert = cert.map_err(|e| {
            validation("DB_CONNECT_FAILED", "Malformed certificate in sslrootcert", &format!("{}: {e}", path.display()))
        })?;
        roots.add(cert).map_err(|e| {
            validation("DB_CONNECT_FAILED", "Rejected certificate in sslrootcert", &format!("{}: {e}", path.display()))
        })?;
        added += 1;
    }
    if added == 0 {
        return Err(validation(
            "DB_CONNECT_FAILED",
            "sslrootcert holds no certificates",
            &format!("{} parsed cleanly but contained no CERTIFICATE blocks", path.display()),
        ));
    }
    Ok(roots)
}

/// Verifier for `sslmode=require`/`prefer`: encrypt, prove nothing.
#[derive(Debug)]
struct NoCertVerification(Arc<CryptoProvider>);

impl ServerCertVerifier for NoCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Verifier for `sslmode=verify-ca`: the chain must be trusted, but the name on
/// the certificate need not match the host dialled. Internal deployments reach
/// the same server by several names; libpq draws the line in the same place.
#[derive(Debug)]
struct ChainOnlyVerification(Arc<WebPkiServerVerifier>);

impl ServerCertVerifier for ChainOnlyVerification {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        match self.0.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now) {
            Err(TlsError::InvalidCertificate(CertificateError::NotValidForName))
            | Err(TlsError::InvalidCertificate(CertificateError::NotValidForNameContext { .. })) => {
                Ok(ServerCertVerified::assertion())
            }
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

/// Wraps a driver error, keeping the server's own message — which is nearly
/// always more specific than anything this layer could say — as the detail.
fn db_error<E: std::fmt::Display>(code: &'static str, message: &str, source: &E) -> PipelineError {
    validation(code, message, &source.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::connectors::QualifiedName;

    fn sink(table: &str, mode: WriteMode) -> PgWrite {
        PgWrite {
            connection: connection(),
            table: QualifiedName::parse(table, "output_sink.table").expect("parse table"),
            mode,
            create_schema: true,
            empty_as_null: true,
        }
    }

    fn connection() -> PgConnection {
        PgConnection {
            dsn: None,
            host: Some("127.0.0.1".to_string()),
            port: Some(1),
            database: Some("health".to_string()),
            user: Some("skald".to_string()),
            password: None,
            ssl_mode: SslMode::Disable,
            root_cert: None,
            connect_timeout_seconds: Some(2),
            application_name: "skald".to_string(),
        }
    }

    #[test]
    fn the_read_statement_casts_every_column_and_strips_newlines() {
        let statement = copy_out_statement(
            "SELECT * FROM \"members\"",
            &["uid".to_string(), "Full Name".to_string()],
        );
        assert_eq!(
            statement,
            "COPY (SELECT \
             replace(replace(\"uid\"::text, E'\\r', ' '), E'\\n', ' ') AS \"uid\", \
             replace(replace(\"Full Name\"::text, E'\\r', ' '), E'\\n', ' ') AS \"Full Name\" \
             FROM (SELECT * FROM \"members\") AS skald_source) \
             TO STDOUT WITH (FORMAT csv, HEADER true)"
        );
    }

    #[test]
    fn the_existence_check_looks_the_table_up_by_its_quoted_name() {
        // Not asserted through the server here, but the shape matters: an
        // unquoted "anon.Ration Members" would be folded to lower case and
        // reported missing, failing an append that should have succeeded.
        let spec = sink("anon.Ration Members", WriteMode::Append);
        assert_eq!(spec.table.quoted(), r#""anon"."Ration Members""#);
        assert_eq!(spec.table.to_string(), "anon.Ration Members");
    }

    #[test]
    fn append_runs_no_ddl_at_all() {
        let statements = ddl_statements(&sink("members", WriteMode::Append), &["a".to_string()]);
        assert!(statements.is_empty(), "append must not touch the schema: {statements:?}");
    }

    #[test]
    fn create_makes_the_table_only_when_it_is_missing() {
        let statements = ddl_statements(
            &sink("anon.members", WriteMode::Create),
            &["uid".to_string(), "Age Band".to_string()],
        );
        assert_eq!(
            statements,
            vec![
                r#"CREATE SCHEMA IF NOT EXISTS "anon""#.to_string(),
                r#"CREATE TABLE IF NOT EXISTS "anon"."members" ("uid" text, "Age Band" text)"#.to_string(),
            ]
        );
    }

    #[test]
    fn truncate_empties_an_existing_table_and_replace_rebuilds_it() {
        assert_eq!(
            ddl_statements(&sink("members", WriteMode::Truncate), &["a".to_string()]),
            vec![
                r#"CREATE TABLE IF NOT EXISTS "members" ("a" text)"#.to_string(),
                r#"TRUNCATE TABLE "members""#.to_string(),
            ]
        );
        assert_eq!(
            ddl_statements(&sink("members", WriteMode::Replace), &["a".to_string()]),
            vec![
                r#"DROP TABLE IF EXISTS "members""#.to_string(),
                r#"CREATE TABLE "members" ("a" text)"#.to_string(),
            ]
        );
    }

    #[test]
    fn create_schema_can_be_switched_off_for_an_unprivileged_user() {
        let mut spec = sink("anon.members", WriteMode::Create);
        spec.create_schema = false;
        let statements = ddl_statements(&spec, &["a".to_string()]);
        assert_eq!(statements.len(), 1, "no CREATE SCHEMA expected: {statements:?}");
    }

    #[test]
    fn the_csv_header_parser_honours_the_quoting_the_pipeline_writes() {
        assert_eq!(parse_csv_header("a,b,c"), vec!["a", "b", "c"]);
        assert_eq!(
            parse_csv_header(r#""Full Name","Age, Banded",plain"#),
            vec!["Full Name", "Age, Banded", "plain"]
        );
        assert_eq!(parse_csv_header(r#""say ""hi""",b"#), vec![r#"say "hi""#, "b"]);
        assert_eq!(parse_csv_header("a,b\r"), vec!["a", "b"], "CRLF input must not leave a stray CR");
    }

    #[test]
    fn a_refused_connection_reports_which_step_failed() {
        // Port 1 refuses immediately, so this exercises the real driver path —
        // config assembly, dial, error mapping — without needing a server.
        let spec = PgRead {
            connection: connection(),
            query: "SELECT 1".to_string(),
            origin: "unit test".to_string(),
        };
        let dir = std::env::temp_dir().join(format!("skald_pg_refused_{}", std::process::id()));
        let mut log = Logger::new(&dir);

        let err = read_to_csv(&spec, &dir.join("staged.csv"), &mut log).expect_err("must fail");
        match err {
            PipelineError::Validation { code, .. } => assert_eq!(code, "DB_CONNECT_FAILED"),
            other => panic!("expected DB_CONNECT_FAILED, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
