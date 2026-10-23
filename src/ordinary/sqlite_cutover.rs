//! Narrow offline cutover for fixed main dfb6b7c/v12. No delivery conversion.
//! Schema whitelist: fixed-main normal product C15 fresh pristine-source;
//! optional runtime schema: fixed-main SQLITE_RUNTIME_SIDECAR_TABLE_STATEMENTS.
use super::{
    owner::ProductOwner,
    store::{Health, KernelError},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Connection, Row, SqliteConnection, sqlite::SqliteConnectOptions};
use std::{
    collections::BTreeMap,
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
    sync::Arc,
    time::Duration,
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
const FORMAT: &str = "ordinary-sqlite-cutover-dfb6b7c-v1";
const SOURCE_SCHEMA: &str = include_str!("sqlite_cutover/source_schema.json");
#[cfg(test)]
tokio::task_local! { static FAIL_AFTER_CORE_COMMIT: bool; static FAIL_AFTER_VERSION_FENCE: bool; static FAIL_DURING_RESTORE: bool; static FAIL_BEFORE_RESTORE_STAGE: bool; }
const SOURCE_VERSION: &str = crate::storage::STORAGE_SCHEMA_VERSION_DURABLE_V12;
const FENCED_VERSION: &str = crate::storage::STORAGE_SCHEMA_VERSION;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    format: String,
    phase: String,
    backup: PathBuf,
    source_profile: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Backup {
    format: String,
    source_profile: String,
    files: Vec<BackupFile>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupFile {
    source: PathBuf,
    name: String,
    sha256: String,
}
struct Member {
    kind: &'static str,
    path: PathBuf,
    conn: SqliteConnection,
}
fn invalid(message: &str) -> Box<dyn Error> {
    Box::new(KernelError::Invalid(message.into()))
}
fn marker(core: &Path) -> PathBuf {
    PathBuf::from(format!("{}.ordinary-cutover.json", core.display()))
}
fn related(core: &Path, suffix: &str) -> PathBuf {
    let raw = core.to_string_lossy();
    if let Some(stem) = raw.strip_suffix(".sqlite") {
        format!("{stem}.{suffix}.sqlite").into()
    } else if let Some(stem) = raw.strip_suffix(".db") {
        format!("{stem}.{suffix}.db").into()
    } else {
        format!("{raw}.{suffix}.db").into()
    }
}
fn sqlite_core(url: &str) -> Result<PathBuf> {
    if !url.starts_with("sqlite:") {
        return Err(invalid("offline cutover supports SQLite only"));
    }
    let options = SqliteConnectOptions::from_str(url)?;
    let filename = options.get_filename();
    if filename.as_os_str().is_empty() || filename == Path::new(":memory:") {
        return Err(invalid("file-backed SQLite required"));
    }
    let absolute = if filename.is_absolute() {
        filename.to_path_buf()
    } else {
        std::env::current_dir()?.join(filename)
    };
    let original_parent = absolute
        .parent()
        .ok_or_else(|| invalid("database parent missing"))?;
    if !original_parent.exists() {
        return Ok(absolute);
    }
    let parent = original_parent.canonicalize()?;
    Ok(parent.join(
        absolute
            .file_name()
            .ok_or_else(|| invalid("database filename missing"))?,
    ))
}
fn family(core: &Path) -> Result<Vec<(&'static str, PathBuf)>> {
    let mut paths = vec![
        ("core", core.to_path_buf()),
        ("delivery", related(core, "delivery")),
        ("dispatch", related(core, "dispatch")),
    ];
    let runtime = related(core, "runtime");
    if runtime.exists() {
        paths.push(("runtime", runtime));
    }
    for (_, path) in &paths {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(invalid(
                "cutover requires regular database files without symlinks",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                return Err(invalid("hard-linked database files are unsupported"));
            }
        }
        for suffix in ["-wal", "-shm"] {
            let side = PathBuf::from(format!("{}{suffix}", path.display()));
            if let Ok(m) = fs::symlink_metadata(side)
                && (!m.is_file() || m.file_type().is_symlink())
            {
                return Err(invalid("invalid SQLite companion file"));
            }
        }
    }
    Ok(paths)
}
/// Old main does not honor ProductOwner. Inspect actual handles before opening.
fn inspect_handles(paths: &[(&str, PathBuf)], allow_current: bool) -> Result<()> {
    let mut command = Command::new("lsof");
    command.arg("-t").arg("--");
    for (_, path) in paths {
        command.arg(path);
        for suffix in ["-wal", "-shm"] {
            let p = PathBuf::from(format!("{}{suffix}", path.display()));
            if p.exists() {
                command.arg(p);
            }
        }
    }
    let output = command
        .output()
        .map_err(|_| invalid("lsof unavailable; cannot verify old process absence"))?;
    if !output.stderr.is_empty() || !matches!(output.status.code(), Some(0 | 1)) {
        return Err(invalid("open-handle inspection failed"));
    }
    let current = std::process::id().to_string();
    if String::from_utf8(output.stdout)?
        .lines()
        .any(|pid| !pid.is_empty() && (!allow_current || pid != current))
    {
        return Err(invalid(
            "database family still has open handles; stop and join every old process first",
        ));
    }
    Ok(())
}
async fn open_locked(paths: &[(&'static str, PathBuf)]) -> Result<Vec<Member>> {
    let mut members = Vec::new();
    for (kind, path) in paths {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(false)
            .busy_timeout(Duration::from_secs(3));
        let mut conn = SqliteConnection::connect_with(&options).await?;
        let row = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .fetch_one(&mut conn)
            .await?;
        if row.get::<i64, _>(0) != 0 {
            return Err(invalid("SQLite checkpoint busy"));
        }
        sqlx::query("PRAGMA synchronous=FULL")
            .execute(&mut conn)
            .await?;
        sqlx::query("PRAGMA temp_store=FILE")
            .execute(&mut conn)
            .await?;
        sqlx::query("BEGIN EXCLUSIVE").execute(&mut conn).await?;
        members.push(Member {
            kind,
            path: path.clone(),
            conn,
        });
    }
    Ok(members)
}
async fn validate_schema(members: &mut [Member]) -> Result<()> {
    validate_source_schema(members, SOURCE_VERSION).await
}
async fn validate_source_schema(members: &mut [Member], expected_version: &str) -> Result<()> {
    let expected: BTreeMap<String, Vec<(String, String, String)>> =
        serde_json::from_str(SOURCE_SCHEMA)?;
    for member in members.iter_mut() {
        let check: String = sqlx::query_scalar("PRAGMA integrity_check")
            .fetch_one(&mut member.conn)
            .await?;
        if check != "ok" {
            return Err(invalid("source integrity_check failed"));
        }
        let expected = &expected[member.kind];
        let max_sql_bytes = expected
            .iter()
            .map(|(_, _, sql)| sql.len())
            .max()
            .unwrap_or(0) as i64;
        let actual = sqlx::query(
            "SELECT type,CASE WHEN length(name)<=128 THEN name END AS name,CASE WHEN length(CAST(sql AS BLOB))<=? THEN sql END AS sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type,name LIMIT ?",
        )
        .bind(max_sql_bytes)
        .bind(expected.len() as i64+1)
        .fetch_all(&mut member.conn)
        .await?;
        if actual.len() != expected.len() {
            return Err(invalid("unsupported fixed-main source schema objects"));
        }
        for (row, (kind, name, sql)) in actual.iter().zip(expected) {
            if row.get::<String, _>("type") != *kind
                || row.get::<Option<String>, _>("name").as_deref() != Some(name.as_str())
                || row
                    .get::<Option<String>, _>("sql")
                    .as_deref()
                    .map(str::trim)
                    != Some(sql.trim())
            {
                return Err(invalid("unsupported or damaged fixed-main schema"));
            }
            if kind == "table" {
                // SQLite permits NULL in several historical TEXT PRIMARY KEYs;
                // keyset pagination must not silently skip damaged identities.
                let columns =
                    sqlx::query(sqlx::AssertSqlSafe(format!("PRAGMA table_info({name})")))
                        .fetch_all(&mut member.conn)
                        .await?;
                for column in columns {
                    if column.get::<i64, _>("pk") > 0 {
                        let column: String = column.get("name");
                        if sqlx::query_scalar::<_,i64>(sqlx::AssertSqlSafe(format!("SELECT EXISTS(SELECT 1 FROM {name} WHERE {column} IS NULL OR length({column})=0)"))).fetch_one(&mut member.conn).await?!=0 {return Err(invalid("NULL or empty source primary identity"));}
                    }
                }
            }
        }
    }
    let core = &mut members[0].conn;
    let version: String = sqlx::query_scalar(
        "SELECT meta_value FROM pushgo_schema_meta WHERE meta_key='schema_version'",
    )
    .fetch_one(&mut *core)
    .await?;
    if version != expected_version {
        return Err(invalid("unsupported source schema version"));
    }
    validate_migration_receipts(core).await?;
    for member in members.iter_mut().skip(1) {
        let key = match member.kind {
            "dispatch" => "dispatch_migrated_from_core_v1",
            "delivery" => "runtime_delivery_migrated_from_core_v1",
            _ => "runtime_migrated_from_core_v1",
        };
        let value: Option<String> =
            sqlx::query_scalar("SELECT meta_value FROM pushgo_sidecar_meta WHERE meta_key=?")
                .bind(key)
                .fetch_optional(&mut member.conn)
                .await?;
        if value.as_deref() != Some("done") {
            return Err(invalid("source sidecar migration is not complete"));
        }
    }
    Ok(())
}
async fn validate_migration_receipts(conn: &mut SqliteConnection) -> Result<()> {
    let rows = sqlx::query(
        "SELECT migration_id,checksum,success FROM pushgo_schema_migrations ORDER BY migration_id",
    )
    .fetch_all(&mut *conn)
    .await?;
    let definitions = crate::storage::database::migration::SCHEMA_MIGRATIONS;
    if rows.len() != definitions.len() {
        return Err(invalid("source migration set is incomplete or unknown"));
    }
    for row in rows {
        let id: String = row.get("migration_id");
        let checksum: String = row.get("checksum");
        if !definitions
            .iter()
            .any(|d| d.id == id && d.checksum == checksum)
            || row.get::<i64, _>("success") != 1
        {
            return Err(invalid("source migration checksum/success mismatch"));
        }
    }
    Ok(())
}
/// Metadata-only transaction: no business conversion can commit under v12.
async fn fence_core(conn: &mut SqliteConnection) -> Result<()> {
    let changed = sqlx::query("UPDATE pushgo_schema_meta SET meta_value=? WHERE meta_key='schema_version' AND meta_value IN (?,?)")
        .bind(FENCED_VERSION).bind(SOURCE_VERSION).bind(FENCED_VERSION)
        .execute(&mut *conn).await?.rows_affected();
    if changed != 1 {
        return Err(invalid("unsupported cutover fence version"));
    }
    sqlx::query("COMMIT").execute(&mut *conn).await?;
    sqlx::query("BEGIN EXCLUSIVE").execute(conn).await?;
    Ok(())
}
/// Use SQLite itself to obtain the canonical C identity definition. A marker or
/// a similarly named table alone must never authorize promotion of a v12 file.
async fn validate_cutover_identity(conn: &mut SqliteConnection) -> Result<()> {
    validate_migration_receipts(conn).await?;
    let mut reference = SqliteConnection::connect("sqlite::memory:").await?;
    sqlx::raw_sql(super::store::MESSAGE_SCHEMA)
        .execute(&mut reference)
        .await?;
    let expected: String = sqlx::query_scalar(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='ordinary_messages'",
    )
    .fetch_one(&mut reference)
    .await?;
    reference.close().await?;
    let actual: Option<String> = sqlx::query_scalar(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='ordinary_messages'",
    )
    .fetch_optional(&mut *conn)
    .await?;
    if actual.as_deref().map(str::trim) != Some(expected.trim()) {
        return Err(invalid("cutover identity schema is incomplete or unknown"));
    }
    let check: String = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_one(conn)
        .await?;
    if check != "ok" {
        return Err(invalid("cutover identity integrity_check failed"));
    }
    Ok(())
}
async fn ensure_cutover_fence(paths: &[(&'static str, PathBuf)]) -> Result<()> {
    let mut members = open_locked(paths).await?;
    inspect_handles(paths, true)?;
    validate_cutover_identity(&mut members[0].conn).await?;
    if sqlx::query_scalar::<_, i64>(
        "SELECT EXISTS(SELECT 1 FROM sender_submit_status WHERE model='message')",
    )
    .fetch_one(&mut members[0].conn)
    .await?
        != 0
    {
        return Err(invalid(
            "cutover retains unconverted ordinary source identities",
        ));
    }
    for member in &mut members {
        if exists(&mut member.conn, "semantic_id_registry").await? {
            let mut cursor = String::new();
            loop {
                let keys = sqlx::query_scalar::<_, String>("SELECT dedupe_key FROM semantic_id_registry WHERE dedupe_key>? ORDER BY dedupe_key LIMIT 256")
                    .bind(&cursor).fetch_all(&mut member.conn).await?;
                if keys.is_empty() {
                    break;
                }
                for key in keys {
                    if scope(&key, "semantic")?.1 == "message" {
                        return Err(invalid(
                            "cutover retains unconverted ordinary semantic identities",
                        ));
                    }
                    cursor = key;
                }
            }
        }
    }
    fence_core(&mut members[0].conn).await?;
    for member in members {
        member.conn.close().await?;
    }
    Ok(())
}
fn scope(key: &str, prefix: &str) -> Result<(String, String, Option<String>, String)> {
    let parts: Vec<_> = key.splitn(5, ':').collect();
    if parts.len() != 5
        || parts[0] != prefix
        || !matches!(parts[2], "message" | "event" | "thing")
        || parts.iter().any(|p| p.is_empty())
    {
        return Err(invalid("unknown or ambiguous source dedupe scope"));
    }
    let channel = crate::util::decode_crockford_base32_128(parts[1])
        .map_err(|_| invalid("invalid source channel scope"))?;
    if parts[1] != crate::util::encode_crockford_base32_128(&channel).to_ascii_lowercase() {
        return Err(invalid("noncanonical source channel scope"));
    }
    crate::value::OpId::parse(parts[4]).map_err(|_| invalid("invalid source operation scope"))?;
    Ok((
        crate::util::encode_lower_hex_128(&channel),
        parts[2].into(),
        (parts[3] != "-").then(|| parts[3].into()),
        parts[4].into(),
    ))
}
async fn exists(conn: &mut SqliteConnection, table: &str) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?)",
    )
    .bind(table)
    .fetch_one(conn)
    .await?
        != 0)
}
async fn check_drained(members: &mut [Member]) -> Result<()> {
    for member in members.iter_mut() {
        if exists(&mut member.conn, "dispatch_delivery_dedupe").await? {
            let mut cursor = String::new();
            loop {
                let rows=sqlx::query("SELECT dedupe_key,delivery_id,state FROM dispatch_delivery_dedupe WHERE dedupe_key>? ORDER BY dedupe_key LIMIT 256").bind(&cursor).fetch_all(&mut member.conn).await?;
                if rows.is_empty() {
                    break;
                }
                for row in rows {
                    cursor = row.get("dedupe_key");
                    let id: String = row.get("delivery_id");
                    if cursor != format!("delivery:{id}")
                        || crate::util::decode_lower_hex_128(&id).is_err()
                        || id != id.to_ascii_lowercase()
                        || row.get::<String, _>("state") != "sent"
                    {
                        return Err(invalid("invalid retained delivery collision identity"));
                    }
                }
            }
        }
        for table in [
            "dispatch_submission",
            "provider_dispatch_outbox",
            "private_payloads",
            "private_outbox",
            "provider_pull_queue",
        ] {
            if exists(&mut member.conn, table).await?
                && sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!(
                    "SELECT EXISTS(SELECT 1 FROM {table})"
                )))
                .fetch_one(&mut member.conn)
                .await?
                    != 0
            {
                return Err(invalid(
                    "offline subset requires all target-bearing tables empty across every model, including terminal/ACK rows",
                ));
            }
        }
        if exists(&mut member.conn, "dispatch_op_dedupe").await? {
            let mut cursor = String::new();
            loop {
                let rows=sqlx::query("SELECT dedupe_key,state,provider_run_token,provider_owner,provider_lease_until FROM dispatch_op_dedupe WHERE dedupe_key>? ORDER BY dedupe_key LIMIT 256").bind(&cursor).fetch_all(&mut member.conn).await?;
                if rows.is_empty() {
                    break;
                }
                for row in rows {
                    cursor = row.get("dedupe_key");
                    let (_, model, _, _) = scope(&cursor, "op")?;
                    if model == "message"
                        || row.get::<String, _>("state") != "sent"
                        || row.get::<Option<String>, _>("provider_run_token").is_some()
                        || row.get::<Option<String>, _>("provider_owner").is_some()
                        || row.get::<Option<i64>, _>("provider_lease_until").is_some()
                    {
                        return Err(invalid(
                            "ordinary or unresolved nonordinary op responsibility is outside cutover subset",
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}
struct Historical {
    key: String,
    message: String,
    op: String,
    channel: String,
    thing: Option<String>,
    created: i64,
    accepted: i64,
    updated: i64,
}
async fn read_history(
    members: &mut [Member],
    source: usize,
    row: &sqlx::sqlite::SqliteRow,
) -> Result<Option<Historical>> {
    let key: String = row.get("dedupe_key");
    let (channel, model, thing, op_key) = scope(&key, "semantic")?;
    if model != "message" {
        return Ok(None);
    }
    if thing.is_some() && op_key.contains(':') {
        return Err(invalid(
            "ambiguous colon-separated thing/operation source scope",
        ));
    }
    let message: String = row.get("semantic_id");
    crate::util::decode_lower_hex_128(&message)
        .map_err(|_| invalid("invalid original message identity"))?;
    let created: i64 = row.get("created_at");
    if row.get::<Option<i64>, _>("expires_at").is_some()
        || row.get::<Option<String>, _>("source").is_some()
        || created <= 0
        || row.get::<i64, _>("updated_at") < created
    {
        return Err(invalid(
            "unsupported source semantic identity expiry/provenance",
        ));
    }
    let status = sqlx::query("SELECT * FROM cutover_status WHERE entity_id=? LIMIT 2")
        .bind(&message)
        .fetch_all(&mut members[0].conn)
        .await?;
    if status.len() != 1 {
        return Err(invalid(
            "ordinary semantic/status relation is missing or ambiguous",
        ));
    }
    let status = &status[0];
    let op: String = status.get("op_id");
    if op.to_ascii_lowercase() != op_key
        || status.get::<String, _>("channel") != channel
        || status.get::<String, _>("status") != "failed"
        || status
            .get::<Option<String>, _>("dispatch_status")
            .as_deref()
            != Some("not_attempted")
        || status
            .get::<Option<String>, _>("provider_run_token")
            .is_some()
    {
        return Err(invalid(
            "ordinary history is not verified zero-target failed/not_attempted",
        ));
    }
    let accepted: i64 = status.get("accepted_at");
    let updated: i64 = status.get("updated_at");
    if accepted <= 0 || updated < accepted || status.get::<i64, _>("expires_at") <= accepted {
        return Err(invalid("invalid source acceptance timestamps"));
    }
    for (index, member) in members.iter_mut().enumerate() {
        if index != source && exists(&mut member.conn, "semantic_id_registry").await? {
            let duplicate:i64=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM semantic_id_registry WHERE semantic_id=? OR dedupe_key=?)").bind(&message).bind(&key).fetch_one(&mut member.conn).await?;
            if duplicate != 0 {
                return Err(invalid(
                    "duplicate semantic identity across source databases",
                ));
            }
        }
    }
    Ok(Some(Historical {
        key,
        message,
        op,
        channel: crate::util::encode_crockford_base32_128(
            &crate::util::decode_lower_hex_128(&channel)
                .map_err(|_| invalid("invalid channel identity"))?,
        ),
        thing,
        created,
        accepted,
        updated,
    }))
}
async fn visit_history(members: &mut [Member], retention: i64, convert: bool) -> Result<u64> {
    let mut count = 0;
    // A disk-backed temporary index avoids one full sender-status scan per
    // history row. The projection is temporary and never part of either DB.
    sqlx::query("CREATE TEMP TABLE cutover_status(op_id TEXT PRIMARY KEY,op_fold TEXT NOT NULL UNIQUE,entity_id TEXT NOT NULL UNIQUE,channel TEXT NOT NULL,status TEXT NOT NULL,dispatch_status TEXT,provider_run_token TEXT,accepted_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,expires_at INTEGER NOT NULL)").execute(&mut members[0].conn).await?;
    let mut status_cursor = String::new();
    loop {
        let rows=sqlx::query("SELECT op_id,entity_id,lower(hex(channel_id)) AS channel,status,dispatch_status,provider_run_token,accepted_at,updated_at,expires_at FROM sender_submit_status WHERE op_id>? AND model='message' ORDER BY op_id LIMIT 256").bind(&status_cursor).fetch_all(&mut members[0].conn).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            status_cursor = row.get("op_id");
            sqlx::query("INSERT INTO cutover_status VALUES(?,?,?,?,?,?,?,?,?,?)")
                .bind(&status_cursor)
                .bind(status_cursor.to_ascii_lowercase())
                .bind(row.get::<String, _>("entity_id"))
                .bind(row.get::<String, _>("channel"))
                .bind(row.get::<String, _>("status"))
                .bind(row.get::<Option<String>, _>("dispatch_status"))
                .bind(row.get::<Option<String>, _>("provider_run_token"))
                .bind(row.get::<i64, _>("accepted_at"))
                .bind(row.get::<i64, _>("updated_at"))
                .bind(row.get::<i64, _>("expires_at"))
                .execute(&mut members[0].conn)
                .await
                .map_err(|_| invalid("duplicate ordinary op aliases/message identity"))?;
        }
    }
    sqlx::query("CREATE TEMP TABLE cutover_seen(op TEXT PRIMARY KEY,message TEXT UNIQUE NOT NULL)")
        .execute(&mut members[0].conn)
        .await?;
    for source in 0..members.len() {
        if !exists(&mut members[source].conn, "semantic_id_registry").await? {
            continue;
        }
        let mut cursor = String::new();
        loop {
            let rows=sqlx::query("SELECT dedupe_key,semantic_id,source,created_at,updated_at,expires_at FROM semantic_id_registry WHERE dedupe_key>? ORDER BY dedupe_key LIMIT 256").bind(&cursor).fetch_all(&mut members[source].conn).await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                cursor = row.get("dedupe_key");
                if let Some(h) = read_history(members, source, &row).await? {
                    sqlx::query("INSERT INTO cutover_seen(op,message) VALUES(?,?)")
                        .bind(h.op.to_ascii_lowercase())
                        .bind(&h.message)
                        .execute(&mut members[0].conn)
                        .await
                        .map_err(|_| invalid("source op/message collision across scopes"))?;
                    let until = h
                        .created
                        .checked_add(retention)
                        .ok_or_else(|| invalid("source retention overflow"))?;
                    if convert {
                        sqlx::query("INSERT INTO ordinary_messages(delivery_id,message_id,op_id,channel_id,thing_id,fingerprint,payload_blob,payload_bytes,accepted_at,expires_at,dedupe_until,status,updated_at,identity_state) VALUES(NULL,?,?,?,?,NULL,x'',0,?,NULL,?,'historical_unverifiable',?,'legacy_unverifiable')").bind(&h.message).bind(&h.op).bind(&h.channel).bind(&h.thing).bind(h.accepted).bind(until).bind(h.updated).execute(&mut members[0].conn).await?;
                        sqlx::query("DELETE FROM semantic_id_registry WHERE dedupe_key=?")
                            .bind(&h.key)
                            .execute(&mut members[source].conn)
                            .await?;
                    }
                    count += 1;
                }
            }
        }
    }
    let statuses: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM cutover_status")
        .fetch_one(&mut members[0].conn)
        .await?;
    if statuses != count as i64 {
        return Err(invalid(
            "orphan ordinary sender status or semantic identity",
        ));
    }
    if convert {
        sqlx::query("DELETE FROM sender_submit_status WHERE model='message'")
            .execute(&mut members[0].conn)
            .await?;
    }
    sqlx::query("DROP TABLE cutover_seen")
        .execute(&mut members[0].conn)
        .await?;
    sqlx::query("DROP TABLE cutover_status")
        .execute(&mut members[0].conn)
        .await?;
    Ok(count)
}
fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}
fn json_new(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.sync_all()?;
    sync_dir(path.parent().ok_or_else(|| invalid("missing parent"))?)
}
fn save_state(core: &Path, state: &State) -> Result<()> {
    let path = marker(core);
    let temp = path.with_extension("json.next");
    // A previous staged state is observed by read_state before this helper is
    // called. In particular an activation intent can never permit rollback.
    if temp.exists() {
        fs::remove_file(&temp)?;
    }
    json_new(&temp, state)?;
    fs::rename(temp, &path)?;
    sync_dir(path.parent().unwrap())
}
fn read_state(core: &Path) -> Result<Option<State>> {
    let path = marker(core);
    let staged = path.with_extension("json.next");
    match fs::read(if staged.exists() { staged } else { path }) {
        Ok(bytes) => {
            let state: State = serde_json::from_slice(&bytes)?;
            if state.format != FORMAT {
                return Err(invalid("unsupported cutover state"));
            }
            Ok(Some(state))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}
/// Only explicit restore may recover a torn staged write. Activation remains
/// fail-closed. Runtime writes begin only after activation rename and fsync.
fn read_restore_state(core: &Path, dir: &Path, paths: &[(&str, PathBuf)]) -> Result<Option<State>> {
    let first = read_state(core);
    if first.is_ok() {
        return first;
    }
    let staged = fs::read(marker(core).with_extension("json.next"))?;
    if !serde_json::from_slice::<State>(&staged).is_err_and(|e| e.is_eof()) {
        return first;
    }
    match fs::read(marker(core)) {
        Ok(bytes) => {
            let stable: State = serde_json::from_slice(&bytes)?;
            if stable.format != FORMAT
                || !matches!(
                    stable.phase.as_str(),
                    "preparing" | "prepared" | "complete" | "restoring"
                )
            {
                return Err(invalid(
                    "restore prohibited: stable state is activated or unknown",
                ));
            }
            Ok(Some(stable))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let manifest: Backup = serde_json::from_slice(&fs::read(dir.join("manifest.json"))?)?;
            if manifest.format != FORMAT {
                return Err(invalid("unsupported restore manifest"));
            }
            retention(&manifest.source_profile)?;
            let allowed: Vec<PathBuf> = paths
                .iter()
                .flat_map(|(_, p)| {
                    [
                        p.clone(),
                        PathBuf::from(format!("{}-wal", p.display())),
                        PathBuf::from(format!("{}-shm", p.display())),
                    ]
                })
                .collect();
            for (_, path) in paths {
                if manifest
                    .files
                    .iter()
                    .filter(|entry| entry.source == *path)
                    .count()
                    != 1
                {
                    return Err(invalid(
                        "first preparing-write restore lacks complete family identity",
                    ));
                }
            }
            for entry in &manifest.files {
                if !allowed.contains(&entry.source)
                    || entry.source.file_name() != Path::new(&entry.name).file_name()
                    || Path::new(&entry.name).file_name().and_then(|s| s.to_str())
                        != Some(entry.name.as_str())
                    || digest(&dir.join(&entry.name))? != entry.sha256
                {
                    return Err(invalid(
                        "invalid first preparing-write backup identity/hash",
                    ));
                }
                if entry.name.ends_with("-shm") {
                    continue;
                }
                if !entry.source.exists()
                    && entry.name.ends_with("-wal")
                    && fs::metadata(dir.join(&entry.name))?.len() == 0
                {
                    continue;
                }
                if digest(&entry.source)? != entry.sha256 {
                    return Err(invalid(
                        "first preparing-write restore requires unchanged source family bytes",
                    ));
                }
            }
            for (_, path) in paths {
                let wal = PathBuf::from(format!("{}-wal", path.display()));
                if wal.exists()
                    && fs::metadata(&wal)?.len() > 0
                    && !manifest.files.iter().any(|entry| entry.source == wal)
                {
                    return Err(invalid(
                        "unexpected current WAL prevents first preparing-write restore",
                    ));
                }
            }
            Ok(Some(State {
                format: FORMAT.into(),
                phase: "preparing".into(),
                backup: dir.canonicalize()?,
                source_profile: manifest.source_profile,
            }))
        }
        Err(error) => Err(error.into()),
    }
}
fn digest(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut bytes = [0; 64 * 1024];
    loop {
        let read = file.read(&mut bytes)?;
        if read == 0 {
            break;
        }
        digest.update(&bytes[..read]);
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
fn copy_sync(from: &Path, to: &Path) -> Result<()> {
    let mut source = File::open(from)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut target = options.open(to)?;
    std::io::copy(&mut source, &mut target)?;
    target.sync_all()?;
    Ok(())
}
fn backup(members: &[Member], dir: &Path, profile: &str) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)?;
    sync_dir(
        dir.parent()
            .ok_or_else(|| invalid("backup parent missing"))?,
    )?;
    let mut files = Vec::new();
    for member in members {
        for suffix in ["", "-wal", "-shm"] {
            let source = PathBuf::from(format!("{}{suffix}", member.path.display()));
            if source.exists() {
                let name = source
                    .file_name()
                    .unwrap()
                    .to_str()
                    .ok_or_else(|| invalid("non UTF8 database filename"))?
                    .to_string();
                let target = dir.join(&name);
                copy_sync(&source, &target)?;
                files.push(BackupFile {
                    source,
                    name,
                    sha256: digest(&target)?,
                });
            }
        }
    }
    json_new(
        &dir.join("manifest.json"),
        &Backup {
            format: FORMAT.into(),
            source_profile: profile.into(),
            files,
        },
    )?;
    sync_dir(dir)
}
fn retention(profile: &str) -> Result<i64> {
    match profile {
        "small" => Ok(7 * 86_400_000),
        "public" => Ok(30 * 86_400_000),
        _ => Err(invalid(
            "explicit fixed-main source profile small|public required; database cannot prove historical configuration",
        )),
    }
}
pub async fn run(
    db_url: &str,
    action: &str,
    backup_dir: &Path,
    source_profile: Option<&str>,
) -> Result<()> {
    if !matches!(action, "plan" | "run" | "restore") {
        return Err(invalid("cutover action must be plan, run, or restore"));
    }
    let core = sqlite_core(db_url)?;
    let owner = ProductOwner::acquire(Some(db_url), Arc::new(Health::default())).await?;
    let result = run_owned(&core, action, backup_dir, source_profile).await;
    owner.shutdown().await?;
    result
}
async fn run_owned(
    core: &Path,
    action: &str,
    backup_dir: &Path,
    profile: Option<&str>,
) -> Result<()> {
    let paths = family(core)?;
    inspect_handles(&paths, false)?;
    let previous = if action == "restore" {
        read_restore_state(core, backup_dir, &paths)?
    } else {
        read_state(core)?
    };
    if action == "restore" {
        return restore(core, &paths, backup_dir, previous).await;
    }
    let profile =
        profile.ok_or_else(|| invalid("--ordinary-source-profile small|public required"))?;
    let retention = retention(profile)?;
    if let Some(state) = previous {
        if matches!(state.phase.as_str(), "complete" | "activated")
            && state.backup == backup_dir.canonicalize()?
            && state.source_profile == profile
        {
            ensure_cutover_fence(&paths).await?;
            println!("offline cutover already {}; no rows changed", state.phase);
            return Ok(());
        }
        return Err(invalid(
            "existing cutover state requires explicit restore; backup must never be overwritten",
        ));
    }
    if backup_dir.exists() {
        return Err(invalid(
            "backup directory already exists; refusing overwrite",
        ));
    }
    let parent = backup_dir
        .parent()
        .ok_or_else(|| invalid("backup parent missing"))?
        .canonicalize()?;
    let backup_dir = parent.join(
        backup_dir
            .file_name()
            .ok_or_else(|| invalid("backup filename missing"))?,
    );
    let mut members = open_locked(&paths).await?;
    inspect_handles(&paths, true)?;
    validate_schema(&mut members).await?;
    check_drained(&mut members).await?;
    let count = visit_history(&mut members, retention, false).await?;
    if action == "plan" {
        println!(
            "offline cutover plan: {count} legacy_unverifiable identities; source profile {profile}; global target tables drained; no conversion"
        );
        return Ok(());
    }
    backup(&members, &backup_dir, profile)?;
    let mut state = State {
        format: FORMAT.into(),
        phase: "preparing".into(),
        backup: backup_dir,
        source_profile: profile.into(),
    };
    save_state(core, &state)?;
    fence_core(&mut members[0].conn).await?;
    #[cfg(test)]
    if FAIL_AFTER_VERSION_FENCE
        .try_with(|enabled| *enabled)
        .unwrap_or(false)
    {
        for member in members {
            member.conn.close().await?;
        }
        return Err(invalid("test interruption before business conversion"));
    }
    state.phase = "prepared".into();
    save_state(core, &state)?;
    sqlx::raw_sql(super::store::MESSAGE_SCHEMA)
        .execute(&mut members[0].conn)
        .await?;
    visit_history(&mut members, retention, true).await?;
    for member in &mut members {
        sqlx::query("COMMIT").execute(&mut member.conn).await?;
        #[cfg(test)]
        if member.kind == "core"
            && FAIL_AFTER_CORE_COMMIT
                .try_with(|enabled| *enabled)
                .unwrap_or(false)
        {
            // Keep the real committed core and roll back the still-uncommitted
            // sidecars through native close, exactly the partial-commit seam.
            for member in members {
                member.conn.close().await?;
            }
            return Err(invalid("test interruption after core COMMIT"));
        }
    }
    for member in members {
        member.conn.close().await?;
        File::open(member.path)?.sync_all()?;
    }
    state.phase = "complete".into();
    save_state(core, &state)?;
    println!(
        "offline cutover complete: {count} historical identities; rollback available only before normal runtime activation"
    );
    Ok(())
}
async fn restore(
    core: &Path,
    paths: &[(&'static str, PathBuf)],
    dir: &Path,
    previous: Option<State>,
) -> Result<()> {
    let mut state = previous.ok_or_else(|| invalid("no cutover state to restore"))?;
    if !matches!(
        state.phase.as_str(),
        "preparing" | "prepared" | "complete" | "restoring"
    ) {
        return Err(invalid("restore prohibited after runtime activation"));
    }
    if state.backup != dir.canonicalize()? {
        return Err(invalid(
            "restore backup does not match durable cutover state",
        ));
    }
    let manifest: Backup = serde_json::from_slice(&fs::read(dir.join("manifest.json"))?)?;
    if manifest.format != FORMAT || manifest.source_profile != state.source_profile {
        return Err(invalid("backup provenance mismatch"));
    }
    let allowed: Vec<PathBuf> = paths
        .iter()
        .flat_map(|(_, p)| {
            [
                p.clone(),
                PathBuf::from(format!("{}-wal", p.display())),
                PathBuf::from(format!("{}-shm", p.display())),
            ]
        })
        .collect();
    for (_, p) in paths {
        if manifest.files.iter().filter(|f| f.source == *p).count() != 1 {
            return Err(invalid(
                "backup omits or duplicates a database family member",
            ));
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for entry in &manifest.files {
        if !allowed.contains(&entry.source)
            || !seen.insert(&entry.source)
            || Path::new(&entry.name).file_name().and_then(|s| s.to_str())
                != Some(entry.name.as_str())
            || entry.source.file_name() != Path::new(&entry.name).file_name()
            || digest(&dir.join(&entry.name))? != entry.sha256
        {
            return Err(invalid("backup file identity/hash mismatch"));
        }
    }
    // A retry may see a mixed database/WAL family from interrupted renames.
    // Never ask SQLite to recover that intermediate state; replace it directly
    // after the mandatory process/handle check and ProductOwner acquisition.
    let mut members = if state.phase == "restoring" {
        Vec::new()
    } else {
        open_locked(paths).await?
    };
    if state.phase == "preparing" {
        // Intent may precede the metadata fence, but never business conversion.
        // Admit only the exact source schema and supported source/fenced header.
        let version: String = sqlx::query_scalar(
            "SELECT meta_value FROM pushgo_schema_meta WHERE meta_key='schema_version'",
        )
        .fetch_one(&mut members[0].conn)
        .await?;
        if !matches!(version.as_str(), SOURCE_VERSION | FENCED_VERSION) {
            return Err(invalid(
                "preparing restore requires pristine source version",
            ));
        }
        validate_source_schema(&mut members, &version).await?;
        check_drained(&mut members).await?;
        visit_history(&mut members, retention(&state.source_profile)?, false).await?;
    }
    // Legacy C15/C16 complete backups may still have the old v12 header.
    // Fence the original family while every member is locked, before exposing
    // a restoring marker or releasing handles for native staging and renames.
    if let Some(member) = members.first_mut() {
        fence_core(&mut member.conn).await?;
    }
    state.phase = "restoring".into();
    save_state(core, &state)?;
    for member in members {
        member.conn.close().await?;
    }
    #[cfg(test)]
    if FAIL_BEFORE_RESTORE_STAGE
        .try_with(|enabled| *enabled)
        .unwrap_or(false)
    {
        return Err(invalid("test interruption before restore staging"));
    }
    // Validate a complete staged backup through native SQLite before changing
    // any published member. The backups were checkpointed while all files were
    // locked; a nonempty WAL is not a restorable byte-exact snapshot here.
    for entry in &manifest.files {
        if entry.name.ends_with("-wal") && fs::metadata(dir.join(&entry.name))?.len() != 0 {
            return Err(invalid("restore requires checkpointed backup WAL"));
        }
    }
    let staged_paths: Vec<_> = paths
        .iter()
        .map(|(kind, path)| {
            (
                *kind,
                PathBuf::from(format!("{}.ordinary-restore", path.display())),
            )
        })
        .collect();
    for (_, path) in &staged_paths {
        for suffix in ["", "-wal", "-shm"] {
            let temporary = PathBuf::from(format!("{}{suffix}", path.display()));
            if temporary.exists() {
                fs::remove_file(temporary)?;
            }
        }
    }
    for ((_, original), (_, staged)) in paths.iter().zip(&staged_paths) {
        let entry = manifest
            .files
            .iter()
            .find(|entry| entry.source == *original)
            .unwrap();
        copy_sync(&dir.join(&entry.name), staged)?;
    }
    let mut staged = open_locked(&staged_paths).await?;
    validate_schema(&mut staged).await?;
    check_drained(&mut staged).await?;
    visit_history(&mut staged, retention(&state.source_profile)?, false).await?;
    fence_core(&mut staged[0].conn).await?;
    for mut member in staged {
        sqlx::query("ROLLBACK").execute(&mut member.conn).await?;
        let row = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .fetch_one(&mut member.conn)
            .await?;
        if row.get::<i64, _>(0) != 0 {
            return Err(invalid("staged restore checkpoint busy"));
        }
        member.conn.close().await?;
        File::open(&member.path)?.sync_all()?;
        for suffix in ["-wal", "-shm"] {
            let side = PathBuf::from(format!("{}{suffix}", member.path.display()));
            if side.exists() {
                fs::remove_file(side)?;
            }
        }
    }
    // Publish the fenced core first. No intermediate family can be admitted by
    // fixed main. All native handles are closed before replacing live files.
    for ((_, original), (_, staged)) in paths.iter().zip(&staged_paths) {
        for suffix in ["-wal", "-shm"] {
            let side = PathBuf::from(format!("{}{suffix}", original.display()));
            if side.exists() {
                fs::remove_file(side)?;
            }
        }
        fs::rename(staged, original)?;
        sync_dir(original.parent().unwrap())?;
        #[cfg(test)]
        if original == core
            && FAIL_DURING_RESTORE
                .try_with(|enabled| *enabled)
                .unwrap_or(false)
        {
            return Err(invalid("test interruption during guarded restore"));
        }
    }
    let mut restored = open_locked(paths).await?;
    validate_source_schema(&mut restored, FENCED_VERSION).await?;
    check_drained(&mut restored).await?;
    visit_history(&mut restored, retention(&state.source_profile)?, false).await?;
    for member in restored {
        member.conn.close().await?;
    }
    // Check exact sibling bytes before the only publication that permits old
    // main. Copy the original core afresh: never patch its SQLite file bytes.
    for entry in &manifest.files {
        if entry.source != core
            && !entry.name.ends_with("-shm")
            && !entry.name.ends_with("-wal")
            && digest(&entry.source)? != entry.sha256
        {
            return Err(invalid("restored sibling bytes do not match backup"));
        }
    }
    let entry = manifest
        .files
        .iter()
        .find(|entry| entry.source == core)
        .unwrap();
    let final_core = &staged_paths[0].1;
    copy_sync(&dir.join(&entry.name), final_core)?;
    for suffix in ["-wal", "-shm"] {
        let side = PathBuf::from(format!("{}{suffix}", core.display()));
        if side.exists() {
            fs::remove_file(side)?;
        }
    }
    fs::rename(final_core, core)?;
    sync_dir(core.parent().unwrap())?;
    if digest(core)? != entry.sha256 {
        return Err(invalid("restored core bytes do not match backup"));
    }
    fs::remove_file(marker(core))?;
    let staged = marker(core).with_extension("json.next");
    if staged.exists() {
        fs::remove_file(staged)?;
    }
    sync_dir(core.parent().unwrap())?;
    println!("complete SQLite family restored; old fixed-main startup is again permitted");
    Ok(())
}
/// Called after ProductOwner and before ANY mutable Storage setup. Even failed
/// subsequent startup consumes rollback because it may have performed writes.
pub async fn activate_before_runtime(
    db_url: Option<&str>,
    target_profile: &str,
) -> std::result::Result<(), KernelError> {
    let url = crate::storage::database::DatabaseDriver::normalize_db_url_public(db_url);
    if !url.starts_with("sqlite:") {
        return Ok(());
    }
    let options = SqliteConnectOptions::from_str(&url)?;
    if options.get_filename() == Path::new(":memory:") {
        return Ok(());
    }
    let result = async {
        let requested = sqlite_core(&url)?;
        let core = if requested.exists() {
            requested.canonicalize()?
        } else {
            requested.clone()
        };
        let final_symlink = fs::symlink_metadata(&requested)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        let has_marker = |path: &Path| {
            marker(path).exists() || marker(path).with_extension("json.next").exists()
        };
        if final_symlink && (has_marker(&requested) || has_marker(&core)) {
            return Err(invalid(
                "cutover dataset cannot start through a final-component symlink alias; use its original database family path",
            ));
        }
        if let Some(mut state) = read_state(&core)? {
            if retention(target_profile)? < retention(&state.source_profile)? {
                return Err(invalid(
                    "target maintenance retention is shorter than source collision identity retention",
                ));
            }
            match state.phase.as_str() {
                "activated" => {
                    let paths = family(&core)?;
                    inspect_handles(&paths, true)?;
                    ensure_cutover_fence(&paths).await?;
                }
                "complete" => {
                    let paths = family(&core)?;
                    inspect_handles(&paths, true)?;
                    ensure_cutover_fence(&paths).await?;
                    state.phase = "activated".into();
                    save_state(&core, &state)?;
                }
                _ => {
                    return Err(invalid(
                        "offline cutover incomplete; explicit restore required before runtime",
                    ));
                }
            }
        }
        Ok::<(), Box<dyn Error>>(())
    }.await;
    result.map_err(|e| KernelError::Invalid(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    const CREATED: i64 = 1_792_000_000_000;
    async fn connect(path: &Path) -> SqliteConnection {
        SqliteConnection::connect_with(
            &SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true),
        )
        .await
        .unwrap()
    }
    async fn fixture(count: usize) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let core = temp.path().join("gateway.sqlite");
        let schema: BTreeMap<String, Vec<(String, String, String)>> =
            serde_json::from_str(SOURCE_SCHEMA).unwrap();
        for kind in ["core", "delivery", "dispatch", "runtime"] {
            let path = if kind == "core" {
                core.clone()
            } else {
                related(&core, kind)
            };
            let mut connection = connect(&path).await;
            for object in ["table", "index"] {
                for (ty, _, statement) in &schema[kind] {
                    if ty == object {
                        sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
                            .execute(&mut connection)
                            .await
                            .unwrap();
                    }
                }
            }
            if kind == "core" {
                sqlx::query("INSERT INTO pushgo_schema_meta VALUES('schema_version','2026-08-20-gateway-v12')").execute(&mut connection).await.unwrap();
                for d in crate::storage::database::migration::SCHEMA_MIGRATIONS {
                    sqlx::query(
                        "INSERT INTO pushgo_schema_migrations VALUES(?,?,?,?,1,1,0,1,NULL)",
                    )
                    .bind(d.id)
                    .bind(d.description)
                    .bind(d.checksum)
                    .bind(d.target_schema_version)
                    .execute(&mut connection)
                    .await
                    .unwrap();
                }
                for index in 0..count {
                    sqlx::query("INSERT INTO sender_submit_status(op_id,channel_id,model,entity_id,status,dispatch_status,accepted_at,updated_at,expires_at) VALUES(?,?,'message',?,'failed','not_attempted',?,?,?)").bind(format!("op-{index}")).bind([1u8;16].as_slice()).bind(format!("{index:032x}")).bind(CREATED+index as i64).bind(CREATED+index as i64+5).bind(CREATED+7*86_400_000).execute(&mut connection).await.unwrap();
                }
                sqlx::query("INSERT INTO sender_submit_status(op_id,channel_id,model,entity_id,status,dispatch_status,accepted_at,updated_at,expires_at) VALUES('event-op',?,'event','retained-event','failed','not_attempted',?,?,?)").bind([1u8;16].as_slice()).bind(CREATED).bind(CREATED+5).bind(CREATED+7*86_400_000).execute(&mut connection).await.unwrap();
                sqlx::query("INSERT INTO sender_submit_status(op_id,channel_id,model,entity_id,status,dispatch_status,accepted_at,updated_at,expires_at) VALUES('thing-op',?,'thing','retained-thing-entity','sent','provider_accepted',?,?,?)").bind([1u8;16].as_slice()).bind(CREATED).bind(CREATED+5).bind(CREATED+7*86_400_000).execute(&mut connection).await.unwrap();
                sqlx::query("INSERT INTO live_activity_tokens VALUES('activity-sentinel','synthetic-la',?,'ios',1,?,?,NULL)").bind([1u8;16].as_slice()).bind(CREATED).bind(CREATED+5).execute(&mut connection).await.unwrap();
                sqlx::query("INSERT INTO widget_push_subscriptions VALUES('synthetic-device','ios','synthetic-widget','kind','small',1,?,?)").bind(CREATED).bind(CREATED+5).execute(&mut connection).await.unwrap();
            } else {
                let key = match kind {
                    "delivery" => "runtime_delivery_migrated_from_core_v1",
                    "dispatch" => "dispatch_migrated_from_core_v1",
                    _ => "runtime_migrated_from_core_v1",
                };
                sqlx::query("INSERT INTO pushgo_sidecar_meta VALUES(?,'done')")
                    .bind(key)
                    .execute(&mut connection)
                    .await
                    .unwrap();
            }
            if kind == "dispatch" {
                let channel =
                    crate::util::encode_crockford_base32_128(&[1u8; 16]).to_ascii_lowercase();
                for index in 0..count {
                    let thing = if index % 2 == 0 {
                        "-"
                    } else {
                        "retained-thing"
                    };
                    sqlx::query("INSERT INTO semantic_id_registry(dedupe_key,semantic_id,created_at,updated_at) VALUES(?,?,?,?)").bind(format!("semantic:{channel}:message:{thing}:op-{index}")).bind(format!("{index:032x}")).bind(CREATED+index as i64).bind(CREATED+index as i64).execute(&mut connection).await.unwrap();
                    let id = format!("{:032x}", index + 1000);
                    sqlx::query("INSERT INTO dispatch_delivery_dedupe VALUES(?,?,'sent',?,?,NULL)")
                        .bind(format!("delivery:{id}"))
                        .bind(id)
                        .bind(CREATED)
                        .bind(CREATED)
                        .execute(&mut connection)
                        .await
                        .unwrap();
                }
                sqlx::query("INSERT INTO semantic_id_registry(dedupe_key,semantic_id,created_at,updated_at) VALUES(?,'retained-event',?,?)").bind(format!("semantic:{channel}:event:-:event-op")).bind(CREATED).bind(CREATED).execute(&mut connection).await.unwrap();
                sqlx::query("INSERT INTO dispatch_op_dedupe(dedupe_key,delivery_id,state,created_at,updated_at) VALUES(?,'event-delivery','sent',?,?)").bind(format!("op:{channel}:event:retained-event:event-op")).bind(CREATED).bind(CREATED).execute(&mut connection).await.unwrap();
                sqlx::query("INSERT INTO semantic_id_registry(dedupe_key,semantic_id,created_at,updated_at) VALUES(?,'retained-thing-entity',?,?)").bind(format!("semantic:{channel}:thing:-:thing-op")).bind(CREATED).bind(CREATED).execute(&mut connection).await.unwrap();
                sqlx::query("INSERT INTO dispatch_op_dedupe(dedupe_key,delivery_id,state,created_at,updated_at) VALUES(?,'thing-delivery','sent',?,?)").bind(format!("op:{channel}:thing:retained-thing-entity:thing-op")).bind(CREATED).bind(CREATED).execute(&mut connection).await.unwrap();
            }
            connection.close().await.unwrap();
        }
        let backup = temp.path().join("backup");
        (temp, core, backup)
    }
    async fn exec(path: &Path, sql: &str) {
        let mut c = connect(path).await;
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .execute(&mut c)
            .await
            .unwrap();
        c.close().await.unwrap();
    }
    async fn shared_snapshot(core: &Path) -> Vec<(String, Vec<String>)> {
        let mut result = Vec::new();
        for (path, table, filter) in [
            (
                core.to_path_buf(),
                "sender_submit_status",
                "model IN ('event','thing')",
            ),
            (core.to_path_buf(), "live_activity_tokens", "1"),
            (core.to_path_buf(), "widget_push_subscriptions", "1"),
            (
                related(core, "dispatch"),
                "semantic_id_registry",
                "dedupe_key NOT LIKE 'semantic:%:message:%'",
            ),
            (related(core, "dispatch"), "dispatch_op_dedupe", "1"),
        ] {
            let mut c = connect(&path).await;
            let columns = sqlx::query(sqlx::AssertSqlSafe(format!("PRAGMA table_info({table})")))
                .fetch_all(&mut c)
                .await
                .unwrap();
            let projection = columns
                .iter()
                .map(|column| format!("quote({})", column.get::<String, _>("name")))
                .collect::<Vec<_>>()
                .join(",");
            let rows=sqlx::query_scalar::<_,String>(sqlx::AssertSqlSafe(format!("SELECT json_array({projection}) AS row_value FROM {table} WHERE {filter} ORDER BY row_value LIMIT 256"))).fetch_all(&mut c).await.unwrap();
            result.push((table.into(), rows));
            c.close().await.unwrap();
        }
        result
    }
    async fn schema_version(core: &Path) -> String {
        let mut conn = connect(core).await;
        let version = sqlx::query_scalar(
            "SELECT meta_value FROM pushgo_schema_meta WHERE meta_key='schema_version'",
        )
        .fetch_one(&mut conn)
        .await
        .unwrap();
        conn.close().await.unwrap();
        version
    }
    fn assert_restored_bytes(core: &Path, backup: &Path) {
        let manifest: Backup =
            serde_json::from_slice(&fs::read(backup.join("manifest.json")).unwrap()).unwrap();
        for entry in manifest.files {
            if !entry.name.ends_with("-wal") && !entry.name.ends_with("-shm") {
                assert_eq!(
                    digest(&entry.source).unwrap(),
                    entry.sha256,
                    "{}",
                    entry.name
                );
            }
        }
        assert!(!marker(core).exists());
    }
    #[tokio::test]
    async fn version_fence_commits_before_business_conversion_and_restore_publishes_original_bytes_last()
     {
        let (_temp, core, backup) = fixture(3).await;
        let error = FAIL_AFTER_VERSION_FENCE
            .scope(true, run_owned(&core, "run", &backup, Some("small")))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("before business conversion"));
        assert_eq!(schema_version(&core).await, FENCED_VERSION);
        assert_eq!(read_state(&core).unwrap().unwrap().phase, "preparing");
        assert!(
            activate_before_runtime(Some(&format!("sqlite://{}", core.display())), "small")
                .await
                .is_err()
        );
        let mut conn = connect(&core).await;
        assert!(!exists(&mut conn, "ordinary_messages").await.unwrap());
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM sender_submit_status WHERE model='message'"
            )
            .fetch_one(&mut conn)
            .await
            .unwrap(),
            3
        );
        conn.close().await.unwrap();
        let error = FAIL_DURING_RESTORE
            .scope(true, run_owned(&core, "restore", &backup, None))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("during guarded restore"));
        assert_eq!(schema_version(&core).await, FENCED_VERSION);
        assert_eq!(read_state(&core).unwrap().unwrap().phase, "restoring");
        run_owned(&core, "restore", &backup, None).await.unwrap();
        assert_restored_bytes(&core, &backup);
        assert_eq!(schema_version(&core).await, SOURCE_VERSION);
    }
    #[tokio::test]
    async fn legacy_complete_restore_fences_before_closing_original_family() {
        let (_temp, core, backup) = fixture(1).await;
        run_owned(&core, "run", &backup, Some("small"))
            .await
            .unwrap();
        // Explicit test injection of the real C15/C16 pre-fence header shape.
        exec(&core, "UPDATE pushgo_schema_meta SET meta_value='2026-08-20-gateway-v12' WHERE meta_key='schema_version'").await;
        assert_eq!(schema_version(&core).await, SOURCE_VERSION);
        let error = FAIL_BEFORE_RESTORE_STAGE
            .scope(true, run_owned(&core, "restore", &backup, None))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("before restore staging"));
        assert_eq!(read_state(&core).unwrap().unwrap().phase, "restoring");
        assert_eq!(schema_version(&core).await, FENCED_VERSION);
        run_owned(&core, "restore", &backup, None).await.unwrap();
        assert_restored_bytes(&core, &backup);
        assert_eq!(schema_version(&core).await, SOURCE_VERSION);
    }
    #[tokio::test]
    async fn preparing_pristine_v12_intent_restores_but_never_activates() {
        let (_temp, core, backup_dir) = fixture(1).await;
        let paths = family(&core).unwrap();
        let members = open_locked(&paths).await.unwrap();
        backup(&members, &backup_dir, "small").unwrap();
        for member in members {
            member.conn.close().await.unwrap();
        }
        let state = State {
            format: FORMAT.into(),
            phase: "preparing".into(),
            backup: backup_dir.canonicalize().unwrap(),
            source_profile: "small".into(),
        };
        save_state(&core, &state).unwrap();
        assert_eq!(schema_version(&core).await, SOURCE_VERSION);
        let url = format!("sqlite://{}", core.display());
        assert!(activate_before_runtime(Some(&url), "small").await.is_err());
        exec(&core, "CREATE TABLE not_pristine(value TEXT)").await;
        let error = run_owned(&core, "restore", &backup_dir, None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("schema"), "{error}");
        assert_eq!(read_state(&core).unwrap().unwrap().phase, "preparing");
        exec(&core, "DROP TABLE not_pristine").await;
        // A torn prepared-state write must fall back to the stable intent.
        fs::write(marker(&core).with_extension("json.next"), b"{\"format\":").unwrap();
        run_owned(&core, "restore", &backup_dir, None)
            .await
            .unwrap();
        assert_restored_bytes(&core, &backup_dir);
        assert_eq!(schema_version(&core).await, SOURCE_VERSION);
    }
    #[tokio::test]
    async fn complete_and_activated_legacy_markers_require_canonical_identity_before_version_upgrade()
     {
        let (_temp, core, backup) = fixture(3).await;
        run_owned(&core, "run", &backup, Some("small"))
            .await
            .unwrap();
        let url = format!("sqlite://{}", core.display());
        assert_eq!(schema_version(&core).await, FENCED_VERSION);
        // C15/C16 complete datasets used the same marker format and v12 header.
        exec(&core, "UPDATE pushgo_schema_meta SET meta_value='2026-08-20-gateway-v12' WHERE meta_key='schema_version'").await;
        activate_before_runtime(Some(&url), "small").await.unwrap();
        assert_eq!(schema_version(&core).await, FENCED_VERSION);
        activate_before_runtime(Some(&url), "small").await.unwrap();
        assert_eq!(schema_version(&core).await, FENCED_VERSION);
        exec(&core, "DROP TABLE ordinary_messages").await;
        assert!(activate_before_runtime(Some(&url), "small").await.is_err());
        let (_temp, core, backup) = fixture(0).await;
        let state = State {
            format: FORMAT.into(),
            phase: "complete".into(),
            backup,
            source_profile: "small".into(),
        };
        save_state(&core, &state).unwrap();
        assert!(
            activate_before_runtime(Some(&format!("sqlite://{}", core.display())), "small")
                .await
                .is_err()
        );
        assert_eq!(schema_version(&core).await, SOURCE_VERSION);
    }
    #[tokio::test]
    async fn paged_identity_cutover_preserves_scope_times_shared_history_and_restores_all_four_files()
     {
        let (_temp, core, backup) = fixture(260).await;
        let shared_before = shared_snapshot(&core).await;
        run_owned(&core, "plan", &backup, Some("small"))
            .await
            .unwrap();
        assert!(!backup.exists());
        assert!(!marker(&core).exists());
        run_owned(&core, "run", &backup, Some("small"))
            .await
            .unwrap();
        assert_eq!(shared_snapshot(&core).await, shared_before);
        run_owned(&core, "run", &backup, Some("small"))
            .await
            .unwrap();
        let mut c = connect(&core).await;
        let rows = sqlx::query("SELECT * FROM ordinary_messages ORDER BY accepted_at")
            .fetch_all(&mut c)
            .await
            .unwrap();
        assert_eq!(rows.len(), 260);
        for (index, row) in rows.iter().enumerate() {
            assert_eq!(row.get::<String, _>("message_id"), format!("{index:032x}"));
            assert_eq!(row.get::<String, _>("op_id"), format!("op-{index}"));
            assert_eq!(row.get::<i64, _>("accepted_at"), CREATED + index as i64);
            assert_eq!(
                row.get::<i64, _>("dedupe_until"),
                CREATED + index as i64 + 7 * 86_400_000
            );
            assert_eq!(
                row.get::<Option<String>, _>("thing_id"),
                (index % 2 != 0).then(|| "retained-thing".into())
            );
            assert!(row.get::<Option<String>, _>("delivery_id").is_none());
            assert!(row.get::<Option<String>, _>("fingerprint").is_none());
            assert!(row.get::<Option<i64>, _>("expires_at").is_none());
            assert_eq!(row.get::<i64, _>("payload_bytes"), 0);
            assert_eq!(row.get::<i64, _>("pending_targets"), 0);
        }
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM sender_submit_status WHERE model='event'"
            )
            .fetch_one(&mut c)
            .await
            .unwrap(),
            1
        );
        c.close().await.unwrap();
        let manifest: Backup =
            serde_json::from_slice(&fs::read(backup.join("manifest.json")).unwrap()).unwrap();
        for name in [
            "gateway.sqlite",
            "gateway.delivery.sqlite",
            "gateway.dispatch.sqlite",
            "gateway.runtime.sqlite",
        ] {
            assert!(manifest.files.iter().any(|f| f.name == name));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
                0o700
            );
            for entry in fs::read_dir(&backup).unwrap() {
                assert_eq!(
                    entry.unwrap().metadata().unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
            assert_eq!(
                fs::metadata(marker(&core)).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        run_owned(&core, "restore", &backup, None).await.unwrap();
        assert_restored_bytes(&core, &backup);
        assert_eq!(shared_snapshot(&core).await, shared_before);
        let mut c = connect(&core).await;
        assert!(!exists(&mut c, "ordinary_messages").await.unwrap());
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM sender_submit_status WHERE model='message'"
            )
            .fetch_one(&mut c)
            .await
            .unwrap(),
            260
        );
        c.close().await.unwrap();
        assert!(!marker(&core).exists());
    }
    #[tokio::test]
    async fn rejects_orphan_status_and_retained_ack_responsibilities_without_backup() {
        let (_temp, core, backup) = fixture(1).await;
        exec(
            &related(&core, "dispatch"),
            "DELETE FROM semantic_id_registry WHERE semantic_id='00000000000000000000000000000000'",
        )
        .await;
        assert!(
            run_owned(&core, "run", &backup, Some("small"))
                .await
                .unwrap_err()
                .to_string()
                .contains("orphan")
        );
        assert!(!backup.exists());
        let (_temp, core, backup) = fixture(1).await;
        exec(&related(&core,"delivery"),"INSERT INTO private_outbox(device_id,delivery_id,status,next_attempt_at,updated_at,acked_at) VALUES(x'01','orphan','acked',1,1,1)").await;
        assert!(
            run_owned(&core, "run", &backup, Some("small"))
                .await
                .unwrap_err()
                .to_string()
                .contains("target-bearing")
        );
        assert!(!backup.exists());
    }
    #[tokio::test]
    async fn rejects_collision_identity_corruption_and_unknown_schema_or_migrations() {
        let (_temp, core, backup) = fixture(1).await;
        exec(
            &related(&core, "dispatch"),
            "UPDATE dispatch_delivery_dedupe SET dedupe_key='delivery:wrong'",
        )
        .await;
        assert!(
            run_owned(&core, "plan", &backup, Some("small"))
                .await
                .unwrap_err()
                .to_string()
                .contains("collision")
        );
        let (_temp, core, backup) = fixture(1).await;
        exec(
            &core,
            "UPDATE pushgo_schema_migrations SET checksum='wrong'",
        )
        .await;
        assert!(
            run_owned(&core, "plan", &backup, Some("small"))
                .await
                .unwrap_err()
                .to_string()
                .contains("checksum")
        );
        let (_temp, core, backup) = fixture(1).await;
        exec(&core, "CREATE TABLE unexpected(value TEXT)").await;
        assert!(
            run_owned(&core, "plan", &backup, Some("small"))
                .await
                .unwrap_err()
                .to_string()
                .contains("schema")
        );
    }
    #[tokio::test]
    async fn requires_source_profile_and_blocks_restore_after_activation_intent() {
        let (_temp, core, backup) = fixture(1).await;
        assert!(run_owned(&core, "run", &backup, None).await.is_err());
        run_owned(&core, "run", &backup, Some("public"))
            .await
            .unwrap();
        let url = format!("sqlite://{}", core.display());
        assert!(activate_before_runtime(Some(&url), "small").await.is_err());
        assert_eq!(read_state(&core).unwrap().unwrap().phase, "complete");
        activate_before_runtime(Some(&url), "public").await.unwrap();
        activate_before_runtime(Some(&url), "public").await.unwrap();
        assert!(
            run_owned(&core, "restore", &backup, None)
                .await
                .unwrap_err()
                .to_string()
                .contains("prohibited")
        );
    }
    #[tokio::test]
    async fn incomplete_and_corrupt_backup_fail_closed_then_restore_can_retry() {
        let (_temp, core, backup) = fixture(1).await;
        run_owned(&core, "run", &backup, Some("small"))
            .await
            .unwrap();
        let mut state = read_state(&core).unwrap().unwrap();
        state.phase = "prepared".into();
        save_state(&core, &state).unwrap();
        let url = format!("sqlite://{}", core.display());
        assert!(activate_before_runtime(Some(&url), "small").await.is_err());
        let file = backup.join("gateway.dispatch.sqlite");
        let bytes = fs::read(&file).unwrap();
        fs::write(&file, b"damaged").unwrap();
        assert!(
            run_owned(&core, "restore", &backup, None)
                .await
                .unwrap_err()
                .to_string()
                .contains("hash")
        );
        fs::write(&file, bytes).unwrap();
        state.phase = "restoring".into();
        save_state(&core, &state).unwrap();
        exec(&core, "CREATE TABLE partial_restore(value TEXT)").await;
        run_owned(&core, "restore", &backup, None).await.unwrap();
        let mut c = connect(&core).await;
        assert!(!exists(&mut c, "partial_restore").await.unwrap());
        c.close().await.unwrap();
    }
    #[tokio::test]
    async fn unchanged_dataset_with_missing_parent_does_not_create_any_files() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("absent").join("gateway.sqlite");
        activate_before_runtime(Some(&format!("sqlite://{}", path.display())), "small")
            .await
            .unwrap();
        assert!(!path.parent().unwrap().exists());
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn final_symlink_cannot_bypass_complete_or_staged_prepared_cutover() {
        let (_temp, core, backup) = fixture(1).await;
        let alias = core.parent().unwrap().join("alias.sqlite");
        std::os::unix::fs::symlink(&core, &alias).unwrap();
        let url = format!("sqlite://{}", alias.display());
        // Established non-cutover alias behavior remains unchanged.
        activate_before_runtime(Some(&url), "small").await.unwrap();
        assert!(!marker(&core).exists());
        assert!(!marker(&alias).exists());
        let mut state = State {
            format: FORMAT.into(),
            phase: "complete".into(),
            backup,
            source_profile: "small".into(),
        };
        save_state(&core, &state).unwrap();
        let before = fs::read(marker(&core)).unwrap();
        assert!(
            activate_before_runtime(Some(&url), "small")
                .await
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );
        assert_eq!(fs::read(marker(&core)).unwrap(), before);
        assert_eq!(read_state(&core).unwrap().unwrap().phase, "complete");
        state.phase = "prepared".into();
        let staged = marker(&core).with_extension("json.next");
        json_new(&staged, &state).unwrap();
        let staged_before = fs::read(&staged).unwrap();
        assert!(
            activate_before_runtime(Some(&url), "small")
                .await
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );
        assert_eq!(fs::read(marker(&core)).unwrap(), before);
        assert_eq!(fs::read(&staged).unwrap(), staged_before);
        assert_eq!(read_state(&core).unwrap().unwrap().phase, "prepared");
        assert!(!marker(&alias).exists());
    }
    #[tokio::test]
    async fn schema_literal_case_change_is_rejected_instead_of_normalized() {
        let (_temp, core, backup) = fixture(1).await;
        let mut c = connect(&core).await;
        sqlx::query("PRAGMA writable_schema=ON")
            .execute(&mut c)
            .await
            .unwrap();
        sqlx::query("UPDATE sqlite_master SET sql=replace(sql,'''active''','''Active''') WHERE name='channel_subscriptions'").execute(&mut c).await.unwrap();
        c.close().await.unwrap();
        assert!(
            run_owned(&core, "plan", &backup, Some("small"))
                .await
                .unwrap_err()
                .to_string()
                .contains("schema")
        );
        assert!(!backup.exists());
        assert!(!marker(&core).exists());
    }
    #[tokio::test]
    async fn preserves_acceptance_clock_before_semantic_reservation_and_memory_runtime_behavior() {
        activate_before_runtime(Some("sqlite::memory:"), "small")
            .await
            .unwrap();
        assert!(
            run("sqlite::memory:", "run", Path::new("unused"), Some("small"))
                .await
                .is_err()
        );
        let (_temp, core, backup) = fixture(1).await;
        exec(&core,&format!("UPDATE sender_submit_status SET accepted_at={},expires_at={} WHERE model='message'",CREATED-5,CREATED-5+7*86_400_000)).await;
        run_owned(&core, "run", &backup, Some("small"))
            .await
            .unwrap();
        let mut c = connect(&core).await;
        let row = sqlx::query("SELECT accepted_at,dedupe_until FROM ordinary_messages")
            .fetch_one(&mut c)
            .await
            .unwrap();
        assert_eq!(row.get::<i64, _>("accepted_at"), CREATED - 5);
        assert_eq!(row.get::<i64, _>("dedupe_until"), CREATED + 7 * 86_400_000);
        c.close().await.unwrap();
    }
    #[tokio::test]
    async fn rejects_every_retained_target_responsibility_and_unsupported_sender_state() {
        for state in ["sent", "partially_failed", "pending"] {
            let (_temp, core, backup) = fixture(1).await;
            exec(
                &core,
                &format!("UPDATE sender_submit_status SET status='{state}' WHERE model='message'"),
            )
            .await;
            assert!(
                run_owned(&core, "plan", &backup, Some("small"))
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("zero-target"),
                "sender state {state}"
            );
            assert!(!backup.exists());
        }
        for location in ["core", "dispatch"] {
            for state in [
                "preparing",
                "pending",
                "retry_wait",
                "leased",
                "provider_accepted",
                "permanent_failed",
                "unknown",
            ] {
                let (_temp, core, backup) = fixture(1).await;
                let path = if location == "core" {
                    core.clone()
                } else {
                    related(&core, location)
                };
                exec(&path,&format!("INSERT INTO provider_dispatch_outbox(job_id,provider,delivery_id,device_key,payload_blob,state,next_attempt_at,accepted_at,expires_at,updated_at) VALUES('orphan','APNS','delivery','device',x'7b7d','{state}',1,1,2,1)")).await;
                assert!(
                    run_owned(&core, "plan", &backup, Some("small"))
                        .await
                        .unwrap_err()
                        .to_string()
                        .contains("target-bearing"),
                    "provider {location} {state}"
                );
                assert!(!backup.exists());
            }
            let (_temp, core, backup) = fixture(1).await;
            let path = if location == "core" {
                core.clone()
            } else {
                related(&core, location)
            };
            exec(&path,"INSERT INTO dispatch_submission(dedupe_key,delivery_id,op_id,payload_version,payload_blob,accepted_at,expires_at) VALUES('orphan','delivery','op',1,x'7b7d',1,2)").await;
            assert!(
                run_owned(&core, "plan", &backup, Some("small"))
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("target-bearing")
            );
        }
        for location in ["core", "delivery"] {
            for state in ["pending", "claimed", "sent", "acked"] {
                let (_temp, core, backup) = fixture(1).await;
                let path = if location == "core" {
                    core.clone()
                } else {
                    related(&core, location)
                };
                exec(&path,&format!("INSERT INTO private_outbox(device_id,delivery_id,status,next_attempt_at,updated_at) VALUES(x'01','orphan','{state}',1,1)")).await;
                assert!(
                    run_owned(&core, "plan", &backup, Some("small"))
                        .await
                        .unwrap_err()
                        .to_string()
                        .contains("target-bearing"),
                    "private {location} {state}"
                );
            }
            for sql in [
                "INSERT INTO private_payloads VALUES('orphan',x'00',1,1,2,1,1)",
                "INSERT INTO provider_pull_queue VALUES(x'01','orphan',x'00',1,1,2,'ios','synthetic-provider',1,1)",
            ] {
                let (_temp, core, backup) = fixture(1).await;
                let path = if location == "core" {
                    core.clone()
                } else {
                    related(&core, location)
                };
                exec(&path, sql).await;
                assert!(
                    run_owned(&core, "plan", &backup, Some("small"))
                        .await
                        .unwrap_err()
                        .to_string()
                        .contains("target-bearing"),
                    "orphan payload {location}"
                );
                assert!(!backup.exists());
            }
        }
    }
    #[tokio::test]
    async fn real_partial_core_commit_rejects_activation_then_full_restore_and_repeat_preserve_260_identities()
     {
        let (_temp, core, backup) = fixture(260).await;
        let shared_before = shared_snapshot(&core).await;
        let error = FAIL_AFTER_CORE_COMMIT
            .scope(true, run_owned(&core, "run", &backup, Some("small")))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("after core COMMIT"));
        assert_eq!(read_state(&core).unwrap().unwrap().phase, "prepared");
        assert_eq!(schema_version(&core).await, FENCED_VERSION);
        let url = format!("sqlite://{}", core.display());
        assert!(activate_before_runtime(Some(&url), "small").await.is_err());
        let mut c = connect(&core).await;
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM ordinary_messages")
                .fetch_one(&mut c)
                .await
                .unwrap(),
            260
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM sender_submit_status WHERE model='message'"
            )
            .fetch_one(&mut c)
            .await
            .unwrap(),
            0
        );
        c.close().await.unwrap();
        let mut c = connect(&related(&core, "dispatch")).await;
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM semantic_id_registry WHERE dedupe_key LIKE 'semantic:%:message:%'").fetch_one(&mut c).await.unwrap(),260);
        c.close().await.unwrap();
        run_owned(&core, "restore", &backup, None).await.unwrap();
        assert_restored_bytes(&core, &backup);
        assert_eq!(shared_snapshot(&core).await, shared_before);
        let second_backup = core.parent().unwrap().join("after-restored-backup");
        run_owned(&core, "run", &second_backup, Some("small"))
            .await
            .unwrap();
        run_owned(&core, "run", &second_backup, Some("small"))
            .await
            .unwrap();
        assert_eq!(shared_snapshot(&core).await, shared_before);
        let mut c = connect(&core).await;
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM ordinary_messages")
                .fetch_one(&mut c)
                .await
                .unwrap(),
            260
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(DISTINCT op_id) FROM ordinary_messages")
                .fetch_one(&mut c)
                .await
                .unwrap(),
            260
        );
        c.close().await.unwrap();
    }
    #[tokio::test]
    async fn explicit_restore_recovers_torn_stage_but_never_stable_activation() {
        for stable_phase in ["complete", "activated"] {
            let (_temp, core, backup) = fixture(1).await;
            run_owned(&core, "run", &backup, Some("small"))
                .await
                .unwrap();
            let mut state = read_state(&core).unwrap().unwrap();
            state.phase = stable_phase.into();
            save_state(&core, &state).unwrap();
            fs::write(marker(&core).with_extension("json.next"), b"").unwrap();
            let url = format!("sqlite://{}", core.display());
            assert!(activate_before_runtime(Some(&url), "small").await.is_err());
            if stable_phase == "activated" {
                assert!(
                    run_owned(&core, "restore", &backup, None)
                        .await
                        .unwrap_err()
                        .to_string()
                        .contains("activated")
                );
                assert!(marker(&core).exists());
            } else {
                run_owned(&core, "restore", &backup, None).await.unwrap();
                assert!(!marker(&core).exists());
            }
        }
        // Interrupt the initial preparing write: the complete backup exists but
        // no main DB conversion was committed, and no stable state exists yet.
        let (_temp, core, backup_dir) = fixture(1).await;
        let paths = family(&core).unwrap();
        let members = open_locked(&paths).await.unwrap();
        backup(&members, &backup_dir, "small").unwrap();
        for member in members {
            member.conn.close().await.unwrap();
        }
        fs::write(marker(&core).with_extension("json.next"), b"{\"format\":").unwrap();
        run_owned(&core, "restore", &backup_dir, None)
            .await
            .unwrap();
        assert!(!marker(&core).exists());
        let mut c = connect(&core).await;
        assert!(!exists(&mut c, "ordinary_messages").await.unwrap());
        c.close().await.unwrap();
    }
}
