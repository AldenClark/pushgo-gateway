//! Fixed-main dfb6b7c/v12 MySQL offline history conversion only.
//! Operators must stop old main: its processes do not honor ProductOwner.
//! Session inspection and table locks are admission checks, not an old-binary
//! restart fence. No connection here is pooled or automatically reconnected.
use super::{
    owner::ProductOwner,
    store::{Health, KernelError},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Connection, MySqlConnection, Row};
use std::{
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
const FORMAT: &str = "ordinary-mysql-cutover-dfb6b7c-v1";
const CATALOG: &str = include_str!("mysql_cutover/catalog.sql");
const SOURCE: &str = include_str!("mysql_cutover/source_schema.json");
const MARKER: &str = "pushgo_ordinary_cutover";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    dataset: String,
    database: String,
    source_profile: String,
    sha256: String,
    histories: u64,
}
struct State {
    phase: String,
    backup: PathBuf,
    profile: String,
    sha256: String,
    dataset: String,
}
fn invalid(s: &str) -> Box<dyn Error> {
    Box::new(KernelError::Invalid(s.into()))
}
fn retention(profile: &str) -> Result<i64> {
    match profile {
        "small" => Ok(7 * 86_400_000),
        "public" => Ok(30 * 86_400_000),
        _ => Err(invalid(
            "explicit fixed-main source profile small|public required",
        )),
    }
}
fn normalized(url: &str) -> Result<String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| invalid("invalid MySQL URL"))?;
    if !scheme.eq_ignore_ascii_case("mysql") {
        return Err(invalid("MySQL URL required"));
    }
    Ok(format!("mysql://{rest}"))
}

fn scope(key: &str, prefix: &str) -> Result<(String, String, Option<String>, String)> {
    let p: Vec<_> = key.splitn(5, ':').collect();
    if p.len() != 5
        || p[0] != prefix
        || !matches!(p[2], "message" | "event" | "thing")
        || p.iter().any(|p| p.is_empty())
    {
        return Err(invalid("unknown or ambiguous source dedupe scope"));
    }
    let channel = crate::util::decode_crockford_base32_128(p[1])
        .map_err(|_| invalid("invalid source channel scope"))?;
    if p[1] != crate::util::encode_crockford_base32_128(&channel).to_ascii_lowercase() {
        return Err(invalid("noncanonical source channel scope"));
    }
    crate::value::OpId::parse(p[4]).map_err(|_| invalid("invalid source operation scope"))?;
    Ok((
        crate::util::encode_lower_hex_128(&channel),
        p[2].into(),
        (p[3] != "-").then(|| p[3].into()),
        p[4].into(),
    ))
}
async fn drained(c: &mut MySqlConnection) -> Result<()> {
    for table in [
        "semantic_id_registry",
        "dispatch_delivery_dedupe",
        "dispatch_op_dedupe",
    ] {
        if sqlx::query_scalar::<_, i64>(&format!(
            "SELECT EXISTS(SELECT 1 FROM {table} WHERE dedupe_key IS NULL OR dedupe_key='')"
        ))
        .fetch_one(&mut *c)
        .await?
            != 0
        {
            return Err(invalid("empty source primary identity"));
        }
    }
    for table in [
        "dispatch_submission",
        "provider_dispatch_outbox",
        "private_payloads",
        "private_outbox",
        "provider_pull_queue",
    ] {
        if sqlx::query_scalar::<_, i64>(&format!("SELECT EXISTS(SELECT 1 FROM {table})"))
            .fetch_one(&mut *c)
            .await?
            != 0
        {
            return Err(invalid(
                "all target-bearing tables must be empty across every model, including terminal/ACK rows",
            ));
        }
    }
    let mut cursor = String::new();
    loop {
        let rows=sqlx::query("SELECT dedupe_key,delivery_id,state FROM dispatch_delivery_dedupe WHERE dedupe_key>? ORDER BY dedupe_key LIMIT 256").bind(&cursor).fetch_all(&mut *c).await?;
        if rows.is_empty() {
            break;
        }
        for r in rows {
            cursor = r.get_unchecked("dedupe_key");
            let id: String = r.get_unchecked("delivery_id");
            if cursor != format!("delivery:{id}")
                || crate::util::decode_lower_hex_128(&id).is_err()
                || id != id.to_ascii_lowercase()
                || r.get_unchecked::<String, _>("state") != "sent"
            {
                return Err(invalid("invalid retained delivery collision identity"));
            }
        }
    }
    cursor.clear();
    loop {
        let rows=sqlx::query("SELECT dedupe_key,state,provider_run_token,provider_owner,provider_lease_until FROM dispatch_op_dedupe WHERE dedupe_key>? ORDER BY dedupe_key LIMIT 256").bind(&cursor).fetch_all(&mut *c).await?;
        if rows.is_empty() {
            break;
        }
        for r in rows {
            cursor = r.get_unchecked("dedupe_key");
            if scope(&cursor, "op")?.1 == "message"
                || r.get_unchecked::<String, _>("state") != "sent"
                || r.get_unchecked::<Option<String>, _>("provider_run_token")
                    .is_some()
                || r.get_unchecked::<Option<String>, _>("provider_owner")
                    .is_some()
                || r.get::<Option<i64>, _>("provider_lease_until").is_some()
            {
                return Err(invalid(
                    "ordinary/unresolved op responsibility outside offline subset",
                ));
            }
        }
    }
    Ok(())
}
/// MySQL InnoDB temporary indexes reside on disk; every fetched batch is <=256.
async fn history(c: &mut MySqlConnection, retention: i64, convert: bool) -> Result<u64> {
    sqlx::query("CREATE TEMPORARY TABLE cutover_status(op_id VARCHAR(128) COLLATE utf8mb4_bin PRIMARY KEY,op_fold VARBINARY(512) NOT NULL UNIQUE,entity_id VARBINARY(512) NOT NULL UNIQUE,channel CHAR(32) NOT NULL,status VARCHAR(32) NOT NULL,dispatch_status VARCHAR(64),provider_run_token VARCHAR(64),accepted_at BIGINT NOT NULL,updated_at BIGINT NOT NULL,expires_at BIGINT NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin").execute(&mut *c).await?;
    sqlx::query("INSERT INTO cutover_status SELECT op_id,lower(op_id),entity_id,lower(hex(channel_id)),status,dispatch_status,provider_run_token,accepted_at,updated_at,expires_at FROM sender_submit_status WHERE model='message'").execute(&mut *c).await.map_err(|_|invalid("duplicate ordinary op aliases/message identity"))?;
    sqlx::query("CREATE TEMPORARY TABLE cutover_seen(op VARBINARY(512) PRIMARY KEY,message VARBINARY(512) NOT NULL UNIQUE) ENGINE=InnoDB").execute(&mut *c).await?;
    let mut cursor = String::new();
    let mut count = 0u64;
    loop {
        let rows=sqlx::query("SELECT dedupe_key,semantic_id,source,created_at,updated_at,expires_at FROM semantic_id_registry WHERE dedupe_key>? ORDER BY dedupe_key LIMIT 256").bind(&cursor).fetch_all(&mut *c).await?;
        if rows.is_empty() {
            break;
        }
        for r in rows {
            cursor = r.get_unchecked("dedupe_key");
            let (channel, model, thing, op_key) = scope(&cursor, "semantic")?;
            if model != "message" {
                continue;
            }
            if thing.is_some() && op_key.contains(':') {
                return Err(invalid(
                    "ambiguous colon-separated thing/operation source scope",
                ));
            }
            let message: String = r.get_unchecked("semantic_id");
            crate::util::decode_lower_hex_128(&message)
                .map_err(|_| invalid("invalid original message identity"))?;
            let created: i64 = r.get("created_at");
            if r.get::<Option<i64>, _>("expires_at").is_some()
                || r.get_unchecked::<Option<String>, _>("source").is_some()
                || created <= 0
                || r.get::<i64, _>("updated_at") < created
            {
                return Err(invalid("unsupported semantic expiry/provenance/timestamp"));
            }
            let statuses = sqlx::query("SELECT * FROM cutover_status WHERE entity_id=? LIMIT 2")
                .bind(&message)
                .fetch_all(&mut *c)
                .await?;
            if statuses.len() != 1 {
                return Err(invalid(
                    "ordinary semantic/status relation missing or ambiguous",
                ));
            }
            let s = &statuses[0];
            let op: String = s.get_unchecked("op_id");
            if op.to_ascii_lowercase() != op_key
                || s.get_unchecked::<String, _>("channel") != channel
                || s.get_unchecked::<String, _>("status") != "failed"
                || s.get_unchecked::<Option<String>, _>("dispatch_status")
                    .as_deref()
                    != Some("not_attempted")
                || s.get_unchecked::<Option<String>, _>("provider_run_token")
                    .is_some()
            {
                return Err(invalid(
                    "ordinary history must be zero-target failed/not_attempted",
                ));
            }
            let accepted: i64 = s.get("accepted_at");
            let updated: i64 = s.get("updated_at");
            if accepted <= 0 || updated < accepted || s.get::<i64, _>("expires_at") <= accepted {
                return Err(invalid("invalid source acceptance timestamps"));
            }
            sqlx::query("INSERT INTO cutover_seen VALUES(?,?)")
                .bind(op.to_ascii_lowercase())
                .bind(&message)
                .execute(&mut *c)
                .await
                .map_err(|_| invalid("source op/message collision across scopes"))?;
            let until = created
                .checked_add(retention)
                .ok_or_else(|| invalid("source retention overflow"))?;
            if convert {
                let ch = crate::util::encode_crockford_base32_128(
                    &crate::util::decode_lower_hex_128(&channel)
                        .map_err(|_| invalid("invalid channel identity"))?,
                );
                sqlx::query("INSERT INTO ordinary_messages(delivery_id,message_id,op_id,channel_id,thing_id,fingerprint,payload_blob,payload_bytes,accepted_at,expires_at,dedupe_until,status,updated_at,identity_state) VALUES(NULL,?,?,?,?,NULL,x'',0,?,NULL,?,'historical_unverifiable',?,'legacy_unverifiable')").bind(&message).bind(&op).bind(ch).bind(thing).bind(accepted).bind(until).bind(updated).execute(&mut *c).await?;
                sqlx::query("DELETE FROM semantic_id_registry WHERE dedupe_key=?")
                    .bind(&cursor)
                    .execute(&mut *c)
                    .await?;
            }
            count += 1;
        }
    }
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM cutover_status")
        .fetch_one(&mut *c)
        .await?;
    if n != count as i64 {
        return Err(invalid(
            "orphan ordinary sender status or semantic identity",
        ));
    }
    if convert {
        sqlx::query("DELETE FROM sender_submit_status WHERE model='message'")
            .execute(&mut *c)
            .await?;
    }
    sqlx::query("DROP TEMPORARY TABLE cutover_seen,cutover_status")
        .execute(c)
        .await?;
    Ok(count)
}

fn digest(path: &Path) -> Result<String> {
    regular(path)?;
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}
fn decode(s: &str) -> Result<String> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() {
                return Err(invalid("invalid MySQL URL encoding"));
            }
            let hex = std::str::from_utf8(&b[i + 1..i + 3])?;
            out.push(
                u8::from_str_radix(hex, 16).map_err(|_| invalid("invalid MySQL URL encoding"))?,
            );
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Ok(String::from_utf8(out)?)
}

fn regular(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_file() || m.file_type().is_symlink() {
        return Err(invalid("backup requires regular files"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.nlink() != 1 {
            return Err(invalid("hardlinked backup file"));
        }
    }
    Ok(())
}
fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}
fn new_file(path: &Path) -> Result<File> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    Ok(o.open(path)?)
}
fn manifest_write(dir: &Path, m: &Manifest) -> Result<()> {
    let mut f = new_file(&dir.join("manifest.json"))?;
    f.write_all(&serde_json::to_vec_pretty(m)?)?;
    f.sync_all()?;
    sync_dir(dir)
}
fn verify_backup(dir: &Path, s: &State, database: &str) -> Result<Manifest> {
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(invalid("invalid backup directory"));
    }
    regular(&dir.join("manifest.json"))?;
    if fs::metadata(dir.join("manifest.json"))?.len() > 65_536 {
        return Err(invalid("oversized native backup manifest"));
    }
    let m: Manifest = serde_json::from_slice(&fs::read(dir.join("manifest.json"))?)?;
    if m.format != FORMAT
        || m.dataset != s.dataset
        || m.database != database
        || m.source_profile != s.profile
        || m.sha256 != s.sha256
        || m.sha256 != digest(&dir.join("source.dump"))?
    {
        return Err(invalid("backup identity/profile/hash mismatch"));
    }
    Ok(m)
}
fn native(tool: &str, url: &str) -> Result<(Command, String)> {
    let u = reqwest::Url::parse(&normalized(url)?).map_err(|_| invalid("invalid MySQL URL"))?;
    let database = decode(u.path().trim_start_matches('/'))?;
    if database.is_empty() || database.contains('/') || database.starts_with('-') {
        return Err(invalid("dedicated named MySQL database required"));
    }
    let mut cmd = Command::new(tool);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("MYSQL_") {
            cmd.env_remove(key);
        }
    }
    // --no-defaults must be the first native option, so local option files
    // cannot change the server or database independently of the fixed session.
    cmd.arg("--no-defaults")
        .arg("--no-login-paths")
        .arg("--protocol=TCP")
        .arg(format!("--user={}", decode(u.username())?));
    for (k, v) in u.query_pairs() {
        if !matches!(k.as_ref(), "ssl-mode" | "sslmode")
            || !matches!(
                v.to_ascii_lowercase().as_str(),
                "disabled" | "preferred" | "required" | "verify_ca" | "verify_identity"
            )
        {
            return Err(invalid("unsupported MySQL native-tool URL option"));
        }
        cmd.arg(format!("--ssl-mode={}", v.to_ascii_uppercase()));
    }
    cmd.env(
        "MYSQL_HOST",
        u.host_str().ok_or_else(|| invalid("MySQL host required"))?,
    )
    .env("MYSQL_TCP_PORT", u.port().unwrap_or(3306).to_string())
    .env("MYSQL_PWD", decode(u.password().unwrap_or(""))?);
    cmd.stderr(Stdio::null());
    Ok((cmd, database))
}
async fn connect(url: &str) -> Result<MySqlConnection> {
    let mut c = MySqlConnection::connect(&normalized(url)?)
        .await
        .map_err(|_| invalid("MySQL cutover connection failed"))?;
    sqlx::query("SET SESSION lock_wait_timeout=3, innodb_lock_wait_timeout=3")
        .execute(&mut c)
        .await?;
    Ok(c)
}
async fn exists(c: &mut MySqlConnection, name: &str) -> Result<bool> {
    Ok(sqlx::query_scalar::<_,i64>("SELECT EXISTS(SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?)").bind(name).fetch_one(c).await?!=0)
}
async fn dataset(c: &mut MySqlConnection) -> Result<String> {
    metadata(c, "pushgo_product_owner", false).await?;
    Ok(sqlx::query_scalar("SELECT CAST(dataset_uuid AS CHAR CHARACTER SET utf8mb4) FROM pushgo_product_owner WHERE singleton=1").fetch_one(c).await?)
}
async fn owner_session(c: &mut MySqlConnection, require_owner: bool) -> Result<Option<u64>> {
    let owner: Option<u64> = if exists(c, "pushgo_product_owner").await? {
        let id = dataset(c).await?;
        sqlx::query_scalar("SELECT IS_USED_LOCK(?)")
            .bind(format!("pushgo-product-{id}"))
            .fetch_one(&mut *c)
            .await?
    } else {
        None
    };
    if require_owner && owner.is_none() {
        return Err(invalid("fixed MySQL owner session missing"));
    }
    Ok(owner)
}
/// A SELECT grant on processlist does not make other users' sessions visible.
/// Require an explicit global PROCESS grant for this offline administrative
/// operation; role-only grants are conservatively outside this narrow entry.
async fn process_visibility(c: &mut MySqlConnection) -> Result<()> {
    let account: String = sqlx::query_scalar("SELECT CURRENT_USER()")
        .fetch_one(&mut *c).await?;
    let parts: Vec<_> = account.split('@').collect();
    if parts.len() != 2 {
        return Err(invalid("cannot verify MySQL migration account privileges"));
    }
    let grantee = format!("'{}'@'{}'", parts[0].replace('\\', "\\\\").replace('\'', "\\'"), parts[1].replace('\\', "\\\\").replace('\'', "\\'"));
    let visible: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES WHERE GRANTEE=? AND PRIVILEGE_TYPE='PROCESS'")
        .bind(grantee).fetch_one(c).await?;
    if visible != 1 {
        return Err(invalid("offline MySQL cutover requires a directly verifiable global PROCESS grant to inspect all old clients"));
    }
    Ok(())
}
/// Read the actual named-lock owner; exclude only that exact connection ID.
/// Every client in this dedicated dataset must be administratively stopped.
async fn alone(c: &mut MySqlConnection, require_owner: bool) -> Result<()> {
    process_visibility(c).await?;
    let owner = owner_session(c, require_owner).await?;
    // The owner UUID table is validated above. The bootstrap lock may already
    // have been released; the actual product lock is the enduring authority.
    let unexpected:i64=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM performance_schema.processlist WHERE DB=DATABASE() AND ID<>CONNECTION_ID() AND (? IS NULL OR ID<>?))").bind(owner).bind(owner).fetch_one(c).await?;
    if unexpected != 0 {
        return Err(invalid(
            "stop and join every old/database client before MySQL cutover",
        ));
    }
    Ok(())
}
async fn metadata(c: &mut MySqlConnection, table: &str, marker: bool) -> Result<()> {
    let cols=sqlx::query("SELECT COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE,COLUMN_DEFAULT,EXTRA,CHARACTER_SET_NAME,COLLATION_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? ORDER BY ORDINAL_POSITION LIMIT 9").bind(table).fetch_all(&mut *c).await?;
    let expected: Vec<(&str, &str, Option<&str>, Option<&str>)> = if marker {
        vec![
            ("singleton", "tinyint", None, None),
            ("format", "varbinary(64)", None, None),
            ("phase", "varbinary(16)", None, None),
            ("backup", "text", Some("utf8mb4"), Some("utf8mb4_bin")),
            ("source_profile", "varbinary(16)", None, None),
            ("sha256", "varbinary(64)", None, None),
            ("dataset", "varbinary(32)", None, None),
        ]
    } else {
        vec![
            ("singleton", "tinyint", None, None),
            (
                "dataset_uuid",
                "varchar(32)",
                Some("ascii"),
                Some("ascii_bin"),
            ),
        ]
    };
    if cols.len() != expected.len()
        || cols
            .iter()
            .zip(expected)
            .any(|(r, (name, kind, charset, collation))| {
                r.get_unchecked::<String, _>("COLUMN_NAME") != name
                    || r.get_unchecked::<String, _>("COLUMN_TYPE") != kind
                    || r.get_unchecked::<String, _>("IS_NULLABLE") != "NO"
                    || r.get_unchecked::<Option<String>, _>("COLUMN_DEFAULT")
                        .is_some()
                    || !r.get_unchecked::<String, _>("EXTRA").is_empty()
                    || r.get_unchecked::<Option<String>, _>("CHARACTER_SET_NAME")
                        .as_deref()
                        != charset
                    || r.get_unchecked::<Option<String>, _>("COLLATION_NAME")
                        .as_deref()
                        != collation
            })
    {
        return Err(invalid("unsupported MySQL owner/cutover metadata columns"));
    }
    let checks=sqlx::query("SELECT c.CHECK_CLAUSE,t.CONSTRAINT_TYPE,t.ENFORCED FROM information_schema.TABLE_CONSTRAINTS t LEFT JOIN information_schema.CHECK_CONSTRAINTS c ON c.CONSTRAINT_SCHEMA=t.CONSTRAINT_SCHEMA AND c.CONSTRAINT_NAME=t.CONSTRAINT_NAME WHERE t.TABLE_SCHEMA=DATABASE() AND t.TABLE_NAME=? ORDER BY t.CONSTRAINT_TYPE LIMIT 4").bind(table).fetch_all(&mut *c).await?;
    let mut kinds = Vec::new();
    for r in &checks {
        let kind: String = r.get_unchecked("CONSTRAINT_TYPE");
        if r.get_unchecked::<String, _>("ENFORCED") != "YES" {
            return Err(invalid("unenforced metadata constraint"));
        }
        if kind == "CHECK" {
            let text: String = r.get_unchecked("CHECK_CLAUSE");
            if text
                .chars()
                .filter(|c| !matches!(c, ' ' | '\n' | '\r' | '\t' | '`' | '(' | ')'))
                .collect::<String>()
                != "singleton=1"
            {
                return Err(invalid("unknown metadata CHECK"));
            }
        }
        kinds.push(kind);
    }
    let expected = if marker {
        vec!["CHECK", "PRIMARY KEY"]
    } else {
        vec!["CHECK", "PRIMARY KEY", "UNIQUE"]
    };
    if kinds.iter().map(String::as_str).collect::<Vec<_>>() != expected {
        return Err(invalid("unknown metadata constraints"));
    }
    let keys=sqlx::query("SELECT INDEX_NAME,CAST(NON_UNIQUE AS SIGNED) AS NON_UNIQUE,CAST(SEQ_IN_INDEX AS SIGNED) AS SEQ_IN_INDEX,COLUMN_NAME,CAST(SUB_PART AS SIGNED) AS SUB_PART,EXPRESSION FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? ORDER BY BINARY INDEX_NAME,SEQ_IN_INDEX LIMIT 4").bind(table).fetch_all(&mut *c).await?;
    if keys.len() != if marker { 1 } else { 2 }
        || keys.iter().any(|r| {
            r.get::<i64, _>("NON_UNIQUE") != 0
                || r.get::<i64, _>("SEQ_IN_INDEX") != 1
                || r.get::<Option<i64>, _>("SUB_PART").is_some()
                || r.get_unchecked::<Option<String>, _>("EXPRESSION").is_some()
                || !matches!(
                    (
                        r.get_unchecked::<String, _>("INDEX_NAME").as_str(),
                        r.get_unchecked::<String, _>("COLUMN_NAME").as_str()
                    ),
                    ("PRIMARY", "singleton") | ("dataset_uuid", "dataset_uuid")
                )
        })
    {
        return Err(invalid("unknown metadata indexes"));
    }
    let valid:i64=sqlx::query_scalar("SELECT ENGINE='InnoDB' AND TABLE_TYPE='BASE TABLE' AND CREATE_OPTIONS='' AND NOT EXISTS(SELECT 1 FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE() AND EVENT_OBJECT_TABLE=?) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?").bind(table).bind(table).fetch_one(c).await?;
    if valid == 0 {
        return Err(invalid("unknown metadata engine/options/triggers"));
    }
    Ok(())
}
async fn state(c: &mut MySqlConnection) -> Result<Option<State>> {
    if !exists(c, MARKER).await? {
        return Ok(None);
    }
    metadata(c, MARKER, true).await?;
    let rows=sqlx::query("SELECT CAST(format AS CHAR CHARACTER SET utf8mb4) AS format,CAST(phase AS CHAR CHARACTER SET utf8mb4) AS phase,backup,CAST(source_profile AS CHAR CHARACTER SET utf8mb4) AS source_profile,CAST(sha256 AS CHAR CHARACTER SET utf8mb4) AS sha256,CAST(dataset AS CHAR CHARACTER SET utf8mb4) AS dataset FROM pushgo_ordinary_cutover LIMIT 2").fetch_all(c).await?;
    if rows.len() != 1 {
        return Err(invalid("damaged MySQL cutover marker"));
    }
    let r = &rows[0];
    if r.get_unchecked::<String, _>("format") != FORMAT {
        return Err(invalid("unknown MySQL cutover marker"));
    }
    let s = State {
        phase: r.get_unchecked("phase"),
        backup: PathBuf::from(r.get_unchecked::<String, _>("backup")),
        profile: r.get_unchecked("source_profile"),
        sha256: r.get_unchecked("sha256"),
        dataset: r.get_unchecked("dataset"),
    };
    retention(&s.profile)?;
    if !matches!(
        s.phase.as_str(),
        "prepared" | "complete" | "restoring" | "activated"
    ) {
        return Err(invalid("unknown MySQL cutover phase"));
    }
    Ok(Some(s))
}
async fn schema(c: &mut MySqlConnection) -> Result<()> {
    schema_inner(c, false).await
}
async fn schema_inner(c: &mut MySqlConnection, messages: bool) -> Result<()> {
    let expected: Vec<(String, String, String)> = serde_json::from_str(SOURCE)?;
    if expected.is_empty() {
        return Err(invalid("native MySQL fixed-main catalog unavailable"));
    }
    let catalog = if messages {
        CATALOG.replace(
            "('pushgo_product_owner','pushgo_ordinary_cutover')",
            "('pushgo_product_owner','pushgo_ordinary_cutover','ordinary_messages')",
        )
    } else {
        CATALOG.into()
    };
    let max_definition = expected.iter().map(|(_, _, definition)| definition.len()).max().unwrap_or(0) as i64;
    let rows = sqlx::query(&format!("SELECT kind,name,CASE WHEN OCTET_LENGTH(definition)<=? THEN definition END AS definition FROM ({catalog}) source_catalog ORDER BY BINARY kind,BINARY name LIMIT ?"))
        .bind(max_definition)
        .bind(expected.len() as i64 + 1)
        .fetch_all(&mut *c)
        .await?;
    if rows.len() != expected.len()
        || rows.iter().zip(expected).any(|(r, e)| {
            (
                r.get_unchecked::<String, _>("kind"),
                r.get_unchecked::<String, _>("name"),
                r.get_unchecked::<Option<String>, _>("definition"),
            ) != (e.0, e.1, Some(e.2))
        })
    {
        return Err(invalid("unsupported fixed-main native MySQL schema"));
    }
    let version:String=sqlx::query_scalar("SELECT CAST(meta_value AS CHAR CHARACTER SET utf8mb4) FROM pushgo_schema_meta WHERE meta_key='schema_version'").fetch_one(&mut *c).await?;
    if version != "2026-08-20-gateway-v12" {
        return Err(invalid("unsupported source schema version"));
    }
    let defs = crate::storage::database::migration::SCHEMA_MIGRATIONS;
    let rows=sqlx::query("SELECT migration_id,checksum,CAST(success AS CHAR) AS success FROM pushgo_schema_migrations ORDER BY migration_id LIMIT ?").bind(defs.len() as i64+1).fetch_all(c).await?;
    if rows.len() != defs.len()
        || rows.iter().any(|r| {
            !defs.iter().any(|d| {
                d.id == r.get_unchecked::<String, _>("migration_id")
                    && d.checksum == r.get_unchecked::<String, _>("checksum")
            }) || r.get_unchecked::<String, _>("success") != "1"
        })
    {
        return Err(invalid("source migration checksum/success mismatch"));
    }
    Ok(())
}
/// Explicit MySQL table locks survive COMMIT until UNLOCK TABLES. No START
/// TRANSACTION is issued while locked: that statement would release the locks.
async fn lock_source(c: &mut MySqlConnection, write: bool, ordinary: bool) -> Result<()> {
    let expected: Vec<(String, String, String)> = serde_json::from_str(SOURCE)?;
    let mut tables = Vec::new();
    for (k, name, definition) in expected {
        if k == "table" {
            let d: serde_json::Value = serde_json::from_str(&definition)?;
            if d[0] != "BASE TABLE" || d[1] != "InnoDB" {
                return Err(invalid("only fixed InnoDB base tables supported"));
            }
            tables.push(format!(
                "`{}` {}",
                name.replace('`', "``"),
                if write { "WRITE" } else { "READ" }
            ));
        }
    }
    if tables.is_empty() {
        return Err(invalid("empty source catalog"));
    }
    tables.push("pushgo_product_owner READ".into());
    if exists(c, MARKER).await? {
        tables.push("pushgo_ordinary_cutover WRITE".into())
    }
    if ordinary {
        tables.push("ordinary_messages WRITE".into())
    }
    // MySQL does not support LOCK/UNLOCK TABLES through COM_STMT_PREPARE.
    // This fixed catalog-derived statement has no input parameters.
    sqlx::raw_sql(&format!("LOCK TABLES {}", tables.join(",")))
        .execute(c)
        .await?;
    Ok(())
}
async fn phase(c: &mut MySqlConnection, health: &Health, value: &str) -> Result<()> {
    health.ensure()?;
    alone(c, true).await?;
    sqlx::query("UPDATE pushgo_ordinary_cutover SET phase=? WHERE singleton=1")
        .bind(value)
        .execute(c)
        .await?;
    health.ensure()?;
    Ok(())
}
/// Offline CLI. Every incomplete durable stage fences candidate startup.
pub async fn run(url: &str, action: &str, dir: &Path, source_profile: Option<&str>) -> Result<()> {
    if !matches!(action, "plan" | "run" | "restore") {
        return Err(invalid("unknown offline cutover action"));
    }
    let mut c = connect(url).await?;
    alone(&mut c, false).await?;
    let health = Arc::new(Health::default());
    let owner = ProductOwner::acquire(Some(url), health.clone()).await?;
    let outcome = run_owned(url, action, dir, source_profile, &mut c, &health).await;
    // Closing the fixed connection rolls back failed DML and releases table
    // locks. No pool/reconnect can replace it after an unknown COMMIT.
    let close = c.close().await;
    let release = owner.shutdown().await;
    outcome?;
    close?;
    release?;
    Ok(())
}
async fn run_owned(
    url: &str,
    action: &str,
    dir: &Path,
    profile: Option<&str>,
    c: &mut MySqlConnection,
    health: &Health,
) -> Result<()> {
    health.ensure()?;
    alone(c, true).await?;
    let id = dataset(c).await?;
    let database: String = sqlx::query_scalar("SELECT DATABASE()")
        .fetch_one(&mut *c)
        .await?;
    if action == "restore" && exists(c, MARKER).await? {
        metadata(c, MARKER, true).await?;
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pushgo_ordinary_cutover")
            .fetch_one(&mut *c)
            .await?;
        if rows == 0 {
            let asserted = profile.ok_or_else(|| {
                invalid("empty marker recovery requires explicit fixed-main source profile")
            })?;
            schema(c).await?;
            lock_source(c, false, false).await?;
            schema(c).await?;
            drained(c).await?;
            history(c, retention(asserted)?, false).await?;
            health.ensure()?;
            alone(c, true).await?;
            sqlx::query("DROP TABLE pushgo_ordinary_cutover")
                .execute(&mut *c)
                .await?;
            sqlx::raw_sql("UNLOCK TABLES").execute(c).await?;
            println!(
                "MySQL empty prepared marker aborted after pristine-source verification; retained backup files unchanged"
            );
            return Ok(());
        }
    }
    if let Some(s) = state(c).await? {
        if s.dataset != id {
            return Err(invalid("cutover dataset identity mismatch"));
        }
        if action == "restore" {
            return restore(url, dir, c, health, &s, &database).await;
        }
        if matches!(s.phase.as_str(), "complete" | "activated")
            && action == "run"
            && profile == Some(s.profile.as_str())
            && dir.canonicalize()? == s.backup
        {
            verify_backup(&s.backup, &s, &database)?;
            return Ok(());
        }
        return Err(invalid(
            "cutover already prepared/activated; explicit restore required before another run",
        ));
    }
    if action == "restore" {
        return Err(invalid("restore requires persistent cutover marker"));
    }
    let profile = profile.ok_or_else(|| invalid("explicit fixed-main source profile required"))?;
    let keep = retention(profile)?;
    schema(c).await?;
    lock_source(c, false, false).await?;
    schema(c).await?;
    drained(c).await?;
    let count = history(c, keep, false).await?;
    health.ensure()?;
    alone(c, true).await?;
    sqlx::raw_sql("UNLOCK TABLES").execute(&mut *c).await?;
    if action == "plan" {
        println!(
            "MySQL offline plan: {count} historical identities; all target-bearing tables empty; stop old main throughout cutover"
        );
        return Ok(());
    }
    let _ = native("mysqldump", url)?;
    let _ = native("mysql", url)?;
    fs::create_dir(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    let dir = dir.canonicalize()?;
    sync_dir(
        dir.parent()
            .ok_or_else(|| invalid("backup parent missing"))?,
    )?;
    health.ensure()?;
    alone(c, true).await?;
    // MySQL CREATE TABLE commits implicitly. An empty marker table is itself an
    // incomplete persistent fence if killed before the singleton INSERT.
    sqlx::query("CREATE TABLE pushgo_ordinary_cutover(singleton TINYINT PRIMARY KEY CHECK(singleton=1),format VARBINARY(64) NOT NULL,phase VARBINARY(16) NOT NULL,backup TEXT NOT NULL,source_profile VARBINARY(16) NOT NULL,sha256 VARBINARY(64) NOT NULL,dataset VARBINARY(32) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin").execute(&mut *c).await?;
    health.ensure()?;
    alone(c, true).await?;
    sqlx::query("INSERT INTO pushgo_ordinary_cutover VALUES(1,?,'prepared',?,?,'',?)")
        .bind(FORMAT)
        .bind(
            dir.to_str()
                .ok_or_else(|| invalid("backup path must be UTF-8"))?,
        )
        .bind(profile)
        .bind(&id)
        .execute(&mut *c)
        .await?;
    health.ensure()?;
    lock_source(c, false, false).await?;
    schema(c).await?;
    drained(c).await?;
    if history(c, keep, false).await? != count {
        return Err(invalid(
            "source changed between admission and prepared fence",
        ));
    }
    health.ensure()?;
    alone(c, true).await?;
    let dump = dir.join("source.dump");
    let output = new_file(&dump)?;
    let (mut command, native_db) = native("mysqldump", url)?;
    if native_db != database {
        return Err(invalid("native backup database identity mismatch"));
    }
    let status = command
        .args([
            "--single-transaction",
            "--skip-lock-tables",
            "--hex-blob",
            "--triggers",
            "--routines",
            "--events",
            "--no-tablespaces",
            "--set-gtid-purged=OFF",
        ])
        .arg(format!("--ignore-table={database}.pushgo_product_owner"))
        .arg(format!("--ignore-table={database}.pushgo_ordinary_cutover"))
        .arg(&database)
        .stdout(Stdio::from(output))
        .status()
        .map_err(|_| invalid("native mysqldump unavailable"))?;
    health.ensure()?;
    alone(c, true).await?;
    if !status.success() {
        return Err(invalid(
            "native consistent mysqldump failed; startup remains fenced",
        ));
    }
    regular(&dump)?;
    File::open(&dump)?.sync_all()?;
    let hash = digest(&dump)?;
    manifest_write(
        &dir,
        &Manifest {
            format: FORMAT.into(),
            dataset: id,
            database,
            source_profile: profile.into(),
            sha256: hash.clone(),
            histories: count,
        },
    )?;
    health.ensure()?;
    alone(c, true).await?;
    sqlx::query("UPDATE pushgo_ordinary_cutover SET sha256=? WHERE singleton=1")
        .bind(hash)
        .execute(&mut *c)
        .await?;
    health.ensure()?;
    alone(c, true).await?;
    sqlx::raw_sql("UNLOCK TABLES").execute(&mut *c).await?;
    // This is the only candidate business DDL. It can commit independently of
    // conversion, so prepared remains durable until the later DML COMMIT.
    health.ensure()?;
    alone(c, true).await?;
    sqlx::raw_sql(super::mysql_store::MESSAGE_SCHEMA)
        .execute(&mut *c)
        .await?;
    health.ensure()?;
    alone(c, true).await?;
    sqlx::query("SET autocommit=0").execute(&mut *c).await?;
    lock_source(c, true, true).await?;
    // Catalog verification excludes only the one newly-created message table
    // during this stage; every other source object must still be exact.
    schema_with_messages(c).await?;
    drained(c).await?;
    health.ensure()?;
    alone(c, true).await?;
    if history(c, keep, true).await? != count {
        return Err(invalid("source history changed before conversion"));
    }
    phase(c, health, "complete").await?;
    health.ensure()?;
    alone(c, true).await?;
    sqlx::query("COMMIT").execute(&mut *c).await?;
    sqlx::raw_sql("UNLOCK TABLES").execute(&mut *c).await?;
    sqlx::query("SET autocommit=1").execute(c).await?;
    println!(
        "MySQL offline cutover complete: {count} historical identities; restore available before activation"
    );
    Ok(())
}
/// The fixed source catalog is compared with candidate-only ordinary_messages
/// omitted. Source acceptance never enables this exclusion.
async fn schema_with_messages(c: &mut MySqlConnection) -> Result<()> {
    schema_inner(c, true).await
}
async fn restore(
    url: &str,
    dir: &Path,
    c: &mut MySqlConnection,
    health: &Health,
    s: &State,
    database: &str,
) -> Result<()> {
    if s.phase == "activated" {
        return Err(invalid("restore prohibited after activation intent"));
    }
    if dir.canonicalize()? != s.backup {
        return Err(invalid("restore backup path mismatch"));
    }
    if s.sha256.is_empty() {
        if s.phase != "prepared" {
            return Err(invalid("unbound backup in nonprepared phase"));
        }
        health.ensure()?;
        alone(c, true).await?;
        schema(c).await?;
        lock_source(c, false, false).await?;
        schema(c).await?;
        drained(c).await?;
        history(c, retention(&s.profile)?, false).await?;
        health.ensure()?;
        alone(c, true).await?;
        sqlx::query("DROP TABLE pushgo_ordinary_cutover")
            .execute(&mut *c)
            .await?;
        sqlx::raw_sql("UNLOCK TABLES").execute(c).await?;
        println!(
            "MySQL prepared backup aborted after pristine-source verification; retained backup files unchanged"
        );
        return Ok(());
    }
    let m = verify_backup(dir, s, database)?;
    health.ensure()?;
    alone(c, true).await?;
    phase(c, health, "restoring").await?;
    // Neither the native dump nor this cleanup may drop the persistent marker.
    // A failure during native implicit DDL keeps restoring until explicit retry.
    sqlx::query("DROP TABLE IF EXISTS ordinary_messages")
        .execute(&mut *c)
        .await?;
    health.ensure()?;
    alone(c, true).await?;
    let (mut command, native_db) = native("mysql", url)?;
    if native_db != database {
        return Err(invalid("native restore database identity mismatch"));
    }
    let status = command
        .arg(database)
        .stdin(Stdio::from(File::open(dir.join("source.dump"))?))
        .stdout(Stdio::null())
        .status()
        .map_err(|_| invalid("native mysql unavailable"))?;
    health.ensure()?;
    alone(c, true).await?;
    if !status.success() {
        return Err(invalid(
            "native MySQL restore failed; startup remains fenced",
        ));
    }
    schema(c).await?;
    lock_source(c, false, false).await?;
    schema(c).await?;
    drained(c).await?;
    if history(c, retention(&s.profile)?, false).await? != m.histories {
        return Err(invalid("restored history count mismatch"));
    }
    health.ensure()?;
    alone(c, true).await?;
    sqlx::query("DROP TABLE pushgo_ordinary_cutover")
        .execute(&mut *c)
        .await?;
    sqlx::raw_sql("UNLOCK TABLES").execute(c).await?;
    println!("MySQL native restore verified; source ready");
    Ok(())
}
/// One startup operation after ProductOwner and before mutable Storage.
pub async fn activate_before_runtime(url: &str, target_profile: &str) -> Result<()> {
    let mut c = connect(url).await?;
    let Some(s) = state(&mut c).await? else {
        c.close().await?;
        return Ok(());
    };
    if !matches!(s.phase.as_str(), "complete" | "activated") {
        return Err(invalid(
            "incomplete MySQL cutover; explicit restore required",
        ));
    }
    if retention(target_profile)? < retention(&s.profile)? {
        return Err(invalid(
            "cutover target retention shorter than source profile",
        ));
    }
    if dataset(&mut c).await? != s.dataset {
        return Err(invalid("cutover dataset identity mismatch"));
    }
    owner_session(&mut c, true).await?;
    if s.phase == "complete" {
        let db: String = sqlx::query_scalar("SELECT DATABASE()")
            .fetch_one(&mut c)
            .await?;
        verify_backup(&s.backup, &s, &db)?;
        owner_session(&mut c, true).await?;
        sqlx::query("UPDATE pushgo_ordinary_cutover SET phase='activated' WHERE singleton=1 AND phase='complete'").execute(&mut c).await?;
    }
    c.close().await?;
    Ok(())
}
