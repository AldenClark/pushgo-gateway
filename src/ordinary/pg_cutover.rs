//! Fixed-main dfb6b7c/v12 PostgreSQL offline history conversion only.
//! Operators must stop old main: its processes do not honor ProductOwner.
//! Session inspection and table locks are admission checks, not an old-binary
//! restart fence. No connection here is pooled or automatically reconnected.
use super::{
    owner::ProductOwner,
    store::{Health, KernelError},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Connection, PgConnection, Row};
use std::{
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
const LEGACY_FORMAT: &str = "ordinary-postgres-cutover-dfb6b7c-v1";
// v2 archives contain the real fenced v13 source header, not a rewritten dump.
const FORMAT: &str = "ordinary-postgres-cutover-dfb6b7c-v2";
const SOURCE_VERSION: &str = crate::storage::STORAGE_SCHEMA_VERSION_DURABLE_V12;
const FENCED_VERSION: &str = crate::storage::STORAGE_SCHEMA_VERSION;
const CATALOG: &str = include_str!("pg_cutover/catalog.sql");
const SOURCE: &str = include_str!("pg_cutover/source_schema.json");
const MARKER: &str = "public.pushgo_ordinary_cutover";
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
    format: String,
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
    let (_, rest) = url
        .split_once("://")
        .ok_or_else(|| invalid("invalid PostgreSQL URL"))?;
    if !matches!(
        url.split(':')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase()
            .as_str(),
        "pg" | "postgres" | "postgresql"
    ) {
        return Err(invalid("PostgreSQL URL required"));
    }
    Ok(format!("postgresql://{rest}"))
}
async fn connect(url: &str) -> Result<PgConnection> {
    let mut c = PgConnection::connect(&normalized(url)?)
        .await
        .map_err(|_| invalid("PostgreSQL cutover connection failed"))?;
    sqlx::query("SET search_path TO public, pg_catalog")
        .execute(&mut c)
        .await?;
    sqlx::query("SET lock_timeout='3s'").execute(&mut c).await?;
    Ok(c)
}
async fn exists(c: &mut PgConnection, name: &str) -> Result<bool> {
    Ok(
        sqlx::query_scalar::<_, bool>("SELECT to_regclass($1) IS NOT NULL")
            .bind(name)
            .fetch_one(c)
            .await?,
    )
}
/// Exclude only this physical session and the unique actual granted owner PID.
async fn alone(c: &mut PgConnection, require_owner: bool) -> Result<()> {
    let owners:Vec<i32>=sqlx::query_scalar("SELECT pid FROM pg_catalog.pg_locks WHERE locktype='advisory' AND classid=1346852687::bigint::oid AND objid=1330791756::bigint::oid AND objsubid=2 AND granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())").fetch_all(&mut *c).await?;
    if owners.len() > 1 || (require_owner && owners.len() != 1) {
        return Err(invalid(
            "fixed PostgreSQL owner session missing or ambiguous",
        ));
    }
    let unexpected:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE datid=(SELECT oid FROM pg_database WHERE datname=current_database()) AND pid<>pg_backend_pid() AND ($1::integer IS NULL OR pid<>$1) AND backend_type='client backend')").bind(owners.first().copied()).fetch_one(c).await?;
    if unexpected {
        return Err(invalid(
            "stop and join every old/database client before PostgreSQL cutover",
        ));
    }
    Ok(())
}
async fn dataset(c: &mut PgConnection) -> Result<String> {
    metadata(c, "pushgo_product_owner", false).await?;
    Ok(
        sqlx::query_scalar(
            "SELECT dataset_uuid FROM public.pushgo_product_owner WHERE singleton=1",
        )
        .fetch_one(c)
        .await?,
    )
}
/// These two intentionally excluded metadata tables have their own exact shape
/// check; excluding their names must not admit arbitrary user-defined schema.
async fn metadata(c: &mut PgConnection, table: &str, marker: bool) -> Result<()> {
    let rows=sqlx::query("SELECT a.attname,format_type(a.atttypid,a.atttypmod) AS kind,a.attnotnull,a.attidentity::text AS identity,a.attgenerated::text AS generated,d.oid IS NOT NULL AS defaulted FROM pg_attribute a JOIN pg_class t ON t.oid=a.attrelid JOIN pg_namespace n ON n.oid=t.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=t.oid AND d.adnum=a.attnum WHERE n.nspname='public' AND t.relname=$1 AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum LIMIT 9").bind(table).fetch_all(&mut *c).await?;
    let expected: Vec<(&str, &str)> = if marker {
        vec![
            ("singleton", "smallint"),
            ("format", "text"),
            ("phase", "text"),
            ("backup", "text"),
            ("source_profile", "text"),
            ("sha256", "text"),
            ("dataset", "text"),
        ]
    } else {
        vec![
            ("singleton", "smallint"),
            ("dataset_uuid", "character varying(32)"),
        ]
    };
    if rows.len() != expected.len()
        || rows.iter().zip(expected).any(|(r, (name, kind))| {
            r.get::<String, _>("attname") != name
                || r.get::<String, _>("kind") != kind
                || !r.get::<bool, _>("attnotnull")
                || r.get::<bool, _>("defaulted")
                || !r.get::<String, _>("identity").is_empty()
                || !r.get::<String, _>("generated").is_empty()
        })
    {
        return Err(invalid(
            "unsupported PostgreSQL cutover/owner metadata columns",
        ));
    }
    let defs:Vec<String>=sqlx::query_scalar("SELECT pg_get_constraintdef(k.oid,true) FROM pg_constraint k JOIN pg_class t ON t.oid=k.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname='public' AND t.relname=$1 ORDER BY pg_get_constraintdef(k.oid,true) LIMIT 4").bind(table).fetch_all(&mut *c).await?;
    let expected = if marker {
        vec!["CHECK (singleton = 1)", "PRIMARY KEY (singleton)"]
    } else {
        vec![
            "CHECK (singleton = 1)",
            "PRIMARY KEY (singleton)",
            "UNIQUE (dataset_uuid)",
        ]
    };
    if defs.iter().map(String::as_str).collect::<Vec<_>>() != expected {
        return Err(invalid(
            "unsupported PostgreSQL cutover/owner metadata constraints",
        ));
    }
    let valid:bool=sqlx::query_scalar("SELECT c.relkind='r' AND c.relpersistence='p' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity AND c.reloptions IS NULL AND (SELECT count(*) FROM pg_index i WHERE i.indrelid=c.oid)=$2 AND NOT EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=$1").bind(table).bind(if marker{1i64}else{2i64}).fetch_one(c).await?;
    if !valid {
        return Err(invalid(
            "unsupported PostgreSQL cutover/owner metadata relation",
        ));
    }
    Ok(())
}
async fn state(c: &mut PgConnection) -> Result<Option<State>> {
    if !exists(c, MARKER).await? {
        return Ok(None);
    }
    metadata(c, "pushgo_ordinary_cutover", true).await?;
    let rows=sqlx::query("SELECT format,phase,backup,source_profile,sha256,dataset FROM public.pushgo_ordinary_cutover LIMIT 2").fetch_all(c).await?;
    if rows.len() != 1 {
        return Err(invalid("damaged PostgreSQL cutover marker"));
    }
    let r = &rows[0];
    if !matches!(
        r.get::<String, _>("format").as_str(),
        FORMAT | LEGACY_FORMAT
    ) {
        return Err(invalid("unknown PostgreSQL cutover marker"));
    }
    let s = State {
        format: r.get("format"),
        phase: r.get("phase"),
        backup: PathBuf::from(r.get::<String, _>("backup")),
        profile: r.get("source_profile"),
        sha256: r.get("sha256"),
        dataset: r.get("dataset"),
    };
    retention(&s.profile)?;
    if !matches!(
        s.phase.as_str(),
        "prepared" | "complete" | "restoring" | "activated"
    ) {
        return Err(invalid("unknown cutover phase"));
    }
    Ok(Some(s))
}
async fn require_version(c: &mut PgConnection, expected: &str) -> Result<()> {
    let value: String = sqlx::query_scalar(
        "SELECT meta_value FROM public.pushgo_schema_meta WHERE meta_key='schema_version'",
    )
    .fetch_one(c)
    .await?;
    if value != expected {
        return Err(invalid(
            "unexpected PostgreSQL schema version for cutover stage",
        ));
    }
    Ok(())
}
async fn set_version(c: &mut PgConnection, expected: &str, next: &str) -> Result<()> {
    let changed = sqlx::query("UPDATE public.pushgo_schema_meta SET meta_value=$1 WHERE meta_key='schema_version' AND meta_value=$2")
        .bind(next).bind(expected).execute(c).await?.rows_affected();
    if changed != 1 {
        return Err(invalid("PostgreSQL schema version changed during cutover"));
    }
    Ok(())
}
async fn schema(c: &mut PgConnection, expected_version: &str) -> Result<()> {
    let expected: Vec<(String, String, String)> = serde_json::from_str(SOURCE)?;
    if expected.is_empty() {
        return Err(invalid("fixed-main native PostgreSQL catalog unavailable"));
    }
    let max_definition = expected
        .iter()
        .map(|(_, _, definition)| definition.len())
        .max()
        .unwrap_or(0) as i64;
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!("SELECT kind,name,CASE WHEN octet_length(definition)<=$2 THEN definition END AS definition FROM ({CATALOG}) source_catalog ORDER BY kind COLLATE \"C\",name COLLATE \"C\" LIMIT $1")))
        .bind(expected.len() as i64 + 1)
        .bind(max_definition)
        .fetch_all(&mut *c)
        .await?;
    if rows.len() != expected.len()
        || rows.iter().zip(expected).any(|(r, e)| {
            (
                r.get::<String, _>("kind"),
                r.get::<String, _>("name"),
                r.get::<Option<String>, _>("definition"),
            ) != (e.0, e.1, Some(e.2))
        })
    {
        return Err(invalid("unsupported fixed-main native PostgreSQL schema"));
    }
    let version: String = sqlx::query_scalar(
        "SELECT meta_value FROM pushgo_schema_meta WHERE meta_key='schema_version'",
    )
    .fetch_one(&mut *c)
    .await?;
    if version != expected_version {
        return Err(invalid("unsupported source schema version"));
    }
    let defs = crate::storage::database::migration::SCHEMA_MIGRATIONS;
    let rows=sqlx::query("SELECT migration_id,checksum,success::text AS success FROM pushgo_schema_migrations ORDER BY migration_id LIMIT $1").bind(defs.len() as i64 + 1).fetch_all(c).await?;
    if rows.len() != defs.len()
        || rows.iter().any(|r| {
            !defs.iter().any(|d| {
                d.id == r.get::<String, _>("migration_id")
                    && d.checksum == r.get::<String, _>("checksum")
            }) || !matches!(r.get::<String, _>("success").as_str(), "true" | "1")
        })
    {
        return Err(invalid("source migration checksum/success mismatch"));
    }
    Ok(())
}
async fn lock_source(c: &mut PgConnection) -> Result<()> {
    // Names are the fixed catalog's tables, never database-supplied SQL.
    let expected: Vec<(String, String, String)> = serde_json::from_str(SOURCE)?;
    let tables: Vec<_> = expected
        .iter()
        .filter(|(k, _, d)| k == "relation" && d.starts_with("r|"))
        .map(|(_, n, _)| format!("public.\"{}\"", n.replace('"', "\"\"")))
        .collect();
    if tables.is_empty() {
        return Err(invalid("empty source catalog"));
    }
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "LOCK TABLE {} IN SHARE MODE",
        tables.join(",")
    )))
    .execute(c)
    .await?;
    Ok(())
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
async fn drained(c: &mut PgConnection) -> Result<()> {
    for table in [
        "semantic_id_registry",
        "dispatch_delivery_dedupe",
        "dispatch_op_dedupe",
    ] {
        if sqlx::query_scalar::<_, bool>(sqlx::AssertSqlSafe(format!(
            "SELECT EXISTS(SELECT 1 FROM {table} WHERE dedupe_key IS NULL OR dedupe_key='')"
        )))
        .fetch_one(&mut *c)
        .await?
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
        if sqlx::query_scalar::<_, bool>(sqlx::AssertSqlSafe(format!(
            "SELECT EXISTS(SELECT 1 FROM {table})"
        )))
        .fetch_one(&mut *c)
        .await?
        {
            return Err(invalid(
                "all target-bearing tables must be empty across every model, including terminal/ACK rows",
            ));
        }
    }
    let mut cursor = String::new();
    loop {
        let rows=sqlx::query("SELECT dedupe_key,delivery_id,state FROM dispatch_delivery_dedupe WHERE dedupe_key>$1 ORDER BY dedupe_key LIMIT 256").bind(&cursor).fetch_all(&mut *c).await?;
        if rows.is_empty() {
            break;
        }
        for r in rows {
            cursor = r.get("dedupe_key");
            let id: String = r.get("delivery_id");
            if cursor != format!("delivery:{id}")
                || crate::util::decode_lower_hex_128(&id).is_err()
                || id != id.to_ascii_lowercase()
                || r.get::<String, _>("state") != "sent"
            {
                return Err(invalid("invalid retained delivery collision identity"));
            }
        }
    }
    cursor.clear();
    loop {
        let rows=sqlx::query("SELECT dedupe_key,state,provider_run_token,provider_owner,provider_lease_until FROM dispatch_op_dedupe WHERE dedupe_key>$1 ORDER BY dedupe_key LIMIT 256").bind(&cursor).fetch_all(&mut *c).await?;
        if rows.is_empty() {
            break;
        }
        for r in rows {
            cursor = r.get("dedupe_key");
            if scope(&cursor, "op")?.1 == "message"
                || r.get::<String, _>("state") != "sent"
                || r.get::<Option<String>, _>("provider_run_token").is_some()
                || r.get::<Option<String>, _>("provider_owner").is_some()
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
/// PostgreSQL temporary indexes spill to disk; every fetched batch is <=256.
async fn history(c: &mut PgConnection, retention: i64, convert: bool) -> Result<u64> {
    sqlx::query("CREATE TEMP TABLE cutover_status(op_id TEXT COLLATE \"C\" PRIMARY KEY,op_fold TEXT COLLATE \"C\" NOT NULL UNIQUE,entity_id TEXT COLLATE \"C\" NOT NULL UNIQUE,channel TEXT NOT NULL,status TEXT NOT NULL,dispatch_status TEXT,provider_run_token TEXT,accepted_at BIGINT NOT NULL,updated_at BIGINT NOT NULL,expires_at BIGINT NOT NULL) ON COMMIT DROP").execute(&mut *c).await?;
    sqlx::query("INSERT INTO cutover_status SELECT op_id,lower(op_id COLLATE \"C\"),entity_id,encode(channel_id,'hex'),status,dispatch_status,provider_run_token,accepted_at,updated_at,expires_at FROM sender_submit_status WHERE model='message'").execute(&mut *c).await.map_err(|_|invalid("duplicate ordinary op aliases/message identity"))?;
    sqlx::query("CREATE TEMP TABLE cutover_seen(op TEXT COLLATE \"C\" PRIMARY KEY,message TEXT COLLATE \"C\" UNIQUE NOT NULL) ON COMMIT DROP").execute(&mut *c).await?;
    let mut cursor = String::new();
    let mut count = 0u64;
    loop {
        let rows=sqlx::query("SELECT dedupe_key,semantic_id,source,created_at,updated_at,expires_at FROM semantic_id_registry WHERE dedupe_key>$1 ORDER BY dedupe_key LIMIT 256").bind(&cursor).fetch_all(&mut *c).await?;
        if rows.is_empty() {
            break;
        }
        for r in rows {
            cursor = r.get("dedupe_key");
            let (channel, model, thing, op_key) = scope(&cursor, "semantic")?;
            if model != "message" {
                continue;
            }
            if thing.is_some() && op_key.contains(':') {
                return Err(invalid(
                    "ambiguous colon-separated thing/operation source scope",
                ));
            }
            let message: String = r.get("semantic_id");
            crate::util::decode_lower_hex_128(&message)
                .map_err(|_| invalid("invalid original message identity"))?;
            let created: i64 = r.get("created_at");
            if r.get::<Option<i64>, _>("expires_at").is_some()
                || r.get::<Option<String>, _>("source").is_some()
                || created <= 0
                || r.get::<i64, _>("updated_at") < created
            {
                return Err(invalid("unsupported semantic expiry/provenance/timestamp"));
            }
            let statuses = sqlx::query("SELECT * FROM cutover_status WHERE entity_id=$1 LIMIT 2")
                .bind(&message)
                .fetch_all(&mut *c)
                .await?;
            if statuses.len() != 1 {
                return Err(invalid(
                    "ordinary semantic/status relation missing or ambiguous",
                ));
            }
            let s = &statuses[0];
            let op: String = s.get("op_id");
            if op.to_ascii_lowercase() != op_key
                || s.get::<String, _>("channel") != channel
                || s.get::<String, _>("status") != "failed"
                || s.get::<Option<String>, _>("dispatch_status").as_deref() != Some("not_attempted")
                || s.get::<Option<String>, _>("provider_run_token").is_some()
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
            sqlx::query("INSERT INTO cutover_seen VALUES($1,$2)")
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
                sqlx::query("INSERT INTO ordinary_messages(delivery_id,message_id,op_id,channel_id,thing_id,fingerprint,payload_blob,payload_bytes,accepted_at,expires_at,dedupe_until,status,updated_at,identity_state) VALUES(NULL,$1,$2,$3,$4,NULL,''::bytea,0,$5,NULL,$6,'historical_unverifiable',$7,'legacy_unverifiable')").bind(&message).bind(&op).bind(ch).bind(thing).bind(accepted).bind(until).bind(updated).execute(&mut *c).await?;
                sqlx::query("DELETE FROM semantic_id_registry WHERE dedupe_key=$1")
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
    sqlx::query("DROP TABLE cutover_seen,cutover_status")
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
                return Err(invalid("invalid PostgreSQL URL encoding"));
            }
            let hex = std::str::from_utf8(&b[i + 1..i + 3])?;
            out.push(
                u8::from_str_radix(hex, 16)
                    .map_err(|_| invalid("invalid PostgreSQL URL encoding"))?,
            );
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Ok(String::from_utf8(out)?)
}
fn native(tool: &str, url: &str) -> Result<Command> {
    let u =
        reqwest::Url::parse(&normalized(url)?).map_err(|_| invalid("invalid PostgreSQL URL"))?;
    let mut cmd = Command::new(tool);
    // A libpq hostaddr/service override must not redirect a native restore
    // away from the dataset verified by the fixed SQLx connection.
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("PG") {
            cmd.env_remove(key);
        }
    }
    cmd.env("PGPASSFILE", "/dev/null")
        .env("PGSSLMODE", "prefer");
    cmd.env(
        "PGHOST",
        u.host_str()
            .ok_or_else(|| invalid("PostgreSQL host required"))?,
    )
    .env("PGPORT", u.port().unwrap_or(5432).to_string())
    .env("PGUSER", decode(u.username())?)
    .env("PGPASSWORD", decode(u.password().unwrap_or(""))?)
    .env("PGDATABASE", decode(u.path().trim_start_matches('/'))?)
    .env("PGCONNECT_TIMEOUT", "5")
    .env("PGAPPNAME", "pushgo-offline-cutover-native");
    cmd.env_remove("PGSERVICE").env_remove("PGOPTIONS");
    for (k, v) in u.query_pairs() {
        if k != "sslmode" {
            return Err(invalid("unsupported PostgreSQL native-tool URL option"));
        }
        cmd.env("PGSSLMODE", v.as_ref());
    }
    cmd.stderr(Stdio::null());
    Ok(cmd)
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
    if m.format != s.format
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
async fn phase(c: &mut PgConnection, health: &Health, value: &str) -> Result<()> {
    health.ensure()?;
    sqlx::query("UPDATE public.pushgo_ordinary_cutover SET phase=$1")
        .bind(value)
        .execute(c)
        .await?;
    health.ensure()?;
    Ok(())
}
/// Explicit CLI only. Every persistent stage fences normal startup.
pub async fn run(url: &str, action: &str, dir: &Path, source_profile: Option<&str>) -> Result<()> {
    if !matches!(action, "plan" | "run" | "restore") {
        return Err(invalid("unknown offline cutover action"));
    }
    let mut c = connect(url).await?;
    alone(&mut c, false).await?;
    let health = Arc::new(Health::default());
    let owner = ProductOwner::acquire(Some(url), health.clone()).await?;
    let outcome = run_owned(url, action, dir, source_profile, &mut c, &health).await;
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
    c: &mut PgConnection,
    health: &Health,
) -> Result<()> {
    health.ensure()?;
    alone(c, true).await?;
    let id = dataset(c).await?;
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&mut *c)
        .await?;
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
            if s.format != FORMAT {
                return Err(invalid(
                    "pre-release PostgreSQL v1 cutover requires normal startup promotion; restore requires the C16 recovery tool",
                ));
            }
            require_version(c, FENCED_VERSION).await?;
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
    sqlx::query("BEGIN ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *c)
        .await?;
    lock_source(c).await?;
    schema(c, SOURCE_VERSION).await?;
    drained(c).await?;
    let count = history(c, keep, false).await?;
    health.ensure()?;
    alone(c, true).await?;
    sqlx::query("ROLLBACK").execute(&mut *c).await?;
    if action == "plan" {
        println!(
            "PostgreSQL offline plan: {count} historical identities; all target-bearing tables empty; stop old main throughout cutover"
        );
        return Ok(());
    }
    let _ = native("pg_dump", url)?;
    let _ = native("pg_restore", url)?;
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
    sqlx::query("BEGIN ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *c)
        .await?;
    lock_source(c).await?;
    schema(c, SOURCE_VERSION).await?;
    drained(c).await?;
    if history(c, keep, false).await? != count {
        return Err(invalid("source changed before durable prepared fence"));
    }
    alone(c, true).await?;
    set_version(c, SOURCE_VERSION, FENCED_VERSION).await?;
    sqlx::query("CREATE TABLE public.pushgo_ordinary_cutover(singleton SMALLINT PRIMARY KEY CHECK(singleton=1),format TEXT NOT NULL,phase TEXT NOT NULL,backup TEXT NOT NULL,source_profile TEXT NOT NULL,sha256 TEXT NOT NULL,dataset TEXT NOT NULL)").execute(&mut *c).await?;
    sqlx::query("INSERT INTO public.pushgo_ordinary_cutover VALUES(1,$1,'prepared',$2,$3,'',$4)")
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
    sqlx::query("COMMIT").execute(&mut *c).await?;
    sqlx::query("BEGIN ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *c)
        .await?;
    lock_source(c).await?;
    schema(c, FENCED_VERSION).await?;
    drained(c).await?;
    let current = history(c, keep, false).await?;
    if count != current {
        return Err(invalid(
            "source changed between admission and prepared fence",
        ));
    }
    alone(c, true).await?;
    health.ensure()?;
    // The prepared commit already published v13. Export this real fenced
    // source snapshot while SHARE locks retain the admitted v12 catalog/data;
    // pg_dump keeps native ownership/ACLs and every nonmetadata object. Header
    // v12 is published only after the entire native restore and verification.
    let snapshot: String = sqlx::query_scalar("SELECT pg_export_snapshot()")
        .fetch_one(&mut *c)
        .await?;
    let dump = dir.join("source.dump");
    let output = new_file(&dump)?;
    let status = native("pg_dump", url)?
        .args([
            "--format=custom",
            "--exclude-table=public.pushgo_product_owner",
            "--exclude-table=public.pushgo_ordinary_cutover",
        ])
        .arg(format!("--snapshot={snapshot}"))
        .stdout(Stdio::from(output))
        .status()
        .map_err(|_| invalid("native pg_dump unavailable"))?;
    health.ensure()?;
    if !status.success() {
        return Err(invalid(
            "native consistent pg_dump failed; startup remains fenced",
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
    if !native("pg_restore", url)?
        .arg("--list")
        .stdin(Stdio::from(File::open(&dump)?))
        .stdout(Stdio::null())
        .status()
        .map_err(|_| invalid("native pg_restore unavailable"))?
        .success()
    {
        return Err(invalid("native backup archive validation failed"));
    }
    health.ensure()?;
    alone(c, true).await?;
    sqlx::query("UPDATE public.pushgo_ordinary_cutover SET sha256=$1")
        .bind(&hash)
        .execute(&mut *c)
        .await?;
    health.ensure()?;
    sqlx::query("COMMIT").execute(&mut *c).await?;
    sqlx::query("BEGIN ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *c)
        .await?;
    lock_source(c).await?;
    schema(c, FENCED_VERSION).await?;
    drained(c).await?;
    alone(c, true).await?;
    health.ensure()?;
    sqlx::raw_sql(super::pg_store::MESSAGE_SCHEMA)
        .execute(&mut *c)
        .await?;
    if history(c, keep, true).await? != count {
        return Err(invalid("source history changed before conversion"));
    }
    phase(c, health, "complete").await?;
    health.ensure()?;
    alone(c, true).await?;
    sqlx::query("COMMIT").execute(c).await?;
    println!(
        "PostgreSQL offline cutover complete: {count} historical identities; restore available before activation"
    );
    Ok(())
}
async fn restore(
    url: &str,
    dir: &Path,
    c: &mut PgConnection,
    health: &Health,
    s: &State,
    database: &str,
) -> Result<()> {
    if s.phase == "activated" {
        return Err(invalid("restore prohibited after activation intent"));
    }
    // A pre-release v1 archive restores v12 inside its native transaction. It
    // cannot provide the v13 fence until verification, so refuse it explicitly.
    if s.format != FORMAT {
        return Err(invalid(
            "pre-release PostgreSQL v1 restore unsupported: use the C16 recovery tool while old main remains stopped",
        ));
    }
    require_version(c, FENCED_VERSION).await?;
    if dir.canonicalize()? != s.backup {
        return Err(invalid("restore backup path mismatch"));
    }
    // No data conversion is allowed before the backup hash commit. A failed or
    // interrupted dump may be aborted only after proving the pristine source.
    if s.sha256.is_empty() {
        if s.phase != "prepared" {
            return Err(invalid("unbound backup in nonprepared phase"));
        }
        alone(c, true).await?;
        health.ensure()?;
        sqlx::query("BEGIN ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *c)
            .await?;
        lock_source(c).await?;
        schema(c, FENCED_VERSION).await?;
        drained(c).await?;
        history(c, retention(&s.profile)?, false).await?;
        health.ensure()?;
        alone(c, true).await?;
        set_version(c, FENCED_VERSION, SOURCE_VERSION).await?;
        sqlx::query("DROP TABLE public.pushgo_ordinary_cutover")
            .execute(&mut *c)
            .await?;
        health.ensure()?;
        alone(c, true).await?;
        sqlx::query("COMMIT").execute(c).await?;
        println!(
            "PostgreSQL prepared backup aborted after pristine-source verification; retained backup files unchanged"
        );
        return Ok(());
    }
    let m = verify_backup(dir, s, database)?;
    alone(c, true).await?;
    health.ensure()?;
    phase(c, health, "restoring").await?;
    // Marker and owner were excluded from dump. Restoring intent survives every
    // native DDL result, including an unknown native COMMIT outcome.
    let status = native("pg_restore", url)?
        .args([
            "--clean",
            "--if-exists",
            "--single-transaction",
            "--exit-on-error",
            "--dbname",
        ])
        .arg(database)
        .stdin(Stdio::from(File::open(dir.join("source.dump"))?))
        .stdout(Stdio::null())
        .status()
        .map_err(|_| invalid("native pg_restore unavailable"))?;
    health.ensure()?;
    if !status.success() {
        return Err(invalid(
            "native PostgreSQL restore failed; startup remains fenced",
        ));
    }
    alone(c, true).await?;
    sqlx::query("BEGIN ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *c)
        .await?;
    lock_source(c).await?;
    sqlx::query("DROP TABLE IF EXISTS public.ordinary_messages")
        .execute(&mut *c)
        .await?;
    schema(c, FENCED_VERSION).await?;
    drained(c).await?;
    if history(c, retention(&s.profile)?, false).await? != m.histories {
        return Err(invalid("restored history count mismatch"));
    }
    health.ensure()?;
    alone(c, true).await?;
    set_version(c, FENCED_VERSION, SOURCE_VERSION).await?;
    sqlx::query("DROP TABLE public.pushgo_ordinary_cutover")
        .execute(&mut *c)
        .await?;
    health.ensure()?;
    alone(c, true).await?;
    sqlx::query("COMMIT").execute(c).await?;
    println!("PostgreSQL native restore verified; source ready");
    Ok(())
}
/// Compatibility fence for the existing C16 identity schema. This deliberately
/// does not claim complete runtime integrity: mutable Storage still performs its
/// own admission checks before entrances. It does reject prior C identity tables.
async fn current_identity(c: &mut PgConnection) -> Result<()> {
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace JOIN pg_attribute a ON a.attrelid=t.oid WHERE n.nspname='public' AND t.relname='ordinary_messages' AND t.relkind='r' AND t.relpersistence='p' AND NOT t.relrowsecurity AND NOT t.relforcerowsecurity AND a.attname='identity_state' AND NOT a.attisdropped AND a.atttypid='text'::regtype AND a.attnotnull AND EXISTS(SELECT 1 FROM pg_constraint k WHERE k.conrelid=t.oid AND k.contype='c' AND k.convalidated AND pg_get_constraintdef(k.oid,true) LIKE '%identity_state = ''live''::text%' AND pg_get_constraintdef(k.oid,true) LIKE '%identity_state = ''legacy_unverifiable''::text%' AND pg_get_constraintdef(k.oid,true) LIKE '%delivery_id IS NULL%' AND pg_get_constraintdef(k.oid,true) LIKE '%fingerprint IS NULL%' AND pg_get_constraintdef(k.oid,true) LIKE '%expires_at IS NULL%' AND pg_get_constraintdef(k.oid,true) LIKE '%historical_unverifiable%'))"
    ).fetch_one(c).await?;
    if !valid {
        return Err(invalid(
            "unsupported current PostgreSQL cutover identity schema",
        ));
    }
    Ok(())
}
/// One startup operation after owner acquisition and before mutable Storage.
pub async fn activate_before_runtime(url: &str, target_profile: &str) -> Result<()> {
    let mut c = connect(url).await?;
    let Some(s) = state(&mut c).await? else {
        c.close().await?;
        return Ok(());
    };
    if !matches!(s.phase.as_str(), "complete" | "activated") {
        return Err(invalid(
            "incomplete PostgreSQL cutover; explicit restore required",
        ));
    }
    if retention(target_profile)? < retention(&s.profile)? {
        return Err(invalid("cutover source/target retention profile mismatch"));
    }
    if dataset(&mut c).await? != s.dataset {
        return Err(invalid("cutover dataset identity mismatch"));
    }
    alone(&mut c, true).await?;
    sqlx::query("BEGIN ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut c)
        .await?;
    sqlx::query("LOCK TABLE public.pushgo_ordinary_cutover,public.pushgo_schema_meta IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut c).await?;
    // Re-read under the marker lock; another phase is never promoted implicitly.
    let current = state(&mut c)
        .await?
        .ok_or_else(|| invalid("cutover marker disappeared"))?;
    if current.format != s.format
        || current.phase != s.phase
        || current.sha256 != s.sha256
        || current.dataset != s.dataset
        || current.profile != s.profile
        || current.backup != s.backup
    {
        return Err(invalid(
            "PostgreSQL cutover marker changed before activation",
        ));
    }
    current_identity(&mut c).await?;
    if s.format == LEGACY_FORMAT {
        // The v1 native archive really contains v12. Its identity must remain
        // unchanged; promoting its live dataset does not relabel that archive.
        let db: String = sqlx::query_scalar("SELECT current_database()")
            .fetch_one(&mut c)
            .await?;
        verify_backup(&s.backup, &s, &db)?;
        let version: String = sqlx::query_scalar(
            "SELECT meta_value FROM public.pushgo_schema_meta WHERE meta_key='schema_version'",
        )
        .fetch_one(&mut c)
        .await?;
        if version == SOURCE_VERSION {
            set_version(&mut c, SOURCE_VERSION, FENCED_VERSION).await?;
        } else if version != FENCED_VERSION {
            return Err(invalid("unsupported pre-release PostgreSQL cutover header"));
        }
    } else {
        require_version(&mut c, FENCED_VERSION).await?;
        if s.phase == "complete" {
            let db: String = sqlx::query_scalar("SELECT current_database()")
                .fetch_one(&mut c)
                .await?;
            verify_backup(&s.backup, &s, &db)?;
        }
    }
    if s.phase == "complete" {
        sqlx::query("UPDATE public.pushgo_ordinary_cutover SET phase='activated' WHERE singleton=1 AND phase='complete'")
            .execute(&mut c).await?;
    }
    alone(&mut c, true).await?;
    sqlx::query("COMMIT").execute(&mut c).await?;
    c.close().await?;
    Ok(())
}
