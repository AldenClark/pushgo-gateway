// PostgreSQL ordinary control operations; wire behavior mirrors the SQLite adapter.
use crate::pg_store::PgDeliveryStore;
use crate::profiling::{Path, Phase, Statement};
use crate::store::{
    KernelError, Result, control_error, hash_password, now, supported_platform, sync_failure,
    verify_password_async,
};
use crate::types::{generate_hex_id_128, normalize_provider_token};
use serde_json::{Value, json};
use sqlx::{Connection, Row};

impl PgDeliveryStore {
    pub async fn register_device(&self, platform: &str, requested: Option<&str>) -> Result<Value> {
        let platform = supported_platform(platform)?;
        let requested = requested.map(str::trim).filter(|key| !key.is_empty());
        let _gate = self
            .counters
            .profile
            .phase(Path::Control, Phase::GateWait, self.gate.lock())
            .await;
        let _gate_hold = self.counters.profile.timer(Path::Control, Phase::GateHold);
        self.health.ensure()?;
        let at = now();
        let mut profile_connection = self
            .counters
            .profile
            .phase(Path::Control, Phase::PoolAcquire, self.acquire())
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(Path::Control, Phase::Begin, profile_connection.begin())
            .await?;
        Self::lock_usage(&mut tx).await?;
        self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("DELETE FROM registration_aliases WHERE old_key IN (SELECT old_key FROM registration_aliases WHERE expires_at<$1 ORDER BY expires_at LIMIT 256)").bind(at).execute(&mut *tx)).await?;
        let mut old_key = None;
        if let Some(key) = requested {
            if let Some(row)=self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("SELECT device_key,platform,provider,provider_token,route_generation,route_revision FROM devices WHERE device_key=$1 AND retired_at IS NULL").bind(key).fetch_optional(&mut *tx)).await?{
                if row.get::<String,_>("platform")==platform.name(){let result=registration_response(&row,false,None)?;self.health.ensure()?;self.counters.profile.phase(Path::Control, Phase::Commit, tx.commit()).await?; drop(profile_connection);return Ok(result)}
                old_key=Some(key);
            } else if let Some(row)=self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("SELECT d.device_key,d.platform,d.provider,d.provider_token,d.route_generation,d.route_revision FROM registration_aliases a JOIN devices d ON d.device_key=a.new_key WHERE a.old_key=$1 AND a.platform=$2 AND a.expires_at>=$3 AND d.platform=$4 AND d.retired_at IS NULL").bind(key).bind(platform.name()).bind(at).bind(platform.name()).fetch_optional(&mut *tx)).await? {
                let result=registration_response(&row,true,Some("platform_mismatch"))?;self.health.ensure()?;self.counters.profile.phase(Path::Control, Phase::Commit, tx.commit()).await?; drop(profile_connection);return Ok(result)
            }
        }
        let key = generate_hex_id_128();
        self.counters
            .profile
            .sql(
                Path::Control,
                Statement::Control,
                sqlx::query("INSERT INTO devices(device_key,platform) VALUES($1,$2)")
                    .bind(&key)
                    .bind(platform.name())
                    .execute(&mut *tx),
            )
            .await?;
        let reason = if let Some(old) = old_key {
            // Retire instead of migrating subscriptions or accepted targets.
            self.counters
                .profile
                .sql(
                    Path::Control,
                    Statement::Control,
                    sqlx::query("UPDATE devices SET retired_at=$1 WHERE device_key=$2")
                        .bind(at)
                        .bind(old)
                        .execute(&mut *tx),
                )
                .await?;
            self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("DELETE FROM channel_subscriptions WHERE device_key=$1 AND channel_id IN (SELECT channel_id FROM channel_subscriptions WHERE device_key=$2 ORDER BY channel_id LIMIT 256)").bind(old).bind(old).execute(&mut *tx)).await?;
            self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("INSERT INTO registration_aliases(old_key,new_key,platform,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT(old_key) DO UPDATE SET new_key=excluded.new_key,platform=excluded.platform,expires_at=excluded.expires_at").bind(old).bind(&key).bind(platform.name()).bind(at.saturating_add(600_000)).execute(&mut *tx)).await?;
            self.retire_targets_tx(&mut tx, old, at, 256).await?;
            "platform_mismatch"
        } else if requested.is_some() {
            "device_key_not_found"
        } else {
            "device_key_missing"
        };
        let row=self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("SELECT device_key,platform,provider,provider_token,route_generation,route_revision FROM devices WHERE device_key=$1 AND retired_at IS NULL").bind(&key).fetch_one(&mut *tx)).await?;
        let result = registration_response(&row, true, Some(reason))?;
        self.health.ensure()?;
        self.counters
            .profile
            .phase(Path::Control, Phase::Commit, tx.commit())
            .await?;
        drop(profile_connection);
        self.notify();
        Ok(result)
    }

    pub async fn route(
        &self,
        device: &str,
        platform: Option<&str>,
        provider: &str,
        raw: &str,
    ) -> Result<()> {
        self.update_route(device, platform, provider, Some(raw))
            .await
            .map(|_| ())
    }
    pub async fn update_route(
        &self,
        device: &str,
        platform: Option<&str>,
        provider: &str,
        raw: Option<&str>,
    ) -> Result<Value> {
        let device = device.trim();
        let _gate = self
            .counters
            .profile
            .phase(Path::Control, Phase::GateWait, self.gate.lock())
            .await;
        let _gate_hold = self.counters.profile.timer(Path::Control, Phase::GateHold);
        self.health.ensure()?;
        let row={ let mut profile_read_connection = self.counters.profile.phase(Path::Control, Phase::PoolAcquire, self.acquire()).await?; self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("SELECT platform,provider,provider_token,route_generation,route_revision FROM devices WHERE device_key=$1 AND retired_at IS NULL").bind(device).fetch_optional(&mut *profile_read_connection)).await }?.ok_or_else(||control_error(400,"device_key_not_found","device_key not found"))?;
        let prior_platform: String = row.get("platform");
        let platform = supported_platform(
            platform
                .filter(|v| !v.trim().is_empty())
                .unwrap_or(&prior_platform),
        )?;
        if platform.name() != prior_platform {
            return Err(control_error(
                400,
                "platform_mismatch",
                "platform does not match device identity",
            ));
        }
        let provider = provider.trim().to_ascii_uppercase();
        let token = if provider == "PRIVATE" {
            if raw.is_some_and(|v| !v.trim().is_empty()) {
                return Err(control_error(
                    400,
                    "provider_token_forbidden_for_private_channel",
                    "provider_token is not allowed for private channel",
                ));
            }
            None
        } else {
            if provider != platform.provider_name() {
                return Err(control_error(
                    400,
                    "invalid_channel_type",
                    "platform/provider mismatch",
                ));
            }
            let raw = raw.filter(|v| !v.trim().is_empty()).ok_or_else(|| {
                control_error(
                    400,
                    "provider_token_required",
                    "provider_token required for provider channel",
                )
            })?;
            Some(
                normalize_provider_token(raw, platform)
                    .map_err(|e| control_error(400, "invalid_provider_token", &e.to_string()))?,
            )
        };
        let stored_provider = if provider == "PRIVATE" {
            None
        } else {
            Some(provider.as_str())
        };
        let changed = row.get::<Option<String>, _>("provider").as_deref() != stored_provider
            || row.get::<Option<String>, _>("provider_token") != token;
        let mut profile_connection = self
            .counters
            .profile
            .phase(Path::Control, Phase::PoolAcquire, self.acquire())
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(Path::Control, Phase::Begin, profile_connection.begin())
            .await?;
        Self::lock_usage(&mut tx).await?;
        if row.get::<i64, _>("route_revision") == i64::MAX
            || (changed && row.get::<i64, _>("route_generation") == i64::MAX)
        {
            return Err(KernelError::Invalid(
                "route revision or generation exhausted".into(),
            ));
        }
        self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("UPDATE devices SET provider=$1,provider_token=$2,route_generation=route_generation+$3,route_revision=route_revision+1 WHERE device_key=$4").bind(stored_provider).bind(&token).bind(i64::from(changed)).bind(device).execute(&mut *tx)).await?;
        self.transition_private_mode_tx(&mut tx, device, stored_provider.is_none())
            .await?;
        if let Some(token) = token.as_deref() {
            self.coalesce_owners_tx(&mut tx, device, platform.name(), token)
                .await?;
        }
        self.health.ensure()?;
        self.counters
            .profile
            .phase(Path::Control, Phase::Commit, tx.commit())
            .await?;
        drop(profile_connection);
        self.notify();
        self.route_response(device).await
    }
    async fn coalesce_owners_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        winner: &str,
        platform: &str,
        token: &str,
    ) -> Result<()> {
        self.fence_private_coalesce_tx(tx, winner, platform, token)
            .await?;
        // SQL owns the set; no allocation proportional to historical owners or
        // deliveries. Frozen attempt rows survive under their original key.
        self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("INSERT INTO channel_subscriptions(channel_id,device_key) SELECT s.channel_id,$1 FROM channel_subscriptions s JOIN devices d ON d.device_key=s.device_key WHERE d.platform=$2 AND d.provider_token=$3 AND d.device_key<>$4 AND d.retired_at IS NULL ON CONFLICT(channel_id,device_key) DO NOTHING").bind(winner).bind(platform).bind(token).bind(winner).execute(&mut **tx)).await?;
        // Coalescing transfers retained Pull ownership only. Already-materialized
        // provider jobs retain their original wire ACK capability and must never
        // start/retry under the winner. An already-owned network future may
        // still return its receipt to the frozen original target key.
        self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("UPDATE targets SET pull_owner=$1,owner_generation=-1 WHERE pull_owner IN (SELECT device_key FROM devices WHERE platform=$2 AND provider_token=$3 AND device_key<>$4 AND retired_at IS NULL)").bind(winner).bind(platform).bind(token).bind(winner).execute(&mut **tx)).await?;
        self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("DELETE FROM channel_subscriptions WHERE device_key IN (SELECT device_key FROM devices WHERE platform=$1 AND provider_token=$2 AND device_key<>$3 AND retired_at IS NULL)").bind(platform).bind(token).bind(winner).execute(&mut **tx)).await?;
        self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("UPDATE devices SET retired_at=$1,coalesced_to=$2 WHERE platform=$3 AND provider_token=$4 AND device_key<>$5 AND retired_at IS NULL").bind(now()).bind(winner).bind(platform).bind(token).bind(winner).execute(&mut **tx)).await?;
        Ok(())
    }
    async fn route_response(&self, device: &str) -> Result<Value> {
        let row = {
            let mut profile_read_connection = self
                .counters
                .profile
                .phase(Path::Control, Phase::PoolAcquire, self.acquire())
                .await?;
            self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("SELECT device_key,platform,provider,provider_token,route_generation,route_revision FROM devices WHERE device_key=$1 AND retired_at IS NULL").bind(device).fetch_one(&mut *profile_read_connection)).await
        }?;
        let revision = row.get::<i64, _>("route_revision");
        let mut result = json!({"device_key":device,"channel_type":row.get::<Option<String>,_>("provider").unwrap_or_else(||"private".into()).to_ascii_lowercase(),"issued_new_key":false,"route_revision":revision});
        if let Some(token) = row.get::<Option<String>, _>("provider_token") {
            result["provider_token"] = token.into();
        }
        Ok(result)
    }
    pub async fn delete_route(&self, device: &str, channel_type: &str) -> Result<Value> {
        let device = device.trim();
        let _gate = self
            .counters
            .profile
            .phase(Path::Control, Phase::GateWait, self.gate.lock())
            .await;
        let _gate_hold = self.counters.profile.timer(Path::Control, Phase::GateHold);
        self.health.ensure()?;
        let route = self.active_route(device).await?;
        if route["channel_type"] != channel_type.trim().to_ascii_lowercase() {
            return Err(control_error(
                400,
                "channel_type_mismatch",
                "channel_type does not match current device route",
            ));
        }
        let changed = {
            let mut connection = self.acquire().await?;
            let mut tx = connection.begin().await?;
            Self::lock_usage(&mut tx).await?;
            let result = self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("UPDATE devices SET route_generation=route_generation+CASE WHEN provider_token IS NOT NULL THEN 1 ELSE 0 END,provider_token=NULL,route_revision=route_revision+1 WHERE device_key=$1 AND route_revision<$2 AND (provider_token IS NULL OR route_generation<$3)").bind(device).bind(i64::MAX).bind(i64::MAX).execute(&mut *tx)).await?;
            self.health.ensure()?;
            tx.commit().await?;
            result.rows_affected()
        };
        if changed == 0 {
            return Err(KernelError::Invalid(
                "route revision or generation exhausted".into(),
            ));
        }
        // Provider delete retains accepted Pull and subscriptions; generation
        // invalidation prevents stale tickets from starting new network work.
        self.notify();
        self.route_response(device).await
    }
    pub async fn retire_provider_token(&self, platform: &str, raw: &str) -> Result<()> {
        let platform = supported_platform(platform)?;
        let token = normalize_provider_token(raw, platform)
            .map_err(|error| control_error(400, "invalid_provider_token", &error.to_string()))?;
        let _gate = self
            .counters
            .profile
            .phase(Path::Control, Phase::GateWait, self.gate.lock())
            .await;
        let _gate_hold = self.counters.profile.timer(Path::Control, Phase::GateHold);
        self.health.ensure()?;
        let mut profile_connection = self
            .counters
            .profile
            .phase(Path::Control, Phase::PoolAcquire, self.acquire())
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(Path::Control, Phase::Begin, profile_connection.begin())
            .await?;
        Self::lock_usage(&mut tx).await?;
        let exhausted:bool=self.counters.profile.sql(Path::Control,Statement::Control,sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devices WHERE platform=$1 AND provider_token=$2 AND retired_at IS NULL AND (route_generation=$3 OR route_revision=$4))").bind(platform.name()).bind(&token).bind(i64::MAX).bind(i64::MAX).fetch_one(&mut *tx)).await?;
        if exhausted {
            return Err(KernelError::Invalid(
                "route revision or generation exhausted".into(),
            ));
        }
        let changed=self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("UPDATE ledger_usage SET control_epoch=control_epoch+1 WHERE singleton=1 AND control_epoch<$1").bind(i64::MAX).execute(&mut *tx)).await?.rows_affected();
        if changed == 0 {
            return Err(KernelError::Invalid("control epoch exhausted".into()));
        }
        self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("INSERT INTO retired_provider_tokens(platform,provider_token,control_epoch) SELECT $1,$2,control_epoch FROM ledger_usage WHERE singleton=1 ON CONFLICT(platform,provider_token) DO UPDATE SET control_epoch=excluded.control_epoch").bind(platform.name()).bind(&token).execute(&mut *tx)).await?;
        self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("UPDATE devices SET provider=NULL,provider_token=NULL,route_generation=route_generation+1,route_revision=route_revision+1 WHERE platform=$1 AND provider_token=$2 AND retired_at IS NULL").bind(platform.name()).bind(&token).execute(&mut *tx)).await?;
        self.retire_token_targets_tx(&mut tx).await?;
        self.health.ensure()?;
        self.counters
            .profile
            .phase(Path::Control, Phase::Commit, tx.commit())
            .await?;
        drop(profile_connection);
        self.notify();
        Ok(())
    }

    pub async fn subscribe(
        &self,
        device: &str,
        channel_id: Option<&str>,
        channel_name: Option<&str>,
        auth: &str,
    ) -> Result<Value> {
        let _gate = self
            .counters
            .profile
            .phase(Path::Control, Phase::GateWait, self.gate.lock())
            .await;
        let _gate_hold = self.counters.profile.timer(Path::Control, Phase::GateHold);
        self.health.ensure()?;
        self.subscribe_under_gate(device, channel_id, channel_name, auth)
            .await
    }
    async fn subscribe_under_gate(
        &self,
        device: &str,
        channel_id: Option<&str>,
        channel_name: Option<&str>,
        auth: &str,
    ) -> Result<Value> {
        let channel_id = channel_id.map(str::trim).filter(|v| !v.is_empty());
        let channel_name = channel_name.map(str::trim).filter(|v| !v.is_empty());
        if channel_id.is_some() == channel_name.is_some() {
            return Err(control_error(
                400,
                "channel_binding_invalid",
                "must provide either channel_id or channel_name",
            ));
        }
        let auth = crate::sender::password(auth)
            .map_err(|error| control_error(400, "invalid_password", &error.to_string()))?;
        if device.is_empty() {
            return Err(KernelError::Invalid("device/channel authorization".into()));
        }
        self.counters.sql(5);
        let mut profile_connection = self
            .counters
            .profile
            .phase(Path::Control, Phase::PoolAcquire, self.acquire())
            .await?;
        let mut tx = self
            .counters
            .profile
            .phase(Path::Control, Phase::Begin, profile_connection.begin())
            .await?;
        Self::lock_usage(&mut tx).await?;
        let binding = self
            .counters
            .profile
            .sql(
                Path::Control,
                Statement::Control,
                sqlx::query(
                    "SELECT provider,provider_token FROM devices WHERE device_key=$1 AND retired_at IS NULL",
                )
                .bind(device)
                .fetch_optional(&mut *tx),
            )
            .await?
            .ok_or_else(|| control_error(400, "device_key_not_found", "device_key not found"))?;
        let provider: Option<String> = binding.try_get("provider")?;
        let token: Option<String> = binding.try_get("provider_token")?;
        // A NULL provider is the current Private route. A non-NULL Provider
        // with no token is a deleted Provider route and cannot subscribe.
        if token.is_none() && !(self.config.private.enabled && provider.is_none()) {
            return Err(control_error(
                400,
                "provider_token_required",
                "provider_token required for provider channel",
            ));
        }
        let channel_id = channel_id
            .map(crate::sender::channel_id)
            .transpose()
            .map_err(|error| control_error(400, "invalid_channel_id", &error.to_string()))?;
        let (id, name, created) = if let Some(id) = channel_id.as_deref() {
            let row = self
                .counters
                .profile
                .sql(
                    Path::Control,
                    Statement::Control,
                    sqlx::query(
                        "SELECT channel_name,password_hash FROM channels WHERE channel_id=$1",
                    )
                    .bind(id)
                    .fetch_optional(&mut *tx),
                )
                .await?
                .ok_or_else(|| {
                    control_error(404, "channel_not_found", "channel not found on gateway")
                })?;
            if !self
                .counters
                .profile
                .phase(
                    Path::Control,
                    Phase::Auth,
                    verify_password_async(row.get::<String, _>("password_hash"), auth.to_owned()),
                )
                .await?
            {
                return Err(control_error(
                    403,
                    "password_mismatch",
                    "channel exists but password mismatch",
                ));
            }
            (id.to_owned(), row.get::<String, _>("channel_name"), false)
        } else {
            let name = channel_name
                .map(str::trim)
                .filter(|v| {
                    !v.is_empty() && v.chars().count() <= 128 && !v.chars().any(char::is_control)
                })
                .ok_or_else(|| {
                    control_error(400, "invalid_channel_name", "invalid channel name")
                })?;
            let id = crate::sender::generate_channel_id();
            self.counters
                .profile
                .sql(
                    Path::Control,
                    Statement::Control,
                    sqlx::query(
                        "INSERT INTO channels(channel_id,channel_name,password_hash) VALUES($1,$2,$3)",
                    )
                    .bind(&id)
                    .bind(name)
                    .bind(hash_password(auth))
                    .execute(&mut *tx),
                )
                .await?;
            (id, name.to_owned(), true)
        };
        let count: i64 = self
            .counters
            .profile
            .sql(
                Path::Control,
                Statement::Control,
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM channel_subscriptions WHERE channel_id=$1",
                )
                .bind(&id)
                .fetch_one(&mut *tx),
            )
            .await?;
        let subscribed: i64 = self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query_scalar(
            "SELECT COUNT(*) FROM channel_subscriptions WHERE channel_id=$1 AND device_key=$2",
        )
        .bind(&id)
        .bind(device)
        .fetch_one(&mut *tx)
        ).await?;
        if count >= 32 && subscribed == 0 {
            return Err(control_error(
                400,
                "channel_subscriber_limit_exceeded",
                "channel subscriber limit exceeded",
            ));
        }
        self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query(
            "INSERT INTO channel_subscriptions(channel_id,device_key) VALUES($1,$2) ON CONFLICT(channel_id,device_key) DO NOTHING",
        )
        .bind(&id)
        .bind(device)
        .execute(&mut *tx)
        ).await?;
        self.health.ensure()?;
        self.counters
            .profile
            .phase(Path::Control, Phase::Commit, tx.commit())
            .await?;
        drop(profile_connection);
        Ok(json!({"channel_id":id,"channel_name":name,"created":created,"subscribed":true}))
    }
    async fn active_route(&self, device: &str) -> Result<Value> {
        let row = { let mut profile_read_connection = self.counters.profile.phase(Path::Control, Phase::PoolAcquire, self.acquire()).await?; self.counters.profile.sql(Path::Control, Statement::Control, sqlx::query("SELECT device_key,platform,provider,provider_token,route_generation,route_revision FROM devices WHERE device_key=$1 AND retired_at IS NULL").bind(device).fetch_optional(&mut *profile_read_connection)).await }?
            .ok_or_else(|| control_error(400, "device_key_not_found", "device_key not found"))?;
        Ok(registration_response(&row, false, None)?["route"].clone())
    }
    pub async fn unsubscribe(&self, device: &str, channel: &str) -> Result<Value> {
        let device = device.trim();
        let channel = crate::sender::channel_id(channel)
            .map_err(|error| control_error(400, "invalid_channel_id", &error.to_string()))?;
        let _gate = self
            .counters
            .profile
            .phase(Path::Control, Phase::GateWait, self.gate.lock())
            .await;
        let _gate_hold = self.counters.profile.timer(Path::Control, Phase::GateHold);
        self.health.ensure()?;
        self.active_route(device).await?;
        let removed = {
            let mut profile_read_connection = self
                .counters
                .profile
                .phase(Path::Control, Phase::PoolAcquire, self.acquire())
                .await?;
            let mut tx = profile_read_connection.begin().await?;
            Self::lock_usage(&mut tx).await?;
            let result = self
                .counters
                .profile
                .sql(
                    Path::Control,
                    Statement::Control,
                    sqlx::query(
                        "DELETE FROM channel_subscriptions WHERE device_key=$1 AND channel_id=$2",
                    )
                    .bind(device)
                    .bind(&channel)
                    .execute(&mut *tx),
                )
                .await?;
            self.health.ensure()?;
            tx.commit().await?;
            result.rows_affected() > 0
        };
        // Subscription changes affect future fanout only. Accepted delivery,
        // retained Pull, operation identity and in-flight receipt remain owned.
        Ok(json!({"channel_id":channel,"removed":removed}))
    }
    pub async fn channel_info(&self, channel: &str) -> Result<Value> {
        let channel = crate::sender::channel_id(channel)
            .map_err(|error| control_error(400, "invalid_channel_id", &error.to_string()))?;
        let name: Option<String> = {
            let mut profile_read_connection = self
                .counters
                .profile
                .phase(Path::Control, Phase::PoolAcquire, self.acquire())
                .await?;
            self.counters
                .profile
                .sql(
                    Path::Control,
                    Statement::Control,
                    sqlx::query_scalar("SELECT channel_name FROM channels WHERE channel_id=$1")
                        .bind(&channel)
                        .fetch_optional(&mut *profile_read_connection),
                )
                .await
        }?;
        let mut result = json!({"channel_id":channel,"exists":name.is_some()});
        if let Some(name) = name {
            result["channel_name"] = name.into();
        }
        Ok(result)
    }
    pub async fn rename_channel(&self, channel: &str, name: &str, password: &str) -> Result<Value> {
        let channel = crate::sender::channel_id(channel)
            .map_err(|error| control_error(400, "invalid_channel_id", &error.to_string()))?;
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 128 || name.chars().any(char::is_control) {
            return Err(control_error(
                400,
                "invalid_channel_name",
                "invalid channel name",
            ));
        }
        let password = crate::sender::password(password)
            .map_err(|error| control_error(400, "invalid_password", &error.to_string()))?;
        let _gate = self
            .counters
            .profile
            .phase(Path::Control, Phase::GateWait, self.gate.lock())
            .await;
        let _gate_hold = self.counters.profile.timer(Path::Control, Phase::GateHold);
        self.health.ensure()?;
        let hash: String = {
            let mut profile_read_connection = self
                .counters
                .profile
                .phase(Path::Control, Phase::PoolAcquire, self.acquire())
                .await?;
            self.counters
                .profile
                .sql(
                    Path::Control,
                    Statement::Control,
                    sqlx::query_scalar("SELECT password_hash FROM channels WHERE channel_id=$1")
                        .bind(&channel)
                        .fetch_optional(&mut *profile_read_connection),
                )
                .await
        }?
        .ok_or_else(|| control_error(404, "channel_not_found", "channel not found on gateway"))?;
        if !self
            .counters
            .profile
            .phase(
                Path::Control,
                Phase::Auth,
                verify_password_async(hash, password.into()),
            )
            .await?
        {
            return Err(control_error(
                403,
                "password_mismatch",
                "channel exists but password mismatch",
            ));
        }
        {
            let mut profile_read_connection = self
                .counters
                .profile
                .phase(Path::Control, Phase::PoolAcquire, self.acquire())
                .await?;
            let mut tx = profile_read_connection.begin().await?;
            Self::lock_usage(&mut tx).await?;
            let result = self
                .counters
                .profile
                .sql(
                    Path::Control,
                    Statement::Control,
                    sqlx::query("UPDATE channels SET channel_name=$1 WHERE channel_id=$2")
                        .bind(name)
                        .bind(&channel)
                        .execute(&mut *tx),
                )
                .await?;
            self.health.ensure()?;
            tx.commit().await?;
            let _ = result;
        }
        Ok(json!({"channel_id":channel,"channel_name":name}))
    }
    pub async fn sync_channels(&self, device: &str, items: Vec<(String, String)>) -> Result<Value> {
        if items.len() > 2000 {
            return Err(control_error(
                400,
                "channels_limit_exceeded",
                "channels exceeds max limit 2000",
            ));
        }
        let device = device.trim();
        let _gate = self
            .counters
            .profile
            .phase(Path::Control, Phase::GateWait, self.gate.lock())
            .await;
        let _gate_hold = self.counters.profile.timer(Path::Control, Phase::GateHold);
        self.health.ensure()?;
        let route = self.active_route(device).await?;
        let mut results = Vec::with_capacity(items.len());
        let mut desired = Vec::with_capacity(items.len());
        for (raw, password) in items {
            let channel = match crate::sender::channel_id(&raw) {
                Ok(channel) => channel,
                Err(error) => {
                    results.push(sync_failure(
                        raw.trim(),
                        400,
                        "invalid_channel_id",
                        &error.to_string(),
                    ));
                    continue;
                }
            };
            if let Err(error) = crate::sender::password(&password) {
                results.push(sync_failure(
                    &channel,
                    400,
                    "invalid_password",
                    &error.to_string(),
                ));
                continue;
            }
            match self
                .subscribe_under_gate(device, Some(&channel), None, &password)
                .await
            {
                Ok(value) => {
                    desired.push(channel);
                    results.push(value);
                }
                Err(KernelError::Control {
                    status,
                    code,
                    message,
                }) => {
                    let code = if code == "provider_token_required" {
                        "provider_token_missing"
                    } else {
                        code
                    };
                    results.push(sync_failure(&channel, status, code, &message));
                }
                Err(error) => return Err(error),
            }
        }
        let success = desired.len();
        let total = results.len();
        if success == total {
            let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
                "DELETE FROM channel_subscriptions WHERE device_key=",
            );
            query.push_bind(device);
            if !desired.is_empty() {
                query.push(" AND channel_id NOT IN (");
                let mut separated = query.separated(",");
                for id in desired {
                    separated.push_bind(id);
                }
                separated.push_unseparated(")");
            }
            {
                let mut profile_read_connection = self
                    .counters
                    .profile
                    .phase(Path::Control, Phase::PoolAcquire, self.acquire())
                    .await?;
                let mut tx = profile_read_connection.begin().await?;
                Self::lock_usage(&mut tx).await?;
                let result = self
                    .counters
                    .profile
                    .sql(
                        Path::Control,
                        Statement::Control,
                        query.build().execute(&mut *tx),
                    )
                    .await?;
                self.health.ensure()?;
                tx.commit().await?;
                let _ = result;
            }
        }
        Ok(
            json!({"device_key":device,"route":route,"total":total,"success":success,"failed":total-success,"channels":results}),
        )
    }
}

fn registration_response(
    row: &sqlx::postgres::PgRow,
    issued: bool,
    reason: Option<&str>,
) -> Result<Value> {
    let revision = row.get::<i64, _>("route_revision");
    let channel = row
        .get::<Option<String>, _>("provider")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| "private".into());
    let mut result = json!({"device_key":row.get::<String,_>("device_key"),"issued_new_key":issued,"route_revision":revision,"route":{"channel_type":channel,"route_revision":revision,"provider_token_present":row.get::<Option<String>,_>("provider_token").is_some()}});
    if let Some(reason) = reason {
        result["issue_reason"] = reason.into();
    }
    Ok(result)
}
