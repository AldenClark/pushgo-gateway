CREATE TABLE IF NOT EXISTS ordinary_messages(delivery_id TEXT COLLATE "C" PRIMARY KEY,message_id TEXT COLLATE "C" NOT NULL UNIQUE,op_id TEXT COLLATE "C" NOT NULL UNIQUE,channel_id TEXT COLLATE "C" NOT NULL,fingerprint TEXT COLLATE "C" NOT NULL,payload_blob BYTEA NOT NULL,payload_bytes BIGINT NOT NULL,accepted_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,dedupe_until BIGINT NOT NULL,status TEXT COLLATE "C" NOT NULL,updated_at BIGINT NOT NULL,pending_targets BIGINT NOT NULL DEFAULT 0,provider_accepted_count BIGINT NOT NULL DEFAULT 0,provider_failed_count BIGINT NOT NULL DEFAULT 0,provider_target_count BIGINT NOT NULL DEFAULT 0,private_enqueued_count BIGINT NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS ordinary_targets(delivery_id TEXT COLLATE "C" NOT NULL REFERENCES ordinary_messages(delivery_id) ON DELETE CASCADE,device_key TEXT COLLATE "C" NOT NULL,pull_owner TEXT COLLATE "C" NOT NULL DEFAULT '',owner_generation BIGINT NOT NULL DEFAULT 0,control_epoch BIGINT NOT NULL DEFAULT 0,platform TEXT COLLATE "C" NOT NULL,provider TEXT COLLATE "C" NOT NULL,provider_token TEXT COLLATE "C" NOT NULL,route_generation BIGINT NOT NULL DEFAULT 0,accepted_at BIGINT NOT NULL DEFAULT 0,state TEXT COLLATE "C" NOT NULL,next_attempt_at BIGINT NOT NULL,attempts BIGINT NOT NULL DEFAULT 0,attempt_id BIGINT NOT NULL DEFAULT 0,provider_status BIGINT,provider_error TEXT COLLATE "C",receipt_at BIGINT,acked_at BIGINT,delivery_mode TEXT COLLATE "C" NOT NULL DEFAULT 'provider',delivery_epoch BIGINT NOT NULL DEFAULT 0,private_claim TEXT COLLATE "C",private_group TEXT COLLATE "C",PRIMARY KEY(delivery_id,device_key));
CREATE INDEX IF NOT EXISTS ordinary_targets_due ON ordinary_targets(provider,state,next_attempt_at,delivery_id);
CREATE INDEX IF NOT EXISTS ordinary_targets_device ON ordinary_targets(pull_owner,accepted_at,delivery_id) WHERE acked_at IS NULL;
CREATE INDEX IF NOT EXISTS ordinary_messages_retention ON ordinary_messages(dedupe_until);
CREATE INDEX IF NOT EXISTS ordinary_messages_expiry ON ordinary_messages(expires_at,delivery_id) WHERE payload_bytes>0;
CREATE TABLE IF NOT EXISTS ordinary_ledger_usage(singleton BIGINT PRIMARY KEY CHECK(singleton=1),messages BIGINT NOT NULL,targets BIGINT NOT NULL,bytes BIGINT NOT NULL,control_epoch BIGINT NOT NULL DEFAULT 0,private_pending BIGINT NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS ordinary_retired_provider_tokens(platform TEXT COLLATE "C" NOT NULL,provider_token TEXT COLLATE "C" NOT NULL,control_epoch BIGINT NOT NULL,PRIMARY KEY(platform,provider_token));
CREATE INDEX IF NOT EXISTS ordinary_targets_owner_delivery ON ordinary_targets(pull_owner,delivery_id,device_key) WHERE acked_at IS NULL;
CREATE INDEX IF NOT EXISTS ordinary_targets_token_retirement ON ordinary_targets(platform,provider_token,control_epoch);
CREATE TABLE IF NOT EXISTS ordinary_provider_cooldowns(provider TEXT COLLATE "C" PRIMARY KEY,next_attempt_at BIGINT NOT NULL);
-- A pending derived Widget refresh is not a second ordinary message/body.
-- No FK: a client ACK may release ordinary content before projection finishes.
CREATE TABLE IF NOT EXISTS ordinary_widget_refresh(delivery_id TEXT COLLATE "C" PRIMARY KEY,channel_id BYTEA NOT NULL CHECK(octet_length(channel_id)=16),acceptance_order BIGINT NOT NULL UNIQUE,accepted_at BIGINT NOT NULL,expires_at BIGINT NOT NULL);
INSERT INTO ordinary_ledger_usage(singleton,messages,targets,bytes) VALUES(1,0,0,0) ON CONFLICT(singleton) DO NOTHING;

-- All counters have one owner: these row triggers, including cascaded deletes.
CREATE OR REPLACE FUNCTION ordinary_messages_usage() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE old_live BIGINT:=0; new_live BIGINT:=0; old_bytes BIGINT:=0; new_bytes BIGINT:=0;
BEGIN
 IF TG_OP <> 'INSERT' THEN old_live := (OLD.pending_targets>0)::int; old_bytes:=OLD.payload_bytes; END IF;
 IF TG_OP <> 'DELETE' THEN new_live := (NEW.pending_targets>0)::int; new_bytes:=NEW.payload_bytes; END IF;
 UPDATE ordinary_ledger_usage SET messages=messages+new_live-old_live,bytes=bytes+new_bytes-old_bytes WHERE singleton=1;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS ordinary_messages_usage ON ordinary_messages;
CREATE TRIGGER ordinary_messages_usage AFTER INSERT OR UPDATE OR DELETE ON ordinary_messages FOR EACH ROW EXECUTE FUNCTION ordinary_messages_usage();
CREATE OR REPLACE FUNCTION ordinary_targets_usage() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE old_live BIGINT:=0; new_live BIGINT:=0; id TEXT;
BEGIN
 IF TG_OP <> 'INSERT' THEN old_live := (OLD.acked_at IS NULL AND (OLD.delivery_mode='private' OR OLD.state IN ('pending','running','retry_wait')))::int; id:=OLD.delivery_id; END IF;
 IF TG_OP <> 'DELETE' THEN new_live := (NEW.acked_at IS NULL AND (NEW.delivery_mode='private' OR NEW.state IN ('pending','running','retry_wait')))::int; id:=NEW.delivery_id; END IF;
 IF new_live <> old_live THEN
  UPDATE ordinary_ledger_usage SET targets=targets+new_live-old_live WHERE singleton=1;
  UPDATE ordinary_messages SET pending_targets=pending_targets+new_live-old_live WHERE delivery_id=id;
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS ordinary_targets_usage ON ordinary_targets;
CREATE TRIGGER ordinary_targets_usage AFTER INSERT OR UPDATE OR DELETE ON ordinary_targets FOR EACH ROW EXECUTE FUNCTION ordinary_targets_usage();
CREATE OR REPLACE FUNCTION ordinary_targets_owner() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.pull_owner='' THEN
  NEW.pull_owner:=NEW.device_key; NEW.owner_generation:=NEW.route_generation;
  SELECT control_epoch INTO NEW.control_epoch FROM ordinary_ledger_usage WHERE singleton=1;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS ordinary_targets_owner ON ordinary_targets;
CREATE TRIGGER ordinary_targets_owner BEFORE INSERT ON ordinary_targets FOR EACH ROW EXECUTE FUNCTION ordinary_targets_owner();

-- These views contain no persisted control state. The normal product records
-- remain the sole authority for channels, active subscriptions and routes.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS ordinary_route_generation BIGINT NOT NULL DEFAULT 0;
CREATE OR REPLACE VIEW ordinary_device_routes AS
 SELECT device_key,platform,
  CASE WHEN lower(channel_type)='private' THEN NULL
       WHEN lower(platform)='android' THEN 'FCM'
       WHEN lower(platform) IN ('ios','ipados','macos','watchos') THEN 'APNS'
       WHEN lower(platform)='windows' THEN 'WNS' ELSE NULL END AS provider,
  provider_token,ordinary_route_generation AS route_generation,route_revision,
  NULL::BIGINT AS retired_at,NULL::TEXT AS coalesced_to,
  watch_alert_window_minutes,device_id,channel_type,route_updated_at
 FROM devices WHERE device_key IS NOT NULL AND platform IS NOT NULL AND channel_type IS NOT NULL;
CREATE OR REPLACE VIEW ordinary_channel_routes AS
 SELECT encode(channel_id,'hex') AS channel_id,password_hash,alias AS channel_name FROM channels;
CREATE OR REPLACE VIEW ordinary_subscriptions AS
 SELECT encode(s.channel_id,'hex') AS channel_id,d.device_key,s.created_at,s.updated_at,s.device_id
 FROM channel_subscriptions s JOIN devices d ON d.device_id=s.device_id
 WHERE s.status='active' AND d.device_key IS NOT NULL AND d.platform IS NOT NULL
  AND ((lower(d.channel_type)='private' AND octet_length(d.device_id)=16)
       OR (lower(d.channel_type)<>'private' AND d.route_updated_at IS NOT NULL
           AND lower(d.platform) IN ('android','ios','ipados','macos','watchos','windows')
           AND d.provider_token IS NOT NULL AND btrim(d.provider_token)<>''));

ALTER TABLE ordinary_targets ADD COLUMN IF NOT EXISTS watch_alert_deadline_at BIGINT;
ALTER TABLE ordinary_messages ADD COLUMN IF NOT EXISTS private_rejected_count BIGINT NOT NULL DEFAULT 0;
ALTER TABLE ordinary_messages ADD COLUMN IF NOT EXISTS thing_id TEXT COLLATE "C";

-- A durable monotonic generation belongs to the canonical route. Replaying a
-- sync does not change it; deleting then registering the same key cannot revive
-- an old frozen Provider capability.
CREATE OR REPLACE FUNCTION ordinary_canonical_route_generation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' OR NEW.ordinary_route_generation=0
    OR NEW.platform IS DISTINCT FROM OLD.platform
    OR NEW.channel_type IS DISTINCT FROM OLD.channel_type
    OR NEW.provider_token IS DISTINCT FROM OLD.provider_token THEN
  UPDATE ordinary_ledger_usage SET control_epoch=control_epoch+1 WHERE singleton=1
   RETURNING control_epoch INTO NEW.ordinary_route_generation;
 ELSE
  NEW.ordinary_route_generation:=OLD.ordinary_route_generation;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS ordinary_canonical_route_generation ON devices;
CREATE TRIGGER ordinary_canonical_route_generation BEFORE INSERT OR UPDATE ON devices
 FOR EACH ROW EXECUTE FUNCTION ordinary_canonical_route_generation();
UPDATE devices SET ordinary_route_generation=0 WHERE ordinary_route_generation=0;
