CREATE TABLE IF NOT EXISTS messages(delivery_id TEXT COLLATE "C" PRIMARY KEY,message_id TEXT COLLATE "C" NOT NULL UNIQUE,op_id TEXT COLLATE "C" NOT NULL UNIQUE,channel_id TEXT COLLATE "C" NOT NULL,fingerprint TEXT COLLATE "C" NOT NULL,payload_blob BYTEA NOT NULL,payload_bytes BIGINT NOT NULL,accepted_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,dedupe_until BIGINT NOT NULL,status TEXT COLLATE "C" NOT NULL,updated_at BIGINT NOT NULL,pending_targets BIGINT NOT NULL DEFAULT 0,provider_accepted_count BIGINT NOT NULL DEFAULT 0,provider_failed_count BIGINT NOT NULL DEFAULT 0,provider_target_count BIGINT NOT NULL DEFAULT 0,private_enqueued_count BIGINT NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS targets(delivery_id TEXT COLLATE "C" NOT NULL REFERENCES messages(delivery_id) ON DELETE CASCADE,device_key TEXT COLLATE "C" NOT NULL,pull_owner TEXT COLLATE "C" NOT NULL DEFAULT '',owner_generation BIGINT NOT NULL DEFAULT 0,control_epoch BIGINT NOT NULL DEFAULT 0,platform TEXT COLLATE "C" NOT NULL,provider TEXT COLLATE "C" NOT NULL,provider_token TEXT COLLATE "C" NOT NULL,route_generation BIGINT NOT NULL DEFAULT 0,accepted_at BIGINT NOT NULL DEFAULT 0,state TEXT COLLATE "C" NOT NULL,next_attempt_at BIGINT NOT NULL,attempts BIGINT NOT NULL DEFAULT 0,attempt_id BIGINT NOT NULL DEFAULT 0,provider_status BIGINT,provider_error TEXT COLLATE "C",receipt_at BIGINT,acked_at BIGINT,delivery_mode TEXT COLLATE "C" NOT NULL DEFAULT 'provider',delivery_epoch BIGINT NOT NULL DEFAULT 0,private_claim TEXT COLLATE "C",private_group TEXT COLLATE "C",PRIMARY KEY(delivery_id,device_key));
CREATE INDEX IF NOT EXISTS targets_due ON targets(provider,state,next_attempt_at,delivery_id);
CREATE INDEX IF NOT EXISTS targets_device ON targets(pull_owner,accepted_at,delivery_id) WHERE acked_at IS NULL;
CREATE INDEX IF NOT EXISTS messages_retention ON messages(dedupe_until);
CREATE INDEX IF NOT EXISTS messages_expiry ON messages(expires_at,delivery_id) WHERE payload_bytes>0;
CREATE TABLE IF NOT EXISTS ledger_usage(singleton BIGINT PRIMARY KEY CHECK(singleton=1),messages BIGINT NOT NULL,targets BIGINT NOT NULL,bytes BIGINT NOT NULL,control_epoch BIGINT NOT NULL DEFAULT 0,private_pending BIGINT NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS devices(device_key TEXT COLLATE "C" PRIMARY KEY,platform TEXT COLLATE "C" NOT NULL,provider TEXT COLLATE "C",provider_token TEXT COLLATE "C",route_generation BIGINT NOT NULL DEFAULT 0,route_revision BIGINT NOT NULL DEFAULT 1,retired_at BIGINT,coalesced_to TEXT COLLATE "C");
CREATE INDEX IF NOT EXISTS devices_retired ON devices(retired_at,device_key) WHERE retired_at IS NOT NULL;
CREATE TABLE IF NOT EXISTS registration_aliases(old_key TEXT COLLATE "C" PRIMARY KEY,new_key TEXT COLLATE "C" NOT NULL,platform TEXT COLLATE "C" NOT NULL,expires_at BIGINT NOT NULL);
CREATE INDEX IF NOT EXISTS registration_alias_expiry ON registration_aliases(expires_at);
CREATE TABLE IF NOT EXISTS channels(channel_id TEXT COLLATE "C" PRIMARY KEY,channel_name TEXT COLLATE "C" NOT NULL,password_hash TEXT COLLATE "C" NOT NULL);
CREATE TABLE IF NOT EXISTS channel_subscriptions(channel_id TEXT COLLATE "C" NOT NULL REFERENCES channels(channel_id),device_key TEXT COLLATE "C" NOT NULL REFERENCES devices(device_key),PRIMARY KEY(channel_id,device_key));
CREATE INDEX IF NOT EXISTS subscriptions_device ON channel_subscriptions(device_key,channel_id);
CREATE TABLE IF NOT EXISTS retired_provider_tokens(platform TEXT COLLATE "C" NOT NULL,provider_token TEXT COLLATE "C" NOT NULL,control_epoch BIGINT NOT NULL,PRIMARY KEY(platform,provider_token));
CREATE INDEX IF NOT EXISTS targets_owner_delivery ON targets(pull_owner,delivery_id,device_key) WHERE acked_at IS NULL;
CREATE INDEX IF NOT EXISTS targets_token_retirement ON targets(platform,provider_token,control_epoch);
CREATE TABLE IF NOT EXISTS provider_cooldowns(provider TEXT COLLATE "C" PRIMARY KEY,next_attempt_at BIGINT NOT NULL);
INSERT INTO ledger_usage(singleton,messages,targets,bytes) VALUES(1,0,0,0) ON CONFLICT(singleton) DO NOTHING;

-- All counters have one owner: these row triggers, including cascaded deletes.
CREATE OR REPLACE FUNCTION messages_usage() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE old_live BIGINT:=0; new_live BIGINT:=0; old_bytes BIGINT:=0; new_bytes BIGINT:=0;
BEGIN
 IF TG_OP <> 'INSERT' THEN old_live := (OLD.pending_targets>0)::int; old_bytes:=OLD.payload_bytes; END IF;
 IF TG_OP <> 'DELETE' THEN new_live := (NEW.pending_targets>0)::int; new_bytes:=NEW.payload_bytes; END IF;
 UPDATE ledger_usage SET messages=messages+new_live-old_live,bytes=bytes+new_bytes-old_bytes WHERE singleton=1;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS messages_usage ON messages;
CREATE TRIGGER messages_usage AFTER INSERT OR UPDATE OR DELETE ON messages FOR EACH ROW EXECUTE FUNCTION messages_usage();
CREATE OR REPLACE FUNCTION targets_usage() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE old_live BIGINT:=0; new_live BIGINT:=0; id TEXT;
BEGIN
 IF TG_OP <> 'INSERT' THEN old_live := (OLD.acked_at IS NULL AND (OLD.delivery_mode='private' OR OLD.state IN ('pending','running','retry_wait')))::int; id:=OLD.delivery_id; END IF;
 IF TG_OP <> 'DELETE' THEN new_live := (NEW.acked_at IS NULL AND (NEW.delivery_mode='private' OR NEW.state IN ('pending','running','retry_wait')))::int; id:=NEW.delivery_id; END IF;
 IF new_live <> old_live THEN
  UPDATE ledger_usage SET targets=targets+new_live-old_live WHERE singleton=1;
  UPDATE messages SET pending_targets=pending_targets+new_live-old_live WHERE delivery_id=id;
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS targets_usage ON targets;
CREATE TRIGGER targets_usage AFTER INSERT OR UPDATE OR DELETE ON targets FOR EACH ROW EXECUTE FUNCTION targets_usage();
CREATE OR REPLACE FUNCTION targets_owner() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.pull_owner='' THEN
  NEW.pull_owner:=NEW.device_key; NEW.owner_generation:=NEW.route_generation;
  SELECT control_epoch INTO NEW.control_epoch FROM ledger_usage WHERE singleton=1;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS targets_owner ON targets;
CREATE TRIGGER targets_owner BEFORE INSERT ON targets FOR EACH ROW EXECUTE FUNCTION targets_owner();
