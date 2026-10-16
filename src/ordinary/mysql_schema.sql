CREATE TABLE IF NOT EXISTS ordinary_messages(delivery_id VARCHAR(32) PRIMARY KEY,message_id VARCHAR(32) NOT NULL UNIQUE,op_id VARBINARY(128) NOT NULL UNIQUE,channel_id VARCHAR(26) NOT NULL,thing_id VARCHAR(64) NULL,fingerprint VARCHAR(128) NOT NULL,payload_blob LONGBLOB NOT NULL,payload_bytes BIGINT NOT NULL,has_payload TINYINT GENERATED ALWAYS AS (payload_bytes>0) STORED,usage_payload_bytes BIGINT NOT NULL DEFAULT 0,accepted_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,dedupe_until BIGINT NOT NULL,status VARCHAR(32) NOT NULL,updated_at BIGINT NOT NULL,pending_targets BIGINT NOT NULL DEFAULT 0,provider_accepted_count BIGINT NOT NULL DEFAULT 0,provider_failed_count BIGINT NOT NULL DEFAULT 0,provider_target_count BIGINT NOT NULL DEFAULT 0,private_enqueued_count BIGINT NOT NULL DEFAULT 0,private_rejected_count BIGINT NOT NULL DEFAULT 0,INDEX messages_retention(dedupe_until),INDEX messages_expiry(has_payload,expires_at,delivery_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS ordinary_targets(delivery_id VARCHAR(32) NOT NULL,device_key VARCHAR(255) NOT NULL,pull_owner VARCHAR(255) NOT NULL,owner_generation BIGINT NOT NULL DEFAULT 0,control_epoch BIGINT NOT NULL DEFAULT 0,platform VARCHAR(16) NOT NULL,provider VARCHAR(16) NOT NULL,provider_token TEXT NOT NULL,route_generation BIGINT NOT NULL DEFAULT 0,accepted_at BIGINT NOT NULL DEFAULT 0,watch_alert_deadline_at BIGINT NULL,state VARCHAR(32) NOT NULL,next_attempt_at BIGINT NOT NULL,attempts BIGINT NOT NULL DEFAULT 0,attempt_id BIGINT NOT NULL DEFAULT 0,provider_status BIGINT,provider_error TEXT,receipt_at BIGINT,acked_at BIGINT,delivery_mode VARCHAR(16) NOT NULL DEFAULT 'provider',delivery_epoch BIGINT NOT NULL DEFAULT 0,private_claim VARCHAR(32),private_group VARCHAR(128),PRIMARY KEY(delivery_id,device_key),FOREIGN KEY(delivery_id) REFERENCES ordinary_messages(delivery_id) ON DELETE CASCADE,INDEX targets_private_owner(pull_owner,delivery_mode,acked_at,private_claim,accepted_at,delivery_id,device_key),INDEX targets_private_logical(pull_owner,delivery_id,delivery_mode,acked_at,device_key),INDEX targets_private_group(private_group,private_claim),INDEX targets_private_recovery(private_claim,delivery_id,device_key),INDEX targets_due(provider,state,next_attempt_at,delivery_id,device_key),INDEX targets_device(pull_owner,accepted_at,delivery_id,acked_at),INDEX targets_owner_delivery(pull_owner,delivery_id,device_key,acked_at),INDEX targets_token_retirement(platform,provider_token(256),control_epoch)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS ordinary_ledger_usage(singleton BIGINT PRIMARY KEY CHECK(singleton=1),messages BIGINT NOT NULL,targets BIGINT NOT NULL,bytes BIGINT NOT NULL,control_epoch BIGINT NOT NULL DEFAULT 0,private_pending BIGINT NOT NULL DEFAULT 0) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS ordinary_retired_provider_tokens(marker_id BIGINT AUTO_INCREMENT PRIMARY KEY,platform VARCHAR(16) NOT NULL,provider_token TEXT NOT NULL,control_epoch BIGINT NOT NULL,INDEX retired_token(platform,provider_token(256),control_epoch)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS ordinary_provider_cooldowns(provider VARCHAR(16) PRIMARY KEY,next_attempt_at BIGINT NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
INSERT INTO ordinary_ledger_usage(singleton,messages,targets,bytes) VALUES(1,0,0,0) ON DUPLICATE KEY UPDATE singleton=singleton;

CREATE TABLE IF NOT EXISTS ordinary_private_usage(device_key VARCHAR(255) PRIMARY KEY,pending BIGINT NOT NULL DEFAULT 0) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- Body-free derived Widget refresh intent. It survives ordinary ACK and does
-- not own ordinary identity, content, recipients or sender delivery status.
CREATE TABLE IF NOT EXISTS ordinary_widget_refresh(delivery_id VARCHAR(32) NOT NULL PRIMARY KEY,channel_id BINARY(16) NOT NULL,coalesce_order BIGINT NOT NULL,accepted_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,UNIQUE KEY ordinary_widget_refresh_order(coalesce_order),UNIQUE KEY ordinary_widget_refresh_channel(channel_id),KEY ordinary_widget_refresh_expiry(expires_at,delivery_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- These views do not copy or own control state. Canonical normal-product
-- control rows are read by the same transaction that freezes recipients.
CREATE OR REPLACE VIEW ordinary_device_routes AS
SELECT device_id,device_key,platform COLLATE utf8mb4_bin AS platform,channel_type,route_updated_at,CASE WHEN watch_alert_window_minutes IN (5,15,30,60) THEN watch_alert_window_minutes ELSE 30 END AS watch_alert_window_minutes,
       CASE WHEN channel_type='private' THEN NULL
            WHEN platform='android' THEN 'FCM'
            WHEN platform IN ('ios','macos','watchos') THEN 'APNS'
            WHEN platform='windows' THEN 'WNS' ELSE NULL END COLLATE utf8mb4_bin AS provider,
       provider_token COLLATE utf8mb4_bin AS provider_token,ordinary_route_generation AS route_generation,route_revision,
       CAST(NULL AS SIGNED) AS retired_at,CAST(NULL AS CHAR(255)) AS coalesced_to
FROM devices WHERE device_key IS NOT NULL;
CREATE OR REPLACE VIEW ordinary_channel_routes AS
SELECT channel_id,password_hash FROM channels;
CREATE OR REPLACE VIEW ordinary_subscriptions AS
SELECT s.channel_id,s.device_id,d.device_key,s.created_at,s.updated_at
FROM channel_subscriptions s JOIN devices d ON d.device_id=s.device_id
WHERE s.status='active' AND d.device_key IS NOT NULL;

-- The epoch survives device deletion and re-registration; route_revision remains
-- the normal control protocol revision, including harmless repeated syncs.
UPDATE ordinary_ledger_usage SET control_epoch=GREATEST(control_epoch,COALESCE((SELECT MAX(ordinary_route_generation) FROM devices),0)) WHERE singleton=1;
DROP TRIGGER IF EXISTS ordinary_device_insert;
CREATE TRIGGER ordinary_device_insert BEFORE INSERT ON devices FOR EACH ROW
BEGIN
  IF NOT EXISTS(SELECT 1 FROM devices WHERE device_id=NEW.device_id) THEN
    UPDATE ordinary_ledger_usage SET control_epoch=control_epoch+1 WHERE singleton=1;
    SET NEW.ordinary_route_generation=(SELECT control_epoch FROM ordinary_ledger_usage WHERE singleton=1);
  END IF;
END;
DROP TRIGGER IF EXISTS ordinary_device_update;
CREATE TRIGGER ordinary_device_update BEFORE UPDATE ON devices FOR EACH ROW
BEGIN
  IF NOT (BINARY NEW.device_key <=> BINARY OLD.device_key)
     OR NOT (BINARY NEW.platform <=> BINARY OLD.platform)
     OR NOT (BINARY NEW.channel_type <=> BINARY OLD.channel_type)
     OR NOT (BINARY NEW.provider_token <=> BINARY OLD.provider_token) THEN
    UPDATE ordinary_ledger_usage SET control_epoch=control_epoch+1 WHERE singleton=1;
    SET NEW.ordinary_route_generation=(SELECT control_epoch FROM ordinary_ledger_usage WHERE singleton=1);
  ELSE
    SET NEW.ordinary_route_generation=OLD.ordinary_route_generation;
  END IF;
END;
