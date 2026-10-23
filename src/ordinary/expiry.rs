//! One ordinary expiry boundary, after the existing ingress timestamp parser.
//!
//! `ttl` is an absolute Unix expiry, accepted as seconds or milliseconds and
//! normalized to milliseconds. Zero and negative values stay valid input; at
//! today's acceptance clock they are already expired, rather than a request
//! to bypass retention or to send a Provider-only no-store notification.
//! Omission, JSON null and an empty timestamp string use the configured default
//! at first durable acceptance (Small: seven days). Replay keeps that first
//! expiry and identity. The 30-day identity history is independent of this
//! payload / delivery expiry.

#[inline]
pub(crate) fn is_expired(expires_at: i64, at: i64) -> bool {
    expires_at <= at
}

#[cfg(test)]
mod tests {
    use super::is_expired;
    use crate::api::handlers::message::MessageIntent;
    use serde_json::{Value, json};

    fn parse(raw_ttl: Option<Value>) -> MessageIntent {
        let mut input = json!({
            "channel_id": crate::value::ChannelId::from([7; 16]).to_string(),
            "password": String::new(),
            "title": "ordinary expiry parser"
        });
        if let Some(ttl) = raw_ttl {
            input["ttl"] = ttl;
        }
        serde_json::from_value(input).unwrap()
    }

    #[test]
    fn exact_deadline_and_one_millisecond_after_are_expired() {
        assert!(!is_expired(1_000, 999));
        assert!(is_expired(1_000, 1_000));
        assert!(is_expired(1_000, 1_001));
        assert!(is_expired(0, 0));
        assert!(is_expired(-1, 0));
    }

    #[test]
    fn expiry_comparison_does_not_overflow_at_signed_boundaries() {
        assert!(is_expired(i64::MIN, i64::MAX));
        assert!(is_expired(i64::MAX, i64::MAX));
        assert!(!is_expired(i64::MAX, i64::MIN));
    }

    #[test]
    fn normal_message_parser_keeps_zero_and_normalizes_negative_seconds() {
        for (raw, expected) in [
            (json!(0), 0),
            (json!(-1), -1_000),
            (json!(-1_725_000_001_i64), -1_725_000_001_000),
            (json!(-1_725_000_001_000_i64), -1_725_000_001_000),
        ] {
            assert_eq!(parse(Some(raw)).ttl, Some(expected));
        }
    }

    #[test]
    fn normal_message_parser_agrees_for_seconds_milliseconds_and_numeric_strings() {
        for raw in [
            json!(1_725_000_001_i64),
            json!(1_725_000_001_000_i64),
            json!("1725000001"),
            json!("1725000001000"),
        ] {
            assert_eq!(parse(Some(raw)).ttl, Some(1_725_000_001_000));
        }
    }

    #[test]
    fn absent_null_and_empty_timestamp_select_the_runtime_default() {
        for raw in [None, Some(Value::Null), Some(json!(" "))] {
            assert_eq!(parse(raw).ttl, None);
        }
        assert_eq!(
            crate::ordinary::Config::default().default_ttl_secs,
            7 * 86_400
        );
        assert_eq!(
            crate::runtime_config::RuntimeTuning::for_profile(
                crate::runtime_config::GatewayRuntimeProfile::Small,
            )
            .private
            .default_ttl_secs,
            7 * 86_400
        );
    }
}
