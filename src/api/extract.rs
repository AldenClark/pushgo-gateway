use std::{borrow::Cow, str::FromStr};

use axum::extract::{FromRequest, Json, Request};
use serde::{Deserialize, de::DeserializeOwned, de::Error as _, de::Visitor};

use super::Error;

pub(crate) struct ApiJson<T>(pub(crate) T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = Error;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(ApiJson(value)),
            Err(rejection) => Err(Error::from_json_rejection(rejection)),
        }
    }
}

pub(crate) fn deserialize_empty_as_none<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: FromStr,
    T::Err: std::fmt::Display,
{
    let raw: Option<Cow<'de, str>> = Option::deserialize(deserializer)?;

    match raw {
        None => Ok(None),
        Some(s) => {
            let t = s.trim();
            if t.is_empty() {
                Ok(None)
            } else {
                T::from_str(t).map(Some).map_err(D::Error::custom)
            }
        }
    }
}

pub(crate) fn deserialize_i64_lenient<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct LenientI64Visitor;

    impl<'de> Visitor<'de> for LenientI64Visitor {
        type Value = Option<i64>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("an i64, a numeric string, or null")
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
            Ok(Some(value))
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            i64::try_from(value).map(Some).map_err(E::custom)
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            trimmed.parse::<i64>().map(Some).map_err(E::custom)
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            self.visit_str(&value)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_none<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
    }

    deserializer.deserialize_any(LenientI64Visitor)
}

fn normalize_unix_timestamp_millis(value: i64) -> i64 {
    const MILLIS_THRESHOLD: i64 = 1_000_000_000_000;
    if value.unsigned_abs() >= MILLIS_THRESHOLD as u64 {
        value
    } else {
        value.saturating_mul(1000)
    }
}

pub(crate) fn deserialize_unix_ts_millis_lenient<'de, D>(
    deserializer: D,
) -> Result<Option<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_i64_lenient(deserializer)
        .map(|value| value.map(normalize_unix_timestamp_millis))
}

#[cfg(test)]
mod tests {
    use super::deserialize_unix_ts_millis_lenient;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct TsPayload {
        #[serde(default, deserialize_with = "deserialize_unix_ts_millis_lenient")]
        ts: Option<i64>,
    }

    #[test]
    fn deserialize_unix_ts_millis_lenient_accepts_seconds() {
        let payload: TsPayload =
            serde_json::from_str(r#"{"ts":1710000000}"#).expect("json should parse");
        assert_eq!(payload.ts, Some(1_710_000_000_000));
    }

    #[test]
    fn deserialize_unix_ts_millis_lenient_keeps_milliseconds() {
        let payload: TsPayload =
            serde_json::from_str(r#"{"ts":1710000000123}"#).expect("json should parse");
        assert_eq!(payload.ts, Some(1_710_000_000_123));
    }

    #[test]
    fn deserialize_unix_ts_millis_lenient_accepts_numeric_string() {
        let payload: TsPayload =
            serde_json::from_str(r#"{"ts":"1710000000456"}"#).expect("json should parse");
        assert_eq!(payload.ts, Some(1_710_000_000_456));
    }
}
