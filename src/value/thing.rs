use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{ValueError, ValueResult};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ExternalIdKey(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThingLocation {
    kind: ThingLocationKind,
    value: ThingLocationValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThingLocationKind {
    Physical,
    Geo,
    Cloud,
    Datacenter,
    Logical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ThingLocationValue {
    Physical(String),
    Geo(GeoLocation),
    Cloud(CloudLocation),
    Datacenter(DatacenterLocation),
    Logical(LogicalLocation),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GeoLocation {
    lat_micros: i32,
    lng_micros: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CloudLocation {
    provider: String,
    region: String,
    zone: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DatacenterLocation {
    site: String,
    room: Option<String>,
    rack: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LogicalLocation {
    segments: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ThingLocationWire {
    #[serde(rename = "type")]
    location_type: String,
    value: String,
}

impl ExternalIdKey {
    pub(crate) fn parse(raw: &str) -> ValueResult<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ValueError::new("external_ids contains empty key"));
        }
        if trimmed.len() > 64 {
            return Err(ValueError::new("external_ids contains oversized key"));
        }
        if !trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | ':' | '.'))
        {
            return Err(ValueError::new("external_ids key format is invalid"));
        }
        Ok(Self(trimmed.to_ascii_lowercase()))
    }

    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}

impl ThingLocation {
    pub(crate) fn parse_patch(
        location_type: Option<&str>,
        location_value: Option<&str>,
    ) -> ValueResult<Option<Self>> {
        match (location_type, location_value) {
            (None, None) => Ok(None),
            (Some(_), None) | (None, Some(_)) => Err(ValueError::new(
                "location_type and location_value must be provided together",
            )),
            (Some(location_type), Some(location_value)) => {
                Ok(Some(Self::parse_pair(location_type, location_value)?))
            }
        }
    }

    pub(crate) fn parse_pair(location_type: &str, location_value: &str) -> ValueResult<Self> {
        let kind = ThingLocationKind::parse(location_type)?;
        let value = match kind {
            ThingLocationKind::Physical => {
                ThingLocationValue::Physical(parse_non_empty_text(location_value)?)
            }
            ThingLocationKind::Geo => ThingLocationValue::Geo(GeoLocation::parse(location_value)?),
            ThingLocationKind::Cloud => {
                ThingLocationValue::Cloud(CloudLocation::parse(location_value)?)
            }
            ThingLocationKind::Datacenter => {
                ThingLocationValue::Datacenter(DatacenterLocation::parse(location_value)?)
            }
            ThingLocationKind::Logical => {
                ThingLocationValue::Logical(LogicalLocation::parse(location_value)?)
            }
        };
        Ok(Self { kind, value })
    }

    pub(crate) fn location_type(&self) -> &'static str {
        self.kind.as_str()
    }

    pub(crate) fn value_text(&self) -> String {
        self.value.as_text()
    }
}

impl ThingLocationKind {
    fn parse(raw: &str) -> ValueResult<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "physical" => Ok(Self::Physical),
            "geo" => Ok(Self::Geo),
            "cloud" => Ok(Self::Cloud),
            "datacenter" => Ok(Self::Datacenter),
            "logical" => Ok(Self::Logical),
            _ => Err(ValueError::new(
                "location_type must be one of physical|geo|cloud|datacenter|logical",
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Physical => "physical",
            Self::Geo => "geo",
            Self::Cloud => "cloud",
            Self::Datacenter => "datacenter",
            Self::Logical => "logical",
        }
    }
}

impl ThingLocationValue {
    fn as_text(&self) -> String {
        match self {
            Self::Physical(value) => value.clone(),
            Self::Geo(value) => value.as_text(),
            Self::Cloud(value) => value.as_text(),
            Self::Datacenter(value) => value.as_text(),
            Self::Logical(value) => value.as_text(),
        }
    }
}

impl GeoLocation {
    fn parse(raw: &str) -> ValueResult<Self> {
        let trimmed = raw.trim();
        let Some((raw_lat, raw_lng)) = trimmed.split_once(',') else {
            return Err(ValueError::new(
                "geo location_value must be formatted as <lat>,<lng>",
            ));
        };
        let lat = parse_geo_component(raw_lat, -90.0, 90.0, "geo lat")?;
        let lng = parse_geo_component(raw_lng, -180.0, 180.0, "geo lng")?;
        Ok(Self {
            lat_micros: lat,
            lng_micros: lng,
        })
    }

    fn as_text(&self) -> String {
        format!(
            "{:.6},{:.6}",
            self.lat_micros as f64 / 1_000_000.0,
            self.lng_micros as f64 / 1_000_000.0
        )
    }
}

impl CloudLocation {
    fn parse(raw: &str) -> ValueResult<Self> {
        let parts = split_token_parts(raw, ':', 2, 3, "cloud")?;
        Ok(Self {
            provider: parts[0].clone(),
            region: parts[1].clone(),
            zone: parts.get(2).cloned(),
        })
    }

    fn as_text(&self) -> String {
        match &self.zone {
            Some(zone) => format!("{}:{}:{zone}", self.provider, self.region),
            None => format!("{}:{}", self.provider, self.region),
        }
    }
}

impl DatacenterLocation {
    fn parse(raw: &str) -> ValueResult<Self> {
        let parts = split_token_parts(raw, ':', 1, 3, "datacenter")?;
        Ok(Self {
            site: parts[0].clone(),
            room: parts.get(1).cloned(),
            rack: parts.get(2).cloned(),
        })
    }

    fn as_text(&self) -> String {
        let mut parts = vec![self.site.clone()];
        if let Some(room) = &self.room {
            parts.push(room.clone());
        }
        if let Some(rack) = &self.rack {
            parts.push(rack.clone());
        }
        parts.join(":")
    }
}

impl LogicalLocation {
    fn parse(raw: &str) -> ValueResult<Self> {
        let segments = split_token_parts(raw, '/', 1, usize::MAX, "logical")?;
        Ok(Self { segments })
    }

    fn as_text(&self) -> String {
        self.segments.join("/")
    }
}

impl Serialize for ThingLocation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ThingLocationWire {
            location_type: self.location_type().to_string(),
            value: self.value_text(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ThingLocation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ThingLocationWire::deserialize(deserializer)?;
        Self::parse_pair(wire.location_type.as_str(), wire.value.as_str())
            .map_err(serde::de::Error::custom)
    }
}

fn parse_non_empty_text(raw: &str) -> ValueResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ValueError::new("location_value must not be empty"));
    }
    if trimmed.len() > 256 {
        return Err(ValueError::new("location_value is too long"));
    }
    Ok(trimmed.to_string())
}

fn parse_geo_component(raw: &str, min: f64, max: f64, label: &'static str) -> ValueResult<i32> {
    let value = raw
        .trim()
        .parse::<f64>()
        .map_err(|_| ValueError::new(format!("{label} must be a number")))?;
    if !value.is_finite() || !(min..=max).contains(&value) {
        return Err(ValueError::new(format!("{label} out of range")));
    }
    Ok((value * 1_000_000.0).round() as i32)
}

fn split_token_parts(
    raw: &str,
    separator: char,
    min_parts: usize,
    max_parts: usize,
    label: &'static str,
) -> ValueResult<Vec<String>> {
    let trimmed = raw.trim();
    let parts = trimmed
        .split(separator)
        .map(parse_token)
        .collect::<ValueResult<Vec<_>>>()?;
    if parts.len() < min_parts || parts.len() > max_parts {
        let message = match label {
            "cloud" => "cloud location_value must be provider:region[:zone]",
            "datacenter" => "datacenter location_value must be site[:room[:rack]]",
            "logical" => "logical location_value must be slash-separated tokens",
            _ => "location_value token format is invalid",
        };
        return Err(ValueError::new(message));
    }
    Ok(parts)
}

fn parse_token(raw: &str) -> ValueResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return Err(ValueError::new("location_value token format is invalid"));
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        return Err(ValueError::new("location_value token format is invalid"));
    }
    Ok(trimmed.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::{ThingLocation, ThingLocationKind};

    #[test]
    fn external_location_patch_requires_type_and_value_together() {
        let err = ThingLocation::parse_patch(Some("geo"), None).expect_err("pair required");
        assert_eq!(
            err.to_string(),
            "location_type and location_value must be provided together"
        );
    }

    #[test]
    fn geo_location_normalizes_precision() {
        let location =
            ThingLocation::parse_pair("geo", " 31.230416 , 121.473701 ").expect("geo parse");
        assert_eq!(location.location_type(), ThingLocationKind::Geo.as_str());
        assert_eq!(location.value_text(), "31.230416,121.473701");
    }

    #[test]
    fn cloud_location_lowercases_tokens() {
        let location =
            ThingLocation::parse_pair("cloud", "AWS:CN-NORTH-1:AZ1").expect("cloud parse");
        assert_eq!(location.location_type(), "cloud");
        assert_eq!(location.value_text(), "aws:cn-north-1:az1");
    }

    #[test]
    fn logical_location_rejects_invalid_token() {
        let err = ThingLocation::parse_pair("logical", "region/app space")
            .expect_err("invalid logical token should fail");
        assert_eq!(err.to_string(), "location_value token format is invalid");
    }

    #[test]
    fn thing_location_serializes_as_type_and_value() {
        let location =
            ThingLocation::parse_pair("datacenter", "sh1:r2:r10").expect("datacenter parse");
        let encoded = serde_json::to_value(&location).expect("location should serialize");
        assert_eq!(encoded["type"], "datacenter");
        assert_eq!(encoded["value"], "sh1:r2:r10");
    }
}
