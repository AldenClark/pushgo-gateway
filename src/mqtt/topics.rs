use crate::api::{ChannelId, Error};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MqttMessageTopic {
    pub channel_id: ChannelId,
}

impl MqttMessageTopic {
    pub const PREFIX: &'static str = "pushgo";
    pub const RESOURCE: &'static str = "messages";

    pub fn parse(raw: &str) -> Result<Self, Error> {
        if raw.contains('#') || raw.contains('+') || raw.starts_with("$share/") {
            return Err(Error::validation_code(
                "wildcard and shared subscriptions are not supported",
                "mqtt_topic_filter_not_supported",
            ));
        }
        let mut parts = raw.split('/');
        let Some(prefix) = parts.next() else {
            return Err(Self::invalid());
        };
        let Some(channel_id_raw) = parts.next() else {
            return Err(Self::invalid());
        };
        let Some(resource) = parts.next() else {
            return Err(Self::invalid());
        };
        if parts.next().is_some() || prefix != Self::PREFIX || resource != Self::RESOURCE {
            return Err(Self::invalid());
        }
        Ok(Self {
            channel_id: ChannelId::parse(channel_id_raw)?,
        })
    }

    pub fn format(channel_id: &str) -> String {
        format!("{}/{}/{}", Self::PREFIX, channel_id, Self::RESOURCE)
    }

    fn invalid() -> Error {
        Error::validation_code("invalid MQTT topic", "mqtt_topic_invalid")
    }
}

#[cfg(test)]
mod tests {
    use super::MqttMessageTopic;

    const CHANNEL_ID: &str = "06J0FZG1Y8XGG14VTQ4Y3G10MR";

    #[test]
    fn parses_message_topic() {
        let topic = MqttMessageTopic::parse(&format!("pushgo/{CHANNEL_ID}/messages"))
            .expect("message topic should parse");
        assert_eq!(topic.channel_id.to_string(), CHANNEL_ID);
    }

    #[test]
    fn rejects_other_models_and_wildcards() {
        assert!(MqttMessageTopic::parse(&format!("pushgo/{CHANNEL_ID}/events")).is_err());
        assert!(MqttMessageTopic::parse("pushgo/+/messages").is_err());
        assert!(MqttMessageTopic::parse("$share/group/pushgo/x/messages").is_err());
    }

    #[test]
    fn formats_message_topic() {
        assert_eq!(
            MqttMessageTopic::format(CHANNEL_ID),
            format!("pushgo/{CHANNEL_ID}/messages")
        );
    }
}
