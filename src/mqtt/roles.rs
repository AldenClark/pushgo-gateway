#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MqttRole {
    IngressPublish,
    IngressWill,
    PrivateReceiver,
}

impl MqttRole {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::IngressPublish => "mqtt_ingress_publish",
            Self::IngressWill => "mqtt_ingress_will",
            Self::PrivateReceiver => "mqtt_private_receiver",
        }
    }
}

#[cfg(test)]
pub(crate) const MQTT_EXTERNAL_BRIDGE_IN_ROLE: &str = "mqtt_external_bridge_in";
#[cfg(test)]
pub(crate) const MQTT_EXTERNAL_BRIDGE_OUT_ROLE: &str = "mqtt_external_bridge_out";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mqtt_roles_are_explicit_and_stable() {
        assert_eq!(MqttRole::IngressPublish.as_str(), "mqtt_ingress_publish");
        assert_eq!(MqttRole::IngressWill.as_str(), "mqtt_ingress_will");
        assert_eq!(MqttRole::PrivateReceiver.as_str(), "mqtt_private_receiver");
        assert_eq!(MQTT_EXTERNAL_BRIDGE_IN_ROLE, "mqtt_external_bridge_in");
        assert_eq!(MQTT_EXTERNAL_BRIDGE_OUT_ROLE, "mqtt_external_bridge_out");
    }
}
