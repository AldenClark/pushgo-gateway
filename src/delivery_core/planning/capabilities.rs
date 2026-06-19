#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReceiverCapability {
    PrivateRealtime,
    PrivateOutbox,
    ProviderInline,
    ProviderWakeupPull,
    MqttReceiver,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ReceiverCapabilities {
    capabilities: Vec<ReceiverCapability>,
}

impl ReceiverCapabilities {
    pub(crate) fn new(capabilities: Vec<ReceiverCapability>) -> Self {
        Self { capabilities }
    }

    pub(crate) fn contains(&self, capability: ReceiverCapability) -> bool {
        self.capabilities.contains(&capability)
    }
}
