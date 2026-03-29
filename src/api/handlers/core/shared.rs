use crate::{api::Error, device_registry::DeviceChannelType, storage::Platform};

pub(super) fn normalized_optional_token(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|item| !item.is_empty())
}

pub(super) fn platform_from_channel_type(
    channel_type: DeviceChannelType,
    device_platform: &str,
) -> Result<Platform, Error> {
    match channel_type {
        DeviceChannelType::Apns => {
            let platform = platform_from_str(device_platform)?;
            if matches!(
                platform,
                Platform::IOS | Platform::MACOS | Platform::WATCHOS
            ) {
                Ok(platform)
            } else {
                Err(Error::validation(
                    "channel_type apns requires apple platform",
                ))
            }
        }
        DeviceChannelType::Fcm => Ok(Platform::ANDROID),
        DeviceChannelType::Wns => Ok(Platform::WINDOWS),
        DeviceChannelType::Private => Err(Error::validation("private has no provider platform")),
    }
}

pub(super) fn platform_from_str(raw: &str) -> Result<Platform, Error> {
    raw.parse()
        .map_err(|_| Error::validation("invalid platform"))
}

pub(super) fn platform_str(platform: Platform) -> &'static str {
    match platform {
        Platform::IOS => "ios",
        Platform::MACOS => "macos",
        Platform::WATCHOS => "watchos",
        Platform::ANDROID => "android",
        Platform::WINDOWS => "windows",
    }
}

#[cfg(test)]
mod tests {
    use super::platform_from_channel_type;
    use crate::{api::Error, device_registry::DeviceChannelType, storage::Platform};

    #[test]
    fn apns_platform_mapping_uses_device_platform() {
        let ios = platform_from_channel_type(DeviceChannelType::Apns, "ios")
            .expect("ios apns mapping should succeed");
        let macos = platform_from_channel_type(DeviceChannelType::Apns, "macos")
            .expect("macos apns mapping should succeed");
        let watchos = platform_from_channel_type(DeviceChannelType::Apns, "watchos")
            .expect("watchos apns mapping should succeed");
        assert_eq!(ios, Platform::IOS);
        assert_eq!(macos, Platform::MACOS);
        assert_eq!(watchos, Platform::WATCHOS);
    }

    #[test]
    fn fcm_wns_platform_mapping_is_stable() {
        let fcm = platform_from_channel_type(DeviceChannelType::Fcm, "ios")
            .expect("fcm mapping should ignore device_platform");
        let wns = platform_from_channel_type(DeviceChannelType::Wns, "android")
            .expect("wns mapping should ignore device_platform");
        assert_eq!(fcm, Platform::ANDROID);
        assert_eq!(wns, Platform::WINDOWS);
    }

    #[test]
    fn apns_platform_mapping_rejects_non_apple_platform() {
        let err = platform_from_channel_type(DeviceChannelType::Apns, "android")
            .expect_err("apns mapping should reject non-apple platform");
        match err {
            Error::Validation { .. } => {}
            other => panic!("unexpected error variant: {other:?}"),
        }
    }
}
