use std::str::FromStr;

use serde::{Deserialize, Serialize};

use super::{StoreError, StoreResult};

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Platform {
    IOS = 1,
    MACOS = 2,
    WATCHOS = 4,
    ANDROID = 5,
    WINDOWS = 6,
}

impl FromStr for Platform {
    type Err = StoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let raw = s.trim();
        let normalized = raw.to_ascii_lowercase();

        match normalized.as_str() {
            "ios" | "ipados" => Ok(Platform::IOS),
            "macos" => Ok(Platform::MACOS),
            "watchos" => Ok(Platform::WATCHOS),
            "android" => Ok(Platform::ANDROID),
            "windows" | "win" => Ok(Platform::WINDOWS),
            _ => Err(StoreError::InvalidPlatform),
        }
    }
}

impl Platform {
    #[inline]
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    #[inline]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Platform::IOS),
            2 => Some(Platform::MACOS),
            4 => Some(Platform::WATCHOS),
            5 => Some(Platform::ANDROID),
            6 => Some(Platform::WINDOWS),
            _ => None,
        }
    }

    #[inline]
    pub fn name(self) -> &'static str {
        match self {
            Platform::IOS => "ios",
            Platform::MACOS => "macos",
            Platform::WATCHOS => "watchos",
            Platform::ANDROID => "android",
            Platform::WINDOWS => "windows",
        }
    }

    #[inline]
    pub fn channel_type(self) -> &'static str {
        match self {
            Platform::ANDROID => "fcm",
            Platform::WINDOWS => "wns",
            Platform::IOS | Platform::MACOS | Platform::WATCHOS => "apns",
        }
    }

    #[inline]
    pub fn provider_name(self) -> &'static str {
        match self {
            Platform::ANDROID => "FCM",
            Platform::WINDOWS => "WNS",
            Platform::IOS | Platform::MACOS | Platform::WATCHOS => "APNS",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseKind {
    Sqlite,
    Postgres,
    Mysql,
}

impl DatabaseKind {
    pub fn from_url(db_url: &str) -> StoreResult<Self> {
        let trimmed = db_url.trim();
        if trimmed.is_empty() {
            return Err(StoreError::MissingDatabaseUrl("sqlite/postgres/mysql"));
        }
        let Some((scheme, _)) = trimmed.split_once("://") else {
            return Err(StoreError::InvalidDatabaseType("unknown".to_string()));
        };
        match scheme.to_ascii_lowercase().as_str() {
            "sqlite" => Ok(DatabaseKind::Sqlite),
            "postgres" | "postgresql" | "pg" => Ok(DatabaseKind::Postgres),
            "mysql" => Ok(DatabaseKind::Mysql),
            other => Err(StoreError::InvalidDatabaseType(other.to_string())),
        }
    }
}
