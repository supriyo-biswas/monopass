use std::time::Duration;

pub(crate) const AUTH_TTL_SETTING: &str = "user.authTtlSeconds";
pub(crate) const GC_SECONDS_SETTING: &str = "user.gcSeconds";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UserSetting {
    pub name: &'static str,
    pub default: &'static str,
    pub min_seconds: u64,
    pub max_seconds: u64,
}

impl UserSetting {
    pub fn parse_seconds(&self, value: &str) -> Result<u64, SettingsError> {
        let seconds = value
            .parse::<u64>()
            .map_err(|_| SettingsError::InvalidValue)?;
        if seconds < self.min_seconds || seconds > self.max_seconds {
            return Err(SettingsError::InvalidValue);
        }
        Ok(seconds)
    }

    pub fn parse_duration(&self, value: &str) -> Result<Duration, SettingsError> {
        Ok(Duration::from_secs(self.parse_seconds(value)?))
    }

    pub fn validate(&self, value: &str) -> Result<(), SettingsError> {
        self.parse_seconds(value).map(|_| ())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SettingsError {
    InvalidValue,
    UnknownSetting,
}

pub(crate) const USER_SETTINGS: &[UserSetting] = &[
    UserSetting {
        name: AUTH_TTL_SETTING,
        default: "900",
        min_seconds: 1,
        max_seconds: 604_800,
    },
    UserSetting {
        name: GC_SECONDS_SETTING,
        default: "3600",
        min_seconds: 60,
        max_seconds: 2_592_000,
    },
];

pub(crate) fn user_setting(name: &str) -> Result<&'static UserSetting, SettingsError> {
    USER_SETTINGS
        .iter()
        .find(|setting| setting.name == name)
        .ok_or(SettingsError::UnknownSetting)
}

#[cfg(test)]
pub(crate) fn auth_ttl_setting() -> &'static UserSetting {
    user_setting(AUTH_TTL_SETTING).expect("auth ttl setting must be registered")
}

#[cfg(test)]
pub(crate) fn gc_seconds_setting() -> &'static UserSetting {
    user_setting(GC_SECONDS_SETTING).expect("gc seconds setting must be registered")
}
