use std::time::Duration;

pub(crate) const AUTH_TTL_SETTING: &str = "user.authTtlSeconds";
pub(crate) const SETTINGS_AUTH_TTL_SETTING: &str = "user.settingsAuthTtlSeconds";
pub(crate) const DENIAL_TTL_SETTING: &str = "user.denialTtlSeconds";
pub(crate) const GC_SECONDS_SETTING: &str = "user.gcSeconds";
pub(crate) const TRUSTED_PROGRAM_PATHS_SETTING: &str = "user.trustedProgramPaths";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UserSettingKind {
    Seconds { min: u64, max: u64 },
    StringArray,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UserSetting {
    pub name: &'static str,
    pub default: &'static str,
    pub kind: UserSettingKind,
}

impl UserSetting {
    pub fn parse_seconds(&self, value: &str) -> Result<u64, SettingsError> {
        let UserSettingKind::Seconds { min, max } = self.kind else {
            return Err(SettingsError::InvalidValue);
        };
        let seconds = value
            .parse::<u64>()
            .map_err(|_| SettingsError::InvalidValue)?;
        if seconds < min || seconds > max {
            return Err(SettingsError::InvalidValue);
        }
        Ok(seconds)
    }

    pub fn parse_duration(&self, value: &str) -> Result<Duration, SettingsError> {
        Ok(Duration::from_secs(self.parse_seconds(value)?))
    }

    #[cfg(test)]
    pub fn validate(&self, value: &str) -> Result<(), SettingsError> {
        self.normalize(value).map(|_| ())
    }

    pub fn normalize(&self, value: &str) -> Result<String, SettingsError> {
        match self.kind {
            UserSettingKind::Seconds { .. } => {
                self.parse_seconds(value)?;
                Ok(value.to_owned())
            }
            UserSettingKind::StringArray => {
                let values = serde_json::from_str::<Vec<String>>(value)
                    .map_err(|_| SettingsError::InvalidValue)?;
                serde_json::to_string(&values).map_err(|_| SettingsError::InvalidValue)
            }
        }
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
        kind: UserSettingKind::Seconds {
            min: 1,
            max: 604_800,
        },
    },
    UserSetting {
        name: SETTINGS_AUTH_TTL_SETTING,
        default: "300",
        kind: UserSettingKind::Seconds {
            min: 1,
            max: 604_800,
        },
    },
    UserSetting {
        name: DENIAL_TTL_SETTING,
        default: "60",
        kind: UserSettingKind::Seconds {
            min: 1,
            max: 604_800,
        },
    },
    UserSetting {
        name: GC_SECONDS_SETTING,
        default: "3600",
        kind: UserSettingKind::Seconds {
            min: 60,
            max: 2_592_000,
        },
    },
    UserSetting {
        name: TRUSTED_PROGRAM_PATHS_SETTING,
        default: "[]",
        kind: UserSettingKind::StringArray,
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
pub(crate) fn settings_auth_ttl_setting() -> &'static UserSetting {
    user_setting(SETTINGS_AUTH_TTL_SETTING).expect("settings auth ttl setting must be registered")
}

#[cfg(test)]
pub(crate) fn denial_ttl_setting() -> &'static UserSetting {
    user_setting(DENIAL_TTL_SETTING).expect("denial ttl setting must be registered")
}

#[cfg(test)]
pub(crate) fn gc_seconds_setting() -> &'static UserSetting {
    user_setting(GC_SECONDS_SETTING).expect("gc seconds setting must be registered")
}

#[cfg(test)]
pub(crate) fn trusted_program_paths_setting() -> &'static UserSetting {
    user_setting(TRUSTED_PROGRAM_PATHS_SETTING)
        .expect("trusted program paths setting must be registered")
}
