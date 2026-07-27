use std::time::Duration;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

pub(crate) const AUTH_TTL_SETTING: &str = "agent.authTtlSeconds";
pub(crate) const SETTINGS_AUTH_TTL_SETTING: &str = "agent.settingsAuthTtlSeconds";
pub(crate) const DENIAL_TTL_SETTING: &str = "agent.denialTtlSeconds";
pub(crate) const GC_SECONDS_SETTING: &str = "agent.gcSeconds";
pub(crate) const AUTO_DELETE_TRASH_ITEMS_AFTER_SETTING: &str =
    "agent.autoDeleteTrashItemsAfterSeconds";
pub(crate) const AUTO_DELETE_OLD_VERSIONS_AFTER_SETTING: &str =
    "agent.autoDeleteOldVersionsAfterSeconds";
pub(crate) const TRUSTED_PROGRAM_PATHS_SETTING: &str = "agent.trustedProgramPaths";
pub(crate) const CLEAR_CLIPBOARD_AFTER_SECONDS_SETTING: &str = "cli.clearClipboardAfterSeconds";

const FIVE_YEARS_SECONDS: u64 = 5 * 365 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SettingKind {
    Seconds { min: u64, max: u64 },
    TrustedProgramPaths,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Setting {
    pub name: &'static str,
    pub default: &'static str,
    pub kind: SettingKind,
}

impl Setting {
    pub fn parse_seconds(&self, value: &str) -> Result<u64, SettingsError> {
        let SettingKind::Seconds { min, max } = self.kind else {
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
            SettingKind::Seconds { .. } => {
                self.parse_seconds(value)?;
                Ok(value.to_owned())
            }
            SettingKind::TrustedProgramPaths => {
                let values = serde_json::from_str::<Vec<String>>(value)
                    .map_err(|_| SettingsError::InvalidValue)?;
                compile_trusted_program_paths(&values)?;
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

pub(crate) const SETTINGS: &[Setting] = &[
    Setting {
        name: AUTH_TTL_SETTING,
        default: "900",
        kind: SettingKind::Seconds {
            min: 1,
            max: 604_800,
        },
    },
    Setting {
        name: SETTINGS_AUTH_TTL_SETTING,
        default: "300",
        kind: SettingKind::Seconds {
            min: 1,
            max: 604_800,
        },
    },
    Setting {
        name: DENIAL_TTL_SETTING,
        default: "60",
        kind: SettingKind::Seconds {
            min: 1,
            max: 604_800,
        },
    },
    Setting {
        name: GC_SECONDS_SETTING,
        default: "3600",
        kind: SettingKind::Seconds {
            min: 60,
            max: 2_592_000,
        },
    },
    Setting {
        name: AUTO_DELETE_TRASH_ITEMS_AFTER_SETTING,
        default: "15552000",
        kind: SettingKind::Seconds {
            min: 0,
            max: FIVE_YEARS_SECONDS,
        },
    },
    Setting {
        name: AUTO_DELETE_OLD_VERSIONS_AFTER_SETTING,
        default: "15552000",
        kind: SettingKind::Seconds {
            min: 0,
            max: FIVE_YEARS_SECONDS,
        },
    },
    Setting {
        name: TRUSTED_PROGRAM_PATHS_SETTING,
        default: "[]",
        kind: SettingKind::TrustedProgramPaths,
    },
    Setting {
        name: CLEAR_CLIPBOARD_AFTER_SECONDS_SETTING,
        default: "30",
        kind: SettingKind::Seconds { min: 10, max: 300 },
    },
];

pub(crate) fn setting(name: &str) -> Result<&'static Setting, SettingsError> {
    SETTINGS
        .iter()
        .find(|setting| setting.name == name)
        .ok_or(SettingsError::UnknownSetting)
}

pub(crate) fn trusted_program_path_matcher(value: &str) -> Result<GlobSet, SettingsError> {
    let patterns =
        serde_json::from_str::<Vec<String>>(value).map_err(|_| SettingsError::InvalidValue)?;
    compile_trusted_program_paths(&patterns)
}

fn compile_trusted_program_paths(patterns: &[String]) -> Result<GlobSet, SettingsError> {
    let mut set = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = GlobBuilder::new(pattern)
            .literal_separator(true)
            .case_insensitive(false)
            .build()
            .map_err(|_| SettingsError::InvalidValue)?;
        set.add(glob);
    }
    set.build().map_err(|_| SettingsError::InvalidValue)
}

#[cfg(test)]
pub(crate) fn auth_ttl_setting() -> &'static Setting {
    setting(AUTH_TTL_SETTING).expect("auth ttl setting must be registered")
}

#[cfg(test)]
pub(crate) fn settings_auth_ttl_setting() -> &'static Setting {
    setting(SETTINGS_AUTH_TTL_SETTING).expect("settings auth ttl setting must be registered")
}

#[cfg(test)]
pub(crate) fn denial_ttl_setting() -> &'static Setting {
    setting(DENIAL_TTL_SETTING).expect("denial ttl setting must be registered")
}

#[cfg(test)]
pub(crate) fn gc_seconds_setting() -> &'static Setting {
    setting(GC_SECONDS_SETTING).expect("gc seconds setting must be registered")
}

#[cfg(test)]
pub(crate) fn trusted_program_paths_setting() -> &'static Setting {
    setting(TRUSTED_PROGRAM_PATHS_SETTING)
        .expect("trusted program paths setting must be registered")
}

#[cfg(test)]
mod tests {
    #[test]
    fn trusted_program_globs_use_case_sensitive_path_separator_semantics() {
        let exact = super::trusted_program_path_matcher(r#"["/opt/tools/bin/example"]"#).unwrap();
        assert!(exact.is_match("/opt/tools/bin/example"));
        assert!(!exact.is_match("/opt/tools/bin/Example"));

        let single = super::trusted_program_path_matcher(r#"["/opt/tools/*/example"]"#).unwrap();
        assert!(single.is_match("/opt/tools/bin/example"));
        assert!(!single.is_match("/opt/tools/team/bin/example"));

        let recursive =
            super::trusted_program_path_matcher(r#"["/opt/tools/**/example"]"#).unwrap();
        assert!(recursive.is_match("/opt/tools/bin/example"));
        assert!(recursive.is_match("/opt/tools/team/bin/example"));
    }

    #[test]
    fn trusted_program_globs_reject_malformed_syntax() {
        assert!(super::trusted_program_path_matcher(r#"["[unterminated"]"#).is_err());
    }

    #[test]
    fn clear_clipboard_seconds_accepts_only_configured_range() {
        let setting = super::setting(super::CLEAR_CLIPBOARD_AFTER_SECONDS_SETTING).unwrap();

        assert_eq!(10, setting.parse_seconds("10").unwrap());
        assert_eq!(300, setting.parse_seconds("300").unwrap());
        for value in ["-1", "invalid", "9", "301"] {
            assert!(setting.parse_seconds(value).is_err(), "{value}");
        }
    }
}
