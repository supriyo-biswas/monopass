use std::io;

use crate::config::Config;
use crate::lock::{AgentLockError, AgentLockGuard};
use crate::{AppResult, db};

pub fn run(config: &Config) -> AppResult {
    let _lock = match AgentLockGuard::acquire(config.agent_lock_path()) {
        Ok(lock) => lock,
        Err(AgentLockError::Running { .. }) => {
            eprintln!("{}", stop_agent_instructions());
            return Err(io::Error::other(
                "monopass agent must be stopped before migrating the database",
            )
            .into());
        }
        Err(error) => return Err(error.into()),
    };

    let password = db::prompt_password("Enter master password: ")?;
    let migrated = db::migrate_encrypted_database_with_password(config.database_path(), &password)?;

    if migrated {
        println!(
            "Migrated database to schema {}",
            db::DATABASE_SCHEMA_VERSION
        );
    } else {
        println!(
            "Database is already on schema {}",
            db::DATABASE_SCHEMA_VERSION
        );
    }
    println!("{}", restart_agent_instructions());
    Ok(())
}

fn current_platform() -> Platform {
    if cfg!(target_os = "linux") {
        Platform::Linux
    } else if cfg!(target_os = "macos") {
        Platform::Macos
    } else {
        Platform::OtherUnix
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Platform {
    Linux,
    Macos,
    OtherUnix,
}

fn stop_agent_instructions() -> &'static str {
    stop_agent_instructions_for(current_platform())
}

fn stop_agent_instructions_for(platform: Platform) -> &'static str {
    match platform {
        Platform::Linux => {
            "monopass agent is running. Stop it with `systemctl --user stop monopass-agent.socket monopass-agent.service`, then retry `monopass migrate`."
        }
        Platform::Macos => {
            "monopass agent is running. Stop it with `launchctl bootout gui/$(id -u)/com.monopass.agent`, then retry `monopass migrate`."
        }
        Platform::OtherUnix => {
            "monopass agent is running. Stop any running `monopass agent` process, then retry `monopass migrate`."
        }
    }
}

fn restart_agent_instructions() -> &'static str {
    restart_agent_instructions_for(current_platform())
}

fn restart_agent_instructions_for(platform: Platform) -> &'static str {
    match platform {
        Platform::Linux => {
            "Start monopass again with `systemctl --user start monopass-agent.socket`."
        }
        Platform::Macos => {
            "Start monopass again with `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.monopass.agent.plist`, then `launchctl enable gui/$(id -u)/com.monopass.agent`, then `launchctl kickstart -k gui/$(id -u)/com.monopass.agent`."
        }
        Platform::OtherUnix => {
            "Start monopass again by starting `monopass agent` with your normal process manager."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Platform, restart_agent_instructions_for, stop_agent_instructions_for};

    #[test]
    fn stop_instructions_name_migrate() {
        for platform in [Platform::Linux, Platform::Macos, Platform::OtherUnix] {
            let instructions = stop_agent_instructions_for(platform);
            assert!(instructions.contains("monopass migrate"));
        }
    }

    #[test]
    fn restart_instructions_name_agent_start() {
        for platform in [Platform::Linux, Platform::Macos, Platform::OtherUnix] {
            assert!(restart_agent_instructions_for(platform).contains("Start monopass again"));
        }
    }
}
