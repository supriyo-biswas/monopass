use std::io;

use crate::commands::password_policy::{
    PASSWD_WEAK_PASSWORD_PROMPT, validate_master_password_with_weak_prompt,
};
use crate::config::Config;
use crate::lock::{AgentLockError, AgentLockGuard};
use crate::{AppResult, db};

pub fn run(config: &Config) -> AppResult {
    let _lock = match AgentLockGuard::acquire(config.agent_lock_path()) {
        Ok(lock) => lock,
        Err(AgentLockError::Running { .. }) => {
            let instructions = stop_agent_instructions();
            eprintln!("{instructions}");
            return Err(io::Error::other(
                "monopass agent must be stopped before changing the master password",
            )
            .into());
        }
        Err(error) => return Err(error.into()),
    };

    let current_password = db::prompt_password("Enter current master password: ")?;
    let conn =
        db::open_encrypted_database_with_password(config.database_path(), &current_password)?;

    let new_password = db::prompt_password("Enter new master password: ")?;
    if passwords_are_unchanged(&current_password, &new_password) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "new master password must differ from current master password",
        )
        .into());
    }

    validate_master_password_with_weak_prompt(&new_password, PASSWD_WEAK_PASSWORD_PROMPT)?;

    let confirmed_password = db::prompt_password("Confirm new master password: ")?;
    if new_password.as_str() != confirmed_password.as_str() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "passwords do not match").into());
    }

    db::rekey_encrypted_database(&conn, &new_password)?;
    println!("Changed master password");
    println!("{}", restart_agent_instructions());

    Ok(())
}

fn stop_agent_instructions() -> &'static str {
    stop_agent_instructions_for(current_platform())
}

fn restart_agent_instructions() -> &'static str {
    restart_agent_instructions_for(current_platform())
}

fn passwords_are_unchanged(current_password: &str, new_password: &str) -> bool {
    current_password == new_password
}

fn current_platform() -> StopAgentPlatform {
    if cfg!(target_os = "linux") {
        StopAgentPlatform::Linux
    } else if cfg!(target_os = "macos") {
        StopAgentPlatform::Macos
    } else {
        StopAgentPlatform::OtherUnix
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StopAgentPlatform {
    Linux,
    Macos,
    OtherUnix,
}

fn stop_agent_instructions_for(platform: StopAgentPlatform) -> &'static str {
    match platform {
        StopAgentPlatform::Linux => {
            "monopass agent is running. Stop it with `systemctl --user stop monopass-agent.socket monopass-agent.service`, then retry `monopass passwd`."
        }
        StopAgentPlatform::Macos => {
            "monopass agent is running. Stop it with `launchctl bootout gui/$(id -u)/com.monopass.agent`, then retry `monopass passwd`."
        }
        StopAgentPlatform::OtherUnix => {
            "monopass agent is running. Stop any running `monopass agent` process, then retry `monopass passwd`."
        }
    }
}

fn restart_agent_instructions_for(platform: StopAgentPlatform) -> &'static str {
    match platform {
        StopAgentPlatform::Linux => {
            "Start monopass again with `systemctl --user start monopass-agent.socket`."
        }
        StopAgentPlatform::Macos => {
            "Start monopass again with `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.monopass.agent.plist`, then `launchctl enable gui/$(id -u)/com.monopass.agent`, then `launchctl kickstart -k gui/$(id -u)/com.monopass.agent`."
        }
        StopAgentPlatform::OtherUnix => {
            "Start monopass again by starting `monopass agent` with your normal process manager."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        StopAgentPlatform, passwords_are_unchanged, restart_agent_instructions_for,
        stop_agent_instructions_for,
    };

    #[test]
    fn linux_stop_instructions_use_systemctl() {
        let instructions = stop_agent_instructions_for(StopAgentPlatform::Linux);

        assert!(
            instructions
                .contains("systemctl --user stop monopass-agent.socket monopass-agent.service")
        );
        assert!(instructions.contains("monopass passwd"));
    }

    #[test]
    fn macos_stop_instructions_use_launchctl() {
        let instructions = stop_agent_instructions_for(StopAgentPlatform::Macos);

        assert!(instructions.contains("launchctl bootout gui/$(id -u)/com.monopass.agent"));
        assert!(instructions.contains("monopass passwd"));
    }

    #[test]
    fn generic_stop_instructions_name_agent_process() {
        let instructions = stop_agent_instructions_for(StopAgentPlatform::OtherUnix);

        assert!(instructions.contains("monopass agent"));
        assert!(instructions.contains("monopass passwd"));
    }

    #[test]
    fn linux_restart_instructions_start_systemd_socket() {
        let instructions = restart_agent_instructions_for(StopAgentPlatform::Linux);

        assert!(instructions.contains("systemctl --user start monopass-agent.socket"));
        assert!(!instructions.contains("start monopass-agent.service"));
    }

    #[test]
    fn macos_restart_instructions_bootstrap_enable_and_kickstart_launch_agent() {
        let instructions = restart_agent_instructions_for(StopAgentPlatform::Macos);

        assert!(instructions.contains(
            "launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.monopass.agent.plist"
        ));
        assert!(instructions.contains("launchctl enable gui/$(id -u)/com.monopass.agent"));
        assert!(instructions.contains("launchctl kickstart -k gui/$(id -u)/com.monopass.agent"));
    }

    #[test]
    fn generic_restart_instructions_name_agent_process() {
        let instructions = restart_agent_instructions_for(StopAgentPlatform::OtherUnix);

        assert!(instructions.contains("monopass agent"));
        assert!(instructions.contains("normal process manager"));
    }

    #[test]
    fn detects_unchanged_password() {
        assert!(passwords_are_unchanged("same", "same"));
        assert!(!passwords_are_unchanged("old", "new"));
    }
}
