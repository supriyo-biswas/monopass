use std::env;
use std::fs;
use std::io;
#[cfg(target_os = "macos")]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(target_os = "macos")]
const PRIVATE_DIR_MODE: u32 = 0o700;

pub fn enable_agent(listen_path: &Path) -> io::Result<()> {
    let exe = env::current_exe()?;
    enable_agent_with_exe(&exe, listen_path)
}

#[cfg(target_os = "linux")]
fn enable_agent_with_exe(exe: &Path, _listen_path: &Path) -> io::Result<()> {
    let service_path = linux_service_unit_path()?;
    let socket_path = linux_socket_unit_path()?;
    if let Some(parent) = service_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&service_path, linux_systemd_service_unit(exe))?;
    fs::write(&socket_path, linux_systemd_socket_unit())?;

    run_command("systemctl", ["--user", "daemon-reload"])?;
    run_command_allow_failure(
        "systemctl",
        ["--user", "disable", "--now", "monopass-agent.service"],
    );
    run_command(
        "systemctl",
        ["--user", "enable", "--now", "monopass-agent.socket"],
    )
}

#[cfg(target_os = "macos")]
fn enable_agent_with_exe(exe: &Path, listen_path: &Path) -> io::Result<()> {
    let plist_path = macos_plist_path()?;
    if let Some(parent) = plist_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = listen_path.parent() {
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(PRIVATE_DIR_MODE))?;
    }
    fs::write(&plist_path, macos_launch_agent_plist(exe, listen_path))?;

    let domain_label = macos_domain_label();
    let service_target = macos_service_target(&domain_label);
    let bootout = Command::new("launchctl")
        .args(["bootout", &service_target])
        .output()?;
    if !bootout.status.success() && !is_not_loaded_launchctl_error(&bootout.stderr) {
        return Err(command_error(
            "launchctl bootout",
            bootout.status,
            &bootout.stderr,
        ));
    }

    let plist = plist_path.to_string_lossy().into_owned();
    run_command("launchctl", ["bootstrap", &domain_label, &plist])?;
    run_command("launchctl", ["enable", &service_target])?;
    run_command("launchctl", ["kickstart", "-k", &service_target])
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn enable_agent_with_exe(_exe: &Path, _listen_path: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "agent auto-start is only supported on Linux and macOS",
    ))
}

#[cfg(target_os = "linux")]
fn linux_service_unit_path() -> io::Result<PathBuf> {
    Ok(config_home()?.join("systemd/user/monopass-agent.service"))
}

#[cfg(target_os = "linux")]
fn linux_socket_unit_path() -> io::Result<PathBuf> {
    Ok(config_home()?.join("systemd/user/monopass-agent.socket"))
}

#[cfg(target_os = "linux")]
fn config_home() -> io::Result<PathBuf> {
    if let Some(config_home) = env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(config_home));
    }

    let home = env::var_os("HOME")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
    Ok(PathBuf::from(home).join(".config"))
}

#[cfg(target_os = "macos")]
fn macos_plist_path() -> io::Result<PathBuf> {
    let home = env::var_os("HOME")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
    Ok(PathBuf::from(home).join("Library/LaunchAgents/com.monopass.agent.plist"))
}

#[cfg(target_os = "macos")]
fn macos_domain_label() -> String {
    let uid = unsafe { libc::getuid() };
    format!("gui/{uid}")
}

#[cfg(target_os = "macos")]
fn macos_service_target(domain_label: &str) -> String {
    format!("{domain_label}/com.monopass.agent")
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn linux_systemd_service_unit(exe: &Path) -> String {
    format!(
        "[Unit]\nDescription=monopass agent\nRequires=monopass-agent.socket\n\n[Service]\nExecStart={} agent\nRestart=on-failure\n",
        exe.display()
    )
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn linux_systemd_socket_unit() -> String {
    "[Unit]\nDescription=monopass agent socket\n\n[Socket]\nListenStream=%t/monopass/agent.sock\nSocketMode=0600\nDirectoryMode=0700\nRemoveOnStop=true\n\n[Install]\nWantedBy=sockets.target\n".to_owned()
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn macos_launch_agent_plist(exe: &Path, listen_path: &Path) -> String {
    let exe = xml_escape(&exe.to_string_lossy());
    let listen_path = xml_escape(&listen_path.to_string_lossy());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.monopass.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>agent</string>
    </array>
    <key>Sockets</key>
    <dict>
        <key>monopass-agent</key>
        <dict>
            <key>SockPathName</key>
            <string>{listen_path}</string>
            <key>SockType</key>
            <string>stream</string>
            <key>SockPassive</key>
            <true/>
            <key>SockPathMode</key>
            <integer>384</integer>
        </dict>
    </dict>
</dict>
</plist>
"#
    )
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_command<const N: usize>(program: &str, args: [&str; N]) -> io::Result<()> {
    let output = Command::new(program).args(args).output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(command_error(program, output.status, &output.stderr))
    }
}

#[cfg(target_os = "linux")]
fn run_command_allow_failure<const N: usize>(program: &str, args: [&str; N]) {
    let _ = Command::new(program).args(args).output();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn command_error(program: &str, status: std::process::ExitStatus, stderr: &[u8]) -> io::Error {
    let stderr = String::from_utf8_lossy(stderr);
    io::Error::other(format!("{program} failed with {status}: {stderr}"))
}

#[cfg(target_os = "macos")]
fn is_not_loaded_launchctl_error(stderr: &[u8]) -> bool {
    let stderr = String::from_utf8_lossy(stderr);
    stderr.contains("not loaded") || stderr.contains("No such process")
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    #[test]
    fn generates_linux_systemd_service_unit() {
        let unit = super::linux_systemd_service_unit(Path::new("/usr/local/bin/monopass"));

        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("Description=monopass agent"));
        assert!(unit.contains("Requires=monopass-agent.socket"));
        assert!(unit.contains("ExecStart=/usr/local/bin/monopass agent"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(!unit.contains("WantedBy=default.target"));
    }

    #[test]
    fn generates_linux_systemd_socket_unit() {
        let unit = super::linux_systemd_socket_unit();

        assert!(unit.contains("[Socket]"));
        assert!(unit.contains("ListenStream=%t/monopass/agent.sock"));
        assert!(unit.contains("SocketMode=0600"));
        assert!(unit.contains("DirectoryMode=0700"));
        assert!(unit.contains("RemoveOnStop=true"));
        assert!(unit.contains("WantedBy=sockets.target"));
    }

    #[test]
    fn generates_macos_launch_agent_plist() {
        let plist = super::macos_launch_agent_plist(
            Path::new("/Applications/monopass"),
            Path::new("/tmp/monopass/agent.sock"),
        );

        assert!(plist.contains("<string>com.monopass.agent</string>"));
        assert!(plist.contains("<key>ProgramArguments</key>"));
        assert!(plist.contains("<string>/Applications/monopass</string>"));
        assert!(plist.contains("<string>agent</string>"));
        assert!(plist.contains("<key>Sockets</key>"));
        assert!(plist.contains("<key>monopass-agent</key>"));
        assert!(plist.contains("<key>SockPathName</key>"));
        assert!(plist.contains("<string>/tmp/monopass/agent.sock</string>"));
        assert!(plist.contains("<key>SockType</key>\n            <string>stream</string>"));
        assert!(plist.contains("<key>SockPassive</key>\n            <true/>"));
        assert!(plist.contains("<key>SockPathMode</key>\n            <integer>384</integer>"));
        assert!(!plist.contains("<key>RunAtLoad</key>"));
        assert!(!plist.contains("<key>KeepAlive</key>"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_service_target_uses_domain_and_label() {
        assert_eq!(
            "gui/501/com.monopass.agent",
            super::macos_service_target("gui/501")
        );
    }

    #[test]
    fn escapes_macos_plist_exe_path() {
        let plist = super::macos_launch_agent_plist(
            Path::new("/tmp/a&b/monopass"),
            Path::new("/tmp/a&b/agent.sock"),
        );

        assert!(plist.contains("/tmp/a&amp;b/monopass"));
        assert!(plist.contains("/tmp/a&amp;b/agent.sock"));
    }
}
