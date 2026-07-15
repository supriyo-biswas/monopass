#[cfg(target_os = "macos")]
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::PermissionsExt;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::io::FromRawFd;
use std::path::Path;
#[cfg(all(target_os = "macos", not(debug_assertions)))]
use std::ptr;

use tokio::net::UnixListener;

use crate::AppResult;
use crate::agent;
use crate::config::Config;
use crate::lock::AgentLockGuard;

#[cfg(target_os = "macos")]
const LAUNCHD_SOCKET_NAME: &str = "monopass-agent";

pub fn run(config: &Config) -> AppResult {
    harden_agent_process()?;

    #[cfg(any(
        target_os = "macos",
        all(target_os = "linux", any(feature = "gtk", feature = "qt"))
    ))]
    {
        configure_prompt_backend_environment();
        run_with_prompt_dispatcher(config)
    }

    #[cfg(not(any(
        target_os = "macos",
        all(target_os = "linux", any(feature = "gtk", feature = "qt"))
    )))]
    {
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(serve(config))
    }
}

#[cfg(all(target_os = "linux", feature = "gtk"))]
fn configure_prompt_backend_environment() {
    // SAFETY: this runs before the agent server/runtime thread is spawned in this process.
    unsafe { std::env::set_var("GDK_BACKEND", "x11") };
}

#[cfg(all(target_os = "linux", not(feature = "gtk"), feature = "qt"))]
fn configure_prompt_backend_environment() {
    // SAFETY: this runs before the agent server/runtime thread is spawned in this process.
    unsafe {
        std::env::set_var("QT_QPA_PLATFORM", "xcb");
        std::env::remove_var("XDG_CURRENT_DESKTOP");
        std::env::remove_var("DESKTOP_SESSION");
        std::env::remove_var("GNOME_DESKTOP_SESSION_ID");
        std::env::remove_var("GTK_MODULES");
        std::env::remove_var("GTK_IM_MODULE");
    };
}

#[cfg(target_os = "macos")]
fn configure_prompt_backend_environment() {}

#[cfg(any(
    target_os = "macos",
    all(target_os = "linux", any(feature = "gtk", feature = "qt"))
))]
fn run_with_prompt_dispatcher(config: &Config) -> AppResult {
    let prompt_receiver = agent::install_prompt_dispatcher();
    let config = config.clone();
    let server = std::thread::spawn(move || -> Result<(), String> {
        let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
        runtime
            .block_on(serve(&config))
            .map_err(|error| error.to_string())
    });

    agent::run_prompt_dispatcher(prompt_receiver, &server);

    match server.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error.into()),
        Err(_) => Err("agent server thread panicked".into()),
    }
}

#[cfg(target_os = "macos")]
fn harden_agent_process() -> io::Result<()> {
    disable_core_dumps()?;

    #[cfg(not(debug_assertions))]
    deny_debug_attach()?;

    Ok(())
}

#[cfg(target_os = "linux")]
fn harden_agent_process() -> io::Result<()> {
    disable_core_dumps()?;

    #[cfg(not(debug_assertions))]
    {
        deny_debug_attach()?;
        ensure_not_traced()?;
    }

    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn harden_agent_process() -> io::Result<()> {
    disable_core_dumps()
}

fn disable_core_dumps() -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let result = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(all(target_os = "macos", not(debug_assertions)))]
fn deny_debug_attach() -> io::Result<()> {
    let result = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, ptr::null_mut(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(all(target_os = "linux", not(debug_assertions)))]
fn deny_debug_attach() -> io::Result<()> {
    let result = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(all(target_os = "linux", not(debug_assertions)))]
fn ensure_not_traced() -> io::Result<()> {
    let status = fs::read_to_string("/proc/self/status")?;
    let tracer_pid = parse_tracer_pid(&status)?;

    if tracer_pid == 0 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "debugger detected; refusing to start agent",
        ))
    }
}

#[cfg(any(test, all(target_os = "linux", not(debug_assertions))))]
fn parse_tracer_pid(status: &str) -> io::Result<u32> {
    let value = status
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find_map(|(name, value)| (name.trim() == "TracerPid").then_some(value.trim()))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "TracerPid is missing from /proc/self/status",
            )
        })?;

    value.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "TracerPid in /proc/self/status is invalid",
        )
    })
}

async fn serve(config: &Config) -> AppResult {
    let listen_path = config.listen_path();
    let _lock = AgentLockGuard::acquire(config.agent_lock_path())?;

    if !config.database_path().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "database file not found: {}",
                config.database_path().display()
            ),
        )
        .into());
    }

    let listener = create_listener(listen_path)?;
    println!("Listening on {}", listen_path.display());

    axum::serve(
        listener,
        agent::Server::new(config)
            .router()
            .into_make_service_with_connect_info::<agent::PeerConnectInfo>(),
    )
    .await?;
    Ok(())
}

fn create_listener(listen_path: &Path) -> io::Result<UnixListener> {
    if let Some(listener) = socket_activated_listener()? {
        return Ok(listener);
    }

    remove_stale_socket(listen_path)?;
    let listener = UnixListener::bind(listen_path)?;
    fs::set_permissions(listen_path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn launch_activate_socket(
        name: *const libc::c_char,
        fds: *mut *mut libc::c_int,
        cnt: *mut usize,
    ) -> libc::c_int;
}

#[cfg(target_os = "linux")]
fn socket_activated_listener() -> io::Result<Option<UnixListener>> {
    let Some(fd) = systemd_socket_activation_fd(
        std::env::var("LISTEN_PID").ok().as_deref(),
        std::env::var("LISTEN_FDS").ok().as_deref(),
        std::process::id(),
    )?
    else {
        return Ok(None);
    };

    let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    listener.set_nonblocking(true)?;
    UnixListener::from_std(listener).map(Some)
}

#[cfg(target_os = "macos")]
fn socket_activated_listener() -> io::Result<Option<UnixListener>> {
    let Some(fd) = launchd_socket_activation_fd()? else {
        return Ok(None);
    };

    let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    listener.set_nonblocking(true)?;
    UnixListener::from_std(listener).map(Some)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn socket_activated_listener() -> io::Result<Option<UnixListener>> {
    Ok(None)
}

#[cfg(target_os = "linux")]
fn systemd_socket_activation_fd(
    listen_pid: Option<&str>,
    listen_fds: Option<&str>,
    current_pid: u32,
) -> io::Result<Option<i32>> {
    match (listen_pid, listen_fds) {
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "incomplete systemd socket activation environment",
        )),
        (Some(listen_pid), Some(listen_fds)) => {
            let listen_pid = listen_pid.parse::<u32>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid LISTEN_PID in systemd socket activation environment",
                )
            })?;
            if listen_pid != current_pid {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "LISTEN_PID does not match current process",
                ));
            }

            let listen_fds = listen_fds.parse::<i32>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid LISTEN_FDS in systemd socket activation environment",
                )
            })?;
            if listen_fds != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "expected exactly one systemd socket activation file descriptor",
                ));
            }

            Ok(Some(3))
        }
    }
}

#[cfg(target_os = "macos")]
fn launchd_socket_activation_fd() -> io::Result<Option<i32>> {
    let name = CString::new(LAUNCHD_SOCKET_NAME).expect("launchd socket name has no nul bytes");
    let mut fds: *mut libc::c_int = std::ptr::null_mut();
    let mut count: usize = 0;
    let result = unsafe { launch_activate_socket(name.as_ptr(), &mut fds, &mut count) };

    if result == libc::ESRCH || result == libc::ENOENT {
        return Ok(None);
    }
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result));
    }

    if fds.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "launchd socket activation returned no file descriptor array",
        ));
    }

    let fd = unsafe {
        let activated_fds = std::slice::from_raw_parts(fds, count);
        if activated_fds.len() == 1 {
            activated_fds[0]
        } else {
            for fd in activated_fds {
                libc::close(*fd);
            }
            libc::free(fds.cast());
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected exactly one launchd socket activation file descriptor",
            ));
        }
    };

    unsafe {
        libc::free(fds.cast());
    }
    Ok(Some(fd))
}

fn remove_stale_socket(listen_path: &Path) -> io::Result<()> {
    match fs::metadata(listen_path) {
        Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(listen_path),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "listen path exists and is not a socket: {}",
                listen_path.display()
            ),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tracer_pid_tests {
    use std::io;

    #[test]
    fn parses_zero_tracer_pid() {
        assert_eq!(
            0,
            super::parse_tracer_pid("Name:\tmonopass\nTracerPid:\t0\n").unwrap()
        );
    }

    #[test]
    fn parses_nonzero_tracer_pid() {
        assert_eq!(1234, super::parse_tracer_pid("TracerPid:\t1234\n").unwrap());
    }

    #[test]
    fn rejects_missing_tracer_pid() {
        let error = super::parse_tracer_pid("Name:\tmonopass\n").unwrap_err();

        assert_eq!(io::ErrorKind::InvalidData, error.kind());
    }

    #[test]
    fn rejects_malformed_tracer_pid() {
        let error = super::parse_tracer_pid("TracerPid:\tunknown\n").unwrap_err();

        assert_eq!(io::ErrorKind::InvalidData, error.kind());
    }

    #[test]
    fn parses_whitespace_formatted_tracer_pid() {
        assert_eq!(
            42,
            super::parse_tracer_pid("  TracerPid :  42  \n").unwrap()
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[test]
    fn missing_systemd_activation_env_falls_back_to_bind() {
        let fd = super::systemd_socket_activation_fd(None, None, 123).unwrap();

        assert_eq!(None, fd);
    }

    #[test]
    fn valid_systemd_activation_env_uses_fd_three() {
        let fd = super::systemd_socket_activation_fd(Some("123"), Some("1"), 123).unwrap();

        assert_eq!(Some(3), fd);
    }

    #[test]
    fn incomplete_systemd_activation_env_is_rejected() {
        assert!(super::systemd_socket_activation_fd(Some("123"), None, 123).is_err());
        assert!(super::systemd_socket_activation_fd(None, Some("1"), 123).is_err());
    }

    #[test]
    fn mismatched_systemd_activation_pid_is_rejected() {
        let error = super::systemd_socket_activation_fd(Some("124"), Some("1"), 123).unwrap_err();

        assert!(error.to_string().contains("LISTEN_PID"));
    }

    #[test]
    fn invalid_systemd_activation_fd_count_is_rejected() {
        assert!(super::systemd_socket_activation_fd(Some("123"), Some("0"), 123).is_err());
        assert!(super::systemd_socket_activation_fd(Some("123"), Some("2"), 123).is_err());
    }
}
