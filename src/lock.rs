use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;

#[derive(Debug)]
pub struct AgentLockGuard {
    file: File,
}

#[derive(Debug)]
pub enum AgentLockError {
    Running { path: PathBuf },
    Io(io::Error),
}

impl AgentLockGuard {
    pub fn acquire(path: impl AsRef<Path>) -> Result<Self, AgentLockError> {
        let path = path.as_ref();
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        options.mode(PRIVATE_FILE_MODE);
        #[cfg(windows)]
        options.share_mode(0);
        let file = match options.open(path) {
            Ok(file) => file,
            #[cfg(windows)]
            Err(error)
                if error.kind() == io::ErrorKind::PermissionDenied
                    || matches!(
                        error.raw_os_error(),
                        Some(code)
                            if code
                                == windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION as i32
                                || code
                                    == windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION as i32
                    ) =>
            {
                return Err(AgentLockError::Running {
                    path: path.to_path_buf(),
                });
            }
            Err(error) => return Err(AgentLockError::Io(error)),
        };
        #[cfg(unix)]
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_FILE_MODE))
            .map_err(AgentLockError::Io)?;
        #[cfg(windows)]
        crate::platform::windows::apply_private_dacl(path).map_err(AgentLockError::Io)?;

        #[cfg(unix)]
        {
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result == 0 {
                return Ok(Self { file });
            }

            let error = io::Error::last_os_error();
            if matches!(
                error.raw_os_error(),
                Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN
            ) {
                Err(AgentLockError::Running {
                    path: path.to_path_buf(),
                })
            } else {
                Err(AgentLockError::Io(error))
            }
        }

        #[cfg(windows)]
        Ok(Self { file })
    }
}

impl Drop for AgentLockGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

impl fmt::Display for AgentLockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Running { path } => write!(
                formatter,
                "monopass agent is already running or another maintenance command holds {}",
                path.display()
            ),
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for AgentLockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Running { .. } => None,
            Self::Io(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AgentLockError, AgentLockGuard};

    #[test]
    fn lock_can_be_reacquired_after_guard_drops() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.lock");

        let first = AgentLockGuard::acquire(&path).unwrap();
        assert!(matches!(
            AgentLockGuard::acquire(&path),
            Err(AgentLockError::Running { .. })
        ));

        drop(first);
        AgentLockGuard::acquire(&path).unwrap();
    }
}
