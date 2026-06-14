use std::path::{Path, PathBuf};

use crate::AppResult;

#[derive(Debug)]
pub struct Config {
    database_path: PathBuf,
    file_store_path: PathBuf,
    job_store_path: PathBuf,
    listen_path: PathBuf,
    agent_lock_path: PathBuf,
}

impl Config {
    #[cfg(test)]
    pub(crate) fn new(
        database_path: PathBuf,
        file_store_path: PathBuf,
        job_store_path: PathBuf,
        listen_path: PathBuf,
        agent_lock_path: PathBuf,
    ) -> Self {
        Self {
            database_path,
            file_store_path,
            job_store_path,
            listen_path,
            agent_lock_path,
        }
    }

    pub fn load() -> AppResult<Self> {
        let xdg_dirs = xdg::BaseDirectories::with_prefix("monopass");
        let database_path = place_data_file(&xdg_dirs, "monopass.db")?;
        let file_store_path = place_data_file(&xdg_dirs, "files")?;
        let job_store_path = place_data_file(&xdg_dirs, "jobs")?;
        let listen_path = place_runtime_file(&xdg_dirs, "agent.sock")?;
        let agent_lock_path = place_data_file(&xdg_dirs, "agent.lock")?;

        Ok(Self {
            database_path,
            file_store_path,
            job_store_path,
            listen_path,
            agent_lock_path,
        })
    }

    pub fn database_path(&self) -> &PathBuf {
        &self.database_path
    }

    pub fn file_store_path(&self) -> &PathBuf {
        &self.file_store_path
    }

    pub fn job_store_path(&self) -> &PathBuf {
        &self.job_store_path
    }

    pub fn listen_path(&self) -> &PathBuf {
        &self.listen_path
    }

    pub fn agent_lock_path(&self) -> &PathBuf {
        &self.agent_lock_path
    }
}

#[cfg(target_os = "macos")]
fn place_data_file(xdg_dirs: &xdg::BaseDirectories, path: impl AsRef<Path>) -> AppResult<PathBuf> {
    if std::env::var_os("XDG_DATA_HOME").is_some() {
        return Ok(xdg_dirs.place_data_file(path)?);
    }

    Ok(place_app_support_file(path)?)
}

#[cfg(not(target_os = "macos"))]
fn place_data_file(xdg_dirs: &xdg::BaseDirectories, path: impl AsRef<Path>) -> AppResult<PathBuf> {
    Ok(xdg_dirs.place_data_file(path)?)
}

#[cfg(target_os = "macos")]
fn place_runtime_file(
    xdg_dirs: &xdg::BaseDirectories,
    path: impl AsRef<Path>,
) -> AppResult<PathBuf> {
    if std::env::var_os("XDG_RUNTIME_DIR").is_some() {
        return Ok(xdg_dirs.place_runtime_file(path)?);
    }

    Ok(place_app_support_file(path)?)
}

#[cfg(not(target_os = "macos"))]
fn place_runtime_file(
    xdg_dirs: &xdg::BaseDirectories,
    path: impl AsRef<Path>,
) -> AppResult<PathBuf> {
    Ok(xdg_dirs.place_runtime_file(path)?)
}

#[cfg(target_os = "macos")]
fn place_app_support_file(path: impl AsRef<Path>) -> std::io::Result<PathBuf> {
    let path = app_support_dir()?.join(path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(path)
}

#[cfg(target_os = "macos")]
fn app_support_dir() -> std::io::Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "HOME is not set"))?;
    Ok(app_support_dir_from_home(home))
}

#[cfg(target_os = "macos")]
fn app_support_dir_from_home(home: impl AsRef<Path>) -> PathBuf {
    home.as_ref().join("Library/Application Support/monopass")
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    #[test]
    fn macos_app_support_dir_uses_pass_rs_subdirectory() {
        assert_eq!(
            std::path::PathBuf::from("/Users/example/Library/Application Support/monopass"),
            super::app_support_dir_from_home("/Users/example")
        );
    }
}
