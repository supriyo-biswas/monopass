use std::io;
use std::os::unix::fs::PermissionsExt;

use clap::{Args as ClapArgs, ValueEnum};

use crate::commands::password_policy::{prompt_confirmation, validate_master_password};
use crate::config::Config;
use crate::{AppResult, db};

mod autostart;

const PRIVATE_DIR_MODE: u32 = 0o700;

#[derive(Debug, Clone, ClapArgs)]
pub struct Args {
    #[arg(
        long,
        value_enum,
        value_name = "yes|no",
        help = "Configure agent auto-start"
    )]
    auto_start: Option<AutoStart>,
    #[arg(
        long,
        help = "Skip database initialization when the database already exists"
    )]
    skip_db_if_exists: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum AutoStart {
    Yes,
    No,
}

pub fn run(config: &Config, args: Args) -> AppResult {
    if config.database_path().exists() && !args.skip_db_if_exists {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "database already exists: {}",
                config.database_path().display()
            ),
        )
        .into());
    }

    if !config.database_path().exists() {
        let password = db::prompt_password("Enter master password: ")?;
        validate_master_password(&password)?;

        let confirmed_password = db::prompt_password("Confirm master password: ")?;

        if password.as_str() != confirmed_password.as_str() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "passwords do not match").into(),
            );
        }

        create_private_dir(config.file_store_path())?;
        create_private_dir(config.job_store_path())?;
        db::create_encrypted_database_with_password(config.database_path(), &password)?;
        println!("Initialized {}", config.database_path().display());
    } else if args.skip_db_if_exists {
        println!(
            "Skipped database initialization for existing {}",
            config.database_path().display()
        );
    }

    if should_configure_auto_start(args.auto_start)? {
        autostart::enable_agent(config.listen_path())?;
        println!("Configured agent auto-start");
    }

    Ok(())
}

fn create_private_dir(path: &std::path::Path) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_DIR_MODE))
}

fn should_configure_auto_start(auto_start: Option<AutoStart>) -> io::Result<bool> {
    match auto_start {
        Some(AutoStart::Yes) => Ok(true),
        Some(AutoStart::No) => Ok(false),
        None => prompt_auto_start(),
    }
}

fn prompt_auto_start() -> io::Result<bool> {
    prompt_confirmation("Configure agent auto-start? [y/n] ")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::{Args, AutoStart, run};
    use crate::config::Config;

    fn config_with_database_path(database_path: PathBuf) -> Config {
        let parent = database_path.parent().unwrap().to_path_buf();
        Config::new(
            database_path,
            parent.join("files"),
            parent.join("jobs"),
            parent.join("agent.sock"),
            parent.join("agent.lock"),
        )
    }

    #[test]
    fn skip_db_if_exists_allows_existing_database_to_reach_auto_start() {
        let tempdir = tempfile::TempDir::new().unwrap();
        let database_path = tempdir.path().join("monopass.db");
        fs::write(&database_path, b"existing database").unwrap();
        let config = config_with_database_path(database_path);

        let args = Args {
            auto_start: Some(AutoStart::No),
            skip_db_if_exists: true,
        };

        run(&config, args).unwrap();

        assert!(config.database_path().exists());
        assert!(!config.file_store_path().exists());
        assert!(!config.job_store_path().exists());
    }
}
