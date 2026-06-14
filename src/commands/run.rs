use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::Command;

use clap::Args as ClapArgs;
use zeroize::Zeroizing;

use crate::AppResult;
use crate::config::Config;

use super::client::Client;
use super::path::{is_reference_value, parse_reference_path};

#[derive(Debug, Clone, ClapArgs)]
pub struct Args {
    #[arg(
        short,
        long = "env-file",
        help = "Read additional environment variables from a dotenv file"
    )]
    env_files: Vec<PathBuf>,
    #[arg(
        required = true,
        trailing_var_arg = true,
        allow_hyphen_values = true,
        help = "Command to run after resolving pass:// and op:// references"
    )]
    command: Vec<String>,
}

pub fn run(config: &Config, args: Args) -> AppResult {
    let client = Client::new(config);
    let mut env: HashMap<String, Zeroizing<String>> = std::env::vars()
        .map(|(key, value)| (key, Zeroizing::new(value)))
        .collect();
    for path in args.env_files {
        overlay_dotenv(&mut env, path)?;
    }

    let tempdir = tempfile::Builder::new().prefix("monopass-run.").tempdir()?;
    let keys: Vec<String> = env.keys().cloned().collect();
    for key in keys {
        let Some(value) = env.get(&key) else {
            continue;
        };
        if !is_reference_value(&value) {
            continue;
        }
        let reference = parse_reference_path(&value)?;
        let item = super::item::raw_item(&client, &reference.dir, &reference.item)?;
        let mut bytes = super::read::fetch_reference(config, &reference)?;
        if item.files.iter().any(|file| file.name == reference.name) {
            let file_path = tempdir.path().join(safe_temp_file_name(&key));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&file_path)?;
            file.write_all(&bytes)?;
            env.insert(
                key,
                Zeroizing::new(file_path.to_string_lossy().into_owned()),
            );
        } else if item.fields.iter().any(|field| field.name == reference.name) {
            let value = String::from_utf8(std::mem::take(&mut *bytes))
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            env.insert(key, Zeroizing::new(value));
        } else {
            return Err(
                io::Error::new(io::ErrorKind::NotFound, "reference not found in item").into(),
            );
        }
    }

    let status = Command::new(&args.command[0])
        .args(&args.command[1..])
        .env_clear()
        .envs(
            env.iter()
                .map(|(key, value)| (key.as_str(), value.as_str())),
        )
        .status()?;
    tempdir.close()?;
    match status.code() {
        Some(code) => std::process::exit(code),
        None => {
            Err(io::Error::new(io::ErrorKind::Interrupted, "child terminated by signal").into())
        }
    }
}

fn overlay_dotenv(env: &mut HashMap<String, Zeroizing<String>>, path: PathBuf) -> io::Result<()> {
    let file = fs::File::open(path)?;
    for line in io::BufReader::new(file).lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid dotenv line",
            ));
        };
        env.insert(key.trim().to_owned(), Zeroizing::new(unquote(value.trim())));
    }
    Ok(())
}

fn unquote(value: &str) -> String {
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value[1..value.len() - 1].to_owned()
    } else {
        value.to_owned()
    }
}

fn safe_temp_file_name(key: &str) -> String {
    key.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Write;

    use super::{overlay_dotenv, safe_temp_file_name};
    use zeroize::Zeroizing;

    #[test]
    fn dotenv_overlay_replaces_existing_values_and_unquotes() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "TOKEN=pass://Personal/api/token").unwrap();
        writeln!(file, "NAME=\"alice\"").unwrap();

        let mut env = HashMap::from([("NAME".to_owned(), Zeroizing::new("old".to_owned()))]);
        overlay_dotenv(&mut env, file.path().to_owned()).unwrap();

        assert_eq!(env["TOKEN"].as_str(), "pass://Personal/api/token");
        assert_eq!(env["NAME"].as_str(), "alice");
    }

    #[test]
    fn temp_file_names_are_path_safe() {
        assert_eq!(safe_temp_file_name("API/TOKEN value"), "API_TOKEN_value");
    }
}
