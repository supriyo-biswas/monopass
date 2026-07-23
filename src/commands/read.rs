use std::fs::{self, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use clap::Args as ClapArgs;
use clap_complete::engine::ArgValueCompleter;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::AppResult;
use crate::config::Config;

use super::client::{AuthMode, Client, api_path, path_component};
use super::path::parse_reference_path;

#[derive(Debug, Clone, ClapArgs)]
pub struct Args {
    #[arg(add = ArgValueCompleter::new(super::completion::reference), help = "Reference path in <dir>/<item>/<fieldOrFile> form")]
    reference: String,
    #[arg(
        short,
        long,
        value_name = "FILE",
        help = "Write output to a file or - for stdout"
    )]
    out_file: Option<PathBuf>,
    #[arg(
        long,
        default_value = "0600",
        value_parser = parse_octal_mode,
        help = "File mode to use when writing to a file"
    )]
    file_mode: u32,
    #[arg(short, long, help = "Overwrite an existing output file")]
    force: bool,
}

pub fn run(config: &Config, args: Args) -> AppResult {
    let reference = parse_reference_path(&args.reference)?;
    let path = api_path(&format!(
        "/ref/{}/{}/{}",
        path_component(&reference.dir),
        path_component(&reference.item),
        path_component(&reference.name)
    ));
    let response = Client::new(config).get_bytes(&path, AuthMode::IncludePassword)?;
    let body = response.body;
    verify_etag(response.headers.get("etag").map(String::as_str), &body)?;

    match args.out_file {
        Some(path) if path.as_os_str() == "-" => write_stdout(&body),
        Some(path) => write_file(path, &body, args.file_mode, args.force),
        None => write_stdout(&body),
    }
}

pub fn fetch_reference(
    config: &Config,
    reference: &super::path::ReferencePath,
) -> AppResult<Zeroizing<Vec<u8>>> {
    let path = api_path(&format!(
        "/ref/{}/{}/{}",
        path_component(&reference.dir),
        path_component(&reference.item),
        path_component(&reference.name)
    ));
    let response = Client::new(config).get_bytes(&path, AuthMode::IncludePassword)?;
    verify_etag(
        response.headers.get("etag").map(String::as_str),
        &response.body,
    )?;
    Ok(response.body)
}

fn write_stdout(bytes: &[u8]) -> AppResult {
    let mut stdout = io::stdout().lock();
    stdout.write_all(bytes)?;
    if io::stdout().is_terminal() {
        stdout.write_all(b"\n")?;
    }
    Ok(())
}

fn write_file(path: PathBuf, bytes: &[u8], mode: u32, force: bool) -> AppResult {
    if path.exists() && !force {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("output file exists: {}", path.display()),
        )
        .into());
    }
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid output path"))?
        .to_string_lossy();
    let tmp_path = dir.join(format!(".{file_name}.tmp.{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp_path)?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&tmp_path);
        return Err(error.into());
    }
    fs::rename(&tmp_path, &path)?;
    Ok(())
}

fn verify_etag(etag: Option<&str>, bytes: &[u8]) -> AppResult {
    let Some(etag) = etag else {
        return Ok(());
    };
    let etag = etag.trim_matches('"');
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual != etag {
        return Err(
            io::Error::new(io::ErrorKind::InvalidData, "reference checksum mismatch").into(),
        );
    }
    Ok(())
}

fn parse_octal_mode(value: &str) -> Result<u32, String> {
    u32::from_str_radix(value.trim_start_matches("0o"), 8).map_err(|error| error.to_string())
}
