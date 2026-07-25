use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use clap::Args as ClapArgs;
use clap_complete::engine::ArgValueCompleter;

use crate::AppResult;
use crate::config::Config;

use super::path::parse_reference_path;

#[derive(Debug, Clone, ClapArgs)]
pub struct Args {
    #[arg(add = ArgValueCompleter::new(super::completion::reference), help = "Reference path in <dir>/<item>/<fieldOrFile> form")]
    reference: String,
}

pub fn run(config: &Config, args: Args) -> AppResult {
    let reference = parse_reference_path(&args.reference)?;
    let bytes = super::read::fetch_reference(config, &reference)?;
    let (program, program_args) = clipboard_command()?;
    write_to_command(program, program_args, &bytes)
}

#[cfg(target_os = "macos")]
fn clipboard_command() -> AppResult<(&'static Path, &'static [&'static str])> {
    const PBCOPY: &str = "/usr/bin/pbcopy";
    let program = Path::new(PBCOPY);
    if !program.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("clipboard command not found: {PBCOPY}"),
        )
        .into());
    }
    Ok((program, &[]))
}

#[cfg(target_os = "linux")]
fn clipboard_command() -> AppResult<(&'static Path, &'static [&'static str])> {
    const XCLIP_PATHS: [&str; 2] = ["/usr/local/bin/xclip", "/usr/bin/xclip"];
    const XCLIP_ARGS: [&str; 2] = ["-selection", "clipboard"];

    let program = XCLIP_PATHS
        .iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "clipboard command not found at {} or {}",
                    XCLIP_PATHS[0], XCLIP_PATHS[1]
                ),
            )
        })?;
    Ok((program, &XCLIP_ARGS))
}

fn write_to_command(program: &Path, args: &[&str], bytes: &[u8]) -> AppResult {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "clipboard command stdin is unavailable",
        )
    })?;
    let write_result = stdin.write_all(bytes);
    drop(stdin);
    let status = child.wait()?;
    write_result?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "clipboard command {} exited with {status}",
            program.display()
        ))
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn writes_exact_bytes_to_clipboard_command_stdin() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("clipboard");
        let command = Path::new("/bin/sh");
        let output_arg = output.to_str().unwrap();

        write_to_command(
            command,
            &["-c", "cat > \"$1\"", "sh", output_arg],
            b"a\0b\n",
        )
        .unwrap();

        assert_eq!(fs::read(output).unwrap(), b"a\0b\n");
    }

    #[test]
    fn rejects_unsuccessful_clipboard_command() {
        let error =
            write_to_command(Path::new("/bin/sh"), &["-c", "exit 7"], b"secret").unwrap_err();

        assert!(error.to_string().contains("exited with exit status: 7"));
    }
}
