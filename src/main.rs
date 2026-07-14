use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> monopass::AppResult {
    let cli = monopass::commands::Cli::parse();
    let config = monopass::config::Config::load()?;
    monopass::commands::run(&config, cli.command)
}
