use std::process::ExitCode;

use clap::Parser;

mod agent;
mod commands;
mod conceal;
mod config;
mod db;
mod lock;
mod secret;
mod settings;

pub type AppResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> AppResult {
    let cli = commands::Cli::parse();
    let config = config::Config::load()?;
    commands::run(&config, cli.command)
}
