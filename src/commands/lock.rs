use crate::AppResult;
use crate::commands::client::Client;
use crate::config::Config;

pub fn run(config: &Config) -> AppResult {
    Client::new(config).post_empty_without_unlock("/api/v1/auth/lock")
}
