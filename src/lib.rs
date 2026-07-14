pub mod agent;
pub mod commands;
pub mod conceal;
pub mod config;
pub mod db;
pub mod lock;
pub mod secret;
pub mod settings;

pub type AppResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
