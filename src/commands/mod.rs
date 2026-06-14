use crate::AppResult;
use crate::config::Config;

use clap::{Parser, Subcommand};

mod agent;
mod client;
mod contact;
#[cfg(debug_assertions)]
mod dbg;
mod dir;
mod import;
mod init;
mod item;
mod lock;
mod models;
mod passwd;
mod password_policy;
mod path;
mod pubkey;
mod pwgen;
mod read;
mod run;
mod share;
mod totp;
mod transfer;
mod wordlist;

#[derive(Debug, Parser)]
#[command(
    name = "monopass",
    version,
    about = "Command line password manager",
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "Initialize the database and configure auto-start")]
    Init(init::Args),
    #[command(about = "Run the password management agent")]
    Agent,
    #[command(about = "Change the database master password")]
    Passwd,
    #[command(about = "Clear cached process authorizations")]
    Lock,
    #[command(about = "Read a field or file reference")]
    Read(read::Args),
    #[command(about = "Run a command with monopass references resolved in the environment")]
    Run(run::Args),
    #[command(about = "Create a directory")]
    Mkdir(dir::MkdirArgs),
    #[command(about = "Remove an empty directory")]
    Rmdir(dir::RmdirArgs),
    #[command(about = "Add an item")]
    Add(item::AddArgs),
    #[command(about = "Edit an item")]
    Edit(item::EditArgs),
    #[command(name = "rm", about = "Remove an item or directory")]
    Remove(item::RemoveArgs),
    #[command(name = "cp", about = "Copy items")]
    Copy(transfer::Args),
    #[command(name = "mv", about = "Move items")]
    Move(transfer::Args),
    #[command(name = "ls", about = "List directories or items")]
    List(dir::ListArgs),
    #[command(name = "ls-versions", about = "List item versions")]
    ListVersions(item::ListVersionsArgs),
    #[command(about = "Restore an item version")]
    Restore(item::RestoreArgs),
    #[command(about = "Show item metadata")]
    Show(item::ShowArgs),
    #[command(name = "ls-contacts", about = "List contacts")]
    ListContacts,
    #[command(name = "add-contact", about = "Add a contact")]
    AddContact(contact::AddArgs),
    #[command(name = "edit-contact", about = "Edit a contact")]
    EditContact(contact::EditArgs),
    #[command(name = "rm-contact", about = "Remove a contact")]
    RemoveContact(contact::RemoveArgs),
    #[command(about = "Print the local age public key")]
    Pubkey,
    #[command(about = "Export an item for a contact")]
    Share(share::Args),
    #[command(about = "Import a shared item")]
    Import(import::Args),
    #[cfg(debug_assertions)]
    #[command(name = "dbg-shell", about = "Open a debug SQL shell")]
    DbgShell,
}

pub fn run(config: &Config, command: Command) -> AppResult {
    match command {
        Command::Init(args) => init::run(config, args),
        Command::Agent => agent::run(config),
        Command::Passwd => passwd::run(config),
        Command::Lock => lock::run(config),
        Command::Read(args) => read::run(config, args),
        Command::Run(args) => run::run(config, args),
        Command::Mkdir(args) => dir::mkdir(config, args),
        Command::Rmdir(args) => dir::rmdir(config, args),
        Command::Add(args) => item::add(config, args),
        Command::Edit(args) => item::edit(config, args),
        Command::Remove(args) => item::remove(config, args),
        Command::Copy(args) => transfer::copy(config, args),
        Command::Move(args) => transfer::move_(config, args),
        Command::List(args) => dir::list(config, args),
        Command::ListVersions(args) => item::list_versions(config, args),
        Command::Restore(args) => item::restore(config, args),
        Command::Show(args) => item::show(config, args),
        Command::ListContacts => contact::list(config),
        Command::AddContact(args) => contact::add(config, args),
        Command::EditContact(args) => contact::edit(config, args),
        Command::RemoveContact(args) => contact::remove(config, args),
        Command::Pubkey => pubkey::run(config),
        Command::Share(args) => share::run(config, args),
        Command::Import(args) => import::run(config, args),
        #[cfg(debug_assertions)]
        Command::DbgShell => dbg::shell(config),
    }
}
