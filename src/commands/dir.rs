use clap::Args as ClapArgs;

use crate::AppResult;
use crate::config::Config;

use super::client::{Client, api_path, path_component};
use super::models::{DirResponse, ItemSummaryResponse, PaginatedResponse};

#[derive(Debug, Clone, ClapArgs)]
pub struct MkdirArgs {
    #[arg(short = 'p', help = "Ignore existing directories")]
    parents: bool,
    #[arg(help = "Directory path")]
    dir: String,
}

#[derive(Debug, Clone, ClapArgs)]
pub struct RmdirArgs {
    #[arg(help = "Directory path")]
    dir: String,
}

#[derive(Debug, Clone, ClapArgs)]
pub struct ListArgs {
    #[arg(help = "Optional directory path")]
    dir: Option<String>,
}

pub fn mkdir(config: &Config, args: MkdirArgs) -> AppResult {
    let client = Client::new(config);
    let path = api_path(&format!("/dir/{}", path_component(&args.dir)));
    match client.put_empty(&path) {
        Ok(()) => Ok(()),
        Err(error) if args.parents && is_conflict(&error) => Ok(()),
        Err(error) => Err(error),
    }
}

pub fn rmdir(config: &Config, args: RmdirArgs) -> AppResult {
    let client = Client::new(config);
    client.delete_empty(&api_path(&format!("/dir/{}", path_component(&args.dir))))
}

pub fn list(config: &Config, args: ListArgs) -> AppResult {
    let client = Client::new(config);
    if let Some(dir) = args.dir {
        for item in list_all_items(&client, &dir)? {
            println!("{}", item.name);
        }
    } else {
        for dir in list_all_dirs(&client)? {
            println!("{}", dir.name);
        }
    }
    Ok(())
}

pub fn list_all_dirs(client: &Client<'_>) -> AppResult<Vec<DirResponse>> {
    let mut entries = Vec::new();
    let mut marker: Option<String> = None;
    loop {
        let path = match &marker {
            Some(marker) => api_path(&format!(
                "/dirs?count=200&marker={}",
                super::client::query_value(marker)
            )),
            None => api_path("/dirs?count=200"),
        };
        let page: PaginatedResponse<DirResponse> = client.get_json(&path)?;
        entries.extend(page.entries);
        match page.next_marker {
            Some(next) => marker = Some(next),
            None => return Ok(entries),
        }
    }
}

pub fn list_all_items(client: &Client<'_>, dir: &str) -> AppResult<Vec<ItemSummaryResponse>> {
    let mut entries = Vec::new();
    let mut marker: Option<String> = None;
    loop {
        let path = match &marker {
            Some(marker) => api_path(&format!(
                "/dir/{}/items?count=200&marker={}",
                path_component(dir),
                super::client::query_value(marker)
            )),
            None => api_path(&format!("/dir/{}/items?count=200", path_component(dir))),
        };
        let page: PaginatedResponse<ItemSummaryResponse> = client.get_json(&path)?;
        entries.extend(page.entries);
        match page.next_marker {
            Some(next) => marker = Some(next),
            None => return Ok(entries),
        }
    }
}

fn is_conflict(error: &Box<dyn std::error::Error>) -> bool {
    error
        .downcast_ref::<super::client::ApiError>()
        .is_some_and(|error| error.status == 409 && error.code == "conflict")
}
