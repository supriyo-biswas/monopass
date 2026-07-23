use clap::Args as ClapArgs;
use clap_complete::engine::ArgValueCompleter;

use crate::AppResult;
use crate::config::Config;

use super::client::{Client, api_path, path_component};
use super::models::{DirResponse, ItemSummaryResponse, PaginatedResponse};
use super::path::parse_dir_or_item_path;

#[derive(Debug, Clone, ClapArgs)]
pub struct MkdirArgs {
    #[arg(short = 'p', help = "Ignore existing directories")]
    parents: bool,
    #[arg(help = "Directory path")]
    dir: String,
}

#[derive(Debug, Clone, ClapArgs)]
pub struct RmdirArgs {
    #[arg(add = ArgValueCompleter::new(super::completion::existing_dir), help = "Directory path")]
    dir: String,
}

#[derive(Debug, Clone, ClapArgs)]
pub struct ListArgs {
    #[arg(
        short = 'g',
        long,
        help = "Treat an item name literally instead of as a glob pattern"
    )]
    globoff: bool,
    #[arg(add = ArgValueCompleter::new(super::completion::dir_or_item), help = "Optional directory or <dir>/<glob> path")]
    path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ListTarget {
    Dirs,
    Items { dir: String, glob: Option<String> },
}

pub fn mkdir(config: &Config, args: MkdirArgs) -> AppResult {
    let client = Client::new(config);
    let path = api_path(&format!("/dir/{}", path_component(&args.dir)));
    match client.put_empty(&path) {
        Ok(()) => Ok(()),
        Err(error) if args.parents && is_conflict(error.as_ref()) => Ok(()),
        Err(error) => Err(error),
    }
}

pub fn rmdir(config: &Config, args: RmdirArgs) -> AppResult {
    let client = Client::new(config);
    client.delete_empty(&api_path(&format!("/dir/{}", path_component(&args.dir))))
}

pub fn list(config: &Config, args: ListArgs) -> AppResult {
    let client = Client::new(config);
    match parse_list_target(args.path.as_deref(), args.globoff)? {
        ListTarget::Items { dir, glob } => {
            for item in list_all_matching_items(&client, &dir, glob.as_deref())? {
                println!("{}", item.name);
            }
        }
        ListTarget::Dirs => {
            for dir in list_all_dirs(&client)? {
                println!("{}", dir.name);
            }
        }
    }
    Ok(())
}

fn parse_list_target(path: Option<&str>, globoff: bool) -> std::io::Result<ListTarget> {
    match path {
        None => Ok(ListTarget::Dirs),
        Some(path) => {
            let (path, has_trailing_slash) = path
                .strip_suffix('/')
                .map_or((path, false), |path| (path, true));
            match parse_dir_or_item_path(path)? {
                Ok(dir) => Ok(ListTarget::Items { dir, glob: None }),
                Err(_) if has_trailing_slash => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "a trailing slash is only valid after a directory name",
                )),
                Err(path) => Ok(ListTarget::Items {
                    dir: path.dir,
                    glob: Some(if globoff {
                        escape_sqlite_glob(&path.item)
                    } else {
                        path.item
                    }),
                }),
            }
        }
    }
}

pub(crate) fn escape_sqlite_glob(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '*' => escaped.push_str("[*]"),
            '?' => escaped.push_str("[?]"),
            '[' => escaped.push_str("[[]"),
            _ => escaped.push(character),
        }
    }
    escaped
}

pub(crate) fn list_all_matching_items(
    client: &Client<'_>,
    dir: &str,
    glob: Option<&str>,
) -> AppResult<Vec<ItemSummaryResponse>> {
    let mut entries = Vec::new();
    let mut marker: Option<String> = None;
    loop {
        let page = list_items_page(client, dir, 200, marker.as_deref(), glob, false)?;
        entries.extend(page.entries);
        match page.next_marker {
            Some(next) => marker = Some(next),
            None => return Ok(entries),
        }
    }
}

pub fn list_items_page(
    client: &Client<'_>,
    dir: &str,
    count: u64,
    marker: Option<&str>,
    glob: Option<&str>,
    descending: bool,
) -> AppResult<PaginatedResponse<ItemSummaryResponse>> {
    let mut path = format!("/dir/{}/items?count={count}", path_component(dir));
    if let Some(marker) = marker {
        path.push_str("&marker=");
        path.push_str(&super::client::query_value(marker));
    }
    if let Some(glob) = glob {
        path.push_str("&glob=");
        path.push_str(&super::client::query_value(glob));
    }
    if descending {
        path.push_str("&dir=desc");
    }
    client.get_json(&api_path(&path))
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

fn is_conflict(error: &(dyn std::error::Error + 'static)) -> bool {
    error
        .downcast_ref::<super::client::ApiError>()
        .is_some_and(|error| error.status == 409 && error.code == "conflict")
}

#[cfg(test)]
mod tests {
    use super::{ListTarget, parse_list_target};

    #[test]
    fn list_target_supports_directories_and_item_globs() {
        assert_eq!(ListTarget::Dirs, parse_list_target(None, false).unwrap());
        assert_eq!(
            ListTarget::Items {
                dir: "Personal".to_owned(),
                glob: None,
            },
            parse_list_target(Some("Personal"), false).unwrap()
        );
        assert_eq!(
            ListTarget::Items {
                dir: "Personal".to_owned(),
                glob: None,
            },
            parse_list_target(Some("Personal/"), false).unwrap()
        );
        assert_eq!(
            ListTarget::Items {
                dir: "Personal".to_owned(),
                glob: None,
            },
            parse_list_target(Some("pass://Personal/"), false).unwrap()
        );
        assert_eq!(
            ListTarget::Items {
                dir: "Personal".to_owned(),
                glob: Some("*Github*".to_owned()),
            },
            parse_list_target(Some("Personal/*Github*"), false).unwrap()
        );
        assert!(parse_list_target(Some("Personal/Github/"), false).is_err());
        assert!(parse_list_target(Some("Personal//"), false).is_err());
    }

    #[test]
    fn list_globoff_treats_the_item_name_literally() {
        assert_eq!(
            ListTarget::Items {
                dir: "Personal".to_owned(),
                glob: Some("literal[*][[]name][?]".to_owned()),
            },
            parse_list_target(Some("Personal/literal*[name]?"), true).unwrap()
        );
    }
}
