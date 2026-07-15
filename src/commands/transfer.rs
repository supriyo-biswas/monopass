use std::collections::HashSet;
use std::io;

use clap::Args as ClapArgs;

use crate::AppResult;
use crate::config::Config;

use super::client::{Client, api_path, path_component, query_value};
use super::models::CreateItemRequest;
use super::path::{ItemPath, parse_dir_or_item_path};

#[derive(Debug, Clone, ClapArgs)]
pub struct Args {
    #[arg(
        short,
        long,
        help = "Expand directory sources and transfer their items"
    )]
    recursive: bool,
    #[arg(
        short = 'g',
        long,
        help = "Treat item source names literally instead of as glob patterns"
    )]
    globoff: bool,
    #[arg(
        required = true,
        num_args = 1..,
        value_name = "SOURCE",
        help = "Source item, glob, or directory path"
    )]
    sources: Vec<String>,
    #[arg(
        value_name = "DESTINATION",
        help = "Destination item or directory path"
    )]
    destination: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Copy,
    Move,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Transfer {
    source: ItemPath,
    dest: ItemPath,
}

pub fn copy(config: &Config, args: Args) -> AppResult {
    run(config, args, Operation::Copy)
}

pub fn move_(config: &Config, args: Args) -> AppResult {
    run(config, args, Operation::Move)
}

fn run(config: &Config, args: Args, operation: Operation) -> AppResult {
    let client = Client::new(config);
    let transfers = plan_transfers(
        args.sources,
        args.destination,
        args.recursive,
        args.globoff,
        |dir, glob| {
            Ok(super::dir::list_all_matching_items(&client, dir, glob)?
                .into_iter()
                .map(|item| item.name)
                .collect())
        },
    )?;

    for transfer in transfers {
        execute_transfer(&client, operation, &transfer)?;
    }
    Ok(())
}

fn execute_transfer(client: &Client<'_>, operation: Operation, transfer: &Transfer) -> AppResult {
    let path = match operation {
        Operation::Copy => api_path(&format!(
            "/dir/{}/item/{}?copy_from={}/{}",
            path_component(&transfer.dest.dir),
            path_component(&transfer.dest.item),
            query_value(&transfer.source.dir),
            query_value(&transfer.source.item)
        )),
        Operation::Move => api_path(&format!(
            "/dir/{}/item/{}?move_from={}/{}",
            path_component(&transfer.dest.dir),
            path_component(&transfer.dest.item),
            query_value(&transfer.source.dir),
            query_value(&transfer.source.item)
        )),
    };

    match operation {
        Operation::Copy => client.put_json(&path, &CreateItemRequest::default()),
        Operation::Move => client.put_empty(&path),
    }
}

fn plan_transfers<F>(
    sources: Vec<String>,
    destination: String,
    recursive: bool,
    globoff: bool,
    mut list_items: F,
) -> AppResult<Vec<Transfer>>
where
    F: FnMut(&str, Option<&str>) -> AppResult<Vec<String>>,
{
    let mut expanded = Vec::new();
    let mut seen = HashSet::new();
    let mut expanded_directory = false;

    for source in &sources {
        match parse_dir_or_item_path(source)? {
            Ok(dir) => {
                if !recursive {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "directory sources require --recursive",
                    )
                    .into());
                }
                expanded_directory = true;
                let items = list_items(&dir, None)?;
                if items.is_empty() {
                    return Err(no_source_matches(source));
                }
                for item in items {
                    push_unique_source(&mut expanded, &mut seen, &dir, item);
                }
            }
            Err(path) if globoff => {
                push_unique_source(&mut expanded, &mut seen, &path.dir, path.item);
            }
            Err(path) => {
                let items = list_items(&path.dir, Some(&path.item))?;
                if items.is_empty() {
                    return Err(no_source_matches(source));
                }
                for item in items {
                    push_unique_source(&mut expanded, &mut seen, &path.dir, item);
                }
            }
        }
    }

    let dest_is_dir = expanded.len() > 1 || expanded_directory;
    if dest_is_dir {
        let dest_dir = parse_dir_path(&destination)?;
        return Ok(expanded
            .into_iter()
            .map(|source| Transfer {
                dest: ItemPath {
                    dir: dest_dir.clone(),
                    item: source.item.clone(),
                },
                source,
            })
            .collect());
    }

    let source = expanded
        .into_iter()
        .next()
        .expect("at least one source exists after path validation");
    let dest = match parse_dir_or_item_path(&destination)? {
        Ok(dir) => ItemPath {
            dir,
            item: source.item.clone(),
        },
        Err(path) => path,
    };
    Ok(vec![Transfer { source, dest }])
}

fn push_unique_source(
    expanded: &mut Vec<ItemPath>,
    seen: &mut HashSet<(String, String)>,
    dir: &str,
    item: String,
) {
    if seen.insert((dir.to_owned(), item.clone())) {
        expanded.push(ItemPath {
            dir: dir.to_owned(),
            item,
        });
    }
}

fn no_source_matches(source: &str) -> Box<dyn std::error::Error> {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("source matched no items: {source}"),
    )
    .into()
}

fn parse_dir_path(input: &str) -> io::Result<String> {
    match parse_dir_or_item_path(input)? {
        Ok(dir) => Ok(dir),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "destination must be a directory",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{ItemPath, Transfer, plan_transfers};
    use crate::AppResult;

    fn no_lists(_: &str, _: Option<&str>) -> AppResult<Vec<String>> {
        panic!("directory listing should not be used")
    }

    #[test]
    fn single_source_to_item_destination_renames() {
        let plan = plan_transfers(
            vec!["Work/Github".to_owned()],
            "Personal/GitHub".to_owned(),
            false,
            true,
            no_lists,
        )
        .unwrap();

        assert_eq!(
            plan,
            vec![Transfer {
                source: ItemPath {
                    dir: "Work".to_owned(),
                    item: "Github".to_owned(),
                },
                dest: ItemPath {
                    dir: "Personal".to_owned(),
                    item: "GitHub".to_owned(),
                },
            }]
        );
    }

    #[test]
    fn single_source_to_directory_destination_preserves_name() {
        let plan = plan_transfers(
            vec!["Work/Github".to_owned()],
            "Personal".to_owned(),
            false,
            true,
            no_lists,
        )
        .unwrap();

        assert_eq!(
            plan[0].dest,
            ItemPath {
                dir: "Personal".to_owned(),
                item: "Github".to_owned(),
            }
        );
    }

    #[test]
    fn multiple_sources_require_directory_destination() {
        let error = plan_transfers(
            vec!["Work/Github".to_owned(), "Fun/Steam".to_owned()],
            "Personal/Github".to_owned(),
            false,
            true,
            no_lists,
        )
        .expect_err("item destination should fail for multiple sources");

        assert!(
            error
                .to_string()
                .contains("destination must be a directory")
        );
    }

    #[test]
    fn multiple_sources_preserve_names_in_destination_directory() {
        let plan = plan_transfers(
            vec!["Work/Github".to_owned(), "Fun/Steam".to_owned()],
            "Personal".to_owned(),
            false,
            true,
            no_lists,
        )
        .unwrap();

        assert_eq!(
            plan,
            vec![
                Transfer {
                    source: ItemPath {
                        dir: "Work".to_owned(),
                        item: "Github".to_owned(),
                    },
                    dest: ItemPath {
                        dir: "Personal".to_owned(),
                        item: "Github".to_owned(),
                    },
                },
                Transfer {
                    source: ItemPath {
                        dir: "Fun".to_owned(),
                        item: "Steam".to_owned(),
                    },
                    dest: ItemPath {
                        dir: "Personal".to_owned(),
                        item: "Steam".to_owned(),
                    },
                },
            ]
        );
    }

    #[test]
    fn directory_source_without_recursive_fails() {
        let error = plan_transfers(
            vec!["Work".to_owned()],
            "Personal".to_owned(),
            false,
            true,
            no_lists,
        )
        .expect_err("directory source should require recursion");

        assert!(error.to_string().contains("--recursive"));
    }

    #[test]
    fn recursive_directory_source_expands_listed_items_and_preserves_names() {
        let plan = plan_transfers(
            vec!["Work".to_owned()],
            "Personal".to_owned(),
            true,
            false,
            |dir, glob| {
                assert_eq!(dir, "Work");
                assert_eq!(glob, None);
                Ok(vec!["Github".to_owned(), "Gitlab".to_owned()])
            },
        )
        .unwrap();

        assert_eq!(
            plan,
            vec![
                Transfer {
                    source: ItemPath {
                        dir: "Work".to_owned(),
                        item: "Github".to_owned(),
                    },
                    dest: ItemPath {
                        dir: "Personal".to_owned(),
                        item: "Github".to_owned(),
                    },
                },
                Transfer {
                    source: ItemPath {
                        dir: "Work".to_owned(),
                        item: "Gitlab".to_owned(),
                    },
                    dest: ItemPath {
                        dir: "Personal".to_owned(),
                        item: "Gitlab".to_owned(),
                    },
                },
            ]
        );
    }

    #[test]
    fn single_glob_match_can_use_item_destination() {
        let plan = plan_transfers(
            vec!["Work/Git*".to_owned()],
            "Personal/Renamed".to_owned(),
            false,
            false,
            |dir, glob| {
                assert_eq!((dir, glob), ("Work", Some("Git*")));
                Ok(vec!["Github".to_owned()])
            },
        )
        .unwrap();

        assert_eq!(plan[0].source.item, "Github");
        assert_eq!(plan[0].dest.item, "Renamed");
    }

    #[test]
    fn multiple_glob_matches_require_directory_destination() {
        let error = plan_transfers(
            vec!["Work/Git*".to_owned()],
            "Personal/Renamed".to_owned(),
            false,
            false,
            |_, _| Ok(vec!["Github".to_owned(), "Gitlab".to_owned()]),
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("destination must be a directory")
        );
    }

    #[test]
    fn glob_and_recursive_sources_must_match_before_planning() {
        for (sources, recursive) in [
            (vec!["Work/Missing*".to_owned()], false),
            (vec!["Work".to_owned()], true),
        ] {
            let error = plan_transfers(sources, "Personal".to_owned(), recursive, false, |_, _| {
                Ok(Vec::new())
            })
            .expect_err("empty source should fail");
            assert!(error.to_string().contains("matched no items"));
        }
    }

    #[test]
    fn overlapping_patterns_are_deduplicated_in_first_match_order() {
        let plan = plan_transfers(
            vec!["Work/Git*".to_owned(), "Work/*hub".to_owned()],
            "Personal".to_owned(),
            false,
            false,
            |_, glob| match glob {
                Some("Git*") => Ok(vec!["Github".to_owned(), "Gitlab".to_owned()]),
                Some("*hub") => Ok(vec!["Github".to_owned(), "Codehub".to_owned()]),
                _ => unreachable!(),
            },
        )
        .unwrap();

        assert_eq!(
            plan.iter()
                .map(|transfer| transfer.source.item.as_str())
                .collect::<Vec<_>>(),
            vec!["Github", "Gitlab", "Codehub"]
        );
    }

    #[test]
    fn globoff_keeps_metacharacters_literal_and_destination_is_never_listed() {
        let plan = plan_transfers(
            vec!["Work/literal*[x]".to_owned()],
            "Personal/dest*".to_owned(),
            false,
            true,
            no_lists,
        )
        .unwrap();

        assert_eq!(plan[0].source.item, "literal*[x]");
        assert_eq!(plan[0].dest.item, "dest*");
    }

    #[test]
    fn destination_is_literal_when_source_globbing_is_enabled() {
        let mut calls = Vec::new();
        let plan = plan_transfers(
            vec!["Work/Git*".to_owned()],
            "Personal/dest*".to_owned(),
            false,
            false,
            |dir, glob| {
                calls.push((dir.to_owned(), glob.map(str::to_owned)));
                Ok(vec!["Github".to_owned()])
            },
        )
        .unwrap();

        assert_eq!(calls, vec![("Work".to_owned(), Some("Git*".to_owned()))]);
        assert_eq!(plan[0].dest.item, "dest*");
    }
}
