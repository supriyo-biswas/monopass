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
        required = true,
        num_args = 2..,
        value_name = "PATHS",
        help = "One or more source paths followed by the destination path"
    )]
    paths: Vec<String>,
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
    let transfers = plan_transfers(args.paths, args.recursive, |dir| {
        Ok(super::dir::list_all_items(&client, dir)?
            .into_iter()
            .map(|item| item.name)
            .collect())
    })?;

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
    paths: Vec<String>,
    recursive: bool,
    mut list_items: F,
) -> AppResult<Vec<Transfer>>
where
    F: FnMut(&str) -> AppResult<Vec<String>>,
{
    if paths.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected at least one source and one destination",
        )
        .into());
    }

    let (dest, sources) = paths
        .split_last()
        .expect("paths length checked before splitting");
    let mut expanded = Vec::new();
    let mut expanded_directory = false;

    for source in sources {
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
                for item in list_items(&dir)? {
                    expanded.push(ItemPath {
                        dir: dir.clone(),
                        item,
                    });
                }
            }
            Err(path) => expanded.push(path),
        }
    }

    let dest_is_dir = sources.len() > 1 || expanded_directory;
    if dest_is_dir {
        let dest_dir = parse_dir_path(dest)?;
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
    let dest = match parse_dir_or_item_path(dest)? {
        Ok(dir) => ItemPath {
            dir,
            item: source.item.clone(),
        },
        Err(path) => path,
    };
    Ok(vec![Transfer { source, dest }])
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

    fn no_dirs(_: &str) -> AppResult<Vec<String>> {
        panic!("directory listing should not be used")
    }

    #[test]
    fn rejects_fewer_than_two_paths() {
        let error = plan_transfers(vec!["Personal/github".to_owned()], false, no_dirs)
            .expect_err("single path should fail");

        assert!(error.to_string().contains("at least one source"));
    }

    #[test]
    fn single_source_to_item_destination_renames() {
        let plan = plan_transfers(
            vec!["Work/Github".to_owned(), "Personal/GitHub".to_owned()],
            false,
            no_dirs,
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
            vec!["Work/Github".to_owned(), "Personal".to_owned()],
            false,
            no_dirs,
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
            vec![
                "Work/Github".to_owned(),
                "Fun/Steam".to_owned(),
                "Personal/Github".to_owned(),
            ],
            false,
            no_dirs,
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
            vec![
                "Work/Github".to_owned(),
                "Fun/Steam".to_owned(),
                "Personal".to_owned(),
            ],
            false,
            no_dirs,
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
            vec!["Work".to_owned(), "Personal".to_owned()],
            false,
            no_dirs,
        )
        .expect_err("directory source should require recursion");

        assert!(error.to_string().contains("--recursive"));
    }

    #[test]
    fn recursive_directory_source_expands_listed_items_and_preserves_names() {
        let plan = plan_transfers(
            vec!["Work".to_owned(), "Personal".to_owned()],
            true,
            |dir| {
                assert_eq!(dir, "Work");
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
}
