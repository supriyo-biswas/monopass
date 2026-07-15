use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::Local;
use clap::Args as ClapArgs;

use crate::AppResult;
use crate::config::Config;

use super::client::{Client, api_path, path_component};
use super::models::{JobAcceptedResponse, JobResponse, JobStatus};
use super::path::{ItemPath, parse_dir_or_item_path};

#[derive(Debug, Clone, ClapArgs)]
pub struct Args {
    #[arg(short, long, help = "Expand directory sources and share their items")]
    recursive: bool,
    #[arg(
        short = 'g',
        long,
        help = "Treat item source names literally instead of as glob patterns"
    )]
    globoff: bool,
    #[arg(
        value_name = "ITEM",
        required = true,
        num_args = 1..,
        help = "Source item, glob, or directory path"
    )]
    items: Vec<String>,
    #[arg(value_name = "CONTACT", help = "Contact email address")]
    contact: String,
    #[arg(
        short,
        long,
        value_name = "FILE",
        conflicts_with = "out_dir",
        help = "Write the encrypted export to a file, or - for stdout"
    )]
    out_file: Option<PathBuf>,
    #[arg(long, value_name = "DIR", help = "Write exports into this directory")]
    out_dir: Option<PathBuf>,
}

pub fn run(config: &Config, args: Args) -> AppResult {
    let Args {
        recursive,
        globoff,
        items,
        contact,
        out_file,
        out_dir,
    } = args;
    let client = Client::new(config);
    let paths = plan_share_items(
        items,
        recursive,
        globoff,
        out_file.is_some(),
        |dir, glob| {
            Ok(super::dir::list_all_matching_items(&client, dir, glob)?
                .into_iter()
                .map(|item| item.name)
                .collect())
        },
    )?;
    let destinations = destinations(&paths, &contact, out_file, out_dir)?;
    let mut copied = Vec::new();

    for (item_path, destination) in paths.into_iter().zip(destinations) {
        let accepted: JobAcceptedResponse = client.put_empty_json(&api_path(&format!(
            "/jobs/export/{}/{}/{}",
            path_component(&item_path.dir),
            path_component(&item_path.item),
            path_component(&contact),
        )))?;
        let output_path = poll_export_job(&client, &accepted.job_id)?;
        copy_job_output(&output_path, &destination)?;
        fs::remove_file(&output_path)?;
        copied.push(destination);
    }

    for path in copied {
        println!("{}", path.display());
    }

    Ok(())
}

fn plan_share_items<F>(
    sources: Vec<String>,
    recursive: bool,
    globoff: bool,
    single_output: bool,
    mut list_items: F,
) -> AppResult<Vec<ItemPath>>
where
    F: FnMut(&str, Option<&str>) -> AppResult<Vec<String>>,
{
    let mut expanded = Vec::new();
    let mut seen = HashSet::new();

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
                let items = list_items(&dir, None)?;
                if items.is_empty() {
                    return Err(no_source_matches(source));
                }
                for item in items {
                    push_unique_item(&mut expanded, &mut seen, &dir, item);
                }
            }
            Err(path) if globoff => {
                push_unique_item(&mut expanded, &mut seen, &path.dir, path.item);
            }
            Err(path) => {
                let items = list_items(&path.dir, Some(&path.item))?;
                if items.is_empty() {
                    return Err(no_source_matches(source));
                }
                for item in items {
                    push_unique_item(&mut expanded, &mut seen, &path.dir, item);
                }
            }
        }
    }

    if single_output && expanded.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--out-file is only allowed when exporting exactly one item",
        )
        .into());
    }

    Ok(expanded)
}

fn push_unique_item(
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

fn destinations(
    paths: &[ItemPath],
    contact: &str,
    out_file: Option<PathBuf>,
    out_dir: Option<PathBuf>,
) -> io::Result<Vec<PathBuf>> {
    if let Some(out_file) = out_file {
        return Ok(vec![out_file]);
    }

    let base_dir = out_dir.unwrap_or_else(|| PathBuf::from("."));
    let mut counts = HashMap::new();
    Ok(paths
        .iter()
        .map(|path| {
            let name = default_file_name(contact, &path.item);
            let unique = unique_file_name(name, &mut counts);
            base_dir.join(unique)
        })
        .collect())
}

fn default_file_name(contact: &str, item: &str) -> String {
    let timestamp = Local::now().format("%Y%m%d-%H%M%S");
    format!("{contact}_{item}_{timestamp}.export")
}

fn unique_file_name(name: String, counts: &mut HashMap<String, usize>) -> String {
    let count = counts.entry(name.clone()).or_insert(0);
    *count += 1;
    if *count == 1 {
        return name;
    }

    match name.strip_suffix(".export") {
        Some(stem) => format!("{stem}-{}.export", *count),
        None => format!("{name}-{}", *count),
    }
}

fn poll_export_job(client: &Client<'_>, job_id: &str) -> AppResult<PathBuf> {
    loop {
        let job: JobResponse = client.get_json(&api_path(&format!(
            "/jobs/status/{}",
            path_component(job_id)
        )))?;
        match job.status {
            JobStatus::Queued | JobStatus::Running => {
                std::thread::sleep(Duration::from_millis(250));
            }
            JobStatus::Succeeded => {
                return job.output_path.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "export job missing output path")
                        .into()
                });
            }
            JobStatus::Failed => {
                let target = format!("{}/{}", job.target.dir, job.target.item);
                let message = job
                    .error
                    .map(|error| {
                        format!(
                            "export failed for {target}: {}: {}",
                            error.code, error.message
                        )
                    })
                    .unwrap_or_else(|| format!("export failed for {target}"));
                return Err(io::Error::other(message).into());
            }
        }
    }
}

fn copy_job_output(source: &Path, destination: &Path) -> io::Result<()> {
    let bytes = fs::read(source)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    file.write_all(&bytes)?;
    file.flush()
}

#[cfg(test)]
mod tests {
    use super::{ItemPath, plan_share_items};
    use crate::AppResult;

    fn no_lists(_: &str, _: Option<&str>) -> AppResult<Vec<String>> {
        panic!("directory listing should not be used")
    }

    #[test]
    fn directory_source_without_recursive_fails() {
        let error = plan_share_items(vec!["Work".to_owned()], false, false, false, no_lists)
            .expect_err("directory source should require recursion");

        assert!(error.to_string().contains("--recursive"));
    }

    #[test]
    fn recursive_directory_source_expands_listed_items() {
        let items = plan_share_items(vec!["Work".to_owned()], true, false, false, |dir, glob| {
            assert_eq!(dir, "Work");
            assert_eq!(glob, None);
            Ok(vec!["Github".to_owned(), "Gitlab".to_owned()])
        })
        .unwrap();

        assert_eq!(
            items,
            vec![
                ItemPath {
                    dir: "Work".to_owned(),
                    item: "Github".to_owned(),
                },
                ItemPath {
                    dir: "Work".to_owned(),
                    item: "Gitlab".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn overlapping_patterns_are_deduplicated_in_first_match_order() {
        let items = plan_share_items(
            vec!["Work/Git*".to_owned(), "Work/*hub".to_owned()],
            false,
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
            items
                .iter()
                .map(|item| item.item.as_str())
                .collect::<Vec<_>>(),
            vec!["Github", "Gitlab", "Codehub"]
        );
    }

    #[test]
    fn globoff_keeps_metacharacters_literal() {
        let items = plan_share_items(
            vec!["Work/literal*[x]".to_owned()],
            false,
            true,
            false,
            no_lists,
        )
        .unwrap();

        assert_eq!(items[0].item, "literal*[x]");
    }

    #[test]
    fn glob_and_recursive_sources_must_match() {
        for (sources, recursive) in [
            (vec!["Work/Missing*".to_owned()], false),
            (vec!["Work".to_owned()], true),
        ] {
            let error = plan_share_items(sources, recursive, false, false, |_, _| Ok(Vec::new()))
                .expect_err("empty source should fail");
            assert!(error.to_string().contains("matched no items"));
        }
    }

    #[test]
    fn out_file_accepts_one_unique_match_and_rejects_multiple_matches() {
        let items = plan_share_items(vec!["Work/Git*".to_owned()], false, false, true, |_, _| {
            Ok(vec!["Github".to_owned()])
        })
        .unwrap();
        assert_eq!(items.len(), 1);

        let error = plan_share_items(vec!["Work/Git*".to_owned()], false, false, true, |_, _| {
            Ok(vec!["Github".to_owned(), "Gitlab".to_owned()])
        })
        .expect_err("multiple matches should reject --out-file");
        assert!(error.to_string().contains("exactly one item"));
    }
}
