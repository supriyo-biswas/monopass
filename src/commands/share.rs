use std::collections::HashMap;
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
use super::path::{ItemPath, parse_item_path};

#[derive(Debug, Clone, ClapArgs)]
pub struct Args {
    #[arg(
        value_name = "ITEM_OR_CONTACT",
        num_args = 2..,
        help = "One or more item paths followed by the contact email"
    )]
    entries: Vec<String>,
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
    let (paths, contact) = split_entries(args.entries)?;
    if args.out_file.is_some() && paths.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--out-file is only allowed when exporting exactly one item",
        )
        .into());
    }

    let client = Client::new(config);
    let destinations = destinations(&paths, &contact, args.out_file, args.out_dir)?;
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

fn split_entries(entries: Vec<String>) -> AppResult<(Vec<ItemPath>, String)> {
    let mut entries = entries.into_iter().collect::<Vec<_>>();
    let contact = entries
        .pop()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "contact is required"))?;
    if entries.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "item path is required").into());
    }
    let paths = entries
        .iter()
        .map(|entry| parse_item_path(entry).map_err(Into::into))
        .collect::<AppResult<Vec<_>>>()?;
    Ok((paths, contact))
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
