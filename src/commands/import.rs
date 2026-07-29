use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use crate::AppResult;
use crate::config::Config;
use clap::Args as ClapArgs;
use clap_complete::engine::ArgValueCompleter;

use super::client::{Client, api_path, path_component};
use super::models::{JobAcceptedResponse, JobResponse, JobStatus};
use super::path::parse_item_path;

#[derive(Debug, Clone, ClapArgs)]
pub struct Args {
    #[arg(add = ArgValueCompleter::new(super::completion::new_item), help = "Item path in <dir>/<item> form")]
    path: String,
    #[arg(help = "Encrypted export file")]
    file: PathBuf,
}

pub fn run(config: &Config, args: Args) -> AppResult {
    let item_path = parse_item_path(&args.path)?;
    let client = Client::new(config);
    let mut encrypted = File::open(args.file)?;
    let content_length = encrypted.metadata()?.len();
    let accepted: JobAcceptedResponse = client.put_reader_json(
        &api_path(&format!(
            "/jobs/import/{}/{}",
            path_component(&item_path.dir),
            path_component(&item_path.item),
        )),
        &mut encrypted,
        content_length,
    )?;
    poll_job(&client, &accepted.job_id)
}

fn poll_job(client: &Client<'_>, job_id: &str) -> AppResult {
    loop {
        let job: JobResponse = client.get_json(&api_path(&format!(
            "/jobs/status/{}",
            path_component(job_id)
        )))?;
        match job.status {
            JobStatus::Queued | JobStatus::Running => {
                std::thread::sleep(Duration::from_millis(250));
            }
            JobStatus::Succeeded => return Ok(()),
            JobStatus::Failed => {
                let message = job
                    .error
                    .map(|error| format!("import failed: {}: {}", error.code, error.message))
                    .unwrap_or_else(|| "import failed".to_owned());
                return Err(io::Error::other(message).into());
            }
        }
    }
}
