use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use clap::Args as ClapArgs;
use zeroize::Zeroizing;

use crate::AppResult;
use crate::config::Config;

use super::client::{Client, api_path, path_component};
use super::models::{JobAcceptedResponse, JobResponse, JobStatus};
use super::path::parse_item_path;

#[derive(Debug, Clone, ClapArgs)]
pub struct Args {
    #[arg(help = "Item path in <dir>/<item> form")]
    path: String,
    #[arg(help = "Encrypted export file")]
    file: PathBuf,
}

pub fn run(config: &Config, args: Args) -> AppResult {
    let item_path = parse_item_path(&args.path)?;
    let client = Client::new(config);
    let encrypted = Zeroizing::new(fs::read(args.file)?);
    let accepted: JobAcceptedResponse = client.put_bytes_json(
        &api_path(&format!(
            "/jobs/import/{}/{}",
            path_component(&item_path.dir),
            path_component(&item_path.item),
        )),
        encrypted,
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
