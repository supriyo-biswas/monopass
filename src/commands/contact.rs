use clap::Args as ClapArgs;

use crate::AppResult;
use crate::config::Config;

use super::client::{Client, api_path, path_component, query_value};
use super::models::{
    ContactResponse, CreateContactRequest, PaginatedResponse, UpdateContactRequest,
};

#[derive(Debug, Clone, ClapArgs)]
pub struct AddArgs {
    #[arg(help = "Contact email address")]
    email: String,
    #[arg(help = "Age public key for the contact")]
    age_public_key: String,
    #[arg(long, help = "Optional display name")]
    name: Option<String>,
}

#[derive(Debug, Clone, ClapArgs)]
pub struct EditArgs {
    #[arg(help = "Existing contact email address")]
    email: String,
    #[arg(long = "email", help = "Change the contact email address")]
    new_email: Option<String>,
    #[arg(long, help = "Update the display name")]
    name: Option<String>,
    #[arg(long, help = "Update the contact age public key")]
    age_public_key: Option<String>,
}

#[derive(Debug, Clone, ClapArgs)]
pub struct RemoveArgs {
    #[arg(help = "Contact email address")]
    email: String,
}

pub fn list(config: &Config) -> AppResult {
    let client = Client::new(config);
    for contact in list_all(&client)? {
        match (&contact.name, &contact.description) {
            (Some(name), Some(description)) => println!(
                "{}\t{}\t{}\t{}",
                contact.email, name, contact.age_public_key, description
            ),
            (Some(name), None) => {
                println!("{}\t{}\t{}", contact.email, name, contact.age_public_key)
            }
            (None, Some(description)) => {
                println!(
                    "{}\t{}\t{}",
                    contact.email, contact.age_public_key, description
                )
            }
            (None, None) => println!("{}\t{}", contact.email, contact.age_public_key),
        }
    }
    Ok(())
}

pub fn add(config: &Config, args: AddArgs) -> AppResult {
    let client = Client::new(config);
    client.put_json(
        &api_path(&format!("/contact/{}", path_component(&args.email))),
        &CreateContactRequest {
            name: args.name,
            age_public_key: args.age_public_key,
            description: None,
        },
    )
}

pub fn edit(config: &Config, args: EditArgs) -> AppResult {
    let client = Client::new(config);
    client.patch_json(
        &api_path(&format!("/contact/{}", path_component(&args.email))),
        &UpdateContactRequest {
            email: args.new_email.unwrap_or_else(|| args.email.clone()),
            name: args.name.map(Some),
            age_public_key: args.age_public_key,
        },
    )
}

pub fn remove(config: &Config, args: RemoveArgs) -> AppResult {
    let client = Client::new(config);
    client.delete_empty(&api_path(&format!(
        "/contact/{}",
        path_component(&args.email)
    )))
}

pub fn list_all(client: &Client<'_>) -> AppResult<Vec<ContactResponse>> {
    let mut entries = Vec::new();
    let mut marker: Option<String> = None;
    loop {
        let path = match &marker {
            Some(marker) => api_path(&format!(
                "/contacts?count=200&marker={}",
                query_value(marker)
            )),
            None => api_path("/contacts?count=200"),
        };
        let page: PaginatedResponse<ContactResponse> = client.get_json(&path)?;
        entries.extend(page.entries);
        match page.next_marker {
            Some(next) => marker = Some(next),
            None => return Ok(entries),
        }
    }
}
