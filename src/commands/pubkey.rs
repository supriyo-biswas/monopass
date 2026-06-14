use std::io;

use crate::AppResult;
use crate::config::Config;

use super::client::{Client, api_path};
use super::models::ItemResponse;

pub fn run(config: &Config) -> AppResult {
    let client = Client::new(config);
    let item: ItemResponse =
        client.get_json(&api_path("/dir/_Internal/item/AgePublicKey?raw=true"))?;
    let key = item
        .fields
        .iter()
        .find(|field| field.name == "key")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "public key field missing"))?;
    println!("{}", key.data);
    Ok(())
}
