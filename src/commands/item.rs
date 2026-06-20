use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use clap::{Args as ClapArgs, ValueEnum};
use zeroize::Zeroizing;

use crate::AppResult;
use crate::conceal::inferred_concealed;
use crate::config::Config;
use crate::secret::SecretString;

use super::client::{ApiError, AuthMode, Client, api_path, path_component, query_value};
use super::models::{
    CreateField, CreateFileResponse, CreateItemRequest, FieldType, FileInput, ItemResponse,
    ItemVersionSummaryResponse, PaginatedResponse, RemoveEntry, UpdateFieldEntry, UpdateFieldSet,
    UpdateFileEntry, UpdateFileSet, UpdateItemRequest,
};
use super::path::{ItemPath, parse_dir_or_item_path, parse_item_path};

#[derive(Debug, Clone, ClapArgs)]
pub struct AddArgs {
    #[arg(help = "Item path in <dir>/<item> form")]
    path: String,
    #[arg(long, help = "Add or update the username field")]
    username: Option<String>,
    #[arg(
        long,
        conflicts_with = "generate_password",
        help = "Prompt for a password"
    )]
    password_prompt: bool,
    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "",
        value_name = "recipe",
        help = "Generate a password"
    )]
    generate_password: Option<String>,
    #[arg(long, help = "Add a TOTP from an otpauth:// URL or a QR code image")]
    totp: Option<String>,
    #[arg(
        long = "field",
        value_name = "key[=value]",
        help = "Add arbitrary fields to the item"
    )]
    fields: Vec<String>,
    #[arg(
        long,
        value_delimiter = ',',
        help = "Mark comma-separated fields as secret"
    )]
    concealed_fields: Option<Vec<String>>,
    #[arg(long = "file", help = "Attach a file using the key=value format")]
    files: Vec<String>,
}

#[derive(Debug, Clone, ClapArgs)]
pub struct EditArgs {
    #[arg(help = "Item path in <dir>/<item> form")]
    path: String,
    #[arg(long, help = "Add or update the username field")]
    username: Option<String>,
    #[arg(
        long,
        conflicts_with = "generate_password",
        help = "Prompt for a password"
    )]
    password_prompt: bool,
    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "",
        value_name = "recipe",
        help = "Generate a password"
    )]
    generate_password: Option<String>,
    #[arg(long, help = "Add a TOTP from an otpauth:// URL or a QR code image")]
    totp: Option<String>,
    #[arg(
        long = "field",
        value_name = "key[=value]",
        help = "Add arbitrary fields to the item"
    )]
    fields: Vec<String>,
    #[arg(
        long,
        value_delimiter = ',',
        help = "Mark comma-separated fields as secret"
    )]
    concealed_fields: Option<Vec<String>>,
    #[arg(long = "file", help = "Attach a file using the key=value format")]
    files: Vec<String>,
    #[arg(
        long = "remove-fields",
        value_delimiter = ',',
        value_name = "name",
        help = "Remove fields by name"
    )]
    remove_fields: Vec<String>,
    #[arg(
        long = "remove-files",
        value_delimiter = ',',
        value_name = "name",
        help = "Remove files by name"
    )]
    remove_files: Vec<String>,
}

#[derive(Debug, Clone, ClapArgs)]
pub struct RemoveArgs {
    #[arg(help = "Directory or item path in <dir>[/<item>] form")]
    path: String,
    #[arg(
        short = 'g',
        long,
        help = "Treat an item source name literally instead of as a SQLite glob"
    )]
    globoff: bool,
    #[arg(
        short,
        long,
        help = "Permanently delete instead of moving items to Trash"
    )]
    force: bool,
    #[arg(
        short,
        long,
        help = "Remove all items in the directory before deleting it"
    )]
    recursive: bool,
}

#[derive(Debug, Clone, ClapArgs)]
pub struct ListVersionsArgs {
    #[arg(help = "Item path in <dir>/<item> form")]
    path: String,
}

#[derive(Debug, Clone, ClapArgs)]
pub struct RestoreArgs {
    #[arg(help = "Item path in <dir>/<item> form")]
    path: String,
    #[arg(help = "Version number to restore")]
    version: i64,
}

#[derive(Debug, Clone, ClapArgs)]
pub struct ShowArgs {
    #[arg(help = "Item path in <dir>/<item> form")]
    path: String,
    #[arg(long, help = "Reveal secret fields and file metadata")]
    reveal: bool,
    #[arg(long, value_enum, default_value = "human", help = "Output format")]
    format: ShowFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ShowFormat {
    Human,
    Json,
}

pub fn add(config: &Config, args: AddArgs) -> AppResult {
    let item_path = parse_item_path(&args.path)?;
    let client = Client::new(config);
    let request = build_create_request(
        &client,
        ItemInput {
            username: args.username,
            password_prompt: args.password_prompt,
            generate_password: args.generate_password,
            totp: args.totp,
            fields: args.fields,
            concealed_fields: args.concealed_fields,
            files: args.files,
        },
    )?;
    client.put_json(
        &api_path(&format!(
            "/dir/{}/item/{}",
            path_component(&item_path.dir),
            path_component(&item_path.item)
        )),
        &request,
    )
}

pub fn edit(config: &Config, args: EditArgs) -> AppResult {
    let item_path = parse_item_path(&args.path)?;
    let client = Client::new(config);
    let mut request = build_update_request(
        &client,
        ItemInput {
            username: args.username,
            password_prompt: args.password_prompt,
            generate_password: args.generate_password,
            totp: args.totp,
            fields: args.fields,
            concealed_fields: args.concealed_fields,
            files: args.files,
        },
    )?;
    for name in args.remove_fields {
        request
            .fields
            .push(UpdateFieldEntry::Remove(RemoveEntry { name, remove: true }));
    }
    for name in args.remove_files {
        request
            .files
            .push(UpdateFileEntry::Remove(RemoveEntry { name, remove: true }));
    }
    client.patch_json(
        &api_path(&format!(
            "/dir/{}/item/{}",
            path_component(&item_path.dir),
            path_component(&item_path.item)
        )),
        &request,
    )
}

pub fn remove(config: &Config, args: RemoveArgs) -> AppResult {
    let client = Client::new(config);
    let target = plan_removal(&args.path, args.recursive, args.globoff, |dir, glob| {
        Ok(super::dir::list_all_matching_items(&client, dir, glob)?
            .into_iter()
            .map(|item| item.name)
            .collect())
    })?;
    match target {
        RemovalPlan::Directory { dir, items } => {
            for item in items {
                remove_item(&client, &dir, &item, args.force)?;
            }
            if !remove_dir_after_recursive_delete(&dir) {
                return Ok(());
            }
            client.delete_empty(&api_path(&format!("/dir/{}", path_component(&dir))))
        }
        RemovalPlan::Items(items) => {
            for path in items {
                remove_item(&client, &path.dir, &path.item, args.force)?;
            }
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RemovalPlan {
    Directory { dir: String, items: Vec<String> },
    Items(Vec<ItemPath>),
}

fn plan_removal<F>(
    path: &str,
    recursive: bool,
    globoff: bool,
    mut list_items: F,
) -> AppResult<RemovalPlan>
where
    F: FnMut(&str, Option<&str>) -> AppResult<Vec<String>>,
{
    let target = parse_dir_or_item_path(path)?;
    match target {
        Ok(dir) => {
            if !recursive {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "directory removal requires --recursive",
                )
                .into());
            }
            let items = list_items(&dir, None)?;
            if items.is_empty() {
                return Err(no_remove_matches(path));
            }
            Ok(RemovalPlan::Directory { dir, items })
        }
        Err(path) if globoff => Ok(RemovalPlan::Items(vec![path])),
        Err(item_glob) => {
            let items = list_items(&item_glob.dir, Some(&item_glob.item))?;
            if items.is_empty() {
                return Err(no_remove_matches(path));
            }
            Ok(RemovalPlan::Items(
                items
                    .into_iter()
                    .map(|item| ItemPath {
                        dir: item_glob.dir.clone(),
                        item,
                    })
                    .collect(),
            ))
        }
    }
}

fn no_remove_matches(source: &str) -> Box<dyn std::error::Error> {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("source matched no items: {source}"),
    )
    .into()
}

pub fn list_versions(config: &Config, args: ListVersionsArgs) -> AppResult {
    let path = parse_item_path(&args.path)?;
    let client = Client::new(config);
    let mut marker: Option<String> = None;
    loop {
        let url = match &marker {
            Some(marker) => api_path(&format!(
                "/dir/{}/item/{}/versions?count=200&marker={}",
                path_component(&path.dir),
                path_component(&path.item),
                query_value(marker)
            )),
            None => api_path(&format!(
                "/dir/{}/item/{}/versions?count=200",
                path_component(&path.dir),
                path_component(&path.item)
            )),
        };
        let page: PaginatedResponse<ItemVersionSummaryResponse> = client.get_json(&url)?;
        for entry in page.entries {
            println!("{}\t{}", entry.version, entry.created_at);
        }
        match page.next_marker {
            Some(next) => marker = Some(next),
            None => return Ok(()),
        }
    }
}

pub fn restore(config: &Config, args: RestoreArgs) -> AppResult {
    let path = parse_item_path(&args.path)?;
    Client::new(config).put_empty(&api_path(&format!(
        "/dir/{}/item/{}/restore?version={}",
        path_component(&path.dir),
        path_component(&path.item),
        args.version
    )))
}

pub fn show(config: &Config, args: ShowArgs) -> AppResult {
    let path = parse_item_path(&args.path)?;
    let query = if args.reveal { "?reveal=true" } else { "" };
    let response = Client::new(config).get_bytes(
        &api_path(&format!(
            "/dir/{}/item/{}{}",
            path_component(&path.dir),
            path_component(&path.item),
            query
        )),
        AuthMode::IncludePassword,
    )?;

    let mut stdout = io::stdout().lock();
    match args.format {
        ShowFormat::Human => {
            let item: ItemResponse = serde_json::from_slice(&response.body)?;
            write_human_item(&mut stdout, &item)?;
        }
        ShowFormat::Json => {
            stdout.write_all(&response.body)?;
            if !response.body.ends_with(b"\n") {
                stdout.write_all(b"\n")?;
            }
        }
    }
    Ok(())
}

fn write_human_item(mut writer: impl Write, item: &ItemResponse) -> io::Result<()> {
    writeln!(writer, "Name: {}", item.name)?;
    writeln!(writer, "Created: {}", item.created_at)?;
    writeln!(writer, "Updated: {}", item.updated_at)?;
    writeln!(writer, "Versions: {}", item.total_versions)?;
    writeln!(writer, "Fields:")?;
    let mut fields: Vec<_> = item.fields.iter().collect();
    fields.sort_by(|left, right| left.name.cmp(&right.name));
    for field in fields {
        writeln!(writer, "  {}: {}", field.name, field.data)?;
    }

    if !item.files.is_empty() {
        writeln!(writer, "Files:")?;
        let mut files: Vec<_> = item.files.iter().collect();
        files.sort_by(|left, right| left.name.cmp(&right.name));
        for file in files {
            writeln!(writer, "  {} [{}]", file.name, human_size(file.size))?;
        }
    }
    Ok(())
}

fn human_size(size: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];

    if size < 100 {
        return format!("{size} B");
    }

    let mut value = size as f64 / 1024.0;
    let mut unit = 1;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

pub fn raw_item(client: &Client<'_>, dir: &str, item: &str) -> AppResult<ItemResponse> {
    client.get_json_with_password(&api_path(&format!(
        "/dir/{}/item/{}?raw=true",
        path_component(dir),
        path_component(item)
    )))
}

fn remove_item(client: &Client<'_>, dir: &str, item: &str, force: bool) -> AppResult {
    if force || dir == "Trash" {
        client.delete_empty(&api_path(&format!(
            "/dir/{}/item/{}",
            path_component(dir),
            path_component(item)
        )))
    } else {
        let source = item_metadata(client, dir, item)?;
        match move_item_to_trash(client, dir, item, item) {
            Ok(()) => Ok(()),
            Err(error) if is_item_exists_conflict(error.as_ref()) => {
                let fallback = trash_fallback_name(item, &source.created_at, None);
                match move_item_to_trash(client, dir, item, &fallback) {
                    Ok(()) => Ok(()),
                    Err(error) if is_item_exists_conflict(error.as_ref()) => {
                        move_item_to_numbered_trash_name(client, dir, item, &source.created_at)
                    }
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    }
}

fn item_metadata(client: &Client<'_>, dir: &str, item: &str) -> AppResult<ItemResponse> {
    client.get_json(&api_path(&format!(
        "/dir/{}/item/{}",
        path_component(dir),
        path_component(item)
    )))
}

fn move_item_to_trash(
    client: &Client<'_>,
    source_dir: &str,
    source_item: &str,
    destination_item: &str,
) -> AppResult {
    client.put_empty(&api_path(&format!(
        "/dir/Trash/item/{}?move_from={}/{}",
        path_component(destination_item),
        query_value(source_dir),
        query_value(source_item)
    )))
}

fn is_item_exists_conflict(error: &(dyn std::error::Error + 'static)) -> bool {
    error.downcast_ref::<ApiError>().is_some_and(|error| {
        error.status == 409 && error.code == "conflict" && error.message == "item already exists"
    })
}

fn trash_fallback_name(item: &str, created_at: &str, number: Option<u16>) -> String {
    const MAX_ITEM_NAME_CHARS: usize = 255;

    let suffix = match number {
        Some(number) => format!(" ({created_at},{number:03})"),
        None => format!(" ({created_at})"),
    };
    let suffix_chars = suffix.chars().count();
    let max_item_chars = MAX_ITEM_NAME_CHARS.saturating_sub(suffix_chars);
    let truncated_item: String = item.chars().take(max_item_chars).collect();
    format!("{truncated_item}{suffix}")
}

fn move_item_to_numbered_trash_name(
    client: &Client<'_>,
    source_dir: &str,
    source_item: &str,
    created_at: &str,
) -> AppResult {
    loop {
        let pattern = trash_numbered_glob(source_item, created_at);
        let page = super::dir::list_items_page(client, "Trash", 1, None, Some(&pattern), true)?;
        let next = next_trash_number(
            page.entries.first().map(|item| item.name.as_str()),
            source_item,
            created_at,
        )?;
        let destination = trash_fallback_name(source_item, created_at, Some(next));
        match move_item_to_trash(client, source_dir, source_item, &destination) {
            Ok(()) => return Ok(()),
            Err(error) if is_item_exists_conflict(error.as_ref()) => continue,
            Err(error) => return Err(error),
        }
    }
}

fn trash_numbered_glob(item: &str, created_at: &str) -> String {
    let numbered = trash_fallback_name(item, created_at, Some(0));
    let prefix = numbered
        .strip_suffix("000)")
        .expect("numbered Trash name has a fixed suffix");
    format!("{}[0-9][0-9][0-9])", escape_sqlite_glob(prefix))
}

fn trash_number(name: &str, item: &str, created_at: &str) -> io::Result<u16> {
    let numbered = trash_fallback_name(item, created_at, Some(0));
    let prefix = numbered
        .strip_suffix("000)")
        .expect("numbered Trash name has a fixed suffix");
    let value = name
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(')'))
        .filter(|value| value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid Trash suffix"))?;
    value
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid Trash suffix"))
}

fn next_trash_number(latest: Option<&str>, item: &str, created_at: &str) -> io::Result<u16> {
    let latest = match latest {
        Some(name) => trash_number(name, item, created_at)?,
        None => return Ok(1),
    };
    if latest >= 999 {
        Err(trash_suffix_limit_error())
    } else {
        Ok(latest + 1)
    }
}

fn escape_sqlite_glob(value: &str) -> String {
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

fn trash_suffix_limit_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        "moving to trash failed: suffix limit 999 reached",
    )
}

struct ItemInput {
    username: Option<String>,
    password_prompt: bool,
    generate_password: Option<String>,
    totp: Option<String>,
    fields: Vec<String>,
    concealed_fields: Option<Vec<String>>,
    files: Vec<String>,
}

fn build_create_request(client: &Client<'_>, input: ItemInput) -> AppResult<CreateItemRequest> {
    let ItemInput {
        username,
        password_prompt,
        generate_password,
        totp,
        fields,
        concealed_fields,
        files,
    } = input;
    let file_inputs = parse_file_inputs(files)?;
    let fields = build_fields(
        username,
        password_prompt,
        generate_password.as_deref(),
        totp.as_deref(),
        fields,
        concealed_fields,
    )?;
    validate_field_and_file_name_overlap(
        fields.iter().map(|field| field.name.as_str()),
        file_inputs.iter().map(|file| file.name.as_str()),
    )?;
    let mut request = CreateItemRequest {
        fields,
        ..CreateItemRequest::default()
    };
    for (name, id) in upload_files(client, file_inputs)? {
        request.files.push(FileInput { name, id });
    }
    Ok(request)
}

fn build_update_request(client: &Client<'_>, input: ItemInput) -> AppResult<UpdateItemRequest> {
    let ItemInput {
        username,
        password_prompt,
        generate_password,
        totp,
        fields,
        concealed_fields,
        files,
    } = input;
    let file_inputs = parse_file_inputs(files)?;
    let mut request = UpdateItemRequest::default();
    for field in build_fields(
        username,
        password_prompt,
        generate_password.as_deref(),
        totp.as_deref(),
        fields,
        concealed_fields,
    )? {
        request.fields.push(UpdateFieldEntry::Set(UpdateFieldSet {
            name: field.name,
            field_type: field.field_type,
            concealed: field.concealed,
            data: field.data,
        }));
    }
    validate_field_and_file_name_overlap(
        request.fields.iter().filter_map(|entry| match entry {
            UpdateFieldEntry::Set(field) => Some(field.name.as_str()),
            UpdateFieldEntry::Remove(_) => None,
        }),
        file_inputs.iter().map(|file| file.name.as_str()),
    )?;
    for (name, id) in upload_files(client, file_inputs)? {
        request
            .files
            .push(UpdateFileEntry::Set(UpdateFileSet { name, id }));
    }
    Ok(request)
}

fn build_fields(
    username: Option<String>,
    password_prompt: bool,
    generate_password: Option<&str>,
    totp: Option<&str>,
    fields: Vec<String>,
    concealed_fields: Option<Vec<String>>,
) -> AppResult<Vec<CreateField>> {
    let concealed: Option<HashSet<String>> =
        concealed_fields.map(|fields| fields.into_iter().collect());
    let mut names = HashSet::new();
    let mut output = Vec::new();
    if let Some(username) = username {
        push_field(
            &mut output,
            &mut names,
            "username".to_owned(),
            string_field(username, Some(false)),
        )?;
    }
    if password_prompt {
        let password = prompt_confirmed_password()?;
        push_field(
            &mut output,
            &mut names,
            "password".to_owned(),
            string_field(password, Some(true)),
        )?;
    }
    if let Some(spec) = generate_password {
        let password = super::pwgen::generate(if spec.is_empty() { None } else { Some(spec) })?;
        push_field(
            &mut output,
            &mut names,
            "password".to_owned(),
            string_field(password, Some(true)),
        )?;
    }
    if let Some(totp) = totp {
        push_field(
            &mut output,
            &mut names,
            "totp".to_owned(),
            CreateField {
                name: String::new(),
                field_type: FieldType::Totp,
                concealed: Some(true),
                data: super::totp::normalize(totp)?,
            },
        )?;
    }
    for raw in fields {
        let (name, value) = match raw.split_once('=') {
            Some((name, value)) => (name.to_owned(), SecretString::from(value)),
            None => prompt_field_value(&raw, concealed_state(&raw, concealed.as_ref()))?,
        };
        let is_concealed = Some(concealed_state(&name, concealed.as_ref()));
        push_field(
            &mut output,
            &mut names,
            name,
            string_field(value, is_concealed),
        )?;
    }
    Ok(output)
}

fn prompt_field_value(name: &str, concealed: bool) -> io::Result<(String, SecretString)> {
    let prompt = format!("{name} value: ");
    if concealed {
        Ok((
            name.to_owned(),
            SecretString::from(Zeroizing::new(rpassword::prompt_password(&prompt)?)),
        ))
    } else {
        let mut value = String::new();
        eprint!("{prompt}");
        io::stderr().flush()?;
        io::stdin().read_line(&mut value)?;
        if value.ends_with('\n') {
            value.pop();
            if value.ends_with('\r') {
                value.pop();
            }
        }
        Ok((name.to_owned(), SecretString::from(value)))
    }
}

fn concealed_state(name: &str, explicit: Option<&HashSet<String>>) -> bool {
    explicit.map_or_else(|| inferred_concealed(name), |fields| fields.contains(name))
}

fn push_field(
    output: &mut Vec<CreateField>,
    names: &mut HashSet<String>,
    name: String,
    mut field: CreateField,
) -> AppResult {
    if name.is_empty() {
        return Err(
            io::Error::new(io::ErrorKind::InvalidInput, "field name must not be empty").into(),
        );
    }
    if !names.insert(name.clone()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("duplicate field name: {name}"),
        )
        .into());
    }
    field.name = name;
    output.push(field);
    Ok(())
}

fn validate_field_and_file_name_overlap<'a>(
    field_names: impl IntoIterator<Item = &'a str>,
    file_names: impl IntoIterator<Item = &'a str>,
) -> AppResult {
    let file_names: HashSet<&str> = file_names.into_iter().collect();
    if let Some(name) = field_names
        .into_iter()
        .find(|name| file_names.contains(name))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("field and file names must be unique: {name}"),
        )
        .into());
    }
    Ok(())
}

struct PendingFileInput {
    name: String,
    path: PathBuf,
}

fn parse_file_inputs(files: Vec<String>) -> AppResult<Vec<PendingFileInput>> {
    let mut output = Vec::new();
    let mut names = HashSet::new();
    for raw in files {
        let (name, path) = raw.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "file arguments must be name=path",
            )
        })?;
        if name.is_empty() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "file name must not be empty").into(),
            );
        }
        if !names.insert(name.to_owned()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("duplicate file name: {name}"),
            )
            .into());
        }
        output.push(PendingFileInput {
            name: name.to_owned(),
            path: PathBuf::from(path),
        });
    }
    Ok(output)
}

fn upload_files(
    client: &Client<'_>,
    files: Vec<PendingFileInput>,
) -> AppResult<Vec<(String, String)>> {
    let mut output = Vec::new();
    for PendingFileInput { name, path } in files {
        let bytes = Zeroizing::new(fs::read(&path)?);
        let response: CreateFileResponse =
            client.put_bytes_json(&api_path("/file/upload"), bytes)?;
        output.push((name, response.id));
    }
    Ok(output)
}

fn string_field(data: impl Into<SecretString>, concealed: Option<bool>) -> CreateField {
    CreateField {
        name: String::new(),
        field_type: FieldType::String,
        concealed,
        data: data.into(),
    }
}

fn prompt_confirmed_password() -> io::Result<Zeroizing<String>> {
    let password = Zeroizing::new(rpassword::prompt_password("Password: ")?);
    let confirmation = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
    if password.as_str() != confirmation.as_str() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "passwords do not match",
        ));
    }
    Ok(password)
}

#[cfg(test)]
fn remove_item_is_permanent_delete(dir: &str, force: bool) -> bool {
    force || dir == "Trash"
}

fn remove_dir_after_recursive_delete(dir: &str) -> bool {
    dir != "Trash"
}

#[cfg(test)]
mod tests {
    use crate::commands::client::ApiError;
    use crate::commands::models::{Field, FileMetadata, ItemResponse};

    use super::{
        FieldType, RemovalPlan, build_fields, escape_sqlite_glob, human_size,
        is_item_exists_conflict, next_trash_number, plan_removal, remove_item_is_permanent_delete,
        trash_fallback_name, trash_number, trash_numbered_glob,
        validate_field_and_file_name_overlap, write_human_item,
    };
    use crate::secret::SecretString;

    #[test]
    fn trash_items_are_permanently_deleted_without_force() {
        assert!(remove_item_is_permanent_delete("Trash", false));
    }

    #[test]
    fn non_trash_items_still_soft_delete_without_force() {
        assert!(!remove_item_is_permanent_delete("Personal", false));
    }

    #[test]
    fn force_still_performs_permanent_delete() {
        assert!(remove_item_is_permanent_delete("Personal", true));
    }

    #[test]
    fn directory_remove_requires_recursive() {
        let error = plan_removal("Personal", false, false, |_, _| unreachable!())
            .expect_err("directory removal should require recursion");

        assert_eq!("directory removal requires --recursive", error.to_string());
    }

    #[test]
    fn recursive_directory_and_item_globs_expand_before_removal() {
        assert_eq!(
            plan_removal("Personal", true, false, |dir, glob| {
                assert_eq!((dir, glob), ("Personal", None));
                Ok(vec!["Github".to_owned()])
            })
            .unwrap(),
            RemovalPlan::Directory {
                dir: "Personal".to_owned(),
                items: vec!["Github".to_owned()],
            }
        );
        assert_eq!(
            plan_removal("Personal/Git*", false, false, |dir, glob| {
                assert_eq!((dir, glob), ("Personal", Some("Git*")));
                Ok(vec!["Github".to_owned(), "Gitlab".to_owned()])
            })
            .unwrap(),
            RemovalPlan::Items(vec![
                super::ItemPath {
                    dir: "Personal".to_owned(),
                    item: "Github".to_owned(),
                },
                super::ItemPath {
                    dir: "Personal".to_owned(),
                    item: "Gitlab".to_owned(),
                },
            ])
        );
    }

    #[test]
    fn removal_globs_and_recursive_directories_must_match() {
        for (path, recursive) in [("Personal/Missing*", false), ("Personal", true)] {
            let error = plan_removal(path, recursive, false, |_, _| Ok(Vec::new()))
                .expect_err("empty source should fail");
            assert!(error.to_string().contains("matched no items"));
        }
    }

    #[test]
    fn removal_globoff_keeps_metacharacters_literal() {
        assert_eq!(
            plan_removal("Personal/literal*[x]", false, true, |_, _| {
                panic!("literal item removal must not list items")
            })
            .unwrap(),
            RemovalPlan::Items(vec![super::ItemPath {
                dir: "Personal".to_owned(),
                item: "literal*[x]".to_owned(),
            }])
        );
    }

    #[test]
    fn recursive_trash_remove_empties_without_deleting_trash_dir() {
        assert!(!super::remove_dir_after_recursive_delete("Trash"));
        assert!(super::remove_dir_after_recursive_delete("Personal"));
    }

    #[test]
    fn detects_item_exists_conflicts() {
        let error = ApiError {
            status: 409,
            code: "conflict".to_owned(),
            message: "item already exists".to_owned(),
        };

        assert!(is_item_exists_conflict(&error));
    }

    #[test]
    fn ignores_other_api_errors_for_trash_retry() {
        let wrong_message = ApiError {
            status: 409,
            code: "conflict".to_owned(),
            message: "directory already exists".to_owned(),
        };
        let wrong_status = ApiError {
            status: 404,
            code: "not_found".to_owned(),
            message: "item not found".to_owned(),
        };

        assert!(!is_item_exists_conflict(&wrong_message));
        assert!(!is_item_exists_conflict(&wrong_status));
    }

    #[test]
    fn trash_fallback_name_uses_created_at() {
        assert_eq!(
            "test (2026-06-07T01:23:45Z)",
            trash_fallback_name("test", "2026-06-07T01:23:45Z", None)
        );
    }

    #[test]
    fn trash_fallback_name_uses_created_at_and_incrementing_suffix() {
        assert_eq!(
            "test (2026-06-07T01:23:45Z,123)",
            trash_fallback_name("test", "2026-06-07T01:23:45Z", Some(123))
        );
    }

    #[test]
    fn trash_fallback_name_truncates_long_item_names() {
        let name = trash_fallback_name(&"a".repeat(260), "2026-06-07T01:23:45Z", Some(123));

        assert_eq!(255, name.chars().count());
        assert!(name.ends_with(" (2026-06-07T01:23:45Z,123)"));
    }

    #[test]
    fn numbered_trash_glob_is_literal_and_suffix_is_parsed() {
        let pattern = trash_numbered_glob("test*[", "2026-06-07T01:23:45Z");
        assert_eq!("test[*][[] (2026-06-07T01:23:45Z,[0-9][0-9][0-9])", pattern);
        assert_eq!("literal[*][?][[]", escape_sqlite_glob("literal*?["));
        assert_eq!(
            42,
            trash_number(
                "test*[ (2026-06-07T01:23:45Z,042)",
                "test*[",
                "2026-06-07T01:23:45Z"
            )
            .unwrap()
        );
    }

    #[test]
    fn next_trash_suffix_starts_at_one_increments_and_stops_at_999() {
        let created_at = "2026-06-07T01:23:45Z";
        assert_eq!(1, next_trash_number(None, "test", created_at).unwrap());
        assert_eq!(
            43,
            next_trash_number(Some("test (2026-06-07T01:23:45Z,042)"), "test", created_at).unwrap()
        );
        assert_eq!(
            "moving to trash failed: suffix limit 999 reached",
            next_trash_number(Some("test (2026-06-07T01:23:45Z,999)"), "test", created_at)
                .unwrap_err()
                .to_string()
        );
    }

    #[test]
    fn human_item_output_lists_fields_and_files_by_name() {
        let item = ItemResponse {
            name: "github".to_owned(),
            created_at: "2026-06-07T01:23:45Z".to_owned(),
            updated_at: "2026-06-07T01:24:00Z".to_owned(),
            total_versions: 3,
            fields: vec![
                Field {
                    name: "username".to_owned(),
                    field_type: FieldType::String,
                    concealed: false,
                    data: SecretString::from("alice"),
                },
                Field {
                    name: "password".to_owned(),
                    field_type: FieldType::String,
                    concealed: true,
                    data: SecretString::from("******"),
                },
            ],
            files: vec![
                FileMetadata {
                    name: "notes.txt".to_owned(),
                    size: 512,
                },
                FileMetadata {
                    name: "archive.zip".to_owned(),
                    size: 1_258_291,
                },
            ],
        };

        let mut output = Vec::new();
        write_human_item(&mut output, &item).unwrap();

        assert_eq!(
            String::from_utf8(output).unwrap(),
            "Name: github\n\
             Created: 2026-06-07T01:23:45Z\n\
             Updated: 2026-06-07T01:24:00Z\n\
             Versions: 3\n\
             Fields:\n\
             \u{20}\u{20}password: ******\n\
             \u{20}\u{20}username: alice\n\
             Files:\n\
             \u{20}\u{20}archive.zip [1.2 MB]\n\
             \u{20}\u{20}notes.txt [0.5 KB]\n"
        );
    }

    #[test]
    fn human_item_output_omits_empty_files_section() {
        let item = ItemResponse {
            name: "github".to_owned(),
            created_at: "2026-06-07T01:23:45Z".to_owned(),
            updated_at: "2026-06-07T01:24:00Z".to_owned(),
            total_versions: 1,
            fields: vec![Field {
                name: "username".to_owned(),
                field_type: FieldType::String,
                concealed: false,
                data: SecretString::from("alice"),
            }],
            files: vec![],
        };

        let mut output = Vec::new();
        write_human_item(&mut output, &item).unwrap();

        assert_eq!(
            String::from_utf8(output).unwrap(),
            "Name: github\n\
             Created: 2026-06-07T01:23:45Z\n\
             Updated: 2026-06-07T01:24:00Z\n\
             Versions: 1\n\
             Fields:\n\
             \u{20}\u{20}username: alice\n"
        );
    }

    #[test]
    fn build_fields_infers_concealment_without_explicit_list() {
        let fields = build_fields(
            None,
            false,
            None,
            None,
            vec!["password=plain-text".to_owned()],
            None,
        )
        .unwrap();

        assert_eq!(1, fields.len());
        assert_eq!(Some(true), fields[0].concealed);
    }

    #[test]
    fn build_fields_uses_explicit_list_for_custom_fields() {
        let fields = build_fields(
            None,
            false,
            None,
            None,
            vec!["password=plain-text".to_owned()],
            Some(vec!["other".to_owned()]),
        )
        .unwrap();

        assert_eq!(1, fields.len());
        assert_eq!(Some(false), fields[0].concealed);
    }

    #[test]
    fn field_and_file_names_must_not_overlap() {
        let error = validate_field_and_file_name_overlap(
            ["password"].iter().copied(),
            ["password"].iter().copied(),
        )
        .unwrap_err();

        assert_eq!(
            "field and file names must be unique: password",
            error.to_string()
        );
    }

    #[test]
    fn human_size_formats_binary_units() {
        assert_eq!("0 B", human_size(0));
        assert_eq!("99 B", human_size(99));
        assert_eq!("0.5 KB", human_size(512));
        assert_eq!("1.0 KB", human_size(1024));
        assert_eq!("1.2 MB", human_size(1_258_291));
    }
}
