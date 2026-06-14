use std::io;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemPath {
    pub dir: String,
    pub item: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferencePath {
    pub dir: String,
    pub item: String,
    pub name: String,
}

pub fn parse_item_path(input: &str) -> io::Result<ItemPath> {
    let path = strip_prefix(input);
    let parts = components(path)?;
    if parts.len() != 2 {
        return Err(invalid_path("expected <dir>/<item>"));
    }
    Ok(ItemPath {
        dir: parts[0].to_owned(),
        item: parts[1].to_owned(),
    })
}

pub fn parse_dir_or_item_path(input: &str) -> io::Result<Result<String, ItemPath>> {
    let path = strip_prefix(input);
    let parts = components(path)?;
    match parts.as_slice() {
        [dir] => Ok(Ok((*dir).to_owned())),
        [dir, item] => Ok(Err(ItemPath {
            dir: (*dir).to_owned(),
            item: (*item).to_owned(),
        })),
        _ => Err(invalid_path("expected <dir> or <dir>/<item>")),
    }
}

pub fn parse_reference_path(input: &str) -> io::Result<ReferencePath> {
    let path = strip_prefix(input);
    let parts = components(path)?;
    if parts.len() != 3 {
        return Err(invalid_path("expected <dir>/<item>/<fieldOrFile>"));
    }
    Ok(ReferencePath {
        dir: parts[0].to_owned(),
        item: parts[1].to_owned(),
        name: parts[2].to_owned(),
    })
}

pub fn is_reference_value(input: &str) -> bool {
    input.starts_with("pass://") || input.starts_with("op://")
}

fn strip_prefix(input: &str) -> &str {
    input
        .strip_prefix("pass://")
        .or_else(|| input.strip_prefix("op://"))
        .unwrap_or(input)
}

fn components(path: &str) -> io::Result<Vec<&str>> {
    let parts: Vec<_> = path.split('/').collect();
    if parts.iter().any(|part| part.is_empty()) {
        return Err(invalid_path("path components must not be empty"));
    }
    Ok(parts)
}

fn invalid_path(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::{parse_item_path, parse_reference_path};

    #[test]
    fn parses_plain_and_prefixed_paths() {
        assert_eq!(parse_item_path("Personal/github").unwrap().item, "github");
        assert_eq!(
            parse_reference_path("pass://Personal/github/password")
                .unwrap()
                .name,
            "password"
        );
        assert!(parse_reference_path("op://Personal//password").is_err());
    }
}
