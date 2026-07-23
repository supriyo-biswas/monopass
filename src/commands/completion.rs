use std::ffi::OsStr;

use clap_complete::engine::CompletionCandidate;

use crate::config::Config;

use super::client::Client;
use super::models::{ShellCompletionEntry, ShellCompletionKind};

const DIR: ShellCompletionKind = ShellCompletionKind::Dir;
const ITEM: ShellCompletionKind = ShellCompletionKind::Item;
const FIELD: ShellCompletionKind = ShellCompletionKind::Field;
const FILE: ShellCompletionKind = ShellCompletionKind::File;
const CONTACT: ShellCompletionKind = ShellCompletionKind::Contact;

#[derive(Clone, Copy)]
enum Terminals {
    None,
    Dir,
    Item,
    Reference,
    DirOrItem,
    Contact,
    Any,
}

pub fn new_item(current: &OsStr) -> Vec<CompletionCandidate> {
    complete(current, &[DIR], Terminals::None, true)
}

pub fn existing_dir(current: &OsStr) -> Vec<CompletionCandidate> {
    complete(current, &[DIR], Terminals::Dir, true)
}

pub fn existing_item(current: &OsStr) -> Vec<CompletionCandidate> {
    let Some(kinds) = existing_item_kinds(current) else {
        return Vec::new();
    };
    complete(current, kinds, Terminals::Item, true)
}

pub fn dir_or_item(current: &OsStr) -> Vec<CompletionCandidate> {
    let Some(kinds) = existing_item_kinds(current) else {
        return Vec::new();
    };
    complete(current, kinds, Terminals::DirOrItem, true)
}

pub fn reference(current: &OsStr) -> Vec<CompletionCandidate> {
    let Some(kinds) = reference_kinds(current) else {
        return Vec::new();
    };
    complete(current, kinds, Terminals::Reference, true)
}

pub fn contact(current: &OsStr) -> Vec<CompletionCandidate> {
    complete(current, &[CONTACT], Terminals::Contact, false)
}

pub fn share(current: &OsStr) -> Vec<CompletionCandidate> {
    complete(current, &[DIR, ITEM, CONTACT], Terminals::Any, true)
}

fn complete(
    current: &OsStr,
    kinds: &[ShellCompletionKind],
    terminals: Terminals,
    preserve_uri_prefix: bool,
) -> Vec<CompletionCandidate> {
    let Some(current) = current.to_str() else {
        return Vec::new();
    };
    let (uri_prefix, prefix) = if preserve_uri_prefix {
        strip_uri_prefix(current)
    } else {
        ("", current)
    };
    let Ok(config) = Config::load() else {
        return Vec::new();
    };
    let Some(response) = Client::new(&config).shell_completions(prefix, kinds) else {
        return Vec::new();
    };
    response
        .entries
        .into_iter()
        .map(|entry| render_candidate(uri_prefix, entry, terminals))
        .map(CompletionCandidate::new)
        .collect()
}

fn render_candidate(uri_prefix: &str, entry: ShellCompletionEntry, terminals: Terminals) -> String {
    let terminal = match terminals {
        Terminals::None => false,
        Terminals::Dir => entry.kind == DIR,
        Terminals::Item => entry.kind == ITEM,
        Terminals::Reference => matches!(entry.kind, FIELD | FILE),
        Terminals::DirOrItem => matches!(entry.kind, DIR | ITEM),
        Terminals::Contact => entry.kind == CONTACT,
        Terminals::Any => true,
    };
    let slash = if terminal || entry.value.ends_with('/') {
        ""
    } else {
        "/"
    };
    format!("{uri_prefix}{}{slash}", entry.value)
}

fn component_count(current: &OsStr) -> Option<usize> {
    let current = current.to_str()?;
    let (_, current) = strip_uri_prefix(current);
    if current.is_empty() {
        Some(0)
    } else {
        Some(current.split('/').count())
    }
}

fn existing_item_kinds(current: &OsStr) -> Option<&'static [ShellCompletionKind]> {
    match component_count(current)? {
        0 | 1 => Some(&[DIR, ITEM]),
        _ => Some(&[ITEM]),
    }
}

fn reference_kinds(current: &OsStr) -> Option<&'static [ShellCompletionKind]> {
    match component_count(current)? {
        0 | 1 => Some(&[DIR, ITEM]),
        2 => Some(&[ITEM, FIELD, FILE]),
        _ => Some(&[FIELD, FILE]),
    }
}

fn strip_uri_prefix(value: &str) -> (&str, &str) {
    for prefix in ["pass://", "op://"] {
        if let Some(value) = value.strip_prefix(prefix) {
            return (prefix, value);
        }
    }
    ("", value)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::{
        DIR, FIELD, FILE, ITEM, ShellCompletionEntry, ShellCompletionKind, Terminals,
        existing_item_kinds, reference_kinds, render_candidate,
    };

    #[test]
    fn command_positions_map_to_the_expected_database_kinds() {
        assert_eq!(Some(&[DIR, ITEM][..]), existing_item_kinds(OsStr::new("x")));
        assert_eq!(Some(&[ITEM][..]), existing_item_kinds(OsStr::new("x/y")));
        assert_eq!(Some(&[DIR, ITEM][..]), reference_kinds(OsStr::new("x")));
        assert_eq!(
            Some(&[ITEM, FIELD, FILE][..]),
            reference_kinds(OsStr::new("x/y"))
        );
        assert_eq!(
            Some(&[FIELD, FILE][..]),
            reference_kinds(OsStr::new("pass://x/y/p"))
        );
    }

    #[test]
    fn uri_prefixes_are_preserved_and_continuations_get_a_slash() {
        assert_eq!(
            "pass://Personal/",
            render_candidate(
                "pass://",
                ShellCompletionEntry {
                    value: "Personal".to_owned(),
                    kind: ShellCompletionKind::Dir,
                },
                Terminals::Item,
            )
        );
        assert_eq!(
            "op://Personal/GitHub",
            render_candidate(
                "op://",
                ShellCompletionEntry {
                    value: "Personal/GitHub".to_owned(),
                    kind: ShellCompletionKind::Item,
                },
                Terminals::Item,
            )
        );
    }
}
