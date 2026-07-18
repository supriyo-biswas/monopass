use std::collections::BTreeMap;
use std::io::{self, Write};

use clap::Args as ClapArgs;

use crate::AppResult;
use crate::config::Config;

use super::client::{Client, api_path, path_component};
use super::models::UpdateSettingRequest;

#[derive(Debug, Clone, ClapArgs)]
pub struct ReadArgs {
    #[arg(help = "Full setting name")]
    name: String,
}

#[derive(Debug, Clone, ClapArgs)]
pub struct WriteArgs {
    #[arg(help = "Full setting name")]
    name: String,
    #[arg(help = "Setting value")]
    value: String,
}

pub fn list(config: &Config) -> AppResult {
    let settings = list_settings(&Client::new(config))?;
    write_settings(&mut io::stdout().lock(), &settings)?;
    Ok(())
}

pub fn read(config: &Config, args: ReadArgs) -> AppResult {
    let settings = list_settings(&Client::new(config))?;
    write_setting(&mut io::stdout().lock(), &settings, &args.name)?;
    Ok(())
}

pub fn write(config: &Config, args: WriteArgs) -> AppResult {
    Client::new(config).put_json(
        &setting_api_path(&args.name),
        &UpdateSettingRequest { value: args.value },
    )
}

fn list_settings(client: &Client<'_>) -> AppResult<BTreeMap<String, String>> {
    client.get_json(&api_path("/settings"))
}

fn setting_api_path(name: &str) -> String {
    api_path(&format!("/settings/{}", path_component(name)))
}

fn write_settings(output: &mut impl Write, settings: &BTreeMap<String, String>) -> io::Result<()> {
    for (name, value) in settings {
        writeln!(output, "{name}\t{value}")?;
    }
    Ok(())
}

fn write_setting(
    output: &mut impl Write,
    settings: &BTreeMap<String, String>,
    name: &str,
) -> io::Result<()> {
    let value = settings.get(name).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("setting `{name}` not found"),
        )
    })?;
    writeln!(output, "{value}")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io;

    use super::{setting_api_path, write_setting, write_settings};
    use crate::commands::models::UpdateSettingRequest;

    #[test]
    fn list_writes_sorted_name_value_rows() {
        let settings = BTreeMap::from([
            ("user.trustedProgramPaths".to_owned(), "[]".to_owned()),
            ("user.authTtlSeconds".to_owned(), "900".to_owned()),
        ]);
        let mut output = Vec::new();

        write_settings(&mut output, &settings).unwrap();

        assert_eq!(
            b"user.authTtlSeconds\t900\nuser.trustedProgramPaths\t[]\n",
            output.as_slice()
        );
    }

    #[test]
    fn read_writes_exact_serialized_value() {
        let settings = BTreeMap::from([(
            "user.trustedProgramPaths".to_owned(),
            r#"["/usr/bin/example"]"#.to_owned(),
        )]);
        let mut output = Vec::new();

        write_setting(&mut output, &settings, "user.trustedProgramPaths").unwrap();

        assert_eq!(b"[\"/usr/bin/example\"]\n", output.as_slice());
    }

    #[test]
    fn read_rejects_missing_setting() {
        let error = write_setting(&mut Vec::new(), &BTreeMap::new(), "user.missing").unwrap_err();

        assert_eq!(io::ErrorKind::NotFound, error.kind());
        assert_eq!("setting `user.missing` not found", error.to_string());
    }

    #[test]
    fn write_path_encodes_the_full_setting_name_and_preserves_the_value() {
        assert_eq!(
            "/api/v1/settings/user.trustedProgramPaths%2Fchild",
            setting_api_path("user.trustedProgramPaths/child")
        );
        assert_eq!(
            r#"{"value":"[\"relative\"]"}"#,
            serde_json::to_string(&UpdateSettingRequest {
                value: r#"["relative"]"#.to_owned(),
            })
            .unwrap()
        );
    }
}
