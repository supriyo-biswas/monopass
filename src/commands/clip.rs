use std::io::{self, Write};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;

use arboard::Clipboard;
#[cfg(target_os = "linux")]
use arboard::SetExtLinux;
use clap::Args as ClapArgs;
use clap_complete::engine::ArgValueCompleter;
use zeroize::Zeroizing;

use crate::AppResult;
use crate::config::Config;
use crate::settings::{CLEAR_CLIPBOARD_AFTER_SECONDS_SETTING, setting};

use super::client::{Client, api_path, path_component};
use super::models::SettingResponse;
use super::path::parse_reference_path;

#[derive(Debug, Clone, ClapArgs)]
pub struct Args {
    #[arg(add = ArgValueCompleter::new(super::completion::reference), help = "Reference path in <dir>/<item>/<fieldOrFile> form")]
    reference: String,
}

pub fn run(config: &Config, args: Args) -> AppResult {
    let reference = parse_reference_path(&args.reference)?;
    let bytes = super::read::fetch_reference(config, &reference)?;
    let clear_after = clear_clipboard_after(&Client::new(config))?;
    let text = clipboard_text(&bytes)?;
    let interrupted = interrupt_receiver()?;
    let mut clipboard = NativeClipboard::new()?;

    copy_and_clear(
        &mut clipboard,
        text,
        clear_after,
        interrupted,
        &mut io::stderr().lock(),
    )
}

fn clear_clipboard_after(client: &Client<'_>) -> AppResult<Duration> {
    let path = api_path(&format!(
        "/settings/{}",
        path_component(CLEAR_CLIPBOARD_AFTER_SECONDS_SETTING)
    ));
    let response: SettingResponse = client.get_json_with_item_scope(&path)?;
    setting(CLEAR_CLIPBOARD_AFTER_SECONDS_SETTING)
        .and_then(|setting| setting.parse_duration(&response.value))
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid {CLEAR_CLIPBOARD_AFTER_SECONDS_SETTING} setting"),
            )
            .into()
        })
}

fn clipboard_text(bytes: &[u8]) -> io::Result<&str> {
    std::str::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "clipboard value is not UTF-8"))
}

fn interrupt_receiver() -> AppResult<Receiver<()>> {
    let (sender, receiver) = mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = sender.send(());
    })?;
    Ok(receiver)
}

trait ClipboardBackend {
    fn set_text(&mut self, text: &str) -> AppResult;
    fn get_text(&mut self) -> AppResult<Zeroizing<String>>;
    fn clear(&mut self) -> AppResult;
}

struct NativeClipboard {
    inner: Clipboard,
}

impl NativeClipboard {
    fn new() -> AppResult<Self> {
        Ok(Self {
            inner: Clipboard::new()?,
        })
    }
}

impl ClipboardBackend for NativeClipboard {
    fn set_text(&mut self, text: &str) -> AppResult {
        #[cfg(target_os = "linux")]
        {
            self.inner
                .set()
                .exclude_from_history()
                .text(text)
                .map_err(Into::into)
        }
        #[cfg(any(target_os = "macos", windows))]
        {
            Ok(self.inner.set_text(text)?)
        }
    }

    fn get_text(&mut self) -> AppResult<Zeroizing<String>> {
        Ok(Zeroizing::new(self.inner.get_text()?))
    }

    fn clear(&mut self) -> AppResult {
        Ok(self.inner.clear()?)
    }
}

fn copy_and_clear(
    clipboard: &mut impl ClipboardBackend,
    text: &str,
    clear_after: Duration,
    interrupted: Receiver<()>,
    output: &mut impl Write,
) -> AppResult {
    clipboard.set_text(text)?;
    writeln!(
        output,
        "Clearing clipboard after {} seconds...",
        clear_after.as_secs()
    )?;

    match interrupted.recv_timeout(clear_after) {
        Ok(()) | Err(RecvTimeoutError::Timeout) => {}
        Err(RecvTimeoutError::Disconnected) => {
            return Err(io::Error::other("clipboard interrupt handler disconnected").into());
        }
    }

    let current = clipboard.get_text()?;
    if current.as_bytes() == text.as_bytes() {
        clipboard.clear()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeClipboard {
        current: Option<Zeroizing<String>>,
        set_values: Vec<Zeroizing<String>>,
        replacement_after_set: Option<Zeroizing<String>>,
        clear_count: usize,
        get_error: bool,
        clear_error: bool,
    }

    impl ClipboardBackend for FakeClipboard {
        fn set_text(&mut self, text: &str) -> AppResult {
            let text = Zeroizing::new(text.to_owned());
            self.current = Some(text.clone());
            self.set_values.push(text);
            if let Some(replacement) = self.replacement_after_set.take() {
                self.current = Some(replacement);
            }
            Ok(())
        }

        fn get_text(&mut self) -> AppResult<Zeroizing<String>> {
            if self.get_error {
                return Err(io::Error::other("clipboard read failed").into());
            }
            self.current
                .clone()
                .ok_or_else(|| io::Error::other("clipboard is empty").into())
        }

        fn clear(&mut self) -> AppResult {
            if self.clear_error {
                return Err(io::Error::other("clipboard clear failed").into());
            }
            self.current = None;
            self.clear_count += 1;
            Ok(())
        }
    }

    fn disconnected_receiver() -> Receiver<()> {
        let (sender, receiver) = mpsc::channel();
        drop(sender);
        receiver
    }

    fn interrupted_receiver() -> Receiver<()> {
        let (sender, receiver) = mpsc::channel();
        sender.send(()).unwrap();
        receiver
    }

    #[test]
    fn interruption_clears_unchanged_text_and_prints_one_line() {
        let mut clipboard = FakeClipboard::default();
        let mut output = Vec::new();

        copy_and_clear(
            &mut clipboard,
            "sëcret\0value",
            Duration::from_secs(30),
            interrupted_receiver(),
            &mut output,
        )
        .unwrap();

        assert_eq!(1, clipboard.clear_count);
        assert!(clipboard.current.is_none());
        assert_eq!(
            vec![Zeroizing::new("sëcret\0value".to_owned())],
            clipboard.set_values
        );
        assert_eq!(
            b"Clearing clipboard after 30 seconds...\n",
            output.as_slice()
        );
    }

    #[test]
    fn replacement_is_preserved() {
        let mut clipboard = FakeClipboard {
            replacement_after_set: Some(Zeroizing::new("replacement".to_owned())),
            ..FakeClipboard::default()
        };
        let mut output = Vec::new();

        copy_and_clear(
            &mut clipboard,
            "secret",
            Duration::from_secs(30),
            interrupted_receiver(),
            &mut output,
        )
        .unwrap();

        assert_eq!(0, clipboard.clear_count);
        assert_eq!(
            Some(&Zeroizing::new("replacement".to_owned())),
            clipboard.current.as_ref()
        );
    }

    #[test]
    fn timeout_clears_unchanged_text() {
        let mut clipboard = FakeClipboard::default();
        let (sender, receiver) = mpsc::channel();

        copy_and_clear(
            &mut clipboard,
            "secret",
            Duration::ZERO,
            receiver,
            &mut Vec::new(),
        )
        .unwrap();
        drop(sender);

        assert_eq!(1, clipboard.clear_count);
    }

    #[test]
    fn read_failure_preserves_clipboard_and_returns_error() {
        let mut clipboard = FakeClipboard {
            get_error: true,
            ..FakeClipboard::default()
        };

        let error = copy_and_clear(
            &mut clipboard,
            "secret",
            Duration::from_secs(30),
            interrupted_receiver(),
            &mut Vec::new(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("clipboard read failed"));
        assert_eq!(0, clipboard.clear_count);
        assert_eq!(
            Some(&Zeroizing::new("secret".to_owned())),
            clipboard.current.as_ref()
        );
    }

    #[test]
    fn clear_failure_is_returned() {
        let mut clipboard = FakeClipboard {
            clear_error: true,
            ..FakeClipboard::default()
        };

        let error = copy_and_clear(
            &mut clipboard,
            "secret",
            Duration::from_secs(30),
            interrupted_receiver(),
            &mut Vec::new(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("clipboard clear failed"));
    }

    #[test]
    fn disconnected_interrupt_handler_is_an_error_without_clearing() {
        let mut clipboard = FakeClipboard::default();

        let error = copy_and_clear(
            &mut clipboard,
            "secret",
            Duration::from_secs(30),
            disconnected_receiver(),
            &mut Vec::new(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("interrupt handler disconnected"));
        assert_eq!(0, clipboard.clear_count);
    }

    #[test]
    fn non_utf8_value_is_rejected() {
        let error = clipboard_text(b"secret\xff").unwrap_err();

        assert_eq!(io::ErrorKind::InvalidData, error.kind());
        assert_eq!("clipboard value is not UTF-8", error.to_string());
    }
}
