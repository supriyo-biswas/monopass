use std::io::{self, BufRead, Write};

use zxcvbn::{Score, zxcvbn};

pub(crate) const MIN_MASTER_PASSWORD_CHARS: usize = 10;
pub(crate) const INIT_WEAK_PASSWORD_PROMPT: &str =
    "Master password is weak. Continue initialization? [y/n] ";
pub(crate) const PASSWD_WEAK_PASSWORD_PROMPT: &str =
    "Master password is weak. Continue password change? [y/n] ";

pub(crate) fn validate_master_password(password: &str) -> io::Result<()> {
    validate_master_password_with_weak_prompt(password, INIT_WEAK_PASSWORD_PROMPT)
}

pub(crate) fn validate_master_password_with_weak_prompt(
    password: &str,
    weak_password_prompt: &str,
) -> io::Result<()> {
    if password.chars().count() < MIN_MASTER_PASSWORD_CHARS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "master password must be at least 10 characters long",
        ));
    }

    if is_weak_password(zxcvbn(password, &[]).score())
        && !prompt_confirmation(weak_password_prompt)?
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "weak master password was not confirmed",
        ));
    }

    Ok(())
}

pub(crate) fn prompt_confirmation(prompt: &str) -> io::Result<bool> {
    let stdin = io::stdin();
    prompt_confirmation_with(prompt, stdin.lock())
}

fn prompt_confirmation_with(prompt: &str, mut input: impl BufRead) -> io::Result<bool> {
    loop {
        eprint!("{prompt}");
        io::stderr().flush()?;

        let mut answer = String::new();
        if input.read_line(&mut answer)? == 0 {
            return Ok(false);
        }

        match parse_confirmation(&answer) {
            Some(confirmed) => return Ok(confirmed),
            None => eprintln!("Please answer y or n."),
        }
    }
}

fn is_weak_password(score: Score) -> bool {
    let score: u8 = score.into();
    score < 3
}

fn parse_confirmation(answer: &str) -> Option<bool> {
    match answer.trim().to_ascii_lowercase().as_str() {
        "y" => Some(true),
        "n" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use zxcvbn::Score;

    use super::{
        is_weak_password, parse_confirmation, prompt_confirmation_with, validate_master_password,
    };

    #[test]
    fn detects_weak_password_threshold() {
        assert!(is_weak_password(Score::Zero));
        assert!(is_weak_password(Score::One));
        assert!(is_weak_password(Score::Two));
        assert!(!is_weak_password(Score::Three));
        assert!(!is_weak_password(Score::Four));
    }

    #[test]
    fn parses_y_n_confirmation() {
        assert_eq!(Some(true), parse_confirmation("y\n"));
        assert_eq!(Some(true), parse_confirmation("Y"));
        assert_eq!(Some(false), parse_confirmation("n\n"));
        assert_eq!(Some(false), parse_confirmation("N"));
        assert_eq!(None, parse_confirmation("yes"));
        assert_eq!(None, parse_confirmation(""));
    }

    #[test]
    fn prompt_confirmation_accepts_only_y_or_n_and_eof_is_no() {
        assert!(prompt_confirmation_with("", io::Cursor::new("y\n")).unwrap());
        assert!(!prompt_confirmation_with("", io::Cursor::new("n\n")).unwrap());
        assert!(prompt_confirmation_with("", io::Cursor::new("yes\ny\n")).unwrap());
        assert!(!prompt_confirmation_with("", io::Cursor::new("")).unwrap());
    }

    #[test]
    fn rejects_short_master_password() {
        let error = validate_master_password("short").unwrap_err();
        assert_eq!(io::ErrorKind::InvalidInput, error.kind());
    }
}
