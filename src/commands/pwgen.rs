use std::io;

use zeroize::Zeroizing;

use super::wordlist::WORDS;

const SYMBOLS: &[u8] = b"!@#$%^&*_-+=?";

pub fn generate(spec: Option<&str>) -> io::Result<Zeroizing<String>> {
    match spec {
        Some(spec) if !spec.trim().is_empty() => generate_from_spec(spec),
        _ => generate_default(),
    }
}

fn generate_default() -> io::Result<Zeroizing<String>> {
    let mut parts = Vec::new();
    for _ in 0..3 {
        let word = WORDS[random_index(WORDS.len())?];
        let mut chars = word.chars();
        let first = chars.next().unwrap().to_ascii_uppercase();
        let rest: String = chars.collect();
        parts.push(format!("{first}{rest}"));
    }
    let symbol = SYMBOLS[random_index(SYMBOLS.len())?] as char;
    let digit = (b'0' + random_index(10)? as u8) as char;
    Ok(Zeroizing::new(format!(
        "{}{}{}",
        parts.join("-"),
        symbol,
        digit
    )))
}

fn generate_from_spec(spec: &str) -> io::Result<Zeroizing<String>> {
    let mut parts = spec.split(',').map(str::trim);
    let len = parts
        .next()
        .ok_or_else(|| invalid("missing password length"))?
        .parse::<usize>()
        .map_err(|_| invalid("invalid password length"))?;
    if len == 0 || len > 4096 {
        return Err(invalid("password length must be between 1 and 4096"));
    }
    let mut alphabet = Vec::new();
    for part in parts {
        match part {
            "upper" => alphabet.extend(b'A'..=b'Z'),
            "lower" => alphabet.extend(b'a'..=b'z'),
            "digit" | "digits" => alphabet.extend(b'0'..=b'9'),
            "alpha" => {
                alphabet.extend(b'A'..=b'Z');
                alphabet.extend(b'a'..=b'z');
            }
            "hex" => alphabet.extend(b"0123456789abcdef"),
            "symbol" | "symbols" => alphabet.extend(SYMBOLS),
            "" => {}
            _ => return Err(invalid("unknown password generation character class")),
        }
    }
    if alphabet.is_empty() {
        alphabet.extend(b'A'..=b'Z');
        alphabet.extend(b'a'..=b'z');
        alphabet.extend(b'0'..=b'9');
    }
    let mut password = String::with_capacity(len);
    for _ in 0..len {
        password.push(alphabet[random_index(alphabet.len())?] as char);
    }
    Ok(Zeroizing::new(password))
}

fn random_index(upper: usize) -> io::Result<usize> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(|error| io::Error::other(error.to_string()))?;
    Ok((u64::from_ne_bytes(bytes) as usize) % upper)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::generate;

    #[test]
    fn generates_requested_character_classes() {
        let password = generate(Some("64,hex")).unwrap();
        assert_eq!(password.len(), 64);
        assert!(
            password
                .chars()
                .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
        );
    }

    #[test]
    fn rejects_unknown_character_classes() {
        assert!(generate(Some("12,emoji")).is_err());
    }
}
