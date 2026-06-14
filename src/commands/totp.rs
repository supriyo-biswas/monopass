use std::io;
use std::path::Path;

use crate::secret::SecretString;

pub fn normalize(input: &str) -> io::Result<SecretString> {
    if input.starts_with("otpauth://") {
        validate_url(input)?;
        return Ok(input.into());
    }
    let image = image::open(Path::new(input))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?
        .to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(image);
    let mut url: Option<SecretString> = None;
    for grid in prepared.detect_grids() {
        let (_, content) = grid
            .decode()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        if !content.starts_with("otpauth://") {
            return Err(invalid("QR payload is not an otpauth URL"));
        }
        validate_url(&content)?;
        if let Some(existing) = &url {
            if existing.as_str() != content {
                return Err(invalid("multiple conflicting TOTP QR codes found"));
            }
        } else {
            url = Some(content.into());
        }
    }
    url.ok_or_else(|| invalid("no TOTP QR code found"))
}

fn validate_url(input: &str) -> io::Result<()> {
    let url = url::Url::parse(input)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    if url.scheme() != "otpauth" || url.host_str() != Some("totp") {
        return Err(invalid("expected otpauth://totp URL"));
    }
    if !url
        .query_pairs()
        .any(|(name, value)| name == "secret" && !value.is_empty())
    {
        return Err(invalid("TOTP URL must include a non-empty secret"));
    }
    Ok(())
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
