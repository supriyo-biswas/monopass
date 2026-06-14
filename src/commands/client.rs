use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

use base64::Engine;
use base64::engine::general_purpose;
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::{Zeroize, Zeroizing};

use crate::AppResult;
use crate::config::Config;

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "api error {} {}: {}",
            self.status, self.code, self.message
        )
    }
}

impl std::error::Error for ApiError {}

#[derive(Clone)]
pub struct Response {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Response {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Response")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("body_len", &self.body.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AuthMode {
    ProcessOnly,
    IncludePassword,
}

#[derive(Debug, Clone)]
pub struct Client<'a> {
    config: &'a Config,
}

impl<'a> Client<'a> {
    pub fn new(config: &'a Config) -> Self {
        Self { config }
    }

    pub fn get_json<T: DeserializeOwned>(&self, path: &str) -> AppResult<T> {
        let response = self.request_with_unlock(
            "GET",
            path,
            Zeroizing::new(Vec::new()),
            None,
            AuthMode::ProcessOnly,
        )?;
        Ok(serde_json::from_slice(&response.body)?)
    }

    pub fn get_json_with_password<T: DeserializeOwned>(&self, path: &str) -> AppResult<T> {
        let response = self.request_with_unlock(
            "GET",
            path,
            Zeroizing::new(Vec::new()),
            None,
            AuthMode::IncludePassword,
        )?;
        Ok(serde_json::from_slice(&response.body)?)
    }

    pub fn get_bytes(&self, path: &str, auth_mode: AuthMode) -> AppResult<Response> {
        self.request_with_unlock("GET", path, Zeroizing::new(Vec::new()), None, auth_mode)
    }

    pub fn post_empty_without_unlock(&self, path: &str) -> AppResult<()> {
        let response = self.request("POST", path, &[], None, None)?;
        if !(200..300).contains(&response.status) {
            return Err(api_error(response).into());
        }
        Ok(())
    }

    pub fn put_empty(&self, path: &str) -> AppResult<()> {
        self.request_with_unlock(
            "PUT",
            path,
            Zeroizing::new(Vec::new()),
            None,
            AuthMode::ProcessOnly,
        )?;
        Ok(())
    }

    pub fn put_empty_json<T: DeserializeOwned>(&self, path: &str) -> AppResult<T> {
        let response = self.request_with_unlock(
            "PUT",
            path,
            Zeroizing::new(Vec::new()),
            None,
            AuthMode::ProcessOnly,
        )?;
        Ok(serde_json::from_slice(&response.body)?)
    }

    pub fn delete_empty(&self, path: &str) -> AppResult<()> {
        self.request_with_unlock(
            "DELETE",
            path,
            Zeroizing::new(Vec::new()),
            None,
            AuthMode::ProcessOnly,
        )?;
        Ok(())
    }

    pub fn put_json<T: Serialize>(&self, path: &str, body: &T) -> AppResult<()> {
        let body = Zeroizing::new(serde_json::to_vec(body)?);
        self.request_with_unlock(
            "PUT",
            path,
            body,
            Some("application/json"),
            AuthMode::ProcessOnly,
        )?;
        Ok(())
    }

    pub fn patch_json<T: Serialize>(&self, path: &str, body: &T) -> AppResult<()> {
        let body = Zeroizing::new(serde_json::to_vec(body)?);
        self.request_with_unlock(
            "PATCH",
            path,
            body,
            Some("application/json"),
            AuthMode::ProcessOnly,
        )?;
        Ok(())
    }

    pub fn put_bytes_json<T: DeserializeOwned>(
        &self,
        path: &str,
        body: Zeroizing<Vec<u8>>,
    ) -> AppResult<T> {
        let response = self.request_with_unlock(
            "PUT",
            path,
            body,
            Some("application/octet-stream"),
            AuthMode::ProcessOnly,
        )?;
        Ok(serde_json::from_slice(&response.body)?)
    }

    pub fn request_with_unlock(
        &self,
        method: &str,
        path: &str,
        body: Zeroizing<Vec<u8>>,
        content_type: Option<&str>,
        auth_mode: AuthMode,
    ) -> AppResult<Response> {
        let mut password: Option<Zeroizing<String>> = None;
        let mut response = self.request(method, path, &body, content_type, None)?;
        if is_access_denied(&response) {
            let prompted = prompt_master_password()?;
            self.unlock(&prompted)?;
            password = Some(prompted);
            let bearer = match auth_mode {
                AuthMode::ProcessOnly => None,
                AuthMode::IncludePassword => password.as_deref().map(String::as_str),
            };
            response = self.request(method, path, &body, content_type, bearer)?;
        }

        if is_access_denied(&response) {
            return Err(ApiError {
                status: response.status,
                code: "access_denied".to_owned(),
                message: "access denied".to_owned(),
            }
            .into());
        }

        if !(200..300).contains(&response.status) {
            return Err(api_error(response).into());
        }

        if let Some(mut password) = password {
            password.zeroize();
        }

        Ok(response)
    }

    fn unlock(&self, password: &str) -> AppResult<()> {
        let response = self.request("POST", "/api/v1/auth/unlock", &[], None, Some(password))?;
        if response.status == 200 {
            return Ok(());
        }
        Err(api_error(response).into())
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        content_type: Option<&str>,
        bearer_password: Option<&str>,
    ) -> AppResult<Response> {
        let mut stream = UnixStream::connect(self.config.listen_path())?;
        let mut request = Zeroizing::new(format!(
            "{method} {path} HTTP/1.1\r\nHost: monopass\r\nConnection: close\r\nContent-Length: {}\r\n",
            body.len()
        ));
        if let Some(content_type) = content_type {
            request.push_str("Content-Type: ");
            request.push_str(content_type);
            request.push_str("\r\n");
        }
        if let Some(password) = bearer_password {
            let token = Zeroizing::new(general_purpose::STANDARD.encode(password.as_bytes()));
            request.push_str("Authorization: Bearer ");
            request.push_str(&token);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");

        stream.write_all(request.as_bytes())?;
        stream.write_all(body)?;

        let mut raw = Zeroizing::new(Vec::new());
        stream.read_to_end(&mut raw)?;
        parse_response(raw)
    }
}

pub fn prompt_master_password() -> io::Result<Zeroizing<String>> {
    rpassword::prompt_password("Enter master password: ").map(Zeroizing::new)
}

pub fn api_path(path: &str) -> String {
    format!("/api/v1{path}")
}

pub fn path_component(value: &str) -> String {
    use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
    const PATH: &AsciiSet = &CONTROLS
        .add(b' ')
        .add(b'"')
        .add(b'#')
        .add(b'%')
        .add(b'<')
        .add(b'>')
        .add(b'?')
        .add(b'`')
        .add(b'{')
        .add(b'}')
        .add(b'/');

    utf8_percent_encode(value, PATH).to_string()
}

pub fn query_value(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn parse_response(raw: Zeroizing<Vec<u8>>) -> AppResult<Response> {
    let header_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed HTTP response"))?;
    let header_bytes = &raw[..header_end];
    let mut body = Zeroizing::new(raw[header_end + 4..].to_vec());
    let headers_text = std::str::from_utf8(header_bytes)?;
    let mut lines = headers_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP status"))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP status code"))?
        .parse::<u16>()?;
    let mut headers = HashMap::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
    }

    if headers
        .get("transfer-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
    {
        body = decode_chunked(&body)?;
    }

    Ok(Response {
        status,
        headers,
        body,
    })
}

fn decode_chunked(mut body: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut decoded = Zeroizing::new(Vec::new());
    loop {
        let line_end = body
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed chunk"))?;
        let size_text = std::str::from_utf8(&body[..line_end])
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let size_text = size_text.split(';').next().unwrap_or(size_text);
        let size = usize::from_str_radix(size_text.trim(), 16)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(decoded);
        }
        if body.len() < size + 2 || &body[size..size + 2] != b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk shorter than declared size",
            ));
        }
        decoded.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

fn is_access_denied(response: &Response) -> bool {
    response.status == 403
        && serde_json::from_slice::<serde_json::Value>(&response.body)
            .ok()
            .and_then(|value| {
                value
                    .pointer("/error/code")
                    .and_then(|code| code.as_str())
                    .map(str::to_owned)
            })
            .as_deref()
            == Some("access_denied")
}

fn api_error(response: Response) -> ApiError {
    let parsed = serde_json::from_slice::<serde_json::Value>(&response.body).ok();
    let code = parsed
        .as_ref()
        .and_then(|value| value.pointer("/error/code"))
        .and_then(|value| value.as_str())
        .unwrap_or("http_error")
        .to_owned();
    let message = parsed
        .as_ref()
        .and_then(|value| value.pointer("/error/message"))
        .and_then(|value| value.as_str())
        .unwrap_or("request failed")
        .to_owned();

    ApiError {
        status: response.status,
        code,
        message,
    }
}
