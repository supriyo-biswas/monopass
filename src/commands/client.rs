use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

use base64::Engine;
use base64::engine::general_purpose;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use super::models::{ShellCompletionKind, ShellCompletionsResponse};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessScope {
    Items,
    Settings,
}

impl AccessScope {
    fn for_api_path(path: &str) -> Self {
        let path = path.split_once('?').map_or(path, |(path, _)| path);
        if path == "/api/v1/settings" || path.starts_with("/api/v1/settings/") {
            Self::Settings
        } else {
            Self::Items
        }
    }

    fn discovery_path(self) -> &'static str {
        match self {
            Self::Items => "/api/v1/auth/unlock/methods",
            Self::Settings => "/api/v1/auth/unlock/methods?scope=settings",
        }
    }
}

#[derive(Debug, Deserialize)]
struct AuthUnlockMethodsResponse {
    methods: Vec<AuthUnlockMethod>,
}

#[derive(Debug, Deserialize)]
struct AuthUnlockMethod {
    url: String,
    accepts_master_password: bool,
}

pub struct Client<'a> {
    config: &'a Config,
    capabilities: Option<String>,
    connection: RefCell<Option<LocalStream>>,
}

impl fmt::Debug for Client<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Client")
            .field("config", &self.config)
            .field("capabilities", &self.capabilities)
            .finish_non_exhaustive()
    }
}

impl Clone for Client<'_> {
    fn clone(&self) -> Self {
        Self {
            config: self.config,
            capabilities: self.capabilities.clone(),
            connection: RefCell::new(None),
        }
    }
}

impl<'a> Client<'a> {
    pub fn new(config: &'a Config) -> Self {
        Self {
            config,
            capabilities: detect_client_capabilities(),
            connection: RefCell::new(None),
        }
    }

    #[cfg(test)]
    fn with_capabilities(config: &'a Config, capabilities: Option<String>) -> Self {
        Self {
            config,
            capabilities,
            connection: RefCell::new(None),
        }
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

    #[cfg(any(
        test,
        target_os = "macos",
        windows,
        all(target_os = "linux", any(feature = "gtk", feature = "qt"))
    ))]
    pub fn get_json_with_item_scope<T: DeserializeOwned>(&self, path: &str) -> AppResult<T> {
        let response = self.request_with_unlock_prompt_for_scope(
            "GET",
            path,
            Zeroizing::new(Vec::new()),
            None,
            AuthMode::ProcessOnly,
            AccessScope::Items,
            prompt_master_password,
        )?;
        Ok(serde_json::from_slice(&response.body)?)
    }

    pub fn shell_completions(
        &self,
        prefix: &str,
        kinds: &[ShellCompletionKind],
    ) -> Option<ShellCompletionsResponse> {
        let kinds = kinds
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let path = format!(
            "/api/v1/shell/completions?prefix={}&kinds={}",
            query_value(prefix),
            query_value(&kinds)
        );
        let mut response = self.request("GET", &path, &[], None, None).ok()?;
        if is_access_denied(&response) {
            let method = self.first_unlock_method(AccessScope::Items).ok()?;
            if method.accepts_master_password || self.unlock(&method, None).is_err() {
                return None;
            }
            response = self.request("GET", &path, &[], None, None).ok()?;
        }
        if !(200..300).contains(&response.status) {
            return None;
        }
        serde_json::from_slice(&response.body).ok()
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
        self.request_with_unlock_prompt(
            method,
            path,
            body,
            content_type,
            auth_mode,
            prompt_master_password,
        )
    }

    fn request_with_unlock_prompt<F>(
        &self,
        method: &str,
        path: &str,
        body: Zeroizing<Vec<u8>>,
        content_type: Option<&str>,
        auth_mode: AuthMode,
        prompt: F,
    ) -> AppResult<Response>
    where
        F: FnOnce() -> io::Result<Zeroizing<String>>,
    {
        self.request_with_unlock_prompt_for_scope(
            method,
            path,
            body,
            content_type,
            auth_mode,
            AccessScope::for_api_path(path),
            prompt,
        )
    }

    fn request_with_unlock_prompt_for_scope<F>(
        &self,
        method: &str,
        path: &str,
        body: Zeroizing<Vec<u8>>,
        content_type: Option<&str>,
        auth_mode: AuthMode,
        access_scope: AccessScope,
        prompt: F,
    ) -> AppResult<Response>
    where
        F: FnOnce() -> io::Result<Zeroizing<String>>,
    {
        let mut password: Option<Zeroizing<String>> = None;
        let mut response = self.request(method, path, &body, content_type, None)?;
        if is_access_denied(&response) {
            let unlock_method = self.first_unlock_method(access_scope)?;
            if unlock_method.accepts_master_password {
                let prompted = prompt()?;
                self.unlock(&unlock_method, Some(&prompted))?;
                password = Some(prompted);
            } else {
                self.unlock(&unlock_method, None)?;
            }

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

    fn first_unlock_method(&self, access_scope: AccessScope) -> AppResult<AuthUnlockMethod> {
        let response = self.request_with_client_capabilities(
            "GET",
            access_scope.discovery_path(),
            &[],
            None,
            None,
            true,
        )?;
        if !(200..300).contains(&response.status) {
            return Err(api_error(response).into());
        }

        let methods: AuthUnlockMethodsResponse = serde_json::from_slice(&response.body)?;
        methods.methods.into_iter().next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "agent returned no unlock methods",
            )
            .into()
        })
    }

    fn unlock(&self, method: &AuthUnlockMethod, password: Option<&str>) -> AppResult<()> {
        let path = unlock_method_api_path(&method.url)?;
        let include_capabilities = path.split_once('?').map_or(path.as_str(), |(path, _)| path)
            == "/api/v1/auth/unlock/gui";
        let response = self.request_with_client_capabilities(
            "POST",
            &path,
            &[],
            None,
            password,
            include_capabilities,
        )?;
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
        self.request_with_client_capabilities(
            method,
            path,
            body,
            content_type,
            bearer_password,
            false,
        )
    }

    fn request_with_client_capabilities(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        content_type: Option<&str>,
        bearer_password: Option<&str>,
        include_client_capabilities: bool,
    ) -> AppResult<Response> {
        let mut request = Zeroizing::new(format!(
            "{method} {path} HTTP/1.1\r\nHost: monopass\r\nConnection: keep-alive\r\nContent-Length: {}\r\n",
            body.len()
        ));
        if let Some(content_type) = content_type {
            request.push_str("Content-Type: ");
            request.push_str(content_type);
            request.push_str("\r\n");
        }
        if include_client_capabilities && let Some(capabilities) = self.capabilities.as_deref() {
            request.push_str("X-Client-Capabilities: ");
            request.push_str(capabilities);
            request.push_str("\r\n");
        }
        if let Some(password) = bearer_password {
            let token = Zeroizing::new(general_purpose::STANDARD.encode(password.as_bytes()));
            request.push_str("Authorization: Bearer ");
            request.push_str(&token);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");

        let mut connection = self.connection.borrow_mut();
        if connection.is_none() {
            *connection = Some(connect_transport(self.config.listen_path())?);
        }

        let result = {
            let stream = connection.as_mut().expect("connection was initialized");
            stream
                .write_all(request.as_bytes())
                .and_then(|()| stream.write_all(body))
                .and_then(|()| read_response(stream, method))
        };
        match result {
            Ok((response, true)) => Ok(response),
            Ok((response, false)) => {
                *connection = None;
                Ok(response)
            }
            Err(error) => {
                *connection = None;
                Err(error.into())
            }
        }
    }
}

#[cfg(unix)]
type LocalStream = UnixStream;
#[cfg(windows)]
type LocalStream = std::fs::File;

#[cfg(unix)]
fn connect_transport(path: &std::path::Path) -> io::Result<LocalStream> {
    UnixStream::connect(path)
}

#[cfg(windows)]
fn connect_transport(path: &std::path::Path) -> io::Result<LocalStream> {
    use std::fs::OpenOptions;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY};
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut launched = false;
    loop {
        match OpenOptions::new().read(true).write(true).open(path) {
            Ok(stream) => {
                let mut server_pid = 0u32;
                if unsafe {
                    GetNamedPipeServerProcessId(stream.as_raw_handle().cast(), &mut server_pid)
                } == 0
                {
                    return Err(io::Error::last_os_error());
                }
                let server_pid = i32::try_from(server_pid)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid agent pid"))?;
                let server_principal = crate::agent::process::windows_process_principal(server_pid)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::PermissionDenied, "unverified agent")
                    })?;
                let current_principal = crate::agent::process::current_windows_principal()
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::PermissionDenied, "unverified client")
                    })?;
                let server_exe = crate::agent::process::windows_process_executable_path(server_pid)
                    .and_then(|path| std::fs::canonicalize(path).ok());
                let current_exe = std::env::current_exe()
                    .ok()
                    .and_then(|path| std::fs::canonicalize(path).ok());
                if server_principal != current_principal
                    || server_exe.is_none()
                    || server_exe != current_exe
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "named-pipe server identity verification failed",
                    ));
                }
                return Ok(stream);
            }
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(code)
                        if code == ERROR_FILE_NOT_FOUND as i32 || code == ERROR_PIPE_BUSY as i32
                ) && Instant::now() < deadline =>
            {
                if !launched && error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) {
                    launch_windows_agent()?;
                    launched = true;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(windows)]
fn launch_windows_agent() -> io::Result<()> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW};

    Command::new(std::env::current_exe()?)
        .arg("agent")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW)
        .spawn()
        .map(|_| ())
}

fn detect_client_capabilities() -> Option<String> {
    #[cfg(windows)]
    {
        return Some("windows-secure-desktop".to_owned());
    }
    #[cfg(unix)]
    client_capabilities_from_env(|name| std::env::var(name).ok())
}

fn client_capabilities_from_env<F>(mut get_env: F) -> Option<String>
where
    F: FnMut(&str) -> Option<String>,
{
    get_env("DISPLAY")
        .filter(|value| !value.is_empty())
        .map(|display| format!("x-session={display}"))
        .or_else(|| {
            get_env("WAYLAND_DISPLAY")
                .filter(|value| !value.is_empty())
                .map(|display| format!("wayland-session={display}"))
        })
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

const MAX_RESPONSE_HEADERS: usize = 64 * 1024;

fn read_response(stream: &mut LocalStream, request_method: &str) -> io::Result<(Response, bool)> {
    for _ in 0..16 {
        let result = read_one_response(stream, request_method)?;
        if (100..200).contains(&result.0.status) && result.0.status != 101 {
            continue;
        }
        return Ok(result);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "too many informational HTTP responses",
    ))
}

fn read_one_response(
    stream: &mut LocalStream,
    request_method: &str,
) -> io::Result<(Response, bool)> {
    let header_bytes = read_headers(stream)?;
    let headers_text =
        std::str::from_utf8(header_bytes.strip_suffix(b"\r\n\r\n").ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "malformed HTTP response")
        })?)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut lines = headers_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP status"))?;
    let mut status_parts = status_line.split_whitespace();
    let version = status_parts
        .next()
        .filter(|version| matches!(*version, "HTTP/1.0" | "HTTP/1.1"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP version"))?;
    let status = status_parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP status code"))?
        .parse::<u16>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut headers = HashMap::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed HTTP header"))?;
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty HTTP header name",
            ));
        }
        let value = value.trim();
        headers
            .entry(name)
            .and_modify(|current: &mut String| {
                current.push_str(", ");
                current.push_str(value);
            })
            .or_insert_with(|| value.to_owned());
    }

    let connection_close = header_has_token(&headers, "connection", "close");
    let connection_keep_alive = header_has_token(&headers, "connection", "keep-alive");
    let bodyless = request_method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status)
        || matches!(status, 204 | 304);
    let chunked = header_has_token(&headers, "transfer-encoding", "chunked");
    let content_length = parse_content_length(&headers)?;

    let (body, close_delimited) = if bodyless {
        (Zeroizing::new(Vec::new()), false)
    } else if chunked {
        (read_chunked_body(stream)?, false)
    } else if let Some(length) = content_length {
        (read_exact_body(stream, length)?, false)
    } else {
        (read_close_delimited_body(stream)?, true)
    };

    let reusable = !connection_close
        && !close_delimited
        && status != 101
        && (version == "HTTP/1.1" || connection_keep_alive);
    Ok((
        Response {
            status,
            headers,
            body,
        },
        reusable,
    ))
}

fn read_headers(stream: &mut LocalStream) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut headers = Zeroizing::new(Vec::new());
    while headers.len() < MAX_RESPONSE_HEADERS {
        let mut byte = [0_u8; 1];
        let read = stream.read(&mut byte)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before response headers completed",
            ));
        }
        headers.push(byte[0]);
        byte.zeroize();
        if headers.ends_with(b"\r\n\r\n") {
            return Ok(headers);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "HTTP response headers exceed 64 KiB",
    ))
}

fn parse_content_length(headers: &HashMap<String, String>) -> io::Result<Option<usize>> {
    let Some(value) = headers.get("content-length") else {
        return Ok(None);
    };
    let mut lengths = value.split(',').map(str::trim);
    let first = lengths
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty Content-Length"))?
        .parse::<usize>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    for length in lengths {
        let length = length
            .parse::<usize>()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if length != first {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "conflicting Content-Length headers",
            ));
        }
    }
    Ok(Some(first))
}

fn header_has_token(headers: &HashMap<String, String>, header_name: &str, expected: &str) -> bool {
    headers.get(header_name).is_some_and(|value| {
        value
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case(expected))
    })
}

fn read_exact_body(stream: &mut LocalStream, length: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut body = Zeroizing::new(vec![0_u8; length]);
    stream.read_exact(&mut body)?;
    Ok(body)
}

fn read_close_delimited_body(stream: &mut LocalStream) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut body = Zeroizing::new(Vec::new());
    let mut buffer = Zeroizing::new([0_u8; 8192]);
    loop {
        match stream.read(&mut *buffer) {
            Ok(0) => return Ok(body),
            Ok(read) => body.extend_from_slice(&buffer[..read]),
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => return Ok(body),
            Err(error) => return Err(error),
        }
    }
}

fn read_chunked_body(stream: &mut LocalStream) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut decoded = Zeroizing::new(Vec::new());
    loop {
        let size_line = read_crlf_line(stream, "chunk size")?;
        let size_text = std::str::from_utf8(&size_line)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let size_text = size_text.split(';').next().unwrap_or(size_text).trim();
        if size_text.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty chunk size",
            ));
        }
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if size == 0 {
            consume_chunk_trailers(stream)?;
            return Ok(decoded);
        }

        let chunk = read_exact_body(stream, size)?;
        decoded.extend_from_slice(&chunk);
        let mut terminator = Zeroizing::new([0_u8; 2]);
        stream.read_exact(&mut *terminator)?;
        if terminator.as_slice() != b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed chunk terminator",
            ));
        }
    }
}

fn consume_chunk_trailers(stream: &mut LocalStream) -> io::Result<()> {
    loop {
        let trailer = read_crlf_line(stream, "chunk trailer")?;
        if trailer.is_empty() {
            return Ok(());
        }
        if !trailer.contains(&b':') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed chunk trailer",
            ));
        }
    }
}

fn read_crlf_line(stream: &mut LocalStream, context: &str) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut line = Zeroizing::new(Vec::new());
    while line.len() < MAX_RESPONSE_HEADERS {
        let mut byte = [0_u8; 1];
        let read = stream.read(&mut byte)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("connection closed while reading {context}"),
            ));
        }
        line.push(byte[0]);
        byte.zeroize();
        if line.ends_with(b"\r\n") {
            let content_length = line.len() - 2;
            line.truncate(content_length);
            return Ok(line);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{context} exceeds 64 KiB"),
    ))
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

fn unlock_method_api_path(url: &str) -> io::Result<String> {
    if url.contains('#') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid unlock method url",
        ));
    }

    let (path, query) = url
        .split_once('?')
        .map_or((url, None), |(path, query)| (path, Some(query)));
    let valid_path = matches!(
        path,
        "/api/v1/auth/unlock/direct" | "/api/v1/auth/unlock/gui"
    );
    let valid_query = query.is_none_or(|query| matches!(query, "scope=items" | "scope=settings"));
    if !valid_path || !valid_query {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid unlock method url",
        ));
    }

    Ok(url.to_owned())
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::path::PathBuf;
    use std::thread;

    use base64::Engine;
    use base64::engine::general_purpose;
    use zeroize::Zeroizing;

    use super::{
        AccessScope, ApiError, AuthMode, AuthUnlockMethodsResponse, Client, Response,
        unlock_method_api_path,
    };
    use crate::commands::models::ShellCompletionKind;
    use crate::config::Config;

    #[test]
    fn unlock_methods_response_uses_methods_array() {
        let response: AuthUnlockMethodsResponse = serde_json::from_str(
            r#"{"methods":[{"url":"/api/v1/auth/unlock/direct","accepts_master_password":true}]}"#,
        )
        .unwrap();

        let method = response.methods.first().unwrap();
        assert_eq!("/api/v1/auth/unlock/direct", method.url);
        assert!(method.accepts_master_password);
    }

    #[test]
    fn settings_collection_and_member_paths_use_settings_scope() {
        assert_eq!(
            AccessScope::Settings,
            AccessScope::for_api_path("/api/v1/settings")
        );
        assert_eq!(
            AccessScope::Settings,
            AccessScope::for_api_path("/api/v1/settings/agent.authTtlSeconds")
        );
        assert_eq!(
            AccessScope::Items,
            AccessScope::for_api_path("/api/v1/dirs")
        );
    }

    #[test]
    fn unlock_method_api_path_accepts_full_api_urls() {
        assert_eq!(
            "/api/v1/auth/unlock/direct",
            unlock_method_api_path("/api/v1/auth/unlock/direct").unwrap()
        );
        assert_eq!(
            "/api/v1/auth/unlock/gui?scope=settings",
            unlock_method_api_path("/api/v1/auth/unlock/gui?scope=settings").unwrap()
        );
    }

    #[test]
    fn unlock_method_api_path_rejects_unexpected_urls() {
        for url in [
            "auth/unlock/direct",
            "/auth/unlock/direct",
            "/auth/unlock/direct?next=/x",
            "/api/v1/auth/unlock/direct?next=/x",
            "/api/v1/auth/unlock/direct?scope=unknown",
            "/api/v1/auth/unlock/direct?scope=settings&next=/x",
            "/api/v1/auth/unlock/direct#fragment",
            "/settings",
        ] {
            assert!(unlock_method_api_path(url).is_err(), "{url}");
        }
    }

    #[test]
    fn client_capabilities_prefer_x_session_then_wayland() {
        let x = super::client_capabilities_from_env(|name| match name {
            "DISPLAY" => Some(":1".to_owned()),
            "WAYLAND_DISPLAY" => Some("wayland-0".to_owned()),
            _ => None,
        });
        assert_eq!(Some("x-session=:1".to_owned()), x);

        let wayland = super::client_capabilities_from_env(|name| match name {
            "WAYLAND_DISPLAY" => Some("wayland-0".to_owned()),
            _ => None,
        });
        assert_eq!(Some("wayland-session=wayland-0".to_owned()), wayland);

        let none = super::client_capabilities_from_env(|_| None);
        assert_eq!(None, none);
    }

    #[test]
    fn request_with_unlock_uses_discovered_method_without_original_bearer_for_process_auth() {
        let server = TestServer::new(vec![
            ExpectedRequest {
                method: "GET",
                path: "/api/v1/dirs",
                authorization: None,
                client_capabilities: None,
                response: access_denied_response(),
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v1/auth/unlock/methods",
                authorization: None,
                client_capabilities: None,
                response: ok_json_response(
                    r#"{"methods":[{"url":"/api/v1/auth/unlock/direct","accepts_master_password":true}]}"#,
                ),
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v1/auth/unlock/direct",
                authorization: Some(bearer("correct")),
                client_capabilities: None,
                response: ok_empty_response(),
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v1/dirs",
                authorization: None,
                client_capabilities: None,
                response: ok_json_response("{}"),
            },
        ]);
        let config = test_config(server.listen_path());

        let response = request_with_test_prompt(&config, AuthMode::ProcessOnly);

        assert_eq!(200, response.status);
        assert_eq!(1, server.join());
    }

    #[test]
    fn request_with_unlock_preserves_migration_needed_from_unlock() {
        let server = TestServer::new(vec![
            ExpectedRequest {
                method: "GET",
                path: "/api/v1/dirs",
                authorization: None,
                client_capabilities: None,
                response: access_denied_response(),
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v1/auth/unlock/methods",
                authorization: None,
                client_capabilities: None,
                response: ok_json_response(
                    r#"{"methods":[{"url":"/api/v1/auth/unlock/direct","accepts_master_password":true}]}"#,
                ),
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v1/auth/unlock/direct",
                authorization: Some(bearer("correct")),
                client_capabilities: None,
                response: http_response(
                    502,
                    r#"{"error":{"code":"migration_needed","message":"database migration required; run `monopass migrate`"}}"#,
                ),
            },
        ]);
        let config = test_config(server.listen_path());

        let error = Client::with_capabilities(&config, None)
            .request_with_unlock_prompt(
                "GET",
                "/api/v1/dirs",
                Zeroizing::new(Vec::new()),
                None,
                AuthMode::ProcessOnly,
                || Ok(Zeroizing::new("correct".to_owned())),
            )
            .unwrap_err();
        let error = error.downcast_ref::<ApiError>().unwrap();

        assert_eq!(502, error.status);
        assert_eq!("migration_needed", error.code);
        assert_eq!(
            "database migration required; run `monopass migrate`",
            error.message
        );
        server.join();
    }

    #[test]
    fn request_with_unlock_uses_settings_scope_for_settings_api() {
        let server = TestServer::new(vec![
            ExpectedRequest {
                method: "GET",
                path: "/api/v1/settings",
                authorization: None,
                client_capabilities: None,
                response: access_denied_response(),
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v1/auth/unlock/methods?scope=settings",
                authorization: None,
                client_capabilities: None,
                response: ok_json_response(
                    r#"{"methods":[{"url":"/api/v1/auth/unlock/direct?scope=settings","accepts_master_password":true}]}"#,
                ),
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v1/auth/unlock/direct?scope=settings",
                authorization: Some(bearer("correct")),
                client_capabilities: None,
                response: ok_empty_response(),
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v1/settings",
                authorization: None,
                client_capabilities: None,
                response: ok_json_response("{}"),
            },
        ]);
        let config = test_config(server.listen_path());

        let response = Client::with_capabilities(&config, None)
            .request_with_unlock_prompt(
                "GET",
                "/api/v1/settings",
                Zeroizing::new(Vec::new()),
                None,
                AuthMode::ProcessOnly,
                || Ok(Zeroizing::new("correct".to_owned())),
            )
            .unwrap();

        assert_eq!(200, response.status);
        server.join();
    }

    #[test]
    fn explicit_item_scope_setting_read_uses_items_unlock_flow() {
        let path = "/api/v1/settings/cli.clearClipboardAfterSeconds";
        let server = TestServer::new(vec![
            ExpectedRequest {
                method: "GET",
                path,
                authorization: None,
                client_capabilities: None,
                response: access_denied_response(),
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v1/auth/unlock/methods",
                authorization: None,
                client_capabilities: None,
                response: ok_json_response(
                    r#"{"methods":[{"url":"/api/v1/auth/unlock/gui","accepts_master_password":false}]}"#,
                ),
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v1/auth/unlock/gui",
                authorization: None,
                client_capabilities: None,
                response: ok_empty_response(),
            },
            ExpectedRequest {
                method: "GET",
                path,
                authorization: None,
                client_capabilities: None,
                response: ok_json_response(r#"{"value":"30"}"#),
            },
        ]);
        let config = test_config(server.listen_path());

        let response: crate::commands::models::SettingResponse =
            Client::with_capabilities(&config, None)
                .get_json_with_item_scope(path)
                .unwrap();

        assert_eq!("30", response.value);
        server.join();
    }

    #[test]
    fn request_with_unlock_retries_original_with_bearer_for_password_auth() {
        let server = TestServer::new(vec![
            ExpectedRequest {
                method: "GET",
                path: "/api/v1/ref/personal/github/password",
                authorization: None,
                client_capabilities: None,
                response: access_denied_response(),
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v1/auth/unlock/methods",
                authorization: None,
                client_capabilities: None,
                response: ok_json_response(
                    r#"{"methods":[{"url":"/api/v1/auth/unlock/direct","accepts_master_password":true}]}"#,
                ),
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v1/auth/unlock/direct",
                authorization: Some(bearer("correct")),
                client_capabilities: None,
                response: ok_empty_response(),
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v1/ref/personal/github/password",
                authorization: Some(bearer("correct")),
                client_capabilities: None,
                response: ok_json_response("{}"),
            },
        ]);
        let config = test_config(server.listen_path());

        let response = Client::with_capabilities(&config, None)
            .request_with_unlock_prompt(
                "GET",
                "/api/v1/ref/personal/github/password",
                Zeroizing::new(Vec::new()),
                None,
                AuthMode::IncludePassword,
                || Ok(Zeroizing::new("correct".to_owned())),
            )
            .unwrap();

        assert_eq!(200, response.status);
        server.join();
    }

    #[test]
    fn request_with_unlock_uses_method_without_master_password_when_advertised() {
        let server = TestServer::new(vec![
            ExpectedRequest {
                method: "GET",
                path: "/api/v1/dirs",
                authorization: None,
                client_capabilities: None,
                response: access_denied_response(),
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v1/auth/unlock/methods",
                authorization: None,
                client_capabilities: Some("x-session=:1".to_owned()),
                response: ok_json_response(
                    r#"{"methods":[{"url":"/api/v1/auth/unlock/gui","accepts_master_password":false}]}"#,
                ),
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v1/auth/unlock/gui",
                authorization: None,
                client_capabilities: Some("x-session=:1".to_owned()),
                response: ok_empty_response(),
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v1/dirs",
                authorization: None,
                client_capabilities: None,
                response: ok_json_response("{}"),
            },
        ]);
        let config = test_config(server.listen_path());

        let response = Client::with_capabilities(&config, Some("x-session=:1".to_owned()))
            .request_with_unlock_prompt(
                "GET",
                "/api/v1/dirs",
                Zeroizing::new(Vec::new()),
                None,
                AuthMode::ProcessOnly,
                || panic!("GUI unlock must not prompt in the CLI"),
            )
            .unwrap();

        assert_eq!(200, response.status);
        server.join();
    }

    #[test]
    fn shell_completions_return_authorized_candidates() {
        let server = TestServer::new(vec![ExpectedRequest {
            method: "GET",
            path: "/api/v1/shell/completions?prefix=Per&kinds=dir%2Citem",
            authorization: None,
            client_capabilities: None,
            response: ok_json_response(
                r#"{"entries":[{"value":"Personal","kind":"dir"}],"truncated":false}"#,
            ),
        }]);
        let config = test_config(server.listen_path());

        let response = Client::with_capabilities(&config, None)
            .shell_completions(
                "Per",
                &[ShellCompletionKind::Dir, ShellCompletionKind::Item],
            )
            .unwrap();
        assert_eq!("Personal", response.entries[0].value);
        server.join();
    }

    #[test]
    fn shell_completions_quietly_refuse_direct_password_unlock() {
        let server = TestServer::new(vec![
            ExpectedRequest {
                method: "GET",
                path: "/api/v1/shell/completions?prefix=Per&kinds=dir",
                authorization: None,
                client_capabilities: None,
                response: access_denied_response(),
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v1/auth/unlock/methods",
                authorization: None,
                client_capabilities: None,
                response: ok_json_response(
                    r#"{"methods":[{"url":"/api/v1/auth/unlock/direct","accepts_master_password":true}]}"#,
                ),
            },
        ]);
        let config = test_config(server.listen_path());

        assert!(
            Client::with_capabilities(&config, None)
                .shell_completions("Per", &[ShellCompletionKind::Dir])
                .is_none()
        );
        server.join();
    }

    #[test]
    fn shell_completions_allow_one_gui_unlock_and_retry() {
        let server = TestServer::new(vec![
            ExpectedRequest {
                method: "GET",
                path: "/api/v1/shell/completions?prefix=Per&kinds=dir",
                authorization: None,
                client_capabilities: None,
                response: access_denied_response(),
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v1/auth/unlock/methods",
                authorization: None,
                client_capabilities: Some("x-session=:1".to_owned()),
                response: ok_json_response(
                    r#"{"methods":[{"url":"/api/v1/auth/unlock/gui","accepts_master_password":false}]}"#,
                ),
            },
            ExpectedRequest {
                method: "POST",
                path: "/api/v1/auth/unlock/gui",
                authorization: None,
                client_capabilities: Some("x-session=:1".to_owned()),
                response: ok_empty_response(),
            },
            ExpectedRequest {
                method: "GET",
                path: "/api/v1/shell/completions?prefix=Per&kinds=dir",
                authorization: None,
                client_capabilities: None,
                response: ok_json_response(r#"{"entries":[],"truncated":false}"#),
            },
        ]);
        let config = test_config(server.listen_path());

        assert!(
            Client::with_capabilities(&config, Some("x-session=:1".to_owned()))
                .shell_completions("Per", &[ShellCompletionKind::Dir])
                .is_some()
        );
        server.join();
    }

    #[test]
    fn shell_completions_silently_drop_malformed_responses() {
        let server = TestServer::new(vec![ExpectedRequest {
            method: "GET",
            path: "/api/v1/shell/completions?prefix=Per&kinds=dir",
            authorization: None,
            client_capabilities: None,
            response: ok_json_response(""),
        }]);
        let config = test_config(server.listen_path());

        assert!(
            Client::with_capabilities(&config, None)
                .shell_completions("Per", &[ShellCompletionKind::Dir])
                .is_none()
        );
        server.join();
    }

    #[test]
    fn consecutive_requests_reuse_one_connection() {
        let server = TestServer::new(vec![
            ExpectedRequest {
                method: "GET",
                path: "/first",
                authorization: None,
                client_capabilities: None,
                response: ok_json_response(r#"{"value":1}"#),
            },
            ExpectedRequest {
                method: "GET",
                path: "/second",
                authorization: None,
                client_capabilities: None,
                response: ok_json_response(r#"{"value":2}"#),
            },
        ]);
        let config = test_config(server.listen_path());
        let client = Client::with_capabilities(&config, None);

        let first = client.request("GET", "/first", &[], None, None).unwrap();
        let second = client.request("GET", "/second", &[], None, None).unwrap();

        assert_eq!(br#"{"value":1}"#, first.body.as_slice());
        assert_eq!(br#"{"value":2}"#, second.body.as_slice());
        assert_eq!(1, server.join());
    }

    #[test]
    fn chunked_response_with_trailers_allows_next_response() {
        let server = TestServer::new(vec![
            ExpectedRequest {
                method: "GET",
                path: "/chunked",
                authorization: None,
                client_capabilities: None,
                response: concat!(
                    "HTTP/1.1 200 OK\r\n",
                    "Transfer-Encoding: chunked\r\n\r\n",
                    "4\r\nWiki\r\n",
                    "5;extension=yes\r\npedia\r\n",
                    "0\r\nChecksum: ignored\r\nAnother: trailer\r\n\r\n"
                )
                .to_owned(),
            },
            ExpectedRequest {
                method: "GET",
                path: "/after",
                authorization: None,
                client_capabilities: None,
                response: ok_json_response("after"),
            },
        ]);
        let config = test_config(server.listen_path());
        let client = Client::with_capabilities(&config, None);

        let chunked = client.request("GET", "/chunked", &[], None, None).unwrap();
        let after = client.request("GET", "/after", &[], None, None).unwrap();

        assert_eq!(b"Wikipedia", chunked.body.as_slice());
        assert_eq!(b"after", after.body.as_slice());
        assert_eq!(1, server.join());
    }

    #[test]
    fn bodyless_response_allows_next_response() {
        let server = TestServer::new(vec![
            ExpectedRequest {
                method: "GET",
                path: "/empty",
                authorization: None,
                client_capabilities: None,
                response: concat!("HTTP/1.1 204 No Content\r\n", "Content-Length: 99\r\n\r\n")
                    .to_owned(),
            },
            ExpectedRequest {
                method: "GET",
                path: "/after",
                authorization: None,
                client_capabilities: None,
                response: ok_json_response("after"),
            },
        ]);
        let config = test_config(server.listen_path());
        let client = Client::with_capabilities(&config, None);

        let empty = client.request("GET", "/empty", &[], None, None).unwrap();
        let after = client.request("GET", "/after", &[], None, None).unwrap();

        assert!(empty.body.is_empty());
        assert_eq!(b"after", after.body.as_slice());
        assert_eq!(1, server.join());
    }

    #[test]
    fn connection_close_reconnects_on_next_explicit_request() {
        let server = TestServer::new(vec![
            ExpectedRequest {
                method: "GET",
                path: "/closing",
                authorization: None,
                client_capabilities: None,
                response: http_response_with_headers(200, "first", "Connection: close\r\n"),
            },
            ExpectedRequest {
                method: "GET",
                path: "/next",
                authorization: None,
                client_capabilities: None,
                response: ok_json_response("second"),
            },
        ]);
        let config = test_config(server.listen_path());
        let client = Client::with_capabilities(&config, None);

        assert_eq!(
            b"first",
            client
                .request("GET", "/closing", &[], None, None)
                .unwrap()
                .body
                .as_slice()
        );
        assert_eq!(
            b"second",
            client
                .request("GET", "/next", &[], None, None)
                .unwrap()
                .body
                .as_slice()
        );
        assert_eq!(2, server.join());
    }

    #[test]
    fn close_delimited_response_reconnects_on_next_explicit_request() {
        let server = TestServer::new(vec![
            ExpectedRequest {
                method: "GET",
                path: "/eof",
                authorization: None,
                client_capabilities: None,
                response: "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nfirst".to_owned(),
            },
            ExpectedRequest {
                method: "GET",
                path: "/next",
                authorization: None,
                client_capabilities: None,
                response: ok_json_response("second"),
            },
        ]);
        let config = test_config(server.listen_path());
        let client = Client::with_capabilities(&config, None);

        let first = client.request("GET", "/eof", &[], None, None).unwrap();
        let second = client.request("GET", "/next", &[], None, None).unwrap();

        assert_eq!(b"first", first.body.as_slice());
        assert_eq!(b"second", second.body.as_slice());
        assert_eq!(2, server.join());
    }

    #[test]
    fn truncated_response_is_not_replayed_and_invalidates_connection() {
        let server = TestServer::new(vec![
            ExpectedRequest {
                method: "GET",
                path: "/truncated",
                authorization: None,
                client_capabilities: None,
                response: concat!(
                    "HTTP/1.1 200 OK\r\n",
                    "Connection: close\r\n",
                    "Content-Length: 10\r\n\r\nshort"
                )
                .to_owned(),
            },
            ExpectedRequest {
                method: "GET",
                path: "/next",
                authorization: None,
                client_capabilities: None,
                response: ok_json_response("ok"),
            },
        ]);
        let config = test_config(server.listen_path());
        let client = Client::with_capabilities(&config, None);

        let error = client
            .request("GET", "/truncated", &[], None, None)
            .unwrap_err();
        assert!(
            error
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::UnexpectedEof)
        );
        assert_eq!(
            b"ok",
            client
                .request("GET", "/next", &[], None, None)
                .unwrap()
                .body
                .as_slice()
        );
        assert_eq!(2, server.join());
    }

    #[test]
    fn malformed_response_is_not_replayed_and_invalidates_connection() {
        let server = TestServer::new(vec![
            ExpectedRequest {
                method: "GET",
                path: "/malformed",
                authorization: None,
                client_capabilities: None,
                response: concat!(
                    "HTTP/1.1 200 OK\r\n",
                    "Connection: close\r\n",
                    "Content-Length: invalid\r\n\r\n"
                )
                .to_owned(),
            },
            ExpectedRequest {
                method: "GET",
                path: "/next",
                authorization: None,
                client_capabilities: None,
                response: ok_json_response("ok"),
            },
        ]);
        let config = test_config(server.listen_path());
        let client = Client::with_capabilities(&config, None);

        assert!(
            client
                .request("GET", "/malformed", &[], None, None)
                .is_err()
        );
        assert_eq!(
            b"ok",
            client
                .request("GET", "/next", &[], None, None)
                .unwrap()
                .body
                .as_slice()
        );
        assert_eq!(2, server.join());
    }

    #[test]
    fn transport_failure_is_not_replayed_and_invalidates_connection() {
        let server = TestServer::new(vec![
            ExpectedRequest {
                method: "GET",
                path: "/failed",
                authorization: None,
                client_capabilities: None,
                response: String::new(),
            },
            ExpectedRequest {
                method: "GET",
                path: "/next",
                authorization: None,
                client_capabilities: None,
                response: ok_json_response("ok"),
            },
        ]);
        let config = test_config(server.listen_path());
        let client = Client::with_capabilities(&config, None);

        assert!(client.request("GET", "/failed", &[], None, None).is_err());
        assert_eq!(
            b"ok",
            client
                .request("GET", "/next", &[], None, None)
                .unwrap()
                .body
                .as_slice()
        );
        assert_eq!(2, server.join());
    }

    #[test]
    fn cloned_client_starts_with_a_disconnected_transport() {
        let server = TestServer::new(vec![ExpectedRequest {
            method: "GET",
            path: "/original",
            authorization: None,
            client_capabilities: None,
            response: ok_json_response("original"),
        }]);
        let config = test_config(server.listen_path());
        let client = Client::with_capabilities(&config, None);
        client.request("GET", "/original", &[], None, None).unwrap();
        let cloned = client.clone();

        assert!(client.connection.borrow().is_some());
        assert!(cloned.connection.borrow().is_none());
        assert_eq!(1, server.join());
    }

    fn request_with_test_prompt(config: &Config, auth_mode: AuthMode) -> Response {
        Client::with_capabilities(config, None)
            .request_with_unlock_prompt(
                "GET",
                "/api/v1/dirs",
                Zeroizing::new(Vec::new()),
                None,
                auth_mode,
                || Ok(Zeroizing::new("correct".to_owned())),
            )
            .unwrap()
    }

    fn test_config(listen_path: &Path) -> Config {
        Config::new(
            "db".into(),
            "files".into(),
            "jobs".into(),
            listen_path.to_owned(),
            "lock".into(),
        )
    }

    fn bearer(password: &str) -> String {
        format!("Bearer {}", general_purpose::STANDARD.encode(password))
    }

    struct ExpectedRequest {
        method: &'static str,
        path: &'static str,
        authorization: Option<String>,
        client_capabilities: Option<String>,
        response: String,
    }

    struct TestServer {
        _tempdir: tempfile::TempDir,
        listen_path: PathBuf,
        handle: thread::JoinHandle<usize>,
    }

    impl TestServer {
        fn new(expected: Vec<ExpectedRequest>) -> Self {
            let tempdir = tempfile::TempDir::new().unwrap();
            let listen_path = tempdir.path().join("agent.sock");
            let listener = UnixListener::bind(&listen_path).unwrap();
            let handle = thread::spawn(move || {
                let mut stream = None;
                let mut connections = 0;
                for expected in expected {
                    if stream.is_none() {
                        let (accepted, _) = listener.accept().unwrap();
                        stream = Some(accepted);
                        connections += 1;
                    }
                    let active = stream.as_mut().unwrap();
                    let request = read_request(active);
                    assert_eq!(expected.method, request.method);
                    assert_eq!(expected.path, request.path);
                    assert_eq!(expected.authorization, request.authorization);
                    assert_eq!(expected.client_capabilities, request.client_capabilities);
                    assert_eq!(Some("keep-alive"), request.connection.as_deref());
                    active.write_all(expected.response.as_bytes()).unwrap();
                    if response_closes_connection(&expected.response) {
                        stream = None;
                    }
                }
                connections
            });

            Self {
                _tempdir: tempdir,
                listen_path,
                handle,
            }
        }

        fn listen_path(&self) -> &Path {
            &self.listen_path
        }

        fn join(self) -> usize {
            self.handle.join().unwrap()
        }
    }

    struct RecordedRequest {
        method: String,
        path: String,
        authorization: Option<String>,
        client_capabilities: Option<String>,
        connection: Option<String>,
    }

    fn read_request(stream: &mut std::os::unix::net::UnixStream) -> RecordedRequest {
        let mut raw = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).unwrap();
            assert_ne!(0, read, "client closed before request headers");
            raw.extend_from_slice(&buffer[..read]);
            if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }

        let header_end = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap();
        let text = std::str::from_utf8(&raw[..header_end]).unwrap();
        let mut lines = text.split("\r\n");
        let mut request_line = lines.next().unwrap().split_whitespace();
        let method = request_line.next().unwrap().to_owned();
        let path = request_line.next().unwrap().to_owned();
        let mut authorization = None;
        let mut client_capabilities = None;
        let mut connection = None;
        let mut content_length = 0;
        for line in lines {
            if let Some(value) = line.strip_prefix("Authorization: ") {
                authorization = Some(value.to_owned());
            }
            if let Some(value) = line.strip_prefix("X-Client-Capabilities: ") {
                client_capabilities = Some(value.to_owned());
            }
            if let Some(value) = line.strip_prefix("Connection: ") {
                connection = Some(value.to_owned());
            }
            if let Some(value) = line.strip_prefix("Content-Length: ") {
                content_length = value.parse::<usize>().unwrap();
            }
        }
        let body_read = raw.len() - header_end - 4;
        if body_read < content_length {
            let mut remaining = vec![0_u8; content_length - body_read];
            stream.read_exact(&mut remaining).unwrap();
        }

        RecordedRequest {
            method,
            path,
            authorization,
            client_capabilities,
            connection,
        }
    }

    fn response_closes_connection(response: &str) -> bool {
        let headers = response
            .split_once("\r\n\r\n")
            .map_or(response, |(headers, _)| headers);
        headers
            .lines()
            .any(|line| line.eq_ignore_ascii_case("Connection: close"))
            || (!headers
                .lines()
                .any(|line| line.to_ascii_lowercase().starts_with("content-length:"))
                && !headers
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("transfer-encoding:")))
    }

    fn access_denied_response() -> String {
        http_response(
            403,
            r#"{"error":{"code":"access_denied","message":"access denied"}}"#,
        )
    }

    fn ok_json_response(body: &str) -> String {
        http_response(200, body)
    }

    fn ok_empty_response() -> String {
        http_response(200, "")
    }

    fn http_response(status: u16, body: &str) -> String {
        http_response_with_headers(status, body, "")
    }

    fn http_response_with_headers(status: u16, body: &str, headers: &str) -> String {
        format!(
            "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n{headers}\r\n{body}",
            body.len()
        )
    }
}
