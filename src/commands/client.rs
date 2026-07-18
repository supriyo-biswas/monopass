use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

use base64::Engine;
use base64::engine::general_purpose;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
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

#[derive(Debug, Clone)]
pub struct Client<'a> {
    config: &'a Config,
    capabilities: Option<String>,
}

impl<'a> Client<'a> {
    pub fn new(config: &'a Config) -> Self {
        Self {
            config,
            capabilities: detect_client_capabilities(),
        }
    }

    #[cfg(test)]
    fn with_capabilities(config: &'a Config, capabilities: Option<String>) -> Self {
        Self {
            config,
            capabilities,
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
        let mut password: Option<Zeroizing<String>> = None;
        let mut response = self.request(method, path, &body, content_type, None)?;
        if is_access_denied(&response) {
            let unlock_method = self.first_unlock_method(AccessScope::for_api_path(path))?;
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

        stream.write_all(request.as_bytes())?;
        stream.write_all(body)?;

        let mut raw = Zeroizing::new(Vec::new());
        stream.read_to_end(&mut raw)?;
        parse_response(raw)
    }
}

fn detect_client_capabilities() -> Option<String> {
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

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::path::PathBuf;
    use std::thread;

    use base64::Engine;
    use base64::engine::general_purpose;
    use zeroize::Zeroizing;

    use super::{AuthMode, AuthUnlockMethodsResponse, Client, Response, unlock_method_api_path};
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
        handle: thread::JoinHandle<()>,
    }

    impl TestServer {
        fn new(expected: Vec<ExpectedRequest>) -> Self {
            let tempdir = tempfile::TempDir::new().unwrap();
            let listen_path = tempdir.path().join("agent.sock");
            let listener = UnixListener::bind(&listen_path).unwrap();
            let handle = thread::spawn(move || {
                for expected in expected {
                    let (mut stream, _) = listener.accept().unwrap();
                    let request = read_request(&mut stream);
                    assert_eq!(expected.method, request.method);
                    assert_eq!(expected.path, request.path);
                    assert_eq!(expected.authorization, request.authorization);
                    assert_eq!(expected.client_capabilities, request.client_capabilities);
                    stream.write_all(expected.response.as_bytes()).unwrap();
                }
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

        fn join(self) {
            self.handle.join().unwrap();
        }
    }

    struct RecordedRequest {
        method: String,
        path: String,
        authorization: Option<String>,
        client_capabilities: Option<String>,
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

        let text = std::str::from_utf8(&raw).unwrap();
        let mut lines = text.split("\r\n");
        let mut request_line = lines.next().unwrap().split_whitespace();
        let method = request_line.next().unwrap().to_owned();
        let path = request_line.next().unwrap().to_owned();
        let mut authorization = None;
        let mut client_capabilities = None;
        for line in lines {
            if let Some(value) = line.strip_prefix("Authorization: ") {
                authorization = Some(value.to_owned());
            }
            if let Some(value) = line.strip_prefix("X-Client-Capabilities: ") {
                client_capabilities = Some(value.to_owned());
            }
        }

        RecordedRequest {
            method,
            path,
            authorization,
            client_capabilities,
        }
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
        format!(
            "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{body}",
            body.len()
        )
    }
}
