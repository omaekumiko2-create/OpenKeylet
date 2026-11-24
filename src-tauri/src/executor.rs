use crate::{
    model::{SecretBundle, StoredConnection},
    policy::{
        blocked_header_names, normalize_api_request_method, redact, redact_values,
        redirect_target_supported, strip_cross_origin_redirect_auth, validate_ssh_command,
        visible_response_headers,
    },
    storage::resolve_user_path,
    vault::{DecryptedConnection, Vault},
};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{
    Client, Method,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use russh::{
    ChannelMsg, Disconnect, client,
    keys::{PrivateKeyWithHashAlg, decode_secret_key, ssh_key},
};
use russh_sftp::{client::SftpSession, protocol::OpenFlags};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt::Display,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use url::Url;
use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

// SSH `exec` carries the complete command in one protocol packet. Keep direct
// requests comfortably below the usual 32 KiB packet limit and stream larger
// commands to the account's configured remote shell instead.
const MAX_DIRECT_SSH_COMMAND_LENGTH: usize = 16_384;
const MAX_HTTP_REDIRECTS: usize = 10;
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 512 * 1024;

#[derive(Debug)]
struct BoundedOutputCapture {
    limit: Option<usize>,
    head: Vec<u8>,
    tail: VecDeque<u8>,
    omitted_bytes: usize,
}

impl BoundedOutputCapture {
    fn new(limit: Option<usize>) -> Self {
        Self {
            limit: limit.filter(|&bytes| bytes > 0),
            head: Vec::new(),
            tail: VecDeque::new(),
            omitted_bytes: 0,
        }
    }

    fn push(&mut self, chunk: &[u8]) {
        if chunk.is_empty() {
            return;
        }
        let Some(limit) = self.limit else {
            self.head.extend_from_slice(chunk);
            return;
        };
        let head_cap = (limit / 2).max(1);
        let tail_cap = limit.saturating_sub(head_cap);
        let mut remaining = chunk;
        if self.head.len() < head_cap {
            let take = (head_cap - self.head.len()).min(remaining.len());
            self.head.extend_from_slice(&remaining[..take]);
            remaining = &remaining[take..];
        }
        if remaining.is_empty() {
            return;
        }
        if tail_cap == 0 {
            self.omitted_bytes = self.omitted_bytes.saturating_add(remaining.len());
            return;
        }
        if remaining.len() >= tail_cap {
            let dropped = self.tail.len() + (remaining.len() - tail_cap);
            self.omitted_bytes = self.omitted_bytes.saturating_add(dropped);
            self.tail.clear();
            self.tail
                .extend(&remaining[remaining.len() - tail_cap..]);
            return;
        }
        let overflow = (self.tail.len() + remaining.len()).saturating_sub(tail_cap);
        if overflow > 0 {
            self.tail.drain(..overflow);
            self.omitted_bytes = self.omitted_bytes.saturating_add(overflow);
        }
        self.tail.extend(remaining);
    }

    fn finish(self, redact_fn: impl Fn(String) -> String) -> (String, bool) {
        if self.omitted_bytes == 0 {
            let mut combined = self.head;
            combined.extend(self.tail);
            return (
                redact_fn(String::from_utf8_lossy(&combined).into_owned()),
                false,
            );
        }
        let head_str = redact_fn(String::from_utf8_lossy(&self.head).into_owned());
        let tail_bytes: Vec<u8> = self.tail.into_iter().collect();
        let tail_str = redact_fn(String::from_utf8_lossy(&tail_bytes).into_owned());
        let notice = format!(
            "\n…[Output truncated: omitted {} bytes; pass maxOutputBytes=0 for unlimited]\n",
            self.omitted_bytes
        );
        (format!("{head_str}{notice}{tail_str}"), true)
    }
}

async fn read_stream_bounded<R: AsyncRead + Unpin>(
    mut reader: R,
    limit: Option<usize>,
) -> std::io::Result<BoundedOutputCapture> {
    let mut capture = BoundedOutputCapture::new(limit);
    let mut buf = [0_u8; 8_192];
    loop {
        let count = reader.read(&mut buf).await?;
        if count == 0 {
            break;
        }
        capture.push(&buf[..count]);
    }
    Ok(capture)
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiRequestInput {
    #[schemars(
        description = "Absolute request URL, saved-service-relative path, or empty to use the saved service URL."
    )]
    pub url: String,
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default)]
    pub query: HashMap<String, Value>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: Option<Value>,
    #[serde(default)]
    pub form: HashMap<String, Value>,
    #[serde(default)]
    pub files: Vec<ApiUploadFile>,
    #[serde(default)]
    pub body_base64: Option<String>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub max_response_bytes: Option<usize>,
    #[serde(default)]
    pub save_response_to: Option<String>,
    #[serde(default)]
    pub overwrite_response_file: bool,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub follow_redirects: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApiUploadFile {
    pub field: String,
    #[schemars(
        description = "Local file path. Absolute and ~/ paths are accepted; relative paths resolve from the OpenKeylet MCP process working directory."
    )]
    pub path: String,
    #[serde(default)]
    pub file_name: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
}

fn default_method() -> String {
    "GET".to_owned()
}

pub fn describe_api_request(connection: &StoredConnection, input: &ApiRequestInput) -> String {
    let method = input.method.trim().to_ascii_uppercase();
    let method = if method.is_empty()
        || method.len() > 20
        || !method
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'-')
    {
        "REQUEST".to_owned()
    } else {
        method
    };
    let Ok(target) = build_api_url(connection, &input.url, &input.query) else {
        return format!("API {method}");
    };
    let origin = target.origin().ascii_serialization();
    let mut path = target.path().to_owned();
    if path.len() > 160 {
        let boundary = path
            .char_indices()
            .map(|(index, _)| index)
            .take_while(|index| *index <= 157)
            .last()
            .unwrap_or(0);
        path.truncate(boundary);
        path.push_str("...");
    }
    format!("API {method} {origin}{path}")
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiResponse {
    pub status: u16,
    pub status_text: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saved_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_transferred: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub captured_secrets: Vec<String>,
}

pub(crate) struct RawApiResponse {
    pub status: u16,
    pub status_text: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub raw_body: String,
    pub truncated: bool,
    pub saved_to: Option<String>,
    pub bytes_transferred: Option<u64>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SshResponse {
    pub exit_code: Option<u32>,
    pub signal: Option<String>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SshTransferResponse {
    pub direction: String,
    pub kind: String,
    pub local_path: String,
    pub remote_path: String,
    pub bytes_transferred: u64,
    pub files_transferred: u64,
    pub directories_transferred: u64,
}

#[derive(Debug, Default)]
struct TransferStats {
    bytes: u64,
    files: u64,
    directories: u64,
}

enum PreparedApiBody {
    Empty,
    Bytes {
        bytes: Vec<u8>,
        default_content_type: Option<&'static str>,
    },
    Multipart {
        form: HashMap<String, Value>,
        files: Vec<ApiUploadFile>,
    },
}

async fn build_multipart_form(
    form: &HashMap<String, Value>,
    files: &[ApiUploadFile],
) -> Result<reqwest::multipart::Form> {
    let mut multipart = reqwest::multipart::Form::new();
    for (name, value) in form {
        for value in form_values(value.clone()) {
            multipart = multipart.text(name.clone(), value);
        }
    }
    for file in files {
        let field = file.field.trim();
        if field.is_empty() {
            bail!("Uploaded file field name cannot be empty");
        }
        let path = resolve_user_path(&file.path)?;
        if !tokio::fs::metadata(&path)
            .await
            .context("Unable to read uploaded file")?
            .is_file()
        {
            bail!("Upload path is not a regular file");
        }
        let mut part = reqwest::multipart::Part::file(&path)
            .await
            .context("Unable to open uploaded file")?;
        if let Some(file_name) = file
            .file_name
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            part = part.file_name(file_name.to_owned());
        }
        if let Some(content_type) = file
            .content_type
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            part = part
                .mime_str(content_type.trim())
                .context("Invalid uploaded file Content-Type")?;
        }
        multipart = multipart.part(field.to_owned(), part);
    }
    Ok(multipart)
}

pub async fn execute_api(
    connection: &DecryptedConnection,
    input: ApiRequestInput,
) -> Result<ApiResponse> {
    let raw = execute_api_raw(connection, input).await?;
    let body = if raw.saved_to.is_some() {
        String::new()
    } else {
        sanitize_api_body(
            raw.raw_body,
            raw.truncated,
            &connection.stored,
            &connection.secrets,
        )
    };
    Ok(ApiResponse {
        status: raw.status,
        status_text: raw.status_text,
        url: raw.url,
        headers: raw.headers,
        body,
        truncated: raw.truncated,
        saved_to: raw.saved_to,
        bytes_transferred: raw.bytes_transferred,
        captured_secrets: Vec::new(),
    })
}

pub(crate) async fn execute_api_raw(
    connection: &DecryptedConnection,
    input: ApiRequestInput,
) -> Result<RawApiResponse> {
    if !connection.stored.enabled {
        bail!("This connection is disabled");
    }
    let mut target = build_api_url(&connection.stored, &input.url, &input.query)?;
    let save_response_to = match input.save_response_to {
        Some(path) => {
            Some(prepare_api_response_destination(&path, input.overwrite_response_file).await?)
        }
        None => None,
    };
    let overwrite_response_file = input.overwrite_response_file;
    let method = normalize_api_request_method(&input.method, &target)?;
    let method = Method::from_bytes(method.as_bytes()).context("Invalid HTTP method")?;
    let blocked = blocked_header_names(&connection.stored);
    let mut headers = HeaderMap::new();
    for (name, value) in input.headers {
        if blocked.contains(&name.to_lowercase()) {
            continue;
        }
        headers.insert(
            HeaderName::from_bytes(name.as_bytes()).context("Invalid request header name")?,
            HeaderValue::from_str(&value).context("Invalid request header content")?,
        );
    }
    apply_api_auth(
        &connection.stored,
        &connection.secrets,
        &mut headers,
        &mut target,
    )?;

    let body_kinds = usize::from(input.body.is_some())
        + usize::from(!input.form.is_empty() || !input.files.is_empty())
        + usize::from(input.body_base64.is_some());
    if body_kinds > 1 {
        bail!("Only one request body format may be selected: body, form/files, or bodyBase64");
    }
    let prepared_body = if !input.files.is_empty() {
        PreparedApiBody::Multipart {
            form: input.form,
            files: input.files,
        }
    } else if !input.form.is_empty() {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (name, value) in input.form {
            for value in form_values(value) {
                serializer.append_pair(&name, &value);
            }
        }
        PreparedApiBody::Bytes {
            bytes: serializer.finish().into_bytes(),
            default_content_type: Some("application/x-www-form-urlencoded"),
        }
    } else if let Some(body_base64) = input.body_base64 {
        let bytes = STANDARD
            .decode(body_base64.trim())
            .context("bodyBase64 is not valid Base64")?;
        PreparedApiBody::Bytes {
            bytes,
            default_content_type: None,
        }
    } else if let Some(body) = input.body {
        if let Some(text) = body.as_str() {
            PreparedApiBody::Bytes {
                bytes: text.as_bytes().to_vec(),
                default_content_type: None,
            }
        } else {
            PreparedApiBody::Bytes {
                bytes: serde_json::to_vec(&body).context("Unable to encode JSON request body")?,
                default_content_type: Some("application/json"),
            }
        }
    } else {
        PreparedApiBody::Empty
    };

    let response_limit = input.max_response_bytes.filter(|limit| *limit > 0);
    let follow_redirects = input.follow_redirects.unwrap_or(true);
    let mut client_builder = Client::builder().redirect(reqwest::redirect::Policy::none());
    if input.insecure {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }
    if let Some(seconds) = input.timeout_seconds.filter(|seconds| *seconds > 0) {
        client_builder = client_builder.timeout(Duration::from_secs(seconds));
    }
    let client = client_builder.build()?;

    let initial_origin = target.origin();
    let mut current_url = target;
    let mut current_method = method;
    let mut current_headers = headers;
    let mut current_body = prepared_body;

    let send_loop = async {
        let mut hops = 0usize;
        loop {
            let mut req_headers = current_headers.clone();
            let mut request = client.request(current_method.clone(), current_url.clone());
            match &current_body {
                PreparedApiBody::Empty => {}
                PreparedApiBody::Bytes {
                    bytes,
                    default_content_type,
                } => {
                    if let Some(ct) = default_content_type
                        && !req_headers.contains_key(reqwest::header::CONTENT_TYPE)
                    {
                        req_headers.insert(
                            reqwest::header::CONTENT_TYPE,
                            HeaderValue::from_static(ct),
                        );
                    }
                    request = request.body(bytes.clone());
                }
                PreparedApiBody::Multipart { form, files } => {
                    req_headers.remove(reqwest::header::CONTENT_TYPE);
                    let multipart = build_multipart_form(form, files).await?;
                    request = request.multipart(multipart);
                }
            }
            let response = request
                .headers(req_headers)
                .send()
                .await
                .map_err(|error| anyhow::anyhow!(api_request_error_message(&error)))?;

            let status = response.status();
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty());

            if !follow_redirects || !status.is_redirection() || hops >= MAX_HTTP_REDIRECTS {
                return Ok::<_, anyhow::Error>(response);
            }
            let Some(location) = location else {
                return Ok(response);
            };
            let Ok(mut next_url) = current_url.join(location) else {
                return Ok(response);
            };
            if !redirect_target_supported(&next_url) {
                return Ok(response);
            }

            if next_url.origin() != initial_origin {
                strip_cross_origin_redirect_auth(
                    &mut current_headers,
                    &mut next_url,
                    &connection.stored,
                    &connection.secrets,
                );
            }

            match status.as_u16() {
                303 => {
                    if current_method != Method::HEAD {
                        current_method = Method::GET;
                    }
                    current_body = PreparedApiBody::Empty;
                    current_headers.remove(reqwest::header::CONTENT_TYPE);
                    current_headers.remove(reqwest::header::CONTENT_LENGTH);
                }
                301 | 302 => {
                    if current_method == Method::POST {
                        current_method = Method::GET;
                        current_body = PreparedApiBody::Empty;
                        current_headers.remove(reqwest::header::CONTENT_TYPE);
                        current_headers.remove(reqwest::header::CONTENT_LENGTH);
                    }
                }
                _ => {
                    // 307 / 308 preserve method and body.
                }
            }

            current_url = next_url;
            hops += 1;
        }
    };

    let mut response = match input.timeout_seconds.filter(|seconds| *seconds > 0) {
        Some(seconds) => tokio::time::timeout(Duration::from_secs(seconds), send_loop)
            .await
            .map_err(|_| anyhow::anyhow!("API request timed out"))??,
        None => send_loop.await?,
    };

    let status = response.status();
    let response_url = response.url().clone();
    let response_headers = visible_response_headers(response.headers())
        .into_iter()
        .map(|(name, value)| (name, redact(value, &connection.stored, &connection.secrets)))
        .collect();
    if let Some(destination) = save_response_to {
        let (saved_to, bytes_transferred) =
            save_api_response_to_file(&mut response, &destination, overwrite_response_file).await?;
        return Ok(RawApiResponse {
            status: status.as_u16(),
            status_text: status.canonical_reason().unwrap_or_default().to_owned(),
            url: redact(
                response_url.to_string(),
                &connection.stored,
                &connection.secrets,
            ),
            headers: response_headers,
            raw_body: String::new(),
            truncated: false,
            saved_to: Some(saved_to),
            bytes_transferred: Some(bytes_transferred),
        });
    }
    let mut bytes = Vec::new();
    let mut truncated = false;
    while let Some(chunk) = response
        .chunk()
        .await
        .context("Unable to read API response")?
    {
        if let Some(limit) = response_limit {
            let remaining = limit.saturating_sub(bytes.len());
            if remaining == 0 {
                truncated = !chunk.is_empty();
                break;
            }
            bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
            if chunk.len() > remaining {
                truncated = true;
                break;
            }
        } else {
            bytes.extend_from_slice(&chunk);
        }
    }
    Ok(RawApiResponse {
        status: status.as_u16(),
        status_text: status.canonical_reason().unwrap_or_default().to_owned(),
        url: redact(
            response_url.to_string(),
            &connection.stored,
            &connection.secrets,
        ),
        headers: response_headers,
        raw_body: String::from_utf8_lossy(&bytes).into_owned(),
        truncated,
        saved_to: None,
        bytes_transferred: None,
    })
}

async fn prepare_api_response_destination(
    destination: &str,
    overwrite: bool,
) -> Result<std::path::PathBuf> {
    let destination = destination.trim();
    if destination.is_empty() || destination.contains('\0') {
        bail!("Invalid API response save path");
    }
    let destination = resolve_user_path(destination)?;
    if let Some(parent) = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(parent)
            .await
            .context("Unable to create API response destination directory")?;
    }
    if tokio::fs::try_exists(&destination).await? {
        if !tokio::fs::symlink_metadata(&destination)
            .await?
            .file_type()
            .is_file()
        {
            bail!(
                "API response destination already exists but is not a regular file; refusing to overwrite"
            );
        }
        if !overwrite {
            bail!(
                "API response destination file already exists; to replace it, explicitly set overwriteResponseFile=true"
            );
        }
    }
    Ok(destination)
}

async fn save_api_response_to_file(
    response: &mut reqwest::Response,
    destination: &std::path::Path,
    overwrite: bool,
) -> Result<(String, u64)> {
    if !overwrite && tokio::fs::try_exists(&destination).await? {
        bail!(
            "API response destination file already exists; to replace it, explicitly set overwriteResponseFile=true"
        );
    }
    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("response");
    let temporary_path = destination.with_file_name(format!(
        ".{file_name}.openkeylet-{}.part",
        Uuid::new_v4().simple()
    ));
    let write_result: Result<u64> = async {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
            .await
            .context("Unable to create API response temporary file")?;
        let mut bytes_transferred = 0_u64;
        while let Some(chunk) = response
            .chunk()
            .await
            .context("Unable to read API response")?
        {
            file.write_all(&chunk)
                .await
                .context("Unable to write API response file")?;
            bytes_transferred = bytes_transferred
                .checked_add(chunk.len() as u64)
                .context("API response file is too large")?;
        }
        file.flush()
            .await
            .context("Unable to flush API response file")?;
        file.sync_all()
            .await
            .context("Unable to sync API response file")?;
        commit_local_file(&temporary_path, destination, overwrite).await?;
        Ok(bytes_transferred)
    }
    .await;
    let bytes_transferred = match write_result {
        Ok(bytes) => bytes,
        Err(error) => {
            let _ = tokio::fs::remove_file(&temporary_path).await;
            return Err(error);
        }
    };
    let saved_to = tokio::fs::canonicalize(destination)
        .await
        .unwrap_or_else(|_| destination.to_path_buf())
        .to_string_lossy()
        .into_owned();
    Ok((saved_to, bytes_transferred))
}

#[cfg(windows)]
fn windows_local_shell() -> (&'static str, bool) {
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            if dir.join("pwsh.exe").is_file() {
                return ("pwsh.exe", false);
            }
        }
    }
    ("powershell.exe", true)
}

pub async fn execute_ssh(
    vault: &Vault,
    connection: &DecryptedConnection,
    command: &str,
    cwd: Option<&str>,
    timeout_seconds: Option<u64>,
    secret_env: &HashMap<String, String>,
    stdin: Option<&str>,
    max_output_bytes: Option<usize>,
) -> Result<SshResponse> {
    if !connection.stored.enabled {
        bail!("This connection is disabled");
    }
    let command = validate_ssh_command(command)?;
    let command = ssh_command_with_secret_environment(&command, secret_env)?;
    let command = match cwd.map(str::trim).filter(|value| !value.is_empty()) {
        Some(cwd) => format!("cd -- {} && {command}", shell_quote(cwd)),
        None => command,
    };
    let command = validate_ssh_command(&command)?;
    let execution = execute_ssh_inner(vault, connection, &command, stdin, max_output_bytes);
    match timeout_seconds.filter(|seconds| *seconds > 0) {
        Some(seconds) => tokio::time::timeout(Duration::from_secs(seconds), execution)
            .await
            .map_err(|_| anyhow::anyhow!("SSH command execution exceeded the timeout set by the caller of {seconds} seconds"))?,
        None => execution.await,
    }
}

pub async fn execute_local(
    connection: Option<&DecryptedConnection>,
    command: &str,
    cwd: Option<&str>,
    timeout_seconds: Option<u64>,
    secret_env: &HashMap<String, String>,
    stdin: Option<&str>,
    max_output_bytes: Option<usize>,
    extra_redactions: &[String],
) -> Result<SshResponse> {
    let command = command.trim();
    if command.is_empty() || command.contains('\0') {
        bail!("Local command cannot be empty or contain a null character");
    }
    if connection.is_some_and(|connection| !connection.stored.enabled) {
        bail!("This connection is disabled");
    }

    #[cfg(windows)]
    let mut process = {
        let (shell, clear_ps_module_path) = windows_local_shell();
        let mut process = tokio::process::Command::new(shell);
        if clear_ps_module_path {
            process.env_remove("PSModulePath");
        }
        process.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command]);
        process
    };
    #[cfg(not(windows))]
    let mut process = {
        let shell = std::env::var("SHELL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "/bin/sh".to_owned());
        let mut process = tokio::process::Command::new(shell);
        process.args(["-lc", command]);
        process
    };

    if let Some(cwd) = cwd.map(str::trim).filter(|value| !value.is_empty()) {
        let cwd = resolve_user_path(cwd)?;
        if !cwd.is_dir() {
            bail!("Local command working directory does not exist or is not a directory");
        }
        process.current_dir(cwd);
    }
    for (name, value) in secret_env {
        if !valid_environment_name(name) {
            bail!("Invalid terminal_run secretEnv environment variable name:{name}");
        }
        if value.contains('\0') {
            bail!("This secret module cannot be used as a local environment variable");
        }
        process.env(name, value);
    }
    process
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let stdin = stdin.map(str::as_bytes).map(<[u8]>::to_vec);
    let execution = async {
        let mut child = process.spawn().context("Unable to start local command")?;
        let child_stdout = child
            .stdout
            .take()
            .context("Unable to open local command stdout")?;
        let child_stderr = child
            .stderr
            .take()
            .context("Unable to open local command stderr")?;
        let input_task = if let Some(input) = stdin {
            let mut child_stdin = child
                .stdin
                .take()
                .context("Unable to open local command standard input")?;
            Some(tokio::spawn(async move {
                child_stdin.write_all(&input).await?;
                child_stdin.shutdown().await
            }))
        } else {
            None
        };
        let stdout_task = tokio::spawn(read_stream_bounded(child_stdout, max_output_bytes));
        let stderr_task = tokio::spawn(read_stream_bounded(child_stderr, max_output_bytes));
        let status = child
            .wait()
            .await
            .context("Unable to wait for local command")?;
        if let Some(task) = input_task {
            task.await
                .context("Local command standard input task ended unexpectedly")??;
        }
        let stdout_capture = stdout_task
            .await
            .context("Local command stdout task ended unexpectedly")?
            .context("Unable to read local command stdout")?;
        let stderr_capture = stderr_task
            .await
            .context("Local command stderr task ended unexpectedly")?
            .context("Unable to read local command stderr")?;
        Ok::<_, anyhow::Error>((status, stdout_capture, stderr_capture))
    };
    let (status, stdout_capture, stderr_capture) = match timeout_seconds.filter(|seconds| *seconds > 0)
    {
        Some(seconds) => tokio::time::timeout(Duration::from_secs(seconds), execution)
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "Local command exceeded the timeout set by the caller of {seconds} seconds"
                )
            })??,
        None => execution.await?,
    };
    let redact_text = |mut text: String| {
        if let Some(connection) = connection {
            text = redact(text, &connection.stored, &connection.secrets);
        }
        if !extra_redactions.is_empty() {
            text = redact_values(text, extra_redactions);
        }
        text
    };
    let (stdout, stdout_truncated) = stdout_capture.finish(&redact_text);
    let (stderr, stderr_truncated) = stderr_capture.finish(&redact_text);
    #[cfg(unix)]
    let signal = status.signal().map(|signal| signal.to_string());
    #[cfg(not(unix))]
    let signal = None;
    Ok(SshResponse {
        exit_code: status.code().map(|code| code as u32),
        signal,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
    })
}

fn ssh_command_with_secret_environment(
    command: &str,
    secret_env: &HashMap<String, String>,
) -> Result<String> {
    if secret_env.is_empty() {
        return Ok(command.to_owned());
    }
    let mut variables = secret_env.iter().collect::<Vec<_>>();
    variables.sort_by(|left, right| left.0.cmp(right.0));
    let mut assignments = Vec::with_capacity(variables.len());
    for (name, value) in variables {
        if !valid_environment_name(name) {
            bail!("Invalid SSH secretEnv environment variable name:{name}");
        }
        if value.contains('\0') {
            bail!("This secret module cannot be used as an SSH environment variable");
        }
        assignments.push(format!("{name}={}", shell_quote(value)));
    }
    Ok(format!(
        "{} sh -c {}",
        assignments.join(" "),
        shell_quote(command)
    ))
}

fn valid_environment_name(name: &str) -> bool {
    let mut characters = name.chars();
    matches!(characters.next(), Some('_' | 'a'..='z' | 'A'..='Z'))
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

async fn execute_ssh_inner(
    vault: &Vault,
    connection: &DecryptedConnection,
    command: &str,
    stdin: Option<&str>,
    max_output_bytes: Option<usize>,
) -> Result<SshResponse> {
    let session = connect_ssh(vault, connection).await?;
    let channel = session.channel_open_session().await?;
    let send_task;
    let mut reader;
    if command.len() <= MAX_DIRECT_SSH_COMMAND_LENGTH || stdin.is_some() {
        channel.exec(true, command).await?;
        let (read_half, write_half) = channel.split();
        reader = read_half;
        send_task = stdin.map(|stdin| {
            let input = stdin.as_bytes().to_vec();
            tokio::spawn(async move {
                write_half.data_bytes(input).await?;
                write_half.eof().await
            })
        });
    } else {
        // A shell channel invokes the account's configured shell, so the same
        // path works for POSIX shells and Windows OpenSSH targets.
        channel.request_shell(true).await?;
        let mut script = Vec::with_capacity(command.len() + 1);
        script.extend_from_slice(command.as_bytes());
        script.push(b'\n');
        let (read_half, write_half) = channel.split();
        reader = read_half;
        send_task = Some(tokio::spawn(async move {
            write_half.data_bytes(script).await?;
            write_half.eof().await
        }));
    }
    let mut stdout_capture = BoundedOutputCapture::new(max_output_bytes);
    let mut stderr_capture = BoundedOutputCapture::new(max_output_bytes);
    let mut exit_code = None;
    let mut signal = None;
    while let Some(message) = reader.wait().await {
        match message {
            ChannelMsg::Data { data } => stdout_capture.push(&data),
            ChannelMsg::ExtendedData { data, .. } => stderr_capture.push(&data),
            ChannelMsg::ExitStatus { exit_status } => exit_code = Some(exit_status),
            ChannelMsg::ExitSignal { signal_name, .. } => signal = Some(format!("{signal_name:?}")),
            _ => {}
        }
    }
    if let Some(task) = send_task {
        task.await
            .context("SSH long command sending task ended unexpectedly")??;
    }
    let _ = session
        .disconnect(Disconnect::ByApplication, "", "en")
        .await;
    let redact_text = |text: String| redact(text, &connection.stored, &connection.secrets);
    let (stdout, stdout_truncated) = stdout_capture.finish(&redact_text);
    let (stderr, stderr_truncated) = stderr_capture.finish(&redact_text);
    Ok(SshResponse {
        exit_code,
        signal,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
    })
}

fn ssh_auth_methods(connection: &DecryptedConnection) -> Vec<&'static str> {
    let mut methods = Vec::new();
    if connection
        .secrets
        .private_key
        .as_deref()
        .is_some_and(|v| !v.trim().is_empty())
    {
        methods.push("privateKey");
    }
    if connection
        .secrets
        .password
        .as_deref()
        .is_some_and(|v| !v.is_empty())
    {
        methods.push("password");
    }
    methods
}

async fn connect_ssh(
    _vault: &Vault,
    connection: &DecryptedConnection,
) -> Result<client::Handle<SshClient>> {
    let username = connection
        .secrets
        .get("username")
        .context("No SSH username in vault")?;
    let methods = ssh_auth_methods(connection);
    if methods.is_empty() {
        bail!("No SSH private key or password in vault");
    }

    let mut session = client::connect(
        Arc::new(client::Config::default()),
        (connection.stored.host.as_str(), connection.stored.port),
        SshClient,
    )
    .await
    .map_err(|error| anyhow::anyhow!(ssh_connect_error_message(&error)))?;

    let mut authenticated = false;
    let mut key_error: Option<anyhow::Error> = None;
    let mut needs_reconnect = false;

    if methods.contains(&"privateKey") {
        let private_key = connection
            .secrets
            .private_key
            .as_deref()
            .expect("privateKey checked non-empty");
        match decode_secret_key(private_key, connection.secrets.passphrase.as_deref()) {
            Ok(key) => match session.best_supported_rsa_hash().await {
                Ok(hash_opt) => {
                    let hash = hash_opt.flatten();
                    match session
                        .authenticate_publickey(
                            username,
                            PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                        )
                        .await
                    {
                        Ok(auth) if auth.success() => authenticated = true,
                        Ok(_) => {}
                        Err(err) => {
                            key_error = Some(err.into());
                            needs_reconnect = true;
                        }
                    }
                }
                Err(err) => {
                    key_error = Some(err.into());
                    needs_reconnect = true;
                }
            },
            Err(err) => {
                key_error = Some(
                    anyhow::Error::from(err)
                        .context("Unable to parse SSH private key or incorrect passphrase"),
                );
            }
        }
    }

    if !authenticated && methods.contains(&"password") {
        if needs_reconnect {
            session = client::connect(
                Arc::new(client::Config::default()),
                (connection.stored.host.as_str(), connection.stored.port),
                SshClient,
            )
            .await
            .map_err(|error| anyhow::anyhow!(ssh_connect_error_message(&error)))?;
        }
        let password = connection
            .secrets
            .password
            .clone()
            .expect("password checked non-empty");
        let auth = session.authenticate_password(username, password).await?;
        if auth.success() {
            authenticated = true;
        }
    }

    if !authenticated {
        if let Some(err) = key_error {
            return Err(err);
        }
        bail!("SSH authentication failed");
    }

    Ok(session)
}

async fn open_sftp(
    vault: &Vault,
    connection: &DecryptedConnection,
) -> Result<(client::Handle<SshClient>, SftpSession)> {
    let session = connect_ssh(vault, connection).await?;
    let channel = session.channel_open_session().await?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .context("The remote does not have the SFTP subsystem enabled")?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .context("Unable to initialize the SFTP session")?;
    Ok((session, sftp))
}

pub async fn ssh_upload(
    vault: &Vault,
    connection: &DecryptedConnection,
    local_path: &str,
    remote_path: &str,
    overwrite: bool,
    timeout_seconds: Option<u64>,
) -> Result<SshTransferResponse> {
    if !connection.stored.enabled {
        bail!("This connection is disabled");
    }
    let local_path = local_path.trim();
    let remote_path = validate_transfer_path(remote_path, "Remote path")?;
    if local_path.is_empty() || local_path.contains('\0') {
        bail!("Invalid local upload path");
    }
    let execution = async {
        let local_path = resolve_user_path(local_path)?;
        let canonical_local = tokio::fs::canonicalize(local_path)
            .await
            .context("Local upload path not found")?;
        let metadata = tokio::fs::metadata(&canonical_local).await?;
        if !metadata.is_file() && !metadata.is_dir() {
            bail!("Local upload path is not a file or directory");
        }
        let (session, sftp) = open_sftp(vault, connection).await?;
        let remote_path = resolve_remote_path(&sftp, &remote_path).await?;
        let (kind, stats) = if metadata.is_dir() {
            (
                "directory",
                upload_local_directory(&sftp, &canonical_local, &remote_path, overwrite).await?,
            )
        } else {
            (
                "file",
                upload_local_file(&sftp, &canonical_local, &remote_path, overwrite).await?,
            )
        };
        let _ = sftp.close().await;
        let _ = session
            .disconnect(Disconnect::ByApplication, "", "en")
            .await;
        Ok(SshTransferResponse {
            direction: "upload".to_owned(),
            kind: kind.to_owned(),
            local_path: canonical_local.to_string_lossy().into_owned(),
            remote_path,
            bytes_transferred: stats.bytes,
            files_transferred: stats.files,
            directories_transferred: stats.directories,
        })
    };
    run_optional_ssh_timeout(execution, timeout_seconds, "SSH upload").await
}

pub async fn ssh_download(
    vault: &Vault,
    connection: &DecryptedConnection,
    remote_path: &str,
    local_path: &str,
    overwrite: bool,
    timeout_seconds: Option<u64>,
) -> Result<SshTransferResponse> {
    if !connection.stored.enabled {
        bail!("This connection is disabled");
    }
    let remote_path = validate_transfer_path(remote_path, "Remote path")?;
    let local_path = local_path.trim();
    if local_path.is_empty() || local_path.contains('\0') {
        bail!("Invalid local save path");
    }
    let local_path = resolve_user_path(local_path)?;
    let execution = async {
        let (session, sftp) = open_sftp(vault, connection).await?;
        let remote_path = resolve_remote_path(&sftp, &remote_path).await?;
        let remote_metadata = sftp
            .metadata(remote_path.clone())
            .await
            .context("Remote download path not found")?;
        let (kind, stats) = if remote_metadata.file_type().is_dir() {
            (
                "directory",
                download_remote_directory(&sftp, &remote_path, &local_path, overwrite).await?,
            )
        } else if remote_metadata.file_type().is_file() {
            (
                "file",
                download_remote_file(&sftp, &remote_path, &local_path, overwrite).await?,
            )
        } else {
            bail!("Remote download path is not a file or directory");
        };
        let _ = sftp.close().await;
        let _ = session
            .disconnect(Disconnect::ByApplication, "", "en")
            .await;
        Ok(SshTransferResponse {
            direction: "download".to_owned(),
            kind: kind.to_owned(),
            local_path: tokio::fs::canonicalize(&local_path)
                .await
                .unwrap_or(local_path)
                .to_string_lossy()
                .into_owned(),
            remote_path,
            bytes_transferred: stats.bytes,
            files_transferred: stats.files,
            directories_transferred: stats.directories,
        })
    };
    run_optional_ssh_timeout(execution, timeout_seconds, "SSH download").await
}

async fn upload_local_file(
    sftp: &SftpSession,
    local_path: &Path,
    remote_path: &str,
    overwrite: bool,
) -> Result<TransferStats> {
    ensure_remote_parent_directories(sftp, remote_path).await?;
    if !overwrite && sftp.try_exists(remote_path.to_owned()).await? {
        bail!("Remote destination already exists; set overwrite to replace it=true");
    }
    let temporary_path = format!("{remote_path}.openkeylet-{}.part", Uuid::new_v4().simple());
    let result: Result<u64> = async {
        let mut local = tokio::fs::File::open(local_path)
            .await
            .context("Unable to open local upload file")?;
        let mut remote = sftp
            .open_with_flags(
                temporary_path.clone(),
                OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
            )
            .await
            .context("Unable to create remote temporary file")?;
        let bytes = tokio::io::copy(&mut local, &mut remote)
            .await
            .context("SFTP upload interrupted")?;
        remote
            .flush()
            .await
            .context("Unable to flush remote file")?;
        remote
            .shutdown()
            .await
            .context("Unable to close remote file")?;
        commit_remote_file(sftp, &temporary_path, remote_path, overwrite).await?;
        Ok(bytes)
    }
    .await;
    match result {
        Ok(bytes) => Ok(TransferStats {
            bytes,
            files: 1,
            directories: 0,
        }),
        Err(error) => {
            let _ = sftp.remove_file(temporary_path).await;
            Err(error)
        }
    }
}

async fn upload_local_directory(
    sftp: &SftpSession,
    local_root: &Path,
    remote_path: &str,
    overwrite: bool,
) -> Result<TransferStats> {
    ensure_remote_parent_directories(sftp, remote_path).await?;
    if !overwrite && sftp.try_exists(remote_path.to_owned()).await? {
        bail!("Remote destination already exists; set overwrite to replace it=true");
    }
    let temporary_path = format!("{remote_path}.openkeylet-{}.part", Uuid::new_v4().simple());
    sftp.create_dir(temporary_path.clone())
        .await
        .context("Unable to create remote temporary directory")?;

    let result: Result<TransferStats> = async {
        let mut stats = TransferStats {
            directories: 1,
            ..Default::default()
        };
        let mut visited = HashSet::from([tokio::fs::canonicalize(local_root).await?]);
        let mut stack = vec![(local_root.to_path_buf(), String::new())];
        while let Some((local_directory, relative_directory)) = stack.pop() {
            let mut entries = tokio::fs::read_dir(&local_directory)
                .await
                .with_context(|| {
                    format!(
                        "Unable to read local directory {}",
                        local_directory.display()
                    )
                })?;
            while let Some(entry) = entries.next_entry().await? {
                let name = entry.file_name();
                let relative_path = if relative_directory.is_empty() {
                    PathBuf::from(&name)
                } else {
                    PathBuf::from(&relative_directory).join(&name)
                };
                let relative_remote = relative_path.to_string_lossy().replace('\\', "/");
                let remote_entry = format!(
                    "{}/{}",
                    temporary_path.trim_end_matches('/'),
                    relative_remote
                );
                let entry_path = entry.path();
                let metadata = tokio::fs::metadata(&entry_path).await?;
                if metadata.is_dir() {
                    let canonical = tokio::fs::canonicalize(&entry_path).await?;
                    if !visited.insert(canonical) {
                        bail!(
                            "Local directory contains a cyclic link:{}",
                            entry_path.display()
                        );
                    }
                    sftp.create_dir(remote_entry).await.with_context(|| {
                        format!("Unable to create remote directory {relative_remote}")
                    })?;
                    stats.directories += 1;
                    stack.push((entry_path, relative_remote));
                } else if metadata.is_file() {
                    let mut local = tokio::fs::File::open(&entry_path).await?;
                    let mut remote = sftp
                        .open_with_flags(
                            remote_entry,
                            OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
                        )
                        .await?;
                    stats.bytes += tokio::io::copy(&mut local, &mut remote)
                        .await
                        .context("SFTP directory upload interrupted")?;
                    remote.flush().await?;
                    remote.shutdown().await?;
                    stats.files += 1;
                } else {
                    bail!(
                        "Local directory contains a special file that cannot be transferred:{}",
                        entry_path.display()
                    );
                }
            }
        }
        commit_remote_directory(sftp, &temporary_path, remote_path, overwrite).await?;
        Ok(stats)
    }
    .await;
    if result.is_err() {
        let _ = remove_remote_tree(sftp, &temporary_path).await;
    }
    result
}

async fn download_remote_file(
    sftp: &SftpSession,
    remote_path: &str,
    local_path: &Path,
    overwrite: bool,
) -> Result<TransferStats> {
    if let Some(parent) = local_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(parent)
            .await
            .context("Unable to create local destination directory")?;
    }
    if !overwrite && tokio::fs::try_exists(local_path).await? {
        bail!("Local destination already exists; set overwrite to replace it=true");
    }
    let file_name = local_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("download");
    let temporary_path = local_path.with_file_name(format!(
        ".{file_name}.openkeylet-{}.part",
        Uuid::new_v4().simple()
    ));
    let result: Result<u64> = async {
        let mut remote = sftp
            .open(remote_path.to_owned())
            .await
            .context("Unable to open remote download file")?;
        let mut local = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
            .await
            .context("Unable to create local temporary file")?;
        let bytes = tokio::io::copy(&mut remote, &mut local)
            .await
            .context("SFTP download interrupted")?;
        local.flush().await.context("Unable to flush local file")?;
        local
            .sync_all()
            .await
            .context("Unable to sync local file")?;
        remote
            .shutdown()
            .await
            .context("Unable to close remote file")?;
        commit_local_file(&temporary_path, local_path, overwrite).await?;
        Ok(bytes)
    }
    .await;
    match result {
        Ok(bytes) => Ok(TransferStats {
            bytes,
            files: 1,
            directories: 0,
        }),
        Err(error) => {
            let _ = tokio::fs::remove_file(&temporary_path).await;
            Err(error)
        }
    }
}

async fn download_remote_directory(
    sftp: &SftpSession,
    remote_root: &str,
    local_path: &Path,
    overwrite: bool,
) -> Result<TransferStats> {
    if let Some(parent) = local_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(parent)
            .await
            .context("Unable to create local destination directory")?;
    }
    if !overwrite && tokio::fs::try_exists(local_path).await? {
        bail!("Local destination already exists; set overwrite to replace it=true");
    }
    let directory_name = local_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("download");
    let temporary_path = local_path.with_file_name(format!(
        ".{directory_name}.openkeylet-{}.part",
        Uuid::new_v4().simple()
    ));
    tokio::fs::create_dir(&temporary_path)
        .await
        .context("Unable to create local temporary directory")?;

    let result: Result<TransferStats> = async {
        let canonical_root = sftp
            .canonicalize(remote_root.to_owned())
            .await
            .unwrap_or_else(|_| remote_root.to_owned());
        let mut visited = HashSet::from([canonical_root]);
        let mut stats = TransferStats {
            directories: 1,
            ..Default::default()
        };
        let mut stack = vec![(remote_root.to_owned(), PathBuf::new())];
        while let Some((remote_directory, relative_directory)) = stack.pop() {
            let entries = sftp
                .read_dir(remote_directory.clone())
                .await
                .with_context(|| format!("Unable to read remote directory {remote_directory}"))?;
            for entry in entries {
                let name = entry.file_name();
                let relative_path = relative_directory.join(&name);
                let local_entry = temporary_path.join(&relative_path);
                let remote_entry = entry.path();
                let metadata = if entry.file_type().is_symlink() {
                    sftp.metadata(remote_entry.clone()).await?
                } else {
                    entry.metadata()
                };
                if metadata.file_type().is_dir() {
                    let canonical = sftp
                        .canonicalize(remote_entry.clone())
                        .await
                        .unwrap_or_else(|_| remote_entry.clone());
                    if !visited.insert(canonical) {
                        bail!("Remote directory contains a cyclic link:{remote_entry}");
                    }
                    tokio::fs::create_dir(&local_entry)
                        .await
                        .with_context(|| format!("Unable to create local directory {}", local_entry.display()))?;
                    stats.directories += 1;
                    stack.push((remote_entry, relative_path));
                } else if metadata.file_type().is_file() {
                    let mut remote = sftp.open(remote_entry.clone()).await?;
                    let mut local = tokio::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&local_entry)
                        .await?;
                    stats.bytes += tokio::io::copy(&mut remote, &mut local)
                        .await
                        .context("SFTP directory download interrupted")?;
                    local.flush().await?;
                    local.sync_all().await?;
                    remote.shutdown().await?;
                    stats.files += 1;
                } else {
                    bail!("Remote directory contains a special file that cannot be transferred:{remote_entry}");
                }
            }
        }
        commit_local_directory(&temporary_path, local_path, overwrite).await?;
        Ok(stats)
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_dir_all(&temporary_path).await;
    }
    result
}

async fn resolve_remote_path(sftp: &SftpSession, path: &str) -> Result<String> {
    if path.starts_with('~') {
        let (home, remainder) = path.split_once('/').unwrap_or((path, ""));
        let Some(expanded_home) = sftp
            .expand_path(home.to_owned())
            .await
            .context("Unable to expand remote home directory")?
        else {
            bail!(
                "Remote SFTP service does not support expanding ~ paths; use an absolute path instead"
            );
        };
        return Ok(if remainder.is_empty() {
            expanded_home
        } else {
            format!("{}/{remainder}", expanded_home.trim_end_matches('/'))
        });
    }
    if remote_path_is_absolute(path) {
        return Ok(path.replace('\\', "/"));
    }
    let base = sftp
        .canonicalize(".")
        .await
        .context("Unable to resolve remote current directory")?;
    Ok(format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.replace('\\', "/").trim_start_matches('/')
    ))
}

fn remote_path_is_absolute(path: &str) -> bool {
    path.starts_with('/')
        || path.starts_with('\\')
        || path
            .as_bytes()
            .get(1)
            .is_some_and(|separator| *separator == b':')
}

async fn ensure_remote_parent_directories(sftp: &SftpSession, path: &str) -> Result<()> {
    for directory in remote_parent_directories(path) {
        if !sftp.try_exists(directory.clone()).await? {
            sftp.create_dir(directory.clone())
                .await
                .with_context(|| format!("Unable to create remote directory {directory}"))?;
        }
    }
    Ok(())
}

fn remote_parent_directories(path: &str) -> Vec<String> {
    let normalized = path.replace('\\', "/");
    let mut parts = normalized.split('/').collect::<Vec<_>>();
    if parts.len() < 2 {
        return Vec::new();
    }
    parts.pop();

    let absolute = normalized.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    let mut root_depth = 0;
    for part in parts {
        match part {
            "" | "." => continue,
            ".." => {
                if stack.len() > root_depth {
                    stack.pop();
                }
            }
            _ => {
                stack.push(part);
                if stack.len() == 1 && part.ends_with(':') {
                    root_depth = 1;
                }
            }
        }
    }
    (1..=stack.len())
        .map(|length| {
            let joined = stack[..length].join("/");
            if absolute {
                format!("/{joined}")
            } else {
                joined
            }
        })
        .collect()
}

async fn commit_remote_file(
    sftp: &SftpSession,
    temporary_path: &str,
    destination_path: &str,
    overwrite: bool,
) -> Result<()> {
    let destination_exists = sftp.try_exists(destination_path.to_owned()).await?;
    if !destination_exists {
        return sftp
            .rename(temporary_path.to_owned(), destination_path.to_owned())
            .await
            .context("Unable to complete remote file write");
    }
    if !overwrite {
        bail!("Remote file already exists; explicitly set overwrite to replace it=true");
    }
    let backup_path = format!(
        "{destination_path}.openkeylet-{}.backup",
        Uuid::new_v4().simple()
    );
    sftp.rename(destination_path.to_owned(), backup_path.clone())
        .await
        .context("Unable to stage existing remote file; original file is unchanged")?;

    if let Err(install_error) = sftp
        .rename(temporary_path.to_owned(), destination_path.to_owned())
        .await
    {
        if let Err(restore_error) = sftp
            .rename(backup_path.clone(), destination_path.to_owned())
            .await
        {
            bail!(
                "Unable to install new remote file ({install_error}), and unable to automatically restore the original file ({restore_error}; original file is retained at {backup_path}"
            );
        }
        return Err(anyhow::anyhow!(install_error))
            .context("Unable to install new remote file; original file has been restored");
    }

    if let Err(cleanup_error) = remove_remote_tree(sftp, &backup_path).await {
        let remove_new = sftp.remove_file(destination_path.to_owned()).await;
        let restore_old = sftp
            .rename(backup_path.clone(), destination_path.to_owned())
            .await;
        if remove_new.is_ok() && restore_old.is_ok() {
            return Err(anyhow::anyhow!(cleanup_error))
                .context("Unable to clean up remote backup; new file has been rolled back and original file restored");
        }
        bail!(
            "New file was written, but unable to clean up remote backup {backup_path}（{cleanup_error}); automatic rollback was also not fully completed"
        );
    }
    Ok(())
}

async fn commit_remote_directory(
    sftp: &SftpSession,
    temporary_path: &str,
    destination_path: &str,
    overwrite: bool,
) -> Result<()> {
    let destination_exists = sftp.try_exists(destination_path.to_owned()).await?;
    if !destination_exists {
        return sftp
            .rename(temporary_path.to_owned(), destination_path.to_owned())
            .await
            .context("Unable to complete remote directory write");
    }
    if !overwrite {
        bail!("Remote destination already exists; set overwrite to replace it=true");
    }
    let backup_path = format!(
        "{destination_path}.openkeylet-{}.backup",
        Uuid::new_v4().simple()
    );
    sftp.rename(destination_path.to_owned(), backup_path.clone())
        .await
        .context("Unable to stage existing remote directory; original directory is unchanged")?;
    if let Err(install_error) = sftp
        .rename(temporary_path.to_owned(), destination_path.to_owned())
        .await
    {
        if let Err(restore_error) = sftp
            .rename(backup_path.clone(), destination_path.to_owned())
            .await
        {
            bail!(
                "Unable to install new remote directory ({install_error}), and unable to automatically restore the original directory ({restore_error}; original directory is retained at {backup_path}"
            );
        }
        return Err(anyhow::anyhow!(install_error)).context(
            "Unable to install new remote directory; original directory has been restored",
        );
    }

    if let Err(cleanup_error) = remove_remote_tree(sftp, &backup_path).await {
        let remove_new = remove_remote_tree(sftp, destination_path).await;
        let restore_old = sftp
            .rename(backup_path.clone(), destination_path.to_owned())
            .await;
        if remove_new.is_ok() && restore_old.is_ok() {
            return Err(cleanup_error).context("Unable to clean up remote directory backup; new directory has been rolled back and original directory restored");
        }
        bail!(
            "New directory was written, but unable to clean up remote backup {backup_path}（{cleanup_error}); automatic rollback was also not fully completed"
        );
    }
    Ok(())
}

async fn remove_remote_tree(sftp: &SftpSession, root: &str) -> Result<()> {
    if !sftp.try_exists(root.to_owned()).await? {
        return Ok(());
    }
    let metadata = sftp.symlink_metadata(root.to_owned()).await?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return sftp
            .remove_file(root.to_owned())
            .await
            .with_context(|| format!("Unable to delete remote file {root}"));
    }

    let mut stack = vec![(root.to_owned(), false)];
    while let Some((path, visited)) = stack.pop() {
        if visited {
            sftp.remove_dir(path.clone())
                .await
                .with_context(|| format!("Unable to delete remote directory {path}"))?;
            continue;
        }
        stack.push((path.clone(), true));
        for entry in sftp
            .read_dir(path.clone())
            .await
            .with_context(|| format!("Unable to read remote directory to be deleted {path}"))?
        {
            if entry.file_type().is_dir() && !entry.file_type().is_symlink() {
                stack.push((entry.path(), false));
            } else {
                let entry_path = entry.path();
                sftp.remove_file(entry_path.clone())
                    .await
                    .with_context(|| format!("Unable to delete remote file {entry_path}"))?;
            }
        }
    }
    Ok(())
}

async fn commit_local_file(
    temporary_path: &std::path::Path,
    destination_path: &std::path::Path,
    overwrite: bool,
) -> Result<()> {
    let destination_exists = tokio::fs::try_exists(destination_path).await?;
    if !destination_exists {
        return tokio::fs::rename(temporary_path, destination_path)
            .await
            .context("Unable to complete local file write");
    }
    if !overwrite {
        bail!("Local file already exists; explicitly set overwrite to replace it=true");
    }
    let file_name = destination_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("download");
    let backup_path = destination_path.with_file_name(format!(
        ".{file_name}.openkeylet-{}.backup",
        Uuid::new_v4().simple()
    ));
    tokio::fs::rename(destination_path, &backup_path)
        .await
        .context("Unable to stage existing local file; original file is unchanged")?;

    if let Err(install_error) = tokio::fs::rename(temporary_path, destination_path).await {
        if let Err(restore_error) = tokio::fs::rename(&backup_path, destination_path).await {
            bail!(
                "Unable to install new local file ({install_error}), and unable to automatically restore the original file ({restore_error}; original file is retained at {}",
                backup_path.display()
            );
        }
        return Err(install_error)
            .context("Unable to install new local file; original file has been restored");
    }

    if let Err(cleanup_error) = remove_local_path(&backup_path).await {
        let remove_new = tokio::fs::remove_file(destination_path).await;
        let restore_old = tokio::fs::rename(&backup_path, destination_path).await;
        if remove_new.is_ok() && restore_old.is_ok() {
            return Err(cleanup_error).context("Unable to clean up local backup; new file has been rolled back and original file restored");
        }
        bail!(
            "New file was written, but unable to clean up local backup {}（{cleanup_error}); automatic rollback was also not fully completed",
            backup_path.display()
        );
    }
    Ok(())
}

async fn commit_local_directory(
    temporary_path: &Path,
    destination_path: &Path,
    overwrite: bool,
) -> Result<()> {
    let destination_exists = tokio::fs::try_exists(destination_path).await?;
    if !destination_exists {
        return tokio::fs::rename(temporary_path, destination_path)
            .await
            .context("Unable to complete local directory write");
    }
    if !overwrite {
        bail!("Local destination already exists; set overwrite to replace it=true");
    }
    let directory_name = destination_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("download");
    let backup_path = destination_path.with_file_name(format!(
        ".{directory_name}.openkeylet-{}.backup",
        Uuid::new_v4().simple()
    ));
    tokio::fs::rename(destination_path, &backup_path)
        .await
        .context("Unable to stage existing local directory; original directory is unchanged")?;
    if let Err(install_error) = tokio::fs::rename(temporary_path, destination_path).await {
        if let Err(restore_error) = tokio::fs::rename(&backup_path, destination_path).await {
            bail!(
                "Unable to install new local directory ({install_error}), and unable to automatically restore the original directory ({restore_error}; original directory is retained at {}",
                backup_path.display()
            );
        }
        return Err(install_error).context(
            "Unable to install new local directory; original directory has been restored",
        );
    }

    if let Err(cleanup_error) = remove_local_path(&backup_path).await {
        let remove_new = tokio::fs::remove_dir_all(destination_path).await;
        let restore_old = tokio::fs::rename(&backup_path, destination_path).await;
        if remove_new.is_ok() && restore_old.is_ok() {
            return Err(cleanup_error).context("Unable to clean up local directory backup; new directory has been rolled back and original directory restored");
        }
        bail!(
            "New directory was written, but unable to clean up local backup {}（{cleanup_error}); automatic rollback was also not fully completed",
            backup_path.display()
        );
    }
    Ok(())
}

async fn remove_local_path(path: &Path) -> Result<()> {
    let file_type = tokio::fs::symlink_metadata(path).await?.file_type();
    if file_type.is_dir() && !file_type.is_symlink() {
        tokio::fs::remove_dir_all(path).await?;
    } else {
        tokio::fs::remove_file(path).await?;
    }
    Ok(())
}

async fn run_optional_ssh_timeout<T>(
    execution: impl std::future::Future<Output = Result<T>>,
    timeout_seconds: Option<u64>,
    action: &str,
) -> Result<T> {
    match timeout_seconds.filter(|seconds| *seconds > 0) {
        Some(seconds) => tokio::time::timeout(Duration::from_secs(seconds), execution)
            .await
            .map_err(|_| anyhow::anyhow!("{action}Exceeded caller-configured {seconds} seconds"))?,
        None => execution.await,
    }
}

fn validate_transfer_path(value: &str, label: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() || value.contains('\0') {
        bail!("{label}Invalid");
    }
    Ok(value.to_owned())
}

pub async fn test_connection(vault: &Vault, connection: &DecryptedConnection) -> Result<String> {
    if connection.stored.test_target(&connection.secrets) == Some("ssh") {
        let testable = DecryptedConnection {
            stored: connection.stored.clone(),
            secrets: connection.secrets.clone(),
        };
        let result = execute_ssh(
            vault,
            &testable,
            "echo mcp-vault-ok",
            None,
            Some(30),
            &HashMap::new(),
            None,
            Some(DEFAULT_MAX_OUTPUT_BYTES),
        )
        .await?;
        validate_ssh_connection_test(&result)?;
        Ok("SSH connection successful".to_owned())
    } else if connection.stored.test_target(&connection.secrets) == Some("http") {
        let mut base = Url::parse(&connection.stored.base_url).context("Invalid API URL")?;
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        let url = if connection.stored.test_path.trim().is_empty() {
            base.to_string()
        } else {
            base.join(connection.stored.test_path.trim().trim_start_matches('/'))
                .context("Invalid API test path")?
                .to_string()
        };
        let result = execute_api(
            connection,
            ApiRequestInput {
                url,
                method: "GET".to_owned(),
                query: HashMap::new(),
                headers: HashMap::new(),
                body: None,
                timeout_seconds: Some(30),
                ..ApiRequestInput::default()
            },
        )
        .await?;
        Ok(format!("API responded: HTTP {}", result.status))
    } else {
        bail!("This project has no connection target that can be tested automatically")
    }
}

fn validate_ssh_connection_test(result: &SshResponse) -> Result<()> {
    if result.exit_code.is_some_and(|code| code != 0)
        || result.signal.is_some()
        || result.stdout.trim_end_matches(['\r', '\n']) != "mcp-vault-ok"
    {
        bail!("SSH connection test failed: {}", result.stderr.trim());
    }
    Ok(())
}

fn build_api_url(
    connection: &StoredConnection,
    request_url: &str,
    query: &HashMap<String, Value>,
) -> Result<Url> {
    let request_url = request_url.trim();
    let mut target = if request_url.is_empty() {
        let saved = connection.base_url.trim();
        if saved.is_empty() {
            bail!("This project has no service URL; provide an absolute URL for this request");
        }
        Url::parse(saved).context("Saved service URL is invalid")?
    } else if let Ok(absolute) = Url::parse(request_url) {
        absolute
    } else {
        let saved = connection.base_url.trim();
        if saved.is_empty() {
            bail!("When no service URL is saved, this request must provide an absolute URL");
        }
        let mut base = Url::parse(saved).context("Saved service URL is invalid")?;
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        base.join(request_url)
            .context("Invalid relative path for API request")?
    };
    if !query.is_empty() {
        let mut pairs = target.query_pairs_mut();
        for (name, value) in query {
            match value {
                Value::Array(values) => {
                    for value in values {
                        pairs.append_pair(name, &query_value(value));
                    }
                }
                Value::Null => {}
                value => {
                    pairs.append_pair(name, &query_value(value));
                }
            }
        }
    }
    Ok(target)
}

fn query_value(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

fn form_values(value: Value) -> Vec<String> {
    match value {
        Value::Array(values) => values
            .into_iter()
            .map(|value| query_value(&value))
            .collect(),
        Value::Null => Vec::new(),
        value => vec![query_value(&value)],
    }
}

fn api_request_error_message(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "API request timed out"
    } else if error.is_connect() {
        "Unable to connect to API service; check the address, network, VPN/proxy, and port"
    } else if error.is_body() {
        "API request or response body transfer failed"
    } else if error.is_request() {
        "Unable to send API request"
    } else {
        "API request failed"
    }
}

fn apply_api_auth(
    connection: &StoredConnection,
    secrets: &SecretBundle,
    headers: &mut HeaderMap,
    target: &mut Url,
) -> Result<()> {
    match connection.http_auth_type.as_str() {
        "bearer" => {
            let prefix = if connection.auth_prefix.trim().is_empty() {
                "Bearer"
            } else {
                connection.auth_prefix.trim()
            };
            let value = format!(
                "{prefix} {}",
                secrets
                    .get("apiCredential")
                    .context("No API credentials in the vault")?
            );
            headers.insert(
                reqwest::header::AUTHORIZATION,
                HeaderValue::from_str(&value)?,
            );
        }
        "apiKey" => {
            let secret = secrets
                .get("apiCredential")
                .context("No API credentials in the vault")?;
            let value = if connection.auth_prefix.trim().is_empty() {
                secret.to_owned()
            } else {
                format!("{} {secret}", connection.auth_prefix.trim())
            };
            if connection.auth_location == "query" {
                replace_query_pair(target, &connection.auth_header, &value);
            } else {
                let name = HeaderName::from_bytes(connection.auth_header.as_bytes())
                    .context("Invalid API Key request header")?;
                headers.insert(name, HeaderValue::from_str(&value)?);
            }
        }
        "basic" => {
            let username = secrets
                .get("username")
                .context("No Basic Auth username in the vault")?;
            let password = secrets
                .password
                .as_deref()
                .context("No Basic Auth password in the vault")?;
            let encoded = STANDARD.encode(format!("{username}:{password}"));
            headers.insert(
                reqwest::header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Basic {encoded}"))?,
            );
        }
        "custom" => {
            for header in &connection.api_auth_headers {
                let name = HeaderName::from_bytes(header.name.as_bytes())
                    .context("Invalid custom authentication request header name")?;
                let value = secrets
                    .get(&header.secret_name)
                    .context("Custom authentication request header missing from the vault")?;
                headers.insert(name, HeaderValue::from_str(value)?);
            }
        }
        _ => {}
    }
    Ok(())
}

fn replace_query_pair(target: &mut Url, name: &str, value: &str) {
    let retained = target
        .query_pairs()
        .filter(|(key, _)| key != name)
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    target.set_query(None);
    let mut pairs = target.query_pairs_mut();
    for (key, value) in retained {
        pairs.append_pair(&key, &value);
    }
    pairs.append_pair(name, value);
}

struct SshClient;

impl client::Handler for SshClient {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

pub(crate) fn sanitize_api_body(
    mut body: String,
    truncated: bool,
    connection: &StoredConnection,
    secrets: &SecretBundle,
) -> String {
    if truncated {
        body.push_str("\n…[Result truncated]");
    }
    redact(body, connection, secrets)
}

fn ssh_connect_error_message(error: &impl Display) -> String {
    let raw = error.to_string();
    let normalized = raw.to_ascii_lowercase();
    if normalized.contains("disconnected") || normalized.contains("connection closed") {
        return "SSH handshake was closed early by the remote (credentials have not been sent); check the remote sshd, VPN/proxy route, or SSH concurrency limit".to_owned();
    }
    if normalized.contains("timed out")
        || normalized.contains("timeout")
        || normalized.contains("os error 10060")
    {
        return "SSH TCP connection timed out; check the target address, VPN/proxy route, and port 22".to_owned();
    }
    if normalized.contains("connection refused") || normalized.contains("os error 10061") {
        return "SSH port refused the connection; the target is reachable, but sshd is not listening on that port".to_owned();
    }
    if normalized.contains("no common") || normalized.contains("key exchange") {
        return format!("SSH handshake algorithms are incompatible:{raw}");
    }
    format!("SSH connection or handshake failed:{raw}")
}

pub(crate) fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ApiAuthHeader, ItemModule, SecretEnvelope};
    use axum::{
        Router,
        body::Bytes,
        extract::Query,
        http::HeaderMap as AxumHeaders,
        response::Redirect,
        routing::{get, post},
    };
    use chrono::Utc;
    use tempfile::tempdir;
    use uuid::Uuid;

    #[test]
    fn ssh_connection_test_accepts_windows_and_unix_line_endings() {
        let mut result = SshResponse {
            exit_code: Some(0),
            signal: None,
            stdout: "mcp-vault-ok\r\n".into(),
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        };
        assert!(validate_ssh_connection_test(&result).is_ok());
        result.stdout = "mcp-vault-ok\n".into();
        assert!(validate_ssh_connection_test(&result).is_ok());
        result.exit_code = Some(1);
        assert!(validate_ssh_connection_test(&result).is_err());
        result.exit_code = Some(0);
        result.stdout = "unexpected\n".into();
        assert!(validate_ssh_connection_test(&result).is_err());
    }

    fn stored(base_url: String) -> StoredConnection {
        StoredConnection {
            login_uris: Vec::new(),
            item_type: String::new(),
            folder: String::new(),
            favorite: false,
            id: Uuid::new_v4(),
            modules: vec![],
            name: "local-api".into(),
            enabled: true,
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
            description: String::new(),
            host: String::new(),
            port: 0,
            ssh_auth_type: String::new(),
            http_auth_type: "bearer".into(),
            private_key_name: String::new(),
            base_url,
            auth_header: "X-API-Key".into(),
            auth_location: "header".into(),
            auth_prefix: String::new(),
            api_auth_headers: vec![],
            test_path: String::new(),
            secret: None,
            encrypted_secrets: SecretEnvelope {
                version: 1,
                nonce: String::new(),
                ciphertext: String::new(),
            },
        }
    }

    #[tokio::test]
    async fn runtime_target_item_does_not_offer_a_fake_connection_test() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let mut stored = stored(String::new());
        stored.modules.push(ItemModule {
            kind: "password".to_owned(),
            ..Default::default()
        });
        let mut secrets = SecretBundle::default();
        secrets.password = Some("synthetic-runtime-password".to_owned());
        let connection = DecryptedConnection { stored, secrets };
        assert!(connection.stored.has_capability(&connection.secrets, "ssh"));
        assert!(
            connection
                .stored
                .has_capability(&connection.secrets, "http")
        );
        assert!(!connection.stored.public(Some(&connection.secrets)).can_test);
        assert_eq!(
            test_connection(&vault, &connection)
                .await
                .unwrap_err()
                .to_string(),
            "This project has no connection target that can be tested automatically"
        );
    }

    #[test]
    fn remote_parent_paths_are_normalized_and_incremental() {
        assert_eq!(
            remote_parent_directories("/home/user/project/file.txt"),
            vec!["/home", "/home/user", "/home/user/project"]
        );
        assert_eq!(
            remote_parent_directories("/home/user/../shared/file.txt"),
            vec!["/home", "/home/shared"]
        );
        assert_eq!(
            remote_parent_directories("C:\\Users\\me\\file.txt"),
            vec!["C:", "C:/Users", "C:/Users/me"]
        );
        assert_eq!(
            remote_parent_directories("C:/../shared/file.txt"),
            vec!["C:", "C:/shared"]
        );
        assert!(remote_parent_directories("file.txt").is_empty());
    }

    #[tokio::test]
    async fn local_transfer_commit_preserves_existing_files_until_replacement_is_ready() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("download.txt");
        let refused_temporary = directory.path().join("refused.part");
        std::fs::write(&destination, "old").unwrap();
        std::fs::write(&refused_temporary, "new").unwrap();

        assert!(
            commit_local_file(&refused_temporary, &destination, false)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read_to_string(&destination).unwrap(), "old");
        assert_eq!(std::fs::read_to_string(&refused_temporary).unwrap(), "new");

        commit_local_file(&refused_temporary, &destination, true)
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(&destination).unwrap(), "new");
        assert!(!refused_temporary.exists());
        assert!(std::fs::read_dir(directory.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".backup")
        }));

        let fresh_temporary = directory.path().join("fresh.part");
        let fresh_destination = directory.path().join("fresh.txt");
        std::fs::write(&fresh_temporary, "fresh").unwrap();
        commit_local_file(&fresh_temporary, &fresh_destination, false)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&fresh_destination).unwrap(),
            "fresh"
        );

        let directory_destination = directory.path().join("existing-directory");
        let directory_temporary = directory.path().join("directory.part");
        std::fs::create_dir(&directory_destination).unwrap();
        std::fs::write(&directory_temporary, "must-not-replace-directory").unwrap();
        commit_local_file(&directory_temporary, &directory_destination, true)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&directory_destination).unwrap(),
            "must-not-replace-directory"
        );
        assert!(!directory_temporary.exists());

        let mixed_directory_temporary = directory.path().join("mixed-directory.part");
        std::fs::create_dir(&mixed_directory_temporary).unwrap();
        std::fs::write(mixed_directory_temporary.join("new.txt"), "directory-wins").unwrap();
        commit_local_directory(&mixed_directory_temporary, &directory_destination, true)
            .await
            .unwrap();
        assert!(directory_destination.is_dir());
        assert_eq!(
            std::fs::read_to_string(directory_destination.join("new.txt")).unwrap(),
            "directory-wins"
        );

        let existing_tree = directory.path().join("existing-tree");
        let replacement_tree = directory.path().join("replacement-tree.part");
        std::fs::create_dir(&existing_tree).unwrap();
        std::fs::write(existing_tree.join("old.txt"), "old-tree").unwrap();
        std::fs::create_dir(&replacement_tree).unwrap();
        std::fs::create_dir(replacement_tree.join("nested")).unwrap();
        std::fs::write(replacement_tree.join("nested/new.txt"), "new-tree").unwrap();

        assert!(
            commit_local_directory(&replacement_tree, &existing_tree, false)
                .await
                .is_err()
        );
        assert_eq!(
            std::fs::read_to_string(existing_tree.join("old.txt")).unwrap(),
            "old-tree"
        );
        commit_local_directory(&replacement_tree, &existing_tree, true)
            .await
            .unwrap();
        assert!(!existing_tree.join("old.txt").exists());
        assert_eq!(
            std::fs::read_to_string(existing_tree.join("nested/new.txt")).unwrap(),
            "new-tree"
        );
        assert!(!replacement_tree.exists());
    }

    #[tokio::test]
    async fn api_injects_vault_auth_overwrites_auth_and_keeps_ordinary_headers() {
        async fn response(headers: AxumHeaders) -> String {
            let auth = headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            let cookie = headers
                .get("cookie")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            format!("auth={auth}\ncookie={cookie}\n{}", "x".repeat(1_048_676))
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/v1/echo", get(response)))
                .await
                .unwrap();
        });

        let mut secrets = SecretBundle::default();
        secrets.token = Some("vault-secret-token-9384".into());
        let connection = DecryptedConnection {
            stored: stored(format!("http://{address}/v1/")),
            secrets,
        };
        let mut headers = HashMap::new();
        headers.insert("Authorization".into(), "Bearer attacker-value".into());
        headers.insert("Cookie".into(), "session=attacker".into());
        let result = execute_api(
            &connection,
            ApiRequestInput {
                url: format!("http://{address}/v1/echo"),
                method: "GET".into(),
                query: HashMap::new(),
                headers,
                body: None,
                ..ApiRequestInput::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(result.status, 200);
        assert!(!result.body.contains("vault-secret-token-9384"));
        assert!(!result.body.contains("attacker-value"));
        assert!(result.body.contains("[REDACTED]"));
        assert!(result.body.contains("cookie=session=attacker"));
        assert!(!result.body.contains("[Result truncated]"));
        assert!(!result.truncated);
        assert!(result.body.len() > 1_048_576);

        let limited = execute_api(
            &connection,
            ApiRequestInput {
                url: format!("http://{address}/v1/echo"),
                method: "GET".into(),
                max_response_bytes: Some(1_024),
                ..ApiRequestInput::default()
            },
        )
        .await
        .unwrap();
        assert!(limited.body.contains("[Result truncated]"));
        assert!(limited.truncated);
        server.abort();
    }

    #[tokio::test]
    async fn api_streams_large_responses_to_a_safe_local_file() {
        async fn artifact() -> Vec<u8> {
            vec![b'Z'; 1_148_576]
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/v1/artifact", get(artifact)))
                .await
                .unwrap();
        });
        let mut secrets = SecretBundle::default();
        secrets.token = Some("artifact-test-token".into());
        let connection = DecryptedConnection {
            stored: stored(format!("http://{address}/v1/")),
            secrets,
        };
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("nested/artifact.bin");
        let request = || ApiRequestInput {
            url: format!("http://{address}/v1/artifact"),
            method: "GET".into(),
            save_response_to: Some(destination.to_string_lossy().into_owned()),
            ..ApiRequestInput::default()
        };

        let result = execute_api(&connection, request()).await.unwrap();
        assert_eq!(result.body, "");
        assert!(!result.truncated);
        assert_eq!(result.bytes_transferred, Some(1_148_576));
        assert_eq!(std::fs::metadata(&destination).unwrap().len(), 1_148_576);
        assert!(
            result
                .saved_to
                .as_deref()
                .is_some_and(|path| path.ends_with("artifact.bin"))
        );

        assert!(execute_api(&connection, request()).await.is_err());
        std::fs::write(&destination, "old").unwrap();
        let overwritten = execute_api(
            &connection,
            ApiRequestInput {
                overwrite_response_file: true,
                ..request()
            },
        )
        .await
        .unwrap();
        assert_eq!(overwritten.bytes_transferred, Some(1_148_576));
        assert_eq!(std::fs::read(&destination).unwrap()[0], b'Z');
        server.abort();
    }

    #[tokio::test]
    async fn api_follows_redirects_and_reports_the_final_url() {
        let final_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let final_address = final_listener.local_addr().unwrap();
        let final_server = tokio::spawn(async move {
            axum::serve(
                final_listener,
                Router::new().route("/v1/final", get(|| async { "redirect-complete" })),
            )
            .await
            .unwrap();
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let redirect_url = format!("http://{final_address}/v1/final");
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route(
                    "/v1/start",
                    get(move || {
                        let redirect_url = redirect_url.clone();
                        async move { Redirect::temporary(&redirect_url) }
                    }),
                ),
            )
            .await
            .unwrap();
        });
        let mut secrets = SecretBundle::default();
        secrets.token = Some("redirect-token-9384".into());
        let connection = DecryptedConnection {
            stored: stored(format!("http://{address}/v1/")),
            secrets,
        };

        let result = execute_api(
            &connection,
            ApiRequestInput {
                url: format!("http://{address}/v1/start"),
                method: "GET".into(),
                ..ApiRequestInput::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(result.status, 200);
        assert_eq!(result.body, "redirect-complete");
        assert_eq!(result.url, format!("http://{final_address}/v1/final"));
        server.abort();
        final_server.abort();
    }

    #[tokio::test]
    async fn api_key_query_replaces_agent_value_without_exposing_secret() {
        async fn response(Query(query): Query<HashMap<String, String>>) -> &'static str {
            if query.get("key").map(String::as_str) == Some("vault-query-key-9384") {
                "correct"
            } else {
                "wrong"
            }
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/v1/echo", get(response)))
                .await
                .unwrap();
        });
        let mut item = stored(format!("http://{address}/v1/"));
        item.http_auth_type = "apiKey".into();
        item.auth_location = "query".into();
        item.auth_header = "key".into();
        let mut secrets = SecretBundle::default();
        secrets.api_key = Some("vault-query-key-9384".into());
        let connection = DecryptedConnection {
            stored: item,
            secrets,
        };
        let mut query = HashMap::new();
        query.insert("key".into(), Value::String("agent-value".into()));

        let result = execute_api(
            &connection,
            ApiRequestInput {
                url: format!("http://{address}/v1/echo"),
                method: "GET".into(),
                query,
                headers: HashMap::new(),
                body: None,
                ..ApiRequestInput::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(result.body, "correct");
        assert!(!result.url.contains("vault-query-key-9384"));
        assert!(result.url.contains("[REDACTED]"));
        server.abort();
    }

    #[tokio::test]
    async fn api_supports_forms_raw_bytes_and_streamed_file_uploads() {
        async fn echo(headers: AxumHeaders, body: Bytes) -> String {
            format!(
                "{}\n{}",
                headers
                    .get("content-type")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default(),
                String::from_utf8_lossy(&body)
            )
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/v1/echo", post(echo)))
                .await
                .unwrap();
        });
        let stored = stored(format!("http://{address}/v1/"));
        let mut secrets = SecretBundle::default();
        secrets.token = Some("vault-form-token-9384".into());
        let connection = DecryptedConnection { stored, secrets };
        let url = format!("http://{address}/v1/echo");

        let mut form = HashMap::new();
        form.insert(
            "tag".into(),
            Value::Array(vec![
                Value::String("one".into()),
                Value::String("two".into()),
            ]),
        );
        let form_result = execute_api(
            &connection,
            ApiRequestInput {
                url: url.clone(),
                method: "POST".into(),
                form,
                ..ApiRequestInput::default()
            },
        )
        .await
        .unwrap();
        assert!(
            form_result
                .body
                .contains("application/x-www-form-urlencoded")
        );
        assert!(form_result.body.contains("tag=one"));
        assert!(form_result.body.contains("tag=two"));

        let raw_result = execute_api(
            &connection,
            ApiRequestInput {
                url: url.clone(),
                method: "POST".into(),
                body_base64: Some(STANDARD.encode(b"raw-binary-marker-9384\0tail")),
                ..ApiRequestInput::default()
            },
        )
        .await
        .unwrap();
        assert!(raw_result.body.contains("raw-binary-marker-9384"));

        let mut text_headers = HashMap::new();
        text_headers.insert("Content-Type".into(), "text/plain; charset=utf-8".into());
        let text_result = execute_api(
            &connection,
            ApiRequestInput {
                url: url.clone(),
                method: "POST".into(),
                headers: text_headers,
                body: Some(Value::String("plain-text-marker-9384".into())),
                max_response_bytes: Some(32 * 1024 * 1024),
                ..ApiRequestInput::default()
            },
        )
        .await
        .unwrap();
        assert!(text_result.body.contains("text/plain"));
        assert!(text_result.body.contains("plain-text-marker-9384"));

        let directory = tempfile::tempdir().unwrap();
        let file_path = directory.path().join("upload.txt");
        std::fs::write(&file_path, "multipart-file-marker-9384").unwrap();
        let mut multipart_fields = HashMap::new();
        multipart_fields.insert("note".into(), Value::String("multipart-note-9384".into()));
        let multipart_result = execute_api(
            &connection,
            ApiRequestInput {
                url,
                method: "POST".into(),
                form: multipart_fields,
                files: vec![ApiUploadFile {
                    field: "attachment".into(),
                    path: file_path.to_string_lossy().into_owned(),
                    file_name: None,
                    content_type: None,
                }],
                ..ApiRequestInput::default()
            },
        )
        .await
        .unwrap();
        assert!(multipart_result.body.contains("multipart/form-data"));
        assert!(multipart_result.body.contains("multipart-note-9384"));
        assert!(multipart_result.body.contains("multipart-file-marker-9384"));
        server.abort();
    }

    #[test]
    fn custom_auth_headers_are_injected_from_named_secrets() {
        let mut item = stored("https://api.example.test/v1/".to_owned());
        item.http_auth_type = "custom".into();
        item.api_auth_headers = vec![ApiAuthHeader {
            name: "X-Client-Secret".into(),
            secret_name: "apiHeader_client".into(),
        }];
        let mut secrets = SecretBundle::default();
        secrets
            .named_secrets
            .insert("apiHeader_client".into(), "custom-secret-9384".into());
        let mut headers = HeaderMap::new();
        let mut target = Url::parse("https://api.example.test/v1/").unwrap();

        apply_api_auth(&item, &secrets, &mut headers, &mut target).unwrap();

        assert_eq!(
            headers.get("x-client-secret").unwrap(),
            "custom-secret-9384"
        );
        assert!(blocked_header_names(&item).contains("x-client-secret"));
    }

    #[test]
    fn api_activity_description_omits_query_and_records_origin_and_path() {
        let mut query = HashMap::new();
        query.insert("token".into(), Value::String("must-not-be-logged".into()));
        let connection = stored("https://api.example.test/v1/".to_owned());
        let description = describe_api_request(
            &connection,
            &ApiRequestInput {
                url: "https://api.example.test/v1/items".into(),
                method: "post".into(),
                query,
                headers: HashMap::new(),
                body: None,
                ..ApiRequestInput::default()
            },
        );
        assert_eq!(description, "API POST https://api.example.test/v1/items");
        assert!(!description.contains("token"));
        assert!(!description.contains("must-not-be-logged"));
    }

    #[test]
    fn api_response_only_redacts_secrets_known_to_openkeylet() {
        let connection = stored("https://api.example.test/v1/".to_owned());
        let mut secrets = SecretBundle::default();
        secrets.token = Some("stored-token-9384".to_owned());
        let body = sanitize_api_body(
            r#"{
                "name": "visible",
                "access_token": "new-access-token",
                "nested": [{"client-secret": "new-client-secret"}],
                "credential": {"value": "new-credential"},
                "echo": "stored-token-9384"
            }"#
            .to_owned(),
            false,
            &connection,
            &secrets,
        );
        assert!(body.contains("visible"));
        for server_value in ["new-access-token", "new-client-secret", "new-credential"] {
            assert!(body.contains(server_value));
        }
        assert!(!body.contains("stored-token-9384"));

        let malformed = sanitize_api_body(
            r#"{"token":"new-token""#.to_owned(),
            false,
            &connection,
            &secrets,
        );
        assert_eq!(malformed, r#"{"token":"new-token""#);

        let truncated = sanitize_api_body(
            r#"{"name":"partial""#.to_owned(),
            true,
            &connection,
            &secrets,
        );
        assert_eq!(truncated, "{\"name\":\"partial\"\n…[Result truncated]");
    }

    #[test]
    fn saved_api_url_accepts_omitted_and_relative_request_urls() {
        let connection = stored("https://api.example.test/v1".to_owned());
        let query = HashMap::new();

        assert_eq!(
            build_api_url(&connection, "", &query).unwrap().as_str(),
            "https://api.example.test/v1"
        );
        assert_eq!(
            build_api_url(&connection, "items/42", &query)
                .unwrap()
                .as_str(),
            "https://api.example.test/v1/items/42"
        );
        assert_eq!(
            build_api_url(&connection, "/health", &query)
                .unwrap()
                .as_str(),
            "https://api.example.test/health"
        );

        let addressless = stored(String::new());
        assert!(build_api_url(&addressless, "", &query).is_err());
        assert!(build_api_url(&addressless, "items", &query).is_err());
        assert_eq!(
            build_api_url(&addressless, "https://other.example/items", &query)
                .unwrap()
                .as_str(),
            "https://other.example/items"
        );
    }

    #[test]
    fn ssh_connect_errors_name_the_failed_stage() {
        assert!(ssh_connect_error_message(&"Disconnected").contains("handshake"));
        assert!(ssh_connect_error_message(&"os error 10060").contains("TCP"));
        assert!(ssh_connect_error_message(&"connection refused").contains("port"));
    }

    #[test]
    fn ssh_secret_environment_quotes_values_and_rejects_invalid_names() {
        let command = ssh_command_with_secret_environment(
            "printf '%s' \"$OPENKEYLET_PASSWORD\"",
            &HashMap::from([(
                "OPENKEYLET_PASSWORD".to_owned(),
                "value with ' quotes and $shell".to_owned(),
            )]),
        )
        .unwrap();
        assert!(
            command.starts_with("OPENKEYLET_PASSWORD='value with '\\'' quotes and $shell' sh -c ")
        );
        assert!(command.contains("$OPENKEYLET_PASSWORD"));
        assert!(
            ssh_command_with_secret_environment(
                "true",
                &HashMap::from([("NOT-VALID".to_owned(), "secret".to_owned())]),
            )
            .is_err()
        );
    }

    #[test]
    fn ssh_auth_methods_prefer_private_key_with_password_fallback() {
        let mut both_secrets = SecretBundle::default();
        both_secrets.private_key = Some("-----BEGIN OPENSSH PRIVATE KEY-----".into());
        both_secrets.password = Some("sudo-password".into());
        let mut both_stored = stored(String::new());
        both_stored.ssh_auth_type = "password".into();
        let both = DecryptedConnection {
            stored: both_stored,
            secrets: both_secrets,
        };
        assert_eq!(ssh_auth_methods(&both), vec!["privateKey", "password"]);

        let mut pw_only_secrets = SecretBundle::default();
        pw_only_secrets.password = Some("only-password".into());
        let pw_only = DecryptedConnection {
            stored: stored(String::new()),
            secrets: pw_only_secrets,
        };
        assert_eq!(ssh_auth_methods(&pw_only), vec!["password"]);
    }

    #[test]
    fn bounded_output_capture_preserves_head_and_tail_and_redacts() {
        let mut capture = BoundedOutputCapture::new(Some(64));
        capture.push(b"HEAD_SECRET=topsecret123_");
        capture.push(&vec![b'M'; 400]);
        capture.push(b"_TAIL_SECRET=topsecret123");
        let (text, truncated) = capture.finish(|s| s.replace("topsecret123", "[REDACTED]"));
        assert!(truncated);
        assert!(text.contains("HEAD_SECRET=[REDACTED]"));
        assert!(text.contains("_TAIL_SECRET=[REDACTED]"));
        assert!(text.contains("Output truncated: omitted"));
        assert!(!text.contains("topsecret123"));

        let mut unlimited = BoundedOutputCapture::new(Some(0));
        unlimited.push(&vec![b'X'; 4096]);
        let (full, full_truncated) = unlimited.finish(|s| s);
        assert!(!full_truncated);
        assert_eq!(full.len(), 4096);
    }

    #[tokio::test]
    async fn api_cross_origin_redirect_strips_custom_auth_headers_and_supports_no_redirect() {
        async fn inspect_headers(headers: AxumHeaders) -> String {
            let auth = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("NONE");
            let api_key = headers
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("NONE");
            let custom = headers
                .get("x-client-secret")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("NONE");
            format!("auth={auth}|key={api_key}|custom={custom}")
        }

        let foreign_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let foreign_addr = foreign_listener.local_addr().unwrap();
        let foreign_server = tokio::spawn(async move {
            axum::serve(
                foreign_listener,
                Router::new().route("/landed", get(inspect_headers)),
            )
            .await
            .unwrap();
        });

        let origin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let foreign_target = format!("http://{foreign_addr}/landed");
        let same_origin_target = format!("http://{origin_addr}/same-landed");
        let origin_server = tokio::spawn(async move {
            axum::serve(
                origin_listener,
                Router::new()
                    .route(
                        "/to-foreign",
                        get({
                            let url = foreign_target.clone();
                            move || {
                                let url = url.clone();
                                async move { Redirect::temporary(&url) }
                            }
                        }),
                    )
                    .route(
                        "/to-same",
                        get({
                            let url = same_origin_target.clone();
                            move || {
                                let url = url.clone();
                                async move { Redirect::temporary(&url) }
                            }
                        }),
                    )
                    .route("/same-landed", get(inspect_headers)),
            )
            .await
            .unwrap();
        });

        let mut item = stored(format!("http://{origin_addr}/"));
        item.http_auth_type = "custom".into();
        item.api_auth_headers = vec![ApiAuthHeader {
            name: "X-Client-Secret".into(),
            secret_name: "clientSecret".into(),
        }];
        let mut secrets = SecretBundle::default();
        secrets
            .named_secrets
            .insert("clientSecret".into(), "custom-header-secret-5544".into());
        let connection = DecryptedConnection {
            stored: item,
            secrets,
        };

        // Cross-origin redirect must follow AND strip X-Client-Secret
        let foreign_res = execute_api(
            &connection,
            ApiRequestInput {
                url: format!("http://{origin_addr}/to-foreign"),
                method: "GET".into(),
                ..ApiRequestInput::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(foreign_res.status, 200);
        assert_eq!(foreign_res.body, "auth=NONE|key=NONE|custom=NONE");

        // Same-origin redirect keeps X-Client-Secret (redacted in echoed body)
        let same_res = execute_api(
            &connection,
            ApiRequestInput {
                url: format!("http://{origin_addr}/to-same"),
                method: "GET".into(),
                ..ApiRequestInput::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(same_res.status, 200);
        assert_eq!(same_res.body, "auth=NONE|key=NONE|custom=[REDACTED]");

        // follow_redirects=false returns 307 + Location without following
        let no_redir = execute_api(
            &connection,
            ApiRequestInput {
                url: format!("http://{origin_addr}/to-foreign"),
                method: "GET".into(),
                follow_redirects: Some(false),
                ..ApiRequestInput::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(no_redir.status, 307);
        assert_eq!(
            no_redir.headers.get("location").map(String::as_str),
            Some(format!("http://{foreign_addr}/landed").as_str())
        );

        origin_server.abort();
        foreign_server.abort();
    }

    #[tokio::test]
    async fn execute_local_truncates_large_output_and_redacts_extra_secrets() {
        #[cfg(windows)]
        let cmd = "Write-Output ('START_sec9988_' + ('Z' * 1200) + '_END_sec9988')";
        #[cfg(not(windows))]
        let cmd = "printf 'START_sec9988_%01200d_END_sec9988\\n' 0";

        let res = execute_local(
            None,
            cmd,
            None,
            Some(15),
            &HashMap::new(),
            None,
            Some(256),
            &["sec9988".to_owned()],
        )
        .await
        .unwrap();
        assert_eq!(res.exit_code, Some(0));
        assert!(res.stdout_truncated);
        assert!(res.stdout.contains("START_[REDACTED]_"));
        assert!(res.stdout.contains("_END_[REDACTED]"));
        assert!(!res.stdout.contains("sec9988"));
    }
}
