use super::*;

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

pub(super) fn default_method() -> String {
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
    /// captureSecrets fields whose JSON path matched nothing; the body is withheld then.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capture_missing: Vec<String>,
    /// Key paths (no values) of a JSON body withheld because a capture failed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub json_paths: Vec<String>,
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
pub(super) struct TransferStats {
    pub(super) bytes: u64,
    pub(super) files: u64,
    pub(super) directories: u64,
}

pub(super) enum PreparedApiBody {
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

fn prepared_body_may_carry_secret(body: &PreparedApiBody, secrets: &SecretBundle) -> bool {
    match body {
        PreparedApiBody::Empty => false,
        PreparedApiBody::Bytes { bytes, .. } => body_contains_secret(bytes, secrets),
        // Multipart parts stream local files that cannot be inspected without reading them.
        PreparedApiBody::Multipart { .. } => true,
    }
}

pub(super) async fn build_multipart_form(
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
    execute_api_scoped(connection, input, &[]).await
}

/// Like [`execute_api`], for a request that also carries substituted values from
/// `secret_sources` (other items, or the same item, whose hidden values were placed into the
/// request). Their website bindings are enforced for the target and every redirect hop.
pub(crate) async fn execute_api_scoped(
    connection: &DecryptedConnection,
    input: ApiRequestInput,
    secret_sources: &[StoredConnection],
) -> Result<ApiResponse> {
    let raw = execute_api_raw(connection, input, secret_sources).await?;
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
        capture_missing: Vec::new(),
        json_paths: Vec::new(),
    })
}

pub(crate) async fn execute_api_raw(
    connection: &DecryptedConnection,
    input: ApiRequestInput,
    secret_sources: &[StoredConnection],
) -> Result<RawApiResponse> {
    if !connection.stored.enabled {
        bail!("This connection is disabled");
    }
    let mut target = build_api_url(&connection.stored, &input.url, &input.query)?;
    // Refuse before anything is read, created, or sent: an item with a saved service URL or
    // website rules only lends its credentials to that destination.
    if let Some(refused) = std::iter::once(&connection.stored)
        .chain(secret_sources)
        .find(|stored| !api_target_allowed(stored, &target))
    {
        bail!("{}", api_target_refusal(refused));
    }
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

            // A hop outside a bound item's website rules is treated like a cross-origin hop
            // even when it stays on the same origin (path-scoped rules).
            let leaves_binding = next_url.origin() != initial_origin
                || !std::iter::once(&connection.stored)
                    .chain(secret_sources)
                    .all(|stored| api_target_allowed(stored, &next_url));

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

            if leaves_binding {
                // A preserved body may carry substituted secrets; never re-send it to another
                // origin. Return the redirect to the caller instead of following it.
                if prepared_body_may_carry_secret(&current_body, &connection.secrets) {
                    return Ok(response);
                }
                strip_cross_origin_redirect_auth(
                    &mut current_headers,
                    &mut next_url,
                    &connection.stored,
                    &connection.secrets,
                );
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
    let redactor = Redactor::new(&connection_redaction_candidates(&connection.secrets));
    let response_headers = visible_response_headers(response.headers())
        .into_iter()
        .map(|(name, value)| (name, redactor.redact_string(value)))
        .collect();
    if let Some(destination) = save_response_to {
        let (saved_to, bytes_transferred) =
            save_api_response_to_file(&mut response, &destination, overwrite_response_file).await?;
        return Ok(RawApiResponse {
            status: status.as_u16(),
            status_text: status.canonical_reason().unwrap_or_default().to_owned(),
            url: redactor.redact_string(response_url.to_string()),
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
        url: redactor.redact_string(response_url.to_string()),
        headers: response_headers,
        raw_body: String::from_utf8_lossy(&bytes).into_owned(),
        truncated,
        saved_to: None,
        bytes_transferred: None,
    })
}

pub(super) async fn prepare_api_response_destination(
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

pub(super) async fn save_api_response_to_file(
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


/// The absolute URL `input` targets for `connection`, before OpenKeylet adds query
/// authentication (which never changes the origin or path).
pub(crate) fn api_request_target(
    connection: &StoredConnection,
    input: &ApiRequestInput,
) -> Result<Url> {
    build_api_url(connection, &input.url, &input.query)
}

pub(super) fn build_api_url(
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

pub(super) fn query_value(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

pub(super) fn form_values(value: Value) -> Vec<String> {
    match value {
        Value::Array(values) => values
            .into_iter()
            .map(|value| query_value(&value))
            .collect(),
        Value::Null => Vec::new(),
        value => vec![query_value(&value)],
    }
}

pub(super) fn api_request_error_message(error: &reqwest::Error) -> &'static str {
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

pub(super) fn apply_api_auth(
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

pub(super) fn replace_query_pair(target: &mut Url, name: &str, value: &str) {
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


pub(crate) fn sanitize_api_body(
    body: String,
    truncated: bool,
    _connection: &StoredConnection,
    secrets: &SecretBundle,
) -> String {
    let redactor = Redactor::new(&connection_redaction_candidates(secrets));
    if !truncated {
        return redactor.redact_string(body);
    }
    // A secret cut by maxResponseBytes would otherwise end the body with its first bytes.
    let (mut kept, _) = redactor.redact_stream(body.as_bytes(), true);
    kept.extend_from_slice("\n…[Result truncated]".as_bytes());
    String::from_utf8_lossy(&kept).into_owned()
}

