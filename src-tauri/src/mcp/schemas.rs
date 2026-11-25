use super::*;

pub(super) fn tool_success<T: Serialize>(value: T) -> CallToolResult {
    match serde_json::to_value(value) {
        Ok(value) => {
            let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
            let mut result = CallToolResult::structured(value);
            result.content = vec![ContentBlock::text(text)];
            result
        }
        Err(_) => tool_error("OpenKeylet could not serialize the tool result."),
    }
}

pub(super) fn tool_error(message: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message.into())])
}

pub(super) fn into_tool_result<T: Serialize>(result: Result<T, String>) -> CallToolResult {
    match result {
        Ok(value) => tool_success(value),
        Err(message) => tool_error(message),
    }
}

pub(super) fn is_false(value: &bool) -> bool {
    !*value
}

pub(super) fn is_zero(value: &usize) -> bool {
    *value == 0
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct AgentNoteOutput {
    pub(super) id: String,
    pub(super) text: String,
    pub(super) author: String,
    pub(super) updated_at: String,
}

impl From<crate::model::AgentNoteEntry> for AgentNoteOutput {
    fn from(entry: crate::model::AgentNoteEntry) -> Self {
        Self {
            id: entry.id.clone(),
            text: entry.text.clone(),
            author: entry.author.clone(),
            updated_at: entry.updated_at.clone(),
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ItemNoteInput {
    #[serde(default)]
    #[schemars(
        description = "Optional OpenKeylet project name, or an unambiguous natural-language phrase containing it. Omit it after this MCP session selected a project, or when exactly one enabled project exists."
    )]
    pub(super) item: String,
    #[serde(default)]
    #[schemars(
        description = "Short factual, non-secret remark (<=200 chars) about this asset's role, environment, workspace path, account tier, or distinguishing context so future sessions pick the right item quickly. Never include passwords, tokens, keys, or secrets. Required for action='add' or 'update'."
    )]
    pub(super) note: String,
    #[serde(default = "default_note_action")]
    #[schemars(
        description = "Operation: 'add' (default, appends a new note and keeps the 5 most recent), 'update' (edits an existing non-owner note by noteId), or 'remove' (deletes an outdated non-owner note by noteId)."
    )]
    pub(super) action: String,
    #[serde(default)]
    #[schemars(
        description = "Target note ID from items_search or item_note output. Required when action is 'update' or 'remove'."
    )]
    pub(super) note_id: Option<String>,
}

pub(super) fn default_note_action() -> String {
    "add".to_owned()
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct ItemNoteOutput {
    pub(super) item: String,
    pub(super) action: String,
    pub(super) locked: bool,
    pub(super) notes: Vec<AgentNoteOutput>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ItemsSearchInput {
    #[serde(default)]
    #[schemars(
        description = "Optional project query. Matches exact or partial project names, natural-language phrases containing the project name, or keywords in saved agentNotes, descriptions, and folders. Exact case-insensitive name matches win."
    )]
    pub(super) query: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct ItemsSearchOutput {
    pub(super) items: Vec<ItemOutput>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct ItemOutput {
    pub(super) name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(super) item_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(super) description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) agent_notes: Vec<AgentNoteOutput>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub(super) agent_notes_locked: bool,
    pub(super) modules: Vec<ItemModuleOutput>,
    pub(super) actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) passkeys: Vec<crate::passkey::PasskeySummary>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct ItemModuleOutput {
    pub(super) kind: String,
    pub(super) name: String,
    pub(super) configured: bool,
    pub(super) agent_visible: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) value: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct CredentialFillOutput {
    pub(super) target: String,
    pub(super) module: String,
    pub(super) submitted: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct OkOutput {
    pub(super) ok: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SshRunInput {
    #[serde(default)]
    #[schemars(
        description = "Optional OpenKeylet project name, or an unambiguous natural-language phrase containing it. Omit it after this MCP session selected a compatible project, or when exactly one enabled project stores a password or private key."
    )]
    pub(super) item: String,
    #[serde(default)]
    #[schemars(
        description = "Optional SSH host override. Omit it to use the host saved in the OpenKeylet project."
    )]
    pub(super) host: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional SSH port override. Omit it to use the saved port, or port 22 when the project has no port."
    )]
    pub(super) port: Option<u16>,
    #[serde(default)]
    #[schemars(
        description = "Optional SSH username override. Omit it to use the encrypted username saved in the OpenKeylet project."
    )]
    pub(super) username: Option<String>,
    #[schemars(
        description = "One command to execute. Modules (secret or public) may be referenced as {{openkeylet:module}} or {{openkeylet:ItemName/module}} (shell-quoted) or {{openkeylet-raw:module}} / {{openkeylet-raw:ItemName/module}} (unquoted raw insertion inside double-quoted strings or connection URLs)."
    )]
    pub(super) command: String,
    #[serde(default)]
    #[schemars(
        description = "Optional text written directly to the remote command's standard input. Supports {{openkeylet:module}} and {{openkeylet:ItemName/module}} placeholders."
    )]
    pub(super) stdin: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional remote working directory. Supports {{openkeylet:module}} and {{openkeylet:ItemName/module}} placeholders."
    )]
    pub(super) cwd: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional execution timeout in seconds. Omit or use 0 for no command deadline."
    )]
    pub(super) timeout_seconds: Option<u64>,
    #[serde(default)]
    #[schemars(
        description = "Optional environment-variable mapping from variable name to any module in item or cross-item 'ItemName/module'. OpenKeylet injects each value into the remote command environment and redacts secrets from output without returning them to the caller."
    )]
    pub(super) secret_env: HashMap<String, String>,
    #[serde(default)]
    #[schemars(
        description = "Optional per-stream stdout/stderr cap in bytes (head+tail truncation). Defaults to 524288 (512 KiB); pass 0 for unlimited."
    )]
    pub(super) max_output_bytes: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SshUploadInput {
    #[serde(default)]
    #[schemars(
        description = "Optional OpenKeylet project name, or an unambiguous natural-language phrase containing it. Omit it after this MCP session selected a compatible project, or when exactly one enabled project stores a password or private key."
    )]
    pub(super) item: String,
    #[serde(default)]
    #[schemars(
        description = "Optional SSH host override. Omit it to use the host saved in the OpenKeylet project."
    )]
    pub(super) host: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional SSH port override. Omit it to use the saved port, or port 22 when the project has no port."
    )]
    pub(super) port: Option<u16>,
    #[serde(default)]
    #[schemars(
        description = "Optional SSH username override. Omit it to use the encrypted username saved in the OpenKeylet project."
    )]
    pub(super) username: Option<String>,
    #[schemars(
        description = "Local file or directory path on the machine running OpenKeylet. Absolute and ~/ paths are accepted; relative paths resolve from the OpenKeylet MCP process working directory. Directories are transferred recursively."
    )]
    pub(super) local_path: String,
    #[serde(default)]
    #[schemars(
        description = "Optional remote file or directory path. Omit it to upload to the SSH login directory using the local source name."
    )]
    pub(super) remote_path: String,
    #[serde(default = "default_true")]
    #[schemars(description = "Replace an existing destination file. Defaults to true.")]
    pub(super) overwrite: bool,
    #[serde(default)]
    #[schemars(
        description = "Optional transfer timeout in seconds. Omit or use 0 for no total deadline."
    )]
    pub(super) timeout_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SshDownloadInput {
    #[serde(default)]
    #[schemars(
        description = "Optional OpenKeylet project name, or an unambiguous natural-language phrase containing it. Omit it after this MCP session selected a compatible project, or when exactly one enabled project stores a password or private key."
    )]
    pub(super) item: String,
    #[serde(default)]
    #[schemars(
        description = "Optional SSH host override. Omit it to use the host saved in the OpenKeylet project."
    )]
    pub(super) host: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional SSH port override. Omit it to use the saved port, or port 22 when the project has no port."
    )]
    pub(super) port: Option<u16>,
    #[serde(default)]
    #[schemars(
        description = "Optional SSH username override. Omit it to use the encrypted username saved in the OpenKeylet project."
    )]
    pub(super) username: Option<String>,
    #[schemars(
        description = "Remote file or directory path on the SSH host. Directories are transferred recursively."
    )]
    pub(super) remote_path: String,
    #[serde(default)]
    #[schemars(
        description = "Optional local file or directory path. Omit it to save in the OpenKeylet MCP process working directory using the remote source name."
    )]
    pub(super) local_path: String,
    #[serde(default = "default_true")]
    #[schemars(description = "Replace an existing destination file. Defaults to true.")]
    pub(super) overwrite: bool,
    #[serde(default)]
    #[schemars(
        description = "Optional transfer timeout in seconds. Omit or use 0 for no total deadline."
    )]
    pub(super) timeout_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct HttpSendInput {
    #[serde(default)]
    #[schemars(
        description = "Optional OpenKeylet project name, or an unambiguous natural-language phrase containing it. Omit it after this MCP session has selected a compatible project, or when exactly one compatible project exists."
    )]
    pub(super) item: String,
    #[serde(default)]
    #[schemars(
        description = "Optional absolute URL or path relative to the project's saved service URL. Omit to request the saved service URL itself. An item without a saved service URL requires an absolute URL; an item with a saved service URL or website rules only accepts a URL on that origin or matching a rule."
    )]
    pub(super) url: String,
    #[serde(default = "default_http_method")]
    #[schemars(description = "HTTP method. Defaults to GET.")]
    pub(super) method: String,
    #[serde(default)]
    #[schemars(description = "Query parameters appended to the URL.")]
    pub(super) query: HashMap<String, Value>,
    #[serde(default)]
    #[schemars(description = "Non-authentication request headers.")]
    pub(super) headers: HashMap<String, String>,
    #[serde(default)]
    #[schemars(
        description = "Optional request body. Objects, arrays, numbers, and booleans are encoded as JSON; a string is sent directly as text."
    )]
    pub(super) body: Option<Value>,
    #[serde(default)]
    #[schemars(description = "Optional URL-encoded form fields. Array values repeat a field.")]
    pub(super) form: HashMap<String, Value>,
    #[serde(default)]
    #[schemars(description = "Optional multipart file uploads from local paths.")]
    pub(super) files: Vec<crate::exec::ApiUploadFile>,
    #[serde(default)]
    #[schemars(description = "Optional Base64-encoded raw request body.")]
    pub(super) body_base64: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional aliases from a placeholder name to a module or cross-item 'ItemName/module'. Usually omit this map and write {{openkeylet:module}} or {{openkeylet:ItemName/module}} directly. OpenKeylet substitutes and redacts values locally."
    )]
    pub(super) secret_bindings: HashMap<String, String>,
    #[serde(default)]
    #[schemars(
        description = "Optional request timeout in seconds. Omit or use 0 for no total deadline."
    )]
    pub(super) timeout_seconds: Option<u64>,
    #[serde(default)]
    #[schemars(
        description = "Optional in-context response-body limit in bytes. Omit or use 0 for no limit. Not used when saveResponseTo is set; very large responses may instead be streamed directly to a file."
    )]
    pub(super) max_response_bytes: Option<usize>,
    #[serde(default)]
    #[schemars(
        description = "Optional local file path for streaming the complete response body without the in-context size limit. Absolute and ~/ paths are accepted; relative paths resolve from the OpenKeylet MCP process working directory. Parent directories are created automatically."
    )]
    pub(super) save_response_to: Option<String>,
    #[serde(default = "default_true")]
    #[schemars(
        description = "Replace an existing response file. Defaults to true and only applies with saveResponseTo."
    )]
    pub(super) overwrite_response_file: bool,
    #[serde(default)]
    #[schemars(
        description = "Allow invalid/self-signed TLS certificates (e.g. internal Proxmox, Harbor, or local Kubernetes APIs). Defaults to false."
    )]
    pub(super) insecure: bool,
    #[serde(default)]
    #[schemars(
        description = "Follow HTTP 3xx redirects. Defaults to true (auth headers and query secrets are stripped on cross-origin redirects, and a redirect that would re-send a secret-bearing body to another origin is returned unfollowed). Set false to inspect redirect Location headers directly."
    )]
    pub(super) follow_redirects: Option<bool>,
    #[serde(default)]
    #[schemars(
        description = "Optional mapping from vault field name to JSON path (e.g. {\"accessToken\": \"$.access_token\"} or {\"token\": \"data.token\"}). Extracts matching values locally from a JSON response, stores them encrypted into the target item, and replaces them in the returned body with [CAPTURED:{{openkeylet:field}}]. If any path matches nothing, or the body is not JSON, the body is withheld and captureMissing and jsonPaths (key paths, no values) are returned instead."
    )]
    pub(super) capture_secrets: HashMap<String, String>,
}

pub(super) fn default_http_method() -> String {
    "GET".to_owned()
}

pub(super) fn default_true() -> bool {
    true
}

pub(super) fn default_shell_secret_literal(value: &str) -> String {
    #[cfg(windows)]
    {
        format!("'{}'", value.replace('\'', "''"))
    }
    #[cfg(not(windows))]
    {
        crate::exec::shell_quote(value)
    }
}

pub(super) fn default_terminal_program() -> String {
    #[cfg(windows)]
    {
        "powershell.exe".to_owned()
    }
    #[cfg(not(windows))]
    {
        std::env::var("SHELL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "/bin/sh".to_owned())
    }
}

/// Arguments for the default shell when the agent passes none. PSReadLine saves typed
/// commands, which may carry substituted secrets, to a history file, and unlike POSIX shells
/// it has no environment variable to turn that off.
pub(super) fn default_terminal_args() -> Vec<String> {
    #[cfg(windows)]
    {
        vec![
            "-NoExit".to_owned(),
            "-Command".to_owned(),
            "try { Set-PSReadLineOption -HistorySaveStyle SaveNothing } catch {}".to_owned(),
        ]
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

pub(super) fn submitted_terminal_line(command: &str) -> String {
    if command.ends_with('\n') || command.ends_with('\r') {
        return command.to_owned();
    }
    #[cfg(windows)]
    let newline = "\r\n";
    #[cfg(not(windows))]
    let newline = "\n";
    format!("{command}{newline}")
}

pub(super) fn transfer_file_name(path: &str, label: &str) -> Result<String, String> {
    let trimmed = path.trim().trim_end_matches(['/', '\\']);
    let name = trimmed
        .rsplit(['/', '\\'])
        .next()
        .filter(|name| !name.is_empty() && !matches!(*name, "." | ".."))
        .ok_or_else(|| format!("Could not use {label} to derive a filename"))?;
    Ok(name.to_owned())
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CredentialFillInput {
    #[serde(default)]
    #[schemars(
        description = "Optional OpenKeylet project name, or an unambiguous natural-language phrase containing it. Omit it after this MCP session or terminal has selected a compatible project, or when exactly one project supports credential filling."
    )]
    pub(super) item: String,
    #[serde(default)]
    #[schemars(
        description = "Optional module name or common phrase such as password, API key, private key, or verification code. Omit it when the project has one configured secret, or mention the module in the item phrase."
    )]
    pub(super) module: String,
    #[serde(default)]
    #[schemars(
        description = "Optional write target: browser, desktop, or terminal. Omit it to target browser when selector/fieldHint/tabId/url is provided, otherwise the current running OpenKeylet terminal if one exists, otherwise browser when Browser Bridge is enabled (never falling back to blind OS typing — pass target='desktop' explicitly to fill a native OS app when Browser Bridge is enabled), otherwise desktop."
    )]
    pub(super) target: String,
    #[serde(default)]
    #[schemars(
        description = "Optional terminal session ID. Omit it to use the current OpenKeylet terminal; provide it only to switch among multiple terminal sessions."
    )]
    pub(super) session_id: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Submit after filling. For terminal and desktop targets this presses Enter; for browser targets it submits the focused field's form when one exists. Defaults to false."
    )]
    pub(super) submit: bool,
    #[serde(default)]
    #[schemars(
        description = "Optional CSS selector on the target browser page (browser target only). Allows filling without manual focus."
    )]
    pub(super) selector: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional human-readable input hint such as 'api key', 'otp', or 'password' (browser target only). Allows filling without manual focus."
    )]
    pub(super) field_hint: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional browser tab ID from browser_inspect (browser target only)."
    )]
    pub(super) tab_id: Option<i64>,
    #[serde(default)]
    #[schemars(
        description = "Optional browser tab URL prefix or substring to target an open tab (browser target only)."
    )]
    pub(super) url: Option<String>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BrowserInspectInput {
    #[serde(default)]
    #[schemars(description = "Optional browser tab ID to inspect. Omit to inspect the active web tab.")]
    pub(super) tab_id: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Optional URL prefix or substring to pick an open browser tab.")]
    pub(super) url: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BrowserOpenInput {
    #[schemars(description = "HTTP or HTTPS URL to open in the paired browser.")]
    pub(super) url: String,
    #[serde(default)]
    #[schemars(description = "Optional existing browser tab ID to navigate. When provided and newTab is omitted, navigates this tab instead of creating a new one.")]
    pub(super) tab_id: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Open in a new tab (defaults to true unless tabId is specified). Set false to navigate tabId or the active tab.")]
    pub(super) new_tab: Option<bool>,
    #[serde(default)]
    #[schemars(description = "Optional timeout in milliseconds (0-25000) to wait for page load completion. Defaults to 15000.")]
    pub(super) wait_ms: Option<u64>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct BrowserOpenOutput {
    pub(super) tab_id: i64,
    pub(super) url: String,
    pub(super) origin: String,
    pub(super) title: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BrowserFillLoginInput {
    #[serde(default)]
    #[schemars(
        description = "Optional OpenKeylet item name. Omit to automatically match an enabled login item for the active browser tab's URL/origin."
    )]
    pub(super) item: String,
    #[serde(default)]
    #[schemars(
        description = "Also fill the current 6-digit TOTP code into any OTP/2FA input (supports single input or split 6-digit boxes). Automatically enabled on OTP-only verification steps when the item has TOTP configured; defaults to false on password pages."
    )]
    pub(super) include_totp: bool,
    #[serde(default)]
    #[schemars(description = "Submit the login form or click its sign-in/continue button after filling. Defaults to false.")]
    pub(super) submit: bool,
    #[serde(default)]
    #[schemars(description = "Optional browser tab ID from browser_inspect.")]
    pub(super) tab_id: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Optional URL prefix or substring to select an open browser tab.")]
    pub(super) url: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BrowserFillPersonalInput {
    #[serde(default)]
    #[schemars(description = "OpenKeylet card or identity item name. Omit when only one enabled card/identity exists.")]
    pub(super) item: String,
    #[serde(default)]
    #[schemars(description = "Optional browser tab ID from browser_inspect.")]
    pub(super) tab_id: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Optional URL prefix or substring to select an open browser tab.")]
    pub(super) url: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BrowserClickInput {
    #[serde(default)]
    #[schemars(description = "Optional CSS selector of the button, link, checkbox, radio, or label to click.")]
    pub(super) selector: Option<String>,
    #[serde(default)]
    #[schemars(description = "Optional visible text or label (case-insensitive match, e.g. 'Sign in with a passkey', 'Next', or 'Remember me').")]
    pub(super) text: Option<String>,
    #[serde(default)]
    #[schemars(description = "Optional browser tab ID from browser_inspect.")]
    pub(super) tab_id: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Optional URL prefix or substring to select an open browser tab.")]
    pub(super) url: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BrowserPasskeyInput {
    #[serde(default)]
    #[schemars(
        description = "Optional OpenKeylet item name containing the passkey (for 'get') or existing item to attach the newly created passkey to (for 'create'). For sign-in ('get'), omit to auto-select the matching enabled passkey for the website's rpId."
    )]
    pub(super) item: String,
    #[serde(default)]
    #[schemars(description = "Optional WebAuthn operation filter: 'get' (sign in) or 'create' (register a new passkey). Omit to accept whichever operation the page invokes.")]
    pub(super) operation: Option<String>,
    #[serde(default)]
    #[schemars(description = "Optional pending passkey requestId returned by browser_inspect.")]
    pub(super) request_id: Option<String>,
    #[serde(default)]
    #[schemars(description = "Optional CSS selector of the webpage button that triggers WebAuthn (armed before clicking to avoid race conditions).")]
    pub(super) trigger_selector: Option<String>,
    #[serde(default)]
    #[schemars(description = "Optional visible text of the webpage button that triggers WebAuthn (e.g. 'Sign in with passkey'). Armed before clicking.")]
    pub(super) trigger_text: Option<String>,
    #[serde(default)]
    #[schemars(description = "Optional browser tab ID from browser_inspect.")]
    pub(super) tab_id: Option<i64>,
    #[serde(default)]
    #[schemars(description = "Optional URL prefix or substring to select an open browser tab.")]
    pub(super) url: Option<String>,
    #[serde(default)]
    #[schemars(description = "Optional timeout in seconds (1–25) to wait for the webpage to invoke navigator.credentials.get/create. Defaults to 15.")]
    pub(super) wait_seconds: Option<u64>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct BrowserLoginOutput {
    pub(super) item: String,
    pub(super) filled_fields: Vec<String>,
    pub(super) submitted: bool,
    pub(super) url: String,
    pub(super) origin: String,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct BrowserPersonalOutput {
    pub(super) item: String,
    pub(super) item_type: String,
    pub(super) filled: u64,
    pub(super) url: String,
    pub(super) origin: String,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct BrowserClickOutput {
    pub(super) clicked_text: String,
    pub(super) tag: String,
    pub(super) url: String,
    pub(super) origin: String,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct BrowserPasskeyOutput {
    pub(super) operation: String,
    pub(super) rp_id: String,
    pub(super) origin: String,
    pub(super) item_name: String,
    pub(super) user_name: String,
    pub(super) credential_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SecretWriteFileInput {
    #[serde(default)]
    #[schemars(
        description = "Optional default OpenKeylet project name, or an unambiguous natural-language phrase containing it. May be omitted when all placeholders use explicit {{openkeylet:ItemName/module}} syntax, when this MCP session selected a compatible project, or when exactly one enabled project contains usable secrets."
    )]
    pub(super) item: String,
    #[schemars(
        description = "Destination local file path (absolute, ~/ or MCP working-directory-relative). Parent directories are created automatically. Cannot target files inside OpenKeylet's own vault data directory."
    )]
    pub(super) path: String,
    #[schemars(
        description = "Template text to write, referencing secret or public modules as {{openkeylet:module}} or cross-item {{openkeylet:ItemName/module}}. OpenKeylet substitutes values locally without returning plaintext."
    )]
    pub(super) content: String,
    #[serde(default = "default_true")]
    #[schemars(
        description = "Replace an existing destination file when append is false. Defaults to true."
    )]
    pub(super) overwrite: bool,
    #[serde(default)]
    #[schemars(
        description = "Append rendered content to the end of the file instead of replacing it. Defaults to false."
    )]
    pub(super) append: bool,
    #[serde(default)]
    #[schemars(
        description = "Optional aliases mapping short placeholder names to modules in item or cross-item 'ItemName/module'."
    )]
    pub(super) secret_bindings: HashMap<String, String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct SecretWriteFileOutput {
    pub(super) path: String,
    pub(super) bytes_written: usize,
    pub(super) modules_used: Vec<String>,
    pub(super) appended: bool,
    pub(super) warning: String,
}

pub(super) const RENDERED_FILE_WARNING: &str = "This file now holds plaintext secrets: do not read it back, print, diff, or commit it. Next time prefer secretEnv or `openkeylet run --env-file`.";
pub(super) const INGESTED_FILE_WARNING: &str = "The source file still holds plaintext secrets: do not read it back, print, diff, or commit it. Use the placeholders instead.";

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DraftModuleSpec {
    #[schemars(
        description = "Module kind: host, port, url, username, password, apiCredential, privateKey, passphrase, totp, or customSecret."
    )]
    pub(super) kind: String,
    #[serde(default)]
    #[schemars(description = "Required field label when kind is customSecret.")]
    pub(super) name: String,
    #[serde(default)]
    #[schemars(
        description = "Public value for host, port, url (or non-secret SSH login username). Secret kinds (password, apiCredential, privateKey, passphrase, totp, customSecret) must leave value empty."
    )]
    pub(super) value: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DraftPrepareInput {
    #[schemars(description = "Display name for the prepared vault item draft.")]
    pub(super) name: String,
    #[serde(default)]
    #[schemars(description = "Item type: login, ssh, api, card, identity, secureNote, or custom.")]
    pub(super) item_type: String,
    #[serde(default)]
    pub(super) folder: String,
    #[serde(default)]
    pub(super) description: String,
    #[serde(default)]
    pub(super) host: String,
    #[serde(default)]
    pub(super) port: Option<u16>,
    #[serde(default)]
    pub(super) url: String,
    #[serde(default)]
    pub(super) username: String,
    #[serde(default)]
    #[schemars(
        description = "Additional module slots (e.g. password, apiCredential, privateKey, totp, or customSecret fields) for the owner to fill in OpenKeylet."
    )]
    pub(super) modules: Vec<DraftModuleSpec>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct DraftPrepareOutput {
    pub(super) draft_id: String,
    pub(super) name: String,
    pub(super) item_type: String,
    pub(super) pending_secret_fields: Vec<String>,
    pub(super) next_step: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CreateItemSpec {
    pub(super) name: String,
    #[serde(default)]
    pub(super) item_type: String,
    #[serde(default)]
    pub(super) folder: String,
    #[serde(default)]
    pub(super) description: String,
    #[serde(default)]
    pub(super) host: String,
    #[serde(default)]
    pub(super) port: Option<u16>,
    #[serde(default)]
    pub(super) url: String,
    #[serde(default)]
    pub(super) username: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SecretGenerateInput {
    #[serde(default)]
    #[schemars(
        description = "Existing OpenKeylet item name/ID to store the generated secret into. Omit if using createItem or the current session item."
    )]
    pub(super) item: String,
    #[serde(default)]
    #[schemars(description = "Optional metadata to create a brand-new enabled vault item.")]
    pub(super) create_item: Option<CreateItemSpec>,
    #[serde(default = "default_password_field")]
    #[schemars(
        description = "Target secret field name (e.g. password, apiCredential, passphrase, or a custom field name like DB_PASSWORD or JWT_SECRET). Defaults to password."
    )]
    pub(super) field: String,
    #[serde(default = "default_password_format")]
    #[schemars(description = "Secret format: password (default), hex, or base64url.")]
    pub(super) format: String,
    #[serde(default = "default_secret_length")]
    #[schemars(
        description = "Length of generated secret (8-128 for password; 16-128 characters for hex/base64url). Defaults to 24."
    )]
    pub(super) length: usize,
    #[serde(default = "default_true")]
    pub(super) uppercase: bool,
    #[serde(default = "default_true")]
    pub(super) lowercase: bool,
    #[serde(default = "default_true")]
    pub(super) digits: bool,
    #[serde(default = "default_true")]
    pub(super) symbols: bool,
    #[serde(default)]
    #[schemars(
        description = "Allow overwriting an already-configured secret field on an existing item. Defaults to false."
    )]
    pub(super) overwrite: bool,
}

pub(super) fn default_password_field() -> String {
    "password".to_owned()
}

pub(super) fn default_password_format() -> String {
    "password".to_owned()
}

pub(super) fn default_secret_length() -> usize {
    24
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct SecretGenerateOutput {
    pub(super) item_id: String,
    pub(super) item_name: String,
    pub(super) field: String,
    pub(super) placeholder: String,
    pub(super) length: usize,
    pub(super) format: String,
    pub(super) created_item: bool,
    pub(super) overwritten: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SshKeygenInput {
    #[serde(default)]
    #[schemars(description = "Name for a new SSH item (omit if attaching to an existing item).")]
    pub(super) name: String,
    #[serde(default)]
    #[schemars(description = "Optional existing item name/ID to attach the new private key to.")]
    pub(super) item: String,
    #[serde(default)]
    pub(super) host: String,
    #[serde(default)]
    pub(super) port: Option<u16>,
    #[serde(default)]
    pub(super) username: String,
    #[serde(default)]
    #[schemars(description = "Public key comment, e.g. deploy@openkeylet.")]
    pub(super) comment: String,
    #[serde(default)]
    pub(super) folder: String,
    #[serde(default)]
    pub(super) description: String,
    #[serde(default)]
    #[schemars(
        description = "Allow replacing an existing privateKey on the target item. Defaults to false."
    )]
    pub(super) overwrite: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct SshKeygenOutput {
    pub(super) item_id: String,
    pub(super) item_name: String,
    pub(super) key_type: String,
    pub(super) public_key: String,
    pub(super) fingerprint: String,
    pub(super) private_key_stored: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SecretIngestFileInput {
    #[schemars(
        description = "Local file path (.env or SSH private key PEM) to ingest directly into OpenKeylet without returning plaintext to the model. Refuses paths inside OpenKeylet's own vault directory."
    )]
    pub(super) path: String,
    #[serde(default)]
    #[schemars(description = "Name for a new vault item (omit if updating an existing item).")]
    pub(super) name: String,
    #[serde(default)]
    #[schemars(description = "Optional existing vault item name/ID to merge ingested secrets into.")]
    pub(super) item: String,
    #[serde(default = "default_auto_format")]
    #[schemars(description = "File format: auto (default), env, or privateKey.")]
    pub(super) format: String,
    #[serde(default)]
    pub(super) folder: String,
    #[serde(default)]
    pub(super) description: String,
    #[serde(default)]
    #[schemars(description = "Allow overwriting existing fields when updating an item. Defaults to false.")]
    pub(super) overwrite: bool,
    #[serde(default)]
    #[schemars(
        description = "Optional output path to write a secret-free template file with {{openkeylet:KEY}} placeholders (for .env files)."
    )]
    pub(super) seal_template_path: Option<String>,
    #[serde(default)]
    #[schemars(description = "Allow overwriting sealTemplatePath if it already exists. Defaults to false.")]
    pub(super) overwrite_template: bool,
}

pub(super) fn default_auto_format() -> String {
    "auto".to_owned()
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct SecretIngestFileOutput {
    pub(super) item_id: String,
    pub(super) item_name: String,
    pub(super) item_type: String,
    pub(super) ingested_keys: Vec<String>,
    pub(super) placeholders: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) template_path: Option<String>,
    /// Lines the template could not seal and replaced with a comment, so the caller
    /// knows the template is not a complete stand-in for the source file.
    #[serde(skip_serializing_if = "is_zero")]
    pub(super) template_removed_lines: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) template_removed_keys: Vec<String>,
    pub(super) warning: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TerminalStartInput {
    #[serde(default)]
    #[schemars(
        description = "Optional OpenKeylet project name or natural-language phrase. Pass it once to bind this terminal session, including when the first command has no secret; later terminal_write calls can then omit item. May be omitted when all placeholders and secretEnv values use explicit 'ItemName/module' syntax."
    )]
    pub(super) item: String,
    #[serde(default)]
    #[schemars(
        description = "Optional program name or path selected by the agent. Omit it to start PowerShell on Windows, or $SHELL with a /bin/sh fallback on macOS and Linux. Native executables start directly; Windows .cmd and .bat scripts use cmd.exe."
    )]
    pub(super) program: String,
    #[serde(default)]
    #[schemars(
        description = "Arguments passed as individual argv values. Supports {{openkeylet:module}} and cross-item {{openkeylet:ItemName/module}} placeholders."
    )]
    pub(super) args: Vec<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional working directory. Absolute and ~/ paths are accepted; relative paths resolve from the OpenKeylet MCP process working directory. Supports {{openkeylet:module}} and {{openkeylet:ItemName/module}} placeholders."
    )]
    pub(super) cwd: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional first line submitted immediately after the terminal starts. When program is omitted, this runs as a command in the platform's default shell. Supports {{openkeylet:module}} / {{openkeylet:ItemName/module}} (shell-quoted) and {{openkeylet-raw:module}} / {{openkeylet-raw:ItemName/module}} (unquoted raw insertion)."
    )]
    pub(super) command: String,
    #[serde(default)]
    #[schemars(
        description = "Optional environment-variable mapping from variable name to a module name or cross-item 'ItemName/module'. OpenKeylet injects each value into the child process and redacts secrets from terminal output without returning them to the caller."
    )]
    pub(super) secret_env: HashMap<String, String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TerminalRunInput {
    #[serde(default)]
    #[schemars(
        description = "Optional OpenKeylet project name or natural-language phrase. Omit it when all placeholders and secretEnv values use explicit 'ItemName/module' syntax, after this MCP session selected a compatible project, or when the command does not use a module."
    )]
    pub(super) item: String,
    #[schemars(
        description = "Shell command to run to completion. Modules (secret or public) may be referenced as {{openkeylet:module}} or {{openkeylet:ItemName/module}} (shell-quoted), or {{openkeylet-raw:module}} / {{openkeylet-raw:ItemName/module}} (unquoted raw insertion inside double-quoted headers or URLs)."
    )]
    pub(super) command: String,
    #[serde(default)]
    #[schemars(
        description = "Optional text written directly to the command's standard input. Supports {{openkeylet:module}} and {{openkeylet:ItemName/module}} placeholders."
    )]
    pub(super) stdin: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional working directory. Absolute, ~/ and MCP-session-relative paths are accepted. Supports {{openkeylet:module}} and {{openkeylet:ItemName/module}} placeholders."
    )]
    pub(super) cwd: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Optional execution timeout in seconds. Omit or use 0 for no command deadline."
    )]
    pub(super) timeout_seconds: Option<u64>,
    #[serde(default)]
    #[schemars(
        description = "Optional environment-variable mapping from variable name to a module or cross-item 'ItemName/module'. OpenKeylet injects and redacts secrets locally."
    )]
    pub(super) secret_env: HashMap<String, String>,
    #[serde(default)]
    #[schemars(
        description = "Optional per-stream stdout/stderr cap in bytes (head+tail truncation). Defaults to 524288 (512 KiB); pass 0 for unlimited."
    )]
    pub(super) max_output_bytes: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TerminalSessionInput {
    #[serde(default)]
    #[schemars(
        description = "Optional session ID returned by terminal_start. Omit it to use the most recently started or explicitly used terminal in this MCP session."
    )]
    pub(super) session_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TerminalReadInput {
    #[serde(default)]
    #[schemars(
        description = "Optional session ID returned by terminal_start. Omit it to read the current terminal for this MCP session."
    )]
    pub(super) session_id: String,
    #[serde(default)]
    #[schemars(
        description = "Optional maximum seconds to wait. Omit it for an unlimited wait when until is provided, or for an immediate read when until is absent."
    )]
    pub(super) wait_seconds: Option<u64>,
    #[serde(default)]
    #[schemars(
        description = "Optional output substring to wait for. OpenKeylet accumulates output until this text appears or the process exits. Omit waitSeconds for no OpenKeylet deadline, or set it to bound the wait."
    )]
    pub(super) until: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TerminalWriteInput {
    #[serde(default)]
    #[schemars(
        description = "Optional OpenKeylet project name or natural-language phrase used when text contains a {{openkeylet:module}} placeholder. Omit it when using explicit {{openkeylet:ItemName/module}}, when terminal_start or an earlier write already bound this session, or when exactly one enabled project contains usable secrets."
    )]
    pub(super) item: String,
    #[serde(default)]
    #[schemars(
        description = "Optional session ID returned by terminal_start. Omit it to write to the current terminal for this MCP session."
    )]
    pub(super) session_id: String,
    #[schemars(
        description = "Interactive terminal input. A module may be inserted as raw input with {{openkeylet:module}} or {{openkeylet:ItemName/module}}. OpenKeylet redacts any echoed secrets from later terminal output."
    )]
    pub(super) text: String,
    #[serde(default)]
    #[schemars(
        description = "Press Enter after text. OpenKeylet uses the correct newline for the current platform and avoids adding a second newline when text already ends with one. Defaults to false."
    )]
    pub(super) submit: bool,
}

