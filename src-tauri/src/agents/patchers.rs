use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EntryState {
    Available,
    Registered,
    Stale,
    Conflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InstructionState {
    Current,
    Missing,
    Conflict,
}

pub(super) fn supports_managed_instruction(client_id: &str) -> bool {
    matches!(
        client_id,
        "codex" | "claude-code" | "opencode" | "antigravity" | "deepseek-harness"
    )
}

pub(super) fn apply_entry_state(status: &mut AgentClientStatus, state: EntryState) {
    match state {
        EntryState::Available => {
            status.state = "available".to_owned();
            status.can_register = true;
            status.message = "Can connect to OpenKeylet".to_owned();
        }
        EntryState::Registered => {
            status.state = "registered".to_owned();
            status.can_register = false;
            status.can_remove = true;
            status.message = "OpenKeylet connected".to_owned();
        }
        EntryState::Stale => {
            status.state = "stale".to_owned();
            status.can_register = false;
            status.can_repair = true;
            status.can_remove = true;
            status.message = "OpenKeylet path, arguments, or global rules need updating".to_owned();
        }
        EntryState::Conflict => {
            status.state = "conflict".to_owned();
            status.can_register = false;
            status.can_repair = true;
            status.message = "An openkeylet configuration with the same name already exists, but its contents differ".to_owned();
        }
    }
}

pub(super) fn with_legacy_state(state: EntryState, has_legacy: bool) -> EntryState {
    if has_legacy && state != EntryState::Conflict {
        EntryState::Stale
    } else {
        state
    }
}

pub(super) fn owned_toml_entry(entry: &Item, executable: &Path) -> bool {
    entry
        .as_table_like()
        .and_then(|entry| entry.get("command"))
        .and_then(Item::as_str)
        .is_some_and(|command| {
            is_openkeylet_command(command) || same_path(Path::new(command), executable)
        })
}

pub(super) fn owned_json_entry(entry: &JsonValue, executable: &Path) -> bool {
    entry
        .get("command")
        .and_then(|command| {
            command
                .as_str()
                .or_else(|| command.as_array()?.first()?.as_str())
        })
        .is_some_and(|command| {
            is_openkeylet_command(command) || same_path(Path::new(command), executable)
        })
}

pub(super) fn legacy_json_paths(client_id: &str) -> &'static [&'static str] {
    if uses_mcp_servers(client_id) {
        &["/mcpServers/kru"]
    } else {
        &["/mcp/kru", "/mcp/servers/kru"]
    }
}

pub(super) fn uses_mcp_servers(client_id: &str) -> bool {
    matches!(client_id, "claude-code" | "cursor" | "antigravity")
}

pub(super) fn validate_json_client_config(client_id: &str, document: &JsonValue) -> Result<()> {
    if !document.is_object() {
        bail!("Agent JSON configuration must be an object; no changes were made");
    }
    if uses_mcp_servers(client_id)
        && document
            .get("mcpServers")
            .is_some_and(|servers| !servers.is_object())
    {
        bail!("Agent mcpServers configuration must be an object; no changes were made");
    }
    Ok(())
}

pub(super) fn json_to_cst(value: &JsonValue) -> CstInputValue {
    match value {
        JsonValue::Null => CstInputValue::Null,
        JsonValue::Bool(value) => CstInputValue::Bool(*value),
        JsonValue::Number(value) => CstInputValue::Number(value.to_string()),
        JsonValue::String(value) => CstInputValue::String(value.clone()),
        JsonValue::Array(values) => CstInputValue::Array(values.iter().map(json_to_cst).collect()),
        JsonValue::Object(values) => CstInputValue::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), json_to_cst(value)))
                .collect(),
        ),
    }
}

pub(super) fn classify_command(command: &str, args: &[String], executable: &Path) -> EntryState {
    if same_path(Path::new(command), executable) && args == ["mcp", "stdio"] {
        EntryState::Registered
    } else if is_openkeylet_command(command) {
        EntryState::Stale
    } else {
        EntryState::Conflict
    }
}

#[derive(Debug, Default)]
pub(super) struct DshBlockInfo {
    pub(super) id: Option<String>,
    pub(super) name: Option<String>,
    pub(super) server_name: Option<String>,
    pub(super) transport: Option<String>,
    pub(super) command: Option<String>,
    pub(super) args: Vec<String>,
}

pub(super) fn parse_cordis_patch_blocks(text: &str) -> Result<(String, Vec<String>)> {
    let normalized = text.replace("\r\n", "\n");
    let mut header_lines = Vec::new();
    let mut blocks: Vec<Vec<String>> = Vec::new();
    for line in normalized.lines() {
        let trimmed = line.trim();
        if blocks.is_empty() {
            if trimmed.is_empty() || trimmed.starts_with('#') {
                header_lines.push(line.to_owned());
                continue;
            }
            if trimmed == "[]" {
                continue;
            }
            if line.starts_with("- ") || line == "-" {
                blocks.push(vec![line.to_owned()]);
                continue;
            }
            bail!(
                "DeepSeek Harness cordis.patch.yml must be a top-level YAML list; no changes were made"
            );
        } else if line.starts_with("- ") || line == "-" {
            blocks.push(vec![line.to_owned()]);
        } else {
            blocks.last_mut().unwrap().push(line.to_owned());
        }
    }
    let header = header_lines.join("\n").trim_end_matches('\n').to_owned();
    let blocks = blocks
        .into_iter()
        .map(|lines| lines.join("\n").trim_end_matches('\n').to_owned())
        .collect();
    Ok((header, blocks))
}

pub(super) fn unquote_yaml_scalar(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        if let Ok(parsed) = serde_json::from_str::<String>(trimmed) {
            return parsed;
        }
        return trimmed[1..trimmed.len() - 1].to_owned();
    }
    if trimmed.starts_with('\'') && trimmed.ends_with('\'') && trimmed.len() >= 2 {
        return trimmed[1..trimmed.len() - 1].replace("''", "'");
    }
    trimmed.to_owned()
}

pub(super) fn parse_yaml_inline_list(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    let Some(inner) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) else {
        return Vec::new();
    };
    if inner.trim().is_empty() {
        return Vec::new();
    }
    inner
        .split(',')
        .map(unquote_yaml_scalar)
        .filter(|s| !s.is_empty())
        .collect()
}

pub(super) fn inspect_dsh_block(block: &str) -> DshBlockInfo {
    let mut info = DshBlockInfo::default();
    let mut in_config = false;
    let mut config_indent = 0usize;
    let mut in_args = false;
    let mut args_indent = 0usize;

    for raw_line in block.lines() {
        let line = raw_line.trim_end();
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if in_args && indent <= args_indent && !trimmed.starts_with("- ") {
            in_args = false;
        }
        if in_args {
            if let Some(rest) = trimmed.strip_prefix("- ") {
                info.args.push(unquote_yaml_scalar(rest));
                continue;
            }
            in_args = false;
        }
        if in_config && indent <= config_indent && !line.starts_with("- ") {
            in_config = false;
        }

        let effective = if line.starts_with("- ") {
            &line[2..]
        } else {
            trimmed
        };
        let Some((key, val)) = effective.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let val = val.trim();
        if !in_config && indent <= 2 {
            match key {
                "id" => info.id = Some(unquote_yaml_scalar(val)),
                "name" => info.name = Some(unquote_yaml_scalar(val)),
                "config" => {
                    in_config = true;
                    config_indent = indent;
                }
                _ => {}
            }
        } else if in_config {
            match key {
                "serverName" => info.server_name = Some(unquote_yaml_scalar(val)),
                "transport" => info.transport = Some(unquote_yaml_scalar(val)),
                "command" => info.command = Some(unquote_yaml_scalar(val)),
                "args" => {
                    if val.is_empty() {
                        in_args = true;
                        args_indent = indent;
                    } else {
                        info.args = parse_yaml_inline_list(val);
                    }
                }
                _ => {}
            }
        }
    }
    info
}

pub(super) fn classify_dsh_entry(info: &DshBlockInfo, executable: &Path) -> EntryState {
    let command = info.command.as_deref().unwrap_or_default();
    let plugin_ok = info.name.as_deref() == Some(DSH_MCP_PLUGIN_NAME);
    let transport_ok = info.transport.as_deref() == Some("stdio");
    let server_ok = info.server_name.as_deref() == Some("openkeylet");
    let id_ok = info.id.as_deref() == Some(DSH_MCP_ENTRY_ID);
    let command_state = classify_command(command, &info.args, executable);
    if command_state == EntryState::Registered && plugin_ok && transport_ok && server_ok && id_ok {
        EntryState::Registered
    } else if command_state == EntryState::Conflict && !is_openkeylet_command(command) {
        EntryState::Conflict
    } else {
        EntryState::Stale
    }
}

pub(super) fn render_dsh_mcp_block(executable: &Path) -> String {
    let quoted_command = serde_json::to_string(&executable.to_string_lossy().into_owned())
        .unwrap_or_else(|_| format!("\"{}\"", executable.display()));
    format!(
        "- id: {DSH_MCP_ENTRY_ID}\n  name: \"{DSH_MCP_PLUGIN_NAME}\"\n  config:\n    serverName: openkeylet\n    transport: stdio\n    command: {quoted_command}\n    args:\n      - mcp\n      - stdio"
    )
}

pub(super) fn render_cordis_patch(header: &str, blocks: &[String]) -> String {
    let mut out = String::new();
    if !header.is_empty() {
        out.push_str(header);
        out.push('\n');
    }
    if blocks.is_empty() {
        out.push_str("[]\n");
    } else {
        out.push_str(&blocks.join("\n"));
        out.push('\n');
    }
    out
}

