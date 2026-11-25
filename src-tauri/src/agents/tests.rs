use super::*;
use tempfile::tempdir;

fn registry() -> (tempfile::TempDir, AgentRegistry) {
    let temp = tempdir().unwrap();
    let exe = temp.path().join(if cfg!(windows) {
        "openkeylet.exe"
    } else {
        "openkeylet"
    });
    fs::write(&exe, b"test").unwrap();
    let registry = AgentRegistry::isolated(exe, temp.path().to_path_buf(), vec![]);
    (temp, registry)
}

#[tokio::test]
async fn claude_registration_works_without_a_callable_cli_and_preserves_user_config() {
    let (_temp, registry) = registry();
    let path = registry.config_path("claude-code");
    let original = serde_json::json!({
        "theme": "dark",
        "oauthAccount": {"accountUuid": "test-account"},
        "projects": {"/workspace": {"mcpServers": {
            "openkeylet": {"command": "/project/openkeylet", "args": ["mcp", "stdio"]}
        }}},
        "mcpServers": {"other": {"type": "http", "url": "https://example.test/mcp"}}
    });
    fs::write(&path, serde_json::to_string_pretty(&original).unwrap()).unwrap();

    let before = registry.status("claude-code").await;
    assert_eq!(before.state, "available");
    assert!(before.can_register);
    let first = registry.mutate("claude-code", "register").await;
    assert!(first.ok, "{}", first.client.message);
    assert_eq!(first.client.state, "registered");
    let registered = fs::read_to_string(&path).unwrap();
    let value: JsonValue = serde_json::from_str(&registered).unwrap();
    assert_eq!(
        value["mcpServers"]["openkeylet"],
        serde_json::json!({
            "type": "stdio", "command": registry.executable, "args": ["mcp", "stdio"]
        })
    );
    for field in ["theme", "oauthAccount", "projects"] {
        assert_eq!(value[field], original[field]);
    }
    assert_eq!(
        value["mcpServers"]["other"],
        original["mcpServers"]["other"]
    );
    let rules = registry.claude_config_dir.join("rules/openkeylet.md");
    assert!(
        fs::read_to_string(&rules)
            .unwrap()
            .contains(OPENKEYLET_INSTRUCTION_BLOCK)
    );
    // A repeated registration is rejected without changing a working entry.
    assert!(!registry.mutate("claude-code", "register").await.ok);
    assert_eq!(fs::read_to_string(&path).unwrap(), registered);
    assert!(registry.mutate("claude-code", "remove").await.ok);
    let removed: JsonValue = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(removed, original);
    assert!(!rules.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn claude_status_and_registration_never_start_the_cli() {
    let (temp, registry) = registry();
    let cli = temp.path().join(".local/bin/claude");
    fs::create_dir_all(cli.parent().unwrap()).unwrap();
    let marker = temp.path().join("cli-was-started");
    fs::write(
        &cli,
        format!("#!/bin/sh\ntouch '{}'\nexit 1\n", marker.display()),
    )
    .unwrap();
    make_test_executable(&cli);
    assert!(registry.find_client_executable("claude-code").is_some());
    assert!(registry.status("claude-code").await.can_register);
    let result = registry.mutate("claude-code", "register").await;
    assert!(result.ok, "{}", result.client.message);
    assert_eq!(result.client.state, "registered");
    assert!(!marker.exists());
}

#[tokio::test]
async fn claude_repair_migrates_legacy_entry_and_preserves_its_environment() {
    let (_temp, registry) = registry();
    let path = registry.config_path("claude-code");
    fs::write(&path, r#"{"mcpServers":{"kru":{"command":"/old/kru","args":[],"env":{"OPENKEYLET_DATA_DIR":"/custom/vault"}},"other":{"command":"other"}}}"#).unwrap();
    assert_eq!(registry.status("claude-code").await.state, "stale");
    let result = registry.mutate("claude-code", "repair").await;
    assert!(result.ok, "{}", result.client.message);
    assert_eq!(result.client.state, "registered");
    let value: JsonValue = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert!(value.pointer("/mcpServers/kru").is_none());
    assert_eq!(
        value["mcpServers"]["openkeylet"]["env"]["OPENKEYLET_DATA_DIR"],
        "/custom/vault"
    );
    assert_eq!(value["mcpServers"]["other"]["command"], "other");
}

#[tokio::test]
async fn claude_repair_checks_arguments_and_preserves_unrelated_legacy_name() {
    let (_temp, registry) = registry();
    let path = registry.config_path("claude-code");
    let original = serde_json::json!({"mcpServers": {
        "openkeylet": {"command": registry.executable, "args": ["gui"]},
        "kru": {"command": "unrelated-tool"}
    }});
    fs::write(&path, serde_json::to_string(&original).unwrap()).unwrap();
    assert_eq!(registry.status("claude-code").await.state, "stale");
    assert!(registry.mutate("claude-code", "repair").await.ok);
    assert!(registry.mutate("claude-code", "remove").await.ok);
    let value: JsonValue = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(value["mcpServers"]["kru"], original["mcpServers"]["kru"]);
}

#[tokio::test]
async fn claude_invalid_config_is_never_replaced() {
    let (_temp, registry) = registry();
    let path = registry.config_path("claude-code");
    for original in ["{broken", "[]", r#"{"mcpServers":[]}"#] {
        fs::write(&path, original).unwrap();
        assert_eq!(registry.status("claude-code").await.state, "error");
        assert!(!registry.mutate("claude-code", "register").await.ok);
        assert!(
            registry
                .mutate_json_client("claude-code", "repair")
                .is_err()
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
    }
}

#[tokio::test]
async fn claude_custom_directory_contains_both_user_config_and_rules() {
    let (temp, mut registry) = registry();
    assert_eq!(
        resolve_claude_config(temp.path(), None),
        (
            temp.path().join(".claude.json"),
            temp.path().join(".claude")
        )
    );
    assert_eq!(
        resolve_claude_config(temp.path(), Some(PathBuf::new())),
        resolve_claude_config(temp.path(), None)
    );
    let custom = temp.path().join("custom-claude");
    (registry.claude_config, registry.claude_config_dir) =
        resolve_claude_config(temp.path(), Some(custom.clone()));
    fs::create_dir_all(&custom).unwrap();
    fs::write(custom.join(".claude.json"), "{}\n").unwrap();
    assert!(registry.mutate("claude-code", "register").await.ok);
    assert_eq!(registry.status("claude-code").await.state, "registered");
    assert!(custom.join("rules/openkeylet.md").is_file());
    assert!(!temp.path().join(".claude.json").exists());
    assert!(!temp.path().join(".claude/rules/openkeylet.md").exists());
}

#[test]
fn legacy_codex_config_is_repaired_without_touching_other_servers() {
    let (_temp, registry) = registry();
    let path = registry.config_path("codex");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "# personal config\n[mcp_servers.other]\ncommand = \"other-tool\"\n[mcp_servers.kru]\ncommand = \"/old/kru\"\nargs = [\"mcp\", \"stdio\"]\n").unwrap();
    assert_eq!(registry.inspect_codex().unwrap(), EntryState::Stale);
    registry.mutate_codex("repair").unwrap();
    assert_eq!(registry.inspect_codex().unwrap(), EntryState::Registered);
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("# personal config"));
    assert!(text.contains("mcp_servers.other"));
    assert!(!text.contains("mcp_servers.kru"));
    // The pre-repair copy holds the same secrets as the config; it must not linger.
    assert!(!fs::read_dir(path.parent().unwrap()).unwrap().any(|entry| {
        entry
            .unwrap()
            .path()
            .extension()
            .is_some_and(|extension| extension == "bak")
    }));
}

#[test]
fn legacy_json_configs_migrate_both_opencode_shapes_and_cursor() {
    for (client, input, new_pointer, old_pointer) in [
        (
            "cursor",
            r#"{"mcpServers":{"kru":{"command":"/old/kru","args":["mcp","stdio"]},"other":{"command":"other-tool"}}}"#,
            "/mcpServers/openkeylet",
            "/mcpServers/kru",
        ),
        (
            "opencode",
            r#"{"mcp":{"kru":{"type":"local","command":["/old/kru","mcp","stdio"]},"other":{"command":["other-tool"]}}}"#,
            "/mcp/openkeylet",
            "/mcp/kru",
        ),
        (
            "opencode",
            r#"{"mcp":{"servers":{"kru":{"command":["/old/kru","mcp","stdio"]},"other":{"command":["other-tool"]}}}}"#,
            "/mcp/servers/openkeylet",
            "/mcp/servers/kru",
        ),
    ] {
        let (_temp, registry) = registry();
        let path = registry.config_path(client);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, format!("// personal config\n{input}\n")).unwrap();
        assert_eq!(
            registry.inspect_json_client(client).unwrap(),
            EntryState::Stale
        );
        registry.mutate_json_client(client, "repair").unwrap();
        assert_eq!(
            registry.inspect_json_client(client).unwrap(),
            EntryState::Registered
        );
        let text = fs::read_to_string(&path).unwrap();
        let value: JsonValue = parse_to_serde_value(&text, &ParseOptions::default()).unwrap();
        assert!(value.pointer(new_pointer).is_some());
        assert!(value.pointer(old_pointer).is_none());
        assert!(text.contains("// personal config"));
        assert!(text.contains("other-tool"));
        assert!(!fs::read_dir(path.parent().unwrap()).unwrap().any(|entry| {
            entry.unwrap().file_name().to_string_lossy().ends_with(".bak")
        }));
    }
}

#[test]
fn unrelated_server_named_kru_is_preserved() {
    let (_temp, registry) = registry();
    let path = registry.config_path("codex");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "[mcp_servers.kru]\ncommand = \"unrelated-tool\"\n").unwrap();
    assert_eq!(registry.inspect_codex().unwrap(), EntryState::Available);
    registry.mutate_codex("register").unwrap();
    assert!(
        fs::read_to_string(&path)
            .unwrap()
            .contains("unrelated-tool")
    );
    let path = registry.config_path("cursor");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        r#"{"mcpServers":{"kru":{"command":"unrelated-tool"}}}"#,
    )
    .unwrap();
    registry.mutate_json_client("cursor", "register").unwrap();
    registry.mutate_json_client("cursor", "remove").unwrap();
    assert!(fs::read_to_string(path).unwrap().contains("unrelated-tool"));
}

#[test]
fn legacy_managed_rules_are_replaced_once_and_preserve_personal_rules() {
    let (_temp, registry) = registry();
    let path = registry.home.join(".claude/rules/kru.md");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, format!("# Personal rules\n\n{LEGACY_INSTRUCTION_START}\nOld rule\n{LEGACY_INSTRUCTION_END}\n")).unwrap();
    assert_eq!(
        registry.active_instruction_path("claude-code").unwrap(),
        path
    );
    registry.refresh_managed_instructions();
    registry.refresh_managed_instructions();
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.starts_with("# Personal rules"));
    assert!(!text.contains(LEGACY_INSTRUCTION_START));
    assert_eq!(text.matches(OPENKEYLET_INSTRUCTION_START).count(), 1);
    remove_managed_instruction(&path, true).unwrap();
    assert_eq!(
        fs::read_to_string(&path).unwrap().trim(),
        "# Personal rules"
    );
}

fn make_test_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions).unwrap();
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[tokio::test]
async fn codex_registration_preserves_unrelated_toml_and_is_idempotent() {
    let (_temp, registry) = registry();
    let path = registry.config_path("codex");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        "# keep\nmodel = \"gpt-test\"\n\n[mcp_servers.other]\ncommand = \"other\"\n",
    )
    .unwrap();
    let first = registry.mutate("codex", "register").await;
    assert!(first.ok, "{}", first.client.message);
    let once = fs::read_to_string(&path).unwrap();
    assert!(once.contains("# keep"));
    assert!(once.contains("mcp_servers.other"));
    assert!(once.contains("mcp_servers.openkeylet"));
    let instruction = fs::read_to_string(registry.codex_home.join("AGENTS.md")).unwrap();
    assert!(instruction.contains(OPENKEYLET_INSTRUCTION_BLOCK));
    let second = registry.mutate("codex", "register").await;
    assert!(!second.ok);
    assert_eq!(once, fs::read_to_string(&path).unwrap());
}

#[tokio::test]
async fn codex_instruction_uses_override_and_removal_preserves_user_content() {
    let (_temp, registry) = registry();
    let config = registry.config_path("codex");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(&config, "model = \"gpt-test\"\n").unwrap();
    let override_path = registry.codex_home.join("AGENTS.override.md");
    fs::write(&override_path, "# Personal rules\n").unwrap();

    assert!(registry.mutate("codex", "register").await.ok);
    let installed = fs::read_to_string(&override_path).unwrap();
    assert!(installed.starts_with("# Personal rules\n"));
    assert!(installed.contains(OPENKEYLET_INSTRUCTION_BLOCK));
    assert!(!registry.codex_home.join("AGENTS.md").exists());

    assert!(registry.mutate("codex", "remove").await.ok);
    assert_eq!(
        fs::read_to_string(&override_path).unwrap(),
        "# Personal rules\n"
    );
}

#[tokio::test]
async fn existing_codex_connection_without_global_rule_requires_repair() {
    let (_temp, registry) = registry();
    registry.mutate_codex("register").unwrap();

    let before = registry.status("codex").await;
    assert_eq!(before.state, "stale");
    assert!(before.can_repair);

    assert!(registry.mutate("codex", "repair").await.ok);
    assert_eq!(registry.status("codex").await.state, "registered");
    assert!(registry.codex_home.join("AGENTS.md").is_file());
}

#[tokio::test]
async fn existing_managed_instruction_is_refreshed_without_touching_user_content() {
    let (_temp, registry) = registry();
    let config = registry.config_path("codex");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(&config, "model = \"gpt-test\"\n").unwrap();
    assert!(registry.mutate("codex", "register").await.ok);
    let path = registry.codex_home.join("AGENTS.md");
    fs::write(
        &path,
        format!(
            "# Personal rules\n\n{OPENKEYLET_INSTRUCTION_START}\nOld OpenKeylet instruction.\n{OPENKEYLET_INSTRUCTION_END}\n"
        ),
    )
    .unwrap();

    registry.refresh_managed_instructions();
    let updated = fs::read_to_string(path).unwrap();
    assert!(updated.starts_with("# Personal rules\n"));
    assert!(updated.contains(OPENKEYLET_INSTRUCTION_BLOCK));
    assert!(!updated.contains("Old OpenKeylet instruction."));
}

#[test]
fn dedicated_rule_never_overwrites_an_unmanaged_file() {
    let temp = tempdir().unwrap();
    let path = temp.path().join("openkeylet.md");
    fs::write(&path, "user-owned rule\n").unwrap();

    let error = upsert_managed_instruction(&path, true).unwrap_err();
    assert!(error.to_string().contains("not an OpenKeylet managed rule"));
    assert_eq!(fs::read_to_string(path).unwrap(), "user-owned rule\n");
}

#[tokio::test]
async fn cursor_registration_and_removal_preserve_jsonc_comments() {
    let (_temp, registry) = registry();
    let path = registry.config_path("cursor");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "{\n  // keep\n  \"theme\": \"dark\",\n  \"mcpServers\": { \"other\": { \"command\": \"other\" } }\n}\n").unwrap();
    assert!(registry.mutate("cursor", "register").await.ok);
    let registered = fs::read_to_string(&path).unwrap();
    assert!(registered.contains("// keep"));
    assert!(registered.contains("\"other\""));
    assert!(registered.contains("\"openkeylet\""));
    assert!(registry.mutate("cursor", "remove").await.ok);
    let removed = fs::read_to_string(&path).unwrap();
    assert!(removed.contains("// keep"));
    assert!(removed.contains("\"other\""));
    assert!(!removed.contains("\"openkeylet\""));
}

#[tokio::test]
async fn conflicting_entry_is_not_overwritten_without_repair() {
    let (_temp, registry) = registry();
    let path = registry.config_path("codex");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let original = "[mcp_servers.openkeylet]\ncommand = \"not-openkeylet\"\nargs = []\n";
    fs::write(&path, original).unwrap();
    let status = registry.status("codex").await;
    assert_eq!(status.state, "conflict");
    assert!(!registry.mutate("codex", "register").await.ok);
    assert_eq!(fs::read_to_string(&path).unwrap(), original);
    assert!(registry.mutate("codex", "repair").await.ok);
    // The pre-repair copy is removed once the repaired config reads back intact.
    assert!(!fs::read_dir(path.parent().unwrap()).unwrap().any(|item| {
        item.unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".openkeylet.")
    }));
}

#[tokio::test]
async fn opencode_registration_defaults_to_v1_and_preserves_jsonc() {
    let (_temp, registry) = registry();
    let path = registry.config_path("opencode");
    assert_eq!(path.file_name().unwrap(), "opencode.jsonc");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        "{\n  // keep this comment\n  \"theme\": \"dark\",\n  \"mcp\": {}\n}\n",
    )
    .unwrap();
    assert!(registry.mutate("opencode", "register").await.ok);
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("// keep this comment"));
    assert!(text.contains("\"theme\": \"dark\""));
    let value: JsonValue = parse_to_serde_value(&text, &ParseOptions::default()).unwrap();
    assert_eq!(
        value.pointer("/mcp/openkeylet/type"),
        Some(&serde_json::json!("local"))
    );
    let command = value
        .pointer("/mcp/openkeylet/command")
        .and_then(JsonValue::as_array)
        .unwrap();
    assert_eq!(command[1], "mcp");
    assert_eq!(command[2], "stdio");
    assert_eq!(
        value.pointer("/mcp/openkeylet/enabled"),
        Some(&serde_json::json!(true))
    );
    assert!(value.pointer("/mcp/servers").is_none());
    assert!(
        fs::read_to_string(registry.opencode_instruction_dir.join("AGENTS.md"))
            .unwrap()
            .contains(OPENKEYLET_INSTRUCTION_BLOCK)
    );
    assert_eq!(registry.status("opencode").await.state, "registered");
}

#[tokio::test]
async fn opencode_registration_uses_v2_when_servers_container_exists() {
    let (_temp, registry) = registry();
    let path = registry.config_path("opencode");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        "{\n  // V2 config\n  \"mcp\": { \"servers\": {} }\n}\n",
    )
    .unwrap();
    assert!(registry.mutate("opencode", "register").await.ok);
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("// V2 config"));
    let value: JsonValue = parse_to_serde_value(&text, &ParseOptions::default()).unwrap();
    assert!(value.pointer("/mcp/openkeylet").is_none());
    assert!(value.pointer("/mcp/servers/openkeylet").is_some());
    assert!(value.pointer("/mcp/servers/openkeylet/enabled").is_none());
    assert_eq!(registry.status("opencode").await.state, "registered");
}

#[tokio::test]
async fn opencode_repair_keeps_v1_shape_and_reenables_entry() {
    let (_temp, registry) = registry();
    let path = registry.config_path("opencode");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let executable = serde_json::to_string(&registry.executable.to_string_lossy()).unwrap();
    fs::write(
        &path,
        format!(
            "{{\n  // V1 setting stays readable\n  \"mcp\": {{\n    \"openkeylet\": {{ \"type\": \"local\", \"command\": [{executable}, \"mcp\", \"stdio\"], \"enabled\": false }}\n  }}\n}}\n"
        ),
    )
    .unwrap();

    let status = registry.status("opencode").await;
    assert_eq!(status.state, "stale");
    assert!(status.can_repair);
    assert!(registry.mutate("opencode", "repair").await.ok);

    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("// V1 setting stays readable"));
    let value: JsonValue = parse_to_serde_value(&text, &ParseOptions::default()).unwrap();
    assert_eq!(
        value.pointer("/mcp/openkeylet/enabled"),
        Some(&serde_json::json!(true))
    );
    assert!(value.pointer("/mcp/servers").is_none());
    assert!(!fs::read_dir(path.parent().unwrap()).unwrap().any(|item| {
        item.unwrap()
            .file_name()
            .to_string_lossy()
            .contains("opencode.jsonc.openkeylet.")
    }));
}

#[tokio::test]
async fn opencode_remove_cleans_current_and_legacy_entries() {
    let (_temp, registry) = registry();
    let path = registry.config_path("opencode");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let executable = serde_json::to_string(&registry.executable.to_string_lossy()).unwrap();
    fs::write(
        &path,
        format!(
            "{{ \"mcp\": {{ \"openkeylet\": {{ \"command\": [{executable}, \"mcp\", \"stdio\"] }}, \"servers\": {{ \"openkeylet\": {{ \"command\": [{executable}, \"mcp\", \"stdio\"] }} }} }} }}\n"
        ),
    )
    .unwrap();

    assert_eq!(registry.status("opencode").await.state, "stale");
    assert!(registry.mutate("opencode", "remove").await.ok);
    let text = fs::read_to_string(&path).unwrap();
    let value: JsonValue = parse_to_serde_value(&text, &ParseOptions::default()).unwrap();
    assert!(value.pointer("/mcp/openkeylet").is_none());
    assert!(value.pointer("/mcp/servers/openkeylet").is_none());
}

#[tokio::test]
async fn opencode_uses_existing_json_file_when_jsonc_is_absent() {
    let (_temp, registry) = registry();
    let directory = registry.home.join(".config").join("opencode");
    fs::create_dir_all(&directory).unwrap();
    let json = directory.join("opencode.json");
    fs::write(&json, "{}\n").unwrap();

    assert_eq!(registry.config_path("opencode"), json);
    assert!(registry.mutate("opencode", "register").await.ok);
    let value: JsonValue = serde_json::from_str(&fs::read_to_string(json).unwrap()).unwrap();
    assert!(value.pointer("/mcp/openkeylet").is_some());
}

#[test]
fn codex_config_path_uses_configured_codex_home() {
    let (temp, mut registry) = registry();
    let codex_home = temp.path().join("portable-codex-home");
    assert_eq!(
        resolve_codex_home(temp.path(), Some(codex_home.clone())),
        codex_home
    );
    registry.codex_home = codex_home.clone();
    assert_eq!(
        registry.config_path("codex"),
        codex_home.join("config.toml")
    );
}

#[test]
fn config_overrides_and_xdg_paths_are_respected() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    let exact = temp.path().join("custom").join("open.jsonc");
    let directory = temp.path().join("opencode-dir");
    let xdg = temp.path().join("xdg");

    let resolved = resolve_opencode_config(
        &home,
        Some(exact.clone()),
        Some(directory.clone()),
        Some(xdg.clone()),
    );
    assert_eq!(resolved, (exact, true));

    let resolved =
        resolve_opencode_config(&home, None, Some(directory.clone()), Some(xdg.clone()));
    assert_eq!(resolved, (directory.join("opencode.jsonc"), true));

    let resolved = resolve_opencode_config(&home, None, None, Some(xdg.clone()));
    assert_eq!(resolved, (xdg.join("opencode/opencode.jsonc"), false));

    let antigravity = temp.path().join("antigravity-custom");
    assert_eq!(
        resolve_antigravity_config_dir(&home, Some(antigravity.clone())),
        antigravity
    );
    assert_eq!(
        resolve_antigravity_config_dir(&home, None),
        home.join(".gemini/config")
    );

    let dsh = temp.path().join("dsh-custom");
    assert_eq!(resolve_dsh_home(&home, Some(dsh.clone())), dsh);
    assert_eq!(resolve_dsh_home(&home, None), home.join(".dsh"));
}

#[test]
fn explicit_opencode_jsonc_path_is_not_replaced_by_a_sibling_json_file() {
    let (temp, mut registry) = registry();
    let directory = temp.path().join("explicit-opencode");
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join("opencode.json"), "{}\n").unwrap();
    let explicit = directory.join("opencode.jsonc");
    registry.opencode_config = explicit.clone();
    registry.opencode_config_explicit = true;

    assert_eq!(registry.config_path("opencode"), explicit);
}

#[tokio::test]
async fn opencode_explicit_or_existing_config_directory_allows_desktop_registration() {
    let (temp, mut registry) = registry();
    registry.opencode_config = temp.path().join("explicit").join("opencode.jsonc");
    registry.opencode_config_explicit = true;
    let explicit = registry.status("opencode").await;
    assert!(explicit.detected);
    assert!(explicit.can_register);
    assert_eq!(explicit.state, "available");

    registry.opencode_config_explicit = false;
    assert!(!registry.status("opencode").await.detected);
    fs::create_dir_all(registry.opencode_config.parent().unwrap()).unwrap();
    let desktop = registry.status("opencode").await;
    assert!(desktop.detected);
    assert!(desktop.can_register);
}

#[test]
fn common_user_bin_directories_are_scanned_by_exact_name() {
    let (temp, registry) = registry();
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    let opencode = temp
        .path()
        .join(".opencode/bin")
        .join(format!("opencode{suffix}"));
    fs::create_dir_all(opencode.parent().unwrap()).unwrap();
    fs::write(&opencode, b"test").unwrap();
    make_test_executable(&opencode);
    assert_eq!(
        registry.find_client_executable("opencode"),
        Some(normalize_path(&opencode))
    );

    let antigravity = temp
        .path()
        .join(".gemini/antigravity/bin")
        .join(format!("agy{suffix}"));
    fs::create_dir_all(antigravity.parent().unwrap()).unwrap();
    fs::write(&antigravity, b"test").unwrap();
    make_test_executable(&antigravity);
    assert_eq!(
        registry.find_client_executable("antigravity"),
        Some(normalize_path(&antigravity))
    );

    let dsh = temp
        .path()
        .join(".local/bin")
        .join(format!("dsh{suffix}"));
    fs::create_dir_all(dsh.parent().unwrap()).unwrap();
    fs::write(&dsh, b"test").unwrap();
    make_test_executable(&dsh);
    assert_eq!(
        registry.find_client_executable("deepseek-harness"),
        Some(normalize_path(&dsh))
    );

    let unrelated = temp.path().join("bin/opencode-helper.exe");
    fs::create_dir_all(unrelated.parent().unwrap()).unwrap();
    fs::write(unrelated, b"test").unwrap();
    fs::remove_file(opencode).unwrap();
    assert!(registry.find_client_executable("opencode").is_none());
}

#[tokio::test]
async fn list_preserves_stable_client_order() {
    let (_temp, registry) = registry();
    let ids = registry
        .list()
        .await
        .into_iter()
        .map(|status| status.client_id)
        .collect::<Vec<_>>();
    assert_eq!(ids, CLIENT_IDS);
}

#[tokio::test]
async fn antigravity_registration_handles_empty_config_and_managed_gemini_rules() {
    let (_temp, registry) = registry();
    let path = registry.config_path("antigravity");
    assert_eq!(path.file_name().unwrap(), "mcp_config.json");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    // Real Antigravity installations may initialize an empty 0-byte mcp_config.json.
    fs::write(&path, "").unwrap();
    let rules_path = registry.antigravity_config_dir.join("GEMINI.md");
    fs::write(&rules_path, "# My Antigravity Rules\n").unwrap();

    let before = registry.status("antigravity").await;
    assert!(before.detected);
    assert_eq!(before.state, "available");
    assert!(before.can_register);

    assert!(registry.mutate("antigravity", "register").await.ok);
    let value: JsonValue = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        value.pointer("/mcpServers/openkeylet/args"),
        Some(&serde_json::json!(["mcp", "stdio"]))
    );
    let rules = fs::read_to_string(&rules_path).unwrap();
    assert!(rules.starts_with("# My Antigravity Rules"));
    assert!(rules.contains(OPENKEYLET_INSTRUCTION_BLOCK));
    assert_eq!(registry.status("antigravity").await.state, "registered");

    assert!(registry.mutate("antigravity", "remove").await.ok);
    assert_eq!(registry.status("antigravity").await.state, "available");
    let after_rules = fs::read_to_string(&rules_path).unwrap();
    assert!(after_rules.starts_with("# My Antigravity Rules"));
    assert!(!after_rules.contains(OPENKEYLET_INSTRUCTION_START));
}

#[tokio::test]
async fn deepseek_harness_registration_repair_and_removal_preserve_cordis_patch() {
    let (_temp, registry) = registry();
    let path = registry.config_path("deepseek-harness");
    assert_eq!(path.file_name().unwrap(), "cordis.patch.yml");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let initial = "\
# DeepSeek Harness desktop profile patch
- id: custom-provider
  name: \"@deepseek-ai/dsh-provider-custom\"
  config:
token: !!js/function () { return process.env.MY_TOKEN; }
";
    fs::write(&path, initial).unwrap();
    let rules_path = registry.dsh_home.join("AGENTS.md");
    fs::write(&rules_path, "# Personal DSH rules\n").unwrap();

    let before = registry.status("deepseek-harness").await;
    assert!(before.detected);
    assert_eq!(before.state, "available");
    assert!(before.can_register);

    assert!(registry.mutate("deepseek-harness", "register").await.ok);
    assert_eq!(registry.status("deepseek-harness").await.state, "registered");
    let registered_text = fs::read_to_string(&path).unwrap();
    assert!(registered_text.contains("# DeepSeek Harness desktop profile patch"));
    assert!(registered_text.contains("!!js/function () { return process.env.MY_TOKEN; }"));
    assert!(registered_text.contains("- id: mcp-openkeylet"));
    assert!(registered_text.contains("name: \"@deepseek-ai/dsh-mcp-client\""));
    assert!(registered_text.contains("serverName: openkeylet"));
    assert!(
        fs::read_to_string(&rules_path)
            .unwrap()
            .contains(OPENKEYLET_INSTRUCTION_BLOCK)
    );

    // Stale legacy entry is migrated cleanly on repair; the temporary backup is removed.
    let stale = format!(
        "{initial}\n- id: mcp-kru\n  name: \"@deepseek-ai/dsh-mcp-client\"\n  config:\n    serverName: kru\n    transport: stdio\n    command: \"/old/kru\"\n    args:\n      - mcp\n      - stdio\n"
    );
    fs::write(&path, &stale).unwrap();
    let stale_status = registry.status("deepseek-harness").await;
    assert_eq!(stale_status.state, "stale");
    assert!(stale_status.can_repair);

    assert!(registry.mutate("deepseek-harness", "repair").await.ok);
    assert_eq!(registry.status("deepseek-harness").await.state, "registered");
    let repaired_text = fs::read_to_string(&path).unwrap();
    assert!(!repaired_text.contains("mcp-kru"));
    assert!(repaired_text.contains("- id: mcp-openkeylet"));
    assert!(repaired_text.contains("!!js/function"));
    assert!(!fs::read_dir(path.parent().unwrap()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("cordis.patch.yml.openkeylet.")
    }));

    // Removal cleans OpenKeylet entry and rules while preserving personal content.
    assert!(registry.mutate("deepseek-harness", "remove").await.ok);
    assert_eq!(registry.status("deepseek-harness").await.state, "available");
    let removed_text = fs::read_to_string(&path).unwrap();
    assert!(!removed_text.contains("mcp-openkeylet"));
    assert!(removed_text.contains("custom-provider"));
    assert!(removed_text.contains("!!js/function"));
    let after_rules = fs::read_to_string(&rules_path).unwrap();
    assert!(after_rules.starts_with("# Personal DSH rules"));
    assert!(!after_rules.contains(OPENKEYLET_INSTRUCTION_START));

    // Unrelated entry with conflicting serverName is reported as conflict and never overwritten.
    let conflict = format!(
        "{initial}\n- id: mcp-openkeylet\n  name: \"@deepseek-ai/dsh-mcp-client\"\n  config:\n    serverName: openkeylet\n    transport: stdio\n    command: \"/usr/bin/other-server\"\n"
    );
    fs::write(&path, &conflict).unwrap();
    assert_eq!(registry.status("deepseek-harness").await.state, "conflict");
    assert!(!registry.mutate("deepseek-harness", "register").await.ok);
    assert_eq!(fs::read_to_string(&path).unwrap(), conflict);
}

#[test]
fn deepseek_harness_selects_existing_profile_config() {
    let (_temp, registry) = registry();
    assert_eq!(
        registry.config_path("deepseek-harness"),
        registry.dsh_home.join("profiles/desktop/cordis.patch.yml")
    );

    let web_patch = registry.dsh_home.join("profiles/web/cordis.patch.yml");
    fs::create_dir_all(web_patch.parent().unwrap()).unwrap();
    fs::write(&web_patch, "[]\n").unwrap();
    assert_eq!(registry.config_path("deepseek-harness"), web_patch);

    let desktop_patch = registry.dsh_home.join("profiles/desktop/cordis.patch.yml");
    fs::create_dir_all(desktop_patch.parent().unwrap()).unwrap();
    fs::write(&desktop_patch, "[]\n").unwrap();
    assert_eq!(registry.config_path("deepseek-harness"), desktop_patch);
}

#[test]
fn managed_instruction_prefers_environment_injection_over_plaintext_files() {
    for expected in [
        "`secretEnv`",
        "openkeylet run --item <item> --env-file <template> -- <command>",
        "only when the program cannot read environment variables",
        "never read it back, diff, or commit it",
        "`captureSecrets`",
    ] {
        assert!(
            OPENKEYLET_INSTRUCTION_BLOCK.contains(expected),
            "managed instruction lacks {expected}"
        );
    }
    assert!(!OPENKEYLET_INSTRUCTION_BLOCK.contains("without exposing plaintext"));
}
