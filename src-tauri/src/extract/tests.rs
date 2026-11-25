use super::*;
use crate::vault::Vault;

#[test]
fn extracts_multiple_heterogeneous_credentials_from_messy_chat_log() {
    let chat = r#"
hi 交接一下上线要用到的几个配置，别发群里了：

【生产服务器】
主机：198.51.100.22
端口：2222
账号：deploy
密码：Pr0d!Server#99

### 生产数据库
postgres://pgadmin:DbS3cr3tPass!@db.prod.internal:5432/orders

后台管理：
网址：https://admin.example.com/login
账号：ops@example.com
密码：AdminP@ss2026

AI Key 顺便也给你：
sk-ant-api03-live-demo-key-1234567890abcdef
还有 GitHub token：ghp_1234567890abcdefghij1234567890ab

2FA 备用：otpauth://totp/GitHub:ops?secret=JBSWY3DPEHPK3PXP&issuer=GitHub
"#;

    let res = extract_batch(chat, None, &[]).unwrap();
    assert_eq!(res.detected_format, "mixed_text");
    assert!(
        res.candidates.len() >= 6,
        "expected at least 6 candidates, got {}: {:?}",
        res.candidates.len(),
        res.candidates.iter().map(|c| (&c.kind, &c.input.name)).collect::<Vec<_>>()
    );

    assert!(res.candidates.iter().any(|c| c.kind == "ssh" && c.input.name == "生产服务器"));
    assert!(res.candidates.iter().any(|c| c.kind == "database" && c.input.name == "生产数据库"));
    assert!(res.candidates.iter().any(|c| c.kind == "login" && c.input.secrets.get("username") == Some("ops@example.com")));
    assert!(res.candidates.iter().any(|c| c.kind == "apiKey" && c.input.name.contains("Anthropic")));
    assert!(res.candidates.iter().any(|c| c.kind == "apiKey" && c.input.name.contains("GitHub")));
    assert!(res.candidates.iter().any(|c| c.kind == "totp"));
}

#[test]
fn filters_env_noise_and_placeholders_while_promoting_api_and_db() {
    let env_text = r#"
NODE_ENV=production
PORT=3000
DEBUG=false
NEXT_PUBLIC_SITE_URL=https://openkeylet.dev
OPENAI_API_KEY=sk-proj-real-production-token-1234567890
DATABASE_URL=postgres://app:SuperSecret99@db.local:5432/app
STRIPE_SECRET_KEY=your-api-key-here
WEBHOOK_SIGNING_SECRET=whsec_9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d
"#;
    let res = extract_batch(env_text, Some(".env.production"), &[]).unwrap();
    assert_eq!(res.detected_format, "env");
    assert!(res.sealed_env_template.is_some());

    // Promoted: OpenAI API, Postgres DB, and 1 grouped Env secret (WEBHOOK_SIGNING_SECRET)
    assert!(res.candidates.iter().any(|c| c.kind == "apiKey" && c.input.name.contains("OpenAI")));
    assert!(res.candidates.iter().any(|c| c.kind == "database"));
    assert!(res.candidates.iter().any(|c| c.kind == "env" && c.input.secrets.get("WEBHOOK_SIGNING_SECRET").is_some()));

    // Noise & placeholder filtered into ignored (each recoverable!)
    assert!(res.ignored.iter().any(|i| i.key == "PORT" && i.reason == "non_secret"));
    assert!(res.ignored.iter().any(|i| i.key == "NODE_ENV" && i.reason == "non_secret"));
    assert!(res.ignored.iter().any(|i| i.key == "STRIPE_SECRET_KEY" && i.reason == "placeholder" && i.candidate.is_some()));
}

#[test]
fn detects_duplicates_and_updates_against_existing_vault() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path().to_path_buf()).unwrap();
    let mut existing_login = blank_input("login", "Example Admin");
    existing_login.modules.push(public_mod("url", "url", "https://admin.example.com"));
    existing_login.login_uris.push(LoginUri {
        uri: "https://admin.example.com".to_owned(),
        match_type: "domain".to_owned(),
    });
    existing_login.modules.push(secret_mod("username", "username"));
    existing_login
        .secrets
        .named_secrets
        .insert("username".to_owned(), "alice@example.com".to_owned());
    existing_login.modules.push(secret_mod("password", "password"));
    existing_login.secrets.password = Some("OldPass!123".to_owned());
    let saved = vault.save_connection(existing_login).unwrap();

    let existing = vault.list_decrypted_connections().unwrap();

    // Exact duplicate -> unchecked
    let dup_res = extract_batch(
        "https://admin.example.com  alice@example.com  OldPass!123",
        None,
        &existing,
    )
    .unwrap();
    assert_eq!(dup_res.candidates.len(), 1);
    assert_eq!(dup_res.candidates[0].match_status, "duplicate");
    assert!(!dup_res.candidates[0].selected);
    assert_eq!(
        dup_res.candidates[0].existing_item_id.as_deref(),
        Some(saved.id.to_string().as_str())
    );

    // Changed password -> marked as update & update_existing = true
    let upd_res = extract_batch(
        "https://admin.example.com  alice@example.com  NewPass!456",
        None,
        &existing,
    )
    .unwrap();
    assert_eq!(upd_res.candidates.len(), 1);
    assert_eq!(upd_res.candidates[0].match_status, "update");
    assert!(upd_res.candidates[0].selected);
    assert!(upd_res.candidates[0].update_existing);
}

#[test]
fn parses_aws_credentials_and_json_config() {
    let aws = "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nregion = us-east-1\n";
    let res = extract_batch(aws, Some("credentials"), &[]).unwrap();
    assert_eq!(res.detected_format, "aws_credentials");
    assert_eq!(res.candidates.len(), 1);
    assert_eq!(res.candidates[0].badge, "AWS");

    let json = r#"{
        "mcpServers": {
            "anthropic": { "env": { "ANTHROPIC_API_KEY": "sk-ant-api03-json-extracted-key-987654" } }
        },
        "port": "8080"
    }"#;
    let json_res = extract_batch(json, Some("mcp.json"), &[]).unwrap();
    assert_eq!(json_res.detected_format, "json_config");
    assert!(json_res.candidates.iter().any(|c| c.kind == "apiKey" && c.input.name.contains("Anthropic")));
    assert!(json_res.ignored.iter().any(|i| i.key == "port"));
}

#[test]
fn captures_unlabeled_url_inside_chinese_chat_login_line() {
    let line = "测试后台 https://test.foo.com 账号：admin 密码：Test1234!";
    let res = extract_batch(line, None, &[]).unwrap();
    assert_eq!(res.candidates.len(), 1);
    let c = &res.candidates[0];
    assert_eq!(c.kind, "login");
    assert_eq!(c.input.name, "测试后台");
    assert_eq!(c.input.secrets.get("username"), Some("admin"));
    assert_eq!(c.input.secrets.get("password"), Some("Test1234!"));
    assert!(c.input.login_uris.iter().any(|u| u.uri == "https://test.foo.com"));
}

fn make_zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut cursor);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, data) in entries {
            writer.start_file(*name, opts).unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap();
    }
    cursor.into_inner()
}

#[test]
fn extracts_keepass_xml_netrc_npmrc_pgpass_and_pypirc() {
    let kp_xml = r#"<?xml version="1.0" encoding="utf-8"?>
    <KeePassFile><Root><Group>
      <Entry>
        <String><Key>Title</Key><Value>GitHub Prod</Value></String>
        <String><Key>UserName</Key><Value>ops@example.com</Value></String>
        <String><Key>Password</Key><Value>Kp&amp;Secret#9</Value></String>
        <String><Key>URL</Key><Value>https://github.com</Value></String>
        <History><Entry><String><Key>Password</Key><Value>OldPass</Value></String></Entry></History>
      </Entry>
    </Group></Root></KeePassFile>"#;
    let kp = extract_batch(kp_xml, Some("vault.xml"), &[]).unwrap();
    assert_eq!(kp.detected_format, "keepass_xml");
    assert_eq!(kp.candidates.len(), 1);
    assert_eq!(kp.candidates[0].input.secrets.get("password"), Some("Kp&Secret#9"));

    let netrc = "machine api.github.com login octocat password ghp_netrcSecretToken123456\n";
    let nr = extract_batch(netrc, Some(".netrc"), &[]).unwrap();
    assert_eq!(nr.detected_format, "netrc");
    assert_eq!(nr.candidates.len(), 1);
    assert_eq!(nr.candidates[0].input.secrets.get("username"), Some("octocat"));

    let npmrc = "//registry.npmjs.org/:_authToken=npm_RealTokenValue987654321\n";
    let npm = extract_batch(npmrc, Some(".npmrc"), &[]).unwrap();
    assert_eq!(npm.detected_format, "npmrc");
    assert_eq!(npm.candidates.len(), 1);

    let pgpass = "db.internal:5432:prod:pgadmin:PgS3cret!99\n";
    let pg = extract_batch(pgpass, Some(".pgpass"), &[]).unwrap();
    assert_eq!(pg.detected_format, "pgpass");
    assert_eq!(pg.candidates.len(), 1);
    assert_eq!(pg.candidates[0].kind, "database");

    let pypirc = "[pypi]\nrepository = https://upload.pypi.org/legacy/\nusername = __token__\npassword = pypi-AgEIcHlwaS5vcmcsecret123456\n";
    let pp = extract_batch(pypirc, Some(".pypirc"), &[]).unwrap();
    assert_eq!(pp.detected_format, "pypirc");
    assert_eq!(pp.candidates.len(), 1);
}

#[test]
fn extracts_xlsx_docx_zip_and_falls_back_to_secure_note_for_arbitrary_files() {
    let shared = r#"<?xml version="1.0" encoding="UTF-8"?>
    <sst>
      <si><t>名称</t></si>
      <si><t>主机</t></si>
      <si><t>端口</t></si>
      <si><t>账号</t></si>
      <si><t>密码</t></si>
      <si><t>生产跳板机</t></si>
      <si><t>10.10.0.5</t></si>
      <si><t>root</t></si>
      <si><t>XlsxS3cret!88</t></si>
    </sst>"#
        .as_bytes();
    let sheet = br#"<?xml version="1.0" encoding="UTF-8"?>
    <worksheet><sheetData>
      <row r="1">
        <c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c><c r="C1" t="s"><v>2</v></c><c r="D1" t="s"><v>3</v></c><c r="E1" t="s"><v>4</v></c>
      </row>
      <row r="2">
        <c r="A2" t="s"><v>5</v></c><c r="B2" t="s"><v>6</v></c><c r="C2"><v>2222</v></c><c r="D2" t="s"><v>7</v></c><c r="E2" t="s"><v>8</v></c>
      </row>
    </sheetData></worksheet>"#;
    let xlsx_bytes = make_zip_bytes(&[
        ("xl/sharedStrings.xml", shared),
        ("xl/worksheets/sheet1.xml", sheet),
    ]);
    let xlsx_res = extract_from_bytes(&xlsx_bytes, "servers.xlsx", &[]).unwrap();
    assert_eq!(xlsx_res.detected_format, "xlsx_table");
    assert_eq!(xlsx_res.candidates.len(), 1);
    assert_eq!(xlsx_res.candidates[0].kind, "ssh");
    assert_eq!(xlsx_res.candidates[0].input.name, "生产跳板机");
    assert_eq!(xlsx_res.candidates[0].input.secrets.get("password"), Some("XlsxS3cret!88"));

    let docx_xml = br#"<?xml version="1.0" encoding="UTF-8"?>
    <w:document><w:body>
      <w:p><w:r><w:t>OpenAI Key: sk-proj-docxExtractedKey1234567890abcdef</w:t></w:r></w:p>
    </w:body></w:document>"#;
    let docx_bytes = make_zip_bytes(&[("word/document.xml", docx_xml)]);
    let docx_res = extract_from_bytes(&docx_bytes, "handover.docx", &[]).unwrap();
    assert_eq!(docx_res.candidates.len(), 1);
    assert_eq!(docx_res.candidates[0].kind, "apiKey");

    let zip_bytes = make_zip_bytes(&[
        (
            "project/.env",
            concat!("STRIPE_SECRET_KEY=", "sk_", "live_", "ZipExtractedKey1234567890abcd\n")
                .as_bytes(),
        ),
        ("project/node_modules/ignored.env", b"SHOULD_SKIP=123\n"),
    ]);
    let zip_res = extract_from_bytes(&zip_bytes, "bundle.zip", &[]).unwrap();
    assert_eq!(zip_res.candidates.len(), 1);

    // Arbitrary plain note file without secret regex -> falls back to editable Secure Note candidate
    let note_res = extract_from_bytes(
        b"Backup recovery instructions:\n1. Call IT desk ext 4401\n2. Safe combo box #3\n",
        "recovery-memo.txt",
        &[],
    )
    .unwrap();
    assert_eq!(note_res.detected_format, "text_note");
    assert_eq!(note_res.candidates.len(), 1);
    assert_eq!(note_res.candidates[0].input.item_type, "secureNote");
    assert_eq!(note_res.candidates[0].input.name, "recovery-memo");
}

#[test]
fn extract_from_paths_walks_folders_separates_mvault_and_images() {
    let dir = tempfile::tempdir().unwrap();
    let folder = dir.path().join("project-bundle");
    std::fs::create_dir_all(folder.join(".git")).unwrap();
    std::fs::write(folder.join(".env"), "OPENAI_API_KEY=sk-proj-folderTestKey1234567890abcd\n").unwrap();
    std::fs::write(folder.join(".git").join("config"), "secret=should_not_scan\n").unwrap();
    std::fs::write(folder.join("backup.mvault"), "{}").unwrap();
    std::fs::write(folder.join("qr.png"), [0x89, b'P', b'N', b'G']).unwrap();

    let outcome = extract_from_paths(&[folder], &[]);
    assert_eq!(outcome.mvault_paths.len(), 1);
    assert_eq!(outcome.images.len(), 1);
    assert_eq!(outcome.images[0].mime_type, "image/png");
    assert_eq!(outcome.batch.candidates.len(), 1);
    assert_eq!(outcome.batch.candidates[0].kind, "apiKey");
}

#[test]
fn one_click_local_search_finds_home_dotfiles_and_suspected_user_files() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let desktop = dir.path().join("Desktop");
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::create_dir_all(&desktop).unwrap();

    std::fs::write(
        home.join(".ssh").join("config"),
        "Host prod-box\n  HostName 10.0.0.12\n  User ubuntu\n  Port 2222\n",
    )
    .unwrap();
    std::fs::write(
        home.join(".git-credentials"),
        "https://alice:ghp_gitCredSecretToken1234567890@github.com\n",
    )
    .unwrap();
    std::fs::write(
        desktop.join("公司密码本.txt"),
        "测试后台 https://portal.example.com 账号：admin 密码：DeskPass!99\n",
    )
    .unwrap();
    // Unrelated file without credential keywords should NOT be scanned or added as note
    std::fs::write(desktop.join("shopping-list.txt"), "milk, bread, apples\n").unwrap();
    std::fs::write(
        desktop.join("v2rayN-custom-non-cn-proxy-vpn.json"),
        r#"{"routing":{"rules":[{"domain":["domain:example.com","full:api.service.example.com"]}]}}"#,
    )
    .unwrap();
    std::fs::write(desktop.join("openkeylet-backup.mvault"), "{}").unwrap();

    let outcome = scan_local_credential_roots(
        Some(&home),
        &[("Desktop", desktop)],
        &[],
    )
    .unwrap();
    let res = outcome.batch;
    assert_eq!(res.detected_format, "local_search");
    assert!(res.candidates.iter().any(|c| c.kind == "ssh"));
    assert!(res.candidates.iter().any(|c| c.input.name.contains("github.com")));
    assert!(res.candidates.iter().any(|c| c.input.secrets.get("password") == Some("DeskPass!99")));
    assert!(!res.candidates.iter().any(|c| c.input.name.contains("shopping")));
    assert!(!res.candidates.iter().any(|c| c.input.name.contains("v2rayN")));
    assert_eq!(outcome.discovered_mvaults.len(), 1);
    assert_eq!(outcome.discovered_mvaults[0].file_name, "openkeylet-backup.mvault");
    assert_eq!(outcome.discovered_mvaults[0].display_path, "Desktop/openkeylet-backup.mvault");
    assert_eq!(outcome.report.mode, "quick_pc");
    // SSH, Git/cloud, AI/MCP (incl. agent rules), shell rc/history, user folders.
    assert_eq!(outcome.report.categories.len(), 5);
}

#[test]
fn local_scan_finds_standalone_ssh_keys_ai_mcp_jsonc_docker_and_cloud_csv() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let downloads = dir.path().join("Downloads");
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::create_dir_all(home.join(".cursor")).unwrap();
    std::fs::create_dir_all(home.join(".config").join("opencode")).unwrap();
    std::fs::create_dir_all(home.join(".docker")).unwrap();
    std::fs::create_dir_all(&downloads).unwrap();

    let bound_pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----\n";
    let standalone_pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nc3RhbmRhbG9uZS1zc2gta2V5LXYx\n-----END OPENSSH PRIVATE KEY-----\n";
    std::fs::write(home.join(".ssh").join("id_bound"), bound_pem).unwrap();
    std::fs::write(home.join(".ssh").join("id_deploy"), standalone_pem).unwrap();
    std::fs::write(home.join(".ssh").join("id_deploy.pub"), "ssh-ed25519 AAAA...").unwrap();
    std::fs::write(
        home.join(".ssh").join("config"),
        format!(
            "Host bound-host\n  HostName 10.0.1.9\n  User deploy\n  IdentityFile {}\n",
            home.join(".ssh").join("id_bound").display()
        ),
    )
    .unwrap();

    // AI MCP config with plaintext token + OpenKeylet placeholder (placeholder must be ignored)
    std::fs::write(
        home.join(".cursor").join("mcp.json"),
        r#"{
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "env": {
                        "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_cursorMcpExtractedToken1234567890",
                        "SEALED_KEY": "{{openkeylet:SEALED}}"
                    }
                }
            }
        }"#,
    )
    .unwrap();

    // JSONC config with // comments and trailing commas
    std::fs::write(
        home.join(".config").join("opencode").join("opencode.jsonc"),
        "// OpenCode user config\n{\n  \"provider\": {\n    \"anthropic\": {\n      \"apiKey\": \"sk-ant-api03-jsoncCommentExtractedKey9876543210\",\n    },\n  },\n}\n",
    )
    .unwrap();

    // Docker config.json base64 auth
    let docker_b64 = BASE64_STANDARD.encode("ops_user:dckr_pat_DockerSecret987654");
    std::fs::write(
        home.join(".docker").join("config.json"),
        format!(r#"{{"auths":{{"https://index.docker.io/v1/":{{"auth":"{docker_b64}"}}}}}}"#),
    )
    .unwrap();

    // AWS IAM accessKeys.csv in Downloads subfolder (depth 2)
    let sub_dl = downloads.join("aws-iam");
    std::fs::create_dir_all(&sub_dl).unwrap();
    std::fs::write(
        sub_dl.join("deploy_accessKeys.csv"),
        "Access key ID,Secret access key\nAKIAIOSFODNN7REALKEY,wJalrXUtnFEMI/K7MDENG/bPxRfiCYREALKEY99\n",
    )
    .unwrap();

    let outcome = scan_local_credential_roots(
        Some(&home),
        &[("Downloads", downloads)],
        &[],
    )
    .unwrap();
    let cands = &outcome.batch.candidates;

    // bound-host is extracted once as SSH; standalone id_deploy is extracted as KEY; id_bound is NOT duplicated
    assert!(cands.iter().any(|c| c.kind == "ssh" && c.input.name == "bound-host"));
    assert!(cands.iter().any(|c| c.kind == "privateKey" && c.input.name.contains("id_deploy")));
    assert!(!cands.iter().any(|c| c.kind == "privateKey" && c.input.name.contains("id_bound")));

    // Cursor MCP & OpenCode JSONC tokens extracted
    assert!(cands.iter().any(|c| c.input.secrets.get("apiCredential") == Some("ghp_cursorMcpExtractedToken1234567890")));
    assert!(cands.iter().any(|c| c.input.secrets.get("apiCredential") == Some("sk-ant-api03-jsoncCommentExtractedKey9876543210")));

    // Docker Hub login decoded
    assert!(cands.iter().any(|c| c.input.name.contains("Docker") && c.input.secrets.get("password") == Some("dckr_pat_DockerSecret987654")));

    // AWS CSV extracted
    assert!(cands.iter().any(|c| c.kind == "aws" && c.input.secrets.get("AWS_ACCESS_KEY_ID") == Some("AKIAIOSFODNN7REALKEY")));

    // Verify category telemetry
    let ai_stat = outcome.report.categories.iter().find(|c| c.id == "ai_mcp").unwrap();
    assert_eq!(ai_stat.matched_files, 2);
    assert_eq!(ai_stat.extracted_count, 2);
}

#[test]
fn workspace_directory_deep_scan_extracts_multi_repo_envs_and_skips_templates() {
    let dir = tempfile::tempdir().unwrap();
    let ws = dir.path().join("Github");
    std::fs::create_dir_all(ws.join("app-alpha")).unwrap();
    std::fs::create_dir_all(ws.join("app-beta").join("packages").join("web")).unwrap();
    std::fs::create_dir_all(ws.join("app-alpha").join("node_modules").join("pkg")).unwrap();

    std::fs::write(
        ws.join("app-alpha").join(".env"),
        "OPENAI_API_KEY=sk-proj-alphaWorkspaceKey1234567890abcd\nCUSTOM_SIGNING_SECRET=alpha_super_secret_signing_998877\n",
    )
    .unwrap();
    std::fs::write(
        ws.join("app-alpha").join(".env.example"),
        "OPENAI_API_KEY=sk-proj-shouldSkipTemplateKey1234567890\n",
    )
    .unwrap();
    std::fs::write(
        ws.join("app-alpha").join("node_modules").join("pkg").join(".env"),
        "OPENAI_API_KEY=sk-proj-shouldSkipNodeModules1234567890\n",
    )
    .unwrap();
    std::fs::write(
        ws.join("app-beta").join("packages").join("web").join(".env.local"),
        "OPENAI_API_KEY=sk-proj-betaWorkspaceKey9876543210zyxw\nCUSTOM_SIGNING_SECRET=beta_different_secret_signing_112233\n",
    )
    .unwrap();
    // Plain README should NEVER become a secure note in workspace scan
    std::fs::write(ws.join("app-alpha").join("README.md"), "# App Alpha\nHello world\n").unwrap();

    let outcome = scan_workspace_directory(&ws, &[]).unwrap();
    assert_eq!(outcome.report.mode, "workspace_folder");
    let cands = &outcome.batch.candidates;

    // Both OpenAI keys and both distinct .env groups kept & disambiguated; .env.example & node_modules & README skipped
    assert_eq!(cands.len(), 4, "got candidates: {:?}", cands.iter().map(|c| &c.input.name).collect::<Vec<_>>());
    assert!(cands.iter().any(|c| c.input.name.contains("app-alpha")));
    assert!(cands.iter().any(|c| c.input.name.contains("web")));
    assert!(!cands.iter().any(|c| c.input.secrets.get("apiCredential") == Some("sk-proj-shouldSkipTemplateKey1234567890")));
    assert!(!cands.iter().any(|c| c.input.item_type == "secureNote"));
}

#[test]
fn rejects_windows_paths_codex_config_and_api_doc_specs_from_local_scan() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let documents = dir.path().join("Documents");
    std::fs::create_dir_all(home.join(".codex")).unwrap();
    std::fs::create_dir_all(documents.join("docs")).unwrap();

    // Realistic Codex config.toml containing Windows extended paths, npm/pnpm paths, model names, and base URLs (NO real secrets)
    let codex_toml = r#"
model = "gpt-5-codex"
model_provider = "openai"
approval_policy = "on-request"
sandbox_mode = "workspace-write"

[model_providers.openai]
name = "OpenAI"
base_url = "https://api.openai.com/v1/"
wire_api = "responses"

[mcp_servers.npm_tools]
command = "C:\\Users\\malou\\Documents\\myenv\\tools\\npm\\npx.cmd"
cwd = "\\\\?\\C:\\Users\\malou\\Documents\\myenv\\runtime"

[mcp_servers.npm_tools.env]
NPM_CONFIG_PREFIX = "C:\\Users\\malou\\Documents\\myenv\\tools\\npm"
PNPM_HOME = "C:\\Users\\malou\\Documents\\myenv\\tools\\pnpm"

[projects.'\\?\C:\Users\malou\Documents\bundled']
trust_level = "trusted"
"#;
    std::fs::write(home.join(".codex").join("config.toml"), codex_toml).unwrap();

    // Realistic API specification JSON under Documents/docs/ (NO real secrets)
    let api_doc_json = r#"{
        "authentication": "Requires an owner account session with the broker:read scope",
        "path": "/api/v1/broker/accounts/{account_id}/pnl-history",
        "basis": "realized_and_unrealized_daily_ledger_rollup",
        "source": "broker_account_pnl_history_materialized_view",
        "primary_key": ["account_id", "trading_date_utc"],
        "method": "GET",
        "description": "Returns historical profit and loss snapshots for the owner account"
    }"#;
    std::fs::write(
        documents.join("docs").join("backend-account-pnl-history.json"),
        api_doc_json,
    )
    .unwrap();

    // Direct extraction of both files must produce ZERO false-positive candidates
    let direct_codex = extract_batch(codex_toml, Some("~/.codex/config.toml"), &[]).unwrap();
    assert!(
        direct_codex.candidates.is_empty(),
        "Codex paths/URLs must NOT extract as API keys, got: {:?}",
        direct_codex.candidates.iter().map(|c| (&c.input.name, &c.fields)).collect::<Vec<_>>()
    );

    let direct_doc = extract_batch(
        api_doc_json,
        Some("Documents/docs/backend-account-pnl-history.json"),
        &[],
    )
    .unwrap();
    assert!(
        direct_doc.candidates.is_empty(),
        "API spec doc must NOT extract as Env secrets, got: {:?}",
        direct_doc.candidates.iter().map(|c| (&c.input.name, &c.fields)).collect::<Vec<_>>()
    );

    // Local scan across home + Documents must produce ZERO candidates for these files
    let outcome = scan_local_credential_roots(Some(&home), &[("Documents", documents)], &[]).unwrap();
    assert!(
        outcome.batch.candidates.is_empty(),
        "Local scan must not return false positives, got: {:?}",
        outcome.batch.candidates.iter().map(|c| (&c.input.name, &c.fields)).collect::<Vec<_>>()
    );
}

#[test]
fn local_and_workspace_scans_cover_pgpass_conf_cloud_configs_and_skip_test_docs_noise() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let appdata = home.join("AppData").join("Roaming");
    std::fs::create_dir_all(appdata.join("postgresql")).unwrap();
    std::fs::create_dir_all(home.join(".kube")).unwrap();
    std::fs::create_dir_all(home.join(".azure")).unwrap();
    std::fs::create_dir_all(home.join(".continue")).unwrap();

    // Windows pgpass.conf
    std::fs::write(
        appdata.join("postgresql").join("pgpass.conf"),
        "db.prod.internal:5432:billing:pgadmin:PgSuperS3cret!77\n",
    )
    .unwrap();
    // ~/.kube/config YAML with bearer token
    std::fs::write(
        home.join(".kube").join("config"),
        "apiVersion: v1\nusers:\n- name: prod-admin\n  user:\n    token: kube_prod_bearer_secret_998877665544\n",
    )
    .unwrap();
    // ~/.azure/credentials INI
    std::fs::write(
        home.join(".azure").join("credentials"),
        "[default]\nsubscription_id=12345\nclient_secret=AzClientS3cretValue_99887766\n",
    )
    .unwrap();
    // ~/.continue/config.yaml with nested provider mapping
    std::fs::write(
        home.join(".continue").join("config.yaml"),
        "models:\n  anthropic:\n    api_key: sk-ant-api03-yamlNestedSecretKey9876543210\n",
    )
    .unwrap();

    let local_out = scan_local_credential_roots(Some(&home), &[], &[]).unwrap();
    let cands = &local_out.batch.candidates;
    assert!(
        cands.iter().any(|c| c.kind == "database" && c.input.secrets.get("password") == Some("PgSuperS3cret!77")),
        "Windows pgpass.conf must extract as database, got: {:?}",
        cands.iter().map(|c| (&c.kind, &c.input.name)).collect::<Vec<_>>()
    );
    assert!(
        cands.iter().any(|c| c.input.secrets.get("apiCredential") == Some("kube_prod_bearer_secret_998877665544")),
        "~/.kube/config token must extract as Vault-safe apiCredential"
    );
    assert!(
        cands.iter().any(|c| c.input.secrets.get("client_secret") == Some("AzClientS3cretValue_99887766")),
        "~/.azure/credentials client_secret must extract"
    );
    assert!(
        cands.iter().any(|c| c.kind == "apiKey"
            && c.input.name.contains("Anthropic")
            && c.input.secrets.get("apiCredential") == Some("sk-ant-api03-yamlNestedSecretKey9876543210")),
        "Nested YAML provider api_key must extract as Anthropic API"
    );

    // Workspace scan must skip tests/, fixtures/, docs/, and template env variants (.env.example.local / sample.env)
    let ws = dir.path().join("workspace");
    std::fs::create_dir_all(ws.join("service-api")).unwrap();
    std::fs::create_dir_all(ws.join("service-api").join("tests")).unwrap();
    std::fs::create_dir_all(ws.join("service-api").join("fixtures")).unwrap();
    std::fs::create_dir_all(ws.join("service-api").join("docs")).unwrap();

    std::fs::write(
        ws.join("service-api").join(".env"),
        "OPENAI_API_KEY=sk-proj-realWorkspaceServiceKey1234567890\n",
    )
    .unwrap();
    std::fs::write(
        ws.join("service-api").join("terraform.tfvars"),
        "db_password = \"TfVarsProdSecret!8899\"\n",
    )
    .unwrap();
    // Should ALL be skipped:
    std::fs::write(
        ws.join("service-api").join(".env.example.local"),
        "OPENAI_API_KEY=sk-proj-skipInfixExampleKey1234567890\n",
    )
    .unwrap();
    std::fs::write(
        ws.join("service-api").join("sample.env"),
        "OPENAI_API_KEY=sk-proj-skipPrefixSampleKey1234567890\n",
    )
    .unwrap();
    std::fs::write(
        ws.join("service-api").join("tests").join(".env"),
        "OPENAI_API_KEY=sk-proj-skipTestDirEnvKey1234567890\n",
    )
    .unwrap();
    std::fs::write(
        ws.join("service-api").join("tests").join("fixture-backup.mvault"),
        "{}",
    )
    .unwrap();
    std::fs::write(
        ws.join("service-api").join("fixtures").join("id_rsa"),
        "-----BEGIN OPENSSH PRIVATE KEY-----\nZHVtbXktZml4dHVyZS1rZXk=\n-----END OPENSSH PRIVATE KEY-----\n",
    )
    .unwrap();
    std::fs::write(
        ws.join("service-api").join("docs").join("api-secret-spec.json"),
        r#"{"token":"sk-proj-skipDocsSpecKey1234567890abcd"}"#,
    )
    .unwrap();

    let ws_out = scan_workspace_directory(&ws, &[]).unwrap();
    let ws_cands = &ws_out.batch.candidates;
    assert_eq!(
        ws_cands.len(),
        2,
        "Expected only service-api/.env and terraform.tfvars, got: {:?}",
        ws_cands.iter().map(|c| (&c.kind, &c.input.name, &c.source_snippet)).collect::<Vec<_>>()
    );
    assert!(ws_cands.iter().any(|c| c.input.secrets.get("apiCredential") == Some("sk-proj-realWorkspaceServiceKey1234567890")));
    assert!(ws_cands.iter().any(|c| c.input.secrets.get("db_password") == Some("TfVarsProdSecret!8899")));
    assert!(ws_out.discovered_mvaults.is_empty(), "Test-dir .mvault fixture should be skipped");
}

#[test]
fn offline_extractor_rejects_unauthenticated_curl_bare_urls_non_password_tables_and_seals_only_secrets() {
    // 1. Bare URL and unauthenticated curl must produce zero candidates
    let bare_url = extract_batch("https://example.com/dashboard", Some("links.txt"), &[]).unwrap();
    assert!(bare_url.candidates.is_empty(), "Bare URL should not become a login candidate");

    let plain_curl = extract_batch("curl -s https://example.com/health", Some("check.sh"), &[]).unwrap();
    assert!(plain_curl.candidates.is_empty(), "Unauthenticated curl should not become an API key");

    let auth_curl = extract_batch(
        "curl -H \"Authorization: Bearer sk-proj-curlRealAuthToken1234567890\" https://api.openai.com/v1/models",
        Some("call.sh"),
        &[],
    )
    .unwrap();
    assert_eq!(auth_curl.candidates.len(), 1);
    assert_eq!(auth_curl.candidates[0].kind, "apiKey");

    // 2. Non-password CSV / TSV (e.g. finance/CRM table) must produce zero candidates
    let crm_csv = "account,email,balance\nAcme Corp,ops@acme.com,12000\n";
    let crm_res = extract_batch(crm_csv, Some("accounts.csv"), &[]).unwrap();
    assert!(crm_res.candidates.is_empty(), "Non-password CSV must not generate empty logins");

    let crm_tsv = "name\temail\turl\nAlice\talice@example.com\thttps://example.com\n";
    let tsv_res = extract_batch(crm_tsv, Some("contacts.tsv"), &[]).unwrap();
    assert!(tsv_res.candidates.is_empty(), "Non-password TSV must not generate empty logins");

    // 3. Prose address block must NOT turn into SSH server
    let prose_addr = "姓名：张三\n地址：北京市朝阳区建国路88号\n邮箱：zhangsan@example.com\n";
    let prose_res = extract_batch(prose_addr, Some("contact.txt"), &[]).unwrap();
    assert!(prose_res.candidates.is_empty(), "Chinese mailing address must not extract as SSH");

    // 4. Sealed .env template must seal ONLY extracted secrets and keep non-secret vars verbatim
    let env_raw = "NODE_ENV=production\nPORT=3000\nNEXT_PUBLIC_APP_URL=https://app.example.com\nOPENAI_API_KEY=sk-proj-sealOnlyRealKey1234567890ab\nWEBHOOK_SIGNING_SECRET=whsec_realSigningValue99887766\nDUMMY_KEY=your-api-key-here\n";
    let env_res = extract_batch(env_raw, Some(".env"), &[]).unwrap();
    let sealed = env_res.sealed_env_template.as_deref().unwrap();
    assert!(sealed.contains("NODE_ENV=production"), "NODE_ENV must NOT be sealed: {sealed}");
    assert!(sealed.contains("PORT=3000"), "PORT must NOT be sealed: {sealed}");
    assert!(sealed.contains("NEXT_PUBLIC_APP_URL=https://app.example.com"), "Public URL must NOT be sealed: {sealed}");
    assert!(sealed.contains("DUMMY_KEY=your-api-key-here"), "Placeholder must NOT be sealed: {sealed}");
    assert!(sealed.contains("OPENAI_API_KEY={{openkeylet:OPENAI_API_KEY}}"));
    assert!(sealed.contains("WEBHOOK_SIGNING_SECRET={{openkeylet:WEBHOOK_SIGNING_SECRET}}"));

    // 5. Folder / ZIP extraction must NOT turn README.md or source files into junk secureNote cards
    let zip_bytes = make_zip_bytes(&[
        ("repo/.env", b"OPENAI_API_KEY=sk-proj-zipRealSecretKey1234567890ab\n"),
        ("repo/.env.example", b"OPENAI_API_KEY=sk-proj-zipTemplateSkipKey1234567890\n"),
        ("repo/README.md", b"# Repo\nJust documentation text with no credentials.\n"),
        ("repo/src/index.ts", b"export const version = '1.0.0';\n"),
    ]);
    let zip_res = extract_from_bytes(&zip_bytes, "repo.zip", &[]).unwrap();
    assert_eq!(zip_res.candidates.len(), 1);
    assert_eq!(zip_res.candidates[0].kind, "apiKey");

    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("my-repo");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::write(repo.join(".env"), "OPENAI_API_KEY=sk-proj-dirRealSecretKey1234567890ab\n").unwrap();
    std::fs::write(repo.join("README.md"), "# My Repo\nNo secrets here.\n").unwrap();
    std::fs::write(repo.join("src").join("app.ts"), "console.log('hello');\n").unwrap();
    let folder_out = extract_from_paths(&[repo], &[]);
    assert_eq!(folder_out.batch.candidates.len(), 1);
    assert_eq!(folder_out.batch.candidates[0].kind, "apiKey");

    // 6. Direct ingest::smart_parse fixes (non-secret single env, Chinese colon URL, public/placeholder keys)
    let non_secret_env = ingest::smart_parse("OPENAI_BASE_URL=https://api.openai.com/v1/", None, None).unwrap();
    assert_ne!(non_secret_env.kind, "apiKey", "OPENAI_BASE_URL must not parse as OpenAI API key");

    let cn_login = ingest::smart_parse(
        "网址：https://admin.example.com/login\n账号：ops_admin\n密码：CnLoginS3cret!99",
        None,
        None,
    )
    .unwrap();
    assert_eq!(cn_login.kind, "serverInfo");
    assert_eq!(cn_login.input.item_type, "login");
    assert!(
        cn_login.input.modules.iter().any(|m| m.kind == "url" && m.value == "https://admin.example.com/login"),
        "Chinese colon URL must not split on https:"
    );

    let pub_key = ingest::smart_parse("pk_live_1234567890abcdef123456", None, None).unwrap();
    assert_ne!(pub_key.kind, "apiKey", "Stripe publishable key must not parse as secret apiKey");

    let dummy_key = ingest::smart_parse("sk-proj-xxxxxxxxxxxxxxxxxxxx", None, None).unwrap();
    assert_ne!(dummy_key.kind, "apiKey", "Repeated-x dummy key must not parse as secret apiKey");
}

/// Helper that commits every selected candidate into a real encrypted Vault (mimicking `commit_smart_batch`),
/// proving zero schema/validation errors (`Unsupported module`, `Invalid custom secret field name`, invalid URL/port, etc.).
fn commit_candidates_to_real_vault(vault: &Vault, candidates: &[ExtractedCandidate]) -> usize {
    let mut used_names: HashSet<String> = vault
        .list_connections()
        .unwrap()
        .into_iter()
        .map(|c| c.name.trim().to_ascii_lowercase())
        .collect();
    let mut saved_count = 0usize;
    for cand in candidates.iter().filter(|c| c.selected) {
        let mut input = cand.input.clone();
        let base = if input.name.trim().is_empty() {
            "Imported item".to_owned()
        } else {
            input.name.trim().to_owned()
        };
        let mut final_name = base.clone();
        let mut idx = 2usize;
        while used_names.contains(&final_name.to_ascii_lowercase()) {
            final_name = format!("{base} ({idx})");
            idx += 1;
        }
        used_names.insert(final_name.to_ascii_lowercase());
        input.name = final_name;
        vault
            .save_connection(input)
            .unwrap_or_else(|err| panic!("Vault rejected extracted candidate '{}' ({}): {err}", cand.input.name, cand.kind));
        saved_count += 1;
    }
    saved_count
}

#[test]
fn real_user_scenarios_paste_exports_cloud_devtools_and_vault_commit() {
    let vault_dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(vault_dir.path().to_path_buf()).unwrap();

    // Scenario 1: Messy WeChat/Feishu handover (colon-less Chinese labels + inline IP + port2222 + URL + DeepSeek + 2FA)
    let wechat_msg = r#"
兄弟，上线要用的账号发你一下：

生产阿里云 47.98.120.44 端口2222 账号 root 密码 Ops@2026!#

测试后台 https://admin.myapp.cn/login 账号 admin@myapp.cn 密码 Admin#2026

DeepSeek 备用 key：sk-deepseekrealkey1234567890abcdef
2FA：otpauth://totp/Cloudflare:ops@myapp.cn?secret=JBSWY3DPEHPK3PXP&issuer=Cloudflare
"#;
    let s1 = extract_batch(wechat_msg, None, &[]).unwrap();
    assert!(
        s1.candidates.iter().any(|c| c.kind == "ssh"
            && c.input.secrets.get("username") == Some("root")
            && c.input.secrets.get("password") == Some("Ops@2026!#")
            && c.input.modules.iter().any(|m| m.kind == "host" && m.value == "47.98.120.44")
            && c.input.modules.iter().any(|m| m.kind == "port" && m.value == "2222")),
        "Colon-less Chinese server line must extract host/port/user/pass, got: {:?}",
        s1.candidates.iter().map(|c| (&c.kind, &c.input.name, &c.summary)).collect::<Vec<_>>()
    );
    assert!(
        s1.candidates.iter().any(|c| c.kind == "login"
            && c.input.secrets.get("username") == Some("admin@myapp.cn")
            && c.input.secrets.get("password") == Some("Admin#2026")),
        "Colon-less Chinese login line must extract"
    );
    assert!(s1.candidates.iter().any(|c| c.kind == "apiKey" && c.input.secrets.get("apiCredential") == Some("sk-deepseekrealkey1234567890abcdef")));
    assert!(s1.candidates.iter().any(|c| c.kind == "totp"));
    assert_eq!(commit_candidates_to_real_vault(&vault, &s1.candidates), s1.candidates.len());

    // Scenario 2: Bitwarden CSV + 1Password CSV + Chinese Cloud IAM CSV + AWS credentials (with region!) + GCP service-account.json
    let bw_csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nWork,,login,GitLab Corp,,,0,https://gitlab.corp.io,dev@corp.io,BwPass!9988,otpauth://totp/GitLab:dev?secret=JBSWY3DPEHPK3PXP\n";
    let s2_bw = extract_batch(bw_csv, Some("bitwarden_export.csv"), &[]).unwrap();
    assert_eq!(s2_bw.candidates.len(), 1);
    assert_eq!(s2_bw.candidates[0].input.secrets.get("password"), Some("BwPass!9988"));
    assert_eq!(commit_candidates_to_real_vault(&vault, &s2_bw.candidates), 1);

    let aliyun_csv = "用户名称,AccessKey ID,AccessKey Secret\nops-deploy,LTAI5tRealAliyunKey123456,AliyunSuperSecretValue9876543210\n";
    let s2_ali = extract_batch(aliyun_csv, Some("AccessKey.csv"), &[]).unwrap();
    assert_eq!(s2_ali.candidates.len(), 1);
    assert_eq!(s2_ali.candidates[0].input.name, "Alibaba Cloud (ops-deploy)");
    assert_eq!(commit_candidates_to_real_vault(&vault, &s2_ali.candidates), 1);

    let aws_ini = "[default]\naws_access_key_id = AKIAIOSFODNN7REALAWS\naws_secret_access_key = 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\nregion = ap-northeast-1\n";
    let s2_aws = extract_batch(aws_ini, Some("~/.aws/credentials"), &[]).unwrap();
    assert_eq!(s2_aws.candidates.len(), 1);
    assert_eq!(commit_candidates_to_real_vault(&vault, &s2_aws.candidates), 1);

    let gcp_sa = r#"{
        "type": "service_account",
        "project_id": "acme-prod-2026",
        "private_key_id": "key9988776655",
        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj\n-----END PRIVATE KEY-----\n",
        "client_email": "deploy@acme-prod-2026.iam.gserviceaccount.com"
    }"#;
    let s2_gcp = extract_batch(gcp_sa, Some("service-account.json"), &[]).unwrap();
    assert_eq!(s2_gcp.detected_format, "gcp_service_account");
    assert_eq!(s2_gcp.candidates.len(), 1);
    assert_eq!(s2_gcp.candidates[0].input.name, "GCP · acme-prod-2026");
    assert_eq!(commit_candidates_to_real_vault(&vault, &s2_gcp.candidates), 1);

    // Scenario 3: Windows Chrome DevTools "Copy as cURL (cmd)" + docker-compose.yml array env + .env with reserved secret names (TOKEN / API_KEY / PASSWORD)
    let win_curl_cmd = "curl ^\"https://api.openai.com/v1/models^\" ^\r\n  -H ^\"authorization: Bearer sk-proj-winCmdDevToolsKey1234567890^\" ^\r\n  -H ^\"content-type: application/json^\"";
    let s3_curl = extract_batch(win_curl_cmd, None, &[]).unwrap();
    assert_eq!(s3_curl.candidates.len(), 1, "Windows cmd Copy-as-cURL must extract");
    assert_eq!(s3_curl.candidates[0].kind, "apiKey");
    assert_eq!(s3_curl.candidates[0].input.secrets.get("apiCredential"), Some("sk-proj-winCmdDevToolsKey1234567890"));
    assert_eq!(commit_candidates_to_real_vault(&vault, &s3_curl.candidates), 1);

    let docker_compose = r#"
services:
  db:
    image: postgres:16
    environment:
      - POSTGRES_PASSWORD=ComposeDbS3cret!9988
      - REDIS_URL=redis://:ComposeRedis!77@redis:6379/0
      - OPENAI_API_KEY=sk-proj-composeArrayEnvKey1234567890ab
      - NODE_ENV=production
"#;
    let s3_dc = extract_batch(docker_compose, Some("docker-compose.yml"), &[]).unwrap();
    assert!(s3_dc.candidates.iter().any(|c| c.kind == "apiKey" && c.input.secrets.get("apiCredential") == Some("sk-proj-composeArrayEnvKey1234567890ab")));
    assert!(s3_dc.candidates.iter().any(|c| c.kind == "database"));
    assert!(s3_dc.candidates.iter().any(|c| c.kind == "env" && c.input.secrets.get("POSTGRES_PASSWORD") == Some("ComposeDbS3cret!9988")));
    assert_eq!(commit_candidates_to_real_vault(&vault, &s3_dc.candidates), s3_dc.candidates.len());

    let reserved_env = "NODE_ENV=production\nTOKEN=raw_service_token_9988776655\nAPI_KEY=raw_generic_apikey_1122334455\nPASSWORD=EnvMasterPass!7788\nWEBHOOK_SECRET=whsec_reservedTest99887766\n";
    let s3_env = extract_batch(reserved_env, Some(".env"), &[]).unwrap();
    assert!(!s3_env.candidates.is_empty());
    assert_eq!(commit_candidates_to_real_vault(&vault, &s3_env.candidates), s3_env.candidates.len());

    // Verify all committed items round-trip decrypt cleanly from the real encrypted Vault
    let all_decrypted = vault.list_decrypted_connections().unwrap();
    assert!(all_decrypted.len() >= 12, "Expected >=12 real committed vault items, got {}", all_decrypted.len());
}

#[test]
fn real_user_scenarios_full_pc_scan_and_multi_repo_workspace_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let vault_dir = dir.path().join("vault");
    let vault = Vault::open(vault_dir).unwrap();

    // --- Part A: Realistic Developer PC Layout (real configs + real-world noise) ---
    let home = dir.path().join("home");
    let appdata = home.join("AppData").join("Roaming");
    let desktop = dir.path().join("Desktop");
    let documents = dir.path().join("Documents");
    let downloads = dir.path().join("Downloads");
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::create_dir_all(home.join(".cursor")).unwrap();
    std::fs::create_dir_all(home.join(".codex")).unwrap();
    std::fs::create_dir_all(home.join(".claude")).unwrap();
    std::fs::create_dir_all(home.join(".aws")).unwrap();
    std::fs::create_dir_all(home.join(".kube")).unwrap();
    std::fs::create_dir_all(appdata.join("postgresql")).unwrap();
    std::fs::create_dir_all(documents.join("docs")).unwrap();
    std::fs::create_dir_all(&desktop).unwrap();
    std::fs::create_dir_all(&downloads).unwrap();

    // Real developer secrets on PC
    std::fs::write(home.join(".ssh").join("config"), "Host prod-sg\n  HostName 10.20.30.40\n  User ops\n  Port 2222\n").unwrap();
    std::fs::write(home.join(".aws").join("credentials"), "[prod]\naws_access_key_id = AKIAIOSFODNN7PCSCAN1\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYPCSCAN111\nregion = ap-southeast-1\n").unwrap();
    std::fs::write(home.join(".kube").join("config"), "apiVersion: v1\nusers:\n- name: k8s-prod\n  user:\n    token: k8s_pc_scan_secret_token_99887766\n").unwrap();
    std::fs::write(appdata.join("postgresql").join("pgpass.conf"), "pg.internal:5432:app:appuser:PgScanPass!9988\n").unwrap();
    std::fs::write(home.join(".cursor").join("mcp.json"), r#"{"mcpServers":{"github":{"env":{"GITHUB_TOKEN":"ghp_pcScanRealGithubToken1234567890ab","SEALED":"{{openkeylet:SEALED}}"}}}}"#).unwrap();
    std::fs::write(desktop.join("运维密码本.txt"), "线上后台 https://ops.company.io 账号 admin 密码 OpsDesk!2026\n").unwrap();
    std::fs::write(downloads.join("openkeylet-backup-2026.mvault"), "{}").unwrap();

    // Real-world noise files (MUST produce ZERO candidates!)
    std::fs::write(home.join(".codex").join("config.toml"), "model = \"gpt-5-codex\"\n[model_providers.openai]\nbase_url = \"https://api.openai.com/v1/\"\n[projects.'\\\\?\\C:\\Users\\dev\\repo']\ntrust_level = \"trusted\"\n").unwrap();
    std::fs::write(home.join(".claude").join("settings.json"), r#"{"model":"claude-sonnet-4-6","permissions":{"allow":["Bash(git status)"]}}"#).unwrap();
    std::fs::write(documents.join("docs").join("api-spec.json"), r#"{"authentication":"Requires bearer scope","path":"/api/v1/accounts/{id}","primary_key":["id"]}"#).unwrap();
    std::fs::write(documents.join("2026报销accounts.csv"), "account,email,amount\nTravel,dev@company.io,520\n").unwrap();
    std::fs::write(desktop.join("todo.txt"), "Buy coffee\nFix CSS bug\n").unwrap();

    let scan1 = scan_local_credential_roots(
        Some(&home),
        &[("Desktop", desktop.clone()), ("Documents", documents.clone()), ("Downloads", downloads.clone())],
        &[],
    )
    .unwrap();
    assert_eq!(scan1.discovered_mvaults.len(), 1);
    assert_eq!(
        scan1.batch.candidates.len(),
        6,
        "Expected exact 6 real PC credentials and 0 noise, got: {:?}",
        scan1.batch.candidates.iter().map(|c| (&c.kind, &c.input.name, &c.source_snippet)).collect::<Vec<_>>()
    );
    // Commit ALL 6 into the real encrypted Vault!
    assert_eq!(commit_candidates_to_real_vault(&vault, &scan1.batch.candidates), 6);

    // Re-scan PC after commit -> EVERY item must now be detected as `duplicate` (unchecked)!
    let existing_after_pc = vault.list_decrypted_connections().unwrap();
    let scan2 = scan_local_credential_roots(
        Some(&home),
        &[("Desktop", desktop), ("Documents", documents), ("Downloads", downloads)],
        &existing_after_pc,
    )
    .unwrap();
    assert_eq!(scan2.batch.candidates.len(), 6);
    assert!(
        scan2.batch.candidates.iter().all(|c| c.match_status == "duplicate" && !c.selected),
        "Every re-scanned item should be marked duplicate & unchecked, got: {:?}",
        scan2.batch.candidates.iter().map(|c| (&c.input.name, &c.match_status, c.selected)).collect::<Vec<_>>()
    );

    // --- Part B: Multi-Repo Code Workspace Deep Scan + Rotation Update Flow ---
    let ws = dir.path().join("Github");
    std::fs::create_dir_all(ws.join("saas-backend")).unwrap();
    std::fs::create_dir_all(ws.join("saas-frontend").join("packages").join("web")).unwrap();
    std::fs::create_dir_all(ws.join("saas-frontend").join("tests")).unwrap();
    std::fs::create_dir_all(ws.join("saas-frontend").join("docs")).unwrap();
    std::fs::create_dir_all(ws.join("infra-tf")).unwrap();
    std::fs::create_dir_all(ws.join("backups")).unwrap();

    std::fs::write(ws.join("saas-backend").join(".env"), "OPENAI_API_KEY=sk-proj-backendKeyInitial1234567890ab\n").unwrap();
    std::fs::write(ws.join("saas-backend").join(".env.example.local"), "OPENAI_API_KEY=sk-proj-skipExampleKey1234567890\n").unwrap();
    std::fs::write(ws.join("saas-backend").join("docker-compose.yml"), "services:\n  db:\n    environment:\n      - POSTGRES_PASSWORD=BackendComposePass!99\n").unwrap();
    std::fs::write(ws.join("saas-frontend").join("packages").join("web").join(".env.local"), "OPENAI_API_KEY=sk-proj-frontendKeyInitial9876543210\n").unwrap();
    std::fs::write(ws.join("saas-frontend").join("tests").join(".env"), "OPENAI_API_KEY=sk-proj-skipTestDirKey1234567890ab\n").unwrap();
    std::fs::write(ws.join("saas-frontend").join("docs").join("spec.json"), r#"{"token":"sk-proj-skipDocsKey1234567890abcd"}"#).unwrap();
    std::fs::write(ws.join("infra-tf").join("prod.tfvars"), "admin_password = \"TfProdAdmin!2026\"\n").unwrap();
    std::fs::write(ws.join("backups").join("team-vault.mvault"), "{}").unwrap();

    let existing_before_ws = vault.list_decrypted_connections().unwrap();
    let ws1 = scan_workspace_directory(&ws, &existing_before_ws).unwrap();
    assert_eq!(ws1.discovered_mvaults.len(), 1);
    assert_eq!(
        ws1.batch.candidates.len(),
        4,
        "Expected 4 real workspace credentials, got: {:?}",
        ws1.batch.candidates.iter().map(|c| (&c.kind, &c.input.name, &c.source_snippet)).collect::<Vec<_>>()
    );
    assert_eq!(commit_candidates_to_real_vault(&vault, &ws1.batch.candidates), 4);

    // Rotate saas-backend OpenAI key & re-scan -> must mark `OpenAI API (saas-backend)` as `update` and the rest as `duplicate`!
    std::fs::write(ws.join("saas-backend").join(".env"), "OPENAI_API_KEY=sk-proj-backendKeyROTATED9999888877\n").unwrap();
    let existing_after_ws = vault.list_decrypted_connections().unwrap();
    let ws2 = scan_workspace_directory(&ws, &existing_after_ws).unwrap();
    let rotated = ws2
        .batch
        .candidates
        .iter()
        .find(|c| c.input.secrets.get("apiCredential") == Some("sk-proj-backendKeyROTATED9999888877"))
        .expect("Rotated backend OpenAI key must be found");
    assert_eq!(rotated.match_status, "update", "Rotated disambiguated key must match existing vault item as update");
    assert!(rotated.selected && rotated.update_existing);
    let dup_count = ws2.batch.candidates.iter().filter(|c| c.match_status == "duplicate" && !c.selected).count();
    assert_eq!(dup_count, 3, "Other 3 untouched workspace items must be unchecked duplicates");
}

// ---------------------------------------------------------------------------
// Sealed templates fail closed
// ---------------------------------------------------------------------------

const MIXED_ENV: &str = "# Production settings\n\
OPENAI_API_KEY=\"sk-proj-sealRealKey1234567890abcdef\"\n\
db_password=LowerCaseSecret!42\n\
spring.datasource.password=DottedSecret#7x\n\
PRIVATE_KEY=\"-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\n\
QyNTUxOQAAACBmultilineBodySecretMaterial0123456789==\n\
-----END OPENSSH PRIVATE KEY-----\"\n\
# OLD_TOKEN=ghp_commentedOutTokenValue1234567890\n\
# rotate sk-ant-api03-commentedSecretInProse12345 next week\n\
ghp_strayTokenLine1234567890abcdefABCD\n\
EMPTY=\n\
TEMPLATED={{openkeylet:apiCredential}}\n\
PORT=3000\n";

const MIXED_ENV_SECRETS: &[&str] = &[
    "sk-proj-sealRealKey1234567890abcdef",
    "LowerCaseSecret!42",
    "DottedSecret#7x",
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB",
    "multilineBodySecretMaterial",
    "BEGIN OPENSSH",
    "ghp_commentedOutTokenValue1234567890",
    "sk-ant-api03-commentedSecretInProse12345",
    "ghp_strayTokenLine1234567890abcdefABCD",
];

fn assert_no_plaintext(template: &str, secrets: &[&str]) {
    for secret in secrets {
        assert!(
            !template.contains(secret),
            "sealed template still contains a value it should have removed (fixture marker {})",
            secret.chars().take(6).collect::<String>()
        );
    }
}

#[test]
fn sealed_template_removes_every_value_the_mcp_ingest_does_not_store() {
    let sealed = ingest::seal_env_template(MIXED_ENV);
    assert_no_plaintext(&sealed.text, MIXED_ENV_SECRETS);
    assert_eq!(sealed.sealed_keys, vec!["OPENAI_API_KEY", "PRIVATE_KEY", "PORT"]);
    assert!(sealed.text.starts_with("# Production settings\n"));
    assert!(sealed.text.contains("OPENAI_API_KEY={{openkeylet:OPENAI_API_KEY}}\n"));
    // The whole multi-line value collapses into one placeholder line.
    assert!(sealed.text.contains("PRIVATE_KEY={{openkeylet:PRIVATE_KEY}}\n# OpenKeylet removed"));
    assert!(sealed.text.contains("EMPTY=\n"));
    assert!(sealed.text.contains("TEMPLATED={{openkeylet:apiCredential}}\n"));
    // The MCP tool stores only shell-style names, so these are removed, not sealed.
    assert!(sealed.text.contains("# OpenKeylet removed the value of db_password (line 3)"));
    assert!(sealed.text.contains("# OpenKeylet removed the value of spring.datasource.password (line 4)"));
    assert_eq!(sealed.removed_keys, vec!["db_password", "spring.datasource.password"]);
    // db_password, spring.datasource.password, commented value, comment with a token, stray token line.
    assert_eq!(sealed.removed_lines, 5);
    assert_eq!(
        sealed.text.lines().filter(|l| l.starts_with(ingest::SEALED_REMOVAL_MARKER)).count(),
        5
    );

    // The old signature used by the MCP tool returns the same template.
    let (text, keys) = ingest::render_sealed_env(MIXED_ENV);
    assert_eq!(text, sealed.text);
    assert_eq!(keys, sealed.sealed_keys);

    // ...and what it seals is exactly what the ingest stores, including the full key body.
    let vars = ingest::parse_env_vars(MIXED_ENV);
    let names: Vec<&str> = vars.iter().map(|v| v.key.as_str()).collect();
    assert_eq!(names, vec!["OPENAI_API_KEY", "PRIVATE_KEY", "PORT"]);
    let pem = &vars[1].value;
    assert!(pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n") && pem.ends_with("-----END OPENSSH PRIVATE KEY-----"));
}

#[test]
fn env_file_import_seals_lowercase_dotted_and_reserved_keys_with_their_vault_fields() {
    let import = ingest::parse_env_file_detailed(MIXED_ENV.as_bytes(), "Env · .env").unwrap();
    assert_eq!(import.fields.get("db_password").map(String::as_str), Some("db_password"));
    assert_eq!(
        import.fields.get("spring.datasource.password").map(String::as_str),
        Some("spring.datasource.password")
    );
    // PRIVATE_KEY lands in the built-in privateKey module.
    assert_eq!(import.fields.get("PRIVATE_KEY").map(String::as_str), Some("privateKey"));
    let secrets = &import.entries[0].1;
    assert_eq!(secrets.get("db_password"), Some("LowerCaseSecret!42"));
    assert!(secrets.get("privateKey").is_some_and(|pem| pem.contains("multilineBodySecretMaterial")));

    let sealed = ingest::seal_env_template_with_fields(MIXED_ENV, &import.fields);
    assert_no_plaintext(&sealed.text, MIXED_ENV_SECRETS);
    assert!(sealed.text.contains("db_password={{openkeylet:db_password}}\n"));
    assert!(sealed.text.contains("spring.datasource.password={{openkeylet:spring.datasource.password}}\n"));
    assert!(sealed.text.contains("PRIVATE_KEY={{openkeylet:privateKey}}\n"));
    // Only the two comments and the stray token line are left as removals.
    assert_eq!(sealed.removed_lines, 3);
    assert!(sealed.removed_keys.is_empty());

    // Reserved names resolve through the field they were stored in; a repeated key is
    // removed because its placeholder would resolve to the first value.
    let raw = "TOKEN=cliTokenValue123456\nexport password='hunter2hunter2'\nAPI_URL=https://api.example.com\nAPI_URL=https://shadow.example.com\n";
    let import = ingest::parse_env_file_detailed(raw.as_bytes(), "Env").unwrap();
    let sealed = ingest::seal_env_template_with_fields(raw, &import.fields);
    assert!(sealed.text.contains("TOKEN={{openkeylet:apiCredential}}\n"));
    assert!(sealed.text.contains("export password={{openkeylet:password}}\n"));
    assert!(sealed.text.contains("API_URL={{openkeylet:API_URL}}\n"));
    assert!(sealed.text.contains("# OpenKeylet removed the value of API_URL (line 4): duplicate of an earlier API_URL"));
    assert_no_plaintext(&sealed.text, &["cliTokenValue123456", "hunter2hunter2", "shadow.example.com"]);
}

#[test]
fn desktop_sealed_template_keeps_public_config_and_removes_weak_or_unparsed_secrets() {
    let raw = "NODE_ENV=production\nPORT=3000\nopenai_api_key=sk-proj-lowercaseDesktopKey1234567890\ndb_pass=abc\nCALLBACK_URL=https://bot:UrlEmbeddedPass77@hooks.example.com/in\nstray words sk-proj-strayDesktopToken1234567890 here\n";
    let res = extract_batch(raw, Some(".env"), &[]).unwrap();
    assert_eq!(res.detected_format, "env");
    let sealed = res.sealed_env_template.as_deref().unwrap();
    assert!(sealed.contains("NODE_ENV=production\n"));
    assert!(sealed.contains("PORT=3000\n"));
    assert!(sealed.contains("openai_api_key={{openkeylet:openai_api_key}}\n"));
    assert!(sealed.contains("# OpenKeylet removed the value of db_pass (line 4)"));
    assert_no_plaintext(
        sealed,
        &["sk-proj-lowercaseDesktopKey1234567890", "db_pass=abc", "UrlEmbeddedPass77", "sk-proj-strayDesktopToken1234567890"],
    );
    assert!(res.candidates.iter().any(|c| c.input.secrets.get("apiCredential") == Some("sk-proj-lowercaseDesktopKey1234567890")));
}

// ---------------------------------------------------------------------------
// Plaintext left behind after an import
// ---------------------------------------------------------------------------

fn fake_openssh_key(cipher: &str) -> String {
    let mut body = b"openssh-key-v1\0".to_vec();
    body.extend_from_slice(&(cipher.len() as u32).to_be_bytes());
    body.extend_from_slice(cipher.as_bytes());
    body.extend_from_slice(b"fixture-key-body-not-a-real-key");
    format!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
        BASE64_STANDARD.encode(body)
    )
}

#[test]
fn plaintext_sources_name_each_kind_of_file_and_skip_protected_or_missing_ones() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let files = [
        (".env", "OPENAI_API_KEY=sk-proj-fixture\n".to_owned()),
        (".ssh/id_ed25519", fake_openssh_key("none")),
        (".ssh/id_protected", fake_openssh_key("aes256-ctr")),
        (".zshrc", "export A=1\n".to_owned()),
        (".claude/CLAUDE.md", "notes\n".to_owned()),
        (".aws/credentials", "[default]\n".to_owned()),
        ("Documents/passwords.csv", "url,user,pass\n".to_owned()),
        (".claude.json.openkeylet.20260101T000000Z.bak", "{}\n".to_owned()),
    ];
    for (rel, content) in &files {
        let path = home.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    let mut paths: Vec<PathBuf> = files.iter().map(|(rel, _)| home.join(rel)).collect();
    paths.push(home.join(".env"));
    paths.push(home.join("deleted-already.txt"));

    let sources = plaintext_sources_with_home(paths, Some(&home));
    let listed: Vec<(&str, &str)> = sources
        .iter()
        .map(|s| (s.display_path.as_str(), s.kind.as_str()))
        .collect();
    assert_eq!(
        listed,
        vec![
            ("~/.aws/credentials", "tool"),
            ("~/.claude.json.openkeylet.20260101T000000Z.bak", "backup"),
            ("~/.claude/CLAUDE.md", "agent"),
            ("~/.env", "env"),
            ("~/.ssh/id_ed25519", "key"),
            ("~/.zshrc", "shell"),
            ("~/Documents/passwords.csv", "document"),
        ]
    );
}

#[test]
fn extracted_candidates_remember_every_file_that_held_the_secret() {
    let dir = tempfile::tempdir().unwrap();
    let env = dir.path().join(".env");
    let notes = dir.path().join("handover.txt");
    std::fs::write(&env, "OPENAI_API_KEY=sk-proj-sharedAcrossFiles1234567890ab\n").unwrap();
    std::fs::write(&notes, "Prod OpenAI key: sk-proj-sharedAcrossFiles1234567890ab\n").unwrap();
    let out = extract_from_paths(&[env.clone(), notes.clone()], &[]);
    let cand = out
        .batch
        .candidates
        .iter()
        .find(|c| c.input.secrets.get("apiCredential") == Some("sk-proj-sharedAcrossFiles1234567890ab"))
        .unwrap();
    assert_eq!(cand.source_paths, vec![env, notes]);
    // Paths never reach the renderer; only opaque references (filled in by the desktop app) do.
    let json = serde_json::to_string(cand).unwrap();
    assert!(!json.contains(dir.path().to_string_lossy().as_ref()));
    assert!(!json.contains("sourcePaths"));

    // SSH hosts point at the key file the config named, not at the config itself.
    let ssh_dir = dir.path().join("home").join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    std::fs::write(ssh_dir.join("deploy_key"), fake_openssh_key("none")).unwrap();
    std::fs::write(ssh_dir.join("config"), "Host prod\n  HostName 198.51.100.30\n  IdentityFile deploy_key\n").unwrap();
    let bytes = std::fs::read(ssh_dir.join("config")).unwrap();
    let (_, _, key_files) = ingest::parse_ssh_config_bytes_with_key_files(&bytes, Some(&ssh_dir)).unwrap();
    assert_eq!(key_files, vec![Some(ssh_dir.join("deploy_key"))]);
}

// ---------------------------------------------------------------------------
// Agent rule files and shell files
// ---------------------------------------------------------------------------

fn write_fixture(root: &Path, rel: &str, content: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

#[test]
fn local_scan_reads_agent_rules_and_shell_files_without_prose_noise() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    write_fixture(
        &home,
        ".claude/CLAUDE.md",
        "# Project notes\n\nAlways run `cargo test` before committing.\nDeploy with ssh deploy@203.0.113.20 and never force-push.\nuser: admin, password: see the vault\nUse {{openkeylet:apiCredential}} for the staging API.\nMy OpenAI key for quick tests: sk-proj-claudeMdPastedKey1234567890abcd\n",
    );
    write_fixture(&home, ".claude/rules/keys.md", "- `ANTHROPIC_API_KEY=sk-ant-api03-ruleFilePastedKey1234567890abcd`\n");
    write_fixture(
        &home,
        ".cursor/rules/style.mdc",
        "---\ndescription: style\n---\nPrefer small functions and the re_compile_pattern_cache helper.\nExample: export OPENAI_API_KEY=sk-...\n",
    );
    write_fixture(&home, ".codex/AGENTS.md", "Answer in English. The database host is db.internal.example.com, user: admin.\n");
    write_fixture(
        &home,
        ".zshrc",
        "export PATH=\"$HOME/bin:$PATH\"\nexport EDITOR=vim\nalias ll='ls -la'\nexport OPENAI_ORG=org-public-name\nexport GITHUB_TOKEN=ghp_zshrcExportedToken1234567890abcdEF\nexport NPM_TOKEN=$(pass show npm)\nHISTSIZE=10000\n",
    );
    write_fixture(&home, ".bashrc", "export PS1='\\u@\\h:\\w$ '\n[ -f ~/.bash_aliases ] && . ~/.bash_aliases\n");
    write_fixture(
        &home,
        ".zsh_history",
        concat!(": 1700000000:0;ssh deploy@203.0.113.21\n: 1700000001:0;export STRIPE_SECRET_KEY=sk_live", "_historyTypedSecret1234567890\n: 1700000002:0;curl -H \"Authorization: Bearer sk-proj-historyCurlToken1234567890abcd\" https://api.openai.com/v1/models\n: 1700000003:0;export STRIPE_SECRET_KEY=sk_live", "_historyTypedSecret1234567890\n: 1700000004:0;git status\n"),
    );
    write_fixture(&home, ".config/fish/config.fish", "set -gx HF_TOKEN hf_fishConfigToken1234567890abcdEFGH\n");

    let outcome = scan_local_credential_roots(Some(&home), &[], &[]).unwrap();
    let res = &outcome.batch;
    let secret_of = |c: &ExtractedCandidate| {
        c.input
            .secrets
            .get("apiCredential")
            .map(str::to_owned)
            .unwrap_or_default()
    };
    let found: HashSet<String> = res.candidates.iter().map(secret_of).collect();
    for (label, expected) in [
        ("CLAUDE.md prose", "sk-proj-claudeMdPastedKey1234567890abcd"),
        ("rules/keys.md bullet", "sk-ant-api03-ruleFilePastedKey1234567890abcd"),
        (".zshrc export", "ghp_zshrcExportedToken1234567890abcdEF"),
        ("zsh history export", concat!("sk_live", "_historyTypedSecret1234567890")),
        ("zsh history curl", "sk-proj-historyCurlToken1234567890abcd"),
        ("fish set -gx", "hf_fishConfigToken1234567890abcdEFGH"),
    ] {
        assert!(found.contains(expected), "missing the credential from {label}");
    }
    // Exactly those six: no SSH hosts from prose or history, no logins from `user:` lines,
    // no EDITOR/HISTSIZE/PS1 noise, no identifier mistaken for a token.
    assert_eq!(res.candidates.len(), 6, "unexpected extra candidates: {:?}", res.candidates.iter().map(|c| &c.input.name).collect::<Vec<_>>());
    assert!(res.ignored.is_empty(), "shell/rule noise must not fill the filtered list");
    for cand in &res.candidates {
        assert_eq!(cand.source_paths.len(), 1);
        assert!(cand.source_paths[0].starts_with(&home));
    }
    let claude = res.candidates.iter().find(|c| secret_of(c) == "sk-proj-claudeMdPastedKey1234567890abcd").unwrap();
    assert_eq!(claude.source_paths, vec![home.join(".claude/CLAUDE.md")]);
    let shell = outcome.report.categories.iter().find(|c| c.id == "shell").unwrap();
    assert_eq!(shell.extracted_count, 4);
    let ai = outcome.report.categories.iter().find(|c| c.id == "ai_mcp").unwrap();
    assert_eq!(ai.extracted_count, 2);
}

#[test]
fn workspace_scan_reads_project_agent_rule_files() {
    let dir = tempfile::tempdir().unwrap();
    let ws = dir.path().join("ws");
    write_fixture(&ws, "app/CLAUDE.md", "Staging DB: postgres://app:WorkspaceDbPass99@db.internal:5432/app\nLocal DB: postgres://localhost/app\nRead the README before editing.\n");
    write_fixture(&ws, "app/.cursor/rules/api.mdc", "Use the Groq key gsk_workspaceRuleToken1234567890abcd for evals\n");
    write_fixture(&ws, "app/AGENTS.md", "Keep functions small. Run ssh ci@203.0.113.40 for logs.\n");
    write_fixture(&ws, "app/tests/CLAUDE.md", "fixture key sk-proj-testDirFixtureKey1234567890abcd\n");

    let out = scan_workspace_directory(&ws, &[]).unwrap();
    let cands = &out.batch.candidates;
    assert!(cands.iter().any(|c| c.input.secrets.get("password") == Some("WorkspaceDbPass99")));
    assert!(cands.iter().any(|c| c.input.secrets.get("apiCredential") == Some("gsk_workspaceRuleToken1234567890abcd")));
    assert_eq!(cands.len(), 2, "prose, address-only URIs and test fixtures must not produce candidates");
}
