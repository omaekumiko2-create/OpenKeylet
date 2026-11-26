//! Cross-platform real-world user & AI Agent scenario E2E tests.
//!
//! Every test runs against the real compiled `openkeylet` binary with fully isolated
//! `OPENKEYLET_DATA_DIR` and `OPENKEYLET_KEY_FILE` paths so host vaults and keyrings
//! are never touched. Works on Windows, Linux, and macOS in both headless and GUI builds.

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Redirect,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    path::PathBuf,
    process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use std::io::{BufRead, BufReader, Write};
use tempfile::TempDir;
use tokio::net::TcpListener;

const BIN: &str = env!("CARGO_BIN_EXE_openkeylet");

struct IsolatedEnv {
    _root: TempDir,
    root_path: PathBuf,
    data_dir: PathBuf,
    key_file: PathBuf,
    work_dir: PathBuf,
}

impl IsolatedEnv {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("create tempdir");
        let root_path = root.path().to_path_buf();
        let data_dir = root_path.join("vault-data");
        let key_file = root_path.join("separated-keys").join("master.key");
        let work_dir = root_path.join("workspace");
        std::fs::create_dir_all(&work_dir).expect("create workspace");
        Self {
            _root: root,
            root_path,
            data_dir,
            key_file,
            work_dir,
        }
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::new(BIN);
        for (k, _) in std::env::vars() {
            if k.starts_with("OPENKEYLET_") {
                cmd.env_remove(k);
            }
        }
        cmd.env("OPENKEYLET_DATA_DIR", &self.data_dir);
        cmd.env("OPENKEYLET_KEY_FILE", &self.key_file);
        cmd.current_dir(&self.work_dir);
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.cmd()
            .args(args)
            .stdin(Stdio::null())
            .output()
            .expect("run openkeylet")
    }

    fn run_with_env(&self, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
        let mut cmd = self.cmd();
        cmd.args(args).stdin(Stdio::null());
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        cmd.output().expect("run openkeylet with env")
    }

    fn run_with_stdin(&self, args: &[&str], stdin_data: &str) -> Output {
        let mut child = self
            .cmd()
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn openkeylet");
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(stdin_data.as_bytes())
                .expect("write stdin");
        }
        child.wait_with_output().expect("wait openkeylet")
    }

    fn spawn_mcp(&self) -> McpStdioClient {
        McpStdioClient::spawn(self)
    }
}

fn free_loopback_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

struct AdminHandle {
    child: Child,
    base_url: String,
    token: String,
    client: reqwest::Client,
}

impl AdminHandle {
    async fn start(env: &IsolatedEnv) -> Self {
        let port = free_loopback_port();
        let token = format!("oka1_test_admin_token_{port}_abcdefghijklmno");
        let child = env
            .cmd()
            .args([
                "admin",
                "serve",
                "--port",
                &port.to_string(),
                "--token-env",
                "TEST_ADMIN_TOKEN",
            ])
            .env("TEST_ADMIN_TOKEN", &token)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn openkeylet admin serve");
        let base_url = format!("http://127.0.0.1:{port}");
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("reqwest client");
        let mut handle = Self {
            child,
            base_url,
            token,
            client,
        };
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(resp) = handle
                .client
                .get(format!("{}/api/status", handle.base_url))
                .bearer_auth(&handle.token)
                .send()
                .await
                && resp.status() == StatusCode::OK
            {
                return handle;
            }
            if let Ok(Some(status)) = handle.child.try_wait() {
                panic!("admin server exited prematurely with {status}");
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for admin server at {}",
                handle.base_url
            );
            tokio::time::sleep(Duration::from_millis(80)).await;
        }
    }

    async fn save_item(&self, input: Value) -> Value {
        let resp = self
            .client
            .post(format!("{}/api/items", self.base_url))
            .bearer_auth(&self.token)
            .json(&json!({ "input": input }))
            .send()
            .await
            .expect("POST /api/items");
        let status = resp.status();
        let body = resp.text().await.expect("read body");
        assert_eq!(status, StatusCode::OK, "save_item failed: {body}");
        serde_json::from_str(&body).expect("parse saved item json")
    }
}

impl Drop for AdminHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct McpStdioClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl McpStdioClient {
    fn spawn(env: &IsolatedEnv) -> Self {
        let mut child = env
            .cmd()
            .args(["mcp", "stdio"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn openkeylet mcp stdio");
        let stdin = child.stdin.take().expect("mcp stdin");
        let stdout = BufReader::new(child.stdout.take().expect("mcp stdout"));
        let mut client = Self {
            child,
            stdin,
            stdout,
            next_id: 1,
        };
        let init = client.request(
            "initialize",
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "RealWorldE2E", "version": "1.0.0" }
            }),
        );
        assert!(init.get("serverInfo").is_some(), "initialize failed: {init}");
        client.notify("notifications/initialized", json!({}));
        client
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let payload = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        });
        writeln!(self.stdin, "{payload}").expect("write mcp request");
        self.stdin.flush().expect("flush mcp stdin");

        loop {
            let mut line = String::new();
            let read = self.stdout.read_line(&mut line).expect("read mcp stdout");
            assert!(read > 0, "MCP server closed stdout unexpectedly during {method}");
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let msg: Value = serde_json::from_str(trimmed)
                .unwrap_or_else(|e| panic!("invalid JSON from MCP server ({e}): {trimmed}"));
            if msg.get("id").and_then(Value::as_u64) == Some(id) {
                if let Some(err) = msg.get("error") {
                    panic!("JSON-RPC error for {method}: {err}");
                }
                return msg.get("result").cloned().unwrap_or(Value::Null);
            }
        }
    }

    fn notify(&mut self, method: &str, params: Value) {
        let payload = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        });
        writeln!(self.stdin, "{payload}").expect("write mcp notification");
        self.stdin.flush().expect("flush mcp notification");
    }

    fn call_tool_raw(&mut self, name: &str, arguments: Value) -> Value {
        self.request(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        )
    }

    fn call_tool(&mut self, name: &str, arguments: Value) -> Value {
        let res = self.call_tool_raw(name, arguments);
        assert!(
            !res.get("isError").and_then(Value::as_bool).unwrap_or(false),
            "MCP tool {name} returned error: {res}"
        );
        if let Some(sc) = res.get("structuredContent") {
            return sc.clone();
        }
        let text = res["content"][0]["text"].as_str().unwrap_or("{}");
        serde_json::from_str(text).unwrap_or_else(|_| json!({ "text": text }))
    }

    fn call_tool_expect_error(&mut self, name: &str, arguments: Value) -> String {
        let res = self.call_tool_raw(name, arguments);
        assert!(
            res.get("isError").and_then(Value::as_bool).unwrap_or(false),
            "expected MCP tool {name} to error, got: {res}"
        );
        res["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }
}

impl Drop for McpStdioClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn assert_ok(out: &Output, label: &str) {
    assert!(
        out.status.success(),
        "{label} failed (code={:?})\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn scenario_01_separated_key_lifecycle_permissions_and_fail_closed() {
    let env = IsolatedEnv::new();
    let sample_env = env.work_dir.join("deploy.env");
    std::fs::write(&sample_env, "PROD_DEPLOY_TOKEN=tok_separated_key_check_991122\n")
        .expect("write deploy.env");

    let add_out = env.run(&[
        "add",
        "--name",
        "Deploy Prod",
        "--file",
        sample_env.to_str().unwrap(),
    ]);
    assert_ok(&add_out, "openkeylet add");

    // Vault data and master key MUST live in completely separate directories.
    assert!(env.data_dir.join("vault.json").exists(), "vault.json missing");
    assert!(env.key_file.exists(), "separated master.key missing");
    assert!(
        !env.data_dir.join("master.key").exists(),
        "master.key must not be created inside vault data dir when OPENKEYLET_KEY_FILE is set"
    );

    // Check strict Unix 0600 permissions on master.key.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&env.key_file)
            .expect("stat master.key")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "master.key must be 0600, got {mode:o}");
    }

    // Status JSON accurately reports the separated key file and item count.
    let status_out = env.run(&["vault", "status"]);
    assert_ok(&status_out, "vault status");
    let status: Value = serde_json::from_slice(&status_out.stdout).expect("status json");
    assert_eq!(status["itemCount"], 1);
    assert_eq!(status["enabledItemCount"], 1);
    let reported_key = status["keyFile"].as_str().expect("keyFile string");
    assert!(
        reported_key.ends_with("master.key"),
        "unexpected keyFile: {reported_key}"
    );
    assert!(
        !String::from_utf8_lossy(&status_out.stdout).contains("tok_separated_key_check_991122"),
        "vault status leaked secret"
    );

    // Simulate missing/moved key file -> vault MUST fail closed and never recreate master.key.
    let backup_key = env.root_path.join("master.key.moved");
    std::fs::rename(&env.key_file, &backup_key).expect("move key away");
    let list_missing = env.run(&["vault", "list"]);
    assert!(
        !list_missing.status.success(),
        "vault list must fail closed when master.key is missing"
    );
    assert!(
        !env.key_file.exists(),
        "missing master.key must never be silently regenerated over an existing vault"
    );

    // Restoring master.key immediately recovers the vault intact.
    std::fs::rename(&backup_key, &env.key_file).expect("restore key");
    let list_ok = env.run(&["vault", "list"]);
    assert_ok(&list_ok, "vault list after restore");
    let items: Value = serde_json::from_slice(&list_ok.stdout).expect("list json");
    assert_eq!(items.as_array().unwrap().len(), 1);
    assert_eq!(items[0]["name"], "Deploy Prod");
}

#[test]
fn scenario_02_messy_dotenv_import_seal_and_openkeylet_run() {
    let env = IsolatedEnv::new();
    let api_secret = "sk_live_realworld_env_secret_987654";
    let db_pass = "p@ss#123_word_secret_456";
    let dotenv_path = env.work_dir.join(".env");
    let messy_content = format!(
        "\u{feff}# Production backend secrets\r\n\
         export OPENAI_API_KEY={api_secret}\r\n\
         DB_PASS=\"{db_pass}\"\r\n\
         stripe_webhook=whsec_lowercase_key_112233\r\n\
         aws.secret=aws_dotted_secret_445566\r\n\
         url=https://api.internal.example/v1\r\n"
    );
    std::fs::write(&dotenv_path, messy_content.as_bytes()).expect("write messy .env");

    // Self-overwrite with --seal .env MUST be refused.
    let refuse_self = env.run(&[
        "import-env",
        dotenv_path.to_str().unwrap(),
        "--name",
        "App Backend",
        "--seal",
        dotenv_path.to_str().unwrap(),
    ]);
    assert!(
        !refuse_self.status.success(),
        "import-env --seal targeting the source file must refuse"
    );

    // Import and seal to a separate template file.
    let template_path = env.work_dir.join(".env.template");
    let import_out = env.run(&[
        "import-env",
        dotenv_path.to_str().unwrap(),
        "--name",
        "App Backend",
        "--seal",
        template_path.to_str().unwrap(),
    ]);
    assert_ok(&import_out, "import-env --seal");
    let import_json: Value = serde_json::from_slice(&import_out.stdout).expect("import json");
    let keys = import_json["keys"].as_array().expect("keys array");
    assert!(keys.len() >= 5, "expected all 5 env keys imported: {import_json}");
    assert!(
        !String::from_utf8_lossy(&import_out.stdout).contains(api_secret),
        "import-env stdout leaked plaintext"
    );

    let template_text = std::fs::read_to_string(&template_path).expect("read template");
    assert!(template_text.contains("{{openkeylet:"));
    assert!(!template_text.contains(api_secret));
    assert!(!template_text.contains(db_pass));
    assert!(!template_text.contains("whsec_lowercase_key_112233"));
    assert!(!template_text.contains("aws_dotted_secret_445566"));

    // Run a real child process via `openkeylet run --env-file` that:
    // 1) proves the real plaintext arrived in child env (checks lengths & prefix/suffix)
    // 2) tries to echo raw, base64, and hex encodings to stdout AND stderr
    // 3) exits with non-zero exit code 42
    let api_b64 = BASE64_STANDARD.encode(api_secret);
    let api_hex = to_hex(api_secret.as_bytes());
    let run_out = if cfg!(windows) {
        let ps_script = format!(
            "$k = $env:OPENAI_API_KEY; \
             $p = $env:DB_PASS; \
             if ($k.Length -eq {} -and $p.Length -eq {} -and $k.StartsWith('sk_live_') -and $k.EndsWith('987654')) {{ Write-Output 'MATCH=YES' }} else {{ Write-Output ('MATCH=NO:' + $k.Length + ':' + $p.Length) }}; \
             Write-Output ('RAW=' + $k); \
             $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($k)); \
             Write-Output ('B64=' + $b64); \
             $hx = -join ([Text.Encoding]::UTF8.GetBytes($k) | ForEach-Object {{ $_.ToString('x2') }}); \
             [Console]::Error.WriteLine('ERR_HEX=' + $hx); \
             [Console]::Error.WriteLine('ERR_DB=' + $p); \
             exit 42",
            api_secret.len(),
            db_pass.len()
        );
        env.run(&[
            "run",
            "--item",
            "App Backend",
            "--env-file",
            template_path.to_str().unwrap(),
            "--",
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &ps_script,
        ])
    } else {
        let sh_script = format!(
            "if [ \"${{#OPENAI_API_KEY}}\" = \"{}\" ] && [ \"${{#DB_PASS}}\" = \"{}\" ]; then echo 'MATCH=YES'; else echo 'MATCH=NO'; fi; \
             echo \"RAW=$OPENAI_API_KEY\"; \
             echo \"B64={api_b64}\"; \
             echo \"ERR_HEX={api_hex}\" >&2; \
             echo \"ERR_DB=$DB_PASS\" >&2; \
             exit 42",
            api_secret.len(),
            db_pass.len()
        );
        env.run(&[
            "run",
            "--item",
            "App Backend",
            "--env-file",
            template_path.to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            &sh_script,
        ])
    };

    assert_eq!(
        run_out.status.code(),
        Some(42),
        "openkeylet run must propagate exact exit code 42; stdout={} stderr={}",
        String::from_utf8_lossy(&run_out.stdout),
        String::from_utf8_lossy(&run_out.stderr)
    );
    let stdout = String::from_utf8_lossy(&run_out.stdout);
    let stderr = String::from_utf8_lossy(&run_out.stderr);
    let combined = format!("{stdout}\n{stderr}");
    assert!(stdout.contains("MATCH=YES"), "child did not receive real secrets: {combined}");
    assert!(combined.contains("[REDACTED"), "expected redaction marker: {combined}");
    assert!(!combined.contains(api_secret), "raw API secret leaked: {combined}");
    assert!(!combined.contains(&api_b64), "base64 API secret leaked: {combined}");
    assert!(!combined.contains(&api_hex), "hex API secret leaked: {combined}");
    assert!(!combined.contains(db_pass), "DB_PASS leaked on stderr: {combined}");
}

#[test]
fn scenario_03_mcp_stdio_full_agent_workflow() {
    let env = IsolatedEnv::new();
    let mut mcp = env.spawn_mcp();

    // 1. Verify full tool catalog is exposed over stdio.
    let tools_res = mcp.request("tools/list", json!({}));
    let tool_names: Vec<&str> = tools_res["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    for expected in [
        "items_search",
        "item_note",
        "credential_fill",
        "http_send",
        "http_save_secret",
        "ssh_run",
        "ssh_upload",
        "ssh_download",
        "terminal_run",
        "terminal_start",
        "terminal_write",
        "terminal_read",
        "terminal_stop",
        "browser_open",
        "browser_inspect",
        "browser_fill_login",
        "browser_save_key",
        "browser_save_login",
        "browser_fill_personal",
        "browser_click",
        "browser_passkey",
        "secret_write_file",
        "secret_generate",
        "ssh_keygen",
        "secret_ingest_file",
        "draft_prepare",
    ] {
        assert!(
            tool_names.contains(&expected),
            "missing MCP tool '{expected}' in {tool_names:?}"
        );
    }

    // 2. Agent generates a database password into a brand-new item without seeing plaintext.
    let generated = mcp.call_tool(
        "secret_generate",
        json!({
            "createItem": {
                "name": "Billing DB",
                "itemType": "custom",
                "folder": "Infra",
                "description": "Primary Postgres cluster"
            },
            "field": "DB_PASSWORD",
            "format": "password",
            "length": 28
        }),
    );
    assert_eq!(generated["itemName"], "Billing DB");
    assert_eq!(generated["createdItem"], true);
    assert_eq!(generated["length"], 28);

    // 3. Agent generates an Ed25519 SSH keypair directly inside the vault.
    let keygen = mcp.call_tool(
        "ssh_keygen",
        json!({
            "name": "Edge Node",
            "host": "10.0.0.42",
            "port": 2222,
            "username": "deploy",
            "comment": "edge@openkeylet"
        }),
    );
    assert_eq!(keygen["privateKeyStored"], true);
    assert!(keygen["publicKey"].as_str().unwrap().starts_with("ssh-ed25519 "));
    assert!(keygen["fingerprint"].as_str().unwrap().starts_with("SHA256:"));
    assert!(!keygen.to_string().contains("BEGIN OPENSSH PRIVATE KEY"));

    // 4. Agent ingests a local .env file and generates a secret-free template.
    let stripe_secret = "sk_test_ingested_secret_77777";
    let dotted_secret = "svc_tok_dotted_88888";
    let src_env = env.work_dir.join("stripe.env");
    let tpl_env = env.work_dir.join("stripe.env.template");
    std::fs::write(
        &src_env,
        format!("STRIPE_KEY={stripe_secret}\nservice.token={dotted_secret}\n"),
    )
    .expect("write stripe.env");
    let ingested = mcp.call_tool(
        "secret_ingest_file",
        json!({
            "path": src_env.to_str().unwrap(),
            "name": "Stripe Env",
            "sealTemplatePath": tpl_env.to_str().unwrap()
        }),
    );
    assert!(!ingested.to_string().contains(stripe_secret));
    assert!(!ingested.to_string().contains(dotted_secret));
    let tpl_text = std::fs::read_to_string(&tpl_env).expect("read stripe template");
    assert!(!tpl_text.contains(stripe_secret));
    assert!(!tpl_text.contains(dotted_secret));
    assert!(tpl_text.contains("{{openkeylet:"));

    // 5. Agent notes: add factual note, search by note keyword, reject secret-containing note, update & remove.
    let added_note = mcp.call_tool(
        "item_note",
        json!({
            "item": "Billing DB",
            "note": "Staging billing database in eu-west-1"
        }),
    );
    let note_id = added_note["notes"][0]["id"].as_str().unwrap().to_owned();
    let search = mcp.call_tool("items_search", json!({ "query": "eu-west-1" }));
    assert_eq!(search["items"].as_array().unwrap().len(), 1);
    assert_eq!(search["items"][0]["name"], "Billing DB");

    let rejected_note_err = mcp.call_tool_expect_error(
        "item_note",
        json!({
            "item": "Stripe Env",
            "note": format!("uses key {stripe_secret}")
        }),
    );
    assert!(!rejected_note_err.contains(stripe_secret));

    mcp.call_tool(
        "item_note",
        json!({
            "item": "Billing DB",
            "action": "update",
            "noteId": note_id,
            "note": "Production billing database in eu-west-1"
        }),
    );
    let removed = mcp.call_tool(
        "item_note",
        json!({
            "item": "Billing DB",
            "action": "remove",
            "noteId": note_id
        }),
    );
    assert!(removed["notes"].as_array().unwrap().is_empty());

    // 6. secret_write_file inside a real Git repo: unignored warns, .gitignore-matched stays clean.
    let repo_dir = env.work_dir.join("demo-repo");
    std::fs::create_dir_all(&repo_dir).expect("create repo_dir");
    let git_init = if cfg!(windows) {
        Command::new("cmd.exe")
            .args(["/d", "/c", "git", "init", "-q"])
            .current_dir(&repo_dir)
            .output()
            .expect("run git init via cmd.exe")
    } else {
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(&repo_dir)
            .output()
            .expect("run git init")
    };
    assert_ok(&git_init, "git init demo-repo");
    std::fs::write(repo_dir.join(".gitignore"), "ignored.env\n").expect("write .gitignore");

    let unignored_file = repo_dir.join("unignored.env");
    let write_warn = mcp.call_tool(
        "secret_write_file",
        json!({
            "path": unignored_file.to_str().unwrap(),
            "content": "DB={{openkeylet:Billing DB/DB_PASSWORD}}\nSTRIPE={{openkeylet:Stripe Env/STRIPE_KEY}}\n"
        }),
    );
    assert!(
        write_warn["warning"]
            .as_str()
            .unwrap()
            .contains(".gitignore"),
        "expected .gitignore warning for unignored file: {write_warn}"
    );
    assert!(!write_warn.to_string().contains(stripe_secret));
    let rendered_disk = std::fs::read_to_string(&unignored_file).expect("read unignored.env");
    assert!(rendered_disk.contains(stripe_secret));
    let db_secret_line = rendered_disk
        .lines()
        .find(|l| l.starts_with("DB="))
        .expect("DB= line");
    let generated_db_pass = db_secret_line.trim_start_matches("DB=").to_owned();
    assert_eq!(generated_db_pass.len(), 28);

    let ignored_file = repo_dir.join("ignored.env");
    let write_clean = mcp.call_tool(
        "secret_write_file",
        json!({
            "path": ignored_file.to_str().unwrap(),
            "content": "STRIPE={{openkeylet:Stripe Env/STRIPE_KEY}}\n"
        }),
    );
    assert!(
        !write_clean["warning"]
            .as_str()
            .unwrap()
            .contains("not matched by .gitignore"),
        "ignored file should not trigger unignored git warning: {write_clean}"
    );

    // 7. terminal_run with secretEnv AND subsequent item-less read of rendered file MUST both redact!
    let run_cmd = if cfg!(windows) {
        "Write-Output ('ENV_LEN=' + $env:TOKEN.Length + ' VAL=' + $env:TOKEN)"
    } else {
        "printf 'ENV_LEN=%s VAL=%s\\n' \"${#TOKEN}\" \"$TOKEN\""
    };
    let term1 = mcp.call_tool(
        "terminal_run",
        json!({
            "command": run_cmd,
            "secretEnv": { "TOKEN": "Stripe Env/STRIPE_KEY" }
        }),
    );
    let term1_str = term1.to_string();
    assert!(
        term1_str.contains(&format!("ENV_LEN={}", stripe_secret.len())),
        "secretEnv did not reach child: {term1_str}"
    );
    assert!(!term1_str.contains(stripe_secret), "terminal_run leaked secret: {term1_str}");

    let cat_cmd = if cfg!(windows) {
        format!("Get-Content -Raw '{}'", unignored_file.display())
    } else {
        format!("cat '{}'", unignored_file.display())
    };
    let term2 = mcp.call_tool("terminal_run", json!({ "command": cat_cmd }));
    let term2_str = term2.to_string();
    assert!(
        !term2_str.contains(stripe_secret),
        "item-less terminal_run leaked STRIPE_KEY from rendered file: {term2_str}"
    );
    assert!(
        !term2_str.contains(&generated_db_pass),
        "item-less terminal_run leaked generated DB_PASSWORD from rendered file: {term2_str}"
    );

    // 8. Interactive PTY session: terminal_start -> terminal_write -> terminal_read -> terminal_stop.
    let started = mcp.call_tool(
        "terminal_start",
        json!({
            "item": "Stripe Env",
            "cwd": env.work_dir.to_str().unwrap()
        }),
    );
    let session_id = started["sessionId"].as_str().unwrap().to_owned();
    let echo_cmd = if cfg!(windows) {
        "Write-Output ('PTY_ECHO=' + '{{openkeylet:STRIPE_KEY}}' + ' PTY_DONE_MARKER')"
    } else {
        "printf 'PTY_ECHO=%s PTY_DONE_MARKER\\n' {{openkeylet:STRIPE_KEY}}"
    };
    mcp.call_tool(
        "terminal_write",
        json!({
            "sessionId": session_id,
            "text": echo_cmd,
            "submit": true
        }),
    );
    let read_res = mcp.call_tool(
        "terminal_read",
        json!({
            "sessionId": session_id,
            "until": "PTY_DONE_MARKER",
            "waitSeconds": 15
        }),
    );
    let pty_out = read_res.to_string();
    assert!(pty_out.contains("PTY_DONE_MARKER"), "PTY did not reach marker: {pty_out}");
    assert!(!pty_out.contains(stripe_secret), "PTY leaked echoed secret: {pty_out}");

    let stopped = mcp.call_tool("terminal_stop", json!({ "sessionId": session_id }));
    assert_eq!(stopped["ok"], true);
}

#[derive(Clone)]
struct MockApiState {
    bearer: String,
    origin_b: String,
    issue_once_hits: Arc<AtomicUsize>,
    rescue_hits: Arc<AtomicUsize>,
    origin_b_auth_seen: Arc<AtomicUsize>,
}

async fn start_mock_api_servers(bearer: &str) -> (String, String, MockApiState) {
    let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_b: SocketAddr = listener_b.local_addr().unwrap();
    let origin_b = format!("http://127.0.0.1:{}", addr_b.port());

    let state = MockApiState {
        bearer: bearer.to_owned(),
        origin_b: origin_b.clone(),
        issue_once_hits: Arc::new(AtomicUsize::new(0)),
        rescue_hits: Arc::new(AtomicUsize::new(0)),
        origin_b_auth_seen: Arc::new(AtomicUsize::new(0)),
    };

    let router_b = Router::new()
        .route(
            "/inspect-auth",
            get(|State(s): State<MockApiState>, headers: HeaderMap| async move {
                if headers.get("authorization").is_some() {
                    s.origin_b_auth_seen.fetch_add(1, Ordering::SeqCst);
                }
                Json(json!({
                    "origin": "B",
                    "hadAuth": headers.get("authorization").is_some()
                }))
            }),
        )
        .with_state(state.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener_b, router_b).await;
    });

    let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_a: SocketAddr = listener_a.local_addr().unwrap();
    let origin_a = format!("http://127.0.0.1:{}", addr_a.port());

    let router_a = Router::new()
        .route(
            "/projects",
            get(|State(s): State<MockApiState>, headers: HeaderMap| async move {
                let auth = headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if auth != format!("Bearer {}", s.bearer) {
                    return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "unauthorized" })));
                }
                (
                    StatusCode::OK,
                    Json(json!({
                        "projects": ["alpha", "beta"],
                        "echoedAuth": auth
                    })),
                )
            }),
        )
        .route(
            "/download",
            get(|| async { "line1:report\nline2:complete\n" }),
        )
        .route(
            "/oauth/token",
            post(|| async {
                Json(json!({
                    "access_token": "tok_inline_captured_999999",
                    "expires_in": 3600,
                    "scope": "read:projects"
                }))
            }),
        )
        .route(
            "/use-inline",
            get(|headers: HeaderMap| async move {
                if headers.get("x-inline-token").and_then(|v| v.to_str().ok())
                    == Some("tok_inline_captured_999999")
                {
                    (StatusCode::OK, Json(json!({ "verified": "inline" })))
                } else {
                    (StatusCode::UNAUTHORIZED, Json(json!({ "error": "bad inline token" })))
                }
            }),
        )
        .route(
            "/issue-once",
            post(|State(s): State<MockApiState>| async move {
                s.issue_once_hits.fetch_add(1, Ordering::SeqCst);
                (
                    StatusCode::CREATED,
                    Json(json!({
                        "envelope": {
                            "api_key": "otk_held_receipt_secret_444444"
                        },
                        "id": "key_01"
                    })),
                )
            }),
        )
        .route(
            "/use-held",
            get(|headers: HeaderMap| async move {
                if headers.get("x-held-key").and_then(|v| v.to_str().ok())
                    == Some("otk_held_receipt_secret_444444")
                {
                    (StatusCode::OK, Json(json!({ "verified": "held" })))
                } else {
                    (StatusCode::UNAUTHORIZED, Json(json!({ "error": "bad held key" })))
                }
            }),
        )
        .route(
            "/issue-weird",
            post(|State(s): State<MockApiState>| async move {
                s.rescue_hits.fetch_add(1, Ordering::SeqCst);
                Json(json!({
                    "nested": {
                        "one_time_key": "otk_rescue_path_secret_555555"
                    }
                }))
            }),
        )
        .route(
            "/use-rescue",
            get(|headers: HeaderMap| async move {
                if headers.get("x-rescue-key").and_then(|v| v.to_str().ok())
                    == Some("otk_rescue_path_secret_555555")
                {
                    (StatusCode::OK, Json(json!({ "verified": "rescue" })))
                } else {
                    (StatusCode::UNAUTHORIZED, Json(json!({ "error": "bad rescue key" })))
                }
            }),
        )
        .route(
            "/redirect-other",
            get(|State(s): State<MockApiState>| async move {
                Redirect::temporary(&format!("{}/inspect-auth", s.origin_b))
            }),
        )
        .with_state(state.clone());

    tokio::spawn(async move {
        let _ = axum::serve(listener_a, router_a).await;
    });

    (origin_a, origin_b, state)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scenario_04_mcp_http_normal_capture_receipt_and_redirect_safety() {
    let env = IsolatedEnv::new();
    let bearer = "ok_live_api_bearer_secret_123456";
    let (origin_a, origin_b, state) = start_mock_api_servers(bearer).await;

    {
        let admin = AdminHandle::start(&env).await;
        admin
            .save_item(json!({
                "name": "Local Cloud API",
                "itemType": "api",
                "enabled": true,
                "httpAuthType": "bearer",
                "modules": [
                    { "kind": "url", "value": origin_a },
                    { "kind": "apiCredential" }
                ],
                "secrets": {
                    "namedSecrets": { "apiCredential": bearer }
                }
            }))
            .await;
    }

    let mut mcp = env.spawn_mcp();

    // (a) Normal GET returns readable business JSON while redacting echoed Bearer secret.
    let projects = mcp.call_tool(
        "http_send",
        json!({ "item": "Local Cloud API", "url": "/projects" }),
    );
    assert_eq!(projects["status"], 200);
    let body_str = projects["body"].as_str().unwrap_or("");
    assert!(body_str.contains("alpha") && body_str.contains("beta"), "body unreadable: {projects}");
    assert!(!projects.to_string().contains(bearer), "echoed bearer leaked: {projects}");

    // (b) saveResponseTo streams normal download to local file.
    let dl_path = env.work_dir.join("report.txt");
    let dl = mcp.call_tool(
        "http_send",
        json!({
            "item": "Local Cloud API",
            "url": "/download",
            "saveResponseTo": dl_path.to_str().unwrap()
        }),
    );
    assert_eq!(dl["status"], 200);
    assert_eq!(
        std::fs::read_to_string(&dl_path).expect("read report.txt"),
        "line1:report\nline2:complete\n"
    );

    // (c) Inline captureSecrets keeps non-secret metadata readable while saving token.
    let inline = mcp.call_tool(
        "http_send",
        json!({
            "item": "Local Cloud API",
            "url": "/oauth/token",
            "method": "POST",
            "captureSecrets": { "accessToken": "$.access_token" }
        }),
    );
    assert_eq!(inline["status"], 200);
    assert!(!inline.to_string().contains("tok_inline_captured_999999"));
    assert!(inline["body"].as_str().unwrap().contains("3600"));
    assert!(inline["body"].as_str().unwrap().contains("read:projects"));
    let inline_ref = inline["references"]["accessToken"].as_str().unwrap().to_owned();
    let use_inline = mcp.call_tool(
        "http_send",
        json!({
            "item": "Local Cloud API",
            "url": "/use-inline",
            "headers": { "X-Inline-Token": inline_ref }
        }),
    );
    assert_eq!(use_inline["status"], 200);
    assert!(use_inline["body"].as_str().unwrap().contains("inline"));

    // (d) holdResponse=true + http_save_secret saves one-time key without repeating /issue-once.
    let held = mcp.call_tool(
        "http_send",
        json!({
            "item": "Local Cloud API",
            "url": "/issue-once",
            "method": "POST",
            "holdResponse": true
        }),
    );
    assert_eq!(held["status"], 201);
    assert!(!held.to_string().contains("otk_held_receipt_secret_444444"));
    let response_id = held["responseId"].as_str().unwrap().to_owned();
    let slot = held["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["kind"] == "apiKey")
        .expect("apiKey candidate")["slot"]
        .as_u64()
        .unwrap();
    let saved_held = mcp.call_tool(
        "http_save_secret",
        json!({
            "responseId": response_id,
            "captureSecrets": { "heldKey": format!("#{slot}") }
        }),
    );
    assert!(!saved_held.to_string().contains("otk_held_receipt_secret_444444"));
    let held_ref = saved_held["heldKey"].as_str().unwrap().to_owned();
    let use_held = mcp.call_tool(
        "http_send",
        json!({
            "item": "Local Cloud API",
            "url": "/use-held",
            "headers": { "X-Held-Key": held_ref }
        }),
    );
    assert_eq!(use_held["status"], 200);
    assert_eq!(state.issue_once_hits.load(Ordering::SeqCst), 1);

    // (e) Wrong-path captureSecrets fallback withholds body + exposes jsonPaths for rescue.
    let rescue_held = mcp.call_tool(
        "http_send",
        json!({
            "item": "Local Cloud API",
            "url": "/issue-weird",
            "method": "POST",
            "captureSecrets": { "rescueKey": "$.wrong_guess" }
        }),
    );
    assert!(!rescue_held.to_string().contains("otk_rescue_path_secret_555555"));
    let rescue_id = rescue_held["responseId"].as_str().unwrap().to_owned();
    let paths: Vec<&str> = rescue_held["jsonPaths"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        paths.contains(&"$.nested.one_time_key"),
        "expected $.nested.one_time_key in {paths:?}"
    );
    let saved_rescue = mcp.call_tool(
        "http_save_secret",
        json!({
            "responseId": rescue_id,
            "captureSecrets": { "rescueKey": "$.nested.one_time_key" }
        }),
    );
    let rescue_ref = saved_rescue["rescueKey"].as_str().unwrap().to_owned();
    let use_rescue = mcp.call_tool(
        "http_send",
        json!({
            "item": "Local Cloud API",
            "url": "/use-rescue",
            "headers": { "X-Rescue-Key": rescue_ref }
        }),
    );
    assert_eq!(use_rescue["status"], 200);
    assert_eq!(state.rescue_hits.load(Ordering::SeqCst), 1);

    // (f) Cross-origin redirect strips Authorization header automatically.
    let redir = mcp.call_tool(
        "http_send",
        json!({
            "item": "Local Cloud API",
            "url": "/redirect-other"
        }),
    );
    assert_eq!(redir["status"], 200);
    assert!(redir["body"].as_str().unwrap().contains("\"hadAuth\":false"), "{redir}");
    assert_eq!(state.origin_b_auth_seen.load(Ordering::SeqCst), 0);

    // (g) Direct call to foreign origin_b using item bound to origin_a is refused.
    let foreign_err = mcp.call_tool_expect_error(
        "http_send",
        json!({
            "item": "Local Cloud API",
            "url": format!("{origin_b}/inspect-auth")
        }),
    );
    assert!(!foreign_err.is_empty());
    assert_eq!(state.origin_b_auth_seen.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn scenario_05_git_credential_helper_and_vault_killswitch() {
    let env = IsolatedEnv::new();
    {
        let admin = AdminHandle::start(&env).await;
        admin
            .save_item(json!({
                "name": "GitHub PAT",
                "itemType": "login",
                "enabled": true,
                "loginUris": [{ "uri": "https://github.com", "matchType": "host" }],
                "modules": [
                    { "kind": "url", "value": "https://github.com" },
                    { "kind": "username" },
                    { "kind": "password" }
                ],
                "secrets": {
                    "password": "ghp_realworld_test_token_123456",
                    "namedSecrets": { "username": "octocat" }
                }
            }))
            .await;
        admin
            .save_item(json!({
                "name": "Local Gitea",
                "itemType": "login",
                "enabled": true,
                "loginUris": [{ "uri": "http://localhost:3000", "matchType": "host" }],
                "modules": [
                    { "kind": "url", "value": "http://localhost:3000" },
                    { "kind": "username" },
                    { "kind": "password" }
                ],
                "secrets": {
                    "password": "gitea_local_dev_token_654321",
                    "namedSecrets": { "username": "devuser" }
                }
            }))
            .await;
    }

    // HTTPS match succeeds.
    let gh = env.run_with_stdin(
        &["git-credential", "get"],
        "protocol=https\nhost=github.com\n\n",
    );
    assert_ok(&gh, "git-credential get https://github.com");
    let gh_out = String::from_utf8_lossy(&gh.stdout);
    assert!(gh_out.contains("username=octocat"), "{gh_out}");
    assert!(gh_out.contains("password=ghp_realworld_test_token_123456"), "{gh_out}");

    // Plain HTTP on non-localhost MUST refuse to output credentials.
    let plain_gh = env.run_with_stdin(
        &["git-credential", "get"],
        "protocol=http\nhost=github.com\n\n",
    );
    assert!(
        !String::from_utf8_lossy(&plain_gh.stdout).contains("ghp_realworld_test_token_123456"),
        "plain HTTP non-localhost must not emit credentials"
    );

    // Loopback HTTP IS allowed for local dev forges.
    let local_git = env.run_with_stdin(
        &["git-credential", "get"],
        "protocol=http\nhost=localhost:3000\n\n",
    );
    assert_ok(&local_git, "git-credential get http://localhost:3000");
    assert!(String::from_utf8_lossy(&local_git.stdout).contains("gitea_local_dev_token_654321"));

    // Kill-switch: disable -> returns empty; enable -> works again.
    assert_ok(&env.run(&["vault", "disable", "GitHub PAT"]), "vault disable");
    let disabled = env.run_with_stdin(
        &["git-credential", "get"],
        "protocol=https\nhost=github.com\n\n",
    );
    assert!(disabled.stdout.is_empty(), "disabled item must not resolve");

    assert_ok(&env.run(&["vault", "enable", "GitHub PAT"]), "vault enable");
    let reenabled = env.run_with_stdin(
        &["git-credential", "get"],
        "protocol=https\nhost=github.com\n\n",
    );
    assert!(String::from_utf8_lossy(&reenabled.stdout).contains("ghp_realworld_test_token_123456"));

    // Trash -> blocked & counted; restore -> recovers cleanly.
    assert_ok(&env.run(&["vault", "trash", "GitHub PAT"]), "vault trash");
    let trashed = env.run_with_stdin(
        &["git-credential", "get"],
        "protocol=https\nhost=github.com\n\n",
    );
    assert!(trashed.stdout.is_empty(), "trashed item must not resolve");
    let st: Value = serde_json::from_slice(&env.run(&["vault", "status"]).stdout).unwrap();
    assert_eq!(st["trashCount"], 1);

    assert_ok(&env.run(&["vault", "restore", "GitHub PAT"]), "vault restore");
    let restored = env.run_with_stdin(
        &["git-credential", "get"],
        "protocol=https\nhost=github.com\n\n",
    );
    assert!(String::from_utf8_lossy(&restored.stdout).contains("ghp_realworld_test_token_123456"));

    // store / erase are intentional no-ops (exit 0 without mutating vault).
    assert_ok(
        &env.run_with_stdin(&["git-credential", "store"], "protocol=https\nhost=github.com\n\n"),
        "git-credential store",
    );
    assert_ok(
        &env.run_with_stdin(&["git-credential", "erase"], "protocol=https\nhost=github.com\n\n"),
        "git-credential erase",
    );
}

#[tokio::test]
async fn scenario_06_passphrase_mvault_cross_machine_recovery() {
    let machine_a = IsolatedEnv::new();
    let secret_pw = "recovery_vault_secret_pw_778899";
    {
        let admin = AdminHandle::start(&machine_a).await;
        admin
            .save_item(json!({
                "name": "Production Cloudflare",
                "itemType": "api",
                "folder": "Cloud",
                "enabled": true,
                "modules": [
                    { "kind": "url", "value": "https://api.cloudflare.com" },
                    { "kind": "apiCredential" },
                    { "kind": "customSecret", "name": "ACCOUNT_ID" }
                ],
                "secrets": {
                    "namedSecrets": {
                        "apiCredential": secret_pw,
                        "ACCOUNT_ID": "cf_acct_99887766"
                    }
                }
            }))
            .await;
    }
    // Add an agent note too so we verify notes survive backup/restore.
    {
        let mut mcp = machine_a.spawn_mcp();
        mcp.call_tool(
            "item_note",
            json!({
                "item": "Production Cloudflare",
                "note": "DNS zone admin token for openkeylet.org"
            }),
        );
    }

    let backup_file = machine_a.work_dir.join("prod.mvault");
    // Non-TTY export without passphrase flags MUST refuse.
    let refuse_no_pass = machine_a.run(&["backup", "export", backup_file.to_str().unwrap()]);
    assert!(
        !refuse_no_pass.status.success(),
        "non-TTY backup export without passphrase must refuse"
    );

    // Export with passphrase-env.
    let export_ok = machine_a.run_with_env(
        &[
            "backup",
            "export",
            backup_file.to_str().unwrap(),
            "--passphrase-env",
            "TEST_BACKUP_PW",
        ],
        &[("TEST_BACKUP_PW", "correct-horse-battery-staple-2026")],
    );
    assert_ok(&export_ok, "backup export --passphrase-env");

    // Inspect exported file: must NOT contain unlockKey or plaintext secrets.
    let raw_backup = std::fs::read_to_string(&backup_file).expect("read mvault");
    assert!(!raw_backup.contains("unlockKey"), "protected backup must not embed unlockKey");
    assert!(!raw_backup.contains(secret_pw), "backup leaked apiCredential");
    assert!(!raw_backup.contains("cf_acct_99887766"), "backup leaked ACCOUNT_ID");

    // Machine B: brand new vault directory and separated key file.
    let machine_b = IsolatedEnv::new();
    let wrong_import = machine_b.run_with_env(
        &[
            "backup",
            "import",
            backup_file.to_str().unwrap(),
            "--passphrase-env",
            "TEST_BACKUP_PW",
        ],
        &[("TEST_BACKUP_PW", "definitely-the-wrong-passphrase")],
    );
    assert!(
        !wrong_import.status.success(),
        "wrong passphrase must fail backup import"
    );

    let good_import = machine_b.run_with_env(
        &[
            "backup",
            "import",
            backup_file.to_str().unwrap(),
            "--passphrase-env",
            "TEST_BACKUP_PW",
        ],
        &[("TEST_BACKUP_PW", "correct-horse-battery-staple-2026")],
    );
    assert_ok(&good_import, "backup import on Machine B");

    // Verify Machine B recovered the item, notes, AND usable secret value.
    let mut mcp_b = machine_b.spawn_mcp();
    let search_b = mcp_b.call_tool("items_search", json!({ "query": "openkeylet.org" }));
    assert_eq!(search_b["items"].as_array().unwrap().len(), 1);
    assert_eq!(search_b["items"][0]["name"], "Production Cloudflare");

    let verify_file = machine_b.work_dir.join("recovered.env");
    mcp_b.call_tool(
        "secret_write_file",
        json!({
            "item": "Production Cloudflare",
            "path": verify_file.to_str().unwrap(),
            "content": "CF={{openkeylet:apiCredential}}\nACCT={{openkeylet:ACCOUNT_ID}}\n"
        }),
    );
    let recovered = std::fs::read_to_string(&verify_file).expect("read recovered.env");
    assert_eq!(recovered, format!("CF={secret_pw}\nACCT=cf_acct_99887766\n"));
}

#[tokio::test]
async fn scenario_07_owner_pin_and_headless_admin_server() {
    let env = IsolatedEnv::new();

    // Configure Owner PIN non-interactively via --pin-env.
    let set_pin = env.run_with_env(
        &["vault", "pin", "set", "--pin-env", "TEST_OWNER_PIN"],
        &[("TEST_OWNER_PIN", "482910")],
    );
    assert_ok(&set_pin, "vault pin set");

    let pin_status: Value =
        serde_json::from_slice(&env.run(&["vault", "pin", "status"]).stdout).unwrap();
    assert_eq!(pin_status["ownerPinConfigured"], true);

    // Non-TTY `vault pin clear` without --force MUST refuse.
    let clear_refused = env.run(&["vault", "pin", "clear"]);
    assert!(!clear_refused.status.success(), "pin clear without --force in non-TTY must fail");

    // Start headless admin server and verify auth boundaries + smart-add.
    {
        let admin = AdminHandle::start(&env).await;
        let unauth = admin
            .client
            .get(format!("{}/api/status", admin.base_url))
            .send()
            .await
            .expect("unauth GET /api/status");
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        let authed = admin
            .client
            .get(format!("{}/api/status", admin.base_url))
            .bearer_auth(&admin.token)
            .send()
            .await
            .expect("authed GET /api/status");
        assert_eq!(authed.status(), StatusCode::OK);
        let status_json: Value = authed.json().await.expect("status json");
        assert_eq!(status_json["ownerPinConfigured"], true);
        assert!(
            status_json["keyFile"]
                .as_str()
                .unwrap()
                .ends_with("master.key")
        );

        let smart = admin
            .client
            .post(format!("{}/api/items/smart-add", admin.base_url))
            .bearer_auth(&admin.token)
            .json(&json!({
                "name": "Headless Added Secret",
                "raw": "ADMIN_API_KEY=adm_secret_value_667788"
            }))
            .send()
            .await
            .expect("POST smart-add");
        assert_eq!(smart.status(), StatusCode::OK);
        let smart_text = smart.text().await.unwrap();
        assert!(!smart_text.contains("adm_secret_value_667788"));

        let list = admin
            .client
            .get(format!("{}/api/items", admin.base_url))
            .bearer_auth(&admin.token)
            .send()
            .await
            .expect("GET /api/items");
        assert_eq!(list.status(), StatusCode::OK);
        let list_text = list.text().await.unwrap();
        assert!(list_text.contains("Headless Added Secret"));
        assert!(!list_text.contains("adm_secret_value_667788"));
    }

    // Explicit --force recovery clears the PIN cleanly.
    assert_ok(&env.run(&["vault", "pin", "clear", "--force"]), "vault pin clear --force");
    let pin_after: Value =
        serde_json::from_slice(&env.run(&["vault", "pin", "status"]).stdout).unwrap();
    assert_eq!(pin_after["ownerPinConfigured"], false);
}

#[test]
fn scenario_08_concurrent_multi_process_vault_writers() {
    let env = IsolatedEnv::new();
    // Initialize the separated key and empty vault first so we specifically test concurrent writes.
    assert_ok(&env.run(&["vault", "status"]), "init vault");

    let mut handles = Vec::new();
    for i in 1..=6 {
        let data_dir = env.data_dir.clone();
        let key_file = env.key_file.clone();
        let work_dir = env.work_dir.clone();
        handles.push(std::thread::spawn(move || {
            let mut cmd = Command::new(BIN);
            for (k, _) in std::env::vars() {
                if k.starts_with("OPENKEYLET_") {
                    cmd.env_remove(k);
                }
            }
            cmd.env("OPENKEYLET_DATA_DIR", &data_dir)
                .env("OPENKEYLET_KEY_FILE", &key_file)
                .current_dir(&work_dir)
                .args([
                    "keygen",
                    &format!("Worker-{i}"),
                    "--host",
                    &format!("10.1.0.{i}"),
                    "--user",
                    "ops",
                ])
                .stdin(Stdio::null())
                .output()
                .expect("spawn concurrent keygen")
        }));
    }

    for (idx, handle) in handles.into_iter().enumerate() {
        let out = handle.join().expect("join thread");
        assert_ok(&out, &format!("concurrent keygen Worker-{}", idx + 1));
        assert!(
            String::from_utf8_lossy(&out.stdout).starts_with("ssh-ed25519 "),
            "unexpected pubkey output"
        );
    }

    let list_out = env.run(&["vault", "list"]);
    assert_ok(&list_out, "vault list after concurrent writes");
    let items: Value = serde_json::from_slice(&list_out.stdout).expect("parse vault list");
    let names: Vec<&str> = items
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["name"].as_str())
        .collect();
    assert_eq!(names.len(), 6, "lost writes during concurrent access: {names:?}");
    for i in 1..=6 {
        let expected = format!("Worker-{i}");
        assert!(names.contains(&expected.as_str()), "missing {expected} in {names:?}");
    }

    // Ensure no leftover temp files remain in the vault directory.
    let stray: Vec<String> = std::fs::read_dir(&env.data_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".tmp") || name.contains("atomic"))
        .collect();
    assert!(stray.is_empty(), "stray temp files in vault dir: {stray:?}");
}

#[tokio::test]
async fn scenario_09_unicode_cjk_quotes_and_multiline_secrets() {
    let env = IsolatedEnv::new();
    let tricky_secret = "p'a\"s$w%o!r&d_中文_999";
    let multiline_pem = "-----BEGIN TEST KEY-----\nLINE_ONE_ABC123456\nLINE_TWO_DEF789012\n-----END TEST KEY-----";
    let item_name = "生产环境 · 阿里云API";

    {
        let admin = AdminHandle::start(&env).await;
        admin
            .save_item(json!({
                "name": item_name,
                "itemType": "custom",
                "folder": "東京クラスター",
                "enabled": true,
                "modules": [
                    { "kind": "password" },
                    { "kind": "customSecret", "name": "CERT_PEM" }
                ],
                "secrets": {
                    "password": tricky_secret,
                    "namedSecrets": {
                        "CERT_PEM": multiline_pem
                    }
                }
            }))
            .await;
    }

    let mut mcp = env.spawn_mcp();
    let rendered_path = env.work_dir.join("unicode.conf");
    let write_res = mcp.call_tool(
        "secret_write_file",
        json!({
            "item": item_name,
            "path": rendered_path.to_str().unwrap(),
            "content": "PW={{openkeylet:password}}\nPEM:\n{{openkeylet:CERT_PEM}}\n"
        }),
    );
    assert!(!write_res.to_string().contains(tricky_secret));
    assert!(!write_res.to_string().contains("LINE_ONE_ABC123456"));

    let on_disk = std::fs::read_to_string(&rendered_path).expect("read unicode.conf");
    assert_eq!(on_disk, format!("PW={tricky_secret}\nPEM:\n{multiline_pem}\n"));

    // Pass tricky secret via `openkeylet run --env` and verify redaction preserves safety.
    let run_out = if cfg!(windows) {
        env.run(&[
            "run",
            "--item",
            item_name,
            "--env",
            "TRICKY=password",
            "--",
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Write-Output ('OK=' + ($env:TRICKY.Contains('中文')) + ' ECHO=' + $env:TRICKY)",
        ])
    } else {
        env.run(&[
            "run",
            "--item",
            item_name,
            "--env",
            "TRICKY=password",
            "--",
            "/bin/sh",
            "-c",
            "printf 'OK=%s ECHO=%s\\n' \"$(printf '%s' \"$TRICKY\" | grep -c '中文')\" \"$TRICKY\"",
        ])
    };
    assert_ok(&run_out, "openkeylet run with unicode/quotes secret");
    let out_str = String::from_utf8_lossy(&run_out.stdout);
    assert!(
        out_str.contains("OK=True") || out_str.contains("OK=1"),
        "unicode secret mangled in child env: {out_str}"
    );
    assert!(!out_str.contains(tricky_secret), "unicode secret leaked: {out_str}");

    // Round-trip through passphrase-protected .mvault backup into a second vault.
    let backup_path = env.work_dir.join("unicode.mvault");
    assert_ok(
        &env.run_with_env(
            &[
                "backup",
                "export",
                backup_path.to_str().unwrap(),
                "--passphrase-env",
                "PW",
            ],
            &[("PW", "unicode-backup-passphrase-2026")],
        ),
        "export unicode backup",
    );
    let env2 = IsolatedEnv::new();
    assert_ok(
        &env2.run_with_env(
            &[
                "backup",
                "import",
                backup_path.to_str().unwrap(),
                "--passphrase-env",
                "PW",
            ],
            &[("PW", "unicode-backup-passphrase-2026")],
        ),
        "import unicode backup",
    );
    let mut mcp2 = env2.spawn_mcp();
    let out2 = env2.work_dir.join("unicode2.conf");
    mcp2.call_tool(
        "secret_write_file",
        json!({
            "item": item_name,
            "path": out2.to_str().unwrap(),
            "content": "{{openkeylet:password}}\n{{openkeylet:CERT_PEM}}"
        }),
    );
    assert_eq!(
        std::fs::read_to_string(&out2).unwrap(),
        format!("{tricky_secret}\n{multiline_pem}")
    );
}

#[test]
fn scenario_10_draft_prepare_config_ssh_hosts_and_platform_key_cmd() {
    let env = IsolatedEnv::new();
    let mut mcp = env.spawn_mcp();

    // 1. Agent prepares a draft skeleton for the owner without touching plaintext.
    let draft = mcp.call_tool(
        "draft_prepare",
        json!({
            "name": "Company Staging DB",
            "itemType": "custom",
            "folder": "Staging",
            "host": "db.staging.internal",
            "port": 5432,
            "username": "app_ro",
            "modules": [
                { "kind": "password" },
                { "kind": "customSecret", "name": "SSL_CLIENT_KEY" }
            ]
        }),
    );
    assert!(draft["draftId"].as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(draft["name"], "Company Staging DB");
    let pending = draft["pendingSecretFields"].as_array().unwrap();
    assert!(pending.len() >= 2, "expected pending secret fields: {draft}");

    // 2. CLI config generators produce valid JSON & TOML client configs.
    let json_cfg = env.run(&["config", "stdio-json"]);
    assert_ok(&json_cfg, "config stdio-json");
    let parsed_cfg: Value = serde_json::from_slice(&json_cfg.stdout).expect("valid stdio-json");
    assert!(parsed_cfg.to_string().contains("openkeylet"));

    let toml_cfg = env.run(&["config", "stdio-toml"]);
    assert_ok(&toml_cfg, "config stdio-toml");
    let toml_text = String::from_utf8_lossy(&toml_cfg.stdout);
    assert!(toml_text.contains("openkeylet"), "unexpected stdio-toml: {toml_text}");

    // 3. SSH pinned host key listing works cleanly on an empty vault.
    let hosts_out = env.run(&["ssh", "hosts"]);
    assert_ok(&hosts_out, "ssh hosts");
    let hosts: Value = serde_json::from_slice(&hosts_out.stdout).expect("ssh hosts json");
    assert_eq!(hosts.as_array().unwrap().len(), 0);

    // 4. macOS-only `openkeylet key migrate` reports no-op cleanly when file key already exists.
    #[cfg(target_os = "macos")]
    {
        let migrate_out = env.run(&["key", "migrate"]);
        assert_ok(&migrate_out, "macos key migrate");
        let stdout = String::from_utf8_lossy(&migrate_out.stdout);
        assert!(
            stdout.contains("already exists") || stdout.contains("no migration"),
            "unexpected macOS key migrate output: {stdout}"
        );
    }
}
