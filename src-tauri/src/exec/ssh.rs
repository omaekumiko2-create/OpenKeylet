use super::*;
use crate::ssh_host_keys::{self, HostKeyVerdict};
use std::sync::Mutex;

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
    execute_ssh_redacting(
        vault,
        connection,
        command,
        cwd,
        timeout_seconds,
        secret_env,
        stdin,
        max_output_bytes,
        &[],
    )
    .await
}

/// [`execute_ssh`] that also redacts `extra_redactions` (raw values) from the output.
pub async fn execute_ssh_redacting(
    vault: &Vault,
    connection: &DecryptedConnection,
    command: &str,
    cwd: Option<&str>,
    timeout_seconds: Option<u64>,
    secret_env: &HashMap<String, String>,
    stdin: Option<&str>,
    max_output_bytes: Option<usize>,
    extra_redactions: &[String],
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
    let execution = execute_ssh_inner(
        vault,
        connection,
        &command,
        stdin,
        max_output_bytes,
        extra_redactions,
    );
    match timeout_seconds.filter(|seconds| *seconds > 0) {
        Some(seconds) => tokio::time::timeout(Duration::from_secs(seconds), execution)
            .await
            .map_err(|_| anyhow::anyhow!("SSH command execution exceeded the timeout set by the caller of {seconds} seconds"))?,
        None => execution.await,
    }
}


pub(super) fn ssh_command_with_secret_environment(
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

pub(super) fn valid_environment_name(name: &str) -> bool {
    let mut characters = name.chars();
    matches!(characters.next(), Some('_' | 'a'..='z' | 'A'..='Z'))
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

pub(super) async fn execute_ssh_inner(
    vault: &Vault,
    connection: &DecryptedConnection,
    command: &str,
    stdin: Option<&str>,
    max_output_bytes: Option<usize>,
    extra_redactions: &[String],
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
    let redactor = output_redactor(Some(connection), extra_redactions);
    let (stdout, stdout_truncated) = stdout_capture.finish(&redactor);
    let (stderr, stderr_truncated) = stderr_capture.finish(&redactor);
    Ok(SshResponse {
        exit_code,
        signal,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
    })
}

pub(super) fn ssh_auth_methods(connection: &DecryptedConnection) -> Vec<&'static str> {
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

pub(super) async fn connect_ssh(
    vault: &Vault,
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

    let mut session = connect_pinned_ssh(vault, connection).await?;

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
            session = connect_pinned_ssh(vault, connection).await?;
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

/// Opens the SSH transport with host key pinning (trust on first use). A
/// rejected host key replaces the generic handshake error so the cause is
/// explicit; russh only reports it as an unknown server key.
async fn connect_pinned_ssh(
    vault: &Vault,
    connection: &DecryptedConnection,
) -> Result<client::Handle<SshClient>> {
    let host_key_rejection = Arc::new(Mutex::new(None));
    let handler = SshClient {
        data_dir: vault.data_dir().to_path_buf(),
        host: connection.stored.host.clone(),
        port: connection.stored.port,
        host_key_rejection: Arc::clone(&host_key_rejection),
    };
    client::connect(
        Arc::new(client::Config::default()),
        (connection.stored.host.as_str(), connection.stored.port),
        handler,
    )
    .await
    .map_err(|error| {
        let rejection = host_key_rejection
            .lock()
            .ok()
            .and_then(|mut slot| slot.take());
        anyhow::anyhow!(rejection.unwrap_or_else(|| ssh_connect_error_message(&error)))
    })
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

pub(super) fn validate_ssh_connection_test(result: &SshResponse) -> Result<()> {
    if result.exit_code.is_some_and(|code| code != 0)
        || result.signal.is_some()
        || result.stdout.trim_end_matches(['\r', '\n']) != "mcp-vault-ok"
    {
        bail!("SSH connection test failed: {}", result.stderr.trim());
    }
    Ok(())
}


pub(super) struct SshClient {
    data_dir: PathBuf,
    host: String,
    port: u16,
    host_key_rejection: Arc<Mutex<Option<String>>>,
}

impl client::Handler for SshClient {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        let algorithm = key.algorithm().to_string();
        let fingerprint = key.fingerprint(ssh_key::HashAlg::Sha256).to_string();
        let data_dir = self.data_dir.clone();
        let host = self.host.clone();
        let port = self.port;
        let verdict = match tokio::task::spawn_blocking(move || {
            ssh_host_keys::verify_or_pin(&data_dir, &host, port, &algorithm, &fingerprint)
        })
        .await
        {
            Ok(verdict) => verdict,
            Err(error) => Err(anyhow::anyhow!(
                "SSH host key check stopped unexpectedly: {error}"
            )),
        };
        let rejection = match verdict {
            Ok(HostKeyVerdict::Pinned | HostKeyVerdict::Matched) => return Ok(true),
            Ok(HostKeyVerdict::Mismatch { expected, actual }) => {
                ssh_host_keys::mismatch_message(&self.host, self.port, &expected, &actual)
            }
            Err(error) => format!(
                "SSH host key for {} could not be checked against the keys pinned on first use, so the connection was refused and no credentials were sent: {error:#}",
                ssh_host_keys::host_port_key(&self.host, self.port)
            ),
        };
        if let Ok(mut slot) = self.host_key_rejection.lock() {
            *slot = Some(rejection);
        }
        Ok(false)
    }
}


pub(super) fn ssh_connect_error_message(error: &impl Display) -> String {
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

