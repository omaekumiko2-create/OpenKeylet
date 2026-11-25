//! Local read-only OpenSSH Agent backed directly by the OpenKeylet vault
//! (`openkeylet ssh-agent`).
//!
//! Implements `draft-miller-ssh-agent` (big-endian `u32` length-prefixed frames):
//! - `SSH_AGENTC_REQUEST_IDENTITIES (11)` -> `SSH_AGENT_IDENTITIES_ANSWER (12)`
//! - `SSH_AGENTC_SIGN_REQUEST (13)` -> `SSH_AGENT_SIGN_RESPONSE (14)`
//! - All mutating or unknown opcodes return `SSH_AGENT_FAILURE (5)`.
//!
//! Private keys are never exported and the vault is re-read on demand so
//! disabling an item in OpenKeylet revokes signing immediately.

#[cfg(unix)]
use crate::storage::resolve_user_path;
use crate::{model::NewActivity, vault::Vault};
use anyhow::{Context, Result, bail, ensure};
use russh::keys::{
    PrivateKey, decode_secret_key,
    signature::Signer,
    ssh_encoding::Encode,
    ssh_key::{HashAlg, private::KeypairData},
};
#[cfg(unix)]
use std::path::{Path, PathBuf};
use std::{collections::HashSet, io::Write, time::Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const SSH_AGENT_USAGE: &str =
    "Usage: openkeylet ssh-agent [--socket <PATH>] [--pipe <NAME>] [--print-env]";

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

pub const SSH_AGENT_RSA_SHA2_256: u32 = 0x02;
pub const SSH_AGENT_RSA_SHA2_512: u32 = 0x04;

const MAX_AGENT_FRAME_LEN: usize = 256 * 1024;
#[cfg(any(windows, test))]
const DEFAULT_WINDOWS_PIPE: &str = r"\\.\pipe\openkeylet-ssh-agent";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshAgentOptions {
    pub socket: Option<String>,
    pub pipe: Option<String>,
    pub print_env: bool,
}

pub fn parse_ssh_agent_args(args: &[String]) -> Result<SshAgentOptions> {
    let mut socket = None;
    let mut pipe = None;
    let mut print_env = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" | "-s" => {
                i += 1;
                let value = args.get(i).context("--socket requires a socket path")?;
                ensure!(!value.trim().is_empty(), "--socket path cannot be empty");
                socket = Some(value.clone());
            }
            "--pipe" | "-p" => {
                i += 1;
                let value = args.get(i).context("--pipe requires a named pipe name")?;
                ensure!(!value.trim().is_empty(), "--pipe name cannot be empty");
                pipe = Some(value.clone());
            }
            "--print-env" => {
                print_env = true;
            }
            other => bail!("Unknown flag for `openkeylet ssh-agent`: {other}\n{SSH_AGENT_USAGE}"),
        }
        i += 1;
    }
    Ok(SshAgentOptions {
        socket,
        pipe,
        print_env,
    })
}

fn read_u32(cursor: &mut &[u8]) -> Option<u32> {
    if cursor.len() < 4 {
        return None;
    }
    let val = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
    *cursor = &cursor[4..];
    Some(val)
}

fn read_ssh_string<'a>(cursor: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = read_u32(cursor)? as usize;
    if cursor.len() < len {
        return None;
    }
    let (data, rest) = cursor.split_at(len);
    *cursor = rest;
    Some(data)
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_ssh_string(out: &mut Vec<u8>, bytes: &[u8]) {
    write_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

struct LoadedIdentity {
    item_name: String,
    key_blob: Vec<u8>,
    comment: String,
    private_key: PrivateKey,
}

fn load_enabled_identities(vault: &Vault) -> Result<Vec<LoadedIdentity>> {
    let connections = vault.list_decrypted_connections()?;
    let mut identities = Vec::new();
    let mut seen_blobs: HashSet<Vec<u8>> = HashSet::new();

    for conn in connections {
        if !conn.stored.enabled {
            continue;
        }
        let Some(pem) = conn
            .secrets
            .private_key
            .as_deref()
            .or_else(|| conn.secrets.get("privateKey"))
            .filter(|v| !v.trim().is_empty())
        else {
            continue;
        };
        let passphrase = conn
            .secrets
            .passphrase
            .as_deref()
            .filter(|v| !v.is_empty());
        let private_key = match decode_secret_key(pem, passphrase) {
            Ok(key) => key,
            Err(err) => {
                eprintln!(
                    "OpenKeylet SSH agent: skipping item '{}' (could not decode private key: {err})",
                    conn.stored.name
                );
                continue;
            }
        };
        let key_blob = match private_key.public_key().to_bytes() {
            Ok(blob) => blob,
            Err(err) => {
                eprintln!(
                    "OpenKeylet SSH agent: skipping item '{}' (could not encode public key: {err})",
                    conn.stored.name
                );
                continue;
            }
        };
        if !seen_blobs.insert(key_blob.clone()) {
            continue;
        }
        identities.push(LoadedIdentity {
            comment: format!("openkeylet:{}", conn.stored.name),
            item_name: conn.stored.name,
            key_blob,
            private_key,
        });
    }
    Ok(identities)
}

fn sign_challenge(private_key: &PrivateKey, data: &[u8], flags: u32) -> Result<Vec<u8>> {
    let signature = match private_key.key_data() {
        KeypairData::Rsa(rsa_keypair) => {
            let hash_alg = if (flags & SSH_AGENT_RSA_SHA2_512) != 0 {
                Some(HashAlg::Sha512)
            } else if (flags & SSH_AGENT_RSA_SHA2_256) != 0 {
                Some(HashAlg::Sha256)
            } else {
                None
            };
            Signer::try_sign(&(rsa_keypair, hash_alg), data)
                .map_err(|err| anyhow::anyhow!("RSA signature failed: {err}"))?
        }
        keypair => Signer::try_sign(keypair, data)
            .map_err(|err| anyhow::anyhow!("SSH key signature failed: {err}"))?,
    };
    let mut encoded = Vec::new();
    signature
        .encode(&mut encoded)
        .map_err(|err| anyhow::anyhow!("Unable to encode SSH signature blob: {err}"))?;
    Ok(encoded)
}

/// Process one raw SSH Agent request payload (without the leading 4-byte frame length)
/// and return the raw response payload (also without the 4-byte frame length).
pub fn handle_agent_message(vault: &Vault, payload: &[u8]) -> Vec<u8> {
    let Some((&opcode, rest)) = payload.split_first() else {
        return vec![SSH_AGENT_FAILURE];
    };

    match opcode {
        SSH_AGENTC_REQUEST_IDENTITIES => handle_request_identities(vault),
        SSH_AGENTC_SIGN_REQUEST => handle_sign_request(vault, rest),
        // Read-only agent: explicitly reject all mutating and unsupported opcodes.
        _ => vec![SSH_AGENT_FAILURE],
    }
}

fn handle_request_identities(vault: &Vault) -> Vec<u8> {
    let identities = match load_enabled_identities(vault) {
        Ok(list) => list,
        Err(err) => {
            eprintln!("OpenKeylet SSH agent: unable to read vault identities: {err:#}");
            return vec![SSH_AGENT_FAILURE];
        }
    };
    let mut response = Vec::with_capacity(64 + identities.len() * 96);
    response.push(SSH_AGENT_IDENTITIES_ANSWER);
    write_u32(&mut response, identities.len() as u32);
    for identity in identities {
        write_ssh_string(&mut response, &identity.key_blob);
        write_ssh_string(&mut response, identity.comment.as_bytes());
    }
    response
}

fn handle_sign_request(vault: &Vault, mut rest: &[u8]) -> Vec<u8> {
    let started = Instant::now();
    let Some(requested_key_blob) = read_ssh_string(&mut rest) else {
        return vec![SSH_AGENT_FAILURE];
    };
    let Some(data) = read_ssh_string(&mut rest) else {
        return vec![SSH_AGENT_FAILURE];
    };
    let Some(flags) = read_u32(&mut rest) else {
        return vec![SSH_AGENT_FAILURE];
    };
    if !rest.is_empty() {
        return vec![SSH_AGENT_FAILURE];
    }

    // Always re-read vault on demand so disabling an item immediately revokes signing.
    let identities = match load_enabled_identities(vault) {
        Ok(list) => list,
        Err(err) => {
            eprintln!("OpenKeylet SSH agent: unable to read vault for signing: {err:#}");
            return vec![SSH_AGENT_FAILURE];
        }
    };
    let Some(matched) = identities
        .into_iter()
        .find(|identity| identity.key_blob.as_slice() == requested_key_blob)
    else {
        return vec![SSH_AGENT_FAILURE];
    };

    match sign_challenge(&matched.private_key, data, flags) {
        Ok(sig_blob) => {
            let _ = vault.add_activity(NewActivity {
                status: "success".to_owned(),
                source: "SSH AGENT".to_owned(),
                connection_name: matched.item_name,
                action: "Sign SSH challenge".to_owned(),
                duration_ms: started.elapsed().as_millis() as u64,
                error: String::new(),
            });
            let mut response = Vec::with_capacity(5 + sig_blob.len());
            response.push(SSH_AGENT_SIGN_RESPONSE);
            write_ssh_string(&mut response, &sig_blob);
            response
        }
        Err(err) => {
            let _ = vault.add_activity(NewActivity {
                status: "error".to_owned(),
                source: "SSH AGENT".to_owned(),
                connection_name: matched.item_name,
                action: "Sign SSH challenge".to_owned(),
                duration_ms: started.elapsed().as_millis() as u64,
                error: err.to_string(),
            });
            vec![SSH_AGENT_FAILURE]
        }
    }
}

/// Serve SSH Agent protocol frames over a single connected stream until EOF or protocol error.
pub async fn serve_connection<S>(vault: Vault, mut stream: S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut len_buf = [0u8; 4];
    let mut payload = Vec::new();
    let mut frame_out = Vec::new();

    loop {
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                return Ok(());
            }
            Err(err) => return Err(err.into()),
        }

        let frame_len = u32::from_be_bytes(len_buf) as usize;
        if frame_len == 0 || frame_len > MAX_AGENT_FRAME_LEN {
            bail!("Invalid SSH agent frame length: {frame_len}");
        }

        payload.resize(frame_len, 0);
        stream.read_exact(&mut payload).await?;

        let response = handle_agent_message(&vault, &payload);

        frame_out.clear();
        write_u32(&mut frame_out, response.len() as u32);
        frame_out.extend_from_slice(&response);
        stream.write_all(&frame_out).await?;
        stream.flush().await?;
    }
}

#[cfg(any(windows, test))]
fn normalize_windows_pipe_name(raw: Option<&str>) -> Result<String> {
    let Some(raw) = raw else {
        return Ok(DEFAULT_WINDOWS_PIPE.to_owned());
    };
    let trimmed = raw.trim();
    ensure!(!trimmed.is_empty(), "Pipe name cannot be empty");
    ensure!(
        !trimmed.contains('\0'),
        "Pipe name cannot contain null characters"
    );
    if trimmed.starts_with(r"\\.\pipe\") {
        Ok(trimmed.to_owned())
    } else {
        let leaf = trimmed.trim_start_matches(['\\', '/']);
        ensure!(!leaf.is_empty(), "Invalid Windows named pipe name");
        Ok(format!(r"\\.\pipe\{leaf}"))
    }
}

#[cfg(unix)]
fn resolve_unix_socket_path(vault: &Vault, raw: Option<&str>) -> Result<PathBuf> {
    match raw {
        Some(path) => resolve_user_path(path),
        None => Ok(vault.data_dir().join("ssh-agent.sock")),
    }
}

#[cfg(unix)]
fn format_shell_env_unix(socket_path: &Path) -> String {
    let raw = socket_path.to_string_lossy();
    let escaped = raw.replace('\'', "'\\''");
    format!("export SSH_AUTH_SOCK='{escaped}'")
}

#[cfg(windows)]
fn format_shell_env_windows(pipe_name: &str) -> String {
    if std::env::var_os("MSYSTEM").is_some() {
        let escaped = pipe_name.replace('\'', "'\\''");
        format!("export SSH_AUTH_SOCK='{escaped}'")
    } else {
        let escaped = pipe_name.replace('\'', "''");
        format!("$env:SSH_AUTH_SOCK = '{escaped}'")
    }
}

#[cfg(unix)]
struct UnixSocketGuard(PathBuf);

#[cfg(unix)]
impl Drop for UnixSocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Entrypoint for `openkeylet ssh-agent`.
pub async fn run_cli(vault: &Vault, args: &[String]) -> Result<()> {
    let options = parse_ssh_agent_args(args)?;

    #[cfg(unix)]
    {
        if options.pipe.is_some() {
            bail!("--pipe is only supported on Windows; use --socket <PATH> on Unix");
        }
        let socket_path = resolve_unix_socket_path(vault, options.socket.as_deref())?;
        if options.print_env {
            println!("{}", format_shell_env_unix(&socket_path));
            return Ok(());
        }
        serve_unix(vault.clone(), socket_path).await
    }

    #[cfg(windows)]
    {
        if options.socket.is_some() {
            bail!("--socket is only supported on Unix; use --pipe <NAME> on Windows");
        }
        let pipe_name = normalize_windows_pipe_name(options.pipe.as_deref())?;
        if options.print_env {
            println!("{}", format_shell_env_windows(&pipe_name));
            return Ok(());
        }
        serve_windows(vault.clone(), pipe_name).await
    }
}

#[cfg(unix)]
async fn serve_unix(vault: Vault, socket_path: PathBuf) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    if let Some(parent) = socket_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Unable to create socket directory {}", parent.display()))?;
    }

    if let Ok(meta) = std::fs::symlink_metadata(&socket_path) {
        if !meta.file_type().is_socket() {
            bail!(
                "Refusing to overwrite non-socket file at {}",
                socket_path.display()
            );
        }
        if tokio::net::UnixStream::connect(&socket_path).await.is_ok() {
            bail!(
                "An SSH agent is already listening at {}",
                socket_path.display()
            );
        }
        std::fs::remove_file(&socket_path).with_context(|| {
            format!("Unable to remove stale socket {}", socket_path.display())
        })?;
    }

    let listener = tokio::net::UnixListener::bind(&socket_path)
        .with_context(|| format!("Unable to bind SSH agent socket {}", socket_path.display()))?;
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("Unable to chmod 0600 {}", socket_path.display()))?;
    let _cleanup = UnixSocketGuard(socket_path.clone());

    let key_count = load_enabled_identities(&vault).map(|v| v.len()).unwrap_or(0);
    println!("{}", format_shell_env_unix(&socket_path));
    let _ = std::io::stdout().flush();
    eprintln!(
        "OpenKeylet SSH agent listening on {} ({} enabled SSH key{}) — press Ctrl+C to stop",
        socket_path.display(),
        key_count,
        if key_count == 1 { "" } else { "s" }
    );

    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let vault_clone = vault.clone();
                        tokio::spawn(async move {
                            let _ = serve_connection(vault_clone, stream).await;
                        });
                    }
                    Err(err) => {
                        eprintln!("OpenKeylet SSH agent accept error: {err}");
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                break;
            }
            _ = async {
                if let Some(sig) = sigterm.as_mut() {
                    sig.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                break;
            }
        }
    }
    eprintln!("OpenKeylet SSH agent stopped.");
    Ok(())
}

#[cfg(windows)]
async fn serve_windows(vault: Vault, pipe_name: String) -> Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .create(&pipe_name)
        .with_context(|| format!("Unable to create Windows named pipe '{pipe_name}'"))?;

    let key_count = load_enabled_identities(&vault).map(|v| v.len()).unwrap_or(0);
    println!("SSH_AUTH_SOCK={pipe_name}");
    let _ = std::io::stdout().flush();
    eprintln!(
        "OpenKeylet SSH agent listening on {pipe_name} ({key_count} enabled SSH key{}) — press Ctrl+C to stop",
        if key_count == 1 { "" } else { "s" }
    );
    eprintln!("PowerShell: {}", format_shell_env_windows(&pipe_name));

    loop {
        tokio::select! {
            connected = server.connect() => {
                match connected {
                    Ok(()) => {
                        let client = server;
                        // Create the next pipe instance immediately so concurrent ssh.exe calls never stall.
                        server = ServerOptions::new()
                            .reject_remote_clients(true)
                            .create(&pipe_name)
                            .with_context(|| {
                                format!("Unable to create next named pipe instance for '{pipe_name}'")
                            })?;
                        let vault_clone = vault.clone();
                        tokio::spawn(async move {
                            let _ = serve_connection(vault_clone, client).await;
                        });
                    }
                    Err(err) => {
                        eprintln!("OpenKeylet SSH agent pipe error: {err}");
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                break;
            }
        }
    }
    eprintln!("OpenKeylet SSH agent stopped.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::{ConnectionInput, ItemModule, SecretBundle},
        crypto::ssh_keygen::generate_ed25519_keypair,
    };
    use russh::keys::{
        agent::client::AgentClient,
        signature::Verifier,
        ssh_encoding::Decode,
        ssh_key::{PublicKey, Signature},
    };
    use tempfile::tempdir;
    use uuid::Uuid;

    fn save_ssh_item(
        vault: &Vault,
        name: &str,
        pem: &str,
        passphrase: Option<&str>,
        enabled: bool,
    ) -> Uuid {
        let mut modules = vec![
            ItemModule {
                kind: "host".to_owned(),
                name: "host".to_owned(),
                value: "prod.example.com".to_owned(),
                agent_visible: Some(true),
            },
            ItemModule {
                kind: "privateKey".to_owned(),
                name: "privateKey".to_owned(),
                value: String::new(),
                agent_visible: Some(false),
            },
        ];
        let mut secrets = SecretBundle::default();
        secrets.private_key = Some(pem.to_owned());
        secrets.private_key_name = Some("id_test".to_owned());
        if let Some(pass) = passphrase {
            modules.push(ItemModule {
                kind: "passphrase".to_owned(),
                name: "passphrase".to_owned(),
                value: String::new(),
                agent_visible: Some(false),
            });
            secrets.passphrase = Some(pass.to_owned());
        }
        vault
            .save_connection(ConnectionInput {
                login_uris: Vec::new(),
                item_type: "ssh".to_owned(),
                folder: "SSH".to_owned(),
                favorite: false,
                id: None,
                modules,
                name: name.to_owned(),
                enabled,
                description: String::new(),
                http_auth_type: String::new(),
                private_key_import_path: String::new(),
                auth_header: String::new(),
                auth_location: String::new(),
                auth_prefix: String::new(),
                api_auth_headers: Vec::new(),
                test_path: String::new(),
                remove_secret_names: Vec::new(),
                secrets,
            })
            .unwrap()
            .id
    }

    async fn round_trip_raw<S: AsyncRead + AsyncWrite + Unpin>(
        client: &mut S,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut frame = Vec::with_capacity(4 + payload.len());
        write_u32(&mut frame, payload.len() as u32);
        frame.extend_from_slice(payload);
        client.write_all(&frame).await.unwrap();
        client.flush().await.unwrap();

        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        let mut resp = vec![0u8; resp_len];
        client.read_exact(&mut resp).await.unwrap();
        resp
    }

    #[tokio::test]
    async fn ed25519_identities_sign_verify_and_immediate_disable_revocation() {
        let dir = tempdir().unwrap();
        let vault = Vault::open(dir.path().join("vault")).unwrap();
        let keypair = generate_ed25519_keypair("deploy@openkeylet").unwrap();
        let expected_pub = PublicKey::from_openssh(&keypair.public_key).unwrap();
        let expected_blob = expected_pub.to_bytes().unwrap();

        let item_id = save_ssh_item(
            &vault,
            "Prod Bastion",
            &keypair.private_key_pem,
            None,
            true,
        );
        // Also store a malformed key to verify graceful skipping without crashing.
        save_ssh_item(&vault, "Corrupt Key", "not-a-valid-pem-key", None, true);

        let (server_io, mut client_io) = tokio::io::duplex(16 * 1024);
        let server_vault = vault.clone();
        let server_task = tokio::spawn(async move { serve_connection(server_vault, server_io).await });

        // 1. REQUEST_IDENTITIES (11) -> IDENTITIES_ANSWER (12)
        let resp = round_trip_raw(&mut client_io, &[SSH_AGENTC_REQUEST_IDENTITIES]).await;
        let mut cursor = resp.as_slice();
        assert_eq!(cursor[0], SSH_AGENT_IDENTITIES_ANSWER);
        cursor = &cursor[1..];
        assert_eq!(read_u32(&mut cursor), Some(1));
        let key_blob = read_ssh_string(&mut cursor).unwrap();
        let comment = std::str::from_utf8(read_ssh_string(&mut cursor).unwrap()).unwrap();
        assert_eq!(key_blob, expected_blob.as_slice());
        assert_eq!(comment, "openkeylet:Prod Bastion");
        assert!(cursor.is_empty());

        // 2. SIGN_REQUEST (13) -> SIGN_RESPONSE (14), cryptographically verified!
        let challenge = b"OpenSSH session challenge payload 2026";
        let mut sign_req = vec![SSH_AGENTC_SIGN_REQUEST];
        write_ssh_string(&mut sign_req, key_blob);
        write_ssh_string(&mut sign_req, challenge);
        write_u32(&mut sign_req, 0);

        let sign_resp = round_trip_raw(&mut client_io, &sign_req).await;
        let mut sc = sign_resp.as_slice();
        assert_eq!(sc[0], SSH_AGENT_SIGN_RESPONSE);
        sc = &sc[1..];
        let mut sig_blob = read_ssh_string(&mut sc).unwrap();
        assert!(sc.is_empty());
        let signature = Signature::decode(&mut sig_blob).unwrap();
        Verifier::verify(&expected_pub, challenge, &signature).unwrap();

        // Audit activity must have been recorded.
        let activities = vault.activities().unwrap();
        assert_eq!(activities.len(), 1);
        assert_eq!(activities[0].source, "SSH AGENT");
        assert_eq!(activities[0].connection_name, "Prod Bastion");
        assert_eq!(activities[0].action, "Sign SSH challenge");

        // 3. Mutating opcodes (ADD_IDENTITY=17, REMOVE_IDENTITY=18, REMOVE_ALL=19, LOCK=22) must fail!
        for opcode in [17u8, 18, 19, 22, 25] {
            let mut req = vec![opcode];
            req.extend_from_slice(&[0u8; 8]);
            let resp = round_trip_raw(&mut client_io, &req).await;
            assert_eq!(resp, vec![SSH_AGENT_FAILURE]);
        }

        // Unknown key sign request must return SSH_AGENT_FAILURE.
        let other_keypair = generate_ed25519_keypair("unknown@openkeylet").unwrap();
        let other_blob = PublicKey::from_openssh(&other_keypair.public_key)
            .unwrap()
            .to_bytes()
            .unwrap();
        let mut unknown_sign_req = vec![SSH_AGENTC_SIGN_REQUEST];
        write_ssh_string(&mut unknown_sign_req, &other_blob);
        write_ssh_string(&mut unknown_sign_req, challenge);
        write_u32(&mut unknown_sign_req, 0);
        let unknown_resp = round_trip_raw(&mut client_io, &unknown_sign_req).await;
        assert_eq!(unknown_resp, vec![SSH_AGENT_FAILURE]);

        // 4. Disabling the item in the vault immediately revokes listing AND signing!
        vault.set_connection_enabled(item_id, false).unwrap();

        let resp_after = round_trip_raw(&mut client_io, &[SSH_AGENTC_REQUEST_IDENTITIES]).await;
        let mut ac = resp_after.as_slice();
        assert_eq!(ac[0], SSH_AGENT_IDENTITIES_ANSWER);
        ac = &ac[1..];
        assert_eq!(read_u32(&mut ac), Some(0));

        let sign_after = round_trip_raw(&mut client_io, &sign_req).await;
        assert_eq!(sign_after, vec![SSH_AGENT_FAILURE]);

        drop(client_io);
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn russh_agent_client_interop_and_rsa_sha2_flags() {
        // Test RSA-SHA2-256 and RSA-SHA2-512 flags plus real russh AgentClient compatibility.
        let dir = tempdir().unwrap();
        let vault = Vault::open(dir.path().join("vault")).unwrap();

        // Standard OpenSSH RSA test key (2048-bit, unencrypted, test-only fixture).
        const TEST_RSA_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\n\
NhAAAAAwEAAQAAAQEAuSvQ9m76zhRB4m0BUKPf17lwccj7KQ1Qtse63AOqP/VYItqEH8un\n\
rxPogXNBgrcCEm/ccLZZsyE3qgp3DRQkkqvJhZ6O8VBPsXxjZesRCqoFNCczy+Mf0R/Qmv\n\
Rnpu5+4DDLz0p7vrsRZW9ji/c98KzxeUonWgkplQaCBYLN875WdeUYMGtb1MLfNCEj177j\n\
gZl3CzttLRK3su6dckowXcXYv1gPTPZAwJb49J43o1QhV7+1zdwXvuFM6zuYHdu9ZHSKir\n\
6k1dXOET3/U+LWG5ofAo8oxUWv/7vs6h7MeajwkUeIBOWYtD+wGYRvVpxvj7nyOoWtg+jm\n\
0X6ndnsD+QAAA8irV+ZAq1fmQAAAAAdzc2gtcnNhAAABAQC5K9D2bvrOFEHibQFQo9/XuX\n\
BxyPspDVC2x7rcA6o/9Vgi2oQfy6evE+iBc0GCtwISb9xwtlmzITeqCncNFCSSq8mFno7x\n\
UE+xfGNl6xEKqgU0JzPL4x/RH9Ca9Gem7n7gMMvPSnu+uxFlb2OL9z3wrPF5SidaCSmVBo\n\
IFgs3zvlZ15Rgwa1vUwt80ISPXvuOBmXcLO20tErey7p1ySjBdxdi/WA9M9kDAlvj0njej\n\
VCFXv7XN3Be+4UzrO5gd271kdIqKvqTV1c4RPf9T4tYbmh8CjyjFRa//u+zqHsx5qPCRR4\n\
gE5Zi0P7AZhG9WnG+PufI6ha2D6ObRfqd2ewP5AAAAAwEAAQAAAQAdELqhI/RsSpO45eFR\n\
9hcZtnrm8WQzImrr9dfn1w9vMKSf++rHTuFIQvi48Q10ZiOGH1bbvlPAIVOqdjAPtnyzJR\n\
HhzmyjhjasJlk30zj+kod0kz63HzSMT9EfsYNfmYoCyMYFCKz52EU3xc87Vhi74XmZz0D0\n\
CgIj6TyZftmzC4YJCiwwU8K+29nxBhcbFRxpgwAksFL6PCSQsPl4y7yvXGcX+7lpZD8547\n\
v58q3jIkH1g2tBOusIuaiphDDStVJhVdKA55Z0Kju2kvCqsRIlf1efrq43blRgJFFFCxNZ\n\
8Cpolt4lOHhg+o3ucjILlCOgjDV8dB21YLxmgN5q+xFNAAAAgQC1P+eLUkHDFXnleCEVrW\n\
xL/DFxEyneLQz3IawGdw7cyAb7vxsYrGUvbVUFkxeiv397pDHLZ5U+t5cOYDBZ7G43Mt2g\n\
YfWBuRNvYhHA9Sdf38m5qPA6XCvm51f+FxInwd/kwRKH01RHJuRGsl/4Apu4DqVob8y00V\n\
WTYyV6JBNDkQAAAIEA322lj7ZJXfK/oLhMM/RS+DvaMea1g/q43mdRJFQQso4XRCL6IIVn\n\
oZXFeOxrMIRByVZBw+FSeB6OayWcZMySpJQBo70GdJOc3pJb3js0T+P2XA9+/jwXS58K9a\n\
+IkgLkv9XkfxNGNKyPEEzXC8QQzvjs1LbmO59VLko8ypwHq/cAAACBANQqaULI0qdwa0vm\n\
d3Ae1+k3YLZ0kapSQGVIMT2lkrhKV35tj7HIFpUPa4vitHzcUwtjYhqFezVF+JyPbJ/Fsp\n\
XmEc0g1fFnQp5/SkUwoN2zm8Up52GBelkq2Jk57mOMzWO0QzzNuNV/feJk02b2aE8rrAqP\n\
QR+u0AypRPmzHnOPAAAAEXJvb3RAMTQwOTExNTQ5NDBkAQ==\n\
-----END OPENSSH PRIVATE KEY-----";

        save_ssh_item(&vault, "Legacy RSA Host", TEST_RSA_KEY, None, true);

        let (server_io, client_io) = tokio::io::duplex(32 * 1024);
        let server_vault = vault.clone();
        let server_task = tokio::spawn(async move { serve_connection(server_vault, server_io).await });

        let mut client = AgentClient::connect(client_io);
        let identities = client.request_identities().await.unwrap();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].comment(), "openkeylet:Legacy RSA Host");
        let pub_key = identities[0].public_key().into_owned();

        let data = b"rsa-sha2-verification-payload";
        let sig_256 = client
            .sign_request_signature(&pub_key, Some(HashAlg::Sha256), data)
            .await
            .unwrap();
        assert_eq!(
            sig_256.algorithm(),
            russh::keys::Algorithm::Rsa {
                hash: Some(HashAlg::Sha256)
            }
        );
        Verifier::verify(&pub_key, data, &sig_256).unwrap();

        let sig_512 = client
            .sign_request_signature(&pub_key, Some(HashAlg::Sha512), data)
            .await
            .unwrap();
        assert_eq!(
            sig_512.algorithm(),
            russh::keys::Algorithm::Rsa {
                hash: Some(HashAlg::Sha512)
            }
        );
        Verifier::verify(&pub_key, data, &sig_512).unwrap();

        drop(client);
        server_task.await.unwrap().unwrap();
    }

    #[test]
    fn windows_pipe_name_normalization() {
        assert_eq!(
            normalize_windows_pipe_name(None).unwrap(),
            DEFAULT_WINDOWS_PIPE
        );
        assert_eq!(
            normalize_windows_pipe_name(Some("custom-agent")).unwrap(),
            r"\\.\pipe\custom-agent"
        );
        assert_eq!(
            normalize_windows_pipe_name(Some(r"\\.\pipe\explicit")).unwrap(),
            r"\\.\pipe\explicit"
        );
    }
}
