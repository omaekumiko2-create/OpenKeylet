use crate::{
    model::{SecretBundle, StoredConnection},
    policy::{
        Redactor, api_target_allowed, api_target_refusal, blocked_header_names,
        body_contains_secret, connection_redaction_candidates, normalize_api_request_method,
        redaction_candidates, redirect_target_supported,
        strip_cross_origin_redirect_auth, validate_ssh_command, visible_response_headers,
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
mod http;
mod local;
mod sftp;
mod ssh;
pub mod terminal;

pub use http::{ApiRequestInput, ApiResponse, ApiUploadFile, HttpCandidate, SshResponse, SshTransferResponse, describe_api_request, execute_api};
pub(crate) use http::{RawApiResponse, api_request_target, execute_api_raw, execute_api_scoped, sanitize_api_body};
pub use local::execute_local;
pub use sftp::{ssh_download, ssh_upload};
pub use ssh::{execute_ssh, execute_ssh_redacting, test_connection};
pub(crate) use ssh::shell_quote;
use http::*;
use sftp::*;
use ssh::*;

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

    fn finish(self, redactor: &Redactor) -> (String, bool) {
        if self.omitted_bytes == 0 {
            let mut combined = self.head;
            combined.extend(self.tail);
            return (
                String::from_utf8_lossy(&redactor.redact_bytes(&combined)).into_owned(),
                false,
            );
        }
        // Head and tail are redacted separately, so a secret straddling either cut would
        // leave its first or last bytes visible; drop such fragments with the omitted part.
        let (head, head_kept) = redactor.redact_stream(&self.head, true);
        let tail_bytes: Vec<u8> = self.tail.into_iter().collect();
        let tail_fragment = redactor.leading_fragment_len(&tail_bytes);
        let tail = redactor.redact_bytes(&tail_bytes[tail_fragment..]);
        let omitted = self.omitted_bytes + (self.head.len() - head_kept) + tail_fragment;
        let notice = format!(
            "\n…[Output truncated: omitted {omitted} bytes; pass maxOutputBytes=0 for unlimited]\n"
        );
        (
            format!(
                "{}{notice}{}",
                String::from_utf8_lossy(&head),
                String::from_utf8_lossy(&tail)
            ),
            true,
        )
    }
}

/// The matcher for a command's output: every hidden value of the item the command used plus
/// `extra` (substituted values from other items and the MCP session's redaction set).
fn output_redactor(connection: Option<&DecryptedConnection>, extra: &[String]) -> Redactor {
    let mut candidates = connection
        .map(|connection| connection_redaction_candidates(&connection.secrets))
        .unwrap_or_default();
    candidates.extend(redaction_candidates(extra));
    Redactor::new(&candidates)
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


#[cfg(test)]
mod tests;
