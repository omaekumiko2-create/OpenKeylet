use super::*;

pub(super) fn normalize_provider(value: &str) -> Result<String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "github" => Ok("github".to_owned()),
        "gitea" | "forgejo" => Ok("gitea".to_owned()),
        _ => bail!("GITHUB_MODE_INVALID"),
    }
}

pub(super) fn normalize_server_url(provider: &str, value: &str) -> Result<String> {
    if provider != "gitea" {
        return Ok(String::new());
    }
    let trimmed = value.trim().trim_end_matches('/');
    let url = Url::parse(trimmed).map_err(|_| anyhow::anyhow!("GITHUB_REPOSITORY_INVALID"))?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost"));
    if url.scheme() != "https" && !(cfg!(test) && url.scheme() == "http" && loopback) {
        bail!("GITHUB_REPOSITORY_INVALID");
    }
    if url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {
        bail!("GITHUB_REPOSITORY_INVALID");
    }
    Ok(trimmed.to_owned())
}

pub(super) fn gitea_api_base(server_url: &str) -> Result<Url> {
    let trimmed = server_url.trim().trim_end_matches('/');
    let base = trimmed.strip_suffix("/api/v1").unwrap_or(trimmed);
    let mut url = Url::parse(base).map_err(|_| anyhow::anyhow!("GITHUB_REPOSITORY_INVALID"))?;
    if !url.path().ends_with('/') {
        let next = format!("{}/", url.path());
        url.set_path(&next);
    }
    url.join("api/v1/")
        .map_err(|_| anyhow::anyhow!("GITHUB_REPOSITORY_INVALID"))
}

pub fn generate_recovery_key() -> Result<String> {
    let mut key = Zeroizing::new([0_u8; 32]);
    getrandom::fill(key.as_mut()).map_err(|_| anyhow::anyhow!("GITHUB_RANDOM_FAILED"))?;
    Ok(format!("okv1_{}", URL_SAFE_NO_PAD.encode(key.as_ref())))
}

pub(super) fn parse_recovery_key(value: &str) -> Result<Zeroizing<[u8; 32]>> {
    crate::crypto::parse_okv1_recovery_key(value)
}

pub(super) fn encrypt_snapshot(plain: &[u8], recovery_key: &str) -> Result<Vec<u8>> {
    if plain.len() > MAX_CLOUD_BYTES {
        bail!("GITHUB_BACKUP_TOO_LARGE");
    }
    let key = parse_recovery_key(recovery_key)?;
    let file = CloudFile {
        format: CLOUD_FORMAT.to_owned(),
        version: 1,
        cipher: "xchacha20poly1305".to_owned(),
        payload: encrypt_bytes(&key, plain, CLOUD_AAD).context("GITHUB_ENCRYPTION_FAILED")?,
    };
    let bytes = serde_json::to_vec(&file).context("GITHUB_ENCRYPTION_FAILED")?;
    if bytes.len() > MAX_CLOUD_BYTES {
        bail!("GITHUB_BACKUP_TOO_LARGE");
    }
    Ok(bytes)
}

pub(super) fn decrypt_snapshot(bytes: &[u8], recovery_key: &str) -> Result<Zeroizing<Vec<u8>>> {
    if bytes.len() > MAX_CLOUD_BYTES {
        bail!("GITHUB_BACKUP_TOO_LARGE");
    }
    let file: CloudFile = serde_json::from_slice(bytes).context("GITHUB_BACKUP_INVALID")?;
    if file.format != CLOUD_FORMAT || file.version != 1 || file.cipher != "xchacha20poly1305" {
        bail!("GITHUB_BACKUP_INVALID");
    }
    let key = parse_recovery_key(recovery_key)?;
    Ok(Zeroizing::new(
        decrypt_bytes(&key, &file.payload, CLOUD_AAD).context("GITHUB_KEY_MISMATCH")?,
    ))
}

pub(super) fn parse_repository_for(input: &str, server_url: &str) -> Result<(String, String)> {
    let trimmed = input.trim();
    let repository = if !server_url.is_empty() {
        let prefix = format!("{}/", server_url.trim().trim_end_matches('/'));
        trimmed
            .strip_prefix(&prefix)
            .or_else(|| trimmed.strip_prefix("https://github.com/"))
            .unwrap_or(trimmed)
    } else {
        trimmed.strip_prefix("https://github.com/").unwrap_or(trimmed)
    };
    parse_repository(repository)
}

pub(super) fn parse_repository(input: &str) -> Result<(String, String)> {
    let repository = input
        .trim()
        .strip_prefix("https://github.com/")
        .unwrap_or(input.trim());
    let repository = repository.trim_end_matches('/');
    let repository = repository.strip_suffix(".git").unwrap_or(repository);
    let parts: Vec<_> = repository.split('/').collect();
    if parts.len() != 2
        || parts.iter().any(|part| {
            part.is_empty()
                || part.len() > 100
                || matches!(*part, "." | "..")
                || !part
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
        })
    {
        bail!("GITHUB_REPOSITORY_INVALID");
    }
    Ok((parts[0].to_owned(), parts[1].to_owned()))
}

pub(super) fn validate_token(token: &str) -> Result<()> {
    if token.is_empty() || token.len() > 2048 || !token.bytes().all(|c| c.is_ascii_graphic()) {
        bail!("GITHUB_TOKEN_INVALID");
    }
    Ok(())
}

pub(super) fn valid_sha(sha: &str) -> bool {
    sha.len() == 40 && sha.bytes().all(|c| c.is_ascii_hexdigit())
}

pub(super) fn blob_sha(bytes: &[u8]) -> String {
    let mut hash = Sha1::new();
    hash.update(format!("blob {}\0", bytes.len()));
    hash.update(bytes);
    format!("{:x}", hash.finalize())
}

pub(super) fn decode_content(content: &str) -> Result<Vec<u8>> {
    if content.len() > MAX_RESPONSE_BYTES {
        bail!("GITHUB_BACKUP_TOO_LARGE");
    }
    let compact: String = content
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let bytes = STANDARD.decode(compact).context("GITHUB_BACKUP_INVALID")?;
    if bytes.len() > MAX_CLOUD_BYTES {
        bail!("GITHUB_BACKUP_TOO_LARGE");
    }
    Ok(bytes)
}

pub(super) fn check_response(response: &Response) -> Result<()> {
    if response.status().is_success() {
        return Ok(());
    }
    // Never echo GitHub response bodies: error messages can contain supplied
    // content, repository descriptions or credentials from a proxy.
    match response.status() {
        StatusCode::UNAUTHORIZED => bail!("GITHUB_AUTH"),
        StatusCode::FORBIDDEN
            if response
                .headers()
                .get("x-ratelimit-remaining")
                .is_some_and(|value| value == "0")
                || response.headers().contains_key("retry-after") =>
        {
            bail!("GITHUB_RATE_LIMIT")
        }
        StatusCode::FORBIDDEN => bail!("GITHUB_PERMISSION"),
        StatusCode::TOO_MANY_REQUESTS => bail!("GITHUB_RATE_LIMIT"),
        StatusCode::NOT_FOUND => bail!("GITHUB_NOT_FOUND"),
        StatusCode::CONFLICT | StatusCode::UNPROCESSABLE_ENTITY => bail!("GITHUB_CONFLICT"),
        status if status.is_redirection() => bail!("GITHUB_REDIRECT"),
        _ => bail!("GITHUB_REMOTE_ERROR"),
    }
}

pub(super) async fn read_json<T: DeserializeOwned>(mut response: Response) -> Result<T> {
    if response
        .content_length()
        .is_some_and(|size| size > MAX_RESPONSE_BYTES as u64)
    {
        bail!("GITHUB_BACKUP_TOO_LARGE");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.context("GITHUB_NETWORK")? {
        if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
            bail!("GITHUB_BACKUP_TOO_LARGE");
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).context("GITHUB_RESPONSE_INVALID")
}

