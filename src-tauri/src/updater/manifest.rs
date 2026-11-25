use super::*;

pub(super) fn is_allowed_update_url(raw: &str, custom_origin: Option<&str>) -> bool {
    let Ok(parsed) = Url::parse(raw) else {
        return false;
    };
    if let Some(allowed_origin) = custom_origin {
        if parsed.origin().ascii_serialization() == allowed_origin
            && matches!(parsed.scheme(), "http" | "https")
        {
            return true;
        }
    }
    if parsed.scheme() != "https" {
        return false;
    }
    let Some(host) = parsed.host_str() else {
        return false;
    };
    ALLOWED_GITHUB_HOSTS
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed))
}

pub(super) fn build_http_client(
    connect_timeout: Duration,
    total_timeout: Duration,
    custom_origin: Option<String>,
) -> Result<reqwest::Client> {
    let policy = Policy::custom(move |attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error("UPDATE_REDIRECT_LIMIT: Too many redirects while contacting GitHub Releases");
        }
        if !is_allowed_update_url(attempt.url().as_str(), custom_origin.as_deref()) {
            return attempt.error("UPDATE_URL_REJECTED: Update redirect pointed outside GitHub Releases");
        }
        attempt.follow()
    });
    reqwest::Client::builder()
        .user_agent(format!("OpenKeylet/{}", current_version()))
        .connect_timeout(connect_timeout)
        .timeout(total_timeout)
        .redirect(policy)
        .build()
        .context("UPDATE_HTTP_CLIENT: Unable to initialize update HTTP client")
}

pub fn verify_signed_manifest(
    raw: &[u8],
    public_key_b64: Option<&str>,
    custom_origin: Option<&str>,
) -> Result<(ReleaseManifest, bool)> {
    if raw.len() > MAX_MANIFEST_BYTES {
        bail!("UPDATE_MANIFEST_TOO_LARGE: Update manifest exceeds 256 KiB limit");
    }
    let envelope: SignedManifestEnvelope = serde_json::from_slice(raw)
        .context("UPDATE_MANIFEST_INVALID: Release manifest is not valid JSON")?;
    if envelope.format != MANIFEST_ENVELOPE_FORMAT {
        bail!(
            "UPDATE_MANIFEST_FORMAT: Unsupported update manifest format '{}'",
            envelope.format
        );
    }

    let signature_verified = if let Some(pk_b64) = public_key_b64.filter(|key| !key.trim().is_empty())
    {
        let pk_bytes = BASE64
            .decode(pk_b64.trim())
            .context("UPDATE_PUBLIC_KEY_INVALID: Embedded update public key is invalid base64")?;
        if pk_bytes.len() != 32 {
            bail!("UPDATE_PUBLIC_KEY_INVALID: Embedded Ed25519 public key must be 32 bytes");
        }
        let sig_bytes = BASE64
            .decode(envelope.signature.trim())
            .context("UPDATE_SIGNATURE_INVALID: Release manifest signature is invalid base64")?;
        if sig_bytes.len() != 64 {
            bail!("UPDATE_SIGNATURE_INVALID: Ed25519 signature must be 64 bytes");
        }
        let mut signing_input =
            Vec::with_capacity(MANIFEST_ENVELOPE_FORMAT.len() + 1 + envelope.payload.len());
        signing_input.extend_from_slice(MANIFEST_ENVELOPE_FORMAT.as_bytes());
        signing_input.push(b'\n');
        signing_input.extend_from_slice(envelope.payload.as_bytes());
        UnparsedPublicKey::new(&ED25519, &pk_bytes)
            .verify(&signing_input, &sig_bytes)
            .map_err(|_| {
                anyhow!("UPDATE_SIGNATURE_INVALID: Release manifest Ed25519 signature verification failed")
            })?;
        true
    } else {
        false
    };

    let manifest: ReleaseManifest = serde_json::from_str(&envelope.payload)
        .context("UPDATE_MANIFEST_INVALID: Signed payload is not a valid release manifest")?;
    if manifest.schema_version != 1 {
        bail!(
            "UPDATE_MANIFEST_SCHEMA: Unsupported manifest schema version {}",
            manifest.schema_version
        );
    }
    Version::parse(manifest.version.trim())
        .context("UPDATE_VERSION_INVALID: Release manifest version is not valid SemVer")?;
    if !is_allowed_update_url(&manifest.release_url, custom_origin) {
        bail!("UPDATE_URL_REJECTED: Release page URL is outside GitHub Releases");
    }
    for asset in manifest.platforms.values() {
        if !is_allowed_update_url(&asset.url, custom_origin) {
            bail!("UPDATE_URL_REJECTED: Release asset URL is outside GitHub Releases");
        }
        if !is_valid_sha256_hex(&asset.sha256) {
            bail!("UPDATE_MANIFEST_INVALID: Release asset SHA-256 is malformed");
        }
        if asset.size == 0 || asset.size > MAX_ARCHIVE_BYTES {
            bail!("UPDATE_MANIFEST_INVALID: Release asset size is out of allowed bounds");
        }
        if !matches!(asset.format.as_str(), "zip" | "tar.gz") {
            bail!("UPDATE_MANIFEST_INVALID: Unsupported archive format '{}'", asset.format);
        }
    }
    Ok((manifest, signature_verified))
}

pub(super) fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn is_newer_version(current: &str, candidate: &str) -> Result<bool> {
    let current = Version::parse(current.trim().trim_start_matches('v'))
        .context("Current application version is not valid SemVer")?;
    let candidate = Version::parse(candidate.trim().trim_start_matches('v'))
        .context("UPDATE_VERSION_INVALID: Remote version is not valid SemVer")?;
    Ok(candidate > current)
}


pub(super) async fn fetch_and_verify_manifest(
    url: &str,
    public_key_b64: Option<&str>,
    custom_origin: Option<&str>,
) -> Result<(ReleaseManifest, bool)> {
    if !is_allowed_update_url(url, custom_origin) {
        bail!("UPDATE_URL_REJECTED: Update manifest URL is outside GitHub Releases");
    }
    let client = build_http_client(
        Duration::from_secs(10),
        Duration::from_secs(15),
        custom_origin.map(str::to_owned),
    )?;
    let response = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .context("UPDATE_NETWORK: Unable to reach GitHub Releases")?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        bail!("UPDATE_MANIFEST_MISSING: No signed update manifest (latest.json) is published on the latest GitHub Release yet");
    }
    if !response.status().is_success() {
        bail!(
            "UPDATE_HTTP_STATUS: GitHub Releases returned HTTP {}",
            response.status().as_u16()
        );
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("UPDATE_NETWORK: Failed while reading update manifest")?;
        if bytes.len().saturating_add(chunk.len()) > MAX_MANIFEST_BYTES {
            bail!("UPDATE_MANIFEST_TOO_LARGE: Update manifest exceeds 256 KiB limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    verify_signed_manifest(&bytes, public_key_b64, custom_origin)
}

