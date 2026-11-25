//! The key repository: a second private repository, next to the one holding the
//! encrypted snapshot, that stores the sync key. Binding the account is then enough
//! to restore on another device, and no single repository holds both the ciphertext
//! and the key that opens it.
use super::*;

pub(super) const KEY_FILE: &str = "openkeylet.key.json";
const KEY_FORMAT: &str = "openkeylet-sync-key";
const KEY_REPO_SUFFIX: &str = "-key";
const MAX_KEY_FILE_BYTES: usize = 4096;

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    format: String,
    version: u8,
    key: String,
}

/// Name of the key repository that belongs to the vault repository `vault_repo`.
pub(super) fn key_repo_name(owner: &str, vault_repo: &str) -> Result<String> {
    let name = format!("{vault_repo}{KEY_REPO_SUFFIX}");
    parse_repository(&format!("{owner}/{name}"))?;
    Ok(name)
}

impl GithubBackup {
    /// Reads the sync key from the key repository. `None` means the repository or its
    /// key file does not exist, or this token cannot see it.
    pub(super) async fn read_repo_key(
        &self,
        owner: &str,
        key_repo: &str,
        token: &str,
        provider: &str,
        server_url: &str,
    ) -> Result<Option<Zeroizing<String>>> {
        let Some(repository) = self
            .find_repository(owner, key_repo, token, provider, server_url)
            .await?
        else {
            return Ok(None);
        };
        let response = self
            .request_for(
                Method::GET,
                owner,
                key_repo,
                &["contents", KEY_FILE],
                token,
                provider,
                server_url,
            )?
            .query(&[("ref", &repository.default_branch)])
            .send()
            .await
            .context("GITHUB_NETWORK")?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        check_response(&response)?;
        let file: ContentFile = read_json(response).await?;
        if file.kind != "file" || file.encoding != "base64" || file.size > MAX_KEY_FILE_BYTES {
            bail!("GITHUB_KEY_REPO_INVALID");
        }
        let bytes = Zeroizing::new(
            decode_content(&file.content).map_err(|_| anyhow::anyhow!("GITHUB_KEY_REPO_INVALID"))?,
        );
        let parsed: KeyFile = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("GITHUB_KEY_REPO_INVALID"))?;
        if parsed.format != KEY_FORMAT
            || parsed.version != 1
            || parse_recovery_key(&parsed.key).is_err()
        {
            bail!("GITHUB_KEY_REPO_INVALID");
        }
        Ok(Some(Zeroizing::new(parsed.key.clone())))
    }

    /// Creates the key repository when it is missing, then stores a fresh sync key in it.
    pub(super) async fn create_repo_key(
        &self,
        owner: &str,
        key_repo: &str,
        token: &str,
        provider: &str,
        server_url: &str,
    ) -> Result<Zeroizing<String>> {
        let repository = match self
            .find_repository(owner, key_repo, token, provider, server_url)
            .await?
        {
            Some(repository) => repository,
            None => {
                // `POST /user/repos` only creates under the authenticated account, so a
                // key repository for an organization has to be created by its owner.
                let user = self.user(token, provider, server_url).await?;
                if !user.login.eq_ignore_ascii_case(owner) {
                    bail!("GITHUB_KEY_REPO_CREATE");
                }
                let response = self
                    .api_request_for(Method::POST, &["user", "repos"], token, provider, server_url)?
                    .json(&serde_json::json!({
                        "name": key_repo,
                        "private": true,
                        "auto_init": true,
                        "description": "OpenKeylet sync key. Keep this repository private.",
                    }))
                    .send()
                    .await
                    .context("GITHUB_CREATE_UNCONFIRMED")?;
                // 422 means another device created it first; the lookup below settles it.
                if response.status() != StatusCode::UNPROCESSABLE_ENTITY {
                    if response.status().is_server_error() {
                        bail!("GITHUB_CREATE_UNCONFIRMED");
                    }
                    check_response(&response).map_err(|error| match error.to_string().as_str() {
                        "GITHUB_PERMISSION" | "GITHUB_NOT_FOUND" => {
                            anyhow::anyhow!("GITHUB_KEY_REPO_CREATE")
                        }
                        _ => error,
                    })?;
                }
                self.find_repository(owner, key_repo, token, provider, server_url)
                    .await?
                    .context("GITHUB_CREATE_UNCONFIRMED")?
            }
        };

        let key = Zeroizing::new(generate_recovery_key()?);
        let body = Zeroizing::new(
            serde_json::to_vec(&KeyFile {
                format: KEY_FORMAT.to_owned(),
                version: 1,
                key: key.to_string(),
            })
            .context("GITHUB_ENCRYPTION_FAILED")?,
        );
        let method = if provider == "gitea" {
            Method::POST
        } else {
            Method::PUT
        };
        let response = self
            .request_for(
                method,
                owner,
                key_repo,
                &["contents", KEY_FILE],
                token,
                provider,
                server_url,
            )?
            .json(&serde_json::json!({
                "message": "Add OpenKeylet sync key",
                "content": STANDARD.encode(&*body),
                "branch": repository.default_branch,
            }))
            .send()
            .await
            .context("GITHUB_UPLOAD_UNCONFIRMED")?;
        check_response(&response)?;
        let result: serde_json::Value = read_json(response).await?;
        if result
            .pointer("/content/sha")
            .and_then(|value| value.as_str())
            != Some(blob_sha(&body).as_str())
        {
            bail!("GITHUB_UPLOAD_UNCONFIRMED");
        }
        Ok(key)
    }
}
