//! Git HTTPS Credential Helper (`openkeylet git-credential <get|store|erase>`).
//!
//! Implements Git's standard `git-credential` key=value stdio protocol:
//! - `get`: resolves matching enabled vault credentials for HTTPS (or loopback HTTP)
//!   targets, writes `username=...\npassword=...\n\n`, and logs an audit activity.
//! - `store` / `erase`: intentional no-op exit 0 so Git never mutates or deletes
//!   vault entries silently.

use crate::{
    login_uri,
    model::NewActivity,
    vault::{DecryptedConnection, Vault},
};
use anyhow::{Result, bail};
use std::{
    io::{Read, Write},
    time::Instant,
};
use url::Url;
use zeroize::Zeroizing;

pub const GIT_CREDENTIAL_USAGE: &str = "Usage: openkeylet git-credential <get|store|erase>";

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GitCredentialRequest {
    pub protocol: String,
    pub host: String,
    pub path: Option<String>,
    pub username: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedGitCredential {
    pub item_name: String,
    pub username: String,
    pub password: Zeroizing<String>,
}

/// Parse Git's `key=value` stdin stream up to the first blank line or EOF.
pub fn parse_git_credential_input(input: &str) -> GitCredentialRequest {
    let mut req = GitCredentialRequest::default();
    let mut fallback_url: Option<String> = None;

    for raw_line in input.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "protocol" => req.protocol = value.to_ascii_lowercase(),
            "host" => req.host = value.to_owned(),
            "path" if !value.is_empty() => req.path = Some(value.to_owned()),
            "username" if !value.is_empty() => req.username = Some(value.to_owned()),
            "url" if !value.is_empty() => fallback_url = Some(value.to_owned()),
            _ => {}
        }
    }

    if (req.protocol.is_empty() || req.host.is_empty())
        && let Some(raw_url) = fallback_url
        && let Ok(parsed) = Url::parse(&raw_url)
    {
        if req.protocol.is_empty() {
            req.protocol = parsed.scheme().to_ascii_lowercase();
        }
        if req.host.is_empty()
            && let Some(host) = parsed.host_str()
        {
            req.host = match parsed.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_owned(),
            };
        }
        if req.username.is_none() && !parsed.username().is_empty() {
            req.username = Some(parsed.username().to_owned());
        }
        if req.path.is_none() {
            let path = parsed.path().trim_start_matches('/');
            if !path.is_empty() {
                req.path = Some(path.to_owned());
            }
        }
    }

    req
}

fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

fn is_git_forge_host(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "github.com" | "gitlab.com" | "codeberg.org" | "bitbucket.org" | "dev.azure.com"
            | "huggingface.co"
    ) || lower.ends_with(".github.com")
        || lower.ends_with(".gitlab.com")
        || lower.starts_with("git.")
        || lower.starts_with("gitea.")
        || lower.starts_with("gitlab.")
}

fn is_token_placeholder_username(username: &str) -> bool {
    matches!(
        username.to_ascii_lowercase().as_str(),
        "x-access-token" | "oauth2" | "git" | "token"
    )
}

fn is_safe_protocol_value(value: &str) -> bool {
    !value.is_empty() && !value.contains('\n') && !value.contains('\r') && !value.contains('\0')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostMatchTier {
    Exact,
    ApiSubdomainFallback,
}

fn match_item_to_target(
    conn: &DecryptedConnection,
    target_origin_url: &Url,
    target_full_str: &str,
    target_origin_str: &str,
) -> Option<HostMatchTier> {
    // 1. Explicit `login_uris` rules take highest precedence.
    if !conn.stored.login_uris.is_empty() {
        let matched = conn.stored.login_uris.iter().any(|rule| {
            login_uri::matches(rule, target_full_str)
                || (target_full_str != target_origin_str
                    && login_uri::matches(rule, target_origin_str))
        });
        if matched {
            return Some(HostMatchTier::Exact);
        }
    }

    // 2. Fallback to item `base_url` (or `url` module).
    let raw_base = conn.stored.base_url.trim();
    if raw_base.is_empty() {
        return None;
    }
    let normalized_base = if raw_base.contains("://") {
        raw_base.to_owned()
    } else {
        format!("https://{raw_base}")
    };
    let Ok(saved_url) = Url::parse(&normalized_base) else {
        return None;
    };

    if saved_url.scheme() != target_origin_url.scheme() {
        return None;
    }
    if saved_url.port_or_known_default() != target_origin_url.port_or_known_default() {
        return None;
    }

    let saved_host = saved_url.host_str()?;
    let target_host = target_origin_url.host_str()?;

    if saved_host.eq_ignore_ascii_case(target_host) {
        return Some(HostMatchTier::Exact);
    }

    // Allow HTTPS API items such as `https://api.github.com/` (auto-created for GitHub PATs)
    // to authenticate HTTPS Git operations against `github.com` when no exact match exists.
    if target_origin_url.scheme() == "https"
        && saved_host.eq_ignore_ascii_case(&format!("api.{target_host}"))
        && conn
            .secrets
            .get("apiCredential")
            .or_else(|| conn.secrets.get("token"))
            .or_else(|| conn.secrets.get("apiKey"))
            .is_some()
    {
        return Some(HostMatchTier::ApiSubdomainFallback);
    }

    None
}

fn extract_credential(
    conn: &DecryptedConnection,
    requested_username: Option<&str>,
    target_host: &str,
) -> Option<(String, Zeroizing<String>, bool)> {
    let saved_username = conn
        .secrets
        .get("username")
        .map(str::trim)
        .filter(|u| !u.is_empty());
    let api_token = conn
        .secrets
        .get("apiCredential")
        .or_else(|| conn.secrets.get("token"))
        .or_else(|| conn.secrets.get("apiKey"));
    let password = conn.secrets.get("password");

    let req_user = requested_username.map(str::trim).filter(|u| !u.is_empty());
    let prefer_token = is_git_forge_host(target_host)
        || req_user.is_some_and(is_token_placeholder_username)
        || password.is_none();

    let (secret, is_token) = if prefer_token {
        if let Some(tok) = api_token {
            (tok, true)
        } else if let Some(pw) = password {
            (pw, false)
        } else {
            return None;
        }
    } else if let Some(pw) = password {
        (pw, false)
    } else if let Some(tok) = api_token {
        (tok, true)
    } else {
        return None;
    };

    let username = match (req_user, saved_username) {
        (Some(req), Some(saved)) => {
            if saved.eq_ignore_ascii_case(req) {
                saved.to_owned()
            } else if is_token && is_token_placeholder_username(req) {
                req.to_owned()
            } else {
                return None;
            }
        }
        (Some(req), None) => {
            // An item without a username can satisfy a requested username only when it's a token placeholder.
            if is_token && is_token_placeholder_username(req) {
                req.to_owned()
            } else {
                return None;
            }
        }
        (None, Some(saved)) => saved.to_owned(),
        (None, None) => {
            if is_token {
                "x-access-token".to_owned()
            } else {
                return None;
            }
        }
    };

    if !is_safe_protocol_value(&username) || !is_safe_protocol_value(secret) {
        return None;
    }

    let exact_user_match = matches!(
        (req_user, saved_username),
        (Some(req), Some(saved)) if saved.eq_ignore_ascii_case(req)
    );
    Some((username, Zeroizing::new(secret.to_owned()), exact_user_match))
}

/// Resolve a Git HTTPS credential request against enabled vault items.
/// Returns `Ok(None)` when the protocol is disallowed, no item matches, or
/// multiple items match ambiguously (standard git-credential fallthrough).
pub fn resolve_git_credential(
    vault: &Vault,
    request: &GitCredentialRequest,
) -> Result<Option<ResolvedGitCredential>> {
    let started = Instant::now();
    let protocol = request.protocol.trim().to_ascii_lowercase();
    let host = request.host.trim();
    if protocol.is_empty() || host.is_empty() {
        return Ok(None);
    }
    if protocol != "https" && protocol != "http" {
        return Ok(None);
    }

    let origin_str = format!("{protocol}://{host}");
    let Ok(origin_url) = Url::parse(&origin_str) else {
        return Ok(None);
    };
    let Some(target_host) = origin_url.host_str() else {
        return Ok(None);
    };
    if protocol == "http" && !is_loopback_host(&origin_url) {
        return Ok(None);
    }

    let full_str = match request
        .path
        .as_deref()
        .map(|p| p.trim_start_matches('/'))
        .filter(|p| !p.is_empty())
    {
        Some(path) => format!("{origin_str}/{path}"),
        None => origin_str.clone(),
    };

    let connections = vault.list_decrypted_connections()?;
    let mut exact_matches: Vec<(ResolvedGitCredential, bool)> = Vec::new();
    let mut fallback_matches: Vec<(ResolvedGitCredential, bool)> = Vec::new();

    for conn in connections {
        if !conn.stored.enabled {
            continue;
        }
        let Some(tier) = match_item_to_target(&conn, &origin_url, &full_str, &origin_str) else {
            continue;
        };
        let Some((username, password, exact_user)) =
            extract_credential(&conn, request.username.as_deref(), target_host)
        else {
            continue;
        };
        let entry = (
            ResolvedGitCredential {
                item_name: conn.stored.name,
                username,
                password,
            },
            exact_user,
        );
        match tier {
            HostMatchTier::Exact => exact_matches.push(entry),
            HostMatchTier::ApiSubdomainFallback => fallback_matches.push(entry),
        }
    }

    let pool = if !exact_matches.is_empty() {
        exact_matches
    } else {
        fallback_matches
    };

    // If a requested username matched saved usernames explicitly, prefer those over placeholder matches.
    let narrowed: Vec<ResolvedGitCredential> =
        if pool.len() > 1 && pool.iter().any(|(_, exact_user)| *exact_user) {
            pool.into_iter()
                .filter(|(_, exact_user)| *exact_user)
                .map(|(cred, _)| cred)
                .collect()
        } else {
            pool.into_iter().map(|(cred, _)| cred).collect()
        };

    // Standard git-credential convention: 0 or >1 matches -> emit nothing so Git falls through.
    if narrowed.len() != 1 {
        return Ok(None);
    }

    let resolved = narrowed.into_iter().next().unwrap();
    let _ = vault.add_activity(NewActivity {
        status: "success".to_owned(),
        source: "GIT CREDENTIAL".to_owned(),
        connection_name: resolved.item_name.clone(),
        action: format!("Git HTTPS credential for {host}"),
        duration_ms: started.elapsed().as_millis() as u64,
        error: String::new(),
    });
    Ok(Some(resolved))
}

pub fn format_git_credential_output(cred: &ResolvedGitCredential) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "username={}\npassword={}\n\n",
        cred.username,
        cred.password.as_str()
    ))
}

/// Entrypoint for `openkeylet git-credential <get|store|erase>`.
pub fn run_cli(vault: &Vault, args: &[String]) -> Result<()> {
    let action = match args {
        [action] => action.as_str(),
        _ => bail!("{GIT_CREDENTIAL_USAGE}"),
    };
    match action {
        "get" => {
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input)?;
            let req = parse_git_credential_input(&input);
            if let Some(cred) = resolve_git_credential(vault, &req)? {
                let output = format_git_credential_output(&cred);
                let mut stdout = std::io::stdout().lock();
                stdout.write_all(output.as_bytes())?;
                stdout.flush()?;
            }
            Ok(())
        }
        // Intentionally never mutate or erase vault items from Git callbacks.
        "store" | "erase" => Ok(()),
        _ => bail!("{GIT_CREDENTIAL_USAGE}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        login_uri::LoginUri,
        model::{ConnectionInput, ItemModule, SecretBundle},
    };
    use tempfile::tempdir;

    #[allow(clippy::too_many_arguments)]
    fn save_git_item(
        vault: &Vault,
        name: &str,
        enabled: bool,
        url: &str,
        login_uris: Vec<LoginUri>,
        username: Option<&str>,
        password: Option<&str>,
        api_credential: Option<&str>,
    ) {
        let mut modules = Vec::new();
        let mut secrets = SecretBundle::default();
        if !url.is_empty() {
            modules.push(ItemModule {
                kind: "url".to_owned(),
                name: "url".to_owned(),
                value: url.to_owned(),
                agent_visible: Some(true),
            });
        }
        if let Some(u) = username {
            modules.push(ItemModule {
                kind: "username".to_owned(),
                name: "username".to_owned(),
                value: String::new(),
                agent_visible: Some(false),
            });
            secrets.named_secrets.insert("username".to_owned(), u.to_owned());
        }
        if let Some(p) = password {
            modules.push(ItemModule {
                kind: "password".to_owned(),
                name: "password".to_owned(),
                value: String::new(),
                agent_visible: Some(false),
            });
            secrets.password = Some(p.to_owned());
        }
        if let Some(tok) = api_credential {
            modules.push(ItemModule {
                kind: "apiCredential".to_owned(),
                name: "apiCredential".to_owned(),
                value: String::new(),
                agent_visible: Some(false),
            });
            secrets
                .named_secrets
                .insert("apiCredential".to_owned(), tok.to_owned());
        }
        vault
            .save_connection(ConnectionInput {
                login_uris,
                item_type: "login".to_owned(),
                folder: String::new(),
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
            .unwrap();
    }

    #[test]
    fn resolves_https_git_token_and_prefers_api_credential_on_git_forges() {
        let dir = tempdir().unwrap();
        let vault = Vault::open(dir.path().join("vault")).unwrap();
        save_git_item(
            &vault,
            "GitHub Account",
            true,
            "https://github.com",
            vec![LoginUri {
                uri: "https://github.com".to_owned(),
                match_type: "host".to_owned(),
            }],
            Some("octocat"),
            Some("web-login-password"),
            Some("ghp_realpat1234567890"),
        );

        let req = parse_git_credential_input("protocol=https\nhost=github.com\n\n");
        let cred = resolve_git_credential(&vault, &req).unwrap().unwrap();
        assert_eq!(cred.username, "octocat");
        assert_eq!(cred.password.as_str(), "ghp_realpat1234567890");
        assert_eq!(
            format_git_credential_output(&cred).as_str(),
            "username=octocat\npassword=ghp_realpat1234567890\n\n"
        );

        // Audit log recorded with GIT CREDENTIAL source.
        let activities = vault.activities().unwrap();
        assert_eq!(activities.len(), 1);
        assert_eq!(activities[0].source, "GIT CREDENTIAL");
        assert_eq!(activities[0].connection_name, "GitHub Account");
    }

    #[test]
    fn api_subdomain_fallback_matches_github_pat_items() {
        let dir = tempdir().unwrap();
        let vault = Vault::open(dir.path().join("vault")).unwrap();
        save_git_item(
            &vault,
            "GitHub API",
            true,
            "https://api.github.com/",
            Vec::new(),
            None,
            None,
            Some("github_pat_xyz987654321"),
        );

        let req = parse_git_credential_input("protocol=https\nhost=github.com\n\n");
        let cred = resolve_git_credential(&vault, &req).unwrap().unwrap();
        assert_eq!(cred.username, "x-access-token");
        assert_eq!(cred.password.as_str(), "github_pat_xyz987654321");
    }

    #[test]
    fn refuses_non_localhost_http_and_allows_loopback_http() {
        let dir = tempdir().unwrap();
        let vault = Vault::open(dir.path().join("vault")).unwrap();
        save_git_item(
            &vault,
            "Remote Git",
            true,
            "http://git.example.com",
            Vec::new(),
            Some("dev"),
            Some("secret-remote"),
            None,
        );
        save_git_item(
            &vault,
            "Local Gitea",
            true,
            "http://127.0.0.1:3000",
            Vec::new(),
            Some("localdev"),
            Some("secret-local"),
            None,
        );

        let remote_http = parse_git_credential_input("protocol=http\nhost=git.example.com\n\n");
        assert!(resolve_git_credential(&vault, &remote_http).unwrap().is_none());

        let local_http = parse_git_credential_input("protocol=http\nhost=127.0.0.1:3000\n\n");
        let cred = resolve_git_credential(&vault, &local_http).unwrap().unwrap();
        assert_eq!(cred.username, "localdev");
        assert_eq!(cred.password.as_str(), "secret-local");
    }

    #[test]
    fn excludes_disabled_items_and_handles_ambiguity_with_username_filter() {
        let dir = tempdir().unwrap();
        let vault = Vault::open(dir.path().join("vault")).unwrap();
        save_git_item(
            &vault,
            "Disabled GitLab",
            false,
            "https://gitlab.com",
            Vec::new(),
            Some("disabled-user"),
            Some("pw-disabled"),
            None,
        );
        save_git_item(
            &vault,
            "Work GitLab",
            true,
            "https://gitlab.com",
            Vec::new(),
            Some("alice"),
            None,
            Some("glpat-alice-111"),
        );
        save_git_item(
            &vault,
            "Personal GitLab",
            true,
            "https://gitlab.com",
            Vec::new(),
            Some("bob"),
            None,
            Some("glpat-bob-222"),
        );

        // Disabled user is never returned.
        let disabled_req =
            parse_git_credential_input("protocol=https\nhost=gitlab.com\nusername=disabled-user\n");
        assert!(resolve_git_credential(&vault, &disabled_req).unwrap().is_none());

        // Ambiguous without username -> returns None silently.
        let ambig_req = parse_git_credential_input("protocol=https\nhost=gitlab.com\n");
        assert!(resolve_git_credential(&vault, &ambig_req).unwrap().is_none());

        // Username disambiguates cleanly.
        let bob_req =
            parse_git_credential_input("protocol=https\nhost=gitlab.com\nusername=bob\n");
        let cred = resolve_git_credential(&vault, &bob_req).unwrap().unwrap();
        assert_eq!(cred.username, "bob");
        assert_eq!(cred.password.as_str(), "glpat-bob-222");
    }

    #[test]
    fn store_and_erase_are_safe_noops() {
        let dir = tempdir().unwrap();
        let vault = Vault::open(dir.path().join("vault")).unwrap();
        save_git_item(
            &vault,
            "Keep Me",
            true,
            "https://github.com",
            Vec::new(),
            Some("alice"),
            Some("pw123"),
            None,
        );

        run_cli(&vault, &["store".to_owned()]).unwrap();
        run_cli(&vault, &["erase".to_owned()]).unwrap();

        let items = vault.list_connections().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "Keep Me");
    }

    #[test]
    fn parses_url_fallback_and_ignores_trailing_lines_after_blank() {
        let req = parse_git_credential_input(
            "url=https://octocat@github.com:443/org/repo.git\n\nprotocol=http\nhost=evil.example\n",
        );
        assert_eq!(req.protocol, "https");
        assert_eq!(req.host, "github.com");
        assert_eq!(req.username.as_deref(), Some("octocat"));
        assert_eq!(req.path.as_deref(), Some("org/repo.git"));
    }
}
