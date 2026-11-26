//! Local encrypted HTTP response receipts for saving newly issued secrets
//! (`http_send` with `holdResponse: true` or `captureSecrets` fallback) without
//! exposing one-time keys in MCP output or repeating issuance requests.
use super::*;
use crate::exec::HttpCandidate;
use std::collections::BTreeMap;

pub(super) const CAPTURE_LIMIT: usize = 1024 * 1024;
const MAX_RECEIPTS: usize = 8;
const LIFETIME: Duration = Duration::from_secs(300);

pub(super) struct HeldResponse {
    id: Uuid,
    item: Uuid,
    created: Instant,
    encrypted: crate::model::SecretEnvelope,
}

#[derive(Serialize, Deserialize)]
struct LocalResponse {
    body: String,
    headers: BTreeMap<String, String>,
    truncated: bool,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SaveHttpInput {
    pub(super) response_id: String,
    #[schemars(
        description = "Vault fields mapped to #slot, a JSON path, $ for a plain-text key, or header:Name."
    )]
    pub(super) capture_secrets: BTreeMap<String, String>,
}

pub(super) fn validate_captures(specs: &BTreeMap<String, String>) -> Result<(), String> {
    if specs.len() > 32
        || specs.iter().any(|(field, path)| {
            field.trim() != field
                || field.is_empty()
                || field.chars().count() > 64
                || field.contains(['/', '{', '}'])
                || field.chars().any(char::is_control)
                || path.trim().is_empty()
                || path.len() > 512
        })
    {
        return Err("Invalid capture mapping. Use a short field name and a slot or path.".into());
    }
    Ok(())
}

fn kind(name: &str) -> &'static str {
    match name.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
        "accesstoken" | "xauthtoken" | "authtoken" | "bearertoken" | "personalaccesstoken" => {
            "accessToken"
        }
        "refreshtoken" | "refresh" => "refreshToken",
        "apikey" | "xapikey" | "apicredential" | "apitoken" | "secretaccesskey" => "apiKey",
        "clientsecret" => "clientSecret",
        "token" | "secret" | "password" | "idtoken" | "privatekey" => "credential",
        _ => "value",
    }
}

fn candidates<'a>(
    local: &'a LocalResponse,
    json: Option<&'a Value>,
) -> Vec<(&'static str, &'a str)> {
    fn visit<'a>(out: &mut Vec<(&'static str, &'a str)>, label: &'static str, node: &'a Value) {
        if out.len() >= 128 {
            return;
        }
        match node {
            Value::String(value) if !value.is_empty() => out.push((label, value)),
            Value::Object(obj) => {
                for (key, child) in obj {
                    visit(out, kind(key), child);
                }
            }
            Value::Array(arr) => {
                for child in arr {
                    visit(out, label, child);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    for (name, value) in &local.headers {
        let label = kind(name);
        if label != "value" && out.len() < 128 {
            out.push((label, value.as_str()));
        }
    }
    if !local.truncated {
        if let Some(json) = json {
            visit(&mut out, "value", json);
        } else if !local.body.trim().is_empty() {
            out.push(("body", local.body.trim()));
        }
    }
    out
}

impl VaultMcp {
    /// Processes an `http_send` response when `hold_response` is true or
    /// `capture_secrets` is non-empty.
    ///
    /// - When `hold_response` is true: keeps the body, headers, and URL path out
    ///   of MCP output and returns an encrypted receipt (`responseId` + numbered
    ///   `candidates`) so the caller can save fields with `http_save_secret`.
    /// - When `hold_response` is false and all `capture_secrets` match and save:
    ///   returns the rest of the redacted body/headers with captured values
    ///   replaced by `[CAPTURED:{{openkeylet:field}}]` plus `references`.
    /// - When `hold_response` is false and any `capture_secrets` path misses or
    ///   saving fails: withholds the body and headers AND stores an encrypted
    ///   receipt (`responseId` + `candidates` + `jsonPaths`) so a one-time
    ///   issuance response can still be saved via `http_save_secret` without
    ///   re-issuing.
    pub(super) fn process_captured_http_response(
        &self,
        connection: &DecryptedConnection,
        raw: crate::exec::RawApiResponse,
        specs: &BTreeMap<String, String>,
        hold_response: bool,
    ) -> Result<ApiResponse> {
        let item = connection.stored.id;
        let local = LocalResponse {
            body: if raw.truncated {
                String::new()
            } else {
                raw.raw_body.clone()
            },
            truncated: raw.truncated,
            headers: raw
                .headers
                .iter()
                .filter(|(k, _)| k.as_str() != "set-cookie")
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        };
        let parsed = (!local.truncated)
            .then(|| serde_json::from_str::<Value>(&local.body).ok())
            .flatten();
        let slots = candidates(&local, parsed.as_ref());
        let (pairs, capture_missing) = select_values(specs, &local, parsed.as_ref(), &slots);

        let mut captured_secrets = Vec::new();
        let mut refs = BTreeMap::new();
        let mut save_failed = false;

        if !pairs.is_empty() && capture_missing.is_empty() {
            if (200..300).contains(&raw.status)
                && self.save_captured_http_secrets(item, &pairs).is_ok()
            {
                refs = references(item, &pairs);
                captured_secrets.extend(refs.keys().cloned());
            } else {
                save_failed = true;
            }
        }

        let need_receipt = hold_response || !capture_missing.is_empty() || save_failed;
        if need_receipt {
            let (response_id, candidate_list) = if !local.body.is_empty() || !local.headers.is_empty()
            {
                let id = self.store_http_receipt(item, &local)?;
                let list = slots
                    .iter()
                    .enumerate()
                    .map(|(slot, (kind, _))| HttpCandidate { slot, kind })
                    .collect();
                (Some(id.to_string()), list)
            } else {
                (None, Vec::new())
            };
            let json_paths = if !hold_response && !capture_missing.is_empty() {
                parsed.as_ref().map(json_key_paths).unwrap_or_default()
            } else {
                Vec::new()
            };
            let body = if hold_response {
                String::new()
            } else if save_failed {
                "[WITHHELD: saving captured secrets failed, so the body is kept in responseId for retry with http_save_secret.]".to_owned()
            } else if parsed.is_some() {
                "[WITHHELD: a captureSecrets path matched nothing, so the body may hold the token. Save directly from responseId with http_save_secret using #slot or jsonPaths.]".to_owned()
            } else {
                "[WITHHELD: the response is not JSON (or was truncated), so captureSecrets could not match. Save directly from responseId with http_save_secret.]".to_owned()
            };
            return Ok(ApiResponse {
                status: raw.status,
                status_text: raw.status_text,
                url: mask_browser_url(&raw.url),
                headers: HashMap::new(),
                body,
                truncated: raw.truncated,
                saved_to: raw.saved_to,
                bytes_transferred: raw.bytes_transferred,
                item_id: Some(item.to_string()),
                response_id,
                candidates: candidate_list,
                captured_secrets,
                references: refs,
                capture_missing,
                json_paths,
                save_failed,
            });
        }

        // All captures matched and saved: return the redacted remainder of the response.
        let redactor = crate::policy::Redactor::new(&crate::policy::connection_redaction_candidates(
            &connection.secrets,
        ));
        let url = redactor.redact_string(crate::policy::replace_captured_secrets(raw.url, &pairs));
        let headers = raw
            .headers
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    redactor.redact_string(crate::policy::replace_captured_secrets(v, &pairs)),
                )
            })
            .collect();
        let body_with_captures = crate::policy::replace_captured_secrets(raw.raw_body, &pairs);
        let body = sanitize_api_body(
            body_with_captures,
            raw.truncated,
            &connection.stored,
            &connection.secrets,
        );
        Ok(ApiResponse {
            status: raw.status,
            status_text: raw.status_text,
            url,
            headers,
            body,
            truncated: raw.truncated,
            saved_to: raw.saved_to,
            bytes_transferred: raw.bytes_transferred,
            item_id: Some(item.to_string()),
            response_id: None,
            candidates: Vec::new(),
            captured_secrets,
            references: refs,
            capture_missing: Vec::new(),
            json_paths: Vec::new(),
            save_failed: false,
        })
    }

    fn store_http_receipt(&self, item: Uuid, local: &LocalResponse) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let held = HeldResponse {
            id,
            item,
            created: Instant::now(),
            encrypted: self.vault.protect_local_state(local)?,
        };
        let mut cache = self
            .http_receipts
            .lock()
            .map_err(|_| anyhow::anyhow!("Response cache unavailable"))?;
        cache.retain(|r| r.created.elapsed() < LIFETIME);
        if cache.len() >= MAX_RECEIPTS {
            cache.pop_front();
        }
        cache.push_back(held);
        Ok(id)
    }

    pub(super) fn save_http_receipt(
        &self,
        input: SaveHttpInput,
    ) -> Result<BTreeMap<String, String>, String> {
        validate_captures(&input.capture_secrets)?;
        if input.capture_secrets.is_empty() {
            return Err("Select a field to save".into());
        }
        let id = Uuid::parse_str(&input.response_id).map_err(|_| "Invalid response ID")?;
        let (item, encrypted) = {
            let mut cache = self
                .http_receipts
                .lock()
                .map_err(|_| "Response cache unavailable")?;
            cache.retain(|r| r.created.elapsed() < LIFETIME);
            let held = cache
                .iter()
                .find(|r| r.id == id)
                .ok_or("Response expired or unavailable in this session")?;
            (held.item, held.encrypted.clone())
        };
        let local: LocalResponse = self
            .vault
            .unprotect_local_state(&encrypted)
            .map_err(|_| "Cannot open held response")?;
        let parsed = serde_json::from_str(&local.body).ok();
        let slots = candidates(&local, parsed.as_ref());
        let (pairs, missing) =
            select_values(&input.capture_secrets, &local, parsed.as_ref(), &slots);
        if !missing.is_empty() {
            return Err(
                "A selected field did not match. Choose another slot or path on this receipt."
                    .into(),
            );
        }
        self.save_captured_http_secrets(item, &pairs)?;
        Ok(references(item, &pairs))
    }
}

fn references(item: Uuid, pairs: &[(String, String)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(f, _)| (f.clone(), format!("{{{{openkeylet:{item}/{f}}}}}")))
        .collect()
}

fn select_values(
    specs: &BTreeMap<String, String>,
    local: &LocalResponse,
    parsed: Option<&Value>,
    slots: &[(&str, &str)],
) -> (Vec<(String, String)>, Vec<String>) {
    let mut pairs = Vec::new();
    let mut missing = Vec::new();
    for (field, path) in specs {
        let value = if let Some(slot) = path.strip_prefix('#') {
            slot.parse::<usize>()
                .ok()
                .and_then(|i| slots.get(i))
                .map(|(_, v)| (*v).to_owned())
        } else if let Some(header) = path.strip_prefix("header:") {
            local.headers.get(&header.to_ascii_lowercase()).cloned()
        } else if local.truncated {
            None
        } else if let Some(json) = parsed {
            extract_json_path(json, path)
        } else {
            (path == "$").then(|| local.body.trim().to_owned())
        };
        match value {
            Some(value) if !value.is_empty() && value.len() <= 64 * 1024 => {
                pairs.push((field.clone(), value))
            }
            _ => missing.push(field.clone()),
        }
    }
    (pairs, missing)
}
