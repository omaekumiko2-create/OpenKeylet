//! Pure local, zero-network multi-target credential extraction engine.
//!
//! Accepts messy free-form text (chat logs, handover docs, notes, emails),
//! structured developer configs (.env, ~/.ssh/config, ~/.aws/credentials,
//! JSON/YAML/TOML), and password-manager exports (Bitwarden JSON, Chrome/1Password CSV),
//! extracts all likely credentials with noise/placeholder filtering, and reconciles
//! them in-memory against the unlocked local Vault to detect duplicates and updates.

use crate::{
    api_catalog,
    login_uri::LoginUri,
    migration,
    model::{ConnectionInput, ItemModule, PortableConnection, SecretBundle},
    vault::DecryptedConnection,
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashSet},
    io::{Cursor, Read},
    path::{Path, PathBuf},
    sync::OnceLock,
    time::Instant,
};
use url::Url;
use uuid::Uuid;

mod formats;
mod freetext;
pub mod ingest;
mod office;
mod precise;
mod reconcile;
mod scan_local;

pub use office::{extract_docx_text, extract_from_bytes, extract_from_paths, extract_xlsx_text};
pub use scan_local::{
    plaintext_source_kind, plaintext_sources, scan_local_dev_configs_with_mvaults,
    scan_workspace_directory,
};
#[cfg(test)]
pub(crate) use scan_local::scan_local_credential_roots;
use formats::*;
use freetext::*;
use office::*;
use precise::*;
use reconcile::*;
use scan_local::*;

const MAX_BATCH_TEXT_BYTES: usize = 16 * 1024 * 1024;
const MAX_BATCH_CANDIDATES: usize = 2000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractedFieldPreview {
    pub label: String,
    pub value: String,
    pub masked: String,
    pub secret: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractedCandidate {
    pub id: String,
    pub kind: String,
    pub badge: String,
    pub badge_zh: String,
    pub confidence: String,
    pub selected: bool,
    pub summary: String,
    pub source_snippet: String,
    pub match_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub existing_item_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub existing_item_name: Option<String>,
    pub update_existing: bool,
    pub fields: Vec<ExtractedFieldPreview>,
    pub input: ConnectionInput,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_uri: Option<String>,
    /// Files the candidate was read from. Never serialized: the desktop app swaps them for
    /// opaque `source_refs`, so the renderer cannot steer a later action to another path.
    #[serde(skip)]
    pub source_paths: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IgnoredSnippet {
    pub reason: String,
    pub reason_zh: String,
    pub key: String,
    pub preview: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate: Option<ExtractedCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmartExtractBatchResult {
    pub detected_format: String,
    pub detected_format_zh: String,
    pub candidates: Vec<ExtractedCandidate>,
    pub ignored: Vec<IgnoredSnippet>,
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sealed_env_template: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmartCommitItem {
    pub input: ConnectionInput,
    #[serde(default)]
    pub update_existing: bool,
    #[serde(default)]
    pub existing_item_id: Option<String>,
    /// Opaque references to the files the candidate came from (see `source_refs`).
    #[serde(default)]
    pub source_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SmartCommitSummary {
    pub added: usize,
    pub updated: usize,
    pub created_ids: Vec<String>,
    /// Files that still hold the plaintext of what was just imported. The import never
    /// changes them, so the user has to be told where they are.
    pub plaintext_sources: Vec<PlaintextSource>,
}

/// A file that still contains plaintext after its credentials were imported.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlaintextSource {
    pub display_path: String,
    /// `env`, `key`, `agent`, `shell`, `tool`, `backup` or `document`. The UI and CLI map
    /// it to the concrete next step for that kind of file.
    pub kind: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DroppedImagePayload {
    pub file_name: String,
    pub mime_type: String,
    pub data_base64: String,
    #[serde(skip)]
    pub source_path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredMvault {
    pub index: usize,
    pub file_name: String,
    pub display_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalScanCategoryStat {
    pub id: String,
    pub label: String,
    pub label_zh: String,
    pub probed_locations: usize,
    pub inspected_files: usize,
    pub matched_files: usize,
    pub extracted_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalScanReport {
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_label: Option<String>,
    pub total_inspected_files: usize,
    pub total_matched_files: usize,
    pub duration_ms: u64,
    pub categories: Vec<LocalScanCategoryStat>,
}

#[derive(Debug, Clone)]
pub struct LocalScanOutcome {
    pub batch: SmartExtractBatchResult,
    pub discovered_mvaults: Vec<DiscoveredMvault>,
    pub mvault_paths: Vec<PathBuf>,
    pub report: LocalScanReport,
}

#[derive(Debug, Clone)]
pub struct ExtractedPathsOutcome {
    pub batch: SmartExtractBatchResult,
    pub images: Vec<DroppedImagePayload>,
    pub mvault_paths: Vec<PathBuf>,
    pub source_files: Vec<String>,
}

pub fn extract_batch(
    raw: &str,
    filename: Option<&str>,
    existing: &[DecryptedConnection],
) -> Result<SmartExtractBatchResult> {
    let trimmed = raw.trim_start_matches('\u{feff}').trim();
    ensure!(!trimmed.is_empty(), "Nothing to extract");
    ensure!(
        trimmed.len() <= MAX_BATCH_TEXT_BYTES,
        "Input exceeds 16 MiB limit"
    );

    let mut result = extract_without_dedup(trimmed, filename)?;
    if result.candidates.len() > MAX_BATCH_CANDIDATES {
        result.candidates.truncate(MAX_BATCH_CANDIDATES);
        result.warnings.push(format!(
            "Truncated preview to first {MAX_BATCH_CANDIDATES} items"
        ));
    }

    reconcile_with_vault(&mut result.candidates, existing);
    Ok(result)
}

pub fn merge_batch_results(
    parts: Vec<SmartExtractBatchResult>,
    existing: &[DecryptedConnection],
) -> SmartExtractBatchResult {
    let mut candidates = Vec::new();
    let mut ignored = Vec::new();
    let mut warnings = Vec::new();
    let mut sealed_env_template = None;
    let mut formats = Vec::new();
    let mut formats_zh = Vec::new();
    let mut seen_fingerprints: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    for part in parts {
        if !formats.contains(&part.detected_format) {
            formats.push(part.detected_format);
            formats_zh.push(part.detected_format_zh);
        }
        if sealed_env_template.is_none() && part.sealed_env_template.is_some() {
            sealed_env_template = part.sealed_env_template;
        }
        for warning in part.warnings {
            if !warnings.contains(&warning) {
                warnings.push(warning);
            }
        }
        for candidate in part.candidates {
            let fp = candidate_dedup_key(&candidate);
            if fp.is_empty() {
                candidates.push(candidate);
            } else if let Some(&kept) = seen_fingerprints.get(&fp) {
                // The same secret found in a second file still leaves plaintext there.
                let kept: &mut ExtractedCandidate = &mut candidates[kept];
                for path in candidate.source_paths {
                    if !kept.source_paths.contains(&path) {
                        kept.source_paths.push(path);
                    }
                }
            } else {
                seen_fingerprints.insert(fp, candidates.len());
                candidates.push(candidate);
            }
        }
        ignored.extend(part.ignored);
    }

    if candidates.len() > MAX_BATCH_CANDIDATES {
        candidates.truncate(MAX_BATCH_CANDIDATES);
        warnings.push(format!(
            "Truncated preview to first {MAX_BATCH_CANDIDATES} items"
        ));
    }

    reconcile_with_vault(&mut candidates, existing);

    let (detected_format, detected_format_zh) = if formats.len() == 1 {
        (formats.remove(0), formats_zh.remove(0))
    } else if formats.is_empty() {
        ("mixed_text".to_owned(), "混合文本".to_owned())
    } else {
        ("multi_source".to_owned(), "多来源混合".to_owned())
    };

    SmartExtractBatchResult {
        detected_format,
        detected_format_zh,
        candidates,
        ignored,
        warnings,
        sealed_env_template,
    }
}


#[cfg(test)]
mod tests;
