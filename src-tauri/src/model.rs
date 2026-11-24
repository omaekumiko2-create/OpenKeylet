use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretEnvelope {
    pub version: u8,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerPinVerifier {
    pub version: u8,
    pub salt: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(default)]
pub struct Settings {
    pub language: String,
    pub close_behavior: String,
    pub browser_enabled: bool,
    pub browser_port: u16,
    pub browser_paired: bool,
    pub browser_agent_passkey: bool,
    pub owner_auto_lock_minutes: u32,
    pub auto_check_enabled: bool,
    pub auto_check_interval_minutes: u32,
    pub update_auto_check: bool,
    pub update_auto_download: bool,
    pub update_skipped_version: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsPatch {
    pub language: Option<String>,
    pub close_behavior: Option<String>,
    pub browser_enabled: Option<bool>,
    pub browser_port: Option<u16>,
    pub browser_agent_passkey: Option<bool>,
    pub owner_auto_lock_minutes: Option<u32>,
    pub auto_check_enabled: Option<bool>,
    pub auto_check_interval_minutes: Option<u32>,
    pub update_auto_check: Option<bool>,
    pub update_auto_download: Option<bool>,
    pub update_skipped_version: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            language: "auto".to_owned(),
            close_behavior: "tray".to_owned(),
            browser_enabled: false,
            browser_port: 39_272,
            browser_paired: false,
            browser_agent_passkey: true,
            owner_auto_lock_minutes: 0,
            auto_check_enabled: true,
            auto_check_interval_minutes: 60,
            update_auto_check: true,
            update_auto_download: true,
            update_skipped_version: String::new(),
        }
    }
}

#[cfg(test)]
mod settings_tests {
    use super::Settings;

    #[test]
    fn older_settings_keep_current_defaults() {
        let settings: Settings = serde_json::from_str(
            r#"{"httpEnabled":false,"httpPort":39271,"browserEnabled":false,"browserPort":39272,"browserPaired":false}"#,
        )
        .unwrap();
        assert_eq!(settings.language, "auto");
        assert_eq!(settings.close_behavior, "tray");
        assert!(settings.browser_agent_passkey);
        assert_eq!(settings.owner_auto_lock_minutes, 0);
        assert!(settings.auto_check_enabled);
        assert_eq!(settings.auto_check_interval_minutes, 60);
        assert!(settings.update_auto_check);
        assert!(settings.update_auto_download);
        assert!(settings.update_skipped_version.is_empty());
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NamedSecrets(pub BTreeMap<String, String>);

impl Zeroize for NamedSecrets {
    fn zeroize(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
        self.0.clear();
    }
}

impl NamedSecrets {
    pub fn values(&self) -> impl Iterator<Item = &String> {
        self.0.values()
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.0.keys()
    }

    pub fn get(&self, name: &str) -> Option<&String> {
        self.0.get(name)
    }

    pub fn insert(&mut self, name: String, value: String) {
        self.0.insert(name, value);
    }

    pub fn remove(&mut self, name: &str) {
        self.0.remove(name);
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.0.iter()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretField {
    pub name: String,
    #[serde(default = "default_secret_field_kind")]
    pub kind: String,
}

fn default_secret_field_kind() -> String {
    "text".to_owned()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretProfile {
    #[serde(default)]
    pub fields: Vec<SecretField>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ItemModule {
    pub kind: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub agent_visible: Option<bool>,
}

pub(crate) fn module_kind_has_plaintext_reveal(kind: &str) -> bool {
    crate::item_types::personal_field(kind)
        || matches!(
            kind,
            "username"
                | "password"
                | "apiCredential"
                | "privateKey"
                | "passphrase"
                | "totp"
                | "customSecret"
        )
}

impl ItemModule {
    pub fn is_secret(&self) -> bool {
        module_kind_has_plaintext_reveal(&self.kind)
    }

    pub fn secret_name(&self) -> Option<&str> {
        match self.kind.as_str() {
            "username" => Some("username"),
            "password" => Some("password"),
            "apiCredential" => Some("apiCredential"),
            "privateKey" => Some("privateKey"),
            "passphrase" => Some("passphrase"),
            "totp" => Some("totp"),
            "customSecret" if !self.name.is_empty() => Some(&self.name),
            kind if crate::item_types::personal_field(kind) => Some(kind),
            _ => None,
        }
    }

    pub fn agent_visible(&self) -> bool {
        self.agent_visible
            .unwrap_or(!module_kind_has_plaintext_reveal(&self.kind))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicItemModule {
    pub kind: String,
    pub name: String,
    pub value: String,
    pub secret: bool,
    pub configured: bool,
    #[serde(default)]
    pub agent_visible: Option<bool>,
}

impl PublicItemModule {
    pub fn agent_visible(&self) -> bool {
        self.agent_visible
            .unwrap_or(!module_kind_has_plaintext_reveal(&self.kind))
    }
}

pub const MAX_AGENT_NOTES: usize = 5;
pub const MAX_AGENT_NOTE_CHARS: usize = 200;
pub const MAX_AGENT_NOTE_AUTHOR_CHARS: usize = 40;

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct AgentNoteEntry {
    pub id: String,
    pub text: String,
    #[serde(default)]
    pub author: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct SecretBundle {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub password_history: Vec<PasswordHistoryEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passkeys: Vec<crate::passkey::StoredPasskey>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_notes: Vec<AgentNoteEntry>,
    #[zeroize(skip)]
    #[serde(default, skip_serializing_if = "is_false")]
    pub agent_notes_locked: bool,
    #[zeroize(skip)]
    #[serde(default)]
    pub private_key_name: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub passphrase: Option<String>,
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub named_secrets: NamedSecrets,
}

impl SecretBundle {
    pub(crate) fn remember_password_change(&mut self, previous: Option<&str>) {
        if let Some(previous) = previous.filter(|v| !v.is_empty()) {
            if self.get("password") != Some(previous) {
                self.password_history.insert(
                    0,
                    PasswordHistoryEntry {
                        password: previous.to_owned(),
                        changed_at: chrono::Utc::now().to_rfc3339(),
                    },
                );
                self.password_history.truncate(20);
            }
        }
    }
    pub fn non_empty_values(&self) -> Vec<String> {
        [
            self.password.as_ref(),
            self.passphrase.as_ref(),
            self.private_key.as_ref(),
            self.token.as_ref(),
            self.api_key.as_ref(),
        ]
        .into_iter()
        .flatten()
        .filter(|value| !value.is_empty())
        .cloned()
        .chain(
            self.named_secrets
                .values()
                .filter(|value| !value.is_empty())
                .cloned(),
        )
        .chain(
            self.password_history
                .iter()
                .filter(|entry| !entry.password.is_empty())
                .map(|entry| entry.password.clone()),
        )
        .collect()
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        let standard = match name {
            "password" => self.password.as_deref(),
            "passphrase" => self.passphrase.as_deref(),
            "privateKey" | "private_key" => self.private_key.as_deref(),
            "token" => self.token.as_deref(),
            "apiKey" | "api_key" => self.api_key.as_deref(),
            "apiCredential" | "api_credential" => self
                .named_secrets
                .get("apiCredential")
                .map(String::as_str)
                .or(self.token.as_deref())
                .or(self.api_key.as_deref()),
            _ => None,
        };
        standard
            .or_else(|| self.named_secrets.get(name).map(String::as_str))
            .filter(|value| !value.is_empty())
    }

    pub fn available_fields(&self, profile: Option<&SecretProfile>) -> Vec<SecretField> {
        let mut fields = profile
            .map(|profile| profile.fields.clone())
            .unwrap_or_default();
        for (name, present) in [
            (
                "password",
                self.password.as_ref().is_some_and(|v| !v.is_empty()),
            ),
            (
                "passphrase",
                self.passphrase.as_ref().is_some_and(|v| !v.is_empty()),
            ),
            (
                "privateKey",
                self.private_key.as_ref().is_some_and(|v| !v.is_empty()),
            ),
            ("token", self.token.as_ref().is_some_and(|v| !v.is_empty())),
            (
                "apiKey",
                self.api_key.as_ref().is_some_and(|v| !v.is_empty()),
            ),
        ] {
            if present && !fields.iter().any(|field| field.name == name) {
                fields.push(SecretField {
                    name: name.to_owned(),
                    kind: "text".to_owned(),
                });
            }
        }
        for name in self.named_secrets.keys() {
            if !fields.iter().any(|field| &field.name == name) {
                fields.push(SecretField {
                    name: name.clone(),
                    kind: if name == "totp" { "totp" } else { "text" }.to_owned(),
                });
            }
        }
        fields
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHistoryEntry {
    pub password: String,
    pub changed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredConnection {
    #[serde(default)]
    pub login_uris: Vec<crate::login_uri::LoginUri>,
    #[serde(default)]
    pub item_type: String,
    #[serde(default)]
    pub folder: String,
    #[serde(default)]
    pub favorite: bool,
    pub id: Uuid,
    #[serde(default)]
    pub modules: Vec<ItemModule>,
    pub name: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub description: String,

    #[serde(default)]
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    #[serde(default)]
    pub ssh_auth_type: String,
    #[serde(default)]
    pub http_auth_type: String,
    #[serde(default)]
    pub private_key_name: String,

    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub auth_header: String,
    #[serde(default)]
    pub auth_location: String,
    #[serde(default)]
    pub auth_prefix: String,
    #[serde(default)]
    pub api_auth_headers: Vec<ApiAuthHeader>,
    #[serde(default)]
    pub test_path: String,
    #[serde(default)]
    pub secret: Option<SecretProfile>,

    pub encrypted_secrets: SecretEnvelope,
}

fn default_ssh_port() -> u16 {
    22
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiAuthHeader {
    pub name: String,
    pub secret_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortableConnection {
    #[serde(default)]
    pub login_uris: Vec<crate::login_uri::LoginUri>,
    #[serde(default)]
    pub item_type: String,
    #[serde(default)]
    pub folder: String,
    #[serde(default)]
    pub favorite: bool,
    pub id: Uuid,
    pub modules: Vec<ItemModule>,
    pub name: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
    pub description: String,
    pub http_auth_type: String,
    pub private_key_name: String,
    pub auth_header: String,
    pub auth_location: String,
    pub auth_prefix: String,
    pub api_auth_headers: Vec<ApiAuthHeader>,
    pub test_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicConnection {
    pub password_history_count: usize,
    pub login_uris: Vec<crate::login_uri::LoginUri>,
    pub item_type: String,
    pub folder: String,
    pub favorite: bool,
    pub passkeys: Vec<crate::passkey::PasskeySummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_notes: Vec<AgentNoteEntry>,
    #[serde(default)]
    pub agent_notes_locked: bool,
    pub id: Uuid,
    pub capabilities: Vec<String>,
    pub can_test: bool,
    #[serde(default)]
    pub modules: Vec<PublicItemModule>,
    pub name: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
    pub description: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub ssh_auth_type: String,
    #[serde(default)]
    pub http_auth_type: String,
    pub private_key_name: String,
    pub base_url: String,
    pub auth_header: String,
    #[serde(default)]
    pub auth_location: String,
    #[serde(default)]
    pub auth_prefix: String,
    #[serde(default)]
    pub api_auth_headers: Vec<ApiAuthHeader>,
    pub test_path: String,
    #[serde(default)]
    pub secret: Option<SecretProfile>,
}

impl StoredConnection {
    pub fn portable(&self) -> PortableConnection {
        PortableConnection {
            login_uris: self.login_uris.clone(),
            item_type: self.item_type().to_owned(),
            folder: self.folder.clone(),
            favorite: self.favorite,
            id: self.id,
            modules: self.modules.clone(),
            name: self.name.clone(),
            enabled: self.enabled,
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
            description: self.description.clone(),
            http_auth_type: self.http_auth_type.clone(),
            private_key_name: self.private_key_name.clone(),
            auth_header: self.auth_header.clone(),
            auth_location: self.auth_location.clone(),
            auth_prefix: self.auth_prefix.clone(),
            api_auth_headers: self.api_auth_headers.clone(),
            test_path: self.test_path.clone(),
        }
    }
    pub fn item_type(&self) -> &str {
        if self.item_type.is_empty() {
            crate::item_types::infer(&self.modules)
        } else {
            &self.item_type
        }
    }
    fn module_configured(&self, secrets: &SecretBundle, kind: &str) -> bool {
        self.modules.iter().any(|module| {
            module.kind == kind
                && module
                    .secret_name()
                    .and_then(|name| secrets.get(name))
                    .is_some()
        })
    }

    pub fn capabilities(&self, secrets: &SecretBundle) -> Vec<String> {
        let can_fill = self.modules.iter().any(|module| {
            !crate::item_types::personal_field(&module.kind)
                && module
                    .secret_name()
                    .and_then(|name| secrets.get(name))
                    .is_some()
        });
        let mut capabilities = Vec::new();
        if can_fill {
            capabilities.push("fill".to_owned());
        }
        if self.module_configured(secrets, "password")
            || self.module_configured(secrets, "privateKey")
        {
            capabilities.push("ssh".to_owned());
        }
        if can_fill {
            capabilities.push("http".to_owned());
        }
        if !secrets.passkeys.is_empty() {
            capabilities.push("passkey".to_owned());
        }
        let has_personal = matches!(self.item_type(), "card" | "identity")
            && self.modules.iter().any(|module| {
                (crate::item_types::CARD_FIELDS.contains(&module.kind.as_str())
                    || crate::item_types::IDENTITY_FIELDS.contains(&module.kind.as_str()))
                    && module
                        .secret_name()
                        .and_then(|name| secrets.get(name))
                        .is_some()
            });
        if has_personal {
            capabilities.push("personal".to_owned());
        }
        let has_configured_visible_module = self.modules.iter().any(|module| {
            module.agent_visible()
                && if let Some(name) = module.secret_name() {
                    secrets.get(name).is_some()
                } else {
                    !module.value.trim().is_empty()
                }
        });
        if (self.item_type() == "secureNote" && self.module_configured(secrets, "secureNote"))
            || (capabilities.is_empty() && has_configured_visible_module)
        {
            capabilities.push("note".to_owned());
        }
        capabilities
    }

    pub fn has_capability(&self, secrets: &SecretBundle, capability: &str) -> bool {
        self.capabilities(secrets)
            .iter()
            .any(|candidate| candidate == capability)
    }

    pub fn test_target(&self, secrets: &SecretBundle) -> Option<&'static str> {
        if self.has_capability(secrets, "ssh")
            && !self.host.trim().is_empty()
            && self.port > 0
            && self.module_configured(secrets, "username")
        {
            Some("ssh")
        } else if self.has_capability(secrets, "http") && !self.base_url.trim().is_empty() {
            Some("http")
        } else {
            None
        }
    }

    pub fn public(&self, secrets: Option<&SecretBundle>) -> PublicConnection {
        PublicConnection {
            password_history_count: secrets.map_or(0, |s| s.password_history.len()),
            login_uris: self.login_uris.clone(),
            item_type: self.item_type().to_owned(),
            folder: self.folder.clone(),
            favorite: self.favorite,
            passkeys: secrets
                .map(|bundle| {
                    bundle
                        .passkeys
                        .iter()
                        .map(crate::passkey::StoredPasskey::summary)
                        .collect()
                })
                .unwrap_or_default(),
            agent_notes: secrets
                .map(|bundle| bundle.agent_notes.clone())
                .unwrap_or_default(),
            agent_notes_locked: secrets.is_some_and(|bundle| bundle.agent_notes_locked),
            id: self.id,
            capabilities: secrets
                .map(|bundle| self.capabilities(bundle))
                .unwrap_or_default(),
            can_test: secrets.is_some_and(|bundle| self.test_target(bundle).is_some()),
            modules: self
                .modules
                .iter()
                .map(|module| {
                    let secret = module.is_secret();
                    PublicItemModule {
                        kind: module.kind.clone(),
                        name: module.name.clone(),
                        value: if secret {
                            String::new()
                        } else {
                            module.value.clone()
                        },
                        secret,
                        configured: if let Some(name) = module.secret_name() {
                            secrets.and_then(|bundle| bundle.get(name)).is_some()
                        } else {
                            !module.value.trim().is_empty()
                        },
                        agent_visible: Some(module.agent_visible()),
                    }
                })
                .collect(),
            name: self.name.clone(),
            enabled: self.enabled,
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
            description: self.description.clone(),
            host: self.host.clone(),
            port: self.port,
            ssh_auth_type: self.ssh_auth_type.clone(),
            http_auth_type: self.http_auth_type.clone(),
            private_key_name: self.private_key_name.clone(),
            base_url: self.base_url.clone(),
            auth_header: self.auth_header.clone(),
            auth_location: self.auth_location.clone(),
            auth_prefix: self.auth_prefix.clone(),
            api_auth_headers: self.api_auth_headers.clone(),
            test_path: self.test_path.clone(),
            secret: Some(SecretProfile {
                fields: secrets
                    .map(|bundle| bundle.available_fields(self.secret.as_ref()))
                    .unwrap_or_default(),
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionInput {
    #[serde(default)]
    pub login_uris: Vec<crate::login_uri::LoginUri>,
    #[serde(default)]
    pub item_type: String,
    #[serde(default)]
    pub folder: String,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub id: Option<Uuid>,
    #[serde(default)]
    pub modules: Vec<ItemModule>,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub description: String,

    #[serde(default)]
    pub http_auth_type: String,
    #[serde(default)]
    pub private_key_import_path: String,
    #[serde(default)]
    pub auth_header: String,
    #[serde(default)]
    pub auth_location: String,
    #[serde(default)]
    pub auth_prefix: String,
    #[serde(default)]
    pub api_auth_headers: Vec<ApiAuthHeader>,
    #[serde(default)]
    pub test_path: String,
    #[serde(default)]
    pub remove_secret_names: Vec<String>,

    #[serde(default)]
    pub secrets: SecretBundle,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Activity {
    pub id: Uuid,
    pub time: String,
    pub status: String,
    pub source: String,
    pub connection_name: String,
    pub action: String,
    pub duration_ms: u64,
    #[serde(default)]
    pub error: String,
}

#[derive(Debug, Clone)]
pub struct NewActivity {
    pub status: String,
    pub source: String,
    pub connection_name: String,
    pub action: String,
    pub duration_ms: u64,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultDocument {
    pub version: u8,
    #[serde(default)]
    pub settings: Settings,
    #[serde(default)]
    pub browser_bridge_secret: Option<SecretEnvelope>,
    #[serde(default)]
    pub owner_pin: Option<OwnerPinVerifier>,
    #[serde(default)]
    pub connections: Vec<StoredConnection>,
    #[serde(default)]
    pub trash: Vec<StoredTrashItem>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deleted_ids: Vec<DeletedItemTombstone>,
    #[serde(default)]
    pub editor_drafts: Vec<StoredEditorDraft>,
    #[serde(default)]
    pub activities: Vec<Activity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletedItemTombstone {
    pub id: Uuid,
    pub deleted_at: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncMergeSummary {
    pub added: usize,
    pub updated: usize,
    pub deleted: usize,
    pub unchanged: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredTrashItem {
    pub deleted_at: String,
    pub connection: StoredConnection,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicTrashItem {
    pub deleted_at: String,
    pub item: PublicConnection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortableTrashItem {
    pub deleted_at: String,
    pub connection: PortableConnection,
    pub secrets: SecretBundle,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredEditorDraft {
    pub id: Uuid,
    pub updated_at: String,
    pub payload: SecretEnvelope,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerEditorDraft {
    pub id: Uuid,
    pub updated_at: String,
    pub input: ConnectionInput,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerSecretField {
    pub name: String,
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerSecretView {
    pub id: Uuid,
    pub fields: Vec<OwnerSecretField>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerLockState {
    pub pin_configured: bool,
    pub unlocked: bool,
    pub expires_in_seconds: u64,
    pub strong_mode: bool,
    pub mode: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpState {
    pub status: String,
    pub error: String,
    pub endpoint: String,
    pub stdio_command: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityState {
    pub encrypted: bool,
    pub storage: String,
    pub strong_mode: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BridgeClientInfo {
    pub peer_ip: String,
    pub connected_at: String,
    pub last_used_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_version: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserBridgeState {
    pub enabled: bool,
    pub paired: bool,
    pub connected: bool,
    pub connected_count: usize,
    pub pairing_active: bool,
    pub status: String,
    pub error: String,
    pub endpoint: String,
    pub app_version: String,
    pub extension_version: Option<String>,
    pub extension_outdated: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bind_address: String,
    #[serde(default)]
    pub lan_mode: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_allowlist: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_origins: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clients: Vec<BridgeClientInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_client_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppState {
    pub settings: Settings,
    pub connections: Vec<PublicConnection>,
    pub activities: Vec<Activity>,
    pub mcp: McpState,
    pub browser_bridge: BrowserBridgeState,
    pub security: SecurityState,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportSummary {
    pub added: usize,
    pub merged: usize,
}

#[cfg(test)]
mod tests {
    use super::{ItemModule, module_kind_has_plaintext_reveal};

    #[test]
    fn plaintext_reveal_capability_drives_default_agent_visibility() {
        for kind in [
            "username",
            "password",
            "apiCredential",
            "privateKey",
            "passphrase",
            "totp",
            "customSecret",
        ] {
            let module = ItemModule {
                kind: kind.to_owned(),
                name: String::new(),
                value: String::new(),
                agent_visible: None,
            };
            assert!(module_kind_has_plaintext_reveal(kind));
            assert!(!module.agent_visible());
        }

        for kind in ["host", "port", "url"] {
            let module = ItemModule {
                kind: kind.to_owned(),
                name: String::new(),
                value: String::new(),
                agent_visible: None,
            };
            assert!(!module_kind_has_plaintext_reveal(kind));
            assert!(module.agent_visible());
        }
    }

    #[test]
    fn explicit_agent_visibility_overrides_the_module_default() {
        let visible_secret = ItemModule {
            kind: "password".to_owned(),
            name: String::new(),
            value: String::new(),
            agent_visible: Some(true),
        };
        let hidden_public_value = ItemModule {
            kind: "host".to_owned(),
            name: String::new(),
            value: String::new(),
            agent_visible: Some(false),
        };

        assert!(visible_secret.agent_visible());
        assert!(!hidden_public_value.agent_visible());
    }

    fn stored_with(item_type: &str, modules: Vec<ItemModule>) -> super::StoredConnection {
        super::StoredConnection {
            login_uris: Vec::new(),
            item_type: item_type.to_owned(),
            folder: String::new(),
            favorite: false,
            id: uuid::Uuid::new_v4(),
            modules,
            name: "test".to_owned(),
            enabled: true,
            created_at: String::new(),
            updated_at: String::new(),
            description: String::new(),
            host: String::new(),
            port: 22,
            ssh_auth_type: String::new(),
            http_auth_type: String::new(),
            private_key_name: String::new(),
            base_url: String::new(),
            auth_header: String::new(),
            auth_location: String::new(),
            auth_prefix: String::new(),
            api_auth_headers: Vec::new(),
            test_path: String::new(),
            secret: None,
            encrypted_secrets: super::SecretEnvelope {
                version: 0,
                nonce: String::new(),
                ciphertext: String::new(),
            },
        }
    }

    #[test]
    fn card_identity_and_secure_note_expose_agent_capabilities_without_credential_actions() {
        let mut card_secrets = super::SecretBundle::default();
        card_secrets
            .named_secrets
            .insert("cardNumber".into(), "4111111111111111".into());
        let card = stored_with(
            "card",
            vec![ItemModule {
                kind: "cardNumber".into(),
                name: "cardNumber".into(),
                value: String::new(),
                agent_visible: Some(false),
            }],
        );
        assert_eq!(card.capabilities(&card_secrets), vec!["personal"]);
        assert!(card.capabilities(&super::SecretBundle::default()).is_empty());

        let mut identity_secrets = super::SecretBundle::default();
        identity_secrets
            .named_secrets
            .insert("firstName".into(), "Alice".into());
        let identity = stored_with(
            "identity",
            vec![ItemModule {
                kind: "firstName".into(),
                name: "firstName".into(),
                value: String::new(),
                agent_visible: Some(false),
            }],
        );
        assert_eq!(identity.capabilities(&identity_secrets), vec!["personal"]);

        let mut note_secrets = super::SecretBundle::default();
        note_secrets
            .named_secrets
            .insert("secureNote".into(), "Recovery instructions".into());
        let note = stored_with(
            "secureNote",
            vec![ItemModule {
                kind: "secureNote".into(),
                name: "secureNote".into(),
                value: String::new(),
                agent_visible: Some(false),
            }],
        );
        assert_eq!(note.capabilities(&note_secrets), vec!["note"]);
        assert!(note.capabilities(&super::SecretBundle::default()).is_empty());

        let visible_only = stored_with(
            "custom",
            vec![ItemModule {
                kind: "url".into(),
                name: String::new(),
                value: "https://internal.example.test".into(),
                agent_visible: Some(true),
            }],
        );
        assert_eq!(
            visible_only.capabilities(&super::SecretBundle::default()),
            vec!["note"]
        );

        let hidden_only = stored_with(
            "custom",
            vec![ItemModule {
                kind: "url".into(),
                name: String::new(),
                value: "https://internal.example.test".into(),
                agent_visible: Some(false),
            }],
        );
        assert!(
            hidden_only
                .capabilities(&super::SecretBundle::default())
                .is_empty()
        );
    }
}
