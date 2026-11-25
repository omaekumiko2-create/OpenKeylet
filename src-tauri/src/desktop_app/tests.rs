use super::{
    OwnerSession, is_valid_chrome_profile_dir, parse_chrome_profiles_from_local_state,
    scrub_locked_app_state, should_hide_on_close,
};
use crate::{
    model::{BrowserBridgeState, ConnectionInput, NewActivity, SettingsPatch},
    vault::Vault,
};
use std::time::{Duration, Instant};

#[test]
fn close_only_hides_when_a_tray_entry_exists() {
    assert!(should_hide_on_close("tray", true));
    assert!(!should_hide_on_close("tray", false));
    assert!(!should_hide_on_close("exit", true));
}

#[test]
fn owner_session_auto_locks_after_idle_timeout_and_resets_on_touch() {
    let base = Instant::now();
    let mut session = OwnerSession::default();
    session.unlock(base);

    // auto_lock_minutes == 0 stays unlocked indefinitely.
    assert_eq!(
        session.is_unlocked_at(base + Duration::from_secs(86_400), 0),
        (true, 0, false)
    );

    // With 5-minute auto-lock, touching at 4m extends the deadline by another 5m.
    let at_4m = base + Duration::from_secs(240);
    assert_eq!(session.is_unlocked_at(at_4m, 5), (true, 60, false));
    session.touch(at_4m);
    assert_eq!(
        session.is_unlocked_at(at_4m + Duration::from_secs(200), 5),
        (true, 100, false)
    );

    // After 5 minutes without activity, session transitions to locked.
    assert_eq!(
        session.is_unlocked_at(at_4m + Duration::from_secs(300), 5),
        (false, 0, true)
    );
    assert_eq!(
        session.is_unlocked_at(at_4m + Duration::from_secs(301), 5),
        (false, 0, false)
    );
}

#[test]
fn owner_session_applies_lightweight_progressive_pin_cooldown_and_clears_on_unlock() {
    let base = Instant::now();
    let mut session = OwnerSession::default();

    assert_eq!(session.record_failed_attempt(base), 0);
    assert_eq!(session.record_failed_attempt(base), 0);
    assert!(session.cooldown_remaining(base).is_none());

    assert_eq!(session.record_failed_attempt(base), 2);
    assert_eq!(session.cooldown_remaining(base), Some(2));
    assert!(session.cooldown_remaining(base + Duration::from_secs(2)).is_none());

    let after_wait = base + Duration::from_secs(3);
    assert_eq!(session.record_failed_attempt(after_wait), 5);
    assert_eq!(session.record_failed_attempt(after_wait), 15);
    assert_eq!(session.record_failed_attempt(after_wait), 15);
    assert_eq!(session.record_failed_attempt(after_wait), 30);

    session.unlock(after_wait + Duration::from_secs(31));
    assert!(session.cooldown_remaining(after_wait + Duration::from_secs(31)).is_none());
    assert_eq!(
        session.record_failed_attempt(after_wait + Duration::from_secs(32)),
        0
    );
}

#[test]
fn locked_app_state_scrubs_items_and_activities_but_preserves_settings() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path().to_path_buf()).unwrap();
    vault
        .update_settings_patch(SettingsPatch {
            language: Some("zh".to_owned()),
            owner_auto_lock_minutes: Some(15),
            ..SettingsPatch::default()
        })
        .unwrap();
    let input: ConnectionInput = serde_json::from_value(serde_json::json!({
        "name": "SensitiveProd",
        "modules": [
            { "kind": "username", "value": "alice" },
            { "kind": "password", "value": "super-secret" }
        ]
    }))
    .unwrap();
    vault.save_connection(input).unwrap();
    vault
        .add_activity(NewActivity {
            status: "success".to_owned(),
            source: "MCP".to_owned(),
            connection_name: "SensitiveProd".to_owned(),
            action: "ssh_run".to_owned(),
            duration_ms: 10,
            error: String::new(),
        })
        .unwrap();

    let state = vault
        .app_state(
            "openkeylet",
            BrowserBridgeState {
                status: "off".to_owned(),
                app_version: env!("CARGO_PKG_VERSION").to_owned(),
                ..BrowserBridgeState::default()
            },
        )
        .unwrap();
    assert_eq!(state.connections.len(), 1);
    assert_eq!(state.activities.len(), 1);

    let scrubbed = scrub_locked_app_state(state);
    assert!(scrubbed.connections.is_empty());
    assert!(scrubbed.activities.is_empty());
    assert_eq!(scrubbed.settings.language, "zh");
    assert_eq!(scrubbed.settings.owner_auto_lock_minutes, 15);
}

#[test]
fn chrome_profile_parser_filters_invalid_and_sorts_last_used_first() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("Default")).unwrap();
    std::fs::create_dir(dir.path().join("Profile 1")).unwrap();
    std::fs::create_dir(dir.path().join("System Profile")).unwrap();
    let raw = r#"{
        "profile": {
            "last_used": "Profile 1",
            "info_cache": {
                "Default": { "name": "Personal", "user_name": "me@example.com" },
                "Profile 1": { "name": "Work", "user_name": "work@example.com" },
                "Profile 2": { "name": "Missing On Disk" },
                "System Profile": { "name": "System" },
                "../evil": { "name": "Traversal" }
            }
        }
    }"#;
    let profiles = parse_chrome_profiles_from_local_state(dir.path(), raw);
    assert_eq!(profiles.len(), 2);
    assert_eq!(profiles[0].directory, "Profile 1");
    assert_eq!(profiles[0].name, "Work");
    assert_eq!(profiles[0].account, "work@example.com");
    assert!(profiles[0].is_last_used);
    assert_eq!(profiles[1].directory, "Default");
    assert_eq!(profiles[1].name, "Personal");
    assert!(!is_valid_chrome_profile_dir("--evil"));
    assert!(!is_valid_chrome_profile_dir("../Profile 1"));
    assert!(!is_valid_chrome_profile_dir("System Profile"));
}
