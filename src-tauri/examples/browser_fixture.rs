//! Isolated backend for scripts/test-browser.mjs; never opens the user's vault.
use openkeylet::{
    browser::BrowserBridge,
    model::{ConnectionInput, SettingsPatch},
    vault::Vault,
};
use serde_json::json;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let root = PathBuf::from(args.get(1).expect("temporary fixture directory"));
    anyhow::ensure!(
        root.file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("openkeylet-browser-test-"),
        "Expected a test directory"
    );
    let port: u16 = args.get(2).expect("bridge port").parse()?;
    let website = args.get(3).expect("test origin");
    let vault = Vault::open(root.join("vault"))?;
    vault.set_owner_pin("123456")?;
    vault.save_browser_login(&json!({"origin":website,"name":"Fixture login","username":"alice","password":"fixture-initial-password"}))?;
    vault.update_settings_patch(SettingsPatch {
        browser_enabled: Some(true),
        browser_port: Some(port),
        ..Default::default()
    })?;
    let bridge = BrowserBridge::new(vault.clone());
    bridge.sync().await;
    bridge.start_quick_pairing().await?;
    println!("READY");
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let control = root.join("desktop-edit.json");
        if control.exists() {
            let input: ConnectionInput = serde_json::from_slice(&std::fs::read(&control)?)?;
            vault.save_connection(input)?;
            std::fs::remove_file(control)?;
            std::fs::write(root.join("desktop-edited"), b"ok")?;
        }
        let settings_control = root.join("settings-patch.json");
        if settings_control.exists() {
            let patch: SettingsPatch = serde_json::from_slice(&std::fs::read(&settings_control)?)?;
            vault.update_settings_patch(patch)?;
            std::fs::remove_file(settings_control)?;
            std::fs::write(root.join("settings-patched"), b"ok")?;
        }
        if root.join("stop").exists() {
            break;
        }
    }
    Ok(())
}
