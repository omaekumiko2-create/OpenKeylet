//! Isolated backend for scripts/test-browser.mjs; never opens the user's vault.
use mcp_vault::{
    browser::BrowserBridge,
    mcp,
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
    let stop = root.join("stop");
    let edit = root.join("desktop-edit.json");
    let desktop_edited = root.join("desktop-edited");
    let watcher_vault = vault.clone();
    let watcher_stop = stop.clone();
    let watcher = std::thread::spawn(move || {
        loop {
            if watcher_stop.exists() {
                break;
            }
            if edit.exists() {
                if let Ok(bytes) = std::fs::read(&edit)
                    && let Ok(input) = serde_json::from_slice::<ConnectionInput>(&bytes)
                    && watcher_vault.save_connection(input).is_ok()
                {
                    let _ = std::fs::write(&desktop_edited, b"ok");
                }
                let _ = std::fs::remove_file(&edit);
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    });

    // stdout is reserved for the MCP stdio transport; startup diagnostics go to stderr.
    eprintln!("READY");
    let mcp_result = mcp::serve_stdio(vault.clone()).await;
    if mcp_result.is_err() {
        // Scripts that drive the bridge without an MCP client keep the fixture alive until they stop it.
        while !stop.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
    let _ = std::fs::write(&stop, b"");
    let _ = watcher.join();
    let _ = bridge.stop().await;
    mcp_result?;

    Ok(())
}
