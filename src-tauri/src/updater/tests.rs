use super::*;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use tempfile::tempdir;

fn generate_test_keypair() -> (Ed25519KeyPair, String) {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let pub_b64 = BASE64.encode(keypair.public_key().as_ref());
    (keypair, pub_b64)
}

fn sign_manifest(keypair: &Ed25519KeyPair, manifest: &ReleaseManifest) -> Vec<u8> {
    let payload = serde_json::to_string(manifest).unwrap();
    let mut msg = Vec::new();
    msg.extend_from_slice(MANIFEST_ENVELOPE_FORMAT.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(payload.as_bytes());
    let sig = keypair.sign(&msg);
    let envelope = SignedManifestEnvelope {
        format: MANIFEST_ENVELOPE_FORMAT.to_owned(),
        key_id: "test-key-1".to_owned(),
        payload,
        signature: BASE64.encode(sig.as_ref()),
    };
    serde_json::to_vec(&envelope).unwrap()
}

fn sample_manifest() -> ReleaseManifest {
    let mut platforms = BTreeMap::new();
    platforms.insert(
        current_platform_key().to_owned(),
        PlatformAsset {
            url: "https://github.com/omaekumiko2-create/OpenKeylet/releases/download/v9.9.9/OpenKeylet_9.9.9_test.zip".to_owned(),
            sha256: "a".repeat(64),
            size: 1024,
            format: "zip".to_owned(),
        },
    );
    ReleaseManifest {
        schema_version: 1,
        version: "9.9.9".to_owned(),
        tag: "v9.9.9".to_owned(),
        published_at: "2026-11-24T10:00:00Z".to_owned(),
        release_url: "https://github.com/omaekumiko2-create/OpenKeylet/releases/tag/v9.9.9"
            .to_owned(),
        notes: "## Highlights\n- Added automatic updates".to_owned(),
        platforms,
    }
}

#[test]
fn verifies_valid_ed25519_signed_manifest_and_rejects_tampering() {
    let (keypair, pub_b64) = generate_test_keypair();
    let manifest = sample_manifest();
    let signed = sign_manifest(&keypair, &manifest);

    let (parsed, verified) =
        verify_signed_manifest(&signed, Some(&pub_b64), None).expect("valid signature");
    assert!(verified);
    assert_eq!(parsed.version, "9.9.9");
    assert_eq!(parsed.tag, "v9.9.9");

    // Tamper with payload inside envelope without re-signing.
    let mut tampered: SignedManifestEnvelope = serde_json::from_slice(&signed).unwrap();
    tampered.payload = tampered.payload.replace("9.9.9", "9.9.8");
    let tampered_bytes = serde_json::to_vec(&tampered).unwrap();
    let err = verify_signed_manifest(&tampered_bytes, Some(&pub_b64), None).unwrap_err();
    assert!(err.to_string().contains("UPDATE_SIGNATURE_INVALID"));

    // Wrong public key is rejected.
    let (_, other_pub_b64) = generate_test_keypair();
    let err = verify_signed_manifest(&signed, Some(&other_pub_b64), None).unwrap_err();
    assert!(err.to_string().contains("UPDATE_SIGNATURE_INVALID"));
}

#[test]
fn rejects_non_github_asset_and_release_urls() {
    let (keypair, pub_b64) = generate_test_keypair();
    let mut manifest = sample_manifest();
    manifest
        .platforms
        .get_mut(current_platform_key())
        .unwrap()
        .url = "https://evil.example.com/openkeylet.zip".to_owned();
    let signed = sign_manifest(&keypair, &manifest);
    let err = verify_signed_manifest(&signed, Some(&pub_b64), None).unwrap_err();
    assert!(err.to_string().contains("UPDATE_URL_REJECTED"));
}

#[test]
fn semver_comparison_prevents_downgrades() {
    assert!(is_newer_version("0.16.0", "0.16.1").unwrap());
    assert!(is_newer_version("0.16.0", "v0.17.0").unwrap());
    assert!(!is_newer_version("0.16.0", "0.16.0").unwrap());
    assert!(!is_newer_version("0.16.0", "0.15.9").unwrap());
    assert!(!is_newer_version("0.16.0", "0.16.0-rc.1").unwrap());
}

#[test]
fn zip_extraction_blocks_path_traversal_and_extracts_valid_package() {
    let dir = tempdir().unwrap();
    let evil_zip = dir.path().join("evil.zip");
    {
        let file = File::create(&evil_zip).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        let opts = zip::write::SimpleFileOptions::default();
        writer.start_file("../escape.txt", opts).unwrap();
        writer.write_all(b"evil").unwrap();
        writer.finish().unwrap();
    }
    let err = extract_archive_safely(&evil_zip, &dir.path().join("out-evil"), "zip")
        .unwrap_err();
    assert!(err.to_string().contains("UPDATE_ARCHIVE_UNSAFE"));

    let good_zip = dir.path().join("good.zip");
    {
        let file = File::create(&good_zip).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        let opts = zip::write::SimpleFileOptions::default();
        writer
            .start_file("OpenKeylet_9.9.9_windows-x64/openkeylet.exe", opts)
            .unwrap();
        writer.write_all(b"NEW_EXE_BYTES").unwrap();
        writer
            .start_file(
                "OpenKeylet_9.9.9_windows-x64/browser-extension/manifest.json",
                opts,
            )
            .unwrap();
        writer.write_all(br#"{"version":"9.9.9"}"#).unwrap();
        writer.finish().unwrap();
    }
    let out_good = dir.path().join("out-good");
    extract_archive_safely(&good_zip, &out_good, "zip").unwrap();
    assert_eq!(
        fs::read(out_good.join("OpenKeylet_9.9.9_windows-x64/openkeylet.exe")).unwrap(),
        b"NEW_EXE_BYTES"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn applies_staged_windows_portable_package_and_syncs_extension() {
    let dir = tempdir().unwrap();
    let install_dir = dir.path().join("installed");
    let staged_dir = dir.path().join("staged");
    fs::create_dir_all(install_dir.join("browser-extension")).unwrap();
    fs::create_dir_all(staged_dir.join("browser-extension")).unwrap();

    let target_exe = install_dir.join("openkeylet.exe");
    fs::write(&target_exe, b"OLD_BINARY_0_16_0").unwrap();
    fs::write(
        install_dir.join("browser-extension/manifest.json"),
        br#"{"version":"0.16.0"}"#,
    )
    .unwrap();
    fs::write(install_dir.join("README.md"), b"OLD_README").unwrap();

    fs::write(staged_dir.join("openkeylet.exe"), b"NEW_BINARY_0_17_0").unwrap();
    fs::write(
        staged_dir.join("browser-extension/manifest.json"),
        br#"{"version":"0.17.0"}"#,
    )
    .unwrap();
    fs::write(staged_dir.join("README.md"), b"NEW_README").unwrap();

    apply_staged_package(&target_exe, &staged_dir).unwrap();

    assert_eq!(fs::read(&target_exe).unwrap(), b"NEW_BINARY_0_17_0");
    assert_eq!(
        fs::read(install_dir.join("browser-extension/manifest.json")).unwrap(),
        br#"{"version":"0.17.0"}"#
    );
    assert_eq!(fs::read(install_dir.join("README.md")).unwrap(), b"NEW_README");
}

#[tokio::test]
async fn end_to_end_local_http_check_download_verify_and_stage() {
    use axum::{Router, routing::get};

    let (keypair, pub_b64) = generate_test_keypair();
    let temp = tempdir().unwrap();
    let install_dir = temp.path().join("install");
    #[cfg(target_os = "windows")]
    let data_dir = temp.path().join("data");
    fs::create_dir_all(&install_dir).unwrap();
    let fake_exe = if cfg!(windows) {
        install_dir.join("openkeylet.exe")
    } else {
        install_dir.join("openkeylet")
    };
    fs::write(&fake_exe, b"OLD_VERSION").unwrap();

    // Build a real archive for the current test platform.
    let archive_bytes = {
        let archive_file = temp.path().join("release.zip");
        let file = File::create(&archive_file).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        let opts = zip::write::SimpleFileOptions::default();
        #[cfg(target_os = "windows")]
        {
            writer
                .start_file("OpenKeylet_9.9.9_windows-x64/openkeylet.exe", opts)
                .unwrap();
            writer.write_all(b"UPGRADED_VERSION_9_9_9").unwrap();
        }
        #[cfg(not(target_os = "windows"))]
        {
            writer
                .start_file("OpenKeylet_9.9.9/openkeylet", opts)
                .unwrap();
            writer.write_all(b"UPGRADED_VERSION_9_9_9").unwrap();
        }
        writer.finish().unwrap();
        fs::read(&archive_file).unwrap()
    };
    let archive_sha = encode_hex(&Sha256::digest(&archive_bytes));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");

    let mut platforms = BTreeMap::new();
    platforms.insert(
        current_platform_key().to_owned(),
        PlatformAsset {
            url: format!("{base_url}/download/release.zip"),
            sha256: archive_sha.clone(),
            size: archive_bytes.len() as u64,
            format: "zip".to_owned(),
        },
    );
    let manifest = ReleaseManifest {
        schema_version: 1,
        version: "9.9.9".to_owned(),
        tag: "v9.9.9".to_owned(),
        published_at: "2026-11-24T12:00:00Z".to_owned(),
        release_url: format!("{base_url}/releases/tag/v9.9.9"),
        notes: "Test release notes".to_owned(),
        platforms,
    };
    let signed_manifest = sign_manifest(&keypair, &manifest);

    let manifest_body = signed_manifest.clone();
    let archive_body = archive_bytes.clone();
    let app = Router::new()
        .route(
            "/latest.json",
            get(move || {
                let body = manifest_body.clone();
                async move { body }
            }),
        )
        .route(
            "/download/release.zip",
            get(move || {
                let body = archive_body.clone();
                async move { body }
            }),
        );
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let custom_origin = Url::parse(&base_url).unwrap().origin().ascii_serialization();
    let (verified_manifest, verified) = fetch_and_verify_manifest(
        &format!("{base_url}/latest.json"),
        Some(&pub_b64),
        Some(&custom_origin),
    )
    .await
    .unwrap();
    assert!(verified);
    assert_eq!(verified_manifest.version, "9.9.9");

    let asset = verified_manifest
        .platforms
        .get(current_platform_key())
        .unwrap();
    let dest = temp.path().join("downloaded.zip");
    download_verified_archive(asset, &dest, Some(custom_origin), |_, _| {})
        .await
        .unwrap();
    assert_eq!(fs::read(&dest).unwrap(), archive_bytes);

    #[cfg(target_os = "windows")]
    {
        let extract_dir = temp.path().join("extracted");
        extract_archive_safely(&dest, &extract_dir, "zip").unwrap();
        let root = locate_extracted_package_root(&extract_dir).unwrap();
        let marker = PendingUpdateMarker {
            version: "9.9.9".to_owned(),
            tag: "v9.9.9".to_owned(),
            platform: current_platform_key().to_owned(),
            archive_sha256: archive_sha,
            staged_root: root.clone(),
            signature_verified: true,
            prepared_at: Utc::now().to_rfc3339(),
            notes: "Test".to_owned(),
            release_url: format!("{base_url}/releases/tag/v9.9.9"),
            published_at: "2026-11-24T12:00:00Z".to_owned(),
        };
        save_pending_update(&data_dir, &marker).unwrap();
        assert!(load_pending_update(&data_dir).is_some());

        apply_staged_package(&fake_exe, &root).unwrap();
        assert_eq!(fs::read(&fake_exe).unwrap(), b"UPGRADED_VERSION_9_9_9");
    }

    server.abort();
}
