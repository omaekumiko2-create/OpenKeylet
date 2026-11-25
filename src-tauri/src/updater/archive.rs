use super::*;

pub(super) async fn download_verified_archive(
    asset: &PlatformAsset,
    destination: &Path,
    custom_origin: Option<String>,
    on_progress: impl Fn(u64, u64),
) -> Result<()> {
    if !is_allowed_update_url(&asset.url, custom_origin.as_deref()) {
        bail!("UPDATE_URL_REJECTED: Release archive URL is outside GitHub Releases");
    }
    let client = build_http_client(
        Duration::from_secs(15),
        Duration::from_secs(300),
        custom_origin,
    )?;
    let response = client
        .get(&asset.url)
        .send()
        .await
        .context("UPDATE_NETWORK: Unable to download release archive from GitHub")?;
    if !response.status().is_success() {
        bail!(
            "UPDATE_HTTP_STATUS: GitHub returned HTTP {} while downloading the update",
            response.status().as_u16()
        );
    }

    let mut file = File::create(destination)
        .with_context(|| format!("Unable to create download file: {}", destination.display()))?;
    let mut hasher = Sha256::new();
    let mut downloaded: u64 = 0;
    let mut last_emit = Instant::now();
    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("UPDATE_NETWORK: Connection interrupted during download")?;
        downloaded = downloaded.saturating_add(chunk.len() as u64);
        if downloaded > asset.size || downloaded > MAX_ARCHIVE_BYTES {
            bail!("UPDATE_SIZE_MISMATCH: Downloaded archive exceeded expected manifest size");
        }
        file.write_all(&chunk)
            .context("Unable to write downloaded update chunk to disk")?;
        hasher.update(&chunk);
        if last_emit.elapsed() >= Duration::from_millis(120) || downloaded == asset.size {
            on_progress(downloaded, asset.size);
            last_emit = Instant::now();
        }
    }
    file.flush()?;
    drop(file);

    if downloaded != asset.size {
        bail!(
            "UPDATE_SIZE_MISMATCH: Downloaded {} bytes, expected {} bytes",
            downloaded,
            asset.size
        );
    }
    let actual_hex = encode_hex(&hasher.finalize());
    if !actual_hex.eq_ignore_ascii_case(&asset.sha256) {
        bail!("UPDATE_CHECKSUM_MISMATCH: Downloaded update SHA-256 did not match the signed manifest");
    }
    Ok(())
}

pub(super) fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

pub(super) fn validate_relative_archive_path(path: &Path) -> Result<PathBuf> {
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!(
                    "UPDATE_ARCHIVE_UNSAFE: Archive contains unsafe path '{}'",
                    path.display()
                );
            }
        }
    }
    if clean.as_os_str().is_empty() {
        bail!("UPDATE_ARCHIVE_UNSAFE: Archive contains an empty entry path");
    }
    Ok(clean)
}

pub(super) fn extract_archive_safely(archive_path: &Path, destination: &Path, format: &str) -> Result<()> {
    if destination.exists() {
        fs::remove_dir_all(destination)?;
    }
    fs::create_dir_all(destination)?;

    match format {
        "zip" => {
            // Validate every zip entry path and total size before extraction.
            let file = File::open(archive_path).context("Unable to open downloaded zip archive")?;
            let mut archive =
                zip::ZipArchive::new(file).context("UPDATE_ARCHIVE_INVALID: Corrupt zip archive")?;
            if archive.len() > MAX_EXTRACTED_FILES {
                bail!("UPDATE_ARCHIVE_UNSAFE: Archive exceeds maximum file count");
            }
            let mut total_uncompressed: u64 = 0;
            for idx in 0..archive.len() {
                let entry = archive.by_index(idx)?;
                let name = entry.name().to_owned();
                if name.starts_with("__MACOSX/") {
                    continue;
                }
                let enclosed = entry
                    .enclosed_name()
                    .ok_or_else(|| anyhow!("UPDATE_ARCHIVE_UNSAFE: Zip entry escapes target directory: {name}"))?;
                let _ = validate_relative_archive_path(&enclosed)?;
                total_uncompressed = total_uncompressed.saturating_add(entry.size());
                if total_uncompressed > MAX_EXTRACTED_BYTES {
                    bail!("UPDATE_ARCHIVE_UNSAFE: Uncompressed archive size exceeds safety cap");
                }
            }

            #[cfg(target_os = "macos")]
            {
                // Preserve macOS code signatures, symlinks, and extended attributes using ditto.
                drop(archive);
                let status = Command::new("/usr/bin/ditto")
                    .arg("-x")
                    .arg("-k")
                    .arg(archive_path)
                    .arg(destination)
                    .status()
                    .context("Unable to execute /usr/bin/ditto to extract macOS update")?;
                if !status.success() {
                    bail!("UPDATE_ARCHIVE_INVALID: macOS ditto extraction failed");
                }
                Ok(())
            }

            #[cfg(not(target_os = "macos"))]
            {
                let mut written_total: u64 = 0;
                for idx in 0..archive.len() {
                    let mut entry = archive.by_index(idx)?;
                    if entry.is_symlink() {
                        bail!("UPDATE_ARCHIVE_UNSAFE: Refusing symlink entry inside zip archive");
                    }
                    let enclosed = entry
                        .enclosed_name()
                        .ok_or_else(|| anyhow!("UPDATE_ARCHIVE_UNSAFE: Unsafe zip entry path"))?;
                    let clean = validate_relative_archive_path(&enclosed)?;
                    let out_path = destination.join(clean);
                    if entry.is_dir() {
                        fs::create_dir_all(&out_path)?;
                        continue;
                    }
                    if let Some(parent) = out_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    let mut out_file = File::create(&out_path)?;
                    let copied = copy_bounded(&mut entry, &mut out_file, MAX_EXTRACTED_BYTES - written_total)?;
                    written_total = written_total.saturating_add(copied);
                    #[cfg(unix)]
                    if let Some(mode) = entry.unix_mode() {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = fs::set_permissions(&out_path, fs::Permissions::from_mode(mode & 0o777));
                    }
                }
                Ok(())
            }
        }
        "tar.gz" => {
            let file = File::open(archive_path).context("Unable to open downloaded tar.gz archive")?;
            let decoder = GzDecoder::new(file);
            let mut archive = tar::Archive::new(decoder);
            let mut file_count: usize = 0;
            let mut written_total: u64 = 0;
            for entry_result in archive
                .entries()
                .context("UPDATE_ARCHIVE_INVALID: Corrupt tar.gz archive")?
            {
                let mut entry = entry_result?;
                file_count += 1;
                if file_count > MAX_EXTRACTED_FILES {
                    bail!("UPDATE_ARCHIVE_UNSAFE: Archive exceeds maximum file count");
                }
                let entry_type = entry.header().entry_type();
                if entry_type.is_symlink() || entry_type.is_hard_link() {
                    bail!("UPDATE_ARCHIVE_UNSAFE: Refusing link entry inside tar.gz archive");
                }
                if !(entry_type.is_file() || entry_type.is_dir()) {
                    continue;
                }
                let raw_path = entry.path()?.into_owned();
                let clean = validate_relative_archive_path(&raw_path)?;
                let out_path = destination.join(clean);
                if entry_type.is_dir() {
                    fs::create_dir_all(&out_path)?;
                    continue;
                }
                if let Some(parent) = out_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                #[cfg(unix)]
                let mode = entry.header().mode().ok();
                let mut out_file = File::create(&out_path)?;
                let copied =
                    copy_bounded(&mut entry, &mut out_file, MAX_EXTRACTED_BYTES - written_total)?;
                written_total = written_total.saturating_add(copied);
                #[cfg(unix)]
                if let Some(mode) = mode {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&out_path, fs::Permissions::from_mode(mode & 0o777));
                }
            }
            Ok(())
        }
        other => bail!("UPDATE_ARCHIVE_INVALID: Unsupported archive format '{other}'"),
    }
}

fn copy_bounded(reader: &mut impl io::Read, writer: &mut impl io::Write, limit: u64) -> Result<u64> {
    let mut buf = [0_u8; 32 * 1024];
    let mut total: u64 = 0;
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > limit {
            bail!("UPDATE_ARCHIVE_UNSAFE: Uncompressed archive exceeded safety size limit");
        }
        writer.write_all(&buf[..read])?;
    }
    Ok(total)
}

pub(super) fn locate_extracted_package_root(extract_dir: &Path) -> Result<PathBuf> {
    if validate_staged_package_root(extract_dir).is_ok() {
        return Ok(extract_dir.to_path_buf());
    }
    let mut dirs = Vec::new();
    for entry in fs::read_dir(extract_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir()
            && !entry
                .file_name()
                .to_string_lossy()
                .starts_with("__MACOSX")
        {
            dirs.push(path);
        }
    }
    for dir in dirs {
        if validate_staged_package_root(&dir).is_ok() {
            return Ok(dir);
        }
    }
    bail!("UPDATE_ARCHIVE_INVALID: Expected OpenKeylet payload was not found inside the downloaded archive")
}

pub(super) fn validate_staged_package_root(package_root: &Path) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        if !package_root.join("openkeylet.exe").is_file() {
            bail!("UPDATE_ARCHIVE_INVALID: Missing openkeylet.exe in Windows package");
        }
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        let app = package_root.join("OpenKeylet.app");
        if !app.join("Contents/MacOS/openkeylet").is_file() {
            bail!("UPDATE_ARCHIVE_INVALID: Missing OpenKeylet.app in macOS package");
        }
        if std::env::var_os("OPENKEYLET_SKIP_CODESIGN_VERIFY").is_none() {
            let status = Command::new("/usr/bin/codesign")
                .args(["--verify", "--deep", "--strict"])
                .arg(&app)
                .status()
                .context("Unable to run codesign verification on downloaded macOS update")?;
            if !status.success() {
                bail!("UPDATE_CODESIGN_INVALID: Downloaded OpenKeylet.app failed macOS codesign verification");
            }
        }
        return Ok(());
    }
    #[cfg(all(target_os = "linux", feature = "gui"))]
    {
        if !package_root.join("OpenKeylet.AppImage").is_file() {
            bail!("UPDATE_ARCHIVE_INVALID: Missing OpenKeylet.AppImage in Linux GUI package");
        }
        return Ok(());
    }
    #[cfg(all(target_os = "linux", not(feature = "gui")))]
    {
        if !package_root.join("openkeylet").is_file() {
            bail!("UPDATE_ARCHIVE_INVALID: Missing openkeylet binary in Linux headless package");
        }
        return Ok(());
    }
}

