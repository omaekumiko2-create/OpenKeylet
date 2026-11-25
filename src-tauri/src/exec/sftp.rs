use super::*;

pub(super) async fn open_sftp(
    vault: &Vault,
    connection: &DecryptedConnection,
) -> Result<(client::Handle<SshClient>, SftpSession)> {
    let session = connect_ssh(vault, connection).await?;
    let channel = session.channel_open_session().await?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .context("The remote does not have the SFTP subsystem enabled")?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .context("Unable to initialize the SFTP session")?;
    Ok((session, sftp))
}

pub async fn ssh_upload(
    vault: &Vault,
    connection: &DecryptedConnection,
    local_path: &str,
    remote_path: &str,
    overwrite: bool,
    timeout_seconds: Option<u64>,
) -> Result<SshTransferResponse> {
    if !connection.stored.enabled {
        bail!("This connection is disabled");
    }
    let local_path = local_path.trim();
    let remote_path = validate_transfer_path(remote_path, "Remote path")?;
    if local_path.is_empty() || local_path.contains('\0') {
        bail!("Invalid local upload path");
    }
    let execution = async {
        let local_path = resolve_user_path(local_path)?;
        let canonical_local = tokio::fs::canonicalize(local_path)
            .await
            .context("Local upload path not found")?;
        let metadata = tokio::fs::metadata(&canonical_local).await?;
        if !metadata.is_file() && !metadata.is_dir() {
            bail!("Local upload path is not a file or directory");
        }
        let (session, sftp) = open_sftp(vault, connection).await?;
        let remote_path = resolve_remote_path(&sftp, &remote_path).await?;
        let (kind, stats) = if metadata.is_dir() {
            (
                "directory",
                upload_local_directory(&sftp, &canonical_local, &remote_path, overwrite).await?,
            )
        } else {
            (
                "file",
                upload_local_file(&sftp, &canonical_local, &remote_path, overwrite).await?,
            )
        };
        let _ = sftp.close().await;
        let _ = session
            .disconnect(Disconnect::ByApplication, "", "en")
            .await;
        Ok(SshTransferResponse {
            direction: "upload".to_owned(),
            kind: kind.to_owned(),
            local_path: canonical_local.to_string_lossy().into_owned(),
            remote_path,
            bytes_transferred: stats.bytes,
            files_transferred: stats.files,
            directories_transferred: stats.directories,
        })
    };
    run_optional_ssh_timeout(execution, timeout_seconds, "SSH upload").await
}

pub async fn ssh_download(
    vault: &Vault,
    connection: &DecryptedConnection,
    remote_path: &str,
    local_path: &str,
    overwrite: bool,
    timeout_seconds: Option<u64>,
) -> Result<SshTransferResponse> {
    if !connection.stored.enabled {
        bail!("This connection is disabled");
    }
    let remote_path = validate_transfer_path(remote_path, "Remote path")?;
    let local_path = local_path.trim();
    if local_path.is_empty() || local_path.contains('\0') {
        bail!("Invalid local save path");
    }
    let local_path = resolve_user_path(local_path)?;
    let execution = async {
        let (session, sftp) = open_sftp(vault, connection).await?;
        let remote_path = resolve_remote_path(&sftp, &remote_path).await?;
        let remote_metadata = sftp
            .metadata(remote_path.clone())
            .await
            .context("Remote download path not found")?;
        let (kind, stats) = if remote_metadata.file_type().is_dir() {
            (
                "directory",
                download_remote_directory(&sftp, &remote_path, &local_path, overwrite).await?,
            )
        } else if remote_metadata.file_type().is_file() {
            (
                "file",
                download_remote_file(&sftp, &remote_path, &local_path, overwrite).await?,
            )
        } else {
            bail!("Remote download path is not a file or directory");
        };
        let _ = sftp.close().await;
        let _ = session
            .disconnect(Disconnect::ByApplication, "", "en")
            .await;
        Ok(SshTransferResponse {
            direction: "download".to_owned(),
            kind: kind.to_owned(),
            local_path: tokio::fs::canonicalize(&local_path)
                .await
                .unwrap_or(local_path)
                .to_string_lossy()
                .into_owned(),
            remote_path,
            bytes_transferred: stats.bytes,
            files_transferred: stats.files,
            directories_transferred: stats.directories,
        })
    };
    run_optional_ssh_timeout(execution, timeout_seconds, "SSH download").await
}

pub(super) async fn upload_local_file(
    sftp: &SftpSession,
    local_path: &Path,
    remote_path: &str,
    overwrite: bool,
) -> Result<TransferStats> {
    ensure_remote_parent_directories(sftp, remote_path).await?;
    if !overwrite && sftp.try_exists(remote_path.to_owned()).await? {
        bail!("Remote destination already exists; set overwrite to replace it=true");
    }
    let temporary_path = format!("{remote_path}.openkeylet-{}.part", Uuid::new_v4().simple());
    let result: Result<u64> = async {
        let mut local = tokio::fs::File::open(local_path)
            .await
            .context("Unable to open local upload file")?;
        let mut remote = sftp
            .open_with_flags(
                temporary_path.clone(),
                OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
            )
            .await
            .context("Unable to create remote temporary file")?;
        let bytes = tokio::io::copy(&mut local, &mut remote)
            .await
            .context("SFTP upload interrupted")?;
        remote
            .flush()
            .await
            .context("Unable to flush remote file")?;
        remote
            .shutdown()
            .await
            .context("Unable to close remote file")?;
        commit_remote_file(sftp, &temporary_path, remote_path, overwrite).await?;
        Ok(bytes)
    }
    .await;
    match result {
        Ok(bytes) => Ok(TransferStats {
            bytes,
            files: 1,
            directories: 0,
        }),
        Err(error) => {
            let _ = sftp.remove_file(temporary_path).await;
            Err(error)
        }
    }
}

pub(super) async fn upload_local_directory(
    sftp: &SftpSession,
    local_root: &Path,
    remote_path: &str,
    overwrite: bool,
) -> Result<TransferStats> {
    ensure_remote_parent_directories(sftp, remote_path).await?;
    if !overwrite && sftp.try_exists(remote_path.to_owned()).await? {
        bail!("Remote destination already exists; set overwrite to replace it=true");
    }
    let temporary_path = format!("{remote_path}.openkeylet-{}.part", Uuid::new_v4().simple());
    sftp.create_dir(temporary_path.clone())
        .await
        .context("Unable to create remote temporary directory")?;

    let result: Result<TransferStats> = async {
        let mut stats = TransferStats {
            directories: 1,
            ..Default::default()
        };
        let mut visited = HashSet::from([tokio::fs::canonicalize(local_root).await?]);
        let mut stack = vec![(local_root.to_path_buf(), String::new())];
        while let Some((local_directory, relative_directory)) = stack.pop() {
            let mut entries = tokio::fs::read_dir(&local_directory)
                .await
                .with_context(|| {
                    format!(
                        "Unable to read local directory {}",
                        local_directory.display()
                    )
                })?;
            while let Some(entry) = entries.next_entry().await? {
                let name = entry.file_name();
                let relative_path = if relative_directory.is_empty() {
                    PathBuf::from(&name)
                } else {
                    PathBuf::from(&relative_directory).join(&name)
                };
                let relative_remote = relative_path.to_string_lossy().replace('\\', "/");
                let remote_entry = format!(
                    "{}/{}",
                    temporary_path.trim_end_matches('/'),
                    relative_remote
                );
                let entry_path = entry.path();
                let metadata = tokio::fs::metadata(&entry_path).await?;
                if metadata.is_dir() {
                    let canonical = tokio::fs::canonicalize(&entry_path).await?;
                    if !visited.insert(canonical) {
                        bail!(
                            "Local directory contains a cyclic link:{}",
                            entry_path.display()
                        );
                    }
                    sftp.create_dir(remote_entry).await.with_context(|| {
                        format!("Unable to create remote directory {relative_remote}")
                    })?;
                    stats.directories += 1;
                    stack.push((entry_path, relative_remote));
                } else if metadata.is_file() {
                    let mut local = tokio::fs::File::open(&entry_path).await?;
                    let mut remote = sftp
                        .open_with_flags(
                            remote_entry,
                            OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
                        )
                        .await?;
                    stats.bytes += tokio::io::copy(&mut local, &mut remote)
                        .await
                        .context("SFTP directory upload interrupted")?;
                    remote.flush().await?;
                    remote.shutdown().await?;
                    stats.files += 1;
                } else {
                    bail!(
                        "Local directory contains a special file that cannot be transferred:{}",
                        entry_path.display()
                    );
                }
            }
        }
        commit_remote_directory(sftp, &temporary_path, remote_path, overwrite).await?;
        Ok(stats)
    }
    .await;
    if result.is_err() {
        let _ = remove_remote_tree(sftp, &temporary_path).await;
    }
    result
}

pub(super) async fn download_remote_file(
    sftp: &SftpSession,
    remote_path: &str,
    local_path: &Path,
    overwrite: bool,
) -> Result<TransferStats> {
    if let Some(parent) = local_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(parent)
            .await
            .context("Unable to create local destination directory")?;
    }
    if !overwrite && tokio::fs::try_exists(local_path).await? {
        bail!("Local destination already exists; set overwrite to replace it=true");
    }
    let file_name = local_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("download");
    let temporary_path = local_path.with_file_name(format!(
        ".{file_name}.openkeylet-{}.part",
        Uuid::new_v4().simple()
    ));
    let result: Result<u64> = async {
        let mut remote = sftp
            .open(remote_path.to_owned())
            .await
            .context("Unable to open remote download file")?;
        let mut local = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
            .await
            .context("Unable to create local temporary file")?;
        let bytes = tokio::io::copy(&mut remote, &mut local)
            .await
            .context("SFTP download interrupted")?;
        local.flush().await.context("Unable to flush local file")?;
        local
            .sync_all()
            .await
            .context("Unable to sync local file")?;
        remote
            .shutdown()
            .await
            .context("Unable to close remote file")?;
        commit_local_file(&temporary_path, local_path, overwrite).await?;
        Ok(bytes)
    }
    .await;
    match result {
        Ok(bytes) => Ok(TransferStats {
            bytes,
            files: 1,
            directories: 0,
        }),
        Err(error) => {
            let _ = tokio::fs::remove_file(&temporary_path).await;
            Err(error)
        }
    }
}

pub(super) async fn download_remote_directory(
    sftp: &SftpSession,
    remote_root: &str,
    local_path: &Path,
    overwrite: bool,
) -> Result<TransferStats> {
    if let Some(parent) = local_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(parent)
            .await
            .context("Unable to create local destination directory")?;
    }
    if !overwrite && tokio::fs::try_exists(local_path).await? {
        bail!("Local destination already exists; set overwrite to replace it=true");
    }
    let directory_name = local_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("download");
    let temporary_path = local_path.with_file_name(format!(
        ".{directory_name}.openkeylet-{}.part",
        Uuid::new_v4().simple()
    ));
    tokio::fs::create_dir(&temporary_path)
        .await
        .context("Unable to create local temporary directory")?;

    let result: Result<TransferStats> = async {
        let canonical_root = sftp
            .canonicalize(remote_root.to_owned())
            .await
            .unwrap_or_else(|_| remote_root.to_owned());
        let mut visited = HashSet::from([canonical_root]);
        let mut stats = TransferStats {
            directories: 1,
            ..Default::default()
        };
        let mut stack = vec![(remote_root.to_owned(), PathBuf::new())];
        while let Some((remote_directory, relative_directory)) = stack.pop() {
            let entries = sftp
                .read_dir(remote_directory.clone())
                .await
                .with_context(|| format!("Unable to read remote directory {remote_directory}"))?;
            for entry in entries {
                let name = entry.file_name();
                let relative_path = relative_directory.join(&name);
                let local_entry = temporary_path.join(&relative_path);
                let remote_entry = entry.path();
                let metadata = if entry.file_type().is_symlink() {
                    sftp.metadata(remote_entry.clone()).await?
                } else {
                    entry.metadata()
                };
                if metadata.file_type().is_dir() {
                    let canonical = sftp
                        .canonicalize(remote_entry.clone())
                        .await
                        .unwrap_or_else(|_| remote_entry.clone());
                    if !visited.insert(canonical) {
                        bail!("Remote directory contains a cyclic link:{remote_entry}");
                    }
                    tokio::fs::create_dir(&local_entry)
                        .await
                        .with_context(|| format!("Unable to create local directory {}", local_entry.display()))?;
                    stats.directories += 1;
                    stack.push((remote_entry, relative_path));
                } else if metadata.file_type().is_file() {
                    let mut remote = sftp.open(remote_entry.clone()).await?;
                    let mut local = tokio::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&local_entry)
                        .await?;
                    stats.bytes += tokio::io::copy(&mut remote, &mut local)
                        .await
                        .context("SFTP directory download interrupted")?;
                    local.flush().await?;
                    local.sync_all().await?;
                    remote.shutdown().await?;
                    stats.files += 1;
                } else {
                    bail!("Remote directory contains a special file that cannot be transferred:{remote_entry}");
                }
            }
        }
        commit_local_directory(&temporary_path, local_path, overwrite).await?;
        Ok(stats)
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_dir_all(&temporary_path).await;
    }
    result
}

pub(super) async fn resolve_remote_path(sftp: &SftpSession, path: &str) -> Result<String> {
    if path.starts_with('~') {
        let (home, remainder) = path.split_once('/').unwrap_or((path, ""));
        let Some(expanded_home) = sftp
            .expand_path(home.to_owned())
            .await
            .context("Unable to expand remote home directory")?
        else {
            bail!(
                "Remote SFTP service does not support expanding ~ paths; use an absolute path instead"
            );
        };
        return Ok(if remainder.is_empty() {
            expanded_home
        } else {
            format!("{}/{remainder}", expanded_home.trim_end_matches('/'))
        });
    }
    if remote_path_is_absolute(path) {
        return Ok(path.replace('\\', "/"));
    }
    let base = sftp
        .canonicalize(".")
        .await
        .context("Unable to resolve remote current directory")?;
    Ok(format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.replace('\\', "/").trim_start_matches('/')
    ))
}

pub(super) fn remote_path_is_absolute(path: &str) -> bool {
    path.starts_with('/')
        || path.starts_with('\\')
        || path
            .as_bytes()
            .get(1)
            .is_some_and(|separator| *separator == b':')
}

pub(super) async fn ensure_remote_parent_directories(sftp: &SftpSession, path: &str) -> Result<()> {
    for directory in remote_parent_directories(path) {
        if !sftp.try_exists(directory.clone()).await? {
            sftp.create_dir(directory.clone())
                .await
                .with_context(|| format!("Unable to create remote directory {directory}"))?;
        }
    }
    Ok(())
}

pub(super) fn remote_parent_directories(path: &str) -> Vec<String> {
    let normalized = path.replace('\\', "/");
    let mut parts = normalized.split('/').collect::<Vec<_>>();
    if parts.len() < 2 {
        return Vec::new();
    }
    parts.pop();

    let absolute = normalized.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    let mut root_depth = 0;
    for part in parts {
        match part {
            "" | "." => continue,
            ".." => {
                if stack.len() > root_depth {
                    stack.pop();
                }
            }
            _ => {
                stack.push(part);
                if stack.len() == 1 && part.ends_with(':') {
                    root_depth = 1;
                }
            }
        }
    }
    (1..=stack.len())
        .map(|length| {
            let joined = stack[..length].join("/");
            if absolute {
                format!("/{joined}")
            } else {
                joined
            }
        })
        .collect()
}

pub(super) async fn commit_remote_file(
    sftp: &SftpSession,
    temporary_path: &str,
    destination_path: &str,
    overwrite: bool,
) -> Result<()> {
    let destination_exists = sftp.try_exists(destination_path.to_owned()).await?;
    if !destination_exists {
        return sftp
            .rename(temporary_path.to_owned(), destination_path.to_owned())
            .await
            .context("Unable to complete remote file write");
    }
    if !overwrite {
        bail!("Remote file already exists; explicitly set overwrite to replace it=true");
    }
    let backup_path = format!(
        "{destination_path}.openkeylet-{}.backup",
        Uuid::new_v4().simple()
    );
    sftp.rename(destination_path.to_owned(), backup_path.clone())
        .await
        .context("Unable to stage existing remote file; original file is unchanged")?;

    if let Err(install_error) = sftp
        .rename(temporary_path.to_owned(), destination_path.to_owned())
        .await
    {
        if let Err(restore_error) = sftp
            .rename(backup_path.clone(), destination_path.to_owned())
            .await
        {
            bail!(
                "Unable to install new remote file ({install_error}), and unable to automatically restore the original file ({restore_error}; original file is retained at {backup_path}"
            );
        }
        return Err(anyhow::anyhow!(install_error))
            .context("Unable to install new remote file; original file has been restored");
    }

    if let Err(cleanup_error) = remove_remote_tree(sftp, &backup_path).await {
        let remove_new = sftp.remove_file(destination_path.to_owned()).await;
        let restore_old = sftp
            .rename(backup_path.clone(), destination_path.to_owned())
            .await;
        if remove_new.is_ok() && restore_old.is_ok() {
            return Err(anyhow::anyhow!(cleanup_error))
                .context("Unable to clean up remote backup; new file has been rolled back and original file restored");
        }
        bail!(
            "New file was written, but unable to clean up remote backup {backup_path}（{cleanup_error}); automatic rollback was also not fully completed"
        );
    }
    Ok(())
}

pub(super) async fn commit_remote_directory(
    sftp: &SftpSession,
    temporary_path: &str,
    destination_path: &str,
    overwrite: bool,
) -> Result<()> {
    let destination_exists = sftp.try_exists(destination_path.to_owned()).await?;
    if !destination_exists {
        return sftp
            .rename(temporary_path.to_owned(), destination_path.to_owned())
            .await
            .context("Unable to complete remote directory write");
    }
    if !overwrite {
        bail!("Remote destination already exists; set overwrite to replace it=true");
    }
    let backup_path = format!(
        "{destination_path}.openkeylet-{}.backup",
        Uuid::new_v4().simple()
    );
    sftp.rename(destination_path.to_owned(), backup_path.clone())
        .await
        .context("Unable to stage existing remote directory; original directory is unchanged")?;
    if let Err(install_error) = sftp
        .rename(temporary_path.to_owned(), destination_path.to_owned())
        .await
    {
        if let Err(restore_error) = sftp
            .rename(backup_path.clone(), destination_path.to_owned())
            .await
        {
            bail!(
                "Unable to install new remote directory ({install_error}), and unable to automatically restore the original directory ({restore_error}; original directory is retained at {backup_path}"
            );
        }
        return Err(anyhow::anyhow!(install_error)).context(
            "Unable to install new remote directory; original directory has been restored",
        );
    }

    if let Err(cleanup_error) = remove_remote_tree(sftp, &backup_path).await {
        let remove_new = remove_remote_tree(sftp, destination_path).await;
        let restore_old = sftp
            .rename(backup_path.clone(), destination_path.to_owned())
            .await;
        if remove_new.is_ok() && restore_old.is_ok() {
            return Err(cleanup_error).context("Unable to clean up remote directory backup; new directory has been rolled back and original directory restored");
        }
        bail!(
            "New directory was written, but unable to clean up remote backup {backup_path}（{cleanup_error}); automatic rollback was also not fully completed"
        );
    }
    Ok(())
}

pub(super) async fn remove_remote_tree(sftp: &SftpSession, root: &str) -> Result<()> {
    if !sftp.try_exists(root.to_owned()).await? {
        return Ok(());
    }
    let metadata = sftp.symlink_metadata(root.to_owned()).await?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return sftp
            .remove_file(root.to_owned())
            .await
            .with_context(|| format!("Unable to delete remote file {root}"));
    }

    let mut stack = vec![(root.to_owned(), false)];
    while let Some((path, visited)) = stack.pop() {
        if visited {
            sftp.remove_dir(path.clone())
                .await
                .with_context(|| format!("Unable to delete remote directory {path}"))?;
            continue;
        }
        stack.push((path.clone(), true));
        for entry in sftp
            .read_dir(path.clone())
            .await
            .with_context(|| format!("Unable to read remote directory to be deleted {path}"))?
        {
            if entry.file_type().is_dir() && !entry.file_type().is_symlink() {
                stack.push((entry.path(), false));
            } else {
                let entry_path = entry.path();
                sftp.remove_file(entry_path.clone())
                    .await
                    .with_context(|| format!("Unable to delete remote file {entry_path}"))?;
            }
        }
    }
    Ok(())
}

pub(super) async fn commit_local_file(
    temporary_path: &std::path::Path,
    destination_path: &std::path::Path,
    overwrite: bool,
) -> Result<()> {
    let destination_exists = tokio::fs::try_exists(destination_path).await?;
    if !destination_exists {
        return tokio::fs::rename(temporary_path, destination_path)
            .await
            .context("Unable to complete local file write");
    }
    if !overwrite {
        bail!("Local file already exists; explicitly set overwrite to replace it=true");
    }
    let file_name = destination_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("download");
    let backup_path = destination_path.with_file_name(format!(
        ".{file_name}.openkeylet-{}.backup",
        Uuid::new_v4().simple()
    ));
    tokio::fs::rename(destination_path, &backup_path)
        .await
        .context("Unable to stage existing local file; original file is unchanged")?;

    if let Err(install_error) = tokio::fs::rename(temporary_path, destination_path).await {
        if let Err(restore_error) = tokio::fs::rename(&backup_path, destination_path).await {
            bail!(
                "Unable to install new local file ({install_error}), and unable to automatically restore the original file ({restore_error}; original file is retained at {}",
                backup_path.display()
            );
        }
        return Err(install_error)
            .context("Unable to install new local file; original file has been restored");
    }

    if let Err(cleanup_error) = remove_local_path(&backup_path).await {
        let remove_new = tokio::fs::remove_file(destination_path).await;
        let restore_old = tokio::fs::rename(&backup_path, destination_path).await;
        if remove_new.is_ok() && restore_old.is_ok() {
            return Err(cleanup_error).context("Unable to clean up local backup; new file has been rolled back and original file restored");
        }
        bail!(
            "New file was written, but unable to clean up local backup {}（{cleanup_error}); automatic rollback was also not fully completed",
            backup_path.display()
        );
    }
    Ok(())
}

pub(super) async fn commit_local_directory(
    temporary_path: &Path,
    destination_path: &Path,
    overwrite: bool,
) -> Result<()> {
    let destination_exists = tokio::fs::try_exists(destination_path).await?;
    if !destination_exists {
        return tokio::fs::rename(temporary_path, destination_path)
            .await
            .context("Unable to complete local directory write");
    }
    if !overwrite {
        bail!("Local destination already exists; set overwrite to replace it=true");
    }
    let directory_name = destination_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("download");
    let backup_path = destination_path.with_file_name(format!(
        ".{directory_name}.openkeylet-{}.backup",
        Uuid::new_v4().simple()
    ));
    tokio::fs::rename(destination_path, &backup_path)
        .await
        .context("Unable to stage existing local directory; original directory is unchanged")?;
    if let Err(install_error) = tokio::fs::rename(temporary_path, destination_path).await {
        if let Err(restore_error) = tokio::fs::rename(&backup_path, destination_path).await {
            bail!(
                "Unable to install new local directory ({install_error}), and unable to automatically restore the original directory ({restore_error}; original directory is retained at {}",
                backup_path.display()
            );
        }
        return Err(install_error).context(
            "Unable to install new local directory; original directory has been restored",
        );
    }

    if let Err(cleanup_error) = remove_local_path(&backup_path).await {
        let remove_new = tokio::fs::remove_dir_all(destination_path).await;
        let restore_old = tokio::fs::rename(&backup_path, destination_path).await;
        if remove_new.is_ok() && restore_old.is_ok() {
            return Err(cleanup_error).context("Unable to clean up local directory backup; new directory has been rolled back and original directory restored");
        }
        bail!(
            "New directory was written, but unable to clean up local backup {}（{cleanup_error}); automatic rollback was also not fully completed",
            backup_path.display()
        );
    }
    Ok(())
}

pub(super) async fn remove_local_path(path: &Path) -> Result<()> {
    let file_type = tokio::fs::symlink_metadata(path).await?.file_type();
    if file_type.is_dir() && !file_type.is_symlink() {
        tokio::fs::remove_dir_all(path).await?;
    } else {
        tokio::fs::remove_file(path).await?;
    }
    Ok(())
}

pub(super) async fn run_optional_ssh_timeout<T>(
    execution: impl std::future::Future<Output = Result<T>>,
    timeout_seconds: Option<u64>,
    action: &str,
) -> Result<T> {
    match timeout_seconds.filter(|seconds| *seconds > 0) {
        Some(seconds) => tokio::time::timeout(Duration::from_secs(seconds), execution)
            .await
            .map_err(|_| anyhow::anyhow!("{action}Exceeded caller-configured {seconds} seconds"))?,
        None => execution.await,
    }
}

pub(super) fn validate_transfer_path(value: &str, label: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() || value.contains('\0') {
        bail!("{label}Invalid");
    }
    Ok(value.to_owned())
}

