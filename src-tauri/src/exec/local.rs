use super::*;

#[cfg(windows)]
pub(super) fn windows_local_shell() -> (&'static str, bool) {
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            if dir.join("pwsh.exe").is_file() {
                return ("pwsh.exe", false);
            }
        }
    }
    ("powershell.exe", true)
}


pub async fn execute_local(
    connection: Option<&DecryptedConnection>,
    command: &str,
    cwd: Option<&str>,
    timeout_seconds: Option<u64>,
    secret_env: &HashMap<String, String>,
    stdin: Option<&str>,
    max_output_bytes: Option<usize>,
    extra_redactions: &[String],
) -> Result<SshResponse> {
    let command = command.trim();
    if command.is_empty() || command.contains('\0') {
        bail!("Local command cannot be empty or contain a null character");
    }
    if connection.is_some_and(|connection| !connection.stored.enabled) {
        bail!("This connection is disabled");
    }

    #[cfg(windows)]
    let mut process = {
        let (shell, clear_ps_module_path) = windows_local_shell();
        let mut process = tokio::process::Command::new(shell);
        if clear_ps_module_path {
            process.env_remove("PSModulePath");
        }
        process.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command]);
        process
    };
    #[cfg(not(windows))]
    let mut process = {
        let shell = std::env::var("SHELL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "/bin/sh".to_owned());
        let mut process = tokio::process::Command::new(shell);
        process.args(["-lc", command]);
        process
    };

    if let Some(cwd) = cwd.map(str::trim).filter(|value| !value.is_empty()) {
        let cwd = resolve_user_path(cwd)?;
        if !cwd.is_dir() {
            bail!("Local command working directory does not exist or is not a directory");
        }
        process.current_dir(cwd);
    }
    for (name, value) in secret_env {
        if !valid_environment_name(name) {
            bail!("Invalid terminal_run secretEnv environment variable name:{name}");
        }
        if value.contains('\0') {
            bail!("This secret module cannot be used as a local environment variable");
        }
        process.env(name, value);
    }
    process
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let stdin = stdin.map(str::as_bytes).map(<[u8]>::to_vec);
    let execution = async {
        let mut child = process.spawn().context("Unable to start local command")?;
        let child_stdout = child
            .stdout
            .take()
            .context("Unable to open local command stdout")?;
        let child_stderr = child
            .stderr
            .take()
            .context("Unable to open local command stderr")?;
        let input_task = if let Some(input) = stdin {
            let mut child_stdin = child
                .stdin
                .take()
                .context("Unable to open local command standard input")?;
            Some(tokio::spawn(async move {
                child_stdin.write_all(&input).await?;
                child_stdin.shutdown().await
            }))
        } else {
            None
        };
        let stdout_task = tokio::spawn(read_stream_bounded(child_stdout, max_output_bytes));
        let stderr_task = tokio::spawn(read_stream_bounded(child_stderr, max_output_bytes));
        let status = child
            .wait()
            .await
            .context("Unable to wait for local command")?;
        if let Some(task) = input_task {
            task.await
                .context("Local command standard input task ended unexpectedly")??;
        }
        let stdout_capture = stdout_task
            .await
            .context("Local command stdout task ended unexpectedly")?
            .context("Unable to read local command stdout")?;
        let stderr_capture = stderr_task
            .await
            .context("Local command stderr task ended unexpectedly")?
            .context("Unable to read local command stderr")?;
        Ok::<_, anyhow::Error>((status, stdout_capture, stderr_capture))
    };
    let (status, stdout_capture, stderr_capture) = match timeout_seconds.filter(|seconds| *seconds > 0)
    {
        Some(seconds) => tokio::time::timeout(Duration::from_secs(seconds), execution)
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "Local command exceeded the timeout set by the caller of {seconds} seconds"
                )
            })??,
        None => execution.await?,
    };
    let redactor = output_redactor(connection, extra_redactions);
    let (stdout, stdout_truncated) = stdout_capture.finish(&redactor);
    let (stderr, stderr_truncated) = stderr_capture.finish(&redactor);
    #[cfg(unix)]
    let signal = status.signal().map(|signal| signal.to_string());
    #[cfg(not(unix))]
    let signal = None;
    Ok(SshResponse {
        exit_code: status.code().map(|code| code as u32),
        signal,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
    })
}

