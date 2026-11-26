use crate::{
    policy::{Redactor, redaction_candidates},
    storage::resolve_user_path,
};
use anyhow::{Context, Result, bail};
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};
use schemars::JsonSchema;
use serde::Serialize;
use std::{
    collections::{HashMap, VecDeque, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TerminalOpenResult {
    #[schemars(with = "String")]
    pub session_id: Uuid,
    pub executable: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TerminalReadResult {
    pub output: String,
    pub running: bool,
    pub exit_code: Option<u32>,
    pub truncated: bool,
}

const MAX_UNREAD_BUFFER_BYTES: usize = 8 * 1024 * 1024;

/// How long bytes that may be the start of a secret are held back while the program runs.
/// A program echoes a value in one write, so the rest of a split secret arrives at once; a
/// longer pause means the bytes were ordinary output, such as a prompt that happens to end
/// with the first characters of some vault secret, and holding them would hide the prompt.
const INCOMPLETE_SECRET_HOLD: Duration = Duration::from_millis(250);

#[derive(Default)]
struct OutputBuffer {
    bytes: VecDeque<u8>,
    truncated: bool,
    last_push: Option<Instant>,
}

impl OutputBuffer {
    fn push(&mut self, bytes: &[u8]) {
        self.last_push = Some(Instant::now());
        if bytes.len() >= MAX_UNREAD_BUFFER_BYTES {
            self.bytes.clear();
            let start = bytes.len() - MAX_UNREAD_BUFFER_BYTES;
            self.bytes.extend(&bytes[start..]);
            self.truncated = true;
            return;
        }
        let overflow = (self.bytes.len() + bytes.len()).saturating_sub(MAX_UNREAD_BUFFER_BYTES);
        if overflow > 0 {
            self.bytes.drain(..overflow);
            self.truncated = true;
        }
        self.bytes.extend(bytes);
    }

    fn take_redacted(&mut self, redactor: &Redactor, running: bool) -> (String, bool) {
        let was_truncated = std::mem::take(&mut self.truncated);
        let source = self.bytes.drain(..).collect::<Vec<u8>>();
        let hold = running
            && self
                .last_push
                .is_some_and(|pushed| pushed.elapsed() < INCOMPLETE_SECRET_HOLD);
        let (mut output, mut consumed) = redactor.redact_stream(&source, hold);
        if running {
            // Keep a UTF-8 character split by the read so it is not replaced by U+FFFD.
            let split = incomplete_utf8_suffix(&source[..consumed]);
            if split > 0 && output.ends_with(&source[consumed - split..consumed]) {
                output.truncate(output.len() - split);
                consumed -= split;
            }
        }
        self.bytes.extend(&source[consumed..]);
        (String::from_utf8_lossy(&output).into_owned(), was_truncated)
    }
}

fn incomplete_utf8_suffix(bytes: &[u8]) -> usize {
    for back in 1..=bytes.len().min(3) {
        let byte = bytes[bytes.len() - back];
        if byte & 0b1100_0000 == 0b1000_0000 {
            continue;
        }
        let needed = match byte {
            0xf0..=0xff => 4,
            0xe0..=0xef => 3,
            0xc0..=0xdf => 2,
            _ => 1,
        };
        return if needed > back { back } else { 0 };
    }
    0
}

struct TerminalSession {
    master: Mutex<Option<Box<dyn MasterPty + Send>>>,
    writer: Arc<Mutex<Option<Box<dyn Write + Send>>>>,
    child: Mutex<Box<dyn Child + Send + Sync>>,
    output: Arc<Mutex<OutputBuffer>>,
    secrets: Mutex<Vec<String>>,
    /// The matcher for the last read, reused while the PTY's own secrets and the caller's
    /// extra redactions are unchanged; `terminal_read` polls every 50 ms.
    redactor: Mutex<Option<(u64, Arc<Redactor>)>>,
    reader_done: Arc<AtomicBool>,
}

impl TerminalSession {
    fn redactor(&self, extra_redactions: &[String]) -> Result<Arc<Redactor>> {
        let secrets = self.secrets.lock().map_err(lock_error)?;
        let mut hasher = DefaultHasher::new();
        secrets.hash(&mut hasher);
        extra_redactions.hash(&mut hasher);
        let fingerprint = hasher.finish();
        let mut cache = self.redactor.lock().map_err(lock_error)?;
        if let Some((cached, redactor)) = cache.as_ref()
            && *cached == fingerprint
        {
            return Ok(redactor.clone());
        }
        let mut values = secrets.clone();
        values.extend_from_slice(extra_redactions);
        let redactor = Arc::new(Redactor::new(&redaction_candidates(&values)));
        *cache = Some((fingerprint, redactor.clone()));
        Ok(redactor)
    }

    fn close_pty_io(&self) {
        if let Ok(mut master) = self.master.lock() {
            master.take();
        }
        if let Ok(mut writer) = self.writer.lock() {
            writer.take();
        }
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        if let Ok(child) = self.child.get_mut() {
            let _ = child.kill();
        }
        if let Ok(master) = self.master.get_mut() {
            master.take();
        }
        if let Ok(mut writer) = self.writer.lock() {
            writer.take();
        }
    }
}

#[derive(Clone)]
pub struct TerminalManager {
    sessions: Arc<Mutex<HashMap<Uuid, Arc<TerminalSession>>>>,
}

impl Default for TerminalManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TerminalManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[cfg(test)]
    pub fn open(
        &self,
        program: &str,
        args: Vec<String>,
        cwd: Option<String>,
    ) -> Result<TerminalOpenResult> {
        self.open_with_env(program, args, cwd, HashMap::new(), Vec::new())
    }

    pub fn open_with_env(
        &self,
        program: &str,
        args: Vec<String>,
        cwd: Option<String>,
        environment: HashMap<String, String>,
        redacted_values: Vec<String>,
    ) -> Result<TerminalOpenResult> {
        if program.trim().is_empty() {
            bail!("Invalid program name");
        }
        if args.iter().any(|arg| arg.contains('\0')) {
            bail!("Terminal arguments cannot contain null characters");
        }
        for (name, value) in &environment {
            if name.is_empty() || name.contains('=') || name.contains('\0') {
                bail!("Invalid environment variable name");
            }
            if value.contains('\0') {
                bail!("Environment variable value cannot contain null characters");
            }
        }
        let cwd = normalize_cwd(cwd)?;
        let resolved = resolve_executable(program.trim(), cwd.as_deref())?;
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: 30,
                cols: 120,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("Could not create local PTY")?;
        let mut command = CommandBuilder::new(&resolved.executable);
        #[cfg(windows)]
        {
            // portable-pty reloads registry values on Windows, which can replace
            // the caller's project PATH and cache directories with stale values.
            command.env_clear();
            for (name, value) in std::env::vars_os() {
                command.env(name, value);
            }
        }
        command.args(resolved.prefix_args);
        command.args(args);
        // A command typed into a managed shell may carry a substituted secret, so the shell
        // must not save it to the user's history file. bash, zsh, ksh and sh read HISTFILE;
        // fish reads fish_private_mode. An rc file that sets HISTFILE itself still wins.
        // PowerShell has no such variable; terminal_start configures PSReadLine instead.
        #[cfg(not(windows))]
        {
            command.env("HISTFILE", "/dev/null");
            command.env("fish_private_mode", "1");
        }
        for (name, value) in environment {
            command.env(name, value);
        }
        #[cfg(windows)]
        if is_windows_powershell(&resolved.executable) {
            // PowerShell 5.1 builds its own Windows module path when this
            // variable is absent. Inheriting a path from pwsh 7 makes it load
            // incompatible type data and breaks built-in commands.
            command.env_remove("PSModulePath");
        }
        #[cfg(not(windows))]
        command.env("TERM", "xterm-256color");
        if let Some(cwd) = &cwd {
            command.cwd(cwd);
        }
        let child = pair
            .slave
            .spawn_command(command)
            .context("Could not launch program in PTY")?;
        drop(pair.slave);
        let mut reader = pair
            .master
            .try_clone_reader()
            .context("Could not read PTY output")?;
        let writer = Arc::new(Mutex::new(Some(
            pair.master
                .take_writer()
                .context("Could not write to PTY")?,
        )));
        let output = Arc::new(Mutex::new(OutputBuffer::default()));
        let reader_output = output.clone();
        let reader_writer = writer.clone();
        let reader_done = Arc::new(AtomicBool::new(false));
        let reader_done_signal = reader_done.clone();
        std::thread::Builder::new()
            .name("openkeylet-pty-reader".to_owned())
            .spawn(move || {
                let mut buffer = [0_u8; 8_192];
                let mut cursor_query_state = 0;
                loop {
                    match reader.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(count) => {
                            // Windows ConPTY asks the terminal for its cursor position before
                            // presenting the child prompt. The request may be split across reads,
                            // so keep parser state and answer with a stable position instead of
                            // leaving the child blocked.
                            if contains_cursor_position_query(
                                &mut cursor_query_state,
                                &buffer[..count],
                            ) && let Ok(mut writer) = reader_writer.lock()
                                && let Some(writer) = writer.as_mut()
                            {
                                // ConPTY pipes are unbuffered. Flushing their Windows file
                                // handle can wait indefinitely for the child to consume the
                                // response while holding the writer lock.
                                let _ = writer.write_all(b"\x1b[1;1R");
                            }
                            if let Ok(mut output) = reader_output.lock() {
                                output.push(&buffer[..count]);
                            }
                        }
                    }
                }
                reader_done_signal.store(true, Ordering::Release);
            })
            .context("Could not start PTY reading thread")?;

        let session_id = Uuid::new_v4();
        self.sessions.lock().map_err(lock_error)?.insert(
            session_id,
            Arc::new(TerminalSession {
                master: Mutex::new(Some(pair.master)),
                writer,
                child: Mutex::new(child),
                output,
                secrets: Mutex::new(redacted_values),
                redactor: Mutex::new(None),
                reader_done,
            }),
        );
        Ok(TerminalOpenResult {
            session_id,
            executable: resolved.executable,
        })
    }

    pub fn input(&self, session_id: Uuid, text: &str) -> Result<()> {
        self.input_redacted(session_id, text, &[])
    }

    pub fn input_redacted(
        &self,
        session_id: Uuid,
        text: &str,
        redacted_values: &[String],
    ) -> Result<()> {
        if text.contains('\0') {
            bail!("Terminal input cannot contain null characters");
        }
        let session = self.session(session_id)?;
        if !redacted_values.is_empty() {
            let mut secrets = session.secrets.lock().map_err(lock_error)?;
            for value in redacted_values {
                if !secrets.iter().any(|secret| secret == value) {
                    secrets.push(value.clone());
                }
            }
        }
        let mut writer = session.writer.lock().map_err(lock_error)?;
        let writer = writer
            .as_mut()
            .context("Terminal session has already ended")?;
        writer
            .write_all(text.as_bytes())
            .context("Could not write to terminal session")
    }

    pub fn fill_value(&self, session_id: Uuid, value: &str, submit: bool) -> Result<()> {
        if value.contains('\0') {
            bail!("Secret field contains null characters and cannot be written to the terminal");
        }
        let mut text = value.to_owned();
        if submit {
            #[cfg(windows)]
            text.push_str("\r\n");
            #[cfg(not(windows))]
            text.push('\n');
        }
        self.input_redacted(session_id, &text, &[value.to_owned()])
            .context("Could not write credentials to the terminal")
    }

    pub fn is_running(&self, session_id: Uuid) -> Result<bool> {
        let session = self.session(session_id)?;
        let running = session
            .child
            .lock()
            .map_err(lock_error)?
            .try_wait()
            .context("Could not read terminal process status")?
            .is_none();
        if !running {
            session.close_pty_io();
        }
        Ok(running)
    }

    pub fn contains(&self, session_id: Uuid) -> Result<bool> {
        Ok(self
            .sessions
            .lock()
            .map_err(lock_error)?
            .contains_key(&session_id))
    }

    pub fn read(&self, session_id: Uuid) -> Result<TerminalReadResult> {
        self.read_redacting(session_id, &[])
    }

    /// Reads unread output, redacting the values this PTY received plus `extra_redactions`
    /// (raw values, such as the MCP session's redaction set).
    pub fn read_redacting(
        &self,
        session_id: Uuid,
        extra_redactions: &[String],
    ) -> Result<TerminalReadResult> {
        let session = self.session(session_id)?;
        let status = session
            .child
            .lock()
            .map_err(lock_error)?
            .try_wait()
            .context("Could not read terminal process status")?;
        if status.is_some() {
            session.close_pty_io();
        }
        let running = status.is_none() || !session.reader_done.load(Ordering::Acquire);
        let redactor = session.redactor(extra_redactions)?;
        let (output, truncated) = session
            .output
            .lock()
            .map_err(lock_error)?
            .take_redacted(&redactor, running);
        Ok(TerminalReadResult {
            output,
            running,
            exit_code: (!running)
                .then(|| status.as_ref().map(|status| status.exit_code()))
                .flatten(),
            truncated,
        })
    }

    pub fn close(&self, session_id: Uuid) -> Result<()> {
        let session = self
            .sessions
            .lock()
            .map_err(lock_error)?
            .remove(&session_id)
            .context("Terminal session not found")?;
        let mut child = session.child.lock().map_err(lock_error)?;
        if child.try_wait()?.is_none() {
            child
                .kill()
                .context("Could not terminate terminal process")?;
        }
        drop(child);
        session.close_pty_io();
        Ok(())
    }

    fn session(&self, id: Uuid) -> Result<Arc<TerminalSession>> {
        self.sessions
            .lock()
            .map_err(lock_error)?
            .get(&id)
            .cloned()
            .context("Terminal session not found; sessions are valid only in the MCP connection that created them")
    }
}

fn normalize_cwd(cwd: Option<String>) -> Result<Option<PathBuf>> {
    let Some(cwd) = cwd.filter(|value| !value.trim().is_empty()) else {
        return Ok(None);
    };
    let cwd = resolve_user_path(&cwd)?;
    if !cwd.is_dir() {
        bail!("Terminal working directory does not exist or is not a directory");
    }
    Ok(Some(cwd))
}

struct ResolvedExecutable {
    executable: String,
    prefix_args: Vec<String>,
}

fn resolve_executable(program: &str, cwd: Option<&Path>) -> Result<ResolvedExecutable> {
    let path = PathBuf::from(program);
    let has_path = path.is_absolute()
        || path.components().count() > 1
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)));
    let candidate = if has_path {
        if path.is_absolute() {
            path
        } else {
            cwd.unwrap_or_else(|| Path::new(".")).join(path)
        }
    } else {
        find_on_path(program).context("Program to run not found")?
    };
    if !candidate.is_file() {
        bail!("Program to run does not exist");
    }
    let candidate = std::fs::canonicalize(&candidate).unwrap_or(candidate);
    #[cfg(windows)]
    if let Some(extension) = candidate.extension().and_then(|value| value.to_str()) {
        if extension.eq_ignore_ascii_case("cmd") || extension.eq_ignore_ascii_case("bat") {
            let command = find_native_windows_executable("cmd")
                .context("Could not find cmd.exe to run Windows script")?;
            return Ok(ResolvedExecutable {
                executable: windows_argument_path(&command),
                prefix_args: vec![
                    "/d".to_owned(),
                    "/s".to_owned(),
                    "/c".to_owned(),
                    "call".to_owned(),
                    windows_argument_path(&candidate),
                ],
            });
        }
    }
    #[cfg(windows)]
    let executable = windows_argument_path(&candidate);
    #[cfg(not(windows))]
    let executable = candidate.to_string_lossy().into_owned();
    Ok(ResolvedExecutable {
        // `canonicalize` is still used above to resolve and validate the actual
        // file. Windows commonly returns its verbatim `\\?\` form, however,
        // and passing that spelling to a child changes PowerShell 5.1's PSHOME
        // and built-in module paths. Use the equivalent ordinary absolute path
        // for CreateProcess while retaining the canonical path for checks.
        executable,
        prefix_args: Vec::new(),
    })
}

#[cfg(windows)]
fn windows_argument_path(path: &Path) -> String {
    crate::platform::strip_windows_verbatim_prefix(path)
}

#[cfg(windows)]
fn is_windows_powershell(executable: &str) -> bool {
    Path::new(executable)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("powershell.exe"))
}

#[cfg(windows)]
fn find_native_windows_executable(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .flat_map(|directory| {
            [".exe", ".com"]
                .into_iter()
                .map(move |extension| directory.join(format!("{program}{extension}")))
        })
        .find(|candidate| candidate.is_file())
        .and_then(|candidate| std::fs::canonicalize(&candidate).ok().or(Some(candidate)))
}

fn find_on_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let extensions = executable_extensions(program);
    for directory in std::env::split_paths(&path) {
        for extension in &extensions {
            let candidate = directory.join(format!("{program}{extension}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(windows)]
fn executable_extensions(program: &str) -> Vec<String> {
    if Path::new(program).extension().is_some() {
        return vec![String::new()];
    }
    std::env::var_os("PATHEXT")
        .map(|value| {
            value
                .to_string_lossy()
                .split(';')
                .filter(|value| !value.is_empty())
                .map(|value| value.to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_else(|| vec![".exe".into(), ".com".into()])
}

#[cfg(not(windows))]
fn executable_extensions(_program: &str) -> Vec<String> {
    vec![String::new()]
}

fn lock_error<T>(error: std::sync::PoisonError<T>) -> anyhow::Error {
    anyhow::anyhow!("Terminal session lock is corrupted:{error}")
}

fn contains_cursor_position_query(state: &mut usize, bytes: &[u8]) -> bool {
    const QUERY: &[u8] = b"\x1b[6n";
    let mut found = false;
    for byte in bytes {
        if *byte == QUERY[*state] {
            *state += 1;
            if *state == QUERY.len() {
                found = true;
                *state = 0;
            }
        } else {
            *state = usize::from(*byte == QUERY[0]);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn redactor_for(values: &[&str]) -> Redactor {
        Redactor::new(&redaction_candidates(
            &values.iter().map(|value| (*value).to_owned()).collect::<Vec<_>>(),
        ))
    }

    #[test]
    fn output_buffer_keeps_all_unread_output() {
        let mut large = OutputBuffer::default();
        large.push(&vec![b'B'; 2 * 1_048_576]);
        let (output, truncated) = large.take_redacted(&redactor_for(&[]), false);
        assert_eq!(output.len(), 2 * 1_048_576);
        assert!(!truncated);
    }

    #[test]
    fn output_buffer_caps_runaway_output_and_sets_truncated() {
        let mut buffer = OutputBuffer::default();
        buffer.push(&vec![b'A'; MAX_UNREAD_BUFFER_BYTES]);
        buffer.push(b"TAIL_MARKER");
        let (output, truncated) = buffer.take_redacted(&redactor_for(&[]), false);
        assert!(truncated);
        assert_eq!(output.len(), MAX_UNREAD_BUFFER_BYTES);
        assert!(output.ends_with("TAIL_MARKER"));

        buffer.push(b"fresh");
        let (next, next_truncated) = buffer.take_redacted(&redactor_for(&[]), false);
        assert_eq!(next, "fresh");
        assert!(!next_truncated);
    }

    #[test]
    fn echoed_secrets_are_redacted_through_wraps_line_endings_and_escape_sequences() {
        let secret = "wrap-secret-0123456789";
        let redactor = redactor_for(&[secret, "line-one-material\nline-two-material"]);
        for echoed in [
            // A line editor wrapping at the right margin.
            "$ echo wrap-secret-01234 \r56789\r\n".to_owned(),
            "$ echo wrap-secret-01234\r\n56789\r\n".to_owned(),
            // Syntax highlighting and cursor movement inside the echo.
            "$ echo \x1b[32mwrap-\x1b[0msecret-\x1b[1;34m0123\x1b[K456789\r\n".to_owned(),
            // An OSC title update in the middle of the value.
            "$ echo wrap-secret\x1b]0;title\x07-0123456789\r\n".to_owned(),
            // A multi-line secret printed with CRLF line endings.
            "$ cat key\r\nline-one-material\r\nline-two-material\r\n".to_owned(),
        ] {
            let mut buffer = OutputBuffer::default();
            buffer.push(echoed.as_bytes());
            let (output, _) = buffer.take_redacted(&redactor, false);
            assert!(output.contains("[REDACTED]"), "{echoed:?} -> {output:?}");
            for fragment in ["wrap-secret", "56789", "line-one", "line-two", "\x1b[1;34m"] {
                assert!(!output.contains(fragment), "{echoed:?} -> {output:?}");
            }
            assert!(output.starts_with("$ "), "{output:?}");
        }
    }

    #[test]
    fn noisy_secret_split_across_reads_is_held_until_complete() {
        let redactor = redactor_for(&["split-secret-0123456789"]);
        let mut buffer = OutputBuffer::default();
        buffer.push(b"prompt split-secret-01\x1b[");
        let (first, _) = buffer.take_redacted(&redactor, true);
        assert_eq!(first, "prompt ");
        buffer.push(b"K23 \r456789 done\r\n");
        let (second, _) = buffer.take_redacted(&redactor, true);
        assert_eq!(second, "[REDACTED] done\r\n");
    }

    #[test]
    fn possible_secret_prefix_is_released_after_the_program_pauses() {
        let redactor = redactor_for(&["Enter-secret-0123456789"]);
        let mut buffer = OutputBuffer::default();
        buffer.push(b"Enter");
        let (held, _) = buffer.take_redacted(&redactor, true);
        assert_eq!(held, "");
        buffer.last_push = Some(Instant::now() - INCOMPLETE_SECRET_HOLD * 2);
        let (released, _) = buffer.take_redacted(&redactor, true);
        assert_eq!(released, "Enter");
    }

    #[test]
    fn utf8_character_split_by_a_read_is_not_mangled() {
        let mut buffer = OutputBuffer::default();
        let text = "ok ✓";
        let bytes = text.as_bytes();
        buffer.push(&bytes[..bytes.len() - 1]);
        let (first, _) = buffer.take_redacted(&redactor_for(&[]), true);
        assert_eq!(first, "ok ");
        buffer.push(&bytes[bytes.len() - 1..]);
        let (second, _) = buffer.take_redacted(&redactor_for(&[]), true);
        assert_eq!(second, "✓");
    }

    #[test]
    fn extra_redactions_apply_to_terminal_reads() {
        let manager = TerminalManager::new();
        let marker = "session-wide-pty-secret-5531";
        let (program, args) = output_command(marker);
        let session = manager.open(&program, args, None).unwrap();
        let mut output = String::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let read = manager
                .read_redacting(session.session_id, &[marker.to_owned()])
                .unwrap();
            output.push_str(&read.output);
            if !read.running {
                break;
            }
            assert!(Instant::now() < deadline, "PTY did not exit: {output:?}");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(output.contains("[REDACTED]"), "{output:?}");
        assert!(!output.contains(marker));
        manager.close(session.session_id).unwrap();
    }

    #[cfg(not(windows))]
    #[test]
    fn managed_terminals_disable_shell_history_files() {
        let manager = TerminalManager::new();
        let session = manager
            .open(
                "sh",
                vec!["-c".into(), "printf '%s|%s' \"$HISTFILE\" \"$fish_private_mode\"".into()],
                None,
            )
            .unwrap();
        let mut output = String::new();
        read_until(
            &manager,
            session.session_id,
            &mut output,
            Duration::from_secs(2),
            |_, result| !result.running,
        );
        // Closing the PTY writer sends a newline and EOF, which the line discipline may
        // echo if the child has not quite exited yet.
        assert_eq!(output.trim_end_matches(['\r', '\n']), "/dev/null|1");
        manager.close(session.session_id).unwrap();
    }

    #[test]
    fn cursor_position_query_is_detected_across_read_boundaries() {
        for split in 0..=4 {
            let mut state = 0;
            let query = b"\x1b[6n";
            assert_eq!(
                contains_cursor_position_query(&mut state, &query[..split]),
                split == query.len()
            );
            if split < query.len() {
                assert!(contains_cursor_position_query(&mut state, &query[split..]));
            }
        }
    }

    fn read_until(
        manager: &TerminalManager,
        session_id: Uuid,
        output: &mut String,
        timeout: Duration,
        ready: impl Fn(&str, &TerminalReadResult) -> bool,
    ) -> TerminalReadResult {
        let deadline = Instant::now() + timeout;
        loop {
            let result = manager.read(session_id).unwrap();
            output.push_str(&result.output);
            if ready(output, &result) {
                return result;
            }
            assert!(
                Instant::now() < deadline,
                "PTY readiness timed out: {output:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_exit_with_unread_output(
        manager: &TerminalManager,
        session_id: Uuid,
        timeout: Duration,
    ) {
        let session = manager.session(session_id).unwrap();
        let deadline = Instant::now() + timeout;
        loop {
            let exited = session.child.lock().unwrap().try_wait().unwrap().is_some();
            if exited {
                session.close_pty_io();
            }
            let has_output = !session.output.lock().unwrap().bytes.is_empty();
            if exited && has_output && session.reader_done.load(Ordering::Acquire) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "PTY did not exit with buffered output before timeout"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn output_command(marker: &str) -> (String, Vec<String>) {
        #[cfg(windows)]
        {
            (
                "cmd.exe".to_owned(),
                vec![
                    "/d".into(),
                    "/q".into(),
                    "/c".into(),
                    format!("echo {marker}"),
                ],
            )
        }
        #[cfg(not(windows))]
        {
            (
                "sh".to_owned(),
                vec!["-c".into(), format!("printf '%s' '{marker}'")],
            )
        }
    }

    fn silent_command() -> (String, Vec<String>) {
        #[cfg(windows)]
        {
            (
                "cmd.exe".to_owned(),
                vec!["/d".into(), "/q".into(), "/c".into(), "exit 0".into()],
            )
        }
        #[cfg(not(windows))]
        {
            ("sh".to_owned(), vec!["-c".into(), ":".into()])
        }
    }

    #[test]
    fn output_redaction_holds_a_secret_split_across_reads() {
        let redactor = redactor_for(&["top-secret"]);
        let mut output = OutputBuffer::default();
        output.push(b"prompt top-");
        let (first, _) = output.take_redacted(&redactor, true);
        assert_eq!(first, "prompt ");

        output.push(b"secret accepted\r\n");
        let (second, _) = output.take_redacted(&redactor, true);
        assert_eq!(second, "[REDACTED] accepted\r\n");
    }

    #[test]
    fn opening_below_capacity_preserves_a_finished_drained_session() {
        let manager = TerminalManager::new();
        let marker = "OpenKeylet-STALE-SESSION";
        let (program, args) = output_command(marker);
        let stale = manager.open(&program, args, None).unwrap();
        let mut output = String::new();
        read_until(
            &manager,
            stale.session_id,
            &mut output,
            Duration::from_secs(2),
            |output, result| !result.running && output.contains(marker),
        );
        // Drain any final bytes that ConPTY publishes just after process exit.
        std::thread::sleep(Duration::from_millis(30));
        let final_read = manager.read(stale.session_id).unwrap();
        assert!(!final_read.running);

        let (program, args) = silent_command();
        let replacement = manager.open(&program, args, None).unwrap();
        assert!(manager.session(stale.session_id).is_ok());
        manager.close(stale.session_id).unwrap();
        manager.close(replacement.session_id).unwrap();
    }

    #[test]
    fn opening_a_terminal_preserves_a_finished_session_with_unread_output() {
        let manager = TerminalManager::new();
        let marker = "OpenKeylet-UNREAD-SESSION";
        let (program, args) = output_command(marker);
        let unread = manager.open(&program, args, None).unwrap();
        wait_for_exit_with_unread_output(&manager, unread.session_id, Duration::from_secs(2));

        let (program, args) = silent_command();
        let replacement = manager.open(&program, args, None).unwrap();
        let result = manager.read(unread.session_id).unwrap();
        assert!(!result.running);
        assert!(
            result.output.contains(marker),
            "unexpected output: {result:?}"
        );

        manager.close(unread.session_id).unwrap();
        manager.close(replacement.session_id).unwrap();
    }

    #[test]
    fn more_than_eight_terminal_sessions_can_coexist() {
        let manager = TerminalManager::new();
        let mut sessions = Vec::new();
        for _ in 0..10 {
            let (program, args) = silent_command();
            let session = manager.open(&program, args, None).unwrap();
            sessions.push(session.session_id);
        }
        assert_eq!(manager.sessions.lock().unwrap().len(), 10);
        for id in sessions {
            manager.close(id).unwrap();
        }
    }

    #[test]
    fn terminal_fill_writes_no_newline_and_redacts_echoed_secret() {
        let manager = TerminalManager::new();
        #[cfg(windows)]
        let (program, args) = (
            "cmd.exe".to_owned(),
            vec![
                "/d".into(),
                "/q".into(),
                "/v:on".into(),
                "/c".into(),
                "set /p VAULT_INPUT=PASSWORD READY: & echo received=!VAULT_INPUT!".into(),
            ],
        );
        #[cfg(not(windows))]
        let (program, args) = (
            "sh".to_owned(),
            vec![
                "-c".into(),
                "printf 'PASSWORD READY: '; read VAULT_INPUT; printf 'received=%s\\n' \"$VAULT_INPUT\""
                    .into(),
            ],
        );
        let session = manager.open(&program, args, None).unwrap();
        let mut combined = String::new();
        let initial = read_until(
            &manager,
            session.session_id,
            &mut combined,
            Duration::from_secs(2),
            |output, _| output.contains("PASSWORD READY"),
        );
        assert!(initial.running);
        manager
            .fill_value(session.session_id, "pty-secret-marker-64928", false)
            .unwrap();
        let after_fill = manager.read(session.session_id).unwrap();
        combined.push_str(&after_fill.output);
        assert!(
            after_fill.running,
            "credential_fill must not submit the prompt"
        );
        manager
            .input(
                session.session_id,
                if cfg!(windows) { "\r\n" } else { "\n" },
            )
            .unwrap();
        read_until(
            &manager,
            session.session_id,
            &mut combined,
            Duration::from_secs(2),
            |output, result| !result.running && output.contains("received=[REDACTED]"),
        );
        assert!(
            combined.contains("PASSWORD READY"),
            "PTY output did not contain the prompt: {combined:?}"
        );
        assert!(
            combined.contains("received=[REDACTED]"),
            "PTY output did not contain the redacted echo: {combined:?}"
        );
        assert!(!combined.contains("pty-secret-marker-64928"));
        manager.close(session.session_id).unwrap();
    }

    #[test]
    fn terminal_fill_can_submit_and_redact_in_one_call() {
        let manager = TerminalManager::new();
        #[cfg(windows)]
        let (program, args) = (
            "cmd.exe".to_owned(),
            vec![
                "/d".into(),
                "/q".into(),
                "/v:on".into(),
                "/c".into(),
                "set /p VAULT_INPUT=PASSWORD READY: & echo received=!VAULT_INPUT!".into(),
            ],
        );
        #[cfg(not(windows))]
        let (program, args) = (
            "sh".to_owned(),
            vec![
                "-c".into(),
                "printf 'PASSWORD READY: '; read VAULT_INPUT; printf 'received=%s\\n' \"$VAULT_INPUT\""
                    .into(),
            ],
        );
        let session = manager.open(&program, args, None).unwrap();
        let mut output = String::new();
        read_until(
            &manager,
            session.session_id,
            &mut output,
            Duration::from_secs(2),
            |output, _| output.contains("PASSWORD READY"),
        );
        manager
            .fill_value(session.session_id, "one-call-secret-7319", true)
            .unwrap();
        read_until(
            &manager,
            session.session_id,
            &mut output,
            Duration::from_secs(2),
            |output, result| !result.running && output.contains("received=[REDACTED]"),
        );
        assert!(output.contains("received=[REDACTED]"));
        assert!(!output.contains("one-call-secret-7319"));
        manager.close(session.session_id).unwrap();
    }

    #[cfg(not(windows))]
    #[test]
    fn terminal_sets_a_useful_term() {
        let manager = TerminalManager::new();
        let session = manager
            .open(
                "sh",
                vec!["-c".into(), "printf '%s' \"$TERM\"".into()],
                None,
            )
            .unwrap();
        let mut output = String::new();
        read_until(
            &manager,
            session.session_id,
            &mut output,
            Duration::from_secs(2),
            |_, result| !result.running,
        );
        assert_eq!(output.trim(), "xterm-256color");
        manager.close(session.session_id).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn standard_npm_cmd_shim_runs_through_the_native_command_processor() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let target = root.join("node_modules").join("demo-cli").join("cli.js");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, "console.log(process.argv.slice(2).join('|'))").unwrap();
        let shim = root.join("demo.cmd");
        std::fs::write(
            &shim,
            r#"@ECHO off
node "%~dp0node_modules\demo-cli\cli.js" %*"#,
        )
        .unwrap();

        let manager = TerminalManager::new();
        let session = manager
            .open(
                shim.to_str().unwrap(),
                vec!["literal with spaces".into(), "plain-arg".into()],
                None,
            )
            .unwrap();
        assert!(session.executable.ends_with("cmd.exe"));
        let mut output = String::new();
        read_until(
            &manager,
            session.session_id,
            &mut output,
            Duration::from_secs(15),
            |output, result| !result.running && output.contains("literal with spaces|plain-arg"),
        );
        manager.close(session.session_id).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn powershell_7_starts_with_the_inherited_terminal_environment() {
        let manager = TerminalManager::new();
        let session = manager
            .open(
                "pwsh.exe",
                vec![
                    "-NoLogo".into(),
                    "-NoProfile".into(),
                    "-NonInteractive".into(),
                    "-Command".into(),
                    "[Console]::Write('OpenKeylet-POWERSHELL-OK')".into(),
                ],
                None,
            )
            .unwrap();
        let mut output = String::new();
        read_until(
            &manager,
            session.session_id,
            &mut output,
            Duration::from_secs(5),
            |output, result| !result.running && output.contains("OpenKeylet-POWERSHELL-OK"),
        );
        assert!(
            !output.contains("Could not start this shell"),
            "unexpected output: {output}"
        );
        manager.close(session.session_id).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_powershell_5_starts_with_the_inherited_terminal_environment() {
        let powershell = PathBuf::from(std::env::var_os("SYSTEMROOT").unwrap())
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        assert!(powershell.is_file(), "Windows PowerShell 5.1 is missing");

        let manager = TerminalManager::new();
        let session = manager
            .open(
                powershell.to_str().unwrap(),
                vec![
                    "-NoLogo".into(),
                    "-NoProfile".into(),
                    "-NonInteractive".into(),
                    "-Command".into(),
                    "$ErrorActionPreference='Stop'; try { Import-Module Microsoft.PowerShell.Security -Force; Get-ExecutionPolicy | Out-Null; [void][Net.ServicePointManager]::SecurityProtocol; [Console]::Write('OpenKeylet-WINDOWS-POWERSHELL-OK') } catch { [Console]::Write($_.Exception.ToString()) }; exit".into(),
                ],
                None,
            )
            .unwrap();
        assert!(
            !session.executable.starts_with(r"\\?\"),
            "verbatim executable path leaks into PowerShell: {}",
            session.executable
        );
        let mut output = String::new();
        read_until(
            &manager,
            session.session_id,
            &mut output,
            Duration::from_secs(10),
            |_, result| !result.running,
        );
        assert!(
            output.contains("OpenKeylet-WINDOWS-POWERSHELL-OK"),
            "Windows PowerShell did not complete its startup checks: {output}"
        );
        assert!(
            !output.contains("ServicePointManager") && !output.contains("Get-ExecutionPolicy"),
            "unexpected Windows PowerShell startup error: {output}"
        );
        manager.close(session.session_id).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_batch_scripts_run_through_the_native_command_processor() {
        let temp = tempfile::tempdir().unwrap();
        for extension in ["bat", "cmd"] {
            let script = temp.path().join(format!("fixture.{extension}"));
            std::fs::write(&script, "@echo off\r\necho OpenKeylet-BATCH-OK").unwrap();
            let resolved = resolve_executable(script.to_str().unwrap(), None).unwrap();
            assert!(
                Path::new(&resolved.executable)
                    .file_name()
                    .is_some_and(|name| name.eq_ignore_ascii_case("cmd.exe"))
            );
            assert_eq!(resolved.prefix_args[0..4], ["/d", "/s", "/c", "call"]);
            let canonical_script = std::fs::canonicalize(&script).unwrap();
            assert_eq!(
                resolved.prefix_args[4],
                windows_argument_path(&canonical_script)
            );
        }
    }
}
