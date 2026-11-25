//! Hidden terminal secret prompting and passphrase acquisition for CLI workflows.

use anyhow::{Context, Result};
use std::{
    env,
    io::{BufRead, IsTerminal, Write},
};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PassphraseSource {
    None,
    Prompt,
    Env(String),
    Stdin,
}

pub fn read_secret_line_hidden(prompt: &str) -> Result<Zeroizing<String>> {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();

    #[cfg(windows)]
    let _echo_guard = {
        if std::io::stdin().is_terminal() {
            windows_echo::disable_console_echo()
        } else {
            None
        }
    };
    #[cfg(unix)]
    let _echo_guard = {
        if std::io::stdin().is_terminal() {
            unix_echo::disable_tty_echo()
        } else {
            None
        }
    };

    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("Unable to read passphrase from stdin")?;
    if std::io::stdin().is_terminal() {
        eprintln!();
    }
    let trimmed = line.trim_end_matches(&['\r', '\n'][..]).to_owned();
    Ok(Zeroizing::new(trimmed))
}

pub fn obtain_passphrase(source: &PassphraseSource, confirm: bool) -> Result<Zeroizing<String>> {
    match source {
        PassphraseSource::Env(var_name) => {
            let val = env::var(var_name)
                .with_context(|| format!("Environment variable '{var_name}' is not set"))?;
            Ok(Zeroizing::new(val))
        }
        PassphraseSource::Stdin => {
            let mut line = String::new();
            std::io::stdin()
                .lock()
                .read_line(&mut line)
                .context("Unable to read passphrase from stdin")?;
            Ok(Zeroizing::new(
                line.trim_end_matches(&['\r', '\n'][..]).to_owned(),
            ))
        }
        PassphraseSource::Prompt => {
            let first = read_secret_line_hidden("Enter backup passphrase (min 12 chars): ")?;
            if confirm {
                let second = read_secret_line_hidden("Confirm backup passphrase: ")?;
                if *first != *second {
                    anyhow::bail!("Backup passphrases do not match");
                }
            }
            Ok(first)
        }
        PassphraseSource::None => {
            anyhow::bail!(
                "This .mvault backup is passphrase-protected. Pass --passphrase, --passphrase-env <VAR>, or --passphrase-stdin."
            )
        }
    }
}

#[cfg(windows)]
mod windows_echo {
    const STD_INPUT_HANDLE: u32 = (-10_i32) as u32;
    const ENABLE_ECHO_INPUT: u32 = 0x0004;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetStdHandle(n_std_handle: u32) -> isize;
        fn GetConsoleMode(h_console_handle: isize, lp_mode: *mut u32) -> i32;
        fn SetConsoleMode(h_console_handle: isize, dw_mode: u32) -> i32;
    }

    pub struct EchoGuard {
        handle: isize,
        original_mode: u32,
    }

    impl Drop for EchoGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = SetConsoleMode(self.handle, self.original_mode);
            }
        }
    }

    pub fn disable_console_echo() -> Option<EchoGuard> {
        unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE);
            if handle == 0 || handle == -1 {
                return None;
            }
            let mut mode: u32 = 0;
            if GetConsoleMode(handle, &mut mode) == 0 {
                return None;
            }
            if SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT) == 0 {
                return None;
            }
            Some(EchoGuard {
                handle,
                original_mode: mode,
            })
        }
    }
}

#[cfg(unix)]
mod unix_echo {
    use std::process::Command;

    pub struct EchoGuard;

    impl Drop for EchoGuard {
        fn drop(&mut self) {
            let _ = Command::new("stty").arg("echo").status();
        }
    }

    pub fn disable_tty_echo() -> Option<EchoGuard> {
        if Command::new("stty")
            .arg("-echo")
            .status()
            .is_ok_and(|s| s.success())
        {
            Some(EchoGuard)
        } else {
            None
        }
    }
}
