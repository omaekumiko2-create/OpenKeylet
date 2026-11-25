//! Structured `clap`-powered CLI entrypoint for OpenKeylet (GUI, MCP stdio,
//! zero-plaintext `run`, `ssh-agent`, `git-credential`, headless admin, and vault ops).

mod ops_cmd;
mod prompt;
pub mod run;
mod ssh_cmd;
mod vault_cmd;

use crate::{git_credential, mcp, ssh_agent, storage::app_data_dir, vault::Vault};
use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::net::IpAddr;

#[derive(Debug, Parser)]
#[command(
    name = "openkeylet",
    version,
    about = "Local-first encrypted password vault and zero-plaintext credential relay for AI agents"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Launch the desktop GUI application (default when invoked with no subcommand).
    Gui,
    /// Run the local MCP server (`openkeylet mcp stdio`).
    Mcp {
        #[command(subcommand)]
        transport: McpTransport,
    },
    /// Execute a command with locally injected vault secrets and output redaction.
    Run {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Run the local read-only OpenSSH Agent backed by the vault.
    #[command(name = "ssh-agent")]
    SshAgent {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Inspect or reset SSH host keys pinned on first use (`hosts`, `forget-host`).
    Ssh {
        #[command(subcommand)]
        action: SshCommand,
    },
    /// Git HTTPS credential helper (`get`, `store`, `erase`).
    #[command(name = "git-credential")]
    GitCredential {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Print ready-to-paste MCP client configuration (`stdio-json` or `stdio-toml`).
    Config { format: String },
    /// Manage the Browser Bridge (`status`, `enable`, `disable`, `pair`, `reset`).
    Browser {
        #[command(subcommand)]
        action: BrowserCommand,
    },
    /// Export or import `.mvault` encrypted backups.
    Backup(BackupArgs),
    /// Headless vault inspection and management.
    Vault {
        #[command(subcommand)]
        action: VaultCommand,
    },
    /// Start the headless local web admin server.
    Admin {
        #[command(subcommand)]
        action: AdminCommand,
    },
    /// Check for or install signed GitHub Releases updates.
    Update {
        #[command(subcommand)]
        action: UpdateCommand,
    },
    /// Smart-ingest a credential from stdin or `--file`.
    Add(AddArgs),
    /// Import a `.env` file into the vault and optionally write a sealed template.
    #[command(name = "import-env")]
    ImportEnv(ImportEnvArgs),
    /// Import hosts from `~/.ssh/config` or an explicit SSH config path.
    #[command(name = "import-ssh")]
    ImportSsh { config_file: Option<String> },
    /// Generate an Ed25519 SSH keypair directly inside the encrypted vault.
    #[command(disable_help_flag = true)]
    Keygen(KeygenArgs),
    /// Migrate legacy macOS Keychain master key to the app-private key file.
    #[cfg(target_os = "macos")]
    Key {
        #[command(subcommand)]
        action: KeyCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum McpTransport {
    Stdio,
}

#[derive(Debug, Subcommand)]
pub enum BrowserCommand {
    Status,
    Enable { port: Option<u16> },
    Disable,
    Pair { port: Option<u16> },
    Reset,
}

#[derive(Debug, Subcommand)]
pub enum SshCommand {
    /// List the SSH host keys pinned on first use on this device.
    Hosts,
    /// Remove pinned SSH host keys so the next connection pins the key the server presents.
    #[command(name = "forget-host")]
    ForgetHost {
        host: String,
        /// Only forget this port (default: every port of the host).
        #[arg(short = 'p', long)]
        port: Option<u16>,
        #[arg(long = "pin-env")]
        pin_env: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BackupAction {
    Export,
    Import,
}

#[derive(Debug, Args)]
pub struct BackupArgs {
    pub action: BackupAction,
    pub file: String,
    #[arg(short = 'p', long = "passphrase")]
    pub passphrase: bool,
    #[arg(long = "passphrase-stdin")]
    pub passphrase_stdin: bool,
    #[arg(long = "passphrase-env")]
    pub passphrase_env: Option<String>,
    /// Export a `.mvault` that carries its own unlock key: anyone who gets a copy of the
    /// file can read every secret in it. Without this flag, export asks for a passphrase.
    #[arg(
        long = "self-unlocking",
        conflicts_with_all = ["passphrase", "passphrase_stdin", "passphrase_env"]
    )]
    pub self_unlocking: bool,
}

impl BackupArgs {
    pub fn passphrase_source(&self) -> prompt::PassphraseSource {
        if let Some(var) = &self.passphrase_env {
            prompt::PassphraseSource::Env(var.clone())
        } else if self.passphrase_stdin {
            prompt::PassphraseSource::Stdin
        } else if self.passphrase {
            prompt::PassphraseSource::Prompt
        } else {
            prompt::PassphraseSource::None
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum VaultCommand {
    Status,
    List {
        #[arg(long)]
        all: bool,
    },
    Show { item: String },
    Enable { item: String },
    Disable { item: String },
    Trash { item: String },
    Restore { item: String },
    Pin {
        #[command(subcommand)]
        action: VaultPinCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum VaultPinCommand {
    Status,
    Set {
        #[arg(long = "pin-env")]
        pin_env: Option<String>,
    },
    /// Clear the local Owner PIN for forgot-PIN recovery (requires interactive confirmation or --force).
    Clear {
        /// Skip interactive confirmation (for local recovery scripts).
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum AdminCommand {
    Serve {
        #[arg(short = 'p', long)]
        port: Option<u16>,
        #[arg(long)]
        bind: Option<IpAddr>,
        #[arg(long = "allow-non-loopback")]
        allow_non_loopback: bool,
        #[arg(long = "token-env")]
        token_env: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum UpdateCommand {
    Check,
    Install,
}

#[derive(Debug, Args)]
pub struct AddArgs {
    #[arg(short = 'n', long)]
    pub name: Option<String>,
    #[arg(short = 'f', long)]
    pub folder: Option<String>,
    #[arg(long)]
    pub file: Option<String>,
    #[arg(long)]
    pub stdin: bool,
}

#[derive(Debug, Args)]
pub struct ImportEnvArgs {
    pub file: String,
    #[arg(short = 'n', long)]
    pub name: Option<String>,
    #[arg(short = 'f', long)]
    pub folder: Option<String>,
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    pub seal: Option<Option<String>>,
}

#[derive(Debug, Args)]
pub struct KeygenArgs {
    pub name: String,
    #[arg(short = 'h', long, default_value = "")]
    pub host: String,
    #[arg(short = 'p', long, default_value_t = 22)]
    pub port: u16,
    #[arg(short = 'u', long, default_value = "")]
    pub user: String,
    #[arg(short = 'C', long, default_value = "")]
    pub comment: String,
    #[arg(short = 'f', long, default_value = "SSH")]
    pub folder: String,
    #[arg(long = "help", action = clap::ArgAction::Help)]
    _help: Option<bool>,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Subcommand)]
pub enum KeyCommand {
    Migrate,
}

pub(crate) fn validate_nonzero_port(port: u16) -> Result<u16> {
    if port == 0 {
        anyhow::bail!("Port must be between 1 and 65535");
    }
    Ok(port)
}

pub async fn run() -> Result<i32> {
    let cli = Cli::parse();
    dispatch(cli).await
}

pub async fn dispatch(cli: Cli) -> Result<i32> {
    match cli.command {
        None | Some(Command::Gui) => {
            #[cfg(feature = "gui")]
            {
                crate::run_gui()?;
                Ok(0)
            }
            #[cfg(not(feature = "gui"))]
            anyhow::bail!(
                "This is the headless version of OpenKeylet; use the mcp stdio, run, ssh-agent, git-credential, config, vault, admin, browser, or backup subcommand"
            )
        }
        #[cfg(target_os = "macos")]
        Some(Command::Key {
            action: KeyCommand::Migrate,
        }) => {
            let data_dir = app_data_dir()?;
            if crate::crypto::MasterKey::migrate_legacy_macos_key(&data_dir)? {
                Vault::open(data_dir)?;
                println!(
                    "The legacy keychain master key has been migrated; future OpenKeylet launches will no longer request keychain permission"
                );
            } else {
                println!("The app-private master key file already exists; no migration is needed");
            }
            Ok(0)
        }
        Some(Command::Ssh { action }) => {
            ssh_cmd::run_ssh(app_data_dir()?, action)?;
            Ok(0)
        }
        Some(cmd) => {
            let vault = Vault::open(app_data_dir()?)?;
            match cmd {
                Command::Run { args } => run::run_cli(&vault, &args).await,
                Command::SshAgent { args } => {
                    ssh_agent::run_cli(&vault, &args).await?;
                    Ok(0)
                }
                Command::GitCredential { args } => {
                    git_credential::run_cli(&vault, &args)?;
                    Ok(0)
                }
                Command::Mcp {
                    transport: McpTransport::Stdio,
                } => {
                    mcp::serve_stdio(vault).await?;
                    Ok(0)
                }
                Command::Config { format } => {
                    println!("{}", mcp::render_config(&format)?);
                    Ok(0)
                }
                Command::Browser { action } => {
                    ops_cmd::run_browser(&vault, action).await?;
                    Ok(0)
                }
                Command::Backup(args) => {
                    ops_cmd::run_backup(&vault, args)?;
                    Ok(0)
                }
                Command::Vault { action } => {
                    vault_cmd::run_vault(&vault, action)?;
                    Ok(0)
                }
                Command::Admin { action } => {
                    ops_cmd::run_admin(vault, action).await?;
                    Ok(0)
                }
                Command::Update { action } => {
                    ops_cmd::run_update(&vault, action).await?;
                    Ok(0)
                }
                Command::Add(args) => {
                    vault_cmd::run_add(&vault, args)?;
                    Ok(0)
                }
                Command::ImportEnv(args) => {
                    vault_cmd::run_import_env(&vault, args)?;
                    Ok(0)
                }
                Command::ImportSsh { config_file } => {
                    vault_cmd::run_import_ssh(&vault, config_file)?;
                    Ok(0)
                }
                Command::Keygen(args) => {
                    vault_cmd::run_keygen(&vault, args)?;
                    Ok(0)
                }
                Command::Gui | Command::Ssh { .. } => unreachable!(),
                #[cfg(target_os = "macos")]
                Command::Key { .. } => unreachable!(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ConnectionInput, ItemModule, SecretBundle};
    use tempfile::tempdir;

    #[test]
    fn cli_backup_parse_supports_passphrase_flags() {
        let parsed = Cli::try_parse_from([
            "openkeylet",
            "backup",
            "export",
            "protected.mvault",
            "--passphrase",
        ])
        .unwrap();
        let Some(Command::Backup(args)) = parsed.command else {
            panic!("expected backup command");
        };
        assert_eq!(args.action, BackupAction::Export);
        assert_eq!(args.file, "protected.mvault");
        assert_eq!(args.passphrase_source(), prompt::PassphraseSource::Prompt);

        let env_parsed = Cli::try_parse_from([
            "openkeylet",
            "backup",
            "import",
            "protected.mvault",
            "--passphrase-env",
            "TEST_BACKUP_PW",
        ])
        .unwrap();
        let Some(Command::Backup(env_args)) = env_parsed.command else {
            panic!("expected backup command");
        };
        assert_eq!(env_args.action, BackupAction::Import);
        assert_eq!(env_args.file, "protected.mvault");
        assert_eq!(
            env_args.passphrase_source(),
            prompt::PassphraseSource::Env("TEST_BACKUP_PW".to_owned())
        );
    }

    fn parse_backup(argv: &[&str]) -> BackupArgs {
        let parsed = Cli::try_parse_from(argv).unwrap();
        let Some(Command::Backup(args)) = parsed.command else {
            panic!("expected backup command");
        };
        args
    }

    #[test]
    fn cli_backup_export_requires_a_passphrase_unless_self_unlocking_is_explicit() {
        use ops_cmd::{ExportProtection, export_protection};

        let plain = parse_backup(&["openkeylet", "backup", "export", "vault.mvault"]);
        assert!(!plain.self_unlocking);
        assert_eq!(
            export_protection(&plain, true).unwrap(),
            ExportProtection::Passphrase(prompt::PassphraseSource::Prompt)
        );
        let error = export_protection(&plain, false).unwrap_err().to_string();
        assert!(error.contains("--passphrase-env"), "{error}");
        assert!(error.contains("--self-unlocking"), "{error}");

        let self_unlocking = parse_backup(&[
            "openkeylet",
            "backup",
            "export",
            "local.mvault",
            "--self-unlocking",
        ]);
        assert_eq!(
            export_protection(&self_unlocking, false).unwrap(),
            ExportProtection::SelfUnlocking
        );

        let from_env = parse_backup(&[
            "openkeylet",
            "backup",
            "export",
            "vault.mvault",
            "--passphrase-env",
            "TEST_BACKUP_PW",
        ]);
        assert_eq!(
            export_protection(&from_env, false).unwrap(),
            ExportProtection::Passphrase(prompt::PassphraseSource::Env("TEST_BACKUP_PW".to_owned()))
        );

        assert!(
            Cli::try_parse_from([
                "openkeylet",
                "backup",
                "export",
                "vault.mvault",
                "--self-unlocking",
                "--passphrase",
            ])
            .is_err(),
            "a self-unlocking file cannot also be passphrase-protected"
        );
    }

    #[test]
    fn cli_import_env_writes_a_resolvable_template_and_leaves_the_source_alone() {
        let dir = tempdir().unwrap();
        let vault = Vault::open(dir.path().join("vault")).unwrap();
        let env_path = dir.path().join(".env");
        let original = "OPENAI_API_KEY=sk-proj-cliImportKey1234567890abcd\ndb_password=CliLowerSecret!1\nTOKEN=cliTokenValue123456\n# OLD=cliCommentedSecret999\n";
        std::fs::write(&env_path, original).unwrap();
        let args = |seal: Option<Option<String>>| ImportEnvArgs {
            file: env_path.display().to_string(),
            name: None,
            folder: None,
            seal,
        };

        // Writing the template over its source would destroy the values it removed.
        let error = vault_cmd::run_import_env(&vault, args(Some(Some(env_path.display().to_string()))))
            .unwrap_err()
            .to_string();
        assert!(error.contains("Refusing to overwrite"), "{error}");
        assert!(vault.list_connections().unwrap().is_empty());

        vault_cmd::run_import_env(&vault, args(Some(None))).unwrap();
        assert_eq!(std::fs::read_to_string(&env_path).unwrap(), original);
        let template = std::fs::read_to_string(dir.path().join(".env.template")).unwrap();
        assert!(template.contains("OPENAI_API_KEY={{openkeylet:OPENAI_API_KEY}}\n"));
        assert!(template.contains("db_password={{openkeylet:db_password}}\n"));
        assert!(template.contains("TOKEN={{openkeylet:apiCredential}}\n"));
        assert!(template.contains("# OpenKeylet removed a commented-out value of OLD (line 4)"));
        for value in ["sk-proj-cliImportKey", "CliLowerSecret", "cliTokenValue", "cliCommentedSecret"] {
            assert!(!template.contains(value), "template kept a plaintext value");
        }
        let stored = vault.list_decrypted_connections().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].secrets.get("db_password"), Some("CliLowerSecret!1"));
        assert_eq!(stored[0].secrets.get("apiCredential"), Some("cliTokenValue123456"));

        let notice = vault_cmd::env_plaintext_notice(&env_path, 3, Some("/tmp/x/.env.template"), 1);
        assert!(notice.starts_with(&format!("Plaintext is still on disk: {}\n", env_path.display())));
        assert!(notice.contains("1 line(s) could not be sealed"));
        assert!(notice.contains("openkeylet run --env-file /tmp/x/.env.template -- <command>"));
        let unsealed = vault_cmd::env_plaintext_notice(&env_path, 3, None, 0);
        assert!(unsealed.contains("--seal"));

        let keys = vec![crate::extract::PlaintextSource {
            display_path: "~/.ssh/id_ed25519".to_owned(),
            kind: "key".to_owned(),
        }];
        let notice = vault_cmd::ssh_plaintext_notice(&keys);
        assert!(notice.contains("Unprotected private keys are still on disk:\n  ~/.ssh/id_ed25519\n"));
        assert!(notice.contains("ssh-keygen -p -f"));
        assert!(vault_cmd::ssh_plaintext_notice(&[]).is_empty());
    }

    #[test]
    fn cli_ssh_host_commands_parse_next_to_ssh_agent() {
        let parsed = Cli::try_parse_from([
            "openkeylet",
            "ssh",
            "forget-host",
            "::1",
            "--port",
            "2222",
        ])
        .unwrap();
        let Some(Command::Ssh {
            action: SshCommand::ForgetHost { host, port, pin_env },
        }) = parsed.command
        else {
            panic!("expected ssh forget-host command");
        };
        assert_eq!(host, "::1");
        assert_eq!(port, Some(2222));
        assert_eq!(pin_env, None);

        let parsed = Cli::try_parse_from(["openkeylet", "ssh", "hosts"]).unwrap();
        assert!(matches!(
            parsed.command,
            Some(Command::Ssh {
                action: SshCommand::Hosts
            })
        ));

        let parsed = Cli::try_parse_from(["openkeylet", "ssh-agent", "--print-env"]).unwrap();
        let Some(Command::SshAgent { args }) = parsed.command else {
            panic!("expected ssh-agent command");
        };
        assert_eq!(args, vec!["--print-env".to_owned()]);
    }

    #[test]
    fn cli_ssh_forget_host_requires_the_owner_pin_when_configured() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().join("vault");
        let vault = Vault::open(data_dir.clone()).unwrap();
        for host in ["server.example", "other.example"] {
            crate::ssh_host_keys::verify_or_pin(&data_dir, host, 22, "ssh-ed25519", "SHA256:test")
                .unwrap();
        }

        ssh_cmd::run_ssh(
            data_dir.clone(),
            SshCommand::ForgetHost {
                host: "Server.Example".to_owned(),
                port: Some(22),
                pin_env: None,
            },
        )
        .unwrap();
        assert_eq!(crate::ssh_host_keys::list(&data_dir).unwrap().len(), 1);

        vault.set_owner_pin("123456").unwrap();
        let error = ssh_cmd::run_ssh(
            data_dir.clone(),
            SshCommand::ForgetHost {
                host: "other.example".to_owned(),
                port: None,
                pin_env: Some("OPENKEYLET_TEST_UNSET_SSH_FORGET_PIN".to_owned()),
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("OPENKEYLET_TEST_UNSET_SSH_FORGET_PIN"));
        assert_eq!(crate::ssh_host_keys::list(&data_dir).unwrap().len(), 1);
    }

    #[test]
    fn cli_vault_enable_disable_trash_restore_work_without_gui() {
        let dir = tempdir().unwrap();
        let vault = Vault::open(dir.path().join("vault")).unwrap();
        let mut secrets = SecretBundle::default();
        secrets
            .named_secrets
            .insert("password".to_owned(), "s3cr3t-password".to_owned());
        let saved = vault
            .save_connection(ConnectionInput {
                login_uris: Vec::new(),
                item_type: "login".to_owned(),
                folder: String::new(),
                favorite: false,
                id: None,
                modules: vec![ItemModule {
                    kind: "password".to_owned(),
                    name: "password".to_owned(),
                    value: String::new(),
                    agent_visible: Some(false),
                }],
                name: "Headless Test".to_owned(),
                enabled: true,
                description: String::new(),
                http_auth_type: String::new(),
                private_key_import_path: String::new(),
                auth_header: String::new(),
                auth_location: String::new(),
                auth_prefix: String::new(),
                api_auth_headers: Vec::new(),
                test_path: String::new(),
                remove_secret_names: Vec::new(),
                secrets,
            })
            .unwrap();

        vault_cmd::run_vault(
            &vault,
            VaultCommand::Disable {
                item: "Headless Test".to_owned(),
            },
        )
        .unwrap();
        assert!(!vault.get_connection(saved.id).unwrap().stored.enabled);

        vault_cmd::run_vault(
            &vault,
            VaultCommand::Enable {
                item: "Headless Test".to_owned(),
            },
        )
        .unwrap();
        assert!(vault.get_connection(saved.id).unwrap().stored.enabled);

        vault_cmd::run_vault(
            &vault,
            VaultCommand::Trash {
                item: saved.id.to_string(),
            },
        )
        .unwrap();
        assert!(vault.list_connections().unwrap().is_empty());
        assert_eq!(vault.trash_items().unwrap().len(), 1);

        vault_cmd::run_vault(
            &vault,
            VaultCommand::Restore {
                item: "Headless Test".to_owned(),
            },
        )
        .unwrap();
        assert_eq!(vault.list_connections().unwrap().len(), 1);
    }
}
