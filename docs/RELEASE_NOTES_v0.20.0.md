# OpenKeylet v0.20.0

First official release under the **OpenKeylet** name (successor to `KRU v0.15.0`), maintaining full backward compatibility with existing local vaults, keys, `.mvault` backups, `{{kru:...}}` placeholders, and `KRU_*` environment variables.

For full documentation, quickstart guides, and demos, see [README.md](https://github.com/omaekumiko2-create/OpenKeylet/blob/main/README.md) ([简体中文](https://github.com/omaekumiko2-create/OpenKeylet/blob/main/README.zh-CN.md)).

---

## What's New

### New Features
- **Direct Migration from Bitwarden, 1Password & KeePass**: Drag and drop **Bitwarden password-protected encrypted JSON** (`PBKDF2-SHA256` / `Argon2id` + `AES-256-CBC` / `HMAC-SHA256`), **1Password `.1pux`**, or **KeePass / KeePassXC `.kdbx` (KDBX 3.1 / 4.x) & XML** onto any OpenKeylet screen to decrypt locally, inspect compatibility warnings, filter/select items, and merge non-destructively — preserving Passkeys, TOTP, SSH keys, folders, and password history.
- **Offline Smart Import Hub & PC Scanner**: 100% offline rule-based extractor for `.env`, cURL, SSH configs/keys, database URIs, and 2FA QR images. **Scan PC / Scan Folder** discovers scattered local credentials (including `CLAUDE.md`, `AGENTS.md`, `.bashrc`, and shell history) without modifying source files and reports plaintext cleanup next steps.
- **Zero-Plaintext Agent Self-Save (26 MCP Tools)**: Added `browser_save_key`, `browser_save_login`, `http_send(captureSecrets / holdResponse)`, and `http_save_secret` so AI agents can save newly issued API keys, tokens, and logins directly into the vault without exposing plaintext to LLM context.
- **Native CLI Bridges & Headless Mode**: Added `openkeylet run --env-file`, `openkeylet import-env --seal`, `openkeylet ssh-agent` (Unix socket / Windows Named Pipe), `openkeylet git-credential`, and headless `admin serve` for remote servers and VPS environments.
- **Dual-Repo Encrypted Cloud Sync & Version History**: Splits encrypted vault ciphertext (`owner/repo`) and master key (`owner/repo-key`) across two separate private GitHub / Gitea / Forgejo repositories with private-repo auto-discovery, strict `private: true` enforcement, and snapshot version history rollback.
- **Signed Auto-Updater**: Checks GitHub Releases directly via Ed25519-signed `latest.json` manifests and SHA-256 checksums (available in **SYSTEM → UPDATE / 07** and via `openkeylet update check` / `openkeylet update install`).
- **Carbon & Porcelain UI + Least-Privilege Browser Extension**: Rebuilt 4-tab monochrome UI (`ITEMS / IMPORT / LOG / SYSTEM`), Dark & Porcelain Light themes, one-click batch health `CHECK`, 6 languages (`en`, `zh`, `zh-TW`, `ja`, `ko`, `es`), and a streamlined browser extension dedicated to current-site autofill, live 2FA, local ES256 WebAuthn Passkeys, and the Agent Browser Bridge.

### Security & Hardening
- **Physical Key Separation**: Default mode stores `master.key` outside the vault data directory (Windows Credential Manager / Linux Secret Service, or a dedicated user key directory with Unix `0600` / Win32 owner-only protected NTFS DACL `D:P`). Explicit `OPENKEYLET_KEY_FILE` strictly bypasses OS keyring fallback.
- **Import & Crypto Hardening**: Moved all KDF, decryption, and drop extraction work to worker threads (`spawn_blocking`) with single-flight concurrency and lock/cancel generation guards; added pre-decode Base64 size caps, bounded regular-file reads, strict Bitwarden/KDBX KDF work limits, KDBX 2 prerelease rejection, iterative group traversal, and a depth-bounded streaming `quick-xml` parser.
- **Leakage & Output Redaction**: Scrubbed `Set-Cookie` / `Set-Cookie2` response headers and URL query/user-info tokens in `http_send`; hardened `secret_write_file` with private permissions before atomic rename plus `git ls-files` detection for already-tracked plaintext files; excluded clipboard copies from Windows `Win+V` history with 30-second auto-clear.

### Bug Fixes
- Tightened `regex` website matching rules to prevent overly broad domain matches.
- Fixed cross-frame/focused-field placeholder redaction and transient `Frame removed` retries during page navigation in `browser_inspect`.
- Fixed Windows `git.cmd` wrapper handling and cross-platform CI/release verification (Windows SDDL `LA` alias for built-in Administrator SIDs, Linux PTY trailing newline handling, and macOS separated key path checks).

---

## Downloads & Upgrading

| Platform | Artifact | Notes |
| --- | --- | --- |
| **macOS arm64** | `OpenKeylet_0.20.0_macos-arm64-portable.zip` | Apple Developer ID signed & notarized `.app` + browser extension |
| **Windows x64** | `OpenKeylet_0.20.0_windows-x64-portable.zip` | Portable GUI, tray, `Win+V` exclusion, Win32 NTFS ACLs + extension |
| **Linux x64 GUI** | `OpenKeylet_0.20.0_linux-x64-portable.tar.gz` | Desktop AppImage, X11 fill & system tray + extension |
| **Linux x64 Headless** | `OpenKeylet_0.20.0_linux-headless-x64.tar.gz` | Zero GUI deps (`--no-default-features`), full MCP / CLI / SSH / `admin serve` |

- **Upgrading from `KRU v0.15.0`**: Replace the binary (your local vault is preserved automatically), open **SYSTEM → MCP / 02 → REPAIR** to migrate existing `kru` MCP entries to `openkeylet`, and restart your agent.
- **Verification**: Archive checksums are published in `SHA256SUMS.txt`; auto-update metadata is Ed25519-signed in `latest.json`.

**Full Changelog**: https://github.com/omaekumiko2-create/OpenKeylet/compare/v0.15.0...v0.20.0

---

*OpenKeylet is a long-term maintained open-source project ([MIT](https://github.com/omaekumiko2-create/OpenKeylet/blob/main/LICENSE), provided AS-IS). Bug reports, suggestions, and discussions are always welcome in [Issues](https://github.com/omaekumiko2-create/OpenKeylet/issues) and [Discussions](https://github.com/omaekumiko2-create/OpenKeylet/discussions).*
