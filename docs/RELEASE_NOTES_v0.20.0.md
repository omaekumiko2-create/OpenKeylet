# OpenKeylet v0.20.0

First official release under the **OpenKeylet** name (successor to `KRU v0.15.0`), keeping full compatibility with existing local vaults, keys, `.mvault` backups, `{{kru:...}}` placeholders, and `KRU_*` environment variables.

> 首次以 **OpenKeylet** 名义发布的正式版本（继承自 `KRU v0.15.0`），完全兼容已有本地密码库、密钥、`.mvault` 备份与旧配置。完整文档与演示请见 [English README](https://github.com/omaekumiko2-create/OpenKeylet/blob/main/README.md) · [简体中文文档](https://github.com/omaekumiko2-create/OpenKeylet/blob/main/README.zh-CN.md)。

---

## Highlights / 主要更新

### New Features · 新增功能
- **Direct Migration from Bitwarden, 1Password & KeePass**: Drag and drop **Bitwarden password-protected encrypted JSON** (`PBKDF2-SHA256` / `Argon2id` + `AES-256-CBC` / `HMAC-SHA256`), **1Password `.1pux`**, or **KeePass / KeePassXC `.kdbx` (KDBX 3.1 / 4.x) & XML** onto any screen to decrypt locally, inspect compatibility warnings, filter/select items, and merge non-destructively (preserving Passkeys, TOTP, SSH keys, folders, and password history).
  - 原生支持本机解密并选择性迁入 **Bitwarden 密码保护加密 JSON**、**1Password `.1pux`** 与 **KeePass `.kdbx` / XML**，保留 Passkey、2FA、SSH 密钥、分组与密码历史，冲突自动安全重命名。
- **Offline Smart Import Hub & PC Scanner**: 100% offline rule-based extraction from `.env`, cURL, SSH configs/keys, database URIs, and 2FA QR images; **Scan PC / Scan Folder** discovers scattered local secrets (including `CLAUDE.md`, `AGENTS.md`, `.bashrc`, shell history) without modifying source files and lists plaintext cleanup steps.
  - 纯离线「智能导入中心」与全机/目录扫描器，支持 2FA 二维码离线解码与导入后明文残留清理提示。
- **Zero-Plaintext Agent Self-Save (26 MCP Tools)**: Added `browser_save_key`, `browser_save_login`, `http_send(captureSecrets / holdResponse)`, and `http_save_secret` so agents can store newly issued API keys, tokens, and logins straight into the vault without exposing plaintext in LLM context.
  - 新增 4 项代理零明文自助存密能力，形成「代执行 + 自助入库」完整闭环（共 26 个 MCP 工具）。
- **Native CLI Bridges & Headless Mode**: Added `openkeylet run --env-file`, `openkeylet import-env --seal`, `openkeylet ssh-agent` (Unix socket / Windows Named Pipe), `openkeylet git-credential`, and headless `admin serve` for remote servers/VPS.
- **Dual-Repo Encrypted Cloud Sync & Version History**: Syncs encrypted vault data (`owner/repo`) and master key (`owner/repo-key`) across two separate private GitHub / Gitea / Forgejo repositories with auto-discovery, `private: true` verification, and snapshot version history rollback.
  - 双仓库物理分离加密云同步与快照版本历史回滚。
- **Signed Auto-Updater**: Verifies Ed25519-signed `latest.json` manifests and SHA-256 checksums directly from GitHub Releases (desktop **SYSTEM → UPDATE / 07** and headless `openkeylet update check/install`).
- **Carbon & Porcelain UI + Least-Privilege Browser Extension**: Rebuilt 4-tab monochrome UI (`ITEMS / IMPORT / LOG / SYSTEM`), Dark & Porcelain Light themes, batch `CHECK`, 6 languages (`en`, `zh`, `zh-TW`, `ja`, `ko`, `es`), and a streamlined browser extension dedicated to current-site autofill, live 2FA, local ES256 WebAuthn Passkeys, and Agent Browser Bridge.

### Security & Hardening · 安全与稳定性加固
- **Physical Key Separation**: Default mode stores `master.key` outside the vault data directory (Windows Credential Manager / Linux Secret Service or dedicated key directory with Unix `0600` / Win32 owner-only protected NTFS DACL `D:P`). Setting `OPENKEYLET_KEY_FILE` strictly bypasses OS keyring fallback.
- **Import & Crypto Hardening**: Moved all KDF/decryption/drop extraction onto worker threads (`spawn_blocking`) with single-flight concurrency and lock/cancel generation guards; added pre-decode Base64 caps, bounded regular-file reads, strict Bitwarden/KDBX KDF work limits, KDBX 2 prerelease rejection, iterative group traversal, and a depth-bounded streaming `quick-xml` parser.
- **Leakage & Output Redaction**: Scrubbed `Set-Cookie` / `Set-Cookie2` headers and URL query/user-info tokens in `http_send`; hardened `secret_write_file` with private permissions before atomic rename and `git ls-files` detection for already-tracked plaintext files; excluded clipboard copies from Windows `Win+V` history with 30s auto-clear.

### Bug Fixes · 问题修复
- Tightened `regex` website matching rules to prevent overly broad domain matches.
- Fixed cross-frame/focused-field placeholder redaction and transient `Frame removed` retries during navigation in `browser_inspect`.
- Fixed Windows `git.cmd` wrapper handling and cross-platform CI/release verification (Windows SDDL `LA` alias for built-in Administrator SID, Linux PTY newline handling, and macOS separated key path smoke checks).

---

## Downloads & Verification / 下载与升级

| Platform | Artifact | Notes |
| --- | --- | --- |
| **macOS arm64** | `OpenKeylet_0.20.0_macos-arm64-portable.zip` | Apple Developer ID signed & notarized `.app` + browser extension |
| **Windows x64** | `OpenKeylet_0.20.0_windows-x64-portable.zip` | Portable GUI, tray, `Win+V` exclusion, Win32 NTFS ACLs + extension |
| **Linux x64 GUI** | `OpenKeylet_0.20.0_linux-x64-portable.tar.gz` | Desktop AppImage, X11 fill & system tray + extension |
| **Linux x64 Headless** | `OpenKeylet_0.20.0_linux-headless-x64.tar.gz` | Zero GUI deps (`--no-default-features`), full MCP / CLI / SSH / `admin serve` |

- **Upgrading from KRU v0.15.0**: Replace the binary (your local vault is preserved automatically), open **SYSTEM → MCP / 02 → REPAIR** to update existing `kru` MCP configs to `openkeylet`, and restart your agent.
- **Verification**: Checksums are published in `SHA256SUMS.txt`; auto-update metadata is Ed25519-signed in `latest.json`.

**Full Changelog**: https://github.com/omaekumiko2-create/OpenKeylet/compare/v0.15.0...v0.20.0

---

*OpenKeylet is a long-term maintained open-source project ([MIT](https://github.com/omaekumiko2-create/OpenKeylet/blob/main/LICENSE), provided AS-IS). Bug reports, suggestions, and discussions are always welcome in [Issues](https://github.com/omaekumiko2-create/OpenKeylet/issues) and [Discussions](https://github.com/omaekumiko2-create/OpenKeylet/discussions).*
