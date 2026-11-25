# Headless, Remote & Multi-Machine OpenKeylet Guide

This guide covers deploying the headless Linux build of OpenKeylet on a server or homelab machine, managing a headless vault safely, connecting a remote browser extension, using passphrase-protected CLI `.mvault` backups, and sharing or syncing vaults across machines.

---

## 1. Headless Architecture & Responsibilities

The headless build (`cargo build --release --no-default-features`) contains the full encrypted vault engine, `stdio` MCP server, SSH/SFTP, HTTP, managed terminal, CLI utilities, Browser Bridge, and opt-in loopback management server — with **zero GUI/WebView dependencies**.

Important distinctions:
- The headless build does **not** include the desktop GUI window.
- The Chromium extension is primarily a browser credential/passkey delivery and popup vault companion; it is **not** a full replacement for the desktop GUI settings panel.
- Remote vault administration on a headless server should use one of:
  1. **Headless CLI** (`openkeylet vault ...`, `openkeylet add`, `openkeylet import-env`, `openkeylet keygen`),
  2. **Loopback Management Server over SSH port forwarding** (`openkeylet admin serve` + `ssh -L 39273:127.0.0.1:39273 user@server`), or
  3. **GitHub / self-hosted Gitea encrypted two-way sync** between a desktop GUI workstation and the server.

---

## 2. Headless Vault Administration

### 2.1 CLI Vault Commands & Diagnostics

All CLI vault commands keep hidden secret values masked by default:

```bash
# Show data directory, explicit-dir status, key source (never key material), counts, and bridge state
openkeylet vault status

# List items (metadata only — never prints hidden secrets)
openkeylet vault list
openkeylet vault list --all   # includes trash

# Inspect one item's modules and metadata
openkeylet vault show "Prod API"

# Agent kill-switch (enable/disable an item for MCP agents)
openkeylet vault disable "Prod API"
openkeylet vault enable "Prod API"

# Soft-delete and restore
openkeylet vault trash "Old Token"
openkeylet vault restore "Old Token"

# Configure 6-digit Owner PIN on headless servers (protects secret reveal & extension access)
openkeylet vault pin set
openkeylet vault pin status
# Local forgot-PIN recovery (prompts for confirmation in a TTY, or pass --force explicitly)
openkeylet vault pin clear [--force]

# SSH host-key pins (device-local ssh-known-hosts.json; never synced or exported)
openkeylet ssh hosts
openkeylet ssh forget-host server.example.com --port 2222
```

OpenKeylet pins the host key presented on the first SSH/SFTP connection to each host and port and refuses later connections that present a different key, before any credential is sent. No MCP tool resets a pin. After a legitimate host-key change (for example a server rebuild), run `openkeylet ssh forget-host <host> [--port <port>]`; it asks for the Owner PIN when one is configured (or reads it from the variable named by `--pin-env`), and the next connection pins the new key (trust-on-first-use). Pinning defends against a network attacker impersonating the server; the pin file is protected only by the OS account, like the rest of the data directory.

#### Importing `.env` files and SSH keys

Importing copies values into the vault; it never changes or deletes the source file. Both commands print the files that still hold plaintext (to stderr) together with the next step, because a plaintext `.env` or key file left on disk is exactly what file-searching malware collects.

```bash
# Import every KEY=VALUE (lowercase, dotted and multi-line quoted values included) and write
# .env.template next to the original, with {{openkeylet:FIELD}} placeholders that resolve
openkeylet import-env .env --seal
openkeylet run --item "Env · .env" --env-file .env.template -- npm run dev
rm .env   # once the app works from the template

# Hosts from ~/.ssh/config; the key files it names stay on disk until you remove them
openkeylet import-ssh
```

The template is safe to commit. Any line OpenKeylet cannot seal (an unrecognized line, a commented-out value, a comment holding a token, a repeated key) is replaced by a comment starting with `# OpenKeylet removed`, which names the key but never the value; the JSON output reports how many (`templateRemovedLines`), and those values exist only in the original file. `--seal` refuses to overwrite the file it reads.

### 2.2 Loopback-Only Headless Management Server (via SSH Tunnel)

`openkeylet admin serve` is **disabled by default** and binds strictly to `127.0.0.1:39273` on the server so SSH provides the authenticated, encrypted transport boundary:

1. On the headless server:
   ```bash
   openkeylet admin serve
   # Optional: openkeylet admin serve --port 39273 --token-env OPENKEYLET_ADMIN_TOKEN
   ```
   OpenKeylet prints a fresh, random 256-bit Bearer token (`oka1_...`) to stderr. The token lives only in RAM and is invalidated on shutdown or revocation.
2. On your workstation, open an SSH tunnel:
   ```bash
   ssh -L 39273:127.0.0.1:39273 user@server
   ```
3. Open `http://127.0.0.1:39273/` in your workstation browser and paste the Bearer token.

Security properties of `openkeylet admin serve`:
- Refuses non-loopback `--bind` addresses unless `--allow-non-loopback` is passed explicitly.
- Every `/api/*` endpoint requires constant-time Bearer token authentication.
- `GET /api/items` returns metadata only — never decrypted secrets.
- `POST /api/items/{id}/reveal` requires an explicit reveal action and verifies the 6-digit Owner PIN (with rate throttling) whenever a PIN is configured.
- `POST /api/session/rotate` immediately invalidates the old token and issues a new one; `POST /api/session/revoke` locks the session completely.
- Do **not** expose the admin server directly to the public Internet.

---

## 3. Remote / LAN Browser Bridge (Headless Server + Workstation Browser)

By default, Browser Bridge binds **only to `127.0.0.1`** (`ws://127.0.0.1:39272/extension`). Non-loopback binding is disabled by default and requires explicit opt-in because Browser Bridge delivers credentials to a browser.

### 3.1 Recommended Approach: SSH Tunnel (Zero LAN Exposure)

Keep Browser Bridge on loopback (`127.0.0.1`) on the server and forward port `39272` from your workstation:

```bash
# On the server:
openkeylet browser enable 39272
openkeylet browser pair 39272

# On your workstation:
ssh -L 39272:127.0.0.1:39272 user@server
```

Then keep the browser extension pointed at `127.0.0.1:39272`.

### 3.2 Direct LAN / Private Tunnel Mode (Explicit Opt-In)

When running on a trusted LAN, WireGuard, or Tailscale network, OpenKeylet separates three addresses:

| Setting (legacy `KRU_*` also accepted) | Purpose | Default |
| --- | --- | --- |
| `OPENKEYLET_BRIDGE_BIND` | Local IP address the listener binds to (e.g. `192.0.2.10` or `0.0.0.0`) | `127.0.0.1` |
| `OPENKEYLET_BRIDGE_ALLOW_LAN` | Must be `1`/`true` to allow any non-loopback `BRIDGE_BIND` | `false` |
| `OPENKEYLET_BRIDGE_HOST` | Hostname or IP advertised to the browser extension | `BRIDGE_BIND` (or `127.0.0.1` if unspecified) |
| `OPENKEYLET_BRIDGE_ALLOW_IPS` | Comma-separated client IPs or CIDRs allowed to connect (e.g. `192.0.2.50,10.0.0.0/24`) | *(empty = any peer on bound interface)* |
| `OPENKEYLET_BRIDGE_ALLOWED_ORIGINS` | Additional allowed extension origins (comma-separated, no `*` wildcards) | Official OpenKeylet extension origin |
| `OPENKEYLET_BRIDGE_SCHEME` | Advertised WebSocket scheme: `ws` or `wss` (when fronted by a TLS reverse proxy) | `ws` |

Internal bridge calls (`/internal/*`) automatically map `0.0.0.0` → `127.0.0.1` and `::` → `::1`, and reject non-local peers even in LAN mode.

Example server setup:
```bash
export OPENKEYLET_BRIDGE_BIND=192.0.2.10
export OPENKEYLET_BRIDGE_HOST=192.0.2.10
export OPENKEYLET_BRIDGE_ALLOW_LAN=1
export OPENKEYLET_BRIDGE_ALLOW_IPS=192.0.2.50

openkeylet browser enable 39272
openkeylet browser pair 39272
openkeylet browser status
```

On the workstation browser extension:
1. Open the OpenKeylet popup → **Connection**.
2. Set **BRIDGE HOST** to `192.0.2.10` and **BRIDGE PORT** to `39272` (check **Use TLS (https / wss)** if terminating TLS via Caddy, nginx, or Tailscale Serve).
3. Click **RECONNECT BRIDGE** during the pairing window.

To inspect connected clients, last-use timestamps, or revoke pairing and rotate the extension token:
```bash
openkeylet browser status   # shows clients[], peerIp, connectedAt, lastUsedAt, ipAllowlist
openkeylet browser reset    # rotates bridge secret & disconnects active clients
```

Connection lifecycle events (pair claims, origin/IP rejections, auth failures, connects/disconnects, resets) are logged to stderr with peer IP metadata only — credential values and tokens are never logged.

---

## 4. Passphrase-Protected `.mvault` Backups (GUI & CLI)

OpenKeylet supports two `.mvault` formats:
1. **Passphrase-protected `.mvault` (`openkeylet-password-backup` v1)** — the default for every export, and what you want on NAS, cloud drives, off-site backups, and removable media. Derives a 256-bit key with **Argon2id** (64 MiB, 3 iterations, 1 lane) + random 128-bit salt, encrypts with **XChaCha20-Poly1305**, stores **no decryption key** inside the file, rejects wrong passphrases without touching the active vault, and cannot be recovered if the passphrase is lost.
2. **Self-unlocking `.mvault` (`mcp-vault-backup` v3–v8)** — carries its own unlock key, so anyone who gets a copy can read every secret; treat it like a plaintext export. The CLI writes one only with `--self-unlocking`, and import still accepts older files of this kind.

CLI usage:
```bash
# Default: Argon2id passphrase-protected export (interactive hidden prompt)
openkeylet backup export protected.mvault
openkeylet backup export protected.mvault --passphrase   # same, explicit

# Non-interactive / scripted export (from env var or stdin). Without a terminal and
# without one of these flags, export refuses instead of writing an unprotected file.
OPENKEYLET_BACKUP_PW="correct-horse-battery-staple" openkeylet backup export protected.mvault --passphrase-env OPENKEYLET_BACKUP_PW
printf '%s\n' "$PW" | openkeylet backup export protected.mvault --passphrase-stdin

# Import automatically detects whether a .mvault file requires a passphrase
openkeylet backup import protected.mvault --passphrase
openkeylet backup import protected.mvault --passphrase-env OPENKEYLET_BACKUP_PW

# Self-unlocking export, only when asked for by name (keep it off shared and synced folders)
openkeylet backup export local-only.mvault --self-unlocking
```

---

## 5. Shared Vault Directories vs. Encrypted Cloud Sync

### Explicit Data Directory (`OPENKEYLET_DATA_DIR` / `KRU_DATA_DIR`)
When `OPENKEYLET_DATA_DIR` (or legacy `KRU_DATA_DIR`) is set to an absolute path:
- OpenKeylet **always** prefers `<DATA_DIR>/master.key` instead of silently consulting an unrelated OS keyring entry.
- If `vault.json` exists while `master.key` is missing, OpenKeylet refuses to generate a new key so existing encrypted data is never overwritten.
- Run `openkeylet vault status` to inspect the active `dataDir` and `keySource` without exposing key material.

### Concurrency & File Safety Model
OpenKeylet uses:
- `bootstrap.lock` (exclusive file lock during startup),
- `vault.lock` (shared lock for concurrent readers, exclusive lock for serialized writers), and
- atomic temp-file replacement (`AtomicWriteFile`) for `vault.json`.

**Important caveat for SMB/NFS network shares**:
- Advisory file locks (`flock` / `LockFileEx`) work reliably across local processes on the same OS, **not** reliably across heterogeneous Windows + Linux clients mounted over SMB/NFS.
- Simultaneous active writers from a Windows GUI and a Linux headless MCP server onto the same SMB/NFS share are **not recommended** — if the share drops mid-operation or lock semantics differ across OSes, operations may fail.
- For multi-machine setups (e.g., Windows desktop GUI + Linux headless server), prefer **GitHub / self-hosted Gitea encrypted two-way sync** (each machine keeps a fast local vault and merges safely via `id`, `updatedAt`, and deletion tombstones).
- Treat `.mvault` strictly as an offline import/export backup format, never as a live multi-writer database.

---

## 6. Using OpenKeylet with Hermes Agent & Other MCP Clients

Generate standard `stdio` MCP client configuration:
```bash
openkeylet config stdio-json
openkeylet config stdio-toml
```

Once connected, agents can configure local services (such as Himalaya, Ortie, `.env`, or TOML/YAML configs) **without plaintext entering chat history or model context in normal use** (this is not a boundary against a malicious or prompt-injected agent; see [SECURITY.md](../SECURITY.md#what-openkeylet-does-not-protect-against)):
- `secret_write_file`: renders local config files from `{{openkeylet:module}}` templates atomically with `0600` permissions on Unix.
- `terminal_run` / `terminal_start`: substitutes `{{openkeylet:module}}` placeholders or injects `secretEnv` into child processes and redacts known secrets from stdout/stderr.
- `draft_prepare`, `secret_generate`, `ssh_keygen`, `secret_ingest_file`: create, generate, or ingest secrets directly into the encrypted vault with zero plaintext returned to the LLM.
