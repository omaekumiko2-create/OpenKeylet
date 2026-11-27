# OpenKeylet — AI Agent Install & Update Runbook

> **Instructions for AI Agents (Claude Code, Antigravity, Codex, Cursor, OpenCode, DeepSeek Harness)**
>
> Follow this runbook strictly when the user asks you to **install** or **update** OpenKeylet.
>
> - **DO NOT `git clone`, `cargo build`, or `npm install`** unless the user explicitly asked to compile from source.
> - **Always use official signed GitHub Releases** (`https://github.com/omaekumiko2-create/OpenKeylet/releases`).
> - **Never delete, overwrite, or read** the user's vault data (`mcp-vault/v2`) or `master.key`.
> - **Never create duplicate installations**: if OpenKeylet is already installed, update it **in place** using OpenKeylet's built-in Ed25519-signed updater (`openkeylet update install`).

---

## Step 0 · Detect Whether OpenKeylet Is Already Installed

First check if an existing `openkeylet` binary is already present on this machine:

- **macOS / Linux**:
  ```bash
  command -v openkeylet \
    || ls -1 /Applications/OpenKeylet.app/Contents/MacOS/openkeylet \
             "$HOME/Applications/OpenKeylet.app/Contents/MacOS/openkeylet" \
             "$HOME/.local/share/openkeylet/openkeylet" 2>/dev/null
  ```
- **Windows (PowerShell)**:
  ```powershell
  (Get-Command openkeylet -ErrorAction SilentlyContinue).Source
  Test-Path "$env:LOCALAPPDATA\Programs\OpenKeylet\openkeylet.exe"
  ```
- Also check the active agent's existing MCP configuration if the user installed a portable copy in a custom folder (so you update that exact path in place instead of creating a second copy).

- **If OpenKeylet is already installed and the user asked to update (or ensure latest)** -> go to **Section A (Update In Place)**.
- **If OpenKeylet is not installed yet** -> go to **Section B (Fresh Install)**.

---

## Section A · Update an Existing Installation (Conflict-Free Built-In Updater)

OpenKeylet ships a built-in **Ed25519 + SHA-256 signed in-place updater** shared between the GUI (`SYSTEM -> UPDATE / 07`) and CLI (`openkeylet update install`). Using it guarantees:

1. **Zero conflict with GUI background updates**: automatically reuses any already-staged `pending-update.json` and clears obsolete staging files after applying.
2. **Zero duplicate copies**: updates the exact installed binary / `.app` / `AppImage` and bundled `browser-extension/` in place, keeping existing MCP paths valid.
3. **Automatic agent rule refresh**: syncs updated managed instructions for already-connected agents without modifying unconnected clients.

Run on the detected existing binary (`<openkeylet>`):

```bash
# Check if `--json` is supported (v0.21+) or run plain `update install` (v0.17–v0.20 compatible)
if <openkeylet> update install --help 2>&1 | grep -q -- '--json'; then
  <openkeylet> update install --json
else
  <openkeylet> update install
  # After upgrading to a newer release, refresh already-connected agent rules if supported:
  <openkeylet> agent sync --json 2>/dev/null || true
fi
```

On Windows PowerShell:

```powershell
$exe = "<existing-openkeylet.exe>"
$help = & $exe update install --help 2>&1 | Out-String
if ($help -match '--json') {
  & $exe update install --json
} else {
  & $exe update install
  & $exe agent sync --json 2>$null
}
```

- On desktop builds, pass `--relaunch` if the user wants the desktop GUI reopened immediately (the new instance seamlessly hands off from any already-running GUI window).
- **Fallback**: Only if the existing binary is older than `update install`, corrupt, or returns `UPDATE_NO_SIGNING_KEY` / `UPDATE_READONLY_DIR` (do **not** bypass `UPDATE_SIGNATURE_INVALID` or `UPDATE_CHECKSUM_MISMATCH`), run the installer script in Section B with `--update` / `-Update` (or `--reinstall` / `-Reinstall` if moving out of a read-only folder).

Then proceed to **Section C (Verify & Report to User)**.

---

## Section B · Fresh Install (Auditable Official Installer)

Download the official installer script to a temporary file (so the user can inspect or approve it before execution), run it, and remove the temporary script afterward.

The official installer automatically:
- Fetches `latest.json` from `https://github.com/omaekumiko2-create/OpenKeylet/releases/latest/download/latest.json`
- Verifies the **Ed25519 release signature** (when Node.js is present) + exact size + archive **SHA-256** + internal package `SHA256SUMS.txt` (+ macOS `codesign --verify --deep --strict`)
- Installs to a canonical user-writable path compatible with future built-in auto-updates (no `sudo` / UAC required):
  - **Windows**: `%LOCALAPPDATA%\Programs\OpenKeylet\openkeylet.exe` (added to User `PATH`)
  - **macOS**: `/Applications/OpenKeylet.app` (or `~/Applications/OpenKeylet.app` if `/Applications` is not writable) + CLI wrapper `~/.local/bin/openkeylet`
  - **Linux (GUI or Headless)**: `~/.local/share/openkeylet/` + CLI wrapper `~/.local/bin/openkeylet` (auto-detects `$DISPLAY`/`$WAYLAND_DISPLAY`, or pass `--headless` on servers)
- Runs `openkeylet setup --json` to initialize the local vault, clean any obsolete update artifacts, and automatically connect detected AI agent clients (`codex`, `claude-code`, `cursor`, `opencode`, `antigravity`, `deepseek-harness`).

### macOS & Linux

```bash
curl -fsSL https://raw.githubusercontent.com/omaekumiko2-create/OpenKeylet/main/scripts/install.sh -o /tmp/openkeylet-install.sh
bash /tmp/openkeylet-install.sh --json
rm -f /tmp/openkeylet-install.sh
```

Useful optional flags:
- `--headless` / `--gui` — Force Linux headless or GUI build
- `--client <id>` — Connect only specific client(s): `codex`, `claude-code`, `cursor`, `opencode`, `antigravity`, `deepseek-harness`
- `--no-connect` — Install binary only without editing agent configs
- `--shortcut` — Create a desktop shortcut (Linux GUI)
- `--launch` — Open the desktop GUI after setup finishes
- `--require-signature` — Require Node.js Ed25519 signature verification (fail if `node` is absent)
- `--update` — Update an existing installation in place via the built-in updater

### Windows (PowerShell)

```powershell
$script = Join-Path $env:TEMP "openkeylet-install.ps1"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/omaekumiko2-create/OpenKeylet/main/scripts/install.ps1" -OutFile $script -UseBasicParsing
powershell -NoProfile -ExecutionPolicy Bypass -File $script -Shortcut -Json
Remove-Item -LiteralPath $script -Force -ErrorAction SilentlyContinue
```

Useful optional flags:
- `-Client codex,claude-code` — Connect only specific client(s)
- `-NoConnect` — Install binary only without editing agent configs
- `-Launch` — Launch the desktop GUI after setup finishes
- `-RequireSignature` — Require Node.js Ed25519 signature verification
- `-Update` — Update an existing installation in place via the built-in updater

---

## Section C · Verify & Report Back to the User

Run these read-only checks (none of them reveal secrets):

```bash
openkeylet --version
openkeylet vault status
openkeylet agent list --json
```

*(If `PATH` was just updated in the current shell session and `openkeylet` is not resolved yet, invoke the full executable path reported in the JSON output.)*

Then summarize clearly for the user:

1. **Installed / updated version** and exact executable path.
2. **Connected AI agent clients** (and any client that reported `conflict` or `error` — never silently overwrite unrelated non-OpenKeylet MCP entries without asking).
3. **Required next step — Restart / new agent session**: tell the user to restart or open a fresh session in their agent client so the new/updated OpenKeylet MCP tools load, and give them the 5-second verification prompt:
   > `List the enabled items you can see in OpenKeylet MCP.`
4. **Optional next step — Browser Extension (Desktop only)**: explain that Chrome/Edge does not allow silent CLI injection of unpacked extensions. If the user wants webpage autofill, 2FA, Passkey, or one-time API key capture, open OpenKeylet -> **SYSTEM -> WEB / 04** and drag the OpenKeylet badge onto `chrome://extensions/` (or load the `browserExtensionPath` shown in the setup output).
