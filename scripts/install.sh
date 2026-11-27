#!/usr/bin/env bash
# OpenKeylet cross-platform installer & update helper for macOS and Linux.
# - Verifies Ed25519 signature (via Node.js when available) + SHA-256 checksums.
# - Installs to a canonical user-writable path compatible with built-in auto-updates.
# - Delegates updates on existing installations to OpenKeylet's built-in signed updater
#   (`openkeylet update install`) so CLI/agent updates never conflict with GUI updates.

set -euo pipefail

REPO="omaekumiko2-create/OpenKeylet"
OFFICIAL_RELEASE_PREFIX="https://github.com/${REPO}/releases/"
OFFICIAL_UPDATE_PUBLIC_KEY="uCBOtL43FyR7FSOGo9eo+MzKfxX7oSb+ZWQb7oGcrfM="
ENVELOPE_FORMAT="openkeylet-update-v1"

INSTALL_DIR=""
BIN_DIR="${HOME}/.local/bin"
MODE="auto"
VERSION="latest"
UPDATE_ONLY=0
REINSTALL=0
NO_CONNECT=0
CLIENTS=()
SHORTCUT=0
AUTOSTART=0
LAUNCH=0
NO_PATH=0
REQUIRE_SIGNATURE=0
JSON_OUTPUT=0
EXPLICIT_INSTALL_DIR=0

usage() {
  cat <<'EOF'
OpenKeylet Installer & Updater (macOS / Linux)

Usage:
  bash scripts/install.sh [options]

Options:
  --install-dir <dir>   Custom installation directory
  --bin-dir <dir>       CLI wrapper directory (default: ~/.local/bin)
  --mode <auto|gui|headless>
                        Linux package mode (default: auto-detect display)
  --headless            Shorthand for --mode headless (Linux)
  --gui                 Shorthand for --mode gui (Linux)
  --version <vX.Y.Z>    Install a specific release tag (default: latest)
  --update              Update an existing OpenKeylet install in place via built-in updater
  --reinstall           Force a fresh verified download and atomic in-place install
  --no-connect          Skip auto-connecting detected AI agents
  --client <id>         Connect only specific agent client(s) (repeatable)
  --shortcut            Create a desktop shortcut (Linux GUI)
  --autostart           Enable launch at login (desktop builds)
  --launch              Launch desktop GUI after install/update
  --no-path             Do not update shell profile PATH entries
  --require-signature   Fail if Ed25519 manifest signature cannot be verified
  --json                Emit machine-readable JSON summary to stdout
  -h, --help            Show this help
EOF
}

log() {
  printf '%s\n' "$*" >&2
}

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-dir)
      [[ $# -ge 2 ]] || die "--install-dir requires a value"
      INSTALL_DIR="$2"
      EXPLICIT_INSTALL_DIR=1
      shift 2
      ;;
    --bin-dir)
      [[ $# -ge 2 ]] || die "--bin-dir requires a value"
      BIN_DIR="$2"
      shift 2
      ;;
    --mode)
      [[ $# -ge 2 ]] || die "--mode requires auto, gui, or headless"
      MODE="$2"
      shift 2
      ;;
    --headless)
      MODE="headless"
      shift
      ;;
    --gui)
      MODE="gui"
      shift
      ;;
    --version)
      [[ $# -ge 2 ]] || die "--version requires a release tag (e.g. v0.20.0)"
      VERSION="$2"
      shift 2
      ;;
    --update)
      UPDATE_ONLY=1
      shift
      ;;
    --reinstall)
      REINSTALL=1
      shift
      ;;
    --no-connect)
      NO_CONNECT=1
      shift
      ;;
    --client)
      [[ $# -ge 2 ]] || die "--client requires a client id"
      CLIENTS+=("$2")
      shift 2
      ;;
    --shortcut)
      SHORTCUT=1
      shift
      ;;
    --autostart)
      AUTOSTART=1
      shift
      ;;
    --launch)
      LAUNCH=1
      shift
      ;;
    --no-path)
      NO_PATH=1
      shift
      ;;
    --require-signature)
      REQUIRE_SIGNATURE=1
      shift
      ;;
    --json)
      JSON_OUTPUT=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Unknown option: $1 (use --help for usage)"
      ;;
  esac
done

case "$MODE" in
  auto|gui|headless) ;;
  *) die "Invalid --mode '$MODE' (expected auto, gui, or headless)" ;;
esac

OS="$(uname -s)"
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64|amd64) ARCH="x64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) die "Unsupported CPU architecture: $ARCH_RAW" ;;
esac

case "$OS" in
  Darwin)
    PLATFORM_KEY="macos-${ARCH}"
    ARCHIVE_FORMAT="zip"
    if [[ -z "$INSTALL_DIR" ]]; then
      if [[ -d /Applications && -w /Applications ]]; then
        INSTALL_DIR="/Applications"
      else
        INSTALL_DIR="${HOME}/Applications"
      fi
    fi
    TARGET_EXE="${INSTALL_DIR}/OpenKeylet.app/Contents/MacOS/openkeylet"
    ;;
  Linux)
    EFFECTIVE_MODE="$MODE"
    if [[ "$EFFECTIVE_MODE" == "auto" ]]; then
      if [[ -n "${DISPLAY:-}" || -n "${WAYLAND_DISPLAY:-}" ]]; then
        EFFECTIVE_MODE="gui"
      else
        EFFECTIVE_MODE="headless"
      fi
    fi
    PLATFORM_KEY="linux-${ARCH}-${EFFECTIVE_MODE}"
    ARCHIVE_FORMAT="tar.gz"
    if [[ -z "$INSTALL_DIR" ]]; then
      INSTALL_DIR="${HOME}/.local/share/openkeylet"
    fi
    TARGET_EXE="${INSTALL_DIR}/openkeylet"
    ;;
  *)
    die "Unsupported OS '$OS'. On Windows, run scripts/install.ps1."
    ;;
esac

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

download_file() {
  local url="$1"
  local dest="$2"
  if have_cmd curl; then
    curl -fsSL --proto '=https' --tlsv1.2 --retry 2 --connect-timeout 15 --max-time 300 -o "$dest" "$url" 2>/dev/null \
      || {
        # Allow local http:// ONLY when OPENKEYLET_UPDATE_MANIFEST_URL explicitly points to http:// (for tests/mirrors).
        if [[ -n "${OPENKEYLET_UPDATE_MANIFEST_URL:-}" && "$url" == http://* ]]; then
          curl -fsSL --retry 2 --connect-timeout 15 --max-time 300 -o "$dest" "$url"
        else
          curl -fsSL --proto '=https' --tlsv1.2 --retry 2 --connect-timeout 15 --max-time 300 -o "$dest" "$url"
        fi
      }
  elif have_cmd wget; then
    wget -qO "$dest" "$url"
  else
    die "Neither curl nor wget is available to download OpenKeylet."
  fi
}

sha256_file() {
  local file="$1"
  if have_cmd sha256sum; then
    sha256sum "$file" | awk '{print tolower($1)}'
  elif have_cmd shasum; then
    shasum -a 256 "$file" | awk '{print tolower($1)}'
  else
    die "Neither sha256sum nor shasum is available to verify SHA-256 checksums."
  fi
}

file_size_bytes() {
  local file="$1"
  if [[ "$OS" == "Darwin" ]]; then
    stat -f%z "$file"
  else
    stat -c%s "$file"
  fi
}

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/}"
  printf '%s' "$s"
}

write_cli_wrapper() {
  local exe_path="$1"
  local wrapper="${BIN_DIR}/openkeylet"
  mkdir -p "$BIN_DIR"
  local escaped_exe="${exe_path//\'/\'\\\'\'}"
  local tmp_wrapper="${wrapper}.new.$$"
  cat > "$tmp_wrapper" <<EOF
#!/bin/sh
exec '${escaped_exe}' "\$@"
EOF
  chmod 755 "$tmp_wrapper"
  mv -f "$tmp_wrapper" "$wrapper"
}

ensure_path_entry() {
  if [[ "$NO_PATH" -eq 1 ]]; then
    return 0
  fi
  case ":${PATH}:" in
    *":${BIN_DIR}:"*) return 0 ;;
  esac

  local profile_file=""
  local shell_name
  shell_name="$(basename "${SHELL:-}")"
  if [[ "$shell_name" == "zsh" || ( "$OS" == "Darwin" && -z "$shell_name" ) ]]; then
    profile_file="${HOME}/.zshrc"
  elif [[ "$shell_name" == "bash" ]]; then
    if [[ -f "${HOME}/.bashrc" ]]; then
      profile_file="${HOME}/.bashrc"
    else
      profile_file="${HOME}/.profile"
    fi
  else
    profile_file="${HOME}/.profile"
  fi

  local export_line
  if [[ "$BIN_DIR" == "${HOME}/.local/bin" ]]; then
    export_line='export PATH="$HOME/.local/bin:$PATH"'
  else
    export_line="export PATH=\"${BIN_DIR}:\$PATH\""
  fi

  if [[ -f "$profile_file" ]] && grep -Fq "$BIN_DIR" "$profile_file" 2>/dev/null; then
    return 0
  fi
  if [[ "$BIN_DIR" == "${HOME}/.local/bin" && -f "$profile_file" ]] && grep -Fq '$HOME/.local/bin' "$profile_file" 2>/dev/null; then
    return 0
  fi

  {
    printf '\n# Added by OpenKeylet installer\n'
    printf '%s\n' "$export_line"
  } >> "$profile_file"
  log "Added ${BIN_DIR} to PATH in ${profile_file}"
}

find_existing_executable() {
  if [[ -n "${OPENKEYLET_BIN:-}" && -x "${OPENKEYLET_BIN}" ]]; then
    printf '%s' "${OPENKEYLET_BIN}"
    return 0
  fi
  if [[ -x "$TARGET_EXE" ]]; then
    printf '%s' "$TARGET_EXE"
    return 0
  fi
  if [[ "$UPDATE_ONLY" -eq 1 && "$EXPLICIT_INSTALL_DIR" -eq 0 ]]; then
    if have_cmd openkeylet; then
      command -v openkeylet
      return 0
    fi
    if [[ "$OS" == "Darwin" ]]; then
      for candidate in \
        "/Applications/OpenKeylet.app/Contents/MacOS/openkeylet" \
        "${HOME}/Applications/OpenKeylet.app/Contents/MacOS/openkeylet"
      do
        if [[ -x "$candidate" ]]; then
          printf '%s' "$candidate"
          return 0
        fi
      done
    else
      if [[ -x "${HOME}/.local/share/openkeylet/openkeylet" ]]; then
        printf '%s' "${HOME}/.local/share/openkeylet/openkeylet"
        return 0
      fi
    fi
  fi
  return 1
}

run_post_install_setup() {
  local exe="$1"
  if "$exe" setup --help >/dev/null 2>&1; then
    local setup_args=(setup)
    if [[ "$NO_CONNECT" -eq 1 ]]; then
      setup_args+=(--no-connect-agents)
    fi
    for client in "${CLIENTS[@]}"; do
      setup_args+=(--client "$client")
    done
    if [[ "$SHORTCUT" -eq 1 ]]; then
      setup_args+=(--shortcut)
    fi
    if [[ "$AUTOSTART" -eq 1 ]]; then
      setup_args+=(--autostart)
    fi
    if [[ "$LAUNCH" -eq 1 ]]; then
      setup_args+=(--launch)
    fi
    if [[ "$JSON_OUTPUT" -eq 1 ]]; then
      setup_args+=(--json)
    fi
    "$exe" "${setup_args[@]}"
    return $?
  fi

  # Fallback for older pinned releases that predate `openkeylet setup`.
  local ver
  ver="$("$exe" --version 2>/dev/null || echo "unknown")"
  if [[ "$JSON_OUTPUT" -eq 1 ]]; then
    printf '{"installed":true,"version":"%s","platform":"%s","executable":"%s","note":"Installed release predates openkeylet setup; connect agents via GUI or openkeylet config stdio-json."}\n' \
      "$(json_escape "$ver")" "$(json_escape "$PLATFORM_KEY")" "$(json_escape "$exe")"
  else
    log "Installed ${ver} at ${exe}."
    log "Note: This version predates 'openkeylet setup'. Open OpenKeylet -> SYSTEM -> MCP / 02 to connect your agent, or run: ${exe} config stdio-json"
  fi
  return 0
}

try_builtin_update() {
  local exe="$1"
  if ! "$exe" update --help >/dev/null 2>&1; then
    return 2
  fi

  local update_help
  update_help="$("$exe" update install --help 2>&1 || true)"
  local supports_json=0
  local supports_relaunch=0
  if grep -Fq -- '--json' <<<"$update_help"; then
    supports_json=1
  fi
  if grep -Fq -- '--relaunch' <<<"$update_help"; then
    supports_relaunch=1
  fi

  local args=(update install)
  if [[ "$UPDATE_ONLY" -eq 1 && "$JSON_OUTPUT" -eq 1 && "$supports_json" -eq 1 ]]; then
    args+=(--json)
  fi
  if [[ "$LAUNCH" -eq 1 && "$supports_relaunch" -eq 1 ]]; then
    args+=(--relaunch)
  fi

  local out_file="${WORK_DIR}/builtin-update.out"
  local err_file="${WORK_DIR}/builtin-update.err"
  if "$exe" "${args[@]}" >"$out_file" 2>"$err_file"; then
    if [[ "$UPDATE_ONLY" -eq 1 ]]; then
      if [[ "$supports_json" -eq 0 ]]; then
        local already_up_to_date=0
        if grep -qi 'already up to date' "$out_file" 2>/dev/null; then
          already_up_to_date=1
        fi
        # Upgraded from an older release; sync managed agent rules with the new binary if available.
        local sync_out=""
        if "$exe" agent sync --help >/dev/null 2>&1; then
          sync_out="$("$exe" agent sync --json 2>/dev/null || true)"
        fi
        if [[ "$JSON_OUTPUT" -eq 1 ]]; then
          local new_ver
          new_ver="$("$exe" --version 2>/dev/null || echo "unknown")"
          if [[ "$already_up_to_date" -eq 1 ]]; then
            printf '{"updated":false,"alreadyUpToDate":true,"method":"builtin","version":"%s","executable":"%s","restartRequired":false}\n' \
              "$(json_escape "$new_ver")" "$(json_escape "$exe")"
          else
            printf '{"updated":true,"alreadyUpToDate":false,"method":"builtin","version":"%s","executable":"%s","restartRequired":true}\n' \
              "$(json_escape "$new_ver")" "$(json_escape "$exe")"
          fi
        else
          cat "$out_file"
          if [[ -n "$sync_out" ]]; then
            log "Synced connected AI agent rules."
          fi
        fi
      else
        cat "$out_file"
      fi
      return 0
    fi

    # Install command detected an existing install at TARGET_EXE and updated it cleanly.
    if [[ "$JSON_OUTPUT" -eq 0 ]]; then
      cat "$out_file" >&2
    fi
    return 0
  fi

  local err_text
  err_text="$(cat "$err_file" 2>/dev/null || true)"
  log "Built-in updater could not apply update directly: ${err_text}"
  if grep -Eq 'UPDATE_NETWORK|UPDATE_HTTP_STATUS|UPDATE_SIGNATURE_INVALID|UPDATE_CHECKSUM_MISMATCH' <<<"$err_text"; then
    # Never bypass signature, checksum, or network errors by silently overwriting.
    return 3
  fi
  return 2
}

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# 1. Update-first path: avoid duplicating installations or fighting OpenKeylet's built-in updater.
if [[ "$REINSTALL" -eq 0 && "$VERSION" == "latest" ]]; then
  if EXISTING_EXE="$(find_existing_executable)"; then
    log "Existing OpenKeylet detected at ${EXISTING_EXE}; using built-in Ed25519-signed updater..."
    set +e
    try_builtin_update "$EXISTING_EXE"
    builtin_rc=$?
    set -e
    if [[ "$builtin_rc" -eq 0 ]]; then
      if [[ "$UPDATE_ONLY" -eq 1 ]]; then
        exit 0
      fi
      if [[ "$EXISTING_EXE" == "$TARGET_EXE" ]]; then
        write_cli_wrapper "$TARGET_EXE"
        ensure_path_entry
      fi
      run_post_install_setup "$EXISTING_EXE"
      exit $?
    elif [[ "$builtin_rc" -eq 3 ]]; then
      exit 1
    else
      if [[ "$UPDATE_ONLY" -eq 1 ]]; then
        log "Falling back to verified release archive installation..."
      fi
    fi
  elif [[ "$UPDATE_ONLY" -eq 1 ]]; then
    log "No existing OpenKeylet installation found; installing latest official release..."
  fi
fi

# 2. Resolve release manifest & verify Ed25519 signature + URL origin.
CUSTOM_MANIFEST_URL="${OPENKEYLET_UPDATE_MANIFEST_URL:-}"
if [[ -n "$CUSTOM_MANIFEST_URL" ]]; then
  MANIFEST_URL="$CUSTOM_MANIFEST_URL"
  EFFECTIVE_PUBKEY="${OPENKEYLET_UPDATE_PUBLIC_KEY:-$OFFICIAL_UPDATE_PUBLIC_KEY}"
  ALLOW_CUSTOM_ORIGIN=1
else
  EFFECTIVE_PUBKEY="$OFFICIAL_UPDATE_PUBLIC_KEY"
  ALLOW_CUSTOM_ORIGIN=0
  if [[ "$VERSION" == "latest" ]]; then
    MANIFEST_URL="${OFFICIAL_RELEASE_PREFIX}latest/download/latest.json"
    SUMS_URL="${OFFICIAL_RELEASE_PREFIX}latest/download/SHA256SUMS.txt"
  else
    MANIFEST_URL="${OFFICIAL_RELEASE_PREFIX}download/${VERSION}/latest.json"
    SUMS_URL="${OFFICIAL_RELEASE_PREFIX}download/${VERSION}/SHA256SUMS.txt"
  fi
fi

MANIFEST_FILE="${WORK_DIR}/latest.json"
SIGNATURE_VERIFIED=0
ASSET_URL=""
ASSET_SHA256=""
ASSET_SIZE=""
ASSET_FORMAT=""
RELEASE_VERSION=""

resolve_from_manifest_with_node() {
  OPENKEYLET_MANIFEST_FILE="$MANIFEST_FILE" \
  OPENKEYLET_PLATFORM_KEY="$PLATFORM_KEY" \
  OPENKEYLET_PUBKEY_B64="$EFFECTIVE_PUBKEY" \
  OPENKEYLET_ENVELOPE_FORMAT="$ENVELOPE_FORMAT" \
  OPENKEYLET_OFFICIAL_PREFIX="$OFFICIAL_RELEASE_PREFIX" \
  OPENKEYLET_CUSTOM_MANIFEST_URL="$CUSTOM_MANIFEST_URL" \
  node -e '
    const crypto = require("node:crypto");
    const fs = require("node:fs");
    const envelope = JSON.parse(fs.readFileSync(process.env.OPENKEYLET_MANIFEST_FILE, "utf8"));
    const fmt = process.env.OPENKEYLET_ENVELOPE_FORMAT;
    if (envelope.format !== fmt) {
      throw new Error(`Unsupported manifest format: ${envelope.format}`);
    }
    const rawPub = Buffer.from(process.env.OPENKEYLET_PUBKEY_B64.trim(), "base64");
    if (rawPub.length !== 32) throw new Error("Invalid Ed25519 public key length");
    const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
    const pubKey = crypto.createPublicKey({ key: Buffer.concat([spkiPrefix, rawPub]), format: "der", type: "spki" });
    const sig = Buffer.from(String(envelope.signature || "").trim(), "base64");
    const msg = Buffer.from(`${fmt}\n${envelope.payload}`, "utf8");
    if (!crypto.verify(null, msg, pubKey, sig)) {
      throw new Error("Ed25519 signature verification failed for latest.json");
    }
    const manifest = JSON.parse(envelope.payload);
    if (manifest.schemaVersion !== 1) {
      throw new Error(`Unsupported manifest schemaVersion: ${manifest.schemaVersion}`);
    }
    const platformKey = process.env.OPENKEYLET_PLATFORM_KEY;
    const asset = manifest.platforms && manifest.platforms[platformKey];
    if (!asset) {
      const available = Object.keys(manifest.platforms || {}).join(", ");
      throw new Error(`No published release archive for platform "${platformKey}" (available: ${available})`);
    }
    const customUrl = process.env.OPENKEYLET_CUSTOM_MANIFEST_URL || "";
    const officialPrefix = process.env.OPENKEYLET_OFFICIAL_PREFIX;
    const parsedAsset = new URL(asset.url);
    let urlOk = asset.url.startsWith(officialPrefix) && parsedAsset.protocol === "https:";
    if (!urlOk && customUrl) {
      const parsedCustom = new URL(customUrl);
      urlOk = parsedAsset.origin === parsedCustom.origin && (parsedAsset.protocol === "http:" || parsedAsset.protocol === "https:");
    }
    if (!urlOk) {
      throw new Error(`Refusing asset URL outside official GitHub Releases: ${asset.url}`);
    }
    if (!/^[0-9a-f]{64}$/i.test(String(asset.sha256 || ""))) {
      throw new Error("Invalid SHA-256 in release manifest");
    }
    process.stdout.write([
      manifest.version || "",
      asset.url,
      String(asset.sha256).toLowerCase(),
      String(asset.size || ""),
      String(asset.format || ""),
      "1"
    ].join("\t"));
  '
}

resolve_from_manifest_with_python() {
  OPENKEYLET_MANIFEST_FILE="$MANIFEST_FILE" \
  OPENKEYLET_PLATFORM_KEY="$PLATFORM_KEY" \
  OPENKEYLET_ENVELOPE_FORMAT="$ENVELOPE_FORMAT" \
  OPENKEYLET_OFFICIAL_PREFIX="$OFFICIAL_RELEASE_PREFIX" \
  OPENKEYLET_CUSTOM_MANIFEST_URL="$CUSTOM_MANIFEST_URL" \
  python3 -c '
import json, os, re, urllib.parse
with open(os.environ["OPENKEYLET_MANIFEST_FILE"], "r", encoding="utf-8") as fh:
    env = json.load(fh)
if env.get("format") != os.environ["OPENKEYLET_ENVELOPE_FORMAT"]:
    raise SystemExit(f"Unsupported manifest format: {env.get(\"format\")}")
manifest = json.loads(env["payload"])
if manifest.get("schemaVersion") != 1:
    raise SystemExit(f"Unsupported schemaVersion: {manifest.get(\"schemaVersion\")}")
key = os.environ["OPENKEYLET_PLATFORM_KEY"]
platforms = manifest.get("platforms") or {}
if key not in platforms:
    raise SystemExit(f"No published release archive for platform \"{key}\" (available: {\", \".join(sorted(platforms))})")
asset = platforms[key]
url = str(asset["url"])
official_prefix = os.environ["OPENKEYLET_OFFICIAL_PREFIX"]
custom_url = os.environ.get("OPENKEYLET_CUSTOM_MANIFEST_URL", "")
parsed = urllib.parse.urlparse(url)
url_ok = url.startswith(official_prefix) and parsed.scheme == "https"
if not url_ok and custom_url:
    cp = urllib.parse.urlparse(custom_url)
    url_ok = parsed.scheme in ("http", "https") and parsed.netloc == cp.netloc and parsed.scheme == cp.scheme
if not url_ok:
    raise SystemExit(f"Refusing asset URL outside official GitHub Releases: {url}")
sha = str(asset.get("sha256", "")).lower()
if not re.fullmatch(r"[0-9a-f]{64}", sha):
    raise SystemExit("Invalid SHA-256 in release manifest")
print("\t".join([str(manifest.get("version", "")), url, sha, str(asset.get("size", "")), str(asset.get("format", "")), "0"]), end="")
'
}

resolve_from_sha256sums() {
  local sums_file="${WORK_DIR}/SHA256SUMS.txt"
  download_file "$SUMS_URL" "$sums_file" || die "Unable to fetch release checksums from ${SUMS_URL}"
  local pattern=""
  case "$PLATFORM_KEY" in
    macos-arm64) pattern='_macos-arm64-portable\.zip$' ;;
    macos-x64) pattern='_macos-x64-portable\.zip$' ;;
    linux-x64-gui) pattern='_linux-x64-portable\.tar\.gz$' ;;
    linux-arm64-gui) pattern='_linux-arm64-portable\.tar\.gz$' ;;
    linux-x64-headless) pattern='_linux-headless-x64\.tar\.gz$' ;;
    linux-arm64-headless) pattern='_linux-headless-arm64\.tar\.gz$' ;;
    *) die "Unsupported platform key: ${PLATFORM_KEY}" ;;
  esac
  local matched
  matched="$(grep -E "$pattern" "$sums_file" | head -n 1 || true)"
  [[ -n "$matched" ]] || die "No release archive matching ${PLATFORM_KEY} found in SHA256SUMS.txt"
  ASSET_SHA256="$(awk '{print tolower($1)}' <<<"$matched")"
  local filename
  filename="$(awk '{print $2}' <<<"$matched")"
  if [[ "$VERSION" == "latest" ]]; then
    ASSET_URL="${OFFICIAL_RELEASE_PREFIX}latest/download/${filename}"
  else
    ASSET_URL="${OFFICIAL_RELEASE_PREFIX}download/${VERSION}/${filename}"
  fi
  ASSET_FORMAT="$ARCHIVE_FORMAT"
  RELEASE_VERSION="${VERSION#v}"
  SIGNATURE_VERIFIED=0
}

log "Checking OpenKeylet release metadata (${PLATFORM_KEY})..."
if download_file "$MANIFEST_URL" "$MANIFEST_FILE" 2>/dev/null; then
  if have_cmd node; then
    IFS=$'\t' read -r RELEASE_VERSION ASSET_URL ASSET_SHA256 ASSET_SIZE ASSET_FORMAT SIGNATURE_VERIFIED < <(resolve_from_manifest_with_node)
    log "Verified Ed25519 signature for OpenKeylet ${RELEASE_VERSION}."
  elif [[ "$REQUIRE_SIGNATURE" -eq 1 ]]; then
    die "--require-signature was requested, but Node.js is not installed to verify the Ed25519 manifest signature."
  elif have_cmd python3; then
    IFS=$'\t' read -r RELEASE_VERSION ASSET_URL ASSET_SHA256 ASSET_SIZE ASSET_FORMAT SIGNATURE_VERIFIED < <(resolve_from_manifest_with_python)
    log "Parsed latest.json for OpenKeylet ${RELEASE_VERSION} (SHA-256 will be verified; built-in updater enforces Ed25519 for future updates)."
  elif [[ "$ALLOW_CUSTOM_ORIGIN" -eq 0 ]]; then
    resolve_from_sha256sums
  else
    die "Node.js or python3 is required to parse custom manifest ${MANIFEST_URL}."
  fi
else
  if [[ "$REQUIRE_SIGNATURE" -eq 1 || "$ALLOW_CUSTOM_ORIGIN" -eq 1 ]]; then
    die "Unable to download signed manifest from ${MANIFEST_URL}."
  fi
  log "Signed manifest latest.json not found for ${VERSION}; falling back to official SHA256SUMS.txt..."
  resolve_from_sha256sums
fi

# 3. Download archive & verify size + SHA-256.
ARCHIVE_PATH="${WORK_DIR}/openkeylet.${ASSET_FORMAT}"
log "Downloading ${ASSET_URL}..."
download_file "$ASSET_URL" "$ARCHIVE_PATH"

if [[ -n "$ASSET_SIZE" ]]; then
  ACTUAL_SIZE="$(file_size_bytes "$ARCHIVE_PATH")"
  if [[ "$ACTUAL_SIZE" != "$ASSET_SIZE" ]]; then
    die "Downloaded archive size mismatch (got ${ACTUAL_SIZE} bytes, expected ${ASSET_SIZE} bytes)."
  fi
fi

ACTUAL_SHA256="$(sha256_file "$ARCHIVE_PATH")"
if [[ "$ACTUAL_SHA256" != "$ASSET_SHA256" ]]; then
  die "SHA-256 checksum mismatch (got ${ACTUAL_SHA256}, expected ${ASSET_SHA256})."
fi
log "Verified archive SHA-256 (${ACTUAL_SHA256})."

# 4. Extract & verify internal package checksums + macOS codesign.
EXTRACT_DIR="${WORK_DIR}/extracted"
mkdir -p "$EXTRACT_DIR"
case "$ASSET_FORMAT" in
  zip)
    if [[ "$OS" == "Darwin" ]]; then
      /usr/bin/ditto -x -k "$ARCHIVE_PATH" "$EXTRACT_DIR"
    elif have_cmd unzip; then
      unzip -q "$ARCHIVE_PATH" -d "$EXTRACT_DIR"
    else
      die "unzip is required to extract ${ARCHIVE_PATH}."
    fi
    ;;
  tar.gz)
    tar -xzf "$ARCHIVE_PATH" -C "$EXTRACT_DIR"
    ;;
  *)
    die "Unsupported archive format: ${ASSET_FORMAT}"
    ;;
esac

PACKAGE_ROOT=""
while IFS= read -r dir; do
  if [[ -f "${dir}/SHA256SUMS.txt" ]]; then
    PACKAGE_ROOT="$dir"
    break
  fi
done < <(find "$EXTRACT_DIR" -mindepth 1 -maxdepth 1 -type d ! -name '__MACOSX' -print | sort)

[[ -n "$PACKAGE_ROOT" ]] || die "Expected OpenKeylet package directory was not found inside archive."

(
  cd "$PACKAGE_ROOT"
  if [[ "$OS" == "Darwin" ]]; then
    shasum -a 256 -c SHA256SUMS.txt >/dev/null
  else
    sha256sum -c SHA256SUMS.txt >/dev/null
  fi
)
log "Verified internal package file checksums."

# 5. Atomic in-place installation.
if [[ "$OS" == "Darwin" ]]; then
  STAGED_APP="${PACKAGE_ROOT}/OpenKeylet.app"
  [[ -x "${STAGED_APP}/Contents/MacOS/openkeylet" ]] || die "OpenKeylet.app missing from macOS archive."
  if [[ -z "${OPENKEYLET_SKIP_CODESIGN_VERIFY:-}" ]]; then
    /usr/bin/codesign --verify --deep --strict "$STAGED_APP" || die "OpenKeylet.app failed macOS codesign verification."
  fi
  mkdir -p "$INSTALL_DIR"
  TARGET_APP="${INSTALL_DIR}/OpenKeylet.app"
  TEMP_APP="${INSTALL_DIR}/OpenKeylet.app.new.$$"
  BACKUP_APP="${INSTALL_DIR}/OpenKeylet.app.old.$$"
  rm -rf "$TEMP_APP" "$BACKUP_APP"
  /usr/bin/ditto "$STAGED_APP" "$TEMP_APP"
  if [[ -e "$TARGET_APP" ]]; then
    mv "$TARGET_APP" "$BACKUP_APP"
  fi
  if ! mv "$TEMP_APP" "$TARGET_APP"; then
    if [[ -e "$BACKUP_APP" ]]; then
      mv "$BACKUP_APP" "$TARGET_APP" || true
    fi
    rm -rf "$TEMP_APP"
    die "Failed to move OpenKeylet.app into ${INSTALL_DIR}."
  fi
  rm -rf "$BACKUP_APP"
  INSTALLED_EXE="${TARGET_APP}/Contents/MacOS/openkeylet"
else
  mkdir -p "$INSTALL_DIR"
  if [[ "$PLATFORM_KEY" == *-gui ]]; then
    [[ -f "${PACKAGE_ROOT}/OpenKeylet.AppImage" ]] || die "OpenKeylet.AppImage missing from Linux GUI archive."
    [[ -f "${PACKAGE_ROOT}/openkeylet" ]] || die "openkeylet launcher missing from Linux GUI archive."
    cp "${PACKAGE_ROOT}/OpenKeylet.AppImage" "${INSTALL_DIR}/.OpenKeylet.AppImage.new.$$"
    chmod 755 "${INSTALL_DIR}/.OpenKeylet.AppImage.new.$$"
    mv -f "${INSTALL_DIR}/.OpenKeylet.AppImage.new.$$" "${INSTALL_DIR}/OpenKeylet.AppImage"

    cp "${PACKAGE_ROOT}/openkeylet" "${INSTALL_DIR}/.openkeylet.new.$$"
    chmod 755 "${INSTALL_DIR}/.openkeylet.new.$$"
    mv -f "${INSTALL_DIR}/.openkeylet.new.$$" "${INSTALL_DIR}/openkeylet"
  else
    [[ -f "${PACKAGE_ROOT}/openkeylet" ]] || die "openkeylet binary missing from Linux headless archive."
    cp "${PACKAGE_ROOT}/openkeylet" "${INSTALL_DIR}/.openkeylet.new.$$"
    chmod 755 "${INSTALL_DIR}/.openkeylet.new.$$"
    mv -f "${INSTALL_DIR}/.openkeylet.new.$$" "${INSTALL_DIR}/openkeylet"
  fi

  if [[ -d "${PACKAGE_ROOT}/browser-extension" ]]; then
    TEMP_EXT="${INSTALL_DIR}/browser-extension.new.$$"
    BACKUP_EXT="${INSTALL_DIR}/browser-extension.old.$$"
    rm -rf "$TEMP_EXT" "$BACKUP_EXT"
    cp -R "${PACKAGE_ROOT}/browser-extension" "$TEMP_EXT"
    if [[ -e "${INSTALL_DIR}/browser-extension" ]]; then
      mv "${INSTALL_DIR}/browser-extension" "$BACKUP_EXT"
    fi
    if ! mv "$TEMP_EXT" "${INSTALL_DIR}/browser-extension"; then
      if [[ -e "$BACKUP_EXT" ]]; then
        mv "$BACKUP_EXT" "${INSTALL_DIR}/browser-extension" || true
      fi
      rm -rf "$TEMP_EXT"
      die "Failed to update browser-extension directory."
    fi
    rm -rf "$BACKUP_EXT"
  fi

  for doc_file in README.md README.zh-CN.md SECURITY.md SECURITY.zh-CN.md LICENSE SHA256SUMS.txt; do
    if [[ -f "${PACKAGE_ROOT}/${doc_file}" ]]; then
      cp "${PACKAGE_ROOT}/${doc_file}" "${INSTALL_DIR}/${doc_file}"
    fi
  done
  INSTALLED_EXE="${INSTALL_DIR}/openkeylet"
fi

write_cli_wrapper "$INSTALLED_EXE"
ensure_path_entry
log "Installed OpenKeylet at ${INSTALLED_EXE} (CLI wrapper: ${BIN_DIR}/openkeylet)."

# 6. Post-install setup (cleans any stale pending-update markers & connects detected agents).
run_post_install_setup "$INSTALLED_EXE"
