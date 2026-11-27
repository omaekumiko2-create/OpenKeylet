<#
.SYNOPSIS
  OpenKeylet Windows installer & update helper.
.DESCRIPTION
  - Verifies Ed25519 release signature (via Node.js when available) + SHA-256 checksums.
  - Installs to a canonical user-writable path (%LOCALAPPDATA%\Programs\OpenKeylet) compatible
    with OpenKeylet's built-in Ed25519-signed in-place auto-updater.
  - Delegates updates on existing installations to `openkeylet update install` so CLI/agent
    updates never conflict with GUI auto-updates or duplicate portable directories.
#>
[CmdletBinding()]
param(
  [string]$InstallDir = "",
  [string]$Version = "latest",
  [switch]$Update,
  [switch]$Reinstall,
  [switch]$NoConnect,
  [string[]]$Client = @(),
  [switch]$Shortcut,
  [switch]$Autostart,
  [switch]$Launch,
  [switch]$NoPath,
  [switch]$RequireSignature,
  [switch]$Json
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Repo = "omaekumiko2-create/OpenKeylet"
$OfficialReleasePrefix = "https://github.com/$Repo/releases/"
$OfficialUpdatePublicKey = "uCBOtL43FyR7FSOGo9eo+MzKfxX7oSb+ZWQb7oGcrfM="
$EnvelopeFormat = "openkeylet-update-v1"

$ExplicitInstallDir = -not [string]::IsNullOrWhiteSpace($InstallDir)
if (-not $ExplicitInstallDir) {
  $localAppData = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { Join-Path $HOME "AppData\Local" }
  $InstallDir = Join-Path $localAppData "Programs\OpenKeylet"
}
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
$TargetExe = Join-Path $InstallDir "openkeylet.exe"

$PlatformKey = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "windows-arm64" } else { "windows-x64" }

function Write-Log([string]$Message) {
  [Console]::Error.WriteLine($Message)
}

function Get-FileSha256([string]$Path) {
  return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Find-ExistingExecutable {
  if ($env:OPENKEYLET_BIN -and (Test-Path -LiteralPath $env:OPENKEYLET_BIN -PathType Leaf)) {
    return [System.IO.Path]::GetFullPath($env:OPENKEYLET_BIN)
  }
  if (Test-Path -LiteralPath $TargetExe -PathType Leaf) {
    return $TargetExe
  }
  if ($Update -and -not $ExplicitInstallDir) {
    $cmd = Get-Command openkeylet -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -and (Test-Path -LiteralPath $cmd.Source -PathType Leaf)) {
      return [System.IO.Path]::GetFullPath($cmd.Source)
    }
  }
  return $null
}

function Add-ToUserPath([string]$Directory) {
  if ($NoPath) { return }
  $normalizedTarget = $Directory.TrimEnd('\')
  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  $entries = @()
  if (-not [string]::IsNullOrWhiteSpace($userPath)) {
    $entries = @($userPath -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  }
  $alreadyPresent = $entries | Where-Object { $_.TrimEnd('\').Equals($normalizedTarget, [System.StringComparison]::OrdinalIgnoreCase) }
  if (-not $alreadyPresent) {
    $updated = ($entries + $Directory) -join ';'
    [Environment]::SetEnvironmentVariable("Path", $updated, "User")
    Write-Log "Added $Directory to User PATH."
  }
  $procEntries = @($env:PATH -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  $inProc = $procEntries | Where-Object { $_.TrimEnd('\').Equals($normalizedTarget, [System.StringComparison]::OrdinalIgnoreCase) }
  if (-not $inProc) {
    $env:PATH = "$Directory;$env:PATH"
  }
}

function Invoke-OpenKeyletCapture([string]$ExePath, [string[]]$ArgList) {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $ExePath
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  $escapedArgs = foreach ($a in $ArgList) {
    if ($a -match '[\s"]') { '"' + ($a -replace '(\\*)"', '$1$1\"') + '"' } else { $a }
  }
  $psi.Arguments = ($escapedArgs -join ' ')
  $proc = [System.Diagnostics.Process]::Start($psi)
  $stdout = $proc.StandardOutput.ReadToEnd()
  $stderr = $proc.StandardError.ReadToEnd()
  $proc.WaitForExit()
  return [PSCustomObject]@{
    ExitCode = $proc.ExitCode
    Stdout   = $stdout
    Stderr   = $stderr
  }
}

function Invoke-PostInstallSetup([string]$ExePath) {
  $helpCheck = Invoke-OpenKeyletCapture $ExePath @("setup", "--help")
  if ($helpCheck.ExitCode -eq 0) {
    $setupArgs = @("setup")
    if ($NoConnect) { $setupArgs += "--no-connect-agents" }
    foreach ($c in $Client) {
      if (-not [string]::IsNullOrWhiteSpace($c)) {
        $setupArgs += "--client"
        $setupArgs += $c
      }
    }
    if ($Shortcut) { $setupArgs += "--shortcut" }
    if ($Autostart) { $setupArgs += "--autostart" }
    if ($Launch) { $setupArgs += "--launch" }
    if ($Json) { $setupArgs += "--json" }
    $res = Invoke-OpenKeyletCapture $ExePath $setupArgs
    if ($res.Stderr) { [Console]::Error.Write($res.Stderr) }
    if ($res.Stdout) { [Console]::Out.Write($res.Stdout) }
    return [int]$res.ExitCode
  }

  $verResult = Invoke-OpenKeyletCapture $ExePath @("--version")
  $ver = $verResult.Stdout.Trim()
  if ($Json) {
    $fallbackJson = @{
      installed  = $true
      version    = $ver
      platform   = $PlatformKey
      executable = $ExePath
      note       = "Installed release predates openkeylet setup; connect agents via GUI or openkeylet config stdio-json."
    } | ConvertTo-Json -Depth 4
    [Console]::Out.WriteLine($fallbackJson)
  } else {
    Write-Log "Installed $ver at $ExePath."
    Write-Log "Note: This release predates 'openkeylet setup'. Open OpenKeylet -> SYSTEM -> MCP / 02 or run: $ExePath config stdio-json"
  }
  return 0
}

function Try-BuiltinUpdate([string]$ExePath) {
  $updateHelp = Invoke-OpenKeyletCapture $ExePath @("update", "install", "--help")
  if ($updateHelp.ExitCode -ne 0) {
    return "fallback"
  }
  $helpText = "$($updateHelp.Stdout)`n$($updateHelp.Stderr)"
  $supportsJson = $helpText -match '--json'
  $supportsRelaunch = $helpText -match '--relaunch'

  $updateArgs = @("update", "install")
  if ($Update -and $Json -and $supportsJson) { $updateArgs += "--json" }
  if ($Launch -and $supportsRelaunch) { $updateArgs += "--relaunch" }

  $res = Invoke-OpenKeyletCapture $ExePath $updateArgs
  if ($res.ExitCode -eq 0) {
    if ($Update) {
      if (-not $supportsJson) {
        $alreadyUpToDate = $res.Stdout -match 'already up to date'
        $syncHelp = Invoke-OpenKeyletCapture $ExePath @("agent", "sync", "--help")
        if ($syncHelp.ExitCode -eq 0) {
          $null = Invoke-OpenKeyletCapture $ExePath @("agent", "sync", "--json")
        }
        if ($Json) {
          $newVer = (Invoke-OpenKeyletCapture $ExePath @("--version")).Stdout.Trim()
          $compatJson = @{
            updated         = (-not $alreadyUpToDate)
            alreadyUpToDate = $alreadyUpToDate
            method          = "builtin"
            version         = $newVer
            executable      = $ExePath
            restartRequired = (-not $alreadyUpToDate)
          } | ConvertTo-Json -Depth 4
          [Console]::Out.WriteLine($compatJson)
        } else {
          if ($res.Stdout) { [Console]::Out.Write($res.Stdout) }
        }
      } else {
        if ($res.Stdout) { [Console]::Out.Write($res.Stdout) }
      }
      return "done"
    }
    if (-not $Json -and $res.Stdout) {
      Write-Log $res.Stdout.Trim()
    }
    return "done"
  }

  $errText = "$($res.Stderr)`n$($res.Stdout)".Trim()
  Write-Log "Built-in updater could not apply update directly: $errText"
  if ($errText -match 'UPDATE_NETWORK|UPDATE_HTTP_STATUS|UPDATE_SIGNATURE_INVALID|UPDATE_CHECKSUM_MISMATCH') {
    return "fatal"
  }
  return "fallback"
}

function Verify-ManifestSignatureWithNode([string]$ManifestPath, [string]$PubKeyB64, [string]$TempDir) {
  $nodeCmd = Get-Command node -ErrorAction SilentlyContinue
  if (-not $nodeCmd) {
    return $false
  }
  $verifyScript = Join-Path $TempDir "verify-manifest.cjs"
  $js = @'
const crypto = require("node:crypto");
const fs = require("node:fs");
const env = JSON.parse(fs.readFileSync(process.env.OPENKEYLET_MANIFEST_FILE, "utf8"));
const fmt = process.env.OPENKEYLET_ENVELOPE_FORMAT;
if (env.format !== fmt) throw new Error("Unexpected manifest format");
const rawPub = Buffer.from(process.env.OPENKEYLET_PUBKEY_B64.trim(), "base64");
if (rawPub.length !== 32) throw new Error("Invalid Ed25519 public key length");
const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
const pubKey = crypto.createPublicKey({ key: Buffer.concat([spkiPrefix, rawPub]), format: "der", type: "spki" });
const sig = Buffer.from(String(env.signature || "").trim(), "base64");
const msg = Buffer.from(`${fmt}\n${env.payload}`, "utf8");
if (!crypto.verify(null, msg, pubKey, sig)) {
  throw new Error("Ed25519 signature verification failed for latest.json");
}
'@
  Set-Content -LiteralPath $verifyScript -Value $js -Encoding UTF8
  $env:OPENKEYLET_MANIFEST_FILE = $ManifestPath
  $env:OPENKEYLET_PUBKEY_B64 = $PubKeyB64
  $env:OPENKEYLET_ENVELOPE_FORMAT = $EnvelopeFormat
  try {
    & $nodeCmd.Source $verifyScript
    if ($LASTEXITCODE -ne 0) {
      throw "Ed25519 signature verification failed for latest.json."
    }
    return $true
  } finally {
    Remove-Item -LiteralPath $verifyScript -Force -ErrorAction SilentlyContinue
    Remove-Item Env:OPENKEYLET_MANIFEST_FILE -ErrorAction SilentlyContinue
    Remove-Item Env:OPENKEYLET_PUBKEY_B64 -ErrorAction SilentlyContinue
    Remove-Item Env:OPENKEYLET_ENVELOPE_FORMAT -ErrorAction SilentlyContinue
  }
}

function Test-AllowedAssetUrl([string]$AssetUrl, [string]$CustomManifestUrl) {
  $uri = [Uri]$AssetUrl
  if ($AssetUrl.StartsWith($OfficialReleasePrefix, [System.StringComparison]::OrdinalIgnoreCase) -and $uri.Scheme -eq "https") {
    return $true
  }
  if (-not [string]::IsNullOrWhiteSpace($CustomManifestUrl)) {
    $customUri = [Uri]$CustomManifestUrl
    if (($uri.Scheme -eq "http" -or $uri.Scheme -eq "https") -and $uri.Scheme -eq $customUri.Scheme -and $uri.Authority -eq $customUri.Authority) {
      return $true
    }
  }
  return $false
}

function Replace-FileSafe([string]$TargetPath, [string]$SourcePath) {
  $parent = Split-Path -Parent $TargetPath
  $leaf = Split-Path -Leaf $TargetPath
  $tempNew = Join-Path $parent "$leaf.new.$PID"
  $backupOld = Join-Path $parent "$leaf.old.$PID.$([guid]::NewGuid().ToString('N'))"

  Copy-Item -LiteralPath $SourcePath -Destination $tempNew -Force
  if (Test-Path -LiteralPath $TargetPath) {
    try {
      Move-Item -LiteralPath $TargetPath -Destination $backupOld -Force
    } catch {
      Remove-Item -LiteralPath $tempNew -Force -ErrorAction SilentlyContinue
      throw "Unable to move running executable aside: $_"
    }
  }
  try {
    Move-Item -LiteralPath $tempNew -Destination $TargetPath -Force
  } catch {
    if (Test-Path -LiteralPath $backupOld) {
      Move-Item -LiteralPath $backupOld -Destination $TargetPath -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $tempNew -Force -ErrorAction SilentlyContinue
    throw "Unable to place updated executable: $_"
  }
  Remove-Item -LiteralPath $backupOld -Force -ErrorAction SilentlyContinue
}

# 1. Update-first path: delegate to built-in Ed25519 updater so CLI/agent updates never conflict with GUI updates.
if (-not $Reinstall -and $Version -eq "latest") {
  $existingExe = Find-ExistingExecutable
  if ($existingExe) {
    Write-Log "Existing OpenKeylet detected at $existingExe; using built-in Ed25519-signed updater..."
    $status = Try-BuiltinUpdate $existingExe
    if ($status -eq "done") {
      if ($Update) {
        exit 0
      }
      if ($existingExe.Equals($TargetExe, [System.StringComparison]::OrdinalIgnoreCase)) {
        Add-ToUserPath $InstallDir
      }
      $setupCode = Invoke-PostInstallSetup $existingExe
      exit $setupCode
    } elseif ($status -eq "fatal") {
      exit 1
    } else {
      Write-Log "Falling back to verified release archive installation..."
    }
  } elseif ($Update) {
    Write-Log "No existing OpenKeylet installation found; installing latest official release..."
  }
}

# 2. Fetch and verify release manifest.
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("openkeylet-install-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $workDir -Force | Out-Null

try {
  $customManifestUrl = if ($env:OPENKEYLET_UPDATE_MANIFEST_URL) { $env:OPENKEYLET_UPDATE_MANIFEST_URL.Trim() } else { "" }
  if ($customManifestUrl) {
    $manifestUrl = $customManifestUrl
    $effectivePubKey = if ($env:OPENKEYLET_UPDATE_PUBLIC_KEY) { $env:OPENKEYLET_UPDATE_PUBLIC_KEY.Trim() } else { $OfficialUpdatePublicKey }
    $sumsUrl = ""
  } else {
    $effectivePubKey = $OfficialUpdatePublicKey
    if ($Version -eq "latest") {
      $manifestUrl = "${OfficialReleasePrefix}latest/download/latest.json"
      $sumsUrl = "${OfficialReleasePrefix}latest/download/SHA256SUMS.txt"
    } else {
      $manifestUrl = "${OfficialReleasePrefix}download/$Version/latest.json"
      $sumsUrl = "${OfficialReleasePrefix}download/$Version/SHA256SUMS.txt"
    }
  }

  $manifestPath = Join-Path $workDir "latest.json"
  $assetUrl = $null
  $assetSha256 = $null
  $assetSize = $null
  $releaseVersion = $Version.TrimStart('v')
  $manifestDownloaded = $false

  Write-Log "Checking OpenKeylet release metadata ($PlatformKey)..."
  try {
    Invoke-WebRequest -Uri $manifestUrl -OutFile $manifestPath -UseBasicParsing
    $manifestDownloaded = $true
  } catch {
    if ($RequireSignature -or $customManifestUrl) {
      throw "Unable to download signed manifest from ${manifestUrl}: $_"
    }
    Write-Log "Signed manifest latest.json not found for $Version; falling back to official SHA256SUMS.txt..."
  }

  if ($manifestDownloaded) {
    $sigVerified = Verify-ManifestSignatureWithNode $manifestPath $effectivePubKey $workDir
    if ($sigVerified) {
      Write-Log "Verified Ed25519 signature for latest.json."
    } elseif ($RequireSignature) {
      throw "-RequireSignature was specified, but Node.js is not available to verify the Ed25519 signature."
    } else {
      Write-Log "Node.js not found; verifying SHA-256 against official GitHub Releases (built-in updater enforces Ed25519 for future updates)."
    }

    $envelope = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($envelope.format -ne $EnvelopeFormat) {
      throw "Unsupported manifest format: $($envelope.format)"
    }
    $manifest = $envelope.payload | ConvertFrom-Json
    if ([int]$manifest.schemaVersion -ne 1) {
      throw "Unsupported manifest schemaVersion: $($manifest.schemaVersion)"
    }
    $releaseVersion = [string]$manifest.version
    $platformProp = $manifest.platforms.PSObject.Properties[$PlatformKey]
    if (-not $platformProp) {
      $avail = ($manifest.platforms.PSObject.Properties | ForEach-Object { $_.Name }) -join ", "
      throw "No published release archive for platform '$PlatformKey' (available: $avail)"
    }
    $asset = $platformProp.Value
    $assetUrl = [string]$asset.url
    $assetSha256 = ([string]$asset.sha256).ToLowerInvariant()
    $assetSize = [int64]$asset.size
    if (-not (Test-AllowedAssetUrl $assetUrl $customManifestUrl)) {
      throw "Refusing asset URL outside official GitHub Releases: $assetUrl"
    }
    if ($assetSha256 -notmatch '^[0-9a-f]{64}$') {
      throw "Malformed SHA-256 checksum in release manifest."
    }
  } else {
    $sumsPath = Join-Path $workDir "SHA256SUMS.txt"
    Invoke-WebRequest -Uri $sumsUrl -OutFile $sumsPath -UseBasicParsing
    $suffix = "${PlatformKey}-portable.zip"
    $line = Get-Content -LiteralPath $sumsPath | Where-Object { $_ -match ([regex]::Escape($suffix) + '$') } | Select-Object -First 1
    if (-not $line) {
      throw "No archive matching $suffix found in SHA256SUMS.txt."
    }
    $parts = $line.Trim() -split '\s+', 2
    $assetSha256 = $parts[0].ToLowerInvariant()
    $fileName = $parts[1].Trim()
    $assetUrl = if ($Version -eq "latest") {
      "${OfficialReleasePrefix}latest/download/$fileName"
    } else {
      "${OfficialReleasePrefix}download/$Version/$fileName"
    }
  }

  # 3. Download archive & verify size + SHA-256.
  $archivePath = Join-Path $workDir "openkeylet.zip"
  Write-Log "Downloading $assetUrl..."
  Invoke-WebRequest -Uri $assetUrl -OutFile $archivePath -UseBasicParsing

  if ($null -ne $assetSize -and $assetSize -gt 0) {
    $actualSize = (Get-Item -LiteralPath $archivePath).Length
    if ($actualSize -ne $assetSize) {
      throw "Downloaded archive size mismatch (got $actualSize bytes, expected $assetSize bytes)."
    }
  }
  $actualSha = Get-FileSha256 $archivePath
  if ($actualSha -ne $assetSha256) {
    throw "Archive SHA-256 checksum mismatch (got $actualSha, expected $assetSha256)."
  }
  Write-Log "Verified archive SHA-256 ($actualSha)."

  # 4. Extract & verify internal package SHA256SUMS.txt.
  $extractDir = Join-Path $workDir "extracted"
  Expand-Archive -LiteralPath $archivePath -DestinationPath $extractDir -Force
  $pkgRoot = $null
  if (Test-Path -LiteralPath (Join-Path $extractDir "openkeylet.exe") -PathType Leaf) {
    $pkgRoot = $extractDir
  } else {
    $pkgRoot = (Get-ChildItem -LiteralPath $extractDir -Directory | Where-Object {
      Test-Path -LiteralPath (Join-Path $_.FullName "openkeylet.exe") -PathType Leaf
    } | Select-Object -First 1).FullName
  }
  if (-not $pkgRoot) {
    throw "openkeylet.exe was not found inside the downloaded archive."
  }

  $internalSums = Join-Path $pkgRoot "SHA256SUMS.txt"
  if (Test-Path -LiteralPath $internalSums -PathType Leaf) {
    Get-Content -LiteralPath $internalSums | ForEach-Object {
      if ($_ -match '^([0-9a-fA-F]{64})  (.+)$') {
        $relPath = $Matches[2] -replace '/', '\'
        $fullPath = Join-Path $pkgRoot $relPath
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
          throw "Missing checksummed package file: $($Matches[2])"
        }
        $fileHash = Get-FileSha256 $fullPath
        if ($fileHash -ne $Matches[1].ToLowerInvariant()) {
          throw "Internal package checksum mismatch: $($Matches[2])"
        }
      }
    }
    Write-Log "Verified internal package file checksums."
  }

  # 5. Atomic in-place installation.
  New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
  Replace-FileSafe $TargetExe (Join-Path $pkgRoot "openkeylet.exe")

  $srcExt = Join-Path $pkgRoot "browser-extension"
  if (Test-Path -LiteralPath $srcExt -PathType Container) {
    $dstExt = Join-Path $InstallDir "browser-extension"
    $tmpExt = Join-Path $InstallDir "browser-extension.new.$PID"
    $oldExt = Join-Path $InstallDir "browser-extension.old.$PID.$([guid]::NewGuid().ToString('N'))"
    if (Test-Path -LiteralPath $tmpExt) { Remove-Item -LiteralPath $tmpExt -Recurse -Force }
    Copy-Item -LiteralPath $srcExt -Destination $tmpExt -Recurse -Force
    if (Test-Path -LiteralPath $dstExt) {
      Move-Item -LiteralPath $dstExt -Destination $oldExt -Force
    }
    try {
      Move-Item -LiteralPath $tmpExt -Destination $dstExt -Force
    } catch {
      if (Test-Path -LiteralPath $oldExt) {
        Move-Item -LiteralPath $oldExt -Destination $dstExt -Force -ErrorAction SilentlyContinue
      }
      Remove-Item -LiteralPath $tmpExt -Recurse -Force -ErrorAction SilentlyContinue
      throw "Failed to install browser-extension folder: $_"
    }
    Remove-Item -LiteralPath $oldExt -Recurse -Force -ErrorAction SilentlyContinue
  }

  foreach ($docFile in @("README.md", "README.zh-CN.md", "SECURITY.md", "SECURITY.zh-CN.md", "LICENSE", "SHA256SUMS.txt")) {
    $srcDoc = Join-Path $pkgRoot $docFile
    if (Test-Path -LiteralPath $srcDoc -PathType Leaf) {
      Copy-Item -LiteralPath $srcDoc -Destination (Join-Path $InstallDir $docFile) -Force
    }
  }

  Add-ToUserPath $InstallDir
  Write-Log "Installed OpenKeylet $releaseVersion at $TargetExe."

  # 6. Post-install setup (cleans stale pending-update markers & connects detected agents).
  $setupExitCode = Invoke-PostInstallSetup $TargetExe
} finally {
  if (Test-Path -LiteralPath $workDir) {
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}
exit $setupExitCode
