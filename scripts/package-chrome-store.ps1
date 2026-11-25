[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $env:MYENV_ROOT) { throw 'Load Use-ProjectEnvironment.ps1 before packaging.' }
$environmentRoot = [IO.Path]::GetFullPath($env:MYENV_ROOT).TrimEnd('\') + '\'
$tempRoot = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\'
if (-not $tempRoot.StartsWith($environmentRoot, [StringComparison]::OrdinalIgnoreCase)) {
  throw 'TEMP must be inside MYENV_ROOT.'
}
$source = Join-Path $projectRoot 'browser-extension'
$manifest = Get-Content -LiteralPath (Join-Path $source 'manifest.json') -Raw | ConvertFrom-Json
if ($manifest.manifest_version -ne 3) { throw 'Manifest V3 is required.' }
if ($manifest.description.Length -gt 132) { throw 'Manifest description exceeds 132 characters.' }
if ($manifest.version -notmatch '^\d+(\.\d+){0,3}$') { throw 'Invalid Chrome extension version.' }
if (@($manifest.permissions | Where-Object { $_ -notin @('scripting', 'storage') }).Count) {
  throw 'Unexpected permission; review the store declaration before packaging.'
}
$packageVersion = (Get-Content -LiteralPath (Join-Path $projectRoot 'package.json') -Raw | ConvertFrom-Json).version
if ($manifest.version -ne $packageVersion) { throw 'Desktop/package and extension versions differ; review compatibility.' }
$stage = Join-Path $tempRoot ('openkeylet-store-' + [Guid]::NewGuid().ToString('N'))
$output = Join-Path $projectRoot 'dist\chrome-web-store'
New-Item -ItemType Directory -Path $stage,$output -Force | Out-Null
try {
  # Explicit allowlist: no tests, desktop binary, private keys, backups or repository files.
  $files = @('manifest.json','service-worker.js','content-script.js','webauthn-main.js',
    'form-reader.js','provider.js','capture.js','agent-actions.js','ui-core.js',
    'popup.html','popup.js','popup.css','request.html','request.js','privacy.html')
  foreach ($file in $files) {
    Copy-Item -LiteralPath (Join-Path $source $file) -Destination (Join-Path $stage $file)
  }
  New-Item -ItemType Directory -Path (Join-Path $stage 'icons') | Out-Null
  Get-ChildItem -LiteralPath (Join-Path $source 'icons') -File -Filter '*.png' |
    Copy-Item -Destination (Join-Path $stage 'icons')
  if (Test-Path -LiteralPath (Join-Path $source 'fonts')) {
    New-Item -ItemType Directory -Path (Join-Path $stage 'fonts') | Out-Null
    Get-ChildItem -LiteralPath (Join-Path $source 'fonts') -File -Filter '*.woff2' |
      Copy-Item -Destination (Join-Path $stage 'fonts')
  }
  # The Web Store assigns the production identity. Never ship a signing private key.
  $manifest.PSObject.Properties.Remove('key')
  $manifest.PSObject.Properties.Remove('update_url')
  [IO.File]::WriteAllText((Join-Path $stage 'manifest.json'), ($manifest | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
  $archive = Join-Path $output ("openkeylet-chrome-store-" + $manifest.version + '.zip')
  Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -Force
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip = [IO.Compression.ZipFile]::OpenRead($archive)
  try {
    $entries = @($zip.Entries | ForEach-Object { $_.FullName.Replace('\','/') })
    foreach ($file in $files) { if ($file -notin $entries) { throw "Missing ZIP entry: $file" } }
    if ('icons/128x128.png' -notin $entries) { throw 'Missing store icon.' }
    if (@($entries | Where-Object { $_ -notin $files -and $_ -notmatch '^icons/[0-9]+x[0-9]+(-light)?\.png$' -and $_ -notmatch '^fonts/[a-z0-9-]+\.woff2$' }).Count) {
      throw 'Unexpected ZIP contents.'
    }
  } finally { $zip.Dispose() }
  $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
  [IO.File]::WriteAllText((Join-Path $output 'SHA256SUMS.txt'), "$hash  $([IO.Path]::GetFileName($archive))`n", [Text.UTF8Encoding]::new($false))
  [pscustomobject]@{ Archive=$archive; Version=$manifest.version; Files=$entries.Count; SHA256=$hash; Status='Prepared for draft upload; production extension ID must be verified before review.' } | ConvertTo-Json
} finally {
  # Verify the resolved absolute target immediately before recursive cleanup.
  $resolvedStage = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $stage).ProviderPath)
  if (-not $resolvedStage.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or
      [IO.Path]::GetFileName($resolvedStage) -notmatch '^openkeylet-store-[a-f0-9]{32}$') {
    throw "Refusing cleanup outside packaging stage: $resolvedStage"
  }
  Remove-Item -LiteralPath $resolvedStage -Recurse -Force
}
