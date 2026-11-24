[CmdletBinding()]
param(
    [int]$Port = 1420
)

$ErrorActionPreference = 'Stop'
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $repoRoot

# 1. Load myenv project environment (sets CARGO_TARGET_DIR, TEMP, RUSTUP_HOME, etc.)
$myenvRoot = if ($env:MYENV_ROOT) { $env:MYENV_ROOT } else { Join-Path $env:USERPROFILE 'Documents\myenv' }
$useProjectEnv = Join-Path $myenvRoot 'config\Use-ProjectEnvironment.ps1'
if (Test-Path $useProjectEnv) {
    . $useProjectEnv -ProjectPath $repoRoot -Quiet
}

# 2. Ensure Node.js is on PATH (supports myenv runtimes\node\<ver> as well as system PATH)
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    $nodeRuntimesDir = Join-Path $myenvRoot 'runtimes\node'
    if (Test-Path $nodeRuntimesDir) {
        $latestNode = Get-ChildItem -Path $nodeRuntimesDir -Directory |
            Sort-Object Name -Descending |
            Where-Object { Test-Path (Join-Path $_.FullName 'node.exe') } |
            Select-Object -First 1
        if ($latestNode) {
            $env:PATH = "$($latestNode.FullName);$env:PATH"
        }
    }
}
$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
if (-not $nodeCmd) {
    throw 'node.exe not found. Ensure Node.js is installed in PATH or under MYENV_ROOT\runtimes\node.'
}
$nodeExe = $nodeCmd.Source

# 3. Ensure MSVC cl.exe / link.exe is on PATH (supports portable myenv MSVC)
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    $msvcSetup = Join-Path $myenvRoot 'tools\msvc\2022\setup_x64.bat'
    if (Test-Path $msvcSetup) {
        $vars = cmd /c "`"$msvcSetup`" >nul && set"
        foreach ($line in $vars) {
            if ($line -match '^([^=]+)=(.*)$') {
                $name = $Matches[1]
                $val  = $Matches[2]
                if ($name -in @('PATH', 'Path', 'INCLUDE', 'LIB', 'VSCMD_ARG_HOST_ARCH', 'VSCMD_ARG_TGT_ARCH', 'VCToolsVersion', 'WindowsSDKVersion', 'VCToolsInstallDir', 'WindowsSdkBinPath')) {
                    [Environment]::SetEnvironmentVariable($name, $val, 'Process')
                }
            }
        }
    }
}

# 4. Ensure cargo.exe is available
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $cargoBin = Join-Path $myenvRoot 'data\cargo\bin'
    if (Test-Path (Join-Path $cargoBin 'cargo.exe')) {
        $env:PATH = "$cargoBin;$env:PATH"
    }
}
$cargoCmd = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $cargoCmd) {
    throw 'cargo.exe not found.'
}

if (-not $env:CARGO_TARGET_DIR) {
    $env:CARGO_TARGET_DIR = Join-Path $env:LOCALAPPDATA 'OpenKeylet-target'
}

$tempBase = if ($env:TEMP) { $env:TEMP } else { [IO.Path]::GetTempPath() }
$supervisorScript = Join-Path $tempBase 'openkeylet-dev-hot.mjs'

@'
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

const repoRoot = path.resolve(process.argv[2]);
let port = Number(process.argv[3] || 1420);
const rendererRoot = path.join(repoRoot, "renderer");
const rustRoot = path.join(repoRoot, "src-tauri");
const targetDir = process.env.CARGO_TARGET_DIR || path.join(rustRoot, "target");
const binaryPath = path.join(targetDir, "debug", process.platform === "win32" ? "openkeylet.exe" : "openkeylet");

function makeTauriConfigOverride(boundPort) {
  return JSON.stringify({
    build: {
      devUrl: `http://127.0.0.1:${boundPort}`,
    },
    app: {
      security: {
        csp: "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: asset: http://asset.localhost; connect-src 'self' ipc: http://ipc.localhost",
      },
    },
  });
}
let tauriConfigOverride = makeTauriConfigOverride(port);

const mime = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".json": "application/json",
  ".woff2": "font/woff2",
};

const clients = new Set();
const reloadClientJs = `(() => {
  const es = new EventSource("/__reload");
  es.onmessage = (e) => {
    if (e.data === "css") {
      document.querySelectorAll('link[rel="stylesheet"]').forEach((link) => {
        const url = new URL(link.href);
        url.searchParams.set("_t", String(Date.now()));
        link.href = url.toString();
      });
    } else {
      location.reload();
    }
  };
})();`;

const server = http.createServer((req, res) => {
  const urlPath = decodeURIComponent((req.url || "/").split("?")[0]);
  if (urlPath === "/__reload") {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    });
    res.write(": connected\n\n");
    clients.add(res);
    req.on("close", () => clients.delete(res));
    return;
  }
  if (urlPath === "/__reload.js") {
    res.writeHead(200, { "Content-Type": mime[".js"], "Cache-Control": "no-store" });
    res.end(reloadClientJs);
    return;
  }
  const filePath = path.resolve(rendererRoot, "." + (urlPath === "/" ? "/index.html" : urlPath));
  if (!filePath.startsWith(rendererRoot + path.sep) || !fs.existsSync(filePath)) {
    res.writeHead(404);
    res.end("Not found");
    return;
  }
  const ext = path.extname(filePath).toLowerCase();
  res.writeHead(200, {
    "Content-Type": mime[ext] || "application/octet-stream",
    "Cache-Control": "no-store",
  });
  if (urlPath === "/" || urlPath === "/index.html") {
    let html = fs.readFileSync(filePath, "utf8");
    html = html.replace("connect-src ipc:", "connect-src 'self' ipc:");
    html = html.replace("</body>", '<script src="/__reload.js"></script></body>');
    res.end(html);
    return;
  }
  fs.createReadStream(filePath).pipe(res);
});

function scanDir(dir, filterFn, out = new Map()) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "target" || entry.name === "node_modules" || entry.name === ".git") continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) scanDir(full, filterFn, out);
    else if (!filterFn || filterFn(full)) {
      try {
        out.set(full, fs.statSync(full).mtimeMs);
      } catch {}
    }
  }
  return out;
}

const rendererMtimes = scanDir(rendererRoot);
const rustMtimes = scanDir(path.join(rustRoot, "src"), (f) => f.endsWith(".rs"));
for (const extra of ["Cargo.toml", "tauri.conf.json"]) {
  const full = path.join(rustRoot, extra);
  if (fs.existsSync(full)) rustMtimes.set(full, fs.statSync(full).mtimeMs);
}

let appProc = null;
let building = false;
let pendingRebuild = false;
let shuttingDown = false;

function cleanupOldBinaries() {
  const debugDir = path.dirname(binaryPath);
  const depsDir = path.join(debugDir, "deps");
  const baseName = path.basename(binaryPath);
  const pdbName = baseName.replace(/\.exe$/i, ".pdb");
  for (const dir of [debugDir, depsDir]) {
    try {
      for (const entry of fs.readdirSync(dir)) {
        if (entry.startsWith(`${baseName}.old.`) || entry.startsWith(`${pdbName}.old.`)) {
          try {
            fs.unlinkSync(path.join(dir, entry));
          } catch {}
        }
      }
    } catch {}
  }
}

function releaseLockedBinary() {
  cleanupOldBinaries();
  if (process.platform !== "win32") return;
  const debugDir = path.dirname(binaryPath);
  const depsDir = path.join(debugDir, "deps");
  const baseName = path.basename(binaryPath);
  const pdbName = baseName.replace(/\.exe$/i, ".pdb");
  const candidates = [
    binaryPath,
    path.join(debugDir, pdbName),
    path.join(depsDir, baseName),
    path.join(depsDir, pdbName),
  ];
  for (const candidate of candidates) {
    if (!fs.existsSync(candidate)) continue;
    try {
      const fd = fs.openSync(candidate, "r+");
      fs.closeSync(fd);
    } catch {
      const aside = `${candidate}.old.${Date.now()}`;
      try {
        fs.renameSync(candidate, aside);
        console.log(`[dev-hot] Moved locked ${path.relative(debugDir, candidate)} aside so live MCP/tray keeps running`);
      } catch (err) {
        console.warn(`[dev-hot] Warning: ${path.relative(debugDir, candidate)} is still locked (${err?.code || err?.message})`);
      }
    }
  }
}

function stopApp() {
  if (!appProc) return false;
  const proc = appProc;
  appProc = null;
  try {
    proc.kill();
  } catch {}
  return true;
}

function launchApp() {
  stopApp();
  console.log(`[dev-hot] Launching ${binaryPath}`);
  const proc = spawn(binaryPath, [], {
    cwd: repoRoot,
    stdio: "inherit",
    env: { ...process.env, TAURI_CONFIG: tauriConfigOverride },
  });
  appProc = proc;
  proc.on("exit", (code) => {
    if (appProc === proc) appProc = null;
    if (!shuttingDown && !building) {
      console.log(`[dev-hot] App exited (code ${code ?? "null"}). Watching for changes...`);
    }
  });
}

function startCargoBuild() {
  releaseLockedBinary();
  const build = spawn("cargo", ["build", "--manifest-path", path.join(rustRoot, "Cargo.toml")], {
    cwd: repoRoot,
    stdio: "inherit",
    env: { ...process.env, TAURI_CONFIG: tauriConfigOverride },
  });
  build.on("exit", (code) => {
    building = false;
    if (shuttingDown) return;
    if (pendingRebuild) {
      buildAndLaunch("queued Rust change");
      return;
    }
    if (code === 0) {
      launchApp();
    } else {
      console.error(`[dev-hot] Rust build failed (exit ${code}). Fix errors and save to retry.`);
    }
  });
}

function buildAndLaunch(reason) {
  if (building) {
    pendingRebuild = true;
    return;
  }
  building = true;
  pendingRebuild = false;
  console.log(`[dev-hot] Building Rust backend (${reason})...`);
  const stopped = stopApp();
  if (stopped) {
    setTimeout(startCargoBuild, 200);
  } else {
    startCargoBuild();
  }
}

// Frontend hot-reload polling (SMB-safe)
setInterval(() => {
  const next = scanDir(rendererRoot);
  let kind = null;
  for (const [file, mtime] of next) {
    if (rendererMtimes.get(file) !== mtime) {
      kind = file.endsWith(".css") && kind !== "full" ? "css" : "full";
    }
  }
  if (!kind && next.size !== rendererMtimes.size) kind = "full";
  if (kind) {
    rendererMtimes.clear();
    for (const [k, v] of next) rendererMtimes.set(k, v);
    for (const res of clients) res.write(`data: ${kind}\n\n`);
    console.log(`[dev-hot] ${kind === "css" ? "CSS hot-swapped" : "Frontend reloaded"}`);
  }
}, 400);

// Backend auto-rebuild polling (SMB-safe)
setInterval(() => {
  const next = scanDir(path.join(rustRoot, "src"), (f) => f.endsWith(".rs"));
  for (const extra of ["Cargo.toml", "tauri.conf.json"]) {
    const full = path.join(rustRoot, extra);
    if (fs.existsSync(full)) next.set(full, fs.statSync(full).mtimeMs);
  }
  let changed = next.size !== rustMtimes.size;
  if (!changed) {
    for (const [file, mtime] of next) {
      if (rustMtimes.get(file) !== mtime) {
        changed = true;
        break;
      }
    }
  }
  if (changed) {
    rustMtimes.clear();
    for (const [k, v] of next) rustMtimes.set(k, v);
    buildAndLaunch("Rust source changed");
  }
}, 800);

function cleanup() {
  if (shuttingDown) return;
  shuttingDown = true;
  stopApp();
  server.close();
  process.exit(0);
}
process.on("SIGINT", cleanup);
process.on("SIGTERM", cleanup);

server.on("error", (err) => {
  if (err && err.code === "EADDRINUSE" && port < 1450) {
    port += 1;
    tauriConfigOverride = makeTauriConfigOverride(port);
    server.listen(port, "127.0.0.1");
    return;
  }
  console.error(err);
  process.exit(1);
});

server.listen(port, "127.0.0.1", () => {
  tauriConfigOverride = makeTauriConfigOverride(port);
  console.log(`[dev-hot] Frontend hot-reload server ready at http://127.0.0.1:${port}`);
  buildAndLaunch("initial startup");
});
'@ | Set-Content -Path $supervisorScript -Encoding UTF8

Write-Host "[dev-hot] Node:  $nodeExe"
Write-Host "[dev-hot] Cargo: $($cargoCmd.Source)"
Write-Host "[dev-hot] Target: $env:CARGO_TARGET_DIR"

try {
    & $nodeExe $supervisorScript $repoRoot "$Port"
}
finally {
    Remove-Item $supervisorScript -Force -ErrorAction SilentlyContinue
}
