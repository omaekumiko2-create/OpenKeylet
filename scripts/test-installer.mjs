#!/usr/bin/env node
/**
 * End-to-end verification of the OpenKeylet installer scripts:
 * - Verifies `scripts/install.sh` uses pure LF line endings and valid bash syntax (when bash is present).
 * - Verifies `scripts/install.ps1` end-to-end on Windows against a local signed mock GitHub Release:
 *   1) Rejects tampered Ed25519 manifest signatures.
 *   2) Verifies Ed25519 signature + archive SHA-256 + internal package SHA256SUMS.txt.
 *   3) Installs into an isolated target directory without modifying User PATH (-NoPath).
 *   4) Runs `openkeylet setup --json` on the installed binary.
 *   5) Confirms `-Update` delegates cleanly to `openkeylet update install` without duplicating files.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";

function runAsync(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      ...options,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`Command timed out: ${command} ${args.join(" ")}\nstderr: ${stderr}`));
    }, 60_000);
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on("close", (status) => {
      clearTimeout(timer);
      resolve({ status, stdout, stderr });
    });
  });
}

const projectRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1")), "..");
const installSh = path.join(projectRoot, "scripts", "install.sh");
const installPs1 = path.join(projectRoot, "scripts", "install.ps1");

// 1. Check LF line endings on scripts/install.sh (CRLF breaks #!/usr/bin/env bash on macOS/Linux).
const shRaw = fs.readFileSync(installSh, "utf8");
assert.ok(!shRaw.includes("\r\n"), "scripts/install.sh must use LF line endings (no CRLF)");
assert.ok(shRaw.startsWith("#!/usr/bin/env bash\n"), "scripts/install.sh must start with bash shebang");

// Optional bash syntax check if bash is available (feed via stdin so WSL bash works on SMB drives).
const bashCheck = spawnSync("bash", ["-n"], { input: shRaw, encoding: "utf8" });
if (!bashCheck.error) {
  assert.equal(bashCheck.status, 0, `bash -n scripts/install.sh failed:\n${bashCheck.stderr}`);
  console.log("PASS: bash -n scripts/install.sh");
} else {
  console.log("SKIP: bash not found on PATH; verified LF endings only.");
}

// 2. On Windows, run full E2E test of scripts/install.ps1 using a real built binary (if provided or found) or mock zip.
if (process.platform !== "win32") {
  console.log("PASS: non-Windows static checks completed.");
  process.exit(0);
}

// PowerShell syntax check first.
const psSyntax = spawnSync(
  "powershell",
  [
    "-NoProfile",
    "-Command",
    `$errors = $null; [System.Management.Automation.Language.Parser]::ParseFile('${installPs1.replace(/'/g, "''")}', [ref]$null, [ref]$errors) | Out-Null; if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Error $_.Message }; exit 1 }`,
  ],
  { encoding: "utf8" },
);
assert.equal(psSyntax.status, 0, `PowerShell syntax error in install.ps1:\n${psSyntax.stderr}`);
console.log("PASS: PowerShell AST parse scripts/install.ps1");

const candidateExe = process.argv[2]
  ? path.resolve(process.argv[2])
  : [
      process.env.CARGO_TARGET_DIR && path.join(process.env.CARGO_TARGET_DIR, "debug", "openkeylet.exe"),
      process.env.CARGO_TARGET_DIR && path.join(process.env.CARGO_TARGET_DIR, "release", "openkeylet.exe"),
      path.join(projectRoot, "src-tauri", "target", "debug", "openkeylet.exe"),
      path.join(projectRoot, "src-tauri", "target", "release", "openkeylet.exe"),
    ].find((p) => p && fs.existsSync(p));

if (!candidateExe) {
  console.log("SKIP: No built openkeylet.exe found; pass binary path as arg to run full Windows E2E.");
  process.exit(0);
}

console.log(`Running Windows install.ps1 E2E with binary: ${candidateExe}`);

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "openkeylet-installer-e2e-"));
try {
  // Build a portable package zip with valid internal SHA256SUMS.txt.
  const pkgName = "OpenKeylet_9.9.9_windows-x64";
  const stageDir = path.join(tmpRoot, "stage", pkgName);
  fs.mkdirSync(path.join(stageDir, "browser-extension"), { recursive: true });
  fs.copyFileSync(candidateExe, path.join(stageDir, "openkeylet.exe"));
  fs.writeFileSync(path.join(stageDir, "browser-extension", "manifest.json"), '{"manifest_version":3,"name":"OpenKeylet"}');
  fs.writeFileSync(path.join(stageDir, "README.md"), "# OpenKeylet\n");
  fs.writeFileSync(path.join(stageDir, "LICENSE"), "MIT\n");

  const sha256File = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  const relFiles = ["LICENSE", "README.md", "browser-extension/manifest.json", "openkeylet.exe"];
  const internalSums = relFiles.map((rel) => `${sha256File(path.join(stageDir, rel))}  ${rel}`).join("\n") + "\n";
  fs.writeFileSync(path.join(stageDir, "SHA256SUMS.txt"), internalSums, "ascii");

  const zipPath = path.join(tmpRoot, `${pkgName}-portable.zip`);
  const compress = spawnSync(
    "powershell",
    [
      "-NoProfile",
      "-Command",
      `Compress-Archive -LiteralPath '${stageDir.replace(/'/g, "''")}' -DestinationPath '${zipPath.replace(/'/g, "''")}' -Force`,
    ],
    { encoding: "utf8" },
  );
  assert.equal(compress.status, 0, `Compress-Archive failed: ${compress.stderr}`);

  const zipBytes = fs.readFileSync(zipPath);
  const zipSha = crypto.createHash("sha256").update(zipBytes).digest("hex");

  // Generate ephemeral Ed25519 signing keypair matching sign-release-manifest.mjs format.
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  const rawPubB64 = spki.subarray(12).toString("base64");

  let serverPort = 0;
  let serveTampered = false;
  const server = http.createServer((req, res) => {
    if (req.url === "/latest.json") {
      const manifest = {
        schemaVersion: 1,
        version: "9.9.9",
        tag: "v9.9.9",
        publishedAt: new Date().toISOString(),
        releaseUrl: `http://127.0.0.1:${serverPort}/release`,
        notes: "Test release",
        platforms: {
          "windows-x64": {
            url: `http://127.0.0.1:${serverPort}/${pkgName}-portable.zip`,
            sha256: zipSha,
            size: zipBytes.length,
            format: "zip",
          },
        },
      };
      const payload = JSON.stringify(manifest);
      const sig = crypto.sign(null, Buffer.from(`openkeylet-update-v1\n${payload}`, "utf8"), privateKey);
      const envelope = {
        format: "openkeylet-update-v1",
        keyId: "e2e-test",
        payload: serveTampered ? payload.replace("9.9.9", "9.9.8") : payload,
        signature: sig.toString("base64"),
      };
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(envelope));
      return;
    }
    if (req.url === `/${pkgName}-portable.zip`) {
      res.writeHead(200, { "Content-Type": "application/zip", "Content-Length": String(zipBytes.length) });
      res.end(zipBytes);
      return;
    }
    res.writeHead(404);
    res.end("not found");
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  serverPort = server.address().port;

  try {
    const installDir = path.join(tmpRoot, "installed");
    const vaultDir = path.join(tmpRoot, "vault");
    const baseEnv = {
      ...process.env,
      OPENKEYLET_UPDATE_MANIFEST_URL: `http://127.0.0.1:${serverPort}/latest.json`,
      OPENKEYLET_UPDATE_PUBLIC_KEY: rawPubB64,
      OPENKEYLET_DATA_DIR: vaultDir,
      OPENKEYLET_ALLOW_DEV_SELF_UPDATE: "1",
    };

    // Test A: Tampered signature MUST be rejected.
    serveTampered = true;
    const tamperedRun = await runAsync(
      "powershell",
      [
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        installPs1,
        "-InstallDir",
        installDir,
        "-NoConnect",
        "-NoPath",
        "-RequireSignature",
        "-Json",
      ],
      { env: baseEnv },
    );
    assert.notEqual(tamperedRun.status, 0, "Tampered manifest must fail verification");
    assert.ok(!tamperedRun.stderr.includes("SyntaxError"), `Verifier hit JS syntax error:\n${tamperedRun.stderr}`);
    assert.ok(tamperedRun.stderr.includes("Ed25519 signature verification failed"), `Expected signature error, got:\n${tamperedRun.stderr}`);
    assert.ok(!fs.existsSync(path.join(installDir, "openkeylet.exe")), "Tampered install must not place binary");
    console.log("PASS: install.ps1 rejects tampered Ed25519 signature");

    // Test B: Valid signed manifest installs cleanly and runs `openkeylet setup --json`.
    serveTampered = false;
    const goodRun = await runAsync(
      "powershell",
      [
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        installPs1,
        "-InstallDir",
        installDir,
        "-NoConnect",
        "-NoPath",
        "-RequireSignature",
        "-Json",
      ],
      { env: baseEnv },
    );
    assert.equal(goodRun.status, 0, `Fresh install failed:\nstdout: ${goodRun.stdout}\nstderr: ${goodRun.stderr}`);
    const setupReport = JSON.parse(goodRun.stdout);
    assert.equal(path.resolve(setupReport.executable), path.resolve(path.join(installDir, "openkeylet.exe")));
    assert.equal(path.resolve(setupReport.browserExtensionPath), path.resolve(path.join(installDir, "browser-extension")));
    assert.equal(path.resolve(setupReport.dataDir), path.resolve(vaultDir));
    console.log("PASS: install.ps1 fresh install + Ed25519 verification + openkeylet setup --json");

    // Test C: Running `-Update -Json` delegates to built-in `openkeylet update install --json` cleanly!
    const updateRun = await runAsync(
      "powershell",
      [
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        installPs1,
        "-InstallDir",
        installDir,
        "-Update",
        "-NoConnect",
        "-NoPath",
        "-Json",
      ],
      { env: baseEnv },
    );
    assert.equal(updateRun.status, 0, `Update delegation failed:\nstdout: ${updateRun.stdout}\nstderr: ${updateRun.stderr}`);
    assert.ok(
      updateRun.stderr.includes("using built-in Ed25519-signed updater"),
      `Expected built-in updater delegation log, got:\n${updateRun.stderr}`,
    );
    const updateReport = JSON.parse(updateRun.stdout);
    assert.equal(updateReport.updated, true);
    assert.equal(updateReport.newVersion, "9.9.9");
    assert.equal(updateReport.signatureVerified, true);
    assert.equal(fs.existsSync(path.join(vaultDir, "updates", "pending-update.json")), false, "pending-update.json must be cleared after update");
    console.log("PASS: install.ps1 -Update delegates to built-in Ed25519 updater with zero conflict");
  } finally {
    server.close();
  }
} finally {
  fs.rmSync(tmpRoot, { recursive: true, force: true });
}
