// Synthetic renderer E2E test for GitHub Private Repo Auto-Discovery & Strong Cloud Vault UI.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import http from "node:http";
import { once } from "node:events";
import { chromium } from "playwright";

const renderer = path.resolve(import.meta.dirname, "../renderer");
const server = http.createServer(async (req, res) => {
  const file = path.resolve(renderer, "." + (req.url === "/" ? "/index.html" : req.url.split("?")[0]));
  if (!file.startsWith(renderer + path.sep)) {
    res.writeHead(403);
    res.end();
    return;
  }
  try {
    const type = file.endsWith(".js")
      ? "text/javascript"
      : file.endsWith(".css")
        ? "text/css"
        : file.endsWith(".svg")
          ? "image/svg+xml"
          : file.endsWith(".png")
            ? "image/png"
            : "text/html";
    res.setHeader("Content-Type", type);
    res.end(await fs.readFile(file));
  } catch {
    res.writeHead(404);
    res.end();
  }
});

server.listen(0, "127.0.0.1");
await once(server, "listening");

const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 460, height: 690 } });
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));

  await page.addInitScript(() => {
    const state = {
      settings: {
        language: "zh",
        closeBehavior: "tray",
        browserEnabled: false,
        browserPort: 39272,
        ownerAutoLockMinutes: 15,
      },
      connections: [],
      activities: [],
      mcp: { status: "ready", stdioCommand: "openkeylet" },
      browserBridge: { status: "off" },
      security: { encrypted: true },
    };

    window.fixture = {
      unlocked: true,
      strongMode: false,
      configured: false,
      passphrase: "",
      recoveryKey: "okv1_TESTRECOVERYKEY0123456789ABCDEFGHIJKLMNOPQR",
      repo: "",
      passphraseChanges: [],
      connectPayloads: [],
      disconnects: 0,
    };

    window.__TAURI__ = {
      event: { listen: async () => () => {} },
      core: {
        invoke: async (cmd, args = {}) => {
          if (cmd === "get_state") return JSON.parse(JSON.stringify(state));
          if (cmd === "owner_status") {
            return {
              pinConfigured: window.fixture.strongMode,
              strongMode: window.fixture.strongMode,
              unlocked: window.fixture.unlocked,
              expiresInSeconds: 0,
              autoLockMinutes: state.settings.ownerAutoLockMinutes,
            };
          }
          if (cmd === "owner_lock") {
            window.fixture.unlocked = false;
            return { pinConfigured: true, strongMode: window.fixture.strongMode, unlocked: false, expiresInSeconds: 0, autoLockMinutes: 15 };
          }
          if (cmd === "owner_unlock") {
            const secret = args.pin || "";
            if (secret === window.fixture.passphrase || secret === window.fixture.recoveryKey) {
              window.fixture.unlocked = true;
              return { pinConfigured: true, strongMode: window.fixture.strongMode, unlocked: true, expiresInSeconds: 0, autoLockMinutes: 15 };
            }
            throw new Error("Invalid master passphrase or recovery key");
          }
          if (cmd === "owner_change_master_passphrase") {
            window.fixture.passphrase = args.newPassphrase;
            window.fixture.passphraseChanges.push(args.newPassphrase);
            return true;
          }
          if (cmd === "owner_editor_drafts") return [];
          if (cmd === "system_integration_status") return { desktopShortcut: false, launchAtLogin: false };
          if (cmd === "agent_mcp_status") return [];
          if (cmd === "list_chrome_profiles") return [];
          if (cmd === "update_status") return { phase: "idle", currentVersion: "0.16.0", platform: "windows-x64", autoCheck: false, autoDownload: false };
          if (cmd === "set_edge_dock_enabled") return null;
          if (cmd === "github_backup_status") {
            return {
              connected: window.fixture.configured,
              strongMode: window.fixture.strongMode,
              repository: window.fixture.repo,
              branch: "main",
              autoSync: window.fixture.configured,
              hasRemoteBackup: window.fixture.configured,
              needsRestore: false,
              pendingSync: false,
              provider: "github",
              lastSyncedAt: window.fixture.configured ? "2026-11-24T12:00:00Z" : null,
            };
          }
          if (cmd === "github_backup_account") {
            return {
              login: "omaekumiko2-create",
              authSource: "cli",
              provider: "github",
              apiBaseUrl: "https://api.github.com",
              discoveredRepos: [
                {
                  fullName: "omaekumiko2-create/openkeylet-vault",
                  name: "openkeylet-vault",
                  branch: "main",
                  hasVaultFile: true,
                  hasVaultTopic: true,
                  updatedAt: "2026-11-24T11:30:00Z",
                },
              ],
            };
          }
          if (cmd === "github_backup_generate_key") return window.fixture.recoveryKey;
          if (cmd === "github_backup_recovery_key") return window.fixture.recoveryKey;
          if (cmd === "github_backup_connect") {
            const payload = args.input || args;
            window.fixture.connectPayloads.push(payload);
            window.fixture.configured = true;
            window.fixture.strongMode = true;
            window.fixture.repo = payload.repository || "omaekumiko2-create/openkeylet-vault";
            window.fixture.passphrase = payload.masterPassphrase || "";
            return {
              connected: true,
              strongMode: true,
              repository: window.fixture.repo,
              branch: "main",
              autoSync: true,
              hasRemoteBackup: true,
              needsRestore: false,
              pendingSync: false,
              provider: "github",
            };
          }
          if (cmd === "github_backup_disconnect") {
            window.fixture.disconnects += 1;
            window.fixture.configured = false;
            window.fixture.strongMode = false;
            window.fixture.repo = "";
            return {
              connected: false,
              strongMode: false,
              repository: "",
              branch: "main",
              autoSync: false,
              hasRemoteBackup: false,
              needsRestore: false,
              pendingSync: false,
              provider: "github",
            };
          }
          return null;
        },
      },
    };
  });

  const port = server.address().port;
  await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: "networkidle" });

  // 1. Navigate to Settings -> CLOUD / 05 and open Connect wizard
  await page.click('.nav-item[data-page="settings"]');
  await page.click("#github-connect");
  await page.waitForSelector("#github-modal:not(.hidden)");

  // 2. Check Account -> auto-discovers private vault repo with 私有/PRIVATE + 密文/VAULT badges
  await page.click("#github-check-account");
  await page.waitForSelector("#github-discovered-box:not(.hidden)");
  const discoveredText = await page.locator("#github-discovered-list").innerText();
  assert.match(discoveredText, /openkeylet-vault/);
  assert.match(discoveredText, /私有|PRIVATE/);

  // Clicking discovered repo selects existing mode & populates repo name
  await page.click(".github-discovered-chip");
  assert.equal(await page.locator("#github-repository").inputValue(), "omaekumiko2-create/openkeylet-vault");

  // 3. Validate Step 3 master passphrase rules: short rejected, mismatch rejected, valid accepted
  await page.fill("#github-recovery-key", "okv1_TESTRECOVERYKEY0123456789ABCDEFGHIJKLMNOPQR");
  await page.check("#github-key-saved");
  await page.fill("#github-master-passphrase", "short123");
  await page.fill("#github-master-passphrase-confirm", "short123");
  await page.click("#github-submit");
  assert.ok(await page.locator("#github-form-error").isVisible());

  await page.fill("#github-master-passphrase", "MyStrongVaultPass2026!");
  await page.fill("#github-master-passphrase-confirm", "DifferentPass2026!");
  await page.click("#github-submit");
  assert.ok(await page.locator("#github-form-error").isVisible());

  await page.fill("#github-master-passphrase-confirm", "MyStrongVaultPass2026!");
  await page.click("#github-submit");
  await page.locator("#github-modal").waitFor({ state: "hidden" });

  // 4. Connected Strong Cloud Vault state: PIN toggle disabled, auto-lock visible, change-passphrase shown
  assert.equal(await page.locator("#pin-enabled").isDisabled(), true);
  assert.ok(!(await page.locator("#owner-auto-lock-option").evaluate((el) => el.classList.contains("hidden"))));
  await page.click("#github-advanced-summary");
  assert.ok(!(await page.locator("#github-change-passphrase").evaluate((el) => el.classList.contains("hidden"))));

  // 5. Change master passphrase flow
  await page.click("#github-change-passphrase");
  await page.waitForSelector("#github-passphrase-panel:not(.hidden)");
  await page.fill("#github-new-passphrase", "RotatedStrongPass2026#");
  await page.fill("#github-new-passphrase-confirm", "RotatedStrongPass2026#");
  await page.click("#github-save-passphrase");
  await page.locator("#github-passphrase-panel").waitFor({ state: "hidden" });
  assert.deepEqual(await page.evaluate(() => window.fixture.passphraseChanges), ["RotatedStrongPass2026#"]);

  // 6. Lock vault -> Strong Mode unlock screen (SEALED, password input, 6-digit PIN hidden)
  await page.click("#owner-lock-button");
  await page.waitForSelector("#owner-lock-layer:not(.hidden)");
  assert.equal(await page.locator("#owner-lock-code").textContent(), "SEALED");
  assert.ok(await page.locator("#owner-pin-field").evaluate((el) => el.classList.contains("hidden")));
  assert.ok(!(await page.locator("#owner-strong-field").evaluate((el) => el.classList.contains("hidden"))));

  // Show/Hide reveal toggle works
  assert.equal(await page.locator("#owner-strong-secret").getAttribute("type"), "password");
  await page.click("#owner-strong-reveal");
  assert.equal(await page.locator("#owner-strong-secret").getAttribute("type"), "text");

  // Unlock with rotated passphrase
  await page.fill("#owner-strong-secret", "RotatedStrongPass2026#");
  await page.click("#owner-unlock-action");
  await page.locator("#owner-lock-layer").waitFor({ state: "hidden" });

  // Lock again and unlock with okv1_ recovery key
  await page.click("#owner-lock-button");
  await page.waitForSelector("#owner-lock-layer:not(.hidden)");
  await page.fill("#owner-strong-secret", "okv1_TESTRECOVERYKEY0123456789ABCDEFGHIJKLMNOPQR");
  await page.click("#owner-unlock-action");
  await page.locator("#owner-lock-layer").waitFor({ state: "hidden" });

  // 7. Disconnect -> confirm dialog -> reverts cleanly to local mode
  await page.click("#github-disconnect");
  await page.waitForSelector("#confirmation-modal:not(.hidden)");
  await page.click("#confirmation-accept");
  await page.waitForFunction(() => window.fixture.disconnects === 1);
  assert.equal(await page.locator("#pin-enabled").isDisabled(), false);

  // 8. Check zero horizontal overflow in Dark & Light modes
  for (const theme of ["dark", "light"]) {
    await page.evaluate((t) => document.documentElement.setAttribute("data-theme", t), theme);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    assert.ok(overflow <= 1, `horizontal overflow in ${theme}: ${overflow}`);
  }

  assert.deepEqual(errors, [], `Unexpected page errors: ${errors.join("; ")}`);
  console.log("Strong Cloud Vault & Private Repo Auto-Discovery UI E2E tests passed.");
} finally {
  await browser.close();
  server.close();
}
