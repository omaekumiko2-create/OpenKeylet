// Synthetic renderer E2E test for the GitHub password sync card: private repo auto-discovery, connect and disconnect.
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
        language: new URLSearchParams(location.search).get("lang") || "zh",
        closeBehavior: "tray",
        browserEnabled: false,
        browserPort: 39272,
        ownerAutoLockMinutes: 15,
      },
      connections: [],
      activities: [],
      mcp: { status: "ready", stdioCommand: "openkeylet" },
      browserBridge: { status: "off" },
      security: {
        encrypted: true,
        keyLocation: "fileOutsideDataDir",
        keyFile: "/home/demo/.config/openkeylet/keys/a1b2c3d4e5f60718/master.key",
      },
    };

    window.fixture = {
      unlocked: true,
      configured: false,
      recoveryKey: "okv1_TESTRECOVERYKEY0123456789ABCDEFGHIJKLMNOPQR",
      repo: "",
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
              pinConfigured: false,
              unlocked: true,
              expiresInSeconds: 0,
              mode: "none",
            };
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
              repository: window.fixture.repo,
              keyRepository: window.fixture.repo ? `${window.fixture.repo}-key` : "",
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
          if (cmd === "github_backup_recovery_key") return window.fixture.recoveryKey;
          if (cmd === "github_backup_connect") {
            const payload = args.input || args;
            window.fixture.connectPayloads.push(payload);
            window.fixture.configured = true;
            window.fixture.repo = payload.repository || "omaekumiko2-create/openkeylet-vault";
            return {
              connected: true,
              repository: window.fixture.repo,
              keyRepository: window.fixture.repo ? `${window.fixture.repo}-key` : "",
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
            window.fixture.repo = "";
            return {
              connected: false,
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

  // 1. Navigate to Settings -> CLOUD / 05: the card is titled as password sync
  await page.click('.nav-item[data-page="settings"]');
  assert.equal(await page.locator("#github-heading").textContent(), "GitHub 密码同步");
  assert.doesNotMatch(await page.locator("#github-note").textContent(), /强加密|主密码/);
  await page.click("#github-connect");
  await page.waitForSelector("#github-modal:not(.hidden)");
  assert.equal(await page.locator("#github-master-passphrase").count(), 0);

  // 2. Check Account -> auto-discovers private vault repo with 私有/PRIVATE + 密文/VAULT badges
  await page.click("#github-check-account");
  await page.waitForSelector("#github-discovered-box:not(.hidden)");
  const discoveredText = await page.locator("#github-discovered-list").innerText();
  assert.match(discoveredText, /openkeylet-vault/);
  assert.match(discoveredText, /私有|PRIVATE/);

  // Clicking discovered repo selects existing mode & populates repo name
  await page.click(".github-discovered-chip");
  assert.equal(await page.locator("#github-repository").inputValue(), "omaekumiko2-create/openkeylet-vault");

  // 3. Binding is enough: no key or passphrase is typed, and the key repository is named
  assert.match(await page.locator("#github-key-repo-help").textContent(), /omaekumiko2-create\/openkeylet-vault-key/);
  assert.equal(await page.locator("#github-key-saved").count(), 0);
  assert.equal(await page.locator("#github-generate-key").count(), 0);
  assert.equal(await page.locator("#github-recovery-key").inputValue(), "");
  await page.click("#github-submit");
  await page.locator("#github-modal").waitFor({ state: "hidden" });
  const payloads = await page.evaluate(() => window.fixture.connectPayloads);
  assert.equal(payloads.length, 1);
  assert.equal(payloads[0].repository, "omaekumiko2-create/openkeylet-vault");
  assert.equal(payloads[0].recoveryKey, "");
  assert.equal("masterPassphrase" in payloads[0], false);
  assert.equal("recoveryKeySaved" in payloads[0], false);
  assert.equal(await page.locator("#github-key-repository-value").textContent(), "omaekumiko2-create/openkeylet-vault-key");

  // 4. Connected state leaves the PIN lock setting and the lock overlay untouched
  assert.equal(await page.locator("#pin-enabled").isDisabled(), false);
  assert.ok(await page.locator("#owner-lock-layer").evaluate((el) => el.classList.contains("hidden")));
  await page.click("#github-advanced-summary");
  assert.equal(await page.locator("#github-change-passphrase").count(), 0);

  // 5. Disconnect -> confirm dialog -> local connection removed
  await page.click("#github-disconnect");
  await page.waitForSelector("#confirmation-modal:not(.hidden)");
  await page.click("#confirmation-accept");
  await page.waitForFunction(() => window.fixture.disconnects === 1);

  // 6. Check zero horizontal overflow in Dark & Light modes
  for (const theme of ["dark", "light"]) {
    await page.evaluate((t) => document.documentElement.setAttribute("data-theme", t), theme);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    assert.ok(overflow <= 1, `horizontal overflow in ${theme}: ${overflow}`);
  }

  // 7. The connect dialog and the connected card fit at 460px in every language and theme
  const widthOverflow = (selectors) => page.evaluate((list) => Math.max(
    document.documentElement.scrollWidth - document.documentElement.clientWidth,
    ...list.map((selector) => {
      const element = document.querySelector(selector);
      return element.scrollWidth - element.clientWidth;
    }),
  ), selectors);
  const headings = {
    en: { heading: "GITHUB PASSWORD SYNC", keyKind: "VAULT KEY · KEY FILE OUTSIDE THE DATA DIRECTORY" },
    zh: { heading: "GitHub 密码同步", keyKind: "密码库密钥 · 数据目录外的密钥文件" },
    "zh-TW": { heading: "GitHub 密碼同步", keyKind: "密碼庫金鑰 · 資料目錄外的金鑰檔" },
    ja: { heading: "GitHub パスワード同期", keyKind: "金庫キー · データフォルダ外の鍵ファイル" },
    ko: { heading: "GitHub 비밀번호 동기화", keyKind: "금고 키 · 데이터 디렉터리 외부의 키 파일" },
    es: { heading: "SINCRONIZACIÓN CON GITHUB", keyKind: "CLAVE DE LA BÓVEDA · ARCHIVO DE CLAVE FUERA DEL DIRECTORIO DE DATOS" },
  };
  for (const [lang, expected] of Object.entries(headings)) {
    await page.goto(`http://127.0.0.1:${port}/index.html?lang=${lang}`, { waitUntil: "networkidle" });
    await page.click('.nav-item[data-page="settings"]');
    assert.equal(await page.locator("#github-heading").textContent(), expected.heading);
    assert.equal(await page.locator("#key-location-box").evaluate((el) => el.classList.contains("hidden")), false);
    assert.equal(await page.locator("#key-location-kind").textContent(), expected.keyKind);
    assert.equal(
      await page.locator("#key-location-path").textContent(),
      "/home/demo/.config/openkeylet/keys/a1b2c3d4e5f60718/master.key",
    );
    await page.click("#github-connect");
    await page.waitForSelector("#github-modal:not(.hidden)");
    await page.click("#github-check-account");
    await page.waitForSelector("#github-discovered-box:not(.hidden)");
    await page.click(".github-discovered-chip");
    for (const theme of ["dark", "light"]) {
      await page.evaluate((t) => document.documentElement.setAttribute("data-theme", t), theme);
      const overflow = await widthOverflow([".github-modal-card", ".github-form-scroll"]);
      assert.ok(overflow <= 1, `connect dialog overflows in ${lang}/${theme}: ${overflow}`);
    }
    await page.click("#github-submit");
    await page.locator("#github-modal").waitFor({ state: "hidden" });
    await page.waitForFunction(() => document.querySelector("#github-key-repository-value").textContent.endsWith("-key"));
    for (const theme of ["dark", "light"]) {
      await page.evaluate((t) => document.documentElement.setAttribute("data-theme", t), theme);
      const overflow = await widthOverflow(["#github-backup-card", "#github-details", "#key-location-box"]);
      assert.ok(overflow <= 1, `sync/key-location card overflows in ${lang}/${theme}: ${overflow}`);
    }
  }

  assert.deepEqual(errors, [], `Unexpected page errors: ${errors.join("; ")}`);
  console.log("GitHub password sync UI E2E tests passed.");
} finally {
  await browser.close();
  server.close();
}
