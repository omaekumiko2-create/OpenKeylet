// Synthetic renderer E2E test for the 4-tab Universal Offline Import Hub.
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
      },
      connections: [],
      activities: [],
      mcp: { status: "ready", stdioCommand: "openkeylet" },
      browserBridge: { status: "off" },
      security: { encrypted: true },
    };

    window.fixture = {
      unlocked: true,
      extractCalls: [],
      commitCalls: [],
      undoCalls: [],
      scanCalls: 0,
      copiedValues: [],
      clearedClipboard: [],
    };

    const sampleResult = {
      detectedFormat: "env",
      detectedFormatZh: ".env 环境变量",
      sealedEnvTemplate: "OPENAI_API_KEY={{openkeylet:OPENAI_API_KEY}}\n",
      warnings: [],
      candidates: [
        {
          id: "cand-api-1",
          kind: "apiKey",
          badge: "API",
          badgeZh: "API",
          confidence: "high",
          selected: true,
          summary: "OpenAI API · api.openai.com/v1",
          sourceSnippet: "OPENAI_API_KEY=sk-proj-••••",
          matchStatus: "new",
          updateExisting: false,
          fields: [
            { label: "URL", value: "https://api.openai.com/v1/", masked: "https://api.openai.com/v1/", secret: false },
            { label: "API Key", value: "sk-proj-secret-value-9999", masked: "sk-pr••••9999", secret: true },
          ],
          input: { name: "OpenAI API", itemType: "api", folder: "", modules: [], secrets: { namedSecrets: { apiCredential: "sk-proj-secret-value-9999" } } },
        },
        {
          id: "cand-login-2",
          kind: "login",
          badge: "LOGIN",
          badgeZh: "账号",
          confidence: "high",
          selected: true,
          summary: "admin.example.com · ops@example.com",
          sourceSnippet: "Login · admin.example.com",
          matchStatus: "update",
          existingItemId: "existing-id-1",
          existingItemName: "Admin Portal",
          updateExisting: true,
          fields: [
            { label: "URL", value: "https://admin.example.com", masked: "https://admin.example.com", secret: false },
            { label: "User", value: "ops@example.com", masked: "ops@example.com", secret: false },
            { label: "Password", value: "NewPass!456", masked: "Ne••••56", secret: true },
          ],
          input: { name: "Admin Portal", itemType: "login", folder: "", modules: [], secrets: { password: "NewPass!456", namedSecrets: { username: "ops@example.com" } } },
        },
        {
          id: "cand-ssh-3",
          kind: "ssh",
          badge: "SSH",
          badgeZh: "SSH",
          confidence: "high",
          selected: false,
          summary: "root@198.51.100.8:22",
          sourceSnippet: "SSH 198.51.100.8:22",
          matchStatus: "duplicate",
          existingItemId: "existing-ssh-1",
          existingItemName: "Prod Box",
          updateExisting: false,
          fields: [
            { label: "Host", value: "198.51.100.8", masked: "198.51.100.8", secret: false },
            { label: "User", value: "root", masked: "root", secret: false },
          ],
          input: { name: "Prod Box", itemType: "ssh", folder: "", modules: [], secrets: {} },
        },
      ],
      ignored: [
        {
          reason: "non_secret",
          reasonZh: "非敏感普通配置",
          key: "PORT",
          preview: "3000",
          candidate: {
            id: "cand-env-port",
            kind: "env",
            badge: "ENV",
            badgeZh: "环境",
            confidence: "low",
            selected: true,
            summary: "PORT = 3000",
            sourceSnippet: ".env",
            matchStatus: "new",
            updateExisting: false,
            fields: [{ label: "PORT", value: "3000", masked: "••••••", secret: true }],
            input: { name: "PORT", itemType: "custom", folder: "Env", modules: [], secrets: { namedSecrets: { PORT: "3000" } } },
          },
        },
      ],
    };

    window.__TAURI__ = {
      event: { listen: async () => () => {} },
      core: {
        invoke: async (cmd, args = {}) => {
          if (cmd === "get_state") return JSON.parse(JSON.stringify(state));
          if (cmd === "owner_status") {
            return { pinConfigured: true, strongMode: false, unlocked: window.fixture.unlocked, expiresInSeconds: 0, autoLockMinutes: 0 };
          }
          if (cmd === "owner_lock") {
            window.fixture.unlocked = false;
            return { pinConfigured: true, strongMode: false, unlocked: false, expiresInSeconds: 0, autoLockMinutes: 0 };
          }
          if (cmd === "owner_editor_drafts") return [];
          if (cmd === "system_integration_status") return { desktopShortcut: false, launchAtLogin: false };
          if (cmd === "agent_mcp_status") return [];
          if (cmd === "list_chrome_profiles") return [];
          if (cmd === "github_backup_status") return { configured: false, strongMode: false, repo: "", branch: "main", autoSync: false, status: "idle" };
          if (cmd === "update_status") return { phase: "idle", currentVersion: "0.16.0", platform: "windows-x64", autoCheck: false, autoDownload: false };
          if (cmd === "set_edge_dock_enabled") return null;
          if (cmd === "update_settings") {
            Object.assign(state.settings, args.patch || {});
            return state.settings;
          }
          if (cmd === "smart_extract_batch") {
            window.fixture.extractCalls.push(args);
            return JSON.parse(JSON.stringify(sampleResult));
          }
          if (cmd === "smart_scan_local_dev_configs") {
            window.fixture.scanCalls += 1;
            return {
              detectedFormat: "ssh_config",
              detectedFormatZh: "SSH 配置 (~/.ssh/config)",
              warnings: [],
              ignored: [],
              candidates: [JSON.parse(JSON.stringify(sampleResult.candidates[2]))],
            };
          }
          if (cmd === "commit_smart_batch") {
            window.fixture.commitCalls.push(args);
            return { added: 2, updated: 1, createdIds: ["new-id-1", "new-id-2"] };
          }
          if (cmd === "undo_smart_batch") {
            window.fixture.undoCalls.push(args.ids);
            return (args.ids || []).length;
          }
          if (cmd === "copy_owner_value") {
            window.fixture.copiedValues.push(args.value);
            return true;
          }
          if (cmd === "clear_clipboard_if_matches") {
            window.fixture.clearedClipboard.push(args.text);
            return true;
          }
          return null;
        },
      },
    };
  });

  const port = server.address().port;
  await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: "networkidle" });

  // 1. Verify 4-tab navigation with Import in 2nd position
  const navOrder = await page.locator(".nav-item").evaluateAll((els) =>
    els.map((el) => ({ page: el.dataset.page, text: el.querySelector("span")?.textContent?.trim() }))
  );
  assert.deepEqual(navOrder, [
    { page: "connections", text: "项目" },
    { page: "import", text: "导入" },
    { page: "activity", text: "记录" },
    { page: "settings", text: "设置" },
  ]);

  // 2. Click 2nd tab (导入) and verify page & metrics switch
  await page.click('.nav-item[data-page="import"]');
  assert.equal(await page.locator(".nav").getAttribute("data-active"), "import");
  assert.ok(await page.locator("#page-import").evaluate((el) => el.classList.contains("active")));
  const metricText = await page.locator("#metrics").innerText();
  assert.match(metricText, /已识别/);
  assert.match(metricText, /待入库/);

  // 3. Paste messy text -> debounced offline extraction -> cards + ignored drawer + dedup badges
  await page.fill("#import-raw-input", "OPENAI_API_KEY=sk-proj-secret-value-9999\nPORT=3000\n");
  await page.waitForSelector(".import-card");
  assert.equal(await page.locator(".import-card").count(), 3);
  // Dropzone auto-compacts after extraction
  assert.ok(await page.locator("#import-dropzone").evaluate((el) => el.classList.contains("is-compact")));

  // 4. Verify dedup status pills: 1 new (checked), 1 update (checked), 1 duplicate (unchecked)
  assert.equal(await page.locator("#import-commit-btn").textContent(), "一键入库 (2)");
  // Toggle update pill from 更新原项 ⇄ to 另存新项 ⇄
  await page.click('[data-import-toggle-update="cand-login-2"]');
  assert.match(await page.locator('[data-import-toggle-update="cand-login-2"]').textContent(), /另存新项/);
  // Toggle back to 更新原项 ⇄
  await page.click('[data-import-toggle-update="cand-login-2"]');
  assert.match(await page.locator('[data-import-toggle-update="cand-login-2"]').textContent(), /更新原项/);

  // 5. Reveal masked secret via eye button
  const apiCard = page.locator('[data-import-card="cand-api-1"]');
  assert.match(await apiCard.innerText(), /sk-pr••••9999/);
  await page.click('[data-import-reveal="cand-api-1"]');
  assert.match(await apiCard.innerText(), /sk-proj-secret-value-9999/);

  // 6. Inline rename + promote an ignored item from noise drawer
  await page.fill('[data-import-rename="cand-api-1"]', "OpenAI Prod Key");
  await page.click("#import-ignored-summary");
  await page.click('[data-import-promote="0"]');
  assert.equal(await page.locator(".import-card").count(), 4);
  assert.equal(await page.locator("#import-commit-btn").textContent(), "一键入库 (3)");

  // 7. Filter via kind pill and top search bar
  await page.click('[data-import-kind="apiKey"]');
  assert.equal(await page.locator(".import-card").count(), 1);
  await page.click('[data-import-kind="all"]');
  assert.equal(await page.locator(".import-card").count(), 4);

  // 8. Check layout geometry (zero horizontal overflow at 460x690 in dark & light modes)
  for (const theme of ["dark", "light"]) {
    await page.evaluate((t) => document.documentElement.setAttribute("data-theme", t), theme);
    const overflow = await page.evaluate(() => ({
      doc: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      nav: document.querySelector(".nav").scrollWidth - document.querySelector(".nav").clientWidth,
    }));
    assert.ok(overflow.doc <= 1, `horizontal overflow in ${theme}: ${overflow.doc}`);
    assert.ok(overflow.nav <= 1, `nav overflow in ${theme}: ${overflow.nav}`);
  }

  // 9. Assign batch folder and commit -> verify payload, plaintext cleared, sealed .env copy, and undo!
  await page.fill("#import-batch-folder", "Production");
  await page.click("#import-commit-btn");
  await page.waitForSelector("#import-done-banner:not(.hidden)");

  const commits = await page.evaluate(() => window.fixture.commitCalls);
  assert.equal(commits.length, 1);
  assert.equal(commits[0].folder, "Production");
  assert.equal(commits[0].items.length, 3);
  assert.equal(commits[0].items[0].input.name, "OpenAI Prod Key");
  assert.equal(commits[0].items[1].updateExisting, true);
  assert.equal(await page.locator("#import-raw-input").inputValue(), "");

  // Copy sealed .env template
  await page.click("#import-done-sealed");
  const copied = await page.evaluate(() => window.fixture.copiedValues);
  assert.equal(copied[0], "OPENAI_API_KEY={{openkeylet:OPENAI_API_KEY}}\n");

  // Undo newly added items
  await page.click("#import-done-undo");
  const undos = await page.evaluate(() => window.fixture.undoCalls);
  assert.deepEqual(undos, [["new-id-1", "new-id-2"]]);

  // 10. Local dev config scan button
  await page.click("#import-chip-scan");
  await page.waitForSelector(".import-card");
  assert.equal(await page.evaluate(() => window.fixture.scanCalls), 1);

  // 11. Locking vault immediately wipes staged plaintext from Import Hub
  await page.click("#owner-lock-button");
  await page.waitForSelector("#owner-lock-layer:not(.hidden)");
  assert.equal(await page.locator(".import-card").count(), 0);
  assert.equal(await page.locator("#import-raw-input").inputValue(), "");

  assert.deepEqual(errors, [], `Unexpected page errors: ${errors.join("; ")}`);
  console.log("Import Hub 4-tab UI E2E tests passed (dark + light, ZH, dedup, noise restore, batch commit, sealed .env, undo, lock wipe).");
} finally {
  await browser.close();
  server.close();
}
