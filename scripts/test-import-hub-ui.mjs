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
      workspaceScanCalls: 0,
      openedMvaultIndices: [],
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
          sourceRefs: ["ref-env-1"],
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
            return { pinConfigured: true, unlocked: window.fixture.unlocked, expiresInSeconds: 0, autoLockMinutes: 0 };
          }
          if (cmd === "owner_lock") {
            window.fixture.unlocked = false;
            return { pinConfigured: true, unlocked: false, expiresInSeconds: 0, autoLockMinutes: 0 };
          }
          if (cmd === "owner_editor_drafts") return [];
          if (cmd === "system_integration_status") return { desktopShortcut: false, launchAtLogin: false };
          if (cmd === "agent_mcp_status") return [];
          if (cmd === "list_chrome_profiles") return [];
          if (cmd === "github_backup_status") return { configured: false, repo: "", branch: "main", autoSync: false, status: "idle" };
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
            const scanCandidates = [
              ...Array.from({ length: 5 }, (_, i) => ({
                ...JSON.parse(JSON.stringify(sampleResult.candidates[0])),
                id: `scan-api-${i + 1}`,
                sourceSnippet: `~/.codex/config-${i + 1}.toml`,
                input: {
                  ...JSON.parse(JSON.stringify(sampleResult.candidates[0].input)),
                  name: `OpenAI API (codex ${i + 1})`,
                },
              })),
              JSON.parse(JSON.stringify(sampleResult.candidates[2])),
            ];
            return {
              detectedFormat: "local_search",
              detectedFormatZh: "本机一键搜索",
              warnings: [],
              ignored: [],
              candidates: scanCandidates,
              discoveredMvaults: [
                {
                  index: 0,
                  fileName: "openkeylet-backup.mvault",
                  displayPath: "Downloads/openkeylet-backup.mvault",
                },
              ],
              scanReport: {
                mode: "quick_pc",
                totalInspectedFiles: 184,
                totalMatchedFiles: 2,
                durationMs: 19,
                categories: [
                  { id: "ssh_keys", label: "SSH & Keys", labelZh: "SSH 与私钥", probedLocations: 2, inspectedFiles: 3, matchedFiles: 1, extractedCount: 1 },
                  { id: "dev_cloud", label: "Git · Cloud · CLI", labelZh: "Git 与云凭据", probedLocations: 18, inspectedFiles: 4, matchedFiles: 0, extractedCount: 0 },
                  { id: "ai_mcp", label: "AI & MCP Configs", labelZh: "AI 与 MCP 配置", probedLocations: 15, inspectedFiles: 3, matchedFiles: 1, extractedCount: 5 },
                  { id: "user_files", label: "Desktop · Docs · Downloads", labelZh: "桌面 · 文档 · 下载", probedLocations: 3, inspectedFiles: 174, matchedFiles: 1, extractedCount: 1 },
                ],
              },
            };
          }
          if (cmd === "open_discovered_mvault") {
            window.fixture.openedMvaultIndices.push(args.index);
            return { fileName: "openkeylet-backup.mvault", requiresPassword: true };
          }
          if (cmd === "smart_scan_workspace_folder") {
            window.fixture.workspaceScanCalls += 1;
            return {
              detectedFormat: "workspace_scan",
              detectedFormatZh: "目录深扫 · Github",
              warnings: [],
              ignored: [],
              candidates: [JSON.parse(JSON.stringify(sampleResult.candidates[0]))],
              scanReport: {
                mode: "workspace_folder",
                targetLabel: "S:/Github",
                totalInspectedFiles: 642,
                totalMatchedFiles: 1,
                durationMs: 34,
                categories: [
                  { id: "env_files", label: "Env Files (.env*)", labelZh: ".env 环境文件", probedLocations: 1, inspectedFiles: 2, matchedFiles: 1, extractedCount: 1 },
                  { id: "ssh_keys", label: "SSH & Keys", labelZh: "私钥与证书", probedLocations: 1, inspectedFiles: 0, matchedFiles: 0, extractedCount: 0 },
                  { id: "project_configs", label: "Configs & Backups", labelZh: "配置与备份", probedLocations: 1, inspectedFiles: 1, matchedFiles: 0, extractedCount: 0 },
                ],
              },
            };
          }
          if (cmd === "commit_smart_batch") {
            window.fixture.commitCalls.push(args);
            return {
              added: 2,
              updated: 1,
              createdIds: ["new-id-1", "new-id-2"],
              plaintextSources: [
                { displayPath: "~/Projects/very-long-workspace-directory-name/services/payments-api/.env.production.local", kind: "env" },
                { displayPath: "~/.ssh/id_ed25519", kind: "key" },
                { displayPath: "~/.claude/CLAUDE.md", kind: "agent" },
                { displayPath: "~/.zsh_history", kind: "shell" },
              ],
            };
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

  // 2. Click 2nd tab (导入) and verify page & metrics switch + 1-click quick-create template cards
  await page.click('.nav-item[data-page="import"]');
  assert.equal(await page.locator(".nav").getAttribute("data-active"), "import");
  assert.ok(await page.locator("#page-import").evaluate((el) => el.classList.contains("active")));
  assert.equal(await page.locator(".import-template-card").count(), 6, "Add tab provides 6 1-click quick-create template cards");
  await page.click('[data-import-quick-template="api"]');
  await page.locator("#connection-modal").waitFor({ state: "visible" });
  assert.equal(await page.locator("#connection-type").inputValue(), "api", "Clicking API quick-template opens editor directly in API mode");
  await page.keyboard.press("Escape");
  await page.locator("#connection-modal").waitFor({ state: "hidden" });
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

  // 7b. Clickable Import HUD metrics (已识别 / 待入库) reset filters, focus & cycle selected candidates
  const importMetrics = await page.evaluate(() => ({
    primaryTag: document.querySelector('[data-metric-action="focus-import-all"]')?.tagName,
    secondaryTag: document.querySelector('[data-metric-action="focus-import-selected"]')?.tagName,
    primaryActionable: document.querySelector('[data-metric-action="focus-import-all"]')?.classList.contains("metric-actionable"),
    secondaryActionable: document.querySelector('[data-metric-action="focus-import-selected"]')?.classList.contains("metric-actionable"),
  }));
  assert.equal(importMetrics.primaryTag, "BUTTON", "已识别 metric is a clickable button");
  assert.equal(importMetrics.secondaryTag, "BUTTON", "待入库 metric is a clickable button");
  assert.equal(importMetrics.primaryActionable, true);
  assert.equal(importMetrics.secondaryActionable, true);

  // Filter by kind + search, then click 已识别 -> clears both and pulses first candidate
  await page.click('[data-import-kind="apiKey"]');
  await page.fill("#title-search-input", "OpenAI");
  assert.equal(await page.locator(".import-card").count(), 1);
  await page.click('[data-metric-action="focus-import-all"]');
  assert.equal(await page.locator("#title-search-input").inputValue(), "", "已识别 metric clears search");
  assert.equal(await page.locator(".import-card").count(), 4, "已识别 metric resets kind filter to show all candidates");
  assert.equal(await page.locator('[data-import-card="cand-api-1"]').evaluate((el) => el.classList.contains("is-focus-pulse")), true, "已识别 metric pulses first candidate");
  assert.equal(await page.evaluate(() => document.activeElement?.closest(".import-card")?.dataset.importCard), "cand-api-1");

  // Click 待入库 repeatedly -> cycles selected candidates (cand-api-1 -> cand-login-2 -> cand-env-port), skipping unchecked cand-ssh-3
  for (const expectedId of ["cand-api-1", "cand-login-2", "cand-env-port", "cand-api-1"]) {
    await page.click('[data-metric-action="focus-import-selected"]');
    assert.equal(
      await page.locator(`[data-import-card="${expectedId}"]`).evaluate((el) => el.classList.contains("is-focus-pulse")),
      true,
      `待入库 metric pulses selected candidate ${expectedId}`
    );
    assert.equal(await page.evaluate(() => document.activeElement?.closest(".import-card")?.dataset.importCard), expectedId);
  }

  // With 0 / 4 selected, clicking 待入库 keeps all extracted cards visible and focuses #import-toggle-all
  for (const id of ["cand-api-1", "cand-login-2", "cand-env-port"]) {
    await page.uncheck(`[data-import-check="${id}"]`);
  }
  assert.equal(await page.locator("#import-commit-btn").textContent(), "一键入库 (0)");
  await page.click('[data-metric-action="focus-import-selected"]');
  assert.equal(await page.locator(".import-card").count(), 4, "待入库 with 0 selected keeps extracted candidates visible");
  assert.equal(await page.evaluate(() => document.activeElement?.id), "import-toggle-all", "待入库 with 0 selected focuses select-all control");
  for (const id of ["cand-api-1", "cand-login-2", "cand-env-port"]) {
    await page.check(`[data-import-check="${id}"]`);
  }
  assert.equal(await page.locator("#import-commit-btn").textContent(), "一键入库 (3)");

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
  // Opaque source references travel back with each item; paths never leave the backend.
  assert.deepEqual(commits[0].items[0].sourceRefs, ["ref-env-1"]);
  assert.deepEqual(commits[0].items[1].sourceRefs, []);

  // Done view lists the files that still hold plaintext, each with its next step
  const plaintextPanel = page.locator("#import-plaintext-sources");
  assert.equal(await plaintextPanel.isVisible(), true, "Done view shows the plaintext-still-on-disk list");
  assert.equal(await page.locator(".import-plaintext-title").textContent(), "明文仍留在磁盘上");
  assert.equal(await page.locator(".import-plaintext-row").count(), 4);
  const plaintextRows = await page.locator(".import-plaintext-row").evaluateAll((rows) =>
    rows.map((row) => ({
      kind: row.dataset.plaintextKind,
      path: row.querySelector(".import-plaintext-path")?.textContent,
      step: row.querySelector(".import-plaintext-step")?.textContent,
    }))
  );
  assert.deepEqual(plaintextRows.map((r) => r.kind), ["env", "key", "agent", "shell"]);
  assert.equal(plaintextRows[1].path, "~/.ssh/id_ed25519");
  assert.match(plaintextRows[0].step, /脱敏 \.env 模板/);
  assert.match(plaintextRows[1].step, /金库中的副本可用后删除/);
  assert.match(plaintextRows[3].step, /删除包含密钥的那一行/);
  // The long path is ellipsized from the left so the file name stays visible
  const longPath = await page.locator(".import-plaintext-path").first().evaluate((el) => ({
    clipped: el.scrollWidth > el.clientWidth,
    direction: getComputedStyle(el).direction,
  }));
  assert.equal(longPath.clipped, true, "Long path is clipped inside its row instead of widening the banner");
  assert.equal(longPath.direction, "rtl");
  await page.click("#import-done-copy-paths");
  assert.equal(
    (await page.evaluate(() => window.fixture.copiedValues)).at(-1),
    "~/Projects/very-long-workspace-directory-name/services/payments-api/.env.production.local\n~/.ssh/id_ed25519\n~/.claude/CLAUDE.md\n~/.zsh_history\n"
  );

  // The list stays inside the 460px frame in all 6 languages and both themes
  const plaintextTitles = {
    en: "Plaintext is still on disk",
    zh: "明文仍留在磁盘上",
    "zh-TW": "明文仍留在磁碟上",
    ja: "平文がまだディスクに残っています",
    ko: "평문이 아직 디스크에 남아 있습니다",
    es: "El texto plano sigue en el disco",
  };
  for (const [langCode, expectedTitle] of Object.entries(plaintextTitles)) {
    await page.click(`.nav-item[data-page="settings"]`);
    await page.click(`#language-switch button[data-language="${langCode}"]`);
    await page.click(`.nav-item[data-page="import"]`);
    assert.equal(await page.locator(".import-plaintext-title").textContent(), expectedTitle, `plaintext title in ${langCode}`);
    const steps = await page.locator(".import-plaintext-step").allTextContents();
    assert.ok(steps.every((s) => s.trim().length > 0), `every row has a next step in ${langCode}`);
    for (const theme of ["dark", "light"]) {
      await page.evaluate((t) => document.documentElement.setAttribute("data-theme", t), theme);
      const overflow = await page.evaluate(() => {
        const banner = document.querySelector("#import-done-banner");
        const panel = document.querySelector("#import-plaintext-sources");
        return {
          doc: document.documentElement.scrollWidth - document.documentElement.clientWidth,
          banner: banner.scrollWidth - banner.clientWidth,
          panel: panel.scrollWidth - panel.clientWidth,
          rows: Math.max(...[...panel.querySelectorAll(".import-plaintext-row")].map((r) => r.scrollWidth - r.clientWidth)),
        };
      });
      for (const [area, value] of Object.entries(overflow)) {
        assert.ok(value <= 1, `${area} overflow in done view ${langCode}/${theme}: ${value}`);
      }
    }
  }
  await page.click(`.nav-item[data-page="settings"]`);
  await page.click(`#language-switch button[data-language="zh"]`);
  await page.click(`.nav-item[data-page="import"]`);
  await page.evaluate(() => document.documentElement.setAttribute("data-theme", "dark"));

  // Copy sealed .env template
  await page.click("#import-done-sealed");
  const copied = await page.evaluate(() => window.fixture.copiedValues);
  assert.equal(copied.at(-1), "OPENAI_API_KEY={{openkeylet:OPENAI_API_KEY}}\n");

  // Undo newly added items
  await page.click("#import-done-undo");
  const undos = await page.evaluate(() => window.fixture.undoCalls);
  assert.deepEqual(undos, [["new-id-1", "new-id-2"]]);

  // 10. Two-tier Add / Scan hierarchy, compact collapsible scan telemetry, unified .mvault item & 4+ visible rows
  assert.equal(await page.locator("#import-mode-switch").getAttribute("data-mode"), "add");
  assert.equal(await page.locator("#import-subbar-add").isVisible(), true);
  assert.equal(await page.locator("#import-subbar-scan").isHidden(), true);

  await page.click("#import-mode-scan");
  assert.equal(await page.locator("#import-mode-switch").getAttribute("data-mode"), "scan");
  assert.equal(await page.locator("#import-subbar-scan").isVisible(), true);
  assert.equal(await page.locator("#import-subbar-add").isHidden(), true);
  assert.equal(await page.locator("#import-dropzone").isHidden(), true, "Add dropzone is hidden in Scan mode");

  await page.click("#import-chip-scan");
  await page.waitForSelector(".import-card");
  assert.equal(await page.evaluate(() => window.fixture.scanCalls), 1);

  // Discovered .mvault renders as a normal unified item inside #import-candidate-list (no standalone orange banner)
  assert.equal(await page.locator("#import-mvault-banner").count(), 0, "No standalone special .mvault banner exists");
  assert.equal(await page.locator('.import-card.is-backup[data-import-mvault="0"]').count(), 1, ".mvault integrates as a unified item card");
  assert.equal(await page.locator(".import-card").count(), 7, "All 6 credentials + 1 .mvault backup appear in the unified list");
  assert.match(await page.locator('[data-import-kind="all"]').innerText(), /7/);
  assert.match(await page.locator('[data-import-kind="mvault"]').innerText(), /备份 1/);

  // Scan telemetry defaults to compact 1-line strip when hits exist, maximizing content space (4+ cards visible at 460x690)
  assert.ok(await page.locator("#import-scan-banner").evaluate((el) => el.classList.contains("is-compact-summary")));
  assert.equal(await page.locator(".import-scan-details").isHidden(), true, "Scan category grid stays collapsed by default when results exist");
  assert.match(await page.locator("#import-scan-banner").innerText(), /184/);

  const visibleCardsBeforeScroll = await page.evaluate(() => {
    const scroller = document.querySelector("#import-scroll-area").getBoundingClientRect();
    const cards = [...document.querySelectorAll(".import-card")];
    return cards.filter((card) => {
      const r = card.getBoundingClientRect();
      return r.top >= scroller.top - 1 && r.bottom <= scroller.bottom + 2;
    }).length;
  });
  assert.ok(visibleCardsBeforeScroll >= 4, `Expected at least 4 complete cards visible in 460x690 viewport, got ${visibleCardsBeforeScroll}`);

  // Expand scan telemetry details on demand -> inspect 4 uniform scope tiles
  await page.click('[data-toggle-scan-details="true"]');
  assert.equal(await page.locator(".import-scan-details").isVisible(), true);
  assert.equal(await page.locator(".import-scan-cat").count(), 4);
  assert.match(await page.locator("#import-scan-banner").innerText(), /AI 与 MCP 配置/);

  // Filter to unified Backup (.mvault) kind & trigger inline import action
  await page.click('[data-import-kind="mvault"]');
  assert.equal(await page.locator(".import-card").count(), 1);
  await page.click('[data-open-discovered-mvault="0"]');
  assert.deepEqual(await page.evaluate(() => window.fixture.openedMvaultIndices), [0]);
  await page.click("#mvault-modal-close");
  await page.click('[data-import-kind="all"]');

  // Switching from Scan tab to Add tab shows a completely isolated clean Add workspace (no scan results or scan banner bleed)
  await page.click("#import-mode-add");
  assert.equal(await page.locator("#import-mode-switch").getAttribute("data-mode"), "add");
  assert.equal(await page.locator(".import-card").count(), 0, "Add tab must not show Scan tab results");
  assert.equal(await page.locator("#import-scan-banner").isHidden(), true, "Add tab must not show Scan telemetry banner");
  assert.equal(await page.locator("#import-dropzone").isVisible(), true, "Add tab shows clean paste/drop input");
  assert.equal(await page.locator("#import-clear-btn").isHidden(), true, "Clear button hidden when Add tab is empty");
  assert.equal(await page.locator("#import-mode-scan-count").textContent(), "7", "Scan tab badge preserves staged item count");
  assert.equal(await page.locator(".lcd-primary .seven-number").getAttribute("aria-label"), "0", "Top HUD reflects empty Add tab");

  // Switching back to Scan tab restores all 7 scan results intact
  await page.click("#import-mode-scan");
  assert.equal(await page.locator(".import-card").count(), 7, "Switching back to Scan restores all scan results");
  assert.equal(await page.locator("#import-scan-banner").isVisible(), true);
  assert.equal(await page.locator(".lcd-primary .seven-number").getAttribute("aria-label"), "7", "Top HUD restores Scan tab count");

  // Workspace folder deep scan directly from Tier-2 Scan bar
  await page.click('[data-scan-workspace-folder="true"]');
  assert.equal(await page.evaluate(() => window.fixture.workspaceScanCalls), 1);
  await page.click('[data-toggle-scan-details="true"]');
  assert.equal(await page.locator(".import-scan-cat").count(), 3);
  assert.match(await page.locator("#import-scan-banner").innerText(), /S:\/Github/);

  // Verify zero horizontal overflow across all 6 languages & both themes in BOTH Add and Scan tiers
  for (const langCode of ["en", "zh", "zh-TW", "ja", "ko", "es"]) {
    await page.click(`.nav-item[data-page="settings"]`);
    await page.click(`#language-switch button[data-language="${langCode}"]`);
    await page.click(`.nav-item[data-page="import"]`);
    for (const mode of ["scan", "add"]) {
      await page.click(`[data-import-mode="${mode}"]`);
      for (const theme of ["dark", "light"]) {
        await page.evaluate((t) => document.documentElement.setAttribute("data-theme", t), theme);
        const overflow = await page.evaluate(() => ({
          doc: document.documentElement.scrollWidth - document.documentElement.clientWidth,
          deck: document.querySelector("#import-deck").scrollWidth - document.querySelector("#import-deck").clientWidth,
          banner: document.querySelector("#import-scan-banner").scrollWidth - document.querySelector("#import-scan-banner").clientWidth,
        }));
        assert.ok(overflow.doc <= 1, `doc overflow in ${langCode}/${mode}/${theme}: ${overflow.doc}`);
        assert.ok(overflow.deck <= 1, `deck overflow in ${langCode}/${mode}/${theme}: ${overflow.deck}`);
        assert.ok(overflow.banner <= 1, `scan banner overflow in ${langCode}/${mode}/${theme}: ${overflow.banner}`);
      }
    }
  }
  await page.click(`.nav-item[data-page="settings"]`);
  await page.click(`#language-switch button[data-language="zh"]`);
  await page.click(`.nav-item[data-page="import"]`);
  await page.click("#import-mode-scan");

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
