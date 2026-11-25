// End-to-end real-user interactive journey tests for OpenKeylet Import Hub & Editor.
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
      settings: { language: "zh", closeBehavior: "tray", browserEnabled: false, browserPort: 39272 },
      connections: [],
      activities: [],
      mcp: { status: "ready", stdioCommand: "openkeylet" },
      browserBridge: { status: "off" },
      security: { encrypted: true },
    };

    window.scenario = {
      clipboardText: "",
      savedDrafts: [],
      savedItems: [],
      commits: [],
      openedMvaults: [],
    };

    window.__TAURI__ = {
      event: { listen: async () => () => {} },
      core: {
        invoke: async (cmd, args = {}) => {
          if (cmd === "get_state") return JSON.parse(JSON.stringify(state));
          if (cmd === "owner_status") return { pinConfigured: true, unlocked: true, expiresInSeconds: 0, autoLockMinutes: 0 };
          if (cmd === "owner_editor_drafts") return window.scenario.savedDrafts;
          if (cmd === "save_owner_editor_draft") {
            const draft = { id: args.id || `draft-${window.scenario.savedDrafts.length + 1}`, updatedAt: new Date().toISOString(), input: args.input };
            window.scenario.savedDrafts.push(draft);
            return draft;
          }
          if (cmd === "delete_owner_editor_draft") {
            window.scenario.savedDrafts = window.scenario.savedDrafts.filter((d) => d.id !== args.id);
            return true;
          }
          if (cmd === "save_connection") {
            const saved = { id: args.input?.id || `conn-${state.connections.length + 1}`, ...args.input, enabled: args.input?.enabled ?? true };
            window.scenario.savedItems.push(saved);
            state.connections.push(saved);
            return saved;
          }
          if (cmd === "read_owner_clipboard") return window.scenario.clipboardText;
          if (cmd === "clear_clipboard_if_matches") return true;
          if (cmd === "copy_owner_value") return true;
          if (cmd === "system_integration_status") return { desktopShortcut: false, launchAtLogin: false };
          if (cmd === "agent_mcp_status") return [];
          if (cmd === "list_chrome_profiles") return [];
          if (cmd === "github_backup_status") return { configured: false, repo: "", branch: "main", autoSync: false, status: "idle" };
          if (cmd === "update_status") return { phase: "idle", currentVersion: "0.16.0", platform: "windows-x64", autoCheck: false, autoDownload: false };
          if (cmd === "set_edge_dock_enabled") return null;
          if (cmd === "smart_extract_batch") {
            const text = String(args.text || "");
            if (text.includes("just a reminder")) {
              return { detectedFormat: "mixed_text", detectedFormatZh: "混合文本", candidates: [], ignored: [], warnings: [], sealedEnvTemplate: null };
            }
            return {
              detectedFormat: "mixed_text",
              detectedFormatZh: "混合文本智能提取",
              warnings: [],
              sealedEnvTemplate: "OPENAI_API_KEY={{openkeylet:OPENAI_API_KEY}}\n",
              candidates: [
                {
                  id: "u-ssh-1",
                  kind: "ssh",
                  badge: "SSH",
                  badgeZh: "SSH",
                  confidence: "high",
                  selected: true,
                  summary: "root@47.98.120.44:2222",
                  sourceSnippet: "SSH 47.98.120.44:2222",
                  matchStatus: "new",
                  updateExisting: false,
                  fields: [
                    { label: "Host", value: "47.98.120.44", masked: "47.98.120.44", secret: false },
                    { label: "User", value: "root", masked: "root", secret: false },
                    { label: "Password", value: "Ops@2026!#", masked: "Op••••!#", secret: true },
                  ],
                  input: {
                    name: "生产阿里云",
                    itemType: "ssh",
                    folder: "",
                    modules: [
                      { kind: "host", name: "host", value: "47.98.120.44", agentVisible: true },
                      { kind: "port", name: "port", value: "2222", agentVisible: true },
                      { kind: "username", name: "username", value: "", agentVisible: false },
                      { kind: "password", name: "password", value: "", agentVisible: false },
                    ],
                    secrets: { password: "Ops@2026!#", namedSecrets: { username: "root" } },
                  },
                },
                {
                  id: "u-api-2",
                  kind: "apiKey",
                  badge: "API",
                  badgeZh: "API",
                  confidence: "high",
                  selected: true,
                  summary: "DeepSeek API · api.deepseek.com",
                  sourceSnippet: "sk-de••••cdef",
                  matchStatus: "new",
                  updateExisting: false,
                  fields: [
                    { label: "URL", value: "https://api.deepseek.com/", masked: "https://api.deepseek.com/", secret: false },
                    { label: "API Key", value: "sk-deepseekrealkey1234567890abcdef", masked: "sk-de••••cdef", secret: true },
                  ],
                  input: {
                    name: "DeepSeek API",
                    itemType: "api",
                    folder: "",
                    modules: [
                      { kind: "url", name: "url", value: "https://api.deepseek.com/", agentVisible: true },
                      { kind: "apiCredential", name: "apiCredential", value: "", agentVisible: false },
                    ],
                    secrets: { namedSecrets: { apiCredential: "sk-deepseekrealkey1234567890abcdef" } },
                  },
                },
              ],
              ignored: [
                {
                  reason: "non_secret",
                  reasonZh: "非敏感普通配置",
                  key: "APP_ENV",
                  preview: "staging",
                  candidate: {
                    id: "u-ign-1",
                    kind: "env",
                    badge: "ENV",
                    badgeZh: "环境",
                    confidence: "low",
                    selected: true,
                    summary: "APP_ENV = staging",
                    sourceSnippet: ".env",
                    matchStatus: "new",
                    updateExisting: false,
                    fields: [{ label: "APP_ENV", value: "staging", masked: "st••••ng", secret: true }],
                    input: { name: "APP_ENV", itemType: "custom", folder: "Env", modules: [{ kind: "customSecret", name: "APP_ENV", value: "", agentVisible: false }], secrets: { namedSecrets: { APP_ENV: "staging" } } },
                  },
                },
              ],
            };
          }
          if (cmd === "smart_scan_local_dev_configs") {
            return {
              detectedFormat: "local_search",
              detectedFormatZh: "本机一键搜索",
              warnings: [],
              ignored: [],
              candidates: [
                {
                  id: "pc-1",
                  kind: "aws",
                  badge: "AWS",
                  badgeZh: "AWS",
                  confidence: "high",
                  selected: true,
                  summary: "AWS · prod · ap-southeast-1",
                  sourceSnippet: "~/.aws/credentials",
                  matchStatus: "new",
                  updateExisting: false,
                  fields: [{ label: "AWS_ACCESS_KEY_ID", value: "AKIAIOSFODNN7PCSCAN1", masked: "AKIAI••••CAN1", secret: true }],
                  input: { name: "AWS (prod)", itemType: "custom", folder: "Cloud", modules: [], secrets: { namedSecrets: { AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7PCSCAN1" } } },
                },
                {
                  id: "pc-2",
                  kind: "database",
                  badge: "DB",
                  badgeZh: "数据库",
                  confidence: "high",
                  selected: false,
                  summary: "appuser@pg.internal:5432/app",
                  sourceSnippet: "AppData/postgresql/pgpass.conf",
                  matchStatus: "duplicate",
                  updateExisting: false,
                  fields: [{ label: "Host", value: "pg.internal", masked: "pg.internal", secret: false }],
                  input: { name: "PostgreSQL · pg.internal/app", itemType: "custom", folder: "Database", modules: [], secrets: {} },
                },
              ],
              discoveredMvaults: [
                { index: 0, fileName: "openkeylet-backup-2026.mvault", displayPath: "Downloads/openkeylet-backup-2026.mvault" },
              ],
              scanReport: {
                mode: "quick_pc",
                totalInspectedFiles: 312,
                totalMatchedFiles: 3,
                durationMs: 28,
                categories: [
                  { id: "ssh_keys", label: "SSH & Keys", labelZh: "SSH 与私钥", probedLocations: 2, inspectedFiles: 2, matchedFiles: 0, extractedCount: 0 },
                  { id: "dev_cloud", label: "Git · Cloud · CLI", labelZh: "Git 与云凭据", probedLocations: 19, inspectedFiles: 6, matchedFiles: 2, extractedCount: 2 },
                  { id: "ai_mcp", label: "AI & MCP Configs", labelZh: "AI 与 MCP 配置", probedLocations: 15, inspectedFiles: 2, matchedFiles: 0, extractedCount: 0 },
                  { id: "user_files", label: "Desktop · Docs · Downloads", labelZh: "桌面 · 文档 · 下载", probedLocations: 3, inspectedFiles: 302, matchedFiles: 1, extractedCount: 1 },
                ],
              },
            };
          }
          if (cmd === "open_discovered_mvault") {
            window.scenario.openedMvaults.push(args.index);
            return { fileName: "openkeylet-backup-2026.mvault", requiresPassword: true };
          }
          if (cmd === "commit_smart_batch") {
            window.scenario.commits.push(args);
            return { added: args.items.length, updated: 0, createdIds: args.items.map((_, i) => `created-${i + 1}`) };
          }
          return null;
        },
      },
    };
  });

  const port = server.address().port;
  await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: "networkidle" });
  await page.click('.nav-item[data-page="import"]');

  // Journey 1: Click 1-click Quick-Create Template -> Esc without changes (0 drafts!) -> Fill & Save + Toggle Reveal All
  await page.click('[data-import-quick-template="login"]');
  await page.locator("#connection-modal").waitFor({ state: "visible" });
  await page.keyboard.press("Escape");
  await page.locator("#connection-modal").waitFor({ state: "hidden" });
  assert.equal(await page.evaluate(() => window.scenario.savedDrafts.length), 0, "Escaping untouched quick-template creates 0 drafts");

  await page.click('[data-import-quick-template="login"]');
  await page.locator("#connection-modal").waitFor({ state: "visible" });
  await page.fill("#connection-name", "公司 OA 后台");
  const secretInputs = page.locator('#module-list [data-secret-value]');
  await secretInputs.nth(0).fill("alice@company.io");
  await secretInputs.nth(1).fill("OaSuperPass!2026");
  // Bulk reveal all / hide all secrets in editor
  assert.equal(await page.locator("#toggle-all-secrets-button").isVisible(), true, "Bulk reveal-all button visible for >=2 secrets");
  await page.click("#toggle-all-secrets-button");
  assert.equal(await page.locator("#toggle-all-secrets-button").getAttribute("aria-pressed"), "true");
  assert.equal(await secretInputs.nth(1).getAttribute("type"), "text", "Password input revealed by bulk toggle");
  await page.click("#toggle-all-secrets-button");
  assert.equal(await secretInputs.nth(1).getAttribute("type"), "password", "Password input hidden again by bulk toggle");
  await page.click('#connection-form button[type="submit"]');
  await page.locator("#connection-modal").waitFor({ state: "hidden" });
  assert.equal(await page.evaluate(() => window.scenario.savedItems.length), 1, "Manual quick-template item saved cleanly");

  // Journey 2: Paste unrecognized plain text -> user gets explicit toast feedback (not silent!)
  await page.evaluate(() => { window.scenario.clipboardText = "just a reminder to buy milk"; });
  await page.click("#import-paste-btn");
  await page.waitForSelector("#toast-region .toast");
  assert.match(await page.locator("#toast-region .toast").last().innerText(), /未识别到结构化凭据/);
  assert.equal(await page.locator(".import-card").count(), 0);

  // Journey 3: Paste realistic WeChat handover -> inspect in editor (Esc creates 0 drafts!) -> save one via editor -> commit remaining
  await page.evaluate(() => { window.scenario.clipboardText = "生产阿里云 47.98.120.44 端口2222 账号 root 密码 Ops@2026!#\nDeepSeek: sk-deepseekrealkey1234567890abcdef"; });
  await page.click("#import-paste-btn");
  await page.waitForSelector(".import-card");
  assert.equal(await page.locator(".import-card").count(), 2);

  // Open SSH candidate in editor -> press Escape without changes -> must NOT save a bogus draft!
  await page.click('[data-import-edit-card="u-ssh-1"]');
  await page.locator("#connection-modal").waitFor({ state: "visible" });
  assert.equal(await page.locator("#connection-name").inputValue(), "生产阿里云");
  await page.keyboard.press("Escape");
  await page.locator("#connection-modal").waitFor({ state: "hidden" });
  assert.equal(await page.evaluate(() => window.scenario.savedDrafts.length), 0, "Escaping untouched candidate editor creates 0 bogus drafts");

  // Re-open SSH candidate -> refine name & save directly -> removes it from staging list!
  await page.click('[data-import-edit-card="u-ssh-1"]');
  await page.locator("#connection-modal").waitFor({ state: "visible" });
  await page.fill("#connection-name", "生产阿里云 · 华东");
  await page.click('#connection-form button[type="submit"]');
  await page.locator("#connection-modal").waitFor({ state: "hidden" });
  assert.equal(await page.locator(".import-card").count(), 1, "Candidate saved in editor is removed from staging list");

  // Commit remaining DeepSeek API card
  await page.click("#import-commit-btn");
  await page.waitForSelector("#import-done-banner:not(.hidden)");
  assert.equal(await page.evaluate(() => window.scenario.commits.length), 1);
  assert.equal(await page.evaluate(() => window.scenario.commits[0].items.length), 1);

  // Journey 4: Scan PC -> get 1 new + 1 dup + 1 .mvault -> commit the 1 new credential -> .mvault card MUST STAY READY TO IMPORT!
  await page.click("#import-mode-scan");
  await page.click("#import-chip-scan");
  await page.waitForSelector(".import-card");
  assert.equal(await page.locator(".import-card").count(), 3, "2 scanned credentials + 1 unified .mvault card");
  assert.equal(await page.locator("#import-commit-btn").textContent(), "一键入库 (1)", "Duplicate item auto-unchecked");

  await page.click("#import-commit-btn");
  await page.waitForSelector("#import-done-banner:not(.hidden)");
  assert.equal(await page.locator('.import-card.is-backup[data-import-mvault="0"]').count(), 1, "Discovered .mvault backup card stays clickable after committing credentials");
  await page.click('[data-open-discovered-mvault="0"]');
  assert.deepEqual(await page.evaluate(() => window.scenario.openedMvaults), [0]);
  await page.click("#mvault-modal-close");

  // Switch back to Add tab -> zero bleed from Scan tab
  await page.click("#import-mode-add");
  assert.equal(await page.locator('.import-card.is-backup').count(), 0, "Add tab stays completely isolated from Scan tab");

  assert.deepEqual(errors, [], `Unexpected page errors: ${errors.join("; ")}`);
  console.log("All 4 end-to-end real-user interactive journeys passed cleanly!");
} finally {
  await browser.close();
  server.close();
}
