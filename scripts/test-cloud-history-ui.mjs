// Synthetic renderer E2E test for cloud version history: open history, pick a version,
// preview it, restore a selection, plus the failed-discovery notice. No GitHub account or
// real vault is accessed.
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
    const type = file.endsWith(".js") ? "text/javascript" : file.endsWith(".css") ? "text/css"
      : file.endsWith(".svg") ? "image/svg+xml" : file.endsWith(".png") ? "image/png" : "text/html";
    res.setHeader("Content-Type", type);
    res.end(await fs.readFile(file));
  } catch {
    res.writeHead(404);
    res.end();
  }
});
server.listen(0, "127.0.0.1");
await once(server, "listening");

const SHA = (seed) => seed.repeat(40).slice(0, 40);
const HEAD = SHA("a1");
const OLDER = SHA("b2");
const FOREIGN = SHA("c3");
const OLDEST = SHA("d4");
const IDS = {
  changed: "11111111-1111-4111-8111-111111111111",
  deleted: "22222222-2222-4222-8222-222222222222",
  trash: "33333333-3333-4333-8333-333333333333",
  same: "44444444-4444-4444-8444-444444444444",
  long: "55555555-5555-4555-8555-555555555555",
  extra: "66666666-6666-4666-8666-666666666666",
};

const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 460, height: 690 } });
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.addInitScript(({ HEAD, OLDER, FOREIGN, OLDEST, IDS }) => {
    const params = new URLSearchParams(location.search);
    const language = params.get("lang") || "en";
    const state = {
      settings: { language, closeBehavior: "tray", browserEnabled: false, browserPort: 39272, ownerAutoLockMinutes: 15 },
      connections: [], activities: [], mcp: { status: "ready", stdioCommand: "openkeylet" },
      browserBridge: { status: "off" }, security: { encrypted: true },
    };
    const connected = (extra = {}) => ({
      connected: true, provider: "github", serverUrl: "", repository: "fixture-user/openkeylet-vault",
      keyRepository: "fixture-user/openkeylet-vault-key", branch: "main", autoSync: true, pendingSync: false,
      needsRestore: false, hasRemoteBackup: true, lastSyncedAt: "2026-11-24T12:00:00Z", ...extra,
    });
    const item = (id, name, status, extra = {}) => ({
      id, name, status, currentName: null, assignedName: null, itemType: "login", folder: "",
      summary: "mail.example.test", passkeyCount: 0, historyCount: 0, ...extra,
    });
    window.fixture = {
      status: connected({ hasRemoteBackup: params.get("remote") !== "0" }),
      historyCalls: [], prepares: [], commits: [], cancels: 0, discoveryFailed: false,
    };
    window.__TAURI__ = { event: { listen: async () => () => {} }, core: { invoke: async (command, args = {}) => {
      if (command === "get_state") return structuredClone(state);
      if (command === "owner_status") return { pinConfigured: false, unlocked: true, expiresInSeconds: 0, mode: "none" };
      if (command === "owner_editor_drafts" || command === "agent_mcp_status" || command === "list_chrome_profiles") return [];
      if (command === "system_integration_status") return { desktopShortcut: false, launchAtLogin: false };
      if (command === "update_status") return { phase: "idle", currentVersion: "0.16.0", platform: "linux-x64", autoCheck: false, autoDownload: false };
      if (command === "github_backup_status") return structuredClone(fixture.status);
      if (command === "github_backup_account") {
        return { login: "fixture-user", discoveredRepos: [], discoveryFailed: fixture.discoveryFailed };
      }
      if (command === "github_backup_history") {
        fixture.historyCalls.push(args.page);
        if (args.page === 1) {
          return { page: 1, hasMore: true, versions: [
            { sha: HEAD, committedAt: "2026-11-24T12:00:00Z", isHead: true },
            { sha: OLDER, committedAt: "2026-11-20T09:30:00Z", isHead: false },
            { sha: FOREIGN, committedAt: "2026-11-18T08:00:00Z", isHead: false },
          ] };
        }
        return { page: 2, hasMore: false, versions: [{ sha: OLDEST, committedAt: "", isHead: false }] };
      }
      if (command === "github_backup_history_prepare") {
        fixture.prepares.push(args.sha);
        if (args.sha === FOREIGN) return { sha: args.sha, unreadable: true, reason: "GITHUB_KEY_MISMATCH" };
        const items = [
          item(IDS.same, "Unchanged note", "same", { itemType: "note", summary: "" }),
          item(IDS.changed, "Mail login", "changed", { passkeyCount: 1, historyCount: 2 }),
          item(IDS.deleted, "Old API", "deleted", { itemType: "api", assignedName: "Old API(2)", summary: "api.example.test/v1" }),
          item(IDS.trash, "Build server", "trash", { itemType: "ssh", currentName: "Build server (retired)", summary: "10.0.0.8:22" }),
          item(IDS.long, "A deliberately long item name that has to be truncated with an ellipsis in every language", "changed", { folder: "A long folder name for overflow checks", summary: "https://a-very-long-hostname-for-overflow-testing.example.test/path/that/keeps/going" }),
          item(IDS.extra, "Database", "changed", { itemType: "database", summary: "db.example.test:5432" }),
        ];
        return { id: `prepared-${fixture.prepares.length}`, sha: args.sha, unreadable: false, preview: {
          createdAt: "2026-11-20T09:30:00Z", totalItems: items.length, changed: 3, deleted: 1, inTrash: 1, same: 1, items,
        } };
      }
      if (command === "github_backup_history_commit") {
        fixture.commits.push(structuredClone(args));
        fixture.status = connected({ pendingSync: true });
        return { summary: { restored: args.selectedIds.length, unchanged: 0 }, preSync: "pushed", status: structuredClone(fixture.status) };
      }
      if (command === "github_backup_history_cancel") { fixture.cancels += 1; return null; }
      return null;
    } } };
  }, { HEAD, OLDER, FOREIGN, OLDEST, IDS });

  const port = server.address().port;
  const openSettings = async (lang = "en", remote = true) => {
    await page.goto(`http://127.0.0.1:${port}/index.html?lang=${lang}&remote=${remote ? 1 : 0}`, { waitUntil: "networkidle" });
    await page.click('.nav-item[data-page="settings"]');
  };

  // 1. The action exists only once a remote backup exists.
  await openSettings("en", false);
  await page.locator("#github-sync").waitFor({ state: "visible" });
  assert.equal(await page.locator("#github-history").isVisible(), false);
  await page.evaluate(async () => { fixture.status.hasRemoteBackup = true; await refresh(false); });
  await page.locator("#github-history").waitFor({ state: "visible" });
  assert.equal(await page.locator("#github-history").textContent(), "VERSION HISTORY");
  assert.ok(await page.locator("#github-history").evaluate((el) => el.closest(".command-well") !== null));

  // 2. Version list: newest first, current marker, short SHA, load more.
  await page.click("#github-history");
  await page.locator("#github-history-modal").waitFor({ state: "visible" });
  assert.equal(await page.locator("#github-history-modal .modal-header").getAttribute("data-tauri-drag-region"), "deep");
  assert.equal(await page.locator("#github-history-close").getAttribute("data-tauri-drag-region"), "false");
  assert.equal(await page.locator("#github-history-close svg").count(), 1);
  await page.waitForFunction(() => document.querySelectorAll(".github-history-version").length === 3);
  assert.equal(await page.locator("#github-history-repository").textContent(), "fixture-user/openkeylet-vault");
  const firstRow = page.locator(".github-history-version").first();
  assert.match(await firstRow.innerText(), /CURRENT/);
  assert.match(await firstRow.innerText(), new RegExp(HEAD.slice(0, 7)));
  assert.doesNotMatch(await page.locator(".github-history-version").nth(1).innerText(), /CURRENT/);
  await page.click("#github-history-more");
  await page.waitForFunction(() => document.querySelectorAll(".github-history-version").length === 4);
  assert.equal(await page.locator("#github-history-more").isVisible(), false);
  assert.match(await page.locator(".github-history-version").nth(3).innerText(), /Unknown date/);
  assert.deepEqual(await page.evaluate(() => fixture.historyCalls), [1, 2]);

  // 3. A version that does not decrypt is marked on its row; the list stays usable.
  await page.click(`[data-history-sha="${FOREIGN}"]`);
  await page.locator("#github-history-error").waitFor({ state: "visible" });
  assert.match(await page.locator("#github-history-error").textContent(), /different key/);
  assert.equal(await page.locator(`[data-history-sha="${FOREIGN}"]`).isDisabled(), true);
  assert.match(await page.locator(`[data-history-sha="${FOREIGN}"]`).innerText(), /UNREADABLE/);
  assert.equal(await page.locator("#github-history-list-panel").isVisible(), true);

  // 4. Preview: rows that match this vault cannot be picked; nothing is preselected.
  await page.click(`[data-history-sha="${OLDER}"]`);
  await page.locator("#github-history-select-panel").waitFor({ state: "visible" });
  assert.equal(await page.locator("#github-history-version").textContent(), OLDER.slice(0, 7));
  assert.equal(await page.locator(`[data-history-check="${IDS.same}"]`).isDisabled(), true);
  assert.equal(await page.locator("#github-history-restore").isDisabled(), true);
  assert.equal(await page.locator("#github-history-counter").textContent(), "0 / 5");
  const firstItem = await page.locator("#github-history-items .mvault-item-row").first().innerText();
  assert.match(firstItem, /CHANGED/, "rows that can be restored are listed first");
  assert.match(await page.locator(`[data-history-row="${IDS.deleted}"]`).innerText(), /DELETED[\s\S]*Old API\(2\)/);
  assert.match(await page.locator(`[data-history-row="${IDS.trash}"]`).innerText(), /IN TRASH[\s\S]*Build server \(retired\)/);
  assert.match(await page.locator(`[data-history-row="${IDS.same}"]`).innerText(), /SAME/);
  // At the default window size at least four full rows are visible without scrolling.
  const visibleRows = await page.evaluate(() => {
    const list = document.querySelector("#github-history-items").getBoundingClientRect();
    return [...document.querySelectorAll("#github-history-items .mvault-item-row")]
      .filter((row) => { const r = row.getBoundingClientRect(); return r.top >= list.top - 1 && r.bottom <= list.bottom + 1; }).length;
  });
  assert.ok(visibleRows >= 4, `only ${visibleRows} rows visible`);
  assert.ok(await page.evaluate(() => document.querySelector(".github-history-card").getBoundingClientRect().bottom <= innerHeight));

  // Select all picks every difference, never the matching row; Back returns to the list.
  await page.check("#github-history-select-all");
  assert.equal(await page.locator("#github-history-counter").textContent(), "5 / 5");
  assert.equal(await page.locator(`[data-history-check="${IDS.same}"]`).isChecked(), false);
  await page.uncheck("#github-history-select-all");
  await page.click("#github-history-back");
  await page.locator("#github-history-list-panel").waitFor({ state: "visible" });
  assert.equal(await page.evaluate(() => fixture.cancels), 1);

  // 5. Restore a selection: confirm, commit only the chosen ids, close, report.
  await page.click(`[data-history-sha="${OLDER}"]`);
  await page.locator("#github-history-select-panel").waitFor({ state: "visible" });
  await page.check(`[data-history-check="${IDS.changed}"]`);
  await page.check(`[data-history-check="${IDS.deleted}"]`);
  assert.equal(await page.locator("#github-history-counter").textContent(), "2 / 5");
  assert.equal(await page.locator("#github-history-select-all").evaluate((el) => el.indeterminate), true);
  assert.equal(await page.locator("#github-history-restore").textContent(), "Restore (2)");
  await page.click("#github-history-restore");
  await page.locator("#confirmation-modal").waitFor({ state: "visible" });
  assert.match(await page.locator("#confirmation-message").textContent(), /syncs first/);
  await page.click("#confirmation-cancel");
  assert.equal(await page.evaluate(() => fixture.commits.length), 0);
  assert.equal(await page.locator("#github-history-select-panel").isVisible(), true);
  await page.click("#github-history-restore");
  await page.click("#confirmation-accept");
  await page.locator("#github-history-modal").waitFor({ state: "hidden" });
  const commits = await page.evaluate(() => fixture.commits);
  assert.equal(commits.length, 1);
  assert.equal(commits[0].id, "prepared-3");
  assert.deepEqual([...commits[0].selectedIds].sort(), [IDS.changed, IDS.deleted].sort());
  await page.waitForFunction(() => document.querySelector("#toast-region").textContent.includes("Restored from history · 2"));
  await page.waitForFunction(() => /PENDING SYNC/.test(document.querySelector("#github-status").textContent));
  assert.equal(await page.evaluate(() => fixture.cancels), 1, "a committed preview is not cancelled again");

  // Escape closes the dialog and drops the prepared version.
  await page.click("#github-history");
  await page.locator("#github-history-modal").waitFor({ state: "visible" });
  await page.keyboard.press("Escape");
  await page.locator("#github-history-modal").waitFor({ state: "hidden" });
  assert.equal(await page.evaluate(() => fixture.cancels), 2);

  // 6. A failed repository listing is reported as such, and no new repository is suggested.
  await page.evaluate(async () => { fixture.status = { connected: false }; fixture.discoveryFailed = true; await refresh(false); });
  await page.locator("#github-connect").waitFor({ state: "visible" });
  await page.click("#github-connect");
  await page.locator("#github-modal").waitFor({ state: "visible" });
  await page.click("#github-check-account");
  await page.waitForFunction(() => document.querySelector("#github-account-status").textContent.includes("fixture-user"));
  assert.match(await page.locator("#github-account-status").textContent(), /Could not list your repositories/);
  assert.equal(await page.locator("#github-repository").inputValue(), "");
  assert.equal(await page.locator("#github-discovered-box").isVisible(), false);

  // 7. No horizontal overflow in any language or theme, on the card, the list and the preview.
  const overflow = (selectors) => page.evaluate((list) => Math.max(
    document.documentElement.scrollWidth - document.documentElement.clientWidth,
    ...list.map((selector) => {
      const element = document.querySelector(selector);
      return element ? element.scrollWidth - element.clientWidth : 0;
    }),
  ), selectors);
  const clipped = () => page.evaluate(() => {
    const card = document.querySelector(".github-history-card").getBoundingClientRect();
    return [...document.querySelectorAll(".github-history-card button:not(.hidden), .github-history-card .mvault-stat-pill")]
      .filter((el) => el.getClientRects().length)
      .some((el) => { const r = el.getBoundingClientRect(); return r.left < card.left - 1 || r.right > card.right + 1; });
  });
  const headings = { en: "VERSION HISTORY", zh: "版本历史", "zh-TW": "版本歷史", ja: "バージョン履歴", ko: "버전 기록", es: "HISTORIAL DE VERSIONES" };
  for (const [lang, label] of Object.entries(headings)) {
    await openSettings(lang);
    await page.locator("#github-history").waitFor({ state: "visible" });
    assert.equal(await page.locator("#github-history").textContent(), label);
    for (const theme of ["dark", "light"]) {
      await page.evaluate((t) => document.documentElement.setAttribute("data-theme", t), theme);
      const value = await overflow(["#github-backup-card", ".github-actions"]);
      assert.ok(value <= 1, `sync card overflows in ${lang}/${theme}: ${value}`);
    }
    await page.click("#github-history");
    await page.waitForFunction(() => document.querySelectorAll(".github-history-version").length === 3);
    for (const theme of ["dark", "light"]) {
      await page.evaluate((t) => document.documentElement.setAttribute("data-theme", t), theme);
      const value = await overflow([".github-history-card", "#github-history-versions", "#github-history-list-panel .mvault-modal-footer"]);
      assert.ok(value <= 1, `version list overflows in ${lang}/${theme}: ${value}`);
      assert.equal(await clipped(), false, `version list controls clipped in ${lang}/${theme}`);
    }
    await page.click(`[data-history-sha="${OLDER}"]`);
    await page.locator("#github-history-select-panel").waitFor({ state: "visible" });
    await page.check(`[data-history-check="${IDS.long}"]`);
    for (const theme of ["dark", "light"]) {
      await page.evaluate((t) => document.documentElement.setAttribute("data-theme", t), theme);
      const value = await overflow([".github-history-card", "#github-history-items", "#github-history-select-panel .mvault-modal-footer", "#github-history-stats"]);
      assert.ok(value <= 1, `preview overflows in ${lang}/${theme}: ${value}`);
      assert.equal(await clipped(), false, `preview controls clipped in ${lang}/${theme}`);
      assert.ok(await page.evaluate(() => document.querySelector(".github-history-card").getBoundingClientRect().bottom <= innerHeight), `preview taller than the window in ${lang}/${theme}`);
    }
    await page.keyboard.press("Escape");
    await page.locator("#github-history-modal").waitFor({ state: "hidden" });
  }

  assert.deepEqual(errors, [], `Unexpected page errors: ${errors.join("; ")}`);
  console.log(JSON.stringify({ ok: true, checks: [
    "history action only with a remote backup", "draggable header", "version list newest first with current marker",
    "load more", "unreadable row", "same rows not selectable", "4+ rows visible", "select all changes", "back cancels",
    "confirm then commit selected ids", "escape cancels", "failed discovery notice", "6 languages x 2 themes without overflow",
  ] }, null, 2));
} finally {
  await browser.close();
  server.close();
}
