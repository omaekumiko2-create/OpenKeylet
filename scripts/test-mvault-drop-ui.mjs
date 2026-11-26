// Synthetic renderer E2E test for drag-and-drop .mvault selective import modal.
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
    const listeners = new Map();
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

    const previewItems = [
      {
        index: 0,
        kind: "item",
        id: "id-1",
        name: "GitHub Personal",
        itemType: "login",
        folder: "Work",
        summary: "github.com",
        status: "conflict",
        assignedName: "GitHub Personal(2)",
        passkeyCount: 1,
        historyCount: 2,
        deletedAt: null,
      },
      {
        index: 1,
        kind: "item",
        id: "id-2",
        name: "Prod Bastion",
        itemType: "ssh",
        folder: "Infra",
        summary: "10.0.0.8:22",
        status: "new",
        assignedName: null,
        passkeyCount: 0,
        historyCount: 0,
        deletedAt: null,
      },
      {
        index: 2,
        kind: "item",
        id: "id-3",
        name: "Already Existing API",
        itemType: "api",
        folder: "",
        summary: "api.example.test/v1",
        status: "duplicate",
        assignedName: null,
        passkeyCount: 0,
        historyCount: 0,
        deletedAt: null,
      },
      {
        index: 0,
        kind: "trash",
        id: "id-4",
        name: "Old Staging Key",
        itemType: "api",
        folder: "",
        summary: "staging.example.test",
        status: "new",
        assignedName: null,
        passkeyCount: 0,
        historyCount: 0,
        deletedAt: "2026-10-01T00:00:00Z",
      },
    ];

    window.fixture = {
      unlocked: true,
      mode: "protected",
      inspectCalls: [],
      prepareCalls: [],
      commitCalls: [],
      cancelCalls: 0,
      emit: (name, payload) => {
        for (const fn of listeners.get(name) || []) {
          fn({ payload });
        }
      },
    };

    window.__TAURI__ = {
      event: {
        listen: async (name, cb) => {
          if (!listeners.has(name)) listeners.set(name, []);
          listeners.get(name).push(cb);
          return () => {};
        },
      },
      core: {
        invoke: async (cmd, args = {}) => {
          if (cmd === "get_state") return JSON.parse(JSON.stringify(state));
          if (cmd === "owner_status") {
            return { pinConfigured: true, unlocked: window.fixture.unlocked, expiresInSeconds: 0 };
          }
          if (cmd === "owner_lock") {
            window.fixture.unlocked = false;
            return { pinConfigured: true, unlocked: false, expiresInSeconds: 0 };
          }
          if (cmd === "owner_editor_drafts") return [];
          if (cmd === "system_integration_status") return { desktopShortcut: false, launchAtLogin: false };
          if (cmd === "agent_mcp_status") return [];
          if (cmd === "list_chrome_profiles") return [];
          if (cmd === "github_backup_status") return { configured: false };
          if (cmd === "update_status") return { phase: "idle", currentVersion: "0.16.0", platform: "windows-x64" };
          if (cmd === "set_edge_dock_enabled") return null;
          if (cmd === "inspect_dropped_backup_bytes") {
            window.fixture.inspectCalls.push(args);
            if (/\.kdbx$/i.test(args.fileName || "")) {
              window.fixture.mode = "keepass_kdbx";
              return { fileName: args.fileName, requiresPassword: true, packageKind: "keepass_kdbx" };
            }
            const parsed = JSON.parse(args.content);
            if (parsed.encrypted === true && parsed.passwordProtected === true) {
              window.fixture.mode = "bitwarden_encrypted";
              return { fileName: args.fileName, requiresPassword: true, packageKind: "bitwarden_encrypted" };
            }
            const requiresPassword = parsed.format === "openkeylet-password-backup";
            window.fixture.mode = requiresPassword ? "protected" : "legacy";
            return { fileName: args.fileName, requiresPassword, packageKind: "mvault" };
          }
          if (cmd === "prepare_import") {
            if (args.format === "bitwarden") {
              window.fixture.mode = "bitwarden_encrypted";
              return {
                redirectVaultPackage: {
                  fileName: "bitwarden_encrypted_2026.json",
                  requiresPassword: true,
                  packageKind: "bitwarden_encrypted",
                },
              };
            }
            return null;
          }
          if (cmd === "prepare_backup_import") {
            window.fixture.prepareCalls.push(args.password);
            const expectedPass = window.fixture.mode === "keepass_kdbx"
              ? "keepass-master"
              : window.fixture.mode === "bitwarden_encrypted"
                ? "bw-export-pass"
                : "correct-backup-pass";
            if (window.fixture.mode !== "legacy" && args.password !== expectedPass) {
              throw new Error("Incorrect backup password or damaged backup");
            }
            const formatLabel = window.fixture.mode === "keepass_kdbx"
              ? "KeePass .kdbx"
              : window.fixture.mode === "bitwarden_encrypted"
                ? "Bitwarden Encrypted JSON"
                : window.fixture.mode === "protected"
                  ? "Protected .mvault (v8)"
                  : "Legacy self-unlocking .mvault (v5)";
            return {
              id: "mvault-session-1",
              preview: {
                formatLabel,
                version: window.fixture.mode === "protected" ? 8 : window.fixture.mode === "legacy" ? 5 : 0,
                protected: window.fixture.mode !== "legacy",
                createdAt: "2026-11-24T12:00:00Z",
                totalItems: 3,
                newItems: 2,
                duplicateSkipped: 1,
                nameConflicts: 1,
                passkeyCount: 1,
                trashCount: 1,
                historyEntries: 2,
                sampleNames: ["GitHub Personal", "Prod Bastion", "Already Existing API"],
                conflictRenames: ["GitHub Personal → GitHub Personal(2)"],
                items: JSON.parse(JSON.stringify(previewItems)),
              },
            };
          }
          if (cmd === "commit_backup_import") {
            window.fixture.commitCalls.push(args);
            const count = (args.selectedItemIndices?.length || 0) + (args.selectedTrashIndices?.length || 0);
            return { added: count, merged: 0 };
          }
          if (cmd === "cancel_backup_import") {
            window.fixture.cancelCalls += 1;
            return null;
          }
          return null;
        },
      },
    };
  });

  const port = server.address().port;
  await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: "networkidle" });

  // 1. Native Tauri drag enter shows global drop overlay on ANY page (e.g. Activity log tab)
  await page.click('.nav-item[data-page="activity"]');
  await page.evaluate(() => {
    window.fixture.emit("native-file-drag", {
      state: "enter",
      hasMvault: true,
      fileNames: ["openkeylet-backup.mvault"],
    });
  });
  await page.locator("#global-mvault-drop-overlay").waitFor({ state: "visible" });
  assert.equal(await page.locator("#global-mvault-drop-file").textContent(), "openkeylet-backup.mvault");
  const dropOverlayTop = await page.evaluate(() => Math.round(document.querySelector("#global-mvault-drop-overlay").getBoundingClientRect().top));
  assert.equal(dropOverlayTop, 0, "Global drop blur overlay covers full window including header");

  // 2. Native drop of protected .mvault hides overlay and automatically opens modal on password step
  await page.evaluate(() => {
    window.fixture.mode = "protected";
    window.fixture.emit("native-file-drag", { state: "leave", hasMvault: false });
    window.fixture.emit("mvault-file-dropped", {
      fileName: "openkeylet-backup.mvault",
      requiresPassword: true,
    });
  });
  await page.locator("#global-mvault-drop-overlay").waitFor({ state: "hidden" });
  await page.locator("#mvault-import-modal").waitFor({ state: "visible" });
  await page.locator("#mvault-unlock-panel").waitFor({ state: "visible" });
  assert.equal(await page.locator("#mvault-file-name").textContent(), "openkeylet-backup.mvault");

  // 3. Wrong password shows inline error WITHOUT closing modal
  await page.fill("#mvault-unlock-password", "wrong-password");
  await page.click("#mvault-unlock-submit");
  await page.locator("#mvault-unlock-error").waitFor({ state: "visible" });
  assert.match(await page.locator("#mvault-unlock-error").textContent(), /Incorrect backup password/);
  assert.ok(await page.locator("#mvault-import-modal").isVisible());

  // 4. Correct password unlocks and renders full selective checklist
  await page.fill("#mvault-unlock-password", "correct-backup-pass");
  await page.click("#mvault-unlock-submit");
  await page.locator("#mvault-select-panel").waitFor({ state: "visible" });
  assert.equal(await page.locator("#mvault-unlock-password").inputValue(), "");
  assert.equal(await page.locator(".mvault-item-row").count(), 4);

  // Duplicate row is disabled and unchecked; 3 importable items are checked by default
  assert.equal(await page.locator('[data-mvault-check="item:2"]').isDisabled(), true);
  assert.equal(await page.locator('[data-mvault-check="item:2"]').isChecked(), false);
  assert.equal(await page.locator("#mvault-select-all").isChecked(), true);
  assert.equal(await page.locator("#mvault-select-confirm").textContent(), "全量导入 (3)");

  // 5. Unchecking one item sets master checkbox indeterminate and updates CTA
  await page.click('[data-mvault-row="trash:0"]');
  assert.equal(await page.locator("#mvault-select-all").evaluate((el) => el.indeterminate), true);
  assert.equal(await page.locator("#mvault-select-confirm").textContent(), "导入所选 (2)");

  // 6. Search + filter pills work cleanly, and Select All toggles only visible importable items
  await page.click('[data-mvault-filter="ssh"]');
  assert.equal(await page.locator(".mvault-item-row").count(), 1);
  assert.equal(await page.locator("#mvault-select-all-text").textContent(), "全选当前筛选");
  await page.click("#mvault-select-all"); // unselect Prod Bastion
  assert.equal(await page.locator("#mvault-select-confirm").textContent(), "导入所选 (1)");
  await page.click('[data-mvault-filter="all"]');
  assert.equal(await page.locator(".mvault-item-row").count(), 4);

  // Check zero horizontal overflow in both dark and light themes while modal is open
  for (const theme of ["dark", "light"]) {
    await page.evaluate((t) => document.documentElement.setAttribute("data-theme", t), theme);
    const overflow = await page.evaluate(() => ({
      doc: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      modal: document.querySelector(".mvault-modal-card").scrollWidth - document.querySelector(".mvault-modal-card").clientWidth,
    }));
    assert.ok(overflow.doc <= 1, `document horizontal overflow in ${theme}: ${overflow.doc}`);
    assert.ok(overflow.modal <= 1, `modal horizontal overflow in ${theme}: ${overflow.modal}`);
  }

  // 7. Commit strictly the 1 checked item (index 0: GitHub Personal)
  await page.click("#mvault-select-confirm");
  await page.locator("#mvault-import-modal").waitFor({ state: "hidden" });
  const commits = await page.evaluate(() => window.fixture.commitCalls);
  assert.equal(commits.length, 1);
  assert.deepEqual(commits[0], {
    id: "mvault-session-1",
    selectedItemIndices: [0],
    selectedTrashIndices: [],
  });

  // 8. HTML5 drop of legacy self-unlocking .mvault on Settings page opens modal directly to checklist
  await page.click('.nav-item[data-page="settings"]');
  await page.evaluate(() => {
    const dt = new DataTransfer();
    const file = new File(
      [JSON.stringify({ format: "mcp-vault-backup", version: 5, cipher: "xchacha20poly1305", unlockKey: "AA", payload: {} })],
      "legacy-openkeylet-backup.mvault",
      { type: "application/octet-stream" }
    );
    dt.items.add(file);
    document.dispatchEvent(new DragEvent("drop", { bubbles: true, cancelable: true, dataTransfer: dt }));
  });
  await page.locator("#mvault-import-modal").waitFor({ state: "visible" });
  await page.locator("#mvault-select-panel").waitFor({ state: "visible" });
  await page.locator("#mvault-legacy-note").waitFor({ state: "visible" });

  // Uncheck all via master checkbox -> confirm disabled -> re-check all -> enabled
  await page.click("#mvault-select-all");
  assert.equal(await page.locator("#mvault-select-confirm").isDisabled(), true);
  await page.click("#mvault-select-all");
  assert.equal(await page.locator("#mvault-select-confirm").isDisabled(), false);
  await page.click("#mvault-select-cancel");
  await page.locator("#mvault-import-modal").waitFor({ state: "hidden" });

  // 8b. HTML5 drop of binary KeePass .kdbx sends base64 and displays KeePass header/pill/master-password flow
  await page.evaluate(() => {
    const dt = new DataTransfer();
    const magic = new Uint8Array([0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 0x00, 0x00, 0x04, 0x00]);
    const file = new File([magic], "work-secrets.kdbx", { type: "application/octet-stream" });
    dt.items.add(file);
    document.dispatchEvent(new DragEvent("drop", { bubbles: true, cancelable: true, dataTransfer: dt }));
  });
  await page.locator("#mvault-import-modal").waitFor({ state: "visible" });
  await page.locator("#mvault-unlock-panel").waitFor({ state: "visible" });
  assert.equal(await page.locator("#mvault-modal-title").textContent(), "导入 KeePass 数据库");
  assert.equal(await page.locator("#mvault-format-pill").textContent(), "KeePass .kdbx");
  assert.equal(await page.locator("#mvault-unlock-password-label").textContent(), "主密码");
  const lastInspect = await page.evaluate(() => window.fixture.inspectCalls.at(-1));
  assert.equal(lastInspect.isBase64, true, "Binary .kdbx drop must send base64");
  await page.fill("#mvault-unlock-password", "keepass-master");
  await page.click("#mvault-unlock-submit");
  await page.locator("#mvault-select-panel").waitFor({ state: "visible" });
  await page.click("#mvault-select-cancel");
  await page.locator("#mvault-import-modal").waitFor({ state: "hidden" });

  // 8c. SAFE migration modal lists 1Password .1pux & KeePass .kdbx and seamlessly redirects encrypted Bitwarden JSON to unlock modal
  await page.click("#migration-open");
  await page.locator("#migration-modal").waitFor({ state: "visible" });
  const migrationOptions = await page.locator("#migration-format option").evaluateAll((els) => els.map((e) => e.value));
  assert.ok(migrationOptions.includes("bitwarden") && migrationOptions.includes("onepassword") && migrationOptions.includes("keepass"));
  await page.selectOption("#migration-format", "bitwarden");
  await page.click("#migration-select");
  await page.locator("#migration-modal").waitFor({ state: "hidden" });
  await page.locator("#mvault-import-modal").waitFor({ state: "visible" });
  await page.locator("#mvault-unlock-panel").waitFor({ state: "visible" });
  assert.equal(await page.locator("#mvault-modal-title").textContent(), "导入 Bitwarden 加密库");
  assert.equal(await page.locator("#mvault-format-pill").textContent(), "Bitwarden");
  assert.equal(await page.locator("#mvault-unlock-password-label").textContent(), "导出密码");
  await page.fill("#mvault-unlock-password", "bw-export-pass");
  await page.click("#mvault-unlock-submit");
  await page.locator("#mvault-select-panel").waitFor({ state: "visible" });

  // 9. Locking vault immediately closes modal and clears staged state
  await page.keyboard.press("Control+Shift+L");
  await page.locator("#owner-lock-layer").waitFor({ state: "visible" });
  await page.locator("#mvault-import-modal").waitFor({ state: "hidden" });

  // Dropping while locked shows toast without left crescent border and keeps modal closed
  await page.evaluate(() => {
    window.fixture.emit("mvault-file-dropped", { fileName: "openkeylet-backup.mvault", locked: true });
  });
  await page.locator("#mvault-import-modal").waitFor({ state: "hidden" });
  assert.match(await page.locator("#toast-region").innerText(), /解锁/);
  const toastBorders = await page.evaluate(() => {
    const t = document.querySelector("#toast-region .toast");
    const s = getComputedStyle(t);
    return { left: s.borderLeftWidth, right: s.borderRightWidth, top: s.borderTopWidth, bottom: s.borderBottomWidth };
  });
  assert.deepEqual(toastBorders, { left: "1px", right: "1px", top: "1px", bottom: "1px" }, "Toast uses uniform 1px border without left crescent accent");

  assert.deepEqual(errors, [], `Unexpected page errors: ${errors.join("; ")}`);
  console.log("Selective .mvault drag-and-drop import UI E2E tests passed (native + HTML5 drop, password retry, checklist, select-all, filter, partial commit, dark/light, lock wipe).");
} finally {
  await browser.close();
  server.close();
}
