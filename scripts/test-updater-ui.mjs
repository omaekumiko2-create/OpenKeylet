// Synthetic renderer fixture for the GitHub Releases auto-updater UI.
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
        updateAutoCheck: true,
        updateAutoDownload: true,
        updateSkippedVersion: "",
      },
      connections: [],
      activities: [],
      mcp: { status: "ready", stdioCommand: "openkeylet" },
      browserBridge: { status: "off" },
      security: { encrypted: true },
    };
    window.fixture = {
      unlocked: true,
      restarts: 0,
      openedReleases: 0,
      settingsPatches: [],
      updateStatus: {
        phase: "idle",
        currentVersion: "0.16.0",
        platform: "windows-x64",
        latestVersion: null,
        tag: null,
        publishedAt: null,
        releaseUrl: "https://github.com/omaekumiko2-create/OpenKeylet/releases/latest",
        notes: "",
        assetSize: null,
        downloadedBytes: 0,
        totalBytes: 0,
        signatureVerified: false,
        signingKeyConfigured: true,
        canAutoInstall: true,
        installBlockedReason: null,
        checkedAt: null,
        errorCode: null,
        errorMessage: null,
        autoCheck: true,
        autoDownload: true,
        skippedVersion: "",
      },
      emit(event, payload) {
        for (const fn of listeners.get(event) || []) fn({ payload });
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
        invoke: async (command, args = {}) => {
          if (command === "get_state") return structuredClone(state);
          if (command === "owner_status") return { pinConfigured: false, unlocked: window.fixture.unlocked, expiresInSeconds: 0 };
          if (command === "owner_editor_drafts" || command === "agent_mcp_status" || command === "list_chrome_profiles") return [];
          if (command === "system_integration_status") return { desktopShortcut: false, launchAtLogin: false };
          if (command === "github_backup_status") return { connected: false };
          if (command === "update_status") return structuredClone(window.fixture.updateStatus);
          if (command === "update_check") {
            Object.assign(window.fixture.updateStatus, {
              phase: "available",
              latestVersion: "0.17.0",
              tag: "v0.17.0",
              publishedAt: "2026-11-24T12:00:00Z",
              releaseUrl: "https://github.com/omaekumiko2-create/OpenKeylet/releases/tag/v0.17.0",
              notes: "## What's Changed\n- Signed GitHub auto-updater",
              assetSize: 12_000_000,
              totalBytes: 12_000_000,
              signatureVerified: true,
              canAutoInstall: true,
              checkedAt: "2026-11-24T12:05:00Z",
            });
            return structuredClone(window.fixture.updateStatus);
          }
          if (command === "update_install_and_restart") {
            window.fixture.restarts += 1;
            return null;
          }
          if (command === "update_skip_version") {
            const v = String(args.version || "");
            state.settings.updateSkippedVersion = v;
            window.fixture.updateStatus.skippedVersion = v;
            return structuredClone(window.fixture.updateStatus);
          }
          if (command === "update_open_release_page") {
            window.fixture.openedReleases += 1;
            return null;
          }
          if (command === "update_settings") {
            const patch = args.patch || {};
            window.fixture.settingsPatches.push(structuredClone(patch));
            Object.assign(state.settings, patch);
            if ("updateAutoCheck" in patch) window.fixture.updateStatus.autoCheck = Boolean(patch.updateAutoCheck);
            if ("updateAutoDownload" in patch) window.fixture.updateStatus.autoDownload = Boolean(patch.updateAutoDownload);
            return structuredClone(state.settings);
          }
          return {};
        },
      },
    };
  });

  await page.goto(`http://127.0.0.1:${server.address().port}`);
  assert.equal(await page.locator("#update-banner").isVisible(), false, "Banner should stay hidden when idle");

  // Open System -> UPDATE settings card and click Check for updates
  await page.locator('[data-page="settings"]').click();
  await page.locator('[data-settings-filter="UPDATE"]').click();
  await page.locator("#update-check-button").click();

  // Banner appears for v0.17.0 available
  await page.locator("#update-banner").waitFor({ state: "visible" });
  assert.ok((await page.locator("#update-banner-title").textContent()).includes("v0.17.0"));

  // Simulate background download progress -> ready transition
  await page.evaluate(() => {
    window.fixture.updateStatus.phase = "downloading";
    window.fixture.updateStatus.downloadedBytes = 6_000_000;
    window.fixture.emit("update-state-changed", structuredClone(window.fixture.updateStatus));
  });
  assert.ok((await page.locator("#update-banner-title").textContent()).includes("50%"));

  await page.evaluate(() => {
    window.fixture.updateStatus.phase = "ready";
    window.fixture.updateStatus.downloadedBytes = 12_000_000;
    window.fixture.emit("update-state-changed", structuredClone(window.fixture.updateStatus));
  });
  assert.ok((await page.locator("#update-banner-title").textContent()).includes("已就绪"));

  // Open release notes modal, verify Ed25519 badge & notes, then trigger restart & update
  await page.locator("#update-banner-notes").click();
  await page.locator("#update-modal").waitFor({ state: "visible" });
  assert.ok((await page.locator("#update-modal-signature").textContent()).includes("ED25519"));
  assert.ok((await page.locator("#update-modal-notes").textContent()).includes("Signed GitHub auto-updater"));
  await page.locator("#update-modal-install").click();
  await page.waitForFunction(() => window.fixture.restarts === 1);

  // Close modal, test skip version & toggle switches
  await page.locator("#update-modal-close").click();
  await page.locator("#update-modal").waitFor({ state: "hidden" });
  await page.locator("#update-banner-notes").click();
  await page.locator("#update-modal-skip").click();
  await page.locator("#update-modal").waitFor({ state: "hidden" });
  assert.equal(await page.locator("#update-banner").isVisible(), false, "Skipped version should hide banner");
  await page.locator("#update-clear-skip-button").click();
  await page.locator("#update-banner").waitFor({ state: "visible" });

  // Toggle background auto-download off -> updates settings cleanly
  await page.locator("#update-auto-download-enabled").uncheck({ force: true });
  await page.waitForFunction(() => window.fixture.settingsPatches.some((p) => p.updateAutoDownload === false));

  assert.deepEqual(errors, [], `Unexpected page errors: ${errors.join("; ")}`);
  console.log("Updater UI Playwright verification passed.");
} finally {
  await browser.close();
  server.close();
}
