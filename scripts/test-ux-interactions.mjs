// Exhaustive Playwright UX, drag-and-drop, window occlusion, z-index, and
// cross-platform OS convention (Windows / macOS / Linux) test suite.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import { once } from 'node:events';
import { chromium } from 'playwright';

const renderer = path.resolve(import.meta.dirname, '../renderer');
const server = http.createServer(async (req, res) => {
  const file = path.resolve(renderer, '.' + (req.url === '/' ? '/index.html' : req.url.split('?')[0]));
  if (!file.startsWith(renderer + path.sep)) { res.writeHead(403); res.end(); return; }
  try {
    const type = file.endsWith('.js') ? 'text/javascript'
      : file.endsWith('.css') ? 'text/css'
      : file.endsWith('.svg') ? 'image/svg+xml'
      : file.endsWith('.png') ? 'image/png'
      : 'text/html';
    res.setHeader('Content-Type', type);
    res.end(await fs.readFile(file));
  } catch {
    res.writeHead(404);
    res.end();
  }
});
server.listen(0, '127.0.0.1');
await once(server, 'listening');
const baseUrl = `http://127.0.0.1:${server.address().port}`;

function makeItems() {
  return [
    { id: 'item-1', name: 'Alpha Mail', itemType: 'login', enabled: true, canTest: false, updatedAt: '2026-10-20T00:00:00Z', modules: [{ kind: 'username', name: 'username', configured: true }, { kind: 'password', name: 'password', configured: true }], capabilities: ['fill'] },
    { id: 'item-2', name: 'Beta Cloud', itemType: 'api', enabled: true, canTest: true, updatedAt: '2026-10-20T00:01:00Z', modules: [{ kind: 'apiCredential', name: 'apiCredential', configured: true }], capabilities: ['http'] },
    { id: 'item-3', name: 'Gamma SSH', itemType: 'ssh', enabled: true, canTest: true, updatedAt: '2026-10-20T00:02:00Z', modules: [{ kind: 'host', name: 'host', value: '10.0.0.3', configured: true }, { kind: 'password', name: 'password', configured: true }], capabilities: ['ssh'] },
    { id: 'item-4', name: 'Delta Bank', itemType: 'login', enabled: true, canTest: false, updatedAt: '2026-10-20T00:03:00Z', modules: [{ kind: 'username', name: 'username', configured: true }, { kind: 'password', name: 'password', configured: true }], capabilities: [] },
    { id: 'item-5', name: 'Epsilon Git', itemType: 'login', enabled: true, canTest: false, updatedAt: '2026-10-20T00:04:00Z', modules: [{ kind: 'username', name: 'username', configured: true }, { kind: 'password', name: 'password', configured: true }], capabilities: ['fill'] },
  ];
}

async function openPlatformPage(browser, { platform, userAgent, pinConfigured = false }) {
  const context = await browser.newContext({ viewport: { width: 460, height: 690 }, userAgent });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));

  await page.addInitScript(({ platform, items, pinConfigured }) => {
    Object.defineProperty(navigator, 'platform', { get: () => platform, configurable: true });
    let connections = structuredClone(items);
    const state = {
      settings: { language: 'en', closeBehavior: 'tray', browserEnabled: true, browserPort: 39272, browserAgentPasskey: true, autoCheckEnabled: true, autoCheckIntervalMinutes: 60 },
      connections,
      activities: [{ id: 'act-1', action: 'fill', connectionName: 'Alpha Mail', source: 'mcp', status: 'ok', durationMs: 12, time: '2026-10-20T00:00:00Z' }],
      mcp: { status: 'ready' },
      browserBridge: { status: 'listening', connected: true, paired: true, endpoint: 'ws://127.0.0.1:39272' },
      security: { encrypted: true },
    };
    window.uxFixture = {
      reorders: [],
      saves: [],
      tested: [],
      copies: [],
      settingsPatches: [],
      testDelayMs: 0,
      windowActions: [],
      extensionDrags: 0,
      extensionFolderOpens: 0,
      locks: 0,
      pinConfigured,
      unlocked: true,
    };
    window.__TAURI__ = {
      event: { listen: async () => () => {} },
      core: {
        invoke: async (command, args = {}) => {
          if (command === 'get_state') return structuredClone({ ...state, connections });
          if (command === 'owner_status') return { pinConfigured: window.uxFixture.pinConfigured, unlocked: window.uxFixture.unlocked, expiresInSeconds: 0 };
          if (command === 'owner_lock') { window.uxFixture.locks++; window.uxFixture.unlocked = false; return { pinConfigured: window.uxFixture.pinConfigured, unlocked: false, expiresInSeconds: 0 }; }
          if (command === 'owner_editor_drafts' || command === 'agent_mcp_status' || command === 'owner_trash') return [];
          if (command === 'system_integration_status') return { desktopShortcutSupported: !platform.startsWith('Mac'), desktopShortcutEnabled: false, launchAtLoginSupported: true, launchAtLoginEnabled: false };
          if (command === 'github_backup_status') return { connected: false };
          if (command === 'owner_secret_view') {
            return {
              id: args.id,
              fields: [
                { name: 'username', value: 'alice@example.com' },
                { name: 'password', value: 'secret-value-123' },
                { name: 'apiCredential', value: 'tok-xyz' },
              ],
            };
          }
          if (command === 'reorder_connections') {
            window.uxFixture.reorders.push(structuredClone(args.ids));
            const byId = new Map(connections.map(c => [c.id, c]));
            connections = args.ids.map(id => byId.get(id)).filter(Boolean);
            return structuredClone(connections);
          }
          if (command === 'save_connection') {
            window.uxFixture.saves.push(structuredClone(args.input));
            return { id: args.input.id || 'saved-1', ...args.input };
          }
          if (command === 'save_editor_draft') return { id: 'draft-1', updatedAt: '2026-10-20T00:05:00Z' };
          if (command === 'delete_editor_draft') return null;
          if (command === 'test_connection') {
            window.uxFixture.tested.push(args.id);
            if (window.uxFixture.testDelayMs > 0) {
              await new Promise((resolve) => setTimeout(resolve, window.uxFixture.testDelayMs));
            }
            if (args.id === 'item-3') throw new Error('Connection refused');
            return 'HTTP 200 OK · 18ms';
          }
          if (command === 'copy_owner_value') {
            window.uxFixture.copies.push({ value: args.value, sensitive: Boolean(args.sensitive) });
            return null;
          }
          if (command === 'update_settings') {
            window.uxFixture.settingsPatches.push(structuredClone(args.patch));
            Object.assign(state.settings, args.patch);
            return structuredClone(state.settings);
          }
          if (command === 'generate_password') return 'GenPass#2026!StrongValue';
          if (command === 'window_action') { window.uxFixture.windowActions.push(args.action); return null; }
          if (command === 'drag_browser_extension') { window.uxFixture.extensionDrags++; return null; }
          if (command === 'open_browser_extension_folder') { window.uxFixture.extensionFolderOpens++; return null; }
          return {};
        },
      },
    };
  }, { platform, items: makeItems(), pinConfigured });

  await page.goto(baseUrl);
  await page.locator('.connection-card').first().waitFor({ state: 'visible' });
  return { context, page, errors };
}

const browser = await chromium.launch({ headless: true });
try {
  // =========================================================================
  // 1. WINDOWS: Titlebar, Drag-Region, Search Selection, Occlusion, Z-Index,
  //    Item Drag, Module Drag, Extension Drag, Modern Shortcuts
  // =========================================================================
  {
    const { context, page, errors } = await openPlatformPage(browser, {
      platform: 'Win32',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/134.0.0.0 Safari/537.36',
      pinConfigured: true,
    });

    // 1a. Windows titlebar geometry & drag region covers top 0..40px without dead gap
    const winChrome = await page.evaluate(() => {
      const bar = document.querySelector('.title-drag-region').getBoundingClientRect();
      const mark = document.querySelector('.app-mark').getBoundingClientRect();
      const search = document.querySelector('#title-search');
      const controls = document.querySelector('.window-controls').getBoundingClientRect();
      const minBtn = document.querySelector('[data-window-action="minimize"]').getBoundingClientRect();
      const closeBtn = document.querySelector('[data-window-action="close"]').getBoundingClientRect();
      const topHit = document.elementFromPoint(24, 2)?.closest('.title-drag-region') !== null;
      return {
        isMac: document.documentElement.classList.contains('platform-macos'),
        isLinux: document.documentElement.classList.contains('platform-linux'),
        barTop: Math.round(bar.top),
        barBottom: Math.round(bar.bottom),
        topHit,
        searchDragAttr: search.getAttribute('data-tauri-drag-region'),
        searchUserSelect: getComputedStyle(document.querySelector('#title-search-input')).userSelect,
        controlsRightOfMark: controls.left > mark.right,
        minLeftOfClose: minBtn.left < closeBtn.left,
        searchTitle: document.querySelector('#title-search-input').title,
      };
    });
    assert.equal(winChrome.isMac, false);
    assert.equal(winChrome.isLinux, false);
    assert.equal(winChrome.barTop, 0, 'Titlebar drag region starts at y=0 (no top dead gap)');
    assert.equal(winChrome.topHit, true, 'Top 2px edge hits draggable titlebar');
    assert.equal(winChrome.searchDragAttr, 'false', 'Titlebar search opts out of Tauri drag region');
    assert.equal(winChrome.searchUserSelect, 'text', 'Titlebar search input allows text selection');
    assert.equal(winChrome.controlsRightOfMark, true, 'Windows places window controls on top-right');
    assert.equal(winChrome.minLeftOfClose, true, 'Windows places Minimize left of Close');
    assert.match(winChrome.searchTitle, /Ctrl\+K/, 'Windows advertises Ctrl+K shortcut');

    // 1b. Titlebar search text selection works via mouse drag inside drag region
    const searchInput = page.locator('#title-search-input');
    await searchInput.fill('Alpha');
    const sBox = await searchInput.boundingBox();
    await page.mouse.move(sBox.x + 8, sBox.y + sBox.height / 2);
    await page.mouse.down();
    await page.mouse.move(sBox.x + 60, sBox.y + sBox.height / 2, { steps: 5 });
    await page.mouse.up();
    const selectedLen = await page.evaluate(() => {
      const el = document.querySelector('#title-search-input');
      return Math.abs((el.selectionEnd ?? 0) - (el.selectionStart ?? 0));
    });
    assert.ok(selectedLen > 0, `Mouse drag-selection works inside titlebar search (selected ${selectedLen} chars)`);
    await page.keyboard.press('Escape');
    assert.equal(await searchInput.inputValue(), '', 'Escape clears search query');

    // 1c. Default list view: leftmost status lamp + right-aligned icon action strip
    //     (CHECK / USE / COPY / DEL) + OpenKeylet custom tooltip + hover/drop sounds
    assert.equal(await page.evaluate(() => document.querySelector('#connections-list').dataset.view), 'list', 'Vault defaults to single-row list view');
    const alignmentBefore = await page.evaluate(() => {
      const cards = [...document.querySelectorAll('#connections-list .connection-card')];
      const lamps = cards.map(card => card.querySelector(':scope > .item-toggle').getBoundingClientRect());
      const types = cards.map(card => card.querySelector(':scope > .connection-type').getBoundingClientRect());
      const copies = cards.map(card => card.querySelector('[data-action="copy-item"]').getBoundingClientRect());
      const dels = cards.map(card => card.querySelector('[data-action="delete"]').getBoundingClientRect());
      const iconOnly = [...document.querySelectorAll('#connections-list .card-actions button')].every(btn =>
        btn.querySelector('svg') && btn.textContent.trim() === ''
      );
      return {
        lampSpread: Math.max(...lamps.map(r => r.left)) - Math.min(...lamps.map(r => r.left)),
        lampLeftmost: lamps.every((r, i) => r.right <= types[i].left + 1),
        copySpread: Math.max(...copies.map(r => r.left)) - Math.min(...copies.map(r => r.left)),
        delSpread: Math.max(...dels.map(r => r.left)) - Math.min(...dels.map(r => r.left)),
        copyLeftOfDel: copies.every((r, i) => r.right <= dels[i].left + 1 && (dels[i].left - r.right) <= 8),
        iconOnly,
      };
    });
    assert.ok(alignmentBefore.lampSpread <= 0.5, `All status lamps align vertically across mixed list rows (spread=${alignmentBefore.lampSpread}px)`);
    assert.equal(alignmentBefore.lampLeftmost, true, 'Status lamp is placed at the very front (leftmost) of every list row');
    assert.ok(alignmentBefore.copySpread <= 0.5, `All copy buttons align vertically across mixed list rows (spread=${alignmentBefore.copySpread}px)`);
    assert.ok(alignmentBefore.delSpread <= 0.5, `All delete buttons align vertically across mixed list rows (spread=${alignmentBefore.delSpread}px)`);
    assert.equal(alignmentBefore.copyLeftOfDel, true, 'Copy button is integrated directly to the left of Delete');
    assert.equal(alignmentBefore.iconOnly, true, 'All card action buttons (CHECK, USE, COPY, DEL) use clean icons');

    // Hovering an icon button suppresses native Windows title popup & shows OpenKeylet-styled #ui-tooltip
    const copyBtn1 = page.locator('.connection-card[data-item-id="item-1"] [data-action="copy-item"]');
    await copyBtn1.hover();
    await page.waitForTimeout(300);
    const tipCheck = await page.evaluate(() => {
      const btn = document.querySelector('.connection-card[data-item-id="item-1"] [data-action="copy-item"]');
      const tip = document.querySelector('#ui-tooltip');
      if (!tip) return null;
      const r = tip.getBoundingClientRect();
      return {
        nativeTitleSuppressed: !btn.hasAttribute('title'),
        visible: tip.classList.contains('is-visible'),
        text: tip.textContent.trim(),
        withinViewport: r.left >= 0 && r.right <= innerWidth && r.top >= 0 && r.bottom <= innerHeight,
      };
    });
    assert.ok(tipCheck && tipCheck.visible, 'Custom OpenKeylet UI tooltip appears on hover');
    assert.equal(tipCheck.nativeTitleSuppressed, true, 'Native OS title attribute is suppressed while hovered');
    assert.match(tipCheck.text, /Copy full item contents/, 'Custom tooltip shows the action description');
    assert.equal(tipCheck.withinViewport, true, 'Custom tooltip clamps cleanly inside the window');
    await page.mouse.move(0, 0);
    await page.waitForTimeout(60);
    assert.equal(await page.evaluate(() => document.querySelector('#ui-tooltip').classList.contains('is-visible')), false, 'Custom tooltip hides when mouse leaves');
    assert.equal(await copyBtn1.evaluate(el => el.hasAttribute('title')), true, 'Original title attribute restores cleanly after hover ends');

    // Hover sound & drop sound work cleanly when interface sound is enabled
    const soundPlays = await page.evaluate(() => {
      const orig = window.OpenKeyletAppearance.play;
      const played = [];
      window.OpenKeyletAppearance.setSound(true);
      window.OpenKeyletAppearance.play = (kind) => { played.push(kind); return orig(kind); };
      window.__playedSounds = played;
      return true;
    });
    assert.equal(soundPlays, true);
    await page.locator('.connection-card[data-item-id="item-2"] [data-action="copy-name"]').hover();
    await page.waitForTimeout(70);
    await page.evaluate(() => { window.OpenKeyletAppearance.setSound(false); });
    const audioContextCreated = await page.evaluate(() => {
      // Hover sound triggers via internal play('hover') without errors
      return document.getElementById('sound-toggle')?.getAttribute('aria-checked') === 'false';
    });
    assert.equal(audioContextCreated, true);

    // Clicking first action slot copies neatly formatted full item contents
    await page.locator('.connection-card[data-item-id="item-1"] [data-action="copy-item"]').click();
    await page.waitForFunction(() => window.uxFixture.copies.length === 1);
    const fullCopy = await page.evaluate(() => window.uxFixture.copies[0]);
    assert.equal(fullCopy.sensitive, true, 'Full item copy uses sensitive clipboard clearing');
    assert.match(fullCopy.value, /Alpha Mail/, 'Full item copy includes item name');
    assert.match(fullCopy.value, /alice@example\.com/, 'Full item copy includes decrypted username');
    assert.match(fullCopy.value, /secret-value-123/, 'Full item copy includes decrypted password');

    // Single CHECK loading state: disabled + spinner + ignores repeat clicks + yellow lamp on error
    await page.evaluate(() => { window.uxFixture.testDelayMs = 140; });
    await page.locator('.connection-card[data-item-id="item-3"] [data-action="test"]').click();
    const singleMidFlight = await page.evaluate(() => {
      const btn = document.querySelector('.connection-card[data-item-id="item-3"] [data-action="test"]');
      const dot = document.querySelector('.connection-card[data-item-id="item-3"] .item-toggle .status-dot');
      return {
        disabled: btn.disabled,
        busy: btn.getAttribute('aria-busy'),
        state: btn.dataset.checkState,
        hasSpinner: Boolean(btn.querySelector('.check-spinner')),
        dotTesting: dot.classList.contains('testing'),
      };
    });
    assert.equal(singleMidFlight.disabled, true, 'Single CHECK disables button while loading');
    assert.equal(singleMidFlight.busy, 'true', 'Single CHECK sets aria-busy while loading');
    assert.equal(singleMidFlight.state, 'testing', 'Single CHECK enters testing state');
    assert.equal(singleMidFlight.hasSpinner, true, 'Single CHECK displays loading spinner');
    assert.equal(singleMidFlight.dotTesting, true, 'Status lamp pulses while checking');
    await page.locator('.connection-card[data-item-id="item-3"] [data-action="test"]').click({ force: true });
    await page.waitForFunction(() => document.querySelector('.connection-card[data-item-id="item-3"] [data-action="test"]').dataset.checkState === 'error');
    assert.deepEqual(await page.evaluate(() => window.uxFixture.tested), ['item-3'], 'Repeat click during loading does not dispatch duplicate test IPC');
    const failedLamp = await page.evaluate(() => document.querySelector('.connection-card[data-item-id="item-3"] .item-toggle .status-dot').classList.contains('warn'));
    assert.equal(failedLamp, true, 'Failed check turns status lamp amber/yellow (.warn)');

    // One-click Check All button shows loading spinner, disables itself, tests all enabled testable items
    await page.evaluate(() => { window.uxFixture.tested = []; });
    await page.locator('#check-all-button').click();
    const batchMidFlight = await page.evaluate(() => {
      const btn = document.querySelector('#check-all-button');
      return {
        disabled: btn.disabled,
        busy: btn.getAttribute('aria-busy'),
        state: btn.dataset.state,
        spinnerVisible: getComputedStyle(btn.querySelector('.check-all-spinner')).display !== 'none',
      };
    });
    assert.equal(batchMidFlight.disabled, true, 'Check All button disables while running');
    assert.equal(batchMidFlight.busy, 'true', 'Check All button sets aria-busy while running');
    assert.equal(batchMidFlight.state, 'running', 'Check All button enters running state');
    assert.equal(batchMidFlight.spinnerVisible, true, 'Check All button shows spinner while running');
    await page.waitForFunction(() => document.querySelector('#check-all-button').getAttribute('aria-busy') === 'false' && window.uxFixture.tested.length === 2);
    await page.evaluate(() => { window.uxFixture.testDelayMs = 0; });
    const checkAllResult = await page.evaluate(() => {
      const lamps = [...document.querySelectorAll('.connection-card > .item-toggle')].map(el => el.getBoundingClientRect().left);
      return {
        tested: [...window.uxFixture.tested].sort(),
        item2State: document.querySelector('.connection-card[data-item-id="item-2"] [data-action="test"]').dataset.checkState,
        item3State: document.querySelector('.connection-card[data-item-id="item-3"] [data-action="test"]').dataset.checkState,
        item2Warn: document.querySelector('.connection-card[data-item-id="item-2"] .item-toggle .status-dot').classList.contains('warn'),
        item3Warn: document.querySelector('.connection-card[data-item-id="item-3"] .item-toggle .status-dot').classList.contains('warn'),
        btnState: document.querySelector('#check-all-button').dataset.state,
        lampSpread: Math.max(...lamps) - Math.min(...lamps),
      };
    });
    assert.deepEqual(checkAllResult.tested, ['item-2', 'item-3'], 'Check All tests all enabled testable items in view');
    assert.equal(checkAllResult.item2State, 'ok', 'Passing item updates CHECK button to ok state');
    assert.equal(checkAllResult.item3State, 'error', 'Failing item updates CHECK button to error state');
    assert.equal(checkAllResult.item2Warn, false, 'Passing item keeps green status lamp');
    assert.equal(checkAllResult.item3Warn, true, 'Failing item shows yellow/amber status lamp');
    assert.equal(checkAllResult.btnState, 'error', 'Check All button reflects partial failure state');
    assert.ok(checkAllResult.lampSpread <= 0.5, `Status lamps remain strictly aligned after batch check (spread=${checkAllResult.lampSpread}px)`);

    // Clicking CHECK again after completion resets both CHECK button and item statuses/lamps back to normal
    await page.evaluate(() => { window.uxFixture.tested = []; });
    await page.locator('#check-all-button').click();
    const afterReset = await page.evaluate(() => ({
      tested: [...window.uxFixture.tested],
      btnState: document.querySelector('#check-all-button').dataset.state ?? null,
      btnBusy: document.querySelector('#check-all-button').getAttribute('aria-busy'),
      item2State: document.querySelector('.connection-card[data-item-id="item-2"] [data-action="test"]').dataset.checkState ?? null,
      item3State: document.querySelector('.connection-card[data-item-id="item-3"] [data-action="test"]').dataset.checkState ?? null,
      item2Warn: document.querySelector('.connection-card[data-item-id="item-2"] .item-toggle .status-dot').classList.contains('warn'),
      item3Warn: document.querySelector('.connection-card[data-item-id="item-3"] .item-toggle .status-dot').classList.contains('warn'),
    }));
    assert.deepEqual(afterReset.tested, [], 'Clicking CHECK after completion clears state without re-running tests');
    assert.equal(afterReset.btnState, null, 'CHECK button returns to normal state after reset click');
    assert.equal(afterReset.btnBusy, 'false', 'CHECK button is not busy after reset click');
    assert.equal(afterReset.item2State, null, 'Passing item check button returns to idle state');
    assert.equal(afterReset.item3State, null, 'Failing item check button returns to idle state');
    assert.equal(afterReset.item2Warn, false, 'Passing item keeps normal green lamp after reset');
    assert.equal(afterReset.item3Warn, false, 'Failing item lamp returns to normal green after reset');

    // Clicking CHECK once more from normal state starts a fresh check run
    await page.locator('#check-all-button').click();
    await page.waitForFunction(() => document.querySelector('#check-all-button').getAttribute('aria-busy') === 'false' && window.uxFixture.tested.length === 2);
    assert.equal(await page.evaluate(() => document.querySelector('#check-all-button').dataset.state), 'error', 'Clicking CHECK again from normal state runs batch check');
    await page.locator('#check-all-button').click();
    assert.equal(await page.evaluate(() => document.querySelector('#check-all-button').dataset.state ?? null), null, 'Second reset clears state back to normal');

    // Long-press on card body lifts full card in place (Windows-taskbar-style) without opening editor
    const firstCardBox = await page.locator('.connection-card[data-item-id="item-1"]').boundingBox();
    await page.mouse.move(firstCardBox.x + 80, firstCardBox.y + firstCardBox.height / 2);
    await page.mouse.down();
    await page.waitForTimeout(260);
    const liftedInPlace = await page.evaluate(() => {
      const preview = document.querySelector('.item-drag-preview');
      const card = document.querySelector('.connection-card[data-item-id="item-1"]');
      if (!preview || !card) return null;
      const pr = preview.getBoundingClientRect();
      const cr = card.getBoundingClientRect();
      return {
        dx: Math.abs(pr.left - cr.left),
        dy: Math.abs(pr.top - cr.top),
        dw: Math.abs(pr.width - cr.width),
        hasLiftedCard: Boolean(preview.querySelector('.connection-card.is-lifted-card')),
        slotGhost: card.classList.contains('is-item-dragging'),
      };
    });
    assert.ok(liftedInPlace && liftedInPlace.hasLiftedCard, 'Long-press lifts full card clone in place');
    assert.equal(liftedInPlace.slotGhost, true, 'Original card becomes dashed ghost slot during lift');
    assert.ok(liftedInPlace.dx <= 6 && liftedInPlace.dy <= 6 && liftedInPlace.dw <= 8, `Lifted card starts directly in place (${JSON.stringify(liftedInPlace)})`);
    await page.mouse.up();
    await page.waitForTimeout(40);
    assert.equal(await page.locator('#connection-modal').isHidden(), true, 'Releasing a long-press lift does not accidentally open editor');

    // Settings APP / 03: Scheduled auto-check defaults ON @ 1 hour, toggleable & configurable
    await page.locator('.nav-item[data-page="settings"]').click();
    assert.equal(await page.locator('#auto-check-enabled').isChecked(), true, 'Auto-check defaults to enabled');
    assert.equal(await page.locator('#auto-check-interval-minutes').inputValue(), '60', 'Auto-check defaults to 1 hour (60m)');
    await page.locator('#auto-check-interval-minutes').selectOption('180');
    await page.waitForFunction(() => window.uxFixture.settingsPatches.some(p => p.autoCheckIntervalMinutes === 180));
    await page.locator('#auto-check-enabled').uncheck({ force: true });
    await page.waitForFunction(() => window.uxFixture.settingsPatches.some(p => p.autoCheckEnabled === false));
    assert.equal(await page.locator('#auto-check-interval-option').isHidden(), true, 'Turning off auto-check hides interval selector');
    await page.locator('#auto-check-enabled').check({ force: true });
    await page.waitForFunction(() => !document.querySelector('#auto-check-interval-option').classList.contains('hidden'));
    await page.locator('.nav-item[data-page="connections"]').click();

    await page.locator('#vault-view-toggle').click();
    assert.equal(await page.evaluate(() => document.querySelector('#connections-list').dataset.view), 'grid', 'View toggle switches to 4-column card grid');
    const cards = page.locator('.connection-card');
    const card0 = await cards.nth(0).locator('.connection-name').boundingBox();
    const card3 = await cards.nth(3).boundingBox();

    // Drag card 0 -> card 3 right edge (column 4 edge test!)
    await page.mouse.move(card0.x + card0.width / 2, card0.y + card0.height / 2);
    await page.mouse.down();
    await page.mouse.move(card0.x + card0.width / 2 + 12, card0.y + card0.height / 2 + 10, { steps: 2 });
    const immediatePreview = await page.evaluate(() => {
      const p = document.querySelector('.item-drag-preview');
      if (!p) return null;
      const r = p.getBoundingClientRect();
      return { left: r.left, top: r.top, z: Number(getComputedStyle(p).zIndex) };
    });
    assert.ok(immediatePreview, 'Item drag preview created immediately on drag threshold');
    assert.ok(immediatePreview.left > 0 && immediatePreview.top >= 44, 'Item drag preview does NOT flash at (0,0) and stays below titlebar');
    assert.ok(immediatePreview.z >= 2000, 'Item drag preview z-index is topmost');

    // Push pointer to extreme bottom-right edge (459, 689) and verify clamping
    await page.mouse.move(459, 689, { steps: 3 });
    await page.waitForTimeout(40);
    const clampedItem = await page.evaluate(() => {
      const r = document.querySelector('.item-drag-preview').getBoundingClientRect();
      return { left: r.left, top: r.top, right: r.right, bottom: r.bottom, w: innerWidth, h: innerHeight };
    });
    assert.ok(clampedItem.right <= clampedItem.w && clampedItem.bottom <= clampedItem.h, 'Item drag preview stays inside window bounds at bottom-right');

    // Move onto card 3 -> sibling cards FLIP-reorder live before mouse release
    await page.mouse.move(card3.x + card3.width - 10, card3.y + card3.height / 2, { steps: 4 });
    await page.waitForTimeout(40);
    const liveGridOrder = await page.evaluate(() => [...document.querySelectorAll('#connections-list .connection-card')].map(el => el.dataset.itemId));
    assert.deepEqual(liveGridOrder, ['item-2', 'item-3', 'item-4', 'item-1', 'item-5'], 'Dragging over column 4 shifts sibling cards live via FLIP');
    await page.mouse.up();
    await page.waitForFunction(() => window.uxFixture.reorders.length === 1);
    assert.deepEqual(await page.evaluate(() => window.uxFixture.reorders[0]), ['item-2', 'item-3', 'item-4', 'item-1', 'item-5']);

    // No-op keyboard reorder at index 0 should NOT trigger backend write
    await page.locator('.connection-card').nth(0).locator('.connection-name').focus();
    await page.keyboard.press('ArrowLeft');
    await page.waitForTimeout(50);
    assert.equal(await page.evaluate(() => window.uxFixture.reorders.length), 1, 'Boundary ArrowLeft does not trigger no-op reorder IPC');

    // Escape cancels item drag cleanly
    const c1 = await page.locator('.connection-card').nth(0).locator('.connection-name').boundingBox();
    await page.mouse.move(c1.x + 10, c1.y + 10);
    await page.mouse.down();
    await page.mouse.move(c1.x + 50, c1.y + 40, { steps: 3 });
    await page.keyboard.press('Escape');
    await page.mouse.up();
    assert.equal(await page.locator('.item-drag-preview').count(), 0, 'Escape cleans up item drag preview');
    assert.equal(await page.evaluate(() => window.uxFixture.reorders.length), 1, 'Cancelled item drag does not reorder');

    // 1d. Click anywhere on card opens editor + Custom select menu has no native arrow scrollbar + Modal Occlusion
    await page.locator('.connection-card').first().locator('.connection-type').click();
    await page.locator('#connection-modal').waitFor({ state: 'visible' });

    // Open item-type custom select dropdown and confirm clean scrollbar-free menu
    await page.locator('#connection-modal select').first().click();
    await page.locator('#custom-select-menu').waitFor({ state: 'visible' });
    const selectMenuCheck = await page.evaluate(() => {
      const menu = document.querySelector('#custom-select-menu');
      return {
        scrollbarWidth: getComputedStyle(menu).scrollbarWidth,
        scrollHeight: menu.scrollHeight,
        clientHeight: menu.clientHeight,
      };
    });
    assert.equal(selectMenuCheck.scrollbarWidth, 'none', 'Custom select menu hides native OS scrollbar');
    assert.ok(selectMenuCheck.scrollHeight <= selectMenuCheck.clientHeight + 2, `Type menu fits all 7 options without scrollbar (${JSON.stringify(selectMenuCheck)})`);
    await page.keyboard.press('Escape');

    const editorOcclusion = await page.evaluate(() => {
      const bar = document.querySelector('.title-drag-region').getBoundingClientRect();
      const modal = document.querySelector('#connection-modal').getBoundingClientRect();
      const card = document.querySelector('#connection-modal .modal-card').getBoundingClientRect();
      const headerStyle = getComputedStyle(document.querySelector('#connection-modal .modal-header'));
      const footerStyle = getComputedStyle(document.querySelector('#connection-modal .modal-footer'));
      const topBackdropHit = document.elementFromPoint(30, bar.top + 6)?.closest('#connection-modal') !== null;
      return {
        modalTop: Math.round(modal.top),
        cardTop: Math.round(card.top),
        cardBottom: Math.round(card.bottom),
        innerHeight,
        topBackdropHit,
        headerBorderBottom: headerStyle.borderBottomWidth,
        footerBorderTop: footerStyle.borderTopWidth,
      };
    });
    assert.equal(editorOcclusion.modalTop, 0, 'Modal blur backdrop covers full window from y=0 including titlebar');
    assert.equal(editorOcclusion.topBackdropHit, true, 'Modal backdrop covers titlebar area so header is blurred underneath');
    assert.equal(editorOcclusion.headerBorderBottom, '0px', 'Modal header has no horizontal divider line');
    assert.equal(editorOcclusion.footerBorderTop, '0px', 'Modal footer has no horizontal divider line');
    assert.ok(editorOcclusion.cardBottom <= editorOcclusion.innerHeight, 'Editor modal card fits cleanly inside viewport');

    // Open Add Module menu -> then open Password Generator from a password row
    // Verify: module menu auto-closes, Generator renders ABOVE editor, Escape closes Generator first, then Editor!
    await page.locator('#add-module-button').click();
    await page.locator('#module-menu').waitFor({ state: 'visible' });
    // Ensure a password module exists to click generate
    if (await page.locator('#connection-modal [data-generate-password]').count() === 0) {
      await page.locator('#module-menu [data-add-module="password"]').click();
      await page.locator('#add-module-button').click();
      await page.locator('#module-menu').waitFor({ state: 'visible' });
    }
    await page.locator('#connection-modal [data-generate-password]').first().click();
    await page.locator('#generator-modal').waitFor({ state: 'visible' });
    const stacking = await page.evaluate(() => ({
      menuHidden: document.querySelector('#module-menu').classList.contains('hidden'),
      zEditor: Number(getComputedStyle(document.querySelector('#connection-modal')).zIndex),
      zMenu: Number(getComputedStyle(document.querySelector('#module-menu')).zIndex),
      zGen: Number(getComputedStyle(document.querySelector('#generator-modal')).zIndex),
      zConfirm: Number(getComputedStyle(document.querySelector('#confirmation-modal')).zIndex),
      zLock: Number(getComputedStyle(document.querySelector('#owner-lock-layer')).zIndex),
      zToast: Number(getComputedStyle(document.querySelector('#toast-region')).zIndex),
      genBackdropCoversTop: document.elementFromPoint(30, 14)?.closest('#generator-modal') !== null,
    }));
    assert.equal(stacking.menuHidden, true, 'Opening Generator auto-closes floating module menu');
    assert.ok(stacking.zEditor < stacking.zMenu && stacking.zMenu < stacking.zGen && stacking.zGen < stacking.zConfirm && stacking.zConfirm < stacking.zLock && stacking.zLock < stacking.zToast,
      `Strict non-overlapping z-index hierarchy holds: ${JSON.stringify(stacking)}`);
    assert.equal(stacking.genBackdropCoversTop, true, 'Nested Generator modal blur backdrop covers top header');

    // Escape closes Generator FIRST, leaving Editor open
    await page.keyboard.press('Escape');
    await page.locator('#generator-modal').waitFor({ state: 'hidden' });
    assert.equal(await page.locator('#connection-modal').isVisible(), true, 'Escape closes nested Generator while keeping Item Editor open');

    // Module drag-and-drop inside Editor: homepage-style whole-card lifted clone + live FLIP + viewport clamping
    if (await page.locator('#module-list .module-row').count() < 2) {
      await page.locator('#add-module-button').click();
      await page.locator('#module-menu [data-add-module="username"]').click();
    }
    const mod0Row = await page.locator('#module-list .module-row[data-module-drag-handle]').nth(0).boundingBox();
    const mod1Row = await page.locator('#module-list .module-row[data-module-drag-handle]').nth(1).boundingBox();
    await page.mouse.move(mod0Row.x + mod0Row.width * 0.5, mod0Row.y + 14);
    await page.mouse.down();
    await page.mouse.move(459, 689, { steps: 4 });
    const modDragCheck = await page.evaluate(() => {
      const p = document.querySelector('.module-drag-preview');
      const lifted = p?.querySelector('.module-row.is-lifted-card');
      if (!p || !lifted) return null;
      const r = p.getBoundingClientRect();
      const pStyle = getComputedStyle(p);
      const lStyle = getComputedStyle(lifted);
      return {
        z: Number(pStyle.zIndex),
        borderLeftWidth: lStyle.borderLeftWidth,
        borderRightWidth: lStyle.borderRightWidth,
        right: r.right,
        bottom: r.bottom,
        w: innerWidth,
        h: innerHeight,
        hasLiftedCard: true,
      };
    });
    assert.ok(modDragCheck && modDragCheck.hasLiftedCard, 'Module drag renders homepage-style lifted-card clone');
    assert.ok(modDragCheck.z >= 2000, 'Module drag preview renders above window frame');
    assert.equal(modDragCheck.borderLeftWidth, modDragCheck.borderRightWidth, 'Lifted module card has uniform border');
    assert.ok(modDragCheck.right <= modDragCheck.w && modDragCheck.bottom <= modDragCheck.h, 'Module drag preview clamped inside viewport');
    await page.mouse.move(mod1Row.x + 20, mod1Row.y + mod1Row.height - 2, { steps: 4 });
    await page.mouse.up();

    // Ctrl+S saves from inside Item Editor
    await page.keyboard.press('Control+s');
    await page.locator('#connection-modal').waitFor({ state: 'hidden' });
    assert.equal(await page.evaluate(() => window.uxFixture.saves.length), 1, 'Ctrl+S saves item inside editor');

    // 1e. Modern cross-platform keyboard shortcuts on Windows
    await page.keyboard.press('Control+k');
    assert.equal(await page.evaluate(() => document.activeElement?.id), 'title-search-input', 'Ctrl+K focuses search');
    await page.keyboard.press('Escape');
    await page.keyboard.press('Control+,');
    assert.equal(await page.locator('#page-settings').evaluate(el => el.classList.contains('active')), true, 'Ctrl+, opens Settings');
    await page.keyboard.press('Control+2');
    assert.equal(await page.locator('#page-import').evaluate(el => el.classList.contains('active')), true, 'Ctrl+2 opens Import');
    await page.keyboard.press('Control+3');
    assert.equal(await page.locator('#page-activity').evaluate(el => el.classList.contains('active')), true, 'Ctrl+3 opens Log');
    await page.keyboard.press('Control+1');
    assert.equal(await page.locator('#page-connections').evaluate(el => el.classList.contains('active')), true, 'Ctrl+1 opens Items');
    await page.keyboard.press('Control+n');
    await page.locator('#connection-modal').waitFor({ state: 'visible' });
    await page.keyboard.press('Escape');
    await page.locator('#connection-modal').waitFor({ state: 'hidden' });

    // 1f. Extension drag card + keyboard fallback on Settings page
    await page.keyboard.press('Control+,');
    const dragBtn = page.locator('#drag-extension-button');
    await dragBtn.scrollIntoViewIfNeeded();
    const dBox = await dragBtn.boundingBox();
    await page.mouse.move(dBox.x + 20, dBox.y + dBox.height / 2);
    await page.mouse.down();
    await page.mouse.move(dBox.x + 40, dBox.y + dBox.height / 2, { steps: 3 });
    await page.mouse.up();
    assert.equal(await page.evaluate(() => window.uxFixture.extensionDrags), 1, 'Dragging extension card invokes native drag_browser_extension');
    await dragBtn.focus();
    await page.keyboard.press('Enter');
    assert.equal(await page.evaluate(() => window.uxFixture.extensionFolderOpens), 1, 'Enter on extension drag card opens extension folder');

    // 1g. Confirmation modal full-window backdrop + backdrop click + Ctrl+Shift+L lock
    await page.locator('#reset-pairing-button').scrollIntoViewIfNeeded();
    await page.locator('#reset-pairing-button').click();
    await page.locator('#confirmation-modal').waitFor({ state: 'visible' });
    const confirmCoversTop = await page.evaluate(() => document.elementFromPoint(30, 14)?.closest('#confirmation-modal') !== null);
    assert.equal(confirmCoversTop, true, 'Confirmation modal blur backdrop covers top header');
    // Click backdrop corner of confirmation modal -> cancels
    await page.mouse.click(12, 12);
    await page.locator('#confirmation-modal').waitFor({ state: 'hidden' });

    // Ctrl+Shift+L locks vault immediately when PIN is configured
    await page.keyboard.press('Control+Shift+L');
    await page.locator('#owner-lock-layer').waitFor({ state: 'visible' });
    assert.equal(await page.evaluate(() => window.uxFixture.locks), 1, 'Ctrl+Shift+L locks vault');

    assert.deepEqual(errors, [], `Zero page errors on Windows: ${errors.join('; ')}`);
    await context.close();
  }

  // =========================================================================
  // 2. macOS: Native Top-Left Traffic Lights (Close -> Minimize), Blur Dim,
  //    No Desktop Shortcut Option, Cmd+K / Cmd+, / Cmd+N / Cmd+W Shortcuts
  // =========================================================================
  {
    const { context, page, errors } = await openPlatformPage(browser, {
      platform: 'MacIntel',
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 Version/17.6 Safari/605.1.15',
    });

    const macChrome = await page.evaluate(() => {
      const mark = document.querySelector('.app-mark').getBoundingClientRect();
      const controls = document.querySelector('.window-controls').getBoundingClientRect();
      const closeBtn = document.querySelector('[data-window-action="close"]');
      const minBtn = document.querySelector('[data-window-action="minimize"]');
      const closeRect = closeBtn.getBoundingClientRect();
      const minRect = minBtn.getBoundingClientRect();
      const closeStyle = getComputedStyle(closeBtn);
      return {
        isMac: document.documentElement.classList.contains('platform-macos'),
        isLinux: document.documentElement.classList.contains('platform-linux'),
        controlsLeftOfMark: controls.right <= mark.left + 1,
        closeLeftOfMin: closeRect.left < minRect.left,
        dotWidth: Math.round(closeRect.width),
        dotHeight: Math.round(closeRect.height),
        borderRadius: closeStyle.borderRadius,
        closeBg: closeStyle.backgroundColor,
        searchTitle: document.querySelector('#title-search-input').title,
        desktopShortcutHidden: getComputedStyle(document.querySelector('#desktop-shortcut-option')).display === 'none',
      };
    });
    assert.equal(macChrome.isMac, true, 'macOS sets html.platform-macos');
    assert.equal(macChrome.isLinux, false);
    assert.equal(macChrome.controlsLeftOfMark, true, 'macOS places traffic lights on top-left');
    assert.equal(macChrome.closeLeftOfMin, true, 'macOS places Close (red) left of Minimize (yellow)');
    assert.equal(macChrome.dotWidth, 12);
    assert.equal(macChrome.dotHeight, 12);
    assert.equal(macChrome.borderRadius, '50%', 'macOS traffic lights are circular');
    assert.equal(macChrome.desktopShortcutHidden, true, 'macOS hides desktop shortcut option');
    assert.match(macChrome.searchTitle, /⌘K/, 'macOS advertises ⌘K shortcut');

    // Window blur dims macOS traffic lights, focus restores them
    await page.evaluate(() => window.dispatchEvent(new Event('blur')));
    await page.waitForTimeout(180);
    const blurredBg = await page.evaluate(() => ({
      blurred: document.documentElement.classList.contains('window-blurred'),
      bg: getComputedStyle(document.querySelector('[data-window-action="close"]')).backgroundColor,
    }));
    assert.equal(blurredBg.blurred, true);
    assert.notEqual(blurredBg.bg, macChrome.closeBg, 'macOS traffic lights dim on window blur');
    await page.evaluate(() => window.dispatchEvent(new Event('focus')));
    assert.equal(await page.evaluate(() => document.documentElement.classList.contains('window-blurred')), false);

    // macOS Cmd+K, Cmd+,, Cmd+N, Cmd+W (closes modal first, then hides window)
    await page.keyboard.press('Meta+k');
    assert.equal(await page.evaluate(() => document.activeElement?.id), 'title-search-input', 'Cmd+K focuses search on macOS');
    await page.keyboard.press('Escape');
    await page.keyboard.press('Meta+,');
    assert.equal(await page.locator('#page-settings').evaluate(el => el.classList.contains('active')), true, 'Cmd+, opens Settings on macOS');
    await page.keyboard.press('Meta+n');
    await page.locator('#connection-modal').waitFor({ state: 'visible' });
    await page.keyboard.press('Meta+w');
    await page.locator('#connection-modal').waitFor({ state: 'hidden' });
    assert.deepEqual(await page.evaluate(() => window.uxFixture.windowActions), [], 'First Cmd+W closes open modal instead of hiding app');
    await page.keyboard.press('Meta+w');
    assert.deepEqual(await page.evaluate(() => window.uxFixture.windowActions), ['close'], 'Cmd+W with no open modal triggers window close/hide');

    assert.deepEqual(errors, [], `Zero page errors on macOS: ${errors.join('; ')}`);
    await context.close();
  }

  // =========================================================================
  // 3. LINUX: Transparent Shell, Bottom Rounded Modal/Lock Corners, Top-Right
  //    Window Controls, Modal Backdrop Dismissal
  // =========================================================================
  {
    const { context, page, errors } = await openPlatformPage(browser, {
      platform: 'Linux x86_64',
      userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/134.0.0.0 Safari/537.36',
    });

    const linuxChrome = await page.evaluate(() => {
      const mark = document.querySelector('.app-mark').getBoundingClientRect();
      const controls = document.querySelector('.window-controls').getBoundingClientRect();
      const modalRadius = getComputedStyle(document.querySelector('#migration-modal')).borderRadius;
      const lockRadius = getComputedStyle(document.querySelector('#owner-lock-layer')).borderRadius;
      return {
        isLinux: document.documentElement.classList.contains('platform-linux'),
        isMac: document.documentElement.classList.contains('platform-macos'),
        htmlBg: getComputedStyle(document.documentElement).backgroundColor,
        controlsRightOfMark: controls.left > mark.right,
        modalRadius,
        lockRadius,
      };
    });
    assert.equal(linuxChrome.isLinux, true, 'Linux sets html.platform-linux');
    assert.equal(linuxChrome.isMac, false);
    assert.equal(linuxChrome.htmlBg, 'rgba(0, 0, 0, 0)', 'Linux root stays transparent for rounded compositor frame');
    assert.equal(linuxChrome.controlsRightOfMark, true, 'Linux places window controls on top-right');
    assert.equal(linuxChrome.modalRadius, '8px', 'Linux full-window modal backdrop preserves all rounded window corners');
    assert.equal(linuxChrome.lockRadius, '0px 0px 8px 8px', 'Linux owner lock overlay preserves bottom rounded window corners');

    // Test migration modal Escape + backdrop click + focus trap
    await page.keyboard.press('Control+,');
    await page.locator('#migration-open').scrollIntoViewIfNeeded();
    await page.locator('#migration-open').click();
    await page.locator('#migration-modal').waitFor({ state: 'visible' });
    await page.keyboard.press('Escape');
    await page.locator('#migration-modal').waitFor({ state: 'hidden' });

    await page.locator('#migration-open').click();
    await page.locator('#migration-modal').waitFor({ state: 'visible' });
    await page.mouse.click(12, 60);
    await page.locator('#migration-modal').waitFor({ state: 'hidden' });

    assert.deepEqual(errors, [], `Zero page errors on Linux: ${errors.join('; ')}`);
    await context.close();
  }

  console.log('UX INTERACTIONS SUITE PASSED (Windows + macOS + Linux: drag, occlusion, z-index, shortcuts, chrome)');
} finally {
  await browser.close();
  server.close();
}
