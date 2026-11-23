// Isolated renderer fixture: no desktop vault or real credentials are used.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import { once } from 'node:events';
import { chromium } from 'playwright';
import { auditControlGeometry } from './fixtures/control-geometry.mjs';
import { auditControlStates } from './fixtures/control-states.mjs';

const renderer = path.resolve(import.meta.dirname, '../renderer');
const artifacts = await fs.mkdtemp(path.join(os.tmpdir(), 'openkeylet-inline-ui-'));
const server = http.createServer(async (req, res) => {
  const pathname = decodeURIComponent(req.url.split('?')[0]);
  const file = path.resolve(renderer, '.' + (pathname === '/' ? '/index.html' : pathname));
  if (!file.startsWith(renderer + path.sep)) { res.writeHead(403); res.end(); return; }
  try {
    res.setHeader('Content-Type', file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.svg') ? 'image/svg+xml' : 'text/html');
    res.end(await fs.readFile(file));
  } catch { res.writeHead(404); res.end(); }
});
server.listen(0, '127.0.0.1'); await once(server, 'listening');
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 460, height: 690 }, deviceScaleFactor: 1.5 });
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => {
    window.setInterval = () => 0;
    const item = (id, name, capabilities) => ({
      id, name, capabilities, itemType: 'custom', description: 'Hidden synthetic description',
      enabled: true, canTest: true, updatedAt: 'revision-1', passkeys: [], folder: '', favorite: id === 'alpha',
      modules: [{ kind: 'url', value: 'https://example.test', agentVisible: true }, { kind: 'password', value: '', configured: true, agentVisible: false }],
      secret: { fields: [] }, passwordHistoryCount: 1,
    });
    const state = {
      settings: { language: 'en', closeBehavior: 'tray', browserEnabled: true, browserPort: 39272 },
      connections: [item('alpha', 'Synthetic service with a very long name', ['http']), item('beta', 'Synthetic server', ['ssh']), { ...item('gamma', 'Synthetic password', ['fill']), itemType: 'login' }],
      activities: [
        { id: 'ok', action: 'Synthetic success', connectionName: 'Synthetic server', status: 'success', source: 'mcp', durationMs: 42, time: new Date().toISOString() },
        { id: 'error', action: 'Synthetic failure', connectionName: 'Synthetic API', status: 'error', source: 'mcp', durationMs: 60, error: 'Fixture failure', time: new Date().toISOString() },
      ], mcp: { status: 'ready', endpoint: 'fixture', stdioCommand: 'fixture' },
      browserBridge: { status: 'listening', enabled: true, connected: true, paired: true, endpoint: 'fixture' },
      security: { encrypted: true, storage: 'fixture' },
    };
    window.fixture = { state, drafts: [], saved: [], orders: [], tested: [], copied: [], histories: [], orderRequests: 0, revision: 1, failDraft: false, failOrder: false,
      owner: { pinConfigured: false, unlocked: true }, integrations: { desktopShortcut: false, launchAtLogin: false },
      integrationWrites: [], settingsWrites: [], failIntegration: false, pinDisables: 0 };
    window.__TAURI__ = { event: { listen: async () => () => {} }, core: { invoke: async (command, args = {}) => {
      if (command === 'get_state') return structuredClone(state);
      if (command === 'owner_status') return structuredClone(fixture.owner);
      if (command === 'owner_disable_pin') { fixture.pinDisables++; fixture.owner.pinConfigured = false; return structuredClone(fixture.owner); }
      if (command === 'owner_editor_drafts') return structuredClone(fixture.drafts);
      if (command === 'agent_mcp_status') return [
        { clientId: 'fixture-ready', displayName: 'Synthetic agent', state: 'available', canRegister: true },
        { clientId: 'fixture-stale', displayName: 'Synthetic stale agent', state: 'stale', canRepair: true, canRemove: true },
      ];
      if (command === 'github_backup_status') return { connected: false };
      if (command === 'system_integration_status') return structuredClone(fixture.integrations);
      if (command === 'set_desktop_shortcut' || command === 'set_launch_at_login') {
        fixture.integrationWrites.push({ command, enabled: args.enabled });
        if (fixture.failIntegration) throw Error('Synthetic integration failure');
        fixture.integrations[command === 'set_desktop_shortcut' ? 'desktopShortcut' : 'launchAtLogin'] = args.enabled;
        return structuredClone(fixture.integrations);
      }
      if (command === 'update_settings') { fixture.settingsWrites.push(args.patch); Object.assign(state.settings, args.patch); return state.settings; }
      if (command === 'owner_secret_view') return { fields: [{ name: 'password', value: 'synthetic-password' }] };
      if (command === 'set_connection_enabled') { state.connections.find(item => item.id === args.id).enabled = args.enabled; return; }
      if (command === 'test_connection') { fixture.tested.push(args.id); return 'Synthetic test completed'; }
      if (command === 'copy_owner_value') { fixture.copied.push(args.value); return; }
      if (command === 'owner_password_history') { fixture.histories.push(args.id); return { entries: [] }; }
      if (command === 'generate_password') return 'Aa1!'.repeat(32).slice(0, args.options.length);
      if (command === 'save_editor_draft') {
        if (fixture.failDraft) throw Error('Synthetic draft failure');
        const draft = { id: args.draftId || `draft-${args.input.id || 'new'}`, input: structuredClone(args.input) };
        fixture.drafts = [draft, ...fixture.drafts.filter(d => d.id !== draft.id)]; return draft;
      }
      if (command === 'delete_editor_draft') { fixture.drafts = fixture.drafts.filter(d => d.id !== args.id); return; }
      if (command === 'save_connection') {
        const index = state.connections.findIndex(i => i.id === args.input.id);
        const existing = state.connections[index];
        if (existing && args.expectedUpdatedAt !== existing.updatedAt) throw Error('Stale edit');
        fixture.saved.push(structuredClone(args.input));
        const saved = { ...existing, ...args.input, updatedAt: `revision-${++fixture.revision}` };
        state.connections[index] = saved; return saved;
      }
      if (command === 'delete_connection') { state.connections = state.connections.filter(i => i.id !== args.id); return; }
      if (command === 'reorder_connections') {
        fixture.orderRequests += 1;
        if (fixture.failOrder) throw Error('Synthetic reorder failure');
        if (JSON.stringify(state.connections.map(i => i.id)) !== JSON.stringify(args.expectedOrder)) throw Error('Stale order');
        if (new Set(args.ids).size !== state.connections.length || args.ids.some(id => !state.connections.some(i => i.id === id))) throw Error('Invalid order');
        state.connections = args.ids.map(id => state.connections.find(i => i.id === id));
        fixture.orders.push(args.ids); return;
      }
      return {};
    } } };
  });
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page.locator('.connection-card').first().waitFor();
  const row = id => page.locator(`.connection-card[data-item-id="${id}"]`);
  const toggle = id => row(id).locator('.item-disclosure');
  const editor = page.locator('#connection-modal');
  const search = page.locator('#title-search-input');
  const fillSearch = async value => {
    if (!await search.isVisible()) await page.locator('#title-search-toggle').click();
    await search.fill(value);
  };
  const slideFilter = async (selector, from, to, cancel = false, expected = cancel ? from : to) => {
    const strip = page.locator(selector), buttons = strip.locator('button');
    const start = await buttons.nth(from).boundingBox(), end = await buttons.nth(to).boundingBox();
    await page.mouse.move(start.x + start.width / 2, start.y + start.height / 2); await page.mouse.down();
    await page.mouse.move(end.x + end.width / 2, end.y + end.height / 2, { steps: 8 });
    assert.equal(await strip.evaluate(el => el.classList.contains('is-dragging')), true);
    assert.equal(await buttons.nth(from).getAttribute('aria-pressed'), 'true', 'Dragging previews without changing the filter before release');
    if (cancel) { await page.keyboard.press('Escape'); await page.waitForTimeout(60); }
    await page.mouse.up();
    await page.waitForFunction(({ selector, index }) => document.querySelector(selector).querySelectorAll('button')[index].getAttribute('aria-pressed') === 'true' && !document.querySelector(selector).hasAttribute('aria-busy'), { selector, index: expected });
    assert.equal(await strip.evaluate(el => el.style.getPropertyValue('--drag-type')), '');
  };
  const dragSwitch = async (selector, from, to, { count = 2, cancel = false, settle = true } = {}) => {
    const control = page.locator(selector);
    await control.scrollIntoViewIfNeeded();
    const box = await control.boundingBox();
    const inset = await control.evaluate(el => parseFloat(getComputedStyle(el).paddingLeft));
    const cell = (box.width - 2 * inset) / count, y = box.y + box.height / 2;
    await page.mouse.move(box.x + inset + cell * (from + .5), y); await page.mouse.down();
    await page.mouse.move(box.x + inset + cell * (to + .5), y, { steps: 8 });
    assert.equal(await control.evaluate(el => el.classList.contains('is-dragging')), true, `${selector} must drag its cap`);
    if (cancel) { await page.keyboard.press('Escape'); await page.waitForTimeout(60); }
    await page.mouse.up();
    if (settle) await page.waitForFunction(selector => !document.querySelector(selector).hasAttribute('aria-busy'), selector);
  };
  const hover = async locator => {
    await page.mouse.move(0, 0); await locator.scrollIntoViewIfNeeded();
    const face = el => { const s = getComputedStyle(el); return [s.backgroundColor, s.backgroundImage, s.boxShadow, el.offsetWidth, el.offsetHeight]; };
    const before = await locator.evaluate(face);
    await locator.hover(); await page.waitForTimeout(150);
    assert.deepEqual(await locator.evaluate(face), before, 'Hover must only illuminate the ink');
  };
  const headerMeasurements = [];
  const geometryMeasurements = [];
  const stateMeasurements = [];
  const display = await page.context().newCDPSession(page);
  for (const language of ['en', 'zh']) for (const theme of ['dark', 'light']) {
    await page.locator(`[data-language="${language}"]`).click();
    if (await page.locator('html').getAttribute('data-theme') !== theme) await page.locator('#theme-toggle').click();
    await page.mouse.move(0, 0); await page.waitForTimeout(170);
    const measure = await page.evaluate(() => {
      const rect = el => el.getBoundingClientRect();
      const center = el => { const r = rect(el); return r.y + r.height / 2; };
      return {
        centers: [...document.querySelectorAll('.title-tools svg, .app-mark-logo, .app-mark strong .lettering-ink')].map(center),
        wells: [...document.querySelectorAll('.title-switch, .language-switch, .window-control-well')].map(el => {
          const style = getComputedStyle(el), cap = el.matches('.title-switch') ? getComputedStyle(el, '::before') : null;
          return { height: rect(el).height, padding: [style.paddingTop, style.paddingRight, style.paddingBottom, style.paddingLeft], cap: cap && [cap.top, cap.left, cap.bottom, cap.width] };
        }),
        colors: [...document.querySelectorAll('.title-switch-option')].map(el => getComputedStyle(el).color),
        inactiveColor: getComputedStyle(document.querySelector('.language-switch button:not(.active)')).color,
        inactiveIcons: [...document.querySelectorAll('.title-switch')].map(el => getComputedStyle(el.querySelector(`[data-state="${el.getAttribute('aria-checked') === 'false'}"]`)).color),
        cards: [...document.querySelectorAll('.connection-card')].map(el => {
          const outer = rect(el), name = rect(el.querySelector('.connection-name'));
          const type = rect(el.querySelector('.connection-type')), actions = rect(el.querySelector('.card-actions'));
          const children = [...el.children].map(rect);
          return { x: outer.x, y: outer.y, width: outer.width, height: outer.height, within: children.every(r => r.left >= outer.left && r.right <= outer.right), vertical: name.bottom <= type.top && type.bottom <= actions.top };
        }),
        overflow: document.documentElement.scrollWidth > innerWidth,
        recesses: [...document.querySelectorAll('.title-search, .title-switch, .language-switch, .window-control-well, .nav, .metric-grid, #item-type-switch, .creation-control')].map(el => {
          const s = getComputedStyle(el); return { readout: el.matches('.metric-grid'), height: rect(el).height, material: [s.backgroundColor, s.boxShadow] };
        }),
      };
    });
    assert.equal(measure.overflow, false);
    assert.equal(new Set(measure.centers).size, 1, 'Header icons and wordmark must share a centerline');
    assert.ok(measure.inactiveIcons.every(color => color === measure.inactiveColor), `Unselected switch icons must use neutral language-button ink: ${JSON.stringify([measure.inactiveIcons, measure.inactiveColor])}`);
    for (const card of measure.cards) {
      assert.ok(card.height >= 86 && card.width < 150 && card.within && card.vertical);
    }
    assert.equal(new Set(measure.cards.map(card => card.y)).size, 1, 'The first three items share one grid row');
    assert.equal(new Set(measure.cards.map(card => card.x)).size, 3, 'The three items occupy distinct columns');
    for (const well of measure.wells) {
      assert.equal(well.height, 32); assert.deepEqual(well.padding, ['4px', '4px', '4px', '4px']);
      if (well.cap) assert.deepEqual(well.cap, ['4px', '4px', '4px', '24px']);
    }
    for (const recess of measure.recesses) {
      assert.equal(recess.height, recess.readout ? 48 : 32, 'Header and readout retain their spacing');
      assert.deepEqual(recess.material, measure.recesses[0].material, 'Every well shares the same floor and edge profile');
    }
    headerMeasurements.push({ language, theme, ...measure });
    for (const scale of [1, 1.25, 1.5, 2]) {
      await display.send('Emulation.setDeviceMetricsOverride', { width: 460, height: 690, deviceScaleFactor: scale, mobile: false });
      geometryMeasurements.push(await auditControlGeometry(page));
    }
    await display.send('Emulation.setDeviceMetricsOverride', { width: 460, height: 690, deviceScaleFactor: 1.5, mobile: false });
    await hover(toggle('alpha'));
    await hover(row('alpha').locator('.connection-name'));
    await hover(row('alpha').locator('.connection-type'));
    const selectedInk = await page.locator('.nav-item.active').evaluate(el => getComputedStyle(el).color);
    for (const selector of ['.window-control.close', '#add-connection-button', '[data-action="copy-name"]']) {
      const action = page.locator(selector).first(); await action.hover(); await page.waitForTimeout(150);
      assert.equal(await action.evaluate(el => getComputedStyle(el).color), selectedInk, 'Ordinary actions share the selected-state accent');
    }
    const destructive = row('alpha').locator('[data-action="delete"]');
    await destructive.hover(); await page.waitForTimeout(150);
    assert.notEqual(await destructive.evaluate(el => getComputedStyle(el).color), selectedInk, 'Destructive actions retain distinct warning ink');
    await page.mouse.move(0, 0);
    await page.screenshot({ path: path.join(artifacts, `compact-${language}-${theme}.png`) });
    await page.locator('[data-page="settings"]').click();
    await page.locator('[data-settings-filter="all"]').click();
    await page.locator('.settings-layout').evaluate(el => { el.scrollTop = 0; });
    geometryMeasurements.push(await auditControlGeometry(page));
    const settingsIssues = await page.evaluate(() => {
      const issues = [];
      const material = el => { const s = getComputedStyle(el); return [s.backgroundColor, s.boxShadow]; };
      const floor = JSON.stringify(material(document.querySelector('.nav')));
      for (const el of document.querySelectorAll('#page-settings :is(.input, .command-well, .status-strip, .extension-drag-card, details > summary)')) {
        if (!el.getBoundingClientRect().width) continue;
        if (JSON.stringify(material(el)) !== floor) issues.push(`${el.id || el.className}: inconsistent recessed material`);
      }
      for (const card of document.querySelectorAll('.settings-card')) {
        if (card.scrollWidth > card.clientWidth + 1) issues.push(`${card.dataset.module}: horizontal overflow`);
        const r = card.getBoundingClientRect();
        for (const el of card.querySelectorAll('button, input, select, summary, .agent-state, .settings-heading')) {
          const b = el.getBoundingClientRect();
          if (b.width && (b.left < r.left || b.right > r.right)) issues.push(`${el.id || el.className}: outside section`);
        }
      }
      return issues;
    });
    assert.deepEqual(settingsIssues, [], `SYSTEM layout in ${language}/${theme}`);
    await page.screenshot({ path: path.join(artifacts, `system-${language}-${theme}.png`) });
    if ((language === 'en' && theme === 'dark') || (language === 'zh' && theme === 'light')) {
      for (const section of ['MCP', 'APP', 'WEB', 'CLOUD', 'SAFE']) {
        await page.locator(`[data-settings-filter="${section}"]`).click();
        if (section === 'MCP') await page.locator('.manual-mcp-config summary').click();
        if (section === 'WEB') await page.locator('.browser-install-fallback summary').click();
        geometryMeasurements.push(await auditControlGeometry(page));
        await page.mouse.move(0, 0);
        await page.screenshot({ path: path.join(artifacts, `system-${section}-${language}-${theme}.png`) });
        if (section === 'MCP') await page.locator('.manual-mcp-config summary').click();
        if (section === 'WEB') await page.locator('.browser-install-fallback summary').click();
      }
    }
    await page.locator('[data-settings-filter="all"]').click();
    await page.locator('[data-page="connections"]').click();
  }
  assert.notDeepEqual(headerMeasurements[0].colors, headerMeasurements[1].colors, 'Switch icons must follow the theme');
  // A failed historical call must not report healthy current services as failed.
  assert.equal(await page.locator('.lcd-primary .seven-number').getAttribute('aria-label'), '3');
  assert.equal(await page.locator('.lcd-secondary .seven-number').getAttribute('aria-label'), '3');
  assert.deepEqual(await page.locator('.lcd-service strong').allTextContents(), ['READY', 'ON', 'OFF']);
  assert.equal(await page.locator('.lcd-status.fault').count(), 0);
  await page.evaluate(async () => { fixture.state.connections[1].enabled = false; await refresh(false); });
  assert.equal(await page.locator('.lcd-primary .seven-number').getAttribute('aria-label'), '3');
  assert.equal(await page.locator('.lcd-secondary .seven-number').getAttribute('aria-label'), '2');
  await page.evaluate(async () => { fixture.state.connections[1].enabled = true; await refresh(false); });
  for (const [status, paired, connected, expected] of [
    ['listening', false, false, 'PAIR'], ['listening', true, false, 'WAIT'],
    ['off', true, false, 'OFF'], ['error', true, false, 'ERROR'],
  ]) {
    await page.evaluate(async values => {
      Object.assign(fixture.state.browserBridge, values); await refresh(false);
    }, { status, paired, connected });
    assert.equal(await page.locator('.lcd-service').nth(1).locator('strong').textContent(), expected);
    assert.equal(await page.locator('.lcd-service').first().locator('strong').textContent(), 'READY');
  }
  await page.evaluate(async () => {
    Object.assign(fixture.state.browserBridge, { status: 'listening', paired: true, connected: true });
    await refresh(false);
  });
  // All travelling caps share drag, cancel and single-commit behavior.
  await dragSwitch('#theme-toggle', 1, 0);
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
  await dragSwitch('#theme-toggle', 0, .3);
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark', 'Returning to the same gear must not toggle it');
  await dragSwitch('#theme-toggle', 0, 1, { cancel: true });
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
  await dragSwitch('#sound-toggle', 0, 1);
  assert.equal(await page.locator('#sound-toggle').getAttribute('aria-checked'), 'true');
  assert.deepEqual(await page.evaluate(() => JSON.parse(localStorage.getItem('openkeylet.appearance.v1'))), { theme: 'dark', sound: true });
  await page.reload(); await page.locator('.connection-card').first().waitFor();
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
  assert.equal(await page.locator('#sound-toggle').getAttribute('aria-checked'), 'true');
  await dragSwitch('#sound-toggle', 1, 0);
  await dragSwitch('#theme-toggle', 0, 1);
  await dragSwitch('#language-switch', 0, 1);
  assert.equal(await page.locator('html').getAttribute('lang'), 'zh-CN');
  await dragSwitch('#language-switch', 1, 0);
  assert.equal(await page.locator('html').getAttribute('lang'), 'en');
  assert.equal(await page.evaluate(() => fixture.state.settings.language), 'en');
  await dragSwitch('.nav', 0, 2, { count: 3 });
  assert.equal(await page.locator('.page.active').getAttribute('id'), 'page-settings');
  geometryMeasurements.push(await auditControlGeometry(page));
  stateMeasurements.push(await auditControlStates(page));
  await dragSwitch('.switch:has(#desktop-shortcut-enabled)', 0, 1);
  assert.equal(await page.locator('#desktop-shortcut-enabled').isChecked(), true);
  assert.equal(await page.evaluate(() => fixture.integrationWrites.length), 1, 'A drag must not also fire the label click');
  await dragSwitch('.switch:has(#desktop-shortcut-enabled)', 1, 0);
  assert.equal(await page.locator('#desktop-shortcut-enabled').isChecked(), false);
  await page.evaluate(() => fixture.failIntegration = true);
  await dragSwitch('.switch:has(#launch-at-login-enabled)', 0, 1);
  assert.equal(await page.locator('#launch-at-login-enabled').isChecked(), false, 'A failed save restores the switch');
  await page.evaluate(() => fixture.failIntegration = false);
  await dragSwitch('.switch:has(#launch-at-login-enabled)', 0, 1);
  await dragSwitch('.switch:has(#launch-at-login-enabled)', 1, 0);
  await dragSwitch('.switch:has(#browser-enabled)', 1, 0);
  assert.equal(await page.evaluate(() => fixture.state.settings.browserEnabled), false);
  await dragSwitch('.switch:has(#browser-enabled)', 0, 1);
  assert.equal(await page.evaluate(() => fixture.state.settings.browserEnabled), true);
  await page.evaluate(async () => { fixture.owner.pinConfigured = true; await refreshOwnerLock(); renderSettings(); });
  await dragSwitch('.switch:has(#pin-enabled)', 1, 0, { settle: false });
  await page.locator('#confirmation-modal').waitFor({ state: 'visible' });
  assert.equal(await page.evaluate(() => fixture.pinDisables), 0, 'PIN drag retains confirmation before removal');
  await page.locator('#confirmation-cancel').click();
  await page.waitForFunction(() => !document.querySelector('#pin-enabled').closest('.switch').hasAttribute('aria-busy'));
  assert.equal(await page.locator('#pin-enabled').isChecked(), true);
  await dragSwitch('.switch:has(#pin-enabled)', 1, 0, { settle: false });
  await page.locator('#confirmation-accept').click();
  await page.waitForFunction(() => !document.querySelector('#pin-enabled').closest('.switch').hasAttribute('aria-busy'));
  assert.equal(await page.evaluate(() => fixture.pinDisables), 1);
  assert.equal(await page.locator('#pin-enabled').isChecked(), false);
  await dragSwitch('.nav', 2, 1, { count: 3 });
  assert.equal(await page.locator('.page.active').getAttribute('id'), 'page-activity');
  await dragSwitch('.nav', 1, 0, { count: 3 });
  await dragSwitch('.creation-options', 0, 1);
  assert.equal(await editor.isHidden(), true, 'The unavailable draft gear springs back');
  assert.equal(await page.locator('#add-connection-button').getAttribute('aria-pressed'), 'true');
  await page.locator('#add-connection-button').click();
  geometryMeasurements.push(await auditControlGeometry(page));
  await page.locator('#connection-name').fill('Switch draft');
  await page.locator('#connection-name').press('Escape'); await editor.waitFor({ state: 'hidden' });
  geometryMeasurements.push(await auditControlGeometry(page));
  await dragSwitch('.creation-options', 0, 1);
  assert.equal(await page.locator('#connection-name').inputValue(), 'Switch draft');
  await page.locator('#connection-name').press('Escape'); await editor.waitFor({ state: 'hidden' });
  await dragSwitch('.creation-options', 1, 0);
  assert.equal(await page.locator('#connection-name').inputValue(), '');
  await page.locator('#connection-name').press('Escape'); await editor.waitFor({ state: 'hidden' });
  await page.evaluate(async () => { fixture.drafts = []; await refreshDrafts(); document.querySelectorAll('.toast').forEach(el => el.remove()); });
  assert.equal(await page.locator('.connection-address, .connection-description, .module-strip').count(), 0);
  assert.equal(await page.locator('.card-actions [data-action="edit"]').count(), 3);
  assert.deepEqual(await page.locator('.connection-type').evaluateAll(elements => elements.map(el => el.dataset.itemType)), ['api', 'ssh', 'login']);
  assert.equal(await page.locator('.connection-type svg').count(), 3);
  assert.deepEqual((await page.locator('.connection-type').allTextContents()).map(text => text.toUpperCase()), ['API', 'SSH', 'PASSWORD']);
  await row('alpha').locator('.item-toggle').click();
  await page.waitForFunction(() => document.querySelector('.connection-card[data-item-id="alpha"] .item-toggle').getAttribute('aria-pressed') === 'false');
  assert.equal(await row('alpha').locator('[data-action="test"]').isDisabled(), true);
  await row('alpha').locator('.item-toggle').click();
  await page.waitForFunction(() => document.querySelector('.connection-card[data-item-id="alpha"] .item-toggle').getAttribute('aria-pressed') === 'true');
  await row('alpha').locator('[data-action="test"]').click();
  await row('alpha').locator('[data-action="copy-name"]').click();
  assert.deepEqual(await page.evaluate(() => fixture.tested), ['alpha']);
  assert.deepEqual(await page.evaluate(() => fixture.copied), ['use Synthetic service with a very long name in OpenKeylet MCP']);
  await row('alpha').locator('[data-action="history"]').click();
  await page.locator('#vault-management-modal').waitFor({ state: 'visible' });
  assert.deepEqual(await page.evaluate(() => fixture.histories), ['alpha']);
  await page.locator('#vault-management-close').click();
  assert.equal(await search.isHidden(), true, 'Search starts as a header icon');
  await slideFilter('#item-type-switch', 0, 3, true);
  assert.equal(await page.locator('.connection-card').count(), 3);
  await slideFilter('#item-type-switch', 0, 1);
  assert.deepEqual(await page.locator('.connection-card').evaluateAll(rows => rows.map(row => row.dataset.itemId)), ['beta']);
  await slideFilter('#item-type-switch', 1, 0);
  await page.locator('[data-item-type-filter="ssh"]').click();
  assert.deepEqual(await page.locator('.connection-card').evaluateAll(rows => rows.map(row => row.dataset.itemId)), ['beta']);
  await page.locator('[data-item-type-filter="login"]').click();
  assert.deepEqual(await page.locator('.connection-card').evaluateAll(rows => rows.map(row => row.dataset.itemId)), ['gamma']);
  await page.locator('[data-item-type-filter="api"]').click();
  assert.deepEqual(await page.locator('.connection-card').evaluateAll(rows => rows.map(row => row.dataset.itemId)), ['alpha']);
  await page.locator('[data-item-type-filter="api"]').press('Home');
  assert.equal(await page.locator('.connection-card').count(), 3);
  // All three pages share the header search and independent filter strips.
  await page.locator('[data-page="activity"]').click();
  assert.equal(await search.getAttribute('data-page-search'), 'activity');
  assert.equal(await page.locator('#page-activity .page-search').count(), 0);
  await slideFilter('#activity-filter-switch', 0, 2);
  assert.match(await page.locator('.activity-title').innerText(), /success/);
  await slideFilter('#activity-filter-switch', 2, 0);
  await page.locator('[data-activity-filter="error"]').click();
  assert.equal(await page.locator('.activity-item').count(), 1);
  assert.match(await page.locator('.activity-title').innerText(), /failure/);
  await page.locator('[data-activity-filter="success"]').click();
  assert.match(await page.locator('.activity-title').innerText(), /success/);
  await page.locator('[data-activity-filter="all"]').click();
  await fillSearch('failure');
  assert.equal(await page.locator('.activity-item').count(), 1);
  await search.press('Escape');
  assert.equal(await page.locator('.activity-item').count(), 2);
  geometryMeasurements.push(await auditControlGeometry(page));
  await page.screenshot({ path: path.join(artifacts, 'activity-filter-strip.png') });
  await page.locator('[data-page="settings"]').click();
  assert.equal(await search.getAttribute('data-page-search'), 'settings');
  assert.equal(await page.locator('#page-settings .page-search').count(), 0);
  await slideFilter('#settings-filter-switch', 0, 2);
  assert.equal(await page.locator('.settings-card:visible').count(), 1);
  await slideFilter('#settings-filter-switch', 2, 0);
  await page.locator('[data-settings-filter="MCP"]').click();
  assert.equal(await page.locator('.settings-card:visible').count(), 1);
  assert.equal(await page.locator('.settings-card:visible').getAttribute('data-module'), 'MCP / 02');
  await fillSearch('Agent');
  await page.locator('[data-page="activity"]').click();
  await page.locator('#title-search-toggle').click();
  assert.equal(await search.inputValue(), '');
  await page.locator('[data-page="settings"]').click();
  await page.locator('#title-search-toggle').click();
  assert.equal(await search.inputValue(), 'Agent');
  await search.press('Escape');
  await page.locator('[data-settings-filter="all"]').click();
  await page.screenshot({ path: path.join(artifacts, 'settings-filter-strip.png') });
  await page.locator('[data-page="connections"]').click();
  const order = () => page.locator('.connection-card').evaluateAll(rows => rows.map(row => row.dataset.itemId));
  const dragItem = async (from, target, after, release = true) => {
    const handle = row(from).locator('.connection-name');
    await handle.scrollIntoViewIfNeeded();
    const start = await handle.boundingBox(), end = await row(target).boundingBox();
    await page.mouse.move(start.x + start.width / 2, start.y + start.height / 2);
    await page.mouse.down();
    await page.mouse.move(after ? end.x + end.width * .8 : end.x + end.width * .2, end.y + end.height / 2, { steps: 8 });
    if (release) await page.mouse.up();
  };
  await page.evaluate(() => {
    window.originalItemFrame = window.requestAnimationFrame;
    window.itemFrameCount = 0;
    window.requestAnimationFrame = callback => window.originalItemFrame.call(window, time => { window.itemFrameCount++; callback(time); });
  });
  await dragItem('alpha', 'gamma', true, false);
  assert.equal(await page.locator('.item-drag-preview').count(), 1);
  await page.locator('.item-drop-after').waitFor();
  await page.waitForTimeout(100);
  const idleFrames = await page.evaluate(() => window.itemFrameCount);
  await page.waitForTimeout(150);
  assert.ok(await page.evaluate(() => window.itemFrameCount) - idleFrames <= 2, 'A stationary drag does not continually recalculate layout');
  await page.evaluate(() => { window.requestAnimationFrame = window.originalItemFrame; });
  await page.screenshot({ path: path.join(artifacts, 'name-drag-feedback.png') });
  await page.mouse.up();
  await page.waitForFunction(() => fixture.orders.length === 1 && !document.querySelector('#connections-list').hasAttribute('aria-busy'));
  assert.deepEqual(await order(), ['beta', 'gamma', 'alpha']);
  await row('alpha').locator('.connection-name').press('Home');
  await page.waitForFunction(() => fixture.orders.length === 2 && !document.querySelector('#connections-list').hasAttribute('aria-busy'));
  assert.deepEqual(await order(), ['alpha', 'beta', 'gamma']);
  await dragItem('alpha', 'gamma', true, false); await page.keyboard.press('Escape'); await page.mouse.up();
  assert.equal(await page.evaluate(() => fixture.orders.length), 2);
  assert.equal(await page.locator('.item-drag-preview').count(), 0);
  await page.evaluate(() => fixture.failOrder = true);
  await dragItem('alpha', 'gamma', true);
  await page.waitForFunction(() => fixture.orderRequests === 3 && !document.querySelector('#connections-list').hasAttribute('aria-busy'));
  assert.deepEqual(await order(), ['alpha', 'beta', 'gamma'], 'A failed reorder must preserve the saved order');
  await page.evaluate(async () => {
    fixture.failOrder = false;
    fixture.state.connections.push({ ...structuredClone(fixture.state.connections[0]), id: 'delta', name: 'Second synthetic API' });
    await refresh();
  });
  await page.locator('[data-item-type-filter="api"]').click();
  await dragItem('delta', 'alpha', false);
  await page.waitForFunction(() => fixture.orders.length === 3 && !document.querySelector('#connections-list').hasAttribute('aria-busy'));
  assert.deepEqual(await page.evaluate(() => fixture.state.connections.map(i => i.id)), ['delta', 'beta', 'gamma', 'alpha'], 'Filtered dragging preserves the hidden item slots');
  await page.locator('[data-item-type-filter="all"]').click();
  await page.evaluate(async () => {
    fixture.state.connections = ['alpha', 'beta', 'gamma'].map(id => fixture.state.connections.find(i => i.id === id));
    await refresh();
  });
  // The pointer can cross a long list without releasing the name handle.
  await page.evaluate(async () => {
    fixture.state.connections.push(...Array.from({ length: 20 }, (_, index) => ({ ...structuredClone(fixture.state.connections[0]), id: `scroll-${index}`, name: `Scroll item ${index}` })));
    await refresh();
    document.querySelector('#connections-list').scrollTop = 0;
  });
  const grid = await page.evaluate(() => {
    const list = document.querySelector('#connections-list'), bounds = list.getBoundingClientRect();
    const cards = [...list.querySelectorAll('.connection-card')].map(card => card.getBoundingClientRect());
    return { rows: [...new Set(cards.slice(0, 12).map(card => card.top))].length,
      columns: [...new Set(cards.slice(0, 4).map(card => card.left))].length,
      lastVisibleBottom: cards[11].bottom, firstExtraTop: cards[12].top, listBottom: bounds.bottom };
  });
  assert.equal(grid.columns, 4);
  assert.equal(grid.rows, 3);
  assert.ok(grid.lastVisibleBottom <= grid.listBottom + .2 && grid.firstExtraTop >= grid.listBottom - .2, `Three complete rows fit before scrolling: ${JSON.stringify(grid)}`);
  await row('alpha').locator('.connection-name').press('ArrowDown');
  await page.waitForFunction(() => !document.querySelector('#connections-list').hasAttribute('aria-busy'));
  assert.deepEqual((await order()).slice(0, 5), ['beta', 'gamma', 'scroll-0', 'scroll-1', 'alpha'], 'Down moves an item one grid row');
  await row('alpha').locator('.connection-name').press('ArrowUp');
  await page.waitForFunction(() => !document.querySelector('#connections-list').hasAttribute('aria-busy'));
  assert.deepEqual((await order()).slice(0, 5), ['alpha', 'beta', 'gamma', 'scroll-0', 'scroll-1'], 'Up returns an item to its previous row');
  const beforeScrollDrag = await page.evaluate(() => fixture.orderRequests);
  const scrollHandle = await row('alpha').locator('.connection-name').boundingBox();
  const scrollList = await page.locator('#connections-list').boundingBox();
  await page.mouse.move(scrollHandle.x + 20, scrollHandle.y + 12); await page.mouse.down();
  await page.mouse.move(scrollHandle.x + 20, scrollList.y + scrollList.height - 5, { steps: 8 });
  await page.waitForFunction(() => document.querySelector('#connections-list').scrollTop > 100);
  await page.mouse.move(scrollList.x - 5, scrollList.y + 50);
  assert.equal(await page.locator('.item-drop-before, .item-drop-after').count(), 0);
  await page.mouse.up();
  assert.equal(await page.evaluate(() => fixture.orderRequests), beforeScrollDrag, 'Dropping outside the list cancels the reorder');
  assert.equal(await page.locator('.item-drag-preview').count(), 0);
  await page.evaluate(async () => {
    fixture.state.connections = fixture.state.connections.filter(item => !item.id.startsWith('scroll-'));
    await refresh();
    document.querySelector('#connections-list').scrollTop = 0;
    document.querySelectorAll('.toast').forEach(el => el.remove());
  });
  await fillSearch('server');
  assert.equal(await page.locator('.connection-card').count(), 1);
  geometryMeasurements.push(await auditControlGeometry(page));
  await page.screenshot({ path: path.join(artifacts, 'expanded-header-search.png') });
  await page.locator('#title-search-toggle').click();
  assert.equal(await search.isHidden(), true);
  assert.equal(await page.locator('.connection-card').count(), 1, 'Collapsing search keeps its query');
  await page.keyboard.press('Control+f');
  assert.equal(await search.isVisible(), true);
  await search.press('Escape');
  assert.equal(await search.isHidden(), true);
  assert.equal(await page.locator('.connection-card').count(), 3);
  await page.locator('[data-language="en"]').click();
  const cardBounds = await row('alpha').boundingBox();
  await toggle('alpha').click();
  await page.waitForFunction(() => document.activeElement.id === 'connection-name');
  assert.equal(await editor.getAttribute('role'), 'dialog');
  assert.equal(await editor.getAttribute('aria-modal'), 'true');
  assert.equal(await editor.evaluate(el => Boolean(el.closest('.connection-card'))), false, 'The editor is an independent dialog');
  assert.deepEqual(await row('alpha').boundingBox(), cardBounds, 'Opening the editor does not reflow the cards');
  assert.equal(await toggle('alpha').getAttribute('aria-haspopup'), 'dialog');
  const moduleSwitch = '#connection-modal [data-kind="password"] .module-agent-toggle';
  await dragSwitch(moduleSwitch, 0, 1);
  assert.equal(await editor.locator('[data-kind="password"] [data-module-visibility]').innerText(), 'AGENT VISIBLE');
  await dragSwitch(moduleSwitch, 1, 0);
  assert.equal(await editor.locator('[data-kind="password"] [data-module-visibility]').innerText(), 'AGENT HIDDEN');
  await page.locator(moduleSwitch).press('Space');
  assert.equal(await editor.locator('[data-kind="password"] [data-module-visibility]').innerText(), 'AGENT VISIBLE');
  await page.locator(moduleSwitch).press('Enter');
  assert.equal(await editor.locator('[data-kind="password"] [data-module-visibility]').innerText(), 'AGENT HIDDEN');
  stateMeasurements.push(await auditControlStates(page));
  geometryMeasurements.push(await auditControlGeometry(page));
  await page.locator('#save-connection-button').focus(); await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(() => document.activeElement.matches('#connection-modal .modal-header [data-close-modal]')), true, 'Tab stays within the dialog');
  await page.locator('#connection-name').fill('Edited synthetic service');
  await page.locator('#connection-description').fill('Keep this unsaved value');
  await page.evaluate(async () => { fixture.state.connections[1].name = 'Refreshed server'; await refresh(); });
  assert.equal(await page.locator('#connection-description').inputValue(), 'Keep this unsaved value');
  await page.evaluate(() => fixture.failDraft = true);
  await page.locator('#connection-modal .modal-header [data-close-modal]').click();
  assert.equal(await editor.isVisible(), true, 'A failed draft write keeps the dialog open');
  assert.equal(await page.locator('#connection-description').inputValue(), 'Keep this unsaved value');
  await page.evaluate(() => fixture.failDraft = false);
  await page.locator('#connection-modal .modal-header [data-close-modal]').click();
  await editor.waitFor({ state: 'hidden' });
  assert.equal(await page.evaluate(() => fixture.drafts[0].input.name), 'Edited synthetic service');
  assert.equal(await page.evaluate(() => document.activeElement.dataset.id), 'alpha', 'Closing restores focus even after a list refresh');
  await toggle('alpha').click();
  assert.equal(await page.locator('#connection-name').inputValue(), 'Edited synthetic service');
  await page.locator('#connection-folder').fill('Unsaved folder');
  const itemSwitch = '.switch:has(#connection-enabled)';
  await dragSwitch(itemSwitch, 1, 0);
  assert.equal(await page.locator('#connection-enabled').isChecked(), false);
  await page.locator('#connection-enabled').press('Space');
  assert.equal(await page.locator('#connection-enabled').isChecked(), true);
  await page.locator('#connection-enabled-label').click();
  assert.equal(await page.locator('#connection-enabled').isChecked(), false);
  await page.locator('[data-generate-password]').click();
  await page.waitForFunction(() => document.querySelector('#generator-result').value.length === 24);
  await page.locator('#generator-use').click();
  assert.equal((await page.locator('[data-kind="password"] [data-secret-value]').inputValue()).length, 24);
  await page.locator('#add-module-button').click(); await page.keyboard.press('Escape');
  assert.equal(await page.locator('#module-menu').isHidden(), true);
  assert.equal(await editor.isVisible(), true);
  await page.locator('#add-module-button').click(); await page.locator('[data-add-module="username"]').click();
  assert.equal(await page.locator('[data-kind="username"]').count(), 1);
  stateMeasurements.push(await auditControlStates(page));
  geometryMeasurements.push(await auditControlGeometry(page));
  await page.mouse.move(0, 0); await page.screenshot({ path: path.join(artifacts, 'item-dialog.png') });
  assert.equal(await editor.evaluate(el => el.scrollWidth > el.clientWidth), false);
  await page.locator('#save-connection-button').click(); await editor.waitFor({ state: 'hidden' });
  assert.equal(await row('alpha').locator('.connection-name').innerText(), 'Edited synthetic service');
  assert.equal(await page.evaluate(() => fixture.drafts.some(d => d.input.id === 'alpha')), false);
  assert.equal(await page.evaluate(() => fixture.saved[0].secrets.password.length), 24);
  assert.equal(await page.evaluate(() => fixture.saved[0].enabled), false);
  assert.equal(await page.evaluate(() => fixture.saved[0].favorite), true, 'Saving preserves existing favorite metadata');
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await toggle('alpha').click(); await page.waitForFunction(() => document.activeElement.id === 'connection-name');
  assert.equal(await editor.locator('.modal-card').evaluate(el => el.getAnimations().length), 0);
  await page.locator('#connection-name').fill('Draft across dialog close');
  await page.locator('#connection-name').press('Escape'); await editor.waitFor({ state: 'hidden' });
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  await toggle('alpha').click();
  assert.equal(await page.locator('#connection-name').inputValue(), 'Draft across dialog close');
  await editor.click({ position: { x: 2, y: 100 } }); await editor.waitFor({ state: 'hidden' });
  assert.equal(await page.evaluate(() => fixture.drafts.find(d => d.input.id === 'alpha').input.name), 'Draft across dialog close');
  await toggle('alpha').click();
  await page.evaluate(async () => { fixture.state.connections = fixture.state.connections.filter(item => item.id !== 'alpha'); await refresh(); });
  await row('alpha').waitFor({ state: 'detached' });
  assert.equal(await editor.count(), 1, 'Removing an edited item preserves the dialog DOM');
  assert.equal(await editor.isHidden(), true);
  await page.locator('#add-connection-button').click();
  assert.equal(await editor.getAttribute('role'), 'dialog');
  await page.locator('[data-item-template="login"]').click(); await page.locator('[data-generate-password]').click();
  await page.locator('#generator-use').click();
  assert.equal(await page.locator('#generator-modal').isHidden(), true, 'Nested dialogs stay above the item editor');
  assert.deepEqual(errors, []);
  await fs.writeFile(path.join(artifacts, 'measurements.json'), JSON.stringify(headerMeasurements, null, 2));
  await fs.writeFile(path.join(artifacts, 'control-geometry.json'), JSON.stringify(geometryMeasurements, null, 2));
  await fs.writeFile(path.join(artifacts, 'control-states.json'), JSON.stringify(stateMeasurements, null, 2));
  console.log(JSON.stringify({ ok: true, checks: ['shared well colours, depths and row heights in both themes', 'neutral inactive icons and glow-only hover', 'draggable theme, sound, language, navigation and add/draft controls', 'settings and module switches commit once and recover from failures', 'PIN drag preserves confirmation and cancellation', 'appearance drag preferences survive reload', 'three-page draggable filter strips with snapping and cancellation', 'modal editor, reduced motion and preserved card layout', 'draft recovery after write failures', 'pointer and keyboard sorting with filtered slots', 'drag cancellation, edge scrolling and save failure', 'refresh preserves edits', 'modal keyboard focus and restoration', 'generator and module menu', 'save, navigation and deletion', 'new-item dialog restoration'], artifacts }, null, 2));
} finally { await browser.close(); server.close(); }
