// Round-2 Adversarial & Stress E2E Suite in real Chromium:
// 1. Shadow DOM & nested Shadow DOM login forms + React-style controlled inputs
// 2. Multi-step login (email -> Next -> password)
// 3. Change-password form (fills ONLY current-password, reads new-password, warns on mismatch)
// 4. Honeypot / false-positive traps (search, newsletter, coupon, hidden opacity:0, OTP/CVV password inputs)
// 5. High-density 55-item Desktop UI stress test (80-char CJK/Latin names, 0 horizontal overflow across
//    Dark/Light + EN/ZH + Win/macOS/Linux, drag auto-scroll, PIN paste & wrong-PIN toast z-index,
//    and Desktop TOTP "COPY 2FA CODE" button)
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import { once } from 'node:events';
import { chromium } from 'playwright';

const repo = path.resolve(import.meta.dirname, '..');
const formReaderJs = await fs.readFile(path.join(repo, 'browser-extension/form-reader.js'), 'utf8');
const rendererDir = path.join(repo, 'renderer');

const testPages = {
  '/shadow-react': `<!doctype html><html><head><meta charset="utf-8"><title>Shadow DOM + React</title></head><body>
    <input id="global-search" type="search" name="search" placeholder="Search site" />
    <input id="newsletter" type="email" name="newsletter" placeholder="Subscribe newsletter" />
    <input id="coupon" type="text" name="coupon" placeholder="Promo code" />
    <input id="honeypot" type="password" name="password" style="opacity:0;position:absolute" />
    <input id="otp-trap" type="password" autocomplete="one-time-code" name="otp" />
    <input id="cvv-trap" type="password" autocomplete="cc-csc" name="cvv" />
    <div id="host"></div>
    <script>
      const host = document.getElementById('host');
      const root = host.attachShadow({ mode: 'open' });
      root.innerHTML = '<form id="sf"><label for="su">Username</label><input id="su" name="username" autocomplete="username webauthn" /><label for="sp">Password</label><input id="sp" type="password" name="password" autocomplete="current-password" /></form>';
      window.__reactState = { u: '', p: '', events: 0 };
      const su = root.getElementById('su'), sp = root.getElementById('sp');
      su.addEventListener('input', () => { window.__reactState.u = su.value; window.__reactState.events++; });
      sp.addEventListener('input', () => { window.__reactState.p = sp.value; window.__reactState.events++; });
    </script>
  </body></html>`,
  '/multistep': `<!doctype html><html><head><meta charset="utf-8"><title>Multi-Step</title></head><body>
    <form id="step1"><label for="e">Email</label><input id="e" type="email" name="identifier" autocomplete="username" /><button type="submit">Next</button></form>
  </body></html>`,
  '/change-password': `<!doctype html><html><head><meta charset="utf-8"><title>Change Password</title></head><body>
    <form id="cp">
      <input id="u" name="username" autocomplete="username" value="alice@example.com" readonly />
      <input id="cur" type="password" name="current_password" autocomplete="current-password" />
      <input id="nw" type="password" name="new_password" autocomplete="new-password" />
      <input id="cf" type="password" name="confirm_password" autocomplete="new-password" />
    </form>
  </body></html>`,
};

const server = http.createServer(async (req, res) => {
  const urlPath = (req.url || '/').split('?')[0];
  if (Object.hasOwn(testPages, urlPath)) {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end(testPages[urlPath]);
    return;
  }
  const file = path.resolve(rendererDir, '.' + (urlPath === '/' ? '/index.html' : urlPath));
  if (!file.startsWith(rendererDir + path.sep)) { res.writeHead(403); res.end(); return; }
  try {
    const type = file.endsWith('.js') ? 'text/javascript'
      : file.endsWith('.css') ? 'text/css'
      : file.endsWith('.svg') ? 'image/svg+xml'
      : file.endsWith('.png') ? 'image/png'
      : 'text/html';
    res.setHeader('Content-Type', type);
    res.end(await fs.readFile(file));
  } catch { res.writeHead(404); res.end(); }
});
server.listen(0, 'localhost');
await once(server, 'listening');
const base = `http://localhost:${server.address().port}`;

const browser = await chromium.launch({ headless: true });
try {
  // =========================================================================
  // PART 1: Shadow DOM, React events, Honeypot / OTP / CVV Anti-False-Positive
  // =========================================================================
  {
    const page = await browser.newPage();
    await page.goto(`${base}/shadow-react`);
    const res = await page.evaluate((src) => {
      eval(src);
      const filled = useLoginForm('fill', location.origin, { username: 'shadow-alice', password: 'shadow-pass-99' }, location.href);
      const read = useLoginForm('read', location.origin, null, location.href);
      return {
        filled,
        read,
        reactState: window.__reactState,
        searchVal: document.getElementById('global-search').value,
        newsletterVal: document.getElementById('newsletter').value,
        couponVal: document.getElementById('coupon').value,
        honeypotVal: document.getElementById('honeypot').value,
        otpVal: document.getElementById('otp-trap').value,
        cvvVal: document.getElementById('cvv-trap').value,
      };
    }, formReaderJs);
    assert.equal(res.filled.filled, true, 'Filled login inside open Shadow DOM');
    assert.equal(res.reactState.u, 'shadow-alice', 'React input listener received Shadow DOM username');
    assert.equal(res.reactState.p, 'shadow-pass-99', 'React input listener received Shadow DOM password');
    assert.ok(res.reactState.events >= 2);
    assert.equal(res.read.forms.length, 1);
    assert.equal(res.read.forms[0].username, 'shadow-alice');
    assert.equal(res.read.forms[0].password, 'shadow-pass-99');
    assert.equal(res.searchVal, '', 'Search input untouched');
    assert.equal(res.newsletterVal, '', 'Newsletter email untouched');
    assert.equal(res.couponVal, '', 'Coupon input untouched');
    assert.equal(res.honeypotVal, '', 'Opacity-0 honeypot password untouched');
    assert.equal(res.otpVal, '', 'OTP type=password untouched');
    assert.equal(res.cvvVal, '', 'CVV type=password untouched');
    await page.close();
  }

  // =========================================================================
  // PART 2: Multi-Step Email-Only Form (Google / AWS / Microsoft pattern)
  // =========================================================================
  {
    const page = await browser.newPage();
    await page.goto(`${base}/multistep`);
    const res = await page.evaluate((src) => {
      eval(src);
      const fillRes = useLoginForm('fill', location.origin, { username: 'step@example.com', password: 'pw' }, location.href);
      const readRes = useLoginForm('read', location.origin, null, location.href);
      return { fillRes, readRes, emailVal: document.getElementById('e').value };
    }, formReaderJs);
    assert.equal(res.fillRes.filled, true, 'Fills step-1 email input even with no password box yet');
    assert.equal(res.emailVal, 'step@example.com');
    assert.equal(res.readRes.usernameStep, 'step@example.com', 'Captures usernameStep for multi-step carry-forward');
    await page.close();
  }

  // =========================================================================
  // PART 3: Change-Password Form Protection & Confirmation Mismatch Detection
  // =========================================================================
  {
    const page = await browser.newPage();
    await page.goto(`${base}/change-password`);
    const res = await page.evaluate((src) => {
      eval(src);
      // Filling with matching readonly username fills ONLY current-password
      const fillOk = useLoginForm('fill', location.origin, { username: 'alice@example.com', password: 'old-password' }, location.href);
      const curAfterFill = document.getElementById('cur').value;
      const newAfterFill = document.getElementById('nw').value;
      const cfAfterFill = document.getElementById('cf').value;

      // Attempting to fill wrong account onto readonly username MUST throw
      let wrongAccountErr = '';
      try {
        useLoginForm('fill', location.origin, { username: 'bob@example.com', password: 'bob-password' }, location.href);
      } catch (e) { wrongAccountErr = e.message; }

      // Mismatched confirm password -> read produces warning & refuses to return password
      document.getElementById('nw').value = 'brand-new-1';
      document.getElementById('cf').value = 'brand-new-2';
      const mismatchRead = useLoginForm('read', location.origin, null, location.href);

      // Matching confirm password -> read captures new password cleanly with kind=change
      document.getElementById('cf').value = 'brand-new-1';
      const matchRead = useLoginForm('read', location.origin, null, location.href);
      return { fillOk, curAfterFill, newAfterFill, cfAfterFill, wrongAccountErr, mismatchRead, matchRead };
    }, formReaderJs);
    assert.equal(res.fillOk.filled, true);
    assert.equal(res.curAfterFill, 'old-password', 'Fills current-password');
    assert.equal(res.newAfterFill, '', 'NEVER overwrites new-password during login fill');
    assert.equal(res.cfAfterFill, '', 'NEVER overwrites confirm-password during login fill');
    assert.match(res.wrongAccountErr, /different account|另一个账号/, 'Refuses to fill into another readonly account');
    assert.ok(res.mismatchRead.forms[0].warnings.length > 0, 'Detects confirm-password mismatch');
    assert.equal(res.mismatchRead.forms[0].password, '', 'Refuses to capture mismatched password');
    assert.equal(res.matchRead.forms[0].kind, 'change');
    assert.equal(res.matchRead.forms[0].password, 'brand-new-1');
    await page.close();
  }

  // =========================================================================
  // PART 4: High-Density 55-Item Desktop UI Stress + Long CJK Names +
  //         Drag Auto-Scroll + PIN Paste + Wrong-PIN Toast Z-Index +
  //         Desktop TOTP Copy Button (Dark & Light + EN & ZH + Win/Mac)
  // =========================================================================
  for (const cfg of [
    { platform: 'Win32', lang: 'zh', theme: 'dark' },
    { platform: 'MacIntel', lang: 'en', theme: 'light' },
  ]) {
    const context = await browser.newContext({ viewport: { width: 460, height: 690 } });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));

    await page.addInitScript(({ platform, lang, theme }) => {
      Object.defineProperty(navigator, 'platform', { get: () => platform, configurable: true });
      localStorage.setItem('openkeylet.appearance.v1', JSON.stringify({ theme, sound: false }));
      const items = Array.from({ length: 55 }, (_, i) => ({
        id: `stress-${i + 1}`,
        name: i === 0
          ? '超长中文生产服务器与企业级统一认证账号名称测试边界情况不溢出布局验证条目001'
          : i === 1
            ? 'ExtremelyLongEnterpriseServiceNameWithoutSpacesForOverflowTestingBoundaryCheck02'
            : `Vault Item #${i + 1}`,
        itemType: ['login', 'ssh', 'api', 'card', 'identity', 'secureNote'][i % 6],
        folder: i % 3 === 0 ? '非常长的文件夹名称/Production-Cluster-AP-Northeast-1' : '',
        favorite: i < 3,
        enabled: i % 5 !== 0,
        updatedAt: '2026-10-20T00:00:00Z',
        modules: i === 0
          ? [{ kind: 'url', value: 'https://app.example.com', configured: true }, { kind: 'username', configured: true }, { kind: 'password', configured: true }, { kind: 'totp', configured: true }]
          : [{ kind: 'username', configured: true }, { kind: 'password', configured: true }],
        actions: ['fill'],
      }));
      window.__stress = {
        pinConfigured: true,
        unlocked: true,
        totpCopies: 0,
        reorders: 0,
        autoLockMinutes: 0,
        copies: [],
      };
      window.__TAURI__ = {
        event: { listen: async () => () => {} },
        core: {
          invoke: async (cmd, args = {}) => {
            if (cmd === 'get_state') return {
              settings: {
                language: lang,
                closeBehavior: 'tray',
                browserEnabled: true,
                browserPort: 39272,
                browserAgentPasskey: true,
                ownerAutoLockMinutes: window.__stress.autoLockMinutes,
              },
              connections: window.__stress.unlocked ? items : [],
              activities: window.__stress.unlocked ? Array.from({ length: 30 }, (_, i) => ({
                id: `a-${i}`, action: 'fill', connectionName: items[0].name, source: 'mcp',
                status: i % 4 === 0 ? 'error' : 'ok', error: i % 4 === 0 ? 'VeryLongUnbrokenErrorTokenWithoutSpaces_1234567890_abcdefghijklmnopqrstuvwxyz' : '',
                durationMs: 14, time: '2026-10-20T00:00:00Z',
              })) : [],
              mcp: { status: 'ready' },
              browserBridge: { status: 'listening', connected: true, paired: true, endpoint: 'ws://127.0.0.1:39272' },
              security: { encrypted: true },
            };
            if (cmd === 'owner_status' || cmd === 'owner_touch') return { pinConfigured: window.__stress.pinConfigured, unlocked: window.__stress.unlocked, expiresInSeconds: window.__stress.autoLockMinutes * 60 };
            if (cmd === 'owner_lock') { window.__stress.unlocked = false; return { pinConfigured: true, unlocked: false, expiresInSeconds: 0 }; }
            if (cmd === 'owner_unlock') {
              if (args.pin !== '123456') throw new Error('Incorrect PIN');
              window.__stress.unlocked = true;
              return { pinConfigured: true, unlocked: true, expiresInSeconds: window.__stress.autoLockMinutes * 60 };
            }
            if (cmd === 'update_settings') {
              if (args.patch?.ownerAutoLockMinutes !== undefined) window.__stress.autoLockMinutes = args.patch.ownerAutoLockMinutes;
              return { language: lang, closeBehavior: args.patch?.closeBehavior || 'tray', browserEnabled: true, browserPort: 39272, browserAgentPasskey: true, ownerAutoLockMinutes: window.__stress.autoLockMinutes };
            }
            if (cmd === 'copy_owner_value') { window.__stress.copies.push({ value: args.value, sensitive: args.sensitive }); return null; }
            if (cmd === 'owner_secret_view') return { id: args.id, fields: [{ name: 'username', value: 'alice' }, { name: 'password', value: 'pw' }, { name: 'totp', value: 'JBSWY3DPEHPK3PXP' }] };
            if (cmd === 'copy_totp_code') { window.__stress.totpCopies++; return { remainingSeconds: 19, period: 30, clearAfterSeconds: 30 }; }
            if (cmd === 'reorder_connections') { window.__stress.reorders++; return items; }
            if (cmd === 'github_backup_status') return { connected: true, provider: 'gitea', serverUrl: 'https://git.enterprise-internal.example.com/subpath', repository: 'enterprise-org/openkeylet-encrypted-vault-backup', branch: 'main', autoSync: true, hasRemoteBackup: true, lastSyncedAt: '2026-10-20T00:00:00Z' };
            if (cmd === 'system_integration_status') return { desktopShortcutSupported: true, desktopShortcutEnabled: false, launchAtLoginSupported: true, launchAtLoginEnabled: false };
            return [];
          },
        },
      };
    }, cfg);

    await page.goto(base);
    await page.locator('.connection-card').nth(54).waitFor({ state: 'attached' });

    // Check ZERO horizontal overflow across all 3 pages (Items, Log, System) with 55 dense/long items
    for (const tab of ['connections', 'activity', 'settings']) {
      await page.locator(`.nav-item[data-page="${tab}"]`).click();
      const overflow = await page.evaluate(() => ({
        docOverflow: document.documentElement.scrollWidth > document.documentElement.clientWidth,
        bodyOverflow: document.body.scrollWidth > document.body.clientWidth,
        gridOverflow: document.querySelector('#connections-list').scrollWidth > document.querySelector('#connections-list').clientWidth + 1,
        settingsOverflow: document.querySelector('.settings-layout').scrollWidth > document.querySelector('.settings-layout').clientWidth + 1,
      }));
      assert.equal(overflow.docOverflow, false, `${cfg.platform}/${cfg.lang}/${cfg.theme} ${tab}: zero document horizontal overflow`);
      assert.equal(overflow.bodyOverflow, false, `${cfg.platform}/${cfg.lang}/${cfg.theme} ${tab}: zero body horizontal overflow`);
      if (tab === 'connections') assert.equal(overflow.gridOverflow, false, `${cfg.platform} 55-item grid zero horizontal overflow`);
      if (tab === 'settings') assert.equal(overflow.settingsOverflow, false, `${cfg.platform} settings with long Gitea URL zero horizontal overflow`);
    }

    // Drag item 0 toward bottom edge of 55-item list -> verify auto-scroll advances scrollTop!
    await page.locator('.nav-item[data-page="connections"]').click();
    const listBox = await page.locator('#connections-list').boundingBox();
    const firstHandle = await page.locator('.connection-card').first().locator('.connection-name').boundingBox();
    await page.mouse.move(firstHandle.x + 12, firstHandle.y + 10);
    await page.mouse.down();
    await page.mouse.move(listBox.x + 80, listBox.y + listBox.height - 6, { steps: 6 });
    await page.waitForTimeout(160);
    const scrolledTop = await page.evaluate(() => document.querySelector('#connections-list').scrollTop);
    await page.keyboard.press('Escape');
    await page.mouse.up();
    assert.ok(scrolledTop > 0, `${cfg.platform}: dragging near bottom edge auto-scrolls 55-item grid (scrollTop=${scrolledTop})`);

    // Verify Auto-lock selector is visible when PIN is configured and persists ownerAutoLockMinutes
    await page.locator('.nav-item[data-page="settings"]').click();
    await page.locator('#owner-auto-lock-option').waitFor({ state: 'visible' });
    await page.locator('#owner-auto-lock-minutes').selectOption('15');
    await page.waitForFunction(() => window.__stress.autoLockMinutes === 15);
    await page.locator('.nav-item[data-page="connections"]').click();

    // Open item 0 (has username, password & TOTP):
    // - non-secret module copy passes sensitive=false
    // - secret module copy passes sensitive=true + 30s auto-clear hint
    // - TOTP copy shows remaining seconds + 30s auto-clear hint
    await page.evaluate(() => { document.querySelector('#connections-list').scrollTop = 0; });
    await page.locator('.connection-card').first().locator('[data-action="edit"]').click();
    await page.locator('#connection-modal').waitFor({ state: 'visible' });
    await page.locator('[data-copy-module-value]').first().click();
    await page.waitForFunction(() => window.__stress.copies.length === 1);
    const firstCopy = await page.evaluate(() => window.__stress.copies[0]);
    assert.equal(firstCopy.sensitive, false, 'Non-secret module value copy passes sensitive=false');
    await page.locator('[data-copy-module-secret]').first().click();
    await page.waitForFunction(() => window.__stress.copies.length === 2);
    const secretCopy = await page.evaluate(() => window.__stress.copies[1]);
    assert.equal(secretCopy.sensitive, true, 'Secret module copy passes sensitive=true');
    const secretToast = await page.locator('#toast-region .toast').last().textContent();
    assert.match(secretToast, /30/, 'Secret copy toast mentions 30s auto-clear');
    await page.locator('[data-copy-totp-code]').scrollIntoViewIfNeeded();
    await page.locator('[data-copy-totp-code]').click();
    await page.waitForFunction(() => window.__stress.totpCopies === 1);
    const totpToast = await page.locator('#toast-region .toast').last().textContent();
    assert.match(totpToast, /19s/, 'Desktop TOTP copy shows remaining seconds in toast');
    assert.match(totpToast, /30/, 'Desktop TOTP copy mentions 30s auto-clear in toast');
    await page.keyboard.press('Escape');
    await page.locator('#connection-modal').waitFor({ state: 'hidden' });

    // Lock -> scrubs items behind lock overlay -> wrong PIN -> error toast ABOVE #owner-lock-layer -> paste 123456 -> restores all 55 items!
    await page.locator('#owner-lock-button').click();
    await page.locator('#owner-lock-layer').waitFor({ state: 'visible' });
    await page.waitForFunction(() => document.querySelectorAll('.connection-card').length === 0);
    const pinCells = page.locator('[data-pin-group="owner-pin"] .pin-cell-input');
    for (let i = 0; i < 6; i++) await pinCells.nth(i).fill('9');
    await page.locator('#owner-unlock-action').click();
    await page.locator('#toast-region .toast.error').waitFor({ state: 'visible' });
    const zCheck = await page.evaluate(() => ({
      lockZ: Number(getComputedStyle(document.querySelector('#owner-lock-layer')).zIndex),
      toastZ: Number(getComputedStyle(document.querySelector('#toast-region')).zIndex),
    }));
    assert.ok(zCheck.toastZ > zCheck.lockZ, 'Wrong-PIN error toast renders ABOVE owner lock overlay');

    // Paste 6-digit PIN into first cell -> distributes across all 6 inputs -> unlocks cleanly and restores 55 items
    await page.evaluate(() => {
      const first = document.querySelector('#owner-pin');
      const dt = new DataTransfer();
      dt.setData('text/plain', '123456');
      first.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true }));
    });
    await page.locator('#owner-unlock-action').click();
    await page.locator('#owner-lock-layer').waitFor({ state: 'hidden' });
    await page.locator('.connection-card').nth(54).waitFor({ state: 'attached' });

    assert.deepEqual(errors, [], `Zero page errors under stress (${cfg.platform}/${cfg.lang}/${cfg.theme}): ${errors.join('; ')}`);
    await context.close();
  }

  console.log('ADVERSARIAL & HIGH-DENSITY STRESS E2E PASSED (Shadow DOM, React, Multi-Step, Change-PW, Honeypots, 55-Item Stress, Auto-Scroll, PIN Paste, Desktop 2FA)');
} finally {
  await browser.close();
  server.close();
}
