/* Settings view, MCP agent client registry, Chrome profiles, Browser Bridge, and system toggles. */
import { $, $$, edgeDockSupported, escapeHtml, isMacOS, normalizeSearch } from '../core/dom.js';
import { store, hooks } from '../core/store.js';
import { api } from '../core/api.js';
import { cleanError, publicMessage, toast, confirmDestructiveAction } from '../core/feedback.js';
import { localized } from '../i18n/index.js';
import { getAutoCheckConfig, scheduleAutoCheck } from './connections.js';
import { renderOwnerLock, refreshOwnerLock } from './owner-lock.js';

const BROWSER_EXTENSIONS_URL = 'chrome://extensions/';
const agentLabels = {
  notDetected: 'NOT FOUND',
  available: 'READY',
  registered: 'CONNECTED',
  stale: 'NEEDS REPAIR',
  conflict: 'CONFLICT',
  error: 'ERROR',
};

function visibleCardText(card) {
  const hiddenSelectors = [];
  if (isMacOS) hiddenSelectors.push('#desktop-shortcut-option');
  if (!edgeDockSupported) hiddenSelectors.push('#edge-dock-option');
  if (!hiddenSelectors.length) return card.textContent || '';
  const skipSelector = hiddenSelectors.join(', ');
  const parts = [];
  const walker = document.createTreeWalker(card, NodeFilter.SHOW_TEXT);
  let node = walker.nextNode();
  while (node) {
    if (!node.parentElement?.closest?.(skipSelector)) {
      parts.push(node.nodeValue || '');
    }
    node = walker.nextNode();
  }
  return parts.join(' ');
}

export function applySettingsSearch() {
  const query = normalizeSearch(store.pageSearch.settings);
  let visible = 0;
  for (const card of $$('.settings-card')) {
    const mod = card.dataset.module || '';
    const matchesSection = store.currentSettingsFilter === 'all'
      || mod.startsWith(`${store.currentSettingsFilter} /`)
      || (store.currentSettingsFilter === 'APP' && mod.startsWith('LANG /'));
    const matches = matchesSection && (!query || normalizeSearch(`${mod} ${visibleCardText(card)}`).includes(query));
    card.classList.toggle('search-hidden', !matches);
    if (matches) visible += 1;
  }
  $('#settings-search-empty').classList.toggle('hidden', visible > 0);
}

export function renderChromeProfiles() {
  const row = $('#chrome-profile-row');
  const select = $('#chrome-profile-select');
  if (!row || !select) return;
  if (!Array.isArray(store.chromeProfiles) || store.chromeProfiles.length < 2) {
    row.classList.add('hidden');
    select.replaceChildren();
    return;
  }
  const previous = select.value;
  select.replaceChildren(...store.chromeProfiles.map((profile) => {
    const title = profile.name || profile.directory;
    const sub = profile.account && profile.account !== title ? profile.account : '';
    const label = sub ? `${title} (${sub})` : title;
    const option = new Option(label, profile.directory);
    option.dataset.title = title;
    if (sub) option.dataset.sub = sub;
    return option;
  }));
  if (previous && store.chromeProfiles.some((profile) => profile.directory === previous)) {
    select.value = previous;
  }
  row.classList.remove('hidden');
}

export async function loadChromeProfiles() {
  try {
    const profiles = await api.chromeProfiles();
    store.chromeProfiles = Array.isArray(profiles) ? profiles : [];
  } catch {
    store.chromeProfiles = [];
  }
  renderChromeProfiles();
}

function agentDetail(client) {
  const details = {
    notDetected: localized('未安装或未发现', 'Not installed'),
    available: localized('可连接', 'Ready to connect'),
    registered: localized('已连接', 'Connected'),
    stale: localized('OpenKeylet 连接或全局规则需要修复', 'OpenKeylet setup needs repair'),
    conflict: localized('配置冲突', 'Config conflict'),
    error: localized('检测失败', 'Detection failed'),
  };
  return details[client.state] || publicMessage(client.message, localized('状态已更新', 'Status updated'));
}

export function renderAgents() {
  const container = $('#agent-client-list');
  container.innerHTML = store.agentClients.length
    ? store.agentClients.map((client) => `<div class="agent-client-row ${client.canRegister ? '' : 'is-disabled'}" data-agent-state="${escapeHtml(client.state)}" data-client-id="${escapeHtml(client.clientId)}" tabindex="-1"><span class="agent-client-copy"><strong>${escapeHtml(client.displayName)}</strong><span>${escapeHtml(agentDetail(client))}</span></span><div class="agent-row-controls"><span class="agent-state ${escapeHtml(client.state)}">${escapeHtml(agentLabels[client.state] || client.state)}</span><div class="agent-row-actions">${client.canRegister ? `<button type="button" class="agent-row-action primary" data-agent-action="connect" data-client-id="${escapeHtml(client.clientId)}">CONNECT</button>` : ''}${client.canRepair ? `<button type="button" class="agent-row-action primary" data-agent-action="repair" data-client-id="${escapeHtml(client.clientId)}">REPAIR</button>` : ''}${client.canRemove ? `<button type="button" class="agent-row-action" data-agent-action="remove" data-client-id="${escapeHtml(client.clientId)}">REMOVE</button>` : ''}</div></div></div>`).join('')
    : `<div class="agent-scan-placeholder">${localized('没有检测到支持的 Agent', 'NO SUPPORTED AGENT DETECTED')}</div>`;
  applySettingsSearch();
}

export async function scanAgents(showToast = false) {
  try {
    store.agentClients = await api.agents();
    renderAgents();
    if (store.state) hooks.renderMetrics?.();
    if (showToast) toast(localized('Agent 扫描完成', 'Agent scan complete'));
  } catch (error) {
    toast(cleanError(error), 'error');
  }
}

export function renderSettings() {
  const state = store.state;
  store.githubBackup?.render();
  store.appUpdater?.render();
  $('#mcp-endpoint').textContent = `${state.mcp.stdioCommand} mcp stdio`;
  const mcpFault = state.mcp.status === 'error';
  const mcpStrip = $('#mcp-status-strip');
  mcpStrip.className = `status-strip ${mcpFault ? 'error' : ''}`;
  mcpStrip.innerHTML = `<span class="status-dot"></span><span class="status-key">${mcpFault ? 'FAULT' : 'READY'}</span><span>${mcpFault ? escapeHtml(publicMessage(state.mcp.error)) : localized('Agent 使用时自动启动 stdio，无需常驻服务。', 'stdio starts on demand. No background service.')}</span>`;
  $('#agent-restart-notice').classList.toggle('hidden', !store.agentRestartRequired);
  $('#desktop-shortcut-enabled').checked = Boolean(store.systemIntegrationState.desktopShortcut);
  $('#launch-at-login-enabled').checked = Boolean(store.systemIntegrationState.launchAtLogin);
  $('#pin-enabled').checked = store.ownerLockState.pinConfigured || store.ownerPinSetupRequested;
  const pinHelp = $('.pin-option small');
  if (pinHelp) {
    pinHelp.textContent = localized('防他人在本机查看明文或管理条目；关闭将移除当前 PIN', 'Locks desktop viewing and management against others on this device. Turning off removes the PIN.');
  }
  $('#owner-auto-lock-option').classList.toggle('hidden', !store.ownerLockState.pinConfigured);
  const autoLockMinutes = Number(state.settings.ownerAutoLockMinutes || 0);
  $('#owner-auto-lock-minutes').value = [0, 5, 15, 30, 60].includes(autoLockMinutes) ? String(autoLockMinutes) : '0';
  const autoCheck = getAutoCheckConfig();
  if ($('#auto-check-enabled')) $('#auto-check-enabled').checked = autoCheck.enabled;
  if ($('#auto-check-interval-option')) $('#auto-check-interval-option').classList.toggle('hidden', !autoCheck.enabled);
  if ($('#auto-check-interval-minutes')) $('#auto-check-interval-minutes').value = String(autoCheck.minutes);
  scheduleAutoCheck();
  $('#close-behavior').value = state.settings.closeBehavior === 'exit' ? 'exit' : 'tray';
  $('#browser-enabled').checked = state.settings.browserEnabled;
  $('#browser-port').value = state.settings.browserPort;
  $('#browser-agent-passkey-enabled').checked = state.settings.browserAgentPasskey === true;

  const bridge = state.browserBridge;
  const online = ['listening', 'delegated'].includes(bridge.status);
  const connectedCount = Number(bridge.connectedCount || (bridge.connected ? 1 : 0));
  const pairingActive = Boolean(bridge.pairingActive);
  const strip = $('#browser-status-strip');
  strip.className = `status-strip ${bridge.status === 'error' ? 'error' : online ? '' : 'offline'}`;
  const statusKey = bridge.status === 'error'
    ? 'FAULT'
    : !online
      ? 'OFF'
      : bridge.connected
        ? 'CONNECTED'
        : pairingActive
          ? 'PAIRING'
          : bridge.paired
            ? 'WAITING'
            : 'READY';
  const statusDetail = bridge.status === 'error'
    ? publicMessage(bridge.error)
    : !online
      ? localized('Browser Bridge 已关闭', 'Browser Bridge is off')
      : bridge.connected
        ? connectedCount > 1
          ? localized(`已连接 ${connectedCount} 个 Chrome 账号 · ${bridge.endpoint}`, `${connectedCount} Chrome profiles connected · ${bridge.endpoint}`)
          : pairingActive
            ? localized('已连接 · 自动配对窗口开启中（可继续添加账号）', 'Connected · pairing window open (add more profiles)')
            : bridge.endpoint
        : pairingActive
          ? localized('自动配对窗口已开启（安装扩展后自动连接）', 'Auto-pairing window open (extensions connect automatically)')
          : bridge.endpoint;
  strip.innerHTML = `<span class="status-dot"></span><span class="status-key">${statusKey}</span><span>${escapeHtml(statusDetail)}</span>`;
  $('#test-browser-bridge-button').disabled = !bridge.connected;
  const reloadExtBtn = $('#reload-extension-button');
  if (reloadExtBtn) {
    reloadExtBtn.disabled = !bridge.connected;
    reloadExtBtn.className = bridge.extensionOutdated ? 'button primary' : 'button quiet';
  }
  const versionStrip = $('#browser-version-strip');
  if (versionStrip) {
    const outdated = Boolean(bridge.connected && bridge.extensionOutdated);
    versionStrip.classList.toggle('hidden', !outdated);
    if (outdated) {
      const appVer = bridge.appVersion ? `v${bridge.appVersion}` : '';
      const extVer = bridge.extensionVersion ? `v${bridge.extensionVersion}` : '?';
      versionStrip.innerHTML = `<span class="status-dot"></span><span class="status-key">${localized('版本不同步', 'OUTDATED')}</span><span>${escapeHtml(localized(`主程序 ${appVer} · 插件 ${extVer} — 点击下方「重载插件」或重新拖入新版扩展目录`, `App ${appVer} · Extension ${extVer} — Click Reload extension or drag the updated folder`))}</span>`;
    }
  }
  $('#reset-pairing-button').disabled = !bridge.paired;
  renderChromeProfiles();
  renderAgents();
  applySettingsSearch();
}

export async function saveBrowserSettings() {
  const port = Number($('#browser-port').value);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    toast(localized('本地端口须在 1024–65535 之间', 'Local port must be between 1024 and 65535'), 'error');
    if (store.state) $('#browser-port').value = store.state.settings.browserPort;
    return;
  }
  try {
    store.state.settings = await api.settings({
      browserEnabled: $('#browser-enabled').checked,
      browserPort: port,
      browserAgentPasskey: $('#browser-agent-passkey-enabled').checked,
    });
    toast(localized('Browser Bridge 设置已保存', 'Browser Bridge settings saved'));
    await hooks.refresh?.();
  } catch (error) {
    toast(cleanError(error), 'error');
    await hooks.refresh?.(false);
  }
}

export async function saveDesktopSettings() {
  try {
    store.state.settings = await api.settings({
      closeBehavior: $('#close-behavior').value,
      ownerAutoLockMinutes: Number($('#owner-auto-lock-minutes').value || 0),
      autoCheckEnabled: $('#auto-check-enabled') ? $('#auto-check-enabled').checked : true,
      autoCheckIntervalMinutes: Number($('#auto-check-interval-minutes')?.value || 60),
    });
    renderSettings();
    toast(localized('窗口与偏好设置已保存', 'Window & preference settings saved'));
  } catch (error) {
    toast(cleanError(error), 'error');
    await hooks.refresh?.(false);
  }
}

export async function setSystemIntegration(kind, enabled) {
  const input = kind === 'desktop' ? $('#desktop-shortcut-enabled') : $('#launch-at-login-enabled');
  input.disabled = true;
  try {
    store.systemIntegrationState = kind === 'desktop'
      ? await api.setDesktopShortcut(enabled)
      : await api.setLaunchAtLogin(enabled);
    renderSettings();
    toast(kind === 'desktop'
      ? (enabled ? localized('桌面快捷方式已创建', 'Desktop shortcut created') : localized('桌面快捷方式已移除', 'Desktop shortcut removed'))
      : (enabled ? localized('开机自启动已开启', 'Launch at login enabled') : localized('开机自启动已关闭', 'Launch at login disabled')));
  } catch (error) {
    input.checked = kind === 'desktop'
      ? Boolean(store.systemIntegrationState.desktopShortcut)
      : Boolean(store.systemIntegrationState.launchAtLogin);
    toast(cleanError(error), 'error');
  } finally {
    input.disabled = false;
  }
}

export async function savePinSettings() {
  const toggle = $('#pin-enabled');
  if (toggle.checked) {
    store.ownerPinSetupRequested = true;
    renderOwnerLock();
    return;
  }
  if (!await confirmDestructiveAction({
    title: localized('关闭 PIN 锁？', 'Turn off PIN lock?'),
    message: localized('当前 PIN 将被移除；再次开启时需要设置新 PIN。', 'The current PIN will be removed. You will need to set a new PIN when enabling the lock again.'),
    acceptLabel: localized('关闭并移除', 'TURN OFF'),
    tag: localized('确认移除 PIN', 'CONFIRM PIN REMOVAL'),
  })) {
    toggle.checked = true;
    return;
  }
  toggle.disabled = true;
  try {
    store.ownerLockState = await api.ownerDisablePin();
    store.ownerPinSetupRequested = false;
    renderOwnerLock();
    hooks.renderMetrics?.();
    renderSettings();
    toast(localized('PIN 锁已关闭', 'PIN lock disabled'));
  } catch (error) {
    toast(cleanError(error), 'error');
    await refreshOwnerLock(false);
    renderSettings();
  } finally {
    toggle.disabled = false;
  }
}

export function initSettingsView() {
  $('#save-browser-settings-button').addEventListener('click', saveBrowserSettings);
  $('#browser-enabled').addEventListener('change', saveBrowserSettings);
  $('#browser-agent-passkey-enabled').addEventListener('change', saveBrowserSettings);

  $('#start-pairing-button').addEventListener('click', async (event) => {
    const port = Number($('#browser-port').value);
    if (!Number.isInteger(port) || port < 1024 || port > 65535) {
      toast(localized('本地端口须在 1024–65535 之间', 'Local port must be between 1024 and 65535'), 'error');
      return;
    }
    const button = event.currentTarget;
    button.disabled = true;
    try {
      await api.quickPair(port);
      $('#browser-enabled').checked = true;
      toast(localized('已开启 5 分钟自动配对窗口，支持连续连接多个 Chrome 账号', '5-minute auto-pairing window open. Multiple Chrome profiles can connect automatically.'));
      await hooks.refresh?.(false);
    } catch (error) {
      toast(cleanError(error), 'error');
    } finally {
      button.disabled = false;
    }
  });

  $('#test-browser-bridge-button').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      const info = await api.testBrowserBridge();
      const tabCount = Array.isArray(info?.tabs) ? info.tabs.length : 0;
      const formCount = Array.isArray(info?.loginForms) ? info.loginForms.length : 0;
      const passkeyCount = Array.isArray(info?.pendingPasskeys) ? info.pendingPasskeys.length : 0;
      const activeTarget = info?.origin || localized('当前标签页非网页', 'Active tab is not a web page');
      toast(localized(
        `扩展连接正常 · ${activeTarget}（${tabCount} 个网页标签，${formCount} 个登录表单，${passkeyCount} 个待处理 Passkey）`,
        `Extension connected · ${activeTarget} (${tabCount} web tabs, ${formCount} login forms, ${passkeyCount} pending passkeys)`,
      ));
    } catch (error) {
      toast(cleanError(error), 'error');
    } finally {
      renderSettings();
    }
  });

  if (!isMacOS) $('#desktop-shortcut-enabled').addEventListener('change', (event) => setSystemIntegration('desktop', event.currentTarget.checked));
  $('#launch-at-login-enabled').addEventListener('change', (event) => setSystemIntegration('startup', event.currentTarget.checked));
  $('#pin-enabled').addEventListener('change', savePinSettings);
  $('#close-behavior').addEventListener('change', saveDesktopSettings);
  $('#owner-auto-lock-minutes').addEventListener('change', saveDesktopSettings);
  $('#auto-check-enabled')?.addEventListener('change', saveDesktopSettings);
  $('#auto-check-interval-minutes')?.addEventListener('change', saveDesktopSettings);

  $('#browser-extensions-url').addEventListener('click', (event) => { event.currentTarget.select(); });
  $('#copy-extensions-url-button').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      await api.copyOwnerValue(BROWSER_EXTENSIONS_URL, false);
      $('#browser-extensions-url').select();
      const port = Number($('#browser-port').value);
      let pairingArmed = false;
      if (Number.isInteger(port) && port >= 1024 && port <= 65535) {
        try {
          await api.quickPair(port);
          $('#browser-enabled').checked = true;
          pairingArmed = true;
          await hooks.refresh?.(false);
        } catch {}
      }
      toast(pairingArmed
        ? localized(`已复制 ${BROWSER_EXTENSIONS_URL}，并已开启自动配对窗口`, `Copied ${BROWSER_EXTENSIONS_URL}. Auto-pairing window is open.`)
        : localized(`已复制 ${BROWSER_EXTENSIONS_URL}，请粘贴到 Chrome 地址栏`, `Copied ${BROWSER_EXTENSIONS_URL}. Paste it into Chrome's address bar.`));
    } catch (error) {
      toast(cleanError(error), 'error');
    } finally {
      button.disabled = false;
    }
  });

  $('#quick-pairing-button').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      $('#browser-open-help').hidden = true;
      let copyError = null;
      try {
        await api.copyOwnerValue(BROWSER_EXTENSIONS_URL, false);
        $('#browser-open-help').hidden = false;
      } catch (error) { copyError = error; }
      let pairingError = null;
      try {
        await api.quickPair(Number($('#browser-port').value));
        $('#browser-enabled').checked = true;
      } catch (error) { pairingError = error; }
      let browserError = null;
      const selectedProfile = $('#chrome-profile-select')?.value || null;
      try { await api.openChrome(selectedProfile); } catch (error) { browserError = error; }
      if (copyError) toast(cleanError(copyError), 'error');
      else if (pairingError && browserError) toast(localized('配对失败，且无法打开 Chrome。请检查 Browser Bridge 并手动打开 Chrome。', 'Pairing failed and Chrome could not be opened. Check Browser Bridge and open Chrome manually.'), 'error');
      else if (pairingError) toast(cleanError(pairingError), 'error');
      else if (browserError) toast(localized('地址已复制，请手动打开 Chrome 并粘贴。', 'Address copied. Open Chrome and paste it manually.'), 'error');
      else toast(localized('地址已复制，5 分钟自动配对窗口已开启。', 'Address copied. 5-minute auto-pairing window is open.'));
      await hooks.refresh?.(false);
    } catch (error) {
      toast(cleanError(error), 'error');
    } finally {
      button.disabled = false;
    }
  });

  $('#reload-extension-button')?.addEventListener('click', async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      const count = await api.reloadBrowserExtension();
      window.OpenKeyletAppearance?.play?.('success');
      toast(count > 0
        ? localized(`已通知 ${count} 个浏览器插件热重载`, `Reload signal sent to ${count} browser extension(s)`)
        : localized('当前没有已连接的浏览器插件', 'No connected browser extensions to reload'));
      setTimeout(() => { void hooks.refresh?.(false); }, 900);
    } catch (error) {
      toast(cleanError(error), 'error');
    } finally {
      button.disabled = !store.state?.browserBridge?.connected;
    }
  });

  $('#reset-pairing-button').addEventListener('click', async () => {
    if (!await confirmDestructiveAction({
      title: localized('重置浏览器配对？', 'Reset browser pairing?'),
      message: localized('所有已配对扩展会立即失效，需要重新配对才能继续使用。', 'Every paired extension will be revoked immediately and must be paired again.'),
      acceptLabel: localized('重置', 'RESET'),
      tag: localized('确认重置配对', 'CONFIRM PAIRING RESET'),
    })) return;
    try {
      await api.resetPair();
      toast(localized('配对已重置', 'Pairing reset'));
      await hooks.refresh?.();
    } catch (error) {
      toast(cleanError(error), 'error');
    }
  });

  $('#open-extension-button').addEventListener('click', () => api.extensionFolder().catch((error) => toast(cleanError(error), 'error')));
  $('#open-data-button').addEventListener('click', () => api.dataFolder().catch((error) => toast(cleanError(error), 'error')));
  $('#rescan-agents').addEventListener('click', () => scanAgents(true));

  let extensionDragStart = null;
  let extensionDragBusy = false;
  const dragExtBtn = $('#drag-extension-button');
  dragExtBtn.addEventListener('pointerdown', (event) => {
    if (event.button === 0) extensionDragStart = { x: event.clientX, y: event.clientY };
  });
  window.addEventListener('pointerup', () => { extensionDragStart = null; });
  window.addEventListener('pointercancel', () => { extensionDragStart = null; });
  dragExtBtn.addEventListener('pointermove', async (event) => {
    if (event.buttons !== 1 || !extensionDragStart || extensionDragBusy || Math.hypot(event.clientX - extensionDragStart.x, event.clientY - extensionDragStart.y) < 5) return;
    extensionDragStart = null;
    extensionDragBusy = true;
    try { await api.dragBrowserExtension(); } catch (error) { toast(cleanError(error), 'error'); } finally { extensionDragBusy = false; }
  });
  dragExtBtn.addEventListener('dragstart', (event) => event.preventDefault());
  dragExtBtn.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      api.extensionFolder().catch((error) => toast(cleanError(error), 'error'));
    }
  });
}
