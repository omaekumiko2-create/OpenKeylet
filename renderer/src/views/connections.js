/* Vault items list/grid view, health checks, full-item copy, and drafts pill. */
import { $, escapeHtml, normalizeSearch } from '../core/dom.js';
import { store, hooks } from '../core/store.js';
import { api } from '../core/api.js';
import { cleanError, publicMessage, toast } from '../core/feedback.js';
import {
  AUTO_CHECK_INTERVALS,
  CARD_ACTION_ICONS,
  MODULE_DEFS,
  itemCapabilities,
  itemDetail,
  itemDisplayKind,
  itemDisplayType,
  itemMetaBadges,
  itemPermission,
  itemSubtitle,
  itemTypeIcon,
  itemTypeLabel,
  moduleSecretName,
} from '../core/item-schema.js';
import { localized } from '../i18n/index.js';

export function clearAutoCheckTimer() {
  if (store.autoCheckTimer !== null) {
    clearTimeout(store.autoCheckTimer);
    store.autoCheckTimer = null;
  }
}

export function getAutoCheckConfig() {
  const enabled = store.state?.settings?.autoCheckEnabled !== false;
  const rawMinutes = Number(store.state?.settings?.autoCheckIntervalMinutes);
  const minutes = AUTO_CHECK_INTERVALS.includes(rawMinutes) ? rawMinutes : 60;
  return { enabled, minutes };
}

export function scheduleAutoCheck() {
  clearAutoCheckTimer();
  if (!store.ownerLockState.unlocked || !store.state?.settings) return;
  const { enabled, minutes } = getAutoCheckConfig();
  if (!enabled) return;
  const delayMs = minutes * 60_000;
  store.autoCheckTimer = setTimeout(async () => {
    store.autoCheckTimer = null;
    if (!store.ownerLockState.unlocked || !store.state?.settings || store.state.settings.autoCheckEnabled === false) return;
    if (!store.checkAllRunning) {
      await runCheckAll({ allItems: true, silent: true });
    }
    scheduleAutoCheck();
  }, delayMs);
}

export function getVisibleConnections() {
  const query = normalizeSearch(store.pageSearch.connections);
  return store.state.connections.filter((item) => {
    if (item.id === store.editorItemId) return true;
    if (store.currentItemTypeFilter !== 'all' && itemDisplayKind(item) !== store.currentItemTypeFilter) return false;
    if (!query) return true;
    const fields = (item.secret?.fields || []).map((field) => field.name).join(' ');
    const notes = (item.agentNotes || []).map((note) => `${note.text || ''} ${note.author || ''}`).join(' ');
    return normalizeSearch([
      item.name,
      item.description,
      item.folder,
      itemTypeLabel(item.itemType),
      itemDisplayType(item),
      itemCapabilities(item).join(' '),
      itemDetail(item),
      itemPermission(item),
      fields,
      notes,
    ].join(' ')).includes(query);
  });
}

export function getTestableVisibleConnections() {
  return getVisibleConnections().filter((item) => item.enabled && item.canTest);
}

export function getAllTestableConnections() {
  return (store.state?.connections || []).filter((item) => item.enabled && item.canTest);
}

function itemCheckButtonView(item) {
  const entry = item.enabled && item.canTest ? store.itemCheckStates.get(item.id) : null;
  if (entry?.status === 'testing') {
    return { state: 'testing', html: '<span class="check-spinner" aria-hidden="true"></span>', title: localized('正在检测连接…', 'Testing connection…'), loading: true };
  }
  if (entry?.status === 'ok') {
    return { state: 'ok', html: CARD_ACTION_ICONS.checkOk, title: entry.message || localized('连接测试通过', 'Connection check passed'), loading: false };
  }
  if (entry?.status === 'error') {
    return { state: 'error', html: CARD_ACTION_ICONS.checkError, title: entry.message || localized('连接测试失败', 'Connection check failed'), loading: false };
  }
  return { state: '', html: CARD_ACTION_ICONS.checkIdle, title: localized('检测连接', 'Test connection'), loading: false };
}

function itemLampView(item) {
  if (!item.enabled) {
    return {
      dotClass: 'status-dot off',
      label: localized('启用此项目；Agent 将可以使用其中的秘密', 'Enable this item so agents can use its secrets'),
    };
  }
  const entry = item.canTest ? store.itemCheckStates.get(item.id) : null;
  if (entry?.status === 'testing') {
    return { dotClass: 'status-dot testing', label: localized('正在检测连接…', 'Testing connection…') };
  }
  if (entry?.status === 'error') {
    const detail = entry.message ? `：${entry.message}` : '';
    return {
      dotClass: 'status-dot warn',
      label: localized(`检测未通过${detail}（点击可停用此项目）`, `Check failed${entry.message ? `: ${entry.message}` : ''} (click to disable)`),
    };
  }
  return {
    dotClass: 'status-dot',
    label: localized('停用此项目；Agent 将无法使用其中的秘密', 'Disable this item; agents will no longer be able to use its secrets'),
  };
}

export function syncListActionsWidth() {
  const list = $('#connections-list');
  if (list) list.style.removeProperty('--list-actions-width');
}

export function syncItemCheckButton(id) {
  const item = store.state.connections.find((candidate) => candidate.id === id);
  const card = $(`.connection-card[data-item-id="${CSS.escape(id)}"]`);
  if (!card || !item) return;
  const canTest = Boolean(item.enabled && item.canTest);
  const button = $('[data-action="test"]', card);
  if (button) {
    const view = itemCheckButtonView(item);
    if (view.state) button.dataset.checkState = view.state;
    else delete button.dataset.checkState;
    button.innerHTML = view.html;
    button.title = view.title;
    button.setAttribute('aria-label', view.title);
    button.disabled = !canTest || view.loading;
    button.setAttribute('aria-busy', view.loading ? 'true' : 'false');
  }
  const toggleBtn = $('.item-toggle', card);
  const dot = $('.item-toggle .status-dot', card);
  if (toggleBtn && dot) {
    const lamp = itemLampView(item);
    dot.className = lamp.dotClass;
    toggleBtn.title = lamp.label;
    toggleBtn.setAttribute('aria-label', lamp.label);
  }
  syncListActionsWidth();
}

export function recomputeCheckAllOutcome() {
  if (!store.lastCheckAllOutcome) return;
  let hasError = false;
  let hasOk = false;
  for (const item of store.state?.connections || []) {
    if (!item.enabled || !item.canTest) continue;
    const entry = store.itemCheckStates.get(item.id);
    if (entry?.status === 'error') hasError = true;
    else if (entry?.status === 'ok') hasOk = true;
  }
  store.lastCheckAllOutcome = hasError ? 'error' : (hasOk ? 'ok' : '');
}

export function clearCheckAllResults() {
  store.lastCheckAllOutcome = '';
  const clearedIds = [];
  for (const [id, entry] of store.itemCheckStates.entries()) {
    if (entry?.status === 'testing') continue;
    store.itemCheckStates.delete(id);
    clearedIds.push(id);
  }
  for (const id of clearedIds) syncItemCheckButton(id);
  syncCheckAllButton();
}

export function syncCheckAllButton() {
  const button = $('#check-all-button');
  const label = $('#check-all-label');
  if (!button || !label) return;
  if (store.checkAllRunning) {
    button.disabled = true;
    button.dataset.state = 'running';
    button.setAttribute('aria-busy', 'true');
    const { done, total } = store.checkAllProgress;
    label.textContent = `${done}/${total}`;
    const tip = localized(`正在批量检测（${done}/${total}）…`, `Checking items (${done}/${total})…`);
    button.title = tip;
    button.setAttribute('aria-label', tip);
    return;
  }
  const testable = getTestableVisibleConnections();
  button.disabled = testable.length === 0;
  button.setAttribute('aria-busy', 'false');
  const hasOutcome = Boolean(store.lastCheckAllOutcome && testable.length > 0);
  if (hasOutcome) button.dataset.state = store.lastCheckAllOutcome;
  else delete button.dataset.state;
  label.textContent = 'CHECK';
  const tip = hasOutcome
    ? (store.lastCheckAllOutcome === 'error'
      ? localized('检测发现异常：点击恢复正常状态', 'Check found issues: click to reset status')
      : localized('检测已完成：点击恢复正常状态', 'Checks finished: click to reset status'))
    : (testable.length > 0
      ? localized(`一键检测当前列表中的 ${testable.length} 个可测试项目`, `Check all ${testable.length} testable items in view`)
      : localized('当前列表没有可检测的已启用项目', 'No enabled testable items in current view'));
  button.title = tip;
  button.setAttribute('aria-label', tip);
}

export async function runSingleItemCheck(item, { showToast = true, doRefresh = true } = {}) {
  if (!item || !item.enabled || !item.canTest) return null;
  if (store.itemCheckStates.get(item.id)?.status === 'testing') return null;
  store.itemCheckStates.set(item.id, { status: 'testing', message: '' });
  syncItemCheckButton(item.id);
  try {
    const raw = await api.test(item.id);
    const msg = publicMessage(raw, localized('连接测试完成', 'Connection test complete'));
    store.itemCheckStates.set(item.id, { status: 'ok', message: msg });
    syncItemCheckButton(item.id);
    recomputeCheckAllOutcome();
    syncCheckAllButton();
    if (showToast) toast(msg);
    if (doRefresh) await hooks.refresh?.(false);
    return { ok: true, message: msg };
  } catch (error) {
    const msg = cleanError(error);
    store.itemCheckStates.set(item.id, { status: 'error', message: msg });
    syncItemCheckButton(item.id);
    recomputeCheckAllOutcome();
    syncCheckAllButton();
    if (showToast) toast(msg, 'error');
    if (doRefresh) await hooks.refresh?.(false);
    return { ok: false, message: msg };
  }
}

export async function runCheckAll({ allItems = false, silent = false } = {}) {
  if (store.checkAllRunning || !store.ownerLockState.unlocked) return;
  const targets = allItems ? getAllTestableConnections() : getTestableVisibleConnections();
  if (!targets.length) {
    if (!silent) toast(localized('当前列表没有可检测的已启用项目', 'No enabled testable items in current view'));
    return;
  }
  const runId = ++store.checkAllRunId;
  store.checkAllRunning = true;
  store.lastCheckAllOutcome = '';
  store.checkAllProgress = { done: 0, total: targets.length };
  for (const item of targets) {
    store.itemCheckStates.set(item.id, { status: 'testing', message: '' });
    syncItemCheckButton(item.id);
  }
  syncCheckAllButton();

  let cursor = 0;
  let passed = 0;
  let failed = 0;
  const workerCount = Math.min(4, targets.length);
  const runWorker = async () => {
    while (cursor < targets.length) {
      if (runId !== store.checkAllRunId || !store.ownerLockState.unlocked) return;
      const item = targets[cursor++];
      try {
        const raw = await api.test(item.id);
        if (runId !== store.checkAllRunId || !store.ownerLockState.unlocked) return;
        const msg = publicMessage(raw, localized('连接测试完成', 'Connection test complete'));
        store.itemCheckStates.set(item.id, { status: 'ok', message: msg });
        passed += 1;
      } catch (error) {
        if (runId !== store.checkAllRunId || !store.ownerLockState.unlocked) return;
        store.itemCheckStates.set(item.id, { status: 'error', message: cleanError(error) });
        failed += 1;
      }
      syncItemCheckButton(item.id);
      store.checkAllProgress = { done: passed + failed, total: targets.length };
      syncCheckAllButton();
    }
  };

  await Promise.all(Array.from({ length: workerCount }, () => runWorker()));
  if (runId !== store.checkAllRunId) return;
  store.checkAllRunning = false;
  store.lastCheckAllOutcome = failed > 0 ? 'error' : 'ok';
  syncCheckAllButton();
  await hooks.refresh?.(false);
  if (silent) {
    if (failed > 0) {
      toast(localized(`定时检测发现 ${failed} 项异常，已亮黄灯提示`, `Scheduled check: ${failed} item(s) flagged with an amber lamp`), 'error');
    }
    return;
  }
  if (failed === 0) {
    window.OpenKeyletAppearance?.play?.('success');
    toast(localized(`一键检测完成：全部 ${passed} 项通过`, `All ${passed} checks passed`));
  } else {
    toast(localized(`一键检测完成：${passed} 项通过，${failed} 项失败（已亮黄灯）`, `Checks finished: ${passed} passed, ${failed} failed (amber lamp)`), 'error');
  }
}

function formatFullItemCopy(item, ownerValues = {}) {
  const lines = [];
  const typeLabel = itemDisplayType(item);
  lines.push(`[${typeLabel}] ${item.name}`);
  const folder = String(item.folder || '').trim();
  const description = String(item.description || '').trim();
  if (folder) lines.push(`${localized('文件夹', 'Folder')}: ${folder}`);
  if (description) lines.push(`${localized('说明', 'Description')}: ${description}`);

  const fieldEntries = [];
  const emittedSecretKeys = new Set();
  for (const module of item.modules || []) {
    const def = MODULE_DEFS[module.kind] || MODULE_DEFS.customSecret;
    const secretKey = moduleSecretName(module);
    const label = module.kind === 'customSecret'
      ? (String(module.name || '').trim() || localized('自定义字段', 'Custom field'))
      : localized(def.zh, def.en);
    let rawVal = '';
    if (secretKey) {
      emittedSecretKeys.add(secretKey);
      rawVal = ownerValues[secretKey] ?? '';
    } else {
      rawVal = module.value ?? '';
    }
    const val = String(rawVal ?? '');
    if (!val.trim()) continue;
    fieldEntries.push([label, val]);
  }
  for (const [key, val] of Object.entries(ownerValues)) {
    if (emittedSecretKeys.has(key)) continue;
    const text = String(val ?? '');
    if (!text.trim()) continue;
    fieldEntries.push([key, text]);
  }
  for (const [label, val] of fieldEntries) {
    if (val.includes('\n')) {
      lines.push(`${label}:`);
      lines.push(val.trimEnd());
    } else {
      lines.push(`${label}: ${val.trim()}`);
    }
  }
  const uris = (item.loginUris || []).map((entry) => String(entry?.uri || '').trim()).filter(Boolean);
  if (uris.length) lines.push(`${localized('匹配网站', 'Websites')}: ${uris.join(', ')}`);
  if (item.passkeys?.length) {
    const passkeySummary = item.passkeys.map((pk) => [pk.rpId, pk.userName || pk.displayName].filter(Boolean).join(' / ')).filter(Boolean);
    if (passkeySummary.length) lines.push(`Passkey: ${passkeySummary.join('; ')}`);
  }
  if (item.agentNotes?.length) {
    lines.push(`${localized('Agent 笔记', 'Agent notes')}:`);
    for (const note of item.agentNotes) {
      const author = note.author === 'OWNER' ? localized('主人', 'OWNER') : (note.author || 'MCP');
      lines.push(`- [${author}] ${note.text}`);
    }
  }
  return lines.join('\n');
}

export async function copyFullItem(item, button = null) {
  if (!item) return;
  try {
    let ownerValues = {};
    try {
      const view = await api.ownerSecrets(item.id);
      ownerValues = Object.fromEntries((view?.fields || []).map((field) => [field.name, field.value]));
    } catch (error) {
      toast(cleanError(error), 'error');
      await hooks.refreshOwnerLock?.(false);
      return;
    }
    const formatted = formatFullItemCopy(item, ownerValues);
    await api.copyOwnerValue(formatted, true);
    if (button?.isConnected) {
      button.classList.add('is-copied');
      button.innerHTML = CARD_ACTION_ICONS.copied;
      setTimeout(() => {
        if (!button.isConnected) return;
        button.classList.remove('is-copied');
        button.innerHTML = CARD_ACTION_ICONS.copy;
      }, 1200);
    }
    toast(localized(`已工整复制「${item.name}」的全部内容（30 秒后清除剪贴板）`, `Copied full contents of "${item.name}" (clears clipboard in 30s)`));
  } catch (error) {
    toast(cleanError(error), 'error');
  }
}

export function syncVaultViewMode() {
  const list = $('#connections-list');
  if (list) {
    list.dataset.view = store.vaultViewMode;
    syncListActionsWidth();
    hooks.updateItemGridRowHeight?.();
  }
  const button = $('#vault-view-toggle');
  if (!button) return;
  button.dataset.view = store.vaultViewMode;
  const label = store.vaultViewMode === 'list'
    ? localized('切换为卡片网格视图', 'Switch to card grid view')
    : localized('切换为列表视图', 'Switch to list view');
  button.setAttribute('aria-label', label);
  button.title = label;
}

export function setVaultViewMode(nextMode) {
  store.vaultViewMode = nextMode === 'grid' ? 'grid' : 'list';
  try { localStorage.setItem('openkeylet.vaultView', store.vaultViewMode); } catch (_) {}
  syncVaultViewMode();
}

export function renderConnections() {
  if (store.itemPointerDrag || store.itemOrderSaving) return;
  syncVaultViewMode();
  const query = normalizeSearch(store.pageSearch.connections);
  const signature = JSON.stringify([store.state.connections, query, store.language, store.editorItemId, store.currentItemTypeFilter]);
  if (signature === store.renderedConnectionsSignature) {
    syncListActionsWidth();
    syncCheckAllButton();
    return;
  }
  store.renderedConnectionsSignature = signature;
  const existingIds = new Set(store.state.connections.map((item) => item.id));
  for (const id of store.itemCheckStates.keys()) {
    if (!existingIds.has(id)) store.itemCheckStates.delete(id);
  }
  recomputeCheckAllOutcome();
  const items = getVisibleConnections();
  const container = $('#connections-list');
  if (store.editorItemId && !store.state.connections.some((item) => item.id === store.editorItemId)) {
    hooks.closeEditor?.();
  }
  if (!items.length) {
    const hasItems = store.state.connections.length > 0;
    container.innerHTML = `<div class="empty-state"><div><div class="empty-code">LOCAL VAULT</div><h3>${hasItems ? localized('没有匹配项目', 'NO MATCHING ITEMS') : localized('还没有秘密项目', 'NO VAULT ITEMS')}</h3><p>${hasItems ? localized('当前筛选没有结果。', 'No items match the current filters.') : localized('保存密码、Passkey、信用卡、身份资料和安全笔记，在需要时使用。', 'Keep passwords, passkeys, cards, identities and secure notes together.')}</p><button class="button primary" data-action="${hasItems ? 'clear-connection-filters' : 'add'}">${hasItems ? localized('清除筛选', 'CLEAR FILTERS') : localized('添加项目', 'ADD ITEM')}</button></div></div>`;
    syncListActionsWidth();
    syncCheckAllButton();
    return;
  }
  container.innerHTML = items.map((item) => {
    const type = itemDisplayType(item);
    const canTest = item.enabled && item.canTest;
    const checkView = itemCheckButtonView(item);
    const lamp = itemLampView(item);
    const agentActions = itemCapabilities(item).length > 0;
    const subtitle = itemSubtitle(item);
    const badges = itemMetaBadges(item);
    const cardLabel = localized(`${item.name}：点击编辑，长按拖拽排序，方向键可调整位置`, `${item.name}: click to edit, hold to drag, or use arrow keys to reorder`);
    const checkStateAttr = checkView.state ? ` data-check-state="${checkView.state}"` : '';
    const checkBusyAttr = checkView.loading ? ' aria-busy="true"' : '';
    return `<article class="connection-card ${itemCapabilities(item).includes('ssh') ? 'ssh' : itemCapabilities(item).includes('http') ? 'http' : 'fill'} ${item.enabled ? '' : 'disabled'}" data-item-id="${escapeHtml(item.id)}" data-item-enabled="${item.enabled ? 'true' : 'false'}" tabindex="-1">
      <button class="connection-name" type="button" draggable="false" data-item-reorder="${escapeHtml(item.id)}" aria-haspopup="dialog" aria-controls="connection-modal" aria-label="${escapeHtml(cardLabel)}" aria-keyshortcuts="ArrowUp ArrowDown ArrowLeft ArrowRight Home End" title="${escapeHtml(cardLabel)}"><span>${escapeHtml(item.name)}</span></button>
      <span class="connection-meta"><span class="connection-sub">${escapeHtml(subtitle)}</span>${badges.map((badge) => `<span class="connection-badge${badge.isNote ? ' is-note' : ''}"${badge.title ? ` title="${escapeHtml(badge.title)}"` : ''}>${escapeHtml(badge.text)}</span>`).join('')}</span>
      <button class="module-state item-toggle" type="button" data-action="toggle-enabled" data-id="${item.id}" aria-pressed="${item.enabled}" title="${escapeHtml(lamp.label)}" aria-label="${escapeHtml(lamp.label)}"><i class="${lamp.dotClass}" aria-hidden="true"></i></button>
      <span class="connection-type" role="img" data-item-type="${itemDisplayKind(item)}" aria-label="${escapeHtml(type)}" title="${escapeHtml(type)}">${itemTypeIcon(itemDisplayKind(item))}<small aria-hidden="true">${escapeHtml(type)}</small></span>
      <div class="card-actions" role="group" aria-label="${escapeHtml(item.name)}">
        ${agentActions ? `<button class="small-button card-icon-btn" type="button" data-action="test" data-id="${item.id}"${checkStateAttr}${checkBusyAttr} title="${escapeHtml(checkView.title)}" aria-label="${escapeHtml(checkView.title)}" ${canTest && !checkView.loading ? '' : 'disabled'}>${checkView.html}</button><button class="small-button card-icon-btn" type="button" data-action="copy-name" data-id="${item.id}" title="${localized('复制 OpenKeylet MCP 使用提示', 'Copy OpenKeylet MCP use prompt')}" aria-label="${localized('复制 OpenKeylet MCP 使用提示', 'Copy OpenKeylet MCP use prompt')}">${CARD_ACTION_ICONS.use}</button>` : ''}${item.passwordHistoryCount ? `<button class="small-button card-icon-btn" type="button" data-action="history" data-id="${item.id}" title="${localized('密码历史', 'Password history')}" aria-label="${localized('密码历史', 'Password history')}">${CARD_ACTION_ICONS.history}</button>` : ''}<button class="small-button card-icon-btn item-disclosure" type="button" data-action="copy-item" data-id="${item.id}" aria-label="${escapeHtml(localized(`复制 ${item.name} 的全部内容`, `Copy full contents of ${item.name}`))}" title="${localized('复制项目全部内容', 'Copy full item contents')}">${CARD_ACTION_ICONS.copy}</button><button class="small-button card-icon-btn delete" type="button" data-action="delete" data-id="${item.id}" title="${localized('移入回收站', 'Move to trash')}" aria-label="${localized('移入回收站', 'Move to trash')}">${CARD_ACTION_ICONS.del}</button>
      </div>
    </article>`;
  }).join('');
  syncListActionsWidth();
  syncCheckAllButton();
}

export function renderDrafts() {
  const button = $('#drafts-button');
  const pill = $('#draft-pill');
  const count = store.editorDrafts.length;
  const hasDraft = count > 0;
  if (!hasDraft) store.creationMode = 'add';
  $('.creation-control').dataset.mode = store.creationMode;
  pill?.classList.toggle('hidden', !hasDraft);
  const deleteButton = $('#delete-draft-button');
  button.disabled = !hasDraft;
  const baseLabel = localized('草稿', 'DRAFT');
  button.textContent = count > 1 ? `${baseLabel} (${count})` : baseLabel;
  const latestName = store.editorDrafts[0]?.input?.name?.trim();
  button.title = !hasDraft
    ? localized('暂无草稿', 'No draft')
    : count > 1
      ? (latestName
        ? localized(`继续最近草稿「${latestName}」（共 ${count} 条待处理）`, `Continue latest draft "${latestName}" (${count} queued)`)
        : localized(`继续最近的草稿（共 ${count} 条待处理）`, `Continue the most recent draft (${count} queued)`))
      : (latestName
        ? localized(`继续草稿「${latestName}」`, `Continue draft "${latestName}"`)
        : localized('继续最近的草稿', 'Continue the most recent draft'));
  deleteButton.classList.toggle('hidden', !hasDraft);
  deleteButton.title = count > 1
    ? localized(`删除最近草稿（剩余 ${count - 1} 条）`, `Delete latest draft (${count - 1} remaining)`)
    : localized('删除草稿', 'Delete draft');
}

export async function refreshDrafts(showError = false) {
  if (!store.ownerLockState.unlocked) {
    store.editorDrafts = [];
    renderDrafts();
    return;
  }
  try {
    store.editorDrafts = await api.drafts();
    renderDrafts();
  } catch (error) {
    if (showError) toast(cleanError(error), 'error');
  }
}

export function initConnectionsView() {
  $('#check-all-button')?.addEventListener('click', () => {
    if (store.checkAllRunning) return;
    if (store.lastCheckAllOutcome) {
      clearCheckAllResults();
      return;
    }
    void runCheckAll();
  });

  $('#vault-view-toggle')?.addEventListener('click', () => {
    setVaultViewMode(store.vaultViewMode === 'list' ? 'grid' : 'list');
  });

  document.fonts?.ready?.then(() => { syncListActionsWidth(); });
}
