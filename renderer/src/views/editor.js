/* Vault item modal editor, module rows, drafts, website matching, agent notes, and smart paste. */
import { $, $$, escapeHtml, value } from '../core/dom.js';
import { store, hooks } from '../core/store.js';
import { api } from '../core/api.js';
import { cleanError, toast, confirmDestructiveAction } from '../core/feedback.js';
import {
  MODULE_DEFS,
  PERSONAL_FIELDS,
  defaultModuleAgentVisible,
  formatTime,
  moduleLabel,
  moduleSecretName,
  typeOptions,
} from '../core/item-schema.js';
import { localized } from '../i18n/index.js';
import { staticCopy } from '../i18n/static-copy.js';
import { OpenKeyletQR } from '../lib/qr-decode.js';
import { refreshOwnerLock } from './owner-lock.js';
import { renderConnections, renderDrafts, refreshDrafts } from './connections.js';
import { finishModulePointerDrag } from './drag-reorder.js';

const MAX_AGENT_NOTES = 5;
const AGENT_NOTE_ICONS = {
  edit: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M11.3 2.7a1.6 1.6 0 0 1 2.2 2.2L6 12.4 3 13l.6-3Z"/></svg>',
  del: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="m4 4 8 8m0-8-8 8"/></svg>',
};

function draftSecretValues(secrets = {}) {
  const named = secrets.namedSecrets || {};
  return {
    ...named,
    password: secrets.password || named.password || '',
    passphrase: secrets.passphrase || named.passphrase || '',
    privateKey: secrets.privateKey || '',
    apiCredential: named.apiCredential || secrets.token || secrets.apiKey || '',
  };
}

export function moduleAgentVisibilityText(visible) {
  return visible
    ? { label: localized('Agent 可查看此值', 'Agent can see this value'), status: localized('Agent 可见', 'AGENT VISIBLE') }
    : { label: localized('不向 Agent 显示此值', 'Hidden from agent'), status: localized('Agent 隐藏', 'AGENT HIDDEN') };
}

export function setModuleAgentVisibility(button, visible) {
  button.setAttribute('aria-pressed', String(visible));
  const { label, status } = moduleAgentVisibilityText(visible);
  button.setAttribute('aria-label', label);
  button.title = label;
  button.closest('.module-row').querySelector('[data-module-visibility]').textContent = status;
  syncModuleDraft();
  syncRevealAllSecretsButton();
}

export function syncModuleDraft() {
  const rows = $$('.module-row', $('#module-list'));
  if (!rows.length) return;
  store.currentModules = rows.map((row, index) => {
    row.dataset.moduleIndex = String(index);
    return {
      kind: row.dataset.kind,
      name: $('[data-module-name]', row)?.value ?? row.dataset.name ?? '',
      value: $('[data-module-value]', row)?.value ?? '',
      secretValue: $('[data-secret-value]', row)?.value ?? '',
      configured: row.dataset.configured === 'true',
      existing: row.dataset.existing === 'true',
      privateKeyName: row.dataset.privateKeyName || '',
      pending: row.dataset.pending === 'true',
      agentVisible: $('[data-module-agent-visible]', row)?.getAttribute('aria-pressed') === 'true',
    };
  });
}

function secretActionButton(kind, secret = true, disabled = false) {
  const disabledAttribute = disabled ? ' disabled' : '';
  if (kind === 'reveal') {
    const label = localized('显示明文', 'Show secret');
    return `<button type="button" class="reveal-secret-button secret-icon-button module-action-icon" data-toggle-module-secret aria-pressed="false" aria-label="${label}" title="${label}"${disabledAttribute}><svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3 10s2.4-4.75 7-4.75S17 10 17 10s-2.4 4.75-7 4.75S3 10 3 10Z"/><circle cx="10" cy="10" r="2.5"/><path class="secret-icon-slash" d="M3.5 3.5l13 13"/></svg></button>`;
  }
  const label = secret ? localized('复制隐私值', 'Copy private value') : localized('复制值', 'Copy value');
  const attribute = secret ? 'data-copy-module-secret' : 'data-copy-module-value';
  return `<button type="button" class="copy-secret-button secret-icon-button module-action-icon" ${attribute} aria-label="${label}" title="${label}"${disabledAttribute}><svg viewBox="0 0 20 20" aria-hidden="true"><rect x="7" y="7" width="10" height="10"/><path d="M14 7V3H3v11h4"/></svg></button>`;
}

export function syncRevealAllSecretsButton() {
  const btn = $('#toggle-all-secrets-button');
  if (!btn) return;
  const toggles = $$('[data-toggle-module-secret]:not(:disabled)', $('#module-list'));
  btn.classList.toggle('hidden', toggles.length < 2);
  if (toggles.length < 2) return;
  const allRevealed = toggles.every((el) => el.getAttribute('aria-pressed') === 'true');
  btn.setAttribute('aria-pressed', String(allRevealed));
  const text = allRevealed ? localized('全部隐藏', 'Hide all') : localized('全部显示', 'Show all');
  const labelEl = $('#toggle-all-secrets-label');
  if (labelEl) labelEl.textContent = text;
  btn.title = text;
}

export function toggleAllModuleSecrets() {
  const toggles = $$('[data-toggle-module-secret]:not(:disabled)', $('#module-list'));
  if (!toggles.length) return;
  const shouldReveal = !toggles.every((el) => el.getAttribute('aria-pressed') === 'true');
  for (const toggle of toggles) {
    const field = $('[data-secret-value]', toggle.closest('.module-row'));
    if (!field) continue;
    if (field.tagName === 'INPUT') field.type = shouldReveal ? 'text' : 'password';
    else field.classList.toggle('secret-masked', !shouldReveal);
    toggle.setAttribute('aria-pressed', String(shouldReveal));
    const label = shouldReveal ? localized('隐藏明文', 'Hide secret') : localized('显示明文', 'Show secret');
    toggle.setAttribute('aria-label', label);
    toggle.title = label;
  }
  syncRevealAllSecretsButton();
}

export function renderModules() {
  finishModulePointerDrag(false);
  const container = $('#module-list');
  if (!store.currentModules.length) {
    container.innerHTML = `<div class="module-empty"><b>EMPTY / DRAFT</b><span>${localized('选择模板或添加任意模块', 'Choose a template or add any module')}</span></div>`;
    syncModuleDraft();
    syncRevealAllSecretsButton();
    return;
  }
  container.innerHTML = store.currentModules.map((module, index) => {
    const definition = MODULE_DEFS[module.kind] || MODULE_DEFS.customSecret;
    const agentVisible = typeof module.agentVisible === 'boolean' ? module.agentVisible : defaultModuleAgentVisible(module.kind);
    const { label: agentVisibilityLabel, status: agentVisibilityStatus } = moduleAgentVisibilityText(agentVisible);
    const secretName = moduleSecretName(module);
    const nameControl = module.kind === 'customSecret'
      ? `<input class="input module-name-input" data-module-name value="${escapeHtml(module.name || '')}" placeholder="${localized('字段名称', 'FIELD NAME')}" />`
      : `<strong>${escapeHtml(moduleLabel(module.kind))}</strong>`;
    const secretCaption = secretName && !PERSONAL_FIELDS.includes(module.kind) && module.kind !== 'customSecret'
      ? `<small>${escapeHtml(secretName)}</small>`
      : '';
    const customName = `${nameControl}<div class="module-metadata">${secretCaption}<span class="module-visibility-state" data-module-visibility aria-hidden="true">${agentVisibilityStatus}</span></div>`;
    let control = '';
    let actions = '';
    if (module.kind === 'privateKey') {
      const keyState = module.pending ? module.privateKeyName : module.configured ? (module.privateKeyName || 'IMPORTED KEY') : localized('尚未导入', 'NOT IMPORTED');
      control = `<div class="module-key-control"><span>${escapeHtml(keyState)}</span><button type="button" class="copy-secret-button" data-choose-module-key>SELECT</button></div>${module.secretValue ? `<div class="secret-input-control module-secret-control multiline module-key-secret"><textarea class="input textarea secret-masked" data-secret-value readonly>${escapeHtml(module.secretValue)}</textarea></div>` : '<input type="hidden" data-secret-value value="" />'}`;
      const keyActionsDisabled = !module.secretValue;
      actions = `${secretActionButton('reveal', true, keyActionsDisabled)}${secretActionButton('copy', true, keyActionsDisabled)}`;
    } else if (definition.secret) {
      const placeholder = module.kind === 'totp' ? localized('Base32 设置密钥', 'BASE32 SETUP KEY') : localized('输入秘密值', 'ENTER SECRET VALUE');
      control = definition.multiline
        ? `<div class="secret-input-control module-secret-control multiline"><textarea class="input textarea secret-masked" data-secret-value rows="6" maxlength="65536" autocomplete="off" placeholder="${placeholder}">${escapeHtml(module.secretValue || '')}</textarea></div>`
        : `<div class="secret-input-control module-secret-control"><input class="input" data-secret-value type="password" autocomplete="off" value="${escapeHtml(module.secretValue || '')}" placeholder="${placeholder}" /></div>`;
      actions = `${secretActionButton('reveal')}${secretActionButton('copy')}`;
      if (module.kind === 'password') control += `<button class="small-button" type="button" data-generate-password>${localized('生成密码', 'GENERATE')}</button>`;
      if (module.kind === 'totp') control += `<div class="totp-inline-actions"><button class="small-button" type="button" data-copy-totp-code>${localized('复制 2FA 验证码', 'COPY 2FA CODE')}</button><button class="small-button" type="button" data-scan-totp-qr>${localized('扫描二维码图片', 'SCAN QR IMAGE')}</button></div>`;
    } else {
      const inputType = module.kind === 'port' ? 'number' : 'text';
      const placeholder = module.kind === 'url' ? 'api.example.com/v1/' : module.kind === 'host' ? 'host.example.com' : '22';
      control = `<input class="input" data-module-value type="${inputType}" ${module.kind === 'port' ? 'min="1" max="65535"' : ''} value="${escapeHtml(module.value || '')}" placeholder="${placeholder}" />`;
      actions = `<span class="module-action-spacer" aria-hidden="true"></span>${secretActionButton('copy', false)}`;
    }
    const removeLabel = localized('删除模块', 'Remove module');
    const reorderLabel = localized('长按或拖动卡片调整顺序，或聚焦后按上/下方向键', 'Hold and drag card to reorder, or focus and use the Up/Down arrow keys');
    return `<div class="module-row" data-module-index="${index}" data-kind="${escapeHtml(module.kind)}" data-name="${escapeHtml(module.name || '')}" data-existing="${Boolean(module.existing)}" data-configured="${Boolean(module.configured)}" data-private-key-name="${escapeHtml(module.privateKeyName || '')}" data-pending="${Boolean(module.pending)}"><button type="button" class="module-agent-toggle" data-module-agent-visible aria-pressed="${agentVisible}" aria-label="${agentVisibilityLabel}" title="${agentVisibilityLabel}"><i aria-hidden="true"></i></button><div class="module-identity" data-module-drag-handle tabindex="0" role="group" aria-label="${reorderLabel}" title="${reorderLabel}" aria-keyshortcuts="ArrowUp ArrowDown">${customName}</div><div class="module-control">${control}</div><div class="module-actions ${actions ? 'full' : 'single'}">${actions}<button type="button" class="remove-module module-action-icon" data-remove-module aria-label="${removeLabel}" title="${removeLabel}"><svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3 5.5h14M7.5 5.5V3.25h5v2.25M5.25 5.5l.75 11h8l.75-11M8.25 8.5v5M11.75 8.5v5"/></svg></button></div></div>`;
  }).join('');
  syncModuleDraft();
  syncRevealAllSecretsButton();
}

export function positionModuleMenu() {
  const menu = $('#module-menu');
  if (menu.classList.contains('hidden')) return;
  const buttonRect = $('#add-module-button').getBoundingClientRect();
  const gutter = 8;
  const menuWidth = Math.min(276, window.innerWidth - gutter * 2);
  menu.style.width = `${menuWidth}px`;
  menu.style.left = `${Math.round(Math.min(Math.max(gutter, buttonRect.right - menuWidth), window.innerWidth - menuWidth - gutter))}px`;
  menu.style.right = 'auto';
  const below = buttonRect.bottom + 4;
  const spaceBelow = Math.max(0, window.innerHeight - gutter - below);
  const spaceAbove = Math.max(0, buttonRect.top - gutter - 4);
  menu.style.maxHeight = `${window.innerHeight - gutter * 2}px`;
  const naturalHeight = menu.scrollHeight;
  if (naturalHeight <= spaceBelow) {
    menu.style.maxHeight = `${Math.round(spaceBelow)}px`;
    menu.style.top = `${Math.round(below)}px`;
  } else if (spaceAbove >= 160) {
    const height = Math.min(naturalHeight, spaceAbove);
    menu.style.maxHeight = `${Math.round(spaceAbove)}px`;
    menu.style.top = `${Math.round(Math.max(gutter, buttonRect.top - height - 4))}px`;
  } else {
    menu.style.maxHeight = `${Math.round(Math.max(spaceBelow, 120))}px`;
    menu.style.top = `${Math.round(below)}px`;
  }
}

export function setModuleMenu(open) {
  const menu = $('#module-menu');
  const home = $('#add-module-button').closest('.module-add-wrap');
  if (open) {
    document.body.appendChild(menu);
    menu.classList.remove('hidden');
    positionModuleMenu();
  } else {
    menu.classList.add('hidden');
    home.appendChild(menu);
    menu.removeAttribute('style');
  }
  $('#add-module-button').setAttribute('aria-expanded', String(Boolean(open)));
}

export function addModule(kind, options = {}) {
  syncModuleDraft();
  if (kind !== 'customSecret' && store.currentModules.some((module) => module.kind === kind)) {
    setModuleMenu(false);
    return toast(localized('这个模块已经存在', 'That module already exists'));
  }
  store.currentModules.push({
    kind,
    name: kind === 'customSecret' ? '' : kind,
    value: kind === 'port' ? '22' : '',
    secretValue: '',
    configured: false,
    existing: false,
    privateKeyName: '',
    pending: false,
    agentVisible: defaultModuleAgentVisible(kind),
    ...options,
  });
  setModuleMenu(false);
  $('#template-picker').classList.add('hidden');
  renderModules();
  const row = $$('.module-row').at(-1);
  ($('[data-module-name]', row) || $('[data-secret-value]', row) || $('[data-module-value]', row))?.focus();
}

export function applyTemplate(template) {
  const presets = {
    login: ['url', 'username', 'password'],
    card: ['cardholderName', 'cardNumber', 'cardBrand', 'cardExpMonth', 'cardExpYear', 'cardSecurityCode'],
    identity: ['firstName', 'lastName', 'email', 'phone', 'address1', 'address2', 'city', 'state', 'postalCode', 'country'],
    secureNote: ['secureNote'],
    ssh: ['host', 'port', 'username', 'password'],
    api: ['apiCredential'],
    blank: [],
  };
  value('#connection-type', template === 'blank' ? 'custom' : template);
  store.currentModules = (presets[template] || []).map((kind) => ({
    kind,
    name: kind,
    value: kind === 'port' ? '22' : '',
    secretValue: '',
    configured: false,
    existing: false,
    privateKeyName: '',
    pending: false,
    agentVisible: defaultModuleAgentVisible(kind),
  }));
  $('#template-picker').classList.add('hidden');
  renderModules();
}

export function updateEditorTitle() {
  const queueSuffix = store.editorOpenedFromDraft && store.editorDrafts.length > 1 ? ` (${store.editorDrafts.length})` : '';
  $('#modal-title').textContent = (store.editorOpenedFromDraft
    ? (store.editorExistingItem ? localized('继续编辑', 'CONTINUE EDIT') : localized('继续草稿', 'CONTINUE DRAFT'))
    : (store.editorExistingItem ? localized('编辑项目', 'EDIT ITEM') : localized('添加项目', 'ADD ITEM'))) + queueSuffix;
}

export function renderLoginUris(rules) {
  const choices = [
    ['origin', '同源', 'Same origin'],
    ['domain', '主域名', 'Base domain'],
    ['host', '主机与端口', 'Host and port'],
    ['exact', '完整网址', 'Exact URL'],
    ['prefix', '网址前缀', 'URL prefix'],
    ['regex', '正则表达式', 'Regular expression'],
    ['never', '不匹配', 'Never'],
  ];
  $('#login-uri-list').innerHTML = rules
    .map((rule) => `<div class="login-uri-row"><input class="input" data-login-uri aria-label="${localized('网站地址', 'Website address')}" value="${escapeHtml(rule.uri)}" maxlength="8192"><select class="input" data-login-match aria-label="${localized('匹配规则', 'Matching rule')}">${choices.map(([key, zh, en]) => `<option value="${key}" ${rule.matchType === key ? 'selected' : ''}>${localized(zh, en)}</option>`).join('')}</select><button class="small-button uri-remove-button" data-remove-uri type="button" aria-label="${localized('移除网站', 'Remove website')}"><svg viewBox="0 0 16 16" aria-hidden="true"><path d="m4 4 8 8m0-8-8 8"/></svg></button></div>`)
    .join('');
}

function formatNoteAuthor(author) {
  const raw = String(author || '').trim();
  if (!raw) return 'MCP';
  if (raw === 'OWNER') return localized('主人', 'OWNER');
  return raw;
}

function applyUpdatedAgentNotesItem(updated) {
  if (!updated?.id) return;
  if (store.editorExistingItem?.id === updated.id) store.editorExistingItem = updated;
  if (store.state?.connections) {
    const idx = store.state.connections.findIndex((candidate) => candidate.id === updated.id);
    if (idx >= 0) store.state.connections[idx] = updated;
  }
  renderAgentNotes(updated, { autoOpen: false });
  renderConnections();
}

export function renderAgentNotes(item = store.editorExistingItem, { autoOpen = false } = {}) {
  const section = $('#agent-notes-section');
  if (!section) return;
  if (!item?.id) {
    section.classList.add('hidden');
    section.open = false;
    return;
  }
  section.classList.remove('hidden');
  const notes = Array.isArray(item.agentNotes) ? item.agentNotes : [];
  const locked = Boolean(item.agentNotesLocked);
  if (autoOpen) section.open = notes.length > 0 || locked;
  const countEl = $('#agent-notes-count');
  if (countEl) countEl.textContent = `${notes.length}/${MAX_AGENT_NOTES}`;
  const lockBadge = $('#agent-notes-lock-badge');
  if (lockBadge) {
    lockBadge.textContent = localized('已锁定', 'LOCKED');
    lockBadge.classList.toggle('hidden', !locked);
  }
  const lockInput = $('#agent-notes-locked');
  if (lockInput) {
    lockInput.checked = locked;
    lockInput.disabled = store.agentNoteBusy;
  }
  const clearBtn = $('#agent-notes-clear');
  if (clearBtn) {
    clearBtn.textContent = localized('清空', 'CLEAR');
    clearBtn.classList.toggle('hidden', notes.length === 0);
    clearBtn.disabled = store.agentNoteBusy;
  }
  const addInput = $('#agent-note-input');
  const addBtn = $('#agent-note-add');
  if (addInput) {
    addInput.placeholder = localized('添加简短用途备注（如：生产 GPU 服务器、/srv/web）…', 'Add a short note (e.g. prod GPU server, /srv/web)…');
    addInput.disabled = store.agentNoteBusy;
  }
  if (addBtn) {
    addBtn.textContent = localized('添加', 'ADD');
    addBtn.disabled = store.agentNoteBusy;
  }
  const list = $('#agent-notes-list');
  if (!list) return;
  if (!notes.length) {
    list.innerHTML = `<p class="agent-notes-empty">${escapeHtml(localized('尚无 Agent 笔记。Agent 使用此项目后可自动记录简短非敏感用途备注，你也可以在下方手动添加。', 'No agent notes yet. Agents can record short non-secret context after using this item, or you can add one below.'))}</p>`;
    return;
  }
  list.innerHTML = notes.map((note) => {
    const isEditing = store.editingAgentNoteId === note.id;
    const isOwner = note.author === 'OWNER';
    const timeText = note.updatedAt ? formatTime(note.updatedAt) : '';
    const body = isEditing
      ? `<div class="agent-note-edit-row"><input class="input" type="text" maxlength="200" autocomplete="off" spellcheck="false" data-edit-note-input="${escapeHtml(note.id)}" value="${escapeHtml(note.text)}" aria-label="${escapeHtml(localized('编辑笔记', 'Edit note'))}" /><button type="button" class="button primary" data-save-note="${escapeHtml(note.id)}">${escapeHtml(localized('保存', 'SAVE'))}</button><button type="button" class="button quiet" data-cancel-note>${escapeHtml(localized('取消', 'Cancel'))}</button></div>`
      : `<p class="agent-note-text">${escapeHtml(note.text)}</p>`;
    return `<div class="agent-note-row" data-note-id="${escapeHtml(note.id)}">
      <div class="agent-note-head">
        <span class="agent-note-author${isOwner ? ' is-owner' : ''}">${escapeHtml(formatNoteAuthor(note.author))}</span>
        <span class="agent-note-time">${escapeHtml(timeText)}</span>
        <span class="agent-note-actions">
          ${isEditing ? '' : `<button type="button" class="agent-note-icon-btn" data-edit-note="${escapeHtml(note.id)}" aria-label="${escapeHtml(localized('编辑笔记', 'Edit note'))}" title="${escapeHtml(localized('编辑笔记', 'Edit note'))}">${AGENT_NOTE_ICONS.edit}</button>`}
          <button type="button" class="agent-note-icon-btn delete" data-delete-note="${escapeHtml(note.id)}" aria-label="${escapeHtml(localized('删除笔记', 'Delete note'))}" title="${escapeHtml(localized('删除笔记', 'Delete note'))}">${AGENT_NOTE_ICONS.del}</button>
        </span>
      </div>
      ${body}
    </div>`;
  }).join('');
}

async function submitNewAgentNote() {
  if (store.agentNoteBusy || !store.editorExistingItem?.id) return;
  const input = $('#agent-note-input');
  const text = String(input?.value || '').trim();
  if (!text) {
    toast(localized('请先输入笔记内容', 'Enter a note first'), 'error');
    input?.focus();
    return;
  }
  store.agentNoteBusy = true;
  renderAgentNotes(store.editorExistingItem, { autoOpen: false });
  try {
    const updated = await api.addAgentNote(store.editorExistingItem.id, text);
    if (input) input.value = '';
    store.editingAgentNoteId = null;
    window.OpenKeyletAppearance?.play?.('success');
    toast(localized('已添加 Agent 笔记', 'Agent note added'));
    applyUpdatedAgentNotesItem(updated);
  } catch (error) {
    toast(cleanError(error), 'error');
  } finally {
    store.agentNoteBusy = false;
    renderAgentNotes(store.editorExistingItem, { autoOpen: false });
  }
}

async function saveEditedAgentNote(noteId) {
  if (store.agentNoteBusy || !store.editorExistingItem?.id || !noteId) return;
  const input = $(`[data-edit-note-input="${CSS.escape(noteId)}"]`);
  const text = String(input?.value || '').trim();
  if (!text) {
    toast(localized('请先输入笔记内容', 'Enter a note first'), 'error');
    input?.focus();
    return;
  }
  store.agentNoteBusy = true;
  renderAgentNotes(store.editorExistingItem, { autoOpen: false });
  try {
    const updated = await api.updateAgentNote(store.editorExistingItem.id, noteId, text);
    store.editingAgentNoteId = null;
    window.OpenKeyletAppearance?.play?.('success');
    toast(localized('已更新 Agent 笔记', 'Agent note updated'));
    applyUpdatedAgentNotesItem(updated);
  } catch (error) {
    toast(cleanError(error), 'error');
  } finally {
    store.agentNoteBusy = false;
    renderAgentNotes(store.editorExistingItem, { autoOpen: false });
  }
}

export function clearSmartParseBanner() {
  store.editorSmartClipboardSource = '';
  store.editorSmartTotpUri = '';
  $('#smart-parse-banner')?.classList.add('hidden');
  $('#smart-parse-warnings')?.classList.add('hidden');
  $('#smart-totp-attach')?.classList.add('hidden');
}

export function closeEditor() {
  finishModulePointerDrag(false);
  clearSmartParseBanner();
  $('#connection-modal').classList.add('hidden');
  setModuleMenu(false);
  store.editorItemId = null;
  store.editorSourceInput = null;
  store.editorCandidateOnSaved = null;
  store.editorOpenedFromDraft = false;
  store.editorInitialSnapshot = '';
  store.editingAgentNoteId = null;
  if ($('#agent-note-input')) $('#agent-note-input').value = '';
  $('#agent-notes-section')?.classList.add('hidden');
  if (!store.editorReturnFocus?.isConnected && store.editorReturnFocus?.dataset.itemReorder) {
    store.editorReturnFocus = $(`[data-item-reorder="${CSS.escape(store.editorReturnFocus.dataset.itemReorder)}"]`);
  }
  if (!store.editorReturnFocus?.isConnected && store.editorReturnFocus?.dataset.action && store.editorReturnFocus?.dataset.id) {
    const prev = store.editorReturnFocus;
    store.editorReturnFocus = $$('[data-action][data-id]').find(
      (button) => button.dataset.action === prev.dataset.action && button.dataset.id === prev.dataset.id,
    );
  }
  if (store.editorReturnFocus?.isConnected && !store.editorReturnFocus.closest('.hidden')) {
    store.editorReturnFocus.focus({ preventScroll: true });
  }
  store.editorReturnFocus = null;
}

function collectModules(validate = true) {
  syncModuleDraft();
  const modules = [];
  const secrets = { namedSecrets: {} };
  const secretNames = new Set();
  for (const module of store.currentModules) {
    const name = moduleSecretName(module);
    if (module.kind === 'customSecret') {
      if (validate && !name) throw new Error(localized('请输入字段名称', 'Enter a field name'));
      const normalizedName = name.toLocaleLowerCase().replace(/[\s_-]+/g, '');
      if (validate && [...Object.keys(MODULE_DEFS).map((k) => k.toLowerCase()), 'token', 'apikey'].includes(normalizedName)) {
        throw new Error(localized(`字段名与内置模块冲突：${name}`, `Field name conflicts with a built-in module: ${name}`));
      }
    }
    const uniqueName = name.toLocaleLowerCase().replace(/[\s_-]+/g, '');
    if (validate && name && secretNames.has(uniqueName)) {
      throw new Error(localized(`字段名重复：${name}`, `Duplicate field name: ${name}`));
    }
    if (name) secretNames.add(uniqueName);
    modules.push({
      kind: module.kind,
      name: module.kind === 'customSecret' ? name : '',
      value: MODULE_DEFS[module.kind]?.secret ? '' : String(module.value || '').trim(),
      agentVisible: Boolean(module.agentVisible),
    });
    const fieldValue = module.secretValue || '';
    if (name === 'password') secrets.password = fieldValue;
    else if (name === 'passphrase') secrets.passphrase = fieldValue;
    else if (name === 'privateKey') secrets.privateKey = fieldValue;
    else if (name) secrets.namedSecrets[name] = fieldValue;
  }
  return {
    modules,
    secrets,
    privateKeyImportPath: store.currentModules.some((module) => module.kind === 'privateKey' && module.pending) ? 'pending' : '',
  };
}

export function serializeItem(validate = true) {
  const name = value('#connection-name').trim();
  if (validate && !name) throw new Error(localized('请输入项目名称', 'Enter an item name'));
  const id = value('#connection-id') || null;
  if (validate && store.state.connections.some((item) => item.id !== id && item.name.trim().toLowerCase() === name.toLowerCase())) {
    throw new Error(localized('项目名称已存在，请使用其他名称', 'An item with this name already exists'));
  }
  syncModuleDraft();
  if (validate && !store.currentModules.length) throw new Error(localized('请至少添加一个模块', 'Add at least one module'));
  const collected = collectModules(validate);
  return {
    id,
    itemType: value('#connection-type'),
    folder: value('#connection-folder').trim(),
    favorite: Boolean(store.editorSourceInput?.favorite),
    loginUris: $$('#login-uri-list .login-uri-row')
      .map((row) => ({ uri: $('[data-login-uri]', row).value.trim(), matchType: $('[data-login-match]', row).value }))
      .filter((rule) => rule.uri),
    modules: collected.modules,
    name,
    description: value('#connection-description'),
    enabled: $('#connection-enabled').checked,
    httpAuthType: store.editorSourceInput?.httpAuthType || 'auto',
    authHeader: store.editorSourceInput?.authHeader || '',
    authLocation: store.editorSourceInput?.authLocation || '',
    authPrefix: store.editorSourceInput?.authPrefix || '',
    apiAuthHeaders: store.editorSourceInput?.apiAuthHeaders || [],
    testPath: store.editorSourceInput?.testPath || '',
    privateKeyImportPath: collected.privateKeyImportPath,
    removeSecretNames: [
      ...new Set([
        ...store.removedSecretFields,
        ...store.currentModules.filter((m) => PERSONAL_FIELDS.includes(m.kind) && m.configured && !m.secretValue).map(moduleSecretName),
      ]),
    ].filter((name) => !store.currentModules.some((module) => moduleSecretName(module) === name && (module.secretValue || module.pending))),
    secrets: collected.secrets,
  };
}

function editorHasDraftContent() {
  syncModuleDraft();
  return Boolean(value('#connection-name').trim() || value('#connection-description').trim() || store.currentModules.length);
}

async function saveDraftAndCloseEditor() {
  try {
    const input = serializeItem(false);
    const changed = JSON.stringify(input) !== store.editorInitialSnapshot;
    let draftsChanged = false;
    if (!editorHasDraftContent() && !store.editorExistingItem) {
      if (store.currentDraftId) {
        await api.deleteDraft(store.currentDraftId);
        draftsChanged = true;
      }
    } else if (changed || store.editorOpenedFromDraft) {
      const saved = await api.saveDraft(store.currentDraftId || null, input);
      store.currentDraftId = saved.id;
      draftsChanged = true;
      toast(store.editorExistingItem
        ? localized('未保存修改已保留，可随时继续', 'Unsaved changes kept for later')
        : localized('草稿已加密保存', 'Draft saved and encrypted'));
    }
    if (draftsChanged) await refreshDrafts();
    closeEditor();
    return true;
  } catch (error) {
    toast(cleanError(error), 'error');
    return false;
  }
}

export function closeEditorWithDraft() {
  if (store.editorClosing) return store.editorClosing;
  store.editorClosing = saveDraftAndCloseEditor().finally(() => { store.editorClosing = null; });
  return store.editorClosing;
}

export async function openEditor(item = null, draft = null) {
  if (store.editorOpening) return false;
  store.editorOpening = true;
  try {
    const launcher = document.activeElement;
    if (!$('#connection-modal').classList.contains('hidden') && !await closeEditorWithDraft()) return false;
    if (!draft && item) draft = store.editorDrafts.find((candidate) => candidate.input?.id === item.id) || null;
    if (!item && draft?.input?.id) item = store.state.connections.find((candidate) => candidate.id === draft.input.id) || null;
    let ownerValues = {};
    if (draft) {
      ownerValues = draftSecretValues(draft.input?.secrets);
    } else if (item) {
      try {
        const view = await api.ownerSecrets(item.id);
        ownerValues = Object.fromEntries(view.fields.map((field) => [field.name, field.value]));
      } catch (error) {
        toast(cleanError(error), 'error');
        await refreshOwnerLock(false);
        return false;
      }
    }
    const source = draft?.input || item || null;
    store.removedSecretFields = new Set();
    store.editorExistingItem = item;
    store.editorSourceInput = source;
    store.editorOpenedFromDraft = Boolean(draft);
    store.currentDraftId = draft?.id || '';
    value('#connection-id', item?.id);
    value('#connection-name', source?.name);
    value('#connection-description', source?.description);
    $('#connection-type').innerHTML = typeOptions('', source?.itemType || 'custom');
    value('#connection-folder', source?.folder);
    renderLoginUris(source?.loginUris || []);
    $('#vault-folder-options').innerHTML = [...new Set(store.state.connections.map((i) => i.folder).filter(Boolean))]
      .map((f) => `<option value="${escapeHtml(f)}"></option>`)
      .join('');
    $('#connection-enabled').checked = source?.enabled ?? true;
    updateEditorTitle();
    $('#template-picker').classList.toggle('hidden', Boolean(item || draft?.input?.modules?.length));
    store.currentModules = (source?.modules || []).map((module) => {
      const secretName = module.kind === 'customSecret' ? module.name : module.kind;
      const privateKeyName = draft?.input?.secrets?.privateKeyName || item?.privateKeyName || '';
      return {
        ...module,
        secretValue: ownerValues[secretName] || '',
        configured: Boolean(module.configured || ownerValues[secretName]),
        existing: Boolean(item),
        privateKeyName: module.kind === 'privateKey' ? privateKeyName : '',
        pending: false,
        agentVisible: typeof module.agentVisible === 'boolean' ? module.agentVisible : defaultModuleAgentVisible(module.kind),
      };
    });
    renderModules();
    store.editorReturnFocus = launcher;
    store.editorItemId = item?.id || null;
    $('#connection-modal').classList.remove('hidden');
    $('#passkey-list').innerHTML = (item?.passkeys || [])
      .map((key) => `<div class="passkey-summary"><strong>PASSKEY · ${escapeHtml(key.rpId)}</strong><span>${escapeHtml(key.displayName || key.userName)}</span><small>${localized('私钥加密保存在本地；在浏览器中使用。移入回收站会停用 Passkey，恢复后可继续使用。', 'Private key encrypted locally. Moving this item to trash disables its passkeys; restore it to use them again.')}</small></div>`)
      .join('');
    store.editingAgentNoteId = null;
    renderAgentNotes(item, { autoOpen: true });
    $('.form-scroll', $('#connection-modal')).scrollTop = 0;
    store.editorInitialSnapshot = JSON.stringify(serializeItem(false));
    requestAnimationFrame(() => {
      if (!$('#connection-modal').classList.contains('hidden') && store.editorExistingItem === item && !$('#connection-modal').contains(document.activeElement)) {
        $('#connection-name').focus({ preventScroll: true });
      }
    });
    return true;
  } finally {
    store.editorOpening = false;
  }
}

export async function applySmartParseToEditor(parsed, options = {}) {
  const sourceInput = parsed?.input;
  if (!sourceInput) return;
  const modalHidden = $('#connection-modal').classList.contains('hidden');
  if (modalHidden) {
    const opened = await openEditor(null, null);
    if (!opened) return;
  } else if (store.editorExistingItem) {
    if (!await closeEditorWithDraft()) return;
    const opened = await openEditor(null, null);
    if (!opened) return;
  }
  store.editorSourceInput = sourceInput;
  store.editorSmartClipboardSource = options.clipboardSource || '';
  store.editorSmartTotpUri = parsed.totpUri || '';
  const uniqueName = (() => {
    const base = String(sourceInput.name || '').trim() || localized('智能导入项目', 'Imported item');
    if (!store.state?.connections?.some((item) => item.name.trim().toLowerCase() === base.toLowerCase())) return base;
    let index = 2;
    while (store.state.connections.some((item) => item.name.trim().toLowerCase() === `${base} (${index})`.toLowerCase())) index++;
    return `${base} (${index})`;
  })();
  value('#connection-name', uniqueName);
  value('#connection-description', sourceInput.description || '');
  $('#connection-type').innerHTML = typeOptions('', sourceInput.itemType || 'custom');
  value('#connection-folder', sourceInput.folder || '');
  renderLoginUris(sourceInput.loginUris || []);
  store.editingAgentNoteId = null;
  renderAgentNotes(null);
  $('#connection-enabled').checked = sourceInput.enabled ?? true;
  $('#template-picker').classList.add('hidden');
  const ownerValues = draftSecretValues(sourceInput.secrets);
  const privateKeyName = sourceInput.secrets?.privateKeyName || '';
  store.currentModules = (sourceInput.modules || []).map((module) => {
    const secretName = module.kind === 'customSecret' ? module.name : module.kind;
    return {
      ...module,
      secretValue: ownerValues[secretName] || '',
      configured: Boolean(ownerValues[secretName]),
      existing: false,
      privateKeyName: module.kind === 'privateKey' ? privateKeyName : '',
      pending: false,
      agentVisible: typeof module.agentVisible === 'boolean' ? module.agentVisible : defaultModuleAgentVisible(module.kind),
    };
  });
  renderModules();

  const banner = $('#smart-parse-banner');
  if (banner) {
    $('#smart-parse-badge').textContent = localized(parsed.labelZh || parsed.label, parsed.label);
    $('#smart-parse-summary').textContent = parsed.summary || '';
    const warningsEl = $('#smart-parse-warnings');
    if (parsed.warnings?.length) {
      warningsEl.textContent = parsed.warnings.join(' · ');
      warningsEl.classList.remove('hidden');
    } else {
      warningsEl.textContent = '';
      warningsEl.classList.add('hidden');
    }
    const attachWrap = $('#smart-totp-attach');
    const targetSelect = $('#smart-totp-target');
    if (parsed.totpUri && store.state?.connections?.length && attachWrap && targetSelect) {
      const issuer = (parsed.totpIssuer || '').toLowerCase();
      const sorted = [...store.state.connections].sort((a, b) => {
        const aMatch = issuer && a.name.toLowerCase().includes(issuer) ? 1 : 0;
        const bMatch = issuer && b.name.toLowerCase().includes(issuer) ? 1 : 0;
        if (aMatch !== bMatch) return bMatch - aMatch;
        return (a.itemType === 'login' ? 0 : 1) - (b.itemType === 'login' ? 0 : 1);
      });
      targetSelect.replaceChildren(...sorted.map((item) => {
        const opt = document.createElement('option');
        opt.value = item.id;
        opt.textContent = item.name;
        return opt;
      }));
      attachWrap.classList.remove('hidden');
    } else if (attachWrap) {
      attachWrap.classList.add('hidden');
    }
    banner.classList.remove('hidden');
  }
  toast(localized(`已智能识别：${parsed.labelZh || parsed.label}`, `Detected: ${parsed.label}`));
}

export async function openCandidateInEditor(candidate, onSaved = null) {
  if (!candidate?.input) return;
  await applySmartParseToEditor({
    input: candidate.input,
    label: candidate.badge || 'IMPORT',
    labelZh: candidate.badgeZh || candidate.badge || '导入',
    summary: candidate.summary || '',
    warnings: [],
    totpUri: candidate.totpUri || '',
  });
  store.editorInitialSnapshot = JSON.stringify(serializeItem(false));
  store.editorCandidateOnSaved = typeof onSaved === 'function' ? onSaved : null;
}

export async function smartIngestText(rawText, options = {}) {
  const text = String(rawText || '').trim();
  if (!text) return toast(localized('剪贴板为空，请先复制 API Key、cURL、SSH、.env 或 2FA', 'Clipboard is empty — copy an API key, cURL, SSH, .env, or 2FA URI first'), 'error');
  await refreshOwnerLock();
  if (!store.ownerLockState.unlocked) return;
  try {
    const parsed = await api.smartParseText(text, options.filename || null, options.url || null);
    await applySmartParseToEditor(parsed, { clipboardSource: options.fromClipboard ? rawText : '' });
  } catch (error) {
    toast(cleanError(error), 'error');
  }
}

export async function triggerSmartPasteFromClipboard() {
  await refreshOwnerLock();
  if (!store.ownerLockState.unlocked) return;
  try {
    if (navigator.clipboard?.read && OpenKeyletQR.supported) {
      try {
        const items = await navigator.clipboard.read();
        for (const item of items) {
          const imgType = item.types.find((t) => t.startsWith('image/'));
          if (imgType) {
            const blob = await item.getType(imgType);
            const decoded = await OpenKeyletQR.decode(blob);
            await smartIngestText(decoded, { fromClipboard: false });
            return;
          }
        }
      } catch (_) {}
    }
    let text = '';
    try { text = await api.readOwnerClipboard(); } catch (_) {}
    if (!text && navigator.clipboard?.readText) {
      try { text = await navigator.clipboard.readText(); } catch (_) {}
    }
    await smartIngestText(text, { fromClipboard: true });
  } catch (error) {
    toast(cleanError(error), 'error');
  }
}

export async function handleSmartFile(file) {
  if (!file) return;
  await refreshOwnerLock();
  if (!store.ownerLockState.unlocked) return;
  try {
    if (file.type?.startsWith('image/') || /\.(png|jpe?g|webp|gif|bmp)$/i.test(file.name || '')) {
      if (!OpenKeyletQR.decode) throw new Error(localized('当前环境不支持二维码图片解码', 'QR decoding is unavailable in this WebView'));
      const decoded = await OpenKeyletQR.decode(file);
      await smartIngestText(decoded, { filename: file.name, fromClipboard: false });
      return;
    }
    if (file.size > 512 * 1024) {
      throw new Error(localized('文件超过 512 KiB，请通过设置页导入大文件', 'File exceeds 512 KiB; use System → Import for larger files'));
    }
    const text = await file.text();
    await smartIngestText(text, { filename: file.name, fromClipboard: false });
  } catch (error) {
    toast(cleanError(error), 'error');
  }
}

export function initEditorView() {
  // Append personal field buttons to #module-menu and register their translations.
  for (const kind of PERSONAL_FIELDS) {
    const button = document.createElement('button');
    button.type = 'button';
    button.dataset.addModule = kind;
    button.textContent = moduleLabel(kind);
    $('#module-menu').append(button);
    staticCopy.push([`#module-menu [data-add-module="${kind}"]`, 'text', MODULE_DEFS[kind].zh, MODULE_DEFS[kind].en]);
  }

  $('#login-uri-add').onclick = () => renderLoginUris([
    ...$$('#login-uri-list .login-uri-row').map((row) => ({ uri: $('[data-login-uri]', row).value, matchType: $('[data-login-match]', row).value })),
    { uri: '', matchType: 'origin' },
  ]);
  $('#login-uri-list').onclick = (event) => event.target.closest('[data-remove-uri]')?.closest('.login-uri-row').remove();

  // Agent notes controls
  $('#agent-note-add')?.addEventListener('click', submitNewAgentNote);
  $('#agent-note-input')?.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      event.stopPropagation();
      submitNewAgentNote();
    }
  });
  $('#agent-notes-locked')?.addEventListener('change', async (event) => {
    if (store.agentNoteBusy || !store.editorExistingItem?.id) return;
    const locked = Boolean(event.currentTarget.checked);
    store.agentNoteBusy = true;
    renderAgentNotes(store.editorExistingItem, { autoOpen: false });
    try {
      const updated = await api.setAgentNotesLocked(store.editorExistingItem.id, locked);
      window.OpenKeyletAppearance?.play?.(locked ? 'toggleOn' : 'toggleOff');
      toast(locked
        ? localized('已锁定笔记，禁止 Agent 修改', 'Agent notes locked')
        : localized('已解锁笔记，允许 Agent 写入', 'Agent notes unlocked'));
      applyUpdatedAgentNotesItem(updated);
    } catch (error) {
      toast(cleanError(error), 'error');
    } finally {
      store.agentNoteBusy = false;
      renderAgentNotes(store.editorExistingItem, { autoOpen: false });
    }
  });
  $('#agent-notes-clear')?.addEventListener('click', async () => {
    if (store.agentNoteBusy || !store.editorExistingItem?.id) return;
    const confirmed = await confirmDestructiveAction({
      title: localized('清空全部 Agent 笔记？', 'Clear all agent notes?'),
      message: localized('此项目上所有已保存的 Agent 笔记都会被移除。', 'All saved agent notes on this item will be removed.'),
      acceptLabel: localized('清空', 'CLEAR'),
    });
    if (!confirmed || !store.editorExistingItem?.id) return;
    store.agentNoteBusy = true;
    renderAgentNotes(store.editorExistingItem, { autoOpen: false });
    try {
      const updated = await api.clearAgentNotes(store.editorExistingItem.id);
      store.editingAgentNoteId = null;
      window.OpenKeyletAppearance?.play?.('success');
      toast(localized('已清空全部 Agent 笔记', 'All agent notes cleared'));
      applyUpdatedAgentNotesItem(updated);
    } catch (error) {
      toast(cleanError(error), 'error');
    } finally {
      store.agentNoteBusy = false;
      renderAgentNotes(store.editorExistingItem, { autoOpen: false });
    }
  });
  $('#agent-notes-list')?.addEventListener('click', async (event) => {
    if (store.agentNoteBusy || !store.editorExistingItem?.id) return;
    const editBtn = event.target.closest('[data-edit-note]');
    if (editBtn) {
      store.editingAgentNoteId = editBtn.dataset.editNote;
      renderAgentNotes(store.editorExistingItem, { autoOpen: false });
      const editInput = $(`[data-edit-note-input="${CSS.escape(store.editingAgentNoteId)}"]`);
      editInput?.focus();
      editInput?.select();
      return;
    }
    const cancelBtn = event.target.closest('[data-cancel-note]');
    if (cancelBtn) {
      store.editingAgentNoteId = null;
      renderAgentNotes(store.editorExistingItem, { autoOpen: false });
      return;
    }
    const saveBtn = event.target.closest('[data-save-note]');
    if (saveBtn) {
      await saveEditedAgentNote(saveBtn.dataset.saveNote);
      return;
    }
    const delBtn = event.target.closest('[data-delete-note]');
    if (delBtn) {
      const noteId = delBtn.dataset.deleteNote;
      store.agentNoteBusy = true;
      renderAgentNotes(store.editorExistingItem, { autoOpen: false });
      try {
        const updated = await api.deleteAgentNote(store.editorExistingItem.id, noteId);
        if (store.editingAgentNoteId === noteId) store.editingAgentNoteId = null;
        window.OpenKeyletAppearance?.play?.('success');
        toast(localized('已删除该条笔记', 'Agent note deleted'));
        applyUpdatedAgentNotesItem(updated);
      } catch (error) {
        toast(cleanError(error), 'error');
      } finally {
        store.agentNoteBusy = false;
        renderAgentNotes(store.editorExistingItem, { autoOpen: false });
      }
    }
  });
  $('#agent-notes-list')?.addEventListener('keydown', (event) => {
    const input = event.target.closest('[data-edit-note-input]');
    if (!input) return;
    if (event.key === 'Enter') {
      event.preventDefault();
      event.stopPropagation();
      saveEditedAgentNote(input.dataset.editNoteInput);
    } else if (event.key === 'Escape') {
      event.preventDefault();
      event.stopPropagation();
      store.editingAgentNoteId = null;
      renderAgentNotes(store.editorExistingItem, { autoOpen: false });
    }
  });

  // Form save
  $('#connection-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = $('#save-connection-button');
    button.disabled = true;
    try {
      const input = serializeItem();
      const pastedClipboard = store.editorSmartClipboardSource;
      const onCandidateSaved = store.editorCandidateOnSaved;
      const savedDraftId = store.currentDraftId;
      await api.save(input);
      if (savedDraftId) {
        await api.deleteDraft(savedDraftId);
        store.editorDrafts = store.editorDrafts.filter((draft) => draft.id !== savedDraftId);
        renderDrafts();
      }
      store.currentDraftId = '';
      closeEditor();
      onCandidateSaved?.();
      let clearedClipboard = false;
      if (pastedClipboard) {
        clearedClipboard = await api.clearClipboardIfMatches(pastedClipboard).catch(() => false);
      }
      window.OpenKeyletAppearance?.play?.('success');
      const remainingDrafts = savedDraftId ? store.editorDrafts.length : 0;
      toast(clearedClipboard
        ? localized('项目已加密保存，并已自动清理剪贴板', 'Item saved and clipboard cleared')
        : remainingDrafts > 0
          ? localized(`项目已加密保存（还有 ${remainingDrafts} 条待处理草稿）`, `Item saved and encrypted · ${remainingDrafts} draft(s) remaining`)
          : localized('项目已加密保存', 'Item saved and encrypted'));
      await hooks.refresh?.();
      await refreshDrafts();
    } catch (error) {
      toast(cleanError(error), 'error');
    } finally {
      button.disabled = false;
    }
  });

  // Smart paste, 2FA attach & TOTP QR file scan
  $('#editor-smart-paste-button')?.addEventListener('click', () => void triggerSmartPasteFromClipboard());

  $('#smart-totp-attach-button')?.addEventListener('click', async () => {
    if (!store.editorSmartTotpUri) return;
    const targetId = $('#smart-totp-target')?.value;
    const item = store.state?.connections?.find((c) => c.id === targetId);
    if (!item) return;
    const btn = $('#smart-totp-attach-button');
    btn.disabled = true;
    try {
      const pastedClipboard = store.editorSmartClipboardSource;
      await api.attachTotpToItem(item.id, store.editorSmartTotpUri, item.updatedAt);
      closeEditor();
      if (pastedClipboard) await api.clearClipboardIfMatches(pastedClipboard).catch(() => false);
      window.OpenKeyletAppearance?.play?.('success');
      toast(localized(`已将 2FA 附加到「${item.name}」`, `Attached 2FA to "${item.name}"`));
      await hooks.refresh?.();
    } catch (error) {
      toast(cleanError(error), 'error');
    } finally {
      btn.disabled = false;
    }
  });

  $('#totp-qr-file-input')?.addEventListener('change', async (event) => {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file || store.pendingTotpQrModuleIndex < 0) return;
    const index = store.pendingTotpQrModuleIndex;
    store.pendingTotpQrModuleIndex = -1;
    try {
      const decoded = await OpenKeyletQR.decode(file);
      const row = $$('#module-list .module-row')[index];
      const input = row && $('[data-secret-value]', row);
      if (input && store.currentModules[index]) {
        input.value = decoded;
        store.currentModules[index].secretValue = decoded;
        toast(localized('已从二维码填充 2FA 密钥', 'Filled 2FA secret from QR image'));
      }
    } catch (error) {
      toast(cleanError(error), 'error');
    }
  });

  document.addEventListener('click', (event) => {
    const scanBtn = event.target.closest('[data-scan-totp-qr]');
    if (!scanBtn) return;
    const row = scanBtn.closest('.module-row');
    if (!row) return;
    store.pendingTotpQrModuleIndex = Number(row.dataset.moduleIndex);
    $('#totp-qr-file-input')?.click();
  });

  window.addEventListener('resize', positionModuleMenu);
  $('.form-scroll', $('#connection-modal')).addEventListener('scroll', positionModuleMenu, { passive: true });
  $('#connections-list').addEventListener('scroll', positionModuleMenu, { passive: true });
}
