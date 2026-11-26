/* Selective .mvault backup import modal and global drag-and-drop file handlers. */
import { $, $$, escapeHtml } from '../core/dom.js';
import { store, hooks } from '../core/store.js';
import { api, listen } from '../core/api.js';
import { cleanError, toast, toastImportSummary } from '../core/feedback.js';
import { itemTypeLabel } from '../core/item-schema.js';
import { localized } from '../i18n/index.js';
import { refreshOwnerLock } from './owner-lock.js';
import { selectPage } from './navigation.js';
import { setModuleMenu } from './editor.js';

export function setGlobalMvaultDropOverlay(visible, options = '') {
  const overlay = $('#global-mvault-drop-overlay');
  if (!overlay) return;
  if (visible) {
    const opts = typeof options === 'string'
      ? { mode: 'mvault', fileNames: options ? [options] : [] }
      : (options || {});
    const mode = opts.mode || 'mvault';
    const fileNames = Array.isArray(opts.fileNames) ? opts.fileNames.filter(Boolean) : [];
    const totalCount = Number(opts.totalCount || fileNames.length || 0);
    const titleEl = $('#global-mvault-drop-title');
    const subEl = $('#global-mvault-drop-subtitle');
    const chipEl = $('#global-mvault-drop-file');
    if (titleEl) {
      if (mode === 'universal') {
        titleEl.textContent = localized('松开即可智能提取并构建项目', 'Drop files to extract & build items');
      } else if (mode === 'mixed') {
        titleEl.textContent = localized('松开即可导入备份并提取文件', 'Drop to import backup & extract files');
      } else if (fileNames.length === 1 && /\.kdbx$/i.test(fileNames[0])) {
        titleEl.textContent = localized('松开即可解锁 KeePass 数据库', 'Drop KeePass database to unlock');
      } else if (fileNames.length === 1 && /\.json$/i.test(fileNames[0])) {
        titleEl.textContent = localized('松开即可解锁 Bitwarden 加密库', 'Drop Bitwarden encrypted vault to unlock');
      } else {
        titleEl.textContent = localized('松开即可导入 .mvault 备份', 'Drop .mvault backup to import');
      }
    }
    if (subEl) {
      if (mode === 'universal') {
        subEl.textContent = localized(
          '支持 Bitwarden / 1Password .1pux / KeePass .kdbx / Excel / Word / ZIP / .env / CSV / 私钥 / 2FA 截图',
          'Supports Bitwarden, 1Password .1pux, KeePass .kdbx, Excel, Word, ZIP, .env, CSV, SSH keys & 2FA QR',
        );
      } else if (mode === 'mixed') {
        subEl.textContent = localized(
          '自动弹窗勾选 .mvault 备份，同时提取其余文件至导入中心',
          'Opens .mvault selector and extracts other files into Import Hub',
        );
      } else {
        subEl.textContent = localized(
          '自动弹窗预览，可勾选需要导入的项目或全选',
          'Opens a preview popup where you can check specific items or select all',
        );
      }
    }
    if (chipEl) {
      let chipText = '';
      if (fileNames.length === 1 && totalCount <= 1) {
        chipText = opts.hasFolder ? `📁 ${fileNames[0]}` : fileNames[0];
      } else if (fileNames.length > 0) {
        const extra = Math.max(0, totalCount - fileNames.length);
        chipText = fileNames.slice(0, 2).join(' · ') + (extra > 0 || fileNames.length > 2 ? ` (+${Math.max(extra, fileNames.length - 2)})` : '');
      }
      chipEl.textContent = chipText;
      chipEl.classList.toggle('hidden', !chipText);
    }
    overlay.classList.remove('hidden');
  } else {
    overlay.classList.add('hidden');
  }
}

export function closeMvaultImportModal(cancelBackend = true) {
  store.mvaultSequence++;
  store.mvaultState = null;
  const modal = $('#mvault-import-modal');
  if (modal) modal.classList.add('hidden');
  const pwInput = $('#mvault-unlock-password');
  if (pwInput) {
    pwInput.value = '';
    pwInput.type = 'password';
  }
  const revealBtn = $('#mvault-unlock-reveal');
  if (revealBtn) revealBtn.textContent = localized('显示', 'SHOW');
  const searchInput = $('#mvault-search-input');
  if (searchInput) searchInput.value = '';
  $('#mvault-unlock-panel')?.classList.add('hidden');
  $('#mvault-loading-panel')?.classList.add('hidden');
  $('#mvault-select-panel')?.classList.add('hidden');
  $('#mvault-unlock-error')?.classList.add('hidden');
  $('#mvault-select-error')?.classList.add('hidden');
  $('#mvault-item-list')?.replaceChildren();
  if (cancelBackend) api.cancelBackupImport().catch(() => {});
}

function mvaultCategoryKey(item) {
  return item.kind === 'trash' ? 'trash' : (item.itemType || 'custom');
}

function mvaultCategoryLabel(key) {
  if (key === 'all') return localized('全部', 'All');
  if (key === 'trash') return localized('回收站', 'Trash');
  return itemTypeLabel(key);
}

function mvaultFilteredItems() {
  if (!store.mvaultState?.items) return [];
  const q = String(store.mvaultState.searchQuery || '').trim().toLowerCase();
  const filter = store.mvaultState.activeTypeFilter || 'all';
  return store.mvaultState.items.filter((item) => {
    if (filter !== 'all' && mvaultCategoryKey(item) !== filter) return false;
    if (!q) return true;
    const hay = [
      item.name,
      item.assignedName || '',
      item.summary || '',
      item.folder || '',
      itemTypeLabel(item.itemType),
      item.kind === 'trash' ? 'trash 回收站' : '',
    ].join(' ').toLowerCase();
    return hay.includes(q);
  });
}

function vaultPackageMeta(packageKind) {
  if (packageKind === 'bitwarden_encrypted') {
    return {
      title: localized('导入 Bitwarden 加密库', 'Import Bitwarden encrypted vault'),
      pill: 'Bitwarden',
      passwordLabel: localized('导出密码', 'Export password'),
      enterPassword: localized('请输入导出密码', 'Enter the export password'),
      unlockHelp: (name) => localized(
        `输入「${name}」导出时设置的保护密码，解密后即可预览并勾选需要导入的项目。`,
        `Enter the export password for "${name}" to decrypt and select items to import.`,
      ),
    };
  }
  if (packageKind === 'keepass_kdbx') {
    return {
      title: localized('导入 KeePass 数据库', 'Import KeePass database'),
      pill: 'KeePass .kdbx',
      passwordLabel: localized('主密码', 'Master password'),
      enterPassword: localized('请输入主密码', 'Enter the master password'),
      unlockHelp: (name) => localized(
        `输入「${name}」的 KeePass 主密码，解密后即可预览并勾选需要导入的项目。`,
        `Enter the KeePass master password for "${name}" to unlock and select items to import.`,
      ),
    };
  }
  return {
    title: localized('导入 .mvault 备份', 'Import .mvault backup'),
    pill: null,
    passwordLabel: localized('备份密码', 'Backup password'),
    enterPassword: localized('请输入备份密码', 'Enter the backup password'),
    unlockHelp: (name) => localized(
      `输入「${name}」创建时设置的备份密码，解密后即可预览并勾选需要导入的项目。`,
      `Enter the backup password for "${name}" to preview and select items to import.`,
    ),
  };
}

function renderMvaultHeader() {
  if (!store.mvaultState) return;
  const meta = vaultPackageMeta(store.mvaultState.packageKind);
  $('#mvault-modal-title').textContent = meta.title;
  $('#mvault-file-name').textContent = store.mvaultState.fileName || 'openkeylet-backup.mvault';
  const formatPill = $('#mvault-format-pill');
  if (meta.pill) {
    formatPill.textContent = meta.pill;
    formatPill.classList.remove('hidden');
  } else if (store.mvaultState.preview) {
    formatPill.textContent = store.mvaultState.preview.protected
      ? `v${store.mvaultState.preview.version}`
      : localized(`旧版 v${store.mvaultState.preview.version}`, `Legacy v${store.mvaultState.preview.version}`);
    formatPill.classList.remove('hidden');
  } else {
    formatPill.textContent = '';
    formatPill.classList.add('hidden');
  }
}

export function renderMvaultUnlockPanel(errorMessage = '') {
  if (!store.mvaultState) return;
  const meta = vaultPackageMeta(store.mvaultState.packageKind);
  renderMvaultHeader();
  $('#mvault-loading-panel').classList.add('hidden');
  $('#mvault-select-panel').classList.add('hidden');
  $('#mvault-unlock-panel').classList.remove('hidden');
  $('#mvault-unlock-help').textContent = meta.unlockHelp(store.mvaultState.fileName);
  $('#mvault-unlock-password-label').textContent = meta.passwordLabel;
  $('#mvault-unlock-cancel').textContent = localized('取消', 'Cancel');
  $('#mvault-unlock-submit').textContent = localized('解锁并预览', 'Unlock & preview');
  $('#mvault-unlock-submit').disabled = false;
  const pwInput = $('#mvault-unlock-password');
  const revealBtn = $('#mvault-unlock-reveal');
  if (revealBtn) {
    revealBtn.textContent = pwInput?.type === 'text' ? localized('隐藏', 'HIDE') : localized('显示', 'SHOW');
  }
  const errEl = $('#mvault-unlock-error');
  if (errorMessage) {
    errEl.textContent = errorMessage;
    errEl.classList.remove('hidden');
  } else {
    errEl.textContent = '';
    errEl.classList.add('hidden');
  }
  requestAnimationFrame(() => {
    pwInput?.focus();
    if (errorMessage) pwInput?.select();
  });
}

function updateMvaultSelectionChrome() {
  const mvaultState = store.mvaultState;
  if (!mvaultState) return;
  const selectAllInput = $('#mvault-select-all');
  const selectAllText = $('#mvault-select-all-text');
  const counterEl = $('#mvault-selection-counter');
  const confirmBtn = $('#mvault-select-confirm');
  const cancelBtn = $('#mvault-select-cancel');
  const hintEl = $('#mvault-footer-hint');
  if (cancelBtn) cancelBtn.textContent = localized('取消', 'Cancel');

  if (!mvaultState.hasItemList) {
    const p = mvaultState.preview || {};
    const count = (p.newItems ?? p.totalItems ?? 0) + (p.trashCount || 0);
    if (selectAllInput) {
      selectAllInput.checked = count > 0;
      selectAllInput.indeterminate = false;
      selectAllInput.disabled = true;
    }
    if (selectAllText) selectAllText.textContent = localized('全选', 'Select all');
    if (counterEl) counterEl.textContent = localized(`共 ${p.totalItems || 0} 项`, `${p.totalItems || 0} items`);
    if (hintEl) hintEl.textContent = localized('同名冲突将自动另存，不覆盖已有项目', 'Conflicts are renamed safely without overwriting');
    if (confirmBtn) {
      const canConfirm = (p.totalItems || 0) > 0 || (p.trashCount || 0) > 0;
      confirmBtn.disabled = !canConfirm || mvaultState.committing;
      confirmBtn.textContent = mvaultState.committing ? localized('正在导入…', 'Importing…') : localized('确认导入', 'Import');
    }
    return;
  }

  const allImportable = mvaultState.items.filter((item) => item.importable);
  const totalSelected = allImportable.filter((item) => item.selected).length;
  const visibleImportable = mvaultFilteredItems().filter((item) => item.importable);
  const visibleSelected = visibleImportable.filter((item) => item.selected).length;
  const isFiltered = (mvaultState.activeTypeFilter && mvaultState.activeTypeFilter !== 'all')
    || Boolean(String(mvaultState.searchQuery || '').trim());

  if (selectAllInput) {
    selectAllInput.disabled = visibleImportable.length === 0;
    selectAllInput.checked = visibleImportable.length > 0 && visibleSelected === visibleImportable.length;
    selectAllInput.indeterminate = visibleSelected > 0 && visibleSelected < visibleImportable.length;
  }
  if (selectAllText) {
    selectAllText.textContent = isFiltered ? localized('全选当前筛选', 'Select visible') : localized('全选', 'Select all');
  }
  if (counterEl) {
    counterEl.textContent = localized(`已选 ${totalSelected} / ${allImportable.length} 项`, `${totalSelected} / ${allImportable.length} selected`);
  }
  if (hintEl) {
    const selectedConflicts = mvaultState.items.filter((i) => i.selected && i.status === 'conflict').length;
    hintEl.textContent = selectedConflicts > 0
      ? localized(`含 ${selectedConflicts} 项同名冲突，将自动另存不覆盖`, `${selectedConflicts} conflict(s) will be safely renamed`)
      : localized('仅导入已勾选项目，不会覆盖已有数据', 'Only checked items are imported; existing items are untouched');
  }
  if (confirmBtn) {
    confirmBtn.disabled = totalSelected === 0 || mvaultState.committing;
    confirmBtn.textContent = mvaultState.committing
      ? localized('正在导入…', 'Importing…')
      : totalSelected > 0 && totalSelected === allImportable.length
        ? localized(`全量导入 (${totalSelected})`, `Import all (${totalSelected})`)
        : localized(`导入所选 (${totalSelected})`, `Import (${totalSelected})`);
  }
}

function renderMvaultItemList() {
  const mvaultState = store.mvaultState;
  if (!mvaultState) return;
  const listEl = $('#mvault-item-list');
  if (!listEl) return;

  if (!mvaultState.hasItemList) {
    const p = mvaultState.preview || {};
    const lines = [
      `${mvaultState.fileName} · ${p.formatLabel || '.mvault'}`,
      localized(
        `共 ${p.totalItems || 0} 项 · 将新增 ${p.newItems || 0} 项 · 跳过相同 ${p.duplicateSkipped || 0} 项 · 同名安全重命名 ${p.nameConflicts || 0} 项`,
        `${p.totalItems || 0} items · ${p.newItems || 0} to add · ${p.duplicateSkipped || 0} identical skipped · ${p.nameConflicts || 0} renamed on conflict`,
      ),
      ...(p.passkeyCount || p.trashCount || p.historyEntries
        ? [localized(
            `含 Passkey ${p.passkeyCount || 0} 个 · 密码历史 ${p.historyEntries || 0} 条 · 回收站 ${p.trashCount || 0} 项`,
            `Includes ${p.passkeyCount || 0} passkeys · ${p.historyEntries || 0} history entries · ${p.trashCount || 0} trashed items`,
          )]
        : []),
      ...(p.sampleNames?.length ? [localized(`示例条目：${p.sampleNames.join('、')}`, `Sample items: ${p.sampleNames.join(', ')}`)] : []),
      ...(p.conflictRenames?.length ? [localized(`同名冲突将自动另存（不覆盖）：${p.conflictRenames.join('；')}`, `Conflicts safely renamed (no overwrite): ${p.conflictRenames.join('; ')}`)] : []),
    ];
    listEl.innerHTML = `<div class="mvault-empty-state" style="text-align:left">${lines.map((line) => `<p style="margin:4px 0">${escapeHtml(line)}</p>`).join('')}</div>`;
    updateMvaultSelectionChrome();
    return;
  }

  const visible = mvaultFilteredItems();
  if (!mvaultState.items.length) {
    listEl.innerHTML = `<div class="mvault-empty-state">${escapeHtml(localized('此备份文件为空，没有可导入的项目。', 'This backup file is empty — no items to import.'))}</div>`;
    updateMvaultSelectionChrome();
    return;
  }
  if (!visible.length) {
    listEl.innerHTML = `<div class="mvault-empty-state">${escapeHtml(localized('当前筛选或搜索条件下没有匹配的项目。', 'No items match the current search or filter.'))}</div>`;
    updateMvaultSelectionChrome();
    return;
  }

  listEl.innerHTML = visible.map((item) => {
    const isDup = !item.importable;
    const rowClasses = ['mvault-item-row', isDup ? 'is-duplicate' : (item.selected ? 'is-selected' : 'is-unchecked')].join(' ');
    const statusBadge = item.status === 'duplicate'
      ? `<span class="mvault-item-status is-dup" title="${escapeHtml(localized('当前密码库中已存在完全相同的条目', 'An identical item already exists in your vault'))}">${escapeHtml(localized('已存在', 'EXISTS'))}</span>`
      : item.status === 'conflict'
        ? `<span class="mvault-item-status is-conflict" title="${escapeHtml(localized('已有同名条目，导入时将自动另存不覆盖', 'Name conflict — will be renamed safely without overwriting'))}">${escapeHtml(localized('同名另存', 'RENAME'))}</span>`
        : `<span class="mvault-item-status is-new">${escapeHtml(localized('新增', 'NEW'))}</span>`;
    const metaChips = [];
    if (item.kind === 'trash') metaChips.push(`<span class="mvault-meta-chip is-trash">${escapeHtml(localized('回收站', 'Trash'))}</span>`);
    if (item.folder) metaChips.push(`<span class="mvault-meta-chip">${escapeHtml(item.folder)}</span>`);
    if (item.passkeyCount > 0) metaChips.push(`<span class="mvault-meta-chip">${escapeHtml(`Passkey ×${item.passkeyCount}`)}</span>`);
    if (item.historyCount > 0) metaChips.push(`<span class="mvault-meta-chip">${escapeHtml(localized(`历史 ${item.historyCount}`, `History ${item.historyCount}`))}</span>`);
    const subParts = [];
    if (item.assignedName) subParts.push(`<span class="mvault-item-rename">→ ${escapeHtml(item.assignedName)}</span>`);
    if (item.summary) subParts.push(`<span class="mvault-item-summary">${escapeHtml(item.summary)}</span>`);
    const subHtml = (subParts.length || metaChips.length) ? `<div class="mvault-item-sub">${subParts.join('')}${metaChips.join('')}</div>` : '';
    return `
      <label class="${rowClasses}" role="listitem" data-mvault-row="${escapeHtml(item.key)}">
        <input type="checkbox" class="mvault-checkbox" data-mvault-check="${escapeHtml(item.key)}" ${item.selected ? 'checked' : ''} ${isDup ? 'disabled' : ''} aria-label="${escapeHtml(item.name)}" />
        <div class="mvault-item-body">
          <div class="mvault-item-head">
            <span class="mvault-item-type">${escapeHtml(itemTypeLabel(item.itemType))}</span>
            <span class="mvault-item-name" title="${escapeHtml(item.name)}">${escapeHtml(item.name)}</span>
            ${statusBadge}
          </div>
          ${subHtml}
        </div>
      </label>
    `;
  }).join('');

  updateMvaultSelectionChrome();
}

const packageWarningCopy = {
  nonWebUris: ['非网页地址已保留，设为“不匹配”。', 'Non-web addresses are preserved with matching disabled.'],
  defaultDomainMatch: ['未指定规则的网址使用主域名匹配。', 'Unspecified URL rules use base-domain matching.'],
  unsupportedTotp: ['部分验证码密钥格式暂不支持生成，原始密钥已保留。', 'Some TOTP formats cannot generate codes yet; original keys are preserved.'],
  passkeyCounter: ['包含旧版计数型 Passkey，导入后请仅在 OpenKeylet 使用。', 'Includes counter-based passkeys; use them only in OpenKeylet after migration.'],
  linkedFields: ['关联字段已作为加密自定义字段保留。', 'Linked fields are preserved as encrypted custom fields.'],
  passwordHistory: ['最近 20 条旧密码进入密码历史。', 'The latest 20 previous passwords appear in history.'],
  reprompt: ['原逐项主密码验证不生效，本地 PIN 锁仍适用。', 'Per-item master-password reprompt is not applied; local PIN lock still applies.'],
  attachments: ['导出包不含文件附件内容，请从原密码库单独保留附件。', 'Attachments are not imported; keep attachment files separately from the source vault.'],
  organization: ['组织项目将转为本地个人项目。', 'Organization items become local personal items.'],
};

export function renderMvaultSelectPanel() {
  const mvaultState = store.mvaultState;
  if (!mvaultState || !mvaultState.preview) return;
  renderMvaultHeader();
  $('#mvault-unlock-panel').classList.add('hidden');
  $('#mvault-loading-panel').classList.add('hidden');
  $('#mvault-select-panel').classList.remove('hidden');

  const p = mvaultState.preview;
  const statsEl = $('#mvault-stats-strip');
  const pills = [];
  const totalCount = mvaultState.hasItemList ? mvaultState.items.length : (p.totalItems || 0);
  pills.push(`<span class="mvault-stat-pill">${escapeHtml(localized(`共 ${totalCount} 项`, `${totalCount} total`))}</span>`);
  if ((p.newItems || 0) > 0) pills.push(`<span class="mvault-stat-pill is-new">${escapeHtml(localized(`可新增 ${p.newItems}`, `${p.newItems} new`))}</span>`);
  if ((p.nameConflicts || 0) > 0) pills.push(`<span class="mvault-stat-pill is-conflict">${escapeHtml(localized(`同名另存 ${p.nameConflicts}`, `${p.nameConflicts} rename`))}</span>`);
  if ((p.duplicateSkipped || 0) > 0) pills.push(`<span class="mvault-stat-pill is-dup">${escapeHtml(localized(`已存在 ${p.duplicateSkipped}`, `${p.duplicateSkipped} existing`))}</span>`);
  if ((p.trashCount || 0) > 0) pills.push(`<span class="mvault-stat-pill">${escapeHtml(localized(`回收站 ${p.trashCount}`, `${p.trashCount} trash`))}</span>`);
  if ((mvaultState.skippedDeleted || 0) > 0) pills.push(`<span class="mvault-stat-pill is-dup">${escapeHtml(localized(`已跳过回收站 ${mvaultState.skippedDeleted}`, `${mvaultState.skippedDeleted} deleted skipped`))}</span>`);
  statsEl.innerHTML = pills.join('');

  const legacyNote = $('#mvault-legacy-note');
  const notices = [];
  if (!p.protected) {
    notices.push(localized(
      '安全提示：此文件为旧版无密码自解锁 .mvault，文件内含解锁密钥。导入后建议删除旧文件并重新导出带密码保护的备份。',
      'Security note: This is a legacy self-unlocking .mvault containing its own unlock key. Delete the old file after importing and export a password-protected backup.',
    ));
  }
  if (Array.isArray(mvaultState.warnings) && mvaultState.warnings.length > 0) {
    for (const code of mvaultState.warnings) {
      notices.push(packageWarningCopy[code] ? localized(...packageWarningCopy[code]) : String(code));
    }
  }
  if (notices.length > 0) {
    legacyNote.textContent = notices.join(' ');
    legacyNote.classList.remove('hidden');
  } else {
    legacyNote.textContent = '';
    legacyNote.classList.add('hidden');
  }

  const searchInput = $('#mvault-search-input');
  if (searchInput) {
    searchInput.placeholder = localized('搜索备份中的项目…', 'Search items in backup…');
    searchInput.parentElement?.classList.toggle('hidden', !mvaultState.hasItemList || mvaultState.items.length === 0);
  }

  const typePillsEl = $('#mvault-type-pills');
  if (typePillsEl) {
    if (mvaultState.hasItemList && mvaultState.items.length > 0) {
      const counts = new Map();
      for (const item of mvaultState.items) {
        const key = mvaultCategoryKey(item);
        counts.set(key, (counts.get(key) || 0) + 1);
      }
      if (counts.size > 1) {
        const keys = ['all', ...counts.keys()];
        typePillsEl.innerHTML = keys.map((key) => {
          const count = key === 'all' ? mvaultState.items.length : counts.get(key);
          const active = mvaultState.activeTypeFilter === key ? 'active' : '';
          return `<button type="button" class="mvault-type-pill ${active}" data-mvault-filter="${escapeHtml(key)}">${escapeHtml(mvaultCategoryLabel(key))} ${count}</button>`;
        }).join('');
        typePillsEl.classList.remove('hidden');
      } else {
        typePillsEl.innerHTML = '';
        typePillsEl.classList.add('hidden');
      }
    } else {
      typePillsEl.innerHTML = '';
      typePillsEl.classList.add('hidden');
    }
  }

  const selectErrorEl = $('#mvault-select-error');
  if (selectErrorEl) {
    selectErrorEl.textContent = '';
    selectErrorEl.classList.add('hidden');
  }

  renderMvaultItemList();
}

async function unlockAndPreviewMvault(password) {
  if (!store.mvaultState) return;
  const sequence = store.mvaultSequence;
  const submitBtn = $('#mvault-unlock-submit');
  if (submitBtn) submitBtn.disabled = true;
  $('#mvault-unlock-error')?.classList.add('hidden');
  $('#mvault-loading-text').textContent = localized('正在解密并分析备份内容…', 'Decrypting & analyzing backup…');
  $('#mvault-unlock-panel').classList.add('hidden');
  $('#mvault-select-panel').classList.add('hidden');
  $('#mvault-loading-panel').classList.remove('hidden');

  try {
    const result = await api.prepareBackupImport(password);
    if (!result || sequence !== store.mvaultSequence || !store.mvaultState) return;
    const pwInput = $('#mvault-unlock-password');
    if (pwInput) pwInput.value = '';
    store.mvaultState.id = result.id;
    store.mvaultState.preview = result.preview;
    store.mvaultState.warnings = Array.isArray(result.warnings) ? result.warnings : [];
    store.mvaultState.skippedDeleted = Number(result.skippedDeleted || 0);
    const rawItems = result.preview?.items;
    if (Array.isArray(rawItems)) {
      store.mvaultState.hasItemList = true;
      store.mvaultState.items = rawItems.map((item) => {
        const importable = item.status !== 'duplicate';
        return {
          key: `${item.kind || 'item'}:${item.index}`,
          index: item.index,
          kind: item.kind || 'item',
          id: item.id || '',
          name: item.name || localized('未命名项目', 'Untitled'),
          itemType: item.itemType || 'custom',
          folder: item.folder || '',
          summary: item.summary || '',
          status: item.status || 'new',
          assignedName: item.assignedName || null,
          passkeyCount: Number(item.passkeyCount || 0),
          historyCount: Number(item.historyCount || 0),
          deletedAt: item.deletedAt || null,
          importable,
          selected: importable,
        };
      });
    } else {
      store.mvaultState.hasItemList = false;
      store.mvaultState.items = [];
    }
    renderMvaultSelectPanel();
  } catch (error) {
    if (sequence !== store.mvaultSequence || !store.mvaultState) return;
    const message = cleanError(error);
    if (store.mvaultState.requiresPassword) {
      renderMvaultUnlockPanel(message);
    } else {
      closeMvaultImportModal(true);
      toast(message, 'error');
    }
  }
}

export async function openMvaultPreviewFlow(picked) {
  if (!picked) return;
  setModuleMenu(false);
  if (!$('#migration-modal')?.classList.contains('hidden')) {
    hooks.resetMigration?.();
    $('#migration-modal').classList.add('hidden');
  }
  store.mvaultSequence++;
  store.mvaultState = {
    fileName: picked.fileName || 'openkeylet-backup.mvault',
    packageKind: picked.packageKind || 'mvault',
    requiresPassword: Boolean(picked.requiresPassword),
    id: null,
    preview: null,
    warnings: [],
    skippedDeleted: 0,
    items: [],
    hasItemList: false,
    activeTypeFilter: 'all',
    searchQuery: '',
    committing: false,
  };
  const pwInput = $('#mvault-unlock-password');
  if (pwInput) {
    pwInput.value = '';
    pwInput.type = 'password';
  }
  const searchInput = $('#mvault-search-input');
  if (searchInput) searchInput.value = '';
  $('#mvault-import-modal').classList.remove('hidden');

  if (store.mvaultState.requiresPassword) {
    renderMvaultUnlockPanel('');
  } else {
    renderMvaultHeader();
    await unlockAndPreviewMvault('');
  }
}

async function fileToBase64(file) {
  const buf = await file.arrayBuffer();
  const bytes = new Uint8Array(buf);
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export async function handleDroppedMvaultFile(file) {
  if (!file) return;
  await refreshOwnerLock();
  if (!store.ownerLockState.unlocked) {
    toast(localized('请先解锁密码库后再拖入 .mvault 备份', 'Unlock OpenKeylet first before dropping a .mvault backup'), 'error');
    return;
  }
  if (file.size > 64 * 1024 * 1024) {
    toast(localized('备份文件超过 64 MiB 限制', 'Backup file exceeds the 64 MiB limit'), 'error');
    return;
  }
  try {
    const isBinaryPackage = /\.kdbx$/i.test(file.name || '');
    const picked = isBinaryPackage
      ? await api.inspectDroppedBackupBytes(file.name || 'database.kdbx', await fileToBase64(file), true)
      : await api.inspectDroppedBackupBytes(file.name || 'openkeylet-backup.mvault', await file.text());
    if (!picked) return;
    await openMvaultPreviewFlow(picked);
  } catch (error) {
    toast(cleanError(error), 'error');
  }
}

export function initMvaultImportView() {
  $('#mvault-modal-close')?.addEventListener('click', () => closeMvaultImportModal(true));
  $('#mvault-unlock-cancel')?.addEventListener('click', () => closeMvaultImportModal(true));
  $('#mvault-select-cancel')?.addEventListener('click', () => closeMvaultImportModal(true));

  $('#mvault-unlock-reveal')?.addEventListener('click', () => {
    const input = $('#mvault-unlock-password');
    const btn = $('#mvault-unlock-reveal');
    if (!input || !btn) return;
    const showing = input.type === 'text';
    input.type = showing ? 'password' : 'text';
    btn.textContent = showing ? localized('显示', 'SHOW') : localized('隐藏', 'HIDE');
    input.focus();
  });

  $('#mvault-unlock-panel')?.addEventListener('submit', (event) => {
    event.preventDefault();
    if (!store.mvaultState) return;
    const password = $('#mvault-unlock-password')?.value || '';
    if (!password) {
      const meta = vaultPackageMeta(store.mvaultState.packageKind);
      renderMvaultUnlockPanel(meta.enterPassword);
      return;
    }
    void unlockAndPreviewMvault(password);
  });

  $('#mvault-search-input')?.addEventListener('input', (event) => {
    if (!store.mvaultState) return;
    store.mvaultState.searchQuery = event.currentTarget.value || '';
    renderMvaultItemList();
  });

  $('#mvault-type-pills')?.addEventListener('click', (event) => {
    const pill = event.target.closest('[data-mvault-filter]');
    if (!pill || !store.mvaultState) return;
    store.mvaultState.activeTypeFilter = pill.dataset.mvaultFilter || 'all';
    for (const btn of $$('#mvault-type-pills [data-mvault-filter]')) {
      btn.classList.toggle('active', btn.dataset.mvaultFilter === store.mvaultState.activeTypeFilter);
    }
    renderMvaultItemList();
  });

  $('#mvault-select-all')?.addEventListener('change', (event) => {
    if (!store.mvaultState?.hasItemList) return;
    const checked = Boolean(event.currentTarget.checked);
    for (const item of mvaultFilteredItems()) {
      if (item.importable) item.selected = checked;
    }
    renderMvaultItemList();
  });

  $('#mvault-item-list')?.addEventListener('change', (event) => {
    const checkbox = event.target.closest('[data-mvault-check]');
    if (!checkbox || !store.mvaultState?.hasItemList) return;
    const key = checkbox.dataset.mvaultCheck;
    const item = store.mvaultState.items.find((entry) => entry.key === key);
    if (!item || !item.importable) return;
    item.selected = Boolean(checkbox.checked);
    const row = checkbox.closest('[data-mvault-row]');
    if (row) {
      row.classList.toggle('is-selected', item.selected);
      row.classList.toggle('is-unchecked', !item.selected);
    }
    updateMvaultSelectionChrome();
  });

  $('#mvault-select-confirm')?.addEventListener('click', async () => {
    if (!store.mvaultState?.id || store.mvaultState.committing) return;
    const sequence = store.mvaultSequence;
    store.mvaultState.committing = true;
    $('#mvault-select-error')?.classList.add('hidden');
    updateMvaultSelectionChrome();
    try {
      let result;
      if (store.mvaultState.hasItemList) {
        const selectedItemIndices = store.mvaultState.items
          .filter((item) => item.kind === 'item' && item.selected)
          .map((item) => item.index);
        const selectedTrashIndices = store.mvaultState.items
          .filter((item) => item.kind === 'trash' && item.selected)
          .map((item) => item.index);
        if (!selectedItemIndices.length && !selectedTrashIndices.length) {
          store.mvaultState.committing = false;
          updateMvaultSelectionChrome();
          return;
        }
        result = await api.commitBackupImport(store.mvaultState.id, selectedItemIndices, selectedTrashIndices);
      } else {
        result = await api.commitBackupImport(store.mvaultState.id);
      }
      if (sequence !== store.mvaultSequence) return;
      closeMvaultImportModal(false);
      window.OpenKeyletAppearance?.play?.('success');
      toastImportSummary(result);
      if (store.activePage === 'import') store.importHub?.notifyExternalImportDone?.(result);
      await hooks.refresh?.();
    } catch (error) {
      if (sequence !== store.mvaultSequence || !store.mvaultState) return;
      store.mvaultState.committing = false;
      const errEl = $('#mvault-select-error');
      if (errEl) {
        errEl.textContent = cleanError(error);
        errEl.classList.remove('hidden');
      }
      updateMvaultSelectionChrome();
    }
  });

  // Global HTML5 + native Tauri drag-and-drop listeners
  let dragDepth = 0;
  const overlay = $('#smart-drop-overlay');
  const isFileDrag = (event) => Array.from(event.dataTransfer?.types || []).includes('Files');
  const splitTransferredFiles = (dt) => {
    const files = Array.from(dt?.files || []);
    const mvaultFiles = files.filter((f) => /\.(mvault|kdbx)$/i.test(f?.name || ''));
    const otherFiles = files.filter((f) => !/\.(mvault|kdbx)$/i.test(f?.name || ''));
    return { files, mvaultFiles, otherFiles };
  };

  document.addEventListener('dragenter', (event) => {
    if (!isFileDrag(event)) return;
    event.preventDefault();
    dragDepth++;
    const { files, mvaultFiles, otherFiles } = splitTransferredFiles(event.dataTransfer);
    if (mvaultFiles.length && otherFiles.length) {
      overlay?.classList.add('hidden');
      setGlobalMvaultDropOverlay(true, { mode: 'mixed', fileNames: files.slice(0, 3).map((f) => f.name), totalCount: files.length });
      return;
    }
    if (mvaultFiles.length) {
      overlay?.classList.add('hidden');
      setGlobalMvaultDropOverlay(true, { mode: 'mvault', fileNames: [mvaultFiles[0].name], totalCount: mvaultFiles.length });
      return;
    }
    if (!store.ownerLockState?.unlocked) return;
    if (store.activePage !== 'import') {
      overlay?.classList.add('hidden');
      setGlobalMvaultDropOverlay(true, { mode: 'universal', fileNames: otherFiles.slice(0, 3).map((f) => f.name), totalCount: otherFiles.length });
    }
  });
  document.addEventListener('dragover', (event) => {
    if (!isFileDrag(event)) return;
    event.preventDefault();
    if (event.dataTransfer) event.dataTransfer.dropEffect = 'copy';
  });
  document.addEventListener('dragleave', (event) => {
    if (!isFileDrag(event)) return;
    dragDepth = Math.max(0, dragDepth - 1);
    if (dragDepth === 0) {
      overlay?.classList.add('hidden');
      setGlobalMvaultDropOverlay(false);
    }
  });
  document.addEventListener('drop', async (event) => {
    if (!isFileDrag(event)) return;
    event.preventDefault();
    dragDepth = 0;
    overlay?.classList.add('hidden');
    setGlobalMvaultDropOverlay(false);
    const { mvaultFiles, otherFiles } = splitTransferredFiles(event.dataTransfer);
    if (otherFiles.length) {
      await refreshOwnerLock();
      if (!store.ownerLockState?.unlocked) {
        toast(localized('请先解锁密码库后再拖入文件', 'Unlock OpenKeylet first before dropping files'), 'error');
      } else {
        if (store.activePage !== 'import') await selectPage('import');
        await store.importHub?.handleFiles?.(otherFiles);
      }
    }
    if (mvaultFiles.length) await handleDroppedMvaultFile(mvaultFiles[0]);
  });

  listen('native-file-drag', (event) => {
    const payload = event?.payload || {};
    if (payload.state === 'enter' && (payload.hasMvault || Number(payload.otherCount || 0) > 0)) {
      overlay?.classList.add('hidden');
      const mode = payload.hasMvault && Number(payload.otherCount || 0) > 0
        ? 'mixed'
        : payload.hasMvault
          ? 'mvault'
          : 'universal';
      setGlobalMvaultDropOverlay(true, {
        mode,
        fileNames: Array.isArray(payload.fileNames) ? payload.fileNames : [],
        totalCount: Number(payload.totalCount || 0),
        hasFolder: Boolean(payload.hasFolder),
      });
    } else {
      setGlobalMvaultDropOverlay(false);
    }
  });

  listen('native-files-dropped', async (event) => {
    const payload = event?.payload || {};
    overlay?.classList.add('hidden');
    setGlobalMvaultDropOverlay(false);
    if (payload.locked) {
      toast(localized('请先解锁密码库后再拖入文件', 'Unlock OpenKeylet first before dropping files'), 'error');
      await refreshOwnerLock(false);
      return;
    }
    if (payload.error) {
      toast(cleanError(payload.error), 'error');
      return;
    }
    if (store.activePage !== 'import') await selectPage('import');
    await store.importHub?.handleNativeDropPayload?.(payload);
  });

  listen('mvault-file-dropped', async (event) => {
    const payload = event?.payload || {};
    overlay?.classList.add('hidden');
    setGlobalMvaultDropOverlay(false);
    if (payload.locked) {
      toast(localized('请先解锁密码库后再拖入 .mvault 备份', 'Unlock OpenKeylet first before dropping a .mvault backup'), 'error');
      await refreshOwnerLock(false);
      return;
    }
    if (payload.error) {
      toast(cleanError(payload.error), 'error');
      return;
    }
    if (payload.fileName) {
      await openMvaultPreviewFlow({
        fileName: payload.fileName,
        requiresPassword: Boolean(payload.requiresPassword),
        packageKind: payload.packageKind || 'mvault',
      });
    }
  });
}
