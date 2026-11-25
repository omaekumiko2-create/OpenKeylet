/* Version history of the encrypted cloud snapshot: pick a version, compare it with this
   vault, restore chosen items. The item step reuses the .mvault selection preview markup.
   Restoring never deletes anything, so only items that differ from this vault can be picked. */
import { escapeHtml, trapFocusInContainer } from '../core/dom.js';
import { itemTypeLabel } from '../core/item-schema.js';

const STATUS_ORDER = { changed: 0, deleted: 1, trash: 2, same: 3 };

export function createCloudHistory({ invoke, localized, toast, confirmAction, errorText, repository, onRestored }) {
  const $ = (id) => document.getElementById(id);
  const modal = $('github-history-modal');
  let view = null;
  // Bumped on every open and close so a late reply never lands in a newer view.
  let sequence = 0;
  let previousFocus = null;

  const isOpen = () => Boolean(modal) && !modal.classList.contains('hidden');

  function dateText(value) {
    const date = value ? new Date(value) : null;
    if (!date || Number.isNaN(date.getTime())) return localized('日期未知', 'Unknown date');
    return date.toLocaleString(document.documentElement.lang || undefined, {
      year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    });
  }

  function unreadableText(reason) {
    if (reason === 'GITHUB_KEY_MISMATCH') return localized('此版本使用了不同的密钥加密，无法打开。', 'This version was encrypted with a different key and cannot be opened.');
    if (reason === 'GITHUB_BACKUP_MISSING') return localized('此版本中没有快照文件。', 'This version holds no snapshot.');
    return localized('此版本不是可读取的加密快照。', 'This version is not a readable encrypted snapshot.');
  }

  function statusBadge(status) {
    const label = {
      changed: localized('已变更', 'CHANGED'),
      deleted: localized('已删除', 'DELETED'),
      trash: localized('在回收站', 'IN TRASH'),
      same: localized('相同', 'SAME'),
    }[status] || status;
    return `<span class="mvault-item-status ${status === 'same' ? 'is-dup' : 'is-conflict'}">${escapeHtml(label)}</span>`;
  }

  function showStep(step) {
    $('github-history-list-panel').classList.toggle('hidden', step !== 'list');
    $('github-history-loading').classList.toggle('hidden', step !== 'loading');
    $('github-history-select-panel').classList.toggle('hidden', step !== 'select');
  }

  function renderHeader() {
    $('github-history-title').textContent = localized('版本历史', 'Version history');
    $('github-history-close').setAttribute('aria-label', localized('关闭', 'Close'));
    const repo = repository() || '';
    $('github-history-repository').textContent = repo;
    $('github-history-repository').classList.toggle('hidden', !repo);
    const pill = $('github-history-version');
    const sha = view?.step === 'select' ? view.prepared?.sha : '';
    pill.textContent = sha ? sha.slice(0, 7) : '';
    pill.title = sha || '';
    pill.classList.toggle('hidden', !sha);
  }

  function renderList() {
    $('github-history-help').textContent = localized(
      '每次改变密码库的同步都会留下一个版本。选择一个版本，与当前密码库对比后，恢复你勾选的项目。',
      'Every sync that changed the vault left a version. Pick one to compare it with this vault and restore the items you choose.',
    );
    const list = $('github-history-versions');
    if (!view.versions.length) {
      const text = view.loadingList ? localized('正在读取版本…', 'Loading versions…') : localized('尚无历史版本。', 'No versions yet.');
      list.innerHTML = `<p class="github-history-empty">${escapeHtml(text)}</p>`;
    } else {
      list.innerHTML = view.versions.map((version) => {
        const reason = view.unreadable.get(version.sha);
        const badge = reason
          ? `<span class="github-history-badge is-unreadable">${escapeHtml(localized('无法读取', 'UNREADABLE'))}</span>`
          : version.isHead ? `<span class="github-history-badge is-current">${escapeHtml(localized('当前', 'CURRENT'))}</span>` : '';
        return `<button type="button" class="github-history-version" data-history-sha="${escapeHtml(version.sha)}" title="${escapeHtml(version.sha)}" ${reason ? 'disabled' : ''}>`
          + `<span class="github-history-date">${escapeHtml(dateText(version.committedAt))}</span>`
          + `<span class="github-history-sha">${escapeHtml(version.sha.slice(0, 7))}</span>${badge}</button>`;
      }).join('');
    }
    const message = view.listError ? errorText(view.listError) : view.rowError ? unreadableText(view.rowError) : '';
    $('github-history-error').textContent = message;
    $('github-history-error').classList.toggle('hidden', !message);
    $('github-history-list-hint').textContent = localized('恢复不会删除任何项目，也不会改写历史。', 'Restoring never deletes items or rewrites history.');
    const more = $('github-history-more');
    more.classList.toggle('hidden', !view.hasMore);
    more.disabled = view.loadingList;
    more.textContent = view.loadingList ? localized('正在读取…', 'Loading…') : localized('加载更多', 'Load more');
    $('github-history-done').textContent = localized('关闭', 'Close');
  }

  function selectableItems() {
    return view.items.filter((item) => item.selectable);
  }

  function renderSelectionChrome() {
    const selectable = selectableItems();
    const selected = selectable.filter((item) => item.selected).length;
    const all = $('github-history-select-all');
    all.disabled = selectable.length === 0 || view.committing;
    all.checked = selectable.length > 0 && selected === selectable.length;
    all.indeterminate = selected > 0 && selected < selectable.length;
    $('github-history-select-all-text').textContent = localized('全选差异项', 'Select all changes');
    $('github-history-counter').textContent = `${selected} / ${selectable.length}`;
    $('github-history-footer-hint').textContent = selectable.length
      ? localized('勾选的项目将作为新的修改恢复并同步到其他设备；之后新建的项目会保留。', 'Checked items come back as new edits and sync to your other devices. Items created later are kept.')
      : localized('此版本与当前密码库没有差异。', 'Nothing in this version differs from this vault.');
    const restore = $('github-history-restore');
    restore.disabled = selected === 0 || view.committing;
    restore.textContent = view.committing ? localized('正在恢复…', 'Restoring…') : `${localized('恢复所选', 'Restore')} (${selected})`;
    const back = $('github-history-back');
    back.textContent = localized('返回', 'Back');
    back.disabled = view.committing;
  }

  function renderSelect() {
    const preview = view.prepared.preview;
    const pills = [[localized('项目', 'Items'), preview.totalItems, '']];
    if (preview.changed) pills.push([localized('已变更', 'Changed'), preview.changed, 'is-conflict']);
    if (preview.deleted) pills.push([localized('已删除', 'Deleted'), preview.deleted, 'is-conflict']);
    if (preview.inTrash) pills.push([localized('在回收站', 'In trash'), preview.inTrash, 'is-conflict']);
    if (preview.same) pills.push([localized('相同', 'Same'), preview.same, 'is-dup']);
    $('github-history-stats').innerHTML = pills
      .map(([label, count, tone]) => `<span class="mvault-stat-pill ${tone}">${escapeHtml(label)} ${count}</span>`)
      .join('');
    const list = $('github-history-items');
    if (!view.items.length) {
      list.innerHTML = `<div class="mvault-empty-state">${escapeHtml(localized('此版本中没有项目。', 'This version has no items.'))}</div>`;
    } else {
      list.innerHTML = view.items.map((item) => {
        const rowState = !item.selectable ? 'is-duplicate' : item.selected ? 'is-selected' : 'is-unchecked';
        const sub = [];
        if (item.assignedName) sub.push(`<span class="mvault-item-rename">→ ${escapeHtml(item.assignedName)}</span>`);
        if (item.summary) sub.push(`<span class="mvault-item-summary">${escapeHtml(item.summary)}</span>`);
        if (item.currentName) sub.push(`<span class="mvault-meta-chip">${escapeHtml(localized('当前名称', 'Current name'))} · ${escapeHtml(item.currentName)}</span>`);
        if (item.folder) sub.push(`<span class="mvault-meta-chip">${escapeHtml(item.folder)}</span>`);
        if (item.passkeyCount > 0) sub.push(`<span class="mvault-meta-chip">${escapeHtml(`Passkey ×${item.passkeyCount}`)}</span>`);
        return `<label class="mvault-item-row ${rowState}" role="listitem" data-history-row="${escapeHtml(item.id)}">`
          + `<input type="checkbox" class="mvault-checkbox" data-history-check="${escapeHtml(item.id)}" ${item.selected ? 'checked' : ''} ${item.selectable && !view.committing ? '' : 'disabled'} aria-label="${escapeHtml(item.name)}" />`
          + '<div class="mvault-item-body"><div class="mvault-item-head">'
          + `<span class="mvault-item-type">${escapeHtml(itemTypeLabel(item.itemType))}</span>`
          + `<span class="mvault-item-name" title="${escapeHtml(item.name)}">${escapeHtml(item.name)}</span>${statusBadge(item.status)}</div>`
          + (sub.length ? `<div class="mvault-item-sub">${sub.join('')}</div>` : '')
          + '</div></label>';
      }).join('');
    }
    const message = view.selectError ? errorText(view.selectError) : '';
    $('github-history-select-error').textContent = message;
    $('github-history-select-error').classList.toggle('hidden', !message);
    renderSelectionChrome();
  }

  function render() {
    if (!view || !isOpen()) return;
    renderHeader();
    showStep(view.step);
    if (view.step === 'list') renderList();
    else if (view.step === 'loading') $('github-history-loading-text').textContent = localized('正在拉取并解密此版本…', 'Fetching and decrypting this version…');
    else renderSelect();
  }

  async function loadPage(page) {
    const current = sequence;
    view.loadingList = true;
    view.listError = '';
    render();
    try {
      const result = await invoke('github_backup_history', { page });
      if (current !== sequence || !view) return;
      const known = new Set(view.versions.map((version) => version.sha));
      for (const version of result?.versions || []) {
        if (!known.has(version.sha)) view.versions.push(version);
      }
      view.page = result?.page || page;
      view.hasMore = Boolean(result?.hasMore);
    } catch (error) {
      if (current !== sequence || !view) return;
      view.listError = error;
    } finally {
      if (current === sequence && view) {
        view.loadingList = false;
        render();
      }
    }
  }

  async function pick(sha) {
    if (!view || view.step !== 'list' || view.unreadable.has(sha)) return;
    const current = sequence;
    view.step = 'loading';
    view.rowError = '';
    view.listError = '';
    render();
    try {
      const result = await invoke('github_backup_history_prepare', { sha });
      if (current !== sequence || !view) return;
      if (result?.unreadable) {
        view.unreadable.set(sha, result.reason || 'GITHUB_BACKUP_INVALID');
        view.rowError = result.reason || 'GITHUB_BACKUP_INVALID';
        view.step = 'list';
        render();
        $(`github-history-versions`)?.querySelector('button:not(:disabled)')?.focus();
        return;
      }
      view.prepared = { id: result.id, sha: result.sha || sha, preview: result.preview || { items: [] } };
      view.items = (view.prepared.preview.items || [])
        .map((item) => ({ ...item, selectable: item.status !== 'same', selected: false }))
        .sort((a, b) => (STATUS_ORDER[a.status] ?? 9) - (STATUS_ORDER[b.status] ?? 9));
      view.selectError = '';
      view.step = 'select';
      render();
      $('github-history-items').scrollTop = 0;
      ($('github-history-select-all').disabled ? $('github-history-back') : $('github-history-select-all')).focus();
    } catch (error) {
      if (current !== sequence || !view) return;
      view.step = 'list';
      view.listError = error;
      render();
    }
  }

  function backToList() {
    if (!view || view.committing) return;
    view.step = 'list';
    view.prepared = null;
    view.items = [];
    invoke('github_backup_history_cancel').catch(() => {});
    render();
    $('github-history-versions').querySelector('button:not(:disabled)')?.focus();
  }

  async function restore() {
    if (!view?.prepared || view.committing) return;
    const ids = selectableItems().filter((item) => item.selected).map((item) => item.id);
    if (!ids.length) return;
    const current = sequence;
    const accepted = await confirmAction({
      title: localized('恢复所选项目？', 'Restore selected items?'),
      message: localized(
        '会先同步一次，当前状态将作为最新版本保留在历史中，可随时恢复回来。随后所选项目作为新的修改恢复，并在所有设备上替换其当前内容。',
        'This device syncs first, so the current state stays in the history as the newest version you can return to. The selected items then come back as new edits and replace their current values on every device.',
      ),
      acceptLabel: localized('恢复', 'RESTORE'),
      tag: localized('版本历史', 'VERSION HISTORY'),
    });
    if (!accepted || current !== sequence || !view?.prepared) return;
    view.committing = true;
    view.selectError = '';
    render();
    try {
      const result = await invoke('github_backup_history_commit', { id: view.prepared.id, selectedIds: ids });
      if (current !== sequence) return;
      close(false);
      window.OpenKeyletAppearance?.play?.('success');
      const restored = Number(result?.summary?.restored || 0);
      toast(restored
        ? `${localized('已从历史版本恢复', 'Restored from history')} · ${restored}`
        : localized('无需恢复：所选项目已与该版本一致。', 'Nothing to restore: the selected items already match this version.'));
      await onRestored(result);
    } catch (error) {
      if (current !== sequence || !view) return;
      view.committing = false;
      if (/GITHUB_HISTORY_EXPIRED/.test(String(error?.message || error))) {
        view.step = 'list';
        view.prepared = null;
        view.items = [];
        view.listError = error;
      } else {
        view.selectError = error;
      }
      render();
    }
  }

  function open() {
    if (!modal || isOpen()) return;
    sequence += 1;
    previousFocus = document.activeElement;
    view = {
      step: 'list', versions: [], page: 0, hasMore: false, loadingList: false, listError: '', rowError: '',
      unreadable: new Map(), prepared: null, items: [], committing: false, selectError: '',
    };
    $('github-history-versions').replaceChildren();
    $('github-history-items').replaceChildren();
    modal.classList.remove('hidden');
    render();
    $('github-history-done').focus();
    void loadPage(1);
  }

  function close(cancelBackend = true) {
    if (!modal) return;
    const wasOpen = isOpen();
    sequence += 1;
    view = null;
    modal.classList.add('hidden');
    $('github-history-versions').replaceChildren();
    $('github-history-items').replaceChildren();
    if (cancelBackend && wasOpen) invoke('github_backup_history_cancel').catch(() => {});
    if (wasOpen && previousFocus?.isConnected && !previousFocus.closest('.hidden')) previousFocus.focus();
    previousFocus = null;
  }

  const closeIfIdle = () => { if (!view?.committing) close(true); };
  $('github-history-close').addEventListener('click', closeIfIdle);
  $('github-history-done').addEventListener('click', closeIfIdle);
  $('github-history-back').addEventListener('click', backToList);
  $('github-history-restore').addEventListener('click', () => { void restore(); });
  $('github-history-more').addEventListener('click', () => { if (view && !view.loadingList) void loadPage(view.page + 1); });
  $('github-history-versions').addEventListener('click', (event) => {
    const row = event.target.closest('[data-history-sha]');
    if (row && !row.disabled) void pick(row.dataset.historySha);
  });
  $('github-history-select-all').addEventListener('change', (event) => {
    if (!view || view.committing) return;
    for (const item of selectableItems()) item.selected = event.currentTarget.checked;
    renderSelect();
  });
  $('github-history-items').addEventListener('change', (event) => {
    const box = event.target.closest('[data-history-check]');
    const item = box && view?.items.find((entry) => entry.id === box.dataset.historyCheck);
    if (!item?.selectable || view.committing) return;
    item.selected = box.checked;
    const row = box.closest('[data-history-row]');
    row?.classList.toggle('is-selected', item.selected);
    row?.classList.toggle('is-unchecked', !item.selected);
    renderSelectionChrome();
  });
  modal.addEventListener('click', (event) => { if (event.target === modal) closeIfIdle(); });
  // This dialog handles its own keys: the app-wide handler knows nothing about it.
  modal.addEventListener('keydown', (event) => {
    event.stopPropagation();
    if (event.key === 'Escape') { event.preventDefault(); closeIfIdle(); }
    if (event.key === 'Tab') trapFocusInContainer(modal.querySelector('.modal-card'), event);
  });

  return { open, close, render, isOpen };
}
