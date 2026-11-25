/* OpenKeylet Desktop Renderer — Native ES Module Entry Point. */
import { $, $$, edgeDockSupported, isMacOS, trapFocusInContainer } from './core/dom.js';
import { store, hooks, ACTIVITY_PAGE_SIZE } from './core/store.js';
import { api, invoke, listen } from './core/api.js';
import { cleanError, publicMessage, toast, finishConfirmation, confirmDestructiveAction } from './core/feedback.js';
import { SETTINGS_FILTER_ORDER, moduleLabel, moduleSecretName } from './core/item-schema.js';
import { applyLanguage, localized, normalizeSetting, resolveLanguage, setLanguage } from './i18n/index.js';
import { initCustomSelect } from './lib/custom-select.js';
import { createCloudSync } from './features/cloud-sync.js';
import { createUpdater } from './features/updater.js';
import { importHub } from './features/import-hub.js';
import { initOwnerLock, lockOwner, refreshOwnerLock, renderOwnerLock } from './views/owner-lock.js';
import { renderMetrics } from './views/metrics.js';
import {
  finishSwitchDrag,
  initSwitchDragging,
  selectCreationMode,
  selectFilterButton,
  selectPage,
  setTitleSearchOpen,
  syncActivityFilterControl,
  syncItemTypeFilter,
  syncSettingsFilterControl,
  syncTitleSearch,
} from './views/navigation.js';
import {
  clearAutoCheckTimer,
  copyFullItem,
  initConnectionsView,
  refreshDrafts,
  renderConnections,
  renderDrafts,
  runSingleItemCheck,
  syncCheckAllButton,
  syncListActionsWidth,
  syncVaultViewMode,
} from './views/connections.js';
import {
  finishItemPointerDrag,
  finishModulePointerDrag,
  initDragReorder,
  updateItemGridRowHeight,
} from './views/drag-reorder.js';
import {
  addModule,
  applyTemplate,
  closeEditor,
  closeEditorWithDraft,
  handleSmartFile,
  initEditorView,
  openCandidateInEditor,
  openEditor,
  renderAgentNotes,
  renderModules,
  serializeItem,
  setModuleAgentVisibility,
  setModuleMenu,
  smartIngestText,
  syncModuleDraft,
  syncRevealAllSecretsButton,
  toggleAllModuleSecrets,
  updateEditorTitle,
} from './views/editor.js';
import { deleteSingleActivity, initActivityView, renderActivity } from './views/activity.js';
import {
  applySettingsSearch,
  initSettingsView,
  loadChromeProfiles,
  renderSettings,
  saveBrowserSettings,
  saveDesktopSettings,
  savePinSettings,
  scanAgents,
  setSystemIntegration,
} from './views/settings.js';
import {
  closeMvaultImportModal,
  handleDroppedMvaultFile,
  initMvaultImportView,
  openMvaultPreviewFlow,
  renderMvaultSelectPanel,
  renderMvaultUnlockPanel,
  setGlobalMvaultDropOverlay,
} from './views/mvault-import.js';
import {
  closeGenerator,
  closeMigration,
  closeVaultManagement,
  finishBackupPassword,
  initSecondaryModals,
  openVaultManagement,
  resetMigration,
  topSecondaryModal,
} from './views/modals.js';

function render() {
  renderMetrics();
  renderConnections();
  renderDrafts();
  renderActivity();
  renderSettings();
  store.importHub?.render?.();
}

async function refresh(showError = true) {
  try {
    store.state = await api.state();
    try {
      store.systemIntegrationState = await api.systemIntegration();
    } catch (_) {
      store.systemIntegrationState = { desktopShortcut: false, launchAtLogin: false };
    }
    store.languagePreference = normalizeSetting(store.state.settings.language);
    store.language = resolveLanguage(store.languagePreference);
    await store.githubBackup?.refresh();
    await store.appUpdater?.refresh();
    applyLanguage();
    render();
  } catch (error) {
    if (showError) toast(cleanError(error), 'error');
  }
}

// Register cross-view coordination hooks (eliminates circular ES module imports).
Object.assign(hooks, {
  refresh,
  render,
  toast,
  cleanError,
  renderOwnerLock,
  refreshOwnerLock,
  renderMetrics,
  renderConnections,
  renderDrafts,
  refreshDrafts,
  renderActivity,
  renderSettings,
  applySettingsSearch,
  scanAgents,
  saveBrowserSettings,
  saveDesktopSettings,
  savePinSettings,
  setSystemIntegration,
  syncItemTypeFilter,
  syncActivityFilterControl,
  syncSettingsFilterControl,
  syncTitleSearch,
  syncCheckAllButton,
  syncListActionsWidth,
  clearAutoCheckTimer,
  updateItemGridRowHeight,
  finishSwitchDrag,
  finishItemPointerDrag,
  finishModulePointerDrag,
  openEditor,
  closeEditor,
  closeEditorWithDraft,
  renderModules,
  syncModuleDraft,
  updateEditorTitle,
  renderAgentNotes,
  setModuleAgentVisibility,
  closeVaultManagement,
  closeMigration,
  resetMigration,
  closeMvaultImportModal,
  setGlobalMvaultDropOverlay,
  renderMvaultSelectPanel,
  renderMvaultUnlockPanel,
  closeGenerator,
  finishBackupPassword,
});

// Expose hooks required by automated Playwright UI tests.
Object.assign(window, {
  refresh,
  refreshOwnerLock,
  renderSettings,
  refreshDrafts,
  serializeItem,
  closeEditor,
});

function initWindowChrome() {
  document.documentElement.classList.toggle('platform-macos', isMacOS);
  window.addEventListener('blur', () => document.documentElement.classList.add('window-blurred'));
  window.addEventListener('focus', () => document.documentElement.classList.remove('window-blurred'));

  const isTitleControl = (target) => Boolean(target.closest?.('button, input, select, textarea, a, label, [role="button"], [data-tauri-drag-region="false"], #title-search'));
  const inDragRegion = (target) => Boolean(target.closest?.('[data-tauri-drag-region="deep"]'));
  document.addEventListener('mousedown', (event) => {
    if (event.button === 0 && inDragRegion(event.target) && !isTitleControl(event.target)) event.preventDefault();
  });
  document.addEventListener('selectstart', (event) => {
    if (inDragRegion(event.target) && !isTitleControl(event.target)) event.preventDefault();
  });
  document.addEventListener('dragstart', (event) => {
    if (inDragRegion(event.target) && !isTitleControl(event.target)) event.preventDefault();
  });
  const titleSearch = document.getElementById('title-search');
  titleSearch?.addEventListener('click', (event) => {
    if (event.target === titleSearch) document.getElementById('title-search-input')?.focus();
  });

  // Vertical-only frameless window resize handles (width remains locked at 460px).
  for (const edge of $$('.window-resize-edge')) {
    edge.addEventListener('mousedown', (event) => {
      if (event.button !== 0) return;
      event.preventDefault();
      const rawDir = edge.dataset.resizeEdge;
      api.startVerticalResize(rawDir)
        .then((handled) => {
          if (handled) return;
          const tauriDir = rawDir === 'north' || rawDir === 'top' ? 'North' : 'South';
          window.__TAURI__?.window?.getCurrentWindow?.().startResizeDragging?.(tauriDir)?.catch?.(() => {});
        })
        .catch(() => {});
    });
  }

  // Screen-edge auto-hide magnetic drawer preference & peek handle (Windows only).
  if (edgeDockSupported) {
    const EDGE_DOCK_KEY = 'openkeylet.edgeDock.v1';
    const edgeDockInput = $('#edge-dock-enabled');
    const peekEl = $('#edge-dock-peek');
    let edgeDockEnabled = (() => {
      try { return localStorage.getItem(EDGE_DOCK_KEY) !== 'false'; } catch (_) { return true; }
    })();
    if (edgeDockInput) edgeDockInput.checked = edgeDockEnabled;

    function syncEdgeDockToBackend() {
      api.setEdgeDockEnabled(edgeDockEnabled).catch(() => {});
    }

    edgeDockInput?.addEventListener('change', (event) => {
      edgeDockEnabled = Boolean(event.currentTarget.checked);
      try { localStorage.setItem(EDGE_DOCK_KEY, edgeDockEnabled ? 'true' : 'false'); } catch (_) {}
      syncEdgeDockToBackend();
    });

    function applyEdgeDockState(payload) {
      const edge = payload?.edge || '';
      const collapsed = Boolean(payload?.collapsed && edge);
      if (edge) document.documentElement.dataset.edgeDock = edge;
      else delete document.documentElement.dataset.edgeDock;
      document.documentElement.dataset.edgeCollapsed = collapsed ? 'true' : 'false';
      if (peekEl) peekEl.classList.toggle('hidden', !collapsed);
    }

    peekEl?.addEventListener('pointerenter', () => { api.edgeDockExpand().catch(() => {}); });
    peekEl?.addEventListener('click', () => { api.edgeDockExpand().catch(() => {}); });
    document.addEventListener('pointerenter', () => {
      if (document.documentElement.dataset.edgeDock) api.edgeDockHover(true).catch(() => {});
    });
    document.addEventListener('pointerleave', () => {
      if (document.documentElement.dataset.edgeDock) api.edgeDockHover(false).catch(() => {});
    });

    listen('edge-dock-state', (event) => { applyEdgeDockState(event?.payload); });
    listen('edge-dock-preference-changed', (event) => {
      edgeDockEnabled = Boolean(event?.payload);
      try { localStorage.setItem(EDGE_DOCK_KEY, edgeDockEnabled ? 'true' : 'false'); } catch (_) {}
      if (edgeDockInput) edgeDockInput.checked = edgeDockEnabled;
    });
    syncEdgeDockToBackend();
  }
}

function initGlobalDelegatedEvents() {
  $('#confirmation-modal').addEventListener('click', (event) => {
    if (event.target === $('#confirmation-modal') || event.target.closest('#confirmation-cancel')) finishConfirmation(false);
    if (event.target.closest('#confirmation-accept')) finishConfirmation(true);
  });

  document.addEventListener('click', async (event) => {
    if (event.target.closest('#title-search-toggle')) {
      const input = $('#title-search-input');
      if (store.pageSearch[store.activePage]) {
        store.pageSearch[store.activePage] = '';
        input.value = '';
        syncTitleSearch();
        if (store.activePage === 'connections') renderConnections();
        if (store.activePage === 'import') store.importHub?.render?.();
        if (store.activePage === 'activity') { store.activityVisibleCount = ACTIVITY_PAGE_SIZE; renderActivity(); }
        if (store.activePage === 'settings') applySettingsSearch();
      }
      input.focus({ preventScroll: true });
    }
    const filterButton = event.target.closest('.filter-strip button');
    if (filterButton && !store.switchSelectionPending) await selectFilterButton(filterButton);
    const languageButton = event.target.closest('[data-language]');
    if (languageButton) await setLanguage(languageButton.dataset.language);
    const nav = event.target.closest('[data-page]');
    if (nav) await selectPage(nav.dataset.page);
    const metricService = event.target.closest('[data-metric-section]');
    if (metricService) {
      const targetSection = metricService.dataset.metricSection;
      await selectPage('settings');
      if (SETTINGS_FILTER_ORDER.includes(targetSection)) {
        store.currentSettingsFilter = targetSection;
        syncSettingsFilterControl();
        applySettingsSearch();
        $('.settings-layout').scrollTop = 0;
      }
    }
    const metricAction = event.target.closest('[data-metric-action]');
    if (metricAction) {
      const action = metricAction.dataset.metricAction;
      if (!window.__openkeyletMetricFocusCursor) window.__openkeyletMetricFocusCursor = {};
      const cursor = window.__openkeyletMetricFocusCursor;
      const clearPageSearchForMetric = (pageKey) => {
        if (!store.pageSearch[pageKey]) return;
        store.pageSearch[pageKey] = '';
        const searchInput = $('#title-search-input');
        if (searchInput) searchInput.value = '';
        syncTitleSearch();
      };
      const pulseAndFocusRow = (targetRow, focusTarget = targetRow) => {
        if (!targetRow) return;
        targetRow.scrollIntoView({ behavior: 'smooth', block: 'center' });
        if (targetRow._focusPulseTimer) {
          clearTimeout(targetRow._focusPulseTimer);
          targetRow._focusPulseTimer = 0;
        }
        targetRow.classList.remove('is-focus-pulse');
        void targetRow.offsetWidth;
        targetRow.classList.add('is-focus-pulse');
        (focusTarget || targetRow).focus({ preventScroll: true });
        targetRow._focusPulseTimer = setTimeout(() => {
          targetRow.classList.remove('is-focus-pulse');
          targetRow._focusPulseTimer = 0;
        }, 1700);
      };

      if (action === 'focus-connections-all' || action === 'focus-connections-enabled') {
        await selectPage('connections');
        clearPageSearchForMetric('connections');
        store.currentItemTypeFilter = 'all';
        syncItemTypeFilter();
        renderConnections();
        const selector = action === 'focus-connections-enabled'
          ? '#connections-list .connection-card[data-item-enabled="true"]'
          : '#connections-list .connection-card';
        const rows = $$(selector);
        if (rows.length) {
          const nextIdx = action === 'focus-connections-enabled' ? ((cursor[action] ?? -1) + 1) % rows.length : 0;
          cursor[action] = nextIdx;
          const targetRow = rows[nextIdx];
          pulseAndFocusRow(targetRow, $('.connection-name', targetRow) || targetRow);
        } else {
          const list = $('#connections-list');
          if (list) list.scrollTop = 0;
        }
      } else if (action === 'focus-import-all' || action === 'focus-import-selected') {
        await selectPage('import');
        clearPageSearchForMetric('import');
        store.importHub?.resetFilter?.();
        const selector = action === 'focus-import-selected'
          ? '#import-candidate-list .import-card[data-import-selected="true"]'
          : '#import-candidate-list .import-card';
        const rows = $$(selector);
        if (rows.length) {
          const nextIdx = action === 'focus-import-selected' ? ((cursor[action] ?? -1) + 1) % rows.length : 0;
          cursor[action] = nextIdx;
          const targetRow = rows[nextIdx];
          const focusTarget = (action === 'focus-import-selected' ? $('.import-card-check', targetRow) : null) || targetRow;
          pulseAndFocusRow(targetRow, focusTarget);
        } else if (action === 'focus-import-selected' && $('#import-candidate-list .import-card')) {
          ($('#import-staging-toolbar') || $('#import-results-wrap'))?.scrollIntoView({ behavior: 'smooth', block: 'start' });
          $('#import-toggle-all')?.focus({ preventScroll: true });
        } else {
          const scrollArea = $('#import-scroll-area');
          if (scrollArea) scrollArea.scrollTop = 0;
          store.importHub?.focusInput?.();
        }
      } else if (action === 'focus-repair-agent' || action === 'focus-linked-agents') {
        await selectPage('settings');
        clearPageSearchForMetric('settings');
        store.currentSettingsFilter = 'MCP';
        syncSettingsFilterControl();
        applySettingsSearch();
        const selector = action === 'focus-repair-agent'
          ? '#agent-client-list .agent-client-row[data-agent-state="stale"], #agent-client-list .agent-client-row[data-agent-state="conflict"], #agent-client-list .agent-client-row[data-agent-state="error"]'
          : '#agent-client-list .agent-client-row[data-agent-state="registered"]';
        const rows = $$(selector);
        if (rows.length) {
          const nextIdx = ((cursor[action] ?? -1) + 1) % rows.length;
          cursor[action] = nextIdx;
          const targetRow = rows[nextIdx];
          const focusTarget = (action === 'focus-repair-agent' ? $('[data-agent-action="repair"]', targetRow) : $('button', targetRow)) || targetRow;
          pulseAndFocusRow(targetRow, focusTarget);
        } else {
          $('[data-module="MCP / 02"]')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      } else if (action === 'focus-activity-errors' || action === 'focus-activity-all') {
        await selectPage('activity');
        clearPageSearchForMetric('activity');
        store.currentActivityFilter = action === 'focus-activity-errors' ? 'error' : 'all';
        store.activityVisibleCount = ACTIVITY_PAGE_SIZE;
        renderActivity();
        const selector = action === 'focus-activity-errors'
          ? '#activity-list .activity-item[data-activity-status="error"]'
          : '#activity-list .activity-item';
        const rows = $$(selector);
        if (rows.length) {
          const nextIdx = action === 'focus-activity-errors' ? ((cursor[action] ?? -1) + 1) % rows.length : 0;
          cursor[action] = nextIdx;
          let targetRow = rows[nextIdx];
          const targetId = targetRow.dataset.activityId;
          if (action === 'focus-activity-errors' && targetId && !store.expandedActivityErrors.has(targetId)) {
            store.expandedActivityErrors.add(targetId);
            renderActivity();
            targetRow = $(`#activity-list .activity-item[data-activity-id="${CSS.escape(targetId)}"]`) || rows[nextIdx];
          }
          pulseAndFocusRow(targetRow, $('.activity-error', targetRow) || targetRow);
        } else {
          $('.activity-panel').scrollTop = 0;
        }
      }
    }

    const windowButton = event.target.closest('[data-window-action]');
    if (windowButton) {
      if (windowButton.dataset.windowAction === 'close' && !$('#connection-modal').classList.contains('hidden')) await closeEditorWithDraft();
      await api.window(windowButton.dataset.windowAction);
      if (windowButton.dataset.windowAction === 'minimize') await refreshOwnerLock(false);
    }
    if (event.target.closest('#owner-lock-button')) {
      if (!$('#connection-modal').classList.contains('hidden')) await closeEditorWithDraft();
      await lockOwner();
    }

    const deleteDraftButton = event.target.closest('#delete-draft-button');
    if (deleteDraftButton && store.editorDrafts[0]) {
      const draft = store.editorDrafts[0];
      const draftId = draft.id;
      const draftName = draft.input?.name?.trim();
      if (!await confirmDestructiveAction({
        title: draftName ? localized(`删除草稿「${draftName}」？`, `Delete draft "${draftName}"?`) : localized('删除当前草稿？', 'Delete this draft?'),
        message: localized('草稿中的未保存内容将永久丢失。', 'Unsaved content in this draft will be permanently lost.'),
      })) return;
      try {
        await api.deleteDraft(draftId);
        store.editorDrafts = store.editorDrafts.filter((candidate) => candidate.id !== draftId);
        renderDrafts();
        (store.editorDrafts.length > 0 ? $('#drafts-button') : $('#add-connection-button')).focus();
        toast(store.editorDrafts.length > 0
          ? localized(`草稿已删除（还有 ${store.editorDrafts.length} 条待处理）`, `Draft deleted (${store.editorDrafts.length} remaining)`)
          : localized('草稿已删除', 'Draft deleted'));
      } catch (error) {
        toast(cleanError(error), 'error');
      }
      return;
    }

    const draftsButton = event.target.closest('#drafts-button');
    if (draftsButton && store.editorDrafts[0]) await selectCreationMode('draft');
    const moduleButton = event.target.closest('#add-module-button');
    if (moduleButton) setModuleMenu(moduleButton.getAttribute('aria-expanded') !== 'true');
    else if (!event.target.closest('#module-menu')) setModuleMenu(false);
    const addModuleButton = event.target.closest('[data-add-module]');
    if (addModuleButton) addModule(addModuleButton.dataset.addModule);
    const templateButton = event.target.closest('[data-item-template]');
    if (templateButton) applyTemplate(templateButton.dataset.itemTemplate);
    if (event.target.closest('#add-connection-button') || event.target.closest('[data-action="add"]')) {
      await selectCreationMode('add');
    }
    if (event.target === $('#connection-modal')) await closeEditorWithDraft();
    if (event.target === $('#confirmation-modal') && store.confirmationResolver) finishConfirmation(false);
    if (event.target === $('#generator-modal')) closeGenerator();
    if (event.target === $('#backup-password-modal')) finishBackupPassword(null);
    if (event.target === $('#mvault-import-modal')) closeMvaultImportModal(true);
    if (event.target === $('#migration-modal')) closeMigration();
    if (event.target === $('#vault-management-modal')) closeVaultManagement();
    if (event.target.closest('[data-close-modal]')) await closeEditorWithDraft();

    const copyInput = event.target.closest('[data-copy-input]');
    const copyModule = event.target.closest('[data-copy-module-secret], [data-copy-module-value]');
    if (copyInput || copyModule) {
      const input = copyInput
        ? $(`#${copyInput.dataset.copyInput}`)
        : $('[data-secret-value], [data-module-value]', copyModule.closest('.module-row'));
      const isSensitive = Boolean(copyModule?.hasAttribute('data-copy-module-secret') || input?.hasAttribute('data-secret-value'));
      try {
        await api.copyOwnerValue(input.value, isSensitive);
        toast(isSensitive ? localized('已复制（30 秒后自动清除）', 'Copied · clears in 30s') : localized('已复制', 'Copied'));
      } catch (error) {
        toast(cleanError(error), 'error');
      }
    }

    const toggleModuleSecret = event.target.closest('[data-toggle-module-secret]');
    if (toggleModuleSecret) {
      const field = $('[data-secret-value]', toggleModuleSecret.closest('.module-row'));
      const revealed = toggleModuleSecret.getAttribute('aria-pressed') !== 'true';
      if (field.tagName === 'INPUT') field.type = revealed ? 'text' : 'password';
      else field.classList.toggle('secret-masked', !revealed);
      toggleModuleSecret.setAttribute('aria-pressed', String(revealed));
      const label = revealed ? localized('隐藏明文', 'Hide secret') : localized('显示明文', 'Show secret');
      toggleModuleSecret.setAttribute('aria-label', label);
      toggleModuleSecret.title = label;
      syncRevealAllSecretsButton();
    }
    if (event.target.closest('#toggle-all-secrets-button')) {
      toggleAllModuleSecrets();
    }

    const toggleAgentVisible = event.target.closest('[data-module-agent-visible]');
    if (toggleAgentVisible) setModuleAgentVisibility(toggleAgentVisible, toggleAgentVisible.getAttribute('aria-pressed') !== 'true');

    const chooseModuleKey = event.target.closest('[data-choose-module-key]');
    if (chooseModuleKey) {
      try {
        const name = await api.chooseKey();
        if (name) {
          syncModuleDraft();
          const index = Number(chooseModuleKey.closest('.module-row').dataset.moduleIndex);
          store.currentModules[index].pending = true;
          store.currentModules[index].configured = true;
          store.currentModules[index].privateKeyName = name;
          renderModules();
        }
      } catch (error) {
        toast(cleanError(error), 'error');
      }
    }

    const removeModuleButton = event.target.closest('[data-remove-module]');
    if (removeModuleButton) {
      syncModuleDraft();
      const row = removeModuleButton.closest('.module-row');
      const index = Number(row.dataset.moduleIndex);
      const removed = store.currentModules[index];
      if (!removed) return;
      const moduleName = removed.kind === 'customSecret' && removed.name.trim() ? removed.name.trim() : moduleLabel(removed.kind);
      if (!await confirmDestructiveAction({
        title: localized(`删除“${moduleName}”模块？`, `Delete the "${moduleName}" module?`),
        message: removed?.existing
          ? localized('保存项目后，该模块及其加密值将永久删除。', 'After you save the item, this module and its encrypted value will be permanently deleted.')
          : localized('该模块中尚未保存的内容将丢失。', 'Unsaved content in this module will be lost.'),
      })) return;
      if (!row.isConnected || $('#connection-modal').classList.contains('hidden')) return;
      if (removed?.existing && moduleSecretName(removed)) store.removedSecretFields.add(moduleSecretName(removed));
      store.currentModules.splice(index, 1);
      renderModules();
      const remainingRows = $$('.module-row', $('#module-list'));
      ($('[data-remove-module]', remainingRows[Math.min(index, remainingRows.length - 1)] || $('#module-list')) || $('#add-module-button')).focus();
    }

    const action = event.target.closest('[data-action]');
    if (action?.dataset.action === 'clear-connection-filters') {
      store.pageSearch.connections = '';
      store.currentItemTypeFilter = 'all';
      $('[data-page-search="connections"]').value = '';
      syncItemTypeFilter();
      syncTitleSearch();
      renderConnections();
    }
    if (action?.dataset.action === 'clear-activity-filters') {
      store.currentActivityFilter = 'all';
      store.pageSearch.activity = '';
      syncTitleSearch();
      store.activityVisibleCount = ACTIVITY_PAGE_SIZE;
      renderActivity();
    }
    if (action?.dataset.action === 'delete-activity' && action.dataset.activityId) {
      await deleteSingleActivity(action.dataset.activityId, action);
      return;
    }
    if (action?.dataset.id) {
      const item = store.state.connections.find((candidate) => candidate.id === action.dataset.id);
      if (action.dataset.action === 'toggle-enabled') {
        try {
          await api.setEnabled(item.id, !item.enabled);
          toast(item.enabled ? localized('项目已停用', 'Item disabled') : localized('项目已启用', 'Item enabled'));
          await refresh();
        } catch (error) { toast(cleanError(error), 'error'); }
      }
      if (action.dataset.action === 'edit') await openEditor(item);
      if (action.dataset.action === 'copy-item') await copyFullItem(item, action);
      if (action.dataset.action === 'history') await openVaultManagement('history', item.id);
      if (action.dataset.action === 'copy-name') {
        try {
          await api.copyOwnerValue(`use ${item.name} in OpenKeylet MCP`, false);
          toast(localized('OpenKeylet MCP 使用提示已复制', 'OpenKeylet MCP use prompt copied'));
        } catch (error) { toast(cleanError(error), 'error'); }
      }
      if (action.dataset.action === 'test') await runSingleItemCheck(item, { showToast: true, doRefresh: true });
      if (action.dataset.action === 'delete' && await confirmDestructiveAction({
        title: localized(`将“${item.name}”移入回收站？`, `Move "${item.name}" to trash?`),
        message: localized('项目将停止用于填写、Passkey 登录和 Agent 操作。你可以在回收站恢复它。', 'The item will stop being available for autofill, passkeys and agents. You can restore it from Trash.'),
        acceptLabel: localized('移入回收站', 'MOVE TO TRASH'),
      })) {
        try {
          await api.remove(item.id, item.updatedAt);
          toast(localized('已移入回收站', 'Moved to trash'));
          await refresh();
          $('#vault-view-toggle')?.focus();
        } catch (error) { toast(cleanError(error), 'error'); }
      }
    } else if (!action && !store.suppressItemClick) {
      const card = event.target.closest('.connection-card[data-item-id]');
      if (card && !event.target.closest('.card-actions, .item-toggle')) {
        const item = store.state.connections.find((candidate) => candidate.id === card.dataset.itemId);
        if (item) {
          $('[data-item-reorder]', card)?.focus({ preventScroll: true });
          await openEditor(item);
        }
      }
    }

    const errorDetail = event.target.closest('[data-expand-error]');
    if (errorDetail) {
      const expanded = errorDetail.getAttribute('aria-expanded') === 'true';
      if (expanded) store.expandedActivityErrors.delete(errorDetail.dataset.expandError);
      else store.expandedActivityErrors.add(errorDetail.dataset.expandError);
      errorDetail.setAttribute('aria-expanded', String(!expanded));
      errorDetail.classList.toggle('expanded', !expanded);
    }

    const copy = event.target.closest('[data-copy-format]');
    if (copy) {
      try {
        await api.copyConfig(copy.dataset.copyFormat);
        toast(localized('stdio 配置已复制', 'stdio configuration copied'));
      } catch (error) { toast(cleanError(error), 'error'); }
    }

    const agentAction = event.target.closest('[data-agent-action]');
    if (agentAction) {
      const kind = agentAction.dataset.agentAction;
      if (kind === 'remove') {
        const client = store.agentClients.find((candidate) => candidate.clientId === agentAction.dataset.clientId);
        if (!await confirmDestructiveAction({
          title: localized(`移除 ${client?.displayName || 'Agent'} 的 OpenKeylet 接入？`, `Remove OpenKeylet from ${client?.displayName || 'this agent'}?`),
          message: localized('将删除该 Agent 的 OpenKeylet MCP 配置；之后可以重新连接。', 'This removes the OpenKeylet MCP configuration from the agent. You can connect it again later.'),
          acceptLabel: localized('移除', 'REMOVE'),
          tag: localized('确认移除接入', 'CONFIRM INTEGRATION REMOVAL'),
        })) return;
      }
      try {
        const result = kind === 'connect'
          ? (await api.registerAgents([agentAction.dataset.clientId]))[0]
          : kind === 'repair'
            ? await api.repairAgent(agentAction.dataset.clientId)
            : await api.removeAgent(agentAction.dataset.clientId);
        if (result?.ok) {
          store.agentRestartRequired = true;
          $('#agent-restart-notice').classList.remove('hidden');
        }
        toast(result?.ok ? localized('已更新 · 新开 Agent 会话后生效', 'Updated · Open a new agent session to apply') : publicMessage(result?.message), result?.ok ? '' : 'error');
        await scanAgents();
      } catch (error) { toast(cleanError(error), 'error'); }
    }
  });

  document.addEventListener('input', (event) => {
    if (event.target.matches('.pin-cell-input')) {
      event.target.value = event.target.value.replace(/\D/g, '').slice(-1);
      if (event.target.value) {
        const inputs = $$('.pin-cell-input', event.target.closest('.pin-control'));
        inputs[inputs.indexOf(event.target) + 1]?.focus();
      }
    }
    if (event.target.closest('.module-row')) syncModuleDraft();
    const page = event.target.dataset.pageSearch;
    if (!page) return;
    store.pageSearch[page] = event.target.value;
    syncTitleSearch();
    if (page === 'connections') renderConnections();
    if (page === 'import') store.importHub?.render?.();
    if (page === 'activity') {
      store.activityVisibleCount = ACTIVITY_PAGE_SIZE;
      renderActivity();
    }
    if (page === 'settings') applySettingsSearch();
  });

  document.addEventListener('paste', (event) => {
    if (event.target.matches('.pin-cell-input')) {
      const digits = event.clipboardData?.getData('text').replace(/\D/g, '').slice(0, 6) || '';
      if (!digits) return;
      event.preventDefault();
      const inputs = $$('.pin-cell-input', event.target.closest('.pin-control'));
      inputs.forEach((input, index) => { input.value = digits[index] || ''; });
      (inputs[Math.min(digits.length, inputs.length) - 1] || inputs[0])?.focus();
      return;
    }
    if (!store.ownerLockState?.unlocked) return;
    const target = event.target;
    if (target && target.closest?.('input, textarea, select, [contenteditable="true"]')) return;
    const modalOpen = $$('.modal-backdrop:not(.hidden)').length > 0;
    const canPasteInBlankEditor = !$('#connection-modal').classList.contains('hidden')
      && !$('#template-picker').classList.contains('hidden');
    if (modalOpen && !canPasteInBlankEditor) return;
    if (!modalOpen && store.activePage !== 'connections' && store.activePage !== 'import') return;
    const dt = event.clipboardData;
    if (!dt) return;
    const imageItem = [...(dt.items || [])].find((item) => item.type?.startsWith('image/'));
    if (imageItem) {
      const blob = imageItem.getAsFile();
      if (blob) {
        event.preventDefault();
        if (!modalOpen && store.activePage === 'import') void store.importHub?.handleFiles?.([blob]);
        else void handleSmartFile(blob);
        return;
      }
    }
    const text = dt.getData('text/plain');
    if (text && text.trim()) {
      event.preventDefault();
      if (!modalOpen && store.activePage === 'import') store.importHub?.handlePasteText?.(text, { fromClipboard: true });
      else void smartIngestText(text, { fromClipboard: true });
    }
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && store.switchPointerDrag) { event.preventDefault(); void finishSwitchDrag(false); return; }
    if (event.key === 'Escape' && store.itemPointerDrag) { event.preventDefault(); finishItemPointerDrag(false); return; }
    if (store.confirmationResolver) {
      if (event.key === 'Escape') { event.preventDefault(); finishConfirmation(false); return; }
      if (event.key === 'Tab') {
        const buttons = [$('#confirmation-cancel'), $('#confirmation-accept')];
        const index = buttons.indexOf(document.activeElement);
        event.preventDefault();
        buttons[(index + (event.shiftKey ? -1 : 1) + buttons.length) % buttons.length].focus();
      }
      return;
    }
    if (event.key === 'Escape' && store.modulePointerDrag) { event.preventDefault(); finishModulePointerDrag(false); return; }
    const lockedOverlayVisible = !$('#owner-lock-layer').classList.contains('hidden');
    if (lockedOverlayVisible) {
      if (event.key === 'Tab') trapFocusInContainer($('#owner-lock-layer'), event);
      if (event.key === 'Escape' && store.ownerPinSetupRequested && !store.ownerLockState.pinConfigured) {
        event.preventDefault();
        $('#owner-pin-cancel')?.click();
      }
      return;
    }
    if ((event.ctrlKey || event.metaKey) && !event.altKey && event.shiftKey && event.key.toLowerCase() === 'l' && store.ownerLockState.pinConfigured && store.ownerLockState.unlocked) {
      event.preventDefault();
      void lockOwner();
      return;
    }
    const secondaryModal = topSecondaryModal();
    if (secondaryModal && !event.defaultPrevented) {
      if (event.key === 'Escape') { event.preventDefault(); secondaryModal.close(); return; }
      if (event.key === 'Tab') { trapFocusInContainer(secondaryModal.el, event); return; }
      if (isMacOS && event.metaKey && !event.ctrlKey && !event.altKey && event.key.toLowerCase() === 'w') {
        event.preventDefault();
        secondaryModal.close();
        return;
      }
    }
    if (store.githubBackup?.isOpen() && !event.defaultPrevented) {
      if (event.key === 'Escape') { event.preventDefault(); $('#github-modal-close')?.click(); return; }
      if (isMacOS && event.metaKey && !event.ctrlKey && !event.altKey && event.key.toLowerCase() === 'w') {
        event.preventDefault();
        $('#github-modal-close')?.click();
        return;
      }
    }
    const editor = $('#connection-modal');
    const editorIsTopmost = !editor.classList.contains('hidden')
      && !$$('.modal-backdrop:not(.hidden)').some((modal) => modal !== editor);
    if (editorIsTopmost && !event.defaultPrevented) {
      const menu = $('#module-menu');
      if (event.key === 'Escape') {
        event.preventDefault();
        if (!menu.classList.contains('hidden')) { setModuleMenu(false); $('#add-module-button').focus(); }
        else void closeEditorWithDraft();
        return;
      }
      if (event.key === 'Tab') {
        trapFocusInContainer(editor, event, !editor.contains(menu) && !menu.classList.contains('hidden') ? [menu] : []);
        return;
      }
      if ((event.ctrlKey || event.metaKey) && !event.altKey && event.key.toLowerCase() === 's') {
        event.preventDefault();
        $('#connection-form')?.requestSubmit();
        return;
      }
      if (isMacOS && event.metaKey && !event.ctrlKey && !event.altKey && event.key.toLowerCase() === 'w') {
        event.preventDefault();
        void closeEditorWithDraft();
        return;
      }
    }
    if (event.target.closest('.creation-options') && ['ArrowLeft', 'ArrowRight'].includes(event.key)) {
      event.preventDefault();
      const button = $(event.key === 'ArrowLeft' ? '#add-connection-button' : '#drafts-button');
      if (!button.disabled) { button.focus(); button.click(); }
      return;
    }
    if (event.target.matches('.pin-cell-input')) {
      const inputs = $$('.pin-cell-input', event.target.closest('.pin-control'));
      const index = inputs.indexOf(event.target);
      if (event.key === 'Backspace' && !event.target.value && index > 0) {
        event.preventDefault();
        inputs[index - 1].value = '';
        inputs[index - 1].focus();
        return;
      }
      if (event.key === 'ArrowLeft' && index > 0) { event.preventDefault(); inputs[index - 1].focus(); return; }
      if (event.key === 'ArrowRight' && index < inputs.length - 1) { event.preventDefault(); inputs[index + 1].focus(); return; }
    }
    const filterButton = event.target.closest?.('.filter-strip button');
    if (filterButton && !store.switchSelectionPending && ['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) {
      event.preventDefault();
      const strip = filterButton.closest('.filter-strip');
      const buttons = $$('button', strip);
      const index = buttons.findIndex((button) => button.getAttribute('aria-pressed') === 'true');
      const next = event.key === 'Home'
        ? 0
        : event.key === 'End'
          ? buttons.length - 1
          : (index + (event.key === 'ArrowLeft' ? -1 : 1) + buttons.length) % buttons.length;
      void selectFilterButton(buttons[next]).then(() => $('[aria-pressed="true"]', strip).focus());
      return;
    }
    const noModalOpen = !$$('.modal-backdrop:not(.hidden)').length && $('#owner-lock-layer').classList.contains('hidden');
    if (noModalOpen && (event.ctrlKey || event.metaKey) && !event.altKey) {
      const key = event.key.toLowerCase();
      if (key === 'f' || key === 'k') {
        event.preventDefault();
        setTitleSearchOpen(true);
        const search = $(`[data-page-search="${store.activePage}"]`);
        search?.focus();
        search?.select();
        return;
      }
      if (key === 'n' && !event.shiftKey) {
        event.preventDefault();
        void selectPage('connections').then(() => selectCreationMode('add'));
        return;
      }
      if (key === ',') { event.preventDefault(); void selectPage('settings'); return; }
      if (key === '1' || key === '2' || key === '3' || key === '4') {
        event.preventDefault();
        void selectPage({ 1: 'connections', 2: 'import', 3: 'activity', 4: 'settings' }[key]);
        return;
      }
      if (isMacOS && event.metaKey && !event.ctrlKey && key === 'w') {
        event.preventDefault();
        void api.window('close');
        return;
      }
    }
    if (event.key === 'Delete' || event.key === 'Backspace') {
      const focusedActivity = event.target.closest?.('#activity-list .activity-item[data-activity-id]');
      if (noModalOpen && store.activePage === 'activity' && focusedActivity && !event.target.closest?.('input, textarea, select')) {
        event.preventDefault();
        void deleteSingleActivity(focusedActivity.dataset.activityId, $('[data-action="delete-activity"]', focusedActivity));
        return;
      }
    }
    if (event.key === 'Escape') {
      const search = event.target.closest?.('[data-page-search]');
      if (search?.value) {
        const page = search.dataset.pageSearch;
        search.value = '';
        store.pageSearch[page] = '';
        if (page === 'connections') renderConnections();
        if (page === 'import') store.importHub?.render?.();
        if (page === 'activity') { store.activityVisibleCount = ACTIVITY_PAGE_SIZE; renderActivity(); }
        if (page === 'settings') applySettingsSearch();
      }
      if (event.target.closest?.('#title-search')) {
        event.preventDefault();
        setTitleSearchOpen(false);
      }
    }
  });
}

function initTauriEventsAndPolling() {
  listen('state-changed', async () => { await refresh(false); await refreshDrafts(); });
  listen('tray-command', async (event) => {
    const action = event?.payload?.action;
    if (!action) return;
    await refreshOwnerLock(false);
    if (!store.ownerLockState.unlocked) return;
    if (action === 'new-item') {
      await selectPage('connections');
      await selectCreationMode('add');
    } else if (action === 'smart-import') {
      await selectPage('import');
    } else if (action === 'settings') {
      await selectPage('settings');
    } else if (action === 'update') {
      const indicator = $('#title-update-indicator');
      if (indicator && !indicator.classList.contains('hidden')) {
        indicator.click();
      } else {
        await selectPage('settings');
        $('[data-module="UPDATE / 07"]')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }
  });
  listen('pin-setup-requested', async () => {
    await refreshOwnerLock(false);
    if (store.ownerLockState.pinConfigured) return;
    store.ownerPinSetupRequested = true;
    renderOwnerLock();
    if (store.state) renderSettings();
  });
  window.addEventListener('focus', async () => {
    await refresh(false);
    await refreshOwnerLock(false);
    await refreshDrafts();
  });
  setInterval(() => { if ($('#page-activity').classList.contains('active')) refresh(false); }, 2000);
  setInterval(() => {
    if (!document.hidden && $('#connection-modal').classList.contains('hidden') && $('#page-connections').classList.contains('active')) {
      refresh(false);
    }
  }, 2000);
}

async function bootstrap() {
  initWindowChrome();
  initCustomSelect();
  initSwitchDragging();
  initOwnerLock();
  initConnectionsView();
  initDragReorder();
  initEditorView();
  initActivityView();
  initSettingsView();
  initMvaultImportView();
  initSecondaryModals();
  initGlobalDelegatedEvents();
  initTauriEventsAndPolling();

  store.githubBackup = createCloudSync({
    invoke,
    localized,
    toast,
    isUnlocked: () => store.ownerLockState.unlocked,
    confirmAction: confirmDestructiveAction,
    onRestore: async () => {
      await refreshOwnerLock(false);
      await refresh(false);
    },
  });

  store.appUpdater = createUpdater({
    invoke,
    localized,
    toast,
    isUnlocked: () => store.ownerLockState.unlocked,
    onSettingsUpdated: (settings) => {
      if (store.state && settings) store.state.settings = settings;
    },
  });

  store.importHub = importHub;
  importHub.init({
    invoke,
    localized,
    toast,
    cleanError,
    getLang: () => store.language,
    getSearchQuery: () => store.pageSearch.import || '',
    ensureUnlocked: async () => {
      await refreshOwnerLock();
      return Boolean(store.ownerLockState?.unlocked);
    },
    onStatsChange: () => renderMetrics(),
    refreshVault: () => refresh(),
    goToItems: () => void selectPage('connections'),
    goToImport: () => void selectPage('import'),
    openBackupRestore: () => $('#header-import-backup-button')?.click(),
    openDroppedMvault: (file) => handleDroppedMvaultFile(file),
    openMvaultPreview: (picked) => openMvaultPreviewFlow(picked),
    openCandidateInEditor: (candidate, onSaved) => openCandidateInEditor(candidate, onSaved),
    openTemplateInEditor: async (template) => {
      if (!await openEditor(null, null)) return;
      applyTemplate(template);
      store.editorInitialSnapshot = JSON.stringify(serializeItem(false));
      requestAnimationFrame(() => $('#connection-name')?.focus({ preventScroll: true }));
    },
  });

  applyLanguage();
  syncVaultViewMode();
  await refreshOwnerLock();
  await refresh();
  await refreshDrafts();
  loadChromeProfiles();
  scanAgents();
}

void bootstrap();
