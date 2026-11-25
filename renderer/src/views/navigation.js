/* Page switching, filter strips, unified titlebar search, and sliding switch-thumb drag. */
import { $, $$, isMacOS } from '../core/dom.js';
import { store, hooks, ACTIVITY_PAGE_SIZE } from '../core/store.js';
import { cleanError, toast } from '../core/feedback.js';
import {
  ITEM_TYPE_FILTER_ORDER,
  SETTINGS_FILTER_ORDER,
  itemDisplayKind,
  itemFilterLabel,
  itemTypeIcon,
} from '../core/item-schema.js';
import { localized, setLanguage } from '../i18n/index.js';

export const activityFilterOrder = ['all', 'error', 'success'];

export function syncFilterStrip(selector, order, selected, attribute, label, showLabels = false) {
  const control = $(selector);
  if (!control.children.length) {
    control.innerHTML = order
      .map((kind) => `<button type="button" ${attribute}="${kind}">${itemTypeIcon(kind)}${showLabels ? '<span data-filter-label></span>' : ''}</button>`)
      .join('');
  }
  control.style.setProperty('--type-count', order.length);
  control.style.setProperty('--selected-type', order.indexOf(selected));
  $$('button', control).forEach((button) => {
    const kind = button.getAttribute(attribute);
    button.setAttribute('aria-pressed', String(kind === selected));
    button.tabIndex = kind === selected ? 0 : -1;
    button.title = label(kind);
    button.setAttribute('aria-label', button.title);
    if (showLabels) $('[data-filter-label]', button).textContent = button.title;
  });
}

export function syncItemTypeFilter() {
  $('#item-type-switch').setAttribute('aria-label', localized('项目类型筛选', 'Item type filter'));
  syncFilterStrip('#item-type-switch', ITEM_TYPE_FILTER_ORDER, store.currentItemTypeFilter, 'data-item-type-filter', itemFilterLabel);
}

export function syncActivityFilterControl() {
  const labels = { all: ['全部', 'ALL'], error: ['错误', 'ERROR'], success: ['成功', 'PASS'] };
  $('#activity-filter-switch').setAttribute('aria-label', localized('记录结果筛选', 'Activity result filter'));
  syncFilterStrip('#activity-filter-switch', activityFilterOrder, store.currentActivityFilter, 'data-activity-filter', (kind) => localized(...labels[kind]), true);
}

export function syncSettingsFilterControl() {
  const labels = {
    all: ['全部设置', 'All settings'],
    SYSTEM: ['系统入口', 'System access'],
    MCP: ['Agent 接入', 'Agent setup'],
    APP: ['窗口与偏好', 'Window & preferences'],
    WEB: ['浏览器', 'Browser'],
    CLOUD: ['云端备份', 'Cloud backup'],
    SAFE: ['本地数据', 'Local data'],
    UPDATE: ['软件更新', 'Updates'],
  };
  $('#settings-filter-switch').setAttribute('aria-label', localized('设置分组筛选', 'Settings section filter'));
  syncFilterStrip('#settings-filter-switch', SETTINGS_FILTER_ORDER, store.currentSettingsFilter, 'data-settings-filter', (kind) => localized(...labels[kind]));
}

export async function setItemTypeFilter(kind) {
  if (!ITEM_TYPE_FILTER_ORDER.includes(kind) || kind === store.currentItemTypeFilter) return;
  const edited = store.state.connections.find((item) => item.id === store.editorItemId);
  if (edited && kind !== 'all' && itemDisplayKind(edited) !== kind && !await hooks.closeEditorWithDraft?.()) return;
  store.currentItemTypeFilter = kind;
  syncItemTypeFilter();
  hooks.renderConnections?.();
}

export async function selectFilterButton(button) {
  if (button.dataset.itemTypeFilter) await setItemTypeFilter(button.dataset.itemTypeFilter);
  if (button.dataset.activityFilter) {
    store.currentActivityFilter = button.dataset.activityFilter;
    store.activityVisibleCount = ACTIVITY_PAGE_SIZE;
    $('.activity-panel').scrollTop = 0;
    hooks.renderActivity?.();
  }
  if (button.dataset.settingsFilter) {
    store.currentSettingsFilter = button.dataset.settingsFilter;
    syncSettingsFilterControl();
    hooks.applySettingsSearch?.();
    $('.settings-layout').scrollTop = 0;
  }
}

export function syncTitleSearch() {
  const labels = {
    connections: ['搜索项目', 'Search items'],
    import: ['筛选候选项目', 'Filter candidates'],
    activity: ['搜索记录', 'Search activity'],
    settings: ['搜索设置', 'Search settings'],
  };
  const label = localized(...(labels[store.activePage] || labels.connections));
  const shortcutHint = isMacOS ? '⌘K' : 'Ctrl+K';
  const hasQuery = Boolean(store.pageSearch[store.activePage]);
  const control = $('#title-search');
  control.classList.toggle('has-query', hasQuery);
  const input = $('#title-search-input');
  input.hidden = false;
  input.dataset.pageSearch = store.activePage;
  input.placeholder = `${label}…`;
  input.setAttribute('aria-label', label);
  input.title = `${label} (${shortcutHint})`;
  if (input.value !== store.pageSearch[store.activePage]) input.value = store.pageSearch[store.activePage];
  const button = $('#title-search-toggle');
  button.title = hasQuery ? localized('清除搜索', 'Clear search') : `${label} (${shortcutHint})`;
  button.setAttribute('aria-label', hasQuery ? localized('清除搜索', 'Clear search') : label);
}

export function setTitleSearchOpen(open, focus = true) {
  store.titleSearchOpen = open;
  syncTitleSearch();
  if (open && focus) $('#title-search-input').focus({ preventScroll: true });
}

export async function selectPage(page) {
  if (store.editorItemId && page !== 'connections' && !await hooks.closeEditorWithDraft?.()) return;
  store.activePage = page;
  syncTitleSearch();
  $('.nav').dataset.active = page;
  $$('.nav-item').forEach((item) => {
    item.classList.toggle('active', item.dataset.page === page);
    if (item.dataset.page === page) item.setAttribute('aria-current', 'page');
    else item.removeAttribute('aria-current');
  });
  $$('.page').forEach((item) => item.classList.toggle('active', item.id === `page-${page}`));
  hooks.renderMetrics?.();
  if (page === 'connections') {
    hooks.syncListActionsWidth?.();
    hooks.syncCheckAllButton?.();
  }
  if (page === 'import') {
    store.importHub?.render?.();
    store.importHub?.focusInput?.();
  }
  if (page === 'settings') hooks.scanAgents?.();
}

export async function selectCreationMode(mode) {
  if (mode === 'draft' && !store.editorDrafts[0]) return;
  if (!await hooks.openEditor?.(null, mode === 'draft' ? store.editorDrafts[0] : null)) return;
  store.creationMode = mode;
  hooks.renderDrafts?.();
}

// Travelling cap drag lifecycle shared by filter strips, toggles, nav, language & module switches.
function switchControlFor(target) {
  const strip = target.closest?.('.filter-strip, .title-switch, .language-switch, .nav, .switch, .module-agent-toggle');
  if (!strip || strip.closest('[inert]') || strip.matches(':disabled, [aria-disabled="true"]')) return null;
  if (strip.matches('.title-switch')) {
    return {
      strip,
      count: 2,
      read: () => Number(strip.getAttribute('aria-checked') === 'true'),
      preview: $$('.title-switch-option', strip),
      focus: () => strip,
      commit: (index) => window.OpenKeyletAppearance[strip.id === 'theme-toggle' ? 'setTheme' : 'setSound'](Boolean(index)),
    };
  }
  if (strip.matches('.switch')) {
    const input = $('input', strip);
    if (input.disabled) return null;
    return {
      strip,
      count: 2,
      read: () => Number(input.checked),
      focus: () => input,
      disabled: () => input.disabled,
      commit: async (index) => {
        input.checked = Boolean(index);
        if (input.id === 'desktop-shortcut-enabled') await hooks.setSystemIntegration?.('desktop', input.checked);
        else if (input.id === 'launch-at-login-enabled') await hooks.setSystemIntegration?.('startup', input.checked);
        else if (input.id === 'browser-enabled' || input.id === 'browser-agent-passkey-enabled') await hooks.saveBrowserSettings?.();
        else if (input.id === 'auto-check-enabled') await hooks.saveDesktopSettings?.();
        else if (input.id === 'pin-enabled') await hooks.savePinSettings?.();
        else input.dispatchEvent(new Event('change', { bubbles: true }));
      },
    };
  }
  if (strip.matches('.module-agent-toggle')) {
    return {
      strip,
      count: 2,
      read: () => Number(strip.getAttribute('aria-pressed') === 'true'),
      focus: () => strip,
      commit: (index) => hooks.setModuleAgentVisibility?.(strip, Boolean(index)),
    };
  }
  const buttons = $$('button', strip);
  const read = () => buttons.findIndex((button) => (
    strip.matches('.nav, .language-switch')
      ? button.classList.contains('active')
      : button.getAttribute('aria-pressed') === 'true'
  ));
  return {
    strip,
    count: buttons.length,
    buttons,
    preview: buttons,
    read,
    disabled: (index) => buttons[index]?.disabled,
    focus: () => buttons[read()],
    commit: async (index) => {
      const button = buttons[index];
      if (strip.matches('.filter-strip')) await selectFilterButton(button);
      else if (strip.matches('.language-switch')) await setLanguage(button.dataset.language);
      else if (strip.matches('.nav')) await selectPage(button.dataset.page);
      else await selectCreationMode(button.id === 'drafts-button' ? 'draft' : 'add');
    },
  };
}

function moveSwitchThumb(event) {
  const drag = store.switchPointerDrag;
  if (!drag || event.pointerId !== drag.pointerId) return;
  const dx = event.clientX - drag.startX;
  if (!drag.started && Math.abs(dx) < 4) return;
  if (!drag.started && event.pointerType === 'touch' && Math.abs(event.clientY - drag.startY) > Math.abs(dx)) return;
  event.preventDefault();
  if (!drag.started) {
    drag.started = true;
    drag.strip.classList.add('is-dragging');
    drag.strip.classList.add('has-drag-preview');
    drag.strip.setPointerCapture(event.pointerId);
  }
  const position = Math.max(0, Math.min(drag.count - 1, drag.origin + dx / drag.cellWidth));
  drag.index = Math.round(position);
  drag.strip.style.setProperty('--drag-type', position);
  drag.preview?.forEach((button, index) => button.classList.toggle('is-preview', index === drag.index && !drag.disabled?.(index)));
}

export async function finishSwitchDrag(commit) {
  const drag = store.switchPointerDrag;
  if (!drag) return;
  store.switchPointerDrag = null;
  if (drag.strip.hasPointerCapture(drag.pointerId)) drag.strip.releasePointerCapture(drag.pointerId);
  drag.strip.classList.remove('is-dragging');
  drag.preview?.forEach((button) => button.classList.remove('is-preview'));
  if (drag.started) {
    store.suppressSwitchClick = drag.strip;
  }
  if (commit && drag.started && drag.index !== drag.read() && !drag.disabled?.(drag.index) && drag.strip.isConnected) {
    store.switchSelectionPending = true;
    drag.strip.setAttribute('aria-busy', 'true');
    drag.strip.style.setProperty('--drag-type', drag.index);
    try {
      if (store.titleSearchOpen) setTitleSearchOpen(false, false);
      await drag.commit(drag.index);
      if (drag.read() === drag.index && drag.strip.id !== 'sound-toggle' && drag.strip.id !== 'theme-toggle') {
        const isBinary = drag.strip.matches('.switch, .module-agent-toggle');
        window.OpenKeyletAppearance.feedback(isBinary ? (drag.index ? 'toggleOn' : 'toggleOff') : 'select');
      }
    } catch (error) {
      toast(cleanError(error), 'error');
    } finally {
      store.switchSelectionPending = false;
      drag.strip.removeAttribute('aria-busy');
      drag.strip.style.removeProperty('--drag-type');
      drag.strip.classList.remove('has-drag-preview');
      if (!store.confirmationResolver && (drag.strip.contains(document.activeElement) || document.activeElement === document.body)) {
        drag.focus()?.focus({ preventScroll: true });
      }
    }
  } else {
    drag.strip.style.removeProperty('--drag-type');
    drag.strip.classList.remove('has-drag-preview');
  }
}

export function initSwitchDragging() {
  document.addEventListener('pointerdown', (event) => {
    store.suppressSwitchClick = null;
    if (event.button !== 0 || !event.isPrimary || store.switchPointerDrag || store.switchSelectionPending || event.ctrlKey || event.metaKey) return;
    const control = switchControlFor(event.target);
    if (!control) return;
    const { strip } = control;
    const button = event.target.closest('button');
    if (button?.disabled) return;
    const style = getComputedStyle(strip);
    const width = strip.getBoundingClientRect().width - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
    const origin = control.buttons?.includes(button) ? control.buttons.indexOf(button) : control.read();
    const cellWidth = parseFloat(style.getPropertyValue('--switch-travel')) || width / control.count;
    store.switchPointerDrag = {
      ...control,
      pointerId: event.pointerId,
      startX: event.clientX,
      startY: event.clientY,
      origin,
      index: origin,
      cellWidth,
      started: false,
    };
  });
  document.addEventListener('pointermove', moveSwitchThumb, { passive: false });
  document.addEventListener('pointerup', (event) => {
    if (store.switchPointerDrag?.pointerId === event.pointerId) {
      moveSwitchThumb(event);
      void finishSwitchDrag(true);
    }
  });
  document.addEventListener('pointercancel', (event) => {
    if (store.switchPointerDrag?.pointerId === event.pointerId) void finishSwitchDrag(false);
  });
  document.addEventListener('lostpointercapture', (event) => {
    if (store.switchPointerDrag?.pointerId === event.pointerId) void finishSwitchDrag(false);
  });
  window.addEventListener('blur', () => { void finishSwitchDrag(false); });
  document.addEventListener('click', (event) => {
    const strip = store.suppressSwitchClick;
    store.suppressSwitchClick = null;
    if (!strip || event.detail === 0 || !strip.contains(event.target)) return;
    event.preventDefault();
    event.stopImmediatePropagation();
  }, true);
}
