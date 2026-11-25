/* Activity log rendering, filtering, incremental pagination, and log cleanup. */
import { $, $$, escapeHtml, normalizeSearch } from '../core/dom.js';
import { store, hooks, ACTIVITY_PAGE_SIZE } from '../core/store.js';
import { api } from '../core/api.js';
import { cleanError, publicMessage, toast, confirmDestructiveAction } from '../core/feedback.js';
import { CARD_ACTION_ICONS, activityAction, activitySource, formatTime } from '../core/item-schema.js';
import { localized } from '../i18n/index.js';
import { syncActivityFilterControl, syncTitleSearch } from './navigation.js';

export function getFilteredActivities() {
  const query = normalizeSearch(store.pageSearch.activity);
  return store.state.activities
    .map((activity, sourceIndex) => ({ activity, sourceIndex }))
    .filter(({ activity }) => {
      if (store.currentActivityFilter !== 'all' && activity.status !== store.currentActivityFilter) return false;
      return !query || normalizeSearch([activity.action, activity.connectionName, activity.source, activity.status, activity.error].join(' ')).includes(query);
    });
}

export function isActivityFilterActive() {
  return store.currentActivityFilter !== 'all' || Boolean(normalizeSearch(store.pageSearch.activity));
}

export function syncClearActivityButton(matchedCount) {
  const button = $('#clear-activity-button');
  if (!button) return;
  const totalCount = store.state?.activities?.length || 0;
  const filtering = isActivityFilterActive() && matchedCount < totalCount;
  button.textContent = filtering ? localized('删除匹配', 'DELETE SHOWN') : localized('清空记录', 'CLEAR LOG');
  button.title = filtering
    ? localized(`删除当前筛选出的 ${matchedCount} 条记录`, `Delete ${matchedCount} matching log entries`)
    : localized('清空全部本地操作记录', 'Clear all local activity logs');
  button.disabled = filtering ? matchedCount === 0 : totalCount === 0;
}

export async function deleteSingleActivity(id, triggerEl = null) {
  if (!id) return;
  const rowsBefore = $$('#activity-list .activity-item');
  const currentIndex = rowsBefore.findIndex((row) => row.dataset.activityId === id);
  const restoreFocus = Boolean(triggerEl && (document.activeElement === triggerEl || triggerEl.closest?.('.activity-item') === document.activeElement));
  if (triggerEl) triggerEl.disabled = true;
  try {
    await api.deleteActivity(id);
    store.expandedActivityErrors.delete(id);
    store.state.activities = store.state.activities.filter((entry) => entry.id !== id);
    renderActivity();
    hooks.renderMetrics?.();
    toast(localized('已删除该条记录', 'Log entry deleted'));
    if (restoreFocus) {
      const rowsAfter = $$('#activity-list .activity-item');
      const nextRow = rowsAfter[Math.min(currentIndex, rowsAfter.length - 1)];
      (nextRow && $('[data-action="delete-activity"]', nextRow))?.focus({ preventScroll: true });
    }
  } catch (error) {
    if (triggerEl) triggerEl.disabled = false;
    toast(cleanError(error), 'error');
  }
}

export function renderActivity() {
  syncActivityFilterControl();
  const container = $('#activity-list');
  const activities = getFilteredActivities();
  store.activityMatchCount = activities.length;
  syncClearActivityButton(activities.length);
  if (!activities.length) {
    const hasActivity = store.state.activities.length > 0;
    container.innerHTML = `<div class="empty-state"><div><h3>${hasActivity ? localized('没有匹配记录', 'NO MATCHING ACTIVITY') : localized('暂无操作记录', 'NO ACTIVITY YET')}</h3><p>${hasActivity ? localized('当前搜索或结果筛选没有记录。', 'No activity matches the current search and result filter.') : localized('Agent 使用 OpenKeylet 后，这里只显示不含秘密的摘要。', 'After an agent uses OpenKeylet, only secret-free summaries appear here.')}</p>${hasActivity ? `<button class="button primary" data-action="clear-activity-filters">${localized('重置搜索与筛选', 'RESET SEARCH & FILTER')}</button>` : ''}</div></div>`;
    return;
  }
  const deleteLabel = localized('删除此记录', 'Delete log entry');
  container.innerHTML = activities.slice(0, store.activityVisibleCount).map(({ activity, sourceIndex }) => {
    const errorExpanded = store.expandedActivityErrors.has(activity.id);
    return `<article class="activity-item" data-activity-id="${escapeHtml(activity.id)}" data-activity-status="${escapeHtml(activity.status)}" tabindex="-1"><div class="log-index">${String(store.state.activities.length - sourceIndex).padStart(4, '0')}</div><div class="activity-status ${activity.status === 'error' ? 'error' : ''}">${activity.status === 'error' ? '×' : '✓'}</div><div class="activity-copy"><div class="activity-title">${escapeHtml(activityAction(activity.action))} · ${escapeHtml(activity.connectionName)}</div><div class="activity-meta">${escapeHtml(activitySource(activity.source))} · ${activity.durationMs} ms</div>${activity.error ? `<button type="button" class="activity-error ${errorExpanded ? 'expanded' : ''}" data-expand-error="${activity.id}" aria-expanded="${errorExpanded}">${escapeHtml(publicMessage(activity.error, localized('操作失败', 'Operation failed. Details are available in the local log.')))}</button>` : ''}</div><div class="activity-trailing"><time class="activity-time">${formatTime(activity.time)}</time><button type="button" class="small-button delete activity-delete-btn" data-action="delete-activity" data-activity-id="${escapeHtml(activity.id)}" title="${escapeHtml(deleteLabel)}" aria-label="${escapeHtml(deleteLabel)}">${CARD_ACTION_ICONS.del}</button></div></article>`;
  }).join('');
}

export function queueMoreActivities() {
  if (store.activityLoadPending || store.activityVisibleCount >= store.activityMatchCount) return;
  store.activityLoadPending = true;
  setTimeout(() => {
    store.activityVisibleCount = Math.min(store.activityVisibleCount + ACTIVITY_PAGE_SIZE, store.activityMatchCount);
    renderActivity();
    store.activityLoadPending = false;
  }, 120);
}

export function initActivityView() {
  $('#page-activity .activity-panel').addEventListener('scroll', (event) => {
    const panel = event.currentTarget;
    if (panel.scrollHeight - panel.scrollTop - panel.clientHeight < 160) queueMoreActivities();
  }, { passive: true });

  $('#clear-activity-button').addEventListener('click', async () => {
    const matched = getFilteredActivities();
    const filtering = isActivityFilterActive() && matched.length < store.state.activities.length;
    if (filtering) {
      if (!matched.length) return;
      const count = matched.length;
      if (!await confirmDestructiveAction({
        title: localized(`删除当前筛选的 ${count} 条记录？`, `Delete ${count} matching log entries?`),
        message: localized('仅删除当前筛选结果中的本地操作记录，其余记录将保留。', 'Only matching local activity entries will be permanently deleted. Other entries will be kept.'),
        acceptLabel: localized('删除', 'DELETE'),
        tag: localized('确认清空记录', 'CONFIRM LOG DELETION'),
      })) return;
      try {
        const ids = matched.map(({ activity }) => activity.id);
        await api.deleteActivities(ids);
        ids.forEach((id) => store.expandedActivityErrors.delete(id));
        toast(localized(`已删除 ${count} 条操作记录`, `Deleted ${count} log entries`));
        await hooks.refresh?.();
      } catch (error) {
        toast(cleanError(error), 'error');
      }
      return;
    }
    if (!store.state.activities.length) return;
    if (!await confirmDestructiveAction({
      title: localized('清空本地操作记录？', 'Clear the local activity log?'),
      message: localized('全部本地操作记录将永久删除。', 'All local activity entries will be permanently deleted.'),
      acceptLabel: localized('清空', 'CLEAR'),
      tag: localized('确认清空记录', 'CONFIRM LOG DELETION'),
    })) return;
    try {
      await api.clear();
      store.currentActivityFilter = 'all';
      store.pageSearch.activity = '';
      store.expandedActivityErrors.clear();
      syncTitleSearch();
      toast(localized('已清空操作记录', 'Activity log cleared'));
      await hooks.refresh?.();
    } catch (error) {
      toast(cleanError(error), 'error');
    }
  });
}
