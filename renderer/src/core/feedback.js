/* Toasts, localized error sanitization, and destructive confirmation modal. */
import { $, $$, HAN_TEXT } from './dom.js';
import { store, hooks } from './store.js';
import { localized } from '../i18n/index.js';

export function publicMessage(value, fallback = localized('操作失败', 'Operation failed')) {
  const raw = String(value || '').replace(/^Error:\s*/, '');
  if (store.language === 'zh' || !HAN_TEXT.test(raw)) return raw || fallback;
  return fallback;
}

export function cleanError(error) {
  return publicMessage(error?.message || error, localized('未知错误', 'Unknown error'));
}

export function toast(message, type = '') {
  if (type === 'error') window.OpenKeyletAppearance?.play?.('danger');
  const item = document.createElement('div');
  item.className = `toast ${type}`;
  item.textContent = message;
  $('#toast-region').append(item);
  setTimeout(() => item.remove(), 3200);
}

export function finishConfirmation(accepted, restoreFocus = true) {
  if (!store.confirmationResolver) return;
  const resolve = store.confirmationResolver;
  store.confirmationResolver = null;
  $('#confirmation-modal').classList.add('hidden');
  store.confirmationInertElements.forEach((element) => { element.inert = false; });
  store.confirmationInertElements = [];
  if (restoreFocus) {
    let previousFocus = store.confirmationPreviousFocus;
    if (!previousFocus?.isConnected && previousFocus?.dataset.action && previousFocus?.dataset.id) {
      previousFocus = $$('[data-action][data-id]').find(
        (button) => button.dataset.action === previousFocus.dataset.action && button.dataset.id === previousFocus.dataset.id,
      );
    }
    if (previousFocus?.isConnected && !previousFocus.closest('.hidden')) previousFocus.focus();
    else if ($('#connection-modal').classList.contains('hidden')) {
      (store.activePage === 'import' ? $('#add-connection-button') : $('#vault-view-toggle'))?.focus();
    }
  }
  store.confirmationPreviousFocus = null;
  resolve(accepted);
}

export function confirmDestructiveAction({
  title,
  message,
  acceptLabel = localized('删除', 'DELETE'),
  tag = localized('确认删除', 'CONFIRM DELETION'),
}) {
  if (store.confirmationResolver) return Promise.resolve(false);
  hooks.finishModulePointerDrag?.(false);
  $('#confirmation-tag').textContent = tag;
  $('#confirmation-title').textContent = title;
  $('#confirmation-message').textContent = message;
  $('#confirmation-cancel').textContent = localized('取消', 'CANCEL');
  $('#confirmation-accept').textContent = acceptLabel;
  store.confirmationPreviousFocus = document.activeElement;
  store.confirmationInertElements = [...document.body.children].filter(
    (element) => element !== $('#confirmation-modal') && !element.inert && !['SCRIPT', 'STYLE'].includes(element.tagName),
  );
  store.confirmationInertElements.forEach((element) => { element.inert = true; });
  $('#confirmation-modal').classList.remove('hidden');
  requestAnimationFrame(() => { if (store.confirmationResolver) $('#confirmation-cancel').focus(); });
  return new Promise((resolve) => { store.confirmationResolver = resolve; });
}

export function toastImportSummary(summary) {
  window.OpenKeyletAppearance?.play?.('success');
  toast(localized(
    `导入完成：新增 ${summary.added}，合并重复 ${summary.merged}`,
    `Import complete: ${summary.added} added, ${summary.merged} duplicates merged`,
  ));
}
