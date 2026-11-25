/* Shared DOM query, escaping, platform, and focus-trap helpers. */

export const $ = (selector, root = document) => root.querySelector(selector);
export const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
export const HAN_TEXT = /[\u3400-\u9fff]/;

export const isMacOS = navigator.platform.startsWith('Mac') || navigator.userAgent.includes('Macintosh');
export const isLinux = !isMacOS && navigator.platform.startsWith('Linux');
export const edgeDockSupported = !isMacOS && !isLinux;

export function value(selector, next) {
  const element = $(selector);
  if (arguments.length > 1) element.value = next ?? '';
  return element.value;
}

export function escapeHtml(raw = '') {
  return String(raw).replace(/[&<>"]/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[ch]);
}

export function normalizeSearch(raw = '') {
  return String(raw).trim().toLocaleLowerCase('zh-CN');
}

export function trapFocusInContainer(container, event, extraElements = []) {
  const selector = 'button:not(:disabled), input:not(:disabled):not([type="hidden"]), select:not(:disabled), textarea:not(:disabled), summary, [tabindex="0"]';
  const controls = [...$$(selector, container), ...extraElements.flatMap((el) => $$(selector, el))]
    .filter((control) => control.getClientRects().length && !control.closest('[inert], .hidden'));
  if (!controls.length) return;
  const first = controls[0];
  const last = controls.at(-1);
  if (
    (event.shiftKey && (document.activeElement === first || !controls.includes(document.activeElement))) ||
    (!event.shiftKey && (document.activeElement === last || !controls.includes(document.activeElement)))
  ) {
    event.preventDefault();
    (event.shiftKey ? last : first).focus();
  }
}
