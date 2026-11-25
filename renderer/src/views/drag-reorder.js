/* Whole-card lifted-card FLIP drag-to-reorder for vault items and editor modules. */
import { $, $$ } from '../core/dom.js';
import { store, hooks } from '../core/store.js';
import { api } from '../core/api.js';
import { cleanError, toast } from '../core/feedback.js';
import { moduleLabel } from '../core/item-schema.js';
import { localized } from '../i18n/index.js';

const ITEM_LONG_PRESS_MS = 220;
const MODULE_LONG_PRESS_MS = 240;

let itemList = null;
let moduleList = null;

export function updateItemGridRowHeight() {
  if (!itemList || !itemList.clientHeight) return;
  const style = getComputedStyle(itemList);
  const gap = parseFloat(style.rowGap) || 0;
  const padding = (parseFloat(style.paddingTop) || 0) + (parseFloat(style.paddingBottom) || 0);
  const threeRowHeight = (itemList.clientHeight - padding - 2 * gap) / 3;
  const height = itemList.clientHeight > 540
    ? Math.min(156, Math.max(86, threeRowHeight))
    : Math.max(86, threeRowHeight);
  itemList.style.setProperty('--item-row-height', `${height}px`);
}

function visibleItemIds() {
  return $$('.connection-card', itemList).map((row) => row.dataset.itemId);
}

async function saveItemOrder(visibleOrder, expectedOrder, focusedId) {
  if (store.itemOrderSaving) return;
  const visible = new Set(visibleOrder);
  let index = 0;
  const ids = expectedOrder.map((id) => (visible.has(id) ? visibleOrder[index++] : id));
  if (ids.every((id, position) => id === expectedOrder[position])) {
    hooks.renderConnections?.();
    return;
  }
  store.itemOrderSaving = true;
  itemList.setAttribute('aria-busy', 'true');
  let saved = false;
  try {
    await api.reorder(ids, expectedOrder);
    saved = true;
  } catch (error) {
    toast(cleanError(error), 'error');
  } finally {
    store.itemOrderSaving = false;
    store.renderedConnectionsSignature = '';
    await hooks.refresh?.(false);
    itemList.removeAttribute('aria-busy');
    const handle = $$('[data-item-reorder]', itemList).find((button) => button.dataset.itemReorder === focusedId);
    handle?.focus({ preventScroll: true });
    if (saved) {
      handle?.scrollIntoView({ block: 'nearest' });
      const name = store.state.connections.find((item) => item.id === focusedId)?.name || '';
      $('#item-reorder-status').textContent = localized(
        `${name}：第 ${ids.indexOf(focusedId) + 1} 项，共 ${ids.length} 项`,
        `${name}: position ${ids.indexOf(focusedId) + 1} of ${ids.length}`,
      );
    }
  }
}

function clearItemFlipTransforms() {
  for (const el of $$('.connection-card', itemList)) {
    if (el._flipTimer) {
      clearTimeout(el._flipTimer);
      el._flipTimer = 0;
    }
    el.style.transition = '';
    el.style.transform = '';
  }
}

function restoreItemDomOrder(orderIds) {
  const byId = new Map($$('.connection-card', itemList).map((el) => [el.dataset.itemId, el]));
  for (const id of orderIds) {
    const el = byId.get(id);
    if (el) itemList.appendChild(el);
  }
}

function flipReorderCard(dragRow, refRow, insertAfter) {
  const siblings = $$('.connection-card', itemList).filter((el) => el !== dragRow);
  const firstRects = new Map();
  for (const el of siblings) firstRects.set(el, el.getBoundingClientRect());
  if (insertAfter) refRow.after(dragRow);
  else refRow.before(dragRow);
  const moved = [];
  for (const el of siblings) {
    const first = firstRects.get(el);
    const last = el.getBoundingClientRect();
    const dx = first.left - last.left;
    const dy = first.top - last.top;
    if (Math.abs(dx) > 0.5 || Math.abs(dy) > 0.5) {
      el.style.transition = 'none';
      el.style.transform = `translate3d(${dx}px, ${dy}px, 0)`;
      moved.push(el);
    }
  }
  if (!moved.length) return;
  void itemList.offsetHeight;
  for (const el of moved) {
    el.style.transition = 'transform 180ms cubic-bezier(0.22, 1, 0.36, 1)';
    el.style.transform = '';
    if (el._flipTimer) clearTimeout(el._flipTimer);
    el._flipTimer = setTimeout(() => {
      el.style.transition = '';
      el._flipTimer = 0;
    }, 200);
  }
}

function beginItemDragLift(drag) {
  if (!drag || drag.started || store.itemPointerDrag !== drag) return;
  if (drag.longPressTimer) {
    clearTimeout(drag.longPressTimer);
    drag.longPressTimer = 0;
  }
  drag.started = true;
  const rect = drag.row.getBoundingClientRect();
  drag.originLeft = rect.left;
  drag.originTop = rect.top;
  drag.cardWidth = rect.width;
  drag.cardHeight = rect.height;
  drag.grabOffsetX = drag.x - rect.left;
  drag.grabOffsetY = drag.y - rect.top;

  const host = document.createElement('div');
  host.className = 'item-drag-preview connections-grid';
  host.dataset.view = store.vaultViewMode;
  host.setAttribute('aria-hidden', 'true');
  const actionsWidth = itemList.style.getPropertyValue('--list-actions-width');
  if (actionsWidth) host.style.setProperty('--list-actions-width', actionsWidth);
  host.style.width = `${rect.width}px`;
  host.style.height = `${rect.height}px`;
  const clone = drag.row.cloneNode(true);
  clone.classList.remove('is-item-dragging');
  clone.classList.add('is-lifted-card');
  clone.removeAttribute('data-item-id');
  host.appendChild(clone);
  document.body.appendChild(host);
  drag.preview = host;

  window.OpenKeyletAppearance?.hideTooltip?.();
  drag.row.classList.add('is-item-dragging');
  itemList.classList.add('is-reordering');
  document.body.classList.add('item-pointer-dragging');
  try { itemList.setPointerCapture(drag.pointerId); } catch (_) { /* Document tracking remains active. */ }
  window.OpenKeyletAppearance?.play?.('select');

  const initX = Math.max(8, Math.min(rect.left, innerWidth - rect.width - 8));
  const initY = Math.max(8, Math.min(rect.top, innerHeight - rect.height - 8));
  drag.preview.style.transform = `translate3d(${initX}px, ${initY}px, 0)`;
}

function cardLayoutRect(card, listRect) {
  if (card.offsetParent === itemList) {
    const left = listRect.left + card.offsetLeft - itemList.scrollLeft;
    const top = listRect.top + card.offsetTop - itemList.scrollTop;
    const width = card.offsetWidth;
    const height = card.offsetHeight;
    return { left, top, right: left + width, bottom: top + height, width, height };
  }
  return card.getBoundingClientRect();
}

function updateItemLivePosition() {
  const drag = store.itemPointerDrag;
  if (!drag?.started) return;
  const bounds = itemList.getBoundingClientRect();
  const isList = store.vaultViewMode === 'list';
  drag.valid = drag.x >= bounds.left && drag.x <= bounds.right && drag.y >= bounds.top && drag.y <= bounds.bottom;
  drag.preview.style.opacity = drag.valid ? '1' : '0.45';

  let posX;
  if (isList) {
    const dampX = Math.max(-10, Math.min(10, (drag.x - drag.startX) * 0.12));
    posX = Math.max(8, Math.min(drag.originLeft + dampX, innerWidth - drag.cardWidth - 8));
  } else {
    posX = Math.max(8, Math.min(drag.x - drag.grabOffsetX, innerWidth - drag.cardWidth - 8));
  }
  const posY = Math.max(8, Math.min(drag.y - drag.grabOffsetY, innerHeight - drag.cardHeight - 8));
  drag.preview.style.transform = `translate3d(${posX}px, ${posY}px, 0)`;

  if (!drag.valid) return;

  const cards = $$('.connection-card', itemList);
  const currentIdx = cards.indexOf(drag.row);
  if (currentIdx < 0) return;

  if (isList) {
    const probeY = drag.y;
    for (let i = 0; i < cards.length; i += 1) {
      const card = cards[i];
      if (card === drag.row) continue;
      const r = cardLayoutRect(card, bounds);
      const midY = r.top + r.height / 2;
      if (i < currentIdx && probeY < midY) {
        flipReorderCard(drag.row, card, false);
        break;
      }
      if (i > currentIdx && probeY > midY) {
        let targetIdx = i;
        for (let j = i + 1; j < cards.length; j += 1) {
          const rj = cardLayoutRect(cards[j], bounds);
          if (probeY > rj.top + rj.height / 2) targetIdx = j;
          else break;
        }
        flipReorderCard(drag.row, cards[targetIdx], true);
        break;
      }
    }
  } else {
    let hit = null;
    for (let i = 0; i < cards.length; i += 1) {
      const card = cards[i];
      if (card === drag.row) continue;
      const r = cardLayoutRect(card, bounds);
      if (drag.x >= r.left && drag.x <= r.right && drag.y >= r.top && drag.y <= r.bottom) {
        hit = { card, idx: i, rect: r };
        break;
      }
    }
    if (hit) flipReorderCard(drag.row, hit.card, hit.idx > currentIdx);
  }
}

function scheduleItemDragFrame() {
  const drag = store.itemPointerDrag;
  if (drag?.started && !drag.frame) drag.frame = requestAnimationFrame(itemDragFrame);
}

function itemDragFrame() {
  const drag = store.itemPointerDrag;
  if (!drag?.started) return;
  drag.frame = 0;
  const bounds = itemList.getBoundingClientRect();
  const previousScroll = itemList.scrollTop;
  if (drag.x >= bounds.left && drag.x <= bounds.right && drag.y >= bounds.top && drag.y <= bounds.bottom) {
    if (drag.y < bounds.top + 32) itemList.scrollTop -= Math.ceil((bounds.top + 32 - drag.y) / 3);
    else if (drag.y > bounds.bottom - 32) itemList.scrollTop += Math.ceil((drag.y - bounds.bottom + 32) / 3);
  }
  updateItemLivePosition();
  if (itemList.scrollTop !== previousScroll) scheduleItemDragFrame();
}

export function finishItemPointerDrag(commit) {
  const drag = store.itemPointerDrag;
  if (!drag) return;
  store.itemPointerDrag = null;
  if (drag.longPressTimer) {
    clearTimeout(drag.longPressTimer);
    drag.longPressTimer = 0;
  }
  cancelAnimationFrame(drag.frame);
  try { if (itemList.hasPointerCapture(drag.pointerId)) itemList.releasePointerCapture(drag.pointerId); } catch (_) {}
  const finalIds = drag.started ? $$('.connection-card', itemList).map((el) => el.dataset.itemId) : [];
  drag.row.classList.remove('is-item-dragging');
  itemList.classList.remove('is-reordering');
  document.body.classList.remove('item-pointer-dragging');
  drag.preview?.remove();
  clearItemFlipTransforms();
  if (drag.started) {
    store.suppressItemClick = true;
    const changed = finalIds.length === drag.visibleOrder.length && finalIds.some((id, idx) => id !== drag.visibleOrder[idx]);
    if (commit && drag.valid) window.OpenKeyletAppearance?.play?.('drop');
    if (commit && drag.valid && changed) {
      void saveItemOrder(finalIds, drag.expectedOrder, drag.id);
    } else {
      restoreItemDomOrder(drag.visibleOrder);
      hooks.renderConnections?.();
    }
  }
}

function clearModuleFlipTransforms() {
  for (const row of $$('.module-row', moduleList)) {
    row.style.transition = '';
    row.style.transform = '';
    if (row._flipTimer) {
      clearTimeout(row._flipTimer);
      row._flipTimer = 0;
    }
  }
}

function flipReorderModuleRow(dragRow, targetRow, insertAfter) {
  if (!dragRow || !targetRow || dragRow === targetRow) return;
  const rows = $$('.module-row', moduleList);
  const beforeRects = new Map();
  for (const row of rows) {
    if (row !== dragRow) beforeRects.set(row, row.getBoundingClientRect());
  }
  moduleList.insertBefore(dragRow, insertAfter ? targetRow.nextElementSibling : targetRow);
  const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)')?.matches;
  for (const [row, prev] of beforeRects) {
    const next = row.getBoundingClientRect();
    const dy = prev.top - next.top;
    if (Math.abs(dy) < 0.5 || reduced) continue;
    row.style.transition = 'none';
    row.style.transform = `translate3d(0, ${dy}px, 0)`;
    void row.offsetHeight;
    row.style.transition = 'transform 180ms cubic-bezier(0.22, 1, 0.36, 1)';
    row.style.transform = '';
    if (row._flipTimer) clearTimeout(row._flipTimer);
    row._flipTimer = setTimeout(() => {
      row.style.transition = '';
      row._flipTimer = 0;
    }, 200);
  }
}

function cloneModuleRowForLift(row) {
  const clone = row.cloneNode(true);
  clone.classList.remove('is-dragging');
  clone.classList.add('is-lifted-card');
  const origInputs = $$('input, textarea, select', row);
  const cloneInputs = $$('input, textarea, select', clone);
  origInputs.forEach((src, i) => {
    const dst = cloneInputs[i];
    if (!dst) return;
    dst.value = src.value;
    dst.tabIndex = -1;
    if (src.tagName === 'INPUT') dst.type = src.type;
    if (src.tagName === 'TEXTAREA' && src.style.height) dst.style.height = src.style.height;
  });
  return clone;
}

function beginModuleDragLift(drag) {
  if (!drag || drag.started || store.modulePointerDrag !== drag) return;
  if (drag.longPressTimer) {
    clearTimeout(drag.longPressTimer);
    drag.longPressTimer = 0;
  }
  drag.started = true;
  const rect = drag.row.getBoundingClientRect();
  drag.originLeft = rect.left;
  drag.originTop = rect.top;
  drag.cardWidth = rect.width;
  drag.cardHeight = rect.height;
  drag.grabOffsetX = drag.x - rect.left;
  drag.grabOffsetY = drag.y - rect.top;

  const host = document.createElement('div');
  host.className = 'module-drag-preview';
  host.setAttribute('aria-hidden', 'true');
  host.style.width = `${rect.width}px`;
  host.style.height = `${rect.height}px`;
  host.appendChild(cloneModuleRowForLift(drag.row));
  document.body.appendChild(host);
  drag.preview = host;

  window.OpenKeyletAppearance?.hideTooltip?.();
  drag.row.classList.add('is-dragging');
  moduleList.classList.add('is-sorting');
  document.body.classList.add('module-pointer-dragging');
  try { moduleList.setPointerCapture(drag.pointerId); } catch (_) {}
  window.OpenKeyletAppearance?.play?.('select');

  const initX = Math.max(8, Math.min(rect.left, window.innerWidth - rect.width - 8));
  const initY = Math.max(8, Math.min(rect.top, window.innerHeight - rect.height - 8));
  drag.preview.style.transform = `translate3d(${initX}px, ${initY}px, 0)`;
}

function updateModuleLivePosition() {
  const drag = store.modulePointerDrag;
  if (!drag?.started) return;
  const scroller = $('.form-scroll', $('#connection-modal'));
  const bounds = (scroller || moduleList).getBoundingClientRect();
  drag.valid = drag.x >= bounds.left - 24 && drag.x <= bounds.right + 24 && drag.y >= bounds.top - 24 && drag.y <= bounds.bottom + 24;
  drag.preview.style.opacity = drag.valid ? '1' : '0.45';

  const dampX = Math.max(-10, Math.min(10, (drag.x - drag.startX) * 0.12));
  const posX = Math.max(8, Math.min(drag.originLeft + dampX, window.innerWidth - drag.cardWidth - 8));
  const posY = Math.max(8, Math.min(drag.y - drag.grabOffsetY, window.innerHeight - drag.cardHeight - 8));
  drag.preview.style.transform = `translate3d(${posX}px, ${posY}px, 0)`;

  if (!drag.valid) return;

  const rows = $$('.module-row', moduleList);
  const currentIdx = rows.indexOf(drag.row);
  if (currentIdx < 0) return;

  const probeY = drag.y;
  for (let i = 0; i < rows.length; i += 1) {
    const row = rows[i];
    if (row === drag.row) continue;
    const r = row.getBoundingClientRect();
    const midY = r.top + r.height / 2;
    if (i < currentIdx && probeY < midY) {
      flipReorderModuleRow(drag.row, row, false);
      break;
    }
    if (i > currentIdx && probeY > midY) {
      let targetIdx = i;
      for (let j = i + 1; j < rows.length; j += 1) {
        const rj = rows[j].getBoundingClientRect();
        if (probeY > rj.top + rj.height / 2) targetIdx = j;
        else break;
      }
      flipReorderModuleRow(drag.row, rows[targetIdx], true);
      break;
    }
  }
}

function scheduleModuleDragFrame() {
  const drag = store.modulePointerDrag;
  if (drag?.started && !drag.frame) drag.frame = requestAnimationFrame(moduleDragFrame);
}

function moduleDragFrame() {
  const drag = store.modulePointerDrag;
  if (!drag?.started) return;
  drag.frame = 0;
  const scroller = $('.form-scroll', $('#connection-modal'));
  if (scroller) {
    const bounds = scroller.getBoundingClientRect();
    const previousScroll = scroller.scrollTop;
    if (drag.x >= bounds.left && drag.x <= bounds.right && drag.y >= bounds.top && drag.y <= bounds.bottom) {
      if (drag.y < bounds.top + 32) scroller.scrollTop -= Math.ceil((bounds.top + 32 - drag.y) / 3);
      else if (drag.y > bounds.bottom - 32) scroller.scrollTop += Math.ceil((drag.y - bounds.bottom + 32) / 3);
    }
    updateModuleLivePosition();
    if (scroller.scrollTop !== previousScroll) scheduleModuleDragFrame();
  } else {
    updateModuleLivePosition();
  }
}

function announceModuleOrder(row) {
  const rows = $$('.module-row', moduleList);
  const name = $('[data-module-name]', row)?.value.trim() || moduleLabel(row.dataset.kind);
  const position = rows.indexOf(row) + 1;
  $('#module-reorder-status').textContent = localized(
    `${name}：第 ${position} 项，共 ${rows.length} 项`,
    `${name}: position ${position} of ${rows.length}`,
  );
}

export function finishModulePointerDrag(commit) {
  const drag = store.modulePointerDrag;
  if (!drag) return;
  store.modulePointerDrag = null;
  if (drag.longPressTimer) {
    clearTimeout(drag.longPressTimer);
    drag.longPressTimer = 0;
  }
  cancelAnimationFrame(drag.frame);
  try { if (moduleList.hasPointerCapture(drag.pointerId)) moduleList.releasePointerCapture(drag.pointerId); } catch (_) {}
  drag.row.classList.remove('is-dragging');
  moduleList.classList.remove('is-sorting');
  document.body.classList.remove('module-pointer-dragging');
  drag.preview?.remove();
  clearModuleFlipTransforms();
  if (drag.started) {
    if (commit && drag.valid) {
      window.OpenKeyletAppearance?.play?.('drop');
      hooks.syncModuleDraft?.();
      announceModuleOrder(drag.row);
    } else if (drag.initialOrder?.length) {
      for (const row of drag.initialOrder) {
        if (row.parentElement === moduleList) moduleList.appendChild(row);
      }
      hooks.syncModuleDraft?.();
    }
  }
}

export function initDragReorder() {
  itemList = $('#connections-list');
  moduleList = $('#module-list');
  new ResizeObserver(updateItemGridRowHeight).observe(itemList);

  // Vault card list / grid pointer & keyboard reorder
  itemList.addEventListener('dragstart', (event) => {
    if (event.target.closest?.('.connection-card')) event.preventDefault();
  });
  document.addEventListener('pointerdown', () => { store.suppressItemClick = false; }, true);
  itemList.addEventListener('pointerdown', (event) => {
    const card = event.target.closest?.('.connection-card[data-item-id]');
    if (!card || event.target.closest?.('.card-actions, .item-toggle')) return;
    if (event.button !== 0 || !event.isPrimary || event.ctrlKey || event.metaKey || event.shiftKey || store.itemPointerDrag || store.itemOrderSaving || store.confirmationResolver || !store.ownerLockState.unlocked) return;
    const id = card.dataset.itemId;
    const item = store.state.connections.find((candidate) => candidate.id === id);
    if (!item) return;
    const drag = {
      id,
      item,
      row: card,
      pointerId: event.pointerId,
      pointerType: event.pointerType || 'mouse',
      startX: event.clientX,
      startY: event.clientY,
      x: event.clientX,
      y: event.clientY,
      started: false,
      valid: true,
      frame: 0,
      visibleOrder: visibleItemIds(),
      expectedOrder: store.state.connections.map((candidate) => candidate.id),
      longPressTimer: 0,
    };
    drag.longPressTimer = setTimeout(() => {
      if (store.itemPointerDrag === drag && !drag.started) beginItemDragLift(drag);
    }, ITEM_LONG_PRESS_MS);
    store.itemPointerDrag = drag;
  });
  document.addEventListener('pointermove', (event) => {
    const drag = store.itemPointerDrag;
    if (!drag || event.pointerId !== drag.pointerId) return;
    drag.x = event.clientX;
    drag.y = event.clientY;
    const dist = Math.hypot(drag.x - drag.startX, drag.y - drag.startY);
    if (!drag.started) {
      if (drag.pointerType === 'touch') {
        if (dist >= 10) finishItemPointerDrag(false);
        return;
      }
      if (dist < 8) return;
      event.preventDefault();
      beginItemDragLift(drag);
      updateItemLivePosition();
      return;
    }
    event.preventDefault();
    scheduleItemDragFrame();
  }, { passive: false });
  document.addEventListener('pointerup', (event) => {
    if (store.itemPointerDrag?.pointerId !== event.pointerId) return;
    if (store.itemPointerDrag.started) {
      event.preventDefault();
      updateItemLivePosition();
    }
    finishItemPointerDrag(true);
  });
  document.addEventListener('pointercancel', (event) => {
    if (store.itemPointerDrag?.pointerId === event.pointerId) finishItemPointerDrag(false);
  });
  itemList.addEventListener('lostpointercapture', (event) => {
    if (store.itemPointerDrag?.pointerId === event.pointerId) finishItemPointerDrag(false);
  });
  window.addEventListener('blur', () => finishItemPointerDrag(false));
  document.addEventListener('click', (event) => {
    if (!store.suppressItemClick) return;
    store.suppressItemClick = false;
    if (event.detail === 0) return;
    event.preventDefault();
    event.stopImmediatePropagation();
  }, true);
  itemList.addEventListener('keydown', (event) => {
    const handle = event.target.closest?.('[data-item-reorder]');
    if (!handle || store.itemPointerDrag || store.itemOrderSaving || store.confirmationResolver || !store.ownerLockState.unlocked || event.altKey || event.ctrlKey || event.metaKey || !['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    event.stopPropagation();
    const ids = visibleItemIds();
    const id = handle.dataset.itemReorder;
    const from = ids.indexOf(id);
    const step = store.vaultViewMode === 'list'
      ? { ArrowUp: -1, ArrowDown: 1, ArrowLeft: -1, ArrowRight: 1 }[event.key]
      : { ArrowUp: -4, ArrowDown: 4, ArrowLeft: -1, ArrowRight: 1 }[event.key];
    const to = event.key === 'Home' ? 0 : event.key === 'End' ? ids.length - 1 : Math.max(0, Math.min(ids.length - 1, from + step));
    if (to === from) return;
    ids.splice(from, 1);
    ids.splice(to, 0, id);
    void saveItemOrder(ids, store.state.connections.map((item) => item.id), id);
  });

  // Editor module rows pointer & keyboard reorder
  moduleList.addEventListener('dragstart', (event) => {
    if (event.target.closest?.('.module-row')) event.preventDefault();
  });
  moduleList.addEventListener('pointerdown', (event) => {
    if (event.button !== 0 || !event.isPrimary || event.ctrlKey || event.metaKey || event.shiftKey || store.confirmationResolver || store.modulePointerDrag) return;
    const row = event.target.closest?.('.module-row');
    if (!row) return;
    if (event.target.closest?.('input, textarea, select, button, a, .module-agent-toggle, .module-actions')) return;
    const drag = {
      row,
      pointerId: event.pointerId,
      pointerType: event.pointerType || 'mouse',
      startX: event.clientX,
      startY: event.clientY,
      x: event.clientX,
      y: event.clientY,
      started: false,
      valid: true,
      frame: 0,
      preview: null,
      initialOrder: $$('.module-row', moduleList),
      longPressTimer: 0,
    };
    drag.longPressTimer = setTimeout(() => {
      if (store.modulePointerDrag === drag && !drag.started) beginModuleDragLift(drag);
    }, MODULE_LONG_PRESS_MS);
    store.modulePointerDrag = drag;
  });
  moduleList.addEventListener('keydown', (event) => {
    const handle = event.target.closest?.('[data-module-drag-handle]');
    if (!handle || event.target.matches?.('input, textarea, select') || store.confirmationResolver || store.modulePointerDrag || !['ArrowUp', 'ArrowDown'].includes(event.key)) return;
    event.preventDefault();
    const row = handle.closest('.module-row');
    const sibling = event.key === 'ArrowUp' ? row.previousElementSibling : row.nextElementSibling;
    if (!sibling) return;
    flipReorderModuleRow(row, sibling, event.key === 'ArrowDown');
    hooks.syncModuleDraft?.();
    handle.focus({ preventScroll: true });
    row.scrollIntoView({ block: 'nearest' });
    announceModuleOrder(row);
  });
  document.addEventListener('pointermove', (event) => {
    const drag = store.modulePointerDrag;
    if (!drag || event.pointerId !== drag.pointerId) return;
    drag.x = event.clientX;
    drag.y = event.clientY;
    const dist = Math.hypot(drag.x - drag.startX, drag.y - drag.startY);
    if (!drag.started) {
      if (drag.pointerType === 'touch') {
        if (dist >= 10) finishModulePointerDrag(false);
        return;
      }
      if (dist < 6) return;
      event.preventDefault();
      beginModuleDragLift(drag);
      updateModuleLivePosition();
      return;
    }
    event.preventDefault();
    scheduleModuleDragFrame();
  }, { passive: false });
  document.addEventListener('pointerup', (event) => {
    if (!store.modulePointerDrag || event.pointerId !== store.modulePointerDrag.pointerId) return;
    if (store.modulePointerDrag.started) {
      event.preventDefault();
      updateModuleLivePosition();
      store.suppressModuleClick = true;
      setTimeout(() => { store.suppressModuleClick = false; }, 0);
    }
    finishModulePointerDrag(true);
  });
  document.addEventListener('pointercancel', (event) => {
    if (store.modulePointerDrag?.pointerId === event.pointerId) finishModulePointerDrag(false);
  });
  moduleList.addEventListener('lostpointercapture', (event) => {
    if (store.modulePointerDrag?.pointerId === event.pointerId) finishModulePointerDrag(false);
  });
  document.addEventListener('click', (event) => {
    if (!store.suppressModuleClick) return;
    store.suppressModuleClick = false;
    if (event.target.closest?.('.module-row')) {
      event.preventDefault();
      event.stopImmediatePropagation();
    }
  }, true);
  window.addEventListener('blur', () => {
    if (store.modulePointerDrag) finishModulePointerDrag(false);
  });
}
