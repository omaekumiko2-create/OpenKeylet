/* Accessible custom dropdown listbox enhancement for native <select> controls. */

export function initCustomSelect() {
  let menu = null;
  let activeSelect = null;
  let activeIndex = -1;
  let menuOpenedAt = 0;

  function ensureMenu() {
    if (menu) return menu;
    menu = document.createElement('div');
    menu.id = 'custom-select-menu';
    menu.className = 'custom-select-menu hidden';
    menu.setAttribute('role', 'listbox');
    menu.tabIndex = -1;
    document.body.append(menu);
    return menu;
  }

  function closeSelectMenu(restoreFocus = false) {
    if (!activeSelect) return;
    const target = activeSelect;
    activeSelect = null;
    activeIndex = -1;
    target.classList.remove('is-select-open');
    target.removeAttribute('aria-expanded');
    if (menu) {
      menu.classList.add('hidden');
      menu.classList.remove('is-flipped');
      menu.replaceChildren();
    }
    if (restoreFocus && target.isConnected) target.focus();
  }

  function setActiveIndex(nextIndex) {
    if (!menu) return;
    const items = [...menu.querySelectorAll('.custom-select-option:not(:disabled)')];
    if (!items.length) return;
    activeIndex = ((nextIndex % items.length) + items.length) % items.length;
    items.forEach((item, index) => item.classList.toggle('is-active', index === activeIndex));
    const activeItem = items[activeIndex];
    if (activeItem && menu.scrollHeight > menu.clientHeight) {
      const top = activeItem.offsetTop;
      const bottom = top + activeItem.offsetHeight;
      if (top < menu.scrollTop) menu.scrollTop = top;
      else if (bottom > menu.scrollTop + menu.clientHeight) menu.scrollTop = bottom - menu.clientHeight;
    }
  }

  function commitOption(value) {
    if (!activeSelect) return;
    const target = activeSelect;
    const changed = target.value !== value;
    target.value = value;
    closeSelectMenu(true);
    if (changed) {
      target.dispatchEvent(new Event('input', { bubbles: true }));
      target.dispatchEvent(new Event('change', { bubbles: true }));
    }
  }

  function openSelectMenu(select) {
    if (!select || select.disabled || select.multiple || !select.options.length) return;
    if (activeSelect === select) {
      closeSelectMenu(true);
      return;
    }
    closeSelectMenu(false);
    const el = ensureMenu();
    activeSelect = select;
    menuOpenedAt = performance.now();
    select.classList.add('is-select-open');
    select.setAttribute('aria-expanded', 'true');
    el.replaceChildren();

    const checkSvg = '<svg class="custom-select-check" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M3.5 8.5 6.5 11.5 12.5 4.5"/></svg>';
    const options = [...select.options];
    let selectedEnabledIdx = -1;
    let enabledCounter = 0;

    for (const opt of options) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'custom-select-option';
      btn.setAttribute('role', 'option');
      btn.dataset.value = opt.value;
      btn.disabled = opt.disabled;
      const selected = opt.value === select.value;
      btn.setAttribute('aria-selected', selected ? 'true' : 'false');
      if (!opt.disabled) {
        if (selected) selectedEnabledIdx = enabledCounter;
        enabledCounter++;
      }

      const title = opt.dataset.title || opt.textContent || '';
      const sub = opt.dataset.sub || '';
      if (sub) {
        btn.classList.add('has-sub');
        const avatar = document.createElement('span');
        avatar.className = 'custom-select-avatar';
        avatar.setAttribute('aria-hidden', 'true');
        avatar.textContent = (title.trim()[0] || '?').toUpperCase();
        const copy = document.createElement('span');
        copy.className = 'custom-select-copy';
        const titleEl = document.createElement('span');
        titleEl.className = 'custom-select-title';
        titleEl.textContent = title;
        const subEl = document.createElement('span');
        subEl.className = 'custom-select-sub';
        subEl.textContent = sub;
        copy.append(titleEl, subEl);
        btn.append(avatar, copy);
      } else {
        const titleEl = document.createElement('span');
        titleEl.className = 'custom-select-title';
        titleEl.textContent = title;
        btn.append(titleEl);
      }
      btn.insertAdjacentHTML('beforeend', checkSvg);
      btn.addEventListener('mousedown', (event) => { event.preventDefault(); });
      btn.addEventListener('click', () => { if (!btn.disabled) commitOption(opt.value); });
      el.append(btn);
    }

    el.classList.remove('hidden', 'is-flipped');
    el.style.visibility = 'hidden';
    const rect = select.getBoundingClientRect();
    const minWidth = Math.min(Math.max(rect.width, 168), window.innerWidth - 16);
    el.style.minWidth = `${minWidth}px`;
    el.style.maxWidth = `${Math.min(Math.max(rect.width, 320), window.innerWidth - 16)}px`;
    const menuRect = el.getBoundingClientRect();
    const left = Math.max(8, Math.min(rect.left, window.innerWidth - menuRect.width - 8));
    const spaceBelow = window.innerHeight - rect.bottom - 10;
    const spaceAbove = rect.top - 10;
    const flip = spaceBelow < menuRect.height && spaceAbove > spaceBelow;
    const top = flip
      ? Math.max(8, rect.top - menuRect.height - 6)
      : Math.min(window.innerHeight - menuRect.height - 8, rect.bottom + 6);
    el.classList.toggle('is-flipped', flip);
    el.style.left = `${Math.round(left)}px`;
    el.style.top = `${Math.round(top)}px`;
    el.style.visibility = '';
    setActiveIndex(selectedEnabledIdx >= 0 ? selectedEnabledIdx : 0);
  }

  document.addEventListener('mousedown', (event) => {
    if (event.button !== 0) return;
    if (menu && !menu.classList.contains('hidden') && event.target.closest('#custom-select-menu')) return;
    const select = event.target.closest('select');
    if (select && !select.disabled && !select.multiple && select.options.length) {
      event.preventDefault();
      select.focus({ preventScroll: true });
      openSelectMenu(select);
      return;
    }
    if (activeSelect) closeSelectMenu(false);
  }, true);

  document.addEventListener('keydown', (event) => {
    if (activeSelect) {
      if (event.key === 'Escape') {
        event.preventDefault();
        event.stopImmediatePropagation();
        closeSelectMenu(true);
        return;
      }
      if (event.key === 'Tab') { closeSelectMenu(false); return; }
      if (event.key === 'ArrowDown') { event.preventDefault(); setActiveIndex(activeIndex + 1); return; }
      if (event.key === 'ArrowUp') { event.preventDefault(); setActiveIndex(activeIndex - 1); return; }
      if (event.key === 'Home') { event.preventDefault(); setActiveIndex(0); return; }
      if (event.key === 'End') {
        event.preventDefault();
        const count = menu?.querySelectorAll('.custom-select-option:not(:disabled)').length || 0;
        if (count) setActiveIndex(count - 1);
        return;
      }
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        const items = [...(menu?.querySelectorAll('.custom-select-option:not(:disabled)') || [])];
        const chosen = items[activeIndex];
        if (chosen) commitOption(chosen.dataset.value);
        return;
      }
      return;
    }
    const select = document.activeElement?.tagName === 'SELECT' ? document.activeElement : null;
    if (select && !select.disabled && !select.multiple && [' ', 'Enter', 'ArrowDown', 'ArrowUp'].includes(event.key)) {
      event.preventDefault();
      openSelectMenu(select);
    }
  }, true);

  window.addEventListener('resize', () => closeSelectMenu(false));
  window.addEventListener('blur', () => closeSelectMenu(false));
  document.addEventListener('scroll', (event) => {
    if (!activeSelect) return;
    if (performance.now() - menuOpenedAt < 120) return;
    if (menu && (event.target === menu || menu.contains(event.target))) return;
    closeSelectMenu(false);
  }, true);
}
