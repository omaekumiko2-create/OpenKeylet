/* Local presentation preferences & tactile acoustic feedback (independent of the encrypted vault). */
(() => {
  // Set native shell platform classes before the first frame is painted.
  const isMac = navigator.platform.startsWith('Mac') || navigator.userAgent.includes('Macintosh');
  document.documentElement.classList.toggle('platform-macos', isMac);
  document.documentElement.classList.toggle('platform-linux', !isMac && navigator.platform.startsWith('Linux'));
  const storageKey = 'openkeylet.appearance.v1';
  let preferences = { theme: 'dark', sound: true };
  try {
    const saved = JSON.parse(localStorage.getItem(storageKey) || 'null');
    preferences = {
      theme: saved?.theme === 'light' ? 'light' : 'dark',
      sound: saved && typeof saved.sound === 'boolean' ? saved.sound : true,
    };
  } catch { /* Unavailable storage leaves safe defaults. */ }
  document.documentElement.dataset.theme = preferences.theme;
  let localize = (zh, en) => en;
  let context;
  let masterBus;
  let noiseBuffer;
  const lastPlayedAt = Object.create(null);

  function render() {
    document.documentElement.dataset.theme = preferences.theme;
    const theme = document.getElementById('theme-toggle');
    const sound = document.getElementById('sound-toggle');
    if (!theme || !sound) return;
    theme.setAttribute('aria-checked', String(preferences.theme === 'light'));
    sound.setAttribute('aria-checked', String(preferences.sound));
    const themeLabel = preferences.theme === 'dark' ? localize('切换为明亮模式', 'Switch to light mode') : localize('切换为深色模式', 'Switch to dark mode');
    const soundLabel = preferences.sound ? localize('关闭界面音效', 'Turn interface sounds off') : localize('开启界面音效', 'Turn interface sounds on');
    theme.title = themeLabel;
    sound.title = soundLabel;
    theme.setAttribute('aria-label', localize('明亮模式', 'Light mode'));
    sound.setAttribute('aria-label', localize('界面音效', 'Interface sounds'));
  }
  function syncThemeToBackend(theme) {
    window.__TAURI__?.core?.invoke?.('sync_appearance_theme', { theme }).catch(() => {});
  }
  function save() {
    try { localStorage.setItem(storageKey, JSON.stringify(preferences)); } catch { /* Session-only preferences still work. */ }
    render();
  }
  function setTheme(light, { silent = false, syncBackend = true } = {}) {
    const theme = light ? 'light' : 'dark';
    if (preferences.theme === theme) return;
    preferences.theme = theme;
    save();
    if (syncBackend) syncThemeToBackend(theme);
    if (!silent) void play(light ? 'toggleOn' : 'toggleOff');
  }
  function setSound(enabled) {
    if (preferences.sound === enabled) return;
    preferences.sound = enabled;
    save();
    if (enabled) void play('toggleOn');
    else if (context) void context.suspend().catch(() => {});
  }

  function ensureAudio() {
    const Audio = window.AudioContext || window.webkitAudioContext;
    if (!Audio) return null;
    if (!context) {
      context = new Audio();
      const filter = context.createBiquadFilter();
      filter.type = 'lowpass';
      filter.frequency.value = 6800;
      filter.Q.value = 0.7;
      const gain = context.createGain();
      gain.gain.value = 0.85;
      filter.connect(gain);
      gain.connect(context.destination);
      masterBus = filter;

      const length = Math.max(1, Math.floor(context.sampleRate * 0.04));
      noiseBuffer = context.createBuffer(1, length, context.sampleRate);
      const data = noiseBuffer.getChannelData(0);
      for (let i = 0; i < length; i += 1) {
        data[i] = (Math.random() * 2 - 1) * Math.exp(-i / (length * 0.35));
      }
    }
    return context;
  }

  function playTone(ctx, dest, { freq, endFreq = freq, duration = 0.05, delay = 0, peak = 0.035, attack = 0.0025, cutoff = 0 }) {
    const start = ctx.currentTime + delay;
    const stop = start + duration + 0.008;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'sine';
    osc.frequency.setValueAtTime(freq, start);
    if (endFreq !== freq) osc.frequency.exponentialRampToValueAtTime(Math.max(40, endFreq), start + duration);
    gain.gain.setValueAtTime(0.0001, start);
    gain.gain.linearRampToValueAtTime(peak, start + attack);
    gain.gain.exponentialRampToValueAtTime(0.0001, start + duration);

    let target = dest;
    let lp;
    if (cutoff > 0) {
      lp = ctx.createBiquadFilter();
      lp.type = 'lowpass';
      lp.frequency.setValueAtTime(cutoff, start);
      lp.connect(dest);
      target = lp;
    }
    osc.connect(gain);
    gain.connect(target);
    osc.onended = () => {
      osc.disconnect();
      gain.disconnect();
      if (lp) lp.disconnect();
    };
    osc.start(start);
    osc.stop(stop);
  }

  function playTick(ctx, dest, { freq = 2900, q = 2.4, duration = 0.009, delay = 0, peak = 0.04 }) {
    if (!noiseBuffer) return;
    const start = ctx.currentTime + delay;
    const src = ctx.createBufferSource();
    src.buffer = noiseBuffer;
    const bp = ctx.createBiquadFilter();
    bp.type = 'bandpass';
    bp.frequency.setValueAtTime(freq, start);
    bp.Q.setValueAtTime(q, start);
    const gain = ctx.createGain();
    gain.gain.setValueAtTime(0.0001, start);
    gain.gain.linearRampToValueAtTime(peak, start + 0.0012);
    gain.gain.exponentialRampToValueAtTime(0.0001, start + duration);
    src.connect(bp);
    bp.connect(gain);
    gain.connect(dest);
    src.onended = () => {
      src.disconnect();
      bp.disconnect();
      gain.disconnect();
    };
    src.start(start, 0, Math.min(noiseBuffer.duration, duration + 0.006));
  }

  async function play(kind = 'tap') {
    if (!preferences.sound || document.hidden || kind === 'hover') return;
    const nowMs = performance.now();
    const cooldown = (kind === 'tap' || kind === 'select') ? 38 : 75;
    if (nowMs - (lastPlayedAt[kind] || -Infinity) < cooldown) return;
    lastPlayedAt[kind] = nowMs;
    try {
      const ctx = ensureAudio();
      if (!ctx || !masterBus) return;
      if (ctx.state === 'suspended') await ctx.resume();
      if (!preferences.sound) return;

      const jitter = 1 + (Math.random() - 0.5) * 0.03;

      switch (kind) {
        case 'hover':
          // Feather-light tactile ceramic micro-whisper on pointer hover / slot slide
          playTick(ctx, masterBus, { freq: 4200 * jitter, q: 3.5, duration: 0.0045, peak: 0.012 });
          playTone(ctx, masterBus, { freq: 660 * jitter, endFreq: 540 * jitter, duration: 0.011, peak: 0.009, attack: 0.0012, cutoff: 3200 });
          break;

        case 'drop':
          // Grounded, damped mechanical settle when placing/dropping a dragged card
          playTick(ctx, masterBus, { freq: 2150 * jitter, q: 2.3, duration: 0.009, peak: 0.036 });
          playTone(ctx, masterBus, { freq: 295 * jitter, endFreq: 165 * jitter, duration: 0.028, peak: 0.038, attack: 0.002, cutoff: 1450 });
          break;

        case 'select':
          // Ultra-light ceramic detent for tabs, filters, view & language switches
          playTick(ctx, masterBus, { freq: 3300 * jitter, q: 2.8, duration: 0.007, peak: 0.034 });
          playTone(ctx, masterBus, { freq: 560 * jitter, endFreq: 420 * jitter, duration: 0.015, peak: 0.024, attack: 0.0015 });
          break;

        case 'primary':
          // Fuller anodized precision detent for primary CTA actions
          playTick(ctx, masterBus, { freq: 3050 * jitter, q: 2.1, duration: 0.01, peak: 0.044 });
          playTone(ctx, masterBus, { freq: 440, endFreq: 330, duration: 0.026, peak: 0.04, attack: 0.002 });
          playTone(ctx, masterBus, { freq: 880, endFreq: 740, duration: 0.02, peak: 0.013, attack: 0.002 });
          break;

        case 'toggleOn':
          // Crisp upward mechanical switch engage (D5 -> A5)
          playTick(ctx, masterBus, { freq: 3100, q: 2.5, duration: 0.007, peak: 0.03 });
          playTone(ctx, masterBus, { freq: 587.33, duration: 0.04, delay: 0, peak: 0.03, attack: 0.002, cutoff: 3200 });
          playTone(ctx, masterBus, { freq: 880, duration: 0.062, delay: 0.026, peak: 0.036, attack: 0.0025, cutoff: 3400 });
          break;

        case 'toggleOff':
          // Grounded downward mechanical release (E5 -> A4)
          playTick(ctx, masterBus, { freq: 2200, q: 2.4, duration: 0.007, peak: 0.026 });
          playTone(ctx, masterBus, { freq: 659.25, duration: 0.036, delay: 0, peak: 0.028, attack: 0.002, cutoff: 2600 });
          playTone(ctx, masterBus, { freq: 440, duration: 0.056, delay: 0.024, peak: 0.03, attack: 0.0025, cutoff: 2200 });
          break;

        case 'copy':
          // Airy glass-ceramic double-glint (D6 -> G6)
          playTick(ctx, masterBus, { freq: 3800, q: 3.0, duration: 0.006, peak: 0.018 });
          playTone(ctx, masterBus, { freq: 1174.66, duration: 0.052, delay: 0, peak: 0.022, attack: 0.0025, cutoff: 3800 });
          playTone(ctx, masterBus, { freq: 1567.98, duration: 0.075, delay: 0.034, peak: 0.026, attack: 0.003, cutoff: 4200 });
          break;

        case 'success':
          // Warm velvet triad shimmer (C5 -> E5 -> G5)
          playTone(ctx, masterBus, { freq: 523.25, duration: 0.09, delay: 0, peak: 0.026, attack: 0.004, cutoff: 2600 });
          playTone(ctx, masterBus, { freq: 659.25, duration: 0.105, delay: 0.038, peak: 0.028, attack: 0.004, cutoff: 2600 });
          playTone(ctx, masterBus, { freq: 783.99, duration: 0.145, delay: 0.076, peak: 0.032, attack: 0.005, cutoff: 2800 });
          break;

        case 'lock':
          // Solid precision vault bolt engaging
          playTone(ctx, masterBus, { freq: 215, endFreq: 112, duration: 0.048, delay: 0, peak: 0.052, attack: 0.002, cutoff: 1200 });
          playTick(ctx, masterBus, { freq: 2100, q: 2.2, duration: 0.011, delay: 0.038, peak: 0.042 });
          playTone(ctx, masterBus, { freq: 310, endFreq: 190, duration: 0.032, delay: 0.038, peak: 0.034, attack: 0.002, cutoff: 1600 });
          break;

        case 'unlock':
          // Smooth mechanical latch release + warm rising fifth
          playTick(ctx, masterBus, { freq: 2600, q: 2.4, duration: 0.008, delay: 0, peak: 0.032 });
          playTone(ctx, masterBus, { freq: 587.33, duration: 0.075, delay: 0.018, peak: 0.03, attack: 0.003, cutoff: 2800 });
          playTone(ctx, masterBus, { freq: 880, duration: 0.125, delay: 0.056, peak: 0.034, attack: 0.004, cutoff: 3200 });
          break;

        case 'danger':
          // Calm muted low double-thump (unmistakable warning without harsh buzz)
          playTone(ctx, masterBus, { freq: 255, endFreq: 185, duration: 0.052, delay: 0, peak: 0.044, attack: 0.003, cutoff: 950 });
          playTone(ctx, masterBus, { freq: 205, endFreq: 145, duration: 0.068, delay: 0.06, peak: 0.042, attack: 0.003, cutoff: 880 });
          break;

        case 'tap':
        default:
          // Crisp dry ceramic/mechanical micro-tick
          playTick(ctx, masterBus, { freq: 2900 * jitter, q: 2.4, duration: 0.008, peak: 0.04 });
          playTone(ctx, masterBus, { freq: 380 * jitter, endFreq: 210 * jitter, duration: 0.018, peak: 0.034, attack: 0.0018 });
          break;
      }
    } catch { /* Audio is optional; device failures must never block controls. */ }
  }

  function classifyControl(control) {
    if (control.matches('input[type="checkbox"]')) return control.checked ? 'toggleOn' : 'toggleOff';
    if (control.matches('#owner-lock-button')) return 'lock';
    if (control.matches('.button.danger, .button.danger-soft, .small-button.delete, [data-action="delete"]')) return 'danger';
    if (control.matches('[data-action="copy-name"], [data-action="copy-item"], [data-copy-module-secret], [data-copy-module-value], [data-copy-totp-code], [data-copy-format], #copy-extensions-url-button, #generator-copy, #github-copy-key, #github-copy-saved-key')) return 'copy';
    if (control.matches('.nav-item, .filter-strip button, .language-switch button, #vault-view-toggle, summary, [data-item-template]')) return 'select';
    if (control.matches('.button.primary, .agent-row-action.primary')) return 'primary';
    return 'tap';
  }

  window.OpenKeyletAppearance = {
    setLanguage(localized) { localize = localized; render(); },
    setTheme,
    setSound,
    play(kind = 'tap') { void play(kind); },
    feedback(kind = 'tap') { void play(kind); },
    hideTooltip() { hideUiTooltip(); },
  };

  /* ---- OpenKeylet-styled floating tooltip (replaces native OS title popups) ---- */
  let tooltipEl = null;
  let tooltipTarget = null;
  let tooltipShowTimer = 0;
  let tooltipLastHiddenAt = 0;
  let tooltipObserver = null;
  const stashedTitles = new WeakMap();
  const suppressedTitleNodes = new Set();

  function ensureTooltipEl() {
    if (tooltipEl?.isConnected) return tooltipEl;
    tooltipEl = document.createElement('div');
    tooltipEl.id = 'ui-tooltip';
    tooltipEl.className = 'ui-tooltip';
    tooltipEl.setAttribute('role', 'tooltip');
    tooltipEl.setAttribute('aria-hidden', 'true');
    document.body.append(tooltipEl);
    return tooltipEl;
  }

  function restoreStashedTitles() {
    for (const node of suppressedTitleNodes) {
      const saved = stashedTitles.get(node);
      if (saved && node.isConnected && !node.hasAttribute('title')) {
        node.setAttribute('title', saved);
      }
      stashedTitles.delete(node);
    }
    suppressedTitleNodes.clear();
  }

  function disconnectTooltipObserver() {
    if (tooltipObserver) {
      tooltipObserver.disconnect();
      tooltipObserver = null;
    }
  }

  function positionUiTooltip(target) {
    if (!tooltipEl || !target?.isConnected) return;
    const rect = target.getBoundingClientRect();
    if (!rect.width && !rect.height) {
      hideUiTooltip();
      return;
    }
    tooltipEl.style.left = '0px';
    tooltipEl.style.top = '0px';
    const tipWidth = tooltipEl.offsetWidth;
    const tipHeight = tooltipEl.offsetHeight;
    const gap = 7;
    const margin = 8;
    const canPlaceAbove = rect.top - tipHeight - gap >= margin;
    const placement = canPlaceAbove ? 'top' : 'bottom';
    const rawY = placement === 'top'
      ? rect.top - tipHeight - gap
      : rect.bottom + gap;
    const y = Math.max(margin, Math.min(rawY, window.innerHeight - tipHeight - margin));
    const centeredX = rect.left + (rect.width - tipWidth) / 2;
    const x = Math.max(margin, Math.min(centeredX, window.innerWidth - tipWidth - margin));
    tooltipEl.dataset.placement = placement;
    tooltipEl.style.left = `${Math.round(x)}px`;
    tooltipEl.style.top = `${Math.round(y)}px`;
  }

  function showUiTooltipNow(target, text) {
    if (!target?.isConnected || !text) return;
    if (document.body.classList.contains('item-pointer-dragging') || document.body.classList.contains('module-pointer-dragging')) return;
    const el = ensureTooltipEl();
    el.textContent = text;
    el.setAttribute('aria-hidden', 'false');
    positionUiTooltip(target);
    el.classList.add('is-visible');
  }

  function hideUiTooltip(restore = true) {
    if (tooltipShowTimer) {
      clearTimeout(tooltipShowTimer);
      tooltipShowTimer = 0;
    }
    disconnectTooltipObserver();
    if (tooltipEl?.classList.contains('is-visible')) {
      tooltipEl.classList.remove('is-visible');
      tooltipEl.setAttribute('aria-hidden', 'true');
      tooltipLastHiddenAt = performance.now();
    }
    tooltipTarget = null;
    if (restore) restoreStashedTitles();
  }

  function resolveTooltipChain(startNode) {
    let bestTarget = null;
    let bestText = '';
    const nodesWithTitle = [];
    let current = startNode instanceof Element ? startNode : startNode?.parentElement;
    while (current && current !== document.documentElement) {
      const text = (current.getAttribute('title') || stashedTitles.get(current) || current.dataset?.tooltip || '').trim();
      if (text) {
        if (!bestTarget) {
          bestTarget = current;
          bestText = text;
        }
        nodesWithTitle.push([current, text]);
      }
      current = current.parentElement;
    }
    return { bestTarget, bestText, nodesWithTitle };
  }

  function activateTooltipFor(startNode, { immediate = false } = {}) {
    const { bestTarget, bestText, nodesWithTitle } = resolveTooltipChain(startNode);
    if (!bestTarget || !bestText) {
      if (tooltipTarget) hideUiTooltip(true);
      return;
    }
    if (bestTarget === tooltipTarget) {
      // Still suppress any newly added native title attribute on the chain
      for (const [node, text] of nodesWithTitle) {
        if (node.hasAttribute('title')) {
          stashedTitles.set(node, text);
          suppressedTitleNodes.add(node);
          node.removeAttribute('title');
        }
      }
      return;
    }
    hideUiTooltip(true);
    for (const [node, text] of nodesWithTitle) {
      if (node.hasAttribute('title')) {
        stashedTitles.set(node, text);
        suppressedTitleNodes.add(node);
        node.removeAttribute('title');
      }
    }
    tooltipTarget = bestTarget;
    disconnectTooltipObserver();
    tooltipObserver = new MutationObserver(() => {
      if (!tooltipTarget?.isConnected) {
        hideUiTooltip(true);
        return;
      }
      const next = (tooltipTarget.getAttribute('title') || '').trim();
      if (next) {
        stashedTitles.set(tooltipTarget, next);
        suppressedTitleNodes.add(tooltipTarget);
        tooltipTarget.removeAttribute('title');
        if (tooltipEl?.classList.contains('is-visible')) {
          tooltipEl.textContent = next;
          positionUiTooltip(tooltipTarget);
        }
      }
    });
    tooltipObserver.observe(bestTarget, { attributes: true, attributeFilter: ['title'] });

    const warm = (performance.now() - tooltipLastHiddenAt) < 420;
    const delay = immediate ? 140 : (warm ? 80 : 240);
    tooltipShowTimer = setTimeout(() => {
      tooltipShowTimer = 0;
      if (tooltipTarget === bestTarget && bestTarget.isConnected) {
        const currentText = stashedTitles.get(bestTarget) || bestTarget.dataset?.tooltip || bestText;
        showUiTooltipNow(bestTarget, currentText);
      }
    }, delay);
  }

  let lastHoveredControl = null;

  document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('theme-toggle').addEventListener('click', () => {
      setTheme(preferences.theme !== 'light');
    });
    document.getElementById('sound-toggle').addEventListener('click', () => {
      setSound(!preferences.sound);
    });
    document.addEventListener('pointerover', (event) => {
      if (event.pointerType === 'touch') return;
      if (document.body.classList.contains('item-pointer-dragging') || document.body.classList.contains('module-pointer-dragging')) {
        hideUiTooltip(true);
        return;
      }
      activateTooltipFor(event.target);
    }, true);
    document.addEventListener('pointerout', (event) => {
      if (!event.relatedTarget) {
        lastHoveredControl = null;
        hideUiTooltip(true);
        return;
      }
      if (tooltipTarget && (!(event.relatedTarget instanceof Node) || !tooltipTarget.contains(event.relatedTarget))) {
        const nextChain = resolveTooltipChain(event.relatedTarget);
        if (nextChain.bestTarget !== tooltipTarget) hideUiTooltip(true);
      } else if (!tooltipTarget && suppressedTitleNodes.size > 0) {
        const stillInsideSuppressed = event.relatedTarget instanceof Node && [...suppressedTitleNodes].some((node) => node.contains(event.relatedTarget));
        if (!stillInsideSuppressed) restoreStashedTitles();
      }
    }, true);
    document.addEventListener('pointerdown', () => {
      hideUiTooltip(false);
      if (preferences.sound) {
        const ctx = ensureAudio();
        if (ctx && ctx.state === 'suspended') void ctx.resume().catch(() => {});
      }
    }, true);
    document.addEventListener('scroll', () => {
      if (tooltipTarget) hideUiTooltip(true);
    }, true);
    document.addEventListener('wheel', () => {
      if (tooltipTarget) hideUiTooltip(true);
    }, { capture: true, passive: true });
    document.addEventListener('focusin', (event) => {
      if (event.target instanceof Element && event.target.matches(':focus-visible')) {
        activateTooltipFor(event.target, { immediate: true });
      }
    }, true);
    document.addEventListener('focusout', () => {
      if (tooltipTarget) hideUiTooltip(true);
    }, true);
    document.addEventListener('keydown', () => {
      if (tooltipTarget) hideUiTooltip(true);
    }, true);
    window.addEventListener('blur', () => {
      lastHoveredControl = null;
      hideUiTooltip(true);
    });
    document.addEventListener('click', (event) => {
      const control = event.target.closest('button, summary, input[type="checkbox"], [role="button"]');
      if (!control || control.id === 'sound-toggle' || control.id === 'theme-toggle' || control.matches(':disabled, [aria-disabled="true"]')) return;
      void play(classifyControl(control));
    });
    document.addEventListener('change', (event) => {
      const select = event.target.closest('select');
      if (select && !select.disabled) void play('select');
    });
    window.__TAURI__?.event?.listen?.('appearance-changed', (event) => {
      const next = event?.payload?.theme;
      if (next === 'light' || next === 'dark') {
        setTheme(next === 'light', { silent: true, syncBackend: false });
      }
    });
    window.addEventListener('storage', (event) => {
      if (event.key !== storageKey) return;
      try {
        const saved = JSON.parse(event.newValue || 'null');
        if (saved?.theme === 'light' || saved?.theme === 'dark') {
          setTheme(saved.theme === 'light', { silent: true, syncBackend: false });
        }
      } catch { /* ignore */ }
    });
    syncThemeToBackend(preferences.theme);
    render();
  });
})();
