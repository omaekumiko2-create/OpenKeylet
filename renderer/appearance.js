/* Local presentation preferences & tactile acoustic feedback (independent of the encrypted vault). */
(() => {
  // Set native shell platform classes before the first frame is painted.
  const isMac = navigator.platform.startsWith('Mac') || navigator.userAgent.includes('Macintosh');
  document.documentElement.classList.toggle('platform-macos', isMac);
  document.documentElement.classList.toggle('platform-linux', !isMac && navigator.platform.startsWith('Linux'));
  const storageKey = 'openkeylet.appearance.v1';
  let preferences = { theme: 'dark', sound: false };
  try {
    const saved = JSON.parse(localStorage.getItem(storageKey) || 'null');
    preferences = { theme: saved?.theme === 'light' ? 'light' : 'dark', sound: saved?.sound === true };
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
  function save() {
    try { localStorage.setItem(storageKey, JSON.stringify(preferences)); } catch { /* Session-only preferences still work. */ }
    render();
  }
  function setTheme(light) {
    const theme = light ? 'light' : 'dark';
    if (preferences.theme === theme) return;
    preferences.theme = theme;
    save();
    void play(light ? 'toggleOn' : 'toggleOff');
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
    if (!preferences.sound || document.hidden) return;
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
    if (control.matches('[data-action="copy-name"], [data-copy-module-secret], [data-copy-module-value], [data-copy-totp-code], [data-copy-format], #copy-extensions-url-button, #generator-copy, #github-copy-key, #github-copy-saved-key')) return 'copy';
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
  };

  document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('theme-toggle').addEventListener('click', () => {
      setTheme(preferences.theme !== 'light');
    });
    document.getElementById('sound-toggle').addEventListener('click', () => {
      setSound(!preferences.sound);
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
    render();
  });
})();
