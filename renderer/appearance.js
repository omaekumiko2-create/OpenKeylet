/* Local presentation preferences are independent of the encrypted vault. */
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
  let lastSoundAt = -Infinity;

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
  }
  function setSound(enabled) {
    if (preferences.sound === enabled) return;
    preferences.sound = enabled;
    save();
    if (enabled) void playClick(1000);
    else if (context) void context.suspend().catch(() => {});
  }
  async function playClick(frequency = 720) {
    if (!preferences.sound || document.hidden || performance.now() - lastSoundAt < 45) return;
    lastSoundAt = performance.now();
    try {
      const Audio = window.AudioContext || window.webkitAudioContext;
      if (!Audio) return;
      context ||= new Audio();
      if (context.state === 'suspended') await context.resume();
      if (!preferences.sound) return;
      const oscillator = context.createOscillator();
      const gain = context.createGain();
      const now = context.currentTime;
      oscillator.type = 'triangle';
      oscillator.frequency.setValueAtTime(frequency, now);
      oscillator.frequency.exponentialRampToValueAtTime(frequency * .45, now + .035);
      gain.gain.setValueAtTime(.0001, now);
      gain.gain.exponentialRampToValueAtTime(.025, now + .003);
      gain.gain.exponentialRampToValueAtTime(.0001, now + .04);
      oscillator.connect(gain);
      gain.connect(context.destination);
      oscillator.onended = () => { oscillator.disconnect(); gain.disconnect(); };
      oscillator.start(now);
      oscillator.stop(now + .045);
    } catch { /* Audio is optional; device failures must never block controls. */ }
  }
  window.OpenKeyletAppearance = {
    setLanguage(localized) { localize = localized; render(); },
    setTheme,
    setSound,
    feedback() { void playClick(); },
  };
  document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('theme-toggle').addEventListener('click', () => {
      setTheme(preferences.theme !== 'light');
    });
    document.getElementById('sound-toggle').addEventListener('click', () => {
      setSound(!preferences.sound);
    });
    document.addEventListener('click', event => {
      const control = event.target.closest('button, summary, input[type="checkbox"], [role="button"]');
      if (control && control.id !== 'sound-toggle' && !control.matches(':disabled, [aria-disabled="true"]')) void playClick();
    });
    render();
  });
})();
