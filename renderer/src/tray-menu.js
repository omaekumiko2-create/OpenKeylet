/* OpenKeylet Custom System Tray Popover Menu Controller (Windows, macOS & Linux). */
(() => {
  const APPEARANCE_KEY = 'openkeylet.appearance.v1';
  const EDGE_DOCK_KEY = 'openkeylet.edgeDock.v1';

  const isMac = navigator.platform.startsWith('Mac') || navigator.userAgent.includes('Macintosh');
  const isLinux = !isMac && navigator.platform.startsWith('Linux');
  const edgeDockSupported = !isMac && !isLinux;
  document.documentElement.classList.toggle('platform-macos', isMac);
  document.documentElement.classList.toggle('platform-linux', isLinux);

  const $ = (id) => document.getElementById(id);
  const invoke = (cmd, args) => window.__TAURI__?.core?.invoke(cmd, args);
  const listen = (event, handler) => window.__TAURI__?.event?.listen(event, handler);

  const COPY = {
    en: {
      unlocked: 'Unlocked',
      locked: 'Locked',
      items: '{n} items',
      itemOne: '1 item',
      updateAvailable: 'Update v{ver}',
      showWindow: 'Show OpenKeylet',
      hideWindow: 'Hide to tray',
      newItem: 'New item',
      smartImport: 'Smart import',
      genPassword: 'Copy strong password',
      copiedBadge: 'Copied {s}s',
      browserBridge: 'Browser bridge',
      bridgeConnected: 'Connected',
      bridgeWaiting: 'Waiting to pair',
      bridgeError: 'Error',
      bridgeOff: 'Off',
      edgeDock: 'Edge-dock drawer',
      settings: 'System settings',
      lockVault: 'Lock vault',
      unlockVault: 'Unlock vault',
      setPinLock: 'Set PIN lock',
      quit: 'Quit OpenKeylet',
      themeToLight: 'Switch to light mode',
      themeToDark: 'Switch to dark mode',
    },
    zh: {
      unlocked: '已解锁',
      locked: '已锁定',
      items: '{n} 项凭据',
      itemOne: '1 项凭据',
      updateAvailable: '发现新版本 v{ver}',
      showWindow: '显示 OpenKeylet',
      hideWindow: '隐藏到托盘',
      newItem: '新建凭据',
      smartImport: '智能导入',
      genPassword: '生成并复制强密码',
      copiedBadge: '已复制 · {s}s',
      browserBridge: '浏览器桥接',
      bridgeConnected: '已连接',
      bridgeWaiting: '等待配对',
      bridgeError: '连接异常',
      bridgeOff: '已关闭',
      edgeDock: '贴边自动收起',
      settings: '系统设置',
      lockVault: '立即锁定',
      unlockVault: '解锁密码库',
      setPinLock: '设置 PIN 锁',
      quit: '退出 OpenKeylet',
      themeToLight: '切换为明亮模式',
      themeToDark: '切换为深色模式',
    },
    'zh-TW': {
      unlocked: '已解鎖',
      locked: '已鎖定',
      items: '{n} 項憑證',
      itemOne: '1 項憑證',
      updateAvailable: '發現新版本 v{ver}',
      showWindow: '顯示 OpenKeylet',
      hideWindow: '隱藏至系統匣',
      newItem: '新增憑證',
      smartImport: '智慧匯入',
      genPassword: '產生並複製強密碼',
      copiedBadge: '已複製 · {s}s',
      browserBridge: '瀏覽器橋接',
      bridgeConnected: '已連線',
      bridgeWaiting: '等待配對',
      bridgeError: '連線異常',
      bridgeOff: '已關閉',
      edgeDock: '貼邊自動收合',
      settings: '系統設定',
      lockVault: '立即鎖定',
      unlockVault: '解鎖密碼庫',
      setPinLock: '設定 PIN 鎖',
      quit: '結束 OpenKeylet',
      themeToLight: '切換為淺色模式',
      themeToDark: '切換為深色模式',
    },
    ja: {
      unlocked: 'ロック解除',
      locked: 'ロック中',
      items: '{n} 件',
      itemOne: '1 件',
      updateAvailable: 'アップデート v{ver}',
      showWindow: 'OpenKeylet を表示',
      hideWindow: 'トレイに隠す',
      newItem: '新規項目',
      smartImport: 'スマートインポート',
      genPassword: '強力なパスワードをコピー',
      copiedBadge: 'コピー済み {s}s',
      browserBridge: 'ブラウザ連携',
      bridgeConnected: '接続済み',
      bridgeWaiting: 'ペアリング待機',
      bridgeError: 'エラー',
      bridgeOff: 'オフ',
      edgeDock: '画面端オートドック',
      settings: 'システム設定',
      lockVault: '今すぐロック',
      unlockVault: 'ロック解除',
      setPinLock: 'PIN ロックを設定',
      quit: 'OpenKeylet を終了',
      themeToLight: 'ライトモードに切替',
      themeToDark: 'ダークモードに切替',
    },
    ko: {
      unlocked: '잠금 해제',
      locked: '잠김',
      items: '{n}개 항목',
      itemOne: '1개 항목',
      updateAvailable: '새 버전 v{ver}',
      showWindow: 'OpenKeylet 표시',
      hideWindow: '트레이로 숨기기',
      newItem: '새 항목',
      smartImport: '스마트 가져오기',
      genPassword: '강력한 비밀번호 복사',
      copiedBadge: '복사됨 {s}s',
      browserBridge: '브라우저 브리지',
      bridgeConnected: '연결됨',
      bridgeWaiting: '페어링 대기',
      bridgeError: '오류',
      bridgeOff: '꺼짐',
      edgeDock: '가장자리 자동 숨김',
      settings: '시스템 설정',
      lockVault: '지금 잠금',
      unlockVault: '금고 잠금 해제',
      setPinLock: 'PIN 잠금 설정',
      quit: 'OpenKeylet 종료',
      themeToLight: '라이트 모드로 전환',
      themeToDark: '다크 모드로 전환',
    },
    es: {
      unlocked: 'Desbloqueada',
      locked: 'Bloqueada',
      items: '{n} elementos',
      itemOne: '1 elemento',
      updateAvailable: 'Actualización v{ver}',
      showWindow: 'Mostrar OpenKeylet',
      hideWindow: 'Ocultar en bandeja',
      newItem: 'Nuevo elemento',
      smartImport: 'Importación inteligente',
      genPassword: 'Copiar contraseña segura',
      copiedBadge: 'Copiada {s}s',
      browserBridge: 'Puente del navegador',
      bridgeConnected: 'Conectado',
      bridgeWaiting: 'Esperando',
      bridgeError: 'Error',
      bridgeOff: 'Apagado',
      edgeDock: 'Acoplamiento en borde',
      settings: 'Ajustes del sistema',
      lockVault: 'Bloquear ahora',
      unlockVault: 'Desbloquear bóveda',
      setPinLock: 'Configurar PIN',
      quit: 'Salir de OpenKeylet',
      themeToLight: 'Cambiar a modo claro',
      themeToDark: 'Cambiar a modo oscuro',
    },
  };

  const ICON_LOCK = '<svg viewBox="0 0 24 24"><rect x="4.5" y="10.5" width="15" height="10" rx="2"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/></svg>';
  const ICON_UNLOCK = '<svg viewBox="0 0 24 24"><rect x="4.5" y="10.5" width="15" height="10" rx="2"/><path d="M8 10.5V7.5a4 4 0 0 1 7.6-1.7"/></svg>';

  let currentState = null;
  let currentTheme = 'dark';
  let busyAction = false;
  let feedbackTimer = null;
  let autoCloseTimer = null;
  let lastReportedHeight = 0;

  function normalizeLang(raw) {
    const lower = String(raw || '').trim().toLowerCase();
    if (['zh-tw', 'zh_tw', 'zh-hk', 'zh_hk', 'zh-hant', 'zh_hant'].some((p) => lower === p || lower.startsWith(`${p}-`))) return 'zh-TW';
    if (lower === 'zh' || lower.startsWith('zh-') || lower.startsWith('zh_')) return 'zh';
    if (lower === 'ja' || lower.startsWith('ja-') || lower.startsWith('ja_')) return 'ja';
    if (lower === 'ko' || lower.startsWith('ko-') || lower.startsWith('ko_')) return 'ko';
    if (lower === 'es' || lower.startsWith('es-') || lower.startsWith('es_')) return 'es';
    if (lower === 'en' || lower.startsWith('en-') || lower.startsWith('en_')) return 'en';
    return 'en';
  }

  function detectSystemLang() {
    const list = Array.isArray(navigator.languages) && navigator.languages.length
      ? navigator.languages
      : [navigator.language || 'en'];
    for (const candidate of list) {
      const lower = String(candidate || '').trim().toLowerCase();
      if (!lower) continue;
      if (['zh-tw', 'zh_tw', 'zh-hk', 'zh_hk', 'zh-hant', 'zh_hant'].some((p) => lower === p || lower.startsWith(`${p}-`))) return 'zh-TW';
      if (lower === 'zh' || lower.startsWith('zh-') || lower.startsWith('zh_')) return 'zh';
      if (lower === 'ja' || lower.startsWith('ja-') || lower.startsWith('ja_')) return 'ja';
      if (lower === 'ko' || lower.startsWith('ko-') || lower.startsWith('ko_')) return 'ko';
      if (lower === 'es' || lower.startsWith('es-') || lower.startsWith('es_')) return 'es';
      if (lower === 'en' || lower.startsWith('en-') || lower.startsWith('en_')) return 'en';
    }
    return 'en';
  }

  function resolveLang(setting, fallbackResolved) {
    const s = String(setting || '').trim().toLowerCase();
    if (!s || s === 'auto' || s === 'system') {
      return detectSystemLang();
    }
    return normalizeLang(setting || fallbackResolved || 'en');
  }

  function dictFor(lang) {
    return COPY[lang] || COPY.en;
  }

  function readStoredTheme() {
    try {
      const saved = JSON.parse(localStorage.getItem(APPEARANCE_KEY) || 'null');
      return saved?.theme === 'light' ? 'light' : 'dark';
    } catch {
      return 'dark';
    }
  }

  function applyTheme(theme) {
    currentTheme = theme === 'light' ? 'light' : 'dark';
    document.documentElement.dataset.theme = currentTheme;
    const toggle = $('tray-theme-toggle');
    if (toggle) {
      toggle.setAttribute('aria-checked', String(currentTheme === 'light'));
      const lang = resolveLang(currentState?.language, currentState?.resolvedLanguage);
      const t = dictFor(lang);
      toggle.title = currentTheme === 'dark' ? t.themeToLight : t.themeToDark;
    }
  }

  function saveLocalTheme(theme) {
    try {
      const existing = JSON.parse(localStorage.getItem(APPEARANCE_KEY) || 'null') || {};
      existing.theme = theme;
      localStorage.setItem(APPEARANCE_KEY, JSON.stringify(existing));
    } catch { /* ignore */ }
  }

  function saveLocalEdgeDock(enabled) {
    try {
      localStorage.setItem(EDGE_DOCK_KEY, enabled ? 'true' : 'false');
    } catch { /* ignore */ }
  }

  function syncWindowHeight() {
    requestAnimationFrame(() => {
      const surface = $('tray-surface');
      if (!surface) return;
      const height = Math.ceil(surface.getBoundingClientRect().height);
      if (height > 100 && height !== lastReportedHeight) {
        lastReportedHeight = height;
        invoke?.('tray_menu_resize', { height }).catch(() => {});
      }
    });
  }

  function render(state) {
    if (!state) return;
    currentState = state;

    const lang = resolveLang(state.language, state.resolvedLanguage);
    document.documentElement.lang = lang === 'zh' ? 'zh-CN' : lang;
    const t = dictFor(lang);

    const resolvedTheme = state.theme === 'light' || state.theme === 'dark' ? state.theme : readStoredTheme();
    saveLocalTheme(resolvedTheme);
    applyTheme(resolvedTheme);

    // Header status strip
    const strip = $('tray-status-strip');
    const statusText = $('tray-status-text');
    const versionEl = $('tray-version');
    strip.dataset.state = state.unlocked ? 'unlocked' : 'locked';
    if (state.unlocked) {
      if (typeof state.itemCount === 'number') {
        const countLabel = state.itemCount === 1 ? t.itemOne : t.items.replace('{n}', String(state.itemCount));
        statusText.textContent = `${t.unlocked} · ${countLabel}`;
      } else {
        statusText.textContent = t.unlocked;
      }
    } else {
      statusText.textContent = t.locked;
    }
    versionEl.textContent = `v${state.version || '0.20.0'}`;

    // Optional update banner pill
    const updatePill = $('tray-update-pill');
    if (state.updateAvailable && state.latestVersion) {
      $('tray-update-label').textContent = t.updateAvailable.replace('{ver}', state.latestVersion);
      updatePill.classList.remove('hidden');
    } else {
      updatePill.classList.add('hidden');
    }

    // Core action labels
    $('label-toggle-main').textContent = state.mainVisible ? t.hideWindow : t.showWindow;
    $('label-new-item').textContent = t.newItem;
    $('label-smart-import').textContent = t.smartImport;
    $('label-gen-password').textContent = t.genPassword;
    $('item-gen-password').disabled = !state.unlocked;

    // Browser Bridge toggle
    const bridgeBtn = $('item-browser-bridge');
    const bridgeSub = $('sub-browser-bridge');
    $('label-browser-bridge').textContent = t.browserBridge;
    bridgeBtn.setAttribute('aria-checked', String(Boolean(state.browserEnabled)));
    bridgeBtn.disabled = !state.unlocked;
    if (!state.browserEnabled) {
      bridgeSub.textContent = t.bridgeOff;
      bridgeSub.dataset.tone = 'muted';
    } else if (state.browserConnected) {
      bridgeSub.textContent = t.bridgeConnected;
      bridgeSub.dataset.tone = 'online';
    } else if (state.browserStatus === 'error') {
      bridgeSub.textContent = t.bridgeError;
      bridgeSub.dataset.tone = 'warn';
    } else {
      bridgeSub.textContent = t.bridgeWaiting;
      bridgeSub.dataset.tone = 'warn';
    }

    // Edge-dock toggle (Windows only)
    const dockBtn = $('item-edge-dock');
    dockBtn.classList.toggle('hidden', !edgeDockSupported);
    if (edgeDockSupported) {
      $('label-edge-dock').textContent = t.edgeDock;
      dockBtn.setAttribute('aria-checked', String(Boolean(state.edgeDockEnabled)));
    }

    // System & Lock / Unlock
    $('label-settings').textContent = t.settings;
    const lockBtn = $('item-lock');
    const lockLabel = $('label-lock');
    const lockIcon = $('icon-lock');
    if (!state.unlocked) {
      lockLabel.textContent = t.unlockVault;
      lockIcon.innerHTML = ICON_UNLOCK;
      lockBtn.classList.add('unlock-highlight');
    } else if (state.pinConfigured) {
      lockLabel.textContent = t.lockVault;
      lockIcon.innerHTML = ICON_LOCK;
      lockBtn.classList.remove('unlock-highlight');
    } else {
      lockLabel.textContent = t.setPinLock;
      lockIcon.innerHTML = ICON_LOCK;
      lockBtn.classList.remove('unlock-highlight');
    }

    $('label-quit').textContent = t.quit;

    syncWindowHeight();
  }

  function showCopiedBadge(ttlSeconds) {
    clearTimeout(feedbackTimer);
    clearTimeout(autoCloseTimer);
    const badge = $('badge-gen-password');
    const lang = resolveLang(currentState?.language, currentState?.resolvedLanguage);
    const t = dictFor(lang);
    badge.textContent = t.copiedBadge.replace('{s}', String(ttlSeconds || 30));
    badge.classList.remove('hidden');
    feedbackTimer = setTimeout(() => {
      badge.classList.add('hidden');
    }, 1800);
    autoCloseTimer = setTimeout(() => {
      invoke?.('tray_menu_hide').catch(() => {});
    }, 950);
  }

  async function refreshState() {
    if (!invoke) return;
    try {
      const state = await invoke('tray_menu_state');
      render(state);
    } catch { /* ignore */ }
  }

  async function runAction(action) {
    if (!action || busyAction || !invoke) return;
    busyAction = true;
    try {
      const res = await invoke('tray_menu_action', { action });
      if (action === 'toggle-edge-dock' && currentState) {
        const next = !currentState.edgeDockEnabled;
        saveLocalEdgeDock(next);
        render({ ...currentState, edgeDockEnabled: next });
      }
      if (res?.feedbackKind === 'password-copied') {
        showCopiedBadge(res.ttlSeconds);
      } else if (res?.keepOpen) {
        await refreshState();
      }
    } catch {
      await refreshState();
    } finally {
      busyAction = false;
    }
  }

  function toggleTheme() {
    const next = currentTheme === 'light' ? 'dark' : 'light';
    saveLocalTheme(next);
    applyTheme(next);
    invoke?.('sync_appearance_theme', {
      theme: next,
      resolvedLanguage: detectSystemLang(),
    }).catch(() => {});
  }

  function focusableItems() {
    return Array.from(document.querySelectorAll('.tray-surface [role="menuitem"], .tray-surface [role="menuitemcheckbox"]'))
      .filter((el) => !el.classList.contains('hidden') && !el.disabled);
  }

  // Event bindings
  document.addEventListener('contextmenu', (e) => e.preventDefault());

  document.addEventListener('click', (e) => {
    const themeBtn = e.target.closest('#tray-theme-toggle');
    if (themeBtn) {
      toggleTheme();
      return;
    }
    const item = e.target.closest('[data-action]');
    if (!item || item.disabled) return;
    void runAction(item.dataset.action);
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      invoke?.('tray_menu_hide').catch(() => {});
      return;
    }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'Home' || e.key === 'End') {
      const items = focusableItems();
      if (!items.length) return;
      e.preventDefault();
      const idx = items.indexOf(document.activeElement);
      let nextIdx = 0;
      if (e.key === 'ArrowDown') nextIdx = idx < 0 ? 0 : (idx + 1) % items.length;
      else if (e.key === 'ArrowUp') nextIdx = idx <= 0 ? items.length - 1 : idx - 1;
      else if (e.key === 'End') nextIdx = items.length - 1;
      items[nextIdx].focus();
    }
  });

  window.addEventListener('storage', (e) => {
    if (e.key === APPEARANCE_KEY) {
      applyTheme(readStoredTheme());
    }
  });

  window.addEventListener('focus', () => {
    clearTimeout(autoCloseTimer);
    applyTheme(readStoredTheme());
    void refreshState();
  });

  // Initial theme & listeners
  applyTheme(readStoredTheme());
  listen?.('tray-state-changed', (event) => {
    if (event?.payload) render(event.payload);
  });
  listen?.('appearance-changed', (event) => {
    const next = event?.payload?.theme;
    if (next === 'light' || next === 'dark') {
      saveLocalTheme(next);
      applyTheme(next);
    }
  });
  void refreshState();

  // Expose preview hook for automated visual tests when running outside Tauri.
  window.__OPENKEYLET_TRAY_PREVIEW__ = (mockState, themeOverride) => {
    if (themeOverride) {
      saveLocalTheme(themeOverride);
      applyTheme(themeOverride);
    }
    render(mockState);
  };
})();
