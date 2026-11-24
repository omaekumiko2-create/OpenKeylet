/* Shared appearance (dark/light monochrome theme), 6-language i18n, and monochrome SVG icons
   for OpenKeylet Agent Browser Bridge extension pages (popup.html & request.html). */
const OpenKeyletUI = (() => {
  const THEME_KEY = "openkeylet.ext.theme.v1";
  const LANG_KEY = "openkeylet.ext.lang.v1";

  let theme = "dark";
  let langSetting = "auto";
  let resolvedLang = "en";
  const listeners = new Set();

  const HTML_LANG_MAP = {
    en: "en",
    zh: "zh-CN",
    "zh-TW": "zh-TW",
    ja: "ja",
    ko: "ko",
    es: "es",
  };

  function normalizeLangCode(raw) {
    const lower = String(raw || "").trim().toLowerCase();
    if (lower === "en" || lower.startsWith("en-") || lower.startsWith("en_")) return "en";
    if (["zh-tw", "zh_tw", "zh-hk", "zh_hk", "zh-hant", "zh_hant"].some(p => lower === p || lower.startsWith(`${p}-`))) return "zh-TW";
    if (lower === "zh" || lower.startsWith("zh-") || lower.startsWith("zh_")) return "zh";
    if (lower === "ja" || lower.startsWith("ja-") || lower.startsWith("ja_")) return "ja";
    if (lower === "ko" || lower.startsWith("ko-") || lower.startsWith("ko_")) return "ko";
    if (lower === "es" || lower.startsWith("es-") || lower.startsWith("es_")) return "es";
    return "en";
  }

  function detectLang() {
    const list = Array.isArray(navigator.languages) && navigator.languages.length
      ? navigator.languages
      : [navigator.language || "en"];
    for (const raw of list) {
      const lower = String(raw || "").trim().toLowerCase();
      if (!lower) continue;
      if (["zh-tw", "zh_tw", "zh-hk", "zh_hk", "zh-hant", "zh_hant"].some(p => lower === p || lower.startsWith(`${p}-`))) return "zh-TW";
      if (lower === "zh" || lower.startsWith("zh-") || lower.startsWith("zh_")) return "zh";
      if (lower === "ja" || lower.startsWith("ja-") || lower.startsWith("ja_")) return "ja";
      if (lower === "ko" || lower.startsWith("ko-") || lower.startsWith("ko_")) return "ko";
      if (lower === "es" || lower.startsWith("es-") || lower.startsWith("es_")) return "es";
      if (lower === "en" || lower.startsWith("en-") || lower.startsWith("en_")) return "en";
    }
    return "en";
  }

  function normalizeLangSetting(val) {
    const lower = String(val || "").trim().toLowerCase();
    if (!lower || lower === "auto" || lower === "system") return "auto";
    const explicit = normalizeLangCode(lower);
    if (explicit === "en" && !(lower === "en" || lower.startsWith("en-") || lower.startsWith("en_"))) return "auto";
    return explicit;
  }

  function resolveLang(setting) {
    const normalized = normalizeLangSetting(setting);
    return normalized === "auto" ? detectLang() : normalized;
  }

  function htmlLangFor(code) {
    return HTML_LANG_MAP[code] || "en";
  }

  try {
    const savedTheme = localStorage.getItem(THEME_KEY);
    if (savedTheme === "light" || savedTheme === "dark") {
      theme = savedTheme;
    } else if (window.matchMedia?.("(prefers-color-scheme: light)")?.matches) {
      theme = "light";
    }
    const savedLang = localStorage.getItem(LANG_KEY);
    if (savedLang) langSetting = normalizeLangSetting(savedLang);
  } catch { /* ignore */ }
  resolvedLang = resolveLang(langSetting);
  document.documentElement.dataset.theme = theme;
  document.documentElement.lang = htmlLangFor(resolvedLang);

  const STRINGS = {
    en: {
      "status.checking": "CHECKING",
      "status.connected": "CONNECTED",
      "status.unavailable": "UNAVAILABLE",
      "header.themeToLight": "Switch to light mode",
      "header.themeToDark": "Switch to dark mode",
      "header.themeLabel": "Light mode",
      "header.githubTitle": "OpenKeylet on GitHub",
      "header.lock": "LOCK",
      "header.lockTitle": "Lock quick autofill",

      "update.title": "Extension update available",
      "update.detail": "Desktop v{app} · Extension v{ext}",
      "update.note": "If reloading does not update the version, re-drag the latest browser-extension folder into chrome://extensions/.",
      "update.reload": "Reload",

      "offline.code": "BRIDGE OFFLINE",
      "offline.title": "Cannot reach OpenKeylet",
      "offline.desc": "Make sure the OpenKeylet desktop app is open and Browser Bridge is enabled.",
      "offline.retry": "Retry",
      "offline.settings": "Connection",

      "unlock.badge": "OWNER ACCESS",
      "unlock.title": "Unlock quick autofill",
      "unlock.desc": "Enter your 6-digit PIN to fill logins, cards, and addresses on this page.",
      "unlock.pinLabel": "6-digit PIN",
      "unlock.submit": "Unlock",
      "unlock.note": "Protected locally on this device · Auto-locks after 5 min",

      "nav.site": "Fill",
      "nav.settings": "Bridge",

      "agent.title": "Agent browser channel",
      "agent.ready": "READY",
      "agent.standby": "STANDBY",
      "agent.desc": "Zero-plaintext bridge for AI Agents to sign Passkeys and fill passwords, cards, and addresses.",
      "agent.capPasskey": "Passkey",
      "agent.capLogin": "Login & 2FA",
      "agent.capPersonal": "Card & Address",
      "agent.lastAction": "LAST",

      "site.emptyTitle": "Open a website to autofill",
      "site.emptyDesc": "Browser internal pages cannot be filled. Open any website for Agent or one-click autofill.",
      "site.noLogins": "No saved logins for this site",
      "site.loginCount": "{count} login",
      "site.loginCountPlural": "{count} logins",
      "site.fillHint": "Fill",
      "site.filled": "Credentials filled",
      "site.totpCopied": "2FA code copied ({seconds}s)",
      "site.totpTitle": "Copy live 2FA code",
      "site.saveLogin": "Save current login",
      "site.quickAutofill": "Cards & addresses",
      "site.fieldsFilled": "Filled {count} fields",
      "site.desktopHandoff": "Manage vault items, keys, and passkeys in OpenKeylet desktop.",

      "type.card": "Card",
      "type.identity": "Identity",

      "capture.title": "Login detected",
      "capture.source": "Source: {origin}",
      "capture.note": "Review account & password before saving to OpenKeylet desktop. Draft expires in 5 minutes.",
      "capture.review": "Review & save",
      "capture.dismiss": "Dismiss",
      "capture.savedTitle": "Saved to OpenKeylet",
      "capture.savedDesc": "Account written to your local encrypted vault.",
      "capture.done": "Done",
      "capture.expired": "The save suggestion expired or its source changed.",

      "save.title": "Save login",
      "save.reviewTitle": "Review login",
      "save.detectedForms": "Choose a form",
      "save.checkAccount": "Check account",
      "save.kind.login": "Sign in",
      "save.kind.signup": "Sign up",
      "save.kind.change": "Password change",
      "save.target": "Save to",
      "save.newItem": "New item",
      "save.name": "Name",
      "save.username": "Username",
      "save.password": "Password",
      "save.show": "Show",
      "save.hide": "Hide",
      "save.generate": "Generate",
      "save.submit": "Save",
      "save.cancel": "Cancel",
      "save.saved": "Saved to OpenKeylet",

      "settings.captureTitle": "Login save suggestions",
      "settings.captureDesc": "Prompt to save submitted logins into OpenKeylet desktop; drafts expire in 5 minutes.",
      "settings.bridgeTitle": "Local bridge",
      "settings.bridgeHost": "Host",
      "settings.bridgePort": "Port",
      "settings.bridgeTls": "Use TLS (https / wss)",
      "settings.lanWarning": "Remote hosts should only be used over a trusted LAN, private tunnel, or TLS proxy with OPENKEYLET_BRIDGE_ALLOW_LAN=1.",
      "settings.reconnect": "Save & reconnect",
      "settings.invalidHost": "Invalid bridge host",
      "settings.invalidPort": "Invalid port (1024–65535)",
      "settings.switchedRemote": "Switched to {host}:{port}. Run openkeylet browser pair {port} on the server.",
      "settings.switchedLocal": "Bridge updated. Use OpenKeylet desktop to pair if needed.",
      "settings.appearanceTitle": "Appearance & language",
      "settings.language": "Language",
      "settings.langAuto": "AUTO",
      "settings.langEn": "EN",
      "settings.langZh": "简中",
      "settings.langZhTw": "繁中",
      "settings.langJa": "日本語",
      "settings.langKo": "한국어",
      "settings.langEs": "ES",
      "settings.footerVault": "Agent bridge",
      "settings.privacy": "Privacy",

      "passkey.subtitle": "PASSKEY",
      "passkey.createTitle": "Save passkey",
      "passkey.getTitle": "Sign in with passkey",
      "passkey.account": "Account",
      "passkey.pinRequired": "This site requires verification. Set a 6-digit PIN in OpenKeylet desktop, then retry.",
      "passkey.note": "Credentials stay encrypted in your local OpenKeylet vault.",
      "passkey.confirm": "Confirm",
      "passkey.fallback": "Use device or security key",
      "passkey.cancel": "Cancel",
    },
    zh: {
      "status.checking": "正在连接",
      "status.connected": "已连接",
      "status.unavailable": "未连接",
      "header.themeToLight": "切换为浅色模式",
      "header.themeToDark": "切换为深色模式",
      "header.themeLabel": "浅色模式",
      "header.githubTitle": "访问 OpenKeylet GitHub",
      "header.lock": "锁定",
      "header.lockTitle": "锁定快捷填充",

      "update.title": "插件版本待更新",
      "update.detail": "桌面端 v{app} · 当前插件 v{ext}",
      "update.note": "若重载后版本未变化，请在 chrome://extensions/ 重新拖入最新版的 browser-extension 目录。",
      "update.reload": "重载",

      "offline.code": "本地桥接未连接",
      "offline.title": "无法连接到 OpenKeylet",
      "offline.desc": "请确认本机 OpenKeylet 桌面端已打开，且浏览器连接已启用。",
      "offline.retry": "重试连接",
      "offline.settings": "连接设置",

      "unlock.badge": "所有者验证",
      "unlock.title": "解锁快捷填充",
      "unlock.desc": "输入 6 位 PIN 码以在当前网页一键填写账号、银行卡和地址。",
      "unlock.pinLabel": "6 位 PIN 码",
      "unlock.submit": "解锁",
      "unlock.note": "仅在本机校验 · 5 分钟后自动锁定",

      "nav.site": "填入",
      "nav.settings": "桥接",

      "agent.title": "Agent 浏览器通道",
      "agent.ready": "就绪",
      "agent.standby": "待命",
      "agent.desc": "供 AI Agent 零明文调用 Passkey 签名，以及在网页自动填入密码、信用卡与地址。",
      "agent.capPasskey": "Passkey",
      "agent.capLogin": "登录与 2FA",
      "agent.capPersonal": "卡与地址",
      "agent.lastAction": "最近",

      "site.emptyTitle": "打开任意网站即可填充",
      "site.emptyDesc": "浏览器内部页面无法填写。打开任意网站即可供 Agent 或一键自动填入。",
      "site.noLogins": "当前网站暂无已保存账号",
      "site.loginCount": "{count} 个账号",
      "site.loginCountPlural": "{count} 个账号",
      "site.fillHint": "填写",
      "site.filled": "已填写账号密码",
      "site.totpCopied": "2FA 验证码已复制 ({seconds}s)",
      "site.totpTitle": "复制当前 2FA 验证码",
      "site.saveLogin": "保存当前页登录",
      "site.quickAutofill": "卡片与地址快速填充",
      "site.fieldsFilled": "已填写 {count} 个字段",
      "site.desktopHandoff": "管理密码库、密钥与 Passkey 请在 OpenKeylet 桌面端操作。",

      "type.card": "卡片",
      "type.identity": "身份与地址",

      "capture.title": "检测到已提交登录",
      "capture.source": "来源：{origin}",
      "capture.note": "请核对账号与密码，确认后写入 OpenKeylet 桌面端；草稿 5 分钟后自动过期。",
      "capture.review": "预览并保存",
      "capture.dismiss": "忽略",
      "capture.savedTitle": "已保存到 OpenKeylet",
      "capture.savedDesc": "账号信息已写入本地加密密码库。",
      "capture.done": "完成",
      "capture.expired": "待保存信息已过期或来源网页已变化",

      "save.title": "保存登录账号",
      "save.reviewTitle": "确认保存登录",
      "save.detectedForms": "选择检测到的表单",
      "save.checkAccount": "账号待确认",
      "save.kind.login": "登录",
      "save.kind.signup": "注册",
      "save.kind.change": "修改密码",
      "save.target": "保存位置",
      "save.newItem": "新建项目",
      "save.name": "名称",
      "save.username": "账号",
      "save.password": "密码",
      "save.show": "显示",
      "save.hide": "隐藏",
      "save.generate": "生成",
      "save.submit": "保存",
      "save.cancel": "取消",
      "save.saved": "已保存到 OpenKeylet",

      "settings.captureTitle": "登录保存提示",
      "settings.captureDesc": "提交网页登录表单时提示保存到桌面端，方便本人与 Agent 复用；草稿 5 分钟后过期。",
      "settings.bridgeTitle": "本地桥接连接",
      "settings.bridgeHost": "主机地址",
      "settings.bridgePort": "端口",
      "settings.bridgeTls": "使用 TLS 加密 (https / wss)",
      "settings.lanWarning": "非本机连接仅限可信局域网、VPN/Tailscale 或 TLS 代理；服务端需开启 OPENKEYLET_BRIDGE_ALLOW_LAN=1。",
      "settings.reconnect": "保存并重连",
      "settings.invalidHost": "桥接主机地址无效",
      "settings.invalidPort": "端口无效 (1024–65535)",
      "settings.switchedRemote": "已切换远程 Bridge ({host}:{port})，请在服务端运行 openkeylet browser pair {port}",
      "settings.switchedLocal": "连接配置已更新，如未配对请在桌面端完成配对",
      "settings.appearanceTitle": "外观与语言",
      "settings.language": "界面语言",
      "settings.langAuto": "自动",
      "settings.langEn": "EN",
      "settings.langZh": "简中",
      "settings.langZhTw": "繁中",
      "settings.langJa": "日本語",
      "settings.langKo": "한국어",
      "settings.langEs": "ES",
      "settings.footerVault": "Agent 浏览器桥接",
      "settings.privacy": "隐私政策",

      "passkey.subtitle": "PASSKEY",
      "passkey.createTitle": "保存 Passkey",
      "passkey.getTitle": "使用 Passkey 登录",
      "passkey.account": "选择账号",
      "passkey.pinRequired": "此网站要求身份验证。请先在 OpenKeylet 桌面端设置 6 位 PIN，再重新发起请求。",
      "passkey.note": "凭据加密保存在本机 OpenKeylet 密码库中。",
      "passkey.confirm": "确认",
      "passkey.fallback": "使用设备或安全密钥",
      "passkey.cancel": "取消",
    },
    "zh-TW": {
      "status.checking": "連線中",
      "status.connected": "已連線",
      "status.unavailable": "未連線",
      "header.themeToLight": "切換為淺色模式",
      "header.themeToDark": "切換為深色模式",
      "header.themeLabel": "淺色模式",
      "header.githubTitle": "造訪 OpenKeylet GitHub",
      "header.lock": "鎖定",
      "header.lockTitle": "鎖定快捷填寫",

      "update.title": "擴充功能版本待更新",
      "update.detail": "桌面端 v{app} · 目前擴充功能 v{ext}",
      "update.note": "若重新載入後版本未變更，請至 chrome://extensions/ 重新拖入最新版的 browser-extension 資料夾。",
      "update.reload": "重載",

      "offline.code": "本機橋接未連線",
      "offline.title": "無法連線至 OpenKeylet",
      "offline.desc": "請確認本機 OpenKeylet 桌面端已開啟，且瀏覽器連線已啟用。",
      "offline.retry": "重試連線",
      "offline.settings": "連線設定",

      "unlock.badge": "擁有者驗證",
      "unlock.title": "解鎖快捷填寫",
      "unlock.desc": "輸入 6 位 PIN 碼以於目前網頁一鍵填寫帳號、卡片與地址。",
      "unlock.pinLabel": "6 位 PIN 碼",
      "unlock.submit": "解鎖",
      "unlock.note": "僅於本機驗證 · 5 分鐘後自動鎖定",

      "nav.site": "填入",
      "nav.settings": "橋接",

      "agent.title": "Agent 瀏覽器通道",
      "agent.ready": "就緒",
      "agent.standby": "待命",
      "agent.desc": "供 AI Agent 零明文呼叫 Passkey 簽章，並於網頁自動填入密碼、信用卡與地址。",
      "agent.capPasskey": "Passkey",
      "agent.capLogin": "登入與 2FA",
      "agent.capPersonal": "卡與地址",
      "agent.lastAction": "最近",

      "site.emptyTitle": "開啟任意網站即可填寫",
      "site.emptyDesc": "瀏覽器內部頁面無法填寫。開啟任意網站即可供 Agent 或一鍵自動填入。",
      "site.noLogins": "此網站尚無已儲存帳號",
      "site.loginCount": "{count} 個帳號",
      "site.loginCountPlural": "{count} 個帳號",
      "site.fillHint": "填寫",
      "site.filled": "已填寫帳號密碼",
      "site.totpCopied": "2FA 驗證碼已複製 ({seconds}s)",
      "site.totpTitle": "複製目前 2FA 驗證碼",
      "site.saveLogin": "儲存目前頁面登入",
      "site.quickAutofill": "卡片與地址快速填寫",
      "site.fieldsFilled": "已填寫 {count} 個欄位",
      "site.desktopHandoff": "管理密碼庫、金鑰與 Passkey 請使用 OpenKeylet 桌面端。",

      "type.card": "卡片",
      "type.identity": "身分與地址",

      "capture.title": "偵測到已提交登入",
      "capture.source": "來源：{origin}",
      "capture.note": "請核對帳號與密碼，確認後寫入 OpenKeylet 桌面端；草稿 5 分鐘後過期。",
      "capture.review": "預覽並儲存",
      "capture.dismiss": "忽略",
      "capture.savedTitle": "已儲存至 OpenKeylet",
      "capture.savedDesc": "帳號資訊已寫入本機加密密碼庫。",
      "capture.done": "完成",
      "capture.expired": "待儲存資訊已過期或來源網頁已變更",

      "save.title": "儲存登入帳號",
      "save.reviewTitle": "確認儲存登入",
      "save.detectedForms": "選擇偵測到的表單",
      "save.checkAccount": "帳號待確認",
      "save.kind.login": "登入",
      "save.kind.signup": "註冊",
      "save.kind.change": "修改密碼",
      "save.target": "儲存位置",
      "save.newItem": "新增項目",
      "save.name": "名稱",
      "save.username": "帳號",
      "save.password": "密碼",
      "save.show": "顯示",
      "save.hide": "隱藏",
      "save.generate": "產生",
      "save.submit": "儲存",
      "save.cancel": "取消",
      "save.saved": "已儲存至 OpenKeylet",

      "settings.captureTitle": "登入儲存提示",
      "settings.captureDesc": "提交網頁登入表單時提示儲存至桌面端，草稿 5 分鐘後自動過期。",
      "settings.bridgeTitle": "本機橋接連線",
      "settings.bridgeHost": "主機位址",
      "settings.bridgePort": "連接埠",
      "settings.bridgeTls": "使用 TLS 加密 (https / wss)",
      "settings.lanWarning": "非本機連線僅限可信區域網路、VPN/Tailscale 或 TLS 代理；伺服器端須開啟 OPENKEYLET_BRIDGE_ALLOW_LAN=1。",
      "settings.reconnect": "儲存並重連",
      "settings.invalidHost": "橋接主機位址無效",
      "settings.invalidPort": "連接埠無效 (1024–65535)",
      "settings.switchedRemote": "已切換遠端 Bridge ({host}:{port})，請在伺服器端執行 openkeylet browser pair {port}",
      "settings.switchedLocal": "連線設定已更新，若未配對請在桌面端完成配對",
      "settings.appearanceTitle": "外觀與語言",
      "settings.language": "介面語言",
      "settings.langAuto": "自動",
      "settings.langEn": "EN",
      "settings.langZh": "简中",
      "settings.langZhTw": "繁中",
      "settings.langJa": "日本語",
      "settings.langKo": "한국어",
      "settings.langEs": "ES",
      "settings.footerVault": "Agent 瀏覽器橋接",
      "settings.privacy": "隱私權政策",

      "passkey.subtitle": "PASSKEY",
      "passkey.createTitle": "儲存 Passkey",
      "passkey.getTitle": "使用 Passkey 登入",
      "passkey.account": "選擇帳號",
      "passkey.pinRequired": "此網站要求身分驗證。請先在 OpenKeylet 桌面端設定 6 位 PIN，再重新發起請求。",
      "passkey.note": "憑證加密儲存在本機 OpenKeylet 密碼庫中。",
      "passkey.confirm": "確認",
      "passkey.fallback": "使用裝置或安全金鑰",
      "passkey.cancel": "取消",
    },
    ja: {
      "status.checking": "確認中",
      "status.connected": "接続済み",
      "status.unavailable": "未接続",
      "header.themeToLight": "ライトモードに切替",
      "header.themeToDark": "ダークモードに切替",
      "header.themeLabel": "ライトモード",
      "header.githubTitle": "OpenKeylet の GitHub を開く",
      "header.lock": "ロック",
      "header.lockTitle": "クイック入力をロック",

      "update.title": "拡張機能の更新があります",
      "update.detail": "デスクトップ v{app} · 拡張機能 v{ext}",
      "update.note": "再読み込みしてもバージョンが変わらない場合は、最新の browser-extension フォルダを chrome://extensions/ に再読み込みしてください。",
      "update.reload": "再読込",

      "offline.code": "ブリッジ未接続",
      "offline.title": "OpenKeylet に接続できません",
      "offline.desc": "OpenKeylet デスクトップアプリが起動しており、ブラウザブリッジが有効か確認してください。",
      "offline.retry": "再試行",
      "offline.settings": "接続設定",

      "unlock.badge": "所有者認証",
      "unlock.title": "クイック入力を解除",
      "unlock.desc": "6桁の PIN を入力してこのページにログイン・カード・住所を入力します。",
      "unlock.pinLabel": "6桁の PIN",
      "unlock.submit": "ロック解除",
      "unlock.note": "この端末でのみ保護 · 5分後に自動ロック",

      "nav.site": "入力",
      "nav.settings": "ブリッジ",

      "agent.title": "Agent ブラウザチャネル",
      "agent.ready": "待機完了",
      "agent.standby": "待機中",
      "agent.desc": "AI Agent が平文を見ずに Passkey 署名やパスワード・カード・住所の入力を行うブリッジです。",
      "agent.capPasskey": "Passkey",
      "agent.capLogin": "ログイン・2FA",
      "agent.capPersonal": "カード・住所",
      "agent.lastAction": "直近",

      "site.emptyTitle": "ウェブサイトを開いて自動入力",
      "site.emptyDesc": "ブラウザ内部ページには入力できません。任意のサイトを開くと Agent・手動入力が利用できます。",
      "site.noLogins": "このサイトの保存済みログインはありません",
      "site.loginCount": "{count} 件のログイン",
      "site.loginCountPlural": "{count} 件のログイン",
      "site.fillHint": "入力",
      "site.filled": "認証情報を入力しました",
      "site.totpCopied": "2FA コードをコピーしました ({seconds}s)",
      "site.totpTitle": "現在の 2FA コードをコピー",
      "site.saveLogin": "このページのログインを保存",
      "site.quickAutofill": "カード・住所のクイック入力",
      "site.fieldsFilled": "{count} 件の項目を入力しました",
      "site.desktopHandoff": "保管庫・キー・パスキーの管理は OpenKeylet デスクトップで行います。",

      "type.card": "カード",
      "type.identity": "住所・個人情報",

      "capture.title": "ログインを検出しました",
      "capture.source": "送信元：{origin}",
      "capture.note": "保存前にアカウントとパスワードを確認してください。下書きは 5 分で失効します。",
      "capture.review": "確認して保存",
      "capture.dismiss": "閉じる",
      "capture.savedTitle": "OpenKeylet に保存しました",
      "capture.savedDesc": "ローカルの暗号化ボールトに書き込まれました。",
      "capture.done": "完了",
      "capture.expired": "保存候補の有効期限が切れたか、ページが変更されました。",

      "save.title": "ログインを保存",
      "save.reviewTitle": "ログインを確認",
      "save.detectedForms": "検出されたフォームを選択",
      "save.checkAccount": "アカウントを確認",
      "save.kind.login": "ログイン",
      "save.kind.signup": "新規登録",
      "save.kind.change": "パスワード変更",
      "save.target": "保存先",
      "save.newItem": "新規項目",
      "save.name": "名前",
      "save.username": "ユーザー名",
      "save.password": "パスワード",
      "save.show": "表示",
      "save.hide": "隠す",
      "save.generate": "生成",
      "save.submit": "保存",
      "save.cancel": "キャンセル",
      "save.saved": "OpenKeylet に保存しました",

      "settings.captureTitle": "ログイン保存の提案",
      "settings.captureDesc": "フォーム送信時に OpenKeylet デスクトップへの保存を提案します。下書きは 5 分で失効します。",
      "settings.bridgeTitle": "ローカルブリッジ",
      "settings.bridgeHost": "ホスト",
      "settings.bridgePort": "ポート",
      "settings.bridgeTls": "TLS を使用 (https / wss)",
      "settings.lanWarning": "リモートホストは信頼できる LAN、VPN、または TLS プロキシ経由のみで使用してください（OPENKEYLET_BRIDGE_ALLOW_LAN=1 が必要）。",
      "settings.reconnect": "保存して再接続",
      "settings.invalidHost": "無効なブリッジホストです",
      "settings.invalidPort": "無効なポートです (1024–65535)",
      "settings.switchedRemote": "{host}:{port} に切り替えました。サーバーで openkeylet browser pair {port} を実行してください。",
      "settings.switchedLocal": "ブリッジを更新しました。必要に応じてデスクトップ側でペアリングしてください。",
      "settings.appearanceTitle": "外観と言語",
      "settings.language": "表示言語",
      "settings.langAuto": "自動",
      "settings.langEn": "EN",
      "settings.langZh": "简中",
      "settings.langZhTw": "繁中",
      "settings.langJa": "日本語",
      "settings.langKo": "한국어",
      "settings.langEs": "ES",
      "settings.footerVault": "Agent ブリッジ",
      "settings.privacy": "プライバシー",

      "passkey.subtitle": "PASSKEY",
      "passkey.createTitle": "パスキーを保存",
      "passkey.getTitle": "パスキーでログイン",
      "passkey.account": "アカウント",
      "passkey.pinRequired": "このサイトは本人確認が必要です。OpenKeylet デスクトップで 6 桁の PIN を設定してから再試行してください。",
      "passkey.note": "認証情報はローカルの OpenKeylet 保管庫に暗号化保存されます。",
      "passkey.confirm": "確認",
      "passkey.fallback": "デバイスまたはセキュリティキーを使用",
      "passkey.cancel": "キャンセル",
    },
    ko: {
      "status.checking": "확인 중",
      "status.connected": "연결됨",
      "status.unavailable": "연결 안 됨",
      "header.themeToLight": "라이트 모드로 전환",
      "header.themeToDark": "다크 모드로 전환",
      "header.themeLabel": "라이트 모드",
      "header.githubTitle": "OpenKeylet GitHub 열기",
      "header.lock": "잠금",
      "header.lockTitle": "빠른 입력 잠금",

      "update.title": "확장 프로그램 업데이트 가능",
      "update.detail": "데스크톱 v{app} · 확장 프로그램 v{ext}",
      "update.note": "새로고침 후에도 버전이 바뀌지 않으면 최신 browser-extension 폴더를 chrome://extensions/에 다시 로드하세요.",
      "update.reload": "새로고침",

      "offline.code": "브리지 오프라인",
      "offline.title": "OpenKeylet에 연결할 수 없습니다",
      "offline.desc": "OpenKeylet 데스크톱 앱이 실행 중이고 브라우저 브리지가 켜져 있는지 확인하세요.",
      "offline.retry": "다시 시도",
      "offline.settings": "연결 설정",

      "unlock.badge": "소유자 인증",
      "unlock.title": "빠른 자동 입력 잠금 해제",
      "unlock.desc": "이 페이지에서 로그인, 카드, 주소를 입력하려면 6자리 PIN을 입력하세요.",
      "unlock.pinLabel": "6자리 PIN",
      "unlock.submit": "잠금 해제",
      "unlock.note": "이 기기에서 로컬 보호 · 5분 후 자동 잠금",

      "nav.site": "입력",
      "nav.settings": "브리지",

      "agent.title": "Agent 브라우저 채널",
      "agent.ready": "준비됨",
      "agent.standby": "대기",
      "agent.desc": "AI Agent가 평문 노출 없이 Passkey 서명과 비밀번호·카드·주소 입력을 수행하는 브리지입니다.",
      "agent.capPasskey": "Passkey",
      "agent.capLogin": "로그인 · 2FA",
      "agent.capPersonal": "카드 · 주소",
      "agent.lastAction": "최근",

      "site.emptyTitle": "웹사이트를 열어 자동 입력",
      "site.emptyDesc": "브라우저 내부 페이지에는 입력할 수 없습니다. 웹사이트를 열면 Agent 또는 원클릭 입력이 동작합니다.",
      "site.noLogins": "이 사이트에 저장된 로그인이 없습니다",
      "site.loginCount": "로그인 {count}개",
      "site.loginCountPlural": "로그인 {count}개",
      "site.fillHint": "입력",
      "site.filled": "자격 증명을 입력했습니다",
      "site.totpCopied": "2FA 코드 복사됨 ({seconds}초)",
      "site.totpTitle": "현재 2FA 코드 복사",
      "site.saveLogin": "현재 페이지 로그인 저장",
      "site.quickAutofill": "카드 및 주소 빠른 입력",
      "site.fieldsFilled": "{count}개 필드를 입력했습니다",
      "site.desktopHandoff": "보관함·키·패스키 관리는 OpenKeylet 데스크톱에서 진행하세요.",

      "type.card": "카드",
      "type.identity": "신원 · 주소",

      "capture.title": "로그인 감지됨",
      "capture.source": "출처: {origin}",
      "capture.note": "저장하기 전에 계정과 비밀번호를 확인하세요. 초안은 5분 후 만료됩니다.",
      "capture.review": "검토 및 저장",
      "capture.dismiss": "무시",
      "capture.savedTitle": "OpenKeylet에 저장됨",
      "capture.savedDesc": "계정이 로컬 암호화 보관함에 저장되었습니다.",
      "capture.done": "완료",
      "capture.expired": "저장 제안이 만료되었거나 페이지가 변경되었습니다.",

      "save.title": "로그인 저장",
      "save.reviewTitle": "로그인 확인",
      "save.detectedForms": "감지된 양식 선택",
      "save.checkAccount": "계정 확인",
      "save.kind.login": "로그인",
      "save.kind.signup": "가입",
      "save.kind.change": "비밀번호 변경",
      "save.target": "저장 위치",
      "save.newItem": "새 항목",
      "save.name": "이름",
      "save.username": "사용자 이름",
      "save.password": "비밀번호",
      "save.show": "표시",
      "save.hide": "숨기기",
      "save.generate": "생성",
      "save.submit": "저장",
      "save.cancel": "취소",
      "save.saved": "OpenKeylet에 저장됨",

      "settings.captureTitle": "로그인 저장 제안",
      "settings.captureDesc": "로그인 양식 제출 시 OpenKeylet 데스크톱에 저장을 제안합니다. 초안은 5분 후 만료됩니다.",
      "settings.bridgeTitle": "로컬 브리지",
      "settings.bridgeHost": "호스트",
      "settings.bridgePort": "포트",
      "settings.bridgeTls": "TLS 사용 (https / wss)",
      "settings.lanWarning": "원격 호스트는 신뢰할 수 있는 LAN, 사설 터널 또는 TLS 프록시에서만 사용하세요(OPENKEYLET_BRIDGE_ALLOW_LAN=1 필요).",
      "settings.reconnect": "저장 및 다시 연결",
      "settings.invalidHost": "유효하지 않은 브리지 호스트",
      "settings.invalidPort": "유효하지 않은 포트 (1024–65535)",
      "settings.switchedRemote": "{host}:{port}로 전환했습니다. 서버에서 openkeylet browser pair {port}를 실행하세요.",
      "settings.switchedLocal": "브리지가 업데이트되었습니다. 필요 시 데스크톱에서 페어링하세요.",
      "settings.appearanceTitle": "외관 및 언어",
      "settings.language": "언어",
      "settings.langAuto": "자동",
      "settings.langEn": "EN",
      "settings.langZh": "简中",
      "settings.langZhTw": "繁中",
      "settings.langJa": "日本語",
      "settings.langKo": "한국어",
      "settings.langEs": "ES",
      "settings.footerVault": "Agent 브리지",
      "settings.privacy": "개인정보",

      "passkey.subtitle": "PASSKEY",
      "passkey.createTitle": "패스키 저장",
      "passkey.getTitle": "패스키로 로그인",
      "passkey.account": "계정",
      "passkey.pinRequired": "이 사이트는 본인 확인이 필요합니다. OpenKeylet 데스크톱에서 6자리 PIN을 설정한 후 다시 시도하세요.",
      "passkey.note": "자격 증명은 로컬 OpenKeylet 보관함에 암호화되어 저장됩니다.",
      "passkey.confirm": "확인",
      "passkey.fallback": "기기 또는 보안 키 사용",
      "passkey.cancel": "취소",
    },
    es: {
      "status.checking": "COMPROBANDO",
      "status.connected": "CONECTADO",
      "status.unavailable": "NO DISPONIBLE",
      "header.themeToLight": "Cambiar a modo claro",
      "header.themeToDark": "Cambiar a modo oscuro",
      "header.themeLabel": "Modo claro",
      "header.githubTitle": "OpenKeylet en GitHub",
      "header.lock": "BLOQUEAR",
      "header.lockTitle": "Bloquear autocompletado",

      "update.title": "Actualización disponible",
      "update.detail": "Escritorio v{app} · Extensión v{ext}",
      "update.note": "Si la versión no cambia al recargar, vuelve a arrastrar la carpeta browser-extension más reciente a chrome://extensions/.",
      "update.reload": "Recargar",

      "offline.code": "PUENTE DESCONECTADO",
      "offline.title": "No se puede conectar con OpenKeylet",
      "offline.desc": "Asegúrate de que OpenKeylet esté abierto y el puente del navegador esté activado.",
      "offline.retry": "Reintentar",
      "offline.settings": "Conexión",

      "unlock.badge": "ACCESO DEL TITULAR",
      "unlock.title": "Desbloquear autocompletado",
      "unlock.desc": "Introduce tu PIN de 6 dígitos para rellenar accesos, tarjetas y direcciones en esta página.",
      "unlock.pinLabel": "PIN de 6 dígitos",
      "unlock.submit": "Desbloquear",
      "unlock.note": "Protegido localmente en este equipo · Bloqueo automático en 5 min",

      "nav.site": "Rellenar",
      "nav.settings": "Puente",

      "agent.title": "Canal de navegador para Agents",
      "agent.ready": "LISTO",
      "agent.standby": "EN ESPERA",
      "agent.desc": "Puente sin texto plano para que los AI Agents firmen Passkeys y rellenen contraseñas, tarjetas y direcciones.",
      "agent.capPasskey": "Passkey",
      "agent.capLogin": "Acceso y 2FA",
      "agent.capPersonal": "Tarjeta y Dirección",
      "agent.lastAction": "ÚLTIMO",

      "site.emptyTitle": "Abre un sitio web para autocompletar",
      "site.emptyDesc": "No se puede rellenar en páginas internas del navegador. Abre cualquier sitio web para usar el puente.",
      "site.noLogins": "No hay accesos guardados para este sitio",
      "site.loginCount": "{count} acceso",
      "site.loginCountPlural": "{count} accesos",
      "site.fillHint": "Rellenar",
      "site.filled": "Credenciales rellenadas",
      "site.totpCopied": "Código 2FA copiado ({seconds}s)",
      "site.totpTitle": "Copiar código 2FA actual",
      "site.saveLogin": "Guardar acceso actual",
      "site.quickAutofill": "Tarjetas y direcciones",
      "site.fieldsFilled": "{count} campos rellenados",
      "site.desktopHandoff": "Gestiona tu bóveda, claves y passkeys desde OpenKeylet escritorio.",

      "type.card": "Tarjeta",
      "type.identity": "Identidad",

      "capture.title": "Inicio de sesión detectado",
      "capture.source": "Origen: {origin}",
      "capture.note": "Revisa cuenta y contraseña antes de guardar en OpenKeylet escritorio. Caduca en 5 minutos.",
      "capture.review": "Revisar y guardar",
      "capture.dismiss": "Descartar",
      "capture.savedTitle": "Guardado en OpenKeylet",
      "capture.savedDesc": "Cuenta guardada en tu bóveda local cifrada.",
      "capture.done": "Listo",
      "capture.expired": "La sugerencia caducó o la página cambió.",

      "save.title": "Guardar acceso",
      "save.reviewTitle": "Revisar acceso",
      "save.detectedForms": "Elegir formulario",
      "save.checkAccount": "Verificar cuenta",
      "save.kind.login": "Iniciar sesión",
      "save.kind.signup": "Registro",
      "save.kind.change": "Cambio de contraseña",
      "save.target": "Guardar en",
      "save.newItem": "Nuevo elemento",
      "save.name": "Nombre",
      "save.username": "Usuario",
      "save.password": "Contraseña",
      "save.show": "Mostrar",
      "save.hide": "Ocultar",
      "save.generate": "Generar",
      "save.submit": "Guardar",
      "save.cancel": "Cancelar",
      "save.saved": "Guardado en OpenKeylet",

      "settings.captureTitle": "Sugerencias para guardar acceso",
      "settings.captureDesc": "Sugiere guardar accesos enviados en OpenKeylet escritorio; los borradores caducan en 5 min.",
      "settings.bridgeTitle": "Puente local",
      "settings.bridgeHost": "Host",
      "settings.bridgePort": "Puerto",
      "settings.bridgeTls": "Usar TLS (https / wss)",
      "settings.lanWarning": "Usa hosts remotos solo en LAN confiable, túnel privado o proxy TLS con OPENKEYLET_BRIDGE_ALLOW_LAN=1.",
      "settings.reconnect": "Guardar y reconectar",
      "settings.invalidHost": "Host de puente inválido",
      "settings.invalidPort": "Puerto inválido (1024–65535)",
      "settings.switchedRemote": "Cambiado a {host}:{port}. Ejecuta openkeylet browser pair {port} en el servidor.",
      "settings.switchedLocal": "Puente actualizado. Empareja desde OpenKeylet si hace falta.",
      "settings.appearanceTitle": "Apariencia e idioma",
      "settings.language": "Idioma",
      "settings.langAuto": "AUTO",
      "settings.langEn": "EN",
      "settings.langZh": "简中",
      "settings.langZhTw": "繁中",
      "settings.langJa": "日本語",
      "settings.langKo": "한국어",
      "settings.langEs": "ES",
      "settings.footerVault": "Puente para Agents",
      "settings.privacy": "Privacidad",

      "passkey.subtitle": "PASSKEY",
      "passkey.createTitle": "Guardar passkey",
      "passkey.getTitle": "Iniciar sesión con passkey",
      "passkey.account": "Cuenta",
      "passkey.pinRequired": "Este sitio requiere verificación. Configura un PIN de 6 dígitos en OpenKeylet y reintenta.",
      "passkey.note": "Las credenciales se guardan cifradas en tu bóveda local de OpenKeylet.",
      "passkey.confirm": "Confirmar",
      "passkey.fallback": "Usar dispositivo o llave de seguridad",
      "passkey.cancel": "Cancelar",
    },
  };

  function t(key, vars = null) {
    const table = STRINGS[resolvedLang] || STRINGS.en;
    let text = Object.hasOwn(table, key) ? table[key] : (STRINGS.en[key] ?? key);
    if (vars) {
      for (const [k, v] of Object.entries(vars)) {
        text = text.replaceAll(`{${k}}`, String(v));
      }
    }
    return text;
  }

  function localizeMessage(raw) {
    const text = String(raw?.message || raw || "").trim();
    if (!text) return "";
    const parts = text.split(" / ");
    if (parts.length === 2) {
      const hasCjkFirst = /[\u3400-\u9fff]/.test(parts[0]);
      const hasCjkSecond = /[\u3400-\u9fff]/.test(parts[1]);
      if (hasCjkFirst && !hasCjkSecond) {
        return (resolvedLang === "zh" || resolvedLang === "zh-TW") ? parts[0].trim() : parts[1].trim();
      }
    }
    return text;
  }

  function applyI18n(root = document) {
    document.documentElement.lang = htmlLangFor(resolvedLang);
    for (const el of root.querySelectorAll("[data-i18n]")) {
      el.textContent = t(el.dataset.i18n);
    }
    for (const el of root.querySelectorAll("[data-i18n-placeholder]")) {
      el.placeholder = t(el.dataset.i18nPlaceholder);
    }
    for (const el of root.querySelectorAll("[data-i18n-title]")) {
      el.title = t(el.dataset.i18nTitle);
    }
    for (const el of root.querySelectorAll("[data-i18n-aria]")) {
      el.setAttribute("aria-label", t(el.dataset.i18nAria));
    }
    const themeToggle = document.getElementById("theme-toggle");
    if (themeToggle) {
      themeToggle.setAttribute("aria-checked", String(theme === "light"));
      themeToggle.title = t(theme === "dark" ? "header.themeToLight" : "header.themeToDark");
      themeToggle.setAttribute("aria-label", t("header.themeLabel"));
    }
    for (const btn of root.querySelectorAll("[data-lang-option]")) {
      btn.classList.toggle("active", btn.dataset.langOption === langSetting);
      btn.setAttribute("aria-pressed", String(btn.dataset.langOption === langSetting));
    }
  }

  function notify() {
    for (const fn of listeners) {
      try { fn({ theme, lang: resolvedLang, langSetting }); } catch { /* ignore */ }
    }
  }

  function setTheme(next) {
    const normalized = next === "light" ? "light" : "dark";
    theme = normalized;
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem(THEME_KEY, theme); } catch { /* ignore */ }
    chrome.storage?.local?.set({ uiTheme: theme }).catch?.(() => {});
    applyI18n();
    notify();
  }

  function toggleTheme() {
    setTheme(theme === "light" ? "dark" : "light");
  }

  function setLanguage(setting) {
    langSetting = normalizeLangSetting(setting);
    resolvedLang = resolveLang(langSetting);
    try { localStorage.setItem(LANG_KEY, langSetting); } catch { /* ignore */ }
    chrome.storage?.local?.set({ uiLang: langSetting }).catch?.(() => {});
    applyI18n();
    notify();
  }

  async function hydrateFromStorage() {
    if (!chrome.storage?.local) return;
    try {
      const stored = await chrome.storage.local.get(["uiTheme", "uiLang"]);
      let changed = false;
      if (stored.uiTheme === "light" || stored.uiTheme === "dark") {
        if (stored.uiTheme !== theme) {
          theme = stored.uiTheme;
          document.documentElement.dataset.theme = theme;
          try { localStorage.setItem(THEME_KEY, theme); } catch { /* ignore */ }
          changed = true;
        }
      }
      if (stored.uiLang) {
        const nextSetting = normalizeLangSetting(stored.uiLang);
        if (nextSetting !== langSetting) {
          langSetting = nextSetting;
          resolvedLang = resolveLang(langSetting);
          try { localStorage.setItem(LANG_KEY, langSetting); } catch { /* ignore */ }
          changed = true;
        }
      }
      if (changed) {
        applyI18n();
        notify();
      }
    } catch { /* ignore */ }
  }

  // Live-follow theme & language pushed from OpenKeylet desktop via Browser Bridge.
  if (typeof chrome !== "undefined" && chrome.storage?.onChanged) {
    chrome.storage.onChanged.addListener((changes, areaName) => {
      if (areaName !== "local") return;
      let changed = false;
      const nextTheme = changes.uiTheme?.newValue;
      if ((nextTheme === "light" || nextTheme === "dark") && nextTheme !== theme) {
        theme = nextTheme;
        document.documentElement.dataset.theme = theme;
        try { localStorage.setItem(THEME_KEY, theme); } catch { /* ignore */ }
        changed = true;
      }
      const rawLang = changes.uiLang?.newValue;
      if (typeof rawLang === "string" && rawLang.trim()) {
        const nextSetting = normalizeLangSetting(rawLang);
        if (nextSetting !== langSetting) {
          langSetting = nextSetting;
          resolvedLang = resolveLang(langSetting);
          try { localStorage.setItem(LANG_KEY, langSetting); } catch { /* ignore */ }
          changed = true;
        }
      }
      if (changed) {
        applyI18n();
        notify();
      }
    });
  }

  const ICONS = {
    login: '<circle cx="8" cy="12" r="3.5"/><path d="M11.5 12H20M17 12v3M14.5 12v2"/>',
    card: '<rect x="2.5" y="5" width="19" height="14" rx="2.5"/><path d="M2.5 10h19M6.5 15h4"/>',
    identity: '<circle cx="12" cy="8" r="3.5"/><path d="M4.5 19a7.5 7.5 0 0 1 15 0"/>',
    fill: '<path d="M5 12h13M13 7l5 5-5 5"/>',
  };

  function icon(name, className = "ico") {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    if (className) svg.setAttribute("class", className);
    svg.innerHTML = ICONS[name] || ICONS.fill;
    return svg;
  }

  return {
    t,
    localizeMessage,
    applyI18n,
    setTheme,
    toggleTheme,
    setLanguage,
    hydrateFromStorage,
    icon,
    get theme() { return theme; },
    get lang() { return resolvedLang; },
    get langSetting() { return langSetting; },
    onChange(fn) { listeners.add(fn); return () => listeners.delete(fn); },
  };
})();
