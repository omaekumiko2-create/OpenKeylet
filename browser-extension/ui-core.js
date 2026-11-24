/* Shared appearance (dark/light monochrome theme), single-language i18n, and monochrome SVG icons
   for OpenKeylet extension pages (popup.html & request.html). */
const OpenKeyletUI = (() => {
  const THEME_KEY = "openkeylet.ext.theme.v1";
  const LANG_KEY = "openkeylet.ext.lang.v1";

  let theme = "dark";
  let langSetting = "auto";
  let resolvedLang = "en";
  const listeners = new Set();

  function detectLang() {
    const list = Array.isArray(navigator.languages) && navigator.languages.length
      ? navigator.languages
      : [navigator.language || "en"];
    for (const raw of list) {
      const lower = String(raw || "").trim().toLowerCase();
      if (!lower) continue;
      if (lower === "zh" || lower.startsWith("zh-") || lower.startsWith("zh_")) return "zh";
      if (lower === "en" || lower.startsWith("en-") || lower.startsWith("en_")) return "en";
    }
    return "en";
  }

  function normalizeLangSetting(val) {
    if (val === "zh" || val === "en") return val;
    return "auto";
  }

  function resolveLang(setting) {
    return setting === "auto" ? detectLang() : setting;
  }

  // Synchronous init from localStorage so first paint never flashes.
  try {
    const savedTheme = localStorage.getItem(THEME_KEY);
    if (savedTheme === "light" || savedTheme === "dark") theme = savedTheme;
    const savedLang = localStorage.getItem(LANG_KEY);
    if (savedLang) langSetting = normalizeLangSetting(savedLang);
  } catch { /* ignore */ }
  resolvedLang = resolveLang(langSetting);
  document.documentElement.dataset.theme = theme;
  document.documentElement.lang = resolvedLang === "zh" ? "zh-CN" : "en";

  const STRINGS = {
    en: {
      // Status & Header
      "status.checking": "CHECKING",
      "status.connected": "CONNECTED",
      "status.unavailable": "UNAVAILABLE",
      "status.locked": "LOCKED",
      "header.themeToLight": "Switch to light mode",
      "header.themeToDark": "Switch to dark mode",
      "header.themeLabel": "Light mode",
      "header.lock": "LOCK",
      "header.lockTitle": "Lock vault",

      // Version mismatch
      "update.title": "Extension update available",
      "update.detail": "Desktop v{app} · Extension v{ext}",
      "update.note": "If reloading does not update the version, re-drag the latest browser-extension folder into chrome://extensions/.",
      "update.reload": "Reload",

      // Offline state
      "offline.code": "BRIDGE OFFLINE",
      "offline.title": "Cannot reach OpenKeylet",
      "offline.desc": "Make sure the OpenKeylet desktop app is open and Browser Bridge is enabled.",
      "offline.retry": "Retry",
      "offline.settings": "Connection",

      // Unlock screen
      "unlock.badge": "OWNER ACCESS",
      "unlock.title": "Unlock local vault",
      "unlock.desc": "Enter your 6-digit PIN to view, fill, and manage credentials.",
      "unlock.pinLabel": "6-digit PIN",
      "unlock.pinPlaceholder": "••••••",
      "unlock.submit": "Unlock",
      "unlock.note": "Protected locally on this device · Auto-locks after 5 min",

      // Navigation tabs
      "nav.site": "Site",
      "nav.vault": "Vault",
      "nav.gen": "Gen",
      "nav.settings": "System",

      // Site tab
      "site.emptyCode": "NO ACTIVE WEBSITE",
      "site.emptyTitle": "Open a website to autofill",
      "site.emptyDesc": "Browser internal pages cannot be filled. Open any sign-in page, or browse your vault below.",
      "site.openVault": "Browse vault",
      "site.noLogins": "No saved logins for this site",
      "site.loginCount": "{count} login",
      "site.loginCountPlural": "{count} logins",
      "site.fillHint": "Fill",
      "site.filled": "Credentials filled",
      "site.totpCopied": "2FA code copied ({seconds}s)",
      "site.totpTitle": "Copy live 2FA code",
      "site.saveLogin": "Save login",
      "site.scanQr": "Scan 2FA",
      "site.smartSave": "Smart save",
      "site.quickAutofill": "Cards & identities",
      "site.fieldsFilled": "Filled {count} fields",

      // Capture notice
      "capture.title": "Login detected",
      "capture.source": "Source: {origin}",
      "capture.note": "Review account & password before saving. Draft expires in 5 minutes.",
      "capture.review": "Review & save",
      "capture.dismiss": "Dismiss",
      "capture.savedTitle": "Saved to OpenKeylet",
      "capture.savedDesc": "Account written to your local encrypted vault.",
      "capture.done": "Done",
      "capture.expired": "The save suggestion expired or its source changed.",

      // Save login sheet
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

      // Smart save sheet
      "quick.title": "Smart save",
      "quick.label": "Paste API key, cURL, SSH, .env, or 2FA URI",
      "quick.placeholder": "sk-... / curl ... / otpauth://totp/...",
      "quick.name": "Name",
      "quick.attachLabel": "Attach 2FA to existing login",
      "quick.attachBtn": "Attach 2FA",
      "quick.attached": "2FA attached to {name}",
      "quick.save": "Save item",
      "quick.qrDetected": "2FA QR code detected",
      "quick.emptyErr": "Paste a secret or key first",
      "quick.parseErr": "Could not parse this content",

      // Vault tab
      "vault.searchPlaceholder": "Search vault…",
      "vault.new": "New",
      "vault.viewActive": "Vault",
      "vault.viewTrash": "Trash",
      "vault.allTypes": "All",
      "vault.allFolders": "All folders",
      "vault.favorites": "Favorites",
      "vault.emptyActive": "No matching items",
      "vault.emptyTrash": "Trash is empty",
      "vault.disabled": "Disabled",
      "vault.fill": "Fill",
      "vault.edit": "Edit",
      "vault.history": "History",
      "vault.trash": "Trash",
      "vault.restore": "Restore",
      "vault.purge": "Delete forever",
      "vault.updated": "Vault updated",
      "vault.confirmTrash": "Move to trash? This item will stop being used for autofill.",
      "vault.confirmPurge": "Delete this item and its passkeys permanently? Existing backups are not affected.",
      "vault.confirmClearHistory": "Clear all previous passwords? The current password stays unchanged.",
      "vault.confirm": "Confirm",
      "vault.cancel": "Cancel",
      "vault.copied": "Copied to clipboard",

      // Item types
      "type.login": "Login",
      "type.passkey": "Passkey",
      "type.card": "Card",
      "type.identity": "Identity",
      "type.secureNote": "Note",
      "type.ssh": "SSH",
      "type.api": "API",
      "type.custom": "Other",

      // Editor sheet
      "editor.name": "Name",
      "editor.folder": "Folder",
      "editor.folderPlaceholder": "Optional",
      "editor.favorite": "Favorite",
      "editor.enabled": "Enabled",
      "editor.websites": "Websites",
      "editor.addWebsite": "Add website",
      "editor.websiteAria": "Website URL",
      "editor.passkeys": "Passkeys",
      "editor.save": "Save",
      "editor.cancel": "Cancel",
      "editor.newTitle": "New {type}",
      "editor.editTitle": "Edit {type}",

      // Match types
      "match.origin": "Origin",
      "match.domain": "Domain",
      "match.host": "Host",
      "match.exact": "Exact URL",
      "match.prefix": "Prefix",
      "match.regex": "Regex",
      "match.never": "Never",

      // Fields
      "field.username": "Username",
      "field.password": "Password",
      "field.totp": "TOTP secret",
      "field.secureNote": "Notes",
      "field.cardholderName": "Cardholder",
      "field.cardNumber": "Card number",
      "field.cardBrand": "Brand",
      "field.cardExpMonth": "Expiry month",
      "field.cardExpYear": "Expiry year",
      "field.cardSecurityCode": "Security code",
      "field.identityTitle": "Title",
      "field.firstName": "First name",
      "field.middleName": "Middle name",
      "field.lastName": "Last name",
      "field.company": "Company",
      "field.email": "Email",
      "field.phone": "Phone",
      "field.address1": "Address line 1",
      "field.address2": "Address line 2",
      "field.address3": "Address line 3",
      "field.city": "City",
      "field.state": "State / Province",
      "field.postalCode": "Postal code",
      "field.country": "Country / Region",
      "field.passportNumber": "Passport",
      "field.licenseNumber": "License",
      "field.nationalId": "National ID",

      // History sheet
      "history.title": "Password history",
      "history.subtitle": "Latest 20 previous passwords",
      "history.empty": "No previous passwords",
      "history.clear": "Clear history",
      "history.close": "Close",

      // Generator tab
      "gen.title": "Password generator",
      "gen.length": "Length",
      "gen.generate": "Regenerate",
      "gen.copy": "Copy",
      "gen.saveForSite": "Save for this site",
      "gen.strengthWeak": "Fair",
      "gen.strengthGood": "Strong",
      "gen.strengthMax": "Very strong",

      // Settings tab
      "settings.captureTitle": "Login save suggestions",
      "settings.captureDesc": "Prompt to save after form submit, sign-in clicks, or Enter. Sent only to local OpenKeylet; drafts expire in 5 minutes.",
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
      "settings.langAuto": "Auto",
      "settings.langEn": "EN",
      "settings.langZh": "简中",
      "settings.footerVault": "Local vault",
      "settings.privacy": "Privacy",

      // Passkey request window
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
      "status.locked": "已锁定",
      "header.themeToLight": "切换为浅色模式",
      "header.themeToDark": "切换为深色模式",
      "header.themeLabel": "浅色模式",
      "header.lock": "锁定",
      "header.lockTitle": "锁定密码库",

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
      "unlock.title": "解锁本地密码库",
      "unlock.desc": "输入 6 位 PIN 码以查看、填写和管理凭据。",
      "unlock.pinLabel": "6 位 PIN 码",
      "unlock.pinPlaceholder": "••••••",
      "unlock.submit": "解锁",
      "unlock.note": "仅在本机校验 · 5 分钟后自动锁定",

      "nav.site": "当前",
      "nav.vault": "密码库",
      "nav.gen": "生成",
      "nav.settings": "设置",

      "site.emptyCode": "非网站页面",
      "site.emptyTitle": "打开任意网站即可填充",
      "site.emptyDesc": "浏览器内部页面无法填写密码，无需重连。你仍可直接管理密码库或生成密码。",
      "site.openVault": "打开密码库",
      "site.noLogins": "当前网站暂无已保存账号",
      "site.loginCount": "{count} 个账号",
      "site.loginCountPlural": "{count} 个账号",
      "site.fillHint": "填写",
      "site.filled": "已填写账号密码",
      "site.totpCopied": "2FA 验证码已复制 ({seconds}s)",
      "site.totpTitle": "复制当前 2FA 验证码",
      "site.saveLogin": "保存登录",
      "site.scanQr": "扫 2FA",
      "site.smartSave": "存密钥",
      "site.quickAutofill": "卡片与身份快速填充",
      "site.fieldsFilled": "已填写 {count} 个字段",

      "capture.title": "检测到已提交登录",
      "capture.source": "来源：{origin}",
      "capture.note": "请核对账号与密码，确认后才会写入密码库；待保存信息 5 分钟后自动过期。",
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
      "save.saved": "已保存到本地密码库",

      "quick.title": "智能存密钥",
      "quick.label": "粘贴 API Key、cURL、SSH、.env 或 2FA 链接",
      "quick.placeholder": "sk-... / curl ... / otpauth://totp/...",
      "quick.name": "名称",
      "quick.attachLabel": "附加 2FA 到已有账号",
      "quick.attachBtn": "附加 2FA",
      "quick.attached": "已将 2FA 附加到 {name}",
      "quick.save": "保存为新项目",
      "quick.qrDetected": "已识别网页中的 2FA 二维码",
      "quick.emptyErr": "请先粘贴要保存的密钥或文本",
      "quick.parseErr": "无法解析当前内容",

      "vault.searchPlaceholder": "搜索密码库…",
      "vault.new": "新建",
      "vault.viewActive": "密码库",
      "vault.viewTrash": "回收站",
      "vault.allTypes": "全部",
      "vault.allFolders": "所有文件夹",
      "vault.favorites": "仅收藏",
      "vault.emptyActive": "没有匹配项目",
      "vault.emptyTrash": "回收站为空",
      "vault.disabled": "已停用",
      "vault.fill": "填写",
      "vault.edit": "编辑",
      "vault.history": "历史",
      "vault.trash": "回收站",
      "vault.restore": "恢复",
      "vault.purge": "永久删除",
      "vault.updated": "已更新本地密码库",
      "vault.confirmTrash": "移入回收站？项目将停止用于填写和登录。",
      "vault.confirmPurge": "永久删除此项目及其 Passkey？无法撤销；已有备份不受影响。",
      "vault.confirmClearHistory": "清除全部旧密码？当前密码保持不变。",
      "vault.confirm": "确认",
      "vault.cancel": "取消",
      "vault.copied": "已复制",

      "type.login": "登录",
      "type.passkey": "Passkey",
      "type.card": "卡片",
      "type.identity": "身份",
      "type.secureNote": "笔记",
      "type.ssh": "SSH",
      "type.api": "API",
      "type.custom": "其他",

      "editor.name": "名称",
      "editor.folder": "文件夹",
      "editor.folderPlaceholder": "选填",
      "editor.favorite": "收藏",
      "editor.enabled": "启用",
      "editor.websites": "关联网站",
      "editor.addWebsite": "添加网站",
      "editor.websiteAria": "网站地址",
      "editor.passkeys": "Passkey",
      "editor.save": "保存",
      "editor.cancel": "取消",
      "editor.newTitle": "新建{type}",
      "editor.editTitle": "编辑{type}",

      "match.origin": "同源",
      "match.domain": "主域名",
      "match.host": "主机",
      "match.exact": "完整网址",
      "match.prefix": "前缀",
      "match.regex": "正则",
      "match.never": "不匹配",

      "field.username": "账号",
      "field.password": "密码",
      "field.totp": "TOTP 密钥",
      "field.secureNote": "安全笔记 / 备注",
      "field.cardholderName": "持卡人",
      "field.cardNumber": "卡号",
      "field.cardBrand": "卡组织",
      "field.cardExpMonth": "到期月",
      "field.cardExpYear": "到期年",
      "field.cardSecurityCode": "安全码",
      "field.identityTitle": "称谓",
      "field.firstName": "名字",
      "field.middleName": "中间名",
      "field.lastName": "姓氏",
      "field.company": "公司",
      "field.email": "邮箱",
      "field.phone": "电话",
      "field.address1": "地址第一行",
      "field.address2": "地址第二行",
      "field.address3": "地址第三行",
      "field.city": "城市",
      "field.state": "省 / 州",
      "field.postalCode": "邮编",
      "field.country": "国家或地区",
      "field.passportNumber": "护照",
      "field.licenseNumber": "驾照",
      "field.nationalId": "身份证",

      "history.title": "密码历史",
      "history.subtitle": "保留最近 20 条旧密码",
      "history.empty": "暂无旧密码记录",
      "history.clear": "清除历史",
      "history.close": "关闭",

      "gen.title": "密码生成器",
      "gen.length": "长度",
      "gen.generate": "重新生成",
      "gen.copy": "复制",
      "gen.saveForSite": "保存到当前网站",
      "gen.strengthWeak": "一般",
      "gen.strengthGood": "强",
      "gen.strengthMax": "极强",

      "settings.captureTitle": "登录保存提示",
      "settings.captureDesc": "提交表单、点击登录或按 Enter 时提示保存，仅发往本机 OpenKeylet，草稿 5 分钟后过期。",
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
      "settings.footerVault": "本地加密密码库",
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

  // Strip legacy "中文 / English" dual strings coming from worker/bridge errors into clean single language.
  function localizeMessage(raw) {
    const text = String(raw?.message || raw || "").trim();
    if (!text) return "";
    const parts = text.split(" / ");
    if (parts.length === 2) {
      const hasCjkFirst = /[\u3400-\u9fff]/.test(parts[0]);
      const hasCjkSecond = /[\u3400-\u9fff]/.test(parts[1]);
      if (hasCjkFirst && !hasCjkSecond) {
        return resolvedLang === "zh" ? parts[0].trim() : parts[1].trim();
      }
    }
    return text;
  }

  function applyI18n(root = document) {
    document.documentElement.lang = resolvedLang === "zh" ? "zh-CN" : "en";
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

  const ICONS = {
    login: '<circle cx="8" cy="12" r="3.5"/><path d="M11.5 12H20M17 12v3M14.5 12v2"/>',
    passkey: '<circle cx="9" cy="8.5" r="3.2"/><path d="M3.5 18.5a5.5 5.5 0 0 1 9.8-3.4M15.5 13.5a2.5 2.5 0 1 1 3.8 2.1L16 19h3.5"/>',
    card: '<rect x="2.5" y="5" width="19" height="14" rx="2.5"/><path d="M2.5 10h19M6.5 15h4"/>',
    identity: '<circle cx="12" cy="8" r="3.5"/><path d="M4.5 19a7.5 7.5 0 0 1 15 0"/>',
    secureNote: '<path d="M6 3.5h8.5L19 8v12.5H6z"/><path d="M14.5 3.5V8H19M9 12h6M9 15.5h4.5"/>',
    ssh: '<rect x="3" y="4.5" width="18" height="15" rx="2.5"/><path d="m7.5 10 3 2.5-3 2.5M12.5 15h4"/>',
    api: '<path d="M9 6 4 12l5 6M15 6l5 6-5 6M13.5 5l-3 14"/>',
    custom: '<rect x="4" y="4" width="16" height="16" rx="3"/><path d="M9 12h6M12 9v6"/>',
    search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
    close: '<path d="m6 6 12 12m0-12L6 18"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    back: '<path d="M15 6 9 12l6 6"/>',
    copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15H4a1.5 1.5 0 0 1-1.5-1.5v-9A1.5 1.5 0 0 1 4 3h9A1.5 1.5 0 0 1 14.5 4.5v1"/>',
    check: '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
    eye: '<path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.5"/>',
    eyeOff: '<path d="M3 3l18 18M10.5 10.6a2.5 2.5 0 0 0 3 3M6.2 6.4C4.2 8 2.8 10.1 2.5 12c1.2 2.4 4.4 6 9.5 6 1.7 0 3.3-.4 4.6-1.1M9.5 6.3A9.6 9.6 0 0 1 12 6c5.1 0 8.3 3.6 9.5 6-.5 1-1.4 2.4-2.8 3.6"/>',
    fill: '<path d="M5 12h13M13 7l5 5-5 5"/>',
    qr: '<rect x="3.5" y="3.5" width="6" height="6" rx="1"/><rect x="14.5" y="3.5" width="6" height="6" rx="1"/><rect x="3.5" y="14.5" width="6" height="6" rx="1"/><path d="M14.5 14.5h2.5v2.5h-2.5zM18.5 14.5h2v2M14.5 18.5h2v2M18.5 18.5h2v2"/>',
    bolt: '<path d="M13 2.5 4.5 13h6.5l-1 8.5L19.5 11H13z"/>',
    lock: '<rect x="4.5" y="10.5" width="15" height="10" rx="2"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/>',
    trash: '<path d="M4.5 6.5h15M9.5 6.5V4.5h5v2M7 6.5l1 13h8l1-13"/>',
    restore: '<path d="M4.5 12a7.5 7.5 0 1 0 2.2-5.3L4.5 9M4.5 4.5V9H9"/>',
    history: '<circle cx="12" cy="12" r="8"/><path d="M12 8v4.5l3 1.5"/>',
    edit: '<path d="M4 20h4.5L19 9.5 14.5 5 4 15.5zM12.5 7l4.5 4.5"/>',
    globe: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.6 2.6 2.6 14.4 0 17M12 3.5c-2.6 2.6-2.6 14.4 0 17"/>',
    shield: '<path d="M12 3.5 5 6.5v5.5c0 4.5 3 7.5 7 8.8 4-1.3 7-4.3 7-8.8V6.5z"/>',
    refresh: '<path d="M19.5 12a7.5 7.5 0 1 1-2.2-5.3L19.5 9M19.5 4.5V9H15"/>',
    star: '<path d="m12 3.5 2.6 5.3 5.9.8-4.3 4.2 1 5.9-5.2-2.8-5.2 2.8 1-5.9-4.3-4.2 5.9-.8z"/>',
    external: '<path d="M14 4.5h5.5V10M19.5 4.5 10.5 13.5M10 6H5.5v12.5H18V14"/>',
    save: '<path d="M5 4.5h11.5L19.5 7.5V19.5H5z"/><path d="M8.5 4.5v5h7v-5M8.5 19.5v-6h7v6"/>',
  };

  function icon(name, className = "ico") {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    if (className) svg.setAttribute("class", className);
    svg.innerHTML = ICONS[name] || ICONS.custom;
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
