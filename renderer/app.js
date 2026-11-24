const { invoke } = window.__TAURI__.core;
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const HAN_TEXT = /[\u3400-\u9fff]/;

const isMacOS = navigator.platform.startsWith('Mac') || navigator.userAgent.includes('Macintosh');
document.documentElement.classList.toggle('platform-macos', isMacOS);
window.addEventListener('blur', () => document.documentElement.classList.add('window-blurred'));
window.addEventListener('focus', () => document.documentElement.classList.remove('window-blurred'));

{
  const isTitleControl = (target) => Boolean(target.closest?.('button, input, select, textarea, a, label, [role="button"], [data-tauri-drag-region="false"], #title-search'));
  const inDragRegion = (target) => Boolean(target.closest?.('[data-tauri-drag-region="deep"]'));
  document.addEventListener('mousedown', (event) => {
    if (event.button === 0 && inDragRegion(event.target) && !isTitleControl(event.target)) event.preventDefault();
  });
  document.addEventListener('selectstart', (event) => {
    if (inDragRegion(event.target) && !isTitleControl(event.target)) event.preventDefault();
  });
  document.addEventListener('dragstart', (event) => {
    if (inDragRegion(event.target) && !isTitleControl(event.target)) event.preventDefault();
  });
  const titleSearch = document.getElementById('title-search');
  titleSearch?.addEventListener('click', (event) => {
    if (event.target === titleSearch) document.getElementById('title-search-input')?.focus();
  });
}

// Keep the first paint deterministic. The persisted setting from the vault is
// applied by refresh(); browser storage can survive an app reinstall and must
// not override the English default while the native state is loading.
let languagePreference = 'auto';
let language = window.OpenKeyletI18n ? window.OpenKeyletI18n.detectSystemLanguage() : 'en';

function normalizeLanguageSetting(raw) {
  return window.OpenKeyletI18n ? window.OpenKeyletI18n.normalizeSetting(raw) : (raw === 'en' ? 'en' : 'zh');
}

function resolveLanguage(setting) {
  return window.OpenKeyletI18n ? window.OpenKeyletI18n.resolveLanguage(setting) : (setting === 'en' ? 'en' : 'zh');
}

function localized(zh, en) {
  return window.OpenKeyletI18n ? window.OpenKeyletI18n.translate(language, zh, en) : (language === 'en' ? en : zh);
}

const staticCopy = [
  ['.nav', 'aria-label', '主导航', 'Main navigation'],
  ['#connections-list', 'aria-label', '项目列表', 'Vault items'],
  ['.activity-panel', 'aria-label', '操作记录', 'Activity log'],
  ['.settings-layout', 'aria-label', '设置', 'Settings'],
  ['#title-search-input', 'placeholder', '搜索项目…', 'Search items…'],
  ['#desktop-shortcut-enabled', 'aria-label', '创建桌面快捷方式', 'Create desktop shortcut'],
  ['#launch-at-login-enabled', 'aria-label', '开机自启动', 'Launch at login'],
  ['#pin-enabled', 'aria-label', '启用 PIN 锁', 'Enable PIN lock'],
  ['#browser-enabled', 'aria-label', '启用 Browser Bridge', 'Enable Browser Bridge'],
  ['#browser-agent-passkey-enabled', 'aria-label', '允许 Agent 使用 Passkey', 'Allow Agent Passkey signing'],
  ['.window-control[data-window-action="minimize"]', 'aria-label', '最小化', 'Minimize'],
  ['.window-control[data-window-action="close"]', 'aria-label', '关闭', 'Close'],
  ['.nav-item[data-page="connections"] > span', 'text', '项目', 'ITEMS'],
  ['.nav-item[data-page="import"] > span', 'text', '导入', 'IMPORT'],
  ['.nav-item[data-page="activity"] > span', 'text', '记录', 'LOG'],
  ['.nav-item[data-page="settings"] > span', 'text', '设置', 'SYSTEM'],
  ['#title-search-input', 'aria-label', '搜索秘密项目', 'Search vault items'],
  ['#add-connection-button', 'text', '＋ 添加', '+ ADD'],
  ['#import-chip-manual', 'text', '＋ 手动新建项目', '+ Manual item'],
  ['#drafts-button', 'text', '草稿', 'DRAFT'],
  ['#generator-open', 'text', '生成器', 'GENERATE'],
  ['#trash-open', 'text', '回收站', 'TRASH'],
  ['#delete-draft-button', 'aria-label', '删除草稿', 'Delete draft'],
  ['#header-export-backup-button', 'text', '一键打包', 'EXPORT'],
  ['#header-import-backup-button', 'text', '一键导入包', 'IMPORT'],
  ['#clear-activity-button', 'text', '清空记录', 'CLEAR LOG'],
  ['[data-module="SYSTEM / 01"] .settings-heading h2', 'text', '系统入口', 'SYSTEM ACCESS'],
  ['[data-module="SYSTEM / 01"] .settings-heading p', 'text', '控制 OpenKeylet 的桌面快捷方式与开机启动。', 'Control the OpenKeylet desktop shortcut and launch at login.'],
  ['#desktop-shortcut-option strong', 'text', '创建快捷方式到桌面', 'CREATE DESKTOP SHORTCUT'],
  ['#desktop-shortcut-option small', 'text', '在当前用户桌面创建 OpenKeylet 快捷方式', 'Create a OpenKeylet shortcut on the current user’s desktop.'],
  ['#launch-at-login-option strong', 'text', '开机自启动', 'LAUNCH AT LOGIN'],
  ['#launch-at-login-option small', 'text', '登录系统后自动启动 OpenKeylet，并保持单实例', 'Start OpenKeylet after sign-in while preserving single-instance behavior.'],
  ['[data-module="MCP / 02"] .settings-heading h2', 'text', 'Agent 接入', 'AGENT SETUP'],
  ['[data-module="MCP / 02"] .settings-heading p', 'text', '注册本地 stdio MCP；支持的 Agent 同时安装“认证任务优先使用 OpenKeylet”规则。', 'Register the local stdio MCP and install the OpenKeylet-first authentication rule where supported.'],
  ['[data-module="APP / 03"] .settings-heading h2', 'text', '窗口与偏好', 'WINDOW & PREFERENCES'],
  ['[data-module="APP / 03"] .settings-heading p', 'text', '控制音效、关闭按钮与本地 PIN 锁。', 'Control sounds, close behavior and local PIN lock.'],
  ['#language-option strong', 'text', '界面语言', 'INTERFACE LANGUAGE'],
  ['#language-option small', 'text', '选择桌面端界面显示语言（默认跟随系统语言）。', 'Choose your preferred display language across the desktop app.'],
  ['#language-switch [data-language="auto"]', 'text', '自动', 'AUTO'],
  ['#sound-option strong', 'text', '界面音效', 'INTERFACE SOUNDS'],
  ['#sound-option small', 'text', '点击按钮与切换开关时播放轻提示音', 'Subtle click feedback for toggles and buttons.'],
  ['label[for="close-behavior"] strong', 'text', '关闭按钮', 'CLOSE BUTTON'],
  ['label[for="close-behavior"] small', 'text', '最小化可保留托盘菜单', 'Minimizing keeps tray controls available.'],
  ['#close-behavior option[value="tray"]', 'text', '最小化到托盘', 'MINIMIZE TO TRAY'],
  ['#close-behavior option[value="exit"]', 'text', '退出 OpenKeylet', 'QUIT OpenKeylet'],
  ['#edge-dock-option strong', 'text', '贴边自动收起抽屉', 'EDGE-DOCK DRAWER'],
  ['#edge-dock-option small', 'text', '将窗口拖至屏幕左、右或顶部边缘时自动收起，鼠标移至边缘自动拉出', 'Snap to the left, right, or top screen edge to auto-hide; hover the edge to slide back out.'],
  ['#edge-dock-enabled', 'aria-label', '贴边自动收起抽屉', 'Edge-dock drawer'],
  ['#auto-check-option strong', 'text', '定时自动检测', 'SCHEDULED HEALTH CHECK'],
  ['#auto-check-option small', 'text', '按设定间隔自动检测全部已启用的可测试项目（API / SSH），异常时亮黄灯提示', 'Automatically check all enabled testable items (API / SSH) and show an amber lamp on failures.'],
  ['#auto-check-enabled', 'aria-label', '定时自动检测', 'Scheduled health check'],
  ['#auto-check-interval-option strong', 'text', '检测时间间隔', 'CHECK INTERVAL'],
  ['#auto-check-interval-option small', 'text', '后台自动全量检测的时间间隔（默认每 1 小时一次）', 'How often OpenKeylet automatically checks testable connections in the background (default 1 hour).'],
  ['#auto-check-interval-minutes option[value="15"]', 'text', '15 分钟', '15 MINUTES'],
  ['#auto-check-interval-minutes option[value="30"]', 'text', '30 分钟', '30 MINUTES'],
  ['#auto-check-interval-minutes option[value="60"]', 'text', '1 小时（默认）', '1 HOUR (DEFAULT)'],
  ['#auto-check-interval-minutes option[value="180"]', 'text', '3 小时', '3 HOURS'],
  ['#auto-check-interval-minutes option[value="360"]', 'text', '6 小时', '6 HOURS'],
  ['#auto-check-interval-minutes option[value="720"]', 'text', '12 小时', '12 HOURS'],
  ['#auto-check-interval-minutes option[value="1440"]', 'text', '24 小时', '24 HOURS'],
  ['.pin-option strong', 'text', 'PIN 锁', 'PIN LOCK'],
  ['.pin-option small', 'text', '防他人在本机查看明文或管理条目；关闭将移除当前 PIN', 'Locks desktop viewing and management against others on this device. Turning off removes the PIN.'],
  ['#owner-auto-lock-option strong', 'text', '空闲自动锁定', 'AUTO-LOCK'],
  ['#owner-auto-lock-option small', 'text', '无操作超时后自动锁定桌面窗口（后台 MCP 保持可用）', 'Lock the desktop window after idle time (background MCP remains active).'],
  ['#owner-auto-lock-minutes option[value="0"]', 'text', '从不（仅手动）', 'NEVER (MANUAL)'],
  ['#owner-auto-lock-minutes option[value="5"]', 'text', '5 分钟', '5 MINUTES'],
  ['#owner-auto-lock-minutes option[value="15"]', 'text', '15 分钟', '15 MINUTES'],
  ['#owner-auto-lock-minutes option[value="30"]', 'text', '30 分钟', '30 MINUTES'],
  ['#owner-auto-lock-minutes option[value="60"]', 'text', '60 分钟', '60 MINUTES'],
  ['.agent-restart-notice span', 'text', '完成后重启 Agent。', 'Restart the agent after setup.'],
  ['#agent-client-list .agent-scan-placeholder', 'text', '正在扫描本机 Agent', 'SCANNING LOCAL AGENTS'],
  ['.manual-mcp-config summary', 'text', '其他 Agent / 手动配置', 'OTHER AGENT / MANUAL SETUP'],
  ['.manual-config-steps > div:nth-child(1) span', 'text', '打开目标 Agent 的 MCP 配置', 'Open the target agent MCP configuration'],
  ['.manual-config-steps > div:nth-child(2) span', 'text', '按配置格式复制 JSON 或 TOML', 'Copy JSON or TOML to match its config format'],
  ['.manual-config-steps > div:nth-child(3) span', 'text', '粘贴保存并重新启动 Agent', 'Paste, save, and restart the agent'],
  ['[data-module="WEB / 04"] .settings-heading h2', 'text', '浏览器接入', 'BROWSER BRIDGE'],
  ['[data-module="WEB / 04"] .settings-heading p', 'text', '通过已配对扩展让 Agent 直接检查网页、填写登录表单/密钥并完成 Passkey 登录。', 'Let agents inspect pages, fill credentials and forms, and complete Passkey sign-in via the paired extension.'],
  ['label[for="browser-port"]', 'text', '本地端口', 'LOCAL PORT'],
  ['#save-browser-settings-button', 'text', '保存', 'SAVE'],
  ['#browser-agent-passkey-option strong', 'text', '允许 Agent 使用 Passkey', 'AGENT PASSKEY SIGNING'],
  ['#browser-agent-passkey-option small', 'text', '允许本地 AI Agent 为已启用项目自动完成网页 WebAuthn Passkey 登录与注册', 'Allow local AI agents to complete WebAuthn Passkey sign-in and registration for enabled items.'],
  ['#browser-install-heading', 'text', '安装插件 · 只需三步', 'INSTALL IN THREE STEPS'],
  ['#browser-step-open-title', 'text', '打开 Chrome', 'Open Chrome'],
  ['#browser-step-open-description', 'text', '启动 Chrome 并自动开启 5 分钟配对窗口（支持多个 Chrome 账号同时连接）。', 'Launch Chrome and open a 5-minute auto-pairing window (supports multiple Chrome profiles at once).'],
  ['#chrome-profile-label', 'text', 'Chrome 账号 / 配置文件', 'CHROME PROFILE'],
  ['#browser-open-help', 'text', '地址已复制。请粘贴到 Chrome 地址栏并按回车，然后开启“开发者模式”。', "Address copied. Paste it into Chrome's address bar and press Enter, then turn on Developer mode."],
  ['#browser-step-copy-title', 'text', '进入扩展设置页', 'Open the extensions page'],
  ['#browser-step-copy-description', 'text', '复制下方地址并粘贴到 Chrome 地址栏按回车，然后开启右上角的“开发者模式”。', "Copy the address below, paste it into Chrome's address bar and press Enter, then turn on Developer mode."],
  ['#browser-extensions-url', 'aria-label', '扩展设置页地址', 'Extensions page address'],
  ['#copy-extensions-url-button', 'text', '复制', 'COPY'],
  ['#browser-step-drag-title', 'text', '拖入插件', 'Drag in the extension'],
  ['#browser-step-drag-description', 'text', '按住下方标识，拖到扩展页的空白区域，松开即可安装。', 'Hold the icon below, drag it onto an empty area of the extensions page, and release to install.'],
  ['#browser-install-complete', 'text', '拖入后会自动连接，请保持 OpenKeylet 运行；如需绑定多个 Chrome 账号，切换账号重复上述步骤即可。', 'Connects automatically after installation. To add another Chrome profile, switch profiles and repeat.'],
  ['#browser-fallback-title', 'text', '拖拽无法安装？', "Can't install by dragging?"],
  ['#browser-fallback-description', 'text', '打开下方扩展目录，然后在扩展页点击“加载已解压的扩展程序”，选择该目录。', 'Open the extension folder below. On the extensions page, click Load unpacked and select that folder.'],
  ['#drag-extension-label', 'text', '按住此处，拖入扩展页', 'Hold and drag to the extensions page'],
  ['#drag-extension-button', 'aria-label', '拖动插件到 Chrome 扩展页；也可按回车打开扩展目录', 'Drag the extension to Chrome Extensions, or press Enter to open its folder'],
  ['#quick-pairing-button', 'text', '打开 Chrome 并复制地址', 'OPEN CHROME & COPY ADDRESS'],
  ['#open-extension-button', 'text', '扩展目录', 'EXTENSION FOLDER'],
  ['#start-pairing-button', 'text', '开启配对', 'START PAIRING'],
  ['#test-browser-bridge-button', 'text', '测试连接', 'TEST BRIDGE'],
  ['#reload-extension-button', 'text', '重载插件', 'RELOAD EXTENSION'],
  ['#reset-pairing-button', 'text', '重置', 'RESET'],
  ['[data-module="SAFE / 06"] .settings-heading h2', 'text', '本地数据与离线包', 'LOCAL DATA & ARCHIVES'],
  ['#safe-export-backup-button', 'text', '导出 .mvault 包', 'EXPORT .MVAULT'],
  ['#safe-import-backup-button', 'text', '恢复 .mvault 包', 'RESTORE .MVAULT'],
  ['#migration-open', 'text', '迁入 Bitwarden / CSV', 'IMPORT BITWARDEN / CSV'],
  ['#smart-paste-button', 'aria-label', '智能粘贴存入（API / cURL / SSH / .env / URI / 2FA）', 'Smart paste from clipboard (API, cURL, SSH, .env, URI, 2FA)'],
  ['#smart-paste-button', 'title', '智能粘贴存入（API / cURL / SSH / .env / URI / 2FA）', 'Smart paste from clipboard (API, cURL, SSH, .env, URI, 2FA)'],
  ['#editor-smart-paste-title', 'text', '从剪贴板智能识别粘贴', 'Smart paste from clipboard'],
  ['#editor-smart-paste-help', 'text', '纯本地自动识别 API 密钥、cURL、SSH、.env、数据库连接串与 2FA', 'Auto-detect API keys, cURL, SSH, .env, DB URIs & 2FA (local only)'],
  ['#smart-totp-attach-label', 'text', '或直接附加 2FA 到已有项目', 'Or attach 2FA directly to an existing item'],
  ['#smart-totp-attach-button', 'text', '附加 2FA', 'ATTACH 2FA'],
  ['#migration-scan-ssh', 'text', '一键扫描 ~/.ssh/config', 'SCAN LOCAL ~/.ssh/config'],
  ['[data-module="SAFE / 06"] .settings-heading p', 'text', '用自定义密码导出 .mvault 离线包，先预览再恢复新旧版备份（v3–v8），或从 Bitwarden / Chrome 迁入。', 'Export password-protected .mvault archives, preview before restoring current or legacy backups (v3–v8), or migrate from Bitwarden / Chrome.'],
  ['#open-data-button', 'text', '打开数据目录', 'OPEN DATA FOLDER'],
  ['#owner-lock-description', 'text', 'PIN 保护明文查看、浏览器密码库访问和 Passkey 验证；模块值默认对 Agent 隐藏。', 'The PIN protects plaintext viewing, browser vault access and passkey verification. Module values are hidden from agents by default.'],
  ['#owner-pin', 'label', '六位数字 PIN', 'SIX-DIGIT PIN'],
  ['#owner-pin-confirm', 'label', '再次输入 PIN', 'CONFIRM PIN'],
  ['.lock-note span', 'text', 'PIN 用于防止他人在本机查看明文或修改密码库；请配合系统锁屏与加密备份保护离线安全。', 'PIN locks desktop viewing and editing against others on this computer; pair with OS screen lock and encrypted backups for offline security.'],
  ['#owner-pin-cancel', 'text', '取消', 'CANCEL'],
  ['[data-close-modal].icon-button', 'aria-label', '关闭编辑器', 'Close editor'],
  ['#connection-name', 'label', '名称', 'NAME'],
  ['#connection-type', 'label', '类型', 'TYPE'],
  ['#connection-folder', 'label', '文件夹', 'FOLDER'],
  ['#connection-description', 'label-html', '公开用途 <em>可选</em>', 'PUBLIC PURPOSE <em>OPTIONAL</em>'],
  ['.template-copy strong', 'text', '从一个组合开始', 'START WITH A PRESET'],
  ['.template-copy small', 'text', '模板只添加模块，不会限制之后的修改。', 'Templates only add modules; you can change anything afterward.'],
  ['.module-editor-heading > div > strong', 'text', '项目模块', 'ITEM MODULES'],
  ['.module-editor-heading > div > small', 'text', '拖动卡片排序 · 开关控制 Agent 可见性', 'DRAG CARDS TO REORDER · SWITCH CONTROLS AGENT VISIBILITY'],
  ['#add-module-button', 'text', '＋ 添加模块', '+ ADD MODULE'],
  ['#module-menu [data-add-module="username"]', 'text', '账号', 'USERNAME'],
  ['#module-menu [data-add-module="password"]', 'text', '密码', 'PASSWORD'],
  ['#module-menu [data-add-module="apiCredential"]', 'text', 'API 凭据', 'API CREDENTIAL'],
  ['#module-menu [data-add-module="privateKey"]', 'text', '私钥', 'PRIVATE KEY'],
  ['#module-menu [data-add-module="passphrase"]', 'text', '私钥口令', 'KEY PASSPHRASE'],
  ['#module-menu [data-add-module="totp"]', 'text', 'TOTP', 'TOTP'],
  ['#module-menu [data-add-module="customSecret"]', 'text', '自定义字段', 'CUSTOM FIELD'],
  ['#module-menu [data-add-module="host"]', 'text', '主机 / IP', 'HOST / IP'],
  ['#module-menu [data-add-module="port"]', 'text', '端口', 'PORT'],
  ['#module-menu [data-add-module="url"]', 'text', '服务 URL', 'SERVICE URL'],
  ['[data-item-template="login"] > span', 'html', '登录<small>账号 + 密码</small>', 'LOGIN<small>USERNAME + PASSWORD</small>'],
  ['[data-item-template="card"] > span', 'html', '信用卡<small>卡号 + 有效期 + 安全码</small>', 'CARD<small>NUMBER + EXPIRY + CODE</small>'],
  ['[data-item-template="identity"] > span', 'html', '身份资料<small>姓名 + 联系方式 + 地址</small>', 'IDENTITY<small>NAME + CONTACT + ADDRESS</small>'],
  ['[data-item-template="secureNote"] > span', 'html', '安全笔记<small>加密保存长文本</small>', 'SECURE NOTE<small>ENCRYPTED TEXT</small>'],
  ['[data-item-template="ssh"] > span', 'html', 'SSH<small>主机 + 端口 + 账号 + 密码</small>', 'SSH<small>HOST + PORT + USER + PASSWORD</small>'],
  ['[data-item-template="api"] > span', 'html', 'API<small>API 凭据</small>', 'API<small>API CREDENTIAL</small>'],
  ['[data-item-template="blank"] > span', 'html', '空白<small>从零添加模块</small>', 'BLANK<small>START WITH NO MODULES</small>'],
  ['#connection-enabled-label', 'text', '启用此项目', 'ENABLE ITEM'],
  ['#connection-enabled-help', 'text', '禁用后 Agent 无法使用', 'Agents cannot use a disabled item.'],
  ['.secret-hint', 'text', '当前项目的明文只在已解锁 GUI 中显示', 'Plaintext is visible only in the unlocked GUI.'],
  ['#connection-form .modal-footer [data-close-modal]', 'text', '关闭', 'CLOSE'],
  ['#save-connection-button', 'text', '保存', 'SAVE'],
  ['.login-websites summary', 'text', '网站匹配', 'WEBSITE MATCHING'],
  ['.login-websites > p', 'text', '设置多个网站及匹配规则', 'Configure websites and matching rules.'],
  ['#login-uri-add', 'text', '＋ 添加网站', '+ ADD WEBSITE'],
  ['#agent-notes-summary-title', 'text', 'Agent 笔记', 'AGENT NOTES'],
  ['#agent-notes-lock-badge', 'text', '已锁定', 'LOCKED'],
  ['#agent-notes-lock-label', 'text', '锁定笔记（禁止 Agent 修改）', 'Lock notes (block agent edits)'],
  ['#agent-notes-clear', 'text', '清空', 'CLEAR'],
  ['#agent-note-input', 'placeholder', '添加简短用途备注（如：生产 GPU 服务器、/srv/web）…', 'Add a short note (e.g. prod GPU server, /srv/web)…'],
  ['#agent-note-input', 'aria-label', '添加 Agent 笔记', 'Add agent note'],
  ['#agent-note-add', 'text', '添加', 'ADD'],
];

function applyLanguage() {
  language = resolveLanguage(languagePreference);
  document.documentElement.lang = window.OpenKeyletI18n ? window.OpenKeyletI18n.htmlLangFor(language) : (language === 'en' ? 'en' : 'zh-CN');
  window.OpenKeyletAppearance.setLanguage(localized);
  invoke?.('sync_appearance_theme', { resolvedLanguage: language }).catch?.(() => {});
  const langButtons = $$('.language-switch button');
  let activeIndex = 0;
  langButtons.forEach((button, index) => {
    const isActive = button.dataset.language === languagePreference;
    button.classList.toggle('active', isActive);
    if (isActive) activeIndex = index;
  });
  const langSwitch = $('#language-switch');
  if (langSwitch) {
    langSwitch.style.setProperty('--language-count', String(Math.max(1, langButtons.length)));
    langSwitch.style.setProperty('--language-index', String(activeIndex));
  }
  for (const [selector, target, zh, en] of staticCopy) {
    const element = $(selector);
    if (!element) continue;
    const copy = localized(zh, en);
    if (target === 'text') element.textContent = copy;
    else if (target === 'html') element.innerHTML = copy;
    else if (target === 'aria-label' || target === 'placeholder' || target === 'title') element.setAttribute(target, copy);
    else if (target === 'label' || target === 'label-html') {
      const label = element.closest('label')?.querySelector(':scope > span') || element.closest('.field')?.querySelector(':scope > span');
      if (label) target === 'label-html' ? label.innerHTML = copy : label.textContent = copy;
    }
  }
  if (isMacOS) {
    $('[data-module="SYSTEM / 01"] .settings-heading p').textContent = localized(
      '控制 OpenKeylet 的登录时启动。',
      'Control whether OpenKeylet launches at login.',
    );
  }
  if (languagePreference === 'auto' && $('#language-option small')) {
    const systemName = window.OpenKeyletI18n ? window.OpenKeyletI18n.languageDisplayName(language) : language;
    $('#language-option small').textContent = localized(`跟随系统语言（${systemName}）`, `Following system (${systemName})`);
  }
  syncItemTypeFilter();
  syncActivityFilterControl();
  syncSettingsFilterControl();
  syncTitleSearch();
  if (state) syncCheckAllButton();
  window.OpenKeyletImportHub?.render?.();
  if (mvaultState && !$('#mvault-import-modal')?.classList.contains('hidden')) {
    if (mvaultState.preview) renderMvaultSelectPanel();
    else if (mvaultState.requiresPassword) renderMvaultUnlockPanel($('#mvault-unlock-error')?.textContent || '');
  }
  if (editorExistingItem && !$('#connection-modal')?.classList.contains('hidden')) {
    renderAgentNotes(editorExistingItem, { autoOpen: false });
  }
}

function publicMessage(value, fallback = localized('操作失败', 'Operation failed')) {
  const raw = String(value || '').replace(/^Error:\s*/, '');
  if (language === 'zh' || !HAN_TEXT.test(raw)) return raw || fallback;
  return fallback;
}

let settingsWriteQueue = Promise.resolve();

function updateSettings(patch) {
  const operation = settingsWriteQueue.then(() => invoke('update_settings', { patch }));
  settingsWriteQueue = operation.catch(() => {});
  return operation;
}

const api = {
  state: () => invoke('get_state'),
  ownerStatus: () => invoke('owner_status'),
  ownerTouch: () => invoke('owner_touch'),
  ownerSetPin: (pin) => invoke('owner_set_pin', { pin }),
  ownerDisablePin: () => invoke('owner_disable_pin'),
  ownerUnlock: (pin) => invoke('owner_unlock', { pin }),
  ownerLock: () => invoke('owner_lock'),
  ownerSecrets: (id) => invoke('owner_secret_view', { id }),
  drafts: () => invoke('owner_editor_drafts'),
  saveDraft: (draftId, input) => invoke('save_editor_draft', { draftId, input }),
  deleteDraft: (id) => invoke('delete_editor_draft', { id }),
  copyOwnerValue: (value, sensitive = true) => invoke('copy_owner_value', { value, sensitive }),
  save: (input) => invoke('save_connection', { input, expectedUpdatedAt: editorExistingItem?.updatedAt || null }),
  setEnabled: (id, enabled) => invoke('set_connection_enabled', { id, enabled }),
  reorder: (ids, expectedOrder) => invoke('reorder_connections', { ids, expectedOrder }),
  remove: (id, expectedUpdatedAt) => invoke('delete_connection', { id, expectedUpdatedAt }),
  trash: () => invoke('owner_trash'),
  restore: (id, deletedAt) => invoke('owner_restore_item', { id, deletedAt }),
  purge: (id, deletedAt) => invoke('owner_purge_item', { id, deletedAt }),
  history: (id) => invoke('owner_password_history', { id }),
  clearHistory: (id, expectedUpdatedAt) => invoke('owner_clear_password_history', { id, expectedUpdatedAt }),
  addAgentNote: (id, text) => invoke('owner_add_agent_note', { id, text }),
  updateAgentNote: (id, noteId, text) => invoke('owner_update_agent_note', { id, noteId, text }),
  deleteAgentNote: (id, noteId) => invoke('owner_delete_agent_note', { id, noteId }),
  clearAgentNotes: (id) => invoke('owner_clear_agent_notes', { id }),
  setAgentNotesLocked: (id, locked) => invoke('owner_set_agent_notes_locked', { id, locked }),
  test: (id) => invoke('test_connection', { id }),
  settings: updateSettings,
  systemIntegration: () => invoke('system_integration_status'),
  setDesktopShortcut: (enabled) => invoke('set_desktop_shortcut', { enabled }),
  setLaunchAtLogin: (enabled) => invoke('set_launch_at_login', { enabled }),
  deleteActivity: (id) => invoke('delete_activity', { id }),
  deleteActivities: (ids) => invoke('delete_activities', { ids }),
  clear: () => invoke('clear_activities'),
  copyConfig: (format) => invoke('copy_mcp_config', { format }),
  agents: () => invoke('agent_mcp_status'),
  registerAgents: (clientIds) => invoke('agent_mcp_register', { clientIds }),
  repairAgent: (clientId) => invoke('agent_mcp_repair', { clientId }),
  removeAgent: (clientId) => invoke('agent_mcp_remove', { clientId }),
  chooseKey: () => invoke('choose_private_key'),
  chromeProfiles: () => invoke('list_chrome_profiles'),
  quickPair: (port) => invoke('quick_pair_browser', { port }),
  openChrome: (profileDirectory = null) => invoke('open_chrome_browser', profileDirectory ? { profileDirectory } : {}),
  testBrowserBridge: () => invoke('test_browser_bridge'),
  reloadBrowserExtension: () => invoke('reload_browser_extension'),
  resetPair: () => invoke('reset_browser_pairing'),
  extensionFolder: () => invoke('open_browser_extension_folder'),
  exportBackup: (password) => invoke('export_backup', { password }),
  importBackup: (password) => invoke('import_backup', { password }),
  pickBackupImportFile: () => invoke('pick_backup_import_file'),
  inspectDroppedBackupBytes: (fileName, content) => invoke('inspect_dropped_backup_bytes', { fileName, content }),
  prepareBackupImport: (password) => invoke('prepare_backup_import', { password }),
  commitBackupImport: (id, selectedItemIndices = null, selectedTrashIndices = null) => invoke('commit_backup_import', {
    id,
    ...(Array.isArray(selectedItemIndices) ? { selectedItemIndices } : {}),
    ...(Array.isArray(selectedTrashIndices) ? { selectedTrashIndices } : {}),
  }),
  cancelBackupImport: () => invoke('cancel_backup_import'),
  prepareImport: (format) => invoke('prepare_import', { format }),
  prepareSshConfigImport: (useDefault) => invoke('prepare_ssh_config_import', { useDefault }),
  smartParseText: (text, filename = null, url = null) => invoke('smart_parse_text', { text, filename, url }),
  readOwnerClipboard: () => invoke('read_owner_clipboard'),
  clearClipboardIfMatches: (text) => invoke('clear_clipboard_if_matches', { text }),
  attachTotpToItem: (id, totp, expectedUpdatedAt) => invoke('attach_totp_to_item', { id, totp, expectedUpdatedAt }),
  commitImport: (id) => invoke('commit_import', { id }),
  cancelImport: () => invoke('cancel_import'),
  dataFolder: () => invoke('open_data_folder'),
  window: (action) => invoke('window_action', { action }),
};

let state;
let systemIntegrationState = { desktopShortcut: false, launchAtLogin: false };
let activePage = 'connections';
let currentActivityFilter = 'all';
const pageSearch = { connections: '', import: '', activity: '', settings: '' };
const itemTypeFilterOrder = ['all', 'ssh', 'login', 'api', 'passkey', 'card', 'identity', 'secureNote', 'custom'];
let currentItemTypeFilter = 'all';
let vaultViewMode = (() => {
  try { return localStorage.getItem('openkeylet.vaultView') === 'grid' ? 'grid' : 'list'; } catch (_) { return 'list'; }
})();
const settingsFilterOrder = ['all', 'SYSTEM', 'MCP', 'APP', 'WEB', 'CLOUD', 'SAFE', 'UPDATE'];
let currentSettingsFilter = 'all';
let titleSearchOpen = false;
let creationMode = 'add';
let currentModules = [];
let editorDrafts = [];
let currentDraftId = '';
let removedSecretFields = new Set();
let editorExistingItem = null;
let editorSourceInput = null;
let editorOpenedFromDraft = false;
let editorInitialSnapshot = '';
let editorReturnFocus = null;
let editorItemId = null;
let editorOpening = false;
let editorClosing = null;
let editorSmartClipboardSource = '';
let editorSmartTotpUri = '';
let editorCandidateOnSaved = null;
let pendingTotpQrModuleIndex = -1;
let switchPointerDrag = null;
let switchSelectionPending = false;
let suppressSwitchClick = null;
let itemPointerDrag = null;
let itemOrderSaving = false;
let suppressItemClick = false;
let agentClients = [];
let chromeProfiles = [];
let agentRestartRequired = false;
let renderedConnectionsSignature = '';
const ACTIVITY_PAGE_SIZE = 50;
let activityVisibleCount = ACTIVITY_PAGE_SIZE;
let activityMatchCount = 0;
let activityLoadPending = false;
const expandedActivityErrors = new Set();
let ownerLockState = { pinConfigured: false, unlocked: false, expiresInSeconds: 0 };
let ownerPinSetupRequested = false;
let confirmationResolver = null;
let confirmationPreviousFocus = null;
let confirmationInertElements = [];
const githubBackup = window.OpenKeyletGithubBackup.create({
  invoke, localized, toast,
  isUnlocked: () => ownerLockState.unlocked,
  confirmAction: confirmDestructiveAction,
  onRestore: async () => {
    await refreshOwnerLock(false);
    await refresh(false);
  },
});
const appUpdater = window.OpenKeyletUpdater.create({
  invoke, localized, toast,
  isUnlocked: () => ownerLockState.unlocked,
  onSettingsUpdated: (settings) => {
    if (state && settings) state.settings = settings;
  },
});

function escapeHtml(value = '') {
  return String(value).replace(/[&<>"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[character]);
}

function cleanError(error) {
  return publicMessage(error?.message || error, localized('未知错误', 'Unknown error'));
}

function normalizeSearch(value = '') {
  return String(value).trim().toLocaleLowerCase('zh-CN');
}

function toast(message, type = '') {
  if (type === 'error') window.OpenKeyletAppearance?.play?.('danger');
  const item = document.createElement('div');
  item.className = `toast ${type}`;
  item.textContent = message;
  $('#toast-region').append(item);
  setTimeout(() => item.remove(), 3200);
}

function finishConfirmation(accepted, restoreFocus = true) {
  if (!confirmationResolver) return;
  const resolve = confirmationResolver;
  confirmationResolver = null;
  $('#confirmation-modal').classList.add('hidden');
  confirmationInertElements.forEach((element) => { element.inert = false; });
  confirmationInertElements = [];
  if (restoreFocus) {
    let previousFocus = confirmationPreviousFocus;
    if (!previousFocus?.isConnected && previousFocus?.dataset.action && previousFocus?.dataset.id) {
      previousFocus = $$('[data-action][data-id]').find((button) => button.dataset.action === confirmationPreviousFocus.dataset.action && button.dataset.id === confirmationPreviousFocus.dataset.id);
    }
    if (previousFocus?.isConnected && !previousFocus.closest('.hidden')) previousFocus.focus();
    else if ($('#connection-modal').classList.contains('hidden')) (activePage === 'import' ? $('#add-connection-button') : $('#vault-view-toggle'))?.focus();
  }
  confirmationPreviousFocus = null;
  resolve(accepted);
}

function confirmDestructiveAction({ title, message, acceptLabel = localized('删除', 'DELETE'), tag = localized('确认删除', 'CONFIRM DELETION') }) {
  if (confirmationResolver) return Promise.resolve(false);
  finishModulePointerDrag(false);
  $('#confirmation-tag').textContent = tag;
  $('#confirmation-title').textContent = title;
  $('#confirmation-message').textContent = message;
  $('#confirmation-cancel').textContent = localized('取消', 'CANCEL');
  $('#confirmation-accept').textContent = acceptLabel;
  confirmationPreviousFocus = document.activeElement;
  confirmationInertElements = [...document.body.children].filter((element) => element !== $('#confirmation-modal') && !element.inert && !['SCRIPT', 'STYLE'].includes(element.tagName));
  confirmationInertElements.forEach((element) => { element.inert = true; });
  $('#confirmation-modal').classList.remove('hidden');
  requestAnimationFrame(() => { if (confirmationResolver) $('#confirmation-cancel').focus(); });
  return new Promise((resolve) => { confirmationResolver = resolve; });
}

function clearOwnerPlaintext() {
  void finishSwitchDrag(false);
  finishItemPointerDrag(false);
  clearAutoCheckTimer();
  checkAllRunId += 1;
  checkAllRunning = false;
  lastCheckAllOutcome = '';
  itemCheckStates.clear();
  syncCheckAllButton();
  githubBackup.clearSecrets();
  appUpdater.closeModal();
  finishConfirmation(false, false);
  closeEditor();
  currentModules.forEach((module) => { module.secretValue = ''; });
  $$('[data-secret-value]').forEach((input) => { input.value = ''; });
}

function pinInputs(id) {
  return $$(`[data-pin-group="${id}"] .pin-cell-input`);
}

function readPin(id) {
  return pinInputs(id).map((input) => input.value).join('');
}

function clearPin(id) {
  pinInputs(id).forEach((input) => { input.value = ''; });
}

function focusPin(id) {
  const inputs = pinInputs(id);
  (inputs.find((input) => !input.value) || inputs[inputs.length - 1])?.focus();
}

function renderOwnerLock() {
  const strongMode = Boolean(ownerLockState.strongMode || ownerLockState.mode === 'strong');
  const configured = Boolean(ownerLockState.pinConfigured || strongMode);
  const unlocked = Boolean(ownerLockState.unlocked);
  const setupRequested = ownerPinSetupRequested && !configured && !strongMode;
  const locked = configured && !unlocked;
  const layerVisible = setupRequested || locked;
  $('#owner-lock-layer').classList.toggle('hidden', !layerVisible);
  $('#owner-lock-button').classList.toggle('hidden', !configured || !unlocked);

  $('#owner-pin-field')?.classList.toggle('hidden', strongMode);
  $('#owner-pin-confirm-field').classList.toggle('hidden', configured || strongMode);
  $('#owner-strong-field')?.classList.toggle('hidden', !strongMode);
  $('#owner-pin-cancel').classList.toggle('hidden', !setupRequested);

  pinInputs('owner-pin').forEach((input) => { input.required = !strongMode; });
  pinInputs('owner-pin-confirm').forEach((input) => { input.required = !configured && !strongMode; });
  const strongInput = $('#owner-strong-secret');
  if (strongInput) {
    strongInput.required = strongMode;
    strongInput.value = '';
    strongInput.type = 'password';
    strongInput.placeholder = localized('输入强主密码或 okv1_ 恢复密钥', 'Enter master passphrase or okv1_ recovery key');
  }
  if ($('#owner-strong-reveal')) $('#owner-strong-reveal').textContent = localized('显示', 'SHOW');
  if ($('#owner-strong-label')) {
    $('#owner-strong-label').textContent = localized('强主密码或 okv1_ 恢复密钥', 'MASTER PASSPHRASE OR okv1_ RECOVERY KEY');
  }

  if (strongMode) {
    if ($('#owner-lock-badge')) $('#owner-lock-badge').textContent = 'STRONG CLOUD VAULT';
    if ($('#owner-lock-sub')) $('#owner-lock-sub').textContent = localized('本地零落盘密钥 · MCP 已暂停', 'ZERO KEY ON DISK · MCP PAUSED');
    $('#owner-lock-mode').textContent = 'STRONG VAULT UNLOCK';
    $('#owner-lock-title').textContent = localized('解锁强加密密码库', 'UNLOCK STRONG VAULT');
    $('#owner-lock-description').textContent = localized(
      '高安全强加密模式已开启：本机硬盘不保存 master.key，请输入强主密码（或 okv1_ 恢复密钥）在内存中解锁。',
      'Strong Cloud Vault active: no master key exists on disk. Enter your master passphrase (or okv1_ recovery key) to unlock in RAM.',
    );
    if ($('#owner-lock-note')) {
      $('#owner-lock-note').textContent = localized(
        '解锁密钥仅驻留内存，点击锁定、空闲超时或退出后立即清零，AI Agent 的 MCP 也会同步暂停。',
        'Decryption key lives only in RAM and wipes immediately on lock, idle timeout, or quit (MCP pauses until unlocked).',
      );
    }
    $('#owner-lock-code').textContent = 'SEALED';
    $('#owner-unlock-action').textContent = localized('解锁密码库', 'UNLOCK VAULT');
  } else {
    if ($('#owner-lock-badge')) $('#owner-lock-badge').textContent = 'OWNER ACCESS';
    if ($('#owner-lock-sub')) $('#owner-lock-sub').textContent = 'LOCAL GUI / MCP REMAINS READY';
    $('#owner-lock-mode').textContent = configured ? 'OWNER VERIFY' : 'SET LOCAL PIN';
    $('#owner-lock-title').textContent = configured
      ? localized('输入六位 PIN', 'ENTER SIX-DIGIT PIN')
      : localized('设置六位 PIN', 'SET SIX-DIGIT PIN');
    $('#owner-lock-description').textContent = localized(
      'PIN 保护明文查看、浏览器密码库访问和 Passkey 验证；模块值默认对 Agent 隐藏。',
      'The PIN protects plaintext viewing, browser vault access and passkey verification. Module values are hidden from agents by default.',
    );
    if ($('#owner-lock-note')) {
      $('#owner-lock-note').textContent = localized(
        'PIN 用于防止他人在本机查看明文或修改密码库；请配合系统锁屏与加密备份保护离线安全。',
        'PIN locks desktop viewing and editing against others on this computer; pair with OS screen lock and encrypted backups for offline security.',
      );
    }
    $('#owner-lock-code').textContent = configured ? 'LOCK' : 'INIT';
    $('#owner-unlock-action').textContent = configured ? 'UNLOCK' : 'SET PIN';
  }
  if (locked) {
    if (!$('#vault-management-modal').classList.contains('hidden')) closeVaultManagement();
    if (!$('#migration-modal').classList.contains('hidden')) closeMigration();
    if (!$('#mvault-import-modal')?.classList.contains('hidden')) closeMvaultImportModal();
    setGlobalMvaultDropOverlay(false);
    closeGenerator();
    finishBackupPassword(null);
    clearOwnerPlaintext();
    window.OpenKeyletImportHub?.clearPlaintext?.();
    editorDrafts = [];
    renderDrafts();
  }
  clearPin('owner-pin');
  clearPin('owner-pin-confirm');
  if (layerVisible) setTimeout(() => (strongMode ? strongInput?.focus() : focusPin('owner-pin')), 0);
}

async function refreshOwnerLock(showError = true) {
  const wasUnlocked = Boolean(ownerLockState.unlocked);
  try {
    ownerLockState = await api.ownerStatus();
    renderOwnerLock();
    if (wasUnlocked && ownerLockState.pinConfigured && !ownerLockState.unlocked) {
      await refresh(false);
    }
  } catch (error) {
    if (showError) toast(cleanError(error), 'error');
  }
}

async function lockOwner() {
  window.OpenKeyletAppearance?.play?.('lock');
  try { ownerLockState = await api.ownerLock(); } catch (_) { ownerLockState.unlocked = false; }
  renderOwnerLock();
  await refresh(false);
}

async function refresh(showError = true) {
  try {
    state = await api.state();
    try {
      systemIntegrationState = await api.systemIntegration();
    } catch (_) {
      systemIntegrationState = { desktopShortcut: false, launchAtLogin: false };
    }
    languagePreference = normalizeLanguageSetting(state.settings.language);
    language = resolveLanguage(languagePreference);
    await githubBackup.refresh();
    await appUpdater.refresh();
    applyLanguage();
    render();
  } catch (error) {
    if (showError) toast(cleanError(error), 'error');
  }
}

function render() {
  renderMetrics();
  renderConnections();
  renderDrafts();
  renderActivity();
  renderSettings();
  window.OpenKeyletImportHub?.render?.();
}

const segmentNames = ['a', 'b', 'c', 'd', 'e', 'f', 'g'];
const segmentGlyphs = {
  0: 'abcdef', 1: 'bc', 2: 'abdeg', 3: 'abcdg', 4: 'bcfg',
  5: 'acdfg', 6: 'acdefg', 7: 'abc', 8: 'abcdefg', 9: 'abcdfg',
  s: 'acdfg', e: 'adefg', t: 'defg', r: 'eg', d: 'bcdeg', y: 'bcdfg', '-': 'g',
};

function sevenSegmentGlyph(character) {
  const lit = segmentGlyphs[String(character).toLowerCase()] || '';
  const segments = segmentNames.map((segment) => `<i class="segment segment-${segment}" data-lit="${lit.includes(segment)}"></i>`).join('');
  // Reuse the exact lamp contours; only the separate emission layer is blurred.
  return `<span class="seven-digit" aria-hidden="true">${segments}<span class="seven-emission" aria-hidden="true">${segments}</span></span>`;
}

function sevenSegmentNumber(value, length = 4) {
  const exact = Math.max(0, Math.trunc(Number(value) || 0));
  const maximum = (10 ** length) - 1;
  const overflow = exact > maximum;
  const shown = String(Math.min(exact, maximum));
  return `<span class="seven-number ${overflow ? 'overflow' : ''}" role="img" aria-label="${exact}"><span class="metric-val" aria-hidden="true">${shown}</span>${overflow ? '<b class="seven-overflow" aria-hidden="true">+</b>' : ''}</span>`;
}

function activityCode(action = '') {
  const value = String(action).toUpperCase();
  if (/BROWSER|浏览器|\bWEB\b/.test(value)) return 'WEB';
  if (/TERMINAL|终端|PTY/.test(value)) return 'TERM';
  if (/SSH/.test(value)) return 'SSH';
  if (/API|HTTP|\bGET\b|\bPOST\b|\bPUT\b|\bPATCH\b|\bDELETE\b/.test(value)) return 'API';
  if (/FILL|填写|填入/.test(value)) return 'FILL';
  if (/TEST|测试|CHECK/.test(value)) return 'CHECK';
  return 'CALL';
}

function renderMetrics() {
  const total = state.connections.length;
  const enabled = state.connections.filter((item) => item.enabled).length;
  const browserOn = ['listening', 'delegated'].includes(state.browserBridge.status);
  const mcpReady = state.mcp.status === 'ready';
  const now = Date.now();
  const since24Hours = now - 86_400_000;
  const activities24h = state.activities.filter((activity) => {
    const timestamp = new Date(activity.time).getTime();
    return Number.isFinite(timestamp) && timestamp >= since24Hours && timestamp <= now;
  });
  const errors24h = activities24h.filter((activity) => activity.status === 'error').length;
  const registeredAgents = agentClients.filter((client) => client.state === 'registered').length;
  const brokenAgents = agentClients.filter((client) => ['stale', 'conflict', 'error'].includes(client.state)).length;
  const importStats = window.OpenKeyletImportHub?.getStats?.() || { total: 0, selected: 0, ignored: 0 };
  const models = {
    connections: {
      value: total, mode: localized('密码库', 'VAULT'), unit: localized('项', 'ITEMS'),
      label: localized('密码库项目总数', 'Total vault items'),
      secondary: {
        value: enabled, mode: localized('已启用', 'ENABLED'), unit: total > 0 ? `/ ${total}` : localized('项', 'ITEMS'),
        tone: enabled > 0 ? 'active' : '',
        label: localized('已启用项目数，包含所有类型', 'Enabled items across all item types'),
      },
    },
    import: {
      value: importStats.total, mode: localized('已识别', 'EXTRACTED'), unit: localized('项', 'FOUND'),
      label: localized('本地规则已提取的候选凭据数', 'Candidate credentials extracted locally'),
      secondary: {
        value: importStats.selected, mode: localized('待入库', 'SELECTED'), unit: importStats.total > 0 ? `/ ${importStats.total}` : localized('项', 'READY'),
        tone: importStats.selected > 0 ? 'active' : '',
        label: localized('已勾选准备批量入库的条目数', 'Selected candidates ready to import'),
      },
    },
    activity: {
      value: activities24h.length, mode: localized('近 24H 调用', 'CALLS · 24H'), unit: localized('次', ''),
      label: localized('本地日志中最近 24 小时的操作数（点击查看全部记录）', 'Operations in the local log from the last 24 hours (click to show all)'),
      action: 'focus-activity-all',
      secondary: {
        value: errors24h, mode: localized('异常失败', 'ERRORS · 24H'), unit: errors24h > 0 ? localized('项', '') : localized('正常', 'CLEAR'),
        tone: errors24h > 0 ? 'fault' : 'ok',
        label: errors24h > 0
          ? localized('点击筛选并定位到失败记录', 'Click to filter and focus failed activity items')
          : localized('本地日志中最近 24 小时的失败数（点击查看错误筛选）', 'Errors in the local log from the last 24 hours (click to view error filter)'),
        action: 'focus-activity-errors',
      },
    },
    settings: {
      value: registeredAgents, mode: localized('已接入 Agent', 'LINKED'), unit: localized('个', 'AGENTS'),
      label: localized('已注册 OpenKeylet MCP 的 Agent 客户端数（点击查看）', 'Agent clients registered with OpenKeylet MCP (click to focus)'),
      action: 'focus-linked-agents',
      secondary: {
        value: brokenAgents, mode: localized('待修复配置', 'REPAIR'), unit: brokenAgents > 0 ? localized('个', 'NEED FIX') : localized('健康', 'OK'),
        tone: brokenAgents > 0 ? 'warn' : 'ok',
        label: brokenAgents > 0
          ? localized('点击定位到待修复的 Agent 配置', 'Click to jump to the Agent configuration needing repair')
          : localized('需要修复接入配置的 Agent 客户端数（点击查看）', 'Agent clients whose connection configuration needs repair (click to view)'),
        action: 'focus-repair-agent',
      },
    },
  };
  const model = models[activePage] || models.connections;
  const secondary = model.secondary;
  // These indicators describe current services, independently of historical operation errors.
  const services = [
    {
      name: 'MCP', target: 'MCP', value: mcpReady ? 'READY' : state.mcp.status === 'error' ? 'ERROR' : 'SETUP',
      tone: mcpReady ? 'on' : state.mcp.status === 'error' ? 'fault' : 'warn',
      label: mcpReady ? localized('本地 MCP 就绪（点击查看设置）', 'Local MCP is ready (click to open setup)') : state.mcp.status === 'error' ? localized('本地 MCP 异常', 'Local MCP has an error') : localized('本地 MCP 需要配置', 'Local MCP needs setup'),
    },
    {
      name: 'WEB', target: 'WEB', value: state.browserBridge.status === 'error' ? 'ERROR' : !browserOn ? 'OFF' : !state.browserBridge.paired ? 'PAIR' : state.browserBridge.connected ? 'ON' : 'WAIT',
      tone: state.browserBridge.status === 'error' ? 'fault' : browserOn ? state.browserBridge.paired && state.browserBridge.connected ? 'on' : 'warn' : '',
      label: state.browserBridge.status === 'error' ? localized('浏览器桥接异常', 'Browser Bridge has an error') : !browserOn ? localized('浏览器桥接已关闭（点击前往开启）', 'Browser Bridge is off (click to configure)') : !state.browserBridge.paired ? localized('浏览器扩展等待配对', 'Browser extension is waiting to pair') : state.browserBridge.connected ? localized('浏览器扩展已连接', 'Browser extension is connected') : localized('等待浏览器扩展连接', 'Waiting for the browser extension to connect'),
    },
    {
      name: 'PIN', target: 'APP', value: ownerLockState.pinConfigured ? 'ON' : 'OFF', tone: ownerLockState.pinConfigured ? 'on' : '',
      label: ownerLockState.pinConfigured ? localized('已开启本地 PIN 锁定', 'Local PIN protection is enabled') : localized('尚未设置本地 PIN（点击前往设置）', 'Local PIN protection is off (click to configure)'),
    },
  ];
  const primaryTag = model.action ? 'button' : 'div';
  const primaryAttrs = model.action
    ? `type="button" class="lcd-primary metric-cell metric-actionable" data-metric-action="${escapeHtml(model.action)}"`
    : `class="lcd-primary metric-cell" role="group"`;
  const secondaryTag = secondary.action ? 'button' : 'div';
  const secondaryAttrs = secondary.action
    ? `type="button" class="lcd-secondary metric-cell metric-actionable ${secondary.tone || ''}" data-metric-action="${escapeHtml(secondary.action)}"`
    : `class="lcd-secondary metric-cell ${secondary.tone || ''}" role="group"`;
  $('#metrics').innerHTML = `
    <div class="lcd-screen">
      <${primaryTag} ${primaryAttrs} aria-label="${escapeHtml(model.label)}" title="${escapeHtml(`${model.label}: ${model.value}`)}">
        <span class="metric-label" aria-hidden="true">${model.mode}</span>
        <div class="metric-readout">${sevenSegmentNumber(model.value)}${model.unit ? `<span class="metric-unit" aria-hidden="true">${model.unit}</span>` : ''}</div>
      </${primaryTag}>
      <${secondaryTag} ${secondaryAttrs} aria-label="${escapeHtml(secondary.label)}" title="${escapeHtml(`${secondary.label}: ${secondary.value}`)}">
        <span class="metric-label" aria-hidden="true">${secondary.mode}</span>
        <div class="metric-readout">${sevenSegmentNumber(secondary.value, 3)}${secondary.unit ? `<span class="metric-unit" aria-hidden="true">${secondary.unit}</span>` : ''}</div>
      </${secondaryTag}>
      <div class="lcd-system" role="group" aria-label="${localized('当前服务状态', 'Current service status')}">
        ${services.map((service) => `<button type="button" class="lcd-service ${service.tone}" data-metric-section="${service.target}" aria-label="${escapeHtml(service.label)}" title="${escapeHtml(service.label)}"><i class="lcd-dot ${service.tone}" aria-hidden="true"></i><span class="lcd-service-name" aria-hidden="true">${service.name}</span><strong class="lcd-status ${service.tone}" aria-hidden="true">${service.value}</strong></button>`).join('')}
      </div>
    </div>`;
}

function compactTargetUrl(raw) {
  const value = String(raw || '').trim();
  if (!value) return '';
  return value.replace(/^https?:\/\//i, '').replace(/\/+$/, '');
}

function itemDetail(item) {
  if (['card', 'identity', 'secureNote'].includes(item.itemType)) {
    return [itemTypeLabel(item.itemType), item.folder, localized('字段已加密', 'ENCRYPTED FIELDS')].filter(Boolean).join(' · ');
  }
  if (item.passkeys?.length && !itemCapabilities(item).length) return `PASSKEY · ${item.passkeys.map(k => k.rpId).join(' · ')}`;
  const capabilities = itemCapabilities(item);
  const targets = [];
  if (capabilities.includes('ssh') && item.host) targets.push(`${item.host}:${item.port || 22}`);
  const urlFromModules = (item.modules || []).find((m) => m.kind === 'url' && m.value)?.value;
  const loginUri = Array.isArray(item.loginUris) ? item.loginUris.find((entry) => entry?.uri)?.uri : '';
  const primaryUrl = compactTargetUrl(item.baseUrl || urlFromModules || loginUri);
  if (primaryUrl && !targets.includes(primaryUrl)) targets.push(primaryUrl);
  if (targets.length) return [targets.join(' · '), item.folder].filter(Boolean).join(' · ');
  const count = (item.modules || []).filter((module) => module.secret).length || item.secret?.fields?.length || 0;
  return capabilities.includes('fill')
    ? `${count} ENCRYPTED FIELD${count === 1 ? '' : 'S'}`
    : localized('草稿 · 尚无可用动作', 'DRAFT · NO AVAILABLE ACTION');
}

function itemCapabilities(item) {
  return Array.isArray(item.capabilities) ? item.capabilities : [];
}

function itemDisplayKind(item) {
  if (item.itemType && item.itemType !== 'custom' && ITEM_TYPES[item.itemType]) return item.itemType;
  const capabilities = itemCapabilities(item);
  if (capabilities.includes('ssh')) return 'ssh';
  if (capabilities.includes('http')) return 'api';
  if (item.passkeys?.length) return 'passkey';
  if (item.modules?.some(module => module.kind === 'apiCredential')) return 'api';
  if (item.modules?.some(module => module.kind === 'password')) return 'login';
  return 'custom';
}

function itemFilterLabel(kind) {
  if (kind === 'all') return localized('全部类型', 'All types');
  if (kind === 'login') return localized('密码', 'Password');
  return itemTypeLabel(kind);
}

function itemDisplayType(item) { return itemFilterLabel(itemDisplayKind(item)); }

function itemTypeIcon(kind) {
  const paths = {
    all: '<rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><rect x="14" y="14" width="6" height="6" rx="1"/>',
    ssh: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3m6 0h4"/>',
    login: '<circle cx="8" cy="8" r="4.5"/><path d="m11.3 11.3 9.2 9.2m-4-4 2-2m-5-1 2-2"/>',
    api: '<path d="m7 7-5 5 5 5m10-10 5 5-5 5M14 4l-4 16"/>',
    passkey: '<circle cx="8" cy="7" r="3"/><path d="M3 20v-2a5 5 0 0 1 10 0v2m5-5v6m0-3h3"/><circle cx="18" cy="12" r="3"/>',
    card: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 10h18M7 15h3"/>',
    identity: '<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="8" cy="10" r="2"/><path d="M5 17v-1a3 3 0 0 1 6 0v1m3-8h4m-4 4h4m-4 4h2"/>',
    secureNote: '<path d="M5 3h10l4 4v14H5Zm9 0v5h5M8 12h8m-8 4h6"/>',
    custom: '<path d="m12 3 8 4v10l-8 4-8-4V7Zm-8 4 8 4 8-4m-8 4v10"/>',
    error: '<circle cx="12" cy="12" r="9"/><path d="m9 9 6 6m0-6-6 6"/>',
    success: '<circle cx="12" cy="12" r="9"/><path d="m7 12 3 3 7-7"/>',
    SYSTEM: '<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M12 17v4m-5 0h10"/>',
    MCP: '<path d="M9 3v4m6-4v4M6 7h12v4a6 6 0 0 1-12 0Zm6 10v4"/>',
    APP: '<path d="M12 3v3m0 12v3M3 12h3m12 0h3M5.6 5.6l2.1 2.1m8.6 8.6 2.1 2.1m0-12.8-2.1 2.1m-8.6 8.6-2.1 2.1"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>',
    WEB: '<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>',
    CLOUD: '<path d="M7 18a5 5 0 1 1 0-10 6 6 0 0 1 11-1 5.5 5.5 0 0 1 0 11Z"/>',
    SAFE: '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6Z"/><path d="m8 12 3 3 5-6"/>',
    UPDATE: '<path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/><path d="M16 16h5v5"/>',
  };
  return `<svg class="item-type-icon" viewBox="0 0 24 24" aria-hidden="true">${paths[kind] || paths.custom}</svg>`;
}

function syncFilterStrip(selector, order, selected, attribute, label, showLabels = false) {
  const control = $(selector);
  if (!control.children.length) {
    control.innerHTML = order.map(kind => `<button type="button" ${attribute}="${kind}">${itemTypeIcon(kind)}${showLabels ? '<span data-filter-label></span>' : ''}</button>`).join('');
  }
  control.style.setProperty('--type-count', order.length);
  control.style.setProperty('--selected-type', order.indexOf(selected));
  $$('button', control).forEach(button => {
    const kind = button.getAttribute(attribute);
    button.setAttribute('aria-pressed', String(kind === selected));
    button.tabIndex = kind === selected ? 0 : -1;
    button.title = label(kind);
    button.setAttribute('aria-label', button.title);
    if (showLabels) $('[data-filter-label]', button).textContent = button.title;
  });
}

function syncItemTypeFilter() {
  $('#item-type-switch').setAttribute('aria-label', localized('项目类型筛选', 'Item type filter'));
  syncFilterStrip('#item-type-switch', itemTypeFilterOrder, currentItemTypeFilter, 'data-item-type-filter', itemFilterLabel);
}

function syncSettingsFilterControl() {
  const labels = { all: ['全部设置', 'All settings'], SYSTEM: ['系统入口', 'System access'], MCP: ['Agent 接入', 'Agent setup'], APP: ['窗口与偏好', 'Window & preferences'], WEB: ['浏览器', 'Browser'], CLOUD: ['云端备份', 'Cloud backup'], SAFE: ['本地数据', 'Local data'], UPDATE: ['软件更新', 'Updates'] };
  $('#settings-filter-switch').setAttribute('aria-label', localized('设置分组筛选', 'Settings section filter'));
  syncFilterStrip('#settings-filter-switch', settingsFilterOrder, currentSettingsFilter, 'data-settings-filter', kind => localized(...labels[kind]));
}

async function selectFilterButton(button) {
  if (button.dataset.itemTypeFilter) await setItemTypeFilter(button.dataset.itemTypeFilter);
  if (button.dataset.activityFilter) {
    currentActivityFilter = button.dataset.activityFilter;
    activityVisibleCount = ACTIVITY_PAGE_SIZE;
    $('.activity-panel').scrollTop = 0;
    renderActivity();
  }
  if (button.dataset.settingsFilter) {
    currentSettingsFilter = button.dataset.settingsFilter;
    syncSettingsFilterControl();
    applySettingsSearch();
    $('.settings-layout').scrollTop = 0;
  }
}

async function setItemTypeFilter(kind) {
  if (!itemTypeFilterOrder.includes(kind) || kind === currentItemTypeFilter) return;
  const edited = state.connections.find(item => item.id === editorItemId);
  if (edited && kind !== 'all' && itemDisplayKind(edited) !== kind && !await closeEditorWithDraft()) return;
  currentItemTypeFilter = kind;
  syncItemTypeFilter();
  renderConnections();
}

async function selectPage(page) {
  if (editorItemId && page !== 'connections' && !await closeEditorWithDraft()) return;
  activePage = page;
  syncTitleSearch();
  $('.nav').dataset.active = page;
  $$('.nav-item').forEach(item => {
    item.classList.toggle('active', item.dataset.page === page);
    if (item.dataset.page === page) item.setAttribute('aria-current', 'page');
    else item.removeAttribute('aria-current');
  });
  $$('.page').forEach(item => item.classList.toggle('active', item.id === `page-${page}`));
  renderMetrics();
  if (page === 'connections') {
    syncListActionsWidth();
    syncCheckAllButton();
  }
  if (page === 'import') {
    window.OpenKeyletImportHub?.render?.();
    window.OpenKeyletImportHub?.focusInput?.();
  }
  if (page === 'settings') scanAgents();
}

async function selectCreationMode(mode) {
  if (mode === 'draft' && !editorDrafts[0]) return;
  if (!await openEditor(null, mode === 'draft' ? editorDrafts[0] : null)) return;
  creationMode = mode;
  renderDrafts();
}

function moduleAgentVisibilityText(visible) {
  return visible
    ? { label: localized('Agent 可查看此值', 'Agent can see this value'), status: localized('Agent 可见', 'AGENT VISIBLE') }
    : { label: localized('不向 Agent 显示此值', 'Hidden from agent'), status: localized('Agent 隐藏', 'AGENT HIDDEN') };
}

function setModuleAgentVisibility(button, visible) {
  button.setAttribute('aria-pressed', String(visible));
  const { label, status } = moduleAgentVisibilityText(visible);
  button.setAttribute('aria-label', label);
  button.title = label;
  button.closest('.module-row').querySelector('[data-module-visibility]').textContent = status;
  syncModuleDraft();
}

// Every travelling cap uses the same drag lifecycle and its existing action.
function switchControlFor(target) {
  const strip = target.closest?.('.filter-strip, .title-switch, .language-switch, .nav, .switch, .module-agent-toggle');
  if (!strip || strip.closest('[inert]') || strip.matches(':disabled, [aria-disabled="true"]')) return null;
  if (strip.matches('.title-switch')) {
    return { strip, count: 2, read: () => Number(strip.getAttribute('aria-checked') === 'true'),
      preview: $$('.title-switch-option', strip), focus: () => strip,
      commit: index => window.OpenKeyletAppearance[strip.id === 'theme-toggle' ? 'setTheme' : 'setSound'](Boolean(index)) };
  }
  if (strip.matches('.switch')) {
    const input = $('input', strip);
    if (input.disabled) return null;
    return { strip, count: 2, read: () => Number(input.checked), focus: () => input,
      disabled: () => input.disabled,
      commit: async index => {
        input.checked = Boolean(index);
        if (input.id === 'desktop-shortcut-enabled') await setSystemIntegration('desktop', input.checked);
        else if (input.id === 'launch-at-login-enabled') await setSystemIntegration('startup', input.checked);
        else if (input.id === 'browser-enabled' || input.id === 'browser-agent-passkey-enabled') await saveBrowserSettings();
        else if (input.id === 'auto-check-enabled') await saveDesktopSettings();
        else if (input.id === 'pin-enabled') await savePinSettings();
        else input.dispatchEvent(new Event('change', { bubbles: true }));
      } };
  }
  if (strip.matches('.module-agent-toggle')) {
    return { strip, count: 2, read: () => Number(strip.getAttribute('aria-pressed') === 'true'), focus: () => strip,
      commit: index => setModuleAgentVisibility(strip, Boolean(index)) };
  }
  const buttons = $$('button', strip);
  const read = () => buttons.findIndex(button => strip.matches('.nav, .language-switch') ? button.classList.contains('active') : button.getAttribute('aria-pressed') === 'true');
  return { strip, count: buttons.length, buttons, preview: buttons, read,
    disabled: index => buttons[index]?.disabled,
    focus: () => buttons[read()],
    commit: async index => {
      const button = buttons[index];
      if (strip.matches('.filter-strip')) await selectFilterButton(button);
      else if (strip.matches('.language-switch')) await setLanguage(button.dataset.language);
      else if (strip.matches('.nav')) await selectPage(button.dataset.page);
      else await selectCreationMode(button.id === 'drafts-button' ? 'draft' : 'add');
    } };
}

function moveSwitchThumb(event) {
  const drag = switchPointerDrag;
  if (!drag || event.pointerId !== drag.pointerId) return;
  const dx = event.clientX - drag.startX;
  if (!drag.started && Math.abs(dx) < 4) return;
  if (!drag.started && event.pointerType === 'touch' && Math.abs(event.clientY - drag.startY) > Math.abs(dx)) return;
  event.preventDefault();
  if (!drag.started) {
    drag.started = true;
    drag.strip.classList.add('is-dragging');
    drag.strip.classList.add('has-drag-preview');
    drag.strip.setPointerCapture(event.pointerId);
  }
  const position = Math.max(0, Math.min(drag.count - 1, drag.origin + dx / drag.cellWidth));
  drag.index = Math.round(position);
  drag.strip.style.setProperty('--drag-type', position);
  drag.preview?.forEach((button, index) => button.classList.toggle('is-preview', index === drag.index && !drag.disabled?.(index)));
}

async function finishSwitchDrag(commit) {
  const drag = switchPointerDrag;
  if (!drag) return;
  switchPointerDrag = null;
  if (drag.strip.hasPointerCapture(drag.pointerId)) drag.strip.releasePointerCapture(drag.pointerId);
  drag.strip.classList.remove('is-dragging');
  drag.preview?.forEach(button => button.classList.remove('is-preview'));
  if (drag.started) {
    // Escape may precede pointer release by any duration. Keep ownership of
    // that gesture's click until it arrives or a new pointer gesture starts.
    suppressSwitchClick = drag.strip;
  }
  if (commit && drag.started && drag.index !== drag.read() && !drag.disabled?.(drag.index) && drag.strip.isConnected) {
    switchSelectionPending = true;
    drag.strip.setAttribute('aria-busy', 'true');
    drag.strip.style.setProperty('--drag-type', drag.index);
    try {
      if (titleSearchOpen) setTitleSearchOpen(false, false);
      await drag.commit(drag.index);
      if (drag.read() === drag.index && drag.strip.id !== 'sound-toggle' && drag.strip.id !== 'theme-toggle') {
        const isBinary = drag.strip.matches('.switch, .module-agent-toggle');
        window.OpenKeyletAppearance.feedback(isBinary ? (drag.index ? 'toggleOn' : 'toggleOff') : 'select');
      }
    } catch (error) { toast(cleanError(error), 'error'); }
    finally {
      switchSelectionPending = false;
      drag.strip.removeAttribute('aria-busy');
      drag.strip.style.removeProperty('--drag-type');
      drag.strip.classList.remove('has-drag-preview');
      // Opening a drawer or confirmation retains its own focus management.
      if (!confirmationResolver && (drag.strip.contains(document.activeElement) || document.activeElement === document.body)) drag.focus()?.focus({ preventScroll: true });
    }
  } else {
    drag.strip.style.removeProperty('--drag-type');
    drag.strip.classList.remove('has-drag-preview');
  }
}

document.addEventListener('pointerdown', event => {
  suppressSwitchClick = null;
  if (event.button !== 0 || !event.isPrimary || switchPointerDrag || switchSelectionPending || event.ctrlKey || event.metaKey) return;
  const control = switchControlFor(event.target);
  if (!control) return;
  const { strip } = control;
  const button = event.target.closest('button');
  if (button?.disabled) return;
  const style = getComputedStyle(strip);
  const width = strip.getBoundingClientRect().width - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
  const origin = control.buttons?.includes(button) ? control.buttons.indexOf(button) : control.read();
  const cellWidth = parseFloat(style.getPropertyValue('--switch-travel')) || width / control.count;
  switchPointerDrag = { ...control, pointerId: event.pointerId, startX: event.clientX, startY: event.clientY, origin, index: origin, cellWidth, started: false };
});
document.addEventListener('pointermove', moveSwitchThumb, { passive: false });
document.addEventListener('pointerup', event => {
  if (switchPointerDrag?.pointerId === event.pointerId) { moveSwitchThumb(event); void finishSwitchDrag(true); }
});
document.addEventListener('pointercancel', event => { if (switchPointerDrag?.pointerId === event.pointerId) void finishSwitchDrag(false); });
document.addEventListener('lostpointercapture', event => { if (switchPointerDrag?.pointerId === event.pointerId) void finishSwitchDrag(false); });
window.addEventListener('blur', () => { void finishSwitchDrag(false); });
document.addEventListener('click', event => {
  const strip = suppressSwitchClick;
  suppressSwitchClick = null;
  if (!strip || event.detail === 0 || !strip.contains(event.target)) return;
  event.preventDefault(); event.stopImmediatePropagation();
}, true);

function syncTitleSearch() {
  const labels = {
    connections: ['搜索项目', 'Search items'],
    import: ['筛选候选项目', 'Filter candidates'],
    activity: ['搜索记录', 'Search activity'],
    settings: ['搜索设置', 'Search settings'],
  };
  const label = localized(...(labels[activePage] || labels.connections));
  const shortcutHint = isMacOS ? '⌘K' : 'Ctrl+K';
  const hasQuery = Boolean(pageSearch[activePage]);
  const control = $('#title-search');
  control.classList.toggle('has-query', hasQuery);
  const input = $('#title-search-input');
  input.hidden = false;
  input.dataset.pageSearch = activePage;
  input.placeholder = `${label}…`;
  input.setAttribute('aria-label', label);
  input.title = `${label} (${shortcutHint})`;
  if (input.value !== pageSearch[activePage]) input.value = pageSearch[activePage];
  const button = $('#title-search-toggle');
  button.title = hasQuery ? localized('清除搜索', 'Clear search') : `${label} (${shortcutHint})`;
  button.setAttribute('aria-label', hasQuery ? localized('清除搜索', 'Clear search') : label);
}

function setTitleSearchOpen(open, focus = true) {
  titleSearchOpen = open;
  syncTitleSearch();
  if (open && focus) $('#title-search-input').focus({ preventScroll: true });
}

function itemPermission(item) {
  const capabilities = itemCapabilities(item);
  if (capabilities.includes('http')) return 'HTTP';
  if (capabilities.includes('ssh')) return 'SSH';
  if (capabilities.includes('fill')) return 'FOCUS INPUT';
  if (capabilities.includes('passkey')) return 'PASSKEY';
  if (capabilities.includes('personal')) return 'PERSONAL';
  if (capabilities.includes('note')) return 'NOTE';
  return 'NOT EXPOSED';
}

const activityFilterDefinitions = {
  all: { key: 'A', label: 'ALL' },
  error: { key: 'B', label: 'ERROR' },
  success: { key: 'C', label: 'PASS' },
};
const activityFilterOrder = Object.keys(activityFilterDefinitions);

function syncActivityFilterControl() {
  const labels = { all: ['全部', 'ALL'], error: ['错误', 'ERROR'], success: ['成功', 'PASS'] };
  $('#activity-filter-switch').setAttribute('aria-label', localized('记录结果筛选', 'Activity result filter'));
  syncFilterStrip('#activity-filter-switch', activityFilterOrder, currentActivityFilter, 'data-activity-filter', kind => localized(...labels[kind]), true);
}

const itemCheckStates = new Map();
const AUTO_CHECK_INTERVALS = [15, 30, 60, 180, 360, 720, 1440];
let checkAllRunning = false;
let checkAllRunId = 0;
let checkAllProgress = { done: 0, total: 0 };
let lastCheckAllOutcome = '';
let autoCheckTimer = null;

function clearAutoCheckTimer() {
  if (autoCheckTimer !== null) {
    clearTimeout(autoCheckTimer);
    autoCheckTimer = null;
  }
}

function getAutoCheckConfig() {
  const enabled = state?.settings?.autoCheckEnabled !== false;
  const rawMinutes = Number(state?.settings?.autoCheckIntervalMinutes);
  const minutes = AUTO_CHECK_INTERVALS.includes(rawMinutes) ? rawMinutes : 60;
  return { enabled, minutes };
}

function scheduleAutoCheck() {
  clearAutoCheckTimer();
  if (!ownerLockState.unlocked || !state?.settings) return;
  const { enabled, minutes } = getAutoCheckConfig();
  if (!enabled) return;
  const delayMs = minutes * 60_000;
  autoCheckTimer = setTimeout(async () => {
    autoCheckTimer = null;
    if (!ownerLockState.unlocked || !state?.settings || state.settings.autoCheckEnabled === false) return;
    if (!checkAllRunning) {
      await runCheckAll({ allItems: true, silent: true });
    }
    scheduleAutoCheck();
  }, delayMs);
}

function getVisibleConnections() {
  const query = normalizeSearch(pageSearch.connections);
  return state.connections.filter((item) => {
    if (item.id === editorItemId) return true;
    if (currentItemTypeFilter !== 'all' && itemDisplayKind(item) !== currentItemTypeFilter) return false;
    if (!query) return true;
    const fields = (item.secret?.fields || []).map((field) => field.name).join(' ');
    const notes = (item.agentNotes || []).map((note) => `${note.text || ''} ${note.author || ''}`).join(' ');
    return normalizeSearch([item.name, item.description, item.folder, itemTypeLabel(item.itemType), itemDisplayType(item), itemCapabilities(item).join(' '), itemDetail(item), itemPermission(item), fields, notes].join(' ')).includes(query);
  });
}

function getTestableVisibleConnections() {
  return getVisibleConnections().filter((item) => item.enabled && item.canTest);
}

function getAllTestableConnections() {
  return (state?.connections || []).filter((item) => item.enabled && item.canTest);
}

const CARD_ACTION_ICONS = {
  checkIdle: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8.5"/><path d="m8.8 12.2 2.2 2.2 4.4-4.6"/></svg>',
  checkOk: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12.5 9.5 17 19 7.5"/></svg>',
  checkError: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8.5"/><path d="M12 8v4.5"/><path d="M12 16h.01"/></svg>',
  use: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3l1.75 4.85L18.6 9.6l-4.85 1.75L12 16.2l-1.75-4.85L5.4 9.6l4.85-1.75Z"/><path d="M19 15.2l.75 2.05L21.8 18l-2.05.75L19 20.8l-.75-2.05L16.2 18l2.05-.75Z"/></svg>',
  history: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3.5 12a8.5 8.5 0 1 0 2.7-6.2L3.5 8"/><path d="M3.5 3.5V8H8"/><path d="M12 7.5V12l3 1.8"/></svg>',
  copy: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15H4a1.5 1.5 0 0 1-1.5-1.5v-9A1.5 1.5 0 0 1 4 3h9A1.5 1.5 0 0 1 14.5 4.5v1"/></svg>',
  copied: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12.5 9.5 17 19 7.5"/></svg>',
  del: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16"/><path d="M9.5 7V4.5A1.5 1.5 0 0 1 11 3h2a1.5 1.5 0 0 1 1.5 1.5V7"/><path d="M6.5 7l.8 12.2A1.8 1.8 0 0 0 9.1 21h5.8a1.8 1.8 0 0 0 1.8-1.8L17.5 7"/><path d="M10 11v6M14 11v6"/></svg>',
};

function itemCheckButtonView(item) {
  const entry = item.enabled && item.canTest ? itemCheckStates.get(item.id) : null;
  if (entry?.status === 'testing') {
    return { state: 'testing', html: '<span class="check-spinner" aria-hidden="true"></span>', title: localized('正在检测连接…', 'Testing connection…'), loading: true };
  }
  if (entry?.status === 'ok') {
    return { state: 'ok', html: CARD_ACTION_ICONS.checkOk, title: entry.message || localized('连接测试通过', 'Connection check passed'), loading: false };
  }
  if (entry?.status === 'error') {
    return { state: 'error', html: CARD_ACTION_ICONS.checkError, title: entry.message || localized('连接测试失败', 'Connection check failed'), loading: false };
  }
  return { state: '', html: CARD_ACTION_ICONS.checkIdle, title: localized('检测连接', 'Test connection'), loading: false };
}

function itemLampView(item) {
  if (!item.enabled) {
    return {
      dotClass: 'status-dot off',
      label: localized('启用此项目；Agent 将可以使用其中的秘密', 'Enable this item so agents can use its secrets'),
    };
  }
  const entry = item.canTest ? itemCheckStates.get(item.id) : null;
  if (entry?.status === 'testing') {
    return {
      dotClass: 'status-dot testing',
      label: localized('正在检测连接…', 'Testing connection…'),
    };
  }
  if (entry?.status === 'error') {
    const detail = entry.message ? `：${entry.message}` : '';
    return {
      dotClass: 'status-dot warn',
      label: localized(`检测未通过${detail}（点击可停用此项目）`, `Check failed${entry.message ? `: ${entry.message}` : ''} (click to disable)`),
    };
  }
  return {
    dotClass: 'status-dot',
    label: localized('停用此项目；Agent 将无法使用其中的秘密', 'Disable this item; agents will no longer be able to use its secrets'),
  };
}

function syncItemCheckButton(id) {
  const item = state.connections.find((candidate) => candidate.id === id);
  const card = $(`.connection-card[data-item-id="${CSS.escape(id)}"]`);
  if (!card || !item) return;
  const canTest = Boolean(item.enabled && item.canTest);
  const button = $('[data-action="test"]', card);
  if (button) {
    const view = itemCheckButtonView(item);
    if (view.state) button.dataset.checkState = view.state;
    else delete button.dataset.checkState;
    button.innerHTML = view.html;
    button.title = view.title;
    button.setAttribute('aria-label', view.title);
    button.disabled = !canTest || view.loading;
    button.setAttribute('aria-busy', view.loading ? 'true' : 'false');
  }
  const toggleBtn = $('.item-toggle', card);
  const dot = $('.item-toggle .status-dot', card);
  if (toggleBtn && dot) {
    const lamp = itemLampView(item);
    dot.className = lamp.dotClass;
    toggleBtn.title = lamp.label;
    toggleBtn.setAttribute('aria-label', lamp.label);
  }
  syncListActionsWidth();
}

function recomputeCheckAllOutcome() {
  if (!lastCheckAllOutcome) return;
  let hasError = false;
  let hasOk = false;
  for (const item of state?.connections || []) {
    if (!item.enabled || !item.canTest) continue;
    const entry = itemCheckStates.get(item.id);
    if (entry?.status === 'error') hasError = true;
    else if (entry?.status === 'ok') hasOk = true;
  }
  lastCheckAllOutcome = hasError ? 'error' : (hasOk ? 'ok' : '');
}

function clearCheckAllResults() {
  lastCheckAllOutcome = '';
  const clearedIds = [];
  for (const [id, entry] of itemCheckStates.entries()) {
    if (entry?.status === 'testing') continue;
    itemCheckStates.delete(id);
    clearedIds.push(id);
  }
  for (const id of clearedIds) {
    syncItemCheckButton(id);
  }
  syncCheckAllButton();
}

function syncCheckAllButton() {
  const button = $('#check-all-button');
  const label = $('#check-all-label');
  if (!button || !label) return;
  if (checkAllRunning) {
    button.disabled = true;
    button.dataset.state = 'running';
    button.setAttribute('aria-busy', 'true');
    const { done, total } = checkAllProgress;
    label.textContent = `${done}/${total}`;
    const tip = localized(`正在批量检测（${done}/${total}）…`, `Checking items (${done}/${total})…`);
    button.title = tip;
    button.setAttribute('aria-label', tip);
    return;
  }
  const testable = getTestableVisibleConnections();
  button.disabled = testable.length === 0;
  button.setAttribute('aria-busy', 'false');
  const hasOutcome = Boolean(lastCheckAllOutcome && testable.length > 0);
  if (hasOutcome) button.dataset.state = lastCheckAllOutcome;
  else delete button.dataset.state;
  label.textContent = 'CHECK';
  const tip = hasOutcome
    ? (lastCheckAllOutcome === 'error'
      ? localized('检测发现异常：点击恢复正常状态', 'Check found issues: click to reset status')
      : localized('检测已完成：点击恢复正常状态', 'Checks finished: click to reset status'))
    : (testable.length > 0
      ? localized(`一键检测当前列表中的 ${testable.length} 个可测试项目`, `Check all ${testable.length} testable items in view`)
      : localized('当前列表没有可检测的已启用项目', 'No enabled testable items in current view'));
  button.title = tip;
  button.setAttribute('aria-label', tip);
}

function syncListActionsWidth() {
  const list = $('#connections-list');
  if (list) list.style.removeProperty('--list-actions-width');
}

async function runSingleItemCheck(item, { showToast = true, doRefresh = true } = {}) {
  if (!item || !item.enabled || !item.canTest) return null;
  if (itemCheckStates.get(item.id)?.status === 'testing') return null;
  itemCheckStates.set(item.id, { status: 'testing', message: '' });
  syncItemCheckButton(item.id);
  try {
    const raw = await api.test(item.id);
    const msg = publicMessage(raw, localized('连接测试完成', 'Connection test complete'));
    itemCheckStates.set(item.id, { status: 'ok', message: msg });
    syncItemCheckButton(item.id);
    recomputeCheckAllOutcome();
    syncCheckAllButton();
    if (showToast) toast(msg);
    if (doRefresh) await refresh(false);
    return { ok: true, message: msg };
  } catch (error) {
    const msg = cleanError(error);
    itemCheckStates.set(item.id, { status: 'error', message: msg });
    syncItemCheckButton(item.id);
    recomputeCheckAllOutcome();
    syncCheckAllButton();
    if (showToast) toast(msg, 'error');
    if (doRefresh) await refresh(false);
    return { ok: false, message: msg };
  }
}

async function runCheckAll({ allItems = false, silent = false } = {}) {
  if (checkAllRunning || !ownerLockState.unlocked) return;
  const targets = allItems ? getAllTestableConnections() : getTestableVisibleConnections();
  if (!targets.length) {
    if (!silent) toast(localized('当前列表没有可检测的已启用项目', 'No enabled testable items in current view'));
    return;
  }
  const runId = ++checkAllRunId;
  checkAllRunning = true;
  lastCheckAllOutcome = '';
  checkAllProgress = { done: 0, total: targets.length };
  for (const item of targets) {
    itemCheckStates.set(item.id, { status: 'testing', message: '' });
    syncItemCheckButton(item.id);
  }
  syncCheckAllButton();

  let cursor = 0;
  let passed = 0;
  let failed = 0;
  const workerCount = Math.min(4, targets.length);
  const runWorker = async () => {
    while (cursor < targets.length) {
      if (runId !== checkAllRunId || !ownerLockState.unlocked) return;
      const item = targets[cursor++];
      try {
        const raw = await api.test(item.id);
        if (runId !== checkAllRunId || !ownerLockState.unlocked) return;
        const msg = publicMessage(raw, localized('连接测试完成', 'Connection test complete'));
        itemCheckStates.set(item.id, { status: 'ok', message: msg });
        passed += 1;
      } catch (error) {
        if (runId !== checkAllRunId || !ownerLockState.unlocked) return;
        itemCheckStates.set(item.id, { status: 'error', message: cleanError(error) });
        failed += 1;
      }
      syncItemCheckButton(item.id);
      checkAllProgress = { done: passed + failed, total: targets.length };
      syncCheckAllButton();
    }
  };

  await Promise.all(Array.from({ length: workerCount }, () => runWorker()));
  if (runId !== checkAllRunId) return;
  checkAllRunning = false;
  lastCheckAllOutcome = failed > 0 ? 'error' : 'ok';
  syncCheckAllButton();
  await refresh(false);
  if (silent) {
    if (failed > 0) {
      toast(localized(`定时检测发现 ${failed} 项异常，已亮黄灯提示`, `Scheduled check: ${failed} item(s) flagged with an amber lamp`), 'error');
    }
    return;
  }
  if (failed === 0) {
    window.OpenKeyletAppearance?.play?.('success');
    toast(localized(`一键检测完成：全部 ${passed} 项通过`, `All ${passed} checks passed`));
  } else {
    toast(localized(`一键检测完成：${passed} 项通过，${failed} 项失败（已亮黄灯）`, `Checks finished: ${passed} passed, ${failed} failed (amber lamp)`), 'error');
  }
}

function formatFullItemCopy(item, ownerValues = {}) {
  const lines = [];
  const typeLabel = itemDisplayType(item);
  lines.push(`[${typeLabel}] ${item.name}`);
  const folder = String(item.folder || '').trim();
  const description = String(item.description || '').trim();
  if (folder) lines.push(`${localized('文件夹', 'Folder')}: ${folder}`);
  if (description) lines.push(`${localized('说明', 'Description')}: ${description}`);

  const fieldEntries = [];
  const emittedSecretKeys = new Set();
  for (const module of item.modules || []) {
    const def = MODULE_DEFS[module.kind] || MODULE_DEFS.customSecret;
    const secretKey = moduleSecretName(module);
    const label = module.kind === 'customSecret'
      ? (String(module.name || '').trim() || localized('自定义字段', 'Custom field'))
      : localized(def.zh, def.en);
    let rawVal = '';
    if (secretKey) {
      emittedSecretKeys.add(secretKey);
      rawVal = ownerValues[secretKey] ?? '';
    } else {
      rawVal = module.value ?? '';
    }
    const val = String(rawVal ?? '');
    if (!val.trim()) continue;
    fieldEntries.push([label, val]);
  }
  for (const [key, val] of Object.entries(ownerValues)) {
    if (emittedSecretKeys.has(key)) continue;
    const text = String(val ?? '');
    if (!text.trim()) continue;
    fieldEntries.push([key, text]);
  }

  for (const [label, val] of fieldEntries) {
    if (val.includes('\n')) {
      lines.push(`${label}:`);
      lines.push(val.trimEnd());
    } else {
      lines.push(`${label}: ${val.trim()}`);
    }
  }

  const uris = (item.loginUris || []).map((entry) => String(entry?.uri || '').trim()).filter(Boolean);
  if (uris.length) {
    lines.push(`${localized('匹配网站', 'Websites')}: ${uris.join(', ')}`);
  }
  if (item.passkeys?.length) {
    const passkeySummary = item.passkeys.map((pk) => [pk.rpId, pk.userName || pk.displayName].filter(Boolean).join(' / ')).filter(Boolean);
    if (passkeySummary.length) lines.push(`Passkey: ${passkeySummary.join('; ')}`);
  }
  if (item.agentNotes?.length) {
    lines.push(`${localized('Agent 笔记', 'Agent notes')}:`);
    for (const note of item.agentNotes) {
      const author = note.author === 'OWNER' ? localized('主人', 'OWNER') : (note.author || 'MCP');
      lines.push(`- [${author}] ${note.text}`);
    }
  }
  return lines.join('\n');
}

async function copyFullItem(item, button = null) {
  if (!item) return;
  try {
    let ownerValues = {};
    try {
      const view = await api.ownerSecrets(item.id);
      ownerValues = Object.fromEntries((view?.fields || []).map((field) => [field.name, field.value]));
    } catch (error) {
      toast(cleanError(error), 'error');
      await refreshOwnerLock(false);
      return;
    }
    const formatted = formatFullItemCopy(item, ownerValues);
    await api.copyOwnerValue(formatted, true);
    if (button?.isConnected) {
      button.classList.add('is-copied');
      button.innerHTML = CARD_ACTION_ICONS.copied;
      setTimeout(() => {
        if (!button.isConnected) return;
        button.classList.remove('is-copied');
        button.innerHTML = CARD_ACTION_ICONS.copy;
      }, 1200);
    }
    toast(localized(`已工整复制「${item.name}」的全部内容（30 秒后清除剪贴板）`, `Copied full contents of "${item.name}" (clears clipboard in 30s)`));
  } catch (error) {
    toast(cleanError(error), 'error');
  }
}

function syncVaultViewMode() {
  const list = $('#connections-list');
  if (list) {
    list.dataset.view = vaultViewMode;
    syncListActionsWidth();
    if (typeof updateItemGridRowHeight === 'function' && itemList) updateItemGridRowHeight();
  }
  const button = $('#vault-view-toggle');
  if (!button) return;
  button.dataset.view = vaultViewMode;
  const label = vaultViewMode === 'list'
    ? localized('切换为卡片网格视图', 'Switch to card grid view')
    : localized('切换为列表视图', 'Switch to list view');
  button.setAttribute('aria-label', label);
  button.title = label;
}

function setVaultViewMode(nextMode) {
  vaultViewMode = nextMode === 'grid' ? 'grid' : 'list';
  try { localStorage.setItem('openkeylet.vaultView', vaultViewMode); } catch (_) {}
  syncVaultViewMode();
}

function itemSubtitle(item) {
  const detail = itemDetail(item);
  if (detail) return detail;
  return [item.folder, item.description, itemDisplayType(item)].filter(Boolean).join(' · ');
}

function itemMetaBadges(item) {
  const badges = [];
  if (item.passkeys?.length) badges.push({ text: 'PASSKEY' });
  const hasTotp = Boolean(item.hasTotp || (item.modules || []).some((m) => m.kind === 'totp' && m.configured !== false));
  if (hasTotp) badges.push({ text: '2FA' });
  const notes = Array.isArray(item.agentNotes) ? item.agentNotes : [];
  if (notes.length) {
    const label = notes.length > 1
      ? localized(`笔记 · ${notes.length}`, `NOTE · ${notes.length}`)
      : localized('笔记', 'NOTE');
    const previewLines = notes.slice(0, 3).map((entry) => {
      const author = entry.author === 'OWNER' ? localized('主人', 'OWNER') : (entry.author || 'MCP');
      return `[${author}] ${entry.text}`;
    });
    if (item.agentNotesLocked) previewLines.unshift(localized('已锁定', 'LOCKED'));
    badges.push({ text: label, title: previewLines.join('\n'), isNote: true });
  }
  if (item.folder && !itemSubtitle(item).includes(item.folder) && badges.length < 3) badges.push({ text: item.folder });
  return badges.slice(0, 3);
}

function renderConnections() {
  if (itemPointerDrag || itemOrderSaving) return;
  syncVaultViewMode();
  const query = normalizeSearch(pageSearch.connections);
  const signature = JSON.stringify([state.connections, query, language, editorItemId, currentItemTypeFilter]);
  if (signature === renderedConnectionsSignature) {
    syncListActionsWidth();
    syncCheckAllButton();
    return;
  }
  renderedConnectionsSignature = signature;
  const existingIds = new Set(state.connections.map((item) => item.id));
  for (const id of itemCheckStates.keys()) {
    if (!existingIds.has(id)) itemCheckStates.delete(id);
  }
  recomputeCheckAllOutcome();
  const items = getVisibleConnections();
  const container = $('#connections-list');
  if (editorItemId && !state.connections.some(item => item.id === editorItemId)) closeEditor();
  if (!items.length) {
    const hasItems = state.connections.length > 0;
    container.innerHTML = `<div class="empty-state"><div><div class="empty-code">LOCAL VAULT</div><h3>${hasItems ? localized('没有匹配项目', 'NO MATCHING ITEMS') : localized('还没有秘密项目', 'NO VAULT ITEMS')}</h3><p>${hasItems ? localized('当前筛选没有结果。', 'No items match the current filters.') : localized('保存密码、Passkey、信用卡、身份资料和安全笔记，在需要时使用。', 'Keep passwords, passkeys, cards, identities and secure notes together.')}</p><button class="button primary" data-action="${hasItems ? 'clear-connection-filters' : 'add'}">${hasItems ? localized('清除筛选', 'CLEAR FILTERS') : localized('添加项目', 'ADD ITEM')}</button></div></div>`;
    syncListActionsWidth();
    syncCheckAllButton();
    return;
  }
  container.innerHTML = items.map((item) => {
    const type = itemDisplayType(item);
    const canTest = item.enabled && item.canTest;
    const checkView = itemCheckButtonView(item);
    const lamp = itemLampView(item);
    const agentActions = itemCapabilities(item).length > 0;
    const subtitle = itemSubtitle(item);
    const badges = itemMetaBadges(item);
    const cardLabel = localized(`${item.name}：点击编辑，长按拖拽排序，方向键可调整位置`, `${item.name}: click to edit, hold to drag, or use arrow keys to reorder`);
    const checkStateAttr = checkView.state ? ` data-check-state="${checkView.state}"` : '';
    const checkBusyAttr = checkView.loading ? ' aria-busy="true"' : '';
    return `<article class="connection-card ${itemCapabilities(item).includes('ssh') ? 'ssh' : itemCapabilities(item).includes('http') ? 'http' : 'fill'} ${item.enabled ? '' : 'disabled'}" data-item-id="${escapeHtml(item.id)}">
      <button class="connection-name" type="button" draggable="false" data-item-reorder="${escapeHtml(item.id)}" aria-haspopup="dialog" aria-controls="connection-modal" aria-label="${escapeHtml(cardLabel)}" aria-keyshortcuts="ArrowUp ArrowDown ArrowLeft ArrowRight Home End" title="${escapeHtml(cardLabel)}"><span class="lettering-ink">${escapeHtml(item.name)}</span></button>
      <span class="connection-meta"><span class="connection-sub">${escapeHtml(subtitle)}</span>${badges.map((badge) => `<span class="connection-badge${badge.isNote ? ' is-note' : ''}"${badge.title ? ` title="${escapeHtml(badge.title)}"` : ''}>${escapeHtml(badge.text)}</span>`).join('')}</span>
      <button class="module-state item-toggle" type="button" data-action="toggle-enabled" data-id="${item.id}" aria-pressed="${item.enabled}" title="${escapeHtml(lamp.label)}" aria-label="${escapeHtml(lamp.label)}"><i class="${lamp.dotClass}" aria-hidden="true"></i></button>
      <span class="connection-type" role="img" data-item-type="${itemDisplayKind(item)}" aria-label="${escapeHtml(type)}" title="${escapeHtml(type)}">${itemTypeIcon(itemDisplayKind(item))}<small aria-hidden="true">${escapeHtml(type)}</small></span>
      <div class="card-actions" role="group" aria-label="${escapeHtml(item.name)}">
        ${agentActions ? `<button class="small-button card-icon-btn" type="button" data-action="test" data-id="${item.id}"${checkStateAttr}${checkBusyAttr} title="${escapeHtml(checkView.title)}" aria-label="${escapeHtml(checkView.title)}" ${canTest && !checkView.loading ? '' : 'disabled'}>${checkView.html}</button><button class="small-button card-icon-btn" type="button" data-action="copy-name" data-id="${item.id}" title="${localized('复制 OpenKeylet MCP 使用提示', 'Copy OpenKeylet MCP use prompt')}" aria-label="${localized('复制 OpenKeylet MCP 使用提示', 'Copy OpenKeylet MCP use prompt')}">${CARD_ACTION_ICONS.use}</button>` : ''}${item.passwordHistoryCount ? `<button class="small-button card-icon-btn" type="button" data-action="history" data-id="${item.id}" title="${localized('密码历史', 'Password history')}" aria-label="${localized('密码历史', 'Password history')}">${CARD_ACTION_ICONS.history}</button>` : ''}<button class="small-button card-icon-btn item-disclosure" type="button" data-action="copy-item" data-id="${item.id}" aria-label="${escapeHtml(localized(`复制 ${item.name} 的全部内容`, `Copy full contents of ${item.name}`))}" title="${localized('复制项目全部内容', 'Copy full item contents')}">${CARD_ACTION_ICONS.copy}</button><button class="small-button card-icon-btn delete" type="button" data-action="delete" data-id="${item.id}" title="${localized('移入回收站', 'Move to trash')}" aria-label="${localized('移入回收站', 'Move to trash')}">${CARD_ACTION_ICONS.del}</button>
      </div>
    </article>`;
  }).join('');
  syncListActionsWidth();
  syncCheckAllButton();
}

function draftSecretValues(secrets = {}) {
  const named = secrets.namedSecrets || {};
  return {
    ...named,
    password: secrets.password || named.password || '',
    passphrase: secrets.passphrase || named.passphrase || '',
    privateKey: secrets.privateKey || '',
    apiCredential: named.apiCredential || secrets.token || secrets.apiKey || '',
  };
}

function renderDrafts() {
  const button = $('#drafts-button');
  const pill = $('#draft-pill');
  const count = editorDrafts.length;
  const hasDraft = count > 0;
  if (!hasDraft) creationMode = 'add';
  $('.creation-control').dataset.mode = creationMode;
  pill?.classList.toggle('hidden', !hasDraft);
  const deleteButton = $('#delete-draft-button');
  button.disabled = !hasDraft;
  const baseLabel = localized('草稿', 'DRAFT');
  button.textContent = count > 1 ? `${baseLabel} (${count})` : baseLabel;
  const latestName = editorDrafts[0]?.input?.name?.trim();
  button.title = !hasDraft
    ? localized('暂无草稿', 'No draft')
    : count > 1
      ? (latestName
        ? localized(`继续最近草稿「${latestName}」（共 ${count} 条待处理）`, `Continue latest draft "${latestName}" (${count} queued)`)
        : localized(`继续最近的草稿（共 ${count} 条待处理）`, `Continue the most recent draft (${count} queued)`))
      : (latestName
        ? localized(`继续草稿「${latestName}」`, `Continue draft "${latestName}"`)
        : localized('继续最近的草稿', 'Continue the most recent draft'));
  deleteButton.classList.toggle('hidden', !hasDraft);
  deleteButton.title = count > 1
    ? localized(`删除最近草稿（剩余 ${count - 1} 条）`, `Delete latest draft (${count - 1} remaining)`)
    : localized('删除草稿', 'Delete draft');
}

async function refreshDrafts(showError = false) {
  if (!ownerLockState.unlocked) {
    editorDrafts = [];
    renderDrafts();
    return;
  }
  try {
    editorDrafts = await api.drafts();
    renderDrafts();
  } catch (error) {
    if (showError) toast(cleanError(error), 'error');
  }
}

function formatTime(value) {
  const diff = Date.now() - new Date(value).getTime();
  if (diff < 60_000) return localized('刚刚', 'JUST NOW');
  if (diff < 3_600_000) return localized(`${Math.floor(diff / 60_000)} 分钟前`, `${Math.floor(diff / 60_000)} MIN AGO`);
  if (diff < 86_400_000) return localized(`${Math.floor(diff / 3_600_000)} 小时前`, `${Math.floor(diff / 3_600_000)} HR AGO`);
  return new Date(value).toLocaleString(language === 'en' ? 'en-US' : 'zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function activityAction(action = '') {
  const raw = String(action);
  if (language !== 'en' || !HAN_TEXT.test(raw)) return raw;
  if (/测试连接/.test(raw)) return 'Test connection';
  if (/重置.*SSH.*主机信任/.test(raw)) return 'Reset SSH host trust';
  if (/导入备份/.test(raw)) return 'Import portable backup';
  if (/填写|填入/.test(raw)) return `Fill secret field (${activityCode(raw)})`;
  return 'OpenKeylet operation';
}

function activitySource(source = '') {
  if (language === 'en' && HAN_TEXT.test(String(source))) return 'APP';
  return source;
}

function getFilteredActivities() {
  const query = normalizeSearch(pageSearch.activity);
  return state.activities
    .map((activity, sourceIndex) => ({ activity, sourceIndex }))
    .filter(({ activity }) => {
      if (currentActivityFilter !== 'all' && activity.status !== currentActivityFilter) return false;
      return !query || normalizeSearch([activity.action, activity.connectionName, activity.source, activity.status, activity.error].join(' ')).includes(query);
    });
}

function isActivityFilterActive() {
  return currentActivityFilter !== 'all' || Boolean(normalizeSearch(pageSearch.activity));
}

function syncClearActivityButton(matchedCount) {
  const button = $('#clear-activity-button');
  if (!button) return;
  const totalCount = state?.activities?.length || 0;
  const filtering = isActivityFilterActive() && matchedCount < totalCount;
  button.textContent = filtering ? localized('删除匹配', 'DELETE SHOWN') : localized('清空记录', 'CLEAR LOG');
  button.title = filtering
    ? localized(`删除当前筛选出的 ${matchedCount} 条记录`, `Delete ${matchedCount} matching log entries`)
    : localized('清空全部本地操作记录', 'Clear all local activity logs');
  button.disabled = filtering ? matchedCount === 0 : totalCount === 0;
}

async function deleteSingleActivity(id, triggerEl = null) {
  if (!id) return;
  const rowsBefore = $$('#activity-list .activity-item');
  const currentIndex = rowsBefore.findIndex((row) => row.dataset.activityId === id);
  const restoreFocus = Boolean(triggerEl && (document.activeElement === triggerEl || triggerEl.closest?.('.activity-item') === document.activeElement));
  if (triggerEl) triggerEl.disabled = true;
  try {
    await api.deleteActivity(id);
    expandedActivityErrors.delete(id);
    state.activities = state.activities.filter((entry) => entry.id !== id);
    renderActivity();
    renderMetrics();
    toast(localized('已删除该条记录', 'Log entry deleted'));
    if (restoreFocus) {
      const rowsAfter = $$('#activity-list .activity-item');
      const nextRow = rowsAfter[Math.min(currentIndex, rowsAfter.length - 1)];
      (nextRow && $('[data-action="delete-activity"]', nextRow))?.focus({ preventScroll: true });
    }
  } catch (error) {
    if (triggerEl) triggerEl.disabled = false;
    toast(cleanError(error), 'error');
  }
}

function renderActivity() {
  syncActivityFilterControl();
  const container = $('#activity-list');
  const activities = getFilteredActivities();
  activityMatchCount = activities.length;
  syncClearActivityButton(activities.length);
  if (!activities.length) {
    const hasActivity = state.activities.length > 0;
    container.innerHTML = `<div class="empty-state"><div><h3>${hasActivity ? localized('没有匹配记录', 'NO MATCHING ACTIVITY') : localized('暂无操作记录', 'NO ACTIVITY YET')}</h3><p>${hasActivity ? localized('当前搜索或结果筛选没有记录。', 'No activity matches the current search and result filter.') : localized('Agent 使用 OpenKeylet 后，这里只显示不含秘密的摘要。', 'After an agent uses OpenKeylet, only secret-free summaries appear here.')}</p>${hasActivity ? `<button class="button primary" data-action="clear-activity-filters">${localized('重置搜索与筛选', 'RESET SEARCH & FILTER')}</button>` : ''}</div></div>`;
    return;
  }
  const deleteLabel = localized('删除此记录', 'Delete log entry');
  container.innerHTML = activities.slice(0, activityVisibleCount).map(({ activity, sourceIndex }) => {
    const errorExpanded = expandedActivityErrors.has(activity.id);
    return `<article class="activity-item" data-activity-id="${escapeHtml(activity.id)}" data-activity-status="${escapeHtml(activity.status)}" tabindex="-1"><div class="log-index">${String(state.activities.length - sourceIndex).padStart(4, '0')}</div><div class="activity-status ${activity.status === 'error' ? 'error' : ''}">${activity.status === 'error' ? '×' : '✓'}</div><div class="activity-copy"><div class="activity-title">${escapeHtml(activityAction(activity.action))} · ${escapeHtml(activity.connectionName)}</div><div class="activity-meta">${escapeHtml(activitySource(activity.source))} · ${activity.durationMs} ms</div>${activity.error ? `<button type="button" class="activity-error ${errorExpanded ? 'expanded' : ''}" data-expand-error="${activity.id}" aria-expanded="${errorExpanded}">${escapeHtml(publicMessage(activity.error, localized('操作失败', 'Operation failed. Details are available in the local log.')))}</button>` : ''}</div><div class="activity-trailing"><time class="activity-time">${formatTime(activity.time)}</time><button type="button" class="small-button delete activity-delete-btn" data-action="delete-activity" data-activity-id="${escapeHtml(activity.id)}" title="${escapeHtml(deleteLabel)}" aria-label="${escapeHtml(deleteLabel)}">${CARD_ACTION_ICONS.del}</button></div></article>`;
  }).join('');
}

function queueMoreActivities() {
  if (activityLoadPending || activityVisibleCount >= activityMatchCount) return;
  activityLoadPending = true;
  setTimeout(() => {
    activityVisibleCount = Math.min(activityVisibleCount + ACTIVITY_PAGE_SIZE, activityMatchCount);
    renderActivity();
    activityLoadPending = false;
  }, 120);
}

function applySettingsSearch() {
  const query = normalizeSearch(pageSearch.settings);
  let visible = 0;
  for (const card of $$('.settings-card')) {
    const mod = card.dataset.module || '';
    const matchesSection = currentSettingsFilter === 'all'
      || mod.startsWith(`${currentSettingsFilter} /`)
      || (currentSettingsFilter === 'APP' && mod.startsWith('LANG /'));
    const matches = matchesSection && (!query || normalizeSearch(`${mod} ${card.textContent}`).includes(query));
    card.classList.toggle('search-hidden', !matches);
    if (matches) visible += 1;
  }
  $('#settings-search-empty').classList.toggle('hidden', visible > 0);
}

function renderSettings() {
  githubBackup.render();
  appUpdater.render();
  $('#mcp-endpoint').textContent = `${state.mcp.stdioCommand} mcp stdio`;
  const mcpFault = state.mcp.status === 'error';
  const mcpStrip = $('#mcp-status-strip');
  mcpStrip.className = `status-strip ${mcpFault ? 'error' : ''}`;
  mcpStrip.innerHTML = `<span class="status-dot"></span><span class="status-key">${mcpFault ? 'FAULT' : 'READY'}</span><span>${mcpFault ? escapeHtml(publicMessage(state.mcp.error)) : localized('Agent 使用时自动启动 stdio，无需常驻服务。', 'stdio starts on demand. No background service.')}</span>`;
  $('#agent-restart-notice').classList.toggle('hidden', !agentRestartRequired);
  $('#desktop-shortcut-enabled').checked = Boolean(systemIntegrationState.desktopShortcut);
  $('#launch-at-login-enabled').checked = Boolean(systemIntegrationState.launchAtLogin);
  const strongMode = Boolean(ownerLockState.strongMode || ownerLockState.mode === 'strong');
  $('#pin-enabled').checked = ownerLockState.pinConfigured || ownerPinSetupRequested || strongMode;
  $('#pin-enabled').disabled = strongMode;
  const pinHelp = $('.pin-option small');
  if (pinHelp) {
    pinHelp.textContent = strongMode
      ? localized('已由「高安全强加密模式」强主密码接管（随 GitHub 私有仓库同步开启/关闭）', 'Managed by Strong Cloud Vault master passphrase (coupled with GitHub private repo binding).')
      : localized('防他人在本机查看明文或管理条目；关闭将移除当前 PIN', 'Locks desktop viewing and management against others on this device. Turning off removes the PIN.');
  }
  $('#owner-auto-lock-option').classList.toggle('hidden', !ownerLockState.pinConfigured && !strongMode);
  const autoLockMinutes = Number(state.settings.ownerAutoLockMinutes || 0);
  $('#owner-auto-lock-minutes').value = [0, 5, 15, 30, 60].includes(autoLockMinutes) ? String(autoLockMinutes) : '0';
  const autoCheck = getAutoCheckConfig();
  if ($('#auto-check-enabled')) $('#auto-check-enabled').checked = autoCheck.enabled;
  if ($('#auto-check-interval-option')) $('#auto-check-interval-option').classList.toggle('hidden', !autoCheck.enabled);
  if ($('#auto-check-interval-minutes')) $('#auto-check-interval-minutes').value = String(autoCheck.minutes);
  scheduleAutoCheck();
  $('#close-behavior').value = state.settings.closeBehavior === 'exit' ? 'exit' : 'tray';
  $('#browser-enabled').checked = state.settings.browserEnabled;
  $('#browser-port').value = state.settings.browserPort;
  $('#browser-agent-passkey-enabled').checked = state.settings.browserAgentPasskey !== false;
  const bridge = state.browserBridge;
  const online = ['listening', 'delegated'].includes(bridge.status);
  const connectedCount = Number(bridge.connectedCount || (bridge.connected ? 1 : 0));
  const pairingActive = Boolean(bridge.pairingActive);
  const strip = $('#browser-status-strip');
  strip.className = `status-strip ${bridge.status === 'error' ? 'error' : online ? '' : 'offline'}`;
  const statusKey = bridge.status === 'error'
    ? 'FAULT'
    : !online
      ? 'OFF'
      : bridge.connected
        ? 'CONNECTED'
        : pairingActive
          ? 'PAIRING'
          : bridge.paired
            ? 'WAITING'
            : 'READY';
  const statusDetail = bridge.status === 'error'
    ? publicMessage(bridge.error)
    : !online
      ? localized('Browser Bridge 已关闭', 'Browser Bridge is off')
      : bridge.connected
        ? connectedCount > 1
          ? localized(
              `已连接 ${connectedCount} 个 Chrome 账号 · ${bridge.endpoint}`,
              `${connectedCount} Chrome profiles connected · ${bridge.endpoint}`,
            )
          : pairingActive
            ? localized(
                `已连接 · 自动配对窗口开启中（可继续添加账号）`,
                `Connected · pairing window open (add more profiles)`,
              )
            : bridge.endpoint
        : pairingActive
          ? localized(
              '自动配对窗口已开启（安装扩展后自动连接）',
              'Auto-pairing window open (extensions connect automatically)',
            )
          : bridge.endpoint;
  strip.innerHTML = `<span class="status-dot"></span><span class="status-key">${statusKey}</span><span>${escapeHtml(statusDetail)}</span>`;
  $('#test-browser-bridge-button').disabled = !bridge.connected;
  const reloadExtBtn = $('#reload-extension-button');
  if (reloadExtBtn) {
    reloadExtBtn.disabled = !bridge.connected;
    reloadExtBtn.className = bridge.extensionOutdated ? 'button primary' : 'button quiet';
  }
  const versionStrip = $('#browser-version-strip');
  if (versionStrip) {
    const outdated = Boolean(bridge.connected && bridge.extensionOutdated);
    versionStrip.classList.toggle('hidden', !outdated);
    if (outdated) {
      const appVer = bridge.appVersion ? `v${bridge.appVersion}` : '';
      const extVer = bridge.extensionVersion ? `v${bridge.extensionVersion}` : '?';
      versionStrip.innerHTML = `<span class="status-dot"></span><span class="status-key">${localized('版本不同步', 'OUTDATED')}</span><span>${escapeHtml(localized(`主程序 ${appVer} · 插件 ${extVer} — 点击下方「重载插件」或重新拖入新版扩展目录`, `App ${appVer} · Extension ${extVer} — Click Reload extension or drag the updated folder`))}</span>`;
    }
  }
  $('#reset-pairing-button').disabled = !bridge.paired;
  renderChromeProfiles();
  renderAgents();
  applySettingsSearch();
}

function renderChromeProfiles() {
  const row = $('#chrome-profile-row');
  const select = $('#chrome-profile-select');
  if (!row || !select) return;
  if (!Array.isArray(chromeProfiles) || chromeProfiles.length < 2) {
    row.classList.add('hidden');
    select.replaceChildren();
    return;
  }
  const previous = select.value;
  select.replaceChildren(...chromeProfiles.map((profile) => {
    const title = profile.name || profile.directory;
    const sub = profile.account && profile.account !== title ? profile.account : '';
    const label = sub ? `${title} (${sub})` : title;
    const option = new Option(label, profile.directory);
    option.dataset.title = title;
    if (sub) option.dataset.sub = sub;
    return option;
  }));
  if (previous && chromeProfiles.some((profile) => profile.directory === previous)) {
    select.value = previous;
  }
  row.classList.remove('hidden');
}

async function loadChromeProfiles() {
  try {
    const profiles = await api.chromeProfiles();
    chromeProfiles = Array.isArray(profiles) ? profiles : [];
  } catch {
    chromeProfiles = [];
  }
  renderChromeProfiles();
}

const agentLabels = { notDetected: 'NOT FOUND', available: 'READY', registered: 'CONNECTED', stale: 'NEEDS REPAIR', conflict: 'CONFLICT', error: 'ERROR' };
function agentDetail(client) {
  const details = {
    notDetected: localized('未安装或未发现', 'Not installed'),
    available: localized('可连接', 'Ready to connect'),
    registered: localized('已连接', 'Connected'),
    stale: localized('OpenKeylet 连接或全局规则需要修复', 'OpenKeylet setup needs repair'),
    conflict: localized('配置冲突', 'Config conflict'),
    error: localized('检测失败', 'Detection failed'),
  };
  return details[client.state] || publicMessage(client.message, localized('状态已更新', 'Status updated'));
}
function renderAgents() {
  const container = $('#agent-client-list');
  container.innerHTML = agentClients.length ? agentClients.map((client) => `<div class="agent-client-row ${client.canRegister ? '' : 'is-disabled'}" data-agent-state="${escapeHtml(client.state)}" data-client-id="${escapeHtml(client.clientId)}" tabindex="-1"><span class="agent-client-copy"><strong>${escapeHtml(client.displayName)}</strong><span>${escapeHtml(agentDetail(client))}</span></span><div class="agent-row-controls"><span class="agent-state ${escapeHtml(client.state)}">${escapeHtml(agentLabels[client.state] || client.state)}</span><div class="agent-row-actions">${client.canRegister ? `<button type="button" class="agent-row-action primary" data-agent-action="connect" data-client-id="${escapeHtml(client.clientId)}">CONNECT</button>` : ''}${client.canRepair ? `<button type="button" class="agent-row-action primary" data-agent-action="repair" data-client-id="${escapeHtml(client.clientId)}">REPAIR</button>` : ''}${client.canRemove ? `<button type="button" class="agent-row-action" data-agent-action="remove" data-client-id="${escapeHtml(client.clientId)}">REMOVE</button>` : ''}</div></div></div>`).join('') : `<div class="agent-scan-placeholder">${localized('没有检测到支持的 Agent', 'NO SUPPORTED AGENT DETECTED')}</div>`;
  applySettingsSearch();
}

async function scanAgents(showToast = false) {
  try {
    agentClients = await api.agents();
    renderAgents();
    if (state) renderMetrics();
    if (showToast) toast(localized('Agent 扫描完成', 'Agent scan complete'));
  } catch (error) { toast(cleanError(error), 'error'); }
}

const MODULE_DEFS = {
  cardholderName: { code: 'CHN', zh: '持卡人姓名', en: 'CARDHOLDER', secret: true },
  cardNumber: { code: 'PAN', zh: '卡号', en: 'CARD NUMBER', secret: true },
  cardBrand: { code: 'BRD', zh: '卡组织', en: 'BRAND', secret: true },
  cardExpMonth: { code: 'MM', zh: '到期月份', en: 'EXPIRY MONTH', secret: true },
  cardExpYear: { code: 'YYYY', zh: '到期年份', en: 'EXPIRY YEAR', secret: true },
  cardSecurityCode: { code: 'CVC', zh: '安全码', en: 'SECURITY CODE', secret: true },
  identityTitle: { code: 'TTL', zh: '称谓', en: 'TITLE', secret: true },
  firstName: { code: 'FN', zh: '名字', en: 'FIRST NAME', secret: true },
  middleName: { code: 'MN', zh: '中间名', en: 'MIDDLE NAME', secret: true },
  lastName: { code: 'LN', zh: '姓氏', en: 'LAST NAME', secret: true },
  company: { code: 'ORG', zh: '公司', en: 'COMPANY', secret: true },
  email: { code: 'MAIL', zh: '电子邮箱', en: 'EMAIL', secret: true },
  phone: { code: 'TEL', zh: '电话号码', en: 'PHONE', secret: true },
  address1: { code: 'AD1', zh: '地址第一行', en: 'ADDRESS LINE 1', secret: true },
  address2: { code: 'AD2', zh: '地址第二行', en: 'ADDRESS LINE 2', secret: true },
  address3: { code: 'AD3', zh: '地址第三行', en: 'ADDRESS LINE 3', secret: true },
  city: { code: 'CTY', zh: '城市', en: 'CITY', secret: true },
  state: { code: 'REG', zh: '省 / 州', en: 'STATE / REGION', secret: true },
  postalCode: { code: 'ZIP', zh: '邮政编码', en: 'POSTAL CODE', secret: true },
  country: { code: 'CTR', zh: '国家 / 地区', en: 'COUNTRY / REGION', secret: true },
  passportNumber: { code: 'PPT', zh: '护照号码', en: 'PASSPORT', secret: true },
  licenseNumber: { code: 'DL', zh: '驾照号码', en: 'DRIVER LICENSE', secret: true },
  nationalId: { code: 'ID', zh: '身份证号码', en: 'NATIONAL ID', secret: true },
  secureNote: { code: 'NOTE', zh: '安全笔记', en: 'SECURE NOTE', secret: true, multiline: true },
  username: { code: 'USR', zh: '账号', en: 'USERNAME', secret: true },
  password: { code: 'PWD', zh: '密码', en: 'PASSWORD', secret: true },
  apiCredential: { code: 'API', zh: 'API 凭据', en: 'API CREDENTIAL', secret: true },
  privateKey: { code: 'KEY', zh: '私钥', en: 'PRIVATE KEY', secret: true },
  passphrase: { code: 'PPH', zh: '私钥口令', en: 'KEY PASSPHRASE', secret: true },
  totp: { code: 'OTP', zh: 'TOTP', en: 'TOTP', secret: true },
  customSecret: { code: 'SEC', zh: '自定义字段', en: 'CUSTOM FIELD', secret: true },
  host: { code: 'HST', zh: '主机 / IP', en: 'HOST / IP', secret: false },
  port: { code: 'PRT', zh: '端口', en: 'PORT', secret: false },
  url: { code: 'URL', zh: '服务 URL', en: 'SERVICE URL', secret: false },
};
const PERSONAL_FIELDS = Object.keys(MODULE_DEFS).slice(0, Object.keys(MODULE_DEFS).indexOf('username'));
const ITEM_TYPES = { login: ['登录', 'Login'], card: ['信用卡', 'Card'], identity: ['身份资料', 'Identity'], secureNote: ['安全笔记', 'Secure note'], ssh: ['SSH', 'SSH'], api: ['API', 'API'], custom: ['自定义', 'Custom'], passkey: ['Passkey', 'Passkey'] };
function itemTypeLabel(kind) { const labels = ITEM_TYPES[kind] || ITEM_TYPES.custom; return localized(...labels); }
function typeOptions(emptyLabel, selected, includePasskey = false) {
  return `${emptyLabel ? `<option value="">${emptyLabel}</option>` : ''}${Object.keys(ITEM_TYPES).filter(k => includePasskey || k !== 'passkey').map(k => `<option value="${k}" ${k === selected ? 'selected' : ''}>${itemTypeLabel(k)}</option>`).join('')}`;
}
for (const kind of PERSONAL_FIELDS) {
  const button = document.createElement('button'); button.type = 'button'; button.dataset.addModule = kind;
  button.textContent = moduleLabel(kind); $('#module-menu').append(button);
  staticCopy.push([`#module-menu [data-add-module="${kind}"]`, 'text', MODULE_DEFS[kind].zh, MODULE_DEFS[kind].en]);
}

function moduleHasPlaintextReveal(kind) {
  return Boolean(MODULE_DEFS[kind]?.secret);
}

function defaultModuleAgentVisible(kind) {
  return !moduleHasPlaintextReveal(kind);
}

function moduleSecretName(module) {
  return module.kind === 'customSecret' ? String(module.name || '').trim() : MODULE_DEFS[module.kind]?.secret ? module.kind : '';
}

function moduleLabel(kind) {
  const definition = MODULE_DEFS[kind] || MODULE_DEFS.customSecret;
  return language === 'en' ? definition.en : definition.zh;
}

function syncModuleDraft() {
  const rows = $$('.module-row', $('#module-list'));
  if (!rows.length) return;
  currentModules = rows.map((row, index) => {
    row.dataset.moduleIndex = String(index);
    return {
      kind: row.dataset.kind,
      name: $('[data-module-name]', row)?.value ?? row.dataset.name ?? '',
      value: $('[data-module-value]', row)?.value ?? '',
      secretValue: $('[data-secret-value]', row)?.value ?? '',
      configured: row.dataset.configured === 'true',
      existing: row.dataset.existing === 'true',
      privateKeyName: row.dataset.privateKeyName || '',
      pending: row.dataset.pending === 'true',
      agentVisible: $('[data-module-agent-visible]', row)?.getAttribute('aria-pressed') === 'true',
    };
  });
}

function renderModules() {
  finishModulePointerDrag(false);
  const container = $('#module-list');
  if (!currentModules.length) {
    container.innerHTML = `<div class="module-empty"><b>EMPTY / DRAFT</b><span>${localized('选择模板或添加任意模块', 'Choose a template or add any module')}</span></div>`;
    syncModuleDraft();
    return;
  }
  container.innerHTML = currentModules.map((module, index) => {
    const definition = MODULE_DEFS[module.kind] || MODULE_DEFS.customSecret;
    const agentVisible = typeof module.agentVisible === 'boolean' ? module.agentVisible : defaultModuleAgentVisible(module.kind);
    const { label: agentVisibilityLabel, status: agentVisibilityStatus } = moduleAgentVisibilityText(agentVisible);
    const secretName = moduleSecretName(module);
    const nameControl = module.kind === 'customSecret'
      ? `<input class="input module-name-input" data-module-name value="${escapeHtml(module.name || '')}" placeholder="${localized('字段名称', 'FIELD NAME')}" />`
      : `<strong>${escapeHtml(moduleLabel(module.kind))}</strong>`;
    const secretCaption = secretName && !PERSONAL_FIELDS.includes(module.kind) && module.kind !== 'customSecret' ? `<small>${escapeHtml(secretName)}</small>` : '';
    const customName = `${nameControl}<div class="module-metadata">${secretCaption}<span class="module-visibility-state" data-module-visibility aria-hidden="true">${agentVisibilityStatus}</span></div>`;
    let control = '';
    let actions = '';
    if (module.kind === 'privateKey') {
      const keyState = module.pending ? module.privateKeyName : module.configured ? (module.privateKeyName || 'IMPORTED KEY') : localized('尚未导入', 'NOT IMPORTED');
      control = `<div class="module-key-control"><span>${escapeHtml(keyState)}</span><button type="button" class="copy-secret-button" data-choose-module-key>SELECT</button></div>${module.secretValue ? `<div class="secret-input-control module-secret-control multiline module-key-secret"><textarea class="input textarea secret-masked" data-secret-value readonly>${escapeHtml(module.secretValue)}</textarea></div>` : '<input type="hidden" data-secret-value value="" />'}`;
      const keyActionsDisabled = !module.secretValue;
      actions = `${secretActionButton('reveal', true, keyActionsDisabled)}${secretActionButton('copy', true, keyActionsDisabled)}`;
    } else if (definition.secret) {
      const placeholder = module.kind === 'totp' ? localized('Base32 设置密钥', 'BASE32 SETUP KEY') : localized('输入秘密值', 'ENTER SECRET VALUE');
      control = definition.multiline
        ? `<div class="secret-input-control module-secret-control multiline"><textarea class="input textarea secret-masked" data-secret-value rows="6" maxlength="65536" autocomplete="off" placeholder="${placeholder}">${escapeHtml(module.secretValue || '')}</textarea></div>`
        : `<div class="secret-input-control module-secret-control"><input class="input" data-secret-value type="password" autocomplete="off" value="${escapeHtml(module.secretValue || '')}" placeholder="${placeholder}" /></div>`;
      actions = `${secretActionButton('reveal')}${secretActionButton('copy')}`;
      if (module.kind === 'password') control += `<button class="small-button" type="button" data-generate-password>${localized('生成密码', 'GENERATE')}</button>`;
      if (module.kind === 'totp') control += `<div class="totp-inline-actions"><button class="small-button" type="button" data-copy-totp-code>${localized('复制 2FA 验证码', 'COPY 2FA CODE')}</button><button class="small-button" type="button" data-scan-totp-qr>${localized('扫描二维码图片', 'SCAN QR IMAGE')}</button></div>`;
    } else {
      const inputType = module.kind === 'port' ? 'number' : 'text';
      const placeholder = module.kind === 'url' ? 'api.example.com/v1/' : module.kind === 'host' ? 'host.example.com' : '22';
      control = `<input class="input" data-module-value type="${inputType}" ${module.kind === 'port' ? 'min="1" max="65535"' : ''} value="${escapeHtml(module.value || '')}" placeholder="${placeholder}" />`;
      actions = `<span class="module-action-spacer" aria-hidden="true"></span>${secretActionButton('copy', false)}`;
    }
    const removeLabel = localized('删除模块', 'Remove module');
    const reorderLabel = localized('长按或拖动卡片调整顺序，或聚焦后按上/下方向键', 'Hold and drag card to reorder, or focus and use the Up/Down arrow keys');
    return `<div class="module-row" data-module-index="${index}" data-kind="${escapeHtml(module.kind)}" data-name="${escapeHtml(module.name || '')}" data-existing="${Boolean(module.existing)}" data-configured="${Boolean(module.configured)}" data-private-key-name="${escapeHtml(module.privateKeyName || '')}" data-pending="${Boolean(module.pending)}"><button type="button" class="module-agent-toggle" data-module-agent-visible aria-pressed="${agentVisible}" aria-label="${agentVisibilityLabel}" title="${agentVisibilityLabel}"><i aria-hidden="true"></i></button><div class="module-identity" data-module-drag-handle tabindex="0" role="group" aria-label="${reorderLabel}" title="${reorderLabel}" aria-keyshortcuts="ArrowUp ArrowDown">${customName}</div><div class="module-control">${control}</div><div class="module-actions ${actions ? 'full' : 'single'}">${actions}<button type="button" class="remove-module module-action-icon" data-remove-module aria-label="${removeLabel}" title="${removeLabel}"><svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3 5.5h14M7.5 5.5V3.25h5v2.25M5.25 5.5l.75 11h8l.75-11M8.25 8.5v5M11.75 8.5v5"/></svg></button></div></div>`;
  }).join('');
  syncModuleDraft();
}

function secretActionButton(kind, secret = true, disabled = false) {
  const disabledAttribute = disabled ? ' disabled' : '';
  if (kind === 'reveal') {
    const label = localized('显示明文', 'Show secret');
    return `<button type="button" class="reveal-secret-button secret-icon-button module-action-icon" data-toggle-module-secret aria-pressed="false" aria-label="${label}" title="${label}"${disabledAttribute}><svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3 10s2.4-4.75 7-4.75S17 10 17 10s-2.4 4.75-7 4.75S3 10 3 10Z"/><circle cx="10" cy="10" r="2.5"/><path class="secret-icon-slash" d="M3.5 3.5l13 13"/></svg></button>`;
  }
  const label = secret ? localized('复制隐私值', 'Copy private value') : localized('复制值', 'Copy value');
  const attribute = secret ? 'data-copy-module-secret' : 'data-copy-module-value';
  return `<button type="button" class="copy-secret-button secret-icon-button module-action-icon" ${attribute} aria-label="${label}" title="${label}"${disabledAttribute}><svg viewBox="0 0 20 20" aria-hidden="true"><rect x="7" y="7" width="10" height="10"/><path d="M14 7V3H3v11h4"/></svg></button>`;
}

function positionModuleMenu() {
  const menu = $('#module-menu');
  if (menu.classList.contains('hidden')) return;
  const buttonRect = $('#add-module-button').getBoundingClientRect();
  const gutter = 8;
  const menuWidth = Math.min(276, window.innerWidth - gutter * 2);
  menu.style.width = `${menuWidth}px`;
  menu.style.left = `${Math.round(Math.min(Math.max(gutter, buttonRect.right - menuWidth), window.innerWidth - menuWidth - gutter))}px`;
  menu.style.right = 'auto';
  menu.style.maxHeight = `${window.innerHeight - gutter * 2}px`;
  const menuHeight = Math.min(menu.scrollHeight, window.innerHeight - gutter * 2);
  const below = buttonRect.bottom + 4;
  const top = below + menuHeight <= window.innerHeight - gutter
    ? below
    : Math.max(gutter, buttonRect.top - menuHeight - 4);
  menu.style.top = `${Math.round(top)}px`;
}

function setModuleMenu(open) {
  const menu = $('#module-menu');
  const home = $('#add-module-button').closest('.module-add-wrap');
  if (open) {
    document.body.appendChild(menu);
    menu.classList.remove('hidden');
    positionModuleMenu();
  } else {
    menu.classList.add('hidden');
    home.appendChild(menu);
    menu.removeAttribute('style');
  }
  $('#add-module-button').setAttribute('aria-expanded', String(Boolean(open)));
}

function addModule(kind, options = {}) {
  syncModuleDraft();
  if (kind !== 'customSecret' && currentModules.some((module) => module.kind === kind)) {
    setModuleMenu(false);
    return toast(localized('这个模块已经存在', 'That module already exists'));
  }
  currentModules.push({
    kind,
    name: kind === 'customSecret' ? '' : kind,
    value: kind === 'port' ? '22' : '',
    secretValue: '',
    configured: false,
    existing: false,
    privateKeyName: '',
    pending: false,
    agentVisible: defaultModuleAgentVisible(kind),
    ...options,
  });
  setModuleMenu(false);
  $('#template-picker').classList.add('hidden');
  renderModules();
  const row = $$('.module-row').at(-1);
  ($('[data-module-name]', row) || $('[data-secret-value]', row) || $('[data-module-value]', row))?.focus();
}

function applyTemplate(template) {
  const presets = {
    login: ['url', 'username', 'password'],
    card: ['cardholderName', 'cardNumber', 'cardBrand', 'cardExpMonth', 'cardExpYear', 'cardSecurityCode'],
    identity: ['firstName', 'lastName', 'email', 'phone', 'address1', 'address2', 'city', 'state', 'postalCode', 'country'],
    secureNote: ['secureNote'],
    ssh: ['host', 'port', 'username', 'password'],
    api: ['apiCredential'],
    blank: [],
  };
  value('#connection-type', template === 'blank' ? 'custom' : template);
  currentModules = (presets[template] || []).map((kind) => ({ kind, name: kind, value: kind === 'port' ? '22' : '', secretValue: '', configured: false, existing: false, privateKeyName: '', pending: false, agentVisible: defaultModuleAgentVisible(kind) }));
  $('#template-picker').classList.add('hidden');
  renderModules();
}

function value(selector, next) {
  const element = $(selector);
  if (arguments.length > 1) element.value = next ?? '';
  return element.value;
}

function updateEditorTitle() {
  const queueSuffix = editorOpenedFromDraft && editorDrafts.length > 1 ? ` (${editorDrafts.length})` : '';
  $('#modal-title').textContent = (editorOpenedFromDraft
    ? (editorExistingItem ? localized('继续编辑', 'CONTINUE EDIT') : localized('继续草稿', 'CONTINUE DRAFT'))
    : (editorExistingItem ? localized('编辑项目', 'EDIT ITEM') : localized('添加项目', 'ADD ITEM'))) + queueSuffix;
}

async function openEditor(item = null, draft = null) {
  if (editorOpening) return false;
  editorOpening = true;
  try {
    const launcher = document.activeElement;
    if (!$('#connection-modal').classList.contains('hidden') && !await closeEditorWithDraft()) return false;
    if (!draft && item) draft = editorDrafts.find((candidate) => candidate.input?.id === item.id) || null;
    if (!item && draft?.input?.id) item = state.connections.find((candidate) => candidate.id === draft.input.id) || null;
    let ownerValues = {};
    if (draft) {
      ownerValues = draftSecretValues(draft.input?.secrets);
    } else if (item) {
      try {
        const view = await api.ownerSecrets(item.id);
        ownerValues = Object.fromEntries(view.fields.map((field) => [field.name, field.value]));
      } catch (error) {
        toast(cleanError(error), 'error');
        await refreshOwnerLock(false);
        return false;
      }
    }
    const source = draft?.input || item || null;
    removedSecretFields = new Set();
    editorExistingItem = item;
    editorSourceInput = source;
    editorOpenedFromDraft = Boolean(draft);
    currentDraftId = draft?.id || '';
    value('#connection-id', item?.id);
    value('#connection-name', source?.name);
    value('#connection-description', source?.description);
    $('#connection-type').innerHTML = typeOptions('', source?.itemType || 'custom');
    value('#connection-folder', source?.folder);
    renderLoginUris(source?.loginUris || []);
    $('#vault-folder-options').innerHTML = [...new Set(state.connections.map(i => i.folder).filter(Boolean))].map(f => `<option value="${escapeHtml(f)}"></option>`).join('');
    $('#connection-enabled').checked = source?.enabled ?? true;
    updateEditorTitle();
    $('#template-picker').classList.toggle('hidden', Boolean(item || draft?.input?.modules?.length));
    currentModules = (source?.modules || []).map((module) => {
      const secretName = module.kind === 'customSecret' ? module.name : module.kind;
      const privateKeyName = draft?.input?.secrets?.privateKeyName || item?.privateKeyName || '';
      return { ...module, secretValue: ownerValues[secretName] || '', configured: Boolean(module.configured || ownerValues[secretName]), existing: Boolean(item), privateKeyName: module.kind === 'privateKey' ? privateKeyName : '', pending: false, agentVisible: typeof module.agentVisible === 'boolean' ? module.agentVisible : defaultModuleAgentVisible(module.kind) };
    });
    renderModules();
    editorReturnFocus = launcher;
    editorItemId = item?.id || null;
    $('#connection-modal').classList.remove('hidden');
    $('#passkey-list').innerHTML = (item?.passkeys || []).map(key => `<div class="passkey-summary"><strong>PASSKEY · ${escapeHtml(key.rpId)}</strong><span>${escapeHtml(key.displayName || key.userName)}</span><small>${localized('私钥加密保存在本地；在浏览器中使用。移入回收站会停用 Passkey，恢复后可继续使用。', 'Private key encrypted locally. Moving this item to trash disables its passkeys; restore it to use them again.')}</small></div>`).join('');
    editingAgentNoteId = null;
    renderAgentNotes(item, { autoOpen: true });
    $('.form-scroll', $('#connection-modal')).scrollTop = 0;
    editorInitialSnapshot = JSON.stringify(serializeItem(false));
    requestAnimationFrame(() => {
      if (!$('#connection-modal').classList.contains('hidden') && editorExistingItem === item && !$('#connection-modal').contains(document.activeElement)) {
        $('#connection-name').focus({ preventScroll: true });
      }
    });
    return true;
  } finally { editorOpening = false; }
}

function clearSmartParseBanner() {
  editorSmartClipboardSource = '';
  editorSmartTotpUri = '';
  $('#smart-parse-banner')?.classList.add('hidden');
  $('#smart-parse-warnings')?.classList.add('hidden');
  $('#smart-totp-attach')?.classList.add('hidden');
}

function closeEditor() {
  finishModulePointerDrag(false);
  clearSmartParseBanner();
  $('#connection-modal').classList.add('hidden');
  setModuleMenu(false);
  editorItemId = null;
  editorSourceInput = null;
  editorCandidateOnSaved = null;
  editorOpenedFromDraft = false;
  editorInitialSnapshot = '';
  editingAgentNoteId = null;
  if ($('#agent-note-input')) $('#agent-note-input').value = '';
  $('#agent-notes-section')?.classList.add('hidden');
  if (!editorReturnFocus?.isConnected && editorReturnFocus?.dataset.itemReorder) {
    editorReturnFocus = $(`[data-item-reorder="${CSS.escape(editorReturnFocus.dataset.itemReorder)}"]`);
  }
  if (!editorReturnFocus?.isConnected && editorReturnFocus?.dataset.action && editorReturnFocus?.dataset.id) {
    editorReturnFocus = $$('[data-action][data-id]').find(button => button.dataset.action === editorReturnFocus.dataset.action && button.dataset.id === editorReturnFocus.dataset.id);
  }
  if (editorReturnFocus?.isConnected && !editorReturnFocus.closest('.hidden')) editorReturnFocus.focus({ preventScroll: true });
  editorReturnFocus = null;
}

function collectModules(validate = true) {
  syncModuleDraft();
  const modules = [];
  const secrets = { namedSecrets: {} };
  const secretNames = new Set();
  for (const module of currentModules) {
    const name = moduleSecretName(module);
    if (module.kind === 'customSecret') {
      if (validate && !name) throw new Error(localized('请输入字段名称', 'Enter a field name'));
      const normalizedName = name.toLocaleLowerCase().replace(/[\s_-]+/g, '');
      if (validate && [...Object.keys(MODULE_DEFS).map(k => k.toLowerCase()), 'token', 'apikey'].includes(normalizedName)) throw new Error(localized(`字段名与内置模块冲突：${name}`, `Field name conflicts with a built-in module: ${name}`));
    }
    const uniqueName = name.toLocaleLowerCase().replace(/[\s_-]+/g, '');
    if (validate && name && secretNames.has(uniqueName)) throw new Error(localized(`字段名重复：${name}`, `Duplicate field name: ${name}`));
    if (name) secretNames.add(uniqueName);
    modules.push({ kind: module.kind, name: module.kind === 'customSecret' ? name : '', value: MODULE_DEFS[module.kind]?.secret ? '' : String(module.value || '').trim(), agentVisible: Boolean(module.agentVisible) });
    const fieldValue = module.secretValue || '';
    if (name === 'password') secrets.password = fieldValue;
    else if (name === 'passphrase') secrets.passphrase = fieldValue;
    else if (name === 'privateKey') secrets.privateKey = fieldValue;
    else if (name) secrets.namedSecrets[name] = fieldValue;
  }
  return { modules, secrets, privateKeyImportPath: currentModules.some((module) => module.kind === 'privateKey' && module.pending) ? 'pending' : '' };
}

function serializeItem(validate = true) {
  const name = value('#connection-name').trim();
  if (validate && !name) throw new Error(localized('请输入项目名称', 'Enter an item name'));
  const id = value('#connection-id') || null;
  if (validate && state.connections.some((item) => item.id !== id && item.name.trim().toLowerCase() === name.toLowerCase())) {
    throw new Error(localized('项目名称已存在，请使用其他名称', 'An item with this name already exists'));
  }
  syncModuleDraft();
  if (validate && !currentModules.length) throw new Error(localized('请至少添加一个模块', 'Add at least one module'));
  const collected = collectModules(validate);
  return {
    id,
    itemType: value('#connection-type'),
    folder: value('#connection-folder').trim(),
    favorite: Boolean(editorSourceInput?.favorite),
    loginUris: $$('#login-uri-list .login-uri-row').map(row => ({uri: $('[data-login-uri]', row).value.trim(), matchType: $('[data-login-match]', row).value})).filter(rule => rule.uri),
    modules: collected.modules,
    name,
    description: value('#connection-description'),
    enabled: $('#connection-enabled').checked,
    httpAuthType: editorSourceInput?.httpAuthType || 'auto',
    authHeader: editorSourceInput?.authHeader || '',
    authLocation: editorSourceInput?.authLocation || '',
    authPrefix: editorSourceInput?.authPrefix || '',
    apiAuthHeaders: editorSourceInput?.apiAuthHeaders || [],
    testPath: editorSourceInput?.testPath || '',
    privateKeyImportPath: collected.privateKeyImportPath,
    // A newly entered replacement must not be deleted by the earlier removal.
    removeSecretNames: [...new Set([...removedSecretFields, ...currentModules.filter(m => PERSONAL_FIELDS.includes(m.kind) && m.configured && !m.secretValue).map(moduleSecretName)])].filter((name) => !currentModules.some((module) =>
      moduleSecretName(module) === name && (module.secretValue || module.pending))),
    secrets: collected.secrets,
  };
}

function editorHasDraftContent() {
  syncModuleDraft();
  return Boolean(value('#connection-name').trim() || value('#connection-description').trim() || currentModules.length);
}

function closeEditorWithDraft() {
  if (editorClosing) return editorClosing;
  editorClosing = saveDraftAndCloseEditor().finally(() => { editorClosing = null; });
  return editorClosing;
}

async function saveDraftAndCloseEditor() {
  try {
    const input = serializeItem(false);
    const changed = JSON.stringify(input) !== editorInitialSnapshot;
    let draftsChanged = false;
    if (!editorHasDraftContent() && !editorExistingItem) {
      if (currentDraftId) { await api.deleteDraft(currentDraftId); draftsChanged = true; }
    } else if (changed || editorOpenedFromDraft || !editorExistingItem) {
      const saved = await api.saveDraft(currentDraftId || null, input);
      currentDraftId = saved.id;
      draftsChanged = true;
      toast(editorExistingItem
        ? localized('未保存修改已保留，可随时继续', 'Unsaved changes kept for later')
        : localized('草稿已加密保存', 'Draft saved and encrypted'));
    }
    if (draftsChanged) await refreshDrafts();
    closeEditor();
    return true;
  } catch (error) {
    toast(cleanError(error), 'error');
    return false;
  }
}

async function saveBrowserSettings() {
  const port = Number($('#browser-port').value);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    toast(localized('本地端口须在 1024–65535 之间', 'Local port must be between 1024 and 65535'), 'error');
    if (state) $('#browser-port').value = state.settings.browserPort;
    return;
  }
  try {
    state.settings = await api.settings({
      browserEnabled: $('#browser-enabled').checked,
      browserPort: port,
      browserAgentPasskey: $('#browser-agent-passkey-enabled').checked,
    });
    toast(localized('Browser Bridge 设置已保存', 'Browser Bridge settings saved'));
    await refresh();
  } catch (error) {
    toast(cleanError(error), 'error');
    await refresh(false);
  }
}

async function saveDesktopSettings() {
  try {
    state.settings = await api.settings({
      closeBehavior: $('#close-behavior').value,
      ownerAutoLockMinutes: Number($('#owner-auto-lock-minutes').value || 0),
      autoCheckEnabled: $('#auto-check-enabled') ? $('#auto-check-enabled').checked : true,
      autoCheckIntervalMinutes: Number($('#auto-check-interval-minutes')?.value || 60),
    });
    renderSettings();
    toast(localized('窗口与偏好设置已保存', 'Window & preference settings saved'));
  } catch (error) {
    toast(cleanError(error), 'error');
    await refresh(false);
  }
}

async function setSystemIntegration(kind, enabled) {
  const input = kind === 'desktop' ? $('#desktop-shortcut-enabled') : $('#launch-at-login-enabled');
  input.disabled = true;
  try {
    systemIntegrationState = kind === 'desktop'
      ? await api.setDesktopShortcut(enabled)
      : await api.setLaunchAtLogin(enabled);
    renderSettings();
    toast(kind === 'desktop'
      ? (enabled ? localized('桌面快捷方式已创建', 'Desktop shortcut created') : localized('桌面快捷方式已移除', 'Desktop shortcut removed'))
      : (enabled ? localized('开机自启动已开启', 'Launch at login enabled') : localized('开机自启动已关闭', 'Launch at login disabled')));
  } catch (error) {
    input.checked = kind === 'desktop'
      ? Boolean(systemIntegrationState.desktopShortcut)
      : Boolean(systemIntegrationState.launchAtLogin);
    toast(cleanError(error), 'error');
  } finally {
    input.disabled = false;
  }
}

async function savePinSettings() {
  const toggle = $('#pin-enabled');
  if (toggle.checked) {
    ownerPinSetupRequested = true;
    renderOwnerLock();
    return;
  }
  if (!await confirmDestructiveAction({
    title: localized('关闭 PIN 锁？', 'Turn off PIN lock?'),
    message: localized('当前 PIN 将被移除；再次开启时需要设置新 PIN。', 'The current PIN will be removed. You will need to set a new PIN when enabling the lock again.'),
    acceptLabel: localized('关闭并移除', 'TURN OFF'),
    tag: localized('确认移除 PIN', 'CONFIRM PIN REMOVAL'),
  })) {
    toggle.checked = true;
    return;
  }
  toggle.disabled = true;
  try {
    ownerLockState = await api.ownerDisablePin();
    ownerPinSetupRequested = false;
    renderOwnerLock();
    renderMetrics();
    renderSettings();
    toast(localized('PIN 锁已关闭', 'PIN lock disabled'));
  } catch (error) {
    toast(cleanError(error), 'error');
    await refreshOwnerLock(false);
    renderSettings();
  } finally {
    toggle.disabled = false;
  }
}

async function setLanguage(next) {
  const selected = normalizeLanguageSetting(next);
  if (selected === languagePreference) return;
  languagePreference = selected;
  applyLanguage();
  if (state) {
    state.settings.language = languagePreference;
    renderOwnerLock();
    render();
    syncModuleDraft();
    if (!$('#connection-modal').classList.contains('hidden')) renderModules();
    if (!$('#connection-modal').classList.contains('hidden')) updateEditorTitle();
    try {
      state.settings = await api.settings({ language: languagePreference });
    } catch (error) {
      toast(cleanError(error), 'error');
    }
  }
}

function toastImportSummary(summary) {
  window.OpenKeyletAppearance?.play?.('success');
  toast(localized(`导入完成：新增 ${summary.added}，合并重复 ${summary.merged}`, `Import complete: ${summary.added} added, ${summary.merged} duplicates merged`));
}

async function exportBackup(button) {
  button.disabled = true;
  try {
    const password = await askBackupPassword(true);
    if (password === null) return;
    const path = await api.exportBackup(password);
    if (path) {
      window.OpenKeyletAppearance?.play?.('success');
      toast(localized('加密备份已导出；恢复时需要备份密码', 'Encrypted backup exported; keep its password for restoration'));
    }
  } catch (error) {
    toast(cleanError(error), 'error');
  } finally {
    button.disabled = false;
  }
}

async function importBackup(button) {
  await refreshOwnerLock();
  if (!ownerLockState.unlocked) return;
  if (button) button.disabled = true;
  try {
    const picked = await api.pickBackupImportFile();
    // Graceful fallback if an older mock harness does not implement pick_backup_import_file.
    if (picked === undefined || (picked && typeof picked === 'object' && !('requiresPassword' in picked))) {
      const password = await askBackupPassword(false);
      if (password === null) return;
      const result = await api.importBackup(password);
      if (!result) return;
      toastImportSummary(result);
      await refresh();
      return;
    }
    if (picked === null) return;
    await openMvaultPreviewFlow(picked);
  } catch (error) {
    toast(cleanError(error), 'error');
  } finally {
    if (button) button.disabled = false;
  }
}

let vaultManagement = null, vaultManagementSequence = 0;
function closeVaultManagement() {
  vaultManagementSequence++; vaultManagement = null;
  $('#vault-management-modal').classList.add('hidden');
  $('#vault-management-list').replaceChildren();
  $('#history-clear').classList.add('hidden');
}
async function openVaultManagement(mode, id = null) {
  await refreshOwnerLock();
  if (!ownerLockState.unlocked) return;
  const sequence = ++vaultManagementSequence;
  vaultManagement = { mode, id };
  $('#vault-management-title').textContent = mode === 'trash' ? localized('回收站', 'TRASH') : localized('密码历史', 'PASSWORD HISTORY');
  $('#vault-management-help').textContent = mode === 'trash'
    ? localized('已删除项目会保留到你选择永久删除。恢复时如有同名项目，会自动改名。', 'Deleted items remain until you permanently delete them. Restored items are renamed if necessary.')
    : localized('保留最近 20 条旧密码；密码历史不会提供给 Agent 或自动填写。', 'The latest 20 previous passwords are kept. History is unavailable to agents and autofill.');
  $('#vault-management-list').textContent = localized('正在读取…', 'Loading…');
  $('#history-clear').classList.add('hidden');
  $('#vault-management-modal').classList.remove('hidden');
  try {
    const data = mode === 'trash' ? await api.trash() : await api.history(id);
    if (sequence !== vaultManagementSequence) return;
    const list = $('#vault-management-list'); list.replaceChildren();
    const entries = mode === 'trash' ? data : data.entries;
    if (!entries.length) { list.textContent = mode === 'trash' ? localized('回收站为空', 'Trash is empty') : localized('暂无旧密码', 'No previous passwords'); return; }
    if (mode === 'history') { vaultManagement.updatedAt = data.updatedAt; $('#history-clear').classList.remove('hidden'); }
    for (const entry of entries) {
      const row = document.createElement('section'); row.className = 'vault-management-row';
      const title = document.createElement('strong');
      const date = new Date(mode === 'trash' ? entry.deletedAt : entry.changedAt).toLocaleString(language === 'zh' ? 'zh-CN' : 'en');
      title.textContent = mode === 'trash' ? `${entry.item.name} · ${itemTypeLabel(entry.item.itemType)}` : date;
      const actions = document.createElement('div'); actions.className = 'button-row';
      row.append(title);
      if (mode === 'trash') {
        const subtitle = document.createElement('small'); subtitle.textContent = date; row.append(subtitle);
        for (const action of ['restore','purge']) {
          const button = document.createElement('button'); button.type='button'; button.className = action === 'purge' ? 'button danger-soft' : 'button';
          button.textContent = action === 'restore' ? localized('恢复', 'RESTORE') : localized('永久删除', 'DELETE FOREVER');
          button.dataset.trashAction = action;
          button.onclick = async () => {
            if (action === 'purge' && !await confirmDestructiveAction({title:localized('永久删除此项目？','Permanently delete this item?'),message:localized('本机回收站中的秘密和 Passkey 将被移除，无法撤销。已有备份不会被改动。','The item and its passkeys will be removed from this vault permanently. Existing backups are unchanged.')})) return;
            button.disabled=true;
            try { await api[action](entry.item.id,entry.deletedAt); await refresh(); if (sequence === vaultManagementSequence) await openVaultManagement('trash'); }
            catch(error) { toast(cleanError(error),'error'); button.disabled=false; }
          };
          actions.append(button);
        }
      } else {
        const input=document.createElement('input'); input.className='input'; input.type='password'; input.readOnly=true; input.autocomplete='off'; input.value=entry.password; input.setAttribute('aria-label',localized('旧密码','Previous password'));
        const reveal=document.createElement('button'); reveal.type='button'; reveal.className='button'; reveal.textContent=localized('显示','SHOW');
        reveal.onclick=()=>{ input.type=input.type==='password'?'text':'password'; reveal.textContent=input.type==='password'?localized('显示','SHOW'):localized('隐藏','HIDE'); };
        const copy=document.createElement('button'); copy.type='button'; copy.className='button'; copy.textContent=localized('复制','COPY');
        copy.onclick=async()=>{ try { await api.copyOwnerValue(input.value, true); toast(localized('已复制（30 秒后自动清除）','Copied · clears in 30s')); } catch(error){toast(cleanError(error),'error');} };
        row.append(input); actions.append(reveal,copy);
      }
      row.append(actions); list.append(row);
    }
  } catch(error) { if (sequence === vaultManagementSequence) $('#vault-management-list').textContent=cleanError(error); }
}
$('#trash-open').onclick = () => openVaultManagement('trash');
$('#vault-management-close').onclick = closeVaultManagement;
$('#history-clear').onclick = async () => {
  const snapshot = vaultManagement;
  if (snapshot?.mode !== 'history' || !await confirmDestructiveAction({title:localized('清除密码历史？','Clear password history?'),message:localized('只清除旧密码，当前密码保持不变。此操作无法撤销。','Previous passwords will be removed permanently. The current password is preserved.')})) return;
  try { await api.clearHistory(snapshot.id,snapshot.updatedAt); await refresh(); if (vaultManagement === snapshot) await openVaultManagement('history',snapshot.id); }
  catch(error){toast(cleanError(error),'error');}
};

function renderLoginUris(rules) {
  const choices = [['origin','同源','Same origin'],['domain','主域名','Base domain'],['host','主机与端口','Host and port'],['exact','完整网址','Exact URL'],['prefix','网址前缀','URL prefix'],['regex','正则表达式','Regular expression'],['never','不匹配','Never']];
  $('#login-uri-list').innerHTML = rules.map(rule => `<div class="login-uri-row"><input class="input" data-login-uri aria-label="${localized('网站地址','Website address')}" value="${escapeHtml(rule.uri)}" maxlength="8192"><select class="input" data-login-match aria-label="${localized('匹配规则','Matching rule')}">${choices.map(([key,zh,en]) => `<option value="${key}" ${rule.matchType===key?'selected':''}>${localized(zh,en)}</option>`).join('')}</select><button class="small-button uri-remove-button" data-remove-uri type="button" aria-label="${localized('移除网站','Remove website')}"><svg viewBox="0 0 16 16" aria-hidden="true"><path d="m4 4 8 8m0-8-8 8"/></svg></button></div>`).join('');
}
$('#login-uri-add').onclick = () => renderLoginUris([...$$('#login-uri-list .login-uri-row').map(row => ({uri:$('[data-login-uri]',row).value,matchType:$('[data-login-match]',row).value})),{uri:'',matchType:'origin'}]);
$('#login-uri-list').onclick = event => event.target.closest('[data-remove-uri]')?.closest('.login-uri-row').remove();

const MAX_AGENT_NOTES = 5;
const AGENT_NOTE_ICONS = {
  edit: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M11.3 2.7a1.6 1.6 0 0 1 2.2 2.2L6 12.4 3 13l.6-3Z"/></svg>',
  del: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="m4 4 8 8m0-8-8 8"/></svg>',
};
let editingAgentNoteId = null;
let agentNoteBusy = false;

function formatNoteAuthor(author) {
  const raw = String(author || '').trim();
  if (!raw) return 'MCP';
  if (raw === 'OWNER') return localized('主人', 'OWNER');
  return raw;
}

function applyUpdatedAgentNotesItem(updated) {
  if (!updated?.id) return;
  if (editorExistingItem?.id === updated.id) {
    editorExistingItem = updated;
  }
  if (state?.connections) {
    const idx = state.connections.findIndex((candidate) => candidate.id === updated.id);
    if (idx >= 0) state.connections[idx] = updated;
  }
  renderAgentNotes(updated, { autoOpen: false });
  renderConnections();
}

function renderAgentNotes(item = editorExistingItem, { autoOpen = false } = {}) {
  const section = $('#agent-notes-section');
  if (!section) return;
  if (!item?.id) {
    section.classList.add('hidden');
    section.open = false;
    return;
  }
  section.classList.remove('hidden');
  const notes = Array.isArray(item.agentNotes) ? item.agentNotes : [];
  const locked = Boolean(item.agentNotesLocked);
  if (autoOpen) {
    section.open = notes.length > 0 || locked;
  }
  const countEl = $('#agent-notes-count');
  if (countEl) countEl.textContent = `${notes.length}/${MAX_AGENT_NOTES}`;
  const lockBadge = $('#agent-notes-lock-badge');
  if (lockBadge) {
    lockBadge.textContent = localized('已锁定', 'LOCKED');
    lockBadge.classList.toggle('hidden', !locked);
  }
  const lockInput = $('#agent-notes-locked');
  if (lockInput) {
    lockInput.checked = locked;
    lockInput.disabled = agentNoteBusy;
  }
  const clearBtn = $('#agent-notes-clear');
  if (clearBtn) {
    clearBtn.textContent = localized('清空', 'CLEAR');
    clearBtn.classList.toggle('hidden', notes.length === 0);
    clearBtn.disabled = agentNoteBusy;
  }
  const addInput = $('#agent-note-input');
  const addBtn = $('#agent-note-add');
  if (addInput) {
    addInput.placeholder = localized('添加简短用途备注（如：生产 GPU 服务器、/srv/web）…', 'Add a short note (e.g. prod GPU server, /srv/web)…');
    addInput.disabled = agentNoteBusy;
  }
  if (addBtn) {
    addBtn.textContent = localized('添加', 'ADD');
    addBtn.disabled = agentNoteBusy;
  }
  const list = $('#agent-notes-list');
  if (!list) return;
  if (!notes.length) {
    list.innerHTML = `<p class="agent-notes-empty">${escapeHtml(localized('尚无 Agent 笔记。Agent 使用此项目后可自动记录简短非敏感用途备注，你也可以在下方手动添加。', 'No agent notes yet. Agents can record short non-secret context after using this item, or you can add one below.'))}</p>`;
    return;
  }
  list.innerHTML = notes.map((note) => {
    const isEditing = editingAgentNoteId === note.id;
    const isOwner = note.author === 'OWNER';
    const timeText = note.updatedAt ? formatTime(note.updatedAt) : '';
    const body = isEditing
      ? `<div class="agent-note-edit-row"><input class="input" type="text" maxlength="200" autocomplete="off" spellcheck="false" data-edit-note-input="${escapeHtml(note.id)}" value="${escapeHtml(note.text)}" aria-label="${escapeHtml(localized('编辑笔记', 'Edit note'))}" /><button type="button" class="button primary" data-save-note="${escapeHtml(note.id)}">${escapeHtml(localized('保存', 'SAVE'))}</button><button type="button" class="button quiet" data-cancel-note>${escapeHtml(localized('取消', 'Cancel'))}</button></div>`
      : `<p class="agent-note-text">${escapeHtml(note.text)}</p>`;
    return `<div class="agent-note-row" data-note-id="${escapeHtml(note.id)}">
      <div class="agent-note-head">
        <span class="agent-note-author${isOwner ? ' is-owner' : ''}">${escapeHtml(formatNoteAuthor(note.author))}</span>
        <span class="agent-note-time">${escapeHtml(timeText)}</span>
        <span class="agent-note-actions">
          ${isEditing ? '' : `<button type="button" class="agent-note-icon-btn" data-edit-note="${escapeHtml(note.id)}" aria-label="${escapeHtml(localized('编辑笔记', 'Edit note'))}" title="${escapeHtml(localized('编辑笔记', 'Edit note'))}">${AGENT_NOTE_ICONS.edit}</button>`}
          <button type="button" class="agent-note-icon-btn delete" data-delete-note="${escapeHtml(note.id)}" aria-label="${escapeHtml(localized('删除笔记', 'Delete note'))}" title="${escapeHtml(localized('删除笔记', 'Delete note'))}">${AGENT_NOTE_ICONS.del}</button>
        </span>
      </div>
      ${body}
    </div>`;
  }).join('');
}

async function submitNewAgentNote() {
  if (agentNoteBusy || !editorExistingItem?.id) return;
  const input = $('#agent-note-input');
  const text = String(input?.value || '').trim();
  if (!text) {
    toast(localized('请先输入笔记内容', 'Enter a note first'), 'error');
    input?.focus();
    return;
  }
  agentNoteBusy = true;
  renderAgentNotes(editorExistingItem, { autoOpen: false });
  try {
    const updated = await api.addAgentNote(editorExistingItem.id, text);
    if (input) input.value = '';
    editingAgentNoteId = null;
    window.OpenKeyletAppearance?.play?.('success');
    toast(localized('已添加 Agent 笔记', 'Agent note added'));
    applyUpdatedAgentNotesItem(updated);
  } catch (error) {
    toast(cleanError(error), 'error');
  } finally {
    agentNoteBusy = false;
    renderAgentNotes(editorExistingItem, { autoOpen: false });
  }
}

async function saveEditedAgentNote(noteId) {
  if (agentNoteBusy || !editorExistingItem?.id || !noteId) return;
  const input = $(`[data-edit-note-input="${CSS.escape(noteId)}"]`);
  const text = String(input?.value || '').trim();
  if (!text) {
    toast(localized('请先输入笔记内容', 'Enter a note first'), 'error');
    input?.focus();
    return;
  }
  agentNoteBusy = true;
  renderAgentNotes(editorExistingItem, { autoOpen: false });
  try {
    const updated = await api.updateAgentNote(editorExistingItem.id, noteId, text);
    editingAgentNoteId = null;
    window.OpenKeyletAppearance?.play?.('success');
    toast(localized('已更新 Agent 笔记', 'Agent note updated'));
    applyUpdatedAgentNotesItem(updated);
  } catch (error) {
    toast(cleanError(error), 'error');
  } finally {
    agentNoteBusy = false;
    renderAgentNotes(editorExistingItem, { autoOpen: false });
  }
}

$('#agent-note-add')?.addEventListener('click', submitNewAgentNote);
$('#agent-note-input')?.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    event.preventDefault();
    event.stopPropagation();
    submitNewAgentNote();
  }
});
$('#agent-notes-locked')?.addEventListener('change', async (event) => {
  if (agentNoteBusy || !editorExistingItem?.id) return;
  const locked = Boolean(event.currentTarget.checked);
  agentNoteBusy = true;
  renderAgentNotes(editorExistingItem, { autoOpen: false });
  try {
    const updated = await api.setAgentNotesLocked(editorExistingItem.id, locked);
    window.OpenKeyletAppearance?.play?.('toggle');
    toast(locked
      ? localized('已锁定笔记，禁止 Agent 修改', 'Agent notes locked')
      : localized('已解锁笔记，允许 Agent 写入', 'Agent notes unlocked'));
    applyUpdatedAgentNotesItem(updated);
  } catch (error) {
    toast(cleanError(error), 'error');
  } finally {
    agentNoteBusy = false;
    renderAgentNotes(editorExistingItem, { autoOpen: false });
  }
});
$('#agent-notes-clear')?.addEventListener('click', async () => {
  if (agentNoteBusy || !editorExistingItem?.id) return;
  const confirmed = await confirmDestructiveAction({
    title: localized('清空全部 Agent 笔记？', 'Clear all agent notes?'),
    message: localized('此项目上所有已保存的 Agent 笔记都会被移除。', 'All saved agent notes on this item will be removed.'),
    confirmLabel: localized('清空', 'CLEAR'),
  });
  if (!confirmed || !editorExistingItem?.id) return;
  agentNoteBusy = true;
  renderAgentNotes(editorExistingItem, { autoOpen: false });
  try {
    const updated = await api.clearAgentNotes(editorExistingItem.id);
    editingAgentNoteId = null;
    window.OpenKeyletAppearance?.play?.('success');
    toast(localized('已清空全部 Agent 笔记', 'All agent notes cleared'));
    applyUpdatedAgentNotesItem(updated);
  } catch (error) {
    toast(cleanError(error), 'error');
  } finally {
    agentNoteBusy = false;
    renderAgentNotes(editorExistingItem, { autoOpen: false });
  }
});
$('#agent-notes-list')?.addEventListener('click', async (event) => {
  if (agentNoteBusy || !editorExistingItem?.id) return;
  const editBtn = event.target.closest('[data-edit-note]');
  if (editBtn) {
    editingAgentNoteId = editBtn.dataset.editNote;
    renderAgentNotes(editorExistingItem, { autoOpen: false });
    const editInput = $(`[data-edit-note-input="${CSS.escape(editingAgentNoteId)}"]`);
    editInput?.focus();
    editInput?.select();
    return;
  }
  const cancelBtn = event.target.closest('[data-cancel-note]');
  if (cancelBtn) {
    editingAgentNoteId = null;
    renderAgentNotes(editorExistingItem, { autoOpen: false });
    return;
  }
  const saveBtn = event.target.closest('[data-save-note]');
  if (saveBtn) {
    await saveEditedAgentNote(saveBtn.dataset.saveNote);
    return;
  }
  const delBtn = event.target.closest('[data-delete-note]');
  if (delBtn) {
    const noteId = delBtn.dataset.deleteNote;
    agentNoteBusy = true;
    renderAgentNotes(editorExistingItem, { autoOpen: false });
    try {
      const updated = await api.deleteAgentNote(editorExistingItem.id, noteId);
      if (editingAgentNoteId === noteId) editingAgentNoteId = null;
      window.OpenKeyletAppearance?.play?.('success');
      toast(localized('已删除该条笔记', 'Agent note deleted'));
      applyUpdatedAgentNotesItem(updated);
    } catch (error) {
      toast(cleanError(error), 'error');
    } finally {
      agentNoteBusy = false;
      renderAgentNotes(editorExistingItem, { autoOpen: false });
    }
  }
});
$('#agent-notes-list')?.addEventListener('keydown', (event) => {
  const input = event.target.closest('[data-edit-note-input]');
  if (!input) return;
  if (event.key === 'Enter') {
    event.preventDefault();
    event.stopPropagation();
    saveEditedAgentNote(input.dataset.editNoteInput);
  } else if (event.key === 'Escape') {
    event.preventDefault();
    event.stopPropagation();
    editingAgentNoteId = null;
    renderAgentNotes(editorExistingItem, { autoOpen: false });
  }
});

let migrationId = null;
let migrationMode = 'migration';
let migrationSequence = 0;
const migrationWarnings = {
  nonWebUris: ['非网页地址已保留，设为“不匹配”。','Non-web addresses are preserved with matching disabled.'],
  defaultDomainMatch: ['未指定规则的网址使用主域名匹配；保存的协议和端口必须一致。可在项目内调整。','Unspecified rules use base-domain matching, with matching scheme and port. Edit rules in the item.'],
  unsupportedTotp: ['部分验证码密钥格式尚不支持生成；原始密钥已保留。','Some TOTP formats cannot generate codes yet; their original keys are preserved.'],
  passkeyCounter: ['包含旧版计数型 Passkey。导入后请只在 OpenKeylet 中使用这些 Passkey，避免另一副本的计数超前。','Includes legacy counter-based passkeys. Use these only in OpenKeylet after migration to avoid diverging counters.'],
  linkedFields: ['关联字段已作为加密自定义字段保留，暂不自动关联填写。','Linked fields are preserved as encrypted custom fields; automatic linking is unavailable.'],
  passwordHistory: ['最近 20 条旧密码会进入密码历史，更早的记录保留在加密自定义字段中。','The latest 20 previous passwords appear in history; older records are archived in an encrypted custom field.'],
  reprompt: ['原逐项主密码验证设置不生效；本地 PIN 锁仍适用。','Source per-item master-password reprompt settings are not applied; the local PIN lock still applies.'],
  attachments: ['JSON 不含附件文件内容；请从原密码库单独保留附件。','JSON does not contain attachment files. Keep them separately from the source vault.'],
  organization: ['组织项目将成为本地个人项目，不保留共享权限。','Organization items become local personal items without sharing permissions.'],
  sshKeyNotFound: ['部分主机引用的本机私钥文件不存在或不可读，已仅导入主机与账号信息。','Some hosts referenced local key files that were missing or unreadable; host and user details were still imported.'],
};
function migrationHelp() {
  const format = $('#migration-format').value;
  $('#migration-scan-ssh')?.classList.toggle('hidden', format !== 'ssh_config');
  if (format === 'mvault') {
    $('#migration-help').textContent = localized(
      '选择 OpenKeylet .mvault 备份包（支持新版密码保护包及旧版 v3–v7 / CLI 自解锁包）。先预览条目与冲突重命名再确认合并。',
      'Choose an OpenKeylet .mvault package (supports current password-protected and legacy v3–v7 / CLI backups). Preview items and conflict renames before merging.'
    );
    return;
  }
  if (format === 'ssh_config') {
    $('#migration-help').textContent = localized(
      '扫描本机 ~/.ssh/config 或选择自定义 SSH 配置文件，自动导入主机、端口、用户名及关联的私钥文件（先预览再确认）。',
      'Scan your local ~/.ssh/config or choose an SSH config file to import hosts, ports, users, and linked private keys with a preview first.'
    );
    return;
  }
  if (format === 'env') {
    $('#migration-help').textContent = localized(
      '选择项目中的 .env 文件，把其中的 KEY=VALUE 加密存为一个安全项目（所有密钥默认对 Agent 隐藏，可通过 {{openkeylet:KEY}} 注入）。',
      'Choose a .env file to store its KEY=VALUE secrets encrypted in one vault item (hidden from agents by default; injectable via {{openkeylet:KEY}}).'
    );
    return;
  }
  $('#migration-help').textContent = format === 'bitwarden'
    ? localized('在 Bitwarden 中导出未加密 JSON，然后选择文件预览。原文件不变；导入的秘密会加密存入本地库。', 'Export unencrypted JSON from Bitwarden, then choose the file to preview. The source is unchanged; imported secrets are encrypted locally.')
    : localized('选择 Chrome 或 Edge 导出的密码 CSV。支持带引号、逗号和多行备注的文件。', 'Choose a password CSV exported by Chrome or Edge. Quoted fields, commas and multiline notes are supported.');
}
function resetMigration() {
  migrationSequence++; migrationId = null; migrationMode = 'migration';
  $('#migration-preview').replaceChildren(); $('#migration-preview').classList.add('hidden');
  $('#migration-confirm').classList.add('hidden');
  $('#migration-error').classList.add('hidden');
}
function closeMigration() {
  resetMigration(); $('#migration-modal').classList.add('hidden');
  api.cancelImport().catch(() => {});
  api.cancelBackupImport().catch(() => {});
}
let mvaultState = null;
let mvaultSequence = 0;

function setGlobalMvaultDropOverlay(visible, options = '') {
  const overlay = $('#global-mvault-drop-overlay');
  if (!overlay) return;
  if (visible) {
    const opts = typeof options === 'string'
      ? { mode: 'mvault', fileNames: options ? [options] : [] }
      : (options || {});
    const mode = opts.mode || 'mvault';
    const fileNames = Array.isArray(opts.fileNames) ? opts.fileNames.filter(Boolean) : [];
    const totalCount = Number(opts.totalCount || fileNames.length || 0);
    const titleEl = $('#global-mvault-drop-title');
    const subEl = $('#global-mvault-drop-subtitle');
    const chipEl = $('#global-mvault-drop-file');
    if (titleEl) {
      if (mode === 'universal') {
        titleEl.textContent = localized('松开即可智能提取并构建项目', 'Drop files to extract & build items');
      } else if (mode === 'mixed') {
        titleEl.textContent = localized('松开即可导入备份并提取文件', 'Drop to import backup & extract files');
      } else {
        titleEl.textContent = localized('松开即可导入 .mvault 备份', 'Drop .mvault backup to import');
      }
    }
    if (subEl) {
      if (mode === 'universal') {
        subEl.textContent = localized(
          '支持 Excel / Word / ZIP / .env / CSV / JSON / KeePass / 私钥 / 2FA 截图 / 文件夹等任意文件',
          'Supports Excel, Word, ZIP, .env, CSV, JSON, KeePass, SSH keys, 2FA QR, folders & any text'
        );
      } else if (mode === 'mixed') {
        subEl.textContent = localized(
          '自动弹窗勾选 .mvault 备份，同时提取其余文件至导入中心',
          'Opens .mvault selector and extracts other files into Import Hub'
        );
      } else {
        subEl.textContent = localized(
          '自动弹窗预览，可勾选需要导入的项目或全选',
          'Opens a preview popup where you can check specific items or select all'
        );
      }
    }
    if (chipEl) {
      let chipText = '';
      if (fileNames.length === 1 && totalCount <= 1) {
        chipText = opts.hasFolder ? `📁 ${fileNames[0]}` : fileNames[0];
      } else if (fileNames.length > 0) {
        const extra = Math.max(0, totalCount - fileNames.length);
        chipText = fileNames.slice(0, 2).join(' · ') + (extra > 0 || fileNames.length > 2 ? ` (+${Math.max(extra, fileNames.length - 2)})` : '');
      }
      chipEl.textContent = chipText;
      chipEl.classList.toggle('hidden', !chipText);
    }
    overlay.classList.remove('hidden');
  } else {
    overlay.classList.add('hidden');
  }
}

function closeMvaultImportModal(cancelBackend = true) {
  mvaultSequence++;
  mvaultState = null;
  const modal = $('#mvault-import-modal');
  if (modal) modal.classList.add('hidden');
  const pwInput = $('#mvault-unlock-password');
  if (pwInput) {
    pwInput.value = '';
    pwInput.type = 'password';
  }
  const revealBtn = $('#mvault-unlock-reveal');
  if (revealBtn) revealBtn.textContent = localized('显示', 'SHOW');
  const searchInput = $('#mvault-search-input');
  if (searchInput) searchInput.value = '';
  $('#mvault-unlock-panel')?.classList.add('hidden');
  $('#mvault-loading-panel')?.classList.add('hidden');
  $('#mvault-select-panel')?.classList.add('hidden');
  $('#mvault-unlock-error')?.classList.add('hidden');
  $('#mvault-select-error')?.classList.add('hidden');
  $('#mvault-item-list')?.replaceChildren();
  if (cancelBackend) api.cancelBackupImport().catch(() => {});
}

function mvaultCategoryKey(item) {
  return item.kind === 'trash' ? 'trash' : (item.itemType || 'custom');
}

function mvaultCategoryLabel(key) {
  if (key === 'all') return localized('全部', 'All');
  if (key === 'trash') return localized('回收站', 'Trash');
  return itemTypeLabel(key);
}

function mvaultFilteredItems() {
  if (!mvaultState?.items) return [];
  const q = String(mvaultState.searchQuery || '').trim().toLowerCase();
  const filter = mvaultState.activeTypeFilter || 'all';
  return mvaultState.items.filter((item) => {
    if (filter !== 'all' && mvaultCategoryKey(item) !== filter) return false;
    if (!q) return true;
    const hay = [
      item.name,
      item.assignedName || '',
      item.summary || '',
      item.folder || '',
      itemTypeLabel(item.itemType),
      item.kind === 'trash' ? 'trash 回收站' : '',
    ]
      .join(' ')
      .toLowerCase();
    return hay.includes(q);
  });
}

function renderMvaultHeader() {
  if (!mvaultState) return;
  $('#mvault-modal-title').textContent = localized('导入 .mvault 备份', 'Import .mvault backup');
  $('#mvault-file-name').textContent = mvaultState.fileName || 'openkeylet-backup.mvault';
  const formatPill = $('#mvault-format-pill');
  if (mvaultState.preview) {
    formatPill.textContent = mvaultState.preview.protected
      ? `v${mvaultState.preview.version}`
      : localized(`旧版 v${mvaultState.preview.version}`, `Legacy v${mvaultState.preview.version}`);
    formatPill.classList.remove('hidden');
  } else {
    formatPill.textContent = '';
    formatPill.classList.add('hidden');
  }
}

function renderMvaultUnlockPanel(errorMessage = '') {
  if (!mvaultState) return;
  renderMvaultHeader();
  $('#mvault-loading-panel').classList.add('hidden');
  $('#mvault-select-panel').classList.add('hidden');
  $('#mvault-unlock-panel').classList.remove('hidden');
  $('#mvault-unlock-help').textContent = localized(
    `输入「${mvaultState.fileName}」创建时设置的备份密码，解密后即可预览并勾选需要导入的项目。`,
    `Enter the backup password for "${mvaultState.fileName}" to preview and select items to import.`
  );
  $('#mvault-unlock-password-label').textContent = localized('备份密码', 'Backup password');
  $('#mvault-unlock-cancel').textContent = localized('取消', 'Cancel');
  $('#mvault-unlock-submit').textContent = localized('解锁并预览', 'Unlock & preview');
  $('#mvault-unlock-submit').disabled = false;
  const pwInput = $('#mvault-unlock-password');
  const revealBtn = $('#mvault-unlock-reveal');
  if (revealBtn) {
    revealBtn.textContent = pwInput?.type === 'text' ? localized('隐藏', 'HIDE') : localized('显示', 'SHOW');
  }
  const errEl = $('#mvault-unlock-error');
  if (errorMessage) {
    errEl.textContent = errorMessage;
    errEl.classList.remove('hidden');
  } else {
    errEl.textContent = '';
    errEl.classList.add('hidden');
  }
  requestAnimationFrame(() => {
    pwInput?.focus();
    if (errorMessage) pwInput?.select();
  });
}

function updateMvaultSelectionChrome() {
  if (!mvaultState) return;
  const selectAllInput = $('#mvault-select-all');
  const selectAllText = $('#mvault-select-all-text');
  const counterEl = $('#mvault-selection-counter');
  const confirmBtn = $('#mvault-select-confirm');
  const cancelBtn = $('#mvault-select-cancel');
  const hintEl = $('#mvault-footer-hint');
  if (cancelBtn) cancelBtn.textContent = localized('取消', 'Cancel');

  if (!mvaultState.hasItemList) {
    const p = mvaultState.preview || {};
    const count = (p.newItems ?? p.totalItems ?? 0) + (p.trashCount || 0);
    if (selectAllInput) {
      selectAllInput.checked = count > 0;
      selectAllInput.indeterminate = false;
      selectAllInput.disabled = true;
    }
    if (selectAllText) selectAllText.textContent = localized('全选', 'Select all');
    if (counterEl) counterEl.textContent = localized(`共 ${p.totalItems || 0} 项`, `${p.totalItems || 0} items`);
    if (hintEl) {
      hintEl.textContent = localized('同名冲突将自动另存，不覆盖已有项目', 'Conflicts are renamed safely without overwriting');
    }
    if (confirmBtn) {
      const canConfirm = (p.totalItems || 0) > 0 || (p.trashCount || 0) > 0;
      confirmBtn.disabled = !canConfirm || mvaultState.committing;
      confirmBtn.textContent = mvaultState.committing
        ? localized('正在导入…', 'Importing…')
        : localized('确认导入', 'Import');
    }
    return;
  }

  const allImportable = mvaultState.items.filter((item) => item.importable);
  const totalSelected = allImportable.filter((item) => item.selected).length;
  const visibleImportable = mvaultFilteredItems().filter((item) => item.importable);
  const visibleSelected = visibleImportable.filter((item) => item.selected).length;
  const isFiltered = (mvaultState.activeTypeFilter && mvaultState.activeTypeFilter !== 'all')
    || Boolean(String(mvaultState.searchQuery || '').trim());

  if (selectAllInput) {
    selectAllInput.disabled = visibleImportable.length === 0;
    selectAllInput.checked = visibleImportable.length > 0 && visibleSelected === visibleImportable.length;
    selectAllInput.indeterminate = visibleSelected > 0 && visibleSelected < visibleImportable.length;
  }
  if (selectAllText) {
    selectAllText.textContent = isFiltered
      ? localized('全选当前筛选', 'Select visible')
      : localized('全选', 'Select all');
  }
  if (counterEl) {
    counterEl.textContent = localized(
      `已选 ${totalSelected} / ${allImportable.length} 项`,
      `${totalSelected} / ${allImportable.length} selected`
    );
  }
  if (hintEl) {
    const selectedConflicts = mvaultState.items.filter((i) => i.selected && i.status === 'conflict').length;
    hintEl.textContent = selectedConflicts > 0
      ? localized(`含 ${selectedConflicts} 项同名冲突，将自动另存不覆盖`, `${selectedConflicts} conflict(s) will be safely renamed`)
      : localized('仅导入已勾选项目，不会覆盖已有数据', 'Only checked items are imported; existing items are untouched');
  }
  if (confirmBtn) {
    confirmBtn.disabled = totalSelected === 0 || mvaultState.committing;
    confirmBtn.textContent = mvaultState.committing
      ? localized('正在导入…', 'Importing…')
      : totalSelected > 0 && totalSelected === allImportable.length
        ? localized(`全量导入 (${totalSelected})`, `Import all (${totalSelected})`)
        : localized(`导入所选 (${totalSelected})`, `Import (${totalSelected})`);
  }
}

function renderMvaultItemList() {
  if (!mvaultState) return;
  const listEl = $('#mvault-item-list');
  if (!listEl) return;

  if (!mvaultState.hasItemList) {
    const p = mvaultState.preview || {};
    const lines = [
      `${mvaultState.fileName} · ${p.formatLabel || '.mvault'}`,
      localized(
        `共 ${p.totalItems || 0} 项 · 将新增 ${p.newItems || 0} 项 · 跳过相同 ${p.duplicateSkipped || 0} 项 · 同名安全重命名 ${p.nameConflicts || 0} 项`,
        `${p.totalItems || 0} items · ${p.newItems || 0} to add · ${p.duplicateSkipped || 0} identical skipped · ${p.nameConflicts || 0} renamed on conflict`
      ),
      ...(p.passkeyCount || p.trashCount || p.historyEntries
        ? [localized(
            `含 Passkey ${p.passkeyCount || 0} 个 · 密码历史 ${p.historyEntries || 0} 条 · 回收站 ${p.trashCount || 0} 项`,
            `Includes ${p.passkeyCount || 0} passkeys · ${p.historyEntries || 0} history entries · ${p.trashCount || 0} trashed items`
          )]
        : []),
      ...(p.sampleNames?.length
        ? [localized(`示例条目：${p.sampleNames.join('、')}`, `Sample items: ${p.sampleNames.join(', ')}`)]
        : []),
      ...(p.conflictRenames?.length
        ? [localized(`同名冲突将自动另存（不覆盖）：${p.conflictRenames.join('；')}`, `Conflicts safely renamed (no overwrite): ${p.conflictRenames.join('; ')}`)]
        : []),
    ];
    listEl.innerHTML = `<div class="mvault-empty-state" style="text-align:left">${lines.map((line) => `<p style="margin:4px 0">${escapeHtml(line)}</p>`).join('')}</div>`;
    updateMvaultSelectionChrome();
    return;
  }

  const visible = mvaultFilteredItems();
  if (!mvaultState.items.length) {
    listEl.innerHTML = `<div class="mvault-empty-state">${escapeHtml(localized('此备份文件为空，没有可导入的项目。', 'This backup file is empty — no items to import.'))}</div>`;
    updateMvaultSelectionChrome();
    return;
  }
  if (!visible.length) {
    listEl.innerHTML = `<div class="mvault-empty-state">${escapeHtml(localized('当前筛选或搜索条件下没有匹配的项目。', 'No items match the current search or filter.'))}</div>`;
    updateMvaultSelectionChrome();
    return;
  }

  listEl.innerHTML = visible.map((item) => {
    const isDup = !item.importable;
    const rowClasses = [
      'mvault-item-row',
      isDup ? 'is-duplicate' : (item.selected ? 'is-selected' : 'is-unchecked'),
    ].join(' ');
    const statusBadge = item.status === 'duplicate'
      ? `<span class="mvault-item-status is-dup" title="${escapeHtml(localized('当前密码库中已存在完全相同的条目', 'An identical item already exists in your vault'))}">${escapeHtml(localized('已存在', 'EXISTS'))}</span>`
      : item.status === 'conflict'
        ? `<span class="mvault-item-status is-conflict" title="${escapeHtml(localized('已有同名条目，导入时将自动另存不覆盖', 'Name conflict — will be renamed safely without overwriting'))}">${escapeHtml(localized('同名另存', 'RENAME'))}</span>`
        : `<span class="mvault-item-status is-new">${escapeHtml(localized('新增', 'NEW'))}</span>`;
    const metaChips = [];
    if (item.kind === 'trash') {
      metaChips.push(`<span class="mvault-meta-chip is-trash">${escapeHtml(localized('回收站', 'Trash'))}</span>`);
    }
    if (item.folder) {
      metaChips.push(`<span class="mvault-meta-chip">${escapeHtml(item.folder)}</span>`);
    }
    if (item.passkeyCount > 0) {
      metaChips.push(`<span class="mvault-meta-chip">${escapeHtml(localized(`Passkey ×${item.passkeyCount}`, `Passkey ×${item.passkeyCount}`))}</span>`);
    }
    if (item.historyCount > 0) {
      metaChips.push(`<span class="mvault-meta-chip">${escapeHtml(localized(`历史 ${item.historyCount}`, `History ${item.historyCount}`))}</span>`);
    }
    const subParts = [];
    if (item.assignedName) {
      subParts.push(`<span class="mvault-item-rename">→ ${escapeHtml(item.assignedName)}</span>`);
    }
    if (item.summary) {
      subParts.push(`<span class="mvault-item-summary">${escapeHtml(item.summary)}</span>`);
    }
    const subHtml = (subParts.length || metaChips.length)
      ? `<div class="mvault-item-sub">${subParts.join('')}${metaChips.join('')}</div>`
      : '';
    return `
      <label class="${rowClasses}" role="listitem" data-mvault-row="${escapeHtml(item.key)}">
        <input type="checkbox" class="mvault-checkbox" data-mvault-check="${escapeHtml(item.key)}" ${item.selected ? 'checked' : ''} ${isDup ? 'disabled' : ''} aria-label="${escapeHtml(item.name)}" />
        <div class="mvault-item-body">
          <div class="mvault-item-head">
            <span class="mvault-item-type">${escapeHtml(itemTypeLabel(item.itemType))}</span>
            <span class="mvault-item-name" title="${escapeHtml(item.name)}">${escapeHtml(item.name)}</span>
            ${statusBadge}
          </div>
          ${subHtml}
        </div>
      </label>
    `;
  }).join('');

  updateMvaultSelectionChrome();
}

function renderMvaultSelectPanel() {
  if (!mvaultState || !mvaultState.preview) return;
  renderMvaultHeader();
  $('#mvault-unlock-panel').classList.add('hidden');
  $('#mvault-loading-panel').classList.add('hidden');
  $('#mvault-select-panel').classList.remove('hidden');

  const p = mvaultState.preview;
  const statsEl = $('#mvault-stats-strip');
  const pills = [];
  const totalCount = mvaultState.hasItemList ? mvaultState.items.length : (p.totalItems || 0);
  pills.push(`<span class="mvault-stat-pill">${escapeHtml(localized(`共 ${totalCount} 项`, `${totalCount} total`))}</span>`);
  if ((p.newItems || 0) > 0) {
    pills.push(`<span class="mvault-stat-pill is-new">${escapeHtml(localized(`可新增 ${p.newItems}`, `${p.newItems} new`))}</span>`);
  }
  if ((p.nameConflicts || 0) > 0) {
    pills.push(`<span class="mvault-stat-pill is-conflict">${escapeHtml(localized(`同名另存 ${p.nameConflicts}`, `${p.nameConflicts} rename`))}</span>`);
  }
  if ((p.duplicateSkipped || 0) > 0) {
    pills.push(`<span class="mvault-stat-pill is-dup">${escapeHtml(localized(`已存在 ${p.duplicateSkipped}`, `${p.duplicateSkipped} existing`))}</span>`);
  }
  if ((p.trashCount || 0) > 0) {
    pills.push(`<span class="mvault-stat-pill">${escapeHtml(localized(`回收站 ${p.trashCount}`, `${p.trashCount} trash`))}</span>`);
  }
  statsEl.innerHTML = pills.join('');

  const legacyNote = $('#mvault-legacy-note');
  if (!p.protected) {
    legacyNote.textContent = localized(
      '安全提示：此文件为旧版无密码自解锁 .mvault，文件内含解锁密钥。导入后建议删除旧文件并重新导出带密码保护的备份。',
      'Security note: This is a legacy self-unlocking .mvault containing its own unlock key. Delete the old file after importing and export a password-protected backup.'
    );
    legacyNote.classList.remove('hidden');
  } else {
    legacyNote.textContent = '';
    legacyNote.classList.add('hidden');
  }

  const searchInput = $('#mvault-search-input');
  if (searchInput) {
    searchInput.placeholder = localized('搜索备份中的项目…', 'Search items in backup…');
    searchInput.parentElement?.classList.toggle('hidden', !mvaultState.hasItemList || mvaultState.items.length === 0);
  }

  const typePillsEl = $('#mvault-type-pills');
  if (typePillsEl) {
    if (mvaultState.hasItemList && mvaultState.items.length > 0) {
      const counts = new Map();
      for (const item of mvaultState.items) {
        const key = mvaultCategoryKey(item);
        counts.set(key, (counts.get(key) || 0) + 1);
      }
      if (counts.size > 1) {
        const keys = ['all', ...counts.keys()];
        typePillsEl.innerHTML = keys.map((key) => {
          const count = key === 'all' ? mvaultState.items.length : counts.get(key);
          const active = mvaultState.activeTypeFilter === key ? 'active' : '';
          return `<button type="button" class="mvault-type-pill ${active}" data-mvault-filter="${escapeHtml(key)}">${escapeHtml(mvaultCategoryLabel(key))} ${count}</button>`;
        }).join('');
        typePillsEl.classList.remove('hidden');
      } else {
        typePillsEl.innerHTML = '';
        typePillsEl.classList.add('hidden');
      }
    } else {
      typePillsEl.innerHTML = '';
      typePillsEl.classList.add('hidden');
    }
  }

  const selectErrorEl = $('#mvault-select-error');
  if (selectErrorEl) {
    selectErrorEl.textContent = '';
    selectErrorEl.classList.add('hidden');
  }

  renderMvaultItemList();
}

async function unlockAndPreviewMvault(password) {
  if (!mvaultState) return;
  const sequence = mvaultSequence;
  const submitBtn = $('#mvault-unlock-submit');
  if (submitBtn) submitBtn.disabled = true;
  $('#mvault-unlock-error')?.classList.add('hidden');
  $('#mvault-loading-text').textContent = localized('正在解密并分析备份内容…', 'Decrypting & analyzing backup…');
  $('#mvault-unlock-panel').classList.add('hidden');
  $('#mvault-select-panel').classList.add('hidden');
  $('#mvault-loading-panel').classList.remove('hidden');

  try {
    const result = await api.prepareBackupImport(password);
    if (!result || sequence !== mvaultSequence || !mvaultState) return;
    const pwInput = $('#mvault-unlock-password');
    if (pwInput) pwInput.value = '';
    mvaultState.id = result.id;
    mvaultState.preview = result.preview;
    const rawItems = result.preview?.items;
    if (Array.isArray(rawItems)) {
      mvaultState.hasItemList = true;
      mvaultState.items = rawItems.map((item) => {
        const importable = item.status !== 'duplicate';
        return {
          key: `${item.kind || 'item'}:${item.index}`,
          index: item.index,
          kind: item.kind || 'item',
          id: item.id || '',
          name: item.name || localized('未命名项目', 'Untitled'),
          itemType: item.itemType || 'custom',
          folder: item.folder || '',
          summary: item.summary || '',
          status: item.status || 'new',
          assignedName: item.assignedName || null,
          passkeyCount: Number(item.passkeyCount || 0),
          historyCount: Number(item.historyCount || 0),
          deletedAt: item.deletedAt || null,
          importable,
          selected: importable,
        };
      });
    } else {
      mvaultState.hasItemList = false;
      mvaultState.items = [];
    }
    renderMvaultSelectPanel();
  } catch (error) {
    if (sequence !== mvaultSequence || !mvaultState) return;
    const message = cleanError(error);
    if (mvaultState.requiresPassword) {
      renderMvaultUnlockPanel(message);
    } else {
      closeMvaultImportModal(true);
      toast(message, 'error');
    }
  }
}

async function openMvaultPreviewFlow(picked) {
  if (!picked) return;
  setModuleMenu(false);
  if (!$('#migration-modal')?.classList.contains('hidden')) {
    resetMigration();
    $('#migration-modal').classList.add('hidden');
  }
  mvaultSequence++;
  mvaultState = {
    fileName: picked.fileName || 'openkeylet-backup.mvault',
    requiresPassword: Boolean(picked.requiresPassword),
    id: null,
    preview: null,
    items: [],
    hasItemList: false,
    activeTypeFilter: 'all',
    searchQuery: '',
    committing: false,
  };
  const pwInput = $('#mvault-unlock-password');
  if (pwInput) {
    pwInput.value = '';
    pwInput.type = 'password';
  }
  const searchInput = $('#mvault-search-input');
  if (searchInput) searchInput.value = '';
  $('#mvault-import-modal').classList.remove('hidden');

  if (mvaultState.requiresPassword) {
    renderMvaultUnlockPanel('');
  } else {
    renderMvaultHeader();
    await unlockAndPreviewMvault('');
  }
}

async function handleDroppedMvaultFile(file) {
  if (!file) return;
  await refreshOwnerLock();
  if (!ownerLockState.unlocked) {
    toast(localized('请先解锁密码库后再拖入 .mvault 备份', 'Unlock OpenKeylet first before dropping a .mvault backup'), 'error');
    return;
  }
  if (file.size > 64 * 1024 * 1024) {
    toast(localized('备份文件超过 64 MiB 限制', 'Backup file exceeds the 64 MiB limit'), 'error');
    return;
  }
  try {
    const content = await file.text();
    const picked = await api.inspectDroppedBackupBytes(file.name || 'openkeylet-backup.mvault', content);
    if (!picked) return;
    await openMvaultPreviewFlow(picked);
  } catch (error) {
    toast(cleanError(error), 'error');
  }
}

$('#mvault-modal-close')?.addEventListener('click', () => closeMvaultImportModal(true));
$('#mvault-unlock-cancel')?.addEventListener('click', () => closeMvaultImportModal(true));
$('#mvault-select-cancel')?.addEventListener('click', () => closeMvaultImportModal(true));

$('#mvault-unlock-reveal')?.addEventListener('click', () => {
  const input = $('#mvault-unlock-password');
  const btn = $('#mvault-unlock-reveal');
  if (!input || !btn) return;
  const showing = input.type === 'text';
  input.type = showing ? 'password' : 'text';
  btn.textContent = showing ? localized('显示', 'SHOW') : localized('隐藏', 'HIDE');
  input.focus();
});

$('#mvault-unlock-panel')?.addEventListener('submit', (event) => {
  event.preventDefault();
  if (!mvaultState) return;
  const password = $('#mvault-unlock-password')?.value || '';
  if (!password) {
    renderMvaultUnlockPanel(localized('请输入备份密码', 'Enter the backup password'));
    return;
  }
  void unlockAndPreviewMvault(password);
});

$('#mvault-search-input')?.addEventListener('input', (event) => {
  if (!mvaultState) return;
  mvaultState.searchQuery = event.currentTarget.value || '';
  renderMvaultItemList();
});

$('#mvault-type-pills')?.addEventListener('click', (event) => {
  const pill = event.target.closest('[data-mvault-filter]');
  if (!pill || !mvaultState) return;
  mvaultState.activeTypeFilter = pill.dataset.mvaultFilter || 'all';
  for (const btn of $$('#mvault-type-pills [data-mvault-filter]')) {
    btn.classList.toggle('active', btn.dataset.mvaultFilter === mvaultState.activeTypeFilter);
  }
  renderMvaultItemList();
});

$('#mvault-select-all')?.addEventListener('change', (event) => {
  if (!mvaultState?.hasItemList) return;
  const checked = Boolean(event.currentTarget.checked);
  for (const item of mvaultFilteredItems()) {
    if (item.importable) item.selected = checked;
  }
  renderMvaultItemList();
});

$('#mvault-item-list')?.addEventListener('change', (event) => {
  const checkbox = event.target.closest('[data-mvault-check]');
  if (!checkbox || !mvaultState?.hasItemList) return;
  const key = checkbox.dataset.mvaultCheck;
  const item = mvaultState.items.find((entry) => entry.key === key);
  if (!item || !item.importable) return;
  item.selected = Boolean(checkbox.checked);
  const row = checkbox.closest('[data-mvault-row]');
  if (row) {
    row.classList.toggle('is-selected', item.selected);
    row.classList.toggle('is-unchecked', !item.selected);
  }
  updateMvaultSelectionChrome();
});

$('#mvault-select-confirm')?.addEventListener('click', async () => {
  if (!mvaultState?.id || mvaultState.committing) return;
  const sequence = mvaultSequence;
  mvaultState.committing = true;
  $('#mvault-select-error')?.classList.add('hidden');
  updateMvaultSelectionChrome();
  try {
    let result;
    if (mvaultState.hasItemList) {
      const selectedItemIndices = mvaultState.items
        .filter((item) => item.kind === 'item' && item.selected)
        .map((item) => item.index);
      const selectedTrashIndices = mvaultState.items
        .filter((item) => item.kind === 'trash' && item.selected)
        .map((item) => item.index);
      if (!selectedItemIndices.length && !selectedTrashIndices.length) {
        mvaultState.committing = false;
        updateMvaultSelectionChrome();
        return;
      }
      result = await api.commitBackupImport(mvaultState.id, selectedItemIndices, selectedTrashIndices);
    } else {
      result = await api.commitBackupImport(mvaultState.id);
    }
    if (sequence !== mvaultSequence) return;
    closeMvaultImportModal(false);
    window.OpenKeyletAppearance?.play?.('success');
    toastImportSummary(result);
    if (activePage === 'import') {
      window.OpenKeyletImportHub?.notifyExternalImportDone?.(result);
    }
    await refresh();
  } catch (error) {
    if (sequence !== mvaultSequence || !mvaultState) return;
    mvaultState.committing = false;
    const errEl = $('#mvault-select-error');
    if (errEl) {
      errEl.textContent = cleanError(error);
      errEl.classList.remove('hidden');
    }
    updateMvaultSelectionChrome();
  }
});
$('#migration-open').onclick = async () => {
  await refreshOwnerLock();
  if (!ownerLockState.unlocked) return;
  if ($('#migration-format').value === 'mvault') $('#migration-format').value = 'bitwarden';
  resetMigration(); migrationHelp(); $('#migration-modal').classList.remove('hidden');
};
$('#migration-close').onclick = closeMigration;
$('#migration-format').onchange = () => { resetMigration(); api.cancelImport().catch(() => {}); api.cancelBackupImport().catch(() => {}); migrationHelp(); };
$('#migration-select').onclick = async () => {
  if ($('#migration-format').value === 'mvault') {
    $('#migration-select').disabled = true;
    try {
      const picked = await api.pickBackupImportFile();
      if (!picked) return;
      await openMvaultPreviewFlow(picked);
    } catch (error) {
      $('#migration-error').textContent = cleanError(error);
      $('#migration-error').classList.remove('hidden');
    } finally {
      $('#migration-select').disabled = false;
    }
    return;
  }
  resetMigration(); const sequence = migrationSequence;
  $('#migration-select').disabled = true;
  try {
    const result = await api.prepareImport($('#migration-format').value);
    if (!result || sequence !== migrationSequence) return;
    migrationId = result.id;
    migrationMode = 'migration';
    const p = result.preview;
    const lines = [localized(`可导入 ${p.total} 项 · Passkey ${p.passkeys} 个`, `${p.total} items · ${p.passkeys} passkeys`),
      ...Object.entries(p.types).map(([type,count]) => `${itemTypeLabel(type)}: ${count}`),
      ...(p.skippedDeleted ? [localized(`跳过回收站项目 ${p.skippedDeleted} 项`, `Skipped ${p.skippedDeleted} deleted items`)] : []),
      ...p.warnings.map(key => migrationWarnings[key] ? localized(...migrationWarnings[key]) : key)];
    const preview = $('#migration-preview'); preview.replaceChildren(...lines.map(line => {const p = document.createElement('p'); p.textContent=line; return p;}));
    preview.classList.remove('hidden'); $('#migration-confirm').classList.toggle('hidden', p.total === 0);
  } catch(error) {
    if (sequence === migrationSequence) { $('#migration-error').textContent=cleanError(error); $('#migration-error').classList.remove('hidden'); }
  } finally { $('#migration-select').disabled = false; }
};
$('#migration-scan-ssh')?.addEventListener('click', async () => {
  resetMigration(); const sequence = migrationSequence;
  const btn = $('#migration-scan-ssh');
  btn.disabled = true;
  try {
    const result = await api.prepareSshConfigImport(true);
    if (!result || sequence !== migrationSequence) return;
    migrationId = result.id;
    migrationMode = 'migration';
    const p = result.preview;
    const lines = [
      ...(result.sourcePath ? [result.sourcePath] : []),
      localized(`可导入 ${p.total} 项 SSH 配置`, `${p.total} SSH host(s) ready to import`),
      ...Object.entries(p.types).map(([type, count]) => `${itemTypeLabel(type)}: ${count}`),
      ...p.warnings.map(key => migrationWarnings[key] ? localized(...migrationWarnings[key]) : key),
    ];
    const preview = $('#migration-preview');
    preview.replaceChildren(...lines.map(line => { const el = document.createElement('p'); el.textContent = line; return el; }));
    preview.classList.remove('hidden');
    $('#migration-confirm').classList.toggle('hidden', p.total === 0);
  } catch (error) {
    if (sequence === migrationSequence) { $('#migration-error').textContent = cleanError(error); $('#migration-error').classList.remove('hidden'); }
  } finally { btn.disabled = false; }
});
$('#migration-confirm').onclick = async () => {
  if (!migrationId) return;
  $('#migration-confirm').disabled = true;
  try {
    const result = migrationMode === 'mvault'
      ? await api.commitBackupImport(migrationId)
      : await api.commitImport(migrationId);
    closeMigration();
    toastImportSummary(result);
    await refresh();
  }
  catch(error) { $('#migration-error').textContent=cleanError(error); $('#migration-error').classList.remove('hidden'); }
  finally { $('#migration-confirm').disabled = false; }
};

document.addEventListener('click', async (event) => {
  if (event.target.closest('#title-search-toggle')) {
    const input = $('#title-search-input');
    if (pageSearch[activePage]) {
      pageSearch[activePage] = '';
      input.value = '';
      syncTitleSearch();
      if (activePage === 'connections') renderConnections();
      if (activePage === 'import') window.OpenKeyletImportHub?.render?.();
      if (activePage === 'activity') { activityVisibleCount = ACTIVITY_PAGE_SIZE; renderActivity(); }
      if (activePage === 'settings') applySettingsSearch();
    }
    input.focus({ preventScroll: true });
  }
  const filterButton = event.target.closest('.filter-strip button');
  if (filterButton && !switchSelectionPending) await selectFilterButton(filterButton);
  const languageButton = event.target.closest('[data-language]');
  if (languageButton) await setLanguage(languageButton.dataset.language);
  const nav = event.target.closest('[data-page]');
  if (nav) await selectPage(nav.dataset.page);
  const metricService = event.target.closest('[data-metric-section]');
  if (metricService) {
    const targetSection = metricService.dataset.metricSection;
    await selectPage('settings');
    if (settingsFilterOrder.includes(targetSection)) {
      currentSettingsFilter = targetSection;
      syncSettingsFilterControl();
      applySettingsSearch();
      $('.settings-layout').scrollTop = 0;
    }
  }
  const metricAction = event.target.closest('[data-metric-action]');
  if (metricAction) {
    const action = metricAction.dataset.metricAction;
    if (!window.__openkeyletMetricFocusCursor) window.__openkeyletMetricFocusCursor = {};
    const cursor = window.__openkeyletMetricFocusCursor;
    if (action === 'focus-repair-agent' || action === 'focus-linked-agents') {
      await selectPage('settings');
      if (pageSearch.settings) {
        pageSearch.settings = '';
        const searchInput = $('#title-search-input');
        if (searchInput) searchInput.value = '';
        syncTitleSearch();
      }
      currentSettingsFilter = 'MCP';
      syncSettingsFilterControl();
      applySettingsSearch();
      const selector = action === 'focus-repair-agent'
        ? '#agent-client-list .agent-client-row[data-agent-state="stale"], #agent-client-list .agent-client-row[data-agent-state="conflict"], #agent-client-list .agent-client-row[data-agent-state="error"]'
        : '#agent-client-list .agent-client-row[data-agent-state="registered"]';
      const rows = $$(selector);
      if (rows.length) {
        const nextIdx = ((cursor[action] ?? -1) + 1) % rows.length;
        cursor[action] = nextIdx;
        const targetRow = rows[nextIdx];
        targetRow.scrollIntoView({ behavior: 'smooth', block: 'center' });
        targetRow.classList.remove('is-focus-pulse');
        void targetRow.offsetWidth;
        targetRow.classList.add('is-focus-pulse');
        const focusTarget = (action === 'focus-repair-agent'
          ? $('[data-agent-action="repair"]', targetRow)
          : $('button', targetRow)) || targetRow;
        focusTarget.focus({ preventScroll: true });
        setTimeout(() => targetRow.classList.remove('is-focus-pulse'), 1700);
      } else {
        const mcpCard = $('[data-module="MCP / 02"]');
        mcpCard?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    } else if (action === 'focus-activity-errors' || action === 'focus-activity-all') {
      await selectPage('activity');
      if (pageSearch.activity) {
        pageSearch.activity = '';
        const searchInput = $('#title-search-input');
        if (searchInput) searchInput.value = '';
        syncTitleSearch();
      }
      currentActivityFilter = action === 'focus-activity-errors' ? 'error' : 'all';
      activityVisibleCount = ACTIVITY_PAGE_SIZE;
      renderActivity();
      const selector = action === 'focus-activity-errors'
        ? '#activity-list .activity-item[data-activity-status="error"]'
        : '#activity-list .activity-item';
      const rows = $$(selector);
      if (rows.length) {
        const nextIdx = action === 'focus-activity-errors'
          ? ((cursor[action] ?? -1) + 1) % rows.length
          : 0;
        cursor[action] = nextIdx;
        let targetRow = rows[nextIdx];
        const targetId = targetRow.dataset.activityId;
        if (action === 'focus-activity-errors' && targetId && !expandedActivityErrors.has(targetId)) {
          expandedActivityErrors.add(targetId);
          renderActivity();
          targetRow = $(`#activity-list .activity-item[data-activity-id="${CSS.escape(targetId)}"]`) || rows[nextIdx];
        }
        targetRow.scrollIntoView({ behavior: 'smooth', block: 'center' });
        targetRow.classList.remove('is-focus-pulse');
        void targetRow.offsetWidth;
        targetRow.classList.add('is-focus-pulse');
        const focusTarget = $('.activity-error', targetRow) || targetRow;
        focusTarget.focus({ preventScroll: true });
        setTimeout(() => targetRow.classList.remove('is-focus-pulse'), 1700);
      } else {
        $('.activity-panel').scrollTop = 0;
      }
    }
  }
  const windowButton = event.target.closest('[data-window-action]');
  if (windowButton) {
    if (windowButton.dataset.windowAction === 'close' && !$('#connection-modal').classList.contains('hidden')) await closeEditorWithDraft();
    await api.window(windowButton.dataset.windowAction);
    if (windowButton.dataset.windowAction === 'minimize') await refreshOwnerLock(false);
  }
  if (event.target.closest('#owner-lock-button')) {
    if (!$('#connection-modal').classList.contains('hidden')) await closeEditorWithDraft();
    await lockOwner();
  }
  const deleteDraftButton = event.target.closest('#delete-draft-button');
  if (deleteDraftButton && editorDrafts[0]) {
    const draft = editorDrafts[0];
    const draftId = draft.id;
    const draftName = draft.input?.name?.trim();
    if (!await confirmDestructiveAction({
      title: draftName
        ? localized(`删除草稿「${draftName}」？`, `Delete draft "${draftName}"?`)
        : localized('删除当前草稿？', 'Delete this draft?'),
      message: localized('草稿中的未保存内容将永久丢失。', 'Unsaved content in this draft will be permanently lost.'),
    })) return;
    try {
      await api.deleteDraft(draftId);
      editorDrafts = editorDrafts.filter((candidate) => candidate.id !== draftId);
      renderDrafts();
      (editorDrafts.length > 0 ? $('#drafts-button') : $('#add-connection-button')).focus();
      toast(editorDrafts.length > 0
        ? localized(`草稿已删除（还有 ${editorDrafts.length} 条待处理）`, `Draft deleted (${editorDrafts.length} remaining)`)
        : localized('草稿已删除', 'Draft deleted'));
    } catch (error) { toast(cleanError(error), 'error'); }
    return;
  }
  const draftsButton = event.target.closest('#drafts-button');
  if (draftsButton && editorDrafts[0]) await selectCreationMode('draft');
  const moduleButton = event.target.closest('#add-module-button');
  if (moduleButton) setModuleMenu(moduleButton.getAttribute('aria-expanded') !== 'true');
  else if (!event.target.closest('#module-menu')) setModuleMenu(false);
  const addModuleButton = event.target.closest('[data-add-module]');
  if (addModuleButton) addModule(addModuleButton.dataset.addModule);
  const templateButton = event.target.closest('[data-item-template]');
  if (templateButton) applyTemplate(templateButton.dataset.itemTemplate);
  if (event.target.closest('#add-connection-button') || event.target.closest('[data-action="add"]')) {
    await selectCreationMode('add');
  }
  if (event.target === $('#connection-modal')) await closeEditorWithDraft();
  if (event.target === $('#confirmation-modal') && confirmationResolver) finishConfirmation(false);
  if (event.target === $('#generator-modal')) closeGenerator();
  if (event.target === $('#backup-password-modal')) finishBackupPassword(null);
  if (event.target === $('#mvault-import-modal')) closeMvaultImportModal(true);
  if (event.target === $('#migration-modal')) closeMigration();
  if (event.target === $('#vault-management-modal')) closeVaultManagement();
  if (event.target.closest('[data-close-modal]')) await closeEditorWithDraft();
  const copyInput = event.target.closest('[data-copy-input]');
  const copyModule = event.target.closest('[data-copy-module-secret], [data-copy-module-value]');
  if (copyInput || copyModule) {
    const input = copyInput ? $(`#${copyInput.dataset.copyInput}`) : $('[data-secret-value], [data-module-value]', copyModule.closest('.module-row'));
    const isSensitive = Boolean(copyModule?.hasAttribute('data-copy-module-secret') || input?.hasAttribute('data-secret-value'));
    try {
      await api.copyOwnerValue(input.value, isSensitive);
      toast(isSensitive ? localized('已复制（30 秒后自动清除）', 'Copied · clears in 30s') : localized('已复制', 'Copied'));
    } catch (error) { toast(cleanError(error), 'error'); }
  }
  const toggleModuleSecret = event.target.closest('[data-toggle-module-secret]');
  if (toggleModuleSecret) {
    const field = $('[data-secret-value]', toggleModuleSecret.closest('.module-row'));
    const revealed = toggleModuleSecret.getAttribute('aria-pressed') !== 'true';
    if (field.tagName === 'INPUT') field.type = revealed ? 'text' : 'password';
    else field.classList.toggle('secret-masked', !revealed);
    toggleModuleSecret.setAttribute('aria-pressed', String(revealed));
    const label = revealed ? localized('隐藏明文', 'Hide secret') : localized('显示明文', 'Show secret');
    toggleModuleSecret.setAttribute('aria-label', label);
    toggleModuleSecret.title = label;
  }
  const toggleAgentVisible = event.target.closest('[data-module-agent-visible]');
  if (toggleAgentVisible) setModuleAgentVisibility(toggleAgentVisible, toggleAgentVisible.getAttribute('aria-pressed') !== 'true');
  const chooseModuleKey = event.target.closest('[data-choose-module-key]');
  if (chooseModuleKey) {
    try {
      const name = await api.chooseKey();
      if (name) {
        syncModuleDraft();
        const index = Number(chooseModuleKey.closest('.module-row').dataset.moduleIndex);
        currentModules[index].pending = true;
        currentModules[index].configured = true;
        currentModules[index].privateKeyName = name;
        renderModules();
      }
    } catch (error) { toast(cleanError(error), 'error'); }
  }
  const removeModuleButton = event.target.closest('[data-remove-module]');
  if (removeModuleButton) {
    syncModuleDraft();
    const row = removeModuleButton.closest('.module-row');
    const index = Number(row.dataset.moduleIndex);
    const removed = currentModules[index];
    if (!removed) return;
    const moduleName = removed.kind === 'customSecret' && removed.name.trim() ? removed.name.trim() : moduleLabel(removed.kind);
    if (!await confirmDestructiveAction({
      title: localized(`删除“${moduleName}”模块？`, `Delete the "${moduleName}" module?`),
      message: removed?.existing
        ? localized('保存项目后，该模块及其加密值将永久删除。', 'After you save the item, this module and its encrypted value will be permanently deleted.')
        : localized('该模块中尚未保存的内容将丢失。', 'Unsaved content in this module will be lost.'),
    })) return;
    if (!row.isConnected || $('#connection-modal').classList.contains('hidden')) return;
    if (removed?.existing && moduleSecretName(removed)) removedSecretFields.add(moduleSecretName(removed));
    currentModules.splice(index, 1);
    renderModules();
    const remainingRows = $$('.module-row', $('#module-list'));
    ($('[data-remove-module]', remainingRows[Math.min(index, remainingRows.length - 1)] || $('#module-list')) || $('#add-module-button')).focus();
  }
  const action = event.target.closest('[data-action]');
  if (action?.dataset.action === 'clear-connection-filters') {
    pageSearch.connections = '';
    currentItemTypeFilter = 'all';
    $('[data-page-search="connections"]').value = '';
    syncItemTypeFilter();
    syncTitleSearch();
    renderConnections();
  }
  if (action?.dataset.action === 'clear-activity-filters') {
    currentActivityFilter = 'all';
    pageSearch.activity = '';
    syncTitleSearch();
    activityVisibleCount = ACTIVITY_PAGE_SIZE;
    renderActivity();
  }
  if (action?.dataset.action === 'delete-activity' && action.dataset.activityId) {
    await deleteSingleActivity(action.dataset.activityId, action);
    return;
  }
  if (action?.dataset.id) {
    const item = state.connections.find((candidate) => candidate.id === action.dataset.id);
    if (action.dataset.action === 'toggle-enabled') {
      try {
        await api.setEnabled(item.id, !item.enabled);
        toast(item.enabled ? localized('项目已停用', 'Item disabled') : localized('项目已启用', 'Item enabled'));
        await refresh();
      } catch (error) { toast(cleanError(error), 'error'); }
    }
    if (action.dataset.action === 'edit') await openEditor(item);
    if (action.dataset.action === 'copy-item') await copyFullItem(item, action);
    if (action.dataset.action === 'history') await openVaultManagement('history', item.id);
    if (action.dataset.action === 'copy-name') {
      try {
        await api.copyOwnerValue(`use ${item.name} in OpenKeylet MCP`, false);
        toast(localized('OpenKeylet MCP 使用提示已复制', 'OpenKeylet MCP use prompt copied'));
      } catch (error) { toast(cleanError(error), 'error'); }
    }
    if (action.dataset.action === 'test') {
      await runSingleItemCheck(item, { showToast: true, doRefresh: true });
    }
    if (action.dataset.action === 'delete' && await confirmDestructiveAction({
      title: localized(`将“${item.name}”移入回收站？`, `Move "${item.name}" to trash?`),
      message: localized('项目将停止用于填写、Passkey 登录和 Agent 操作。你可以在回收站恢复它。', 'The item will stop being available for autofill, passkeys and agents. You can restore it from Trash.'),
      acceptLabel: localized('移入回收站', 'MOVE TO TRASH'),
    })) {
      try { await api.remove(item.id, item.updatedAt); toast(localized('已移入回收站', 'Moved to trash')); await refresh(); $('#vault-view-toggle')?.focus(); } catch (error) { toast(cleanError(error), 'error'); }
    }
  } else if (!action && !suppressItemClick) {
    const card = event.target.closest('.connection-card[data-item-id]');
    if (card && !event.target.closest('.card-actions, .item-toggle')) {
      const item = state.connections.find((candidate) => candidate.id === card.dataset.itemId);
      if (item) {
        $('[data-item-reorder]', card)?.focus({ preventScroll: true });
        await openEditor(item);
      }
    }
  }
  const errorDetail = event.target.closest('[data-expand-error]');
  if (errorDetail) {
    const expanded = errorDetail.getAttribute('aria-expanded') === 'true';
    if (expanded) expandedActivityErrors.delete(errorDetail.dataset.expandError);
    else expandedActivityErrors.add(errorDetail.dataset.expandError);
    errorDetail.setAttribute('aria-expanded', String(!expanded));
    errorDetail.classList.toggle('expanded', !expanded);
  }
  const copy = event.target.closest('[data-copy-format]');
  if (copy) {
    try { await api.copyConfig(copy.dataset.copyFormat); toast(localized('stdio 配置已复制', 'stdio configuration copied')); } catch (error) { toast(cleanError(error), 'error'); }
  }
  const agentAction = event.target.closest('[data-agent-action]');
  if (agentAction) {
    const kind = agentAction.dataset.agentAction;
    if (kind === 'remove') {
      const client = agentClients.find((candidate) => candidate.clientId === agentAction.dataset.clientId);
      if (!await confirmDestructiveAction({
        title: localized(`移除 ${client?.displayName || 'Agent'} 的 OpenKeylet 接入？`, `Remove OpenKeylet from ${client?.displayName || 'this agent'}?`),
        message: localized('将删除该 Agent 的 OpenKeylet MCP 配置；之后可以重新连接。', 'This removes the OpenKeylet MCP configuration from the agent. You can connect it again later.'),
        acceptLabel: localized('移除', 'REMOVE'),
        tag: localized('确认移除接入', 'CONFIRM INTEGRATION REMOVAL'),
      })) return;
    }
    try {
      const result = kind === 'connect'
        ? (await api.registerAgents([agentAction.dataset.clientId]))[0]
        : kind === 'repair'
          ? await api.repairAgent(agentAction.dataset.clientId)
          : await api.removeAgent(agentAction.dataset.clientId);
      if (result?.ok) {
        agentRestartRequired = true;
        $('#agent-restart-notice').classList.remove('hidden');
      }
      toast(result?.ok ? localized('已更新 · 新开 Agent 会话后生效', 'Updated · Open a new agent session to apply') : publicMessage(result?.message), result?.ok ? '' : 'error');
      await scanAgents();
    } catch (error) { toast(cleanError(error), 'error'); }
  }
});

document.addEventListener('input', (event) => {
  if (event.target.matches('.pin-cell-input')) {
    event.target.value = event.target.value.replace(/\D/g, '').slice(-1);
    if (event.target.value) {
      const inputs = $$('.pin-cell-input', event.target.closest('.pin-control'));
      inputs[inputs.indexOf(event.target) + 1]?.focus();
    }
  }
  if (event.target.closest('.module-row')) syncModuleDraft();
  const page = event.target.dataset.pageSearch;
  if (!page) return;
  pageSearch[page] = event.target.value;
  syncTitleSearch();
  if (page === 'connections') renderConnections();
  if (page === 'import') window.OpenKeyletImportHub?.render?.();
  if (page === 'activity') {
    activityVisibleCount = ACTIVITY_PAGE_SIZE;
    renderActivity();
  }
  if (page === 'settings') applySettingsSearch();
});

const itemList = $('#connections-list');

function updateItemGridRowHeight() {
  if (!itemList.clientHeight) return;
  const style = getComputedStyle(itemList);
  const gap = parseFloat(style.rowGap) || 0;
  const padding = (parseFloat(style.paddingTop) || 0) + (parseFloat(style.paddingBottom) || 0);
  const threeRowHeight = (itemList.clientHeight - padding - 2 * gap) / 3;
  const height = itemList.clientHeight > 540
    ? Math.min(156, Math.max(86, threeRowHeight))
    : Math.max(86, threeRowHeight);
  itemList.style.setProperty('--item-row-height', `${height}px`);
}
new ResizeObserver(updateItemGridRowHeight).observe(itemList);

function visibleItemIds() { return $$('.connection-card', itemList).map(row => row.dataset.itemId); }

async function saveItemOrder(visibleOrder, expectedOrder, focusedId) {
  if (itemOrderSaving) return;
  const visible = new Set(visibleOrder);
  let index = 0;
  // A filtered list rearranges only its own slots, leaving hidden items in place.
  const ids = expectedOrder.map(id => visible.has(id) ? visibleOrder[index++] : id);
  if (ids.every((id, position) => id === expectedOrder[position])) { renderConnections(); return; }
  itemOrderSaving = true;
  itemList.setAttribute('aria-busy', 'true');
  let saved = false;
  try { await api.reorder(ids, expectedOrder); saved = true; }
  catch (error) { toast(cleanError(error), 'error'); }
  finally {
    itemOrderSaving = false;
    renderedConnectionsSignature = '';
    await refresh(false);
    itemList.removeAttribute('aria-busy');
    const handle = $$('[data-item-reorder]', itemList).find(button => button.dataset.itemReorder === focusedId);
    handle?.focus({ preventScroll: true });
    if (saved) {
      handle?.scrollIntoView({ block: 'nearest' });
      const name = state.connections.find(item => item.id === focusedId)?.name || '';
      $('#item-reorder-status').textContent = localized(`${name}：第 ${ids.indexOf(focusedId) + 1} 项，共 ${ids.length} 项`, `${name}: position ${ids.indexOf(focusedId) + 1} of ${ids.length}`);
    }
  }
}

const ITEM_LONG_PRESS_MS = 220;

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
  for (const el of siblings) {
    firstRects.set(el, el.getBoundingClientRect());
  }
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
  window.OpenKeyletAppearance?.play?.('hover');
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
  if (!drag || drag.started || itemPointerDrag !== drag) return;
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
  host.dataset.view = vaultViewMode;
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
  const drag = itemPointerDrag;
  if (!drag?.started) return;
  const bounds = itemList.getBoundingClientRect();
  const isList = vaultViewMode === 'list';
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
    if (hit) {
      flipReorderCard(drag.row, hit.card, hit.idx > currentIdx);
    }
  }
}

function scheduleItemDragFrame() {
  const drag = itemPointerDrag;
  if (drag?.started && !drag.frame) drag.frame = requestAnimationFrame(itemDragFrame);
}

function itemDragFrame() {
  const drag = itemPointerDrag;
  if (!drag?.started) return;
  drag.frame = 0;
  const bounds = itemList.getBoundingClientRect(), previousScroll = itemList.scrollTop;
  if (drag.x >= bounds.left && drag.x <= bounds.right && drag.y >= bounds.top && drag.y <= bounds.bottom) {
    if (drag.y < bounds.top + 32) itemList.scrollTop -= Math.ceil((bounds.top + 32 - drag.y) / 3);
    else if (drag.y > bounds.bottom - 32) itemList.scrollTop += Math.ceil((drag.y - bounds.bottom + 32) / 3);
  }
  updateItemLivePosition();
  if (itemList.scrollTop !== previousScroll) scheduleItemDragFrame();
}

function finishItemPointerDrag(commit) {
  const drag = itemPointerDrag;
  if (!drag) return;
  itemPointerDrag = null;
  if (drag.longPressTimer) {
    clearTimeout(drag.longPressTimer);
    drag.longPressTimer = 0;
  }
  cancelAnimationFrame(drag.frame);
  try { if (itemList.hasPointerCapture(drag.pointerId)) itemList.releasePointerCapture(drag.pointerId); } catch (_) { /* Already released. */ }
  const finalIds = drag.started ? $$('.connection-card', itemList).map((el) => el.dataset.itemId) : [];
  drag.row.classList.remove('is-item-dragging');
  itemList.classList.remove('is-reordering');
  document.body.classList.remove('item-pointer-dragging');
  drag.preview?.remove();
  clearItemFlipTransforms();
  if (drag.started) {
    suppressItemClick = true;
    const changed = finalIds.length === drag.visibleOrder.length && finalIds.some((id, idx) => id !== drag.visibleOrder[idx]);
    if (commit && drag.valid) {
      window.OpenKeyletAppearance?.play?.('drop');
    }
    if (commit && drag.valid && changed) {
      void saveItemOrder(finalIds, drag.expectedOrder, drag.id);
    } else {
      restoreItemDomOrder(drag.visibleOrder);
      renderConnections();
    }
  }
}

itemList.addEventListener('dragstart', event => {
  if (event.target.closest?.('.connection-card')) event.preventDefault();
});
document.addEventListener('pointerdown', () => {
  suppressItemClick = false;
}, true);
itemList.addEventListener('pointerdown', event => {
  const card = event.target.closest?.('.connection-card[data-item-id]');
  if (!card || event.target.closest?.('.card-actions, .item-toggle')) return;
  if (event.button !== 0 || !event.isPrimary || event.ctrlKey || event.metaKey || event.shiftKey || itemPointerDrag || itemOrderSaving || confirmationResolver || !ownerLockState.unlocked) return;
  const id = card.dataset.itemId;
  const item = state.connections.find((candidate) => candidate.id === id);
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
    expectedOrder: state.connections.map((candidate) => candidate.id),
    longPressTimer: 0,
  };
  drag.longPressTimer = setTimeout(() => {
    if (itemPointerDrag === drag && !drag.started) {
      beginItemDragLift(drag);
    }
  }, ITEM_LONG_PRESS_MS);
  itemPointerDrag = drag;
});
document.addEventListener('pointermove', event => {
  const drag = itemPointerDrag;
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
document.addEventListener('pointerup', event => {
  if (itemPointerDrag?.pointerId !== event.pointerId) return;
  if (itemPointerDrag.started) {
    event.preventDefault();
    updateItemLivePosition();
  }
  finishItemPointerDrag(true);
});
document.addEventListener('pointercancel', event => { if (itemPointerDrag?.pointerId === event.pointerId) finishItemPointerDrag(false); });
itemList.addEventListener('lostpointercapture', event => { if (itemPointerDrag?.pointerId === event.pointerId) finishItemPointerDrag(false); });
window.addEventListener('blur', () => finishItemPointerDrag(false));
document.addEventListener('click', event => {
  if (!suppressItemClick) return;
  suppressItemClick = false;
  if (event.detail === 0) return;
  event.preventDefault(); event.stopImmediatePropagation();
}, true);
itemList.addEventListener('keydown', event => {
  const handle = event.target.closest?.('[data-item-reorder]');
  if (!handle || itemPointerDrag || itemOrderSaving || confirmationResolver || !ownerLockState.unlocked || event.altKey || event.ctrlKey || event.metaKey || !['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
  event.preventDefault(); event.stopPropagation();
  const ids = visibleItemIds(), id = handle.dataset.itemReorder, from = ids.indexOf(id);
  const step = vaultViewMode === 'list'
    ? { ArrowUp: -1, ArrowDown: 1, ArrowLeft: -1, ArrowRight: 1 }[event.key]
    : { ArrowUp: -4, ArrowDown: 4, ArrowLeft: -1, ArrowRight: 1 }[event.key];
  const to = event.key === 'Home' ? 0 : event.key === 'End' ? ids.length - 1 : Math.max(0, Math.min(ids.length - 1, from + step));
  if (to === from) return;
  ids.splice(from, 1); ids.splice(to, 0, id);
  void saveItemOrder(ids, state.connections.map(item => item.id), id);
});

let modulePointerDrag = null;
let suppressModuleClick = false;
const moduleList = $('#module-list');
const MODULE_LONG_PRESS_MS = 240;

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
    if (Math.abs(dy) < 0.5) continue;
    if (reduced) continue;
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
  if (!drag || drag.started || modulePointerDrag !== drag) return;
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
  try { moduleList.setPointerCapture(drag.pointerId); } catch (_) { /* document tracking remains active */ }
  window.OpenKeyletAppearance?.play?.('select');

  const initX = Math.max(8, Math.min(rect.left, window.innerWidth - rect.width - 8));
  const initY = Math.max(8, Math.min(rect.top, window.innerHeight - rect.height - 8));
  drag.preview.style.transform = `translate3d(${initX}px, ${initY}px, 0)`;
}

function updateModuleLivePosition() {
  const drag = modulePointerDrag;
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
  const drag = modulePointerDrag;
  if (drag?.started && !drag.frame) drag.frame = requestAnimationFrame(moduleDragFrame);
}

function moduleDragFrame() {
  const drag = modulePointerDrag;
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

function finishModulePointerDrag(commit) {
  const drag = modulePointerDrag;
  if (!drag) return;
  modulePointerDrag = null;
  if (drag.longPressTimer) {
    clearTimeout(drag.longPressTimer);
    drag.longPressTimer = 0;
  }
  cancelAnimationFrame(drag.frame);
  try { if (moduleList.hasPointerCapture(drag.pointerId)) moduleList.releasePointerCapture(drag.pointerId); } catch (_) { /* already released */ }
  drag.row.classList.remove('is-dragging');
  moduleList.classList.remove('is-sorting');
  document.body.classList.remove('module-pointer-dragging');
  drag.preview?.remove();
  clearModuleFlipTransforms();
  if (drag.started) {
    if (commit && drag.valid) {
      window.OpenKeyletAppearance?.play?.('drop');
      syncModuleDraft();
      announceModuleOrder(drag.row);
    } else if (drag.initialOrder?.length) {
      for (const row of drag.initialOrder) {
        if (row.parentElement === moduleList) moduleList.appendChild(row);
      }
      syncModuleDraft();
    }
  }
}

function announceModuleOrder(row) {
  const rows = $$('.module-row', moduleList);
  const name = $('[data-module-name]', row)?.value.trim() || moduleLabel(row.dataset.kind);
  const position = rows.indexOf(row) + 1;
  $('#module-reorder-status').textContent = localized(`${name}：第 ${position} 项，共 ${rows.length} 项`, `${name}: position ${position} of ${rows.length}`);
}

moduleList.addEventListener('dragstart', (event) => {
  if (event.target.closest?.('.module-row')) event.preventDefault();
});
moduleList.addEventListener('pointerdown', (event) => {
  if (event.button !== 0 || !event.isPrimary || event.ctrlKey || event.metaKey || event.shiftKey || confirmationResolver || modulePointerDrag) return;
  const row = event.target.closest?.('.module-row');
  if (!row) return;
  // Never steal pointer from inputs, buttons, switches, or action icons.
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
    if (modulePointerDrag === drag && !drag.started) {
      beginModuleDragLift(drag);
    }
  }, MODULE_LONG_PRESS_MS);
  modulePointerDrag = drag;
});
moduleList.addEventListener('keydown', (event) => {
  const handle = event.target.closest?.('[data-module-drag-handle]');
  if (!handle || event.target.matches?.('input, textarea, select') || confirmationResolver || modulePointerDrag || !['ArrowUp', 'ArrowDown'].includes(event.key)) return;
  event.preventDefault();
  const row = handle.closest('.module-row');
  const sibling = event.key === 'ArrowUp' ? row.previousElementSibling : row.nextElementSibling;
  if (!sibling) return;
  flipReorderModuleRow(row, sibling, event.key === 'ArrowDown');
  syncModuleDraft();
  handle.focus({ preventScroll: true });
  row.scrollIntoView({ block: 'nearest' });
  announceModuleOrder(row);
});
document.addEventListener('pointermove', (event) => {
  const drag = modulePointerDrag;
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
  if (!modulePointerDrag || event.pointerId !== modulePointerDrag.pointerId) return;
  if (modulePointerDrag.started) {
    event.preventDefault();
    updateModuleLivePosition();
    suppressModuleClick = true;
    setTimeout(() => { suppressModuleClick = false; }, 0);
  }
  finishModulePointerDrag(true);
});
document.addEventListener('pointercancel', (event) => {
  if (modulePointerDrag?.pointerId === event.pointerId) finishModulePointerDrag(false);
});
moduleList.addEventListener('lostpointercapture', (event) => {
  if (modulePointerDrag?.pointerId === event.pointerId) finishModulePointerDrag(false);
});
document.addEventListener('click', (event) => {
  if (!suppressModuleClick) return;
  suppressModuleClick = false;
  if (event.target.closest?.('.module-row')) {
    event.preventDefault();
    event.stopImmediatePropagation();
  }
}, true);
window.addEventListener('blur', () => {
  if (modulePointerDrag) finishModulePointerDrag(false);
});

document.addEventListener('paste', (event) => {
  if (!event.target.matches('.pin-cell-input')) return;
  const digits = event.clipboardData?.getData('text').replace(/\D/g, '').slice(0, 6) || '';
  if (!digits) return;
  event.preventDefault();
  const inputs = $$('.pin-cell-input', event.target.closest('.pin-control'));
  inputs.forEach((input, index) => { input.value = digits[index] || ''; });
  (inputs[Math.min(digits.length, inputs.length) - 1] || inputs[0])?.focus();
});

function trapFocusInContainer(container, event, extraElements = []) {
  const selector = 'button:not(:disabled), input:not(:disabled):not([type="hidden"]), select:not(:disabled), textarea:not(:disabled), summary, [tabindex="0"]';
  const controls = [...$$(selector, container), ...extraElements.flatMap(el => $$(selector, el))]
    .filter(control => control.getClientRects().length && !control.closest('[inert], .hidden'));
  if (!controls.length) return;
  const first = controls[0], last = controls.at(-1);
  if ((event.shiftKey && (document.activeElement === first || !controls.includes(document.activeElement))) ||
    (!event.shiftKey && (document.activeElement === last || !controls.includes(document.activeElement)))) {
    event.preventDefault();
    (event.shiftKey ? last : first).focus();
  }
}

function topSecondaryModal() {
  for (const [id, close] of [
    ['#backup-password-modal', () => finishBackupPassword(null)],
    ['#mvault-import-modal', () => closeMvaultImportModal(true)],
    ['#generator-modal', closeGenerator],
    ['#migration-modal', closeMigration],
    ['#vault-management-modal', closeVaultManagement],
  ]) {
    const el = $(id);
    if (el && !el.classList.contains('hidden')) return { el, close };
  }
  return null;
}

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && switchPointerDrag) {
    event.preventDefault(); void finishSwitchDrag(false); return;
  }
  if (event.key === 'Escape' && itemPointerDrag) {
    event.preventDefault(); finishItemPointerDrag(false); return;
  }
  if (confirmationResolver) {
    if (event.key === 'Escape') {
      event.preventDefault();
      finishConfirmation(false);
      return;
    }
    if (event.key === 'Tab') {
      const buttons = [$('#confirmation-cancel'), $('#confirmation-accept')];
      const index = buttons.indexOf(document.activeElement);
      event.preventDefault();
      buttons[(index + (event.shiftKey ? -1 : 1) + buttons.length) % buttons.length].focus();
    }
    return;
  }
  if (event.key === 'Escape' && modulePointerDrag) {
    event.preventDefault();
    finishModulePointerDrag(false);
    return;
  }
  const lockedOverlayVisible = !$('#owner-lock-layer').classList.contains('hidden');
  if (lockedOverlayVisible) {
    if (event.key === 'Tab') trapFocusInContainer($('#owner-lock-layer'), event);
    if (event.key === 'Escape' && ownerPinSetupRequested && !ownerLockState.pinConfigured) {
      event.preventDefault();
      $('#owner-pin-cancel')?.click();
    }
    return;
  }
  if ((event.ctrlKey || event.metaKey) && !event.altKey && event.shiftKey && event.key.toLowerCase() === 'l' && ownerLockState.pinConfigured && ownerLockState.unlocked) {
    event.preventDefault();
    void lockOwner();
    return;
  }
  const secondaryModal = topSecondaryModal();
  if (secondaryModal && !event.defaultPrevented) {
    if (event.key === 'Escape') {
      event.preventDefault();
      secondaryModal.close();
      return;
    }
    if (event.key === 'Tab') {
      trapFocusInContainer(secondaryModal.el, event);
      return;
    }
    if (isMacOS && event.metaKey && !event.ctrlKey && !event.altKey && event.key.toLowerCase() === 'w') {
      event.preventDefault();
      secondaryModal.close();
      return;
    }
  }
  if (githubBackup.isOpen() && !event.defaultPrevented) {
    if (event.key === 'Escape') {
      event.preventDefault();
      $('#github-modal-close')?.click();
      return;
    }
    if (isMacOS && event.metaKey && !event.ctrlKey && !event.altKey && event.key.toLowerCase() === 'w') {
      event.preventDefault();
      $('#github-modal-close')?.click();
      return;
    }
  }
  // Like Bricktone's WorkspaceDialog, keep keyboard navigation in the editor.
  // Nested dialogs keep their own keyboard handling and draft saving stays intact.
  const editor = $('#connection-modal');
  const editorIsTopmost = !editor.classList.contains('hidden') &&
    !$$('.modal-backdrop:not(.hidden)').some(modal => modal !== editor);
  if (editorIsTopmost && !event.defaultPrevented) {
    const menu = $('#module-menu');
    if (event.key === 'Escape') {
      event.preventDefault();
      if (!menu.classList.contains('hidden')) { setModuleMenu(false); $('#add-module-button').focus(); }
      else void closeEditorWithDraft();
      return;
    }
    if (event.key === 'Tab') {
      trapFocusInContainer(editor, event, !editor.contains(menu) && !menu.classList.contains('hidden') ? [menu] : []);
      return;
    }
    if ((event.ctrlKey || event.metaKey) && !event.altKey && event.key.toLowerCase() === 's') {
      event.preventDefault();
      $('#connection-form')?.requestSubmit();
      return;
    }
    if (isMacOS && event.metaKey && !event.ctrlKey && !event.altKey && event.key.toLowerCase() === 'w') {
      event.preventDefault();
      void closeEditorWithDraft();
      return;
    }
  }
  if (event.target.closest('.creation-options') && ['ArrowLeft', 'ArrowRight'].includes(event.key)) {
    event.preventDefault();
    const button = $(event.key === 'ArrowLeft' ? '#add-connection-button' : '#drafts-button');
    if (!button.disabled) { button.focus(); button.click(); }
    return;
  }
  if (event.target.matches('.pin-cell-input')) {
    const inputs = $$('.pin-cell-input', event.target.closest('.pin-control'));
    const index = inputs.indexOf(event.target);
    if (event.key === 'Backspace' && !event.target.value && index > 0) {
      event.preventDefault();
      inputs[index - 1].value = '';
      inputs[index - 1].focus();
      return;
    }
    if (event.key === 'ArrowLeft' && index > 0) { event.preventDefault(); inputs[index - 1].focus(); return; }
    if (event.key === 'ArrowRight' && index < inputs.length - 1) { event.preventDefault(); inputs[index + 1].focus(); return; }
  }
  const filterButton = event.target.closest?.('.filter-strip button');
  if (filterButton && !switchSelectionPending && ['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) {
    event.preventDefault();
    const strip = filterButton.closest('.filter-strip');
    const buttons = $$('button', strip);
    const index = buttons.findIndex(button => button.getAttribute('aria-pressed') === 'true');
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? buttons.length - 1 : (index + (event.key === 'ArrowLeft' ? -1 : 1) + buttons.length) % buttons.length;
    void selectFilterButton(buttons[next]).then(() => $('[aria-pressed="true"]', strip).focus());
    return;
  }
  const noModalOpen = !$$('.modal-backdrop:not(.hidden)').length && $('#owner-lock-layer').classList.contains('hidden');
  if (noModalOpen && (event.ctrlKey || event.metaKey) && !event.altKey) {
    const key = event.key.toLowerCase();
    if (key === 'f' || key === 'k') {
      event.preventDefault();
      setTitleSearchOpen(true);
      const search = $(`[data-page-search="${activePage}"]`);
      search?.focus();
      search?.select();
      return;
    }
    if (key === 'n' && !event.shiftKey) {
      event.preventDefault();
      void selectPage('connections').then(() => selectCreationMode('add'));
      return;
    }
    if (key === ',') {
      event.preventDefault();
      void selectPage('settings');
      return;
    }
    if (key === '1' || key === '2' || key === '3' || key === '4') {
      event.preventDefault();
      void selectPage({ 1: 'connections', 2: 'import', 3: 'activity', 4: 'settings' }[key]);
      return;
    }
    if (isMacOS && event.metaKey && !event.ctrlKey && key === 'w') {
      event.preventDefault();
      void api.window('close');
      return;
    }
  }
  if (event.key === 'Delete' || event.key === 'Backspace') {
    const focusedActivity = event.target.closest?.('#activity-list .activity-item[data-activity-id]');
    if (noModalOpen && activePage === 'activity' && focusedActivity && !event.target.closest?.('input, textarea, select')) {
      event.preventDefault();
      void deleteSingleActivity(focusedActivity.dataset.activityId, $('[data-action="delete-activity"]', focusedActivity));
      return;
    }
  }
  if (event.key === 'Escape') {
    const search = event.target.closest?.('[data-page-search]');
    if (search?.value) {
      const page = search.dataset.pageSearch;
      search.value = '';
      pageSearch[page] = '';
      if (page === 'connections') renderConnections();
      if (page === 'import') window.OpenKeyletImportHub?.render?.();
      if (page === 'activity') { activityVisibleCount = ACTIVITY_PAGE_SIZE; renderActivity(); }
      if (page === 'settings') applySettingsSearch();
    }
    if (event.target.closest?.('#title-search')) { event.preventDefault(); setTitleSearchOpen(false); }
  }
});

$('#connection-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('#save-connection-button');
  button.disabled = true;
  try {
    const input = serializeItem();
    const pastedClipboard = editorSmartClipboardSource;
    const onCandidateSaved = editorCandidateOnSaved;
    const savedDraftId = currentDraftId;
    await api.save(input);
    if (savedDraftId) {
      await api.deleteDraft(savedDraftId);
      editorDrafts = editorDrafts.filter((draft) => draft.id !== savedDraftId);
      renderDrafts();
    }
    currentDraftId = '';
    closeEditor();
    onCandidateSaved?.();
    let clearedClipboard = false;
    if (pastedClipboard) {
      clearedClipboard = await api.clearClipboardIfMatches(pastedClipboard).catch(() => false);
    }
    window.OpenKeyletAppearance?.play?.('success');
    const remainingDrafts = savedDraftId ? editorDrafts.length : 0;
    toast(clearedClipboard
      ? localized('项目已加密保存，并已自动清理剪贴板', 'Item saved and clipboard cleared')
      : remainingDrafts > 0
        ? localized(`项目已加密保存（还有 ${remainingDrafts} 条待处理草稿）`, `Item saved and encrypted · ${remainingDrafts} draft(s) remaining`)
        : localized('项目已加密保存', 'Item saved and encrypted'));
    await refresh();
    await refreshDrafts();
  } catch (error) { toast(cleanError(error), 'error'); } finally { button.disabled = false; }
});
$('#owner-strong-reveal')?.addEventListener('click', () => {
  const input = $('#owner-strong-secret');
  const btn = $('#owner-strong-reveal');
  if (!input || !btn) return;
  const showing = input.type === 'text';
  input.type = showing ? 'password' : 'text';
  btn.textContent = showing ? localized('显示', 'SHOW') : localized('隐藏', 'HIDE');
  input.focus();
});
$('#owner-lock-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const strongMode = Boolean(ownerLockState.strongMode || ownerLockState.mode === 'strong');
  const button = $('#owner-unlock-action');
  const cancelButton = $('#owner-pin-cancel');
  let credential = '';
  if (strongMode) {
    credential = $('#owner-strong-secret')?.value || '';
    if (!credential.trim()) {
      return toast(localized('请输入强主密码或 okv1_ 恢复密钥', 'Enter your master passphrase or okv1_ recovery key'), 'error');
    }
  } else {
    credential = readPin('owner-pin');
    if (!/^\d{6}$/.test(credential)) return toast(localized('PIN 必须是六位数字', 'PIN must contain six digits'), 'error');
    if (!ownerLockState.pinConfigured && credential !== readPin('owner-pin-confirm')) return toast(localized('两次 PIN 不一致', 'PIN entries do not match'), 'error');
  }
  button.disabled = true;
  cancelButton.disabled = true;
  try {
    const settingPin = !strongMode && !ownerLockState.pinConfigured;
    ownerLockState = (strongMode || ownerLockState.pinConfigured)
      ? await api.ownerUnlock(credential)
      : await api.ownerSetPin(credential);
    credential = '';
    if ($('#owner-strong-secret')) $('#owner-strong-secret').value = '';
    ownerPinSetupRequested = false;
    window.OpenKeyletAppearance?.play?.(settingPin ? 'success' : 'unlock');
    renderOwnerLock();
    if (settingPin) toast(localized('PIN 锁已开启', 'PIN lock enabled'));
    await refresh(false);
    await refreshDrafts(true);
  } catch (error) {
    toast(cleanError(error), 'error');
    if (strongMode) {
      if ($('#owner-strong-secret')) {
        $('#owner-strong-secret').value = '';
        $('#owner-strong-secret').focus();
      }
    } else {
      clearPin('owner-pin');
      focusPin('owner-pin');
    }
  } finally {
    button.disabled = false;
    cancelButton.disabled = false;
  }
});
$('#owner-pin-cancel').addEventListener('click', () => {
  ownerPinSetupRequested = false;
  renderOwnerLock();
  renderSettings();
});
$('#confirmation-modal').addEventListener('click', (event) => {
  if (event.target === $('#confirmation-modal') || event.target.closest('#confirmation-cancel')) finishConfirmation(false);
  if (event.target.closest('#confirmation-accept')) finishConfirmation(true);
});
$('#clear-activity-button').addEventListener('click', async () => {
  const matched = getFilteredActivities();
  const filtering = isActivityFilterActive() && matched.length < state.activities.length;
  if (filtering) {
    if (!matched.length) return;
    const count = matched.length;
    if (!await confirmDestructiveAction({
      title: localized(`删除当前筛选的 ${count} 条记录？`, `Delete ${count} matching log entries?`),
      message: localized('仅删除当前筛选结果中的本地操作记录，其余记录将保留。', 'Only matching local activity entries will be permanently deleted. Other entries will be kept.'),
      acceptLabel: localized('删除', 'DELETE'),
      tag: localized('确认清空记录', 'CONFIRM LOG DELETION'),
    })) return;
    try {
      const ids = matched.map(({ activity }) => activity.id);
      await api.deleteActivities(ids);
      ids.forEach((id) => expandedActivityErrors.delete(id));
      toast(localized(`已删除 ${count} 条操作记录`, `Deleted ${count} log entries`));
      await refresh();
    } catch (error) { toast(cleanError(error), 'error'); }
    return;
  }
  if (!state.activities.length) return;
  if (!await confirmDestructiveAction({
    title: localized('清空本地操作记录？', 'Clear the local activity log?'),
    message: localized('全部本地操作记录将永久删除。', 'All local activity entries will be permanently deleted.'),
    acceptLabel: localized('清空', 'CLEAR'),
    tag: localized('确认清空记录', 'CONFIRM LOG DELETION'),
  })) return;
  try {
    await api.clear();
    currentActivityFilter = 'all';
    pageSearch.activity = '';
    expandedActivityErrors.clear();
    syncTitleSearch();
    toast(localized('已清空操作记录', 'Activity log cleared'));
    await refresh();
  } catch (error) { toast(cleanError(error), 'error'); }
});
$('#save-browser-settings-button').addEventListener('click', saveBrowserSettings);
$('#browser-enabled').addEventListener('change', saveBrowserSettings);
$('#browser-agent-passkey-enabled').addEventListener('change', saveBrowserSettings);
$('#start-pairing-button').addEventListener('click', async (event) => {
  const port = Number($('#browser-port').value);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    toast(localized('本地端口须在 1024–65535 之间', 'Local port must be between 1024 and 65535'), 'error');
    return;
  }
  const button = event.currentTarget;
  button.disabled = true;
  try {
    await api.quickPair(port);
    $('#browser-enabled').checked = true;
    toast(localized('已开启 5 分钟自动配对窗口，支持连续连接多个 Chrome 账号', '5-minute auto-pairing window open. Multiple Chrome profiles can connect automatically.'));
    await refresh(false);
  } catch (error) {
    toast(cleanError(error), 'error');
  } finally {
    button.disabled = false;
  }
});
$('#test-browser-bridge-button').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    const info = await api.testBrowserBridge();
    const tabCount = Array.isArray(info?.tabs) ? info.tabs.length : 0;
    const formCount = Array.isArray(info?.loginForms) ? info.loginForms.length : 0;
    const passkeyCount = Array.isArray(info?.pendingPasskeys) ? info.pendingPasskeys.length : 0;
    const activeTarget = info?.origin || localized('当前标签页非网页', 'Active tab is not a web page');
    toast(localized(
      `扩展连接正常 · ${activeTarget}（${tabCount} 个网页标签，${formCount} 个登录表单，${passkeyCount} 个待处理 Passkey）`,
      `Extension connected · ${activeTarget} (${tabCount} web tabs, ${formCount} login forms, ${passkeyCount} pending passkeys)`,
    ));
  } catch (error) {
    toast(cleanError(error), 'error');
  } finally {
    renderSettings();
  }
});
if (!isMacOS) $('#desktop-shortcut-enabled').addEventListener('change', (event) => setSystemIntegration('desktop', event.currentTarget.checked));
$('#launch-at-login-enabled').addEventListener('change', (event) => setSystemIntegration('startup', event.currentTarget.checked));
$('#pin-enabled').addEventListener('change', savePinSettings);
$('#close-behavior').addEventListener('change', saveDesktopSettings);
$('#owner-auto-lock-minutes').addEventListener('change', saveDesktopSettings);
$('#auto-check-enabled')?.addEventListener('change', saveDesktopSettings);
$('#auto-check-interval-minutes')?.addEventListener('change', saveDesktopSettings);
const BROWSER_EXTENSIONS_URL = 'chrome://extensions/';
$('#browser-extensions-url').addEventListener('click', (event) => {
  event.currentTarget.select();
});
$('#copy-extensions-url-button').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    await api.copyOwnerValue(BROWSER_EXTENSIONS_URL, false);
    $('#browser-extensions-url').select();
    const port = Number($('#browser-port').value);
    let pairingArmed = false;
    if (Number.isInteger(port) && port >= 1024 && port <= 65535) {
      try {
        await api.quickPair(port);
        $('#browser-enabled').checked = true;
        pairingArmed = true;
        await refresh(false);
      } catch {}
    }
    toast(pairingArmed
      ? localized(
          `已复制 ${BROWSER_EXTENSIONS_URL}，并已开启自动配对窗口`,
          `Copied ${BROWSER_EXTENSIONS_URL}. Auto-pairing window is open.`,
        )
      : localized(
          `已复制 ${BROWSER_EXTENSIONS_URL}，请粘贴到 Chrome 地址栏`,
          `Copied ${BROWSER_EXTENSIONS_URL}. Paste it into Chrome's address bar.`,
        ));
  } catch (error) {
    toast(cleanError(error), 'error');
  } finally {
    button.disabled = false;
  }
});
$('#quick-pairing-button').addEventListener('click', async event => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    $('#browser-open-help').hidden = true;
    let copyError = null;
    try {
      await api.copyOwnerValue(BROWSER_EXTENSIONS_URL, false);
      $('#browser-open-help').hidden = false;
    } catch (error) { copyError = error; }
    let pairingError = null;
    try {
      await api.quickPair(Number($('#browser-port').value));
      $('#browser-enabled').checked = true;
    } catch (error) { pairingError = error; }
    let browserError = null;
    const selectedProfile = $('#chrome-profile-select')?.value || null;
    try { await api.openChrome(selectedProfile); } catch (error) { browserError = error; }
    if (copyError) toast(cleanError(copyError), 'error');
    else if (pairingError && browserError) toast(localized('配对失败，且无法打开 Chrome。请检查 Browser Bridge 并手动打开 Chrome。', 'Pairing failed and Chrome could not be opened. Check Browser Bridge and open Chrome manually.'), 'error');
    else if (pairingError) toast(cleanError(pairingError), 'error');
    else if (browserError) toast(localized('地址已复制，请手动打开 Chrome 并粘贴。', 'Address copied. Open Chrome and paste it manually.'), 'error');
    else toast(localized('地址已复制，5 分钟自动配对窗口已开启。', 'Address copied. 5-minute auto-pairing window is open.'));
    await refresh(false);
  } catch (error) {
    toast(cleanError(error), 'error');
  } finally {
    button.disabled = false;
  }
});
$('#reload-extension-button')?.addEventListener('click', async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    const count = await api.reloadBrowserExtension();
    window.OpenKeyletAppearance?.play?.('success');
    toast(count > 0
      ? localized(`已通知 ${count} 个浏览器插件热重载`, `Reload signal sent to ${count} browser extension(s)`)
      : localized('当前没有已连接的浏览器插件', 'No connected browser extensions to reload'));
    setTimeout(() => { void refresh(false); }, 900);
  } catch (error) {
    toast(cleanError(error), 'error');
  } finally {
    button.disabled = !state?.browserBridge?.connected;
  }
});
$('#reset-pairing-button').addEventListener('click', async () => {
  if (!await confirmDestructiveAction({
    title: localized('重置浏览器配对？', 'Reset browser pairing?'),
    message: localized('所有已配对扩展会立即失效，需要重新配对才能继续使用。', 'Every paired extension will be revoked immediately and must be paired again.'),
    acceptLabel: localized('重置', 'RESET'),
    tag: localized('确认重置配对', 'CONFIRM PAIRING RESET'),
  })) return;
  try { await api.resetPair(); toast(localized('配对已重置', 'Pairing reset')); await refresh(); } catch (error) { toast(cleanError(error), 'error'); }
});
$('#open-extension-button').addEventListener('click', () => api.extensionFolder().catch((error) => toast(cleanError(error), 'error')));
$('#open-data-button').addEventListener('click', () => api.dataFolder().catch((error) => toast(cleanError(error), 'error')));
$('#rescan-agents').addEventListener('click', () => scanAgents(true));
$('#header-export-backup-button').addEventListener('click', (event) => exportBackup(event.currentTarget));
$('#header-import-backup-button').addEventListener('click', (event) => importBackup(event.currentTarget));
$('#safe-export-backup-button')?.addEventListener('click', (event) => exportBackup(event.currentTarget));
$('#safe-import-backup-button')?.addEventListener('click', (event) => importBackup(event.currentTarget));

let generatorTarget = null, generatorSequence = 0;
let backupPasswordResolve = null, backupPasswordExport = false;
function finishBackupPassword(result) {
  $('#backup-password-form').reset(); $('#backup-password-modal').classList.add('hidden');
  const resolve = backupPasswordResolve; backupPasswordResolve = null; resolve?.(result);
}
function askBackupPassword(exporting, fileName = '') {
  setModuleMenu(false);
  finishBackupPassword(null); backupPasswordExport = exporting;
  $('#backup-password-title').textContent = exporting ? localized('导出加密备份', 'EXPORT ENCRYPTED BACKUP') : localized('输入备份密码', 'UNLOCK .MVAULT BACKUP');
  $('#backup-password-help').textContent = exporting
    ? localized('设置至少 12 个字符的备份密码。恢复时需要此密码，请妥善保管。', 'Use a backup password of at least 12 characters. Keep it for restoration.')
    : fileName
      ? localized(`输入「${fileName}」创建时设置的备份密码，验证后将先展示导入预览。`, `Enter the backup password for "${fileName}" to preview its contents before importing.`)
      : localized('输入创建备份时设置的密码；旧版自动解锁备份可留空。', 'Enter the backup password. Leave blank for older automatically unlocked backups.');
  const submitButton = $('#backup-password-form button[type="submit"]');
  if (submitButton) {
    submitButton.textContent = exporting
      ? localized('选择保存位置', 'CHOOSE DESTINATION')
      : fileName
        ? localized('解密并预览', 'UNLOCK & PREVIEW')
        : localized('选择文件', 'CHOOSE FILE');
  }
  $('#backup-password-confirm-field').classList.toggle('hidden', !exporting);
  $('#backup-password').required = exporting || Boolean(fileName);
  $('#backup-password-confirm').required = exporting;
  $('#backup-password-modal').classList.remove('hidden'); $('#backup-password').focus();
  return new Promise(resolve => { backupPasswordResolve = resolve; });
}
$('#backup-password-close').onclick = () => finishBackupPassword(null);
$('#backup-password-form').onsubmit = e => {
  e.preventDefault();
  const password = $('#backup-password').value;
  if (backupPasswordExport && ([...password].length < 12 || password !== $('#backup-password-confirm').value))
    return toast(localized('密码须至少 12 个字符，且两次输入一致', 'Use at least 12 characters and matching passwords'), 'error');
  finishBackupPassword(password);
};
function closeGenerator() {
  generatorSequence++;
  $('#generator-modal').classList.add('hidden'); $('#generator-result').value = ''; generatorTarget = null;
}
async function generatePassword() {
  const sequence = ++generatorSequence;
  try {
    const options = { length: Number($('#generator-length').value) };
    for (const key of ['uppercase', 'lowercase', 'digits', 'symbols']) options[key] = $(`#generator-${key}`).checked;
    const result = await invoke('generate_password', { options });
    if (sequence === generatorSequence && !$('#generator-modal').classList.contains('hidden')) $('#generator-result').value = result;
  } catch (error) { toast(cleanError(error), 'error'); }
}
function openGenerator(target = null) {
  setModuleMenu(false);
  generatorTarget = target; $('#generator-use').classList.toggle('hidden', !target);
  $('#generator-modal').classList.remove('hidden'); generatePassword();
  requestAnimationFrame(() => $('#generator-length')?.focus());
}
$('#generator-open').onclick = () => openGenerator();
$('#generator-close').onclick = closeGenerator;
$('#generator-regenerate').onclick = generatePassword;
$('#generator-copy').onclick = async () => { try { if ($('#generator-result').value) { await api.copyOwnerValue($('#generator-result').value, true); toast(localized('已复制（30 秒后自动清除）', 'Copied · clears in 30s')); } } catch(error) { toast(cleanError(error), 'error'); } };
$('#generator-use').onclick = () => {
  if (generatorTarget?.isConnected && $('#generator-result').value) { generatorTarget.value = $('#generator-result').value; generatorTarget.dispatchEvent(new Event('input', { bubbles:true })); syncModuleDraft(); }
  closeGenerator();
};
document.addEventListener('click', e => {
  const button = e.target.closest('[data-generate-password]');
  if (button) openGenerator($('[data-secret-value]', button.closest('.module-row')));
  const totpButton = e.target.closest('[data-copy-totp-code]');
  if (totpButton) {
    const secret = $('[data-secret-value]', totpButton.closest('.module-row'))?.value?.trim() || '';
    if (!secret) { toast(localized('请先输入 TOTP 密钥', 'Enter a TOTP setup key first'), 'error'); return; }
    invoke('copy_totp_code', { secret })
      .then((res) => toast(localized(`2FA 验证码已复制（剩余 ${res?.remainingSeconds ?? 30}s，30 秒后清除）`, `2FA code copied (${res?.remainingSeconds ?? 30}s left · clears in 30s)`)))
      .catch((error) => toast(cleanError(error), 'error'));
  }
});

$('#page-activity .activity-panel').addEventListener('scroll', (event) => {
  const panel = event.currentTarget;
  if (panel.scrollHeight - panel.scrollTop - panel.clientHeight < 160) queueMoreActivities();
}, { passive: true });

window.__TAURI__.event.listen('state-changed', async () => { await refresh(false); await refreshDrafts(); });
window.__TAURI__.event.listen('tray-command', async (event) => {
  const action = event?.payload?.action;
  if (!action) return;
  await refreshOwnerLock(false);
  if (!ownerLockState.unlocked) return;
  if (action === 'new-item') {
    await selectPage('connections');
    await selectCreationMode('add');
  } else if (action === 'smart-import') {
    await selectPage('import');
  } else if (action === 'settings') {
    await selectPage('settings');
  } else if (action === 'update') {
    const indicator = $('#title-update-indicator');
    if (indicator && !indicator.classList.contains('hidden')) {
      indicator.click();
    } else {
      await selectPage('settings');
      const updateCard = $('[data-module="UPDATE / 07"]');
      updateCard?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }
});
window.__TAURI__.event.listen('pin-setup-requested', async () => {
  await refreshOwnerLock(false);
  if (ownerLockState.pinConfigured) return;
  ownerPinSetupRequested = true;
  renderOwnerLock();
  if (state) renderSettings();
});
window.addEventListener('focus', async () => { await refresh(false); await refreshOwnerLock(false); await refreshDrafts(); });
window.addEventListener('resize', positionModuleMenu);
$('.form-scroll', $('#connection-modal')).addEventListener('scroll', positionModuleMenu, { passive: true });
$('#connections-list').addEventListener('scroll', positionModuleMenu, { passive: true });
setInterval(() => { if ($('#page-activity').classList.contains('active')) refresh(false); }, 2000);
setInterval(() => { if (!document.hidden && $('#connection-modal').classList.contains('hidden') && $('#page-connections').classList.contains('active')) refresh(false); }, 2000);
let lastOwnerTouchAt = 0;
function touchOwnerActivity() {
  if (!ownerLockState.pinConfigured || !ownerLockState.unlocked || !Number(state?.settings?.ownerAutoLockMinutes || 0)) return;
  const now = Date.now();
  if (now - lastOwnerTouchAt < 20_000) return;
  lastOwnerTouchAt = now;
  api.ownerTouch().then((next) => {
    if (next && typeof next.unlocked === 'boolean') {
      const wasUnlocked = ownerLockState.unlocked;
      ownerLockState = next;
      if (wasUnlocked && next.pinConfigured && !next.unlocked) {
        renderOwnerLock();
        refresh(false);
      }
    }
  }).catch(() => {});
}
window.addEventListener('pointerdown', touchOwnerActivity, { passive: true });
window.addEventListener('keydown', touchOwnerActivity, { passive: true });
setInterval(() => {
  if (ownerLockState.pinConfigured && ownerLockState.unlocked && Number(state?.settings?.ownerAutoLockMinutes || 0) > 0) {
    refreshOwnerLock(false);
  }
}, 15_000);
let extensionDragStart = null, extensionDragBusy = false;
$('#drag-extension-button').addEventListener('pointerdown', event => { if(event.button === 0) extensionDragStart = {x:event.clientX,y:event.clientY}; });
window.addEventListener('pointerup', () => { extensionDragStart = null; });
window.addEventListener('pointercancel', () => { extensionDragStart = null; });
$('#drag-extension-button').addEventListener('pointermove', async event => {
  if(event.buttons !== 1 || !extensionDragStart || extensionDragBusy || Math.hypot(event.clientX-extensionDragStart.x,event.clientY-extensionDragStart.y)<5)return;
  extensionDragStart=null; extensionDragBusy=true;
  try { await invoke('drag_browser_extension'); } catch(error) { toast(cleanError(error), 'error'); } finally { extensionDragBusy=false; }
});
$('#drag-extension-button').addEventListener('dragstart', event => event.preventDefault());
$('#drag-extension-button').addEventListener('keydown', event => { if(event.key==='Enter' || event.key===' ') { event.preventDefault(); api.extensionFolder().catch(error=>toast(cleanError(error),'error')); } });

$('#check-all-button')?.addEventListener('click', () => {
  if (checkAllRunning) return;
  if (lastCheckAllOutcome) {
    clearCheckAllResults();
    return;
  }
  void runCheckAll();
});

$('#vault-view-toggle')?.addEventListener('click', () => {
  setVaultViewMode(vaultViewMode === 'list' ? 'grid' : 'list');
});

document.fonts?.ready?.then(() => {
  syncListActionsWidth();
});

(() => {
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
      btn.addEventListener('mousedown', (event) => {
        event.preventDefault();
      });
      btn.addEventListener('click', () => {
        if (!btn.disabled) commitOption(opt.value);
      });
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
      if (event.key === 'Tab') {
        closeSelectMenu(false);
        return;
      }
      if (event.key === 'ArrowDown') {
        event.preventDefault();
        setActiveIndex(activeIndex + 1);
        return;
      }
      if (event.key === 'ArrowUp') {
        event.preventDefault();
        setActiveIndex(activeIndex - 1);
        return;
      }
      if (event.key === 'Home') {
        event.preventDefault();
        setActiveIndex(0);
        return;
      }
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
})();

async function applySmartParseToEditor(parsed, options = {}) {
  const sourceInput = parsed?.input;
  if (!sourceInput) return;
  const modalHidden = $('#connection-modal').classList.contains('hidden');
  if (modalHidden) {
    const opened = await openEditor(null, null);
    if (!opened) return;
  } else if (editorExistingItem) {
    // Do not overwrite an existing item being edited; close draft first and open fresh.
    if (!await closeEditorWithDraft()) return;
    const opened = await openEditor(null, null);
    if (!opened) return;
  }
  editorSourceInput = sourceInput;
  editorSmartClipboardSource = options.clipboardSource || '';
  editorSmartTotpUri = parsed.totpUri || '';
  const uniqueName = (() => {
    const base = String(sourceInput.name || '').trim() || localized('智能导入项目', 'Imported item');
    if (!state?.connections?.some((item) => item.name.trim().toLowerCase() === base.toLowerCase())) return base;
    let index = 2;
    while (state.connections.some((item) => item.name.trim().toLowerCase() === `${base} (${index})`.toLowerCase())) index++;
    return `${base} (${index})`;
  })();
  value('#connection-name', uniqueName);
  value('#connection-description', sourceInput.description || '');
  $('#connection-type').innerHTML = typeOptions('', sourceInput.itemType || 'custom');
  value('#connection-folder', sourceInput.folder || '');
  renderLoginUris(sourceInput.loginUris || []);
  editingAgentNoteId = null;
  renderAgentNotes(null);
  $('#connection-enabled').checked = sourceInput.enabled ?? true;
  $('#template-picker').classList.add('hidden');
  const ownerValues = draftSecretValues(sourceInput.secrets);
  const privateKeyName = sourceInput.secrets?.privateKeyName || '';
  currentModules = (sourceInput.modules || []).map((module) => {
    const secretName = module.kind === 'customSecret' ? module.name : module.kind;
    return {
      ...module,
      secretValue: ownerValues[secretName] || '',
      configured: Boolean(ownerValues[secretName]),
      existing: false,
      privateKeyName: module.kind === 'privateKey' ? privateKeyName : '',
      pending: false,
      agentVisible: typeof module.agentVisible === 'boolean' ? module.agentVisible : defaultModuleAgentVisible(module.kind),
    };
  });
  renderModules();

  const banner = $('#smart-parse-banner');
  if (banner) {
    $('#smart-parse-badge').textContent = localized(parsed.labelZh || parsed.label, parsed.label);
    $('#smart-parse-summary').textContent = parsed.summary || '';
    const warningsEl = $('#smart-parse-warnings');
    if (parsed.warnings?.length) {
      warningsEl.textContent = parsed.warnings.join(' · ');
      warningsEl.classList.remove('hidden');
    } else {
      warningsEl.textContent = '';
      warningsEl.classList.add('hidden');
    }
    const attachWrap = $('#smart-totp-attach');
    const targetSelect = $('#smart-totp-target');
    if (parsed.totpUri && state?.connections?.length && attachWrap && targetSelect) {
      const issuer = (parsed.totpIssuer || '').toLowerCase();
      const sorted = [...state.connections].sort((a, b) => {
        const aMatch = issuer && a.name.toLowerCase().includes(issuer) ? 1 : 0;
        const bMatch = issuer && b.name.toLowerCase().includes(issuer) ? 1 : 0;
        if (aMatch !== bMatch) return bMatch - aMatch;
        return (a.itemType === 'login' ? 0 : 1) - (b.itemType === 'login' ? 0 : 1);
      });
      targetSelect.replaceChildren(...sorted.map((item) => {
        const opt = document.createElement('option');
        opt.value = item.id;
        opt.textContent = item.name;
        return opt;
      }));
      attachWrap.classList.remove('hidden');
    } else if (attachWrap) {
      attachWrap.classList.add('hidden');
    }
    banner.classList.remove('hidden');
  }
  toast(localized(`已智能识别：${parsed.labelZh || parsed.label}`, `Detected: ${parsed.label}`));
}

async function openCandidateInEditor(candidate, onSaved = null) {
  if (!candidate?.input) return;
  await applySmartParseToEditor({
    input: candidate.input,
    label: candidate.badge || 'IMPORT',
    labelZh: candidate.badgeZh || candidate.badge || '导入',
    summary: candidate.summary || '',
    warnings: [],
    totpUri: candidate.totpUri || '',
  });
  editorCandidateOnSaved = typeof onSaved === 'function' ? onSaved : null;
}

async function smartIngestText(rawText, options = {}) {
  const text = String(rawText || '').trim();
  if (!text) return toast(localized('剪贴板为空，请先复制 API Key、cURL、SSH、.env 或 2FA', 'Clipboard is empty — copy an API key, cURL, SSH, .env, or 2FA URI first'), 'error');
  await refreshOwnerLock();
  if (!ownerLockState.unlocked) return;
  try {
    const parsed = await api.smartParseText(text, options.filename || null, options.url || null);
    await applySmartParseToEditor(parsed, { clipboardSource: options.fromClipboard ? rawText : '' });
  } catch (error) {
    toast(cleanError(error), 'error');
  }
}

async function triggerSmartPasteFromClipboard() {
  await refreshOwnerLock();
  if (!ownerLockState.unlocked) return;
  try {
    // Try image from clipboard first (e.g. screenshot of a 2FA QR code).
    if (navigator.clipboard?.read && window.OpenKeyletQR?.supported) {
      try {
        const items = await navigator.clipboard.read();
        for (const item of items) {
          const imgType = item.types.find((t) => t.startsWith('image/'));
          if (imgType) {
            const blob = await item.getType(imgType);
            const decoded = await window.OpenKeyletQR.decode(blob);
            await smartIngestText(decoded, { fromClipboard: false });
            return;
          }
        }
      } catch (_) {
        // Fallback to text clipboard read below.
      }
    }
    let text = '';
    try { text = await api.readOwnerClipboard(); } catch (_) {}
    if (!text && navigator.clipboard?.readText) {
      try { text = await navigator.clipboard.readText(); } catch (_) {}
    }
    await smartIngestText(text, { fromClipboard: true });
  } catch (error) {
    toast(cleanError(error), 'error');
  }
}

async function handleSmartFile(file) {
  if (!file) return;
  await refreshOwnerLock();
  if (!ownerLockState.unlocked) return;
  try {
    if (file.type?.startsWith('image/') || /\.(png|jpe?g|webp|gif|bmp)$/i.test(file.name || '')) {
      if (!window.OpenKeyletQR?.decode) throw new Error(localized('当前环境不支持二维码图片解码', 'QR decoding is unavailable in this WebView'));
      const decoded = await window.OpenKeyletQR.decode(file);
      await smartIngestText(decoded, { filename: file.name, fromClipboard: false });
      return;
    }
    if (file.size > 512 * 1024) {
      throw new Error(localized('文件超过 512 KiB，请通过设置页导入大文件', 'File exceeds 512 KiB; use System → Import for larger files'));
    }
    const text = await file.text();
    await smartIngestText(text, { filename: file.name, fromClipboard: false });
  } catch (error) {
    toast(cleanError(error), 'error');
  }
}

$('#smart-paste-button')?.addEventListener('click', () => void triggerSmartPasteFromClipboard());
$('#editor-smart-paste-button')?.addEventListener('click', () => void triggerSmartPasteFromClipboard());

$('#smart-totp-attach-button')?.addEventListener('click', async () => {
  if (!editorSmartTotpUri) return;
  const targetId = $('#smart-totp-target')?.value;
  const item = state?.connections?.find((c) => c.id === targetId);
  if (!item) return;
  const btn = $('#smart-totp-attach-button');
  btn.disabled = true;
  try {
    const pastedClipboard = editorSmartClipboardSource;
    await api.attachTotpToItem(item.id, editorSmartTotpUri, item.updatedAt);
    closeEditor();
    if (pastedClipboard) await api.clearClipboardIfMatches(pastedClipboard).catch(() => false);
    window.OpenKeyletAppearance?.play?.('success');
    toast(localized(`已将 2FA 附加到「${item.name}」`, `Attached 2FA to "${item.name}"`));
    await refresh();
  } catch (error) {
    toast(cleanError(error), 'error');
  } finally {
    btn.disabled = false;
  }
});

$('#totp-qr-file-input')?.addEventListener('change', async (event) => {
  const file = event.target.files?.[0];
  event.target.value = '';
  if (!file || pendingTotpQrModuleIndex < 0) return;
  const index = pendingTotpQrModuleIndex;
  pendingTotpQrModuleIndex = -1;
  try {
    const decoded = await window.OpenKeyletQR.decode(file);
    const row = $$('#module-list .module-row')[index];
    const input = row && $('[data-secret-value]', row);
    if (input && currentModules[index]) {
      input.value = decoded;
      currentModules[index].secretValue = decoded;
      toast(localized('已从二维码填充 2FA 密钥', 'Filled 2FA secret from QR image'));
    }
  } catch (error) {
    toast(cleanError(error), 'error');
  }
});

document.addEventListener('click', (event) => {
  const scanBtn = event.target.closest('[data-scan-totp-qr]');
  if (!scanBtn) return;
  const row = scanBtn.closest('.module-row');
  if (!row) return;
  pendingTotpQrModuleIndex = Number(row.dataset.moduleIndex);
  $('#totp-qr-file-input')?.click();
});

document.addEventListener('paste', (event) => {
  if (!ownerLockState?.unlocked) return;
  const target = event.target;
  if (target && target.closest?.('input, textarea, select, [contenteditable="true"]')) return;
  const modalOpen = $$('.modal-backdrop:not(.hidden)').length > 0;
  const canPasteInBlankEditor = !$('#connection-modal').classList.contains('hidden')
    && !$('#template-picker').classList.contains('hidden');
  if (modalOpen && !canPasteInBlankEditor) return;
  if (!modalOpen && activePage !== 'connections' && activePage !== 'import') return;
  const dt = event.clipboardData;
  if (!dt) return;
  const imageItem = [...(dt.items || [])].find((item) => item.type?.startsWith('image/'));
  if (imageItem) {
    const blob = imageItem.getAsFile();
    if (blob) {
      event.preventDefault();
      if (!modalOpen && activePage === 'import') void window.OpenKeyletImportHub?.handleFiles?.([blob]);
      else void handleSmartFile(blob);
      return;
    }
  }
  const text = dt.getData('text/plain');
  if (text && text.trim()) {
    event.preventDefault();
    if (!modalOpen && activePage === 'import') window.OpenKeyletImportHub?.handlePasteText?.(text, { fromClipboard: true });
    else void smartIngestText(text, { fromClipboard: true });
  }
});

{
  let dragDepth = 0;
  const overlay = $('#smart-drop-overlay');
  const isFileDrag = (event) => Array.from(event.dataTransfer?.types || []).includes('Files');
  const splitTransferredFiles = (dt) => {
    const files = Array.from(dt?.files || []);
    const mvaultFiles = files.filter((f) => /\.mvault$/i.test(f?.name || ''));
    const otherFiles = files.filter((f) => !/\.mvault$/i.test(f?.name || ''));
    return { files, mvaultFiles, otherFiles };
  };
  document.addEventListener('dragenter', (event) => {
    if (!isFileDrag(event)) return;
    event.preventDefault();
    dragDepth++;
    const { files, mvaultFiles, otherFiles } = splitTransferredFiles(event.dataTransfer);
    if (mvaultFiles.length && otherFiles.length) {
      overlay?.classList.add('hidden');
      setGlobalMvaultDropOverlay(true, {
        mode: 'mixed',
        fileNames: files.slice(0, 3).map((f) => f.name),
        totalCount: files.length,
      });
      return;
    }
    if (mvaultFiles.length) {
      overlay?.classList.add('hidden');
      setGlobalMvaultDropOverlay(true, {
        mode: 'mvault',
        fileNames: [mvaultFiles[0].name],
        totalCount: mvaultFiles.length,
      });
      return;
    }
    if (!ownerLockState?.unlocked) return;
    if (activePage !== 'import') {
      overlay?.classList.add('hidden');
      setGlobalMvaultDropOverlay(true, {
        mode: 'universal',
        fileNames: otherFiles.slice(0, 3).map((f) => f.name),
        totalCount: otherFiles.length,
      });
    }
  });
  document.addEventListener('dragover', (event) => {
    if (!isFileDrag(event)) return;
    event.preventDefault();
    if (event.dataTransfer) event.dataTransfer.dropEffect = 'copy';
  });
  document.addEventListener('dragleave', (event) => {
    if (!isFileDrag(event)) return;
    dragDepth = Math.max(0, dragDepth - 1);
    if (dragDepth === 0) {
      overlay?.classList.add('hidden');
      setGlobalMvaultDropOverlay(false);
    }
  });
  document.addEventListener('drop', async (event) => {
    if (!isFileDrag(event)) return;
    event.preventDefault();
    dragDepth = 0;
    overlay?.classList.add('hidden');
    setGlobalMvaultDropOverlay(false);
    const { mvaultFiles, otherFiles } = splitTransferredFiles(event.dataTransfer);
    if (otherFiles.length) {
      await refreshOwnerLock();
      if (!ownerLockState?.unlocked) {
        toast(localized('请先解锁密码库后再拖入文件', 'Unlock OpenKeylet first before dropping files'), 'error');
      } else {
        if (activePage !== 'import') await selectPage('import');
        await window.OpenKeyletImportHub?.handleFiles?.(otherFiles);
      }
    }
    if (mvaultFiles.length) {
      await handleDroppedMvaultFile(mvaultFiles[0]);
    }
  });

  if (window.__TAURI__?.event?.listen) {
    window.__TAURI__.event.listen('native-file-drag', (event) => {
      const payload = event?.payload || {};
      if (payload.state === 'enter' && (payload.hasMvault || Number(payload.otherCount || 0) > 0)) {
        overlay?.classList.add('hidden');
        const mode = payload.hasMvault && Number(payload.otherCount || 0) > 0
          ? 'mixed'
          : payload.hasMvault
            ? 'mvault'
            : 'universal';
        setGlobalMvaultDropOverlay(true, {
          mode,
          fileNames: Array.isArray(payload.fileNames) ? payload.fileNames : [],
          totalCount: Number(payload.totalCount || 0),
          hasFolder: Boolean(payload.hasFolder),
        });
      } else {
        setGlobalMvaultDropOverlay(false);
      }
    });
    window.__TAURI__.event.listen('native-files-dropped', async (event) => {
      const payload = event?.payload || {};
      overlay?.classList.add('hidden');
      setGlobalMvaultDropOverlay(false);
      if (payload.locked) {
        toast(localized('请先解锁密码库后再拖入文件', 'Unlock OpenKeylet first before dropping files'), 'error');
        await refreshOwnerLock(false);
        return;
      }
      if (payload.error) {
        toast(cleanError(payload.error), 'error');
        return;
      }
      if (activePage !== 'import') await selectPage('import');
      await window.OpenKeyletImportHub?.handleNativeDropPayload?.(payload);
    });
    window.__TAURI__.event.listen('mvault-file-dropped', async (event) => {
      const payload = event?.payload || {};
      overlay?.classList.add('hidden');
      setGlobalMvaultDropOverlay(false);
      if (payload.locked) {
        toast(localized('请先解锁密码库后再拖入 .mvault 备份', 'Unlock OpenKeylet first before dropping a .mvault backup'), 'error');
        await refreshOwnerLock(false);
        return;
      }
      if (payload.error) {
        toast(cleanError(payload.error), 'error');
        return;
      }
      if (payload.fileName) {
        await openMvaultPreviewFlow({
          fileName: payload.fileName,
          requiresPassword: Boolean(payload.requiresPassword),
        });
      }
    });
  }
}

{
  // Vertical-only frameless window resize handles (width remains locked at 460px).
  for (const edge of $$('.window-resize-edge')) {
    edge.addEventListener('mousedown', (event) => {
      if (event.button !== 0) return;
      event.preventDefault();
      const rawDir = edge.dataset.resizeEdge;
      invoke('start_vertical_resize', { direction: rawDir })
        .then((handled) => {
          if (handled) return;
          const tauriDir = rawDir === 'north' || rawDir === 'top' ? 'North' : 'South';
          window.__TAURI__?.window?.getCurrentWindow?.().startResizeDragging?.(tauriDir)?.catch?.(() => {});
        })
        .catch(() => {});
    });
  }

  // Screen-edge auto-hide magnetic drawer preference & peek handle.
  const EDGE_DOCK_KEY = 'openkeylet.edgeDock.v1';
  const edgeDockInput = $('#edge-dock-enabled');
  const peekEl = $('#edge-dock-peek');
  let edgeDockEnabled = (() => {
    try { return localStorage.getItem(EDGE_DOCK_KEY) !== 'false'; } catch (_) { return true; }
  })();
  if (edgeDockInput) edgeDockInput.checked = edgeDockEnabled;

  function syncEdgeDockToBackend() {
    invoke('set_edge_dock_enabled', { enabled: edgeDockEnabled }).catch(() => {});
  }

  edgeDockInput?.addEventListener('change', (event) => {
    edgeDockEnabled = Boolean(event.currentTarget.checked);
    try { localStorage.setItem(EDGE_DOCK_KEY, edgeDockEnabled ? 'true' : 'false'); } catch (_) {}
    syncEdgeDockToBackend();
  });

  function applyEdgeDockState(payload) {
    const edge = payload?.edge || '';
    const collapsed = Boolean(payload?.collapsed && edge);
    if (edge) document.documentElement.dataset.edgeDock = edge;
    else delete document.documentElement.dataset.edgeDock;
    document.documentElement.dataset.edgeCollapsed = collapsed ? 'true' : 'false';
    if (peekEl) peekEl.classList.toggle('hidden', !collapsed);
  }

  peekEl?.addEventListener('pointerenter', () => { invoke('edge_dock_expand').catch(() => {}); });
  peekEl?.addEventListener('click', () => { invoke('edge_dock_expand').catch(() => {}); });
  document.addEventListener('pointerenter', () => {
    if (document.documentElement.dataset.edgeDock) invoke('edge_dock_hover', { entered: true }).catch(() => {});
  });
  document.addEventListener('pointerleave', () => {
    if (document.documentElement.dataset.edgeDock) invoke('edge_dock_hover', { entered: false }).catch(() => {});
  });

  if (window.__TAURI__?.event?.listen) {
    window.__TAURI__.event.listen('edge-dock-state', (event) => {
      applyEdgeDockState(event?.payload);
    });
    window.__TAURI__.event.listen('edge-dock-preference-changed', (event) => {
      edgeDockEnabled = Boolean(event?.payload);
      try { localStorage.setItem(EDGE_DOCK_KEY, edgeDockEnabled ? 'true' : 'false'); } catch (_) {}
      if (edgeDockInput) edgeDockInput.checked = edgeDockEnabled;
    });
  }
  syncEdgeDockToBackend();
}

async function bootstrap() {
  window.OpenKeyletImportHub?.init?.({
    invoke,
    localized,
    toast,
    cleanError,
    getLang: () => language,
    getSearchQuery: () => pageSearch.import || '',
    ensureUnlocked: async () => {
      await refreshOwnerLock();
      return Boolean(ownerLockState?.unlocked);
    },
    onStatsChange: () => renderMetrics(),
    refreshVault: () => refresh(),
    goToItems: () => void selectPage('connections'),
    goToImport: () => void selectPage('import'),
    openBackupRestore: () => $('#header-import-backup-button')?.click(),
    openDroppedMvault: (file) => handleDroppedMvaultFile(file),
    openMvaultPreview: (picked) => openMvaultPreviewFlow(picked),
    openCandidateInEditor: (candidate, onSaved) => openCandidateInEditor(candidate, onSaved),
  });
  applyLanguage();
  syncVaultViewMode();
  await refreshOwnerLock();
  await refresh();
  await refreshDrafts();
  loadChromeProfiles();
  scanAgents();
}
bootstrap();
