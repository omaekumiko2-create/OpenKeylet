const { invoke } = window.__TAURI__.core;
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const HAN_TEXT = /[\u3400-\u9fff]/;

const isMacOS = navigator.platform.startsWith('Mac') || navigator.userAgent.includes('Macintosh');
document.documentElement.classList.toggle('platform-macos', isMacOS);
window.addEventListener('blur', () => document.documentElement.classList.add('window-blurred'));
window.addEventListener('focus', () => document.documentElement.classList.remove('window-blurred'));

{
  const titleDragRegion = document.querySelector('.title-drag-region');
  const isTitleControl = (target) => Boolean(target.closest?.('button, input, select, textarea, a, [role="button"], #title-search'));
  titleDragRegion.addEventListener('mousedown', (event) => {
    if (event.button === 0 && !isTitleControl(event.target)) event.preventDefault();
  });
  titleDragRegion.addEventListener('selectstart', (event) => {
    if (!isTitleControl(event.target)) event.preventDefault();
  });
  titleDragRegion.addEventListener('dragstart', (event) => {
    if (!isTitleControl(event.target)) event.preventDefault();
  });
  const titleSearch = document.getElementById('title-search');
  titleSearch?.addEventListener('click', (event) => {
    if (event.target === titleSearch) document.getElementById('title-search-input')?.focus();
  });
}

// Keep the first paint deterministic. The persisted setting from the vault is
// applied by refresh(); browser storage can survive an app reinstall and must
// not override the English default while the native state is loading.
let language = 'en';

function localized(zh, en) {
  return language === 'en' ? en : zh;
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
  ['.nav-item[data-page="activity"] > span', 'text', '记录', 'LOG'],
  ['.nav-item[data-page="settings"] > span', 'text', '设置', 'SYSTEM'],
  ['#title-search-input', 'aria-label', '搜索秘密项目', 'Search vault items'],
  ['#add-connection-button', 'text', '＋ 添加', '+ ADD'],
  ['#drafts-button', 'text', '草稿', 'DRAFT'],
  ['#generator-open', 'text', '生成器', 'GENERATE'],
  ['#trash-open', 'text', '回收站', 'TRASH'],
  ['#delete-draft-button', 'aria-label', '删除草稿', 'Delete draft'],
  ['#header-export-backup-button', 'text', '一键打包', 'EXPORT'],
  ['#header-import-backup-button', 'text', '一键导入包', 'IMPORT'],
  ['[data-module="SYSTEM / 01"] .settings-heading h2', 'text', '系统入口', 'SYSTEM ACCESS'],
  ['[data-module="SYSTEM / 01"] .settings-heading p', 'text', '控制 OpenKeylet 的桌面快捷方式与开机启动。', 'Control the OpenKeylet desktop shortcut and launch at login.'],
  ['#desktop-shortcut-option strong', 'text', '创建快捷方式到桌面', 'CREATE DESKTOP SHORTCUT'],
  ['#desktop-shortcut-option small', 'text', '在当前用户桌面创建 OpenKeylet 快捷方式', 'Create a OpenKeylet shortcut on the current user’s desktop.'],
  ['#launch-at-login-option strong', 'text', '开机自启动', 'LAUNCH AT LOGIN'],
  ['#launch-at-login-option small', 'text', '登录系统后自动启动 OpenKeylet，并保持单实例', 'Start OpenKeylet after sign-in while preserving single-instance behavior.'],
  ['[data-module="MCP / 02"] .settings-heading h2', 'text', 'Agent 接入', 'AGENT SETUP'],
  ['[data-module="MCP / 02"] .settings-heading p', 'text', '注册本地 stdio MCP；支持的 Agent 同时安装“认证任务优先使用 OpenKeylet”规则。', 'Register the local stdio MCP and install the OpenKeylet-first authentication rule where supported.'],
  ['[data-module="APP / 03"] .settings-heading h2', 'text', '窗口与偏好', 'WINDOW & PREFERENCES'],
  ['[data-module="APP / 03"] .settings-heading p', 'text', '控制界面语言、音效、关闭按钮与本地 PIN 锁。', 'Control language, sounds, close behavior and local PIN lock.'],
  ['#language-option strong', 'text', '界面语言', 'INTERFACE LANGUAGE'],
  ['#language-option small', 'text', '在中文与英文界面之间切换', 'Switch between English and Simplified Chinese.'],
  ['#sound-option strong', 'text', '界面音效', 'INTERFACE SOUNDS'],
  ['#sound-option small', 'text', '点击按钮与切换开关时播放轻提示音', 'Subtle click feedback for toggles and buttons.'],
  ['label[for="close-behavior"] strong', 'text', '关闭按钮', 'CLOSE BUTTON'],
  ['label[for="close-behavior"] small', 'text', '最小化可保留托盘菜单', 'Minimizing keeps tray controls available.'],
  ['#close-behavior option[value="tray"]', 'text', '最小化到托盘', 'MINIMIZE TO TRAY'],
  ['#close-behavior option[value="exit"]', 'text', '退出 OpenKeylet', 'QUIT OpenKeylet'],
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
  ['#browser-install-heading', 'text', '安装插件 · 只需两步', 'INSTALL IN TWO STEPS'],
  ['#browser-step-open-title', 'text', '打开扩展页', 'Open the extensions page'],
  ['#browser-step-open-description', 'text', '打开 Chrome / Edge 并复制扩展页地址，粘贴后开启右上角的“开发者模式”。', 'Open Chrome or Edge and copy the extensions page address. Paste it into the address bar, then turn on Developer mode.'],
  ['#browser-open-help', 'text', '地址已复制。请粘贴到浏览器地址栏并按回车，然后开启“开发者模式”。', "Address copied. Paste it into your browser's address bar and press Enter, then turn on Developer mode."],
  ['#browser-step-drag-title', 'text', '拖入插件', 'Drag in the extension'],
  ['#browser-step-drag-description', 'text', '按住下方标识，拖到扩展页的空白区域，松开即可安装。', 'Hold the icon below, drag it onto an empty area of the extensions page, and release to install.'],
  ['#browser-install-complete', 'text', '安装后会自动连接，请保持 OpenKeylet 运行。', 'Once installed, the extension connects automatically. Keep OpenKeylet running.'],
  ['#browser-fallback-title', 'text', '拖拽无法安装？', "Can't install by dragging?"],
  ['#browser-fallback-description', 'text', '打开下方扩展目录，然后在扩展页点击“加载已解压的扩展程序”，选择该目录。', 'Open the extension folder below. On the extensions page, click Load unpacked and select that folder.'],
  ['#drag-extension-label', 'text', '按住此处，拖入扩展页', 'Hold and drag to the extensions page'],
  ['#drag-extension-button', 'aria-label', '拖动插件到 Chrome 扩展页；也可按回车打开扩展目录', 'Drag the extension to Chrome Extensions, or press Enter to open its folder'],
  ['#quick-pairing-button', 'text', '打开浏览器并复制地址', 'OPEN BROWSER & COPY ADDRESS'],
  ['#open-extension-button', 'text', '扩展目录', 'EXTENSION FOLDER'],
  ['#start-pairing-button', 'text', '开启配对', 'START PAIRING'],
  ['#test-browser-bridge-button', 'text', '测试连接', 'TEST BRIDGE'],
  ['#reset-pairing-button', 'text', '重置', 'RESET'],
  ['[data-module="SAFE / 06"] .settings-heading h2', 'text', '本地数据', 'LOCAL DATA'],
  ['#migration-open', 'text', '迁入密码库', 'IMPORT VAULT'],
  ['[data-module="SAFE / 06"] .settings-heading p', 'text', '用独立备份密码加密导出全部项目与 Passkey，也可恢复旧版备份。', 'Export all items and passkeys encrypted with a separate backup password, or restore an existing backup.'],
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
  ['.module-editor-heading > div > small', 'text', '拖动把手排序 · 开关控制 Agent 可见性', 'DRAG HANDLE TO REORDER · SWITCH CONTROLS AGENT VISIBILITY'],
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
];

function applyLanguage() {
  document.documentElement.lang = language === 'en' ? 'en' : 'zh-CN';
  window.OpenKeyletAppearance.setLanguage(localized);
  $$('.language-switch button').forEach((button) => button.classList.toggle('active', button.dataset.language === language));
  for (const [selector, target, zh, en] of staticCopy) {
    const element = $(selector);
    if (!element) continue;
    const copy = localized(zh, en);
    if (target === 'text') element.textContent = copy;
    else if (target === 'html') element.innerHTML = copy;
    else if (target === 'aria-label' || target === 'placeholder') element.setAttribute(target, copy);
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
  syncItemTypeFilter();
  syncActivityFilterControl();
  syncSettingsFilterControl();
  syncTitleSearch();
}

function publicMessage(value, fallback = localized('操作失败', 'Operation failed')) {
  const raw = String(value || '').replace(/^Error:\s*/, '');
  if (language !== 'en' || !HAN_TEXT.test(raw)) return raw || fallback;
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
  test: (id) => invoke('test_connection', { id }),
  settings: updateSettings,
  systemIntegration: () => invoke('system_integration_status'),
  setDesktopShortcut: (enabled) => invoke('set_desktop_shortcut', { enabled }),
  setLaunchAtLogin: (enabled) => invoke('set_launch_at_login', { enabled }),
  clear: () => invoke('clear_activities'),
  copyConfig: (format) => invoke('copy_mcp_config', { format }),
  agents: () => invoke('agent_mcp_status'),
  registerAgents: (clientIds) => invoke('agent_mcp_register', { clientIds }),
  repairAgent: (clientId) => invoke('agent_mcp_repair', { clientId }),
  removeAgent: (clientId) => invoke('agent_mcp_remove', { clientId }),
  chooseKey: () => invoke('choose_private_key'),
  quickPair: (port) => invoke('quick_pair_browser', { port }),
  openChrome: () => invoke('open_chrome_browser'),
  testBrowserBridge: () => invoke('test_browser_bridge'),
  resetPair: () => invoke('reset_browser_pairing'),
  extensionFolder: () => invoke('open_browser_extension_folder'),
  exportBackup: (password) => invoke('export_backup', { password }),
  importBackup: (password) => invoke('import_backup', { password }),
  prepareImport: (format) => invoke('prepare_import', { format }),
  commitImport: (id) => invoke('commit_import', { id }),
  cancelImport: () => invoke('cancel_import'),
  dataFolder: () => invoke('open_data_folder'),
  window: (action) => invoke('window_action', { action }),
};

let state;
let systemIntegrationState = { desktopShortcut: false, launchAtLogin: false };
let activePage = 'connections';
let currentActivityFilter = 'all';
const pageSearch = { connections: '', activity: '', settings: '' };
const itemTypeFilterOrder = ['all', 'ssh', 'login', 'api', 'passkey', 'card', 'identity', 'secureNote', 'custom'];
let currentItemTypeFilter = 'all';
const settingsFilterOrder = ['all', 'SYSTEM', 'MCP', 'APP', 'WEB', 'CLOUD', 'SAFE'];
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
let switchPointerDrag = null;
let switchSelectionPending = false;
let suppressSwitchClick = null;
let itemPointerDrag = null;
let itemOrderSaving = false;
let suppressItemClick = false;
let agentClients = [];
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
  onRestore: () => refresh(),
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
    else if ($('#connection-modal').classList.contains('hidden')) $('#add-connection-button').focus();
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
  confirmationInertElements = [...document.body.children].filter((element) => element !== $('#confirmation-modal') && !element.classList.contains('title-drag-region') && !element.inert && !['SCRIPT', 'STYLE'].includes(element.tagName));
  confirmationInertElements.forEach((element) => { element.inert = true; });
  $('#confirmation-modal').classList.remove('hidden');
  requestAnimationFrame(() => { if (confirmationResolver) $('#confirmation-cancel').focus(); });
  return new Promise((resolve) => { confirmationResolver = resolve; });
}

function clearOwnerPlaintext() {
  void finishSwitchDrag(false);
  finishItemPointerDrag(false);
  githubBackup.clearSecrets();
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
  const configured = ownerLockState.pinConfigured;
  const unlocked = ownerLockState.unlocked;
  const setupRequested = ownerPinSetupRequested && !configured;
  const locked = configured && !unlocked;
  const layerVisible = setupRequested || locked;
  $('#owner-lock-layer').classList.toggle('hidden', !layerVisible);
  $('#owner-lock-button').classList.toggle('hidden', !configured || !unlocked);
  $('#owner-pin-confirm-field').classList.toggle('hidden', configured);
  $('#owner-pin-cancel').classList.toggle('hidden', !setupRequested);
  pinInputs('owner-pin-confirm').forEach((input) => { input.required = !configured; });
  $('#owner-lock-mode').textContent = configured ? 'OWNER VERIFY' : 'SET LOCAL PIN';
  $('#owner-lock-title').textContent = configured
    ? localized('输入六位 PIN', 'ENTER SIX-DIGIT PIN')
    : localized('设置六位 PIN', 'SET SIX-DIGIT PIN');
  $('#owner-lock-code').textContent = configured ? 'LOCK' : 'INIT';
  $('#owner-unlock-action').textContent = configured ? 'UNLOCK' : 'SET PIN';
  if (locked) {
    if (!$('#vault-management-modal').classList.contains('hidden')) closeVaultManagement();
    if (!$('#migration-modal').classList.contains('hidden')) closeMigration();
    closeGenerator();
    finishBackupPassword(null);
    clearOwnerPlaintext();
    editorDrafts = [];
    renderDrafts();
  }
  clearPin('owner-pin');
  clearPin('owner-pin-confirm');
  if (layerVisible) setTimeout(() => focusPin('owner-pin'), 0);
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
    language = state.settings.language === 'en' ? 'en' : 'zh';
    await githubBackup.refresh();
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
  const models = {
    connections: {
      value: total, mode: localized('密码库', 'VAULT'), unit: localized('项', 'ITEMS'),
      label: localized('密码库项目总数', 'Total vault items'),
      secondary: {
        value: enabled, mode: localized('已启用', 'ENABLED'), unit: total > 0 ? `/ ${total}` : localized('项', 'ITEMS'),
        tone: enabled > 0 ? 'active' : '',
        ratio: total > 0 ? Math.round((enabled / total) * 100) : 0,
        label: localized('已启用项目数，包含所有类型', 'Enabled items across all item types'),
      },
    },
    activity: {
      value: activities24h.length, mode: localized('近 24H 调用', 'CALLS · 24H'), unit: localized('次', ''),
      label: localized('本地日志中最近 24 小时的操作数', 'Operations in the local log from the last 24 hours'),
      secondary: {
        value: errors24h, mode: localized('异常失败', 'ERRORS · 24H'), unit: errors24h > 0 ? localized('项', '') : localized('正常', 'CLEAR'),
        tone: errors24h > 0 ? 'fault' : 'ok',
        label: localized('本地日志中最近 24 小时的失败数', 'Errors in the local log from the last 24 hours'),
      },
    },
    settings: {
      value: registeredAgents, mode: localized('已接入 Agent', 'LINKED'), unit: localized('个', 'AGENTS'),
      label: localized('已注册 OpenKeylet MCP 的 Agent 客户端数', 'Agent clients registered with OpenKeylet MCP'),
      secondary: {
        value: brokenAgents, mode: localized('待修复配置', 'REPAIR'), unit: brokenAgents > 0 ? localized('个', 'NEED FIX') : localized('健康', 'OK'),
        tone: brokenAgents > 0 ? 'warn' : 'ok',
        label: localized('需要修复接入配置的 Agent 客户端数', 'Agent clients whose connection configuration needs repair'),
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
  const progress = typeof secondary.ratio === 'number'
    ? `<span class="metric-bar" aria-hidden="true"><i style="width:${secondary.ratio}%"></i></span>`
    : '';
  $('#metrics').innerHTML = `
    <div class="lcd-screen">
      <div class="lcd-primary metric-cell" role="group" aria-label="${escapeHtml(model.label)}" title="${escapeHtml(`${model.label}: ${model.value}`)}">
        <span class="metric-label" aria-hidden="true">${model.mode}</span>
        <div class="metric-readout">${sevenSegmentNumber(model.value)}${model.unit ? `<span class="metric-unit" aria-hidden="true">${model.unit}</span>` : ''}</div>
      </div>
      <div class="lcd-secondary metric-cell ${secondary.tone || ''}" role="group" aria-label="${escapeHtml(secondary.label)}" title="${escapeHtml(`${secondary.label}: ${secondary.value}`)}">
        <span class="metric-label" aria-hidden="true">${secondary.mode}</span>
        <div class="metric-readout">${sevenSegmentNumber(secondary.value, 3)}${secondary.unit ? `<span class="metric-unit" aria-hidden="true">${secondary.unit}</span>` : ''}</div>
        ${progress}
      </div>
      <div class="lcd-system" role="group" aria-label="${localized('当前服务状态', 'Current service status')}">
        ${services.map((service) => `<button type="button" class="lcd-service ${service.tone}" data-metric-section="${service.target}" aria-label="${escapeHtml(service.label)}" title="${escapeHtml(service.label)}"><i class="lcd-dot ${service.tone}" aria-hidden="true"></i><span class="lcd-service-name" aria-hidden="true">${service.name}</span><strong class="lcd-status ${service.tone}" aria-hidden="true">${service.value}</strong></button>`).join('')}
      </div>
    </div>`;
}

function itemDetail(item) {
  if (['card', 'identity', 'secureNote'].includes(item.itemType)) {
    return [itemTypeLabel(item.itemType), item.folder, localized('字段已加密', 'ENCRYPTED FIELDS')].filter(Boolean).join(' · ');
  }
  if (item.passkeys?.length && !itemCapabilities(item).length) return `PASSKEY · ${item.passkeys.map(k => k.rpId).join(' · ')}`;
  const capabilities = itemCapabilities(item);
  const targets = [];
  if (capabilities.includes('ssh') && item.host) targets.push(`${item.host}:${item.port || 22}`);
  if (capabilities.includes('http') && item.baseUrl) targets.push(item.baseUrl);
  if (targets.length) return targets.join(' · ');
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
  const labels = { all: ['全部设置', 'All settings'], SYSTEM: ['系统入口', 'System access'], MCP: ['Agent 接入', 'Agent setup'], APP: ['窗口与偏好', 'Window & preferences'], WEB: ['浏览器', 'Browser'], CLOUD: ['云端备份', 'Cloud backup'], SAFE: ['本地数据', 'Local data'] };
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
        else if (input.id === 'pin-enabled') await savePinSettings();
        else if (input.id === 'github-auto-sync') input.dispatchEvent(new Event('change', { bubbles: true }));
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
      if (drag.read() === drag.index && drag.strip.id !== 'sound-toggle') window.OpenKeyletAppearance.feedback();
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
  const labels = { connections: ['搜索项目', 'Search items'], activity: ['搜索记录', 'Search activity'], settings: ['搜索设置', 'Search settings'] };
  const label = localized(...labels[activePage]);
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
  return capabilities.includes('fill') ? 'FOCUS INPUT' : 'NOT EXPOSED';
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

function renderConnections() {
  if (itemPointerDrag || itemOrderSaving) return;
  const query = normalizeSearch(pageSearch.connections);
  const signature = JSON.stringify([state.connections, query, language, editorItemId, currentItemTypeFilter]);
  if (signature === renderedConnectionsSignature) return;
  renderedConnectionsSignature = signature;
  const items = state.connections.filter((item) => {
    if (item.id === editorItemId) return true;
    if (currentItemTypeFilter !== 'all' && itemDisplayKind(item) !== currentItemTypeFilter) return false;
    if (!query) return true;
    const fields = (item.secret?.fields || []).map((field) => field.name).join(' ');
    return normalizeSearch([item.name, item.description, item.folder, itemTypeLabel(item.itemType), itemDisplayType(item), itemCapabilities(item).join(' '), itemDetail(item), itemPermission(item), fields].join(' ')).includes(query);
  });
  const container = $('#connections-list');
  if (editorItemId && !state.connections.some(item => item.id === editorItemId)) closeEditor();
  if (!items.length) {
    const hasItems = state.connections.length > 0;
    container.innerHTML = `<div class="empty-state"><div><div class="empty-code">LOCAL VAULT</div><h3>${hasItems ? localized('没有匹配项目', 'NO MATCHING ITEMS') : localized('还没有秘密项目', 'NO VAULT ITEMS')}</h3><p>${hasItems ? localized('当前筛选没有结果。', 'No items match the current filters.') : localized('保存密码、Passkey、信用卡、身份资料和安全笔记，在需要时使用。', 'Keep passwords, passkeys, cards, identities and secure notes together.')}</p><button class="button primary" data-action="${hasItems ? 'clear-connection-filters' : 'add'}">${hasItems ? localized('清除筛选', 'CLEAR FILTERS') : localized('添加项目', 'ADD ITEM')}</button></div></div>`;
    return;
  }
  container.innerHTML = items.map((item) => {
    const type = itemDisplayType(item);
    const canTest = item.enabled && item.canTest;
    const agentActions = itemCapabilities(item).length > 0;
    const reorderLabel = localized(`${item.name}：拖动排序，或按方向键`, `${item.name}: drag to reorder, or use the arrow keys`);
    const toggleLabel = item.enabled
      ? localized('停用此项目；Agent 将无法使用其中的秘密', 'Disable this item; agents will no longer be able to use its secrets')
      : localized('启用此项目；Agent 将可以使用其中的秘密', 'Enable this item so agents can use its secrets');
    return `<article class="connection-card ${itemCapabilities(item).includes('ssh') ? 'ssh' : itemCapabilities(item).includes('http') ? 'http' : 'fill'} ${item.enabled ? '' : 'disabled'}" data-item-id="${escapeHtml(item.id)}">
      <button class="connection-name" type="button" draggable="false" data-item-reorder="${escapeHtml(item.id)}" aria-label="${escapeHtml(reorderLabel)}" aria-keyshortcuts="ArrowUp ArrowDown ArrowLeft ArrowRight Home End" title="${escapeHtml(reorderLabel)}"><span class="lettering-ink">${escapeHtml(item.name)}</span></button>
      <button class="module-state item-toggle" type="button" data-action="toggle-enabled" data-id="${item.id}" aria-pressed="${item.enabled}" title="${toggleLabel}" aria-label="${toggleLabel}"><i class="status-dot ${item.enabled ? '' : 'off'}" aria-hidden="true"></i></button>
      <span class="connection-type" role="img" data-item-type="${itemDisplayKind(item)}" aria-label="${escapeHtml(type)}" title="${escapeHtml(type)}">${itemTypeIcon(itemDisplayKind(item))}<small aria-hidden="true">${escapeHtml(type)}</small></span>
      <div class="card-actions" role="group" aria-label="${escapeHtml(item.name)}">
        <div class="item-disclosure-well"><button class="item-disclosure" type="button" data-action="edit" data-id="${item.id}" aria-haspopup="dialog" aria-controls="connection-modal" aria-label="${escapeHtml(localized(`编辑 ${item.name}`, `Edit ${item.name}`))}" title="${localized('编辑项目', 'Edit item')}"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m5 19 3.5-.7L19 7.8 16.2 5 5.7 15.5 5 19Zm9.8-12.6 2.8 2.8"/></svg></button></div>
        ${agentActions ? `<button class="small-button" type="button" data-action="test" data-id="${item.id}" ${canTest ? '' : 'disabled'}>CHECK</button><button class="small-button" type="button" data-action="copy-name" data-id="${item.id}" title="${localized('复制 OpenKeylet MCP 使用提示', 'Copy OpenKeylet MCP use prompt')}" aria-label="${localized('复制 OpenKeylet MCP 使用提示', 'Copy OpenKeylet MCP use prompt')}">USE</button>` : ''}${item.passwordHistoryCount ? `<button class="small-button" type="button" data-action="history" data-id="${item.id}" title="${localized('密码历史', 'Password history')}" aria-label="${localized('密码历史', 'Password history')}">HIS</button>` : ''}<button class="small-button delete" type="button" data-action="delete" data-id="${item.id}">DEL</button>
      </div>
    </article>`;
  }).join('');
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
  const hasDraft = Boolean(editorDrafts[0]);
  if (!hasDraft) creationMode = 'add';
  $('.creation-control').dataset.mode = creationMode;
  pill?.classList.toggle('hidden', !hasDraft);
  const deleteButton = $('#delete-draft-button');
  button.disabled = !hasDraft;
  button.textContent = localized('草稿', 'DRAFT');
  button.title = hasDraft ? localized('继续最近的草稿', 'Continue the most recent draft') : localized('暂无草稿', 'No draft');
  deleteButton.classList.toggle('hidden', !hasDraft);
  deleteButton.title = localized('删除草稿', 'Delete draft');
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

function renderActivity() {
  syncActivityFilterControl();
  const container = $('#activity-list');
  const query = normalizeSearch(pageSearch.activity);
  const activities = state.activities.map((activity, sourceIndex) => ({ activity, sourceIndex })).filter(({ activity }) => {
    if (currentActivityFilter !== 'all' && activity.status !== currentActivityFilter) return false;
    return !query || normalizeSearch([activity.action, activity.connectionName, activity.source, activity.status, activity.error].join(' ')).includes(query);
  });
  activityMatchCount = activities.length;
  if (!activities.length) {
    const hasActivity = state.activities.length > 0;
    container.innerHTML = `<div class="empty-state"><div><h3>${hasActivity ? localized('没有匹配记录', 'NO MATCHING ACTIVITY') : localized('暂无操作记录', 'NO ACTIVITY YET')}</h3><p>${hasActivity ? localized('当前搜索或结果筛选没有记录。', 'No activity matches the current search and result filter.') : localized('Agent 使用 OpenKeylet 后，这里只显示不含秘密的摘要。', 'After an agent uses OpenKeylet, only secret-free summaries appear here.')}</p>${hasActivity ? `<button class="button primary" data-action="clear-activity-filters">${localized('重置搜索与筛选', 'RESET SEARCH & FILTER')}</button>` : ''}</div></div>`;
    return;
  }
  container.innerHTML = activities.slice(0, activityVisibleCount).map(({ activity, sourceIndex }) => {
    const errorExpanded = expandedActivityErrors.has(activity.id);
    return `<article class="activity-item"><div class="log-index">${String(state.activities.length - sourceIndex).padStart(4, '0')}</div><div class="activity-status ${activity.status === 'error' ? 'error' : ''}">${activity.status === 'error' ? '×' : '✓'}</div><div><div class="activity-title">${escapeHtml(activityAction(activity.action))} · ${escapeHtml(activity.connectionName)}</div><div class="activity-meta">${escapeHtml(activitySource(activity.source))} · ${activity.durationMs} ms</div>${activity.error ? `<button type="button" class="activity-error ${errorExpanded ? 'expanded' : ''}" data-expand-error="${activity.id}" aria-expanded="${errorExpanded}">${escapeHtml(publicMessage(activity.error, localized('操作失败', 'Operation failed. Details are available in the local log.')))}</button>` : ''}</div><time class="activity-time">${formatTime(activity.time)}</time></article>`;
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
    const matchesSection = currentSettingsFilter === 'all' || card.dataset.module?.startsWith(`${currentSettingsFilter} /`);
    const matches = matchesSection && (!query || normalizeSearch(`${card.dataset.module || ''} ${card.textContent}`).includes(query));
    card.classList.toggle('search-hidden', !matches);
    if (matches) visible += 1;
  }
  $('#settings-search-empty').classList.toggle('hidden', visible > 0);
}

function renderSettings() {
  githubBackup.render();
  $('#mcp-endpoint').textContent = `${state.mcp.stdioCommand} mcp stdio`;
  const mcpFault = state.mcp.status === 'error';
  const mcpStrip = $('#mcp-status-strip');
  mcpStrip.className = `status-strip ${mcpFault ? 'error' : ''}`;
  mcpStrip.innerHTML = `<span class="status-dot"></span><span class="status-key">${mcpFault ? 'FAULT' : 'READY'}</span><span>${mcpFault ? escapeHtml(publicMessage(state.mcp.error)) : localized('Agent 使用时自动启动 stdio，无需常驻服务。', 'stdio starts on demand. No background service.')}</span>`;
  $('#agent-restart-notice').classList.toggle('hidden', !agentRestartRequired);
  $('#desktop-shortcut-enabled').checked = Boolean(systemIntegrationState.desktopShortcut);
  $('#launch-at-login-enabled').checked = Boolean(systemIntegrationState.launchAtLogin);
  $('#pin-enabled').checked = ownerLockState.pinConfigured || ownerPinSetupRequested;
  $('#owner-auto-lock-option').classList.toggle('hidden', !ownerLockState.pinConfigured);
  const autoLockMinutes = Number(state.settings.ownerAutoLockMinutes || 0);
  $('#owner-auto-lock-minutes').value = [0, 5, 15, 30, 60].includes(autoLockMinutes) ? String(autoLockMinutes) : '0';
  $('#close-behavior').value = state.settings.closeBehavior === 'exit' ? 'exit' : 'tray';
  $('#browser-enabled').checked = state.settings.browserEnabled;
  $('#browser-port').value = state.settings.browserPort;
  $('#browser-agent-passkey-enabled').checked = state.settings.browserAgentPasskey !== false;
  const bridge = state.browserBridge;
  const online = ['listening', 'delegated'].includes(bridge.status);
  const strip = $('#browser-status-strip');
  strip.className = `status-strip ${bridge.status === 'error' ? 'error' : online ? '' : 'offline'}`;
  strip.innerHTML = `<span class="status-dot"></span><span class="status-key">${bridge.status === 'error' ? 'FAULT' : online ? (bridge.connected ? 'CONNECTED' : bridge.paired ? 'WAITING' : 'READY') : 'OFF'}</span><span>${bridge.status === 'error' ? escapeHtml(publicMessage(bridge.error)) : online ? escapeHtml(bridge.endpoint) : localized('Browser Bridge 已关闭', 'Browser Bridge is off')}</span>`;
  $('#test-browser-bridge-button').disabled = !bridge.connected;
  $('#reset-pairing-button').disabled = !bridge.paired;
  renderAgents();
  applySettingsSearch();
}

const agentLabels = { notDetected: 'NOT FOUND', available: 'READY', registered: 'CONNECTED', stale: 'NEEDS REPAIR', conflict: 'CONFLICT', error: 'ERROR' };
function agentDetail(client) {
  const details = language === 'en'
    ? { notDetected: 'Not installed', available: 'Ready to connect', registered: 'Connected', stale: 'OpenKeylet setup needs repair', conflict: 'Config conflict', error: 'Detection failed' }
    : { notDetected: '未安装或未发现', available: '可连接', registered: '已连接', stale: 'OpenKeylet 连接或全局规则需要修复', conflict: '配置冲突', error: '检测失败' };
  return details[client.state] || publicMessage(client.message, localized('状态已更新', 'Status updated'));
}
function renderAgents() {
  const container = $('#agent-client-list');
  container.innerHTML = agentClients.length ? agentClients.map((client) => `<div class="agent-client-row ${client.canRegister ? '' : 'is-disabled'}"><span class="agent-client-copy"><strong>${escapeHtml(client.displayName)}</strong><span>${escapeHtml(agentDetail(client))}</span></span><div class="agent-row-controls"><span class="agent-state ${escapeHtml(client.state)}">${escapeHtml(agentLabels[client.state] || client.state)}</span><div class="agent-row-actions">${client.canRegister ? `<button type="button" class="agent-row-action primary" data-agent-action="connect" data-client-id="${escapeHtml(client.clientId)}">CONNECT</button>` : ''}${client.canRepair ? `<button type="button" class="agent-row-action primary" data-agent-action="repair" data-client-id="${escapeHtml(client.clientId)}">REPAIR</button>` : ''}${client.canRemove ? `<button type="button" class="agent-row-action" data-agent-action="remove" data-client-id="${escapeHtml(client.clientId)}">REMOVE</button>` : ''}</div></div></div>`).join('') : `<div class="agent-scan-placeholder">${localized('没有检测到支持的 Agent', 'NO SUPPORTED AGENT DETECTED')}</div>`;
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
      if (module.kind === 'totp') control += `<button class="small-button" type="button" data-copy-totp-code>${localized('复制 2FA 验证码', 'COPY 2FA CODE')}</button>`;
    } else {
      const inputType = module.kind === 'port' ? 'number' : 'text';
      const placeholder = module.kind === 'url' ? 'api.example.com/v1/' : module.kind === 'host' ? 'host.example.com' : '22';
      control = `<input class="input" data-module-value type="${inputType}" ${module.kind === 'port' ? 'min="1" max="65535"' : ''} value="${escapeHtml(module.value || '')}" placeholder="${placeholder}" />`;
      actions = `<span class="module-action-spacer" aria-hidden="true"></span>${secretActionButton('copy', false)}`;
    }
    const removeLabel = localized('删除模块', 'Remove module');
    const reorderLabel = localized('拖动调整顺序，或聚焦后按上/下方向键', 'Drag to reorder, or focus and use the Up/Down arrow keys');
    return `<div class="module-row" data-module-index="${index}" data-kind="${escapeHtml(module.kind)}" data-name="${escapeHtml(module.name || '')}" data-existing="${Boolean(module.existing)}" data-configured="${Boolean(module.configured)}" data-private-key-name="${escapeHtml(module.privateKeyName || '')}" data-pending="${Boolean(module.pending)}"><button type="button" class="module-drag-handle" data-module-drag-handle aria-label="${reorderLabel}" title="${reorderLabel}" aria-keyshortcuts="ArrowUp ArrowDown"><svg viewBox="0 0 12 20" aria-hidden="true"><path d="M4 5h.01M8 5h.01M4 10h.01M8 10h.01M4 15h.01M8 15h.01"/></svg></button><button type="button" class="module-agent-toggle" data-module-agent-visible aria-pressed="${agentVisible}" aria-label="${agentVisibilityLabel}" title="${agentVisibilityLabel}"><i aria-hidden="true"></i></button><div class="module-identity">${customName}</div><div class="module-control">${control}</div><div class="module-actions ${actions ? 'full' : 'single'}">${actions}<button type="button" class="remove-module module-action-icon" data-remove-module aria-label="${removeLabel}" title="${removeLabel}"><svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3 5.5h14M7.5 5.5V3.25h5v2.25M5.25 5.5l.75 11h8l.75-11M8.25 8.5v5M11.75 8.5v5"/></svg></button></div></div>`;
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
  $('#modal-title').textContent = editorOpenedFromDraft
    ? (editorExistingItem ? localized('继续编辑', 'CONTINUE EDIT') : localized('继续草稿', 'CONTINUE DRAFT'))
    : (editorExistingItem ? localized('编辑项目', 'EDIT ITEM') : localized('添加项目', 'ADD ITEM'));
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

function closeEditor() {
  finishModulePointerDrag(false);
  $('#connection-modal').classList.add('hidden');
  setModuleMenu(false);
  editorItemId = null;
  editorSourceInput = null;
  editorOpenedFromDraft = false;
  editorInitialSnapshot = '';
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
    });
    renderSettings();
    toast(localized('窗口与锁屏设置已保存', 'Window & lock settings saved'));
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
  const selected = next === 'en' ? 'en' : 'zh';
  if (selected === language) return;
  language = selected;
  applyLanguage();
  if (state) {
    state.settings.language = language;
    renderOwnerLock();
    render();
    syncModuleDraft();
    if (!$('#connection-modal').classList.contains('hidden')) renderModules();
    if (!$('#connection-modal').classList.contains('hidden')) updateEditorTitle();
    try {
      state.settings = await api.settings({ language });
    } catch (error) {
      toast(cleanError(error), 'error');
    }
  }
}

function toastImportSummary(summary) {
  toast(localized(`导入完成：新增 ${summary.added}，合并重复 ${summary.merged}`, `Import complete: ${summary.added} added, ${summary.merged} duplicates merged`));
}

async function exportBackup(button) {
  button.disabled = true;
  try {
    const password = await askBackupPassword(true);
    if (password === null) return;
    const path = await api.exportBackup(password);
    if (path) toast(localized('加密备份已导出；恢复时需要备份密码', 'Encrypted backup exported; keep its password for restoration'));
  } catch (error) {
    toast(cleanError(error), 'error');
  } finally {
    button.disabled = false;
  }
}

async function importBackup(button) {
  button.disabled = true;
  try {
    const password = await askBackupPassword(false);
    if (password === null) return;
    const result = await api.importBackup(password);
    if (!result) return;
    toastImportSummary(result);
    await refresh();
  } catch (error) {
    toast(cleanError(error), 'error');
  } finally {
    button.disabled = false;
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
  $('#login-uri-list').innerHTML = rules.map(rule => `<div class="login-uri-row"><input class="input" data-login-uri aria-label="${localized('网站地址','Website address')}" value="${escapeHtml(rule.uri)}" maxlength="8192"><select class="input" data-login-match aria-label="${localized('匹配规则','Matching rule')}">${choices.map(([key,zh,en]) => `<option value="${key}" ${rule.matchType===key?'selected':''}>${localized(zh,en)}</option>`).join('')}</select><button class="small-button" data-remove-uri type="button" aria-label="${localized('移除网站','Remove website')}">×</button></div>`).join('');
}
$('#login-uri-add').onclick = () => renderLoginUris([...$$('#login-uri-list .login-uri-row').map(row => ({uri:$('[data-login-uri]',row).value,matchType:$('[data-login-match]',row).value})),{uri:'',matchType:'origin'}]);
$('#login-uri-list').onclick = event => event.target.closest('[data-remove-uri]')?.closest('.login-uri-row').remove();

let migrationId = null;
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
};
function migrationHelp() {
  $('#migration-help').textContent = $('#migration-format').value === 'bitwarden'
    ? localized('在 Bitwarden 中导出未加密 JSON，然后选择文件预览。原文件不变；导入的秘密会加密存入本地库。', 'Export unencrypted JSON from Bitwarden, then choose the file to preview. The source is unchanged; imported secrets are encrypted locally.')
    : localized('选择 Chrome 或 Edge 导出的密码 CSV。支持带引号、逗号和多行备注的文件。', 'Choose a password CSV exported by Chrome or Edge. Quoted fields, commas and multiline notes are supported.');
}
function resetMigration() {
  migrationSequence++; migrationId = null;
  $('#migration-preview').replaceChildren(); $('#migration-preview').classList.add('hidden');
  $('#migration-confirm').classList.add('hidden');
  $('#migration-error').classList.add('hidden');
}
function closeMigration() {
  resetMigration(); $('#migration-modal').classList.add('hidden');
  api.cancelImport().catch(() => {});
}
$('#migration-open').onclick = async () => {
  await refreshOwnerLock();
  if (!ownerLockState.unlocked) return;
  resetMigration(); migrationHelp(); $('#migration-modal').classList.remove('hidden');
};
$('#migration-close').onclick = closeMigration;
$('#migration-format').onchange = () => { resetMigration(); api.cancelImport().catch(() => {}); migrationHelp(); };
$('#migration-select').onclick = async () => {
  resetMigration(); const sequence = migrationSequence;
  $('#migration-select').disabled = true;
  try {
    const result = await api.prepareImport($('#migration-format').value);
    if (!result || sequence !== migrationSequence) return;
    migrationId = result.id;
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
$('#migration-confirm').onclick = async () => {
  if (!migrationId) return;
  $('#migration-confirm').disabled = true;
  try { const result = await api.commitImport(migrationId); closeMigration(); toastImportSummary(result); await refresh(); }
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
    const draftId = editorDrafts[0].id;
    if (!await confirmDestructiveAction({
      title: localized('删除当前草稿？', 'Delete this draft?'),
      message: localized('草稿中的未保存内容将永久丢失。', 'Unsaved content in this draft will be permanently lost.'),
    })) return;
    try {
      await api.deleteDraft(draftId);
      editorDrafts = editorDrafts.filter((draft) => draft.id !== draftId);
      renderDrafts();
      $('#add-connection-button').focus();
      toast(localized('草稿已删除', 'Draft deleted'));
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
    $('[data-page-search="activity"]').value = '';
    activityVisibleCount = ACTIVITY_PAGE_SIZE;
    renderActivity();
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
    if (action.dataset.action === 'history') await openVaultManagement('history', item.id);
    if (action.dataset.action === 'copy-name') {
      try {
        await api.copyOwnerValue(`use ${item.name} in OpenKeylet MCP`, false);
        toast(localized('OpenKeylet MCP 使用提示已复制', 'OpenKeylet MCP use prompt copied'));
      } catch (error) { toast(cleanError(error), 'error'); }
    }
    if (action.dataset.action === 'test') {
      try { toast(publicMessage(await api.test(item.id), localized('连接测试完成', 'Connection test complete'))); await refresh(false); } catch (error) { toast(cleanError(error), 'error'); }
    }
    if (action.dataset.action === 'delete' && await confirmDestructiveAction({
      title: localized(`将“${item.name}”移入回收站？`, `Move "${item.name}" to trash?`),
      message: localized('项目将停止用于填写、Passkey 登录和 Agent 操作。你可以在回收站恢复它。', 'The item will stop being available for autofill, passkeys and agents. You can restore it from Trash.'),
      acceptLabel: localized('移入回收站', 'MOVE TO TRASH'),
    })) {
      try { await api.remove(item.id, item.updatedAt); toast(localized('已移入回收站', 'Moved to trash')); await refresh(); $('#add-connection-button').focus(); } catch (error) { toast(cleanError(error), 'error'); }
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
  itemList.style.setProperty('--item-row-height', `${Math.max(86, (itemList.clientHeight - padding - 2 * gap) / 3)}px`);
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

function clearItemDropSeam() {
  $$('.item-drop-before, .item-drop-after', itemList).forEach(row => row.classList.remove('item-drop-before', 'item-drop-after'));
}

function updateItemDropSeam() {
  const drag = itemPointerDrag;
  if (!drag?.started) return;
  const bounds = itemList.getBoundingClientRect();
  drag.valid = drag.x >= bounds.left && drag.x <= bounds.right && drag.y >= bounds.top && drag.y <= bounds.bottom;
  const original = drag.row.getBoundingClientRect();
  const overOriginal = drag.x >= original.left && drag.x <= original.right && drag.y >= original.top && drag.y <= original.bottom;
  let target = null;
  if (drag.valid && !overOriginal) {
    for (const row of $$('.connection-card', itemList)) {
      if (row === drag.row) continue;
      const rect = row.getBoundingClientRect();
      const dx = Math.max(rect.left - drag.x, 0, drag.x - rect.right);
      const dy = Math.max(rect.top - drag.y, 0, drag.y - rect.bottom);
      const centerX = rect.left + rect.width / 2, centerY = rect.top + rect.height / 2;
      const candidate = { row, after: drag.x >= centerX, distance: dx * dx + dy * dy, centerDistance: (drag.x - centerX) ** 2 + (drag.y - centerY) ** 2 };
      if (!target || candidate.distance < target.distance || (candidate.distance === target.distance && candidate.centerDistance < target.centerDistance)) target = candidate;
    }
  }
  if (drag.target?.row !== target?.row || drag.target?.after !== target?.after) {
    drag.target?.row.classList.remove('item-drop-before', 'item-drop-after');
    target?.row.classList.add(target.after ? 'item-drop-after' : 'item-drop-before');
  }
  drag.target = target;
  drag.preview.style.opacity = drag.valid ? '1' : '.5';
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
  updateItemDropSeam();
  const x = Math.max(8, Math.min(drag.x + 14, innerWidth - drag.previewWidth - 8));
  const y = Math.max(44, Math.min(drag.y + 14, innerHeight - drag.previewHeight - 8));
  drag.preview.style.transform = `translate3d(${x}px, ${y}px, 0)`;
  if (itemList.scrollTop !== previousScroll) scheduleItemDragFrame();
}

function finishItemPointerDrag(commit) {
  const drag = itemPointerDrag;
  if (!drag) return;
  itemPointerDrag = null;
  cancelAnimationFrame(drag.frame);
  try { if (itemList.hasPointerCapture(drag.pointerId)) itemList.releasePointerCapture(drag.pointerId); } catch (_) { /* Already released. */ }
  drag.row.classList.remove('is-item-dragging');
  itemList.classList.remove('is-reordering');
  document.body.classList.remove('item-pointer-dragging');
  drag.preview?.remove();
  clearItemDropSeam();
  if (drag.started) {
    suppressItemClick = true;
    setTimeout(() => { suppressItemClick = false; }, 0);
  }
  if (commit && drag.started && drag.valid && drag.target) {
    const ids = drag.visibleOrder.filter(id => id !== drag.id);
    const position = ids.indexOf(drag.target.row.dataset.itemId) + (drag.target.after ? 1 : 0);
    ids.splice(position, 0, drag.id);
    void saveItemOrder(ids, drag.expectedOrder, drag.id);
  } else renderConnections();
}

itemList.addEventListener('dragstart', event => {
  if (event.target.closest?.('[data-item-reorder]')) event.preventDefault();
});
itemList.addEventListener('pointerdown', event => {
  const handle = event.target.closest?.('[data-item-reorder]');
  if (!handle || event.button !== 0 || !event.isPrimary || event.ctrlKey || event.metaKey || event.shiftKey || itemPointerDrag || itemOrderSaving || confirmationResolver || !ownerLockState.unlocked) return;
  event.preventDefault();
  handle.focus({ preventScroll: true });
  itemPointerDrag = { id: handle.dataset.itemReorder, item: state.connections.find(item => item.id === handle.dataset.itemReorder), row: handle.closest('.connection-card'), pointerId: event.pointerId, startX: event.clientX, startY: event.clientY, x: event.clientX, y: event.clientY, started: false, visibleOrder: visibleItemIds(), expectedOrder: state.connections.map(item => item.id) };
});
document.addEventListener('pointermove', event => {
  const drag = itemPointerDrag;
  if (!drag || event.pointerId !== drag.pointerId) return;
  drag.x = event.clientX; drag.y = event.clientY;
  if (!drag.started && Math.hypot(drag.x - drag.startX, drag.y - drag.startY) < 6) return;
  event.preventDefault();
  if (!drag.started) {
    drag.started = true;
    drag.row.classList.add('is-item-dragging');
    itemList.classList.add('is-reordering');
    document.body.classList.add('item-pointer-dragging');
    const item = drag.item;
    drag.preview = document.createElement('div');
    drag.preview.className = 'item-drag-preview';
    drag.preview.setAttribute('aria-hidden', 'true');
    drag.preview.innerHTML = `${itemTypeIcon(itemDisplayKind(item))}<span>${escapeHtml(item.name)}</span>`;
    document.body.appendChild(drag.preview);
    try { itemList.setPointerCapture(event.pointerId); } catch (_) { /* Document tracking remains active. */ }
    drag.previewWidth = drag.preview.offsetWidth;
    drag.previewHeight = drag.preview.offsetHeight;
    const initX = Math.max(8, Math.min(drag.x + 14, innerWidth - drag.previewWidth - 8));
    const initY = Math.max(44, Math.min(drag.y + 14, innerHeight - drag.previewHeight - 8));
    drag.preview.style.transform = `translate3d(${initX}px, ${initY}px, 0)`;
  }
  scheduleItemDragFrame();
}, { passive: false });
document.addEventListener('pointerup', event => {
  if (itemPointerDrag?.pointerId !== event.pointerId) return;
  if (itemPointerDrag.started) { event.preventDefault(); updateItemDropSeam(); }
  finishItemPointerDrag(true);
});
document.addEventListener('pointercancel', event => { if (itemPointerDrag?.pointerId === event.pointerId) finishItemPointerDrag(false); });
itemList.addEventListener('lostpointercapture', event => { if (itemPointerDrag?.pointerId === event.pointerId) finishItemPointerDrag(false); });
window.addEventListener('blur', () => finishItemPointerDrag(false));
document.addEventListener('click', event => {
  if (!suppressItemClick) return;
  suppressItemClick = false;
  event.preventDefault(); event.stopImmediatePropagation();
}, true);
itemList.addEventListener('keydown', event => {
  const handle = event.target.closest?.('[data-item-reorder]');
  if (!handle || itemPointerDrag || itemOrderSaving || confirmationResolver || !ownerLockState.unlocked || event.altKey || event.ctrlKey || event.metaKey || !['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
  event.preventDefault(); event.stopPropagation();
  const ids = visibleItemIds(), id = handle.dataset.itemReorder, from = ids.indexOf(id);
  const step = { ArrowUp: -4, ArrowDown: 4, ArrowLeft: -1, ArrowRight: 1 }[event.key];
  const to = event.key === 'Home' ? 0 : event.key === 'End' ? ids.length - 1 : Math.max(0, Math.min(ids.length - 1, from + step));
  if (to === from) return;
  ids.splice(from, 1); ids.splice(to, 0, id);
  void saveItemOrder(ids, state.connections.map(item => item.id), id);
});

let draggedModuleRow = null;
let moduleDropTarget = null;
let moduleDropAfter = false;
let moduleDragPreview = null;
let modulePointerDrag = null;
let suppressModuleClick = false;
const moduleList = $('#module-list');
function clearModuleDropSeam() {
  $$('.module-row.drop-before, .module-row.drop-after', moduleList).forEach((row) => row.classList.remove('drop-before', 'drop-after'));
  moduleDropTarget = null;
  moduleDropAfter = false;
}

function beginModulePointerDrag(event) {
  draggedModuleRow = modulePointerDrag.row;
  draggedModuleRow.classList.add('is-dragging');
  moduleList.classList.add('is-sorting');
  document.body.classList.add('module-pointer-dragging');
  const definition = MODULE_DEFS[draggedModuleRow.dataset.kind] || MODULE_DEFS.customSecret;
  moduleDragPreview = document.createElement('div');
  moduleDragPreview.className = 'module-drag-preview';
  moduleDragPreview.innerHTML = `<b>${escapeHtml(definition.code)}</b><span>${escapeHtml(moduleLabel(draggedModuleRow.dataset.kind))}</span>`;
  document.body.appendChild(moduleDragPreview);
  modulePointerDrag.started = true;
  positionModuleDragPreview(event.clientX, event.clientY);
  try { draggedModuleRow.setPointerCapture(event.pointerId); } catch (_) { /* document tracking remains active */ }
}

function updateModuleDropSeam(clientY) {
  clearModuleDropSeam();
  const rows = $$('.module-row', moduleList);
  if (!rows.length) return;
  const seams = rows.map((row) => ({ row, after: false, y: row.getBoundingClientRect().top }));
  const lastRow = rows.at(-1);
  seams.push({ row: lastRow, after: true, y: lastRow.getBoundingClientRect().bottom });
  const closest = seams.reduce((best, seam) => Math.abs(clientY - seam.y) < Math.abs(clientY - best.y) ? seam : best);
  moduleDropTarget = closest.row;
  moduleDropAfter = closest.after;
  moduleDropTarget.classList.add(moduleDropAfter ? 'drop-after' : 'drop-before');
}

function positionModuleDragPreview(clientX, clientY) {
  if (!moduleDragPreview) return;
  const w = moduleDragPreview.offsetWidth || 176;
  const h = moduleDragPreview.offsetHeight || 38;
  const x = Math.max(8, Math.min(Math.round(clientX + 14), window.innerWidth - w - 8));
  const y = Math.max(44, Math.min(Math.round(clientY + 14), window.innerHeight - h - 8));
  moduleDragPreview.style.transform = `translate3d(${x}px, ${y}px, 0)`;
}

function autoScrollModuleEditor(clientY) {
  const scroller = $('.form-scroll', $('#connection-modal'));
  if (!scroller) return;
  const bounds = scroller.getBoundingClientRect();
  if (clientY < bounds.top + 34) scroller.scrollTop -= 12;
  else if (clientY > bounds.bottom - 34) scroller.scrollTop += 12;
}

function finishModulePointerDrag(commit) {
  if (!modulePointerDrag) return;
  const { row, pointerId, started } = modulePointerDrag;
  if (started && commit && moduleDropTarget) {
    moduleList.insertBefore(row, moduleDropAfter ? moduleDropTarget.nextElementSibling : moduleDropTarget);
  }
  try { if (row.hasPointerCapture(pointerId)) row.releasePointerCapture(pointerId); } catch (_) { /* capture may already be released */ }
  row.classList.remove('is-dragging');
  moduleList.classList.remove('is-sorting');
  document.body.classList.remove('module-pointer-dragging');
  moduleDragPreview?.remove();
  moduleDragPreview = null;
  draggedModuleRow = null;
  modulePointerDrag = null;
  clearModuleDropSeam();
  if (started && commit) {
    syncModuleDraft();
    $('[data-module-drag-handle]', row)?.focus({ preventScroll: true });
    announceModuleOrder(row);
  }
}

function announceModuleOrder(row) {
  const rows = $$('.module-row', moduleList);
  const name = $('[data-module-name]', row)?.value.trim() || moduleLabel(row.dataset.kind);
  const position = rows.indexOf(row) + 1;
  $('#module-reorder-status').textContent = localized(`${name}：第 ${position} 项，共 ${rows.length} 项`, `${name}: position ${position} of ${rows.length}`);
}

moduleList.addEventListener('dragstart', (event) => {
  if (event.target.closest?.('[data-module-drag-handle]')) event.preventDefault();
});
moduleList.addEventListener('pointerdown', (event) => {
  if (event.button !== 0 || !event.isPrimary || confirmationResolver) return;
  const handle = event.target.closest?.('[data-module-drag-handle]');
  const row = handle?.closest('.module-row');
  if (!row || modulePointerDrag) return;
  event.preventDefault();
  handle.focus({ preventScroll: true });
  modulePointerDrag = { row, pointerId: event.pointerId, startX: event.clientX, startY: event.clientY, started: false };
});
moduleList.addEventListener('keydown', (event) => {
  const handle = event.target.closest?.('[data-module-drag-handle]');
  if (!handle || confirmationResolver || modulePointerDrag || !['ArrowUp', 'ArrowDown'].includes(event.key)) return;
  event.preventDefault();
  const row = handle.closest('.module-row');
  const sibling = event.key === 'ArrowUp' ? row.previousElementSibling : row.nextElementSibling;
  if (!sibling) return;
  moduleList.insertBefore(row, event.key === 'ArrowUp' ? sibling : sibling.nextElementSibling);
  syncModuleDraft();
  handle.focus({ preventScroll: true });
  row.scrollIntoView({ block: 'nearest' });
  announceModuleOrder(row);
});
document.addEventListener('pointermove', (event) => {
  if (!modulePointerDrag || event.pointerId !== modulePointerDrag.pointerId) return;
  if (!modulePointerDrag.started && Math.hypot(event.clientX - modulePointerDrag.startX, event.clientY - modulePointerDrag.startY) < 6) return;
  if (!modulePointerDrag.started) beginModulePointerDrag(event);
  event.preventDefault();
  autoScrollModuleEditor(event.clientY);
  updateModuleDropSeam(event.clientY);
  positionModuleDragPreview(event.clientX, event.clientY);
}, { passive: false });
document.addEventListener('pointerup', (event) => {
  if (!modulePointerDrag || event.pointerId !== modulePointerDrag.pointerId) return;
  if (modulePointerDrag.started) {
    event.preventDefault();
    suppressModuleClick = true;
    setTimeout(() => { suppressModuleClick = false; }, 0);
  }
  finishModulePointerDrag(true);
});
document.addEventListener('pointercancel', (event) => {
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
    if (key === '1' || key === '2' || key === '3') {
      event.preventDefault();
      void selectPage({ 1: 'connections', 2: 'activity', 3: 'settings' }[key]);
      return;
    }
    if (key === 'l' && event.shiftKey && ownerLockState.pinConfigured && ownerLockState.unlocked) {
      event.preventDefault();
      void lockOwner();
      return;
    }
    if (isMacOS && event.metaKey && !event.ctrlKey && key === 'w') {
      event.preventDefault();
      void api.window('close');
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
    await api.save(input);
    if (currentDraftId) await api.deleteDraft(currentDraftId);
    currentDraftId = '';
    closeEditor();
    toast(localized('项目已加密保存', 'Item saved and encrypted'));
    await refresh();
    await refreshDrafts();
  } catch (error) { toast(cleanError(error), 'error'); } finally { button.disabled = false; }
});
$('#owner-lock-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const pin = readPin('owner-pin');
  if (!/^\d{6}$/.test(pin)) return toast(localized('PIN 必须是六位数字', 'PIN must contain six digits'), 'error');
  if (!ownerLockState.pinConfigured && pin !== readPin('owner-pin-confirm')) return toast(localized('两次 PIN 不一致', 'PIN entries do not match'), 'error');
  const button = $('#owner-unlock-action');
  const cancelButton = $('#owner-pin-cancel');
  button.disabled = true;
  cancelButton.disabled = true;
  try {
    const settingPin = !ownerLockState.pinConfigured;
    ownerLockState = ownerLockState.pinConfigured ? await api.ownerUnlock(pin) : await api.ownerSetPin(pin);
    ownerPinSetupRequested = false;
    renderOwnerLock();
    if (settingPin) toast(localized('PIN 锁已开启', 'PIN lock enabled'));
    await refresh(false);
    await refreshDrafts(true);
  } catch (error) {
    toast(cleanError(error), 'error');
    clearPin('owner-pin');
    focusPin('owner-pin');
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
    $('[data-page-search="activity"]').value = '';
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
    toast(localized('已开启 120 秒配对窗口，已安装的扩展会自动连接', '120s pairing window open. Installed extensions will connect automatically.'));
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
$('#quick-pairing-button').addEventListener('click', async event => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    $('#browser-open-help').hidden = true;
    let copyError = null;
    try {
      await api.copyOwnerValue('chrome://extensions/', false);
      $('#browser-open-help').hidden = false;
    } catch (error) { copyError = error; }
    let pairingError = null;
    try {
      await api.quickPair(Number($('#browser-port').value));
      $('#browser-enabled').checked = true;
    } catch (error) { pairingError = error; }
    let browserError = null;
    try { await api.openChrome(); } catch (error) { browserError = error; }
    if (copyError) toast(cleanError(copyError), 'error');
    else if (pairingError && browserError) toast(localized('配对失败，且无法打开 Chrome。请检查 Browser Bridge 并手动打开 Chrome。', 'Pairing failed and Chrome could not be opened. Check Browser Bridge and open Chrome manually.'), 'error');
    else if (pairingError) toast(cleanError(pairingError), 'error');
    else if (browserError) toast(localized('地址已复制，请手动打开 Chrome 并粘贴。', 'Address copied. Open Chrome and paste it manually.'), 'error');
    else toast(localized('地址已复制，配对已准备。', 'Address copied. Pairing is ready.'));
    await refresh(false);
  } catch (error) {
    toast(cleanError(error), 'error');
  } finally {
    button.disabled = false;
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

let generatorTarget = null, generatorSequence = 0;
let backupPasswordResolve = null, backupPasswordExport = false;
function finishBackupPassword(result) {
  $('#backup-password-form').reset(); $('#backup-password-modal').classList.add('hidden');
  const resolve = backupPasswordResolve; backupPasswordResolve = null; resolve?.(result);
}
function askBackupPassword(exporting) {
  setModuleMenu(false);
  finishBackupPassword(null); backupPasswordExport = exporting;
  $('#backup-password-title').textContent = exporting ? localized('导出加密备份', 'EXPORT ENCRYPTED BACKUP') : localized('恢复备份', 'RESTORE BACKUP');
  $('#backup-password-help').textContent = exporting
    ? localized('设置至少 12 个字符的备份密码。恢复时需要此密码，请妥善保管。', 'Use a backup password of at least 12 characters. Keep it for restoration.')
    : localized('输入创建备份时设置的密码；旧版自动解锁备份可留空。', 'Enter the backup password. Leave blank for older automatically unlocked backups.');
  $('#backup-password-confirm-field').classList.toggle('hidden', !exporting);
  $('#backup-password').required = exporting;
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

async function bootstrap() {
  applyLanguage();
  initLettering();
  await refreshOwnerLock();
  await refresh();
  await refreshDrafts();
  scanAgents();
}
bootstrap();
