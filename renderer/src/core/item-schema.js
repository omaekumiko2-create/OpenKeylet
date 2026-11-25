/* Pure item/module schema, SVG icon maps, and formatting helpers. */
import { HAN_TEXT } from './dom.js';
import { store } from './store.js';
import { localized } from '../i18n/index.js';

export const ITEM_TYPE_FILTER_ORDER = ['all', 'ssh', 'login', 'api', 'passkey', 'card', 'identity', 'secureNote', 'custom'];
export const SETTINGS_FILTER_ORDER = ['all', 'SYSTEM', 'MCP', 'APP', 'WEB', 'CLOUD', 'SAFE', 'UPDATE'];
export const AUTO_CHECK_INTERVALS = [15, 30, 60, 180, 360, 720, 1440];

export const MODULE_DEFS = {
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

export const PERSONAL_FIELDS = Object.keys(MODULE_DEFS).slice(0, Object.keys(MODULE_DEFS).indexOf('username'));

export const ITEM_TYPES = {
  login: ['登录', 'Login'],
  card: ['信用卡', 'Card'],
  identity: ['身份资料', 'Identity'],
  secureNote: ['安全笔记', 'Secure note'],
  ssh: ['SSH', 'SSH'],
  api: ['API', 'API'],
  custom: ['自定义', 'Custom'],
  passkey: ['Passkey', 'Passkey'],
};

export const CARD_ACTION_ICONS = {
  checkIdle: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8.5"/><path d="m8.8 12.2 2.2 2.2 4.4-4.6"/></svg>',
  checkOk: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12.5 9.5 17 19 7.5"/></svg>',
  checkError: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8.5"/><path d="M12 8v4.5"/><path d="M12 16h.01"/></svg>',
  use: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3l1.75 4.85L18.6 9.6l-4.85 1.75L12 16.2l-1.75-4.85L5.4 9.6l4.85-1.75Z"/><path d="M19 15.2l.75 2.05L21.8 18l-2.05.75L19 20.8l-.75-2.05L16.2 18l2.05-.75Z"/></svg>',
  history: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3.5 12a8.5 8.5 0 1 0 2.7-6.2L3.5 8"/><path d="M3.5 3.5V8H8"/><path d="M12 7.5V12l3 1.8"/></svg>',
  copy: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15H4a1.5 1.5 0 0 1-1.5-1.5v-9A1.5 1.5 0 0 1 4 3h9A1.5 1.5 0 0 1 14.5 4.5v1"/></svg>',
  copied: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12.5 9.5 17 19 7.5"/></svg>',
  del: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16"/><path d="M9.5 7V4.5A1.5 1.5 0 0 1 11 3h2a1.5 1.5 0 0 1 1.5 1.5V7"/><path d="M6.5 7l.8 12.2A1.8 1.8 0 0 0 9.1 21h5.8a1.8 1.8 0 0 0 1.8-1.8L17.5 7"/><path d="M10 11v6M14 11v6"/></svg>',
};

export function itemTypeLabel(kind) {
  const labels = ITEM_TYPES[kind] || ITEM_TYPES.custom;
  return localized(...labels);
}

export function typeOptions(emptyLabel, selected, includePasskey = false) {
  return `${emptyLabel ? `<option value="">${emptyLabel}</option>` : ''}${Object.keys(ITEM_TYPES)
    .filter((k) => includePasskey || k !== 'passkey')
    .map((k) => `<option value="${k}" ${k === selected ? 'selected' : ''}>${itemTypeLabel(k)}</option>`)
    .join('')}`;
}

export function moduleHasPlaintextReveal(kind) {
  return Boolean(MODULE_DEFS[kind]?.secret);
}

export function defaultModuleAgentVisible(kind) {
  return !moduleHasPlaintextReveal(kind);
}

export function moduleSecretName(module) {
  return module.kind === 'customSecret'
    ? String(module.name || '').trim()
    : MODULE_DEFS[module.kind]?.secret
      ? module.kind
      : '';
}

export function moduleLabel(kind) {
  const definition = MODULE_DEFS[kind] || MODULE_DEFS.customSecret;
  return localized(definition.zh, definition.en);
}

export function itemCapabilities(item) {
  return Array.isArray(item.capabilities) ? item.capabilities : [];
}

export function itemDisplayKind(item) {
  if (item.itemType && item.itemType !== 'custom' && ITEM_TYPES[item.itemType]) return item.itemType;
  const capabilities = itemCapabilities(item);
  if (capabilities.includes('ssh')) return 'ssh';
  if (capabilities.includes('http')) return 'api';
  if (item.passkeys?.length) return 'passkey';
  if (item.modules?.some((module) => module.kind === 'apiCredential')) return 'api';
  if (item.modules?.some((module) => module.kind === 'password')) return 'login';
  return 'custom';
}

export function itemFilterLabel(kind) {
  if (kind === 'all') return localized('全部类型', 'All types');
  if (kind === 'login') return localized('密码', 'Password');
  return itemTypeLabel(kind);
}

export function itemDisplayType(item) {
  return itemFilterLabel(itemDisplayKind(item));
}

export function itemTypeIcon(kind) {
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

export function compactTargetUrl(raw) {
  const text = String(raw || '').trim();
  if (!text) return '';
  return text.replace(/^https?:\/\//i, '').replace(/\/+$/, '');
}

export function itemDetail(item) {
  if (['card', 'identity', 'secureNote'].includes(item.itemType)) {
    return [itemTypeLabel(item.itemType), item.folder, localized('字段已加密', 'ENCRYPTED FIELDS')].filter(Boolean).join(' · ');
  }
  if (item.passkeys?.length && !itemCapabilities(item).length) {
    return `PASSKEY · ${item.passkeys.map((k) => k.rpId).join(' · ')}`;
  }
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

export function itemPermission(item) {
  const capabilities = itemCapabilities(item);
  if (capabilities.includes('http')) return 'HTTP';
  if (capabilities.includes('ssh')) return 'SSH';
  if (capabilities.includes('fill')) return 'FOCUS INPUT';
  if (capabilities.includes('passkey')) return 'PASSKEY';
  if (capabilities.includes('personal')) return 'PERSONAL';
  if (capabilities.includes('note')) return 'NOTE';
  return 'NOT EXPOSED';
}

export function itemSubtitle(item) {
  const detail = itemDetail(item);
  if (detail) return detail;
  return [item.folder, item.description, itemDisplayType(item)].filter(Boolean).join(' · ');
}

export function itemMetaBadges(item) {
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
  if (item.folder && !itemSubtitle(item).includes(item.folder) && badges.length < 3) {
    badges.push({ text: item.folder });
  }
  return badges.slice(0, 3);
}

export function activityCode(action = '') {
  const upper = String(action).toUpperCase();
  if (/BROWSER|浏览器|\bWEB\b/.test(upper)) return 'WEB';
  if (/TERMINAL|终端|PTY/.test(upper)) return 'TERM';
  if (/SSH/.test(upper)) return 'SSH';
  if (/API|HTTP|\bGET\b|\bPOST\b|\bPUT\b|\bPATCH\b|\bDELETE\b/.test(upper)) return 'API';
  if (/FILL|填写|填入/.test(upper)) return 'FILL';
  if (/TEST|测试|CHECK/.test(upper)) return 'CHECK';
  return 'CALL';
}

export function formatTime(val) {
  const diff = Date.now() - new Date(val).getTime();
  if (diff < 60_000) return localized('刚刚', 'JUST NOW');
  if (diff < 3_600_000) return localized(`${Math.floor(diff / 60_000)} 分钟前`, `${Math.floor(diff / 60_000)} MIN AGO`);
  if (diff < 86_400_000) return localized(`${Math.floor(diff / 3_600_000)} 小时前`, `${Math.floor(diff / 3_600_000)} HR AGO`);
  return new Date(val).toLocaleString(store.language === 'en' ? 'en-US' : 'zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function activityAction(action = '') {
  const raw = String(action);
  if (store.language !== 'en' || !HAN_TEXT.test(raw)) return raw;
  if (/测试连接/.test(raw)) return 'Test connection';
  if (/重置.*SSH.*主机信任/.test(raw)) return 'Reset SSH host trust';
  if (/导入备份/.test(raw)) return 'Import portable backup';
  if (/填写|填入/.test(raw)) return `Fill secret field (${activityCode(raw)})`;
  return 'OpenKeylet operation';
}

export function activitySource(source = '') {
  if (store.language === 'en' && HAN_TEXT.test(String(source))) return 'APP';
  return source;
}
