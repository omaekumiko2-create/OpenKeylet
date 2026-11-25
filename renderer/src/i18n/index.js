/* Multi-language translation engine and DOM copy updater (en, zh, zh-TW, ja, ko, es). */
import { LANGUAGES, DICT, PATTERNS } from './dictionary.js';
import { staticCopy } from './static-copy.js';
import { $, $$, isMacOS } from '../core/dom.js';
import { store, hooks } from '../core/store.js';
import { api } from '../core/api.js';

export { LANGUAGES };
export const SUPPORTED_SET = new Set(LANGUAGES.map((entry) => entry.code));
const LANG_INDEX = { 'zh-TW': 0, ja: 1, ko: 2, es: 3 };

export function normalizeLanguage(raw) {
  const lower = String(raw || '').trim().toLowerCase();
  if (lower === 'en' || lower.startsWith('en-') || lower.startsWith('en_')) return 'en';
  if (['zh-tw', 'zh_tw', 'zh-hk', 'zh_hk', 'zh-hant', 'zh_hant'].includes(lower)) return 'zh-TW';
  if (lower === 'zh' || lower.startsWith('zh-') || lower.startsWith('zh_')) return 'zh';
  if (lower === 'ja' || lower.startsWith('ja-') || lower.startsWith('ja_')) return 'ja';
  if (lower === 'ko' || lower.startsWith('ko-') || lower.startsWith('ko_')) return 'ko';
  if (lower === 'es' || lower.startsWith('es-') || lower.startsWith('es_')) return 'es';
  return 'en';
}

export function detectSystemLanguage() {
  const candidates = Array.isArray(navigator.languages) && navigator.languages.length
    ? navigator.languages
    : [navigator.language || 'en'];
  for (const candidate of candidates) {
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

export function normalizeSetting(raw) {
  const lower = String(raw || '').trim().toLowerCase();
  if (!lower || lower === 'auto' || lower === 'system') return 'auto';
  const explicit = normalizeLanguage(lower);
  if (explicit === 'en' && !(lower === 'en' || lower.startsWith('en-') || lower.startsWith('en_'))) return 'auto';
  return explicit;
}

export function resolveLanguage(setting) {
  const normalized = normalizeSetting(setting);
  return normalized === 'auto' ? detectSystemLanguage() : normalized;
}

export function languageDisplayName(code) {
  const found = LANGUAGES.find((entry) => entry.code === normalizeLanguage(code));
  return found ? found.label : 'English';
}

export function htmlLangFor(code) {
  const found = LANGUAGES.find((entry) => entry.code === normalizeLanguage(code));
  return found ? found.htmlLang : 'en';
}

export function translate(lang, zh, en) {
  const code = normalizeLanguage(lang);
  if (code === 'zh') return zh;
  if (code === 'en') return en;
  const idx = LANG_INDEX[code];
  if (idx === undefined) return en;
  const enKey = String(en ?? '');
  const exact = DICT[enKey];
  if (exact && exact[idx] !== undefined) return exact[idx];
  for (const [regex, builder] of PATTERNS) {
    const match = enKey.match(regex);
    if (match) return builder(match)[idx];
  }
  if (enKey.includes('New:') && enKey.includes('Passkeys:')) {
    const m = enKey.match(/^(.+?) · New: (\d+), Identical skipped: (\d+), Renamed conflicts: (\d+) · Passkeys: (\d+), Trash: (\d+)$/);
    if (m) {
      return [
        `${m[1]} · 新增 ${m[2]} 項，略過相同 ${m[3]} 項，衝突另存 ${m[4]} 項 · Passkey ${m[5]} 個，回收桶 ${m[6]} 項`,
        `${m[1]} · 新規 ${m[2]}、重複スキップ ${m[3]}、改名保存 ${m[4]} · パスキー ${m[5]}、ゴミ箱 ${m[6]}`,
        `${m[1]} · 신규 ${m[2]}, 동일 건너뜀 ${m[3]}, 충돌 별도 저장 ${m[4]} · 패스키 ${m[5]}, 휴지통 ${m[6]}`,
        `${m[1]} · Nuevos: ${m[2]}, omitidos: ${m[3]}, renombrados: ${m[4]} · Passkeys: ${m[5]}, papelera: ${m[6]}`,
      ][idx];
    }
  }
  return en;
}

store.language = detectSystemLanguage();

export function localized(zh, en) {
  return translate(store.language, zh, en);
}

export function applyLanguage() {
  store.language = resolveLanguage(store.languagePreference);
  document.documentElement.lang = htmlLangFor(store.language);
  window.OpenKeyletAppearance?.setLanguage?.(localized);
  api.syncAppearanceTheme({ resolvedLanguage: store.language }).catch?.(() => {});
  const langButtons = $$('.language-switch button');
  let activeIndex = 0;
  langButtons.forEach((button, index) => {
    const isActive = button.dataset.language === store.languagePreference;
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
      if (label) {
        if (target === 'label-html') label.innerHTML = copy;
        else label.textContent = copy;
      }
    }
  }
  if (isMacOS) {
    $('[data-module="SYSTEM / 01"] .settings-heading p').textContent = localized(
      '控制 OpenKeylet 的登录时启动。',
      'Control whether OpenKeylet launches at login.',
    );
  }
  if (store.languagePreference === 'auto' && $('#language-option small')) {
    const systemName = languageDisplayName(store.language);
    $('#language-option small').textContent = localized(`跟随系统语言（${systemName}）`, `Following system (${systemName})`);
  }
  hooks.syncItemTypeFilter?.();
  hooks.syncActivityFilterControl?.();
  hooks.syncSettingsFilterControl?.();
  hooks.syncTitleSearch?.();
  if (store.state) hooks.syncCheckAllButton?.();
  store.importHub?.render?.();
  if (store.mvaultState && !$('#mvault-import-modal')?.classList.contains('hidden')) {
    if (store.mvaultState.preview) hooks.renderMvaultSelectPanel?.();
    else if (store.mvaultState.requiresPassword) hooks.renderMvaultUnlockPanel?.($('#mvault-unlock-error')?.textContent || '');
  }
  if (store.editorExistingItem && !$('#connection-modal')?.classList.contains('hidden')) {
    hooks.renderAgentNotes?.(store.editorExistingItem, { autoOpen: false });
  }
}

export async function setLanguage(next) {
  const selected = normalizeSetting(next);
  if (selected === store.languagePreference) return;
  store.languagePreference = selected;
  applyLanguage();
  if (store.state) {
    store.state.settings.language = store.languagePreference;
    hooks.renderOwnerLock?.();
    hooks.render?.();
    hooks.syncModuleDraft?.();
    if (!$('#connection-modal').classList.contains('hidden')) {
      hooks.renderModules?.();
      hooks.updateEditorTitle?.();
    }
    try {
      store.state.settings = await api.settings({ language: store.languagePreference });
    } catch (error) {
      hooks.toast?.(hooks.cleanError?.(error) || String(error), 'error');
    }
  }
}

export const OpenKeyletI18n = {
  LANGUAGES,
  SUPPORTED_SET,
  normalizeLanguage,
  detectSystemLanguage,
  normalizeSetting,
  resolveLanguage,
  languageDisplayName,
  htmlLangFor,
  translate,
};

window.OpenKeyletI18n = OpenKeyletI18n;
