/* Owner PIN lock overlay, auto-lock activity touch, and plaintext wipe. */
import { $, $$ } from '../core/dom.js';
import { store, hooks } from '../core/store.js';
import { api } from '../core/api.js';
import { cleanError, toast, finishConfirmation } from '../core/feedback.js';
import { localized } from '../i18n/index.js';

export function pinInputs(id) {
  return $$(`[data-pin-group="${id}"] .pin-cell-input`);
}

export function readPin(id) {
  return pinInputs(id).map((input) => input.value).join('');
}

export function clearPin(id) {
  pinInputs(id).forEach((input) => { input.value = ''; });
}

export function focusPin(id) {
  const inputs = pinInputs(id);
  (inputs.find((input) => !input.value) || inputs[inputs.length - 1])?.focus();
}

export function clearOwnerPlaintext() {
  void hooks.finishSwitchDrag?.(false);
  hooks.finishItemPointerDrag?.(false);
  hooks.clearAutoCheckTimer?.();
  store.checkAllRunId += 1;
  store.checkAllRunning = false;
  store.lastCheckAllOutcome = '';
  store.itemCheckStates.clear();
  hooks.syncCheckAllButton?.();
  store.githubBackup?.clearSecrets();
  store.appUpdater?.closeModal();
  finishConfirmation(false, false);
  hooks.closeEditor?.();
  store.currentModules.forEach((module) => { module.secretValue = ''; });
  $$('[data-secret-value]').forEach((input) => { input.value = ''; });
}

export function renderOwnerLock() {
  const configured = Boolean(store.ownerLockState.pinConfigured);
  const unlocked = Boolean(store.ownerLockState.unlocked);
  const setupRequested = store.ownerPinSetupRequested && !configured;
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

  if (locked) {
    if (!$('#vault-management-modal').classList.contains('hidden')) hooks.closeVaultManagement?.();
    if (!$('#migration-modal').classList.contains('hidden')) hooks.closeMigration?.();
    if (!$('#mvault-import-modal')?.classList.contains('hidden')) hooks.closeMvaultImportModal?.();
    hooks.setGlobalMvaultDropOverlay?.(false);
    hooks.closeGenerator?.();
    hooks.finishBackupPassword?.(null);
    clearOwnerPlaintext();
    store.importHub?.clearPlaintext?.();
    store.editorDrafts = [];
    hooks.renderDrafts?.();
  }
  clearPin('owner-pin');
  clearPin('owner-pin-confirm');
  if (layerVisible) setTimeout(() => focusPin('owner-pin'), 0);
}

export async function refreshOwnerLock(showError = true) {
  const wasUnlocked = Boolean(store.ownerLockState.unlocked);
  try {
    store.ownerLockState = await api.ownerStatus();
    renderOwnerLock();
    if (wasUnlocked && store.ownerLockState.pinConfigured && !store.ownerLockState.unlocked) {
      await hooks.refresh?.(false);
    }
  } catch (error) {
    if (showError) toast(cleanError(error), 'error');
  }
}

export async function lockOwner() {
  window.OpenKeyletAppearance?.play?.('lock');
  try { store.ownerLockState = await api.ownerLock(); } catch (_) { store.ownerLockState.unlocked = false; }
  renderOwnerLock();
  await hooks.refresh?.(false);
}

let lastOwnerTouchAt = 0;

export function touchOwnerActivity() {
  if (!store.ownerLockState.pinConfigured || !store.ownerLockState.unlocked || !Number(store.state?.settings?.ownerAutoLockMinutes || 0)) return;
  const now = Date.now();
  if (now - lastOwnerTouchAt < 20_000) return;
  lastOwnerTouchAt = now;
  api.ownerTouch().then((next) => {
    if (next && typeof next.unlocked === 'boolean') {
      const wasUnlocked = store.ownerLockState.unlocked;
      store.ownerLockState = next;
      if (wasUnlocked && next.pinConfigured && !next.unlocked) {
        renderOwnerLock();
        hooks.refresh?.(false);
      }
    }
  }).catch(() => {});
}

export function initOwnerLock() {
  $('#owner-lock-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = $('#owner-unlock-action');
    const cancelButton = $('#owner-pin-cancel');
    let pin = readPin('owner-pin');
    if (!/^\d{6}$/.test(pin)) return toast(localized('PIN 必须是六位数字', 'PIN must contain six digits'), 'error');
    if (!store.ownerLockState.pinConfigured && pin !== readPin('owner-pin-confirm')) {
      return toast(localized('两次 PIN 不一致', 'PIN entries do not match'), 'error');
    }
    button.disabled = true;
    cancelButton.disabled = true;
    try {
      const settingPin = !store.ownerLockState.pinConfigured;
      store.ownerLockState = settingPin
        ? await api.ownerSetPin(pin)
        : await api.ownerUnlock(pin);
      pin = '';
      store.ownerPinSetupRequested = false;
      window.OpenKeyletAppearance?.play?.(settingPin ? 'success' : 'unlock');
      renderOwnerLock();
      if (settingPin) toast(localized('PIN 锁已开启', 'PIN lock enabled'));
      await hooks.refresh?.(false);
      await hooks.refreshDrafts?.(true);
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
    store.ownerPinSetupRequested = false;
    renderOwnerLock();
    hooks.renderSettings?.();
  });

  window.addEventListener('pointerdown', touchOwnerActivity, { passive: true });
  window.addEventListener('keydown', touchOwnerActivity, { passive: true });
  setInterval(() => {
    if (store.ownerLockState.pinConfigured && store.ownerLockState.unlocked && Number(store.state?.settings?.ownerAutoLockMinutes || 0) > 0) {
      refreshOwnerLock(false);
    }
  }, 15_000);
}
