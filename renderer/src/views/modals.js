/* Secondary modals: password generator, backup password, Bitwarden/CSV/SSH migration, trash & history. */
import { $ } from '../core/dom.js';
import { store, hooks } from '../core/store.js';
import { api } from '../core/api.js';
import { cleanError, toast, confirmDestructiveAction, toastImportSummary } from '../core/feedback.js';
import { itemTypeLabel } from '../core/item-schema.js';
import { localized } from '../i18n/index.js';
import { refreshOwnerLock } from './owner-lock.js';
import { setModuleMenu, syncModuleDraft } from './editor.js';
import { openMvaultPreviewFlow, closeMvaultImportModal } from './mvault-import.js';

const migrationWarnings = {
  nonWebUris: ['非网页地址已保留，设为“不匹配”。', 'Non-web addresses are preserved with matching disabled.'],
  defaultDomainMatch: ['未指定规则的网址使用主域名匹配；保存的协议和端口必须一致。可在项目内调整。', 'Unspecified rules use base-domain matching, with matching scheme and port. Edit rules in the item.'],
  unsupportedTotp: ['部分验证码密钥格式尚不支持生成；原始密钥已保留。', 'Some TOTP formats cannot generate codes yet; their original keys are preserved.'],
  passkeyCounter: ['包含旧版计数型 Passkey。导入后请只在 OpenKeylet 中使用这些 Passkey，避免另一副本的计数超前。', 'Includes legacy counter-based passkeys. Use these only in OpenKeylet after migration to avoid diverging counters.'],
  linkedFields: ['关联字段已作为加密自定义字段保留，暂不自动关联填写。', 'Linked fields are preserved as encrypted custom fields; automatic linking is unavailable.'],
  passwordHistory: ['最近 20 条旧密码会进入密码历史，更早的记录保留在加密自定义字段中。', 'The latest 20 previous passwords appear in history; older records are archived in an encrypted custom field.'],
  reprompt: ['原逐项主密码验证设置不生效；本地 PIN 锁仍适用。', 'Source per-item master-password reprompt settings are not applied; the local PIN lock still applies.'],
  attachments: ['JSON 不含附件文件内容；请从原密码库单独保留附件。', 'JSON does not contain attachment files. Keep them separately from the source vault.'],
  organization: ['组织项目将成为本地个人项目，不保留共享权限。', 'Organization items become local personal items without sharing permissions.'],
  sshKeyNotFound: ['部分主机引用的本机私钥文件不存在或不可读，已仅导入主机与账号信息。', 'Some hosts referenced local key files that were missing or unreadable; host and user details were still imported.'],
};

export function finishBackupPassword(result) {
  $('#backup-password-form').reset();
  $('#backup-password-modal').classList.add('hidden');
  const resolve = store.backupPasswordResolve;
  store.backupPasswordResolve = null;
  resolve?.(result);
}

export function askBackupPassword(exporting, fileName = '') {
  setModuleMenu(false);
  finishBackupPassword(null);
  store.backupPasswordExport = exporting;
  $('#backup-password-title').textContent = exporting
    ? localized('导出加密备份', 'EXPORT ENCRYPTED BACKUP')
    : localized('输入备份密码', 'UNLOCK .MVAULT BACKUP');
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
  $('#backup-password-modal').classList.remove('hidden');
  $('#backup-password').focus();
  return new Promise((resolve) => { store.backupPasswordResolve = resolve; });
}

export async function exportBackup(button) {
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

export async function importBackup(button) {
  await refreshOwnerLock();
  if (!store.ownerLockState.unlocked) return;
  if (button) button.disabled = true;
  try {
    const picked = await api.pickBackupImportFile();
    if (!picked) return;
    await openMvaultPreviewFlow(picked);
  } catch (error) {
    toast(cleanError(error), 'error');
  } finally {
    if (button) button.disabled = false;
  }
}

export function closeGenerator() {
  store.generatorSequence++;
  $('#generator-modal').classList.add('hidden');
  $('#generator-result').value = '';
  store.generatorTarget = null;
}

export async function generatePassword() {
  const sequence = ++store.generatorSequence;
  try {
    const options = { length: Number($('#generator-length').value) };
    for (const key of ['uppercase', 'lowercase', 'digits', 'symbols']) options[key] = $(`#generator-${key}`).checked;
    const result = await api.generatePassword(options);
    if (sequence === store.generatorSequence && !$('#generator-modal').classList.contains('hidden')) {
      $('#generator-result').value = result;
    }
  } catch (error) {
    toast(cleanError(error), 'error');
  }
}

export function openGenerator(target = null) {
  setModuleMenu(false);
  store.generatorTarget = target;
  $('#generator-use').classList.toggle('hidden', !target);
  $('#generator-modal').classList.remove('hidden');
  generatePassword();
  requestAnimationFrame(() => $('#generator-length')?.focus());
}

export function closeVaultManagement() {
  store.vaultManagementSequence++;
  store.vaultManagement = null;
  $('#vault-management-modal').classList.add('hidden');
  $('#vault-management-list').replaceChildren();
  $('#history-clear').classList.add('hidden');
}

export async function openVaultManagement(mode, id = null) {
  await refreshOwnerLock();
  if (!store.ownerLockState.unlocked) return;
  const sequence = ++store.vaultManagementSequence;
  store.vaultManagement = { mode, id };
  $('#vault-management-title').textContent = mode === 'trash' ? localized('回收站', 'TRASH') : localized('密码历史', 'PASSWORD HISTORY');
  $('#vault-management-help').textContent = mode === 'trash'
    ? localized('已删除项目会保留到你选择永久删除。恢复时如有同名项目，会自动改名。', 'Deleted items remain until you permanently delete them. Restored items are renamed if necessary.')
    : localized('保留最近 20 条旧密码；密码历史不会提供给 Agent 或自动填写。', 'The latest 20 previous passwords are kept. History is unavailable to agents and autofill.');
  $('#vault-management-list').textContent = localized('正在读取…', 'Loading…');
  $('#history-clear').classList.add('hidden');
  $('#vault-management-modal').classList.remove('hidden');
  try {
    const data = mode === 'trash' ? await api.trash() : await api.history(id);
    if (sequence !== store.vaultManagementSequence) return;
    const list = $('#vault-management-list');
    list.replaceChildren();
    const entries = mode === 'trash' ? data : data.entries;
    if (!entries.length) {
      list.textContent = mode === 'trash' ? localized('回收站为空', 'Trash is empty') : localized('暂无旧密码', 'No previous passwords');
      return;
    }
    if (mode === 'history') {
      store.vaultManagement.updatedAt = data.updatedAt;
      $('#history-clear').classList.remove('hidden');
    }
    for (const entry of entries) {
      const row = document.createElement('section');
      row.className = 'vault-management-row';
      const title = document.createElement('strong');
      const date = new Date(mode === 'trash' ? entry.deletedAt : entry.changedAt).toLocaleString(store.language === 'zh' ? 'zh-CN' : 'en');
      title.textContent = mode === 'trash' ? `${entry.item.name} · ${itemTypeLabel(entry.item.itemType)}` : date;
      const actions = document.createElement('div');
      actions.className = 'button-row';
      row.append(title);
      if (mode === 'trash') {
        const subtitle = document.createElement('small');
        subtitle.textContent = date;
        row.append(subtitle);
        for (const action of ['restore', 'purge']) {
          const button = document.createElement('button');
          button.type = 'button';
          button.className = action === 'purge' ? 'button danger-soft' : 'button';
          button.textContent = action === 'restore' ? localized('恢复', 'RESTORE') : localized('永久删除', 'DELETE FOREVER');
          button.dataset.trashAction = action;
          button.onclick = async () => {
            if (action === 'purge' && !await confirmDestructiveAction({
              title: localized('永久删除此项目？', 'Permanently delete this item?'),
              message: localized('本机回收站中的秘密和 Passkey 将被移除，无法撤销。已有备份不会被改动。', 'The item and its passkeys will be removed from this vault permanently. Existing backups are unchanged.'),
            })) return;
            button.disabled = true;
            try {
              await api[action](entry.item.id, entry.deletedAt);
              await hooks.refresh?.();
              if (sequence === store.vaultManagementSequence) await openVaultManagement('trash');
            } catch (error) {
              toast(cleanError(error), 'error');
              button.disabled = false;
            }
          };
          actions.append(button);
        }
      } else {
        const input = document.createElement('input');
        input.className = 'input';
        input.type = 'password';
        input.readOnly = true;
        input.autocomplete = 'off';
        input.value = entry.password;
        input.setAttribute('aria-label', localized('旧密码', 'Previous password'));
        const reveal = document.createElement('button');
        reveal.type = 'button';
        reveal.className = 'button';
        reveal.textContent = localized('显示', 'SHOW');
        reveal.onclick = () => {
          input.type = input.type === 'password' ? 'text' : 'password';
          reveal.textContent = input.type === 'password' ? localized('显示', 'SHOW') : localized('隐藏', 'HIDE');
        };
        const copy = document.createElement('button');
        copy.type = 'button';
        copy.className = 'button';
        copy.textContent = localized('复制', 'COPY');
        copy.onclick = async () => {
          try {
            await api.copyOwnerValue(input.value, true);
            toast(localized('已复制（30 秒后自动清除）', 'Copied · clears in 30s'));
          } catch (error) {
            toast(cleanError(error), 'error');
          }
        };
        row.append(input);
        actions.append(reveal, copy);
      }
      row.append(actions);
      list.append(row);
    }
  } catch (error) {
    if (sequence === store.vaultManagementSequence) $('#vault-management-list').textContent = cleanError(error);
  }
}

function migrationHelp() {
  const format = $('#migration-format').value;
  $('#migration-scan-ssh')?.classList.toggle('hidden', format !== 'ssh_config');
  if (format === 'mvault') {
    $('#migration-help').textContent = localized(
      '选择 OpenKeylet .mvault 备份包（支持新版密码保护包及旧版 v3–v7 / CLI 自解锁包）。先预览条目与冲突重命名再确认合并。',
      'Choose an OpenKeylet .mvault package (supports current password-protected and legacy v3–v7 / CLI backups). Preview items and conflict renames before merging.',
    );
    return;
  }
  if (format === 'ssh_config') {
    $('#migration-help').textContent = localized(
      '扫描本机 ~/.ssh/config 或选择自定义 SSH 配置文件，自动导入主机、端口、用户名及关联的私钥文件（先预览再确认）。',
      'Scan your local ~/.ssh/config or choose an SSH config file to import hosts, ports, users, and linked private keys with a preview first.',
    );
    return;
  }
  if (format === 'env') {
    $('#migration-help').textContent = localized(
      '选择项目中的 .env 文件，把其中的 KEY=VALUE 加密存为一个安全项目（所有密钥默认对 Agent 隐藏，可通过 {{openkeylet:KEY}} 注入）。',
      'Choose a .env file to store its KEY=VALUE secrets encrypted in one vault item (hidden from agents by default; injectable via {{openkeylet:KEY}}).',
    );
    return;
  }
  if (format === 'onepassword') {
    $('#migration-help').textContent = localized(
      '在 1Password 桌面端选择「导出 → 1Password 交换格式 (.1pux)」，自动导入登录账号、2FA、SSH 密钥、API 凭据、卡片和笔记（跳过已归档项目）。',
      'Export as 1Password Unencrypted Export (.1pux) from 1Password desktop to import logins, 2FA, SSH keys, API credentials, cards, and notes (archived items are skipped).',
    );
    return;
  }
  if (format === 'keepass') {
    $('#migration-help').textContent = localized(
      '支持直接选择 KeePass / KeePassXC 的加密 .kdbx 数据库（弹窗输入主密码解锁并勾选导入），也支持 KeePass 2.x XML 导出。',
      'Choose a KeePass / KeePassXC encrypted .kdbx database (unlock with master password and select items) or a KeePass 2.x XML export.',
    );
    return;
  }
  $('#migration-help').textContent = format === 'bitwarden'
    ? localized('支持 Bitwarden 未加密 JSON，以及「密码保护加密 JSON」（自动弹窗输入导出密码解密并勾选导入）；原文件不变。', 'Supports both Bitwarden unencrypted JSON and password-protected encrypted JSON (unlock & preview items before importing). Source file stays unchanged.')
    : localized('选择 Chrome 或 Edge 导出的密码 CSV。支持带引号、逗号和多行备注的文件。', 'Choose a password CSV exported by Chrome or Edge. Quoted fields, commas and multiline notes are supported.');
}

export function resetMigration() {
  store.migrationSequence++;
  store.migrationId = null;
  store.migrationMode = 'migration';
  $('#migration-preview').replaceChildren();
  $('#migration-preview').classList.add('hidden');
  $('#migration-confirm').classList.add('hidden');
  $('#migration-error').classList.add('hidden');
}

export function closeMigration() {
  resetMigration();
  $('#migration-modal').classList.add('hidden');
  api.cancelImport().catch(() => {});
  api.cancelBackupImport().catch(() => {});
}

export function topSecondaryModal() {
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

export function initSecondaryModals() {
  $('#header-export-backup-button').addEventListener('click', (event) => exportBackup(event.currentTarget));
  $('#header-import-backup-button').addEventListener('click', (event) => importBackup(event.currentTarget));
  $('#safe-export-backup-button')?.addEventListener('click', (event) => exportBackup(event.currentTarget));
  $('#safe-import-backup-button')?.addEventListener('click', (event) => importBackup(event.currentTarget));

  $('#backup-password-close').onclick = () => finishBackupPassword(null);
  $('#backup-password-form').onsubmit = (e) => {
    e.preventDefault();
    const password = $('#backup-password').value;
    if (store.backupPasswordExport && ([...password].length < 12 || password !== $('#backup-password-confirm').value)) {
      return toast(localized('密码须至少 12 个字符，且两次输入一致', 'Use at least 12 characters and matching passwords'), 'error');
    }
    finishBackupPassword(password);
  };

  $('#generator-open').onclick = () => openGenerator();
  $('#generator-close').onclick = closeGenerator;
  $('#generator-regenerate').onclick = generatePassword;
  $('#generator-copy').onclick = async () => {
    try {
      if ($('#generator-result').value) {
        await api.copyOwnerValue($('#generator-result').value, true);
        toast(localized('已复制（30 秒后自动清除）', 'Copied · clears in 30s'));
      }
    } catch (error) {
      toast(cleanError(error), 'error');
    }
  };
  $('#generator-use').onclick = () => {
    if (store.generatorTarget?.isConnected && $('#generator-result').value) {
      store.generatorTarget.value = $('#generator-result').value;
      store.generatorTarget.dispatchEvent(new Event('input', { bubbles: true }));
      syncModuleDraft();
    }
    closeGenerator();
  };

  document.addEventListener('click', (e) => {
    const button = e.target.closest('[data-generate-password]');
    if (button) openGenerator($('[data-secret-value]', button.closest('.module-row')));
    const totpButton = e.target.closest('[data-copy-totp-code]');
    if (totpButton) {
      const secret = $('[data-secret-value]', totpButton.closest('.module-row'))?.value?.trim() || '';
      if (!secret) {
        toast(localized('请先输入 TOTP 密钥', 'Enter a TOTP setup key first'), 'error');
        return;
      }
      api.copyTotpCode(secret)
        .then((res) => toast(localized(
          `2FA 验证码已复制（剩余 ${res?.remainingSeconds ?? 30}s，30 秒后清除）`,
          `2FA code copied (${res?.remainingSeconds ?? 30}s left · clears in 30s)`,
        )))
        .catch((error) => toast(cleanError(error), 'error'));
    }
  });

  $('#trash-open').onclick = () => openVaultManagement('trash');
  $('#vault-management-close').onclick = closeVaultManagement;
  $('#history-clear').onclick = async () => {
    const snapshot = store.vaultManagement;
    if (snapshot?.mode !== 'history' || !await confirmDestructiveAction({
      title: localized('清除密码历史？', 'Clear password history?'),
      message: localized('只清除旧密码，当前密码保持不变。此操作无法撤销。', 'Previous passwords will be removed permanently. The current password is preserved.'),
    })) return;
    try {
      await api.clearHistory(snapshot.id, snapshot.updatedAt);
      await hooks.refresh?.();
      if (store.vaultManagement === snapshot) await openVaultManagement('history', snapshot.id);
    } catch (error) {
      toast(cleanError(error), 'error');
    }
  };

  $('#migration-open').onclick = async () => {
    await refreshOwnerLock();
    if (!store.ownerLockState.unlocked) return;
    if ($('#migration-format').value === 'mvault') $('#migration-format').value = 'bitwarden';
    resetMigration();
    migrationHelp();
    $('#migration-modal').classList.remove('hidden');
  };
  $('#migration-close').onclick = closeMigration;
  $('#migration-format').onchange = () => {
    resetMigration();
    api.cancelImport().catch(() => {});
    api.cancelBackupImport().catch(() => {});
    migrationHelp();
  };
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
    resetMigration();
    const sequence = store.migrationSequence;
    $('#migration-select').disabled = true;
    try {
      const result = await api.prepareImport($('#migration-format').value);
      if (!result || sequence !== store.migrationSequence) return;
      if (result.redirectVaultPackage) {
        await openMvaultPreviewFlow(result.redirectVaultPackage);
        return;
      }
      store.migrationId = result.id;
      store.migrationMode = 'migration';
      const p = result.preview;
      const lines = [
        localized(`可导入 ${p.total} 项 · Passkey ${p.passkeys} 个`, `${p.total} items · ${p.passkeys} passkeys`),
        ...Object.entries(p.types).map(([type, count]) => `${itemTypeLabel(type)}: ${count}`),
        ...(p.skippedDeleted ? [localized(`跳过回收站项目 ${p.skippedDeleted} 项`, `Skipped ${p.skippedDeleted} deleted items`)] : []),
        ...p.warnings.map((key) => (migrationWarnings[key] ? localized(...migrationWarnings[key]) : key)),
      ];
      const preview = $('#migration-preview');
      preview.replaceChildren(...lines.map((line) => { const el = document.createElement('p'); el.textContent = line; return el; }));
      preview.classList.remove('hidden');
      $('#migration-confirm').classList.toggle('hidden', p.total === 0);
    } catch (error) {
      if (sequence === store.migrationSequence) {
        $('#migration-error').textContent = cleanError(error);
        $('#migration-error').classList.remove('hidden');
      }
    } finally {
      $('#migration-select').disabled = false;
    }
  };

  $('#migration-scan-ssh')?.addEventListener('click', async () => {
    resetMigration();
    const sequence = store.migrationSequence;
    const btn = $('#migration-scan-ssh');
    btn.disabled = true;
    try {
      const result = await api.prepareSshConfigImport(true);
      if (!result || sequence !== store.migrationSequence) return;
      store.migrationId = result.id;
      store.migrationMode = 'migration';
      const p = result.preview;
      const lines = [
        ...(result.sourcePath ? [result.sourcePath] : []),
        localized(`可导入 ${p.total} 项 SSH 配置`, `${p.total} SSH host(s) ready to import`),
        ...Object.entries(p.types).map(([type, count]) => `${itemTypeLabel(type)}: ${count}`),
        ...p.warnings.map((key) => (migrationWarnings[key] ? localized(...migrationWarnings[key]) : key)),
      ];
      const preview = $('#migration-preview');
      preview.replaceChildren(...lines.map((line) => { const el = document.createElement('p'); el.textContent = line; return el; }));
      preview.classList.remove('hidden');
      $('#migration-confirm').classList.toggle('hidden', p.total === 0);
    } catch (error) {
      if (sequence === store.migrationSequence) {
        $('#migration-error').textContent = cleanError(error);
        $('#migration-error').classList.remove('hidden');
      }
    } finally {
      btn.disabled = false;
    }
  });

  $('#migration-confirm').onclick = async () => {
    if (!store.migrationId) return;
    $('#migration-confirm').disabled = true;
    try {
      const result = store.migrationMode === 'mvault'
        ? await api.commitBackupImport(store.migrationId)
        : await api.commitImport(store.migrationId);
      closeMigration();
      toastImportSummary(result);
      await hooks.refresh?.();
    } catch (error) {
      $('#migration-error').textContent = cleanError(error);
      $('#migration-error').classList.remove('hidden');
    } finally {
      $('#migration-confirm').disabled = false;
    }
  };
}
