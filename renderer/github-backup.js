/* GitHub backup UI. No credentials are persisted in browser storage. */
window.OpenKeyletGithubBackup = {
  create({ invoke, localized, toast, isUnlocked, confirmAction, onRestore }) {
    const $ = (id) => document.getElementById(id);
    const modal = $('github-modal');
    let status = { connected: false };
    let busy = false;
    let refreshing = false;
    let secretEpoch = 0;
    let previousFocus;
    let inertElements = [];
    let lastError = '';
    let formError = '';
    let accountLogin = '';

    const copy = {
      'github-heading': ['个人加密仓库（可选）', 'PERSONAL VAULT REPO (OPTIONAL)'],
      'github-description': ['将密码库加密存放到你自己的私有 GitHub / Gitea 仓库，支持多端自动双向同步。', 'Store your encrypted vault in your own private GitHub or Gitea repo with optional two-way sync.'],
      'github-repository-label': ['仓库', 'Repository'],
      'github-backup-label': ['上次同步/上传', 'Last upload'],
      'github-restore-label': ['上次拉取/恢复', 'Last restore'],
      'github-auto-sync-label': ['自动双向同步', 'AUTO TWO-WAY SYNC'],
      'github-auto-sync-help': ['打开软件自动拉取合并，修改/删除项目后自动加密推送到私有仓库', 'Pull and merge on open; push encrypted changes automatically after edits.'],
      'github-connect': ['配置私有密码仓库', 'SET UP VAULT REPO'],
      'github-sync': ['立即同步', 'SYNC NOW'],
      'github-upload': ['仅上传', 'BACK UP NOW'],
      'github-restore': ['仅恢复', 'RESTORE'],
      'github-show-key': ['查看恢复密钥', 'RECOVERY KEY'],
      'github-reconfigure': ['更新连接', 'RECONNECT'],
      'github-disconnect': ['断开', 'DISCONNECT'],
      'github-saved-key-label': ['恢复密钥', 'Recovery key'],
      'github-copy-saved-key': ['复制密钥', 'COPY KEY'],
      'github-hide-key': ['隐藏', 'HIDE'],
      'github-key-warning': ['请保存在仓库之外。拥有此密钥及备份文件的人可以读取整个备份。', 'Keep this outside the repository. Anyone with this key and the backup can read its contents.'],
      'github-modal-title': ['配置私有密码仓库', 'Connect Vault Repository'],
      'github-step-auth': ['1 · 选择平台与账号', '1 · Platform & account'],
      'github-provider-label': ['仓库平台', 'Platform'],
      'github-provider-github': ['GitHub', 'GitHub'],
      'github-provider-gitea': ['Gitea / Forgejo（自建 HTTPS）', 'Gitea / Forgejo (Self-hosted HTTPS)'],
      'github-server-url-label': ['服务器地址（HTTPS）', 'Server URL (HTTPS)'],
      'github-step-repository': ['2 · 选择私有仓库', '2 · Choose a private repository'],
      'github-step-key': ['3 · 保管恢复密钥', '3 · Keep your recovery key'],
      'github-auth-label': ['授权方式', 'Authorization'],
      'github-auth-cli': ['使用本机 GitHub CLI 登录', 'Use local GitHub CLI login'],
      'github-auth-token': ['使用访问令牌', 'Use an access token'],
      'github-cli-help': ['已用 gh auth login 登录 GitHub 的用户可直接复用授权；仅安装 Git 不代表已登录。授权在连接后加密保存在本机。也可切换为访问令牌。', 'Reuse your gh auth login authorization. Installing Git alone does not sign you in. Authorization is stored encrypted on this device after connecting. You can also use an access token.'],
      'github-check-account': ['检查账号', 'CHECK ACCOUNT'],
      'github-login-help': ['GitHub 登录帮助 ↗', 'LOGIN HELP ↗'],
      'github-create-repository-label': ['由 OpenKeylet 在我的账号下创建此私有仓库', 'Create this private repository in my account'],
      'github-first-upload-label': ['连接成功后，立即上传第一份加密备份', 'Upload the first encrypted backup after connecting'],
      'github-connect-auto-sync-label': ['连接后开启自动双向同步（多端修改与删除自动合并）', 'Enable automatic two-way sync after connecting'],
      'github-repository-input-label': ['私有仓库', 'Private repository'],
      'github-create-repo': ['创建私有仓库 ↗', 'CREATE PRIVATE REPO ↗'],
      'github-create-token': ['创建访问令牌 ↗', 'CREATE ACCESS TOKEN ↗'],
      'github-token-label': ['访问令牌（PAT）', 'Access token'],
      'github-token-help': ['连接现有仓库：细粒度令牌选择该仓库，授予 Contents 读写权限。由程序创建新仓库还需创建仓库的授权（Administration 写入）；也可在网页先建私有仓库。令牌仅在本机加密保存。', 'For an existing repository, use a token with repository Contents read/write permission. Creating a repository also requires repository creation permission. Tokens are stored encrypted locally.'],
      'github-mode-label': ['连接方式', 'Connection mode'],
      'github-mode-new': ['创建新仓库备份', 'Create a new vault backup'],
      'github-mode-existing': ['连接已有密码仓库', 'Connect an existing vault repo'],
      'github-key-label': ['恢复密钥', 'Recovery key'],
      'github-generate-key': ['生成恢复密钥', 'GENERATE KEY'],
      'github-copy-key': ['复制密钥', 'COPY KEY'],
      'github-recovery-help': ['换机时需要这把密钥。请另行保管；密钥丢失且没有已连接设备时，无法恢复云端密码库。', 'You need this key on a new device. Keep a separate copy: without it or a connected device, the encrypted repo cannot be recovered.'],
      'github-key-saved-label': ['已将恢复密钥保存到仓库之外', 'I saved the recovery key outside the repository'],
      'github-local-only': ['连接成功后，可随时同步或手动备份。', 'Connect first, then sync or back up anytime.'],
      'github-submit': ['连接仓库', 'CONNECT'],
    };

    const errors = {
      GITHUB_CLI_MISSING: ['未找到 GitHub CLI（gh）。可安装并登录，或改用访问令牌。', 'GitHub CLI (gh) was not found. Install and sign in, or use an access token.'],
      GITHUB_CLI_AUTH: ['未能读取 GitHub CLI 登录。请先运行 gh auth login，或改用访问令牌。', 'Sign in with gh auth login first, or use an access token.'],
      GITHUB_CLI_TIMEOUT: ['读取本机 GitHub 登录超时，请重试或使用访问令牌。', 'Reading the local GitHub login timed out. Retry or use an access token.'],
      GITHUB_AUTH_SOURCE: ['请选择受支持的授权方式。', 'Choose a supported authorization method.'],
      GITHUB_CREATE_MODE: ['恢复已有备份时不能创建仓库。', 'Repository creation is unavailable when restoring an existing backup.'],
      GITHUB_CREATE_OWNER: ['只能在当前授权账号下创建仓库，请先检查账号。组织仓库请在 GitHub 建好后连接。', 'Create under the authenticated account. Check the account first. Create organization repositories on GitHub before connecting.'],
      GITHUB_REPOSITORY_EXISTS: ['仓库已存在或名称不可用。已有仓库请取消勾选“由 OpenKeylet 创建”，或使用其他名称。', 'The repository exists or its name is unavailable. Uncheck Create repository to connect an existing one, or choose another name.'],
      GITHUB_CREATE_UNCONFIRMED: ['创建仓库的结果尚未确认。请在 GitHub 检查；若已创建，取消勾选“由 OpenKeylet 创建”后连接。', 'Repository creation could not be confirmed. Check GitHub; if it exists, uncheck Create repository and connect.'],
      GITHUB_REPOSITORY_INVALID: ['请输入 owner/repository 或 GitHub 仓库链接。', 'Enter owner/repository or a GitHub repository URL.'],
      GITHUB_TOKEN_INVALID: ['请输入有效的 GitHub 访问令牌。', 'Enter a valid GitHub access token.'],
      GITHUB_KEY_INVALID: ['恢复密钥格式不正确。请完整粘贴以 okv1_ 开头的密钥。', 'Paste the complete recovery key beginning with okv1_.'],
      GITHUB_KEY_NOT_SAVED: ['请先将恢复密钥保存到仓库之外。', 'Save your recovery key outside the repository first.'],
      GITHUB_KEY_MISMATCH: ['密钥不匹配，或云端备份已损坏。本地数据未被恢复操作修改。', 'The key does not match, or the backup is damaged. No data was restored.'],
      GITHUB_PRIVATE_REQUIRED: ['只支持私有仓库。请检查仓库可见性。', 'Only private repositories are supported. Check its visibility.'],
      GITHUB_AUTH: ['令牌无效或已过期，请更新连接。', 'The token is invalid or expired. Reconnect with a new token.'],
      GITHUB_PERMISSION: ['无法访问仓库。请检查令牌的仓库选择、Contents 读写权限和组织授权。', 'Check the token’s repository access, Contents read/write permission, and organization approval.'],
      GITHUB_NOT_FOUND: ['找不到仓库或无权访问。请检查仓库名称和令牌权限。', 'Repository not found or inaccessible. Check its name and token permissions.'],
      GITHUB_BACKUP_EXISTS: ['仓库已有备份。请选择“连接已有备份”并使用原来的恢复密钥。', 'A backup already exists. Choose Connect an existing backup and use its original key.'],
      GITHUB_BACKUP_MISSING: ['没有找到云端备份。若要重新建立备份，请更新连接并选择“创建新备份”。', 'No remote backup was found. To start again, reconnect and choose Create a new backup.'],
      GITHUB_RESTORE_REQUIRED: ['请先恢复合并云端备份，再上传本机数据。', 'Restore and merge the remote backup before uploading this device.'],
      GITHUB_REMOTE_CHANGED: ['云端版本已变更，已停止上传。请先恢复合并；若云端已被删除，请重新连接。', 'The remote version changed. Upload stopped. Restore first, or reconnect if the remote file was deleted.'],
      GITHUB_CONFLICT: ['云端发生并发更新，或仓库规则拒绝了提交。请先恢复，并检查分支保护规则。', 'A concurrent update or repository rule rejected the write. Restore first and check branch protection.'],
      GITHUB_UPLOAD_UNCONFIRMED: ['上传结果尚未确认。请先恢复云端备份，确认最新版本后再上传。', 'Upload could not be confirmed. Restore the remote backup before uploading again.'],
      GITHUB_RATE_LIMIT: ['GitHub 暂时限制了请求。请稍后再试。', 'GitHub temporarily limited requests. Try again later.'],
      GITHUB_NETWORK: ['无法连接 GitHub。请检查网络后重试。', 'Cannot reach GitHub. Check your connection and try again.'],
      GITHUB_REDIRECT: ['仓库地址发生跳转。请使用仓库的最新地址重新连接。', 'The repository address redirects. Reconnect using its current address.'],
      GITHUB_REPOSITORY_CHANGED: ['该地址对应的仓库已改变。请重新连接。', 'This address now identifies a different repository. Reconnect to continue.'],
      GITHUB_BRANCH_CHANGED: ['默认分支已变更，请重新连接。', 'The default branch changed. Reconnect to continue.'],
      GITHUB_REPOSITORY_READ_ONLY: ['仓库已归档或停用，无法用于备份。', 'The repository is archived or disabled.'],
      GITHUB_BACKUP_INVALID: ['云端文件不是受支持的完整加密备份。', 'The remote file is not a valid supported encrypted backup.'],
      GITHUB_BACKUP_TOO_LARGE: ['备份超过当前 8 MB 限制，未上传或恢复。', 'The backup exceeds the current 8 MB limit. It was not uploaded or restored.'],
      GITHUB_NOT_CONNECTED: ['请先连接 GitHub 仓库。', 'Connect a GitHub repository first.'],
      GITHUB_LOCAL_STATE: ['无法读取或保存本机连接配置。请检查数据目录；可重新连接。', 'Cannot read or save the local connection. Check the data directory or reconnect.'],
      GITHUB_RESTORE_FAILED: ['恢复未完成，请检查备份和本机数据目录后重试。', 'Restore did not complete. Check the backup and local data directory.'],
      GITHUB_LOCAL_VAULT: ['无法读取本机保险库，请检查数据目录。', 'Cannot read the local vault. Check its data directory.'],
    };

    function errorText(error) {
      const code = String(error?.message || error).match(/GITHUB_[A-Z_]+/)?.[0];
      return errors[code] ? localized(...errors[code]) : localized('操作未完成，请检查连接后重试。', 'The operation did not complete. Check your connection and retry.');
    }

    function dateText(value) {
      return value ? new Date(value).toLocaleString(document.documentElement.lang, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : localized('尚无', 'Not yet');
    }

    function render() {
      for (const [id, values] of Object.entries(copy)) $(id).textContent = localized(...values);
      $('github-modal-close').setAttribute('aria-label', localized('关闭', 'Close'));
      $('github-backup-card').setAttribute('aria-busy', String(busy));
      const connected = status.connected && isUnlocked();
      const strip = $('github-status');
      strip.className = `status-strip ${lastError ? 'error' : connected ? '' : 'offline'}`;
      strip.textContent = busy ? localized('正在同步处理，请稍候…', 'Working, please wait…')
        : connected ? (status.needsRestore ? localized('待同步/恢复云端数据', 'SYNC / RESTORE REQUIRED')
          : status.autoSync ? localized('已连接 · 自动双向同步', 'CONNECTED · AUTO-SYNC')
            : localized('已连接 · 手动模式', 'CONNECTED · MANUAL'))
          : localized('未配置 · 仅本地离线（可选）', 'NOT CONNECTED · LOCAL ONLY');
      $('github-connect').classList.toggle('hidden', connected);
      for (const id of ['github-sync', 'github-upload', 'github-restore', 'github-details', 'github-auto-sync-section', 'github-manage']) $(id)?.classList.toggle('hidden', !connected);
      const providerPrefix = status.provider === 'gitea' && status.serverUrl ? `${status.serverUrl.replace(/^https?:\/\//, '')} · ` : '';
      $('github-repository-value').textContent = connected ? `${providerPrefix}${status.repository} · ${status.branch}` : '';
      $('github-backup-value').textContent = dateText(status.lastSyncedAt || status.lastBackupAt);
      $('github-restore-value').textContent = dateText(status.lastRestoreAt);
      if ($('github-auto-sync')) $('github-auto-sync').checked = Boolean(status.autoSync);
      $('github-note').textContent = connected && status.needsRestore
        ? localized('此设备需要先同步或恢复合并云端内容，才能上传。现有本地项目会保留。', 'Sync or restore the remote contents before uploading. Existing local items are kept.')
        : connected && status.autoSync
          ? localized('已开启自动同步：增删改后会自动加密推送，打开时自动拉取并按时间合并。本机 PIN、配对和 Agent 配置不会上传。', 'Auto-sync is on: edits push encrypted automatically and remote changes merge on open. Local PIN, pairing and agent setup never leave this device.')
          : localized('完全可选：所有条目经独立恢复密钥在本地端到端加密后才存入你的私有仓库。本机配对、PIN 和 Agent 配置不会上传。', 'Optional: your vault is encrypted end-to-end with your recovery key before touching your private repo. Pairing, PIN and agent setup stay local.');
      $('github-error').textContent = lastError ? errorText(lastError) : '';
      $('github-error').classList.toggle('hidden', !lastError);
      $('github-form-error').textContent = formError ? errorText(formError) : '';
      $('github-form-error').classList.toggle('hidden', !formError);
      for (const button of document.querySelectorAll('#github-backup-card button, #github-modal button')) button.disabled = busy || !isUnlocked();
      for (const input of document.querySelectorAll('#github-form input, #github-form select, #github-form textarea')) input.disabled = busy;
      if ($('github-auto-sync')) $('github-auto-sync').disabled = busy || !isUnlocked() || !connected;
      $('github-upload').disabled = busy || !isUnlocked() || status.needsRestore;
      $('github-restore').disabled = busy || !isUnlocked() || !status.hasRemoteBackup;
      const isGitea = $('github-provider')?.value === 'gitea';
      const isNew = $('github-mode').value === 'new';
      if (isGitea && $('github-auth-source').value === 'cli') $('github-auth-source').value = 'token';
      const useCli = !isGitea && $('github-auth-source').value === 'cli';
      $('github-server-url-section')?.classList.toggle('hidden', !isGitea);
      if ($('github-server-url')) $('github-server-url').required = isGitea;
      $('github-auth-source-field')?.classList.toggle('hidden', isGitea);
      $('github-check-account').classList.toggle('hidden', isGitea);
      $('github-create-repo').classList.toggle('hidden', isGitea);
      $('github-token-section').classList.toggle('hidden', useCli);
      $('github-cli-help').classList.toggle('hidden', !useCli);
      $('github-login-help').classList.toggle('hidden', !useCli);
      $('github-create-token').classList.toggle('hidden', useCli || isGitea);
      $('github-token').required = !useCli;
      $('github-account-status').textContent = accountLogin ? localized(`已验证 GitHub 账号：${accountLogin}`, `Verified GitHub account: ${accountLogin}`) : '';
      $('github-create-repository-field').classList.toggle('hidden', !isNew);
      $('github-first-upload-field').classList.toggle('hidden', !isNew);
      $('github-recovery-key').readOnly = isNew;
      $('github-generate-key').classList.toggle('hidden', !isNew);
      $('github-copy-key').disabled = busy || !$('github-recovery-key').value || !isUnlocked();
      $('github-local-only').textContent = isNew && $('github-first-upload').checked
        ? localized('将加密上传整个保险库。GitHub 不会收到恢复密钥。', 'The full vault will be encrypted and uploaded. GitHub never receives the recovery key.')
        : localized('仅保存连接。之后由你选择上传或恢复。', 'Save the connection, then choose upload or restore.');
      $('github-submit').textContent = busy ? localized('正在处理…', 'WORKING…') : isNew && $('github-first-upload').checked ? localized('连接并上传', 'CONNECT & UPLOAD') : localized(...copy['github-submit']);
    }

    async function refresh() {
      if (busy || refreshing || !isUnlocked()) return render();
      refreshing = true;
      try { status = await invoke('github_backup_status'); }
      catch (error) { lastError = error; }
      finally { refreshing = false; render(); }
    }

    function closeModal(restoreFocus = true) {
      secretEpoch += 1;
      modal.classList.add('hidden');
      $('github-form').reset();
      $('github-token').value = '';
      $('github-recovery-key').value = '';
      formError = '';
      accountLogin = '';
      inertElements.forEach((element) => { element.inert = false; });
      inertElements = [];
      if (restoreFocus && previousFocus?.isConnected && !previousFocus.closest('.hidden')) previousFocus.focus();
      previousFocus = null;
    }

    function clearSecrets() {
      closeModal(false);
      $('github-saved-key').value = '';
      $('github-key-display').classList.add('hidden');
    }

    function openModal() {
      if (busy || !isUnlocked()) return;
      clearSecrets();
      previousFocus = document.activeElement;
      $('github-provider').value = status.provider || 'github';
      if ($('github-server-url')) $('github-server-url').value = status.serverUrl || '';
      if ($('github-connect-auto-sync')) $('github-connect-auto-sync').checked = Boolean(status.autoSync);
      $('github-repository').value = status.repository || '';
      $('github-mode').value = status.hasRemoteBackup ? 'existing' : 'new';
      inertElements = [...document.body.children].filter((element) => element !== modal && !element.inert && !['SCRIPT', 'STYLE'].includes(element.tagName));
      inertElements.forEach((element) => { element.inert = true; });
      modal.classList.remove('hidden');
      render();
      $('github-repository').focus();
    }

    async function operate(action) {
      if (busy || !isUnlocked()) return;
      busy = true;
      lastError = '';
      render();
      try { await action(); }
      catch (error) { lastError = error; toast(errorText(error), 'error'); }
      finally { busy = false; await refresh(); }
    }

    $('github-connect').addEventListener('click', openModal);
    $('github-reconfigure').addEventListener('click', openModal);
    $('github-modal-close').addEventListener('click', () => { if (!busy) closeModal(); });
    modal.addEventListener('click', (event) => { if (event.target === modal && !busy) closeModal(); });
    modal.addEventListener('keydown', (event) => {
      event.stopPropagation();
      if (event.key === 'Escape') { event.preventDefault(); if (!busy) closeModal(); }
      if (event.key === 'Tab') {
        const focusable = [...modal.querySelectorAll('button, input, select, textarea')].filter((element) => !element.disabled && !element.closest('.hidden'));
        if (!focusable.length) { event.preventDefault(); return; }
        const index = focusable.indexOf(document.activeElement);
        if ((event.shiftKey && index <= 0) || (!event.shiftKey && index === focusable.length - 1)) {
          event.preventDefault(); focusable[event.shiftKey ? focusable.length - 1 : 0].focus();
        }
      }
    });
    $('github-mode').addEventListener('change', () => {
      secretEpoch += 1;
      $('github-recovery-key').value = '';
      $('github-key-saved').checked = false;
      render();
    });
    $('github-first-upload').addEventListener('change', render);
    $('github-provider')?.addEventListener('change', () => {
      secretEpoch++; accountLogin = ''; formError = ''; render();
    });
    $('github-auth-source').addEventListener('change', () => {
      secretEpoch++; accountLogin=''; formError=''; $('github-token').value=''; render();
    });
    $('github-token').addEventListener('input', () => { accountLogin=''; render(); });
    $('github-check-account').addEventListener('click', async () => {
      if (busy || !isUnlocked()) return;
      const epoch = secretEpoch;
      const input = {authSource:$('github-auth-source').value,token:$('github-token').value.trim()};
      busy=true;formError='';render();
      try {
        const account = await invoke('github_backup_account',{input});
        if(epoch!==secretEpoch || !isUnlocked() || modal.classList.contains('hidden'))return;
        accountLogin=account.login;
        if(!$('github-repository').value.trim()) $('github-repository').value=`${account.login}/openkeylet-vault`;
      } catch(error) { if(epoch===secretEpoch)formError=error; }
      finally { input.token='';busy=false;render(); }
    });
    $('github-recovery-key').addEventListener('input', () => { $('github-key-saved').checked = false; render(); });
    $('github-generate-key').addEventListener('click', async () => {
      const epoch = secretEpoch;
      try {
        const key = await invoke('github_backup_generate_key');
        if (epoch !== secretEpoch || !isUnlocked() || modal.classList.contains('hidden')) return;
        $('github-recovery-key').value = key;
        $('github-key-saved').checked = false;
        render();
      } catch (error) { formError = error; render(); }
    });
    async function copyKey(id) {
      const value = $(id).value;
      if (!value || !isUnlocked()) return;
      try { await invoke('copy_owner_value', { value, sensitive: true }); toast(localized('密钥已复制（30 秒后自动清除），请保存在仓库之外', 'Key copied (clears in 30s). Save it outside the repository.')); }
      catch (error) { toast(errorText(error), 'error'); }
    }
    $('github-copy-key').addEventListener('click', () => copyKey('github-recovery-key'));
    $('github-copy-saved-key').addEventListener('click', () => copyKey('github-saved-key'));
    $('github-show-key').addEventListener('click', async () => {
      const epoch = secretEpoch;
      try {
        const key = await invoke('github_backup_recovery_key');
        if (epoch !== secretEpoch || !isUnlocked()) return;
        $('github-saved-key').value = key;
        $('github-key-display').classList.remove('hidden');
        $('github-saved-key').focus();
      } catch (error) { lastError = error; render(); }
    });
    $('github-hide-key').addEventListener('click', clearSecrets);
    for (const button of document.querySelectorAll('[data-github-help]')) button.addEventListener('click', async () => {
      try { await invoke('github_backup_help', { page: button.dataset.githubHelp }); }
      catch (error) { formError = error; render(); }
    });
    $('github-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      if (busy || !isUnlocked()) return;
      if (!/^okv1_[A-Za-z0-9_-]{43}$/.test($('github-recovery-key').value.trim())) {
        formError = 'GITHUB_KEY_INVALID'; render(); return;
      }
      const provider = $('github-provider')?.value || 'github';
      const input = {
        repository: $('github-repository').value.trim(),
        token: $('github-token').value.trim(),
        recoveryKey: $('github-recovery-key').value.trim(),
        mode: $('github-mode').value,
        recoveryKeySaved: $('github-key-saved').checked,
        authSource: provider === 'gitea' ? 'token' : $('github-auth-source').value,
        createRepository: $('github-mode').value === 'new' && $('github-create-repository').checked,
        autoSync: Boolean($('github-connect-auto-sync')?.checked),
        provider,
        serverUrl: provider === 'gitea' ? ($('github-server-url')?.value.trim() || '') : '',
      };
      const firstUpload = input.mode==='new' && $('github-first-upload').checked;
      busy = true; formError = ''; render();
      let connected = false;
      try {
        status = await invoke('github_backup_connect', { input });
        input.token=''; input.recoveryKey='';
        connected = true;
        lastError = '';
        closeModal();
        if(firstUpload) {
          status=await invoke('github_backup_upload');
          toast(localized('第一份加密备份已上传到你的私有仓库', 'Your first encrypted backup is in your private repository.'));
        } else toast(status.needsRestore ? localized('连接成功，请先恢复云端备份', 'Connected. Restore the remote backup first.') : localized('连接成功，可以备份了', 'Connected. Ready to back up.'));
      } catch (error) {
        if(connected) { lastError=error;toast(localized('仓库已连接，但首次上传未完成。连接已保留，可按提示重试。', 'Connected, but the first upload did not complete. The connection is saved; follow the error to retry.'),'error'); }
        else formError = error;
      }
      finally { input.token = ''; input.recoveryKey = ''; busy = false; render(); }
    });
    $('github-sync')?.addEventListener('click', async () => {
      await operate(async () => {
        const result = await invoke('github_backup_sync');
        status = result.status;
        const labels = {
          up_to_date: localized('已是最新状态，无需上传', 'Already up to date'),
          pushed: localized('已加密推送到私有仓库', 'Encrypted vault pushed to repository'),
          pulled: localized(`已拉取云端更新（新增 ${result.merge.added}，更新 ${result.merge.updated}，删除 ${result.merge.deleted}）`, `Pulled remote changes (+${result.merge.added}, ~${result.merge.updated}, -${result.merge.deleted})`),
          merged: localized(`双向同步完成（新增 ${result.merge.added}，更新 ${result.merge.updated}，删除 ${result.merge.deleted}）`, `Two-way sync complete (+${result.merge.added}, ~${result.merge.updated}, -${result.merge.deleted})`),
        };
        toast(labels[result.action] || localized('同步完成', 'Sync complete'));
        if (result.merge.added || result.merge.updated || result.merge.deleted) await onRestore();
      });
    });
    $('github-auto-sync')?.addEventListener('change', async (event) => {
      const enabled = event.currentTarget.checked;
      await operate(async () => {
        status = await invoke('github_backup_set_auto_sync', { enabled });
        toast(enabled ? localized('已开启私有仓库自动双向同步', 'Automatic two-way sync enabled') : localized('已切换为手动备份模式', 'Switched to manual backup mode'));
      });
    });
    if (window.__TAURI__?.event?.listen) {
      window.__TAURI__.event.listen('cloud-sync-updated', (event) => {
        if (event?.payload && !busy) { status = event.payload; lastError = ''; render(); }
      });
      window.__TAURI__.event.listen('cloud-sync-error', (event) => {
        if (event?.payload && !busy) { lastError = event.payload; render(); }
      });
    }
    $('github-upload').addEventListener('click', async () => {
      if (busy || !await confirmAction({ title: localized('上传加密备份？', 'Upload encrypted backup?'), message: localized(`将整个保险库加密上传到 ${status.repository}。GitHub 历史会保留旧版密文。`, `Encrypt and upload the entire vault to ${status.repository}. GitHub history retains older encrypted snapshots.`), acceptLabel: localized('立即备份', 'BACK UP'), tag: localized('手动云端备份', 'MANUAL CLOUD BACKUP') })) return;
      await operate(async () => { status = await invoke('github_backup_upload'); toast(localized('加密备份已上传', 'Encrypted backup uploaded')); });
    });
    $('github-restore').addEventListener('click', async () => {
      if (busy || !await confirmAction({ title: localized('恢复云端备份？', 'Restore remote backup?'), message: localized('云端项目会合并到本机。相同内容不重复导入；同名但内容不同的项目会另存，现有项目不会被覆盖或删除。', 'Merge cloud items into this device. Identical items are skipped; differing items are kept separately. Existing items are never overwritten or deleted.'), acceptLabel: localized('恢复并合并', 'RESTORE & MERGE'), tag: localized('恢复加密备份', 'RESTORE BACKUP') })) return;
      await operate(async () => {
        const result = await invoke('github_backup_restore'); status = result.status;
        toast(localized(`恢复完成：新增 ${result.summary.added}，跳过重复 ${result.summary.merged}`, `Restored: ${result.summary.added} added, ${result.summary.merged} duplicates skipped`));
        await onRestore();
      });
    });
    $('github-disconnect').addEventListener('click', async () => {
      if (busy || !await confirmAction({ title: localized('断开 GitHub 备份？', 'Disconnect GitHub backup?'), message: localized('移除此设备保存的令牌和恢复密钥。仓库中的备份及本机项目会保留；请确保另有恢复密钥副本。', 'Remove this device’s saved token and recovery key. Remote backups and local items remain. Make sure you have a separate copy of your recovery key.'), acceptLabel: localized('断开', 'DISCONNECT'), tag: localized('移除本机连接', 'REMOVE LOCAL CONNECTION') })) return;
      await operate(async () => { status = await invoke('github_backup_disconnect'); clearSecrets(); toast(localized('已断开，云端备份已保留', 'Disconnected. Remote backups are retained.')); });
    });
    document.addEventListener('click', (event) => { const nav = event.target.closest('[data-page]'); if (nav && nav.dataset.page !== 'settings') clearSecrets(); });
    window.addEventListener('pagehide', clearSecrets);
    return { render, refresh, clearSecrets, isOpen: () => !modal.classList.contains('hidden') };
  },
};
