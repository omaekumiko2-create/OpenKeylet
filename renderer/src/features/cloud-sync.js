/* GitHub backup UI. No credentials are persisted in browser storage. */
import { createCloudHistory } from '../views/cloud-history.js';

export function createCloudSync({ invoke, localized, toast, isUnlocked, confirmAction, onRestore }) {
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
    let discoveredRepos = [];
    // The account was verified but its repositories could not be listed: an empty
    // discovery result then says nothing about whether a vault repository exists.
    let discoveryFailed = false;

    const copy = {
      'github-heading': ['GitHub 密码同步', 'GITHUB PASSWORD SYNC'],
      'github-description': ['将密码库加密存放到你自己的私有 GitHub / Gitea 仓库，支持多端自动双向同步。', 'Store your encrypted vault in your own private GitHub or Gitea repo with optional two-way sync.'],
      'github-repository-label': ['仓库', 'Repository'],
      'github-key-repository-label': ['钥匙仓库', 'Key repository'],
      'github-backup-label': ['上次同步/上传', 'Last upload'],
      'github-restore-label': ['上次拉取/恢复', 'Last restore'],
      'github-auto-sync-label': ['自动双向同步', 'AUTO TWO-WAY SYNC'],
      'github-auto-sync-help': ['打开软件自动拉取合并，修改/删除项目后自动加密推送到私有仓库', 'Pull and merge on open; push encrypted changes automatically after edits.'],
      'github-connect': ['配置私有密码仓库', 'SET UP VAULT REPO'],
      'github-sync': ['立即同步', 'SYNC NOW'],
      'github-history': ['版本历史', 'VERSION HISTORY'],
      'github-advanced-summary': ['高级：手动快照与连接管理', 'Advanced · Manual snapshot & connection'],
      'github-upload': ['仅上传快照', 'BACK UP ONLY'],
      'github-restore': ['仅拉取恢复', 'RESTORE ONLY'],
      'github-show-key': ['查看恢复密钥', 'RECOVERY KEY'],
      'github-reconfigure': ['更新连接', 'RECONNECT'],
      'github-disconnect': ['断开连接', 'DISCONNECT'],
      'github-discovered-title': ['已精准发现你的 OpenKeylet 私有仓库', 'Discovered private OpenKeylet repositories'],
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
      'github-step-key': ['3 · 钥匙仓库', '3 · Key repository'],
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
      'github-token-help': ['细粒度令牌需同时选择密文仓库和钥匙仓库（密文仓库名加 -key），并授予 Contents 读写权限。由程序创建仓库还需 Administration 写入权限；也可先在网页上建好这两个私有仓库。令牌仅在本机加密保存。', 'A fine-grained token must include both the vault repo and the key repo (the vault repo name plus -key) with Contents read/write permission. Creating repositories also needs Administration write, or create both private repos on the web first. Tokens are stored encrypted locally.'],
      'github-mode-label': ['连接方式', 'Connection mode'],
      'github-mode-new': ['创建新仓库备份', 'Create a new vault backup'],
      'github-mode-existing': ['连接已有密码仓库', 'Connect an existing vault repo'],
      'github-key-label': ['恢复密钥（可选）', 'Recovery key (optional)'],
      'github-recovery-help': ['仅当钥匙仓库不可用时，填写你离线保存的恢复密钥。', 'Only if the key repository is unavailable: enter the recovery key you kept offline.'],
      'github-local-only': ['连接成功后，可随时同步或手动备份。', 'Connect first, then sync or back up anytime.'],
      'github-submit': ['连接仓库', 'CONNECT'],
    };

    const errors = {
      GITHUB_CLI_MISSING: ['未找到 GitHub CLI（gh）。可安装并登录，或改用访问令牌。', 'GitHub CLI (gh) was not found. Install and sign in, or use an access token.'],
      GITHUB_CLI_AUTH: ['未能读取 GitHub CLI 登录。请先运行 gh auth login，或改用访问令牌。', 'Sign in with gh auth login first, or use an access token.'],
      GITHUB_CLI_TIMEOUT: ['读取本机 GitHub 登录超时，请重试或使用访问令牌。', 'Reading the local GitHub login timed out. Retry or use an access token.'],
      GITHUB_AUTH_SOURCE: ['请选择受支持的授权方式。', 'Choose a supported authorization method.'],
      GITHUB_CREATE_MODE: ['恢复已有备份时不能创建仓库。', 'Repository creation is unavailable when restoring an existing backup.'],
      GITHUB_CREATE_OWNER: ['只能在当前授权账号下创建仓库，请先检查账号。组织仓库请在远端平台建好后连接。', 'Create under the authenticated account. Check the account first. Create organization repositories on the host before connecting.'],
      GITHUB_REPOSITORY_EXISTS: ['仓库已存在或名称不可用。已有仓库请取消勾选“由 OpenKeylet 创建”，或使用其他名称。', 'The repository exists or its name is unavailable. Uncheck Create repository to connect an existing one, or choose another name.'],
      GITHUB_CREATE_UNCONFIRMED: ['创建仓库的结果尚未确认。请在远端平台检查；若已创建，取消勾选“由 OpenKeylet 创建”后连接。', 'Repository creation could not be confirmed. Check the host; if it exists, uncheck Create repository and connect.'],
      GITHUB_REPOSITORY_INVALID: ['请输入 owner/repository 或有效的仓库链接。', 'Enter owner/repository or a valid repository URL.'],
      GITHUB_TOKEN_INVALID: ['请输入有效的访问令牌。', 'Enter a valid access token.'],
      GITHUB_KEY_INVALID: ['恢复密钥格式不正确。请完整粘贴以 okv1_ 开头的密钥。', 'Paste the complete recovery key beginning with okv1_.'],
      GITHUB_KEY_REPO_MISSING: ['找不到钥匙仓库，或其中没有钥匙文件。请确认授权能访问它；如果它已不存在，可在下方填写离线保存的恢复密钥。', 'The key repository or its key file was not found. Check that your authorization can access it, or enter the recovery key you kept offline below.'],
      GITHUB_KEY_REPO_CREATE: ['无法创建钥匙仓库。请先在网页上创建名称为密文仓库名加 -key 的私有仓库，或改用有创建权限的授权。', 'The key repository could not be created. Create a private repository named after the vault repo plus -key on the web first, or use an authorization that can create repositories.'],
      GITHUB_KEY_REPO_INVALID: ['钥匙仓库里的钥匙文件无法识别。', 'The key file in the key repository is not valid.'],
      GITHUB_KEY_MISMATCH: ['密钥不匹配，或云端备份已损坏。本地数据未被恢复操作修改。', 'The key does not match, or the backup is damaged. No data was restored.'],
      GITHUB_PRIVATE_REQUIRED: ['只支持私有仓库。请检查仓库可见性。', 'Only private repositories are supported. Check its visibility.'],
      GITHUB_AUTH: ['令牌无效或已过期，请更新连接。', 'The token is invalid or expired. Reconnect with a new token.'],
      GITHUB_PERMISSION: ['无法访问仓库。请检查令牌的仓库选择、Contents 读写权限和组织授权。', 'Check the token’s repository access, Contents read/write permission, and organization approval.'],
      GITHUB_NOT_FOUND: ['找不到仓库或无权访问。请检查仓库名称和令牌权限。', 'Repository not found or inaccessible. Check its name and token permissions.'],
      GITHUB_BACKUP_EXISTS: ['仓库已有备份。请选择“连接已有密码仓库”。', 'A backup already exists. Choose Connect an existing vault repo.'],
      GITHUB_BACKUP_MISSING: ['没有找到云端备份。若要重新建立备份，请更新连接并选择“创建新仓库备份”。', 'No remote backup was found. To start again, reconnect and choose Create a new vault backup.'],
      GITHUB_RESTORE_REQUIRED: ['请先同步或恢复合并云端备份，再上传本机数据。', 'Sync or restore the remote backup before uploading this device.'],
      GITHUB_REMOTE_CHANGED: ['云端版本已变更，已停止覆盖上传。请点击「立即同步」自动合并，或先拉取恢复。', 'The remote version changed. Click Sync now to merge, or restore first.'],
      GITHUB_CONFLICT: ['云端发生并发更新，或仓库规则拒绝了提交。请点击「立即同步」合并，并检查分支保护规则。', 'A concurrent update or repository rule rejected the write. Click Sync now and check branch protection.'],
      GITHUB_UPLOAD_UNCONFIRMED: ['上传结果尚未确认。请先同步或恢复云端备份，确认最新版本后再上传。', 'Upload could not be confirmed. Sync or restore the remote backup before uploading again.'],
      GITHUB_RATE_LIMIT: ['远端仓库服务暂时限制了请求，请稍后再试。', 'The remote repository host temporarily limited requests. Try again later.'],
      GITHUB_NETWORK: ['无法连接远端仓库服务，请检查网络或服务器地址后重试。', 'Cannot reach the remote repository host. Check your network or server URL and retry.'],
      GITHUB_REDIRECT: ['仓库地址发生跳转。请使用仓库的最新地址重新连接。', 'The repository address redirects. Reconnect using its current address.'],
      GITHUB_REPOSITORY_CHANGED: ['该地址对应的仓库已改变。请重新连接。', 'This address now identifies a different repository. Reconnect to continue.'],
      GITHUB_BRANCH_CHANGED: ['默认分支已变更，请重新连接。', 'The default branch changed. Reconnect to continue.'],
      GITHUB_REPOSITORY_READ_ONLY: ['仓库已归档或停用，无法用于备份。', 'The repository is archived or disabled.'],
      GITHUB_BACKUP_INVALID: ['云端文件不是受支持的完整加密备份。', 'The remote file is not a valid supported encrypted backup.'],
      GITHUB_BACKUP_TOO_LARGE: ['备份超过当前 8 MB 限制，未上传或恢复。', 'The backup exceeds the current 8 MB limit. It was not uploaded or restored.'],
      GITHUB_NOT_CONNECTED: ['请先配置私有密码仓库。', 'Connect a private vault repository first.'],
      GITHUB_LOCAL_STATE: ['无法读取或保存本机连接配置。请检查数据目录；可重新连接。', 'Cannot read or save the local connection. Check the data directory or reconnect.'],
      GITHUB_RESTORE_FAILED: ['恢复未完成，请检查备份和本机数据目录后重试。', 'Restore did not complete. Check the backup and local data directory.'],
      GITHUB_LOCAL_VAULT: ['无法读取本机保险库，请检查数据目录。', 'Cannot read the local vault. Check its data directory.'],
      GITHUB_HISTORY_EXPIRED: ['版本预览已过期，请重新选择该版本。', 'The version preview expired. Pick the version again.'],
      GITHUB_HISTORY_INVALID: ['无法识别该版本，请重新打开版本历史。', 'That version could not be identified. Open the version history again.'],
      GITHUB_HISTORY_EMPTY: ['请至少勾选一个要恢复的项目。', 'Select at least one item to restore.'],
    };

    function errorText(error) {
      const code = String(error?.message || error).match(/GITHUB_[A-Z_]+/)?.[0];
      return errors[code] ? localized(...errors[code]) : localized('操作未完成，请检查连接后重试。', 'The operation did not complete. Check your connection and retry.');
    }

    function dateText(value) {
      return value ? new Date(value).toLocaleString(document.documentElement.lang, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : localized('尚无', 'Not yet');
    }

    function selectDiscoveredRepo(repo) {
      $('github-repository').value = repo.fullName;
      $('github-mode').value = repo.hasVaultFile ? 'existing' : 'new';
      $('github-create-repository').checked = false;
      render();
    }

    function renderDiscoveredRepos() {
      const box = $('github-discovered-box');
      const list = $('github-discovered-list');
      if (!box || !list) return;
      const show = Boolean(accountLogin) && discoveredRepos.length > 0;
      box.classList.toggle('hidden', !show);
      if (!show) {
        list.replaceChildren();
        return;
      }
      const currentRepo = $('github-repository').value.trim().toLowerCase();
      list.replaceChildren();
      for (const repo of discoveredRepos) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = `github-discovered-chip${repo.fullName.toLowerCase() === currentRepo ? ' selected' : ''}`;
        button.disabled = busy;
        const nameSpan = document.createElement('span');
        nameSpan.textContent = repo.fullName;
        const badges = document.createElement('span');
        badges.className = 'github-discovered-badges';
        const priv = document.createElement('span');
        priv.className = 'github-discovered-badge';
        priv.textContent = localized('私有', 'PRIVATE');
        badges.append(priv);
        if (repo.hasVaultFile) {
          const vaultBadge = document.createElement('span');
          vaultBadge.className = 'github-discovered-badge is-vault';
          vaultBadge.textContent = localized('含密码库', 'VAULT');
          badges.append(vaultBadge);
        } else if (repo.hasTopic) {
          const topicBadge = document.createElement('span');
          topicBadge.className = 'github-discovered-badge';
          topicBadge.textContent = 'TOPIC';
          badges.append(topicBadge);
        }
        button.append(nameSpan, badges);
        button.addEventListener('click', () => selectDiscoveredRepo(repo));
        list.append(button);
      }
    }

    function render() {
      for (const [id, values] of Object.entries(copy)) {
        const el = $(id);
        if (el) el.textContent = localized(...values);
      }
      $('github-modal-close').setAttribute('aria-label', localized('关闭', 'Close'));
      $('github-backup-card').setAttribute('aria-busy', String(busy));
      const connected = status.connected && isUnlocked();
      const activeError = lastError || status.lastSyncError || '';
      const strip = $('github-status');
      strip.className = `status-strip ${activeError ? 'error' : connected ? (status.pendingSync ? 'pending' : '') : 'offline'}`;
      strip.textContent = busy ? localized('正在同步处理，请稍候…', 'Working, please wait…')
        : connected ? (status.needsRestore ? localized('待同步/恢复云端数据', 'SYNC / RESTORE REQUIRED')
          : activeError ? localized('待重试 · 上次自动同步未完成（点击立即同步重试）', 'SYNC FAILED · Click Sync now to retry')
            : status.pendingSync ? localized('待同步 · 本地有未推送变更（点击立即同步）', 'PENDING SYNC · Local edits waiting to push')
              : status.autoSync ? localized('已连接 · 自动双向同步', 'CONNECTED · AUTO-SYNC')
                : localized('已连接 · 手动同步模式', 'CONNECTED · MANUAL'))
          : localized('未配置 · 仅本地离线（可选）', 'NOT CONNECTED · LOCAL ONLY');
      $('github-connect').classList.toggle('hidden', connected);
      for (const id of ['github-sync', 'github-advanced', 'github-details', 'github-auto-sync-section']) $(id)?.classList.toggle('hidden', !connected);
      $('github-history').classList.toggle('hidden', !connected || !status.hasRemoteBackup);
      $('github-sync').textContent = status.needsRestore
        ? localized('同步并恢复云端数据', 'SYNC & RESTORE')
        : status.pendingSync
          ? localized('立即同步（有待推变更）', 'SYNC PENDING CHANGES')
          : localized(...copy['github-sync']);
      const providerPrefix = status.provider === 'gitea' && status.serverUrl ? `${status.serverUrl.replace(/^https?:\/\//, '')} · ` : '';
      $('github-repository-value').textContent = connected ? `${providerPrefix}${status.repository} · ${status.branch}` : '';
      $('github-key-repository-value').textContent = connected ? (status.keyRepository || localized('由你自行保管', 'Held by you')) : '';
      $('github-backup-value').textContent = dateText(status.lastSyncedAt || status.lastBackupAt);
      $('github-restore-value').textContent = dateText(status.lastRestoreAt);
      if ($('github-auto-sync')) $('github-auto-sync').checked = Boolean(status.autoSync);
      $('github-note').textContent = connected && status.needsRestore
        ? localized('此设备需要先同步或恢复合并云端内容，才能上传。现有本地项目会保留。', 'Sync or restore the remote contents before uploading. Existing local items are kept.')
        : connected && status.autoSync
          ? localized('密文和钥匙分别存放在两个私有仓库里，自动双向同步。本机 PIN、配对和 Agent 配置不会上传。', 'Ciphertext and key live in two separate private repositories and sync automatically. Local PIN, pairing and agent setup never leave this device.')
          : localized('可选：密码库加密后存入你的私有仓库，钥匙放在另一个私有仓库；单文件离线备份请使用下方本机数据导出 .mvault。', 'Optional: the vault is encrypted before it reaches your private repo, and its key is kept in a second private repo. Use Local data below for offline .mvault archives.');
      $('github-error').textContent = activeError ? errorText(activeError) : '';
      $('github-error').classList.toggle('hidden', !activeError);
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
      $('github-check-account').classList.remove('hidden');
      $('github-check-account').textContent = isGitea
        ? localized('测试服务器与账号', 'CHECK SERVER & ACCOUNT')
        : localized(...copy['github-check-account']);
      $('github-create-repo').classList.toggle('hidden', isGitea);
      $('github-token-section').classList.toggle('hidden', useCli);
      $('github-cli-help').classList.toggle('hidden', !useCli);
      $('github-login-help').classList.toggle('hidden', !useCli);
      $('github-create-token').classList.toggle('hidden', useCli || isGitea);
      $('github-token').required = !useCli;
      $('github-account-status').textContent = !accountLogin ? ''
        : discoveryFailed
          ? `${localized(`已验证远端账号：${accountLogin}`, `Verified account: ${accountLogin}`)} · ${localized('无法列出你的仓库，未能自动发现；请检查授权的仓库访问权限，或在下方手动填写仓库名。', 'Could not list your repositories, so none were discovered. Check the authorization’s repository access, or enter the repository below.')}`
          : discoveredRepos.length
            ? localized(`已验证远端账号：${accountLogin} · 精准发现 ${discoveredRepos.length} 个私有密码仓`, `Verified account: ${accountLogin} · Found ${discoveredRepos.length} private vault repo(s)`)
            : localized(`已验证远端账号：${accountLogin} · 未发现已有私有密码仓（可勾选下方自动创建私有仓）`, `Verified account: ${accountLogin} · No existing private vault repo found`);
      renderDiscoveredRepos();
      versionHistory.render();
      $('github-create-repository-field').classList.toggle('hidden', !isNew);
      $('github-first-upload-field').classList.toggle('hidden', !isNew);
      const repoName = $('github-repository').value.trim().replace(/^https?:\/\/[^/]+\//, '').replace(/\.git$/, '').replace(/\/+$/, '');
      const keyRepoName = /^[^/\s]+\/[^/\s]+$/.test(repoName) ? `${repoName}-key` : '';
      const keyRepoHelp = isNew
        ? localized('钥匙会存入同一账号下的另一个私有仓库（不存在时自动创建），与密文分开；换设备时只需授权，不用记任何密钥。', 'The key is stored in a second private repository of the same account (created if missing), apart from the ciphertext. A new device only needs your authorization.')
        : localized('钥匙会从同一账号下的钥匙仓库读取，无需手动输入。', 'The key is read from the key repository of the same account. Nothing to type.');
      $('github-key-repo-help').textContent = keyRepoName ? `${keyRepoHelp} → ${keyRepoName}` : keyRepoHelp;
      $('github-manual-key-section').classList.toggle('hidden', isNew);
      $('github-local-only').textContent = isNew && $('github-first-upload').checked
        ? localized('将加密上传整个密码库；钥匙存入另一个私有仓库。', 'The full vault is encrypted and uploaded; its key goes to a second private repo.')
        : localized('仅保存连接，之后由你选择同步或恢复。', 'Save the connection, then choose upload or restore.');
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
      discoveredRepos = [];
      discoveryFailed = false;
      inertElements.forEach((element) => { element.inert = false; });
      inertElements = [];
      if (restoreFocus && previousFocus?.isConnected && !previousFocus.closest('.hidden')) previousFocus.focus();
      previousFocus = null;
    }

    function clearSecrets() {
      closeModal(false);
      versionHistory.close(true);
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

    const versionHistory = createCloudHistory({
      invoke,
      localized,
      toast,
      confirmAction,
      errorText,
      repository: () => status.repository || '',
      onRestored: async (result) => {
        if (result?.status) status = result.status;
        lastError = '';
        render();
        await onRestore();
      },
    });

    $('github-connect').addEventListener('click', openModal);
    $('github-history').addEventListener('click', () => {
      if (busy || !isUnlocked() || !status.connected || !status.hasRemoteBackup) return;
      versionHistory.open();
    });
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
      render();
    });
    $('github-first-upload').addEventListener('change', render);
    $('github-provider')?.addEventListener('change', () => {
      secretEpoch++; accountLogin = ''; discoveredRepos = []; discoveryFailed = false; formError = ''; render();
    });
    $('github-auth-source').addEventListener('change', () => {
      secretEpoch++; accountLogin=''; discoveredRepos = []; discoveryFailed = false; formError=''; $('github-token').value=''; render();
    });
    $('github-token').addEventListener('input', () => { accountLogin=''; discoveredRepos = []; discoveryFailed = false; render(); });
    $('github-repository').addEventListener('input', render);
    $('github-check-account').addEventListener('click', async () => {
      if (busy || !isUnlocked()) return;
      const epoch = secretEpoch;
      const provider = $('github-provider')?.value || 'github';
      const input = {
        authSource: provider === 'gitea' ? 'token' : $('github-auth-source').value,
        token: $('github-token').value.trim(),
        provider,
        serverUrl: provider === 'gitea' ? ($('github-server-url')?.value.trim() || '') : '',
      };
      busy=true;formError='';discoveredRepos=[];discoveryFailed=false;render();
      try {
        const account = await invoke('github_backup_account',{input});
        if(epoch!==secretEpoch || !isUnlocked() || modal.classList.contains('hidden'))return;
        accountLogin=account.login;
        discoveredRepos = Array.isArray(account.discoveredRepos) ? account.discoveredRepos : [];
        discoveryFailed = Boolean(account.discoveryFailed);
        if (discoveredRepos.length > 0) {
          selectDiscoveredRepo(discoveredRepos[0]);
        } else if (!discoveryFailed && !$('github-repository').value.trim()) {
          // Suggesting a new repository is only safe when the listing showed there is none.
          $('github-repository').value = `${account.login}/openkeylet-vault`;
          $('github-mode').value = 'new';
        }
      } catch(error) { if(epoch===secretEpoch)formError=error; }
      finally { input.token='';busy=false;render(); }
    });
    $('github-recovery-key').addEventListener('input', () => { formError = ''; render(); });
    async function copyKey(id) {
      const value = $(id).value;
      if (!value || !isUnlocked()) return;
      try { await invoke('copy_owner_value', { value, sensitive: true }); toast(localized('密钥已复制（30 秒后自动清除），请保存在仓库之外', 'Key copied (clears in 30s). Save it outside the repository.')); }
      catch (error) { toast(errorText(error), 'error'); }
    }
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
      // The key normally comes from the key repository; a pasted one is only a fallback.
      const manualKey = $('github-mode').value === 'existing' ? $('github-recovery-key').value.trim() : '';
      if (manualKey && !/^okv1_[A-Za-z0-9_-]{43}$/.test(manualKey)) {
        formError = 'GITHUB_KEY_INVALID'; render(); return;
      }
      const provider = $('github-provider')?.value || 'github';
      const input = {
        repository: $('github-repository').value.trim(),
        token: $('github-token').value.trim(),
        recoveryKey: manualKey,
        mode: $('github-mode').value,
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
          toast(localized('第一份加密备份已上传到你的私有仓库。', 'Your first encrypted backup is in your private repository.'));
        } else toast(status.needsRestore ? localized('连接成功，请先恢复云端备份。', 'Connected. Restore the remote backup first.') : localized('连接成功，可以开始同步备份。', 'Connected. Ready to back up.'));
        await onRestore();
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
        window.OpenKeyletAppearance?.play?.('success');
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
      if (busy || !await confirmAction({ title: localized('上传加密快照？', 'Upload encrypted snapshot?'), message: localized(`将整个保险库加密上传到 ${status.repository}。Git 历史会保留旧版密文。`, `Encrypt and upload the entire vault to ${status.repository}. Git history retains older encrypted snapshots.`), acceptLabel: localized('立即上传', 'UPLOAD'), tag: localized('手动云端快照', 'MANUAL CLOUD SNAPSHOT') })) return;
      await operate(async () => { status = await invoke('github_backup_upload'); window.OpenKeyletAppearance?.play?.('success'); toast(localized('加密快照已上传', 'Encrypted snapshot uploaded')); });
    });
    $('github-restore').addEventListener('click', async () => {
      if (busy || !await confirmAction({ title: localized('拉取并恢复云端快照？', 'Restore remote snapshot?'), message: localized('云端项目会合并到本机。相同内容不重复导入；同名但内容不同的项目会另存，现有项目不会被覆盖或删除。', 'Merge cloud items into this device. Identical items are skipped; differing items are kept separately. Existing items are never overwritten or deleted.'), acceptLabel: localized('恢复并合并', 'RESTORE & MERGE'), tag: localized('恢复加密快照', 'RESTORE SNAPSHOT') })) return;
      await operate(async () => {
        const result = await invoke('github_backup_restore'); status = result.status;
        window.OpenKeyletAppearance?.play?.('success');
        toast(localized(`恢复完成：新增 ${result.summary.added}，跳过重复 ${result.summary.merged}`, `Restored: ${result.summary.added} added, ${result.summary.merged} duplicates skipped`));
        await onRestore();
      });
    });
    $('github-disconnect').addEventListener('click', async () => {
      const disconnectMsg = localized('移除此设备保存的令牌和钥匙。仓库里的内容和本机项目都会保留，之后可以重新绑定。', 'Remove this device’s saved token and key. The repositories and local items remain, and you can connect again later.');
      if (busy || !await confirmAction({ title: localized('断开云端仓库连接？', 'Disconnect vault repository?'), message: disconnectMsg, acceptLabel: localized('断开', 'DISCONNECT'), tag: localized('移除本机连接', 'REMOVE LOCAL CONNECTION') })) return;
      await operate(async () => {
        status = await invoke('github_backup_disconnect');
        clearSecrets();
        await onRestore();
        toast(localized('已断开连接，云端加密快照已保留。', 'Disconnected. Remote snapshots are retained.'));
      });
    });
    document.addEventListener('click', (event) => { const nav = event.target.closest('[data-page]'); if (nav && nav.dataset.page !== 'settings') clearSecrets(); });
    window.addEventListener('pagehide', clearSecrets);
    return { render, refresh, clearSecrets, isOpen: () => !modal.classList.contains('hidden') };
}

window.OpenKeyletGithubBackup = { create: createCloudSync };
