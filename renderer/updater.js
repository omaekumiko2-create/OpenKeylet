/* GitHub Releases Auto-Updater UI. Communicates only with GitHub Releases; zero vault data sent. */
window.OpenKeyletUpdater = {
  create({ invoke, localized, toast, isUnlocked, onSettingsUpdated }) {
    const $ = (id) => document.getElementById(id);
    const modal = $('update-modal');
    let status = {
      phase: 'idle',
      currentVersion: '',
      platform: '',
      latestVersion: null,
      tag: null,
      publishedAt: null,
      releaseUrl: 'https://github.com/omaekumiko2-create/OpenKeylet/releases/latest',
      notes: '',
      assetSize: null,
      downloadedBytes: 0,
      totalBytes: 0,
      signatureVerified: false,
      signingKeyConfigured: false,
      canAutoInstall: false,
      installBlockedReason: null,
      checkedAt: null,
      errorCode: null,
      errorMessage: null,
      autoCheck: true,
      autoDownload: true,
      skippedVersion: '',
    };
    let busy = false;
    let dismissedVersion = '';
    let previousFocus = null;
    let inertElements = [];
    const PROMPT_PREF_KEY = 'openkeylet.updatePrompt.v1';
    let promptEnabled = (() => {
      try { return localStorage.getItem(PROMPT_PREF_KEY) !== 'false'; } catch (_) { return true; }
    })();

    function setPromptEnabled(next) {
      promptEnabled = Boolean(next);
      try { localStorage.setItem(PROMPT_PREF_KEY, promptEnabled ? 'true' : 'false'); } catch (_) {}
      render();
    }

    const errorCopy = {
      UPDATE_NETWORK: ['无法连接 GitHub Releases，请检查网络或代理后重试，也可前往网页手动下载。', 'Cannot reach GitHub Releases. Check your network or proxy, or download manually from GitHub.'],
      UPDATE_MANIFEST_MISSING: ['最新 GitHub Release 尚未包含签名更新清单（latest.json），可先前往 Release 页面手动查看。', 'The latest GitHub Release does not include a signed update manifest (latest.json) yet.'],
      UPDATE_SIGNATURE_INVALID: ['更新清单的 Ed25519 签名校验失败，已阻止安装以保护密码库安全。', 'Ed25519 signature verification failed. Update blocked to protect your vault.'],
      UPDATE_CHECKSUM_MISMATCH: ['下载的安装包 SHA-256 校验不一致，已自动丢弃。请重试或手动下载。', 'Downloaded archive SHA-256 checksum did not match the signed manifest. Retry or download manually.'],
      UPDATE_SIZE_MISMATCH: ['下载的安装包大小与签名清单不符，已中止更新。', 'Downloaded archive size did not match the signed manifest.'],
      UPDATE_NO_SIGNING_KEY: ['当前为本地自编译版本（未内置发布公钥），仅支持版本提示；请前往 GitHub Releases 手动下载正式版。', 'This local build has no release signing key embedded. Download official signed builds from GitHub Releases.'],
      UPDATE_DEV_BUILD: ['当前正在从源码构建目录运行，已禁用原地自动覆盖；请使用打包后的正式版体验自动更新。', 'Running from a source build directory; in-place auto-update is disabled.'],
      UPDATE_READONLY_DIR: ['当前安装目录没有写入权限，无法原地替换；请将 OpenKeylet 移至可写目录或手动下载覆盖。', 'The current installation folder is read-only. Move OpenKeylet to a writable folder or update manually.'],
      UPDATE_UNSUPPORTED_PLATFORM: ['当前发布版本未包含此系统架构的安装包，请打开 GitHub Releases 查看。', 'No release archive matches this OS/architecture. Open GitHub Releases to check available packages.'],
      UPDATE_CODESIGN_INVALID: ['下载的 macOS 应用签名校验未通过，已拒绝安装。', 'Downloaded macOS app bundle failed codesign verification.'],
      UPDATE_URL_REJECTED: ['更新链接不在受信任的 GitHub Releases 域名内，已拦截。', 'Update URL is outside trusted GitHub Releases hosts and was blocked.'],
      UPDATE_HTTP_STATUS: ['GitHub Releases 返回了异常状态，请稍后重试或手动下载。', 'GitHub Releases returned an unexpected HTTP error. Try again later or download manually.'],
    };

    function localizedError(code, fallbackMessage) {
      if (code && errorCopy[code]) return localized(...errorCopy[code]);
      if (fallbackMessage) return fallbackMessage;
      return localized('更新操作未完成，请重试或前往 GitHub Releases 手动下载。', 'Update did not complete. Retry or download manually from GitHub Releases.');
    }

    function formatBytes(bytes) {
      const value = Number(bytes || 0);
      if (!value) return '0 B';
      if (value < 1024) return `${value} B`;
      if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
      return `${(value / (1024 * 1024)).toFixed(1)} MB`;
    }

    function progressPercent() {
      if (status.phase === 'ready' || status.phase === 'verifying' || status.phase === 'applying') return 100;
      const total = Number(status.totalBytes || status.assetSize || 0);
      if (!total) return 0;
      return Math.max(0, Math.min(100, Math.round((Number(status.downloadedBytes || 0) / total) * 100)));
    }

    function formatDate(value) {
      if (!value) return localized('尚无', 'Not yet');
      try {
        return new Date(value).toLocaleString(document.documentElement.lang || 'en', {
          month: 'short',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit',
        });
      } catch (_) {
        return value;
      }
    }

    function hasNewerVersion() {
      return Boolean(status.latestVersion) && ['available', 'downloading', 'verifying', 'ready', 'applying'].includes(status.phase);
    }

    function isSkippedCurrentLatest() {
      return Boolean(status.latestVersion) && status.skippedVersion === status.latestVersion;
    }

    function shouldShowBanner() {
      if (!promptEnabled) return false;
      if (!['available', 'downloading', 'verifying', 'ready', 'applying'].includes(status.phase)) return false;
      if (isSkippedCurrentLatest() && status.phase !== 'downloading' && status.phase !== 'verifying' && status.phase !== 'applying') return false;
      if (dismissedVersion && dismissedVersion === `${status.phase}:${status.latestVersion || ''}`) return false;
      return true;
    }

    function shouldShowTopIndicator() {
      if (!promptEnabled) return false;
      if (!hasNewerVersion()) return false;
      if (isSkippedCurrentLatest() && !['downloading', 'verifying', 'applying'].includes(status.phase)) return false;
      return true;
    }

    function renderTopIndicator() {
      const indicator = $('title-update-indicator');
      if (!indicator) return;
      const visible = shouldShowTopIndicator();
      indicator.classList.toggle('hidden', !visible);
      if (!visible) return;
      const phase = status.phase;
      const ver = status.latestVersion ? `v${status.latestVersion}` : '';
      indicator.classList.toggle('is-ready', phase === 'ready');
      indicator.classList.toggle('is-working', ['downloading', 'verifying', 'applying'].includes(phase));
      const label = phase === 'ready'
        ? localized(`新版本 ${ver} 已就绪 · 点击重启更新`, `Update ${ver} ready · Click to restart`)
        : phase === 'downloading'
          ? localized(`正在下载 ${ver} · ${progressPercent()}%`, `Downloading ${ver} · ${progressPercent()}%`)
          : phase === 'verifying'
            ? localized(`正在校验 ${ver}…`, `Verifying ${ver}…`)
            : localized(`发现新版本 ${ver} · 点击查看更新`, `Update ${ver} available · Click to view`);
      indicator.title = label;
      indicator.setAttribute('aria-label', label);
    }

    function renderBanner() {
      const banner = $('update-banner');
      if (!banner) return;
      const visible = shouldShowBanner();
      banner.classList.toggle('hidden', !visible);
      if (!visible) return;

      const phase = status.phase;
      const ver = status.latestVersion ? `v${status.latestVersion}` : '';
      const pct = progressPercent();
      banner.className = `update-banner${phase === 'ready' ? ' is-ready' : ''}${['downloading', 'verifying', 'applying'].includes(phase) ? ' is-working' : ''}${phase === 'error' ? ' is-error' : ''}`;

      const titleEl = $('update-banner-title');
      const subEl = $('update-banner-sub');
      const primaryBtn = $('update-banner-primary');
      const notesBtn = $('update-banner-notes');
      const progressTrack = $('update-banner-progress');
      const progressFill = $('update-banner-progress-fill');

      if (phase === 'ready') {
        titleEl.textContent = localized(`新版本 ${ver} 已就绪`, `Update ${ver} ready`);
        subEl.textContent = localized('已通过签名校验 · 重启立即生效（下次启动也会自动应用）', 'Signature verified · Restart to apply (or auto-applies next launch)');
        primaryBtn.textContent = localized('重启更新', 'RESTART');
        primaryBtn.classList.remove('hidden');
        primaryBtn.disabled = busy || !isUnlocked();
      } else if (phase === 'downloading') {
        titleEl.textContent = localized(`正在后台下载 ${ver} · ${pct}%`, `Downloading ${ver} · ${pct}%`);
        subEl.textContent = `${formatBytes(status.downloadedBytes)} / ${formatBytes(status.totalBytes || status.assetSize)}`;
        primaryBtn.classList.add('hidden');
      } else if (phase === 'verifying') {
        titleEl.textContent = localized(`正在校验 ${ver} 签名与完整性…`, `Verifying ${ver} signature…`);
        subEl.textContent = localized('Ed25519 + SHA-256 校验中', 'Checking Ed25519 & SHA-256');
        primaryBtn.classList.add('hidden');
      } else if (phase === 'applying') {
        titleEl.textContent = localized(`正在应用 ${ver} 并重启…`, `Applying ${ver} & restarting…`);
        subEl.textContent = localized('正在安全替换程序文件', 'Replacing application files safely');
        primaryBtn.classList.add('hidden');
      } else {
        titleEl.textContent = localized(`发现新版本 ${ver}`, `Update ${ver} available`);
        subEl.textContent = status.canAutoInstall
          ? localized('来自 GitHub Releases · 支持一键自动更新', 'From GitHub Releases · Ready for 1-click update')
          : localized('来自 GitHub Releases · 请前往页面手动下载', 'From GitHub Releases · Download manually');
        primaryBtn.textContent = status.canAutoInstall
          ? localized('立即更新', 'UPDATE')
          : localized('去下载 ↗', 'DOWNLOAD ↗');
        primaryBtn.classList.remove('hidden');
        primaryBtn.disabled = busy || (status.canAutoInstall && !isUnlocked());
      }

      notesBtn.textContent = localized('详情', 'NOTES');
      notesBtn.disabled = busy;
      $('update-banner-dismiss').setAttribute('aria-label', localized('暂时收起提示', 'Dismiss for now'));

      const showProgress = ['downloading', 'verifying', 'applying'].includes(phase);
      progressTrack.classList.toggle('hidden', !showProgress);
      progressFill.style.width = `${pct}%`;
    }

    function renderSettingsCard() {
      const card = $('update-settings-card');
      if (!card) return;

      $('update-card-heading').textContent = localized('软件更新（GitHub Releases）', 'SOFTWARE UPDATES');
      $('update-card-description').textContent = localized(
        '直接通过官方 GitHub Releases 检查与验证签名更新包，无需第三方域名，不上传任何本地数据。',
        'Check and install Ed25519-signed releases directly from GitHub Releases. No custom server; zero vault data sent.',
      );
      $('update-current-version-label').textContent = localized('当前版本', 'Current version');
      $('update-current-version-value').textContent = status.currentVersion ? `v${status.currentVersion}` : '—';
      $('update-platform-label').textContent = localized('运行平台', 'Platform');
      $('update-platform-value').textContent = status.platform || '—';
      $('update-latest-label').textContent = localized('最新版本', 'Latest release');
      $('update-latest-value').textContent = status.latestVersion
        ? `v${status.latestVersion}${status.signatureVerified ? ' ✓' : ''}`
        : localized('尚未检查', 'Not checked');
      $('update-checked-label').textContent = localized('上次检查', 'Last checked');
      $('update-checked-value').textContent = formatDate(status.checkedAt);

      const promptLabel = $('update-prompt-label');
      const promptHelp = $('update-prompt-help');
      const promptInput = $('update-prompt-enabled');
      if (promptLabel) promptLabel.textContent = localized('顶部自动更新提示', 'TOP-BAR UPDATE INDICATOR');
      if (promptHelp) {
        promptHelp.textContent = localized(
          '发现新版本时在顶部搜索框旁显示呼吸提示图标（默认开启；关闭后仅在设置内查看）',
          'Show a breathing update icon beside the top search bar when a newer version is available (on by default).',
        );
      }
      if (promptInput) promptInput.checked = promptEnabled;

      $('update-auto-check-label').textContent = localized('启动时自动检查更新', 'AUTO-CHECK ON LAUNCH');
      $('update-auto-check-help').textContent = localized(
        '打开软件后在后台静默检查 GitHub Releases 新版本（关闭后仅手动检查）',
        'Silently check GitHub Releases after launch (turn off for manual checks only).',
      );
      $('update-auto-download-label').textContent = localized('后台静默下载，重启自动生效', 'BACKGROUND AUTO-DOWNLOAD');
      $('update-auto-download-help').textContent = localized(
        '发现已签名的新版本后自动在后台下载并验签，就绪后提示重启或下次启动生效；关闭则仅提示更新',
        'Download and verify signed updates in the background, then prompt to restart or apply on next launch.',
      );

      const autoCheckInput = $('update-auto-check-enabled');
      const autoDownloadInput = $('update-auto-download-enabled');
      if (autoCheckInput) {
        autoCheckInput.checked = status.autoCheck !== false;
        autoCheckInput.disabled = busy || !isUnlocked();
      }
      if (autoDownloadInput) {
        autoDownloadInput.checked = status.autoDownload !== false;
        autoDownloadInput.disabled = busy || !isUnlocked() || !status.autoCheck;
      }

      const strip = $('update-status-strip');
      const phase = status.phase;
      const ver = status.latestVersion ? `v${status.latestVersion}` : '';
      strip.className = `status-strip ${phase === 'error' ? 'error' : phase === 'ready' ? 'ready' : ['available', 'downloading', 'verifying', 'checking'].includes(phase) ? 'pending' : ''}`;
      if (phase === 'checking') {
        strip.textContent = localized('正在从 GitHub Releases 检查更新…', 'CHECKING GITHUB RELEASES…');
      } else if (phase === 'up_to_date') {
        strip.textContent = localized(`已是最新版本 · v${status.currentVersion}`, `UP TO DATE · v${status.currentVersion}`);
      } else if (phase === 'available') {
        strip.textContent = status.canAutoInstall
          ? localized(`发现新版本 ${ver} · 已验证发布签名`, `UPDATE AVAILABLE · ${ver} (VERIFIED)`)
          : localized(`发现新版本 ${ver} · 请前往 GitHub Releases 手动下载`, `UPDATE AVAILABLE · ${ver} (MANUAL DOWNLOAD)`);
      } else if (phase === 'downloading') {
        strip.textContent = localized(`正在下载 ${ver} · ${progressPercent()}%`, `DOWNLOADING ${ver} · ${progressPercent()}%`);
      } else if (phase === 'verifying') {
        strip.textContent = localized(`正在验证 ${ver} 签名与 SHA-256…`, `VERIFYING ${ver}…`);
      } else if (phase === 'ready') {
        strip.textContent = localized(`${ver} 已就绪 · 点击立即重启更新（或下次启动自动生效）`, `${ver} READY · RESTART TO APPLY`);
      } else if (phase === 'applying') {
        strip.textContent = localized(`正在安装 ${ver} 并重启…`, `INSTALLING ${ver}…`);
      } else if (phase === 'error') {
        strip.textContent = localized('检查或下载更新失败', 'UPDATE CHECK OR DOWNLOAD FAILED');
      } else {
        strip.textContent = status.autoCheck
          ? localized('已启用 GitHub 自动检查更新', 'AUTO-CHECK ENABLED · GITHUB RELEASES')
          : localized('手动检查模式 · 未发起联网检查', 'MANUAL CHECK ONLY · NO BACKGROUND REQUESTS');
      }

      const progressWrap = $('update-card-progress');
      const showProgress = ['downloading', 'verifying'].includes(phase);
      progressWrap.classList.toggle('hidden', !showProgress);
      if (showProgress) {
        $('update-card-progress-fill').style.width = `${progressPercent()}%`;
        $('update-card-progress-bytes').textContent = `${formatBytes(status.downloadedBytes)} / ${formatBytes(status.totalBytes || status.assetSize)}`;
        $('update-card-progress-pct').textContent = `${progressPercent()}%`;
      }

      const errorEl = $('update-card-error');
      const showBlockedNotice = !status.canAutoInstall && hasNewerVersion() && status.installBlockedReason;
      const errText = phase === 'error'
        ? localizedError(status.errorCode, status.errorMessage)
        : showBlockedNotice
          ? localizedError(status.installBlockedReason, '')
          : '';
      errorEl.textContent = errText;
      errorEl.classList.toggle('hidden', !errText);

      const noteEl = $('update-card-note');
      if (status.skippedVersion) {
        noteEl.textContent = localized(
          `已跳过版本 v${status.skippedVersion}（仍可随时手动点击检查更新安装）。`,
          `Skipped version v${status.skippedVersion} (you can still check and install manually anytime).`,
        );
      } else {
        noteEl.textContent = localized(
          '所有自动安装包均强制校验 Ed25519 发布签名与 SHA-256，保留本机密码库与 MCP 路径。',
          'All automatic updates enforce Ed25519 signature and SHA-256 verification while preserving your local vault and MCP paths.',
        );
      }

      const checkBtn = $('update-check-button');
      const actionBtn = $('update-primary-action-button');
      const notesBtn = $('update-open-notes-button');
      const releaseBtn = $('update-open-releases-button');
      const clearSkipBtn = $('update-clear-skip-button');

      checkBtn.textContent = phase === 'checking'
        ? localized('检查中…', 'CHECKING…')
        : localized('检查更新', 'CHECK FOR UPDATES');
      checkBtn.disabled = busy || ['checking', 'downloading', 'verifying', 'applying'].includes(phase);

      const showAction = ['available', 'ready'].includes(phase) && status.canAutoInstall;
      actionBtn.classList.toggle('hidden', !showAction);
      if (showAction) {
        actionBtn.textContent = phase === 'ready'
          ? localized('立即重启并更新', 'RESTART & UPDATE')
          : localized('下载并更新', 'DOWNLOAD & UPDATE');
        actionBtn.disabled = busy || !isUnlocked();
      }

      notesBtn.classList.toggle('hidden', !hasNewerVersion());
      notesBtn.textContent = localized('更新日志', 'RELEASE NOTES');
      notesBtn.disabled = busy;

      releaseBtn.textContent = localized('GitHub Releases ↗', 'GITHUB RELEASES ↗');
      releaseBtn.disabled = busy;

      clearSkipBtn.classList.toggle('hidden', !status.skippedVersion);
      clearSkipBtn.textContent = localized('重置已跳过版本', 'CLEAR SKIPPED');
      clearSkipBtn.disabled = busy || !isUnlocked();
    }

    function renderModal() {
      if (!modal || modal.classList.contains('hidden')) return;
      const ver = status.latestVersion ? `v${status.latestVersion}` : '';
      $('update-modal-title').textContent = status.phase === 'ready'
        ? localized(`更新已就绪 · ${ver}`, `Update Ready · ${ver}`)
        : localized(`发现新版本 · ${ver}`, `Update Available · ${ver}`);
      $('update-modal-close').setAttribute('aria-label', localized('关闭', 'Close'));
      $('update-modal-version').textContent = `v${status.currentVersion || '?'} → ${ver || '?'}`;

      const badge = $('update-modal-signature');
      badge.className = `update-signature-badge${status.signatureVerified ? ' verified' : ''}`;
      badge.textContent = status.signatureVerified
        ? localized('ED25519 签名已验证', 'ED25519 VERIFIED')
        : localized('仅版本提示（未配置公钥）', 'UNVERIFIED BUILD');

      const metaParts = [];
      if (status.publishedAt) metaParts.push(localized(`发布时间：${formatDate(status.publishedAt)}`, `Published: ${formatDate(status.publishedAt)}`));
      if (status.assetSize) metaParts.push(localized(`安装包大小：${formatBytes(status.assetSize)}`, `Package size: ${formatBytes(status.assetSize)}`));
      $('update-modal-meta').textContent = metaParts.join(' · ');

      $('update-modal-notes').textContent = (status.notes || '').trim()
        || localized('此版本包含常规修复与体验改进，完整详情可前往 GitHub Releases 查看。', 'General improvements and bug fixes. See GitHub Releases for complete details.');

      const showProgress = ['downloading', 'verifying', 'applying'].includes(status.phase);
      $('update-modal-progress').classList.toggle('hidden', !showProgress);
      if (showProgress) {
        $('update-modal-progress-fill').style.width = `${progressPercent()}%`;
        $('update-modal-progress-bytes').textContent = status.phase === 'verifying'
          ? localized('正在校验签名与 SHA-256…', 'Verifying signature & SHA-256…')
          : status.phase === 'applying'
            ? localized('正在替换文件并准备重启…', 'Applying update & restarting…')
            : `${formatBytes(status.downloadedBytes)} / ${formatBytes(status.totalBytes || status.assetSize)}`;
        $('update-modal-progress-pct').textContent = `${progressPercent()}%`;
      }

      const modalErr = $('update-modal-error');
      const errText = status.phase === 'error'
        ? localizedError(status.errorCode, status.errorMessage)
        : !status.canAutoInstall && status.installBlockedReason
          ? localizedError(status.installBlockedReason, '')
          : '';
      modalErr.textContent = errText;
      modalErr.classList.toggle('hidden', !errText);

      const primaryBtn = $('update-modal-install');
      const skipBtn = $('update-modal-skip');
      const laterBtn = $('update-modal-later');
      const githubBtn = $('update-modal-github');

      githubBtn.textContent = localized('GitHub 页面 ↗', 'GITHUB ↗');
      skipBtn.textContent = localized('跳过此版本', 'SKIP VERSION');
      skipBtn.disabled = busy || !isUnlocked() || !status.latestVersion;
      laterBtn.textContent = localized('稍后', 'LATER');
      laterBtn.disabled = busy;

      if (status.canAutoInstall) {
        primaryBtn.textContent = status.phase === 'ready'
          ? localized('立即重启并更新', 'RESTART & UPDATE')
          : status.phase === 'downloading'
            ? localized('正在下载…', 'DOWNLOADING…')
            : status.phase === 'verifying'
              ? localized('正在校验…', 'VERIFYING…')
              : status.phase === 'applying'
                ? localized('正在重启…', 'RESTARTING…')
                : localized('下载并立即更新', 'DOWNLOAD & UPDATE');
        primaryBtn.disabled = busy || !isUnlocked() || ['downloading', 'verifying', 'applying'].includes(status.phase);
      } else {
        primaryBtn.textContent = localized('前往 GitHub 下载 ↗', 'OPEN GITHUB RELEASES ↗');
        primaryBtn.disabled = busy;
      }
    }

    function render() {
      renderTopIndicator();
      renderBanner();
      renderSettingsCard();
      renderModal();
    }

    function closeModal(restoreFocus = true) {
      if (!modal || modal.classList.contains('hidden')) return;
      modal.classList.add('hidden');
      inertElements.forEach((el) => { el.inert = false; });
      inertElements = [];
      if (restoreFocus && previousFocus?.isConnected && !previousFocus.closest('.hidden')) {
        previousFocus.focus();
      }
      previousFocus = null;
    }

    function openModal() {
      if (!modal) return;
      previousFocus = document.activeElement;
      inertElements = [...document.body.children].filter(
        (el) => el !== modal && !el.inert && !['SCRIPT', 'STYLE'].includes(el.tagName),
      );
      inertElements.forEach((el) => { el.inert = true; });
      modal.classList.remove('hidden');
      renderModal();
      $('update-modal-install')?.focus();
    }

    async function refresh() {
      try {
        const next = await invoke('update_status');
        if (next && typeof next === 'object' && typeof next.phase === 'string') {
          status = { ...status, ...next };
        }
        render();
      } catch (_) {}
    }

    async function checkNow() {
      if (busy) return;
      busy = true;
      dismissedVersion = '';
      render();
      try {
        status = await invoke('update_check');
        if (status.phase === 'up_to_date') {
          toast(localized(`当前已是最新版本 v${status.currentVersion}`, `Already up to date (v${status.currentVersion})`));
        } else if (status.phase === 'available' || status.phase === 'ready') {
          toast(localized(`发现新版本 v${status.latestVersion}`, `Update v${status.latestVersion} available`));
        }
      } catch (error) {
        const msg = String(error?.message || error);
        const code = msg.match(/UPDATE_[A-Z0-9_]+/)?.[0];
        toast(localizedError(code, ''), 'error');
      } finally {
        busy = false;
        await refresh();
      }
    }

    async function installOrOpen() {
      if (busy) return;
      if (!status.canAutoInstall) {
        try { await invoke('update_open_release_page'); } catch (error) { toast(String(error), 'error'); }
        return;
      }
      if (!isUnlocked()) {
        toast(localized('请先解锁 PIN 后再安装更新', 'Unlock OpenKeylet before installing updates'), 'error');
        return;
      }
      busy = true;
      render();
      try {
        await invoke('update_install_and_restart');
        toast(localized('更新已应用，正在重启 OpenKeylet…', 'Update applied; restarting OpenKeylet…'));
        busy = false;
        render();
      } catch (error) {
        const msg = String(error?.message || error);
        const code = msg.match(/UPDATE_[A-Z0-9_]+/)?.[0];
        toast(localizedError(code, ''), 'error');
        busy = false;
        await refresh();
      }
    }

    async function saveToggle(patch) {
      if (busy || !isUnlocked()) return;
      busy = true;
      render();
      try {
        const updatedSettings = await invoke('update_settings', { patch });
        onSettingsUpdated?.(updatedSettings);
        toast(localized('更新偏好已保存', 'Update preferences saved'));
      } catch (error) {
        toast(String(error?.message || error), 'error');
      } finally {
        busy = false;
        await refresh();
      }
    }

    async function skipCurrentVersion() {
      if (busy || !isUnlocked() || !status.latestVersion) return;
      busy = true;
      render();
      try {
        const ver = status.latestVersion;
        status = await invoke('update_skip_version', { version: ver });
        closeModal();
        toast(localized(`已跳过版本 v${ver}`, `Skipped version v${ver}`));
      } catch (error) {
        toast(String(error?.message || error), 'error');
      } finally {
        busy = false;
        render();
      }
    }

    async function clearSkippedVersion() {
      if (busy || !isUnlocked()) return;
      busy = true;
      render();
      try {
        status = await invoke('update_skip_version', { version: '' });
        dismissedVersion = '';
        toast(localized('已重置跳过的版本', 'Cleared skipped version'));
      } catch (error) {
        toast(String(error?.message || error), 'error');
      } finally {
        busy = false;
        render();
      }
    }

    // Event bindings
    $('title-update-indicator')?.addEventListener('click', openModal);
    $('update-prompt-enabled')?.addEventListener('change', (event) => {
      setPromptEnabled(Boolean(event.currentTarget.checked));
    });
    $('update-banner-primary')?.addEventListener('click', installOrOpen);
    $('update-banner-notes')?.addEventListener('click', openModal);
    $('update-banner-dismiss')?.addEventListener('click', () => {
      dismissedVersion = `${status.phase}:${status.latestVersion || ''}`;
      renderBanner();
    });

    $('update-check-button')?.addEventListener('click', checkNow);
    $('update-primary-action-button')?.addEventListener('click', installOrOpen);
    $('update-open-notes-button')?.addEventListener('click', openModal);
    $('update-open-releases-button')?.addEventListener('click', () => {
      invoke('update_open_release_page').catch((error) => toast(String(error), 'error'));
    });
    $('update-clear-skip-button')?.addEventListener('click', clearSkippedVersion);

    $('update-auto-check-enabled')?.addEventListener('change', (event) => {
      saveToggle({ updateAutoCheck: Boolean(event.currentTarget.checked) });
    });
    $('update-auto-download-enabled')?.addEventListener('change', (event) => {
      saveToggle({ updateAutoDownload: Boolean(event.currentTarget.checked) });
    });

    $('update-modal-close')?.addEventListener('click', () => closeModal());
    $('update-modal-later')?.addEventListener('click', () => closeModal());
    $('update-modal-skip')?.addEventListener('click', skipCurrentVersion);
    $('update-modal-install')?.addEventListener('click', installOrOpen);
    $('update-modal-github')?.addEventListener('click', () => {
      invoke('update_open_release_page').catch((error) => toast(String(error), 'error'));
    });
    modal?.addEventListener('click', (event) => {
      if (event.target === modal && !busy) closeModal();
    });
    modal?.addEventListener('keydown', (event) => {
      event.stopPropagation();
      if (event.key === 'Escape') {
        event.preventDefault();
        if (!busy) closeModal();
      }
    });

    if (window.__TAURI__?.event?.listen) {
      window.__TAURI__.event.listen('update-state-changed', (event) => {
        if (event?.payload) {
          const prevPhase = status.phase;
          status = event.payload;
          // If an update transitions to ready in the background, surface the banner even if "available" was dismissed earlier.
          if (status.phase === 'ready' && prevPhase !== 'ready') {
            dismissedVersion = '';
          }
          render();
        }
      });
    }

    return {
      refresh,
      render,
      closeModal: () => closeModal(false),
    };
  },
};
