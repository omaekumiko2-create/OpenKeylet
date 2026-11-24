/* OpenKeylet Universal Offline Import Hub controller.
   Pure local rule extraction, noise filtering, vault dedup & batch commit. */
(() => {
  const $ = (sel, root = document) => root.querySelector(sel);

  let host = null;
  let debounceTimer = null;
  let rawText = '';
  let sourceFilename = null;
  let clipboardSource = '';
  let inputExpanded = true;
  let activeKindFilter = 'all';
  let isExtracting = false;
  let isCommitting = false;

  // Current staging state
  let detectedFormat = '';
  let detectedFormatZh = '';
  let candidates = [];
  let ignored = [];
  let warnings = [];
  let discoveredMvaults = [];
  let scanReport = null;
  let activeScanMode = null;
  let sealedEnvTemplate = null;
  let revealedIds = new Set();
  let expandedIds = new Set();

  // Last commit summary for undo / feedback
  let lastCommit = null;

  function lang() {
    return host?.getLang?.() || 'en';
  }

  function t(zh, en) {
    if (host?.localized) return host.localized(zh, en);
    return lang().startsWith('zh') ? zh : en;
  }

  function esc(str) {
    return String(str ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  }

  function getStats() {
    const selected = candidates.filter((c) => c.selected).length;
    return {
      total: candidates.length,
      selected,
      ignored: ignored.length,
    };
  }

  function notifyMetrics() {
    host?.onStatsChange?.();
  }

  function getSearchQuery() {
    return String(host?.getSearchQuery?.() || '').trim().toLowerCase();
  }

  function filteredCandidates() {
    const q = getSearchQuery();
    return candidates.filter((c) => {
      if (activeKindFilter !== 'all' && c.kind !== activeKindFilter) return false;
      if (!q) return true;
      const hay = [
        c.input?.name,
        c.summary,
        c.badge,
        c.badgeZh,
        c.input?.folder,
        ...(c.fields || []).map((f) => `${f.label} ${f.secret ? '' : f.value}`),
      ]
        .join(' ')
        .toLowerCase();
      return hay.includes(q);
    });
  }

  function resetAll({ keepDoneBanner = false } = {}) {
    rawText = '';
    sourceFilename = null;
    clipboardSource = '';
    inputExpanded = true;
    activeKindFilter = 'all';
    detectedFormat = '';
    detectedFormatZh = '';
    candidates = [];
    ignored = [];
    warnings = [];
    discoveredMvaults = [];
    scanReport = null;
    activeScanMode = null;
    sealedEnvTemplate = null;
    revealedIds.clear();
    expandedIds.clear();
    if (!keepDoneBanner) lastCommit = null;
    const ta = $('#import-raw-input');
    if (ta) ta.value = '';
    const folderInput = $('#import-batch-folder');
    if (folderInput) folderInput.value = '';
    render();
    notifyMetrics();
  }

  function applyBatchResult(result, { append = false } = {}) {
    lastCommit = null;
    if (!result) return;
    detectedFormat = result.detectedFormat || 'mixed_text';
    detectedFormatZh = result.detectedFormatZh || '混合文本';
    if (append && candidates.length) {
      const existingIds = new Set(candidates.map((c) => c.id));
      for (const c of result.candidates || []) {
        if (!existingIds.has(c.id)) candidates.push(c);
      }
      ignored = [...ignored, ...(result.ignored || [])];
      warnings = [...new Set([...warnings, ...(result.warnings || [])])];
      if (!sealedEnvTemplate && result.sealedEnvTemplate) {
        sealedEnvTemplate = result.sealedEnvTemplate;
      }
    } else {
      candidates = Array.isArray(result.candidates) ? result.candidates : [];
      ignored = Array.isArray(result.ignored) ? result.ignored : [];
      warnings = Array.isArray(result.warnings) ? result.warnings : [];
      discoveredMvaults = Array.isArray(result.discoveredMvaults) ? result.discoveredMvaults : [];
      scanReport = result.scanReport || null;
      sealedEnvTemplate = result.sealedEnvTemplate || null;
      revealedIds.clear();
      expandedIds.clear();
      activeKindFilter = 'all';
    }
    if (candidates.length > 0 || ignored.length > 0 || discoveredMvaults.length > 0) {
      inputExpanded = false;
    }
    render();
    notifyMetrics();
  }

  async function runExtract(text, filename = null, { append = false } = {}) {
    const trimmed = String(text || '').trim();
    if (!trimmed) {
      if (!append) {
        candidates = [];
        ignored = [];
        warnings = [];
        detectedFormat = '';
        detectedFormatZh = '';
        scanReport = null;
        sealedEnvTemplate = null;
        inputExpanded = true;
        render();
        notifyMetrics();
      }
      return;
    }
    if (!await host.ensureUnlocked()) return;
    isExtracting = true;
    render();
    try {
      const result = await host.invoke('smart_extract_batch', {
        text: trimmed,
        filename: filename || null,
      });
      applyBatchResult(result, { append });
    } catch (error) {
      host.toast(host.cleanError(error), 'error');
    } finally {
      isExtracting = false;
      render();
      notifyMetrics();
    }
  }

  async function handlePasteClipboard() {
    if (!await host.ensureUnlocked()) return;
    try {
      // 1. Check image QR in clipboard first
      if (navigator.clipboard?.read && window.OpenKeyletQR?.supported) {
        try {
          const items = await navigator.clipboard.read();
          for (const item of items) {
            const imgType = item.types.find((type) => type.startsWith('image/'));
            if (imgType) {
              const blob = await item.getType(imgType);
              const decoded = await window.OpenKeyletQR.decode(blob);
              rawText = decoded;
              sourceFilename = 'QR Screenshot';
              clipboardSource = '';
              const ta = $('#import-raw-input');
              if (ta) ta.value = decoded;
              await runExtract(decoded, sourceFilename);
              return;
            }
          }
        } catch (_) {
          // Fall through to text clipboard
        }
      }
      let text = '';
      try {
        text = await host.invoke('read_owner_clipboard');
      } catch (_) {}
      if (!text && navigator.clipboard?.readText) {
        try {
          text = await navigator.clipboard.readText();
        } catch (_) {}
      }
      if (!text || !text.trim()) {
        host.toast(
          t(
            '剪贴板为空，请先复制文本、.env、cURL、账号清单或 2FA 截图',
            'Clipboard is empty — copy text, .env, cURL, credentials, or a 2FA QR image first'
          ),
          'error'
        );
        return;
      }
      rawText = text;
      sourceFilename = null;
      clipboardSource = text;
      const ta = $('#import-raw-input');
      if (ta) ta.value = text;
      await runExtract(text, null);
    } catch (error) {
      host.toast(host.cleanError(error), 'error');
    }
  }

  function isBinaryExtractable(name) {
    return /\.(docx|xlsx|zip)$/i.test(String(name || ''));
  }

  async function fileToBase64(file) {
    const buf = await file.arrayBuffer();
    const bytes = new Uint8Array(buf);
    let binary = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
  }

  async function decodeDroppedImages(images, { append = true } = {}) {
    if (!Array.isArray(images) || !images.length) return 0;
    if (!window.OpenKeyletQR?.decode) {
      host.toast(t('当前环境不支持二维码图片解码', 'QR decoding is unavailable in this WebView'), 'error');
      return 0;
    }
    let decodedCount = 0;
    let shouldAppend = append;
    for (const img of images) {
      try {
        const bin = atob(img.dataBase64 || '');
        const arr = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
        const blob = new Blob([arr], { type: img.mimeType || 'image/png' });
        const decoded = await window.OpenKeyletQR.decode(blob);
        await runExtract(decoded, img.fileName || 'QR Image', { append: shouldAppend });
        shouldAppend = true;
        decodedCount++;
      } catch (error) {
        host.toast(`${img.fileName || 'Image'}: ${host.cleanError(error)}`, 'error');
      }
    }
    return decodedCount;
  }

  async function handlePickFiles() {
    if (!await host.ensureUnlocked()) return;
    isExtracting = true;
    render();
    try {
      const result = await host.invoke('smart_pick_and_extract_files');
      if (!result) return;
      sourceFilename = Array.isArray(result.sourceFiles) && result.sourceFiles.length
        ? result.sourceFiles.slice(0, 3).join(' · ')
        : null;
      clipboardSource = '';
      const hasExtracted = (result.candidates?.length || 0) > 0
        || (result.ignored?.length || 0) > 0
        || (result.warnings?.length || 0) > 0;
      if (hasExtracted) {
        applyBatchResult(result, { append: false });
      }
      const qrCount = await decodeDroppedImages(result.images, { append: hasExtracted });
      const totalExtracted = (result.candidates?.length || 0) + qrCount;
      if (totalExtracted > 0) {
        host.toast(
          t(
            `已从文件提取 ${totalExtracted} 项候选凭据`,
            `Extracted ${totalExtracted} candidate item(s) from files`
          )
        );
      }
      if (result.mvaultFile) {
        await host.openMvaultPreview?.(result.mvaultFile);
      }
    } catch (error) {
      host.toast(host.cleanError(error), 'error');
    } finally {
      isExtracting = false;
      render();
      notifyMetrics();
    }
  }

  async function handleNativeDropPayload(payload) {
    if (!payload) return;
    if (!await host.ensureUnlocked()) return;
    const batch = payload.batch || null;
    const sourceFiles = Array.isArray(payload.sourceFiles) ? payload.sourceFiles : [];
    sourceFilename = sourceFiles.length
      ? sourceFiles.slice(0, 3).join(' · ') + (sourceFiles.length > 3 ? ` (+${sourceFiles.length - 3})` : '')
      : null;
    clipboardSource = '';
    const hasBatchContent = Boolean(
      batch && ((batch.candidates?.length || 0) > 0 || (batch.ignored?.length || 0) > 0 || (batch.warnings?.length || 0) > 0)
    );
    if (hasBatchContent) {
      applyBatchResult(batch, { append: false });
    }
    const qrCount = await decodeDroppedImages(payload.images, { append: hasBatchContent });
    const count = (batch?.candidates?.length || 0) + qrCount;
    if (count > 0) {
      host.toast(
        t(
          `已从拖入文件提取 ${count} 项候选项目，勾选后即可一键入库`,
          `Extracted ${count} item(s) from dropped file(s) — check items to import`
        )
      );
    } else if (batch?.warnings?.length) {
      host.toast(batch.warnings[0], 'error');
    }
  }

  async function handleScanLocal() {
    if (!await host.ensureUnlocked()) return;
    isExtracting = true;
    activeScanMode = 'quick_pc';
    render();
    try {
      const result = await host.invoke('smart_scan_local_dev_configs');
      sourceFilename = null;
      clipboardSource = '';
      applyBatchResult(result, { append: false });
      const foundCount = (result?.candidates?.length || 0);
      const mvaultCount = (result?.discoveredMvaults?.length || 0);
      const inspectedCount = (result?.scanReport?.totalInspectedFiles || 0);
      if (foundCount > 0 || mvaultCount > 0) {
        const parts = [];
        if (foundCount > 0) parts.push(t(`${foundCount} 项疑似凭据`, `${foundCount} credential(s)`));
        if (mvaultCount > 0) parts.push(t(`${mvaultCount} 个 .mvault 备份`, `${mvaultCount} .mvault backup(s)`));
        host.toast(
          t(
            `本机一键搜索发现 ${parts.join('、')}`,
            `Local scan found ${parts.join(' & ')}`
          )
        );
      } else {
        host.toast(
          t(
            `已巡检 ${inspectedCount} 个本地文件，未发现未入库明文凭据`,
            `Inspected ${inspectedCount} local file(s) — no plaintext credentials found`
          )
        );
      }
    } catch (error) {
      host.toast(host.cleanError(error), 'error');
    } finally {
      isExtracting = false;
      activeScanMode = null;
      render();
      notifyMetrics();
    }
  }

  async function handleScanWorkspaceFolder() {
    if (!await host.ensureUnlocked()) return;
    isExtracting = true;
    activeScanMode = 'workspace_folder';
    render();
    try {
      const result = await host.invoke('smart_scan_workspace_folder');
      if (!result) return;
      sourceFilename = null;
      clipboardSource = '';
      applyBatchResult(result, { append: false });
      const foundCount = (result?.candidates?.length || 0);
      const mvaultCount = (result?.discoveredMvaults?.length || 0);
      const inspectedCount = (result?.scanReport?.totalInspectedFiles || 0);
      if (foundCount > 0 || mvaultCount > 0) {
        const parts = [];
        if (foundCount > 0) parts.push(t(`${foundCount} 项凭据`, `${foundCount} credential(s)`));
        if (mvaultCount > 0) parts.push(t(`${mvaultCount} 个备份`, `${mvaultCount} backup(s)`));
        host.toast(
          t(
            `目录深扫完成：发现 ${parts.join('、')}`,
            `Workspace scan found ${parts.join(' & ')}`
          )
        );
      } else {
        host.toast(
          t(
            `已深扫目录内 ${inspectedCount} 个文件，未发现明文凭据`,
            `Scanned ${inspectedCount} file(s) in folder — no plaintext secrets found`
          )
        );
      }
    } catch (error) {
      host.toast(host.cleanError(error), 'error');
    } finally {
      isExtracting = false;
      activeScanMode = null;
      render();
      notifyMetrics();
    }
  }

  async function handleFiles(fileList) {
    const files = Array.from(fileList || []);
    if (!files.length) return;
    if (!await host.ensureUnlocked()) return;
    let combinedFirst = true;
    for (const file of files) {
      const lower = (file.name || '').toLowerCase();
      if (lower.endsWith('.mvault')) {
        if (host.openDroppedMvault) {
          await host.openDroppedMvault(file);
        } else {
          host.toast(
            t(
              '检测到 .mvault 加密备份，正在打开备份恢复窗口',
              'Detected .mvault backup — opening backup restore flow'
            )
          );
          host.openBackupRestore?.();
        }
        continue;
      }
      if (file.type?.startsWith('image/') || /\.(png|jpe?g|webp|gif|bmp)$/i.test(lower)) {
        try {
          if (!window.OpenKeyletQR?.decode) {
            throw new Error(t('当前环境不支持二维码图片解码', 'QR decoding is unavailable in this WebView'));
          }
          const decoded = await window.OpenKeyletQR.decode(file);
          await runExtract(decoded, file.name, { append: !combinedFirst });
          combinedFirst = false;
        } catch (error) {
          host.toast(`${file.name}: ${host.cleanError(error)}`, 'error');
        }
        continue;
      }
      if (file.size > 16 * 1024 * 1024) {
        host.toast(
          t(`${file.name} 超过 16 MiB 限制，已跳过`, `${file.name} exceeds 16 MiB limit`),
          'error'
        );
        continue;
      }
      if (isBinaryExtractable(lower)) {
        isExtracting = true;
        render();
        try {
          const dataBase64 = await fileToBase64(file);
          const result = await host.invoke('smart_extract_dropped_binary', {
            fileName: file.name,
            dataBase64,
          });
          if (combinedFirst) sourceFilename = file.name;
          applyBatchResult(result, { append: !combinedFirst });
          combinedFirst = false;
        } catch (error) {
          host.toast(`${file.name}: ${host.cleanError(error)}`, 'error');
        } finally {
          isExtracting = false;
          render();
          notifyMetrics();
        }
        continue;
      }
      try {
        const text = await file.text();
        if (combinedFirst) {
          rawText = text;
          sourceFilename = file.name;
          const ta = $('#import-raw-input');
          if (ta) ta.value = text.length > 16000 ? `${text.slice(0, 16000)}\n…` : text;
        }
        await runExtract(text, file.name, { append: !combinedFirst });
        combinedFirst = false;
      } catch (error) {
        host.toast(`${file.name}: ${host.cleanError(error)}`, 'error');
      }
    }
  }

  async function handleCommit() {
    const selected = candidates.filter((c) => c.selected);
    if (!selected.length || isCommitting) return;
    if (!await host.ensureUnlocked()) return;
    isCommitting = true;
    render();
    try {
      const batchFolder = ($('#import-batch-folder')?.value || '').trim();
      const payload = selected.map((c) => ({
        input: c.input,
        updateExisting: Boolean(c.matchStatus === 'update' && c.updateExisting),
        existingItemId: c.existingItemId || null,
      }));
      const summary = await host.invoke('commit_smart_batch', {
        items: payload,
        folder: batchFolder || null,
      });
      const sealedBackup = sealedEnvTemplate;
      if (clipboardSource) {
        await host.invoke('clear_clipboard_if_matches', { text: clipboardSource }).catch(() => false);
      }
      lastCommit = {
        added: summary?.added || 0,
        updated: summary?.updated || 0,
        createdIds: Array.isArray(summary?.createdIds) ? summary.createdIds : [],
        sealedEnvTemplate: sealedBackup,
      };
      resetAll({ keepDoneBanner: true });
      window.OpenKeyletAppearance?.play?.('success');
      host.toast(
        t(
          `已入库 ${lastCommit.added + lastCommit.updated} 项（新增 ${lastCommit.added} · 更新 ${lastCommit.updated}）`,
          `Imported ${lastCommit.added + lastCommit.updated} item(s) (${lastCommit.added} added · ${lastCommit.updated} updated)`
        )
      );
      await host.refreshVault();
    } catch (error) {
      host.toast(host.cleanError(error), 'error');
    } finally {
      isCommitting = false;
      render();
      notifyMetrics();
    }
  }

  async function handleUndoLastCommit() {
    if (!lastCommit?.createdIds?.length) return;
    if (!await host.ensureUnlocked()) return;
    try {
      const removed = await host.invoke('undo_smart_batch', { ids: lastCommit.createdIds });
      lastCommit = null;
      render();
      host.toast(
        t(`已撤销并移入回收站：${removed} 项`, `Undid ${removed} newly imported item(s) (moved to Trash)`)
      );
      await host.refreshVault();
    } catch (error) {
      host.toast(host.cleanError(error), 'error');
    }
  }

  function renderKindPills() {
    const counts = new Map();
    for (const c of candidates) {
      counts.set(c.kind, (counts.get(c.kind) || 0) + 1);
    }
    const labels = {
      all: [t('全部', 'All'), candidates.length],
      apiKey: ['API', counts.get('apiKey') || 0],
      login: [t('账号', 'Login'), counts.get('login') || 0],
      ssh: ['SSH', counts.get('ssh') || 0],
      database: [t('数据库', 'DB'), counts.get('database') || 0],
      totp: ['2FA', counts.get('totp') || 0],
      privateKey: [t('私钥', 'Key'), counts.get('privateKey') || 0],
      aws: ['AWS', counts.get('aws') || 0],
      env: [t('环境', 'Env'), counts.get('env') || 0],
      custom: [t('其他', 'Other'), counts.get('custom') || 0],
    };
    const keys = ['all', ...Array.from(counts.keys())];
    return keys
      .map((k) => {
        const [label, count] = labels[k] || [k, counts.get(k) || 0];
        return `<button type="button" class="import-kind-pill ${activeKindFilter === k ? 'active' : ''}" data-import-kind="${esc(k)}">${esc(label)} ${count}</button>`;
      })
      .join('');
  }

  function renderMatchPill(c) {
    if (c.matchStatus === 'duplicate') {
      return `<span class="import-match-pill is-dup" title="${esc(t('与现有金库条目完全一致', 'Identical to an existing vault item'))}">${esc(t('已重复', 'DUP'))}</span>`;
    }
    if (c.matchStatus === 'update') {
      const label = c.updateExisting
        ? t('更新原项 ⇄', 'UPDATE ⇄')
        : t('另存新项 ⇄', 'AS NEW ⇄');
      const title = c.updateExisting
        ? t(`将更新已有条目「${c.existingItemName || ''}」，点击切换为另存新项`, `Will update "${c.existingItemName || ''}" — click to save as new`)
        : t('将作为新条目保存，点击切换为更新原项', 'Will save as new — click to update existing');
      return `<button type="button" class="import-match-pill is-update" data-import-toggle-update="${esc(c.id)}" title="${esc(title)}">${esc(label)}</button>`;
    }
    return `<span class="import-match-pill is-new">${esc(t('新增', 'NEW'))}</span>`;
  }

  function renderCandidateCard(c) {
    const isRevealed = revealedIds.has(c.id);
    const isExpanded = expandedIds.has(c.id);
    const badgeText = lang().startsWith('zh') ? (c.badgeZh || c.badge) : c.badge;
    const visibleFields = (c.fields || []).slice(0, isExpanded ? 20 : 4);
    const hiddenCount = Math.max(0, (c.fields || []).length - visibleFields.length);
    const currentType = c.input?.itemType || 'custom';
    const typeChoices = [
      ['login', t('登录', 'Login')],
      ['api', 'API'],
      ['ssh', 'SSH'],
      ['card', t('信用卡', 'Card')],
      ['identity', t('身份资料', 'Identity')],
      ['secureNote', t('安全笔记', 'Secure note')],
      ['custom', t('自定义', 'Custom')],
    ];
    return `
      <article class="import-card ${c.selected ? '' : 'is-unchecked'}" data-import-card="${esc(c.id)}">
        <div class="import-card-top">
          <input type="checkbox" class="import-card-check" data-import-check="${esc(c.id)}" ${c.selected ? 'checked' : ''} aria-label="${esc(t('选择此条', 'Select item'))}" />
          <span class="import-type-badge">${esc(badgeText)}</span>
          <input type="text" class="import-title-input" data-import-rename="${esc(c.id)}" value="${esc(c.input?.name || '')}" maxlength="80" aria-label="${esc(t('条目名称', 'Item name'))}" />
          ${renderMatchPill(c)}
          <button type="button" class="import-card-icon-btn" data-import-edit-card="${esc(c.id)}" title="${esc(t('在编辑器中精修并保存', 'Refine & save in item editor'))}" aria-label="${esc(t('在编辑器中精修并保存', 'Refine & save in item editor'))}">
            <svg viewBox="0 0 24 24"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>
          </button>
          <button type="button" class="import-card-icon-btn" data-import-reveal="${esc(c.id)}" title="${esc(isRevealed ? t('隐藏明文', 'Hide values') : t('查看明文核对', 'Reveal values'))}" aria-label="${esc(isRevealed ? t('隐藏明文', 'Hide values') : t('查看明文核对', 'Reveal values'))}">
            <svg viewBox="0 0 24 24"><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z"/><circle cx="12" cy="12" r="2.5"/></svg>
          </button>
          <button type="button" class="import-card-icon-btn" data-import-expand="${esc(c.id)}" title="${esc(t('更多设置', 'More options'))}" aria-label="${esc(t('更多设置', 'More options'))}">
            <svg viewBox="0 0 24 24"><path d="${isExpanded ? 'm6 15 6-6 6 6' : 'm6 9 6 6 6-6'}"/></svg>
          </button>
        </div>
        <div class="import-card-fields">
          ${c.sourceSnippet && (c.sourceSnippet.includes('/') || c.sourceSnippet.startsWith('~')) ? `<span class="import-field-chip"><b>${esc(t('来源', 'File'))}</b><code>${esc(c.sourceSnippet)}</code></span>` : ''}
          ${visibleFields.map((f) => `<span class="import-field-chip"><b>${esc(f.label)}</b><code>${esc(isRevealed ? f.value : f.masked)}</code></span>`).join('')}
          ${hiddenCount > 0 ? `<span class="import-field-chip"><b>+${hiddenCount}</b></span>` : ''}
        </div>
        ${isExpanded ? `
          <div class="import-card-extra">
            <label><span>${esc(t('类型', 'Type'))}</span> <select data-import-type="${esc(c.id)}">${typeChoices.map(([v, l]) => `<option value="${esc(v)}" ${currentType === v ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select></label>
            <label><span>${esc(t('文件夹', 'Folder'))}</span> <input type="text" data-import-folder="${esc(c.id)}" value="${esc(c.input?.folder || '')}" placeholder="${esc(t('可选', 'Optional'))}" maxlength="48" /></label>
            <button type="button" class="import-mini-btn quiet" data-import-remove="${esc(c.id)}">${esc(t('移除', 'Remove'))}</button>
          </div>
        ` : ''}
      </article>
    `;
  }

  function render() {
    const page = $('#page-import');
    if (!page) return;

    // Static localized chrome
    const privacyText = $('#import-privacy-text');
    if (privacyText) {
      privacyText.textContent = t('离线规则提取 · 零联网', 'Offline rule extractor · Zero network');
    }
    const ta = $('#import-raw-input');
    if (ta) {
      ta.placeholder = t(
        '直接粘贴任何杂乱内容，或随时拖入任意文件 / 文件夹（.mvault · Excel .xlsx · Word .docx · ZIP · .env · CSV/TSV · JSON/YAML/TOML/INI · KeePass XML · SSH/私钥 · 2FA 截图）…',
        'Paste anything messy or drop any file / folder (.mvault, Excel .xlsx, Word .docx, ZIP, .env, CSV/TSV, JSON/YAML/TOML/INI, KeePass XML, SSH/keys, 2FA QR)…'
      );
    }

    const dropzone = $('#import-dropzone');
    const hasResults = candidates.length > 0 || ignored.length > 0;
    const hasAnyContent = hasResults || discoveredMvaults.length > 0;
    if (dropzone) {
      dropzone.classList.toggle('is-compact', hasAnyContent && !inputExpanded);
    }

    const formatBadge = $('#import-format-badge');
    if (formatBadge) {
      const baseFmt = lang().startsWith('zh') ? (detectedFormatZh || '智能提取') : (detectedFormat || 'smart');
      formatBadge.textContent = sourceFilename && sourceFilename !== baseFmt ? `${baseFmt} · ${sourceFilename}` : baseFmt;
    }
    const toggleBtn = $('#import-toggle-input-btn');
    if (toggleBtn) {
      toggleBtn.textContent = inputExpanded ? t('收起输入', 'Collapse') : t('展开输入', 'Edit input');
    }
    const clearBtn = $('#import-clear-btn');
    if (clearBtn) {
      clearBtn.classList.toggle('hidden', !rawText && !hasAnyContent && !lastCommit && !scanReport);
      clearBtn.textContent = t('清空', 'Clear');
    }

    // Quick buttons text
    const setBtnLabel = (id, zh, en) => {
      const el = $(id);
      if (el) el.textContent = t(zh, en);
    };
    setBtnLabel('#import-paste-btn-label', '粘贴', 'Paste');
    setBtnLabel('#import-file-btn-label', '文件', 'Files');
    setBtnLabel('#import-scan-btn-label', '一键搜索', 'Scan PC');
    setBtnLabel('#import-drop-badge', '拖入任意文件 / .mvault', 'Drop any file / .mvault');
    const scanBtn = $('#import-chip-scan');
    if (scanBtn) {
      scanBtn.title = t(
        '只读巡检本机 SSH 与私钥、Git/云凭据、AI/MCP 配置及桌面、文档、下载目录',
        'Read-only scan of SSH & keys, Git/cloud CLI, AI/MCP configs, and Desktop / Documents / Downloads'
      );
    }

    const scanBanner = $('#import-scan-banner');
    if (scanBanner) {
      const folderSvg = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M2 4.5A1.5 1.5 0 0 1 3.5 3h2.6l1.4 1.5h5A1.5 1.5 0 0 1 14 6v6a1.5 1.5 0 0 1-1.5 1.5h-9A1.5 1.5 0 0 1 2 12Z"/></svg>';
      const checkSvg = '<svg viewBox="0 0 14 14" aria-hidden="true"><path d="m2.5 7.2 2.8 2.8 6.2-6.4"/></svg>';
      if (activeScanMode) {
        scanBanner.classList.remove('hidden', 'is-idle');
        const scanningTitle = activeScanMode === 'workspace_folder'
          ? t('正在深度扫描项目目录…', 'Deep-scanning workspace folder…')
          : t('正在巡检本机凭据位置…', 'Scanning local credential locations…');
        scanBanner.innerHTML = `
          <div class="import-scan-head">
            <div class="import-scan-title-group">
              <span class="import-scan-dot is-hit" aria-hidden="true"></span>
              <span class="import-scan-title">${esc(scanningTitle)}</span>
            </div>
          </div>
        `;
      } else if (scanReport) {
        scanBanner.classList.remove('hidden', 'is-idle');
        const totalHits = candidates.length + discoveredMvaults.length;
        const isWorkspace = scanReport.mode === 'workspace_folder';
        const title = isWorkspace
          ? t('项目目录深扫完成', 'Workspace scan complete')
          : t('本机深度巡检完成', 'Local scan complete');
        const filesCount = Number(scanReport.totalInspectedFiles || 0);
        const ms = Math.max(1, Number(scanReport.durationMs || 1));
        const metaText = `${filesCount} ${t('文件', 'files')} · ${ms}ms`;
        const cats = Array.isArray(scanReport.categories) ? scanReport.categories : [];
        const catHtml = cats
          .map((cat) => {
            const hit = Number(cat.extractedCount || 0);
            const inspected = Number(cat.inspectedFiles || 0);
            const probed = Number(cat.probedLocations || 0);
            const stat = hit > 0 ? `+${hit}` : (inspected > 0 ? `${inspected}` : `0/${probed}`);
            const catLabel = t(cat.labelZh || cat.label, cat.label || cat.labelZh);
            return `
              <div class="import-scan-cat ${hit > 0 ? 'has-hit' : ''}">
                <span class="import-scan-cat-name">${checkSvg}<span>${esc(catLabel)}</span></span>
                <span class="import-scan-cat-stat">${esc(stat)}</span>
              </div>
            `;
          })
          .join('');
        const emptyNote = totalHits === 0
          ? `<div class="import-scan-empty-note">${esc(
              isWorkspace
                ? t(
                    '该目录下未发现高置信明文凭据（已自动跳过 node_modules 与 .env.example 模板）。',
                    'No plaintext secrets found in this folder (node_modules & .env.example skipped).'
                  )
                : t(
                    '常用路径未发现未入库明文凭据；若 .env 或密钥在其他代码盘，请点右上角「扫项目目录…」。',
                    'No plaintext secrets in default paths — click Scan Folder… to inspect code workspaces.'
                  )
            )}</div>`
          : '';
        scanBanner.innerHTML = `
          <div class="import-scan-head">
            <div class="import-scan-title-group">
              <span class="import-scan-dot ${totalHits > 0 ? 'is-hit' : ''}" aria-hidden="true"></span>
              <span class="import-scan-title">${esc(title)}</span>
              <span class="import-scan-meta">${esc(metaText)}</span>
            </div>
            <div class="import-scan-actions">
              <button type="button" class="import-scan-folder-btn" data-scan-workspace-folder="true" title="${esc(t('选择任意代码工作区目录（如 Github / Projects）深度扫描 .env 与密钥', 'Pick a code workspace folder to deep-scan for .env & keys'))}">${folderSvg}<span>${esc(t('扫项目目录…', 'Scan Folder…'))}</span></button>
            </div>
          </div>
          ${isWorkspace && scanReport.targetLabel ? `<div class="import-scan-path" title="${esc(scanReport.targetLabel)}">${esc(scanReport.targetLabel)}</div>` : ''}
          ${cats.length ? `<div class="import-scan-grid">${catHtml}</div>` : ''}
          ${emptyNote}
        `;
      } else if (!hasAnyContent && !lastCommit) {
        scanBanner.classList.remove('hidden');
        scanBanner.classList.add('is-idle');
        scanBanner.innerHTML = `
          <div class="import-scan-idle-copy">
            ${folderSvg}
            <span>${esc(t('代码盘有 .env / 私钥？支持按项目目录深度巡检', 'Have .env or keys in code folders? Deep-scan a workspace'))}</span>
          </div>
          <button type="button" class="import-scan-folder-btn" data-scan-workspace-folder="true">${folderSvg}<span>${esc(t('扫项目目录…', 'Scan Folder…'))}</span></button>
        `;
      } else {
        scanBanner.classList.add('hidden');
        scanBanner.classList.remove('is-idle');
        scanBanner.innerHTML = '';
      }
    }

    const supportedStrip = $('#import-supported-strip');
    if (supportedStrip) {
      supportedStrip.classList.toggle('hidden', hasAnyContent || Boolean(lastCommit) || Boolean(scanReport));
      const caps = [
        [t('加密备份', 'Encrypted backup'), t('.mvault 拖入勾选或全选', '.mvault selective popup')],
        [t('表格与文档', 'Office & archives'), t('Excel .xlsx · Word .docx · ZIP', 'Excel .xlsx · Word .docx · ZIP')],
        [t('密码管理器', 'Password exports'), t('Bitwarden · KeePass · CSV/TSV', 'Bitwarden · KeePass · CSV/TSV')],
        [t('开发与 AI 配置', 'Dev & AI configs'), t('.env · SSH/私钥 · MCP · 云凭据', '.env · SSH/Keys · MCP · Cloud')],
        [t('杂乱文本与 2FA', 'Text & 2FA QR'), t('聊天记录 · cURL · 二维码截图', 'Chat logs · cURL · 2FA QR')],
        [t('文件夹与任意文本', 'Folders & notes'), t('整个文件夹 · 普通文本转笔记', 'Folders · Text to secure note')],
      ];
      supportedStrip.innerHTML = caps
        .map(([title, desc]) => `<div class="import-cap-item"><strong>${esc(title)}</strong><span>${esc(desc)}</span></div>`)
        .join('');
    }

    // Discovered local .mvault backups — one-click open selective import modal
    const mvaultBanner = $('#import-mvault-banner');
    if (mvaultBanner) {
      if (discoveredMvaults.length) {
        mvaultBanner.classList.remove('hidden');
        mvaultBanner.innerHTML = discoveredMvaults
          .map(
            (mv) => `
              <div class="import-mvault-row">
                <div class="import-mvault-copy">
                  <strong>${esc(t('发现本机 .mvault 加密备份', 'Local .mvault backup found'))}</strong>
                  <code title="${esc(mv.displayPath)}">${esc(mv.displayPath)}</code>
                </div>
                <button type="button" class="import-mini-btn primary" data-open-discovered-mvault="${esc(mv.index)}">${esc(t('选择导入', 'Import…'))}</button>
              </div>
            `
          )
          .join('');
      } else {
        mvaultBanner.classList.add('hidden');
        mvaultBanner.innerHTML = '';
      }
    }

    // Done banner
    const doneEl = $('#import-done-banner');
    if (doneEl) {
      if (lastCommit) {
        doneEl.classList.remove('hidden');
        doneEl.innerHTML = `
          <div class="import-done-top">
            <strong>${esc(
              t(
                `已成功入库 ${lastCommit.added + lastCommit.updated} 项（新增 ${lastCommit.added} · 更新 ${lastCommit.updated}）`,
                `Imported ${lastCommit.added + lastCommit.updated} item(s) (${lastCommit.added} added · ${lastCommit.updated} updated)`
              )
            )}</strong>
          </div>
          <div class="import-done-actions">
            <button type="button" class="import-mini-btn" id="import-done-view">${esc(t('查看项目', 'View items'))}</button>
            ${lastCommit.createdIds.length ? `<button type="button" class="import-mini-btn quiet" id="import-done-undo">${esc(t('撤销新增', 'Undo added'))}</button>` : ''}
            ${lastCommit.sealedEnvTemplate ? `<button type="button" class="import-mini-btn" id="import-done-sealed">${esc(t('复制 .env 脱敏模板', 'Copy sealed .env'))}</button>` : ''}
            <button type="button" class="import-mini-btn quiet" id="import-done-more">${esc(t('继续导入', 'Import more'))}</button>
          </div>
        `;
      } else {
        doneEl.classList.add('hidden');
        doneEl.innerHTML = '';
      }
    }

    // Warnings
    const warnEl = $('#import-warning-strip');
    if (warnEl) {
      if (warnings.length) {
        warnEl.classList.remove('hidden');
        warnEl.textContent = warnings.join(' · ');
      } else {
        warnEl.classList.add('hidden');
        warnEl.textContent = '';
      }
    }

    // Results area
    const resultsWrap = $('#import-results-wrap');
    if (resultsWrap) {
      resultsWrap.classList.toggle('hidden', !hasResults && !isExtracting);
    }

    const toolbar = $('#import-staging-toolbar');
    const listEl = $('#import-candidate-list');
    const ignoredEl = $('#import-ignored-drawer');
    const commitBar = $('#import-commit-bar');

    if (isExtracting) {
      if (toolbar) toolbar.innerHTML = '';
      if (listEl) {
        listEl.innerHTML = `<div class="import-empty-result">${esc(t('正在本地规则提取…', 'Extracting locally…'))}</div>`;
      }
      if (ignoredEl) ignoredEl.classList.add('hidden');
      if (commitBar) commitBar.classList.add('hidden');
      return;
    }

    if (hasResults) {
      const visible = filteredCandidates();
      const selectedCount = candidates.filter((c) => c.selected).length;
      const allVisibleSelected = visible.length > 0 && visible.every((c) => c.selected);

      if (toolbar) {
        toolbar.innerHTML = `
          <div class="import-kind-pills">${renderKindPills()}</div>
          <button type="button" class="import-select-all-btn" id="import-toggle-all">
            ${esc(allVisibleSelected ? t('取消全选', 'Unselect all') : t('全选当前', 'Select all'))}
          </button>
        `;
      }

      if (listEl) {
        if (visible.length) {
          listEl.innerHTML = visible.map(renderCandidateCard).join('');
        } else if (candidates.length) {
          listEl.innerHTML = `<div class="import-empty-result">${esc(t('当前筛选条件下无匹配项', 'No candidates match the current filter'))}</div>`;
        } else {
          listEl.innerHTML = `<div class="import-empty-result">${esc(t('未提取到高置信凭据，可展开下方已过滤项手动恢复', 'No high-confidence secrets extracted — expand filtered items below to promote any entry'))}</div>`;
        }
      }

      if (ignoredEl) {
        if (ignored.length) {
          ignoredEl.classList.remove('hidden');
          const summary = $('#import-ignored-summary');
          const rows = $('#import-ignored-list');
          if (summary) {
            summary.textContent = t(
              `已自动过滤 ${ignored.length} 项非敏感或占位内容（点击展开可手动恢复）`,
              `Filtered ${ignored.length} non-secret / placeholder item(s) (click to inspect or restore)`
            );
          }
          if (rows) {
            rows.innerHTML = ignored
              .map(
                (item, idx) => `
                  <div class="import-ignored-row">
                    <div class="import-ignored-meta">
                      <code>${esc(item.key)} = ${esc(item.preview)}</code>
                      <small>${esc(lang().startsWith('zh') ? item.reasonZh : item.reason)}</small>
                    </div>
                    ${item.candidate ? `<button type="button" class="import-mini-btn quiet" data-import-promote="${idx}">${esc(t('+ 恢复', '+ Restore'))}</button>` : ''}
                  </div>
                `
              )
              .join('');
          }
        } else {
          ignoredEl.classList.add('hidden');
        }
      }

      if (commitBar) {
        commitBar.classList.toggle('hidden', candidates.length === 0);
        const folderInput = $('#import-batch-folder');
        if (folderInput) {
          folderInput.placeholder = t('统一归入文件夹（可选）', 'Assign folder (optional)');
        }
        const commitBtn = $('#import-commit-btn');
        if (commitBtn) {
          commitBtn.disabled = selectedCount === 0 || isCommitting;
          commitBtn.textContent = isCommitting
            ? t('正在入库…', 'Importing…')
            : t(`一键入库 (${selectedCount})`, `Import (${selectedCount})`);
        }
      }
    } else {
      if (toolbar) toolbar.innerHTML = '';
      if (listEl) listEl.innerHTML = '';
      if (ignoredEl) {
        ignoredEl.classList.add('hidden');
        const rows = $('#import-ignored-list');
        if (rows) rows.innerHTML = '';
      }
      if (commitBar) commitBar.classList.add('hidden');
    }
  }

  function bindEvents() {
    const page = $('#page-import');
    if (!page) return;

    const ta = $('#import-raw-input');
    ta?.addEventListener('input', () => {
      rawText = ta.value;
      sourceFilename = null;
      clipboardSource = '';
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        void runExtract(rawText, sourceFilename);
      }, 220);
    });

    ta?.addEventListener('paste', (event) => {
      const dt = event.clipboardData;
      if (!dt) return;
      const imageItem = [...(dt.items || [])].find((item) => item.type?.startsWith('image/'));
      if (imageItem) {
        const blob = imageItem.getAsFile();
        if (blob) {
          event.preventDefault();
          void handleFiles([blob]);
        }
      }
    });

    const dropzone = $('#import-dropzone');
    dropzone?.addEventListener('dragover', (event) => {
      event.preventDefault();
      dropzone.classList.add('is-dragover');
    });
    dropzone?.addEventListener('dragleave', () => {
      dropzone.classList.remove('is-dragover');
    });
    dropzone?.addEventListener('drop', (event) => {
      event.preventDefault();
      event.stopPropagation();
      dropzone.classList.remove('is-dragover');
      document.getElementById('global-mvault-drop-overlay')?.classList.add('hidden');
      if (event.dataTransfer?.files?.length) {
        void handleFiles(event.dataTransfer.files);
      }
    });

    $('#import-paste-btn')?.addEventListener('click', () => void handlePasteClipboard());
    $('#import-file-btn')?.addEventListener('click', () => void handlePickFiles());
    $('#import-clear-btn')?.addEventListener('click', () => resetAll());
    $('#import-toggle-input-btn')?.addEventListener('click', () => {
      inputExpanded = !inputExpanded;
      render();
    });

    $('#import-chip-scan')?.addEventListener('click', () => void handleScanLocal());

    $('#import-commit-btn')?.addEventListener('click', () => void handleCommit());

    page.addEventListener('click', (event) => {
      if (event.target.closest('[data-scan-workspace-folder]')) {
        void handleScanWorkspaceFolder();
        return;
      }
      const openMvaultBtn = event.target.closest('[data-open-discovered-mvault]');
      if (openMvaultBtn) {
        const index = Number(openMvaultBtn.dataset.openDiscoveredMvault);
        openMvaultBtn.disabled = true;
        void host
          .invoke('open_discovered_mvault', { index })
          .then((picked) => host.openMvaultPreview?.(picked))
          .catch((error) => host.toast(host.cleanError(error), 'error'))
          .finally(() => {
            openMvaultBtn.disabled = false;
          });
        return;
      }
      const kindBtn = event.target.closest('[data-import-kind]');
      if (kindBtn) {
        activeKindFilter = kindBtn.dataset.importKind;
        render();
        return;
      }
      if (event.target.closest('#import-toggle-all')) {
        const visible = filteredCandidates();
        const allSelected = visible.length > 0 && visible.every((c) => c.selected);
        for (const c of visible) c.selected = !allSelected;
        render();
        notifyMetrics();
        return;
      }
      const toggleUpdate = event.target.closest('[data-import-toggle-update]');
      if (toggleUpdate) {
        const cand = candidates.find((c) => c.id === toggleUpdate.dataset.importToggleUpdate);
        if (cand) {
          cand.updateExisting = !cand.updateExisting;
          render();
        }
        return;
      }
      const editBtn = event.target.closest('[data-import-edit-card]');
      if (editBtn) {
        const id = editBtn.dataset.importEditCard;
        const cand = candidates.find((c) => c.id === id);
        if (cand && host?.openCandidateInEditor) {
          void host.openCandidateInEditor(cand, () => {
            candidates = candidates.filter((c) => c.id !== id);
            render();
            notifyMetrics();
          });
        }
        return;
      }
      const revealBtn = event.target.closest('[data-import-reveal]');
      if (revealBtn) {
        const id = revealBtn.dataset.importReveal;
        if (revealedIds.has(id)) revealedIds.delete(id);
        else revealedIds.add(id);
        render();
        return;
      }
      const expandBtn = event.target.closest('[data-import-expand]');
      if (expandBtn) {
        const id = expandBtn.dataset.importExpand;
        if (expandedIds.has(id)) expandedIds.delete(id);
        else expandedIds.add(id);
        render();
        return;
      }
      const removeBtn = event.target.closest('[data-import-remove]');
      if (removeBtn) {
        const id = removeBtn.dataset.importRemove;
        candidates = candidates.filter((c) => c.id !== id);
        render();
        notifyMetrics();
        return;
      }
      const promoteBtn = event.target.closest('[data-import-promote]');
      if (promoteBtn) {
        const idx = Number(promoteBtn.dataset.importPromote);
        const item = ignored[idx];
        if (item?.candidate) {
          item.candidate.selected = true;
          candidates.push(item.candidate);
          ignored.splice(idx, 1);
          render();
          notifyMetrics();
        }
        return;
      }
      if (event.target.closest('#import-done-view')) {
        host?.goToItems?.();
        return;
      }
      if (event.target.closest('#import-done-undo')) {
        void handleUndoLastCommit();
        return;
      }
      if (event.target.closest('#import-done-sealed')) {
        if (lastCommit?.sealedEnvTemplate) {
          void host
            .invoke('copy_owner_value', { value: lastCommit.sealedEnvTemplate, sensitive: false })
            .then(() =>
              host.toast(
                t('已复制脱敏 .env 模板（含 {{openkeylet:KEY}} 占位符）', 'Copied sealed .env template with {{openkeylet:KEY}} placeholders')
              )
            )
            .catch((e) => host.toast(host.cleanError(e), 'error'));
        }
        return;
      }
      if (event.target.closest('#import-done-more')) {
        lastCommit = null;
        render();
        $('#import-raw-input')?.focus();
      }
    });

    page.addEventListener('change', (event) => {
      const chk = event.target.closest('[data-import-check]');
      if (chk) {
        const cand = candidates.find((c) => c.id === chk.dataset.importCheck);
        if (cand) {
          cand.selected = Boolean(chk.checked);
          render();
          notifyMetrics();
        }
        return;
      }
      const typeSel = event.target.closest('[data-import-type]');
      if (typeSel) {
        const cand = candidates.find((c) => c.id === typeSel.dataset.importType);
        if (cand && cand.input) {
          cand.input.itemType = typeSel.value || 'custom';
        }
      }
    });

    page.addEventListener('input', (event) => {
      const rename = event.target.closest('[data-import-rename]');
      if (rename) {
        const cand = candidates.find((c) => c.id === rename.dataset.importRename);
        if (cand && cand.input) cand.input.name = rename.value;
        return;
      }
      const folder = event.target.closest('[data-import-folder]');
      if (folder) {
        const cand = candidates.find((c) => c.id === folder.dataset.importFolder);
        if (cand && cand.input) cand.input.folder = folder.value;
      }
    });
  }

  window.OpenKeyletImportHub = {
    init(bridge) {
      host = bridge;
      bindEvents();
      render();
    },
    render,
    getStats,
    handleFiles,
    handleNativeDropPayload,
    notifyExternalImportDone(summary) {
      const added = Number(summary?.added || 0);
      const merged = Number(summary?.merged || 0);
      if (added <= 0 && merged <= 0) return;
      lastCommit = {
        added,
        updated: 0,
        createdIds: [],
        sealedEnvTemplate: null,
      };
      render();
      notifyMetrics();
    },
    handlePasteText(text, { fromClipboard = false } = {}) {
      rawText = String(text || '');
      sourceFilename = null;
      clipboardSource = fromClipboard ? rawText : '';
      const ta = $('#import-raw-input');
      if (ta) ta.value = rawText;
      void runExtract(rawText, null);
    },
    focusInput() {
      if (!candidates.length && !ignored.length) {
        $('#import-raw-input')?.focus({ preventScroll: true });
      }
    },
    clearPlaintext() {
      resetAll();
    },
  };
})();
