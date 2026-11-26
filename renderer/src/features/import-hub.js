/* OpenKeylet Universal Offline Import Hub controller.
   Two independent pages (Add / Scan) with isolated staging state, pure local rule extraction,
   unified results (including .mvault), vault dedup & high-density batch commit. */
import { OpenKeyletQR } from '../lib/qr-decode.js';

const $ = (sel, root = document) => root.querySelector(sel);

let host = null;
let debounceTimer = null;
let activeMode = 'add'; // 'add' | 'scan'

function createPaneState(mode) {
  return {
    mode,
    rawText: '',
    sourceFilename: null,
    clipboardSource: '',
    inputExpanded: mode === 'add',
    scanDetailsExpanded: false,
    activeKindFilter: 'all',
    isExtracting: false,
    isCommitting: false,
    detectedFormat: '',
    detectedFormatZh: '',
    candidates: [],
    ignored: [],
    warnings: [],
    discoveredMvaults: [],
    scanReport: null,
    activeScanMode: null,
    sealedEnvTemplate: null,
    batchFolder: '',
    scrollTop: 0,
    revealedIds: new Set(),
    expandedIds: new Set(),
    lastCommit: null,
  };
}

const panes = {
  add: createPaneState('add'),
  scan: createPaneState('scan'),
};

function currentPane() {
  return panes[activeMode] || panes.add;
}

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

function paneItemCount(pane) {
  return pane.candidates.length + pane.discoveredMvaults.length;
}

function getStats() {
  const pane = currentPane();
  const selected = pane.candidates.filter((c) => c.selected).length;
  return {
    total: paneItemCount(pane),
    selectable: pane.candidates.length,
    selected,
    ignored: pane.ignored.length,
  };
}

function notifyMetrics() {
  host?.onStatsChange?.();
}

function getSearchQuery() {
  return String(host?.getSearchQuery?.() || '').trim().toLowerCase();
}

function filteredCandidates(pane = currentPane()) {
  if (pane.activeKindFilter === 'mvault') return [];
  const q = getSearchQuery();
  return pane.candidates.filter((c) => {
    if (pane.activeKindFilter !== 'all' && c.kind !== pane.activeKindFilter) return false;
    if (!q) return true;
    const hay = [
      c.input?.name,
      c.summary,
      c.sourceSnippet,
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

function filteredMvaults(pane = currentPane()) {
  if (pane.activeKindFilter !== 'all' && pane.activeKindFilter !== 'mvault') return [];
  const q = getSearchQuery();
  return pane.discoveredMvaults.filter((mv) => {
    if (!q) return true;
    const hay = `${mv.fileName || ''} ${mv.displayPath || ''} mvault backup 备份`.toLowerCase();
    return hay.includes(q);
  });
}

function syncPaneDomInputs() {
  const pane = currentPane();
  const ta = $('#import-raw-input');
  if (ta && ta.value !== panes.add.rawText) {
    ta.value = panes.add.rawText;
  }
  const folderInput = $('#import-batch-folder');
  if (folderInput && folderInput.value !== pane.batchFolder) {
    folderInput.value = pane.batchFolder;
  }
}

function setMode(nextMode, { playSound = false } = {}) {
  const normalized = nextMode === 'scan' ? 'scan' : 'add';
  if (activeMode === normalized) return;
  const scroller = $('#import-scroll-area');
  if (scroller) {
    currentPane().scrollTop = scroller.scrollTop;
  }
  const folderInput = $('#import-batch-folder');
  if (folderInput) {
    currentPane().batchFolder = folderInput.value;
  }
  activeMode = normalized;
  if (playSound) {
    window.OpenKeyletAppearance?.play?.('select');
  }
  syncPaneDomInputs();
  render();
  notifyMetrics();
  if (scroller) {
    scroller.scrollTop = currentPane().scrollTop || 0;
  }
}

function resetPane(pane, { keepDoneBanner = false } = {}) {
  const preservedCommit = keepDoneBanner ? pane.lastCommit : null;
  const fresh = createPaneState(pane.mode);
  Object.assign(pane, fresh);
  pane.lastCommit = preservedCommit;
  if (pane === currentPane()) {
    syncPaneDomInputs();
    const scroller = $('#import-scroll-area');
    if (scroller) scroller.scrollTop = 0;
  }
  render();
  notifyMetrics();
}

function resetAllPanes() {
  Object.assign(panes.add, createPaneState('add'));
  Object.assign(panes.scan, createPaneState('scan'));
  const ta = $('#import-raw-input');
  if (ta) ta.value = '';
  const folderInput = $('#import-batch-folder');
  if (folderInput) folderInput.value = '';
  const scroller = $('#import-scroll-area');
  if (scroller) scroller.scrollTop = 0;
  render();
  notifyMetrics();
}

function applyBatchResult(pane, result, { append = false } = {}) {
  pane.lastCommit = null;
  if (!result) return;
  pane.detectedFormat = result.detectedFormat || 'mixed_text';
  pane.detectedFormatZh = result.detectedFormatZh || '混合文本';
  if (append && pane.candidates.length) {
    const existingIds = new Set(pane.candidates.map((c) => c.id));
    for (const c of result.candidates || []) {
      if (!existingIds.has(c.id)) pane.candidates.push(c);
    }
    pane.ignored = [...pane.ignored, ...(result.ignored || [])];
    pane.warnings = [...new Set([...pane.warnings, ...(result.warnings || [])])];
    if (!pane.sealedEnvTemplate && result.sealedEnvTemplate) {
      pane.sealedEnvTemplate = result.sealedEnvTemplate;
    }
  } else {
    pane.candidates = Array.isArray(result.candidates) ? result.candidates : [];
    pane.ignored = Array.isArray(result.ignored) ? result.ignored : [];
    pane.warnings = Array.isArray(result.warnings) ? result.warnings : [];
    pane.discoveredMvaults = Array.isArray(result.discoveredMvaults) ? result.discoveredMvaults : [];
    pane.scanReport = result.scanReport || null;
    pane.sealedEnvTemplate = result.sealedEnvTemplate || null;
    pane.revealedIds.clear();
    pane.expandedIds.clear();
    pane.activeKindFilter = 'all';
    const totalHits = paneItemCount(pane);
    pane.scanDetailsExpanded = Boolean(pane.scanReport) && totalHits === 0;
  }
  if (pane.mode === 'add' && (pane.candidates.length > 0 || pane.ignored.length > 0 || pane.discoveredMvaults.length > 0)) {
    pane.inputExpanded = false;
  }
  render();
  notifyMetrics();
}

// Candidates decoded from a QR image come back from a text extraction that knows nothing
// about the image file, so the image's opaque source reference is attached here.
function tagSourceRef(result, sourceRef) {
  if (!result || !sourceRef) return;
  const cards = [
    ...(Array.isArray(result.candidates) ? result.candidates : []),
    ...(Array.isArray(result.ignored) ? result.ignored.map((item) => item.candidate).filter(Boolean) : []),
  ];
  for (const card of cards) {
    const refs = Array.isArray(card.sourceRefs) ? card.sourceRefs : [];
    if (!refs.includes(sourceRef)) card.sourceRefs = [...refs, sourceRef];
  }
}

async function runExtract(text, filename = null, { append = false, sourceRef = null } = {}) {
  const pane = panes.add;
  const trimmed = String(text || '').trim();
  if (!trimmed) {
    if (!append) {
      pane.candidates = [];
      pane.ignored = [];
      pane.warnings = [];
      pane.discoveredMvaults = [];
      pane.detectedFormat = '';
      pane.detectedFormatZh = '';
      pane.sealedEnvTemplate = null;
      pane.inputExpanded = true;
      render();
      notifyMetrics();
    }
    return;
  }
  if (!await host.ensureUnlocked()) return;
  if (activeMode !== 'add') setMode('add');
  pane.isExtracting = true;
  render();
  try {
    const result = await host.invoke('smart_extract_batch', {
      text: trimmed,
      filename: filename || null,
    });
    tagSourceRef(result, sourceRef);
    applyBatchResult(pane, result, { append });
  } catch (error) {
    host.toast(host.cleanError(error), 'error');
  } finally {
    pane.isExtracting = false;
    render();
    notifyMetrics();
  }
}

async function handlePasteClipboard() {
  if (!await host.ensureUnlocked()) return;
  if (activeMode !== 'add') setMode('add');
  const pane = panes.add;
  try {
    // 1. Check image QR in clipboard first
    if (navigator.clipboard?.read && OpenKeyletQR?.supported) {
      try {
        const items = await navigator.clipboard.read();
        for (const item of items) {
          const imgType = item.types.find((type) => type.startsWith('image/'));
          if (imgType) {
            const blob = await item.getType(imgType);
            const decoded = await OpenKeyletQR.decode(blob);
            pane.rawText = decoded;
            pane.sourceFilename = 'QR Screenshot';
            pane.clipboardSource = '';
            const ta = $('#import-raw-input');
            if (ta) ta.value = decoded;
            await runExtract(decoded, pane.sourceFilename);
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
    pane.rawText = text;
    pane.sourceFilename = null;
    pane.clipboardSource = text;
    const ta = $('#import-raw-input');
    if (ta) ta.value = text;
    await runExtract(text, null);
    if (pane.candidates.length === 0 && pane.ignored.length === 0 && pane.discoveredMvaults.length === 0) {
      host.toast(
        t(
          '已粘贴原文，未识别到结构化凭据；可直接检查或点下方模板新建',
          'Pasted text — no structured credentials detected; inspect or create from templates below'
        )
      );
      ta?.focus({ preventScroll: true });
    }
  } catch (error) {
    host.toast(host.cleanError(error), 'error');
  }
}

function isBinaryExtractable(name) {
  return /\.(docx|xlsx|zip|1pux)$/i.test(String(name || ''));
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
  if (!OpenKeyletQR?.decode) {
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
      const decoded = await OpenKeyletQR.decode(blob);
      await runExtract(decoded, img.fileName || 'QR Image', { append: shouldAppend, sourceRef: img.sourceRef || null });
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
  if (activeMode !== 'add') setMode('add');
  const pane = panes.add;
  pane.isExtracting = true;
  render();
  try {
    const result = await host.invoke('smart_pick_and_extract_files');
    if (!result) return;
    pane.sourceFilename = Array.isArray(result.sourceFiles) && result.sourceFiles.length
      ? result.sourceFiles.slice(0, 3).join(' · ')
      : null;
    pane.clipboardSource = '';
    const hasExtracted = (result.candidates?.length || 0) > 0
      || (result.ignored?.length || 0) > 0
      || (result.warnings?.length || 0) > 0;
    if (hasExtracted) {
      applyBatchResult(pane, result, { append: false });
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
    pane.isExtracting = false;
    render();
    notifyMetrics();
  }
}

async function handleNativeDropPayload(payload) {
  if (!payload) return;
  if (!await host.ensureUnlocked()) return;
  if (activeMode !== 'add') setMode('add');
  const pane = panes.add;
  const batch = payload.batch || null;
  const sourceFiles = Array.isArray(payload.sourceFiles) ? payload.sourceFiles : [];
  pane.sourceFilename = sourceFiles.length
    ? sourceFiles.slice(0, 3).join(' · ') + (sourceFiles.length > 3 ? ` (+${sourceFiles.length - 3})` : '')
    : null;
  pane.clipboardSource = '';
  const hasBatchContent = Boolean(
    batch && ((batch.candidates?.length || 0) > 0 || (batch.ignored?.length || 0) > 0 || (batch.warnings?.length || 0) > 0)
  );
  if (hasBatchContent) {
    applyBatchResult(pane, batch, { append: false });
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
  const pane = panes.scan;
  if (pane.activeScanMode) return;
  if (!await host.ensureUnlocked()) return;
  if (activeMode !== 'scan') setMode('scan');
  pane.isExtracting = true;
  pane.activeScanMode = 'quick_pc';
  render();
  try {
    const result = await host.invoke('smart_scan_local_dev_configs');
    pane.sourceFilename = null;
    pane.clipboardSource = '';
    applyBatchResult(pane, result, { append: false });
    const foundCount = (result?.candidates?.length || 0);
    const mvaultCount = (result?.discoveredMvaults?.length || 0);
    const inspectedCount = (result?.scanReport?.totalInspectedFiles || 0);
    if (foundCount > 0 || mvaultCount > 0) {
      const parts = [];
      if (foundCount > 0) parts.push(t(`${foundCount} 项凭据`, `${foundCount} credential(s)`));
      if (mvaultCount > 0) parts.push(t(`${mvaultCount} 个备份`, `${mvaultCount} backup(s)`));
      host.toast(
        t(
          `本机扫描发现 ${parts.join('、')}`,
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
    pane.isExtracting = false;
    pane.activeScanMode = null;
    render();
    notifyMetrics();
  }
}

async function handleScanWorkspaceFolder() {
  const pane = panes.scan;
  if (pane.activeScanMode) return;
  if (!await host.ensureUnlocked()) return;
  if (activeMode !== 'scan') setMode('scan');
  pane.isExtracting = true;
  pane.activeScanMode = 'workspace_folder';
  render();
  try {
    const result = await host.invoke('smart_scan_workspace_folder');
    if (!result) return;
    pane.sourceFilename = null;
    pane.clipboardSource = '';
    applyBatchResult(pane, result, { append: false });
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
    pane.isExtracting = false;
    pane.activeScanMode = null;
    render();
    notifyMetrics();
  }
}

async function handleFiles(fileList) {
  const files = Array.from(fileList || []);
  if (!files.length) return;
  if (!await host.ensureUnlocked()) return;
  if (activeMode !== 'add') setMode('add');
  const pane = panes.add;
  let combinedFirst = true;
  for (const file of files) {
    const lower = (file.name || '').toLowerCase();
    if (lower.endsWith('.mvault') || lower.endsWith('.kdbx')) {
      if (host.openDroppedMvault) {
        await host.openDroppedMvault(file);
      } else {
        host.toast(
          t(
            '检测到加密密码库文件，正在打开解锁恢复窗口',
            'Detected encrypted vault file — opening unlock & import flow'
          )
        );
        host.openBackupRestore?.();
      }
      continue;
    }
    if (lower.endsWith('.json') && file.size <= 64 * 1024 * 1024 && host.openDroppedMvault) {
      try {
        const jsonText = await file.text();
        const parsed = JSON.parse(jsonText.replace(/^\uFEFF/, ''));
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && parsed.encrypted === true) {
          await host.openDroppedMvault(file);
          continue;
        }
      } catch {
        // Fall through to standard text extraction
      }
    }
    if (file.type?.startsWith('image/') || /\.(png|jpe?g|webp|gif|bmp)$/i.test(lower)) {
      try {
        if (!OpenKeyletQR?.decode) {
          throw new Error(t('当前环境不支持二维码图片解码', 'QR decoding is unavailable in this WebView'));
        }
        const decoded = await OpenKeyletQR.decode(file);
        await runExtract(decoded, file.name, { append: !combinedFirst });
        combinedFirst = false;
      } catch (error) {
        host.toast(`${file.name}: ${host.cleanError(error)}`, 'error');
      }
      continue;
    }
    const maxSize = lower.endsWith('.1pux') ? 64 * 1024 * 1024 : 16 * 1024 * 1024;
    if (file.size > maxSize) {
      host.toast(
        t(`${file.name} 超过大小限制，已跳过`, `${file.name} exceeds file size limit`),
        'error'
      );
      continue;
    }
    if (isBinaryExtractable(lower)) {
      pane.isExtracting = true;
      render();
      try {
        const dataBase64 = await fileToBase64(file);
        const result = await host.invoke('smart_extract_dropped_binary', {
          fileName: file.name,
          dataBase64,
        });
        if (combinedFirst) pane.sourceFilename = file.name;
        applyBatchResult(pane, result, { append: !combinedFirst });
        combinedFirst = false;
      } catch (error) {
        host.toast(`${file.name}: ${host.cleanError(error)}`, 'error');
      } finally {
        pane.isExtracting = false;
        render();
        notifyMetrics();
      }
      continue;
    }
    try {
      const text = await file.text();
      if (combinedFirst) {
        pane.rawText = text;
        pane.sourceFilename = file.name;
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
  const pane = currentPane();
  const selected = pane.candidates.filter((c) => c.selected);
  if (!selected.length || pane.isCommitting) return;
  if (!await host.ensureUnlocked()) return;
  pane.isCommitting = true;
  render();
  try {
    const batchFolder = ($('#import-batch-folder')?.value || pane.batchFolder || '').trim();
    const payload = selected.map((c) => ({
      input: c.input,
      updateExisting: Boolean(c.matchStatus === 'update' && c.updateExisting),
      existingItemId: c.existingItemId || null,
      sourceRefs: Array.isArray(c.sourceRefs) ? c.sourceRefs : [],
    }));
    const summary = await host.invoke('commit_smart_batch', {
      items: payload,
      folder: batchFolder || null,
    });
    const sealedBackup = pane.sealedEnvTemplate;
    const preservedMvaults = Array.isArray(pane.discoveredMvaults) ? [...pane.discoveredMvaults] : [];
    if (pane.clipboardSource) {
      await host.invoke('clear_clipboard_if_matches', { text: pane.clipboardSource }).catch(() => false);
    }
    pane.lastCommit = {
      added: summary?.added || 0,
      updated: summary?.updated || 0,
      createdIds: Array.isArray(summary?.createdIds) ? summary.createdIds : [],
      sealedEnvTemplate: sealedBackup,
      plaintextSources: Array.isArray(summary?.plaintextSources) ? summary.plaintextSources : [],
    };
    resetPane(pane, { keepDoneBanner: true });
    if (preservedMvaults.length) {
      pane.discoveredMvaults = preservedMvaults;
      render();
      notifyMetrics();
    }
    window.OpenKeyletAppearance?.play?.('success');
    host.toast(
      t(
        `已入库 ${pane.lastCommit.added + pane.lastCommit.updated} 项（新增 ${pane.lastCommit.added} · 更新 ${pane.lastCommit.updated}）`,
        `Imported ${pane.lastCommit.added + pane.lastCommit.updated} item(s) (${pane.lastCommit.added} added · ${pane.lastCommit.updated} updated)`
      )
    );
    await host.refreshVault();
  } catch (error) {
    host.toast(host.cleanError(error), 'error');
  } finally {
    pane.isCommitting = false;
    render();
    notifyMetrics();
  }
}

async function handleUndoLastCommit() {
  const pane = currentPane();
  if (!pane.lastCommit?.createdIds?.length) return;
  if (!await host.ensureUnlocked()) return;
  try {
    const removed = await host.invoke('undo_smart_batch', { ids: pane.lastCommit.createdIds });
    pane.lastCommit = null;
    render();
    host.toast(
      t(`已撤销并移入回收站：${removed} 项`, `Undid ${removed} newly imported item(s) (moved to Trash)`)
    );
    await host.refreshVault();
  } catch (error) {
    host.toast(host.cleanError(error), 'error');
  }
}

function renderKindPills(pane) {
  const counts = new Map();
  for (const c of pane.candidates) {
    counts.set(c.kind, (counts.get(c.kind) || 0) + 1);
  }
  if (pane.discoveredMvaults.length > 0) {
    counts.set('mvault', pane.discoveredMvaults.length);
  }
  const totalCount = paneItemCount(pane);
  const labels = {
    all: [t('全部', 'All'), totalCount],
    apiKey: ['API', counts.get('apiKey') || 0],
    login: [t('账号', 'Login'), counts.get('login') || 0],
    ssh: ['SSH', counts.get('ssh') || 0],
    database: [t('数据库', 'DB'), counts.get('database') || 0],
    totp: ['2FA', counts.get('totp') || 0],
    privateKey: [t('私钥', 'Key'), counts.get('privateKey') || 0],
    aws: ['AWS', counts.get('aws') || 0],
    env: [t('环境', 'Env'), counts.get('env') || 0],
    mvault: [t('备份', 'Backup'), counts.get('mvault') || 0],
    custom: [t('其他', 'Other'), counts.get('custom') || 0],
  };
  const keys = ['all', ...Array.from(counts.keys())];
  if (!keys.includes(pane.activeKindFilter)) {
    pane.activeKindFilter = 'all';
  }
  return keys
    .map((k) => {
      const [label, count] = labels[k] || [k, counts.get(k) || 0];
      return `<button type="button" class="import-kind-pill ${pane.activeKindFilter === k ? 'active' : ''}" data-import-kind="${esc(k)}">${esc(label)} ${count}</button>`;
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

function pickVisibleFields(fields, isExpanded) {
  const all = Array.isArray(fields) ? fields : [];
  if (isExpanded || all.length <= 3) return all.slice(0, 20);
  const picked = all.slice(0, 3);
  const firstSecret = all.find((f) => f.secret);
  if (firstSecret && !picked.includes(firstSecret)) {
    picked[2] = firstSecret;
  }
  return picked;
}

function renderCandidateCard(pane, c) {
  const isRevealed = pane.revealedIds.has(c.id);
  const isExpanded = pane.expandedIds.has(c.id);
  const badgeText = lang().startsWith('zh') ? (c.badgeZh || c.badge) : c.badge;
  const allFields = Array.isArray(c.fields) ? c.fields : [];
  const visibleFields = pickVisibleFields(allFields, isExpanded);
  const hiddenCount = Math.max(0, allFields.length - visibleFields.length);
  const hasSourcePath = Boolean(c.sourceSnippet && (c.sourceSnippet.includes('/') || c.sourceSnippet.startsWith('~')));
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
  const sourceSvg = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M4 2.5h5l3 3v8H4Z"/><path d="M9 2.5v3h3"/></svg>';
  return `
    <article class="import-card ${c.selected ? '' : 'is-unchecked'} ${isRevealed ? 'is-revealed' : ''} ${isExpanded ? 'is-expanded' : ''}" data-import-card="${esc(c.id)}" data-import-selected="${c.selected ? 'true' : 'false'}" tabindex="-1">
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
        ${visibleFields.map((f) => {
          const shown = isRevealed ? f.value : f.masked;
          return `<span class="import-field-chip ${f.secret ? 'is-secret' : ''}" title="${esc(f.secret && !isRevealed ? f.label : `${f.label}: ${shown}`)}"><b>${esc(f.label)}</b><code>${esc(shown)}</code></span>`;
        }).join('')}
        ${hiddenCount > 0 ? `<span class="import-field-chip is-secret"><b>+${hiddenCount}</b></span>` : ''}
        ${hasSourcePath ? `<span class="import-field-chip is-source" title="${esc(`${t('来源', 'File')}: ${c.sourceSnippet}`)}">${sourceSvg}<code>${esc(c.sourceSnippet)}</code></span>` : ''}
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

function renderMvaultCard(mv) {
  const fileName = mv.fileName || mv.displayPath || 'backup.mvault';
  const sourceSvg = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M4 2.5h5l3 3v8H4Z"/><path d="M9 2.5v3h3"/></svg>';
  return `
    <article class="import-card is-backup" data-import-mvault="${esc(mv.index)}" tabindex="-1">
      <div class="import-card-top">
        <span class="import-card-slot-icon" aria-hidden="true">
          <svg viewBox="0 0 16 16"><rect x="3" y="7" width="10" height="6.5" rx="1.5"/><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2"/></svg>
        </span>
        <span class="import-type-badge">${esc(t('备份', 'BACKUP'))}</span>
        <span class="import-card-static-title" title="${esc(fileName)}">${esc(fileName)}</span>
        <button type="button" class="import-card-action-btn" data-open-discovered-mvault="${esc(mv.index)}">${esc(t('选择导入', 'Import…'))}</button>
      </div>
      <div class="import-card-fields">
        <span class="import-field-chip is-secret"><b>${esc(t('格式', 'Format'))}</b><code>.mvault</code></span>
        <span class="import-field-chip is-source" title="${esc(`${t('路径', 'Path')}: ${mv.displayPath}`)}">${sourceSvg}<code>${esc(mv.displayPath)}</code></span>
      </div>
    </article>
  `;
}

// The concrete next step for each kind of file reported by commit_smart_batch.
function plaintextStep(kind) {
  switch (kind) {
    case 'env':
      return t('改用脱敏 .env 模板，然后删除此文件', 'Use the sealed .env template instead, then delete this file');
    case 'key':
      return t('确认金库中的副本可用后删除此文件', 'Delete it once the vault copy works');
    case 'agent':
      return t('从此文件中删掉粘贴进去的密钥', 'Remove the pasted secret from this file');
    case 'shell':
      return t('删除包含密钥的那一行', 'Delete the line that holds the secret');
    case 'tool':
      return t('该工具会直接读取此文件；改用 OpenKeylet 后再删掉密钥', 'Its tool reads this file; remove the secret once you switch to OpenKeylet');
    case 'backup':
      return t('这是 OpenKeylet 旧的修复备份，可直接删除', 'Old OpenKeylet repair backup; delete it');
    default:
      return t('删除此文件，并清空回收站', 'Delete this file, then empty the trash');
  }
}

function renderPlaintextSources(sources) {
  const list = Array.isArray(sources) ? sources.filter((s) => s && s.displayPath) : [];
  if (!list.length) return '';
  const title = t('明文仍留在磁盘上', 'Plaintext is still on disk');
  return `
    <section class="import-plaintext" id="import-plaintext-sources" aria-label="${esc(title)}">
      <div class="import-plaintext-head">
        <span class="import-plaintext-dot" aria-hidden="true"></span>
        <strong class="import-plaintext-title" title="${esc(title)}">${esc(title)}</strong>
        <button type="button" class="import-mini-btn quiet" id="import-done-copy-paths">${esc(t('复制路径', 'Copy paths'))}</button>
      </div>
      <p class="import-plaintext-note">${esc(t(
        '导入不会改动原文件，任何搜索磁盘的程序仍能读到这些密钥。',
        'The import left these files unchanged; anything that searches your disk can still read them.'
      ))}</p>
      <ul class="import-plaintext-list">
        ${list.map((source) => `
          <li class="import-plaintext-row" data-plaintext-kind="${esc(source.kind || 'document')}">
            <code class="import-plaintext-path" title="${esc(source.displayPath)}"><bdi>${esc(source.displayPath)}</bdi></code>
            <span class="import-plaintext-step">${esc(plaintextStep(source.kind))}</span>
          </li>
        `).join('')}
      </ul>
    </section>
  `;
}

function renderScanBanner(pane, hasAnyContent) {
  const scanBanner = $('#import-scan-banner');
  if (!scanBanner) return;

  // Scan banner belongs strictly to the Scan tab — never bleeds into Add tab
  if (pane.mode !== 'scan') {
    scanBanner.className = 'import-scan-banner hidden';
    scanBanner.innerHTML = '';
    return;
  }

  const checkSvg = '<svg viewBox="0 0 14 14" aria-hidden="true"><path d="m2.5 7.2 2.8 2.8 6.2-6.4"/></svg>';
  const chevronSvg = '<svg viewBox="0 0 14 14" aria-hidden="true"><path d="m3.5 5.25 3.5 3.5 3.5-3.5"/></svg>';

  if (pane.activeScanMode) {
    scanBanner.className = 'import-scan-banner is-scanning';
    const scanningTitle = pane.activeScanMode === 'workspace_folder'
      ? t('正在深度扫描项目目录…', 'Deep-scanning workspace folder…')
      : t('正在巡检本机凭据位置…', 'Scanning local credential locations…');
    scanBanner.innerHTML = `
      <div class="import-scan-head">
        <div class="import-scan-title-group">
          <span class="import-scan-dot is-pulse" aria-hidden="true"></span>
          <span class="import-scan-title">${esc(scanningTitle)}</span>
        </div>
      </div>
    `;
    return;
  }

  if (pane.scanReport) {
    const totalHits = paneItemCount(pane);
    const isWorkspace = pane.scanReport.mode === 'workspace_folder';
    const baseTitle = isWorkspace
      ? (pane.scanReport.targetLabel
        ? `${t('目录深扫', 'Workspace scan')} · ${pane.scanReport.targetLabel}`
        : t('项目目录深扫完成', 'Workspace scan complete'))
      : t('本机巡检完成', 'Local scan complete');
    const filesCount = Number(pane.scanReport.totalInspectedFiles || 0);
    const ms = Math.max(1, Number(pane.scanReport.durationMs || 1));
    const metaText = `${filesCount} ${t('文件', 'files')} · ${ms}ms`;
    const cats = Array.isArray(pane.scanReport.categories) ? pane.scanReport.categories : [];
    const expanded = totalHits === 0 || pane.scanDetailsExpanded;

    const catHtml = cats
      .map((cat) => {
        const hit = Number(cat.extractedCount || 0);
        const inspected = Number(cat.inspectedFiles || 0);
        const probed = Number(cat.probedLocations || 0);
        const stat = hit > 0 ? `+${hit}` : '0';
        const catLabel = t(cat.labelZh || cat.label, cat.label || cat.labelZh);
        const tip = hit > 0
          ? t(
              `${catLabel} · 已检 ${inspected} 个文件 · 命中 ${hit} 项`,
              `${catLabel} · ${inspected} files inspected · ${hit} found`
            )
          : t(
              `${catLabel} · 已检 ${inspected} 个文件（探测 ${probed} 处）· 无命中`,
              `${catLabel} · ${inspected} files (${probed} locations) · 0 found`
            );
        return `
          <div class="import-scan-cat ${hit > 0 ? 'has-hit' : ''}" title="${esc(tip)}">
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
                '常用路径未发现未入库明文凭据；若 .env 或密钥在其他代码盘，请点上方「扫项目目录…」。',
                'No plaintext secrets in default paths — click Scan Folder… above to inspect code workspaces.'
              )
        )}</div>`
      : '';

    scanBanner.className = totalHits > 0
      ? `import-scan-banner is-compact-summary${expanded ? ' is-expanded' : ''}`
      : 'import-scan-banner';

    scanBanner.innerHTML = `
      <div class="import-scan-head">
        <div class="import-scan-title-group">
          <span class="import-scan-dot ${totalHits > 0 ? 'is-hit' : ''}" aria-hidden="true"></span>
          <span class="import-scan-title" title="${esc(baseTitle)}">${esc(baseTitle)}</span>
          <span class="import-scan-meta">${esc(metaText)}</span>
        </div>
        ${totalHits > 0 && cats.length ? `
          <button type="button" class="import-scan-detail-btn" data-toggle-scan-details="true" aria-expanded="${expanded ? 'true' : 'false'}">
            <span>${esc(expanded ? t('收起', 'Hide') : t('详情', 'Details'))}</span>
            ${chevronSvg}
          </button>
        ` : ''}
      </div>
      <div class="import-scan-details${expanded ? '' : ' hidden'}">
        ${isWorkspace && pane.scanReport.targetLabel ? `<div class="import-scan-path" title="${esc(pane.scanReport.targetLabel)}">${esc(pane.scanReport.targetLabel)}</div>` : ''}
        ${cats.length ? `<div class="import-scan-grid">${catHtml}</div>` : ''}
        ${emptyNote}
      </div>
    `;
    return;
  }

  if (!hasAnyContent && !pane.lastCommit) {
    scanBanner.className = 'import-scan-banner';
    const scopes = [
      [t('SSH 与私钥', 'SSH & Keys'), '~/.ssh/config · id_* · .pem'],
      [t('Git 与云凭据', 'Git · Cloud · CLI'), 'AWS · Azure · GCP · npm · gh'],
      [t('AI 与 MCP 配置', 'AI & MCP Configs'), 'Claude · Cursor · Codex · Gemini'],
      [t('常用目录', 'Common folders'), t('桌面 · 文档 · 下载中的配置与备份', 'Desktop · Docs · Downloads')],
    ];
    scanBanner.innerHTML = `
      <div class="import-scan-head">
        <div class="import-scan-title-group">
          <span class="import-scan-dot is-hit" aria-hidden="true"></span>
          <span class="import-scan-title">${esc(t('本机只读巡检 · 零联网', 'Read-only local scan · Offline'))}</span>
        </div>
      </div>
      <div class="import-scan-scope-grid">
        ${scopes.map(([label, desc]) => `
          <div class="import-scan-scope-tile">
            <strong>${esc(label)}</strong>
            <span>${esc(desc)}</span>
          </div>
        `).join('')}
      </div>
      <div class="import-scan-empty-note">${esc(t('点击上方「本机扫描」快速巡检，或点「扫项目目录…」深扫代码盘中的 .env 与密钥。', 'Use Scan PC above for common paths, or Scan Folder… to inspect code workspaces.'))}</div>
    `;
    return;
  }

  scanBanner.className = 'import-scan-banner hidden';
  scanBanner.innerHTML = '';
}

function render() {
  const page = $('#page-import');
  if (!page) return;

  const pane = currentPane();
  const hasResults = pane.candidates.length > 0 || pane.ignored.length > 0 || pane.discoveredMvaults.length > 0;
  const hasAnyContent = hasResults;

  // Tier 1: Primary Mode Switcher (two independent pages)
  const modeSwitch = $('#import-mode-switch');
  if (modeSwitch) {
    modeSwitch.dataset.mode = activeMode;
  }
  const addTab = $('#import-mode-add');
  const scanTab = $('#import-mode-scan');
  if (addTab) {
    addTab.classList.toggle('active', activeMode === 'add');
    addTab.setAttribute('aria-selected', String(activeMode === 'add'));
  }
  if (scanTab) {
    scanTab.classList.toggle('active', activeMode === 'scan');
    scanTab.setAttribute('aria-selected', String(activeMode === 'scan'));
  }

  // Per-tab staged item counters so users can see background tab counts at a glance
  const addCount = paneItemCount(panes.add);
  const scanCount = paneItemCount(panes.scan);
  const addCountEl = $('#import-mode-add-count');
  const scanCountEl = $('#import-mode-scan-count');
  if (addCountEl) {
    addCountEl.textContent = String(addCount);
    addCountEl.classList.toggle('hidden', addCount === 0);
  }
  if (scanCountEl) {
    scanCountEl.textContent = String(scanCount);
    scanCountEl.classList.toggle('hidden', scanCount === 0);
  }

  // Tier 2: Contextual Sub-Action Bars
  const addSubbar = $('#import-subbar-add');
  const scanSubbar = $('#import-subbar-scan');
  if (addSubbar) addSubbar.classList.toggle('hidden', activeMode !== 'add');
  if (scanSubbar) scanSubbar.classList.toggle('hidden', activeMode !== 'scan');

  const setBtnLabel = (id, zh, en) => {
    const el = $(id);
    if (el) el.textContent = t(zh, en);
  };
  setBtnLabel('#import-mode-add-label', '添加', 'Add');
  setBtnLabel('#import-mode-scan-label', '搜索', 'Scan');
  setBtnLabel('#add-connection-label', '新建', 'New');
  setBtnLabel('#import-paste-btn-label', '粘贴', 'Paste');
  setBtnLabel('#import-file-btn-label', '文件', 'Files');
  setBtnLabel('#import-scan-btn-label', '本机扫描', 'Scan PC');
  setBtnLabel('#import-workspace-btn-label', '扫项目目录…', 'Scan Folder…');
  setBtnLabel('#import-drop-badge', '拖入文件或文件夹', 'Drop files or folders');

  const scanBtn = $('#import-chip-scan');
  if (scanBtn) {
    scanBtn.disabled = Boolean(panes.scan.activeScanMode);
    scanBtn.title = t(
      '只读巡检本机 SSH 与私钥、Git/云凭据、AI/MCP 配置及桌面、文档、下载目录',
      'Read-only scan of SSH & keys, Git/cloud CLI, AI/MCP configs, and Desktop / Documents / Downloads'
    );
  }
  const workspaceBtn = $('#import-workspace-scan-btn');
  if (workspaceBtn) {
    workspaceBtn.disabled = Boolean(panes.scan.activeScanMode);
    workspaceBtn.title = t(
      '选择任意代码工作区目录（如 Github / Projects）深度扫描 .env 与密钥',
      'Pick a code workspace folder to deep-scan for .env & keys'
    );
  }

  const toggleBtn = $('#import-toggle-input-btn');
  if (toggleBtn) {
    const showSourceToggle = activeMode === 'add' && hasAnyContent;
    toggleBtn.classList.toggle('hidden', !showSourceToggle);
    toggleBtn.setAttribute('aria-expanded', String(panes.add.inputExpanded));
    setBtnLabel('#import-toggle-input-label', panes.add.inputExpanded ? '收起' : '原文', panes.add.inputExpanded ? 'Hide' : 'Source');
  }

  const clearBtn = $('#import-clear-btn');
  if (clearBtn) {
    const canClear = Boolean(pane.rawText || hasAnyContent || pane.lastCommit || pane.scanReport);
    clearBtn.classList.toggle('hidden', !canClear);
    clearBtn.textContent = t('清空', 'Clear');
  }

  // Dropzone belongs strictly to Add tab
  const privacyText = $('#import-privacy-text');
  if (privacyText) {
    privacyText.textContent = t('离线规则提取 · 零联网', 'Offline rule extractor · Zero network');
  }
  const ta = $('#import-raw-input');
  if (ta) {
    ta.placeholder = t(
      '直接粘贴任意文本或配置，也可拖入文件 / 文件夹（.env · SSH/私钥 · Excel/Word/ZIP · CSV/JSON/YAML/TOML · KeePass · .mvault · 2FA 截图）…',
      'Paste any text or config, or drop files / folders (.env, SSH/keys, Excel/Word/ZIP, CSV/JSON/YAML/TOML, KeePass, .mvault, 2FA QR)…'
    );
  }

  const dropzone = $('#import-dropzone');
  if (dropzone) {
    const isAddTab = activeMode === 'add';
    const isCompact = isAddTab && hasAnyContent && !pane.inputExpanded;
    dropzone.classList.toggle('is-compact', isCompact);
    dropzone.classList.toggle('hidden', !isAddTab);
    dropzone.classList.toggle('is-inline-editor', isAddTab && hasAnyContent && pane.inputExpanded);
  }

  renderScanBanner(pane, hasAnyContent);

  const supportedStrip = $('#import-supported-strip');
  if (supportedStrip) {
    const showQuickAdd = activeMode === 'add' && !hasAnyContent && !pane.lastCommit && !pane.isExtracting;
    supportedStrip.classList.toggle('hidden', !showQuickAdd);
    if (showQuickAdd) {
      const quickTemplates = [
        [
          'login',
          t('账号密码', 'Login'),
          t('网站 · 账号 · 密码', 'Site · user · pass'),
          '<svg viewBox="0 0 18 18" aria-hidden="true"><circle cx="9" cy="6.25" r="2.75"/><path d="M4 14.5c.8-2.4 2.7-3.5 5-3.5s4.2 1.1 5 3.5"/></svg>',
        ],
        [
          'api',
          t('API 密钥', 'API key'),
          t('接口地址 · Token', 'Endpoint · token'),
          '<svg viewBox="0 0 18 18" aria-hidden="true"><circle cx="6.25" cy="9" r="2.75"/><path d="M9 9h6.25M12.75 9v2.25M15 9v1.75"/></svg>',
        ],
        [
          'ssh',
          t('SSH 服务器', 'SSH server'),
          t('主机 · 端口 · 私钥', 'Host · port · key'),
          '<svg viewBox="0 0 18 18" aria-hidden="true"><rect x="2.5" y="3.5" width="13" height="11" rx="2"/><path d="m5.5 7.25 2.25 1.75-2.25 1.75M9.5 11h3"/></svg>',
        ],
        [
          'secureNote',
          t('安全笔记', 'Secure note'),
          t('加密备忘 · 恢复码', 'Encrypted notes'),
          '<svg viewBox="0 0 18 18" aria-hidden="true"><path d="M4.5 3h6.5l3 3v9h-9.5Z"/><path d="M11 3v3h3M6.75 9h4.5M6.75 11.75h3.25"/></svg>',
        ],
        [
          'card',
          t('银行卡', 'Card'),
          t('卡号 · 有效期 · 安全码', 'Number · exp · CVV'),
          '<svg viewBox="0 0 18 18" aria-hidden="true"><rect x="2.25" y="4" width="13.5" height="10" rx="1.75"/><path d="M2.25 7.5h13.5M5.25 11h3"/></svg>',
        ],
        [
          'identity',
          t('身份资料', 'Identity'),
          t('联系方式 · 地址', 'Contact · address'),
          '<svg viewBox="0 0 18 18" aria-hidden="true"><rect x="2.5" y="3.5" width="13" height="11" rx="1.75"/><circle cx="6.5" cy="8" r="1.5"/><path d="M4.5 12c.4-1.2 1.2-1.75 2-1.75s1.6.55 2 1.75M10.5 7.5h3M10.5 10.5h2.25"/></svg>',
        ],
      ];
      supportedStrip.innerHTML = quickTemplates
        .map(([tpl, title, desc, icon]) => `
          <button type="button" class="import-template-card" data-import-quick-template="${esc(tpl)}">
            <span class="import-template-icon" aria-hidden="true">${icon}</span>
            <span class="import-template-copy">
              <strong>${esc(title)}</strong>
              <span>${esc(desc)}</span>
            </span>
          </button>
        `)
        .join('');
    }
  }

  // Done banner (scoped to active tab)
  const doneEl = $('#import-done-banner');
  if (doneEl) {
    if (pane.lastCommit) {
      doneEl.classList.remove('hidden');
      doneEl.innerHTML = `
        <div class="import-done-top">
          <strong>${esc(
            t(
              `已成功入库 ${pane.lastCommit.added + pane.lastCommit.updated} 项（新增 ${pane.lastCommit.added} · 更新 ${pane.lastCommit.updated}）`,
              `Imported ${pane.lastCommit.added + pane.lastCommit.updated} item(s) (${pane.lastCommit.added} added · ${pane.lastCommit.updated} updated)`
            )
          )}</strong>
        </div>
        <div class="import-done-actions">
          <button type="button" class="import-mini-btn" id="import-done-view">${esc(t('查看项目', 'View items'))}</button>
          ${pane.lastCommit.createdIds.length ? `<button type="button" class="import-mini-btn quiet" id="import-done-undo">${esc(t('撤销新增', 'Undo added'))}</button>` : ''}
          ${pane.lastCommit.sealedEnvTemplate ? `<button type="button" class="import-mini-btn" id="import-done-sealed">${esc(t('复制 .env 脱敏模板', 'Copy sealed .env'))}</button>` : ''}
          <button type="button" class="import-mini-btn quiet" id="import-done-more">${esc(t('继续导入', 'Import more'))}</button>
        </div>
        ${renderPlaintextSources(pane.lastCommit.plaintextSources)}
      `;
    } else {
      doneEl.classList.add('hidden');
      doneEl.innerHTML = '';
    }
  }

  // Warnings (scoped to active tab)
  const warnEl = $('#import-warning-strip');
  if (warnEl) {
    if (pane.warnings.length) {
      warnEl.classList.remove('hidden');
      warnEl.textContent = pane.warnings.join(' · ');
    } else {
      warnEl.classList.add('hidden');
      warnEl.textContent = '';
    }
  }

  // Unified Results area (scoped to active tab)
  const resultsWrap = $('#import-results-wrap');
  if (resultsWrap) {
    resultsWrap.classList.toggle('hidden', !hasResults && !pane.isExtracting);
  }

  const toolbar = $('#import-staging-toolbar');
  const listEl = $('#import-candidate-list');
  const ignoredEl = $('#import-ignored-drawer');
  const commitBar = $('#import-commit-bar');

  if (pane.isExtracting) {
    if (toolbar) toolbar.innerHTML = '';
    if (listEl) {
      listEl.innerHTML = `<div class="import-empty-result">${esc(t('正在本地规则提取…', 'Extracting locally…'))}</div>`;
    }
    if (ignoredEl) ignoredEl.classList.add('hidden');
    if (commitBar) commitBar.classList.add('hidden');
    return;
  }

  if (hasResults) {
    const visibleCands = filteredCandidates(pane);
    const visibleMvaults = filteredMvaults(pane);
    const selectedCount = pane.candidates.filter((c) => c.selected).length;
    const allVisibleSelected = visibleCands.length > 0 && visibleCands.every((c) => c.selected);

    if (toolbar) {
      toolbar.innerHTML = `
        <div class="import-kind-pills">${renderKindPills(pane)}</div>
        ${visibleCands.length > 0 ? `
          <button type="button" class="import-select-all-btn" id="import-toggle-all">
            ${esc(allVisibleSelected ? t('取消全选', 'Unselect all') : t('全选当前', 'Select all'))}
          </button>
        ` : ''}
      `;
    }

    if (listEl) {
      const cardsHtml = [
        ...visibleCands.map((c) => renderCandidateCard(pane, c)),
        ...visibleMvaults.map(renderMvaultCard),
      ].join('');
      if (cardsHtml) {
        listEl.innerHTML = cardsHtml;
      } else if (pane.candidates.length || pane.discoveredMvaults.length) {
        listEl.innerHTML = `<div class="import-empty-result">${esc(t('当前筛选条件下无匹配项', 'No candidates match the current filter'))}</div>`;
      } else {
        listEl.innerHTML = `<div class="import-empty-result">${esc(t('未提取到高置信凭据，可展开下方已过滤项手动恢复', 'No high-confidence secrets extracted — expand filtered items below to promote any entry'))}</div>`;
      }
    }

    if (ignoredEl) {
      if (pane.ignored.length) {
        ignoredEl.classList.remove('hidden');
        const summary = $('#import-ignored-summary');
        const rows = $('#import-ignored-list');
        if (summary) {
          summary.textContent = t(
            `已自动过滤 ${pane.ignored.length} 项非敏感或占位内容（点击展开可手动恢复）`,
            `Filtered ${pane.ignored.length} non-secret / placeholder item(s) (click to inspect or restore)`
          );
        }
        if (rows) {
          rows.innerHTML = pane.ignored
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
      commitBar.classList.toggle('hidden', pane.candidates.length === 0);
      const folderInput = $('#import-batch-folder');
      if (folderInput) {
        folderInput.placeholder = t('统一归入文件夹（可选）', 'Assign folder (optional)');
        if (folderInput.value !== pane.batchFolder) {
          folderInput.value = pane.batchFolder;
        }
      }
      const commitBtn = $('#import-commit-btn');
      if (commitBtn) {
        commitBtn.disabled = selectedCount === 0 || pane.isCommitting;
        commitBtn.textContent = pane.isCommitting
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
    const pane = panes.add;
    pane.rawText = ta.value;
    pane.sourceFilename = null;
    pane.clipboardSource = '';
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      void runExtract(pane.rawText, pane.sourceFilename);
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

  const folderInput = $('#import-batch-folder');
  folderInput?.addEventListener('input', () => {
    currentPane().batchFolder = folderInput.value;
  });

  const well = $('#import-well');
  const dropzone = $('#import-dropzone');
  well?.addEventListener('dragover', (event) => {
    event.preventDefault();
    well.classList.add('is-dragover');
    dropzone?.classList.add('is-dragover');
  });
  well?.addEventListener('dragleave', (event) => {
    if (!well.contains(event.relatedTarget)) {
      well.classList.remove('is-dragover');
      dropzone?.classList.remove('is-dragover');
    }
  });
  well?.addEventListener('drop', (event) => {
    event.preventDefault();
    event.stopPropagation();
    well.classList.remove('is-dragover');
    dropzone?.classList.remove('is-dragover');
    document.getElementById('global-mvault-drop-overlay')?.classList.add('hidden');
    if (event.dataTransfer?.files?.length) {
      void handleFiles(event.dataTransfer.files);
    }
  });

  $('#import-mode-switch')?.addEventListener('keydown', (event) => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const next = event.key === 'ArrowRight' || event.key === 'End' ? 'scan' : 'add';
    setMode(next, { playSound: true });
    $(next === 'scan' ? '#import-mode-scan' : '#import-mode-add')?.focus();
  });

  $('#import-paste-btn')?.addEventListener('click', () => void handlePasteClipboard());
  $('#import-file-btn')?.addEventListener('click', () => void handlePickFiles());
  $('#import-clear-btn')?.addEventListener('click', () => resetPane(currentPane()));
  $('#import-toggle-input-btn')?.addEventListener('click', () => {
    panes.add.inputExpanded = !panes.add.inputExpanded;
    render();
    if (panes.add.inputExpanded) {
      $('#import-raw-input')?.focus();
    }
  });

  $('#import-chip-scan')?.addEventListener('click', () => void handleScanLocal());
  $('#import-commit-btn')?.addEventListener('click', () => void handleCommit());

  page.addEventListener('click', (event) => {
    const quickTpl = event.target.closest('[data-import-quick-template]');
    if (quickTpl) {
      const tpl = quickTpl.dataset.importQuickTemplate;
      if (tpl && host?.openTemplateInEditor) {
        void host.openTemplateInEditor(tpl);
      }
      return;
    }
    const modeBtn = event.target.closest('[data-import-mode]');
    if (modeBtn) {
      setMode(modeBtn.dataset.importMode, { playSound: true });
      return;
    }
    const pane = currentPane();
    if (event.target.closest('[data-toggle-scan-details]')) {
      pane.scanDetailsExpanded = !pane.scanDetailsExpanded;
      render();
      return;
    }
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
      pane.activeKindFilter = kindBtn.dataset.importKind;
      render();
      return;
    }
    if (event.target.closest('#import-toggle-all')) {
      const visible = filteredCandidates(pane);
      const allSelected = visible.length > 0 && visible.every((c) => c.selected);
      for (const c of visible) c.selected = !allSelected;
      render();
      notifyMetrics();
      return;
    }
    const toggleUpdate = event.target.closest('[data-import-toggle-update]');
    if (toggleUpdate) {
      const cand = pane.candidates.find((c) => c.id === toggleUpdate.dataset.importToggleUpdate);
      if (cand) {
        cand.updateExisting = !cand.updateExisting;
        render();
      }
      return;
    }
    const editBtn = event.target.closest('[data-import-edit-card]');
    if (editBtn) {
      const id = editBtn.dataset.importEditCard;
      const cand = pane.candidates.find((c) => c.id === id);
      if (cand && host?.openCandidateInEditor) {
        void host.openCandidateInEditor(cand, () => {
          pane.candidates = pane.candidates.filter((c) => c.id !== id);
          render();
          notifyMetrics();
        });
      }
      return;
    }
    const revealBtn = event.target.closest('[data-import-reveal]');
    if (revealBtn) {
      const id = revealBtn.dataset.importReveal;
      if (pane.revealedIds.has(id)) pane.revealedIds.delete(id);
      else pane.revealedIds.add(id);
      render();
      return;
    }
    const expandBtn = event.target.closest('[data-import-expand]');
    if (expandBtn) {
      const id = expandBtn.dataset.importExpand;
      if (pane.expandedIds.has(id)) pane.expandedIds.delete(id);
      else pane.expandedIds.add(id);
      render();
      return;
    }
    const removeBtn = event.target.closest('[data-import-remove]');
    if (removeBtn) {
      const id = removeBtn.dataset.importRemove;
      pane.candidates = pane.candidates.filter((c) => c.id !== id);
      render();
      notifyMetrics();
      return;
    }
    const promoteBtn = event.target.closest('[data-import-promote]');
    if (promoteBtn) {
      const idx = Number(promoteBtn.dataset.importPromote);
      const item = pane.ignored[idx];
      if (item?.candidate) {
        item.candidate.selected = true;
        pane.candidates.push(item.candidate);
        pane.ignored.splice(idx, 1);
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
      if (pane.lastCommit?.sealedEnvTemplate) {
        // Lines the backend could not seal are replaced by comments starting with this
        // marker; their values exist only in the original file.
        const hasRemovedLines = /^# OpenKeylet removed/m.test(pane.lastCommit.sealedEnvTemplate);
        void host
          .invoke('copy_owner_value', { value: pane.lastCommit.sealedEnvTemplate, sensitive: false })
          .then(() =>
            host.toast(
              hasRemovedLines
                ? t(
                    '已复制脱敏模板；无法脱敏的行已替换为注释，其值只保留在原文件中',
                    'Copied sealed .env; lines that could not be sealed became comments and their values remain only in the original file'
                  )
                : t('已复制脱敏 .env 模板（含 {{openkeylet:KEY}} 占位符）', 'Copied sealed .env template with {{openkeylet:KEY}} placeholders')
            )
          )
          .catch((e) => host.toast(host.cleanError(e), 'error'));
      }
      return;
    }
    if (event.target.closest('#import-done-copy-paths')) {
      const paths = (pane.lastCommit?.plaintextSources || []).map((s) => s.displayPath).filter(Boolean);
      if (paths.length) {
        void host
          .invoke('copy_owner_value', { value: `${paths.join('\n')}\n`, sensitive: false })
          .then(() => host.toast(t('已复制文件路径', 'Copied file paths')))
          .catch((e) => host.toast(host.cleanError(e), 'error'));
      }
      return;
    }
    if (event.target.closest('#import-done-more')) {
      pane.lastCommit = null;
      render();
      if (activeMode === 'add') {
        $('#import-raw-input')?.focus();
      }
    }
  });

  page.addEventListener('change', (event) => {
    const pane = currentPane();
    const chk = event.target.closest('[data-import-check]');
    if (chk) {
      const cand = pane.candidates.find((c) => c.id === chk.dataset.importCheck);
      if (cand) {
        cand.selected = Boolean(chk.checked);
        render();
        notifyMetrics();
      }
      return;
    }
    const typeSel = event.target.closest('[data-import-type]');
    if (typeSel) {
      const cand = pane.candidates.find((c) => c.id === typeSel.dataset.importType);
      if (cand && cand.input) {
        cand.input.itemType = typeSel.value || 'custom';
      }
    }
  });

  page.addEventListener('input', (event) => {
    const pane = currentPane();
    const rename = event.target.closest('[data-import-rename]');
    if (rename) {
      const cand = pane.candidates.find((c) => c.id === rename.dataset.importRename);
      if (cand && cand.input) cand.input.name = rename.value;
      return;
    }
    const folder = event.target.closest('[data-import-folder]');
    if (folder) {
      const cand = pane.candidates.find((c) => c.id === folder.dataset.importFolder);
      if (cand && cand.input) cand.input.folder = folder.value;
    }
  });
}

export const importHub = {
  init(bridge) {
    host = bridge;
    bindEvents();
    render();
  },
  render,
  getStats,
  setMode,
  handleFiles,
  handleNativeDropPayload,
  notifyExternalImportDone(summary) {
    const added = Number(summary?.added || 0);
    const merged = Number(summary?.merged || 0);
    if (added <= 0 && merged <= 0) return;
    currentPane().lastCommit = {
      added,
      updated: 0,
      createdIds: [],
      sealedEnvTemplate: null,
      plaintextSources: [],
    };
    render();
    notifyMetrics();
  },
  handlePasteText(text, { fromClipboard = false } = {}) {
    if (activeMode !== 'add') setMode('add');
    const pane = panes.add;
    pane.rawText = String(text || '');
    pane.sourceFilename = null;
    pane.clipboardSource = fromClipboard ? pane.rawText : '';
    const ta = $('#import-raw-input');
    if (ta) ta.value = pane.rawText;
    void runExtract(pane.rawText, null);
  },
  focusInput() {
    if (activeMode === 'add' && !panes.add.candidates.length && !panes.add.ignored.length) {
      $('#import-raw-input')?.focus({ preventScroll: true });
    }
  },
  resetFilter() {
    const pane = currentPane();
    pane.activeKindFilter = 'all';
    if (pane.mode === 'add' && (pane.candidates.length > 0 || pane.discoveredMvaults.length > 0)) {
      pane.inputExpanded = false;
    }
    render();
  },
  clearPlaintext() {
    resetAllPanes();
  },
};

window.OpenKeyletImportHub = importHub;
