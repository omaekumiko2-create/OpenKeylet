// Vault access is handled by the authenticated extension service worker.
const $ = s => document.querySelector(s);
const { t, localizeMessage, icon } = OpenKeyletUI;

let currentOrigin = "", entries = [], saving = false, reading = false, loading = false, editingVersion = "";
let refreshError = false;
let personalEntries = [];
let bridgeConnected = false;
let vaultLocked = true;
let pageAvailableState = false;
let activeTab = "site";
let settingsOverlayWhenUnavailable = false;
let toastTimer = null;

const captureParams = new URLSearchParams(location.search);
let captureContext = captureParams.get("capture") || "";
let quickContext = captureParams.get("quick") || "";
document.body.classList.toggle("capture-page", Boolean(captureContext));
document.body.classList.toggle("quick-page", Boolean(quickContext));
const captureTabId = captureParams.has("tab") ? Number(captureParams.get("tab")) : undefined;

let pendingCapture = null, savingCapture = null, saveEntries = [], detectedForms = [], readSource = null, openedCapture = "";
let quickParsed = null, quickParseTimer = null, openedQuick = "", quickOrigin = "";
let genDebounceTimer = null;

function showError(e, tone = "") {
  refreshError = false;
  clearTimeout(toastTimer);
  const el = $("#error");
  const isErr = tone === "error" || (e instanceof Error && !tone);
  const resolvedTone = tone || (isErr ? "error" : "info");
  const text = localizeMessage(e);
  el.dataset.tone = resolvedTone;
  el.textContent = text;
  if (text && resolvedTone !== "error") {
    toastTimer = setTimeout(() => {
      if (el.textContent === text) el.textContent = "";
    }, 3200);
  }
}

async function call(action, fields = {}) {
  const reply = await chrome.runtime.sendMessage({
    type: "vault-ui",
    action,
    origin: currentOrigin,
    captureId: captureContext || undefined,
    quickId: quickContext || undefined,
    captureTabId,
    ...fields,
  });
  if (!reply?.ok) throw new Error(reply?.error || "OpenKeylet unavailable");
  return reply.result;
}

function hasOpenSheet() {
  return !$("#save-form").hidden
    || !$("#quick-store-form").hidden
    || !$("#vault-editor").hidden
    || !$("#vault-history").hidden;
}

function isStandaloneWindow() {
  return document.body.classList.contains("capture-page")
    || document.body.classList.contains("quick-page");
}

function syncChromeVisibility() {
  const sheetOpen = hasOpenSheet();
  const standalone = isStandaloneWindow();
  const unlockedReady = bridgeConnected && !vaultLocked;
  const showingSettings = unlockedReady
    ? (!sheetOpen && activeTab === "settings")
    : settingsOverlayWhenUnavailable;

  // Nav bar: shown when unlocked & connected & not in sheet or standalone window
  $("#main-nav").hidden = !unlockedReady || sheetOpen || standalone;
  $("#main-nav").dataset.active = activeTab;
  for (const btn of document.querySelectorAll("#main-nav .nav-item")) {
    const isAct = btn.dataset.tab === activeTab;
    btn.classList.toggle("active", isAct);
    if (isAct) btn.setAttribute("aria-current", "page");
    else btn.removeAttribute("aria-current");
  }

  // Offline & Lock panels
  const wasLockHidden = $("#unlock-form").hidden;
  $("#offline-panel").hidden = bridgeConnected || showingSettings;
  $("#unlock-form").hidden = !bridgeConnected || !vaultLocked || showingSettings;
  $("#vault-panel").hidden = !unlockedReady || showingSettings;
  if (wasLockHidden && !$("#unlock-form").hidden) {
    $("#pin")?.focus();
  }

  // Page hint visibility:
  // - When connected & locked on non-web page: show compact hint above unlock card
  // - When unlocked on Site tab & non-web page & no sheet open: show hint with quick buttons
  const showHintLocked = bridgeConnected && vaultLocked && !pageAvailableState && !showingSettings && !standalone;
  const showHintSite = unlockedReady && !sheetOpen && activeTab === "site" && !pageAvailableState && !standalone;
  $("#page-hint").hidden = !(showHintLocked || showHintSite);
  $("#page-hint-actions").hidden = vaultLocked;

  // Capture notice banner (hidden while in settings or save sheet)
  $("#capture-notice").hidden = !pendingCapture || showingSettings || !$("#save-form").hidden || !$("#capture-complete").hidden;

  // Tab views inside #vault-panel
  for (const view of document.querySelectorAll("#vault-panel > .tab-view")) {
    view.hidden = sheetOpen || view.dataset.tabView !== activeTab;
  }

  // Settings tab (lives outside #vault-panel so it works when locked or offline)
  $("#tab-settings").hidden = !showingSettings;
}

function setActiveTab(tab) {
  if (!["site", "vault", "generator", "settings"].includes(tab)) return;
  if (!bridgeConnected || vaultLocked) {
    settingsOverlayWhenUnavailable = tab === "settings";
    syncChromeVisibility();
    return;
  }
  activeTab = tab;
  settingsOverlayWhenUnavailable = false;
  syncChromeVisibility();
  if (tab === "generator" && !$("#generator-output").value) {
    void triggerGeneratePassword();
  }
}

function updateBridgeStatusUI(statusKey, lampClass, stripClass) {
  const label = t(statusKey);
  $("#status").textContent = label;
  $("#lamp").className = `lamp ${lampClass}`.trim();
  $("#settings-status").textContent = label;
  $("#settings-status-strip").className = `status-strip ${stripClass}`.trim();
}

function updateStrengthMeter() {
  const pw = $("#generator-output").value || "";
  const len = pw.length;
  let pool = 0;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pw)) pool += 32;
  const entropy = len > 0 && pool > 0 ? len * Math.log2(pool) : 0;
  const fill = $("#gen-strength-fill");
  const label = $("#gen-strength-label");
  if (!len) {
    fill.style.width = "0%";
    fill.className = "";
    label.textContent = "";
    return;
  }
  const pct = Math.min(100, Math.max(15, Math.round((entropy / 120) * 100)));
  fill.style.width = `${pct}%`;
  if (entropy >= 90) {
    fill.className = "";
    label.textContent = t("gen.strengthMax");
  } else if (entropy >= 60) {
    fill.className = "warn";
    label.textContent = t("gen.strengthGood");
  } else {
    fill.className = "danger";
    label.textContent = t("gen.strengthWeak");
  }
}

function renderSiteEntries() {
  const container = $("#entries");
  container.replaceChildren();

  const countPill = $("#website-count");
  if (entries.length) {
    countPill.textContent = t(entries.length === 1 ? "site.loginCount" : "site.loginCountPlural", { count: entries.length });
    countPill.hidden = false;
  } else {
    countPill.hidden = true;
  }

  if (!entries.length) {
    const empty = document.createElement("div");
    empty.className = "entries-empty";
    empty.textContent = t("site.noLogins");
    container.append(empty);
    return;
  }

  for (const item of entries) {
    const row = document.createElement("div");
    row.className = "login-entry-row";

    const button = document.createElement("button");
    button.type = "button";
    button.className = "login-entry";

    const avatar = document.createElement("span");
    avatar.className = "entry-avatar";
    avatar.append(icon("login"));

    const copy = document.createElement("div");
    copy.className = "entry-copy";
    const title = document.createElement("strong");
    title.textContent = item.name;
    const sub = document.createElement("small");
    sub.textContent = item.username || t("site.fillHint");
    copy.append(title, sub);

    const cue = document.createElement("span");
    cue.className = "entry-fill-cue";
    cue.append(icon("fill"));

    button.append(avatar, copy, cue);
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await call("fill", { id: item.id });
        showError(t("site.filled"), "success");
      } catch (e) {
        showError(e);
      } finally {
        button.disabled = false;
      }
    });
    row.append(button);

    if (item.hasTotp) {
      const totpBtn = document.createElement("button");
      totpBtn.type = "button";
      totpBtn.className = "button secondary totp-copy-button";
      totpBtn.textContent = "2FA";
      totpBtn.title = t("site.totpTitle");
      totpBtn.addEventListener("click", async () => {
        totpBtn.disabled = true;
        try {
          const res = await call("totp", { id: item.id });
          await navigator.clipboard.writeText(res.code);
          showError(t("site.totpCopied", { seconds: res.remainingSeconds }), "success");
        } catch (e) {
          showError(e);
        } finally {
          totpBtn.disabled = false;
        }
      });
      row.append(totpBtn);
    }
    container.append(row);
  }
}

function renderSiteAutofill() {
  const section = $("#site-autofill");
  const list = $("#site-autofill-list");
  list.replaceChildren();

  const fillable = personalEntries
    .filter(item => item.itemType === "card" || item.itemType === "identity")
    .sort((a, b) => Number(b.favorite) - Number(a.favorite));

  if (!pageAvailableState || !fillable.length) {
    section.hidden = true;
    return;
  }

  section.hidden = false;
  for (const item of fillable.slice(0, 4)) {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "quick-fill-chip";

    const ico = document.createElement("span");
    ico.className = "chip-ico";
    ico.append(icon(item.itemType));

    const txt = document.createElement("div");
    txt.className = "chip-text";
    const strong = document.createElement("strong");
    strong.textContent = item.name;
    const small = document.createElement("small");
    small.textContent = [t(`type.${item.itemType}`), item.subtitle].filter(Boolean).join(" · ");
    txt.append(strong, small);

    const actionTag = document.createElement("span");
    actionTag.className = "chip-action";
    actionTag.textContent = t("vault.fill");

    chip.append(ico, txt, actionTag);
    chip.addEventListener("click", async () => {
      chip.disabled = true;
      try {
        const res = await call("personal-fill", { id: item.id });
        showError(t("site.fieldsFilled", { count: res.filled }), "success");
      } catch (e) {
        showError(e);
      } finally {
        chip.disabled = false;
      }
    });
    list.append(chip);
  }
}

async function refresh() {
  if (loading || saving || reading) return;
  loading = true;
  try {
    const stored = await chrome.storage.local.get(["bridgeHost", "bridgePort", "bridgeTls", "captureEnabled", "desktopAppVersion"]);
    const extVersion = chrome.runtime.getManifest?.().version || "";
    const appVersion = stored.desktopAppVersion || "";
    const verLabel = $("#ext-version-label");
    if (verLabel && extVersion) {
      verLabel.textContent = `OpenKeylet v${extVersion} · ${t("settings.footerVault")}`;
    }

    const mismatchEl = $("#version-mismatch");
    if (mismatchEl) {
      const outdated = Boolean(appVersion && extVersion && appVersion !== extVersion);
      mismatchEl.hidden = !outdated;
      if (outdated) {
        $("#version-mismatch-detail").textContent = t("update.detail", { app: appVersion, ext: extVersion });
      }
    }

    const bridgeHost = (stored.bridgeHost || "127.0.0.1").trim() || "127.0.0.1";
    const bridgePort = stored.bridgePort || 39272;
    const bridgeTls = stored.bridgeTls === true;
    const isRemote = !["127.0.0.1", "localhost", "::1"].includes(bridgeHost.toLowerCase());

    $("#capture-enabled").checked = stored.captureEnabled === true;
    if (document.activeElement !== $("#host")) $("#host").value = bridgeHost;
    if (document.activeElement !== $("#port")) $("#port").value = bridgePort;
    $("#bridge-tls").checked = bridgeTls;
    $("#lan-warning").hidden = !isRemote;

    const formattedHost = bridgeHost.includes(":") && !bridgeHost.startsWith("[") ? `[${bridgeHost}]` : bridgeHost;
    $("#detail").textContent = `${bridgeTls ? "wss://" : ""}${formattedHost}:${bridgePort}`;

    const state = await call("list");
    if (saving || reading) return;

    bridgeConnected = true;
    vaultLocked = Boolean(state.locked);
    pageAvailableState = Boolean(state.pageAvailable);

    if (state.captureExpired) { captureContext = ""; closeSave(); }
    if (state.quickExpired) { quickContext = ""; closeQuickStore(); }

    updateBridgeStatusUI("status.connected", "on", "online");

    if (state.locked) {
      closeSave();
      closeQuickStore();
      OpenKeyletVaultUI.close();
      $("#generator-output").value = "";
      updateStrengthMeter();
    } else if (hasOpenSheet() || OpenKeyletVaultUI.isEditing()) {
      syncChromeVisibility();
      return;
    }

    OpenKeyletVaultUI.apply(state.vault, state.personal, pageAvailableState);

    if (refreshError || currentOrigin !== state.origin) showError("");
    if (state.captureExpired) showError(t("capture.expired"));

    const entriesChanged = currentOrigin !== state.origin || JSON.stringify(entries) !== JSON.stringify(state.entries);
    const personalChanged = JSON.stringify(personalEntries) !== JSON.stringify(state.personal);
    currentOrigin = state.origin;
    entries = state.entries;
    personalEntries = state.personal || [];

    // Website bar
    $("#website").textContent = currentOrigin;
    $("#website-bar").hidden = !pageAvailableState;
    $("#website-icon").classList.toggle("secure", currentOrigin.startsWith("https://"));

    // Site actions visibility
    $("#entries").hidden = !pageAvailableState;
    $("#read-form").hidden = !pageAvailableState;
    $("#scan-page-qr").hidden = !pageAvailableState;
    $("#site-actions").hidden = !pageAvailableState;
    $("#save-generated-password").hidden = !pageAvailableState || !$("#generator-output").value;

    // Header lock button
    $("#lock").hidden = !state.pinConfigured || vaultLocked;

    // Capture notice
    pendingCapture = state.capture;
    $("#capture-source").textContent = pendingCapture ? t("capture.source", { origin: pendingCapture.origin }) : "";
    $("#capture-review").disabled = vaultLocked;

    syncChromeVisibility();

    if (entriesChanged) renderSiteEntries();
    if (entriesChanged || personalChanged) renderSiteAutofill();

    if (captureContext && pendingCapture && !vaultLocked && openedCapture !== pendingCapture.id) {
      openedCapture = pendingCapture.id;
      reviewCapture();
    }
    if (quickContext && !vaultLocked && openedQuick !== quickContext) {
      openedQuick = quickContext;
      openQuickFromCapture();
    }
  } catch (e) {
    bridgeConnected = false;
    vaultLocked = true;
    pageAvailableState = false;
    closeSave();
    closeQuickStore();
    OpenKeyletVaultUI.close();
    updateBridgeStatusUI("status.unavailable", "error", "error");
    currentOrigin = "";
    entries = [];
    personalEntries = [];
    pendingCapture = null;
    $("#entries").replaceChildren();
    $("#site-autofill-list").replaceChildren();
    $("#site-autofill").hidden = true;
    $("#lock").hidden = true;
    $("#generator-output").value = "";
    updateStrengthMeter();
    syncChromeVisibility();
    showError(localizeMessage(e), "error");
    refreshError = true;
  } finally {
    loading = false;
  }
}

// Header & Navigation controls
$("#theme-toggle").addEventListener("click", () => OpenKeyletUI.toggleTheme());

$("#status-pill").addEventListener("click", () => {
  if (hasOpenSheet()) return;
  if (!bridgeConnected || vaultLocked) {
    settingsOverlayWhenUnavailable = !settingsOverlayWhenUnavailable;
    syncChromeVisibility();
  } else {
    setActiveTab(activeTab === "settings" ? "site" : "settings");
  }
});

$("#offline-retry").addEventListener("click", async () => {
  settingsOverlayWhenUnavailable = false;
  showError("");
  await chrome.runtime.sendMessage({ type: "bridge-config-updated" }).catch(() => {});
  setTimeout(() => void refresh(), 250);
});
$("#offline-settings").addEventListener("click", () => {
  settingsOverlayWhenUnavailable = true;
  syncChromeVisibility();
});

for (const btn of document.querySelectorAll("#main-nav .nav-item")) {
  btn.addEventListener("click", () => setActiveTab(btn.dataset.tab));
}

$("#hint-open-vault").addEventListener("click", () => setActiveTab("vault"));
$("#hint-smart-save").addEventListener("click", () => void openQuickStore("", currentOrigin));

for (const btn of document.querySelectorAll("[data-lang-option]")) {
  btn.addEventListener("click", () => OpenKeyletUI.setLanguage(btn.dataset.langOption));
}

$("#reload-extension")?.addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "reload-extension" }).catch(() => chrome.runtime.reload());
});

// Unlock & Lock
$("#unlock-form").addEventListener("submit", async e => {
  e.preventDefault();
  try {
    await call("unlock", { pin: $("#pin").value });
    $("#pin").value = "";
    showError("");
    await refresh();
  } catch (err) {
    showError(err);
  }
});

$("#lock").addEventListener("click", async () => {
  closeSave();
  closeQuickStore();
  OpenKeyletVaultUI.close();
  $("#generator-output").value = "";
  updateStrengthMeter();
  try {
    await call("lock");
    await refresh();
  } catch (err) {
    showError(err);
  }
});

// Save Login (Manual & Capture)
$("#read-form").addEventListener("click", async () => {
  if (reading || saving) return;
  reading = true;
  try {
    const form = await call("read-form");
    savingCapture = null;
    saveEntries = entries;
    readSource = { sourceUrl: form.sourceUrl, sourceTabId: form.sourceTabId };
    detectedForms = form.forms;
    $("#detected-form").replaceChildren(...detectedForms.map((candidate, i) =>
      new Option(`${i + 1} · ${candidate.username || t("save.checkAccount")} · ${t(`save.kind.${candidate.kind}`)}`, String(i))));
    $("#detected-form").value = String(form.selectedIndex);
    $("#detected-form").hidden = $("#detected-form-label").hidden = detectedForms.length < 2;
    presentLogin(form, currentOrigin);
  } catch (e) {
    showError(e);
  } finally {
    reading = false;
  }
});

function presentLogin(form, origin) {
  $("#save-sheet-title").textContent = savingCapture ? t("save.reviewTitle") : t("save.title");
  $("#save-target").replaceChildren(
    new Option(t("save.newItem"), ""),
    ...saveEntries.map(i => new Option(`${i.name} · ${i.username}`, i.id)),
  );
  const match = form.username ? saveEntries.filter(i => i.username === form.username) : [];
  $("#save-target").value = match.length === 1 ? match[0].id : "";
  $("#name").value = match.length === 1 ? match[0].name : new URL(origin).hostname;
  $("#username").value = form.username;
  $("#password").value = form.password;
  $("#use-generated-password").hidden = Boolean(savingCapture);
  $("#save-source").textContent = origin;
  $("#save-warning").textContent = (form.warnings || []).map(localizeMessage).join(" · ");
  selectTarget();
  $("#save-form").hidden = false;
  showError("");
  syncChromeVisibility();
}

async function reviewCapture() {
  if (reading || saving || !pendingCapture) return;
  reading = true;
  try {
    const form = await call("capture-read", { captureId: pendingCapture.id });
    savingCapture = form.capture;
    saveEntries = form.entries;
    detectedForms = [];
    readSource = null;
    $("#detected-form").replaceChildren();
    $("#detected-form").hidden = $("#detected-form-label").hidden = true;
    presentLogin(form, form.capture.origin);
  } catch (error) {
    showError(error);
  } finally {
    reading = false;
  }
}

$("#capture-review").addEventListener("click", reviewCapture);
$("#capture-dismiss").addEventListener("click", async () => {
  if (!pendingCapture) return;
  try {
    await call("capture-dismiss", { captureId: pendingCapture.id });
    captureContext = "";
    closeSave();
    if (document.body.classList.contains("capture-page")) window.close();
    else await refresh();
  } catch (error) {
    showError(error);
  }
});

$("#capture-enabled").addEventListener("change", async () => {
  await chrome.storage.local.set({ captureEnabled: $("#capture-enabled").checked });
  if (!$("#capture-enabled").checked) {
    captureContext = "";
    closeSave();
  }
  await refresh();
});

$("#detected-form").addEventListener("change", () => {
  presentLogin(detectedForms[Number($("#detected-form").value)], currentOrigin);
});

function selectTarget() {
  const item = saveEntries.find(i => i.id === $("#save-target").value);
  editingVersion = item?.updatedAt || "";
  $("#name").disabled = Boolean(item);
  if (item) $("#name").value = item.name;
}
$("#save-target").addEventListener("change", selectTarget);

function closeSave() {
  $("#save-form").reset();
  $("#save-form").hidden = true;
  $("#password").type = "password";
  $("#toggle-saved-password").textContent = t("save.show");
  $("#detected-form").replaceChildren();
  $("#save-warning").textContent = "";
  $("#save-source").textContent = "";
  savingCapture = null;
  saveEntries = [];
  detectedForms = [];
  readSource = null;
  syncChromeVisibility();
}

async function cancelSaveFlow() {
  if (document.body.classList.contains("capture-page")) {
    if (pendingCapture) await call("capture-dismiss", { captureId: pendingCapture.id }).catch(() => {});
    window.close();
    return;
  }
  closeSave();
  refresh();
}
$("#cancel-save").addEventListener("click", cancelSaveFlow);
$("#save-back").addEventListener("click", cancelSaveFlow);

$("#toggle-saved-password").addEventListener("click", () => {
  const visible = $("#password").type === "password";
  $("#password").type = visible ? "text" : "password";
  $("#toggle-saved-password").textContent = t(visible ? "save.hide" : "save.show");
});

$("#capture-close").addEventListener("click", () => window.close());

$("#save-form").addEventListener("submit", async e => {
  e.preventDefault();
  if (saving) return;
  saving = true;
  try {
    await call(savingCapture ? "capture-save" : "save", {
      captureId: savingCapture?.id,
      ...readSource,
      id: $("#save-target").value,
      expectedUpdatedAt: editingVersion,
      name: $("#name").value,
      username: $("#username").value,
      password: $("#password").value,
    });
    if (savingCapture) {
      captureContext = "";
      $("#capture-complete").hidden = !document.body.classList.contains("capture-page");
    }
    closeSave();
    showError(t("save.saved"), "success");
  } catch (err) {
    showError(err);
  } finally {
    saving = false;
    refresh();
  }
});

// Bridge Settings
$("#host").addEventListener("input", () => {
  const val = ($("#host").value || "127.0.0.1").trim().toLowerCase();
  $("#lan-warning").hidden = ["", "127.0.0.1", "localhost", "::1"].includes(val);
});

$("#pair-form").addEventListener("submit", async e => {
  e.preventDefault();
  const host = ($("#host").value || "127.0.0.1").trim();
  const port = Number($("#port").value);
  const tls = Boolean($("#bridge-tls").checked);
  if (!host || /\s|[/@?#\\]/.test(host)) { showError(t("settings.invalidHost"), "error"); return; }
  if (!Number.isInteger(port) || port < 1024 || port > 65535) { showError(t("settings.invalidPort"), "error"); return; }
  const prev = await chrome.storage.local.get(["bridgeHost", "bridgePort", "bridgeTls"]);
  const changedEndpoint = (prev.bridgeHost || "127.0.0.1") !== host || (prev.bridgePort || 39272) !== port || Boolean(prev.bridgeTls) !== tls;
  await chrome.storage.local.set({ bridgeHost: host, bridgePort: port, bridgeTls: tls });
  if (changedEndpoint) {
    await chrome.storage.local.remove("bridgeToken");
  }
  await chrome.runtime.sendMessage({ type: "bridge-config-updated" }).catch(() => {});
  const isRemote = !["127.0.0.1", "localhost", "::1"].includes(host.toLowerCase());
  showError(
    isRemote ? t("settings.switchedRemote", { host, port }) : t("settings.switchedLocal"),
    "info",
  );
  setTimeout(() => void refresh(), 500);
});

// Password Generator
async function generatePassword() {
  const len = Math.max(8, Math.min(128, Number($("#generator-length").value) || 24));
  const options = { length: len };
  for (const key of ["uppercase", "lowercase", "digits", "symbols"]) {
    options[key] = $(`#gen-${key}`).checked;
  }
  return call("generate", { options });
}

async function triggerGeneratePassword() {
  try {
    const pw = await generatePassword();
    $("#generator-output").value = pw;
    $("#save-generated-password").hidden = !pageAvailableState || !pw;
    updateStrengthMeter();
    showError("");
  } catch (e) {
    showError(e);
  }
}

$("#generate-password").onclick = () => void triggerGeneratePassword();

$("#generator-range").addEventListener("input", () => {
  $("#generator-length").value = $("#generator-range").value;
  clearTimeout(genDebounceTimer);
  genDebounceTimer = setTimeout(() => void triggerGeneratePassword(), 80);
});
$("#generator-length").addEventListener("input", () => {
  const val = Number($("#generator-length").value);
  if (Number.isFinite(val)) $("#generator-range").value = String(Math.max(8, Math.min(64, val)));
});
for (const key of ["uppercase", "lowercase", "digits", "symbols"]) {
  $(`#gen-${key}`).addEventListener("change", () => {
    const anyChecked = ["uppercase", "lowercase", "digits", "symbols"].some(k => $(`#gen-${k}`).checked);
    if (!anyChecked) $(`#gen-${key}`).checked = true;
    void triggerGeneratePassword();
  });
}

$("#copy-generated-password").onclick = async () => {
  try {
    const pw = $("#generator-output").value;
    if (pw) {
      await navigator.clipboard.writeText(pw);
      $("#save-generated-password").hidden = !pageAvailableState;
      showError(t("vault.copied"), "success");
    }
  } catch (e) {
    showError(e);
  }
};

$("#save-generated-password").onclick = () => {
  const pw = $("#generator-output").value;
  if (!pw || !currentOrigin) return;
  closeQuickStore();
  savingCapture = null;
  saveEntries = entries;
  detectedForms = [];
  readSource = { generatedDirect: true };
  $("#detected-form").hidden = $("#detected-form-label").hidden = true;
  presentLogin({ username: "", password: pw, warnings: [] }, currentOrigin);
  $("#username").focus();
};

$("#use-generated-password").onclick = async () => {
  try {
    $("#password").value = await generatePassword();
  } catch (e) {
    showError(e);
  }
};

// Smart Save & 2FA QR
function closeQuickStore() {
  clearTimeout(quickParseTimer);
  quickParsed = null;
  quickOrigin = "";
  $("#quick-store-form").reset();
  $("#quick-store-form").hidden = true;
  $("#quick-store-detected").hidden = true;
  $("#quick-totp-attach-box").hidden = true;
  $("#quick-store-source").textContent = "";
  syncChromeVisibility();
}

function applyQuickParsed(parsed, origin) {
  quickParsed = parsed;
  quickOrigin = origin || currentOrigin || "";
  if (!parsed) {
    $("#quick-store-detected").hidden = true;
    $("#quick-totp-attach-box").hidden = true;
    return;
  }
  $("#quick-store-badge").textContent = OpenKeyletUI.lang === "zh"
    ? (parsed.labelZh || parsed.label || "SECRET")
    : (parsed.label || parsed.labelZh || "SECRET");
  $("#quick-store-summary").textContent = parsed.summary || "";
  $("#quick-store-detected").hidden = false;
  $("#quick-store-name").value = parsed.input?.name || "";

  const attachBox = $("#quick-totp-attach-box");
  if (parsed.totpUri && entries.length && quickOrigin) {
    $("#quick-totp-target").replaceChildren(
      ...entries.map(item => new Option(`${item.name}${item.username ? ` · ${item.username}` : ""}`, item.id)),
    );
    attachBox.hidden = false;
  } else {
    attachBox.hidden = true;
  }
}

async function parseQuickStoreText(rawText, origin) {
  const text = String(rawText || "").trim();
  if (!text) { applyQuickParsed(null, origin); return; }
  try {
    const parsed = await call("quick-parse", { text, origin: origin || currentOrigin || "" });
    applyQuickParsed(parsed, origin || currentOrigin || "");
    showError("");
  } catch (e) {
    applyQuickParsed(null, origin);
    showError(e);
  }
}

async function openQuickStore(prefillText = "", origin = currentOrigin) {
  closeSave();
  OpenKeyletVaultUI.close();
  quickOrigin = origin || currentOrigin || "";
  $("#quick-store-source").textContent = quickOrigin || "";
  $("#quick-store-text").value = prefillText;
  $("#quick-store-name").value = "";
  $("#quick-store-detected").hidden = true;
  $("#quick-totp-attach-box").hidden = true;
  $("#quick-store-form").hidden = false;
  syncChromeVisibility();
  if (prefillText) {
    await parseQuickStoreText(prefillText, quickOrigin);
  } else {
    $("#quick-store-text").focus();
  }
}

async function openQuickFromCapture() {
  if (!quickContext) return;
  reading = true;
  try {
    const draft = await call("quick-capture-read");
    await openQuickStore(draft.text, draft.origin);
  } catch (e) {
    quickContext = "";
    showError(e);
  } finally {
    reading = false;
  }
}

$("#quick-store-open").onclick = () => void openQuickStore("", currentOrigin);
$("#scan-page-qr").onclick = async () => {
  if (reading || saving) return;
  reading = true;
  try {
    const res = await call("scan-page-qr");
    await openQuickStore(res.text, res.origin);
    applyQuickParsed(res.parsed, res.origin);
    showError(t("quick.qrDetected"), "success");
  } catch (e) {
    showError(e);
  } finally {
    reading = false;
  }
};

$("#quick-store-text").addEventListener("input", () => {
  clearTimeout(quickParseTimer);
  const value = $("#quick-store-text").value;
  quickParseTimer = setTimeout(() => void parseQuickStoreText(value, quickOrigin), 220);
});

async function cancelQuickStoreFlow() {
  const wasQuickWindow = Boolean(quickContext);
  if (quickContext) await call("quick-capture-dismiss").catch(() => {});
  quickContext = "";
  closeQuickStore();
  if (wasQuickWindow) window.close();
  else refresh();
}
$("#quick-store-cancel").onclick = cancelQuickStoreFlow;
$("#quick-back").onclick = cancelQuickStoreFlow;

$("#quick-totp-attach").onclick = async () => {
  if (saving || !quickParsed?.totpUri) return;
  const targetId = $("#quick-totp-target").value;
  const target = entries.find(e => e.id === targetId);
  if (!target) return;
  saving = true;
  try {
    await call("attach-totp", {
      origin: quickOrigin || currentOrigin,
      id: target.id,
      expectedUpdatedAt: target.updatedAt,
      name: target.name,
      username: target.username || "",
      totp: quickParsed.totpUri,
    });
    const wasQuickWindow = Boolean(quickContext);
    quickContext = "";
    closeQuickStore();
    showError(t("quick.attached", { name: target.name }), "success");
    if (wasQuickWindow) setTimeout(() => window.close(), 700);
  } catch (e) {
    showError(e);
  } finally {
    saving = false;
    refresh();
  }
};

$("#quick-store-form").addEventListener("submit", async e => {
  e.preventDefault();
  if (saving) return;
  saving = true;
  try {
    const raw = $("#quick-store-text").value.trim();
    if (!raw) throw new Error(t("quick.emptyErr"));
    if (!quickParsed) await parseQuickStoreText(raw, quickOrigin);
    if (!quickParsed?.input) throw new Error(t("quick.parseErr"));
    const input = structuredClone(quickParsed.input);
    const customName = $("#quick-store-name").value.trim();
    if (customName) input.name = customName;
    await call("quick-save", { input });
    const wasQuickWindow = Boolean(quickContext);
    quickContext = "";
    closeQuickStore();
    showError(t("save.saved"), "success");
    if (wasQuickWindow) setTimeout(() => window.close(), 700);
  } catch (err) {
    showError(err);
  } finally {
    saving = false;
    refresh();
  }
});

// React to language/theme updates
OpenKeyletUI.onChange(() => {
  updateBridgeStatusUI(
    bridgeConnected ? "status.connected" : "status.unavailable",
    bridgeConnected ? "on" : "error",
    bridgeConnected ? "online" : "error",
  );
  const extVersion = chrome.runtime.getManifest?.().version || "";
  if (extVersion) $("#ext-version-label").textContent = `OpenKeylet v${extVersion} · ${t("settings.footerVault")}`;
  renderSiteEntries();
  renderSiteAutofill();
  updateStrengthMeter();
  if (pendingCapture) $("#capture-source").textContent = t("capture.source", { origin: pendingCapture.origin });
});

// Initial paint & polling
OpenKeyletUI.applyI18n();
void OpenKeyletUI.hydrateFromStorage();
syncChromeVisibility();
void refresh();
setInterval(refresh, 2000);
