// OpenKeylet Agent Browser Bridge & Current-Site Autofill popup controller.
const $ = s => document.querySelector(s);
const { t, localizeMessage, icon } = OpenKeyletUI;

let currentOrigin = "";
let entries = [];
let personalEntries = [];
let lastAgentAction = null;
let saving = false;
let reading = false;
let loading = false;
let editingVersion = "";
let refreshError = false;
let bridgeConnected = false;
let vaultLocked = true;
let pageAvailableState = false;
let activeTab = "site";
let settingsOverlayWhenUnavailable = false;
let toastTimer = null;

const captureParams = new URLSearchParams(location.search);
let captureContext = captureParams.get("capture") || "";
document.body.classList.toggle("capture-page", Boolean(captureContext));
const captureTabId = captureParams.has("tab") ? Number(captureParams.get("tab")) : undefined;

let pendingCapture = null;
let savingCapture = null;
let saveEntries = [];
let detectedForms = [];
let readSource = null;
let openedCapture = "";

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
    captureTabId,
    ...fields,
  });
  if (!reply?.ok) throw new Error(reply?.error || "OpenKeylet unavailable");
  return reply.result;
}

function hasOpenSheet() {
  return !$("#save-form").hidden;
}

function isStandaloneWindow() {
  return document.body.classList.contains("capture-page");
}

function syncChromeVisibility() {
  const sheetOpen = hasOpenSheet();
  const standalone = isStandaloneWindow();
  const unlockedReady = bridgeConnected && !vaultLocked;
  const showingSettings = unlockedReady
    ? (!sheetOpen && activeTab === "settings")
    : settingsOverlayWhenUnavailable;

  $("#main-nav").hidden = !unlockedReady || sheetOpen || standalone;
  $("#main-nav").dataset.active = activeTab;
  for (const btn of document.querySelectorAll("#main-nav .nav-item")) {
    const isAct = btn.dataset.tab === activeTab;
    btn.classList.toggle("active", isAct);
    if (isAct) btn.setAttribute("aria-current", "page");
    else btn.removeAttribute("aria-current");
  }

  const wasLockHidden = $("#unlock-form").hidden;
  $("#offline-panel").hidden = bridgeConnected || showingSettings;
  $("#unlock-form").hidden = !bridgeConnected || !vaultLocked || showingSettings;
  $("#vault-panel").hidden = !unlockedReady || showingSettings;
  if (wasLockHidden && !$("#unlock-form").hidden) {
    $("#pin")?.focus();
  }

  const showHintSite = unlockedReady && !sheetOpen && activeTab === "site" && !pageAvailableState && !standalone;
  $("#page-hint").hidden = !showHintSite;

  $("#capture-notice").hidden = !pendingCapture || showingSettings || !$("#save-form").hidden || !$("#capture-complete").hidden;

  for (const view of document.querySelectorAll("#vault-panel > .tab-view")) {
    view.hidden = sheetOpen || view.dataset.tabView !== activeTab;
  }

  $("#tab-settings").hidden = !showingSettings;
}

function setActiveTab(tab) {
  if (!["site", "settings"].includes(tab)) return;
  if (!bridgeConnected || vaultLocked) {
    settingsOverlayWhenUnavailable = tab === "settings";
    syncChromeVisibility();
    return;
  }
  activeTab = tab;
  settingsOverlayWhenUnavailable = false;
  syncChromeVisibility();
}

function updateBridgeStatusUI(statusKey, lampClass, stripClass) {
  const label = t(statusKey);
  $("#status").textContent = label;
  $("#lamp").className = `lamp ${lampClass}`.trim();
  $("#settings-status").textContent = label;
  $("#settings-status-strip").className = `status-strip ${stripClass}`.trim();
}

function formatActionKind(kind) {
  const map = {
    inspect_page: "inspect",
    fill_login: "fill_login",
    fill_field: "fill_field",
    fill_personal: "fill_card_addr",
    click: "click",
    passkey_capture: "passkey",
    passkey_resolve: "passkey",
    fill: "fill",
  };
  return map[kind] || kind || "";
}

function renderAgentChannel() {
  const stateEl = $("#agent-channel-state");
  const lastRow = $("#agent-last-row");
  const lastVal = $("#agent-last-value");
  if (stateEl) {
    stateEl.textContent = t(pageAvailableState ? "agent.ready" : "agent.standby");
    stateEl.classList.toggle("active", pageAvailableState);
  }
  if (!lastRow || !lastVal) return;
  if (!lastAgentAction?.kind) {
    lastRow.hidden = true;
    return;
  }
  let host = "";
  try {
    host = lastAgentAction.origin ? new URL(lastAgentAction.origin).host : "";
  } catch {
    host = "";
  }
  const ageSec = Math.max(0, Math.round((Date.now() - Number(lastAgentAction.at || Date.now())) / 1000));
  const ageText = ageSec < 60 ? `${ageSec}s` : `${Math.round(ageSec / 60)}m`;
  const parts = [formatActionKind(lastAgentAction.kind), host, ageText].filter(Boolean);
  lastVal.textContent = parts.join(" · ");
  lastRow.classList.toggle("is-error", lastAgentAction.ok === false);
  lastRow.hidden = false;
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
  for (const item of fillable.slice(0, 6)) {
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
    actionTag.textContent = t("site.fillHint");

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
    lastAgentAction = state.lastAgentAction || null;

    if (state.captureExpired) { captureContext = ""; closeSave(); }

    updateBridgeStatusUI("status.connected", "on", "online");

    if (state.locked) {
      closeSave();
    } else if (hasOpenSheet()) {
      syncChromeVisibility();
      return;
    }

    if (refreshError || currentOrigin !== state.origin) showError("");
    if (state.captureExpired) showError(t("capture.expired"));

    const entriesChanged = currentOrigin !== state.origin || JSON.stringify(entries) !== JSON.stringify(state.entries);
    const personalChanged = JSON.stringify(personalEntries) !== JSON.stringify(state.personal);
    currentOrigin = state.origin;
    entries = state.entries || [];
    personalEntries = state.personal || [];

    $("#website").textContent = currentOrigin;
    $("#website-bar").hidden = !pageAvailableState;
    $("#website-icon").classList.toggle("secure", currentOrigin.startsWith("https://"));

    $("#entries").hidden = !pageAvailableState;
    $("#read-form").hidden = !pageAvailableState;
    $("#site-actions").hidden = !pageAvailableState;

    $("#lock").hidden = !state.pinConfigured || vaultLocked;

    pendingCapture = state.capture;
    $("#capture-source").textContent = pendingCapture ? t("capture.source", { origin: pendingCapture.origin }) : "";
    $("#capture-review").disabled = vaultLocked;

    syncChromeVisibility();
    renderAgentChannel();

    if (entriesChanged) renderSiteEntries();
    if (entriesChanged || personalChanged) renderSiteAutofill();

    if (captureContext && pendingCapture && !vaultLocked && openedCapture !== pendingCapture.id) {
      openedCapture = pendingCapture.id;
      reviewCapture();
    }
  } catch (e) {
    bridgeConnected = false;
    vaultLocked = true;
    pageAvailableState = false;
    lastAgentAction = null;
    closeSave();
    updateBridgeStatusUI("status.unavailable", "error", "error");
    currentOrigin = "";
    entries = [];
    personalEntries = [];
    pendingCapture = null;
    $("#entries").replaceChildren();
    $("#site-autofill-list").replaceChildren();
    $("#site-autofill").hidden = true;
    $("#lock").hidden = true;
    syncChromeVisibility();
    showError(localizeMessage(e), "error");
    refreshError = true;
  } finally {
    loading = false;
  }
}

// Header & Navigation controls
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

$("#use-generated-password").addEventListener("click", async () => {
  try {
    const pw = await call("generate", { options: { length: 24, uppercase: true, lowercase: true, digits: true, symbols: true } });
    $("#password").value = pw;
    $("#password").type = "text";
    $("#toggle-saved-password").textContent = t("save.hide");
    showError("");
  } catch (e) {
    showError(e);
  }
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

// React to language/theme updates
OpenKeyletUI.onChange(() => {
  updateBridgeStatusUI(
    bridgeConnected ? "status.connected" : "status.unavailable",
    bridgeConnected ? "on" : "error",
    bridgeConnected ? "online" : "error",
  );
  const extVersion = chrome.runtime.getManifest?.().version || "";
  if (extVersion) $("#ext-version-label").textContent = `OpenKeylet v${extVersion} · ${t("settings.footerVault")}`;
  renderAgentChannel();
  renderSiteEntries();
  renderSiteAutofill();
  if (pendingCapture) $("#capture-source").textContent = t("capture.source", { origin: pendingCapture.origin });
});

// Initial paint & polling
OpenKeyletUI.applyI18n();
void OpenKeyletUI.hydrateFromStorage();
syncChromeVisibility();
void refresh();
setInterval(refresh, 2000);
