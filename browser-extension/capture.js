// Submitted credentials stay in this worker's memory for at most five minutes.
// Content scripts can offer a draft, but only extension UI can read/save it.
const loginCaptures = new Map();
const usernameSteps = new Map();
const CAPTURE_TTL = 5 * 60 * 1000;
const USERNAME_STEP_TTL = 2 * 60 * 1000;
let captureEnabled = false;
const capturePreferencesReady = storageReady.then(() => chrome.storage.local.get("captureEnabled"))
  .then(value => { captureEnabled = value.captureEnabled === true; });
async function announceCapturePreference() {
  const tabs = await chrome.tabs.query({});
  await Promise.all(tabs.map(tab => chrome.tabs.sendMessage(tab.id, {
    type: "openkeylet-capture-preferences", enabled: captureEnabled,
  }).catch(() => {})));
}
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.captureEnabled) {
    captureEnabled = changes.captureEnabled.newValue === true;
    if (!captureEnabled) clearLoginCaptures();
    announceCapturePreference().catch(() => {});
  }
});
function clearLoginCapture(tabId, expectedId) {
  const draft = loginCaptures.get(tabId);
  if (!draft || (expectedId && draft.id !== expectedId)) return;
  clearTimeout(draft.timer);
  loginCaptures.delete(tabId);
  chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {});
  chrome.tabs.sendMessage(tabId, { type: "openkeylet-capture-notice", available: false }, { frameId: 0 }).catch(() => {});
}
function clearLoginCaptures() {
  for (const tabId of loginCaptures.keys()) clearLoginCapture(tabId);
  for (const key of usernameSteps.keys()) clearUsernameStep(key);
}
function clearUsernameStep(key) {
  const step = usernameSteps.get(key);
  if (step) clearTimeout(step.timer);
  usernameSteps.delete(key);
}
function clearTabUsernameSteps(tabId, origin) {
  for (const [key, step] of usernameSteps) if (step.tabId === tabId && (!origin || step.origin !== origin)) clearUsernameStep(key);
}
async function offerUsernameStep(message, sender) {
  if (!captureEnabled || socket?.readyState !== WebSocket.OPEN
      || typeof message.username !== "string" || !message.username || message.username.length > 4096) return {};
  const page = await captureSenderPage(sender);
  if (!page || !captureEnabled) return {};
  const key = `${page.tab.id}:${sender.frameId ?? 0}`;
  clearUsernameStep(key);
  while (usernameSteps.size >= 20) clearUsernameStep(usernameSteps.keys().next().value);
  const step = { tabId: page.tab.id, origin: page.source.origin, username: message.username, expiresAt: Date.now() + USERNAME_STEP_TTL };
  step.timer = setTimeout(() => clearUsernameStep(key), USERNAME_STEP_TTL);
  usernameSteps.set(key, step);
  return {};
}
function getLoginCapture(tabId, id) {
  const draft = loginCaptures.get(tabId);
  if (!draft || (id && draft.id !== id)) return null;
  if (draft.expiresAt <= Date.now()) { clearLoginCapture(tabId, draft.id); return null; }
  return draft;
}
async function captureSenderPage(sender) {
  if (sender.id !== chrome.runtime.id || !Number.isInteger(sender.tab?.id) || !sender.url) return null;
  const source = new URL(sender.url);
  if (source.protocol !== "https:" && !(source.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(source.hostname))) return null;
  const tab = await chrome.tabs.get(sender.tab.id);
  if (new URL(tab.url).origin !== source.origin) return null;
  return { tab, source };
}
function captureSummary(draft) {
  return draft?.ready ? { id: draft.id, origin: draft.origin, kind: draft.kind } : null;
}
async function announceLoginCapture(draft) {
  if (getLoginCapture(draft.tabId)?.id !== draft.id || !draft.ready) return;
  const current = await chrome.tabs.get(draft.tabId).catch(() => null);
  if (!current?.url || new URL(current.url).origin !== draft.origin) { clearLoginCapture(draft.tabId, draft.id); return; }
  if (getLoginCapture(draft.tabId)?.id !== draft.id) return;
  await chrome.action.setBadgeBackgroundColor({ tabId: draft.tabId, color: "#111114" });
  await chrome.action.setBadgeTextColor?.({ tabId: draft.tabId, color: "#f4f4f5" }).catch?.(() => {});
  await chrome.action.setBadgeText({ tabId: draft.tabId, text: "+" });
  chrome.tabs.sendMessage(draft.tabId, { type: "openkeylet-capture-notice", available: true }, { frameId: 0 }).catch(() => {});
}
async function offerLoginCapture(message, sender) {
  if (!captureEnabled || socket?.readyState !== WebSocket.OPEN) return {};
  const page = await captureSenderPage(sender);
  const form = message.form;
  if (!captureEnabled || !page || !form || typeof form.username !== "string" || typeof form.password !== "string"
      || !form.password || form.username.length > 4096 || form.password.length > 16384
      || !["login", "signup", "change"].includes(form.kind)) return {};
  const stepKey = `${page.tab.id}:${sender.frameId ?? 0}`, step = usernameSteps.get(stepKey);
  const username = form.kind === "login" && !form.username && form.usernamePresent === false
    && step?.origin === page.source.origin && step.expiresAt > Date.now() ? step.username : form.username;
  clearUsernameStep(stepKey);
  const previous = getLoginCapture(page.tab.id);
  // Duplicate click/submit events must not replace a carried-forward account with a blank one.
  if (previous && previous.url === page.source.href && previous.password === form.password
      && (previous.username === username || (!username && form.usernamePresent === false))) return {};
  clearLoginCapture(page.tab.id);
  while (loginCaptures.size >= 10) clearLoginCapture(loginCaptures.keys().next().value);
  const draft = { id: crypto.randomUUID(), tabId: page.tab.id, origin: page.source.origin,
    url: page.source.href, username, password: form.password, kind: form.kind,
    expiresAt: Date.now() + CAPTURE_TTL };
  loginCaptures.set(page.tab.id, draft);
  draft.timer = setTimeout(() => clearLoginCapture(draft.tabId, draft.id), CAPTURE_TTL);
  // Suppress an unchanged saved login, without returning vault data to the page.
  try {
    const status = await bridgeCall("status");
    if (!status.locked && draft.username) {
      const items = (await bridgeCall("password.list", { origin: draft.url })).filter(item => item.username === draft.username);
      if (items.length === 1) {
        const saved = await bridgeCall("password.get", { origin: draft.url, id: items[0].id });
        if (saved.password === draft.password) { clearLoginCapture(draft.tabId, draft.id); return {}; }
      }
    }
  } catch { /* The owner can unlock or reconnect before reviewing. */ }
  draft.ready = true;
  await announceLoginCapture(draft);
  return {};
}
async function captureContentAction(message, sender) {
  const page = await captureSenderPage(sender);
  if (!page) return {};
  const draft = getLoginCapture(page.tab.id);
  if (!draft?.ready || draft.origin !== page.source.origin) return { available: false };
  if (message.type === "openkeylet-capture-review") {
    await chrome.windows.create({ url: chrome.runtime.getURL(`popup.html?capture=${draft.id}&tab=${draft.tabId}`),
      type: "popup", width: 420, height: 680 });
    return {};
  }
  if (message.type === "openkeylet-capture-dismiss") { clearLoginCapture(draft.tabId, draft.id); return {}; }
  return { available: true };
}
async function captureForUi(message) {
  let tabId = message.captureTabId;
  if (!Number.isInteger(tabId)) tabId = (await activePage(false))?.tab.id;
  const draft = getLoginCapture(tabId, message.captureId);
  if (!draft) throw new Error("待保存信息已过期，请重新填写 / The save suggestion expired");
  const tab = await chrome.tabs.get(draft.tabId);
  if (!tab.url || new URL(tab.url).origin !== draft.origin) {
    clearLoginCapture(draft.tabId, draft.id);
    throw new Error("来源网站已变化，请重新填写 / The source website changed");
  }
  return draft;
}
async function captureUiAction(message) {
  const draft = await captureForUi(message);
  if (message.action === "capture-dismiss") { clearLoginCapture(draft.tabId, draft.id); return {}; }
  const status = await bridgeCall("status");
  if (status.locked) throw new Error("请先解锁 OpenKeylet / Unlock OpenKeylet first");
  if (message.action === "capture-read") {
    const entries = await bridgeCall("password.list", { origin: draft.url });
    await captureForUi({ captureTabId: draft.tabId, captureId: draft.id });
    return { username: draft.username, password: draft.password, kind: draft.kind, warnings: [],
      capture: captureSummary(draft), entries };
  }
  if (message.action === "capture-save") {
    await captureForUi({ captureTabId: draft.tabId, captureId: draft.id });
    const result = await bridgeCall("password.save", { origin: draft.url, id: message.id || null,
      expectedUpdatedAt: message.expectedUpdatedAt, name: message.name, username: message.username, password: message.password });
    clearLoginCapture(draft.tabId, draft.id);
    return result;
  }
  throw new Error("Unsupported capture action");
}
chrome.tabs.onRemoved.addListener(tabId => { clearLoginCapture(tabId); clearTabUsernameSteps(tabId); });
chrome.tabs.onUpdated.addListener((tabId, change) => {
  if (change.url) clearTabUsernameSteps(tabId, new URL(change.url).origin);
  if (change.status === "complete") chrome.tabs.get(tabId).then(tab => {
    // Internal pages have no readable URL without the broad tabs permission.
    if (!tab.url) { clearLoginCapture(tabId); clearTabUsernameSteps(tabId); }
  }).catch(() => { clearLoginCapture(tabId); clearTabUsernameSteps(tabId); });
  const draft = getLoginCapture(tabId);
  if (draft && change.url && new URL(change.url).origin !== draft.origin) clearLoginCapture(tabId, draft.id);
  else if (draft?.ready && change.status === "complete") announceLoginCapture(draft).catch(() => {});
});
chrome.runtime.onMessage.addListener((message, sender, respond) => {
  let work;
  if (message?.type === "openkeylet-capture-preferences" && sender.id === chrome.runtime.id && sender.tab) {
    // Return only this public preference, never storage contents or pairing data.
    work = capturePreferencesReady.then(() => ({ enabled: captureEnabled }));
  }
  else if (message?.type === "openkeylet-login-submitted") work = offerLoginCapture(message, sender);
  else if (message?.type === "openkeylet-username-step") work = offerUsernameStep(message, sender);
  else if (["openkeylet-capture-status", "openkeylet-capture-review", "openkeylet-capture-dismiss"].includes(message?.type))
    work = captureContentAction(message, sender);
  else return false;
  work.then(result => respond({ ok: true, result }), () => respond({ ok: false }));
  return true;
});
// Worker restarts intentionally discard drafts; remove stale UI left in open tabs.
chrome.tabs.query({}).then(tabs => {
  for (const tab of tabs) {
    if (getLoginCapture(tab.id)) continue;
    chrome.action.setBadgeText({ tabId: tab.id, text: "" }).catch(() => {});
    chrome.tabs.sendMessage(tab.id, { type: "openkeylet-capture-notice", available: false }, { frameId: 0 }).catch(() => {});
  }
}).catch(() => {});
