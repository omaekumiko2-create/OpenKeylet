let socket;
let reconnectTimer;
let heartbeatTimer;
let connectTask;
let forceReconnectAfterCurrent = false;
let lastAgentAction = null;
const focusedFrameByTab = new Map();
const JOB_TIMEOUT_MS = 35_000;
const EXTENSION_VERSION = chrome.runtime.getManifest?.().version || "";
// Pairing tokens belong to the worker and extension UI, never content scripts.
const storageReady = chrome.storage.local.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });

chrome.runtime.onMessage.addListener((message, sender, respond) => {
  if (["openkeylet-focus", "kru-focus"].includes(message?.type) && sender.tab?.id != null) {
    focusedFrameByTab.set(sender.tab.id, sender.frameId ?? 0);
    return;
  }
  if (message?.type === "bridge-config-updated" && trustedUi(sender, "popup.html")) {
    requestConnect({ force: true });
    respond({ ok: true });
    return;
  }
  if (message?.type === "reload-extension" && trustedUi(sender, "popup.html")) {
    respond({ ok: true });
    setTimeout(() => chrome.runtime.reload(), 20);
    return;
  }
});

chrome.tabs.onRemoved.addListener((tabId) => focusedFrameByTab.delete(tabId));
chrome.tabs.onActivated.addListener(() => announceActive());
chrome.windows.onFocusChanged.addListener((windowId) => {
  if (windowId !== chrome.windows.WINDOW_ID_NONE) announceActive();
});

async function setStatus(status, detail) {
  await chrome.storage.local.set({ bridgeStatus: status, bridgeDetail: detail });
}

async function applyDesktopAppearance(payload) {
  const patch = {};
  if (payload?.theme === "light" || payload?.theme === "dark") {
    patch.uiTheme = payload.theme;
  }
  if (typeof payload?.language === "string" && payload.language.trim()) {
    patch.uiLang = payload.language.trim();
  }
  if (Object.keys(patch).length) {
    await chrome.storage.local.set(patch);
  }
}

function reconnectAfter(delay = 1500) {
  clearTimeout(reconnectTimer);
  reconnectTimer = setTimeout(requestConnect, delay);
}

function socketIsLive() {
  return socket &&
    (socket.readyState === WebSocket.CONNECTING || socket.readyState === WebSocket.OPEN);
}

function announceActive() {
  if (socket?.readyState !== WebSocket.OPEN) {
    requestConnect();
    return;
  }
  try {
    socket.send(JSON.stringify({ type: "activate" }));
  } catch {
    handleDisconnect(socket);
  }
}

async function announceIfFocused() {
  try {
    const window = await chrome.windows.getLastFocused();
    if (window?.focused) announceActive();
  } catch {
    // The next tab/window activation will update the active extension.
  }
}

function requestConnect({ force = false } = {}) {
  if (!force && socketIsLive()) return connectTask || Promise.resolve();
  if (connectTask) {
    if (force) forceReconnectAfterCurrent = true;
    return connectTask;
  }
  connectTask = (async () => {
    let forceCurrent = force;
    do {
      forceReconnectAfterCurrent = false;
      await connectOnce(forceCurrent);
      forceCurrent = forceReconnectAfterCurrent;
    } while (forceCurrent);
  })().finally(() => {
    connectTask = null;
  });
  return connectTask;
}

function disposeSocket(ws, close = false) {
  if (socket !== ws) return false;
  socket = null;
  clearInterval(heartbeatTimer);
  heartbeatTimer = null;
  ws.onopen = null;
  ws.onmessage = null;
  ws.onerror = null;
  ws.onclose = null;
  if (close && (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN)) {
    ws.close();
  }
  return true;
}

function normalizeBridgeHost(raw) {
  const host = String(raw || "127.0.0.1").trim();
  if (!host || /\s|[/@?#\\]/.test(host)) return "127.0.0.1";
  return host;
}

function formatHostForUrl(host) {
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

function resolveBridgeTarget(stored = {}) {
  const host = normalizeBridgeHost(stored.bridgeHost);
  const port = Number.isInteger(stored.bridgePort) && stored.bridgePort >= 1 && stored.bridgePort <= 65535
    ? stored.bridgePort
    : 39272;
  const tls = stored.bridgeTls === true;
  const urlHost = formatHostForUrl(host);
  const httpScheme = tls ? "https" : "http";
  const wsScheme = tls ? "wss" : "ws";
  return {
    host,
    port,
    tls,
    httpOrigin: `${httpScheme}://${urlHost}:${port}`,
    wsUrl: `${wsScheme}://${urlHost}:${port}/extension`,
    label: `${tls ? "wss://" : ""}${urlHost}:${port}`,
  };
}

async function handleDisconnect(ws) {
  if (!disposeSocket(ws, true)) return;
  failBridgeRequests();
  const stored = await chrome.storage.local.get(["bridgeHost", "bridgePort", "bridgeTls"]);
  const target = resolveBridgeTarget(stored);
  await setStatus("disconnected", target.label);
  reconnectAfter();
}

function startHeartbeat(ws) {
  clearInterval(heartbeatTimer);
  heartbeatTimer = setInterval(() => {
    if (socket === ws && ws.readyState === WebSocket.OPEN) {
      try {
        ws.send(JSON.stringify({ type: "ping" }));
      } catch {
        handleDisconnect(ws);
      }
    } else {
      handleDisconnect(ws);
    }
  }, 20000);
}

async function claimPairing(target) {
  try {
    const response = await fetch(`${target.httpOrigin}/claim`, { method: "POST" });
    if (!response.ok) return false;
    const payload = await response.json();
    if (!payload?.token || !payload?.port) return false;
    await chrome.storage.local.set({ bridgePort: payload.port, bridgeToken: payload.token });
    return true;
  } catch {
    return false;
  }
}

async function connectOnce(force = false) {
  await storageReady;
  clearTimeout(reconnectTimer);
  if (!force && socketIsLive()) return;
  if (socket) {
    disposeSocket(socket, true);
  }
  const stored = await chrome.storage.local.get([
    "bridgeHost",
    "bridgePort",
    "bridgeTls",
    "bridgeToken",
  ]);
  const target = resolveBridgeTarget(stored);
  const bridgeToken = stored.bridgeToken || "";
  if (!bridgeToken) {
    await setStatus("waiting", target.label);
    if (await claimPairing(target)) {
      reconnectAfter(50);
      return;
    }
    reconnectAfter();
    return;
  }
  await setStatus("connecting", target.label);
  const ws = new WebSocket(target.wsUrl);
  socket = ws;
  ws.onopen = () => ws.send(JSON.stringify({
    type: "auth",
    token: bridgeToken,
    extensionVersion: EXTENSION_VERSION,
  }));
  ws.onmessage = async (event) => {
    let message;
    try {
      message = JSON.parse(event.data);
    } catch {
      return;
    }
    if (message.type === "rpc-result") { finishBridgeRequest(message); return; }
    if (message.type === "reload") {
      chrome.runtime.reload();
      return;
    }
    if (message.type === "appearance") {
      await applyDesktopAppearance(message);
      return;
    }
    if (message.type === "ready") {
      const appVersion = typeof message.appVersion === "string" ? message.appVersion.trim() : "";
      await chrome.storage.local.set({
        desktopAppVersion: appVersion,
        extensionVersion: EXTENSION_VERSION,
      });
      await applyDesktopAppearance(message);
      if (appVersion && EXTENSION_VERSION && appVersion !== EXTENSION_VERSION) {
        const { lastAutoReloadedForVersion = "" } = await chrome.storage.local.get("lastAutoReloadedForVersion");
        if (lastAutoReloadedForVersion !== appVersion) {
          await chrome.storage.local.set({ lastAutoReloadedForVersion: appVersion });
          chrome.runtime.reload();
          return;
        }
      } else if (appVersion && appVersion === EXTENSION_VERSION) {
        await chrome.storage.local.remove("lastAutoReloadedForVersion");
      }
      await setStatus("connected", target.label);
      startHeartbeat(ws);
      await announceIfFocused();
      return;
    }
    if (message.type === "pong") return;
    if (message.type === "auth-error") {
      await chrome.storage.local.remove("bridgeToken");
      await setStatus("waiting", target.label);
      disposeSocket(ws, true);
      reconnectAfter();
      return;
    }
    if (message.type === "job") {
      const result = await handleBrowserJob(message.job);
      const jobKind = String(message.job?.kind || "").trim();
      if (jobKind) {
        const origin = typeof result?.data?.origin === "string"
          ? result.data.origin
          : (typeof message.job?.payload?.url === "string" ? message.job.payload.url : "");
        lastAgentAction = {
          kind: jobKind,
          ok: Boolean(result?.ok),
          origin,
          at: Date.now(),
        };
      }
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          type: "complete",
          jobId: message.job?.id,
          ok: Boolean(result?.ok),
          message: result?.message || "",
          data: result?.data ?? null,
        }));
      }
    }
  };
  ws.onerror = () => handleDisconnect(ws);
  ws.onclose = () => handleDisconnect(ws);
}

function jobExpiresAt(job, now = Date.now()) {
  const raw = job?.expiresAt ?? job?.expires_at;
  const latest = now + JOB_TIMEOUT_MS;
  if (raw === undefined || raw === null) return latest;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? Math.min(parsed, latest) : latest;
}

async function fillFocused(value, expiresAt, submit = false) {
  if (typeof value !== "string") return { ok: false, message: "The fill value is invalid" };
  let [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (!tab?.id) [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return { ok: false, message: "No active tab" };
  const frameId = focusedFrameByTab.get(tab.id) ?? 0;
  try {
    const [execution] = await chrome.scripting.executeScript({
      target: { tabId: tab.id, frameIds: [frameId] },
      func: writeToFocusedControl,
      args: [value, expiresAt, submit],
    });
    return execution?.result || { ok: false, message: "The page did not return a fill result" };
  } catch {
    return { ok: false, message: "Cannot fill the focused control; check the page and extension permissions" };
  }
}

function writeToFocusedControl(value, expiresAt, submit = false) {
  if (Number.isFinite(expiresAt) && Date.now() >= expiresAt) {
    return { ok: false, message: "The fill task has expired" };
  }
  const findActiveElement = (root) => {
    const element = root.activeElement;
    const shadowRoot = element?.shadowRoot;
    return shadowRoot?.activeElement ? findActiveElement(shadowRoot) : element;
  };
  const element = findActiveElement(document);
  if (!element || element === document.body || element === document.documentElement) {
    return { ok: false, message: "The current page has no focused input control" };
  }
  const tag = element.tagName?.toLowerCase();
  const editable = element.isContentEditable;
  if (tag !== "input" && tag !== "textarea" && !editable) {
    return { ok: false, message: "The focused element is not an input control" };
  }
  try {
    element.focus();
    if (editable) {
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(element);
      selection.removeAllRanges();
      selection.addRange(range);
      document.execCommand("insertText", false, value);
    } else {
      const prototype = tag === "textarea" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(prototype, "value")?.set;
      if (!setter) return { ok: false, message: "The current control does not support safe filling" };
      setter.call(element, value);
    }
    element.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText" }));
    element.dispatchEvent(new Event("change", { bubbles: true }));
    if (submit) {
      const form = element.form || element.closest?.("form");
      if (!form || typeof form.requestSubmit !== "function") {
        return { ok: false, message: "Filled the focused control, but no form was available to submit" };
      }
      setTimeout(() => form.requestSubmit(), 0);
      return { ok: true, message: "Filled and submitted the current form" };
    }
    return { ok: true, message: "Filled the focused control" };
  } catch {
    return { ok: false, message: "The page refused to fill the current control" };
  }
}

importScripts("form-reader.js", "provider.js", "capture.js", "agent-actions.js");
requestConnect();
