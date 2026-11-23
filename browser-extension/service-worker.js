let socket;
let reconnectTimer;
let heartbeatTimer;
let connectTask;
let connectionIdentity = null;
let forceReconnectAfterCurrent = false;
const focusedFrameByTab = new Map();
const browserCredentialOperations = new Map();
const JOB_TIMEOUT_MS = 35_000;
// The test harness flips this only in its disposable extension copy.
const SYNTHETIC_HTTP_LOOPBACK_ALLOWED = false;
// Pairing tokens belong to the worker and extension UI, never content scripts.
const storageReady = chrome.storage.local.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });

chrome.runtime.onMessage.addListener((message, sender) => {
  if (["openkeylet-focus", "kru-focus"].includes(message?.type) && sender.tab?.id != null) {
    focusedFrameByTab.set(sender.tab.id, sender.frameId ?? 0);
    return;
  }
  if (message?.type === "bridge-config-updated" && trustedUi(sender, "popup.html")) {
    requestConnect({ force: true });
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
  connectionIdentity = null;
  failBrowserCredentialOperations(ws);
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

async function handleDisconnect(ws) {
  if (!disposeSocket(ws, true)) return;
  failBridgeRequests();
  const { bridgePort = 39272 } = await chrome.storage.local.get("bridgePort");
  await setStatus("disconnected", `127.0.0.1:${bridgePort}`);
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

async function claimPairing(port) {
  try {
    const response = await fetch(`http://127.0.0.1:${port}/claim`, { method: "POST" });
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
  const { bridgePort = 39272, bridgeToken = "", browserInstanceId: storedBrowserInstanceId = "" } = await chrome.storage.local.get([
    "bridgePort",
    "bridgeToken",
    "browserInstanceId",
  ]);
  const browserInstanceId = storedBrowserInstanceId || crypto.randomUUID();
  if (!storedBrowserInstanceId) await chrome.storage.local.set({ browserInstanceId });
  if (!bridgeToken) {
    await setStatus("waiting", `127.0.0.1:${bridgePort}`);
    if (await claimPairing(bridgePort)) {
      reconnectAfter(50);
      return;
    }
    reconnectAfter();
    return;
  }
  await setStatus("connecting", `127.0.0.1:${bridgePort}`);
  const ws = new WebSocket(`ws://127.0.0.1:${bridgePort}/extension`);
  socket = ws;
  ws.onopen = () => ws.send(JSON.stringify({
    type: "auth",
    token: bridgeToken,
    extensionId: chrome.runtime.id,
    browserInstanceId,
  }));
  ws.onmessage = async (event) => {
    let message;
    try {
      message = JSON.parse(event.data);
    } catch {
      return;
    }
    if (message.type === "rpc-result") { finishBridgeRequest(message); return; }
    if (message.type === "prepared" || message.type === "prepare-rejected") {
      finishCredentialBinding(ws, message);
      return;
    }
    if (message.type === "ready") {
      if (!message.applicationId || !message.connectionId
          || message.browserInstanceId !== browserInstanceId) {
        disposeSocket(ws, true);
        await setStatus("disconnected", `127.0.0.1:${bridgePort}`);
        reconnectAfter();
        return;
      }
      connectionIdentity = {
        applicationId: message.applicationId,
        connectionId: message.connectionId,
        browserInstanceId: message.browserInstanceId,
      };
      await setStatus("connected", `127.0.0.1:${bridgePort}`);
      startHeartbeat(ws);
      await announceIfFocused();
      return;
    }
    if (message.type === "pong") return;
    if (message.type === "auth-error") {
      await chrome.storage.local.remove("bridgeToken");
      await setStatus("waiting", `127.0.0.1:${bridgePort}`);
      disposeSocket(ws, true);
      reconnectAfter();
      return;
    }
    if (message.type === "job") {
      await processCredentialJob(ws, message.job);
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

function failBrowserCredentialOperations(ws) {
  for (const [operationId, pending] of browserCredentialOperations) {
    if (pending.ws !== ws) continue;
    clearTimeout(pending.timer);
    browserCredentialOperations.delete(operationId);
    pending.reject(new Error("OpenKeylet disconnected"));
  }
}

function waitForCredentialBinding(ws, identity, operationId, fieldToken, expiresAt) {
  if (browserCredentialOperations.has(operationId)) return Promise.reject(new Error("Duplicate credential operation"));
  return new Promise((resolve, reject) => {
    const timeoutMs = Math.max(1, Math.min(5000, expiresAt - Date.now()));
    const timer = setTimeout(() => {
      browserCredentialOperations.delete(operationId);
      reject(new Error("Credential target binding was not acknowledged"));
    }, timeoutMs);
    browserCredentialOperations.set(operationId, { ws, identity, fieldToken, resolve, reject, timer });
  });
}

function finishCredentialBinding(ws, message) {
  const pending = browserCredentialOperations.get(message.operationId);
  if (!pending || pending.ws !== ws
      || message.applicationId !== pending.identity.applicationId
      || message.connectionId !== pending.identity.connectionId
      || message.browserInstanceId !== pending.identity.browserInstanceId
      || message.fieldToken !== pending.fieldToken) return;
  clearTimeout(pending.timer);
  browserCredentialOperations.delete(message.operationId);
  if (message.type === "prepared") pending.resolve(true);
  else pending.reject(new Error("Credential target binding was rejected"));
}

function currentCredentialConnection(ws, identity, job) {
  return socket === ws && ws.readyState === WebSocket.OPEN
    && connectionIdentity?.applicationId === identity.applicationId
    && connectionIdentity?.connectionId === identity.connectionId
    && connectionIdentity?.browserInstanceId === identity.browserInstanceId
    && job?.applicationId === identity.applicationId
    && job?.connectionId === identity.connectionId
    && job?.browserInstanceId === identity.browserInstanceId;
}

function credentialOriginAllowed(origin) {
  try {
    const url = new URL(origin);
    if (url.origin !== origin || url.username || url.password || url.search || url.hash) return false;
    if (url.protocol === "https:") return true;
    return SYNTHETIC_HTTP_LOOPBACK_ALLOWED && url.protocol === "http:"
      && ["localhost", "127.0.0.1", "[::1]", "::1"].includes(url.hostname);
  } catch {
    return false;
  }
}

async function activeCredentialPage() {
  const { tab, origin } = await activePage();
  if (!credentialOriginAllowed(origin)) throw new Error("Browser credentials require a secure HTTPS origin");
  const focusedWindow = await chrome.windows.getLastFocused();
  const currentTab = await chrome.tabs.get(tab.id);
  if (!focusedWindow?.focused || focusedWindow.id !== tab.windowId
      || !currentTab.active || currentTab.windowId !== tab.windowId || currentTab.url !== tab.url) {
    throw new Error("The active browser tab changed");
  }
  const target = await loginPage(currentTab, origin);
  return {
    tab: currentTab,
    origin,
    frameId: target.frameId,
    url: target.url,
    topUrl: target.topUrl,
    documentId: target.documentId,
    topDocumentId: target.topDocumentId,
  };
}

async function revalidateCredentialPage(ws, identity, job, original, expiresAt) {
  if (Date.now() >= expiresAt || !currentCredentialConnection(ws, identity, job)) {
    throw new Error("The credential operation expired or its connection changed");
  }
  const { tab, origin } = await activePage();
  if (tab.id !== original.tab.id || tab.windowId !== original.tab.windowId
      || tab.url !== original.topUrl || origin !== original.origin) {
    throw new Error("The active browser tab or origin changed");
  }
  const focusedWindow = await chrome.windows.getLastFocused();
  const currentTab = await chrome.tabs.get(original.tab.id);
  if (!focusedWindow?.focused || focusedWindow.id !== original.tab.windowId
      || !currentTab.active || currentTab.windowId !== original.tab.windowId
      || currentTab.url !== original.topUrl) {
    throw new Error("The active browser tab changed");
  }
  const target = await loginPage(currentTab, original.origin);
  if (target.frameId !== original.frameId || target.url !== original.url
      || target.topUrl !== original.topUrl || target.documentId !== original.documentId
      || target.topDocumentId !== original.topDocumentId) {
    throw new Error("The browser frame or document changed");
  }
  return target;
}

function sendCredentialCompletion(ws, job, identity, target, fieldToken, ok, delivered, readback) {
  if (!identity || socket !== ws || ws.readyState !== WebSocket.OPEN) return;
  const metadata = target || {};
  try {
    ws.send(JSON.stringify({
      type: "complete",
      operationId: job?.id,
      applicationId: identity.applicationId,
      connectionId: identity.connectionId,
      browserInstanceId: identity.browserInstanceId,
      origin: metadata.origin || "",
      tabId: Number.isInteger(metadata.tabId) ? metadata.tabId : -1,
      windowId: Number.isInteger(metadata.windowId) ? metadata.windowId : -1,
      frameId: Number.isInteger(metadata.frameId) ? metadata.frameId : -1,
      documentId: metadata.documentId || "",
      topDocumentId: metadata.topDocumentId || "",
      fieldRole: job?.credentialRef?.module || "",
      fieldToken: fieldToken || "",
      ok: Boolean(ok),
      delivered: Boolean(delivered),
      readback: Boolean(readback),
      submitted: false,
    }));
  } catch {
    // A disconnected operation is never replayed on another extension socket.
  }
}

function injectionMatches(execution, target) {
  return execution?.frameId === target.frameId && execution?.documentId === target.documentId;
}

async function processCredentialJob(ws, job) {
  const identity = connectionIdentity;
  let target = null;
  let fieldToken = "";
  let secretValue = "";
  let login = null;
  let delivered = false;
  let readback = false;
  try {
    if (!identity || !currentCredentialConnection(ws, identity, job)
        || !/^[0-9a-f-]{36}$/i.test(job?.id || "")
        || !job?.credentialRef || !/^[0-9a-f-]{36}$/i.test(job.credentialRef.itemId || "")
        || !["username", "password"].includes(job.credentialRef.module)
        || Object.keys(job).some(key => !["id", "expiresAt", "applicationId", "connectionId", "browserInstanceId", "credentialRef"].includes(key))
        || Object.keys(job.credentialRef).some(key => !["itemId", "module"].includes(key))) {
      throw new Error("Invalid reference-only browser credential job");
    }
    const expiresAt = jobExpiresAt(job);
    if (Date.now() >= expiresAt) throw new Error("The credential operation expired");
    const page = await activeCredentialPage();
    target = {
      origin: page.origin,
      tabId: page.tab.id,
      windowId: page.tab.windowId,
      frameId: page.frameId,
      documentId: page.documentId,
      topDocumentId: page.topDocumentId,
      url: page.url,
      topUrl: page.topUrl,
      tab: page.tab,
    };
    fieldToken = crypto.randomUUID();
    const [preparedExecution] = await chrome.scripting.executeScript({
      target: { tabId: page.tab.id, documentIds: [page.documentId] },
      func: prepareCredentialField,
      args: [page.origin, page.topUrl, page.url, job.id, fieldToken, job.credentialRef.module],
    });
    if (!injectionMatches(preparedExecution, target) || !preparedExecution.result?.ok) {
      throw new Error("The focused field is not a valid credential target");
    }
    if (!currentCredentialConnection(ws, identity, job)) throw new Error("The extension connection changed");

    const bindingAcknowledged = waitForCredentialBinding(ws, identity, job.id, fieldToken, expiresAt);
    // A socket that fails during `prepare` must not surface an unhandled rejection.
    bindingAcknowledged.catch(() => {});
    ws.send(JSON.stringify({
      type: "prepare",
      operationId: job.id,
      applicationId: identity.applicationId,
      connectionId: identity.connectionId,
      browserInstanceId: identity.browserInstanceId,
      origin: target.origin,
      tabId: target.tabId,
      windowId: target.windowId,
      frameId: target.frameId,
      documentId: target.documentId,
      topDocumentId: target.topDocumentId,
      fieldRole: job.credentialRef.module,
      fieldToken,
    }));
    await bindingAcknowledged;

    // This is the same origin-bound vault lookup used by the browser popup.
    login = await bridgeCall("password.get", { origin: target.url, id: job.credentialRef.itemId });
    secretValue = login?.[job.credentialRef.module];
    if (typeof secretValue !== "string" || secretValue.length === 0) {
      throw new Error("The selected credential module is empty");
    }
    await revalidateCredentialPage(ws, identity, job, target, expiresAt);

    const [fillExecution] = await chrome.scripting.executeScript({
      target: { tabId: target.tabId, documentIds: [target.documentId] },
      func: fillCredentialField,
      args: [target.origin, target.topUrl, target.url, job.id, fieldToken,
        job.credentialRef.module, secretValue, expiresAt],
    });
    delivered = injectionMatches(fillExecution, target) && fillExecution.result?.delivered === true;
    if (!delivered) throw new Error("Credential delivery was not confirmed");

    await revalidateCredentialPage(ws, identity, job, target, expiresAt);
    const [readbackExecution] = await chrome.scripting.executeScript({
      target: { tabId: target.tabId, documentIds: [target.documentId] },
      func: verifyCredentialField,
      args: [target.origin, target.topUrl, target.url, job.id, fieldToken,
        job.credentialRef.module, secretValue, expiresAt],
    });
    readback = injectionMatches(readbackExecution, target) && readbackExecution.result?.readback === true;
    if (!readback) throw new Error("Independent field readback failed");

    sendCredentialCompletion(ws, job, identity, target, fieldToken, true, true, true);
  } catch {
    sendCredentialCompletion(ws, job, identity, target, fieldToken, false, delivered, readback);
  } finally {
    secretValue = "";
    login = null;
  }
}

importScripts("form-reader.js", "provider.js", "capture.js");
requestConnect();
