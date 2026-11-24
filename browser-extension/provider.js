/* Runs only in the extension service worker. Page messages never select vault RPC methods. */
const bridgeRequests = new Map();
const credentialRequests = new Map();
const preparingCredentials = new Map();
const agentPasskeyWaiters = [];
function bridgeCall(method, params = {}) {
  if (socket?.readyState !== WebSocket.OPEN) return Promise.reject(new Error("Open OpenKeylet and connect Browser Bridge first"));
  if (bridgeRequests.size >= 32) return Promise.reject(new Error("Too many pending requests"));
  const requestId = crypto.randomUUID();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { bridgeRequests.delete(requestId); reject(new Error("OpenKeylet did not respond")); }, 20000);
    bridgeRequests.set(requestId, { resolve, reject, timer });
    try { socket.send(JSON.stringify({ type: "rpc", requestId, method, params })); }
    catch (e) { clearTimeout(timer); bridgeRequests.delete(requestId); reject(e); }
  });
}
function finishBridgeRequest(message) {
  const pending = bridgeRequests.get(message.requestId); if (!pending) return;
  clearTimeout(pending.timer); bridgeRequests.delete(message.requestId);
  message.ok ? pending.resolve(message.result) : pending.reject(new Error(message.error || "Operation failed"));
}
function failBridgeRequests() {
  clearLoginCaptures();
  for (const p of bridgeRequests.values()) { clearTimeout(p.timer); p.reject(new Error("OpenKeylet disconnected")); }
  bridgeRequests.clear();
  preparingCredentials.clear();
  while (agentPasskeyWaiters.length) {
    const waiter = agentPasskeyWaiters.pop();
    clearTimeout(waiter.timer);
    waiter.reject(new Error("OpenKeylet disconnected"));
  }
  for (const [id] of credentialRequests) finishCredentialRequest(id, { fallback: true });
}
function trustedUi(sender, page) { return sender.id === chrome.runtime.id && sender.url?.split("?")[0] === chrome.runtime.getURL(page); }
async function activePage(required = true) {
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (!tab?.id || !/^https?:\/\//.test(tab.url || "")) {
    if (required) throw new Error("请先打开需要登录的网站 / Open the website you want to sign in to");
    return null;
  }
  return { tab, origin: new URL(tab.url).origin };
}
async function pageStillMatches(tabId, origin) {
  const tab = await chrome.tabs.get(tabId);
  if (new URL(tab.url).origin !== origin) throw new Error("The website changed; try again");
}

async function loginPage(tab, origin) {
  const frameId = focusedFrameByTab.get(tab.id) ?? 0;
  const [result] = await chrome.scripting.executeScript({target:{tabId:tab.id,frameIds:[frameId]},func:()=>location.href});
  if (!result?.result || new URL(result.result).origin !== origin) throw new Error("Cannot use credentials in a different-origin frame");
  return {frameId,url:result.result};
}
async function formAction(tab, origin, mode, login, target) {
  target ||= await loginPage(tab, origin);
  if (mode === "read") {
    const [result] = await chrome.scripting.executeScript({ target: { tabId: tab.id, frameIds: [target.frameId] },
      func: useLoginForm, args: ["read", origin, null, target.url] });
    const forms = result?.result;
    if (!forms?.forms.length) throw new Error("未识别到登录表单 / No login form found");
    return { ...forms.forms[forms.selectedIndex], ...forms, sourceUrl: target.url, sourceTabId: tab.id };
  }
  const [result] = await chrome.scripting.executeScript({ target: { tabId: tab.id, frameIds: [target.frameId] }, func: useLoginForm, args: [mode, origin, login || null, target.url] });
  if (!result?.result) throw new Error("Could not access the login form");
  return result.result;
}
async function popupAction(message) {
  if (["capture-read", "capture-save", "capture-dismiss"].includes(message.action)) return captureUiAction(message);
  const vaultMethods = {"vault-get":"vault.get","vault-save":"vault.save","vault-trash":"vault.trash","vault-restore":"vault.restore","vault-purge":"vault.purge","vault-history":"vault.history","vault-clear-history":"vault.clearHistory"};
  if (Object.hasOwn(vaultMethods,message.action)) return bridgeCall(vaultMethods[message.action], {
    id:message.id, input:message.input, expectedUpdatedAt:message.expectedUpdatedAt, deletedAt:message.deletedAt });
  if (message.action === "unlock") return bridgeCall("unlock", { pin: message.pin });
  if (message.action === "lock") { clearLoginCaptures(); return bridgeCall("lock"); }
  if (message.action === "generate") return bridgeCall("password.generate", message.options);
  if (message.action === "list") {
    const status = await bridgeCall("status");
    const captured = message.captureId ? await captureForUi(message).catch(() => null) : null;
    const page = captured ? { tab: await chrome.tabs.get(captured.tabId), origin: captured.origin } : await activePage(false);
    const target = page && !status.locked ? await loginPage(page.tab, page.origin).catch(()=>null) : null;
    return { ...status, pageAvailable: Boolean(page), origin: page?.origin || "",
      capture: captureSummary(captured || (page && getLoginCapture(page.tab.id))),
      captureExpired: Boolean(message.captureId && !captured),
      entries: status.locked || (!target && !captured) ? [] : await bridgeCall("password.list", { origin: captured?.url || target.url }),
      personal: status.locked ? [] : await bridgeCall("personal.list"),
      vault: status.locked ? null : await bridgeCall("vault.list") };
  }
  if (message.action === "personal-edit") return bridgeCall("personal.get", { id: message.id });
  if (message.action === "personal-save") return bridgeCall("personal.save", {
    id: message.id || null, itemType: message.itemType, name: message.name,
    fields: message.fields, expectedUpdatedAt: message.expectedUpdatedAt });
  const { tab, origin } = await activePage();
  if (message.origin !== origin) throw new Error("The website changed; reopen the extension");
  if (message.action === "personal-fill") {
    const url = new URL(origin);
    if (url.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))
      throw new Error("请在 HTTPS 安全网站上填写信用卡或身份信息 / Use an HTTPS website");
    const item = await bridgeCall("personal.get", { id: message.id });
    if (!["card", "identity"].includes(item.itemType)) throw new Error("This item cannot be autofilled");
    const fillFields = { ...item.fields };
    for (const field of ["passportNumber", "licenseNumber", "nationalId"]) delete fillFields[field];
    await pageStillMatches(tab.id, origin);
    const [result] = await chrome.scripting.executeScript({
      target: { tabId: tab.id, frameIds: [focusedFrameByTab.get(tab.id) ?? 0] },
      func: usePersonalForm, args: [origin, item.itemType, fillFields] });
    if (!result?.result?.filled) throw new Error("没有识别到可填写的字段 / No matching form fields");
    return result.result;
  }
  if (message.action === "fill") {
    const target = await loginPage(tab, origin);
    const login = await bridgeCall("password.get", { origin: target.url, id: message.id });
    await pageStillMatches(tab.id, origin);
    return formAction(tab, origin, "fill", login, target);
  }
  if (message.action === "totp") {
    const target = await loginPage(tab, origin);
    return bridgeCall("password.totp", { origin: target.url, id: message.id });
  }
  if (message.action === "read-form") return formAction(tab, origin, "read");
  if (message.action === "save") {
    const target = await loginPage(tab, origin);
    if (message.sourceUrl !== target.url || message.sourceTabId !== tab.id)
      throw new Error("网页已经变化，请重新读取 / The page changed; read the form again");
    return bridgeCall("password.save", { origin: target.url, id: message.id || null, expectedUpdatedAt: message.expectedUpdatedAt,
      name: message.name, username: message.username, password: message.password });
  }
  throw new Error("Unsupported operation");
}

// The browser supplies the target tab. Values never go through page messaging.
function usePersonalForm(expectedOrigin, kind, values) {
  if (location.origin !== expectedOrigin) throw new Error("The website changed");
  const card = {
    "cc-name": "cardholderName", "cc-number": "cardNumber", "cc-type": "cardBrand",
    "cc-exp-month": "cardExpMonth", "cc-exp-year": "cardExpYear", "cc-csc": "cardSecurityCode",
  };
  const identity = {
    "honorific-prefix": "identityTitle", "given-name": "firstName", "additional-name": "middleName",
    "family-name": "lastName", "organization": "company", "email": "email", "tel": "phone",
    "tel-national": "phone", "tel-local": "phone",
    "address-line1": "address1", "address-line2": "address2", "address-line3": "address3",
    "address-level2": "city", "address-level1": "state", "postal-code": "postalCode",
    "country": "country", "country-name": "country",
  };
  const tokens = kind === "card" ? card : identity;
  const aliases = kind === "card" ? {
    "cc-name":["cardholder","cardholdername","nameoncard","ccname","持卡人","持卡人姓名"],
    "cc-number":["cardnumber","creditcardnumber","ccnumber","ccnum","cardnum","cardno","卡号","信用卡号","银行卡号"],
    "cc-exp":["cardexpiry","cardexpiration","expirationdate","expirydate","expiration","expdate","expiry","ccexp","mmyy","mmyyyy","有效期","有效期限","到期日","到期年月"],
    "cc-exp-month":["expmonth","expirymonth","expirationmonth","cardexpmonth","ccmonth"],
    "cc-exp-year":["expyear","expiryyear","expirationyear","cardexpyear","ccyear"],
    "cc-csc":["cvv","cvv2","cvc","cvc2","ccv","cccsc","securitycode","cardsecuritycode","安全码"],
  } : {
    "given-name":["firstname","givenname","名字"],"family-name":["lastname","surname","familyname","姓氏"],
    "additional-name":["middlename"],"name":["fullname","contactname","姓名"],
    "email":["email","emailaddress","contactemail","邮箱","电子邮箱"],"tel":["phone","phonenumber","telephone","mobile","电话","手机号码","手机号"],
    "organization":["company","companyname","organization","公司"],
    "address-line1":["address","address1","addressline1","streetaddress","地址"],
    "address-line2":["address2","addressline2"],"address-line3":["address3","addressline3"],
    "address-level2":["city","town","城市"],"address-level1":["state","province","region","省份","省","州"],
    "postal-code":["zip","zipcode","postalcode","postcode","邮编","邮政编码"],"country":["country","countrycode","countryname","国家","国家地区"],
  };
  const countryAliases = [
    ["cn", "chn", "china", "prc", "中国", "中华人民共和国"],
    ["us", "usa", "united states", "united states of america", "美国"],
    ["gb", "uk", "gbr", "united kingdom", "great britain", "英国"],
    ["jp", "jpn", "japan", "日本"],
    ["kr", "kor", "south korea", "korea", "韩国"],
    ["de", "deu", "germany", "deutschland", "德国"],
    ["fr", "fra", "france", "法国"],
    ["ca", "can", "canada", "加拿大"],
    ["au", "aus", "australia", "澳大利亚"],
    ["sg", "sgp", "singapore", "新加坡"],
    ["hk", "hkg", "hong kong", "香港", "中国香港"],
    ["tw", "twn", "taiwan", "台湾", "中国台湾"],
  ];
  function tokenFor(element) {
    const explicit = (element.autocomplete || "").toLowerCase().split(/\s/).at(-1);
    if (explicit && !["on","off"].includes(explicit)) return explicit;
    const normalize = value => value.toLowerCase().replace(/[^\p{L}\p{N}]/gu,"").replace(/^(billing|shipping|payment|checkout)/,"");
    const names = [element.name,element.id,element.getAttribute("aria-label"),...Array.from(element.labels || [],l=>l.textContent)]
      .filter(Boolean).map(normalize);
    const matches = Object.keys(aliases).filter(token=>names.some(name=>aliases[token].includes(name)));
    return matches.length === 1 ? matches[0] : "";
  }
  const elements = [];
  function collect(root) {
    for (const e of root.querySelectorAll("*")) {
      if (e.matches("input, select, textarea") && !e.disabled && !e.readOnly
          && (!e.matches("input") || ["text","tel","email","number","month"].includes(e.type) || (kind === "card" && e.type === "password" && tokenFor(e) === "cc-csc"))
          && e.getClientRects().length && getComputedStyle(e).visibility === "visible"
          && e.checkVisibility?.({checkOpacity:true,checkVisibilityCSS:true}) !== false) elements.push(e);
      if (e.shadowRoot) collect(e.shadowRoot);
    }
  }
  collect(document);
  let active = document.activeElement; while (active?.shadowRoot?.activeElement) active = active.shadowRoot.activeElement;
  const activeForm = active?.form && elements.some(e => e.form === active.form && (tokens[tokenFor(e)] || ["cc-exp","name","street-address"].includes(tokenFor(e)))) ? active.form : null;
  let filled = 0;
  for (const element of elements) {
    if (activeForm && element.form !== activeForm) continue;
    const token = tokenFor(element);
    let value = values[tokens[token]];
    if (kind === "card" && token === "cc-exp" && values.cardExpMonth && values.cardExpYear) {
      const rawMonth = values.cardExpMonth.trim(), rawYear = values.cardExpYear.trim();
      const month = rawMonth.padStart(2,"0"), year = rawYear.length === 2 ? `20${rawYear}` : rawYear;
      const hint = (element.placeholder || "").replace(/\s/g,"").toUpperCase();
      value = element.type === "month" ? `${year}-${month}`
        : hint === "MMYYYY" ? `${month}${year}` : hint === "MMYY" || element.maxLength === 4 ? `${month}${year.slice(-2)}`
        : hint.includes("YYYY") || element.maxLength === 7 ? `${month}/${year}` : `${month}/${year.slice(-2)}`;
    }
    if (kind === "card" && token === "cc-exp-year" && value && element.maxLength === 2) value = value.trim().slice(-2);
    if (kind === "identity" && token === "name") {
      const cjk = s => /[\u3400-\u9fff]/.test(s || "");
      value = !values.middleName && cjk(values.firstName) && cjk(values.lastName)
        ? `${values.lastName.trim()}${values.firstName.trim()}`
        : [values.firstName, values.middleName, values.lastName].filter(Boolean).join(" ");
    }
    if (kind === "identity" && token === "street-address")
      value = [values.address1, values.address2, values.address3].filter(Boolean).join("\n");
    if (!value) continue;
    if (element instanceof HTMLSelectElement) {
      const normalized = value.trim().toLowerCase();
      const monthNames = ["january","february","march","april","may","june","july","august","september","october","november","december"];
      const countryGroup = (token === "country" || token === "country-name")
        ? countryAliases.find(group => group.includes(normalized)) : null;
      const option = [...element.options].find(o => {
        if (o.disabled) return false;
        const optVal = o.value.trim().toLowerCase();
        const optText = o.textContent.trim().toLowerCase();
        if (optVal === normalized || optText === normalized) return true;
        if (countryGroup && (countryGroup.includes(optVal) || countryGroup.includes(optText))) return true;
        if (token === "cc-exp-month" && (Number(o.value) === Number(value)
          || parseInt(optText, 10) === Number(value)
          || (monthNames[Number(value)-1]?.startsWith(optText) && optText.length >= 3))) return true;
        if (token === "cc-exp-year" && optVal.slice(-2) === normalized.slice(-2)) return true;
        return false;
      });
      if (!option) continue;
      value = option.value;
    }
    const proto = element instanceof HTMLSelectElement ? HTMLSelectElement.prototype
      : element instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, "value").set.call(element, value);
    element.dispatchEvent(new InputEvent("input", { bubbles:true, composed:true, inputType:"insertText" }));
    element.dispatchEvent(new Event("change", { bubbles:true }));
    filled++;
  }
  return { filled };
}

function takeMatchingPasskeyWaiter(tabId, operation) {
  const index = agentPasskeyWaiters.findIndex(w =>
    (w.tabId == null || w.tabId === tabId) && (!w.operation || w.operation === operation));
  if (index === -1) return null;
  const [waiter] = agentPasskeyWaiters.splice(index, 1);
  clearTimeout(waiter.timer);
  return waiter;
}

function listPendingCredentialRequests() {
  return [...credentialRequests.entries()].map(([requestId, p]) => ({
    requestId,
    tabId: p.tabId,
    origin: p.params.origin,
    operation: p.params.operation,
    rpId: p.info.rpId,
    account: p.params.options?.user?.name || "",
    verificationRequired: Boolean(p.info.verificationRequired),
    agentManaged: Boolean(p.agentManaged),
    matchingCredentials: (p.info.entries || []).map(e => ({
      itemId: e.itemId,
      itemName: e.name,
      credentialId: e.passkey.credentialId,
      userName: e.passkey.userName,
      displayName: e.passkey.displayName,
    })),
  }));
}

async function captureAgentPasskey(payload = {}, expiresAt) {
  const requestedId = typeof payload.requestId === "string" ? payload.requestId.trim() : "";
  const requestedOp = typeof payload.operation === "string" && ["create", "get"].includes(payload.operation)
    ? payload.operation : "";
  let targetTab = null;
  if (requestedId) {
    const existing = credentialRequests.get(requestedId);
    if (!existing) throw new Error("Pending passkey request not found or already expired");
    return {
      requestId: requestedId,
      tabId: existing.tabId,
      origin: existing.params.origin,
      operation: existing.params.operation,
      rpId: existing.info.rpId,
      options: existing.params.options,
      verificationRequired: Boolean(existing.info.verificationRequired),
    };
  }
  if (payload.tabId != null || payload.url) {
    targetTab = await resolveTargetTab(payload);
  }
  for (const [id, p] of credentialRequests.entries()) {
    if (targetTab && p.tabId !== targetTab.id) continue;
    if (requestedOp && p.params.operation !== requestedOp) continue;
    return {
      requestId: id,
      tabId: p.tabId,
      origin: p.params.origin,
      operation: p.params.operation,
      rpId: p.info.rpId,
      options: p.params.options,
      verificationRequired: Boolean(p.info.verificationRequired),
    };
  }

  targetTab ||= await resolveTargetTab(payload);
  if (!targetTab?.id || !/^https?:\/\//.test(targetTab.url || "")) {
    throw new Error("No active HTTP/HTTPS browser tab for WebAuthn passkey");
  }
  const hasTrigger = Boolean((payload.triggerSelector || "").trim() || (payload.triggerText || "").trim());
  const defaultWait = hasTrigger ? 15000 : 12000;
  const maxRemaining = Number.isFinite(expiresAt) ? Math.max(500, expiresAt - Date.now() - 500) : defaultWait;
  const waitMs = Math.min(Math.max(Number(payload.waitMs) || defaultWait, 1000), maxRemaining);

  const waitPromise = new Promise((resolve, reject) => {
    const waiter = {
      tabId: targetTab.id,
      operation: requestedOp,
      resolve,
      reject,
      timer: null,
    };
    waiter.timer = setTimeout(() => {
      const idx = agentPasskeyWaiters.indexOf(waiter);
      if (idx !== -1) agentPasskeyWaiters.splice(idx, 1);
      reject(new Error("Timed out waiting for the webpage to trigger a WebAuthn Passkey request"));
    }, waitMs);
    agentPasskeyWaiters.push(waiter);
  });

  if (hasTrigger) {
    const clickResult = await clickJob({
      tabId: targetTab.id,
      selector: payload.triggerSelector || "",
      text: payload.triggerText || "",
    }, expiresAt);
    if (!clickResult?.ok) {
      // Cancel waiter cleanly if clicking the trigger button failed.
      const idx = agentPasskeyWaiters.findIndex(w => w.tabId === targetTab.id && w.operation === requestedOp);
      if (idx !== -1) {
        const [w] = agentPasskeyWaiters.splice(idx, 1);
        clearTimeout(w.timer);
      }
      throw new Error(clickResult?.message || "Failed to click passkey trigger button");
    }
  }

  return waitPromise;
}

async function resolveAgentPasskey(payload = {}) {
  const id = typeof payload.requestId === "string" ? payload.requestId : "";
  const p = credentialRequests.get(id);
  if (!p) throw new Error("This passkey request has expired or was cancelled");
  if (payload.fallback) {
    finishCredentialRequest(id, { fallback: true });
    return { resolved: true, fallback: true };
  }
  if (payload.error) {
    finishCredentialRequest(id, { error: payload.error, name: payload.name || "NotAllowedError" });
    return { resolved: true, rejected: true };
  }
  await pageStillMatches(p.tabId, p.params.origin);
  finishCredentialRequest(id, { credential: payload.credential });
  return {
    resolved: true,
    origin: p.params.origin,
    operation: p.params.operation,
    rpId: p.info.rpId,
  };
}

function finishCredentialRequest(id, result) {
  const p = credentialRequests.get(id); if (!p) return;
  credentialRequests.delete(id); clearTimeout(p.timer); p.resolve(result);
  if (p.windowId) chrome.windows.remove(p.windowId).catch(() => {});
}
async function startCredentialRequest(message, sender) {
  if (!sender.tab?.id || sender.frameId !== 0 || !["create", "get"].includes(message.operation)) return { fallback: true };
  if (typeof message.requestId !== "string" || message.requestId.length > 128 || !message.options || typeof message.options !== "object") throw new Error("Invalid passkey request");
  const origin = new URL(sender.url).origin;
  if (credentialRequests.size + preparingCredentials.size >= 8 || JSON.stringify(message.options).length > 128000) throw new Error("Too many or oversized passkey requests");
  const params = { origin, operation: message.operation, options: message.options };
  const preparingKey = `${sender.tab.id}:${message.requestId}`;
  if (preparingCredentials.has(preparingKey)) throw new Error("Duplicate request");
  // Register before the first await so an immediate AbortSignal cannot leave an orphan prompt.
  const preparation = {};
  preparingCredentials.set(preparingKey, preparation);
  let info, prepareError = null;
  try {
    await pageStillMatches(sender.tab.id, origin);
    if (preparingCredentials.get(preparingKey) === preparation) info = await bridgeCall("passkey.prepare", params);
    await pageStillMatches(sender.tab.id, origin);
  } catch (err) {
    if (err?.message?.startsWith("InvalidStateError:")) {
      prepareError = { error: err.message, name: "InvalidStateError" };
    }
    // Unsupported options and an unavailable vault use the browser's native provider.
    info = null;
  }
  if (preparingCredentials.get(preparingKey) !== preparation) return { error: "Aborted", name: "AbortError" };
  preparingCredentials.delete(preparingKey);
  const waiter = takeMatchingPasskeyWaiter(sender.tab.id, message.operation);
  if (prepareError) {
    if (waiter) waiter.reject(new Error(prepareError.error));
    return prepareError;
  }
  if (!info) {
    if (waiter) waiter.reject(new Error("WebAuthn request is unsupported by OpenKeylet or bridge is unavailable"));
    return { fallback: true };
  }
  if (message.operation === "get" && !info.entries.length) {
    if (waiter) waiter.reject(new Error(`No matching passkey saved in OpenKeylet for ${info.rpId}`));
    return { fallback: true };
  }
  const id = crypto.randomUUID();
  return new Promise((resolve) => {
    const timer = setTimeout(() => finishCredentialRequest(id, { error: "Passkey request expired", name: "NotAllowedError" }), Math.min(Math.max(Number(message.options.timeout) || 120000, 1000), 120000));
    credentialRequests.set(id, { params, info, tabId: sender.tab.id, pageRequestId: message.requestId, resolve, timer, busy: false, agentManaged: Boolean(waiter) });
    if (waiter) {
      waiter.resolve({
        requestId: id,
        tabId: sender.tab.id,
        origin,
        operation: message.operation,
        rpId: info.rpId,
        options: message.options,
        verificationRequired: Boolean(info.verificationRequired),
      });
      return;
    }
    chrome.windows.create({ url: chrome.runtime.getURL(`request.html?id=${id}`), type: "popup", width: 420, height: 640, focused: true }).then(w => {
      const p = credentialRequests.get(id); if (p) p.windowId = w.id; else chrome.windows.remove(w.id).catch(() => {});
    }).catch(() => finishCredentialRequest(id, { fallback: true }));
  });
}
async function requestAction(message) {
  const p = credentialRequests.get(message.id); if (!p) throw new Error("This request has expired");
  if (message.action === "info") return { origin: p.params.origin, operation: p.params.operation, account: p.params.options.user?.name || "", ...p.info };
  if (message.action === "fallback") { finishCredentialRequest(message.id, { fallback: true }); return {}; }
  if (message.action === "cancel") { finishCredentialRequest(message.id, { error: "Cancelled", name: "NotAllowedError" }); return {}; }
  if (message.action !== "confirm" || p.busy) throw new Error("Request is already being processed");
  p.busy = true;
  try {
    await pageStillMatches(p.tabId, p.params.origin);
    const entry = p.info.entries.find(e => e.passkey.credentialId === message.credentialId);
    if (p.params.operation === "get" && !entry) throw new Error("Select a passkey");
    const result = await bridgeCall(`passkey.${p.params.operation}`, { ...p.params, itemId: entry?.itemId, credentialId: entry?.passkey.credentialId, pin: message.pin || "" });
    finishCredentialRequest(message.id, { credential: result }); return {};
  } catch(error) {
    if(error.message.startsWith("InvalidStateError:")) { finishCredentialRequest(message.id,{error:error.message,name:"InvalidStateError"}); return {}; }
    throw error;
  } finally { p.busy = false; }
}
chrome.windows.onRemoved.addListener(windowId => { for (const [id,p] of credentialRequests) if (p.windowId === windowId) finishCredentialRequest(id, { error: "Cancelled", name: "NotAllowedError" }); });
function cancelTabCredentials(tabId) {
  for (const key of preparingCredentials.keys()) if (key.startsWith(`${tabId}:`)) preparingCredentials.delete(key);
  for (const [id,p] of credentialRequests) if (p.tabId === tabId) finishCredentialRequest(id, { error: "Website closed or navigated", name: "NotAllowedError" });
}
chrome.tabs.onRemoved.addListener(cancelTabCredentials);
chrome.tabs.onUpdated.addListener((tabId, change) => { if (change.status === "loading") cancelTabCredentials(tabId); });
chrome.runtime.onMessage.addListener((message, sender, respond) => {
  let work;
  if (message?.type === "vault-ui" && trustedUi(sender, "popup.html")) work = popupAction(message);
  else if (message?.type === "credential-ui" && trustedUi(sender, "request.html")) work = requestAction(message);
  else if (message?.type === "openkeylet-webauthn" && sender.tab) work = startCredentialRequest(message, sender);
  else if (message?.type === "openkeylet-webauthn-cancel" && sender.tab) {
    preparingCredentials.delete(`${sender.tab.id}:${message.requestId}`);
    for (const [id,p] of credentialRequests) if (p.tabId === sender.tab.id && p.pageRequestId === message.requestId) finishCredentialRequest(id, { error: "Aborted", name: "AbortError" });
    return false;
  } else return false;
  work.then(result => respond({ ok: true, result }), error => respond({ ok: false, error: error.message }));
  return true;
});
