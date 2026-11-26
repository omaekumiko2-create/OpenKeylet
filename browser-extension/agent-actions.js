/* Agent-driven browser operations executed by the paired extension service worker.
 * Secrets flow directly from the authenticated local OpenKeylet bridge into page inputs;
 * inspection responses never include input values or secrets. */

async function resolveTargetTab(payload = {}) {
  if (Number.isInteger(payload?.tabId)) {
    const tab = await chrome.tabs.get(payload.tabId).catch(() => null);
    if (!tab?.id) throw new Error(`Tab ${payload.tabId} was not found`);
    return tab;
  }
  const tabs = await chrome.tabs.query({});
  const httpTabs = tabs.filter(tab => tab.id != null && /^https?:\/\//.test(tab.url || ""));
  if (typeof payload?.url === "string" && payload.url.trim()) {
    const needle = payload.url.trim().toLowerCase();
    let expectedOrigin = "";
    try { expectedOrigin = new URL(payload.url.trim()).origin; } catch {}
    const matched = httpTabs.filter(tab => {
      const url = (tab.url || "").toLowerCase();
      if (url === needle || url.startsWith(needle)) return true;
      if (expectedOrigin) {
        try { return new URL(tab.url).origin === expectedOrigin; } catch {}
      }
      return url.includes(needle);
    });
    if (matched.length) {
      return matched.find(tab => tab.active) || matched[0];
    }
    throw new Error(`No open browser tab matches URL: ${payload.url}`);
  }
  const [focusedActive] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (focusedActive?.id && /^https?:\/\//.test(focusedActive.url || "")) return focusedActive;
  const [currentActive] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (currentActive?.id && /^https?:\/\//.test(currentActive.url || "")) return currentActive;
  const anyActive = httpTabs.find(tab => tab.active);
  if (anyActive) return anyActive;
  if (httpTabs.length) return httpTabs[0];
  return focusedActive || currentActive || null;
}

/* Inspection results go into the agent's context, and query strings and fragments often
 * carry one-time codes, OAuth state, or tokens. Listed tabs drop them entirely; the inspected
 * page and its frames keep parameter names so the agent can still tell, for example, an
 * error callback from a login form. Credentials in the URL's userinfo are always dropped. */
function urlWithoutQuery(rawUrl) {
  try {
    const url = new URL(rawUrl);
    url.username = "";
    url.password = "";
    url.search = "";
    url.hash = "";
    return url.href;
  } catch {
    return "";
  }
}

function urlWithMaskedQuery(rawUrl) {
  try {
    const url = new URL(rawUrl);
    const keys = [...new Set(url.searchParams.keys())];
    const query = url.search
      ? `?${keys.length ? keys.map(key => `${encodeURIComponent(key)}=…`).join("&") : "…"}`
      : "";
    return `${urlWithoutQuery(rawUrl)}${query}${url.hash ? "#…" : ""}`;
  } catch {
    return "";
  }
}

async function listHttpTabs() {
  const tabs = await chrome.tabs.query({});
  return tabs
    .filter(tab => tab.id != null && /^https?:\/\//.test(tab.url || ""))
    .slice(0, 30)
    .map(tab => {
      let origin = "";
      try { origin = new URL(tab.url).origin; } catch {}
      return {
        tabId: tab.id,
        active: Boolean(tab.active),
        title: (tab.title || "").slice(0, 160),
        url: urlWithoutQuery(tab.url || ""),
        origin,
      };
    });
}

function isSecureOrigin(originStr) {
  try {
    const u = new URL(originStr);
    return u.protocol === "https:" || ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
  } catch {
    return false;
  }
}

async function listEligibleFrames(tabId, topOrigin) {
  const topSecure = isSecureOrigin(topOrigin);
  let probes = [];
  try {
    probes = await chrome.scripting.executeScript({
      target: { tabId, allFrames: true },
      func: () => ({ origin: location.origin, href: location.href }),
    });
  } catch {
    return [{ frameId: 0, origin: topOrigin, href: "" }];
  }
  const frames = [];
  for (const entry of probes || []) {
    const info = entry?.result;
    if (!info?.origin || !/^https?:\/\//.test(info.href || "")) continue;
    const sameOrigin = info.origin === topOrigin;
    const allowedCrossOrigin = !sameOrigin && topSecure && isSecureOrigin(info.origin);
    if (entry.frameId === 0 || sameOrigin || allowedCrossOrigin) {
      frames.push({ frameId: entry.frameId, origin: info.origin, href: info.href });
    }
  }
  frames.sort((a, b) => a.frameId - b.frameId);
  return frames.length ? frames : [{ frameId: 0, origin: topOrigin, href: "" }];
}

async function orderedFramesForTab(tab, topOrigin, explicitFrameId = null) {
  const eligible = await listEligibleFrames(tab.id, topOrigin);
  if (Number.isInteger(explicitFrameId)) {
    const picked = eligible.find(f => f.frameId === explicitFrameId);
    if (picked) return [picked];
  }
  const preferred = focusedFrameByTab.get(tab.id);
  const ordered = [];
  const pushUnique = (frame) => {
    if (frame && !ordered.some(f => f.frameId === frame.frameId)) ordered.push(frame);
  };
  if (Number.isInteger(preferred)) {
    pushUnique(eligible.find(f => f.frameId === preferred));
  }
  pushUnique(eligible.find(f => f.frameId === 0));
  for (const frame of eligible) pushUnique(frame);
  return ordered;
}

async function targetFrameForTab(tab, origin) {
  const preferred = focusedFrameByTab.get(tab.id) ?? 0;
  if (preferred === 0) return { frameId: 0, url: tab.url };
  try {
    const [result] = await chrome.scripting.executeScript({
      target: { tabId: tab.id, frameIds: [preferred] },
      func: () => location.href,
    });
    if (result?.result) {
      const frameOrigin = new URL(result.result).origin;
      if (frameOrigin === origin || (isSecureOrigin(origin) && isSecureOrigin(frameOrigin))) {
        return { frameId: preferred, url: result.result };
      }
    }
  } catch {}
  return { frameId: 0, url: tab.url };
}

function inspectPageDom(expectedOrigin) {
  const isSecure = (originStr) => {
    try {
      const u = new URL(originStr);
      return u.protocol === "https:" || ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
    } catch {
      return false;
    }
  };
  const isTopFrame = window === window.top;
  if (location.origin !== expectedOrigin) {
    if (isTopFrame) {
      throw new Error("The website changed during inspection");
    }
    if (!isSecure(expectedOrigin) || !isSecure(location.origin)) {
      return null;
    }
  }
  const isVisible = (el) => {
    if (!el || el.disabled) return false;
    if (!el.getClientRects?.().length) return false;
    const style = getComputedStyle(el);
    if (style.visibility === "hidden" || style.display === "none" || style.opacity === "0") return false;
    if (el.checkVisibility?.({ checkOpacity: true, checkVisibilityCSS: true }) === false) return false;
    return true;
  };
  const labelTextFor = (el) => {
    const parts = [];
    if (el.getAttribute("aria-label")) parts.push(el.getAttribute("aria-label"));
    for (const label of Array.from(el.labels || [])) {
      if (label.textContent) parts.push(label.textContent.trim());
    }
    const labelledBy = (el.getAttribute("aria-labelledby") || "").split(/\s+/).filter(Boolean).slice(0, 4);
    for (const id of labelledBy) {
      const text = el.getRootNode().getElementById?.(id)?.textContent?.trim();
      if (text) parts.push(text);
    }
    return parts.join(" ").replace(/\s+/g, " ").trim().slice(0, 120);
  };
  const selectorHintFor = (el) => {
    const tag = el.tagName.toLowerCase();
    if (el.id && /^[a-zA-Z_][\w-]*$/.test(el.id)) return `#${el.id}`;
    if (el.name && /^[a-zA-Z0-9_.-]+$/.test(el.name)) {
      if (tag === "input" && ["checkbox", "radio"].includes(el.type)) {
        return `input[type="${el.type}"][name="${el.name}"]`;
      }
      return `${tag}[name="${el.name}"]`;
    }
    if (el.autocomplete && el.autocomplete !== "off" && el.autocomplete !== "on") {
      return `${tag}[autocomplete="${el.autocomplete}"]`;
    }
    if (el.type && tag === "input") return `input[type="${el.type}"]`;
    return tag;
  };
  // Handles live only in this document's isolated world for keyCandidates (and optional handle selectors).
  const handles = new Map();
  const keyHandleFor = (el) => {
    const id = "keylet-control:" + crypto.getRandomValues(new Uint32Array(4)).join("-");
    handles.set(id, el);
    return id;
  };
  globalThis.openKeyletControls = handles;
  // Collect entered values from sensitive inputs and visible key candidate nodes so
  // readable page text, titles, alerts, and URLs never accidentally echo them.
  const sensitiveValues = [];
  const pushSensitive = (raw) => {
    const v = (raw || "").trim();
    if (!v || sensitiveValues.length >= 64 || sensitiveValues.includes(v)) return;
    sensitiveValues.push(v);
  };
  const scrubSensitive = (text) => {
    if (!text || !sensitiveValues.length) return text;
    let out = text;
    for (const sv of sensitiveValues) {
      if (sv && out.includes(sv)) out = out.split(sv).join("[REDACTED]");
    }
    return out;
  };
  const allInputs = [];
  const allButtons = [];
  const keyCandidates = [];
  const alertElements = [];
  const summaryElements = [];
  const ALERT_SELECTOR = '[role="alert"], [role="status"], [aria-live="assertive"], [aria-live="polite"], .alert, .error, .error-message, .form-error, .flash-error, .flash-warn, .flash-notice, .notification, .toast, [data-error], [data-testid*="error" i], [data-testid*="alert" i]';
  const SUMMARY_SELECTOR = 'h1, h2, h3, [role="heading"], dialog[open], [role="dialog"], [role="alertdialog"], form legend, form p, main p';

  function collect(root) {
    for (const el of root.querySelectorAll("*")) {
      if (el.matches("input, textarea") && typeof el.value === "string") {
        const v = el.value.trim();
        if ((el.type === "password" && v.length >= 3) || v.length >= 6) {
          pushSensitive(v);
        }
      }
      if (allInputs.length < 200 && el.matches("input, select, textarea") && isVisible(el)) {
        if (!el.matches("input") || !["hidden", "submit", "button", "image", "reset", "file"].includes(el.type)) {
          allInputs.push(el);
        }
      }
      if (allButtons.length < 100 && el.matches("button, input[type=submit], input[type=button], a[href], [role=button]") && isVisible(el)) {
        const text = (el.tagName === "INPUT" ? el.value : el.textContent || "").replace(/\s+/g, " ").trim();
        const aria = (el.getAttribute("aria-label") || "").trim();
        if (text || aria) allButtons.push(el);
      }
      if (isTopFrame && keyCandidates.length < 32 && el.matches("output, code, pre:not(:has(code)), textarea[readonly], input[readonly]:is([type=text], :not([type]))") && isVisible(el)) {
        keyCandidates.push({ selectorHint: keyHandleFor(el), kind: el.localName });
        const raw = (el.matches("input, textarea") ? el.value : el.innerText || "").trim();
        if (raw.length >= 8 && raw.length <= 16384 && !/\s/.test(raw) && !/[•…]|\*{3,}|\.{3,}/.test(raw)) {
          pushSensitive(raw);
        }
      }
      if (alertElements.length < 24 && el.matches(ALERT_SELECTOR) && isVisible(el)) {
        alertElements.push(el);
      }
      if (summaryElements.length < 40 && el.matches(SUMMARY_SELECTOR) && isVisible(el)) {
        summaryElements.push(el);
      }
      if (el.shadowRoot) collect(el.shadowRoot);
    }
  }
  collect(document);

  const safeTextOf = (rootEl, maxLen = 280) => {
    const chunks = [];
    let len = 0;
    const walk = (node) => {
      if (!node || len >= maxLen) return;
      if (node.nodeType === Node.TEXT_NODE) {
        const t = (node.nodeValue || "").replace(/\s+/g, " ").trim();
        if (t) {
          chunks.push(t);
          len += t.length + 1;
        }
        return;
      }
      if (node.nodeType !== Node.ELEMENT_NODE) return;
      const tag = node.tagName?.toLowerCase() || "";
      if (["input", "textarea", "select", "script", "style", "noscript", "template"].includes(tag)) return;
      if (node.isContentEditable) return;
      if (node.shadowRoot) {
        for (const child of node.shadowRoot.childNodes) walk(child);
      }
      for (const child of node.childNodes) walk(child);
    };
    walk(rootEl);
    let text = chunks.join(" ").replace(/\s+/g, " ").trim().slice(0, maxLen);
    if (text && sensitiveValues.some(sv => text.includes(sv))) {
      for (const sv of sensitiveValues) {
        if (sv) text = text.split(sv).join("[REDACTED]");
      }
    }
    return text;
  };

  const alerts = [];
  const pushAlert = (text) => {
    const clean = (text || "").replace(/\s+/g, " ").trim().slice(0, 240);
    if (!clean || alerts.length >= 10) return;
    if (!alerts.some(existing => existing === clean || existing.includes(clean))) {
      alerts.push(clean);
    }
  };
  for (const el of alertElements) pushAlert(safeTextOf(el, 240));
  for (const el of allInputs) {
    if (el.validity && !el.validity.valid && el.validationMessage) {
      const msg = String(el.validationMessage).trim();
      if (msg && !sensitiveValues.some(sv => sv.length >= 3 && msg.includes(sv))) {
        pushAlert(msg);
      }
    }
  }

  const summaryParts = [...alerts];
  const pushSummary = (text) => {
    const clean = (text || "").replace(/\s+/g, " ").trim().slice(0, 320);
    if (!clean) return;
    if (summaryParts.some(existing => existing === clean || existing.includes(clean))) return;
    summaryParts.push(clean);
  };
  for (const el of summaryElements) {
    pushSummary(safeTextOf(el, 320));
    if (summaryParts.join(" | ").length >= 1500) break;
  }
  const pageTextSummary = summaryParts.join(" | ").slice(0, 1500);

  let active = document.activeElement;
  while (active?.shadowRoot?.activeElement) active = active.shadowRoot.activeElement;
  const focused = active && active !== document.body && active !== document.documentElement ? {
    tag: active.tagName?.toLowerCase() || "",
    type: active.type || "",
    name: active.name || "",
    id: active.id || "",
    autocomplete: active.autocomplete || "",
    placeholder: (active.placeholder || "").slice(0, 80),
    editable: Boolean(active.isContentEditable || ["input", "textarea", "select"].includes(active.tagName?.toLowerCase() || "")),
  } : null;

  const isOtpInput = (el) => {
    const tokens = (el.autocomplete || "").toLowerCase().split(/\s+/);
    if (tokens.includes("one-time-code")) return true;
    const meta = [el.name, el.id, el.placeholder, labelTextFor(el)].join(" ").toLowerCase();
    return /(?:^|[\s_.-])(?:otp|totp|2fa|mfa|passcode|verification.?code|one.?time)(?:$|[\s_.-])|验证码|驗證碼|动态码|動態碼/.test(meta);
  };
  let otpInputs = allInputs.filter(el => el.matches("input") && !["checkbox", "radio"].includes(el.type) && isOtpInput(el));
  if (!otpInputs.length) {
    const singleBoxes = allInputs.filter(el =>
      el.matches("input")
      && ["text", "tel", "number"].includes(el.type)
      && (el.maxLength === 1 || el.getAttribute("maxlength") === "1")
      && (el.inputMode === "numeric" || /(?:code|digit|otp|pin|token|char|box)/i.test([el.name, el.id, el.placeholder, labelTextFor(el)].join(" ")))
    );
    if (singleBoxes.length >= 4 && singleBoxes.length <= 8) {
      otpInputs = singleBoxes;
    }
  }

  let loginForms = [];
  if (typeof useLoginForm === "function") {
    try {
      const read = useLoginForm("read", location.origin, null, location.href);
      loginForms = (read.forms || []).map((f, index) => ({
        index,
        kind: f.kind,
        hasUsername: Boolean(f.usernamePresent),
        hasPassword: true,
        hasOtp: otpInputs.length > 0,
        focused: Boolean(f.focused),
        warnings: f.warnings || [],
      }));
      if (!loginForms.length && (read.usernameStep !== undefined)) {
        const hasUsernameStep = allInputs.some(el =>
          el.matches("input") && ["text", "email", "tel"].includes(el.type)
          && (/username|email|login|account|identifier|账号|邮箱|用户名/i.test([el.autocomplete, el.name, el.id, el.placeholder, labelTextFor(el)].join(" "))));
        if (hasUsernameStep) {
          loginForms.push({
            index: 0,
            kind: "username-step",
            hasUsername: true,
            hasPassword: false,
            hasOtp: otpInputs.length > 0,
            focused: Boolean(active && allInputs.includes(active)),
            warnings: [],
          });
        }
      }
    } catch {}
  }

  const fields = allInputs.slice(0, 40).map((el, index) => {
    const isCheckable = el.matches("input") && (el.type === "checkbox" || el.type === "radio");
    const entry = {
      index,
      tag: el.tagName.toLowerCase(),
      type: el.type || "",
      name: (el.name || "").slice(0, 80),
      id: (el.id || "").slice(0, 80),
      autocomplete: (el.autocomplete || "").slice(0, 80),
      placeholder: scrubSensitive((el.placeholder || "").slice(0, 80)),
      label: scrubSensitive(labelTextFor(el)),
      selectorHint: selectorHintFor(el),
      hasValue: isCheckable ? Boolean(el.checked) : Boolean(el.value),
      focused: el === active,
      readOnly: Boolean(el.readOnly),
    };
    if (isCheckable) entry.checked = Boolean(el.checked);
    return entry;
  });

  const buttons = allButtons.slice(0, 25).map((el, index) => ({
    index,
    tag: el.tagName.toLowerCase(),
    type: el.type || "",
    text: scrubSensitive(((el.tagName === "INPUT" ? el.value : el.textContent) || "").replace(/\s+/g, " ").trim().slice(0, 100)),
    ariaLabel: scrubSensitive((el.getAttribute("aria-label") || "").slice(0, 100)),
    selectorHint: selectorHintFor(el),
    disabled: Boolean(el.disabled || el.getAttribute("aria-disabled") === "true"),
  }));

  return {
    url: location.href,
    origin: location.origin,
    title: scrubSensitive((document.title || "").slice(0, 160)),
    keyCandidates,
    _scrubValues: sensitiveValues,
    focused,
    loginForms,
    otpFieldCount: otpInputs.length,
    fields,
    buttons,
    alerts,
    pageTextSummary,
  };
}

function fillLoginDom(expectedOrigin, payload, expiresAt) {
  if (Number.isFinite(expiresAt) && Date.now() >= expiresAt) {
    return { ok: false, message: "The browser login fill task has expired" };
  }
  if (location.origin !== expectedOrigin) {
    return { ok: false, message: "The website origin changed before filling" };
  }

  const isVisible = (el) => {
    if (!el || el.disabled) return false;
    if (!el.getClientRects?.().length) return false;
    const style = getComputedStyle(el);
    if (style.visibility === "hidden" || style.display === "none" || style.opacity === "0") return false;
    if (el.checkVisibility?.({ checkOpacity: true, checkVisibilityCSS: true }) === false) return false;
    return true;
  };
  const setInputValue = (el, val) => {
    if (!el || !el.isConnected || el.readOnly || el.disabled) return false;
    if (location.origin !== expectedOrigin) return false;
    el.focus();
    const proto = el.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const desc = Object.getOwnPropertyDescriptor(proto, "value");
    if (!desc?.set || !desc?.get) return false;
    desc.set.call(el, val);
    el.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType: "insertText", data: val }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    return el.isConnected && location.origin === expectedOrigin && desc.get.call(el) === val;
  };

  const inputs = [];
  function collect(root) {
    for (const el of root.querySelectorAll("*")) {
      if (inputs.length >= 400) return;
      if (el.matches("input") && isVisible(el)) inputs.push(el);
      if (el.shadowRoot) collect(el.shadowRoot);
    }
  }
  collect(document);

  const tokens = el => (el.autocomplete || "").toLowerCase().split(/\s+/).filter(Boolean);
  const meta = el => [
    el.name, el.id, el.getAttribute("aria-label"), el.placeholder,
    ...Array.from(el.labels || [], l => l.textContent.slice(0, 200)),
  ].filter(Boolean).join(" ").replace(/([a-z])([A-Z])/g, "$1 $2").toLowerCase();

  const isOtp = el => tokens(el).includes("one-time-code")
    || /(?:^|[\s_.-])(?:otp|totp|2fa|mfa|passcode|verification.?code|one.?time)(?:$|[\s_.-])|验证码|驗證碼|动态码|動態碼/.test(meta(el));

  const filledFields = [];
  let targetForm = null;
  let lastFilledElement = null;

  // 1. Try filling username & password via smart login matching (supports 1-step and 2-step flows).
  const wantUsername = typeof payload.username === "string" && payload.username.length > 0;
  const wantPassword = typeof payload.password === "string" && payload.password.length > 0;
  const wantTotp = typeof payload.totp === "string" && payload.totp.length > 0;

  let active = document.activeElement;
  while (active?.shadowRoot?.activeElement) active = active.shadowRoot.activeElement;

  const passwordFields = inputs.filter(el => !isOtp(el) && (
    el.type === "password" || (el.type === "text" && (
      tokens(el).some(t => ["current-password", "new-password"].includes(t))
      || /(?:^|[\s_.-])(?:password|passwd|pwd)(?:$|[\s_.-])/.test(meta(el))
    ))
  ));
  const nonConfirmPasswords = passwordFields.filter(el => !/confirm|repeat|retype|确认|確認|重复|重複/.test(meta(el)));
  const passwordEl = nonConfirmPasswords.includes(active)
    ? active
    : nonConfirmPasswords.find(el => tokens(el).includes("current-password")) || nonConfirmPasswords[0] || null;

  const scope = passwordEl?.form
    || passwordEl?.closest?.("dialog,[role=dialog],section,[role=form]")
    || null;

  const usernameScore = (el) => {
    if (!["text", "email", "tel"].includes(el.type) || isOtp(el)) return 0;
    const t = tokens(el), m = meta(el);
    if (t.includes("username")) return 120;
    if (t.some(x => !["on", "off", "email", "tel", "webauthn"].includes(x) && !x.startsWith("section-"))) return 0;
    if (/search|coupon|promo|first.?name|last.?name|city|搜索|优惠|姓名/.test(m)) return 0;
    if (/username|user.?name|user.?id|login|account|identifier|(?:^|[\s_.-])(?:user|uid)(?:$|[\s_.-])|账号|帳號|账户|帳戶|用户名|用戶名/.test(m)) return 100;
    if (el.type === "email" || t.includes("email") || /email|e.mail|邮箱|郵箱/.test(m)) return 90;
    if (/address|地址/.test(m)) return 0;
    if (el.type === "tel" || t.includes("tel") || /phone|mobile|手机|电话/.test(m)) return 70;
    return 0;
  };

  const scopedUserCandidates = inputs
    .filter(el => el !== passwordEl && (!scope || el.form === scope || scope.contains(el)))
    .map(el => ({ el, score: usernameScore(el) }))
    .filter(item => item.score > 0)
    .sort((a, b) => b.score - a.score);

  let usernameEl = scopedUserCandidates[0]?.el || null;
  if (!usernameEl && scope) {
    const plainText = inputs.filter(el => el !== passwordEl && ["text", "email"].includes(el.type) && !isOtp(el)
      && (el.form === scope || scope.contains(el))
      && !/search|coupon|promo|address|city|搜索|地址/.test(meta(el)));
    if (plainText.length === 1) usernameEl = plainText[0];
  }

  if (wantUsername && usernameEl) {
    if (usernameEl.readOnly && usernameEl.value && usernameEl.value !== payload.username) {
      return { ok: false, message: "This login form belongs to a different read-only account" };
    }
    if (setInputValue(usernameEl, payload.username)) {
      filledFields.push("username");
      targetForm ||= usernameEl.form || usernameEl.closest?.("form");
      lastFilledElement = usernameEl;
    }
  }
  if (wantPassword && passwordEl) {
    if (setInputValue(passwordEl, payload.password)) {
      filledFields.push("password");
      targetForm ||= passwordEl.form || passwordEl.closest?.("form");
      lastFilledElement = passwordEl;
    }
  }

  // 2. Fill TOTP/OTP (supports both single OTP input and split 6-digit single-char boxes).
  if (wantTotp) {
    const code = payload.totp.trim();
    const otpCandidates = inputs.filter(el => ["text", "tel", "number", "password"].includes(el.type) && isOtp(el));
    const singleCharBoxes = inputs.filter(el =>
      ["text", "tel", "number"].includes(el.type)
      && (el.maxLength === 1 || el.getAttribute("maxlength") === "1")
      && (isOtp(el) || /(?:code|digit|otp|pin|token|char|box)/i.test(meta(el)) || el.inputMode === "numeric")
    );
    if (singleCharBoxes.length >= code.length && code.length >= 4 && code.length <= 8) {
      for (let i = 0; i < code.length; i++) {
        setInputValue(singleCharBoxes[i], code[i]);
      }
      filledFields.push("totp");
      targetForm ||= singleCharBoxes[0].form || singleCharBoxes[0].closest?.("form");
      lastFilledElement = singleCharBoxes[code.length - 1];
    } else if (otpCandidates.length) {
      if (setInputValue(otpCandidates[0], code)) {
        filledFields.push("totp");
        targetForm ||= otpCandidates[0].form || otpCandidates[0].closest?.("form");
        lastFilledElement = otpCandidates[0];
      }
    }
  }

  if (!filledFields.length) {
    return { ok: false, message: "No matching login or OTP fields were found on this page" };
  }

  let submitted = false;
  if (payload.submit) {
    if (targetForm && typeof targetForm.requestSubmit === "function") {
      setTimeout(() => targetForm.requestSubmit(), 0);
      submitted = true;
    } else {
      const container = scope || lastFilledElement?.closest?.("dialog,[role=dialog],section,[role=form]") || document;
      const submitBtn = [...container.querySelectorAll("button, input[type=submit], [role=button]")]
        .find(btn => isVisible(btn) && !btn.disabled && btn.getAttribute("aria-disabled") !== "true" && (
          btn.type === "submit"
          || /sign[\s-]*in|log[\s-]*in|continue|next|verify|submit|登录|登陆|登入|下一步|继续|验证|提交/i.test(
            `${btn.textContent || ""} ${btn.value || ""} ${btn.getAttribute("aria-label") || ""}`
          )
        ));
      if (submitBtn) {
        setTimeout(() => submitBtn.click(), 0);
        submitted = true;
      }
    }
  }

  return {
    ok: true,
    message: submitted
      ? `Filled ${filledFields.join(", ")} and submitted`
      : `Filled ${filledFields.join(", ")}`,
    data: {
      filledFields,
      submitted,
      url: location.href,
      origin: location.origin,
    },
  };
}

function fillFieldDom(value, submit, payload, expiresAt) {
  if (Number.isFinite(expiresAt) && Date.now() >= expiresAt) {
    return { ok: false, message: "The fill task has expired" };
  }
  const isVisible = (el) => {
    if (!el || el.disabled) return false;
    if (!el.getClientRects?.().length) return false;
    const style = getComputedStyle(el);
    if (style.visibility === "hidden" || style.display === "none" || style.opacity === "0") return false;
    if (el.checkVisibility?.({ checkOpacity: true, checkVisibilityCSS: true }) === false) return false;
    return true;
  };
  const findActive = (root) => {
    const el = root.activeElement;
    return el?.shadowRoot?.activeElement ? findActive(el.shadowRoot) : el;
  };
  const collectEditable = (root, out = []) => {
    for (const el of root.querySelectorAll("*")) {
      if (out.length >= 300) return out;
      if ((el.matches("input, textarea") || el.isContentEditable) && isVisible(el)) {
        if (!el.matches("input") || !["hidden", "submit", "button", "image", "reset", "file", "checkbox", "radio"].includes(el.type)) {
          out.push(el);
        }
      }
      if (el.shadowRoot) collectEditable(el.shadowRoot, out);
    }
    return out;
  };
  const queryDeep = (root, selector) => {
    try {
      const hit = root.querySelector(selector);
      if (hit) return hit;
    } catch { return null; }
    for (const el of root.querySelectorAll("*")) {
      if (el.shadowRoot) {
        const hit = queryDeep(el.shadowRoot, selector);
        if (hit) return hit;
      }
    }
    return null;
  };
  const writeValue = (el, text) => {
    if (!el || !el.isConnected || el.disabled || el.readOnly) return false;
    if (payload?.expectedOrigin && location.origin !== payload.expectedOrigin) return false;
    el.focus();
    const tag = el.tagName?.toLowerCase();
    if (el.isContentEditable) {
      const sel = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(el);
      sel.removeAllRanges();
      sel.addRange(range);
      document.execCommand("insertText", false, text);
      el.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType: "insertText" }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
      return el.isConnected;
    } else {
      const proto = tag === "textarea" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      const desc = Object.getOwnPropertyDescriptor(proto, "value");
      if (!desc?.set || !desc?.get) return false;
      desc.set.call(el, text);
      el.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType: "insertText" }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
      return el.isConnected && (!payload?.expectedOrigin || location.origin === payload.expectedOrigin) && desc.get.call(el) === text;
    }
  };

  let target = null;
  const selector = typeof payload?.selector === "string" ? payload.selector.trim() : "";
  const hint = typeof payload?.fieldHint === "string" ? payload.fieldHint.trim().toLowerCase() : "";
  const moduleKind = typeof payload?.moduleKind === "string" ? payload.moduleKind.trim() : "";

  if (selector) {
    target = selector.startsWith("keylet-control:") ? globalThis.openKeyletControls?.get(selector) : queryDeep(document, selector);
    if (!target) return { ok: false, message: `No element matched selector: ${selector}` };
  }

  // Split OTP boxes support when filling TOTP without explicit selector.
  if (!target && (moduleKind === "totp" || /\b(otp|totp|2fa|code)\b|验证码|动态码/.test(hint))) {
    const all = collectEditable(document);
    const trimmed = value.trim();
    const boxes = all.filter(el => el.matches("input") && (el.maxLength === 1 || el.getAttribute("maxlength") === "1"));
    if (boxes.length >= trimmed.length && trimmed.length >= 4 && trimmed.length <= 8) {
      for (let i = 0; i < trimmed.length; i++) writeValue(boxes[i], trimmed[i]);
      let submitted = false;
      if (submit) {
        const form = boxes[0].form || boxes[0].closest?.("form");
        if (form && typeof form.requestSubmit === "function") {
          setTimeout(() => form.requestSubmit(), 0);
          submitted = true;
        }
      }
      return { ok: true, message: submitted ? "Filled split OTP code and submitted" : "Filled split OTP code", data: { splitBoxes: trimmed.length, submitted } };
    }
  }

  if (!target && hint) {
    const all = collectEditable(document);
    const score = (el) => {
      const text = [
        el.name, el.id, el.autocomplete, el.placeholder, el.getAttribute("aria-label"), el.type,
        ...Array.from(el.labels || [], l => l.textContent),
      ].filter(Boolean).join(" ").toLowerCase();
      if (text.includes(hint)) return 100;
      const words = hint.split(/\s+/).filter(Boolean);
      const hits = words.filter(w => text.includes(w)).length;
      return hits ? hits * 20 : 0;
    };
    const ranked = all.map(el => ({ el, score: score(el) })).filter(x => x.score > 0).sort((a, b) => b.score - a.score);
    target = ranked[0]?.el || null;
  }

  if (!target) {
    const active = findActive(document);
    const tag = active?.tagName?.toLowerCase();
    if (active && active !== document.body && active !== document.documentElement && (tag === "input" || tag === "textarea" || active.isContentEditable)) {
      target = active;
    }
  }

  if (!target && moduleKind) {
    const all = collectEditable(document);
    if (moduleKind === "password") target = all.find(el => el.type === "password") || null;
    else if (moduleKind === "totp") {
      target = all.find(el => (el.autocomplete || "").toLowerCase().includes("one-time-code")
        || /otp|totp|2fa|code|验证|动态码/i.test(`${el.name} ${el.id} ${el.placeholder}`)) || null;
    } else if (moduleKind === "username") {
      target = all.find(el => ["email", "text", "tel"].includes(el.type)
        && /user|email|login|account|账号|邮箱/i.test(`${el.autocomplete} ${el.name} ${el.id} ${el.placeholder}`)) || null;
    }
  }

  if (!target) {
    return { ok: false, message: "No focused or matching input control found on this page" };
  }
  if (!writeValue(target, value)) {
    return { ok: false, message: "The target control does not support safe filling" };
  }
  let submitted = false;
  if (submit) {
    const form = target.form || target.closest?.("form");
    if (form && typeof form.requestSubmit === "function") {
      setTimeout(() => form.requestSubmit(), 0);
      submitted = true;
    } else {
      target.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", code: "Enter", bubbles: true }));
      target.dispatchEvent(new KeyboardEvent("keyup", { key: "Enter", code: "Enter", bubbles: true }));
      submitted = true;
    }
  }
  return {
    ok: true,
    message: submitted ? "Filled and submitted target field" : "Filled target field",
    data: { submitted, url: location.href, origin: location.origin },
  };
}

function clickElementDom(payload, expiresAt) {
  if (Number.isFinite(expiresAt) && Date.now() >= expiresAt) {
    return { ok: false, message: "The click task has expired" };
  }
  const isVisible = (el) => {
    if (!el || el.disabled || el.getAttribute?.("aria-disabled") === "true") return false;
    if (!el.getClientRects?.().length) return false;
    const style = getComputedStyle(el);
    if (style.visibility === "hidden" || style.display === "none" || style.opacity === "0") return false;
    if (el.checkVisibility?.({ checkOpacity: true, checkVisibilityCSS: true }) === false) return false;
    return true;
  };
  const queryDeep = (root, selector) => {
    try {
      const hit = root.querySelector(selector);
      if (hit) return hit;
    } catch { return null; }
    for (const el of root.querySelectorAll("*")) {
      if (el.shadowRoot) {
        const hit = queryDeep(el.shadowRoot, selector);
        if (hit) return hit;
      }
    }
    return null;
  };
  const CLICKABLE_SELECTOR = "button, input[type=submit], input[type=button], input[type=checkbox], input[type=radio], label, a[href], [role=button], [role=checkbox], [role=radio], [role=switch]";
  const collectClickables = (root, out = []) => {
    for (const el of root.querySelectorAll("*")) {
      if (out.length >= 250) return out;
      if (el.matches(CLICKABLE_SELECTOR) && isVisible(el)) {
        out.push(el);
      }
      if (el.shadowRoot) collectClickables(el.shadowRoot, out);
    }
    return out;
  };
  const labelForClickable = (el) => {
    if (el.tagName === "INPUT" && ["checkbox", "radio"].includes(el.type)) {
      const parts = [];
      if (el.getAttribute("aria-label")) parts.push(el.getAttribute("aria-label"));
      for (const lbl of Array.from(el.labels || [])) {
        if (lbl.textContent) parts.push(lbl.textContent.trim());
      }
      const labelledBy = (el.getAttribute("aria-labelledby") || "").split(/\s+/).filter(Boolean).slice(0, 4);
      for (const id of labelledBy) {
        const text = el.getRootNode().getElementById?.(id)?.textContent?.trim();
        if (text) parts.push(text);
      }
      return parts.join(" ").replace(/\s+/g, " ").trim();
    }
    if (el.tagName === "INPUT") {
      return (el.value || el.getAttribute("aria-label") || "").replace(/\s+/g, " ").trim();
    }
    return (el.textContent || el.getAttribute("aria-label") || "").replace(/\s+/g, " ").trim();
  };

  let target = null;
  const selector = typeof payload?.selector === "string" ? payload.selector.trim() : "";
  const text = typeof payload?.text === "string" ? payload.text.trim().toLowerCase() : "";

  if (selector) {
    target = selector.startsWith("keylet-control:") ? globalThis.openKeyletControls?.get(selector) : queryDeep(document, selector);
    if (!target || !isVisible(target)) {
      return { ok: false, message: `No visible clickable element matched selector: ${selector}` };
    }
  } else if (text) {
    const clickables = collectClickables(document);
    target = clickables.find(el => labelForClickable(el).toLowerCase() === text)
      || clickables.find(el => labelForClickable(el).toLowerCase().includes(text))
      || null;
    if (!target) {
      return { ok: false, message: `No visible clickable element matched text: ${payload.text}` };
    }
  } else {
    return { ok: false, message: "Provide selector or text to click" };
  }

  const clickedText = labelForClickable(target).slice(0, 120);
  target.scrollIntoView?.({ block: "center", inline: "center" });
  target.focus?.();
  target.click();
  const data = {
    clickedText,
    tag: target.tagName.toLowerCase(),
    url: location.href,
    origin: location.origin,
  };
  if (target.tagName === "INPUT" && ["checkbox", "radio"].includes(target.type)) {
    data.checked = Boolean(target.checked);
  }
  return {
    ok: true,
    message: `Clicked ${clickedText || target.tagName.toLowerCase()}`,
    data,
  };
}

function waitForTabSettle(tabId, waitMs = 1500, requireNonBlank = false) {
  if (!tabId || waitMs <= 0) return Promise.resolve();
  return new Promise((resolve) => {
    let settled = false;
    const done = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      chrome.tabs.onUpdated.removeListener(onUpdated);
      chrome.tabs.onRemoved.removeListener(onRemoved);
      resolve();
    };
    const onUpdated = (updatedId, changeInfo) => {
      if (updatedId === tabId && changeInfo.status === "complete") done();
    };
    const onRemoved = (removedId) => {
      if (removedId === tabId) done();
    };
    const timer = setTimeout(done, waitMs);
    chrome.tabs.onUpdated.addListener(onUpdated);
    chrome.tabs.onRemoved.addListener(onRemoved);
    chrome.tabs.get(tabId).then((latest) => {
      if (latest?.status === "complete" && (!requireNonBlank || (latest.url && latest.url !== "about:blank"))) {
        done();
      }
    }).catch(done);
  });
}

function isTransientNavigationError(error) {
  const msg = String(error?.message || error || "");
  return /frame.*was removed|frame.*removed|document.*unloaded|back\/forward cache|cannot access contents of url|frame.*not found/i.test(msg);
}

async function openTabJob(payload = {}, expiresAt) {
  if (Number.isFinite(expiresAt) && Date.now() >= expiresAt) {
    return { ok: false, message: "The open tab task has expired" };
  }
  const rawUrl = typeof payload?.url === "string" ? payload.url.trim() : "";
  if (!rawUrl) {
    return { ok: false, message: "A valid HTTP or HTTPS url is required" };
  }
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { ok: false, message: `Invalid URL: ${rawUrl}` };
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    return { ok: false, message: "browser_open only supports http:// and https:// URLs" };
  }

  const explicitTabId = Number.isInteger(payload?.tabId) ? payload.tabId : null;
  const openNewTab = typeof payload?.newTab === "boolean"
    ? payload.newTab
    : explicitTabId === null;

  let tab;
  try {
    if (openNewTab) {
      tab = await chrome.tabs.create({ url: parsed.href, active: true });
    } else if (explicitTabId !== null) {
      tab = await chrome.tabs.update(explicitTabId, { url: parsed.href, active: true });
    } else {
      const existing = await resolveTargetTab({}).catch(() => null);
      if (existing?.id) {
        tab = await chrome.tabs.update(existing.id, { url: parsed.href, active: true });
      } else {
        tab = await chrome.tabs.create({ url: parsed.href, active: true });
      }
    }
  } catch (error) {
    return { ok: false, message: `Unable to open browser tab: ${error?.message || error}` };
  }

  if (!tab?.id) {
    return { ok: false, message: "Browser did not return a tab ID" };
  }

  const maxRemaining = Number.isFinite(expiresAt) ? Math.max(0, expiresAt - Date.now() - 500) : 15000;
  const requestedWait = Number.isFinite(Number(payload?.waitMs)) ? Number(payload.waitMs) : 15000;
  const waitMs = Math.min(Math.max(requestedWait, 0), maxRemaining, 25000);

  if (waitMs > 0) {
    await waitForTabSettle(tab.id, waitMs, true);
  }

  const finalTab = await chrome.tabs.get(tab.id).catch(() => tab);
  const finalUrl = finalTab?.url || parsed.href;
  let finalOrigin = parsed.origin;
  try { finalOrigin = new URL(finalUrl).origin; } catch {}
  return {
    ok: true,
    message: `Opened ${finalOrigin}`,
    data: {
      tabId: tab.id,
      url: urlWithMaskedQuery(finalUrl),
      origin: finalOrigin,
      title: (finalTab?.title || "").slice(0, 160),
    },
  };
}

async function inspectPageJob(payload = {}) {
  let tabs = await listHttpTabs();
  const pendingPasskeys = listPendingCredentialRequests();
  let tab = await resolveTargetTab(payload).catch(() => null);
  if (tab?.id && tab.status === "loading") {
    await waitForTabSettle(tab.id, 1500, false);
    tab = await chrome.tabs.get(tab.id).catch(() => tab);
    tabs = await listHttpTabs();
  }
  if (!tab?.id || !/^https?:\/\//.test(tab.url || "")) {
    return {
      ok: true,
      message: "No active HTTP/HTTPS page",
      data: {
        tabId: tab?.id ?? null,
        url: urlWithMaskedQuery(tab?.url || ""),
        origin: "",
        title: tab?.title || "",
        tabs,
        focused: null,
        loginForms: [],
        otpFieldCount: 0,
        fields: [],
        buttons: [],
        alerts: [],
        pageTextSummary: "",
        frames: [],
        pendingPasskeys,
      },
    };
  }
  try {
    let executions = null;
    let origin = new URL(tab.url).origin;
    let lastError = null;
    for (let attempt = 0; attempt < 4; attempt++) {
      if (attempt > 0) {
        await waitForTabSettle(tab.id, 1200, false);
        await new Promise((r) => setTimeout(r, 120));
        const refreshed = await chrome.tabs.get(tab.id).catch(() => null);
        if (!refreshed?.id || !/^https?:\/\//.test(refreshed.url || "")) {
          break;
        }
        tab = refreshed;
        origin = new URL(tab.url).origin;
        tabs = await listHttpTabs();
      }
      try {
        executions = await chrome.scripting.executeScript({
          target: { tabId: tab.id, allFrames: true },
          func: inspectPageDom,
          args: [origin],
        });
        lastError = null;
        break;
      } catch (error) {
        lastError = error;
        const latestTab = await chrome.tabs.get(tab.id).catch(() => null);
        if (!latestTab?.id) throw error;
        if (!isTransientNavigationError(error) && latestTab.status !== "loading") {
          throw error;
        }
        tab = latestTab;
      }
    }
    if (lastError) throw lastError;
    if (!executions) {
      return {
        ok: true,
        message: "No active HTTP/HTTPS page",
        data: {
          tabId: tab?.id ?? null,
          url: urlWithMaskedQuery(tab?.url || ""),
          origin: "",
          title: tab?.title || "",
          tabs,
          focused: null,
          loginForms: [],
          otpFieldCount: 0,
          fields: [],
          buttons: [],
          alerts: [],
          pageTextSummary: "",
          frames: [],
          pendingPasskeys,
        },
      };
    }
    const topExec = executions.find(e => e.frameId === 0);
    const dom = topExec?.result || {
      url: tab.url,
      origin,
      title: (tab.title || "").slice(0, 160),
      focused: null,
      loginForms: [],
      otpFieldCount: 0,
      fields: [],
      buttons: [],
      alerts: [],
      pageTextSummary: "",
    };

    const mergedFields = [...(dom.fields || [])];
    const mergedButtons = [...(dom.buttons || [])];
    const mergedLoginForms = [...(dom.loginForms || [])];
    const mergedAlerts = [...(dom.alerts || [])];
    const summaryChunks = dom.pageTextSummary ? [dom.pageTextSummary] : [];
    let totalOtp = dom.otpFieldCount || 0;
    let focused = dom.focused || null;
    const frames = [];

    for (const exec of executions) {
      if (exec.frameId === 0 || !exec.result) continue;
      const child = exec.result;
      const childFields = child.fields || [];
      const childButtons = child.buttons || [];
      const childForms = child.loginForms || [];
      const childAlerts = child.alerts || [];
      const childOtp = child.otpFieldCount || 0;
      if (!childFields.length && !childButtons.length && !childForms.length && !childAlerts.length && !child.focused) {
        continue;
      }
      frames.push({
        frameId: exec.frameId,
        frameOrigin: child.origin || "",
        url: urlWithMaskedQuery(child.url || ""),
        // Website rules can match on the query; OpenKeylet removes this before the agent
        // sees the result.
        matchUrl: child.url || "",
        fieldCount: childFields.length,
        buttonCount: childButtons.length,
        otpFieldCount: childOtp,
        hasLoginForm: childForms.length > 0,
      });
      totalOtp += childOtp;
      for (const f of childFields) {
        if (mergedFields.length >= 60) break;
        mergedFields.push({
          ...f,
          index: mergedFields.length,
          frameId: exec.frameId,
          frameOrigin: child.origin || "",
        });
      }
      for (const b of childButtons) {
        if (mergedButtons.length >= 35) break;
        mergedButtons.push({
          ...b,
          index: mergedButtons.length,
          frameId: exec.frameId,
          frameOrigin: child.origin || "",
        });
      }
      for (const lf of childForms) {
        mergedLoginForms.push({
          ...lf,
          index: mergedLoginForms.length,
          frameId: exec.frameId,
          frameOrigin: child.origin || "",
        });
      }
      for (const alert of childAlerts) {
        if (mergedAlerts.length >= 12) break;
        if (!mergedAlerts.includes(alert)) mergedAlerts.push(alert);
      }
      if (child.pageTextSummary && summaryChunks.join(" | ").length < 1500) {
        summaryChunks.push(child.pageTextSummary);
      }
      if (child.focused && (!focused || focused.tag === "iframe")) {
        focused = {
          ...child.focused,
          frameId: exec.frameId,
          frameOrigin: child.origin || "",
        };
      }
    }

    const scrubValues = Array.isArray(dom._scrubValues) ? dom._scrubValues : [];
    const scrubDisplay = (value) => {
      if (!value || !scrubValues.length) return value;
      let out = value;
      for (const sv of scrubValues) {
        if (sv && out.includes(sv)) out = out.split(sv).join("[REDACTED]");
      }
      return out;
    };
    const scrubbedTabs = scrubValues.length
      ? tabs.map(t => ({ ...t, title: scrubDisplay(t.title), url: scrubDisplay(t.url) }))
      : tabs;

    return {
      ok: true,
      message: `Inspected ${origin}`,
      data: {
        tabId: tab.id,
        url: scrubDisplay(urlWithMaskedQuery(dom.url || tab.url)),
        matchUrl: dom.url || tab.url,
        origin: dom.origin || origin,
        title: scrubDisplay(dom.title || (tab.title || "").slice(0, 160)),
        keyCandidates: dom.keyCandidates || [],
        focused,
        loginForms: mergedLoginForms,
        otpFieldCount: totalOtp,
        fields: mergedFields,
        buttons: mergedButtons,
        alerts: mergedAlerts,
        pageTextSummary: summaryChunks.join(" | ").slice(0, 1500),
        frames,
        tabs: scrubbedTabs,
        pendingPasskeys,
      },
    };
  } catch (error) {
    return { ok: false, message: `Unable to inspect page: ${error?.message || error}` };
  }
}

async function fillLoginJob(payload = {}, expiresAt) {
  if (Number.isFinite(expiresAt) && Date.now() >= expiresAt) {
    return { ok: false, message: "The login fill task has expired" };
  }
  let tab;
  try { tab = await resolveTargetTab(payload); } catch (e) { return { ok: false, message: e.message }; }
  if (!tab?.id || !/^https?:\/\//.test(tab.url || "")) {
    return { ok: false, message: "No active HTTP/HTTPS browser tab to fill" };
  }
  const origin = new URL(tab.url).origin;
  if (payload.expectedOrigin && payload.expectedOrigin !== origin) {
    return { ok: false, message: `Active tab origin (${origin}) does not match expected origin (${payload.expectedOrigin})` };
  }
  const explicitFrameId = Number.isInteger(payload.frameId) ? payload.frameId : null;
  const allowedOrigins = Array.isArray(payload.allowedFrameOrigins) && payload.allowedFrameOrigins.length
    ? new Set(payload.allowedFrameOrigins.filter(x => typeof x === "string" && x.trim()))
    : new Set([origin]);
  const frames = (await orderedFramesForTab(tab, origin, explicitFrameId))
    .filter(frame => allowedOrigins.has(frame.origin));
  if (!frames.length) {
    return { ok: false, message: "No browser frame matched this item's allowed website origins" };
  }
  let lastError = "No matching login or OTP fields were found on this page";
  for (const frame of frames) {
    try {
      const [execution] = await chrome.scripting.executeScript({
        target: { tabId: tab.id, frameIds: [frame.frameId] },
        func: fillLoginDom,
        args: [frame.origin, payload, expiresAt],
      });
      const result = execution?.result;
      if (result?.ok) {
        if (result.data?.url) result.data.url = urlWithMaskedQuery(result.data.url);
        if (frame.frameId !== 0 && result.data) {
          result.data.frameId = frame.frameId;
          result.data.frameOrigin = frame.origin;
        }
        return result;
      }
      if (result?.message) {
        lastError = result.message;
        if (/expired|read-only account|origin changed/i.test(result.message)) {
          return result;
        }
      }
    } catch (error) {
      if (frame.frameId === 0) {
        lastError = `Cannot fill login form: ${error?.message || error}`;
      }
    }
  }
  return { ok: false, message: lastError };
}

async function fillFieldJob(value, submit, payload = {}, expiresAt) {
  if (typeof value !== "string") return { ok: false, message: "The fill value is invalid" };
  if (Number.isFinite(expiresAt) && Date.now() >= expiresAt) {
    return { ok: false, message: "The fill task has expired" };
  }
  let tab;
  try { tab = await resolveTargetTab(payload); } catch (e) { return { ok: false, message: e.message }; }
  if (!tab?.id || !/^https?:\/\//.test(tab.url || "")) {
    return { ok: false, message: "No active HTTP/HTTPS browser tab to fill" };
  }
  const origin = new URL(tab.url).origin;
  if (payload.expectedOrigin && payload.expectedOrigin !== origin) {
    return { ok: false, message: `Active tab origin (${origin}) does not match expected origin (${payload.expectedOrigin})` };
  }
  const explicitFrameId = Number.isInteger(payload.frameId) ? payload.frameId : null;
  const focusedFrameId = focusedFrameByTab.get(tab.id);
  const frames = (await orderedFramesForTab(tab, origin, explicitFrameId))
    .filter(frame => frame.origin === origin
      || (explicitFrameId !== null && frame.frameId === explicitFrameId)
      || (Number.isInteger(focusedFrameId) && frame.frameId === focusedFrameId));
  let lastError = "No focused or matching input control found on this page";
  for (const frame of frames) {
    try {
      const [execution] = await chrome.scripting.executeScript({
        target: { tabId: tab.id, frameIds: [frame.frameId] },
        func: fillFieldDom,
        args: [value, Boolean(submit), { ...payload, expectedOrigin: frame.origin }, expiresAt],
      });
      const result = execution?.result;
      if (result?.ok) {
        if (result.data?.url) result.data.url = urlWithMaskedQuery(result.data.url);
        if (frame.frameId !== 0 && result.data) {
          result.data.frameId = frame.frameId;
          result.data.frameOrigin = frame.origin;
        }
        return result;
      }
      if (result?.message) {
        lastError = result.message;
        if (/expired/i.test(result.message)) return result;
      }
    } catch (error) {
      if (frame.frameId === 0) {
        lastError = `Cannot fill target field: ${error?.message || error}`;
      }
    }
  }
  return { ok: false, message: lastError };
}

async function fillPersonalJob(payload = {}, expiresAt) {
  if (Number.isFinite(expiresAt) && Date.now() >= expiresAt) {
    return { ok: false, message: "The personal fill task has expired" };
  }
  let tab;
  try { tab = await resolveTargetTab(payload); } catch (e) { return { ok: false, message: e.message }; }
  if (!tab?.id || !/^https?:\/\//.test(tab.url || "")) {
    return { ok: false, message: "No active HTTP/HTTPS browser tab to fill" };
  }
  const url = new URL(tab.url);
  if (!isSecureOrigin(url.origin)) {
    return { ok: false, message: "Card and identity autofill requires HTTPS or localhost" };
  }
  if (!["card", "identity"].includes(payload.itemType)) {
    return { ok: false, message: "Only card and identity items can be autofilled with fill_personal" };
  }
  const fillFields = { ...(payload.fields || {}) };
  for (const field of ["passportNumber", "licenseNumber", "nationalId"]) delete fillFields[field];
  const frames = await listEligibleFrames(tab.id, url.origin);
  let totalFilled = 0;
  let lastError = null;
  for (const frame of frames) {
    if (!isSecureOrigin(frame.origin)) continue;
    try {
      const [execution] = await chrome.scripting.executeScript({
        target: { tabId: tab.id, frameIds: [frame.frameId] },
        func: usePersonalForm,
        args: [frame.origin, payload.itemType, fillFields],
      });
      totalFilled += execution?.result?.filled || 0;
    } catch (error) {
      if (frame.frameId === 0) lastError = error;
    }
  }
  if (!totalFilled) {
    if (lastError) {
      return { ok: false, message: `Cannot autofill personal fields: ${lastError?.message || lastError}` };
    }
    return { ok: false, message: "No matching card or identity fields were found on this page" };
  }
  return {
    ok: true,
    message: `Filled ${totalFilled} ${payload.itemType} field(s)`,
    data: { filled: totalFilled, itemType: payload.itemType, url: urlWithMaskedQuery(tab.url), origin: url.origin },
  };
}

async function clickJob(payload = {}, expiresAt) {
  if (Number.isFinite(expiresAt) && Date.now() >= expiresAt) {
    return { ok: false, message: "The click task has expired" };
  }
  let tab;
  try { tab = await resolveTargetTab(payload); } catch (e) { return { ok: false, message: e.message }; }
  if (!tab?.id || !/^https?:\/\//.test(tab.url || "")) {
    return { ok: false, message: "No active HTTP/HTTPS browser tab to click" };
  }
  const origin = new URL(tab.url).origin;
  const frames = await orderedFramesForTab(tab, origin, Number.isInteger(payload.frameId) ? payload.frameId : null);
  let lastError = "No visible clickable element matched on this page";
  for (const frame of frames) {
    try {
      const [execution] = await chrome.scripting.executeScript({
        target: { tabId: tab.id, frameIds: [frame.frameId] },
        func: clickElementDom,
        args: [payload, expiresAt],
      });
      const result = execution?.result;
      if (result?.ok) {
        if (result.data?.url) result.data.url = urlWithMaskedQuery(result.data.url);
        if (frame.frameId !== 0 && result.data) {
          result.data.frameId = frame.frameId;
          result.data.frameOrigin = frame.origin;
        }
        return result;
      }
      if (result?.message) {
        lastError = result.message;
        if (/expired|Provide selector or text/i.test(result.message)) return result;
      }
    } catch (error) {
      if (frame.frameId === 0) {
        lastError = `Cannot click target element: ${error?.message || error}`;
      }
    }
  }
  return { ok: false, message: lastError };
}

async function passkeyCaptureJob(payload = {}, expiresAt) {
  try {
    const data = await captureAgentPasskey(payload, expiresAt);
    return { ok: true, message: "Captured WebAuthn passkey request", data };
  } catch (error) {
    return { ok: false, message: error?.message || String(error) };
  }
}

async function passkeyResolveJob(payload = {}) {
  try {
    const data = await resolveAgentPasskey(payload);
    return { ok: true, message: "Completed WebAuthn passkey request", data };
  } catch (error) {
    return { ok: false, message: error?.message || String(error) };
  }
}

async function saveIssuedKeyJob(payload, expiresAt) {
  const { tabId, origin, selectorHint, name } = payload;
  const tab = await chrome.tabs.get(tabId).catch(() => null);
  if (!tab?.url || new URL(tab.url).origin !== origin || !isSecureOrigin(origin)) {
    return { ok: false, message: "The issuing site changed or is unavailable" };
  }
  const status = await bridgeCall("status").catch(() => null);
  if (!status || status.locked) return { ok: false, message: "Unlock the paired extension before saving" };
  const [capture] = await chrome.scripting.executeScript({
    target: { tabId, frameIds: [0] },
    args: [origin, selectorHint],
    func: (expected, handle) => {
      if (location.origin !== expected || window.top !== window) return null;
      let value;
      if (handle) {
        const el = globalThis.openKeyletControls?.get(handle);
        if (!el?.isConnected || !el.matches("output,code,pre,textarea[readonly],input[readonly]:is([type=text],:not([type]))")
            || !el.getClientRects().length || getComputedStyle(el).visibility !== "visible"
            || getComputedStyle(el).opacity === "0"
            || el.checkVisibility?.({ checkOpacity: true, checkVisibilityCSS: true }) === false) return null;
        value = el.matches("input,textarea") ? el.value : el.innerText;
      } else {
        value = window.getSelection()?.toString();
      }
      value = value?.trim();
      return value && value.length <= 16384 && !/\s/.test(value) && !/[•…]|\*{3,}|\.{3,}/.test(value) ? value : null;
    },
  });
  if (!capture?.result) return { ok: false, message: "Choose a visible key field from browser_inspect or select the complete issued key in the page" };
  const [current] = await chrome.scripting.executeScript({
    target: { tabId, frameIds: [0] }, func: () => location.origin,
  });
  if (current?.documentId !== capture.documentId || current?.result !== origin || Date.now() >= expiresAt) {
    return { ok: false, message: "The issuing page changed or the task expired" };
  }
  const result = await bridgeCall("apiKey.save", { origin, name, serviceOrigin: payload.serviceOrigin, value: capture.result }).catch(() => null);
  if (!result) return { ok: false, message: "Could not save the key. Check the lock and use a unique item name." };
  return { ok: true, data: { itemId: result.id } };
}

async function handleBrowserJob(job) {
  const expiresAt = jobExpiresAt(job);
  if (Number.isFinite(expiresAt) && Date.now() >= expiresAt) {
    return { ok: false, message: "The browser task has expired" };
  }
  const kind = job?.kind || "fill_focused";
  switch (kind) {
    case "fill_focused":
      return fillFocused(job?.value, expiresAt, Boolean(job?.submit));
    case "open_tab":
      return openTabJob(job?.payload || {}, expiresAt);
    case "inspect_page":
      return inspectPageJob(job?.payload || {});
    case "fill_login":
      return fillLoginJob(job?.payload || {}, expiresAt);
    case "save_key":
      return saveIssuedKeyJob(job.payload, expiresAt);
    case "save_login":
      return saveCapturedLoginJob(job?.payload || {}, expiresAt);
    case "fill_field":
      return fillFieldJob(job?.value, Boolean(job?.submit), job?.payload || {}, expiresAt);
    case "fill_personal":
      return fillPersonalJob(job?.payload || {}, expiresAt);
    case "click":
      return clickJob(job?.payload || {}, expiresAt);
    case "passkey_capture":
      return passkeyCaptureJob(job?.payload || {}, expiresAt);
    case "passkey_resolve":
      return passkeyResolveJob(job?.payload || {});
    default:
      return { ok: false, message: `Unsupported browser job kind: ${kind}` };
  }
}
