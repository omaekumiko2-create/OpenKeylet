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
        url: tab.url || "",
        origin,
      };
    });
}

async function targetFrameForTab(tab, origin) {
  const preferred = focusedFrameByTab.get(tab.id) ?? 0;
  if (preferred === 0) return { frameId: 0, url: tab.url };
  try {
    const [result] = await chrome.scripting.executeScript({
      target: { tabId: tab.id, frameIds: [preferred] },
      func: () => location.href,
    });
    if (result?.result && new URL(result.result).origin === origin) {
      return { frameId: preferred, url: result.result };
    }
  } catch {}
  return { frameId: 0, url: tab.url };
}

function inspectPageDom(expectedOrigin) {
  if (location.origin !== expectedOrigin) {
    throw new Error("The website changed during inspection");
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
    if (el.name && /^[a-zA-Z0-9_.-]+$/.test(el.name)) return `${tag}[name="${el.name}"]`;
    if (el.autocomplete && el.autocomplete !== "off" && el.autocomplete !== "on") {
      return `${tag}[autocomplete="${el.autocomplete}"]`;
    }
    if (el.type && tag === "input") return `input[type="${el.type}"]`;
    return tag;
  };
  const allInputs = [];
  const allButtons = [];
  function collect(root) {
    for (const el of root.querySelectorAll("*")) {
      if (allInputs.length < 200 && el.matches("input, select, textarea") && isVisible(el)) {
        if (!el.matches("input") || !["hidden", "submit", "button", "image", "reset", "file", "checkbox", "radio"].includes(el.type)) {
          allInputs.push(el);
        }
      }
      if (allButtons.length < 100 && el.matches("button, input[type=submit], input[type=button], a[href], [role=button]") && isVisible(el)) {
        const text = (el.tagName === "INPUT" ? el.value : el.textContent || "").replace(/\s+/g, " ").trim();
        const aria = (el.getAttribute("aria-label") || "").trim();
        if (text || aria) allButtons.push(el);
      }
      if (el.shadowRoot) collect(el.shadowRoot);
    }
  }
  collect(document);

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
  const otpInputs = allInputs.filter(el => el.matches("input") && isOtpInput(el));

  let loginForms = [];
  if (typeof useLoginForm === "function") {
    try {
      const read = useLoginForm("read", expectedOrigin, null, location.href);
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

  const fields = allInputs.slice(0, 40).map((el, index) => ({
    index,
    tag: el.tagName.toLowerCase(),
    type: el.type || "",
    name: (el.name || "").slice(0, 80),
    id: (el.id || "").slice(0, 80),
    autocomplete: (el.autocomplete || "").slice(0, 80),
    placeholder: (el.placeholder || "").slice(0, 80),
    label: labelTextFor(el),
    selectorHint: selectorHintFor(el),
    hasValue: Boolean(el.value),
    focused: el === active,
    readOnly: Boolean(el.readOnly),
  }));

  const buttons = allButtons.slice(0, 25).map((el, index) => ({
    index,
    tag: el.tagName.toLowerCase(),
    type: el.type || "",
    text: ((el.tagName === "INPUT" ? el.value : el.textContent) || "").replace(/\s+/g, " ").trim().slice(0, 100),
    ariaLabel: (el.getAttribute("aria-label") || "").slice(0, 100),
    selectorHint: selectorHintFor(el),
    disabled: Boolean(el.disabled || el.getAttribute("aria-disabled") === "true"),
  }));

  return {
    url: location.href,
    origin: location.origin,
    title: (document.title || "").slice(0, 160),
    focused,
    loginForms,
    otpFieldCount: otpInputs.length,
    fields,
    buttons,
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
    target = queryDeep(document, selector);
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
  const collectClickables = (root, out = []) => {
    for (const el of root.querySelectorAll("*")) {
      if (out.length >= 200) return out;
      if (el.matches("button, input[type=submit], input[type=button], a[href], [role=button]") && isVisible(el)) {
        out.push(el);
      }
      if (el.shadowRoot) collectClickables(el.shadowRoot, out);
    }
    return out;
  };

  let target = null;
  const selector = typeof payload?.selector === "string" ? payload.selector.trim() : "";
  const text = typeof payload?.text === "string" ? payload.text.trim().toLowerCase() : "";

  if (selector) {
    target = queryDeep(document, selector);
    if (!target || !isVisible(target)) {
      return { ok: false, message: `No visible clickable element matched selector: ${selector}` };
    }
  } else if (text) {
    const clickables = collectClickables(document);
    const labelOf = (el) => ((el.tagName === "INPUT" ? el.value : el.textContent) || el.getAttribute("aria-label") || "")
      .replace(/\s+/g, " ").trim().toLowerCase();
    target = clickables.find(el => labelOf(el) === text)
      || clickables.find(el => labelOf(el).includes(text))
      || null;
    if (!target) {
      return { ok: false, message: `No visible clickable element matched text: ${payload.text}` };
    }
  } else {
    return { ok: false, message: "Provide selector or text to click" };
  }

  const clickedText = ((target.tagName === "INPUT" ? target.value : target.textContent) || target.getAttribute("aria-label") || "")
    .replace(/\s+/g, " ").trim().slice(0, 120);
  target.scrollIntoView?.({ block: "center", inline: "center" });
  target.focus?.();
  target.click();
  return {
    ok: true,
    message: `Clicked ${clickedText || target.tagName.toLowerCase()}`,
    data: {
      clickedText,
      tag: target.tagName.toLowerCase(),
      url: location.href,
      origin: location.origin,
    },
  };
}

async function inspectPageJob(payload = {}) {
  const tabs = await listHttpTabs();
  const pendingPasskeys = listPendingCredentialRequests();
  const tab = await resolveTargetTab(payload).catch(() => null);
  if (!tab?.id || !/^https?:\/\//.test(tab.url || "")) {
    return {
      ok: true,
      message: "No active HTTP/HTTPS page",
      data: {
        tabId: tab?.id ?? null,
        url: tab?.url || "",
        origin: "",
        title: tab?.title || "",
        tabs,
        focused: null,
        loginForms: [],
        otpFieldCount: 0,
        fields: [],
        buttons: [],
        pendingPasskeys,
      },
    };
  }
  const origin = new URL(tab.url).origin;
  const target = await targetFrameForTab(tab, origin);
  try {
    const [execution] = await chrome.scripting.executeScript({
      target: { tabId: tab.id, frameIds: [target.frameId] },
      func: inspectPageDom,
      args: [origin],
    });
    const dom = execution?.result || {};
    return {
      ok: true,
      message: `Inspected ${origin}`,
      data: {
        tabId: tab.id,
        ...dom,
        tabs,
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
  const target = await targetFrameForTab(tab, origin);
  try {
    const [execution] = await chrome.scripting.executeScript({
      target: { tabId: tab.id, frameIds: [target.frameId] },
      func: fillLoginDom,
      args: [origin, payload, expiresAt],
    });
    return execution?.result || { ok: false, message: "The page did not return a login fill result" };
  } catch (error) {
    return { ok: false, message: `Cannot fill login form: ${error?.message || error}` };
  }
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
  const target = await targetFrameForTab(tab, origin);
  try {
    const [execution] = await chrome.scripting.executeScript({
      target: { tabId: tab.id, frameIds: [target.frameId] },
      func: fillFieldDom,
      args: [value, Boolean(submit), { ...payload, expectedOrigin: origin }, expiresAt],
    });
    return execution?.result || { ok: false, message: "The page did not return a fill result" };
  } catch (error) {
    return { ok: false, message: `Cannot fill target field: ${error?.message || error}` };
  }
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
  if (url.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) {
    return { ok: false, message: "Card and identity autofill requires HTTPS or localhost" };
  }
  if (!["card", "identity"].includes(payload.itemType)) {
    return { ok: false, message: "Only card and identity items can be autofilled with fill_personal" };
  }
  const fillFields = { ...(payload.fields || {}) };
  for (const field of ["passportNumber", "licenseNumber", "nationalId"]) delete fillFields[field];
  const target = await targetFrameForTab(tab, url.origin);
  try {
    const [execution] = await chrome.scripting.executeScript({
      target: { tabId: tab.id, frameIds: [target.frameId] },
      func: usePersonalForm,
      args: [url.origin, payload.itemType, fillFields],
    });
    const filled = execution?.result?.filled || 0;
    if (!filled) return { ok: false, message: "No matching card or identity fields were found on this page" };
    return {
      ok: true,
      message: `Filled ${filled} ${payload.itemType} field(s)`,
      data: { filled, itemType: payload.itemType, url: tab.url, origin: url.origin },
    };
  } catch (error) {
    return { ok: false, message: `Cannot autofill personal fields: ${error?.message || error}` };
  }
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
  const target = await targetFrameForTab(tab, origin);
  try {
    const [execution] = await chrome.scripting.executeScript({
      target: { tabId: tab.id, frameIds: [target.frameId] },
      func: clickElementDom,
      args: [payload, expiresAt],
    });
    return execution?.result || { ok: false, message: "The page did not return a click result" };
  } catch (error) {
    return { ok: false, message: `Cannot click target element: ${error?.message || error}` };
  }
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

async function handleBrowserJob(job) {
  const expiresAt = jobExpiresAt(job);
  if (Number.isFinite(expiresAt) && Date.now() >= expiresAt) {
    return { ok: false, message: "The browser task has expired" };
  }
  const kind = job?.kind || "fill_focused";
  switch (kind) {
    case "fill_focused":
      return fillFocused(job?.value, expiresAt, Boolean(job?.submit));
    case "inspect_page":
      return inspectPageJob(job?.payload || {});
    case "fill_login":
      return fillLoginJob(job?.payload || {}, expiresAt);
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
