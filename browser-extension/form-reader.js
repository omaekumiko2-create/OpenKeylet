// Self-contained: also serialized by chrome.scripting for an explicit owner read.
function useLoginForm(mode, expectedOrigin, login, expectedUrl, submittedScope) {
  if (location.origin !== expectedOrigin || (expectedUrl && location.href !== expectedUrl))
    throw new Error("网页已经变化，请重新读取 / The page changed; read the form again");
  const inputs = [];
  function collect(root) {
    for (const element of root.querySelectorAll("*")) {
      if (inputs.length >= 500) return;
      if (element.matches("input") && !element.disabled && element.getClientRects().length
          && element.checkVisibility?.({ checkOpacity: true, checkVisibilityCSS: true }) !== false)
        inputs.push(element);
      if (element.shadowRoot) collect(element.shadowRoot);
    }
  }
  collect(document);
  const tokens = element => (element.autocomplete || "").toLowerCase().split(/\s+/).filter(Boolean);
  const metadata = element => [
    element.name, element.id, element.getAttribute("aria-label"), element.placeholder,
    ...Array.from(element.labels || [], label => label.textContent.slice(0, 200)),
    ...(element.getAttribute("aria-labelledby") || "").split(/\s+/).filter(Boolean).slice(0, 8)
      .map(id => element.getRootNode().getElementById?.(id)?.textContent?.slice(0, 200)),
  ].filter(Boolean).join(" ").slice(0, 1000).replace(/([a-z])([A-Z])/g, "$1 $2").toLowerCase();
  const excluded = element => tokens(element).some(t => t === "one-time-code" || t.startsWith("cc-"))
    || /(?:^|[\s_.\[\]-])(?:otp|cvv|cvc|captcha|verification|pin|one.time)(?:$|[\s_.\[\]-])|验证码|驗證碼|动态码|動態碼|安全码/.test(metadata(element));
  const inScope = element => !submittedScope || (submittedScope instanceof HTMLFormElement
    ? element.form === submittedScope : submittedScope.contains(element));
  const passwords = inputs.filter(element => inScope(element) && !excluded(element)
    && (element.type === "password" || (element.type === "text"
      && (tokens(element).some(t => ["current-password", "new-password"].includes(t))
        || /(?:^|[\s_.\[\]-])(?:password|passwd|pwd)(?:$|[\s_.\[\]-])/.test(metadata(element))))));
  let active = document.activeElement;
  while (active?.shadowRoot?.activeElement) active = active.shadowRoot.activeElement;
  function groupFor(element) {
    if (submittedScope && inScope(element)) return submittedScope;
    return element.form || element.closest("dialog,[role=dialog],section,[role=form]") || element.getRootNode();
  }
  function usernameScore(element) {
    const hints = tokens(element), info = metadata(element);
    if (hints.includes("username")) return 120;
    if (hints.some(t => !["on", "off", "email", "tel", "webauthn"].includes(t) && !t.startsWith("section-"))) return 0;
    if (/search|coupon|promo|first.?name|last.?name|city|搜索|优惠|姓名/.test(info)) return 0;
    if (/username|user.?name|user.?id|login|account|identifier|(?:^|[\s_.\[\]-])(?:user|uid)(?:$|[\s_.\[\]-])|账号|帳號|账户|帳戶|用户名|用戶名|ユーザー名/.test(info)) return 100;
    if (element.type === "email" || hints.includes("email") || /email|e.mail|邮箱|郵箱/.test(info)) return 90;
    if (/address|地址/.test(info)) return 0;
    if (element.type === "tel" || hints.includes("tel") || /phone|mobile|手机|電話|电话/.test(info)) return 70;
    return 0;
  }
  function rankUsernames(elements) {
    return elements.map(element => ({ element, score: usernameScore(element) }))
      .filter(item => item.score > 0).sort((a, b) => b.score - a.score);
  }
  const groups = new Map();
  for (const password of passwords) {
    const key = groupFor(password);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(password);
  }
  const forms = [];
  const references = [];
  for (const [group, fields] of groups) {
    if (forms.length >= 12) break;
    const classification = element => {
      const info = metadata(element);
      if (/confirm|repeat|retype|确认|確認|重复|重複|再次/.test(info)) return "confirm";
      if (tokens(element).includes("new-password") || /new[\s_-]*(?:pass|pwd)|(?:pass|pwd)[\s_-]*new|新密码|新密碼/.test(info)) return "new";
      if (tokens(element).includes("current-password") || /(?:old|current)[\s_-]*(?:pass|pwd)|旧密码|舊密碼|原密码/.test(info)) return "current";
      return "password";
    };
    const newFields = fields.filter(element => classification(element) === "new");
    const confirmations = fields.filter(element => classification(element) === "confirm");
    const candidates = newFields.length ? newFields : fields.filter(element => classification(element) !== "confirm");
    const password = candidates[0];
    if (!password) continue;
    const warnings = [];
    const values = [...new Set(candidates.map(element => element.value).filter(Boolean))];
    if (values.length > 1) warnings.push("识别到不同的密码，请手动确认 / Multiple different passwords; check manually");
    const confirmationMismatch = [...confirmations, ...newFields.slice(1)]
      .some(element => element.value && element.value !== password.value);
    if (confirmationMismatch) warnings.push("两次输入的密码不一致 / Password confirmation does not match");
    const usernameFields = inputs.filter(element => inScope(element) && ["text", "email", "tel"].includes(element.type)
      && groupFor(element) === group && !fields.includes(element) && !excluded(element));
    const ranked = rankUsernames(usernameFields);
    let username = ranked[0]?.element;
    if (!username && usernameFields.length === 1 && usernameFields[0].type === "text"
        && !/search|coupon|promo|address|name|city|搜索|优惠|地址|姓名/.test(metadata(usernameFields[0]))
        && !tokens(usernameFields[0]).some(t => t && !["on", "off"].includes(t)))
      username = usernameFields[0];
    const ambiguousUsername = ranked.length > 1 && ranked[0].score === ranked[1].score
      && ranked[0].element.value !== ranked[1].element.value;
    if (ambiguousUsername) warnings.push("账号字段不明确，请手动确认 / Check the account field");
    const usernameTooLong = (username?.value.length || 0) > 4096;
    if (usernameTooLong || password.value.length > 16384)
      warnings.push("字段超过支持长度，请手动确认 / Field exceeds the supported length");
    const hasCurrent = fields.some(element => classification(element) === "current");
    const kind = newFields.length ? (hasCurrent ? "change" : "signup")
      : confirmations.length ? "signup" : "login";
    forms.push({
      username: ambiguousUsername || usernameTooLong ? "" : (username?.value || ""),
      password: warnings.length ? "" : password.value,
      kind, warnings,
      usernamePresent: Boolean(username),
      focused: fields.includes(active) || usernameFields.includes(active),
    });
    references.push({ username, password, fields, classification, ambiguousUsername });
  }
  const selectedIndex = Math.max(0, forms.findIndex(form => form.focused));
  const stepCandidates = passwords.length ? [] : rankUsernames(inputs.filter(element => inScope(element)
    && ["text", "email", "tel"].includes(element.type) && !excluded(element)));
  const step = stepCandidates.length === 1 && stepCandidates[0].score >= 90 ? stepCandidates[0].element : null;
  if (mode !== "fill") return { forms, selectedIndex,
    usernameStep: step?.value && step.value.length <= 4096 ? step.value : "" };
  let username = references[selectedIndex]?.username || step, password;
  if (references[selectedIndex]) {
    const selected = references[selectedIndex];
    if (forms[selectedIndex].kind === "signup" || selected.ambiguousUsername
        || (selected.fields.includes(active) && ["new", "confirm"].includes(selected.classification(active))))
      throw new Error("请手动检查注册或改密表单 / Check the new-password form manually");
    const current = selected.fields.filter(element => ["current", "password"].includes(selected.classification(element)));
    password = current.includes(active) ? active : current.find(element => selected.classification(element) === "current") || (current.length === 1 ? current[0] : null);
    if (!password) throw new Error("无法明确选择密码字段，请先聚焦 / Focus the password field first");
  }
  if (!username && !password) throw new Error("No login fields found; focus a login field and try again");
  if (username?.readOnly && username.value && username.value !== login.username)
    throw new Error("网页显示的是另一个账号 / This form belongs to a different account");
  function set(element, value) {
    if (!element || element.readOnly) return;
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(element, value);
    element.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType: "insertText" }));
    element.dispatchEvent(new Event("change", { bubbles: true }));
  }
  set(username, login.username); set(password, login.password);
  return { filled: true };
}
function readLoginForms(expectedOrigin, expectedUrl, submittedScope) {
  return useLoginForm("read", expectedOrigin, null, expectedUrl, submittedScope);
}

function prepareCredentialField(expectedOrigin, expectedTopUrl, expectedUrl, operationId, fieldToken, module) {
  const activeElement = (root = document) => {
    let element = root.activeElement;
    while (element?.shadowRoot?.activeElement) element = element.shadowRoot.activeElement;
    return element;
  };
  const expectedDocument = () => {
    try {
      return location.origin === expectedOrigin
        && location.href === expectedUrl
        && window.top.location.href === expectedTopUrl
        && new URL(expectedTopUrl).origin === expectedOrigin
        && document.hasFocus()
        && (!window.frameElement || window.top.document.activeElement === window.frameElement);
    } catch {
      return false;
    }
  };
  const matchesRole = (element, role) => {
    if (!(element instanceof HTMLInputElement) || !element.isConnected || element.disabled || element.readOnly) return false;
    if (!element.getClientRects().length || getComputedStyle(element).visibility !== "visible"
        || element.checkVisibility?.({ checkOpacity: true, checkVisibilityCSS: true }) === false) return false;
    const type = (element.type || "").toLowerCase();
    const autocomplete = (element.getAttribute("autocomplete") || "").toLowerCase().split(/\s+/);
    const hints = [element.id, element.name, element.getAttribute("aria-label"), element.getAttribute("placeholder"),
      ...(element.labels ? Array.from(element.labels).map(label => label.textContent || "") : [])].join(" ").toLowerCase();
    if (role === "password") return type === "password" && !autocomplete.includes("new-password")
      && !/(new|confirm|repeat|verify)[\s_-]*password/.test(hints);
    if (role === "username") return ["text", "email", "tel"].includes(type)
      && (autocomplete.includes("username") || /(user(name)?|login|account|e-?mail)/.test(hints));
    return false;
  };

  if (!expectedDocument() || !/^[0-9a-f-]{36}$/i.test(operationId || "")
      || !/^[0-9a-f-]{36}$/i.test(fieldToken || "") || !["username", "password"].includes(module)) {
    return { ok: false, fieldRole: module };
  }
  const element = activeElement(document);
  if (!matchesRole(element, module)) return { ok: false, fieldRole: module };
  const tokenKey = "__openkeyletCredentialTarget_" + operationId.replace(/[^a-z0-9]/gi, "")
    + "_" + fieldToken.replace(/[^a-z0-9]/gi, "");
  try {
    Object.defineProperty(element, tokenKey, {
      value: fieldToken,
      enumerable: false,
      configurable: false,
      writable: false,
    });
  } catch {
    return { ok: false, fieldRole: module };
  }
  return { ok: true, fieldRole: module };
}

function fillCredentialField(expectedOrigin, expectedTopUrl, expectedUrl, operationId, fieldToken, module, value, expiresAt) {
  const activeElement = (root = document) => {
    let element = root.activeElement;
    while (element?.shadowRoot?.activeElement) element = element.shadowRoot.activeElement;
    return element;
  };
  const expectedDocument = () => {
    try {
      return location.origin === expectedOrigin
        && location.href === expectedUrl
        && window.top.location.href === expectedTopUrl
        && new URL(expectedTopUrl).origin === expectedOrigin
        && document.hasFocus()
        && (!window.frameElement || window.top.document.activeElement === window.frameElement);
    } catch {
      return false;
    }
  };
  const matchesRole = (element, role) => {
    if (!(element instanceof HTMLInputElement) || !element.isConnected || element.disabled || element.readOnly) return false;
    if (!element.getClientRects().length || getComputedStyle(element).visibility !== "visible"
        || element.checkVisibility?.({ checkOpacity: true, checkVisibilityCSS: true }) === false) return false;
    const type = (element.type || "").toLowerCase();
    const autocomplete = (element.getAttribute("autocomplete") || "").toLowerCase().split(/\s+/);
    const hints = [element.id, element.name, element.getAttribute("aria-label"), element.getAttribute("placeholder"),
      ...(element.labels ? Array.from(element.labels).map(label => label.textContent || "") : [])].join(" ").toLowerCase();
    if (role === "password") return type === "password" && !autocomplete.includes("new-password")
      && !/(new|confirm|repeat|verify)[\s_-]*password/.test(hints);
    if (role === "username") return ["text", "email", "tel"].includes(type)
      && (autocomplete.includes("username") || /(user(name)?|login|account|e-?mail)/.test(hints));
    return false;
  };

  if (!expectedDocument() || Date.now() >= expiresAt || typeof value !== "string" || value.length === 0
      || !/^[0-9a-f-]{36}$/i.test(operationId || "") || !/^[0-9a-f-]{36}$/i.test(fieldToken || "")) {
    return { delivered: false, fieldRole: module };
  }
  const tokenKey = "__openkeyletCredentialTarget_" + operationId.replace(/[^a-z0-9]/gi, "")
    + "_" + fieldToken.replace(/[^a-z0-9]/gi, "");
  const element = activeElement(document);
  if (!matchesRole(element, module) || element[tokenKey] !== fieldToken) {
    return { delivered: false, fieldRole: module };
  }
  const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
  if (!descriptor?.set || !descriptor?.get) return { delivered: false, fieldRole: module };
  try {
    descriptor.set.call(element, value);
    element.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType: "insertText" }));
    element.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
    return {
      delivered: descriptor.get.call(element) === value && element.isConnected
        && element[tokenKey] === fieldToken && activeElement(document) === element,
      fieldRole: module,
    };
  } catch {
    return { delivered: false, fieldRole: module };
  }
}

function verifyCredentialField(expectedOrigin, expectedTopUrl, expectedUrl, operationId, fieldToken, module, value, expiresAt) {
  const activeElement = (root = document) => {
    let element = root.activeElement;
    while (element?.shadowRoot?.activeElement) element = element.shadowRoot.activeElement;
    return element;
  };
  const expectedDocument = () => {
    try {
      return location.origin === expectedOrigin
        && location.href === expectedUrl
        && window.top.location.href === expectedTopUrl
        && new URL(expectedTopUrl).origin === expectedOrigin
        && document.hasFocus()
        && (!window.frameElement || window.top.document.activeElement === window.frameElement);
    } catch {
      return false;
    }
  };
  const tokenKey = "__openkeyletCredentialTarget_" + operationId.replace(/[^a-z0-9]/gi, "")
    + "_" + fieldToken.replace(/[^a-z0-9]/gi, "");
  if (!expectedDocument() || Date.now() >= expiresAt || typeof value !== "string"
      || !/^[0-9a-f-]{36}$/i.test(operationId || "") || !/^[0-9a-f-]{36}$/i.test(fieldToken || "")) {
    return { readback: false, fieldRole: module };
  }
  const element = activeElement(document);
  const type = (element?.type || "").toLowerCase();
  const autocomplete = (element?.getAttribute("autocomplete") || "").toLowerCase().split(/\s+/);
  const roleMatches = module === "password"
    ? type === "password" && !autocomplete.includes("new-password")
    : module === "username" && ["text", "email", "tel"].includes(type);
  if (!(element instanceof HTMLInputElement) || !element.isConnected || element.disabled || element.readOnly
      || !element.getClientRects().length || getComputedStyle(element).visibility !== "visible"
      || !roleMatches || element[tokenKey] !== fieldToken) {
    return { readback: false, fieldRole: module };
  }
  const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
  if (!descriptor?.get) return { readback: false, fieldRole: module };
  try {
    return {
      readback: descriptor.get.call(element) === value && element.isConnected
        && element[tokenKey] === fieldToken && activeElement(document) === element,
      fieldRole: module,
    };
  } catch {
    return { readback: false, fieldRole: module };
  }
}
