function reportFocus() {
  chrome.runtime.sendMessage({ type: "openkeylet-focus" }).catch(() => {});
}

document.addEventListener("focusin", reportFocus, true);
window.addEventListener("focus", reportFocus, true);

if (document.hasFocus()) reportFocus();

// Opt-in only: sample submit/click/Enter actions, never values while typing.
const interactedLoginForms = new WeakSet();
const observedFormRoots = new WeakSet();
let captureSubmissionEnabled = false;
let capturePreferenceReceived = false;
chrome.runtime.onMessage.addListener((message, sender) => {
  if (sender.id === chrome.runtime.id && message?.type === "openkeylet-capture-preferences") {
    capturePreferenceReceived = true;
    captureSubmissionEnabled = message.enabled === true;
  }
});
chrome.runtime.sendMessage({ type: "openkeylet-capture-preferences" }).then(reply => {
  if (!capturePreferenceReceived) captureSubmissionEnabled = reply?.ok && reply.result?.enabled === true;
}).catch(() => {});
function rememberForm(form) {
  if (!form) return;
  interactedLoginForms.add(form);
  const root = form.getRootNode();
  if (root !== document && !observedFormRoots.has(root)) {
    observedFormRoots.add(root);
    root.addEventListener("submit", captureSubmittedForm, true);
  }
}
document.addEventListener("input", event => {
  const input = event.composedPath()[0];
  if (event.isTrusted && input instanceof HTMLInputElement && input.form)
    rememberForm(input.form);
}, true);
document.addEventListener("click", event => {
  if (!event.isTrusted) return;
  const button = event.composedPath().find(element => element instanceof HTMLElement
    && element.matches("button,input[type=submit],input[type=image],[role=button]"));
  if (!button || button.matches(":disabled") || button.getAttribute("aria-disabled") === "true") return;
  if (button?.form && ["submit", "image"].includes(button.type)) rememberForm(button.form);
  const label = [button.textContent, button.value, button.getAttribute("aria-label")].join(" ").slice(0, 300);
  if ((button.form && ["submit", "image"].includes(button.type))
      || /sign[\s-]*in|log[\s-]*in|sign[\s-]*up|register|create.*account|change.*password|save.*password|next|continue|登录|登陆|登入|注册|註冊|下一步|继续|繼續|修改密码|保存密码|ログイン|サインイン|次へ/.test(label.toLowerCase()))
    captureLoginScope(authScope(button), label);
}, true);
function authScope(element) {
  if (element.form) return element.form;
  const declared = element.closest("[role=form],dialog,section");
  if (declared) return declared;
  let parent = element.parentElement;
  while (parent && !parent.querySelector("input")) parent = parent.parentElement;
  return parent;
}
function captureLoginScope(scope, label = "") {
  if (!captureSubmissionEnabled || !scope) return;
  const url = new URL(location.href);
  if (url.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) return;
  const controls = scope instanceof HTMLFormElement ? [...scope.elements] : [...scope.querySelectorAll("input")];
  if (controls.some(input => input.willValidate && !input.validity.valid)) return;
  const result = readLoginForms(location.origin, location.href, scope);
  if (!result.forms.length && result.usernameStep
      && /next|continue|sign[\s-]*in|log[\s-]*in|下一步|继续|繼續|登录|登入|次へ|ログイン/.test(label.toLowerCase())) {
    chrome.runtime.sendMessage({ type: "openkeylet-username-step", username: result.usernameStep }).catch(() => {});
    return;
  }
  if (result.forms.length !== 1 || !result.forms[0].password || result.forms[0].warnings.length) return;
  const { username, password, kind, usernamePresent } = result.forms[0];
  chrome.runtime.sendMessage({ type: "openkeylet-login-submitted", form: { username, password, kind, usernamePresent } }).catch(() => {});
}
document.addEventListener("keydown", event => {
  if (!event.isTrusted || event.key !== "Enter" || event.isComposing || event.ctrlKey || event.altKey || event.metaKey) return;
  const input = event.composedPath()[0];
  if (!(input instanceof HTMLInputElement) || !/password|username|email|login|account|identifier/.test(
      `${input.type} ${input.autocomplete} ${input.name} ${input.id}`.toLowerCase())) return;
  captureLoginScope(authScope(input), "continue");
}, true);
function captureSubmittedForm(event) {
  const form = event.target;
  if (!captureSubmissionEnabled || !event.isTrusted || !(form instanceof HTMLFormElement) || !interactedLoginForms.has(form)) return;
  captureLoginScope(form, event.submitter?.textContent || event.submitter?.value || "");
}
document.addEventListener("submit", captureSubmittedForm, true);

let saveNotice;
function showSaveNotice(available) {
  if (window !== window.top) return;
  if (!available) { saveNotice?.remove(); saveNotice = null; return; }
  if (saveNotice?.isConnected || !document.documentElement) return;
  saveNotice = document.createElement("div");
  saveNotice.setAttribute("data-openkeylet-save-notice", "");
  saveNotice.style.cssText = "all:initial!important;position:fixed!important;right:16px!important;bottom:16px!important;z-index:2147483647!important;";
  const shadow = saveNotice.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = ":host{color-scheme:dark}section{box-sizing:border-box;width:min(340px,calc(100vw - 32px));padding:15px 16px;border:1px solid #27272e;border-radius:12px;background:#0d0d10;color:#f4f4f5;box-shadow:0 16px 40px rgba(0,0,0,.65);font:13px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}strong{display:block;color:#f4f4f5;font-weight:600;letter-spacing:-.02em}p{margin:6px 0 12px;color:#a1a1aa}button{font:inherit;font-size:12px;font-weight:600;cursor:pointer;border:1px solid #2e2e36;border-radius:8px;background:#1b1b1f;color:#f4f4f5;padding:7px 12px;margin-right:8px}button:first-of-type{background:#f4f4f5;color:#09090b;border-color:transparent}button:focus-visible{outline:2px solid #f4f4f5;outline-offset:2px}";
  const section = document.createElement("section");
  section.setAttribute("role", "status");
  const title = document.createElement("strong"); title.textContent = "OpenKeylet · 保存登录信息";
  const description = document.createElement("p");
  description.textContent = "检测到已提交的账号信息。打开插件预览，确认后保存。";
  const review = document.createElement("button"); review.type = "button"; review.textContent = "预览保存 / Review";
  const dismiss = document.createElement("button"); dismiss.type = "button"; dismiss.textContent = "忽略 / Dismiss";
  review.addEventListener("click", event => {
    if (event.isTrusted) chrome.runtime.sendMessage({ type: "openkeylet-capture-review" }).then(reply => {
      if (reply?.result?.available === false) showSaveNotice(false);
    }).catch(() => {});
  });
  dismiss.addEventListener("click", event => {
    if (event.isTrusted) chrome.runtime.sendMessage({ type: "openkeylet-capture-dismiss" }).catch(() => {});
  });
  section.append(title, description, review, dismiss);
  shadow.append(style, section);
  document.documentElement.append(saveNotice);
}
chrome.runtime.onMessage.addListener((message, sender) => {
  if (sender.id === chrome.runtime.id && message?.type === "openkeylet-capture-notice")
    showSaveNotice(message.available === true);
});
async function restoreSaveNotice() {
  if (window !== window.top) return;
  const reply = await chrome.runtime.sendMessage({ type: "openkeylet-capture-status" }).catch(() => null);
  showSaveNotice(reply?.ok && reply.result?.available);
}
if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", restoreSaveNotice, { once: true });
else restoreSaveNotice();

window.addEventListener("message", async event => {
  if (window !== window.top || event.source !== window || event.origin !== location.origin) return;
  const m = event.data;
  if (m?.type === "openkeylet-webauthn-cancel") { chrome.runtime.sendMessage({ type:m.type, requestId:m.requestId }).catch(() => {}); return; }
  if (m?.type !== "openkeylet-webauthn-call" || typeof m.requestId !== "string" || !["create","get"].includes(m.operation)) return;
  let result;
  try {
    const reply = await chrome.runtime.sendMessage({ type: "openkeylet-webauthn", requestId:m.requestId, operation:m.operation, options:m.options });
    result = reply?.ok ? reply.result : { error: reply?.error || "OpenKeylet request failed" };
  } catch { result = { fallback:true }; }
  window.postMessage({ type:"openkeylet-webauthn-result", requestId:m.requestId, result }, location.origin);
});
