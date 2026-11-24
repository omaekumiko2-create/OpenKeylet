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

const NOTICE_STRINGS = {
  en: {
    title: "OpenKeylet · Save login",
    desc: "Submitted login detected. Review and confirm before saving locally.",
    review: "Review & save",
    dismiss: "Dismiss",
  },
  zh: {
    title: "OpenKeylet · 保存登录信息",
    desc: "检测到已提交的账号信息。预览确认后才会写入本地密码库。",
    review: "预览并保存",
    dismiss: "忽略",
  },
  "zh-TW": {
    title: "OpenKeylet · 儲存登入資訊",
    desc: "偵測到已提交的帳號資訊。預覽確認後才會寫入本機密碼庫。",
    review: "預覽並儲存",
    dismiss: "忽略",
  },
  ja: {
    title: "OpenKeylet · ログインを保存",
    desc: "送信されたログイン情報を検出しました。確認後にローカルへ保存されます。",
    review: "確認して保存",
    dismiss: "閉じる",
  },
  ko: {
    title: "OpenKeylet · 로그인 저장",
    desc: "제출된 로그인 정보가 감지되었습니다. 확인 후 로컬 보관함에 저장됩니다.",
    review: "검토 및 저장",
    dismiss: "무시",
  },
  es: {
    title: "OpenKeylet · Guardar acceso",
    desc: "Inicio de sesión detectado. Revisa y confirma antes de guardar localmente.",
    review: "Revisar y guardar",
    dismiss: "Descartar",
  },
};

function resolveNoticeLang(storedSetting) {
  const normalize = (raw) => {
    const lower = String(raw || "").trim().toLowerCase();
    if (!lower || lower === "auto" || lower === "system") return null;
    if (["zh-tw", "zh_tw", "zh-hk", "zh_hk", "zh-hant", "zh_hant"].some(p => lower === p || lower.startsWith(`${p}-`))) return "zh-TW";
    if (lower === "zh" || lower.startsWith("zh-") || lower.startsWith("zh_")) return "zh";
    if (lower === "ja" || lower.startsWith("ja-") || lower.startsWith("ja_")) return "ja";
    if (lower === "ko" || lower.startsWith("ko-") || lower.startsWith("ko_")) return "ko";
    if (lower === "es" || lower.startsWith("es-") || lower.startsWith("es_")) return "es";
    if (lower === "en" || lower.startsWith("en-") || lower.startsWith("en_")) return "en";
    return null;
  };
  const explicit = normalize(storedSetting);
  if (explicit) return explicit;
  const list = Array.isArray(navigator.languages) && navigator.languages.length
    ? navigator.languages
    : [navigator.language || "en"];
  for (const raw of list) {
    const detected = normalize(raw);
    if (detected) return detected;
  }
  return "en";
}

let saveNotice;
async function showSaveNotice(available) {
  if (window !== window.top) return;
  if (!available) { saveNotice?.remove(); saveNotice = null; return; }
  if (saveNotice?.isConnected || !document.documentElement) return;
  let storedLang = "auto";
  try {
    const stored = await chrome.storage?.local?.get?.(["uiLang"]);
    if (stored?.uiLang) storedLang = stored.uiLang;
  } catch { /* ignore */ }
  if (saveNotice?.isConnected || !document.documentElement) return;
  const copy = NOTICE_STRINGS[resolveNoticeLang(storedLang)] || NOTICE_STRINGS.en;
  saveNotice = document.createElement("div");
  saveNotice.setAttribute("data-openkeylet-save-notice", "");
  saveNotice.style.cssText = "all:initial!important;position:fixed!important;right:16px!important;bottom:16px!important;z-index:2147483647!important;";
  const shadow = saveNotice.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = `
    :host { color-scheme: dark light; }
    section {
      box-sizing: border-box;
      width: min(336px, calc(100vw - 32px));
      padding: 14px 15px;
      border: 1px solid #26262b;
      border-radius: 10px;
      background: #111114;
      color: #f4f4f5;
      box-shadow: 0 16px 40px rgba(0, 0, 0, 0.65), 0 0 0 1px rgba(255, 255, 255, 0.04);
      font: 12px/1.5 "Inter", "Segoe UI Variable", "Segoe UI", "PingFang SC", "Microsoft YaHei UI", -apple-system, BlinkMacSystemFont, sans-serif;
      -webkit-font-smoothing: antialiased;
    }
    .head { display: flex; align-items: center; gap: 8px; }
    .mark { width: 17px; height: 17px; flex: none; display: block; }
    .ring { fill: #f4f4f5; }
    .bit { fill: #a1a1aa; }
    strong { display: block; color: #f4f4f5; font-size: 12.5px; font-weight: 600; letter-spacing: -0.015em; }
    p { margin: 6px 0 12px; color: #a1a1aa; font-size: 11.5px; line-height: 1.5; }
    .actions { display: flex; align-items: center; gap: 8px; }
    button {
      font: inherit;
      font-size: 11.5px;
      font-weight: 600;
      height: 30px;
      padding: 0 12px;
      cursor: pointer;
      border: 1px solid #26262b;
      border-radius: 6px;
      background: #1b1b1f;
      color: #f4f4f5;
      transition: background-color 140ms ease, border-color 140ms ease;
    }
    button:hover { background: #25252a; border-color: #383840; }
    button:first-of-type { background: #f4f4f5; color: #09090b; border-color: transparent; }
    button:first-of-type:hover { background: #ffffff; }
    button:focus-visible { outline: 2px solid #f4f4f5; outline-offset: 2px; }
    @media (prefers-color-scheme: light) {
      section {
        background: #ffffff;
        color: #111114;
        border-color: rgba(17, 17, 20, 0.13);
        box-shadow: 0 16px 40px rgba(17, 17, 20, 0.14), 0 0 0 1px rgba(17, 17, 20, 0.06);
      }
      .ring { fill: #111114; }
      .bit { fill: #52525b; }
      strong { color: #111114; }
      p { color: #52525b; }
      button { background: #f2f2f4; color: #111114; border-color: rgba(17, 17, 20, 0.13); }
      button:hover { background: #e4e4e8; border-color: rgba(17, 17, 20, 0.24); }
      button:first-of-type { background: #111114; color: #ffffff; border-color: transparent; }
      button:first-of-type:hover { background: #27272c; }
      button:focus-visible { outline-color: #111114; }
    }
  `;
  const section = document.createElement("section");
  section.setAttribute("role", "status");
  const head = document.createElement("div");
  head.className = "head";
  head.innerHTML = '<svg class="mark" viewBox="0 0 400 400" aria-hidden="true"><path class="ring" fill-rule="evenodd" d="M24 8H276A16 16 0 0 1 292 24V276A16 16 0 0 1 276 292H24A16 16 0 0 1 8 276V24A16 16 0 0 1 24 8ZM124 108H176A16 16 0 0 1 192 124V176A16 16 0 0 1 176 192H124A16 16 0 0 1 108 176V124A16 16 0 0 1 124 108Z"/><path class="bit" d="M324 208H376A16 16 0 0 1 392 224V376A16 16 0 0 1 376 392H224A16 16 0 0 1 208 376V324A16 16 0 0 1 224 308H292A16 16 0 0 0 308 292V224A16 16 0 0 1 324 208Z"/></svg>';
  const title = document.createElement("strong");
  title.textContent = copy.title;
  head.append(title);
  const description = document.createElement("p");
  description.textContent = copy.desc;
  const actions = document.createElement("div");
  actions.className = "actions";
  const review = document.createElement("button");
  review.type = "button";
  review.textContent = copy.review;
  const dismiss = document.createElement("button");
  dismiss.type = "button";
  dismiss.textContent = copy.dismiss;
  review.addEventListener("click", event => {
    if (event.isTrusted) chrome.runtime.sendMessage({ type: "openkeylet-capture-review" }).then(reply => {
      if (reply?.result?.available === false) showSaveNotice(false);
    }).catch(() => {});
  });
  dismiss.addEventListener("click", event => {
    if (event.isTrusted) chrome.runtime.sendMessage({ type: "openkeylet-capture-dismiss" }).catch(() => {});
  });
  actions.append(review, dismiss);
  section.append(head, description, actions);
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
