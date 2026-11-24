const $ = s => document.querySelector(s);
const { t, localizeMessage } = OpenKeyletUI;
const id = new URL(location.href).searchParams.get("id");

async function call(action, fields = {}) {
  const r = await chrome.runtime.sendMessage({ type: "credential-ui", id, action, ...fields });
  if (!r?.ok) throw new Error(r?.error || "Request unavailable");
  return r.result;
}

let currentInfo = null;

function renderRequestInfo() {
  if (!currentInfo) return;
  $("#title").textContent = currentInfo.operation === "create"
    ? t("passkey.createTitle")
    : t("passkey.getTitle");
  if (currentInfo.verificationRequired && !currentInfo.pinConfigured) {
    $("#note").textContent = t("passkey.pinRequired");
    $("#confirm").disabled = true;
  } else {
    $("#note").textContent = t("passkey.note");
  }
}

async function load() {
  OpenKeyletUI.applyI18n();
  await OpenKeyletUI.hydrateFromStorage();
  try {
    const info = await call("info");
    currentInfo = info;
    $("#origin").textContent = info.origin;
    $("#account").textContent = info.operation === "create"
      ? `${info.account} · ${info.rpId}`
      : info.rpId;
    $("#credential").hidden = info.operation === "create";
    document.querySelector('label[for="credential"]').hidden = info.operation === "create";
    $("#credential").replaceChildren();
    for (const e of info.entries) {
      $("#credential").add(new Option(`${e.passkey.displayName || e.passkey.userName} · ${e.name}`, e.passkey.credentialId));
    }
    $("#pin-panel").hidden = !info.pinConfigured;
    $("#pin").required = info.pinConfigured;
    renderRequestInfo();
    if (!(info.verificationRequired && !info.pinConfigured)) {
      (info.pinConfigured ? $("#pin") : $("#confirm")).focus();
    }
  } catch (e) {
    $("#error").textContent = localizeMessage(e);
    $("#confirm").disabled = true;
  }
}

$("#theme-toggle").addEventListener("click", () => OpenKeyletUI.toggleTheme());

$("#request-form").addEventListener("submit", async e => {
  e.preventDefault();
  $("#confirm").disabled = true;
  try {
    await call("confirm", { credentialId: $("#credential").value, pin: $("#pin").value });
  } catch (err) {
    $("#error").textContent = localizeMessage(err);
    $("#confirm").disabled = false;
  } finally {
    $("#pin").value = "";
  }
});

for (const action of ["fallback", "cancel"]) {
  $("#" + action).addEventListener("click", () => call(action).catch(() => window.close()));
}

document.addEventListener("keydown", e => {
  if (e.key === "Escape") {
    e.preventDefault();
    call("cancel").catch(() => window.close());
  }
});

OpenKeyletUI.onChange(renderRequestInfo);
void load();
