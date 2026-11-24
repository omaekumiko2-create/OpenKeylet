// Vault access is handled by the authenticated extension service worker.
const $ = s => document.querySelector(s);
let currentOrigin = "", entries = [], saving = false, reading = false, loading = false, editingVersion = "";
let refreshError = false;
let personalEntries = [], personalEdit = null;
const captureParams = new URLSearchParams(location.search);
let captureContext = captureParams.get("capture") || "";
document.body.classList.toggle("capture-page", Boolean(captureContext));
const captureTabId = captureParams.has("tab") ? Number(captureParams.get("tab")) : undefined;
let pendingCapture = null, savingCapture = null, saveEntries = [], detectedForms = [], readSource = null, openedCapture = "";
const showError = e => { refreshError = false; $("#error").textContent = e?.message || String(e || ""); };
async function call(action, fields = {}) {
  const reply = await chrome.runtime.sendMessage({ type: "vault-ui", action, origin: currentOrigin,
    captureId: captureContext || undefined, captureTabId, ...fields });
  if (!reply?.ok) throw new Error(reply?.error || "OpenKeylet unavailable");
  return reply.result;
}
async function refresh() {
  if (loading || saving || reading) return;
  loading = true;
  try {
    const stored = await chrome.storage.local.get(["bridgePort", "captureEnabled"]);
    $("#capture-enabled").checked = stored.captureEnabled === true;
    $("#port").value = stored.bridgePort || 39272;
    $("#detail").textContent = `127.0.0.1:${stored.bridgePort || 39272}`;
    const state = await call("list");
    if (saving || reading) return;
    if (state.captureExpired) { captureContext = ""; closeSave(); }
    $("#status").textContent = "已连接本地密码库 / CONNECTED";
    $("#lamp").classList.add("on");
    if (state.locked) { closeSave(); closePersonal(); OpenKeyletVaultUI.close(); }
    else if (!$("#save-form").hidden || !$("#personal-form").hidden || OpenKeyletVaultUI.isEditing()) return;
    OpenKeyletVaultUI.apply(state.vault);
    if (refreshError || currentOrigin !== state.origin) showError("");
    if (state.captureExpired) showError("待保存信息已过期或来源网页已变化 / The save suggestion expired or its source changed");
    const entriesChanged = currentOrigin !== state.origin || JSON.stringify(entries) !== JSON.stringify(state.entries);
    currentOrigin = state.origin; entries = state.entries;
    $("#website").textContent = currentOrigin;
    $("#website").hidden = !state.pageAvailable;
    $("#page-hint").hidden = state.pageAvailable;
    $("#unlock-form").hidden = !state.locked;
    $("#vault-panel").hidden = state.locked;
    $("#entries").hidden = !state.pageAvailable;
    $("#read-form").hidden = !state.pageAvailable;
    $("#lock").hidden = !state.pinConfigured;
    pendingCapture = state.capture;
    $("#capture-notice").hidden = !pendingCapture;
    $("#capture-source").textContent = pendingCapture ? `来源网站 / Source: ${pendingCapture.origin}` : "";
    $("#capture-review").disabled = state.locked;
    if (state.locked) $("#generator-output").value = "";
    if (entriesChanged || JSON.stringify(personalEntries) !== JSON.stringify(state.personal)) {
      personalEntries = state.personal;
      renderPersonal();
    }
    if (captureContext && pendingCapture && !state.locked && openedCapture !== pendingCapture.id) {
      openedCapture = pendingCapture.id;
      reviewCapture();
    }
    if (!entriesChanged) return;
    $("#entries").replaceChildren();
    if (!entries.length) { const p=document.createElement("p"); p.textContent="这个网站还没有保存的密码 / No saved logins"; $("#entries").append(p); }
    for (const item of entries) {
      const row = document.createElement("div"); row.className = "login-entry-row";
      const button = document.createElement("button"); button.type = "button"; button.className = "login-entry";
      const title = document.createElement("strong"); title.textContent = item.name;
      const sub = document.createElement("small"); sub.textContent = item.username || "填写 / Fill";
      button.append(title, sub); button.addEventListener("click", async () => { button.disabled=true; try { await call("fill",{id:item.id}); showError("已填写 / Filled"); } catch(e) { showError(e); } finally { button.disabled=false; } });
      row.append(button);
      if (item.hasTotp) {
        const totpBtn = document.createElement("button"); totpBtn.type = "button"; totpBtn.className = "secondary totp-copy-button";
        totpBtn.textContent = "2FA"; totpBtn.title = "复制当前 TOTP 验证码 / Copy live 2FA code";
        totpBtn.addEventListener("click", async () => {
          totpBtn.disabled = true;
          try {
            const res = await call("totp", { id: item.id });
            await navigator.clipboard.writeText(res.code);
            showError(`2FA 已复制 (${res.remainingSeconds}s) / 2FA code copied`);
          } catch (e) { showError(e); }
          finally { totpBtn.disabled = false; }
        });
        row.append(totpBtn);
      }
      $("#entries").append(row);
    }
  } catch(e) {
    closeSave(); closePersonal(); OpenKeyletVaultUI.close();
    $("#status").textContent = "暂不可用 / UNAVAILABLE";
    $("#lamp").classList.remove("on");
    $("#vault-panel").hidden = true; $("#unlock-form").hidden = true;
    $("#website").hidden = true; $("#page-hint").hidden = true;
    currentOrigin = ""; entries = []; $("#entries").replaceChildren();
    personalEntries = []; $("#personal-entries").replaceChildren();
    pendingCapture = null; $("#capture-notice").hidden = true;
    $("#generator-output").value = "";
    showError(`请确认 OpenKeylet 已打开且浏览器连接已启用。 / Check that OpenKeylet and Browser Bridge are running.\n${e.message || e}`);
    refreshError = true;
  } finally { loading=false; }
}
$("#unlock-form").addEventListener("submit", async e => { e.preventDefault(); try { await call("unlock",{pin:$("#pin").value}); $("#pin").value=""; showError(""); await refresh(); } catch(e) { showError(e); } });
$("#lock").addEventListener("click",async () => { closeSave(); closePersonal(); OpenKeyletVaultUI.close(); $("#generator-output").value=""; try { await call("lock"); await refresh(); } catch(e) { showError(e); } });
$("#read-form").addEventListener("click", async () => {
  if (reading || saving) return;
  reading = true;
  try {
    const form=await call("read-form");
    savingCapture = null; saveEntries = entries;
    readSource = { sourceUrl: form.sourceUrl, sourceTabId: form.sourceTabId };
    detectedForms = form.forms;
    $("#detected-form").replaceChildren(...detectedForms.map((candidate, i) =>
      new Option(`${i + 1} · ${candidate.username || "账号待确认 / Check account"} · ${{login:"登录",signup:"注册",change:"修改密码"}[candidate.kind]}`, String(i))));
    $("#detected-form").value = String(form.selectedIndex);
    $("#detected-form").hidden = $("#detected-form-label").hidden = detectedForms.length < 2;
    presentLogin(form, currentOrigin);
  } catch(e) { showError(e); } finally { reading = false; }
});
function presentLogin(form, origin) {
  $("#save-target").replaceChildren(new Option("新项目 / New item", ""), ...saveEntries.map(i=>new Option(`${i.name} · ${i.username}`,i.id)));
  const match = form.username ? saveEntries.filter(i => i.username === form.username) : [];
  $("#save-target").value = match.length === 1 ? match[0].id : "";
  $("#name").value = match.length === 1 ? match[0].name : new URL(origin).hostname;
  $("#username").value = form.username; $("#password").value = form.password;
  $("#use-generated-password").hidden = Boolean(savingCapture);
  $("#save-source").textContent = `来源网站 / Source: ${origin}`;
  $("#save-warning").textContent = (form.warnings || []).join(" · ");
  selectTarget(); $("#save-form").hidden = false; showError("");
}
async function reviewCapture() {
  if (reading || saving || !pendingCapture) return;
  reading = true;
  try {
    const form = await call("capture-read", { captureId: pendingCapture.id });
    savingCapture = form.capture; saveEntries = form.entries;
    detectedForms = []; readSource = null;
    $("#detected-form").replaceChildren();
    $("#detected-form").hidden = $("#detected-form-label").hidden = true;
    presentLogin(form, form.capture.origin);
    if (!document.body.classList.contains("capture-page")) $("#save-form").scrollIntoView({ block: "start" });
  } catch (error) { showError(error); } finally { reading = false; }
}
$("#capture-review").addEventListener("click", reviewCapture);
$("#capture-dismiss").addEventListener("click", async () => {
  if (!pendingCapture) return;
  try {
    await call("capture-dismiss", { captureId: pendingCapture.id }); captureContext = ""; closeSave();
    if (document.body.classList.contains("capture-page")) window.close();
    else await refresh();
  }
  catch (error) { showError(error); }
});
$("#capture-enabled").addEventListener("change", async () => {
  await chrome.storage.local.set({ captureEnabled: $("#capture-enabled").checked });
  if (!$("#capture-enabled").checked) { captureContext = ""; closeSave(); }
  await refresh();
});
$("#detected-form").addEventListener("change", () => presentLogin(detectedForms[Number($("#detected-form").value)], currentOrigin));
function selectTarget() { const item=saveEntries.find(i=>i.id===$("#save-target").value); editingVersion=item?.updatedAt || ""; $("#name").disabled=Boolean(item); if(item) $("#name").value=item.name; }
$("#save-target").addEventListener("change",selectTarget);
function closeSave() {
  $("#save-form").reset(); $("#save-form").hidden=true;
  $("#password").type = "password"; $("#toggle-saved-password").textContent = "显示密码 / Show password";
  $("#detected-form").replaceChildren(); $("#save-warning").textContent = ""; $("#save-source").textContent = "";
  savingCapture = null; saveEntries = []; detectedForms = []; readSource = null;
}
$("#cancel-save").addEventListener("click", async () => {
  if (document.body.classList.contains("capture-page")) {
    if (pendingCapture) await call("capture-dismiss", { captureId: pendingCapture.id }).catch(() => {});
    window.close(); return;
  }
  closeSave(); refresh();
});
$("#toggle-saved-password").addEventListener("click", () => {
  const visible = $("#password").type === "password";
  $("#password").type = visible ? "text" : "password";
  $("#toggle-saved-password").textContent = visible ? "隐藏密码 / Hide password" : "显示密码 / Show password";
});
$("#capture-close").addEventListener("click", () => window.close());
$("#save-form").addEventListener("submit",async e=>{
  e.preventDefault(); if(saving)return; saving=true;
  try {
    await call(savingCapture ? "capture-save" : "save", { captureId: savingCapture?.id, ...readSource,
      id:$("#save-target").value,expectedUpdatedAt:editingVersion,name:$("#name").value,username:$("#username").value,password:$("#password").value });
    if (savingCapture) {
      captureContext = "";
      $("#capture-complete").hidden = !document.body.classList.contains("capture-page");
    }
    closeSave(); showError("已保存到本地密码库 / Saved to OpenKeylet");
  }
  catch(e){showError(e);} finally {saving=false;refresh();}
});
$("#pair-form").addEventListener("submit",async e=>{ e.preventDefault(); const port=Number($("#port").value); if(!Number.isInteger(port)||port<1024||port>65535){showError("Invalid port");return;} await chrome.storage.local.set({bridgePort:port}); await chrome.runtime.sendMessage({type:"bridge-config-updated"}); showError("在 OpenKeylet 安装指引中点击“打开浏览器并复制地址” / Click Open Chrome & copy address in OpenKeylet"); });
const PERSONAL_LABELS = {
  secureNote: { secureNote:"安全笔记 / Secure note" },
  card: { cardholderName:"持卡人 / Cardholder", cardNumber:"卡号 / Number", cardBrand:"卡组织 / Brand", cardExpMonth:"到期月 / Expiry month", cardExpYear:"到期年 / Expiry year", cardSecurityCode:"安全码 / Security code" },
  identity: { identityTitle:"称谓 / Title", firstName:"名字 / First name", middleName:"中间名 / Middle name", lastName:"姓氏 / Last name", company:"公司 / Company", email:"邮箱 / Email", phone:"电话 / Phone", address1:"地址第一行 / Address line 1", address2:"地址第二行 / Address line 2", address3:"地址第三行 / Address line 3", city:"城市 / City", state:"省或州 / State", postalCode:"邮编 / Postal code", country:"国家或地区 / Country", passportNumber:"护照 / Passport", licenseNumber:"驾照 / License", nationalId:"身份证 / National ID" },
};
function renderPersonal() {
  const container = $("#personal-entries"); container.replaceChildren();
  for (const item of [...personalEntries].sort((a,b) => Number(b.favorite) - Number(a.favorite))) {
    const row = document.createElement("div"); row.className = "personal-entry";
    const title = document.createElement("strong"); title.textContent = `${item.favorite ? "★ " : ""}${item.name}`;
    const subtitle = document.createElement("small"); subtitle.textContent = `${item.itemType === "card" ? "CARD" : item.itemType === "secureNote" ? "NOTE" : "IDENTITY"} ${item.subtitle}`;
    const actions = document.createElement("div"); actions.className = "personal-actions";
    const fill = document.createElement("button"); fill.type = "button"; fill.textContent = "填写 / Fill";
    fill.disabled = !currentOrigin;
    fill.onclick = async () => { fill.disabled = true; try { const result = await call("personal-fill",{id:item.id}); showError(`已填写 ${result.filled} 个字段 / Fields filled`); } catch(e) { showError(e); } finally { fill.disabled = false; } };
    const edit = document.createElement("button"); edit.type = "button"; edit.textContent = "编辑 / Edit";
    edit.onclick = async () => { edit.disabled = true; reading = true; try { openPersonal(await call("personal-edit",{id:item.id})); } catch(e) { showError(e); } finally { reading = false; edit.disabled = false; } };
    if (item.itemType !== "secureNote") actions.append(fill);
    actions.append(edit); row.append(title,subtitle,actions); container.append(row);
  }
}
function openPersonal(item) {
  personalEdit = item;
  $("#personal-title").textContent = item.itemType === "card" ? "信用卡 / Card" : item.itemType === "secureNote" ? "安全笔记 / Secure note" : "身份资料 / Identity";
  $("#personal-name").value = item.name || "";
  $("#personal-fields").replaceChildren();
  for (const [name, label] of Object.entries(PERSONAL_LABELS[item.itemType])) {
    const field = document.createElement("label"); field.textContent = label; field.htmlFor = `personal-${name}`;
    const input = document.createElement(name === "secureNote" ? "textarea" : "input"); input.id = `personal-${name}`; input.dataset.personalField = name;
    input.autocomplete = "off"; input.maxLength = name === "secureNote" ? 65536 : 4096;
    if (name === "secureNote") input.rows = 7;
    else input.type = ["cardNumber","cardSecurityCode","passportNumber","licenseNumber","nationalId"].includes(name) ? "password" : "text";
    input.value = item.fields?.[name] || "";
    $("#personal-fields").append(field,input);
  }
  $("#personal-form").hidden = false; showError(""); $("#personal-name").focus();
}
function closePersonal() { $("#personal-form").reset(); $("#personal-fields").replaceChildren(); $("#personal-form").hidden = true; personalEdit = null; }
$("#add-card").onclick = () => openPersonal({itemType:"card"});
$("#add-identity").onclick = () => openPersonal({itemType:"identity"});
$("#add-note").onclick = () => openPersonal({itemType:"secureNote"});
$("#personal-cancel").onclick = () => { closePersonal(); refresh(); };
$("#personal-form").addEventListener("submit", async e => {
  e.preventDefault(); if (saving) return; saving = true;
  try {
    const fields = Object.fromEntries([...document.querySelectorAll("[data-personal-field]")].map(input=>[input.dataset.personalField,input.value]));
    await call("personal-save",{ id:personalEdit.id, expectedUpdatedAt:personalEdit.updatedAt, itemType:personalEdit.itemType, name:$("#personal-name").value, fields });
    closePersonal(); showError("已保存到本地密码库 / Saved to OpenKeylet");
  } catch(e) { showError(e); } finally { saving = false; refresh(); }
});
async function generatePassword() {
  const options = {length:Number($("#generator-length").value)};
  for (const key of ["uppercase","lowercase","digits","symbols"]) options[key] = $(`#gen-${key}`).checked;
  return call("generate",{options});
}
$("#generate-password").onclick = async () => { try { $("#generator-output").value = await generatePassword(); showError(""); } catch(e) { showError(e); } };
$("#copy-generated-password").onclick = async () => { try { if ($("#generator-output").value) { await navigator.clipboard.writeText($("#generator-output").value); showError("已复制 / Copied"); } } catch(e) { showError(e); } };
$("#use-generated-password").onclick = async () => { try { $("#password").value = await generatePassword(); } catch(e) { showError(e); } };
refresh(); setInterval(refresh,2000);
