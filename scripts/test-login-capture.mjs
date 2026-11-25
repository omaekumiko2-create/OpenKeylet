// Isolated extension + synthetic vault/forms only. Never opens a user's profile.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import http from "node:http";
import net from "node:net";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { chromium } from "playwright";

const repo = path.resolve(import.meta.dirname, "..");
const root = await fs.mkdtemp(path.join(os.tmpdir(), "openkeylet-browser-test-capture-"));
const extension = path.join(root, "extension");
const fixture = process.argv[2] || path.join(process.env.CARGO_TARGET_DIR, "debug/examples",
  process.platform === "win32" ? "browser_fixture.exe" : "browser_fixture");
const readerSource = await fs.readFile(path.join(repo, "browser-extension/form-reader.js"), "utf8");
const login = '<form action="/done" method="post"><label>账号<input id="account" autocomplete="username"></label><label>密码<input id="secret" type="password" autocomplete="current-password"></label><button>登录</button></form>';
const signup = '<form action="/done" method="post"><label>Email<input id="account" type="email" autocomplete="username"></label><label>新密码<input id="secret" type="password" autocomplete="new-password"></label><label>确认密码<input id="confirm" type="password" autocomplete="new-password"></label><button>注册</button></form>';
const change = '<form action="/done" method="post"><input id="account" autocomplete="username" value="alice" readonly><input id="old" type="password" autocomplete="current-password"><input id="secret" type="password" autocomplete="new-password"><input id="confirm" type="password" name="confirm"><button>修改密码</button></form>';
const server = http.createServer((request, response) => {
  response.setHeader("Content-Type", "text/html; charset=utf-8");
  if (request.method === "POST") { request.resume(); response.writeHead(303, { Location: "/done" }); response.end(); return; }
  const content = request.url === "/signup" ? signup : request.url === "/change" ? change
    : request.url === "/done" ? "<p>这是测试结果页，不代表认证成功。</p>" : login;
  response.end(`<!doctype html><meta charset="utf-8"><title>Synthetic login</title>${content}`);
});
server.listen(0, "127.0.0.1"); await once(server, "listening");
const origin = `http://localhost:${server.address().port}`;
const portProbe = net.createServer(); portProbe.listen(0, "127.0.0.1"); await once(portProbe, "listening");
const port = portProbe.address().port; await new Promise(resolve => portProbe.close(resolve));
await fs.cp(path.join(repo, "browser-extension"), extension, { recursive: true });
const swPath = path.join(extension, "service-worker.js");
await fs.writeFile(swPath, (await fs.readFile(swPath, "utf8")).replaceAll("39272", String(port)));
const child = spawn(fixture, [root, String(port), origin], { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
let output = "", context;
child.stdout.on("data", data => { output += data; }); child.stderr.on("data", data => { output += data; });
async function until(check, label, timeout = 20000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) { if (await check()) return; await new Promise(resolve => setTimeout(resolve, 100)); }
  throw new Error(`Timed out: ${label}. ${output.slice(-1200)}`);
}
try {
  await until(() => output.includes("READY"), "fixture startup");
  console.log("Synthetic vault ready");
  context = await chromium.launchPersistentContext(path.join(root, "profile"), { channel: "chromium", headless: true,
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`] });
  const worker = context.serviceWorkers()[0] || await context.waitForEvent("serviceworker");
  const errors = [];
  worker.on("console", message => { if (message.type() === "error") errors.push(message.text()); });
  const extensionId = new URL(worker.url()).host;
  await until(async () => (await worker.evaluate(() => chrome.storage.local.get("bridgeStatus"))).bridgeStatus === "connected", "pairing");
  const site = await context.newPage(); await site.goto(origin);
  const reader = await context.newPage(); await reader.goto(origin);
  await reader.addScriptTag({ content: readerSource });
  async function inspect(html) {
    await reader.setContent(html);
    return reader.evaluate(() => readLoginForms(location.origin, location.href));
  }
  let scan = await inspect(`<form><input type="email" value="newsletter@example.test"></form>
    <form><input type="search" value="ignore"><label>账号<input value="real-user"></label><input type="password" value="synthetic-secret"></form>`);
  assert.equal(scan.forms.length, 1); assert.equal(scan.forms[0].username, "real-user");
  scan = await inspect(`<form><input autocomplete="username" value="alice"><input type="password" autocomplete="current-password" value="old">
    <input type="password" autocomplete="new-password" value="new"><input type="password" name="confirm" value="new"></form>`);
  assert.equal(scan.forms[0].kind, "change"); assert.equal(scan.forms[0].password, "new");
  scan = await inspect(`<form><input type="password" autocomplete="new-password" value="new"><input type="password" name="confirm" value="different"></form>`);
  assert.equal(scan.forms[0].password, ""); assert.ok(scan.forms[0].warnings.length);
  scan = await inspect(`<form><input type="password" autocomplete="one-time-code" value="123456"><input type="password" name="cvv" value="123">
    <input type="password" value="hidden" style="display:none"></form>`);
  assert.equal(scan.forms.length, 0);
  scan = await inspect(`<form><input autocomplete="username" value="first"><input type="password" value="first-secret"></form>
    <form><input autocomplete="username" value="second"><input type="password" value="second-secret"></form>`);
  assert.equal(scan.forms.length, 2);
  scan = await inspect(`<form><input name="search" value="ignore"><input type="password" value="real-secret"></form>`);
  assert.equal(scan.forms[0].username, "");
  await reader.setContent('<div id="host"></div>');
  await reader.evaluate(() => {
    document.querySelector("#host").attachShadow({ mode: "open" }).innerHTML =
      '<form><input autocomplete="username" value="shadow-user" readonly><input type="password" value="shadow-secret"></form>';
  });
  scan = await reader.evaluate(() => readLoginForms(location.origin, location.href));
  assert.equal(scan.forms[0].username, "shadow-user"); await reader.close();
  console.log("Field selection: forms, labels, new passwords, confirmation, OTP, hidden fields, shadow DOM");

  const count = () => worker.evaluate(() => loginCaptures.size);
  // Real browser boundary: the content-script world cannot retrieve the pairing token.
  const privacyTabId = await worker.evaluate(async origin => (await chrome.tabs.query({})).find(tab => tab.url === `${origin}/`).id, origin);
  const storageDenied = await worker.evaluate(async tabId => (await chrome.scripting.executeScript({
    target: { tabId }, world: "ISOLATED", func: async () => {
      try { await chrome.storage.local.get("bridgeToken"); return false; } catch { return true; }
    },
  }))[0].result, privacyTabId);
  assert.equal(storageDenied, true, "Content scripts cannot read trusted extension storage");
  await site.bringToFront();
  await site.locator("#account").fill("before-consent");
  await site.locator("#secret").fill("not-collected");
  await site.locator("button").click(); await site.waitForURL(`${origin}/done`);
  assert.equal(await count(), 0, "Save suggestions are disabled before explicit opt-in");
  const preferences = await context.newPage();
  await preferences.goto(`chrome-extension://${extensionId}/popup.html`);
  await preferences.locator("#status-pill").click();
  await preferences.locator("#capture-enabled").check();
  await until(() => worker.evaluate(() => captureEnabled), "explicit consent stored");
  await preferences.close();
  await site.goto(origin);
  await until(async () => await worker.evaluate(async tabId => (await chrome.scripting.executeScript({
    target: { tabId }, world: "ISOLATED", func: () => captureSubmissionEnabled,
  }))[0].result, privacyTabId), "only public preference reaches content script");
  console.log("Privacy: storage isolation, default-off suggestions and explicit consent");
  await site.bringToFront();
  await site.evaluate(() => {
    document.querySelector("#account").value = "untrusted";
    document.querySelector("#secret").value = "untrusted-secret";
    document.querySelector("form").dispatchEvent(new Event("submit", { bubbles: true }));
    window.postMessage({ type: "openkeylet-login-submitted", form: { username: "forged", password: "forged", kind: "login" } }, location.origin);
  });
  assert.equal(await count(), 0);
  await site.evaluate(() => document.querySelector("form").requestSubmit());
  await site.waitForURL(`${origin}/done`);
  assert.equal(await count(), 0, "Programmatic submission without user interaction is ignored");
  await site.goto(origin);
  await site.locator("#account").fill("new-user");
  await site.locator("#secret").fill("synthetic-new-secret");
  await site.locator("button").click(); await site.waitForURL(`${origin}/done`);
  await until(async () => await count() === 1, "capture survives navigation");
  await site.locator("[data-openkeylet-save-notice]").waitFor();
  const tabId = await worker.evaluate(async () => (await chrome.tabs.query({ active: true, lastFocusedWindow: true }))[0].id);
  try {
    await until(async () => await worker.evaluate(id => chrome.action.getBadgeText({ tabId: id }), tabId) === "+", "save badge");
  } catch (error) {
    console.log(await worker.evaluate(async () => ({ drafts: [...loginCaptures.values()].map(draft => ({ tabId: draft.tabId, origin: draft.origin })),
      tabs: (await chrome.tabs.query({})).map(tab => ({ id: tab.id, active: tab.active, url: tab.url })),
      requests: bridgeRequests.size, connected: socket?.readyState, errors: chrome.runtime.lastError?.message })));
    throw error;
  }
  const local = await worker.evaluate(() => chrome.storage.local.get(null));
  assert.equal(JSON.stringify(local).includes("synthetic-new-secret"), false);
  const locked = await worker.evaluate(() => bridgeCall("status")); assert.equal(locked.locked, true);
  assert.equal(await worker.evaluate(id => captureUiAction({ action: "capture-read", captureTabId: id }).then(() => false, () => true), tabId), true);
  await site.screenshot({ path: path.join(root, "save-notice.png") });
  // Click the closed-shadow notice as a user would, without exposing its internals to pages.
  const bounds = await site.locator("[data-openkeylet-save-notice]").boundingBox();
  await site.mouse.click(bounds.x + 60, bounds.y + bounds.height - 32);
  await until(() => context.pages().some(page => page.url().includes("popup.html?capture=")), "review window");
  const popup = context.pages().find(page => page.url().includes("popup.html?capture="));
  await popup.setViewportSize({ width: 400, height: 680 });
  await popup.locator("#unlock-form").waitFor({ state: "visible" });
  await popup.locator("#pin").fill("123456"); await popup.locator("#unlock-form button").click();
  await popup.locator("#save-form").waitFor({ state: "visible" });
  assert.equal(await popup.locator("#username").inputValue(), "new-user");
  assert.equal(await popup.locator("#password").getAttribute("type"), "password");
  assert.match(await popup.locator("#save-source").textContent(), /localhost/);
  const before = await worker.evaluate(o => bridgeCall("password.list", { origin: o }), origin);
  assert.equal(before.some(item => item.username === "new-user"), false, "Suggestion never auto-saves");
  await popup.screenshot({ path: path.join(root, "save-preview.png"), fullPage: true });
  await popup.locator('#save-form button[type="submit"]').click();
  await until(async () => await count() === 0, "confirmed save consumes draft");
  const saved = (await worker.evaluate(o => bridgeCall("password.list", { origin: o }), origin)).find(item => item.username === "new-user");
  assert.ok(saved);
  assert.equal((await worker.evaluate(args => bridgeCall("password.get", args), { origin, id: saved.id })).password, "synthetic-new-secret");
  await popup.close();
  console.log("Trusted submission, post-navigation suggestion, locked preview, explicit save and memory-only draft");

  async function submit(url, account, password, old) {
    await site.goto(`${origin}${url}`); await site.bringToFront();
    // Navigation starts a new content script. Wait for its public preference IPC;
    // before initialization it correctly refuses to sample credentials.
    const enabled = await worker.evaluate(() => captureEnabled);
    await until(async () => await worker.evaluate(async ({ tabId, enabled }) =>
      (await chrome.scripting.executeScript({ target: { tabId }, world: "ISOLATED",
        func: () => captureSubmissionEnabled,
      }))[0].result === enabled, { tabId, enabled }), "capture preference after navigation");
    if (await site.locator("#account").getAttribute("readonly") === null) await site.locator("#account").fill(account);
    if (old) await site.locator("#old").fill(old);
    await site.locator("#secret").fill(password);
    if (await site.locator("#confirm").count()) await site.locator("#confirm").fill(password);
    await site.locator("button").click(); await site.waitForURL(`${origin}/done`);
  }
  await submit("/", "new-user", "synthetic-new-secret");
  await until(async () => await count() === 0, "unchanged credential suppressed");
  assert.equal(await site.locator("[data-openkeylet-save-notice]").count(), 0);
  await submit("/signup", "register@example.test", "synthetic-register-secret");
  await until(async () => await count() === 1, "registration captured");
  assert.equal(await worker.evaluate(id => getLoginCapture(id).kind, tabId), "signup");
  await worker.evaluate(id => captureUiAction({ action: "capture-dismiss", captureTabId: id }), tabId);
  assert.equal((await worker.evaluate(o => bridgeCall("password.list", { origin: o }), origin)).some(item => item.username === "register@example.test"), false);
  await submit("/change", "alice", "synthetic-changed-secret", "fixture-initial-password");
  await until(async () => await count() === 1, "password change captured");
  const changed = await worker.evaluate(id => captureUiAction({ action: "capture-read", captureTabId: id }), tabId);
  assert.equal(changed.password, "synthetic-changed-secret"); assert.equal(changed.kind, "change");
  const original = changed.entries.find(item => item.username === "alice");
  await worker.evaluate(args => captureUiAction(args), { action: "capture-save", captureTabId: tabId, id: original.id,
    expectedUpdatedAt: original.updatedAt, name: original.name, username: "alice", password: changed.password });
  assert.equal((await worker.evaluate(args => bridgeCall("password.get", args), { origin, id: original.id })).password, "synthetic-changed-secret");
  assert.equal(await worker.evaluate(id => bridgeCall("vault.history", { id }).then(() => false, () => true), original.id), true, "Browser bridge keeps password history restricted to desktop");
  console.log("Registration, unchanged-login suppression, existing-login update and least-privilege history boundary");

  // Cross-origin frames cannot offer credentials under the top-level site's identity.
  assert.deepEqual(await worker.evaluate(async ({ tabId, origin }) => offerLoginCapture(
    { form: { username: "foreign", password: "foreign-secret", kind: "login" } },
    { id: chrome.runtime.id, tab: { id: tabId }, frameId: 1, url: origin.replace("localhost", "127.0.0.1") }),
  { tabId, origin }), {});
  assert.equal(await count(), 0);
  await site.goto(origin); await site.bringToFront();
  await site.evaluate(url => { const frame = document.createElement("iframe"); frame.src = url; document.body.append(frame); }, origin);
  const sameOriginFrame = site.frameLocator("iframe");
  await sameOriginFrame.locator("#account").fill("frame-user"); await sameOriginFrame.locator("#secret").fill("frame-secret");
  await sameOriginFrame.locator("button").click();
  await until(async () => await count() === 1, "same-origin frame capture");
  await site.locator("[data-openkeylet-save-notice]").waitFor();
  await worker.evaluate(id => clearLoginCapture(id), tabId);
  await site.goto(origin); await site.bringToFront();
  await site.evaluate(url => { const frame = document.createElement("iframe"); frame.src = url; document.body.append(frame); }, origin.replace("localhost", "127.0.0.1"));
  const foreignFrame = site.frameLocator("iframe");
  await foreignFrame.locator("#account").fill("foreign-user"); await foreignFrame.locator("#secret").fill("foreign-secret");
  await foreignFrame.locator("button").click();
  await foreignFrame.getByText("这是测试结果页，不代表认证成功。").waitFor();
  assert.equal(await count(), 0, "Cross-origin frame credentials are not captured");
  await submit("/", "boundary-user", "boundary-secret"); await until(async () => await count() === 1, "boundary draft");
  const pageRead = await worker.evaluate(async tabId => (await chrome.scripting.executeScript({ target: { tabId },
    func: async () => { try { return (await chrome.runtime.sendMessage({ type: "vault-ui", action: "capture-read" })) || null; } catch { return null; } }
  }))[0].result, tabId);
  assert.equal(pageRead, null, "A content script cannot use owner-only capture actions");
  const olderDraft = await worker.evaluate(id => getLoginCapture(id).id, tabId);
  await submit("/", "boundary-user", "replacement-secret");
  await until(async () => {
    const current = await worker.evaluate(id => getLoginCapture(id)?.id, tabId);
    return Boolean(current && current !== olderDraft);
  }, "replacement draft");
  assert.equal(await worker.evaluate(args => captureUiAction(args).then(() => false, () => true),
    { action: "capture-save", captureTabId: tabId, captureId: olderDraft, name: "wrong draft", username: "boundary-user", password: "old-secret" }), true);
  await worker.evaluate(id => clearLoginCapture(id), tabId);
  console.log("Cross-origin rejection, content-script access boundary and superseded draft rejection");

  await worker.evaluate(() => chrome.storage.local.set({ captureEnabled: false }));
  await submit("/", "disabled-user", "disabled-secret"); assert.equal(await count(), 0);
  await worker.evaluate(() => chrome.storage.local.set({ captureEnabled: true }));
  await submit("/", "expired-user", "expired-secret"); await until(async () => await count() === 1, "expiry draft");
  await worker.evaluate(id => { getLoginCapture(id).expiresAt = Date.now() - 1; }, tabId);
  assert.equal(await worker.evaluate(id => getLoginCapture(id), tabId), null);
  await submit("/", "navigation-user", "navigation-secret"); await until(async () => await count() === 1, "navigation draft");
  await site.goto(origin.replace("localhost", "127.0.0.1"));
  await until(async () => await count() === 0, "cross-origin navigation clears draft");
  await submit("/", "lock-user", "lock-secret"); await until(async () => await count() === 1, "lock draft");
  await worker.evaluate(() => popupAction({ action: "lock" })); assert.equal(await count(), 0);
  await submit("/", "closed-user", "closed-secret"); await until(async () => await count() === 1, "closed draft");
  await site.close(); await until(async () => await count() === 0, "closed tab clears draft");
  assert.deepEqual(errors, []);
  console.log(JSON.stringify({ ok: true, artifacts: root, checks: ["recognition", "trusted submissions", "confirmation only",
    "source binding", "memory-only/expiry", "registration", "password update/history", "deduplication", "opt-out", "lock/tab cleanup"] }));
} finally {
  if (context) await context.close();
  child.kill(); await new Promise(resolve => server.close(resolve));
}
