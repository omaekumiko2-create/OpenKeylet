// Real MV3 extension and framework runtimes, but only synthetic pages and credentials.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import http from "node:http";
import net from "node:net";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { build } from "esbuild";
import { chromium } from "playwright";

const repo = path.resolve(import.meta.dirname, "..");
const root = await fs.mkdtemp(path.join(os.tmpdir(), "openkeylet-browser-test-flows-"));
const extension = path.join(root, "extension");
const nodePaths = process.env.NODE_PATH ? process.env.NODE_PATH.split(path.delimiter).filter(Boolean) : undefined;
const bundle = await build({ entryPoints: [path.join(import.meta.dirname, "fixtures/controlled-logins.jsx")],
  bundle: true, write: false, format: "iife", platform: "browser", ...(nodePaths ? { nodePaths } : {}),
  define: { "process.env.NODE_ENV": '"production"', __VUE_OPTIONS_API__: "true",
    __VUE_PROD_DEVTOOLS__: "false", __VUE_PROD_HYDRATION_MISMATCH_DETAILS__: "false" } });
const fields = '<input id="u" autocomplete="username"><input id="p" type="password" autocomplete="current-password">';
const password = '<input id="p" type="password" autocomplete="current-password">';
const stepOne = `<form id="step"><input id="u" autocomplete="username"><button id="next">Next</button></form>
  <script>document.querySelector('#step').addEventListener('submit', event => { event.preventDefault();
    event.currentTarget.outerHTML=${JSON.stringify(`<form onsubmit="event.preventDefault()">${password}<button id="submit">Sign in</button></form>`)}; });</script>`;
const pages = {
  standard: `<form onsubmit="event.preventDefault();this.remove()">${fields}<button id="submit">Sign in</button></form>`,
  button: `<div role="form">${fields}<button id="submit" type="button" onclick="this.parentElement.remove()">Sign in</button></div>`,
  direct: `<form action="/done">${fields}<button id="submit" type="button" onclick="HTMLFormElement.prototype.submit.call(this.form)">Sign in</button></form>`,
  enter: `<div role="form" onkeydown="if(event.key==='Enter'){event.preventDefault();this.remove()}">${fields}<button type="button">Sign in</button></div>`,
  shadow: `<div id="host"></div><script>document.querySelector('#host').attachShadow({mode:'open'}).innerHTML=${JSON.stringify(`<form onsubmit="event.preventDefault()">${fields}<button id="submit">Sign in</button></form>`)};</script>`,
  dynamic: `<div id="app"></div><script>setTimeout(()=>document.querySelector('#app').innerHTML=${JSON.stringify(`<form onsubmit="event.preventDefault()">${fields}<button id="submit">Sign in</button></form>`)},30)</script>`,
  "step-spa": stepOne,
  "step-first": '<form action="/step-last"><input id="u" autocomplete="username"><button id="next">Continue</button></form>',
  "step-last": `<form onsubmit="event.preventDefault()">${password}<button id="submit">Sign in</button></form>`,
  actions: `<form onsubmit="event.preventDefault()">${fields}<button id="show" type="button" onclick="document.querySelector('#p').type='text'">Show password</button><button id="cancel" type="button">Cancel</button><button id="submit">Sign in</button></form>`,
  invalid: '<form><input id="u" type="email" autocomplete="username" required><input id="p" type="password" required><button id="submit">Sign in</button></form>',
  done: "<p>Done</p>",
};
const server = http.createServer((request, response) => {
  const key = new URL(request.url, "http://localhost").pathname.slice(1);
  if (key === "framework.js") { response.setHeader("Content-Type", "text/javascript"); response.end(bundle.outputFiles[0].text); return; }
  response.setHeader("Content-Type", "text/html; charset=utf-8");
  const framework = ["react", "vue"].includes(key);
  response.end(`<!doctype html><meta charset="utf-8"><body data-framework="${framework ? key : ""}">`
    + (framework ? '<div id="app"></div><script src="/framework.js"></script>' : pages[key] || pages.standard));
});
server.listen(0, "127.0.0.1"); await once(server, "listening");
const origin = `http://localhost:${server.address().port}`;
const probe = net.createServer(); probe.listen(0, "127.0.0.1"); await once(probe, "listening");
const port = probe.address().port; await new Promise(resolve => probe.close(resolve));
await fs.cp(path.join(repo, "browser-extension"), extension, { recursive: true, dereference: true });
const sw = path.join(extension, "service-worker.js");
await fs.writeFile(sw, (await fs.readFile(sw, "utf8")).replaceAll("39272", String(port)));
const executable = path.join(process.env.CARGO_TARGET_DIR, "debug/examples", process.platform === "win32" ? "browser_fixture.exe" : "browser_fixture");
const child = spawn(executable, [root, String(port), origin], { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
let output = "", context, worker, page;
child.stdout.on("data", data => { output += data; }); child.stderr.on("data", data => { output += data; });
const results = [];
const pageErrors = [];
async function until(check, message, timeout = 12000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) { if (await check()) return; await new Promise(resolve => setTimeout(resolve, 60)); }
  throw new Error(`Timeout: ${message}`);
}
async function test(name, run) {
  const only = process.argv.find(argument => argument.startsWith("--case="))?.slice(7);
  if (only && !name.includes(only)) return;
  await worker.evaluate(() => clearLoginCaptures());
  const previousErrors = pageErrors.length;
  try { await run(); assert.deepEqual(pageErrors.slice(previousErrors), []); results.push({ name, ok: true }); console.log("PASS", name); }
  catch (error) {
    results.push({ name, ok: false, error: error.message }); console.log("FAIL", name, error.message);
    console.log(await worker.evaluate(() => ({ drafts: loginCaptures.size, steps: usernameSteps.size,
      enabled: captureEnabled, connected: socket?.readyState, pendingRpc: bridgeRequests.size })));
  }
}
async function offer(account = "flow-user", secret = "synthetic-flow-secret", enter = false) {
  await page.locator("#p").waitFor();
  if (await page.locator("#u").count()) await page.locator("#u").fill(account);
  await page.locator("#p").fill(secret);
  if (enter) await page.locator("#p").press("Enter"); else await page.locator("#submit").click();
}
async function draft() {
  await until(() => worker.evaluate(() => [...loginCaptures.values()].some(item => item.ready)), "ready suggestion");
  return worker.evaluate(() => {
    const item = [...loginCaptures.values()].find(item => item.ready);
    return captureUiAction({ action: "capture-read", captureTabId: item.tabId, captureId: item.id });
  });
}
try {
  await until(() => output.includes("READY"), "fixture");
  context = await chromium.launchPersistentContext(path.join(root, "profile"), { channel: "chromium", headless: true,
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`] });
  context.setDefaultTimeout(8000);
  context.on("page", target => target.on("pageerror", error => pageErrors.push(error.message)));
  worker = context.serviceWorkers()[0] || await context.waitForEvent("serviceworker");
  await until(async () => (await worker.evaluate(() => chrome.storage.local.get("bridgeStatus"))).bridgeStatus === "connected", "pairing");
  await worker.evaluate(() => bridgeCall("unlock", { pin: "123456" }));
  page = await context.newPage();
  await test("automatic capture requires opt-in", async () => {
    assert.equal(await worker.evaluate(() => captureEnabled), false);
    await page.goto(`${origin}/standard`); await offer("disabled-user", "disabled-secret");
    assert.equal(await worker.evaluate(() => loginCaptures.size), 0);
  });
  await worker.evaluate(() => chrome.storage.local.set({ captureEnabled: true }));
  await until(() => worker.evaluate(() => captureEnabled), "capture opt-in");
  for (const name of ["standard", "button", "direct", "enter", "shadow", "dynamic"]) await test(name, async () => {
    await page.goto(`${origin}/${name}`); await page.bringToFront();
    await offer("flow-user", "synthetic-flow-secret", name === "enter");
    const capture = await draft(); assert.equal(capture.username, "flow-user"); assert.equal(capture.password, "synthetic-flow-secret");
  });
  for (const framework of ["react", "vue"]) await test(`${framework}: controlled fill, rerender and capture`, async () => {
    await page.goto(`${origin}/${framework}`); await page.bringToFront();
    await page.locator("#p").waitFor();
    const login = (await worker.evaluate(o => bridgeCall("password.list", { origin: o }), origin))[0];
    await worker.evaluate(args => popupAction(args), { action: "fill", id: login.id, origin });
    await page.locator("#render").click();
    assert.equal(await page.locator("#u").inputValue(), "alice");
    assert.equal(await page.locator("#p").inputValue(), "fixture-initial-password");
    await offer(`${framework}-user`, `${framework}-synthetic-secret`);
    await page.locator("#done").waitFor();
    const submitted = await page.evaluate(() => window.lastSubmit);
    assert.equal(submitted.username, `${framework}-user`); assert.equal(submitted.password, `${framework}-synthetic-secret`);
    const capture = await draft(); assert.equal(capture.username, submitted.username); assert.equal(capture.password, submitted.password);
  });
  for (const name of ["step-spa", "step-first"]) await test(`${name}: username followed by password`, async () => {
    await page.goto(`${origin}/${name}`, { waitUntil: "networkidle" }); await page.bringToFront(); await page.waitForTimeout(80);
    await page.locator("#u").fill("two-step-user"); await page.locator("#next").click();
    await page.locator("#p").waitFor(); await offer("", "two-step-secret");
    const capture = await draft(); assert.equal(capture.username, "two-step-user"); assert.equal(capture.password, "two-step-secret");
  });
  await test("non-submit buttons never suggest saving; revealed password still works", async () => {
    await page.goto(`${origin}/actions`, { waitUntil: "networkidle" }); await page.waitForTimeout(80); await page.locator("#u").fill("toggle-user"); await page.locator("#p").fill("toggle-secret");
    await page.locator("#show").click(); await page.locator("#cancel").click();
    assert.equal(await worker.evaluate(() => loginCaptures.size), 0);
    await page.locator("#submit").click(); assert.equal((await draft()).password, "toggle-secret");
  });
  await test("HTML validation prevents premature suggestion", async () => {
    await page.goto(`${origin}/invalid`, { waitUntil: "networkidle" }); await offer("not-an-email", "invalid-secret");
    assert.equal(await worker.evaluate(() => loginCaptures.size), 0);
  });
  await test("username step expires", async () => {
    await page.goto(`${origin}/step-spa`, { waitUntil: "networkidle" }); await page.waitForTimeout(80); await page.locator("#u").fill("expired-user"); await page.locator("#next").click();
    await until(() => worker.evaluate(() => usernameSteps.size === 1), "username step");
    await worker.evaluate(() => { for (const step of usernameSteps.values()) step.expiresAt = 0; });
    await offer("", "expired-secret"); assert.equal((await draft()).username, "");
  });
  await test("username does not cross origins", async () => {
    await page.goto(`${origin}/step-spa`, { waitUntil: "networkidle" }); await page.waitForTimeout(80); await page.locator("#u").fill("foreign-user"); await page.locator("#next").click();
    await until(() => worker.evaluate(() => usernameSteps.size === 1), "username step");
    await page.goto(`${origin.replace("localhost", "127.0.0.1")}/step-last`, { waitUntil: "networkidle" }); await page.waitForTimeout(80);
    await offer("", "foreign-secret"); assert.equal((await draft()).username, "");
    assert.equal(await worker.evaluate(() => usernameSteps.size), 0);
  });
  await test("username does not cross tabs", async () => {
    await page.goto(`${origin}/step-spa`, { waitUntil: "networkidle" }); await page.waitForTimeout(80); await page.locator("#u").fill("other-tab-user"); await page.locator("#next").click();
    await until(() => worker.evaluate(() => usernameSteps.size === 1), "username step");
    const original = page; page = await context.newPage();
    try { await page.goto(`${origin}/step-last`, { waitUntil: "networkidle" }); await page.waitForTimeout(80); await offer("", "other-tab-secret"); assert.equal((await draft()).username, ""); }
    finally { await page.close(); page = original; }
  });
  await fs.writeFile(path.join(root, "results.json"), JSON.stringify(results, null, 2));
  console.log(JSON.stringify({ artifacts: root, browser: context.browser()?.version(), total: results.length,
    passed: results.filter(item => item.ok).length, failures: results.filter(item => !item.ok) }, null, 2));
  if (results.some(item => !item.ok)) process.exitCode = 1;
} finally {
  if (context) await context.close();
  child.kill(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
}
