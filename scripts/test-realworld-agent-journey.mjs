// Real-world multi-page AI Agent + Browser Extension + MCP E2E journey.
// Runs against an isolated synthetic developer portal, real OpenKeylet extension,
// real browser_fixture bridge, and real `openkeylet mcp stdio`. Never touches user profiles.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import http from "node:http";
import net from "node:net";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createPublicKey, verify, createHash, createHmac } from "node:crypto";
import { chromium } from "playwright";

const repo = path.resolve(import.meta.dirname, "..");
const targetDir = process.env.CARGO_TARGET_DIR || path.join(repo, "src-tauri/target");
const exeExt = process.platform === "win32" ? ".exe" : "";
const fixtureBin = process.argv[2] || path.join(targetDir, "debug/examples", `browser_fixture${exeExt}`);
const openkeyletBin = process.argv[3] || path.join(targetDir, "debug", `openkeylet${exeExt}`);

const root = await fs.mkdtemp(path.join(os.tmpdir(), "openkeylet-browser-test-realworld-journey-"));
const extension = path.join(root, "extension");

function totpSha1(base32Secret, nowSec = Math.floor(Date.now() / 1000)) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, buffer = 0;
  const bytes = [];
  for (const ch of base32Secret.toUpperCase().replace(/[^A-Z2-7]/g, "")) {
    buffer = (buffer << 5) | alphabet.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  const counter = BigInt(Math.floor(nowSec / 30));
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(counter);
  const digest = createHmac("sha1", Buffer.from(bytes)).update(msg).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const code = (((digest[offset] & 0x7f) << 24)
    | ((digest[offset + 1] & 0xff) << 16)
    | ((digest[offset + 2] & 0xff) << 8)
    | (digest[offset + 3] & 0xff)) % 1_000_000;
  return String(code).padStart(6, "0");
}

const VALID_USER = "dev@acme-cloud.test";
const VALID_PASS = "acme-realworld-portal-pw-8899";
const WRONG_PASS = "wrong-old-password-1234";
const TOTP_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const ISSUED_WEB_KEY = "acme_live_web_issued_key_77112233";
const ISSUED_API_KEY = "acme_live_api_minted_key_44556677";
const NEW_SIGNUP_PASS = "new-service-account-pw-554433";
let mintHits = 0;

function readBody(req) {
  return new Promise(resolve => {
    let data = "";
    req.on("data", chunk => { data += chunk; });
    req.on("end", () => resolve(data));
  });
}

const server = http.createServer(async (req, res) => {
  const urlObj = new URL(req.url, "http://localhost");
  const pathname = urlObj.pathname;

  if (pathname === "/api/projects") {
    const ok = req.headers.authorization === `Bearer ${ISSUED_WEB_KEY}`;
    res.writeHead(ok ? 200 : 401, { "Content-Type": "application/json" });
    res.end(JSON.stringify(ok
      ? { workspace: "acme-prod", projects: ["payments-api", "edge-worker"] }
      : { error: "unauthorized" }));
    return;
  }

  if (pathname === "/api/mint" && req.method === "POST") {
    mintHits++;
    const ok = req.headers.authorization === `Bearer ${ISSUED_WEB_KEY}`;
    res.writeHead(ok ? 201 : 401, { "Content-Type": "application/json" });
    res.end(JSON.stringify(ok
      ? { created: true, data: { api_key: ISSUED_API_KEY, label: "ci-runner" } }
      : { error: "unauthorized" }));
    return;
  }

  if (pathname === "/api/check-minted") {
    const ok = req.headers["x-runner-key"] === ISSUED_API_KEY;
    res.writeHead(ok ? 200 : 401, { "Content-Type": "application/json" });
    res.end(JSON.stringify(ok ? { runner: "active", region: "ap-northeast-1" } : { error: "denied" }));
    return;
  }

  if (pathname === "/signup-done" && req.method === "POST") {
    await readBody(req);
    res.writeHead(303, { Location: "/account-created" });
    res.end();
    return;
  }

  res.setHeader("Content-Type", "text/html; charset=utf-8");

  if (pathname === "/login") {
    res.end(`<!doctype html>
<meta charset="utf-8">
<title>Acme Cloud — Sign in</title>
<main>
  <h1>Sign in to Acme Cloud</h1>
  <div id="login-alert" role="alert" style="display:none"></div>
  <form id="step1-form">
    <label>Work Email <input id="email" type="email" autocomplete="username"></label>
    <button id="next-btn" type="submit">Continue</button>
  </form>
  <form id="step2-form" style="display:none">
    <p id="selected-user"></p>
    <label>Password <input id="password" type="password" autocomplete="current-password"></label>
    <button id="signin-btn" type="submit">Sign in</button>
  </form>
</main>
<script>
  let chosenEmail = "";
  const alertEl = document.getElementById("login-alert");
  document.getElementById("step1-form").addEventListener("submit", e => {
    e.preventDefault();
    chosenEmail = document.getElementById("email").value.trim();
    if (!chosenEmail) {
      alertEl.textContent = "Please enter your work email.";
      alertEl.style.display = "block";
      return;
    }
    alertEl.style.display = "none";
    document.getElementById("step1-form").style.display = "none";
    document.getElementById("selected-user").textContent = chosenEmail;
    document.getElementById("step2-form").style.display = "block";
  });
  document.getElementById("step2-form").addEventListener("submit", e => {
    e.preventDefault();
    const pw = document.getElementById("password").value;
    if (chosenEmail === ${JSON.stringify(VALID_USER)} && pw === ${JSON.stringify(VALID_PASS)}) {
      location.href = "/mfa";
    } else {
      alertEl.textContent = "Invalid email or password — check credentials and retry";
      alertEl.style.display = "block";
    }
  });
</script>`);
    return;
  }

  if (pathname === "/mfa") {
    res.end(`<!doctype html>
<meta charset="utf-8">
<title>Acme Cloud — Two-Factor Verification</title>
<main>
  <h1>Enter 6-digit verification code</h1>
  <div id="mfa-alert" role="alert" style="display:none"></div>
  <form id="mfa-form">
    <div id="otp-boxes">
      <input class="otp-box" maxlength="1" inputmode="numeric" autocomplete="one-time-code" aria-label="Digit 1">
      <input class="otp-box" maxlength="1" inputmode="numeric" aria-label="Digit 2">
      <input class="otp-box" maxlength="1" inputmode="numeric" aria-label="Digit 3">
      <input class="otp-box" maxlength="1" inputmode="numeric" aria-label="Digit 4">
      <input class="otp-box" maxlength="1" inputmode="numeric" aria-label="Digit 5">
      <input class="otp-box" maxlength="1" inputmode="numeric" aria-label="Digit 6">
    </div>
    <button id="verify-btn" type="submit">Verify code</button>
  </form>
</main>
<script>
  document.getElementById("mfa-form").addEventListener("submit", e => {
    e.preventDefault();
    const code = [...document.querySelectorAll(".otp-box")].map(el => el.value).join("");
    if (/^\\d{6}$/.test(code)) {
      location.href = "/dashboard?code=oauth_one_time_code_999&tab=keys#access_token=frag_secret_888";
    } else {
      const a = document.getElementById("mfa-alert");
      a.textContent = "Verification code must be 6 digits";
      a.style.display = "block";
    }
  });
</script>`);
    return;
  }

  if (pathname === "/dashboard") {
    res.end(`<!doctype html>
<meta charset="utf-8">
<title>Developer Console · Keys</title>
<main>
  <h1>Developer Console</h1>
  <p>Manage API keys, team accounts, billing, and passkeys.</p>
  <section id="keys-section">
    <button id="gen-key-btn" type="button">Generate API Key</button>
    <div id="issued-banner" role="status" style="display:none"></div>
    <pre><code id="issued-key-box"></code></pre>
  </section>
  <section id="billing-section">
    <h2>Billing Card</h2>
    <form id="card-form">
      <input id="cardholder" autocomplete="cc-name">
      <input id="cardnumber" autocomplete="cc-number">
      <select id="cardmonth" autocomplete="cc-exp-month"><option value=""></option><option value="11">Nov</option></select>
      <input id="cardyear" autocomplete="cc-exp-year">
      <input id="cardcode" autocomplete="cc-csc">
    </form>
  </section>
  <section id="passkey-section">
    <button id="register-passkey-btn" type="button">Register Passkey</button>
    <button id="signin-passkey-btn" type="button">Sign in with Passkey</button>
  </section>
  <section id="signup-section">
    <h2>Create Service Account</h2>
    <form id="signup-form" action="/signup-done" method="post">
      <label>Account Email <input id="new-user" type="email" autocomplete="username"></label>
      <label>New Password <input id="new-pass" type="password" autocomplete="new-password"></label>
      <button id="create-acct-btn" type="submit">Create Service Account</button>
    </form>
  </section>
</main>
<script>
  window.__passkeyCreate = null;
  window.__passkeyGet = null;
  document.getElementById("gen-key-btn").addEventListener("click", () => {
    const key = ${JSON.stringify(ISSUED_WEB_KEY)};
    document.getElementById("issued-key-box").textContent = key;
    const banner = document.getElementById("issued-banner");
    banner.textContent = "Created key " + key + " — copy it now";
    banner.style.display = "block";
    document.title = "Issued " + key;
    history.replaceState(null, "", "/dashboard/keys/" + key + "?created=" + key);
  });
  document.getElementById("register-passkey-btn").addEventListener("click", async () => {
    try {
      const cred = await navigator.credentials.create({
        publicKey: {
          challenge: new Uint8Array(32).fill(21),
          rp: { id: "localhost", name: "Acme Cloud" },
          user: { id: new Uint8Array([9, 8, 7]), name: "dev@acme-cloud.test", displayName: "Acme Dev" },
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          authenticatorSelection: { residentKey: "required", userVerification: "required" }
        }
      });
      window.__passkeyCreate = { ok: true, json: cred.toJSON() };
    } catch (e) {
      window.__passkeyCreate = { ok: false, error: e.message };
    }
  });
  document.getElementById("signin-passkey-btn").addEventListener("click", async () => {
    try {
      const cred = await navigator.credentials.get({
        publicKey: {
          challenge: new Uint8Array(32).fill(22),
          rpId: "localhost",
          userVerification: "required"
        }
      });
      window.__passkeyGet = { ok: true, json: cred.toJSON() };
    } catch (e) {
      window.__passkeyGet = { ok: false, error: e.message };
    }
  });
</script>`);
    return;
  }

  if (pathname === "/account-created") {
    res.end(`<!doctype html><meta charset="utf-8"><title>Service Account Ready</title><main><h1>Service account created</h1></main>`);
    return;
  }

  res.end(`<!doctype html><meta charset="utf-8"><title>Acme Cloud Home</title><a href="/login">Go to Sign in</a>`);
});

server.listen(0, "127.0.0.1");
await once(server, "listening");
const origin = `http://localhost:${server.address().port}`;

const portProbe = net.createServer();
portProbe.listen(0, "127.0.0.1");
await once(portProbe, "listening");
const port = portProbe.address().port;
await new Promise(r => portProbe.close(r));

await fs.cp(path.join(repo, "browser-extension"), extension, { recursive: true, dereference: true });
const swPath = path.join(extension, "service-worker.js");
await fs.writeFile(swPath, (await fs.readFile(swPath, "utf8")).replaceAll("39272", String(port)));

const fixtureChild = spawn(fixtureBin, [root, String(port), origin], {
  windowsHide: true,
  stdio: ["ignore", "pipe", "pipe"],
});
let fixtureOutput = "";
fixtureChild.stdout.on("data", d => { fixtureOutput += d; });
fixtureChild.stderr.on("data", d => { fixtureOutput += d; });

class McpClient {
  constructor(binary, dataDir) {
    this.child = spawn(binary, ["mcp", "stdio"], {
      windowsHide: true,
      env: { ...process.env, OPENKEYLET_DATA_DIR: dataDir },
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.nextId = 1;
    this.pending = new Map();
    this.buffer = "";
    this.stderr = "";
    this.child.stderr.on("data", d => { this.stderr += d; });
    this.child.stdout.on("data", chunk => {
      this.buffer += chunk.toString("utf8");
      while (true) {
        const idx = this.buffer.indexOf("\n");
        if (idx === -1) break;
        const line = this.buffer.slice(0, idx).trim();
        this.buffer = this.buffer.slice(idx + 1);
        if (!line) continue;
        const msg = JSON.parse(line);
        if (msg.id != null && this.pending.has(msg.id)) {
          const { resolve, reject } = this.pending.get(msg.id);
          this.pending.delete(msg.id);
          if (msg.error) reject(new Error(JSON.stringify(msg.error)));
          else resolve(msg.result);
        }
      }
    });
  }
  request(method, params = {}) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`MCP ${method} timed out. stderr: ${this.stderr.slice(-1000)}`));
      }, 25000);
      this.pending.set(id, {
        resolve: v => { clearTimeout(timer); resolve(v); },
        reject: e => { clearTimeout(timer); reject(e); },
      });
      this.child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }
  notify(method, params = {}) {
    this.child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
  }
  async initialize() {
    const res = await this.request("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "RealWorldJourney", version: "1.0.0" },
    });
    this.notify("notifications/initialized", {});
    return res;
  }
  async callTool(name, args = {}) {
    const res = await this.request("tools/call", { name, arguments: args });
    if (res.isError) throw new Error(`Tool ${name} error: ${JSON.stringify(res.content)}`);
    return res.structuredContent ?? JSON.parse(res.content?.[0]?.text || "{}");
  }
  close() {
    try { this.child.stdin.end(); } catch {}
    try { this.child.kill(); } catch {}
  }
}

async function until(fn, description, timeout = 20000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    if (await fn()) return;
    await new Promise(r => setTimeout(r, 100));
  }
  throw new Error(`Timed out: ${description}. ${fixtureOutput.slice(-1500)}`);
}

async function seedItem(input) {
  await fs.rm(path.join(root, "desktop-edited"), { force: true });
  await fs.writeFile(path.join(root, "desktop-edit.json"), JSON.stringify(input));
  await until(() => fs.access(path.join(root, "desktop-edited")).then(() => true, () => false), `seed ${input.name}`);
}

async function patchSettings(patch) {
  await fs.rm(path.join(root, "settings-patched"), { force: true });
  await fs.writeFile(path.join(root, "settings-patch.json"), JSON.stringify(patch));
  await until(() => fs.access(path.join(root, "settings-patched")).then(() => true, () => false), "patch settings");
}

let context, mcp;
try {
  await until(() => fixtureOutput.includes("READY"), "fixture startup");
  await seedItem({
    name: "Acme Stale Login",
    itemType: "login",
    enabled: true,
    loginUris: [{ uri: origin, matchType: "host" }],
    modules: [{ kind: "url", value: origin }, { kind: "username" }, { kind: "password" }],
    secrets: { password: WRONG_PASS, namedSecrets: { username: VALID_USER } },
  });
  await seedItem({
    name: "Acme Prod Login",
    itemType: "login",
    enabled: true,
    loginUris: [{ uri: origin, matchType: "host" }],
    modules: [{ kind: "url", value: origin }, { kind: "username" }, { kind: "password" }, { kind: "totp" }],
    secrets: { password: VALID_PASS, namedSecrets: { username: VALID_USER, totp: TOTP_SECRET } },
  });
  await seedItem({
    name: "Acme Billing Card",
    itemType: "card",
    enabled: true,
    modules: [
      { kind: "cardholderName" }, { kind: "cardNumber" },
      { kind: "cardExpMonth" }, { kind: "cardExpYear" }, { kind: "cardSecurityCode" },
    ],
    secrets: {
      namedSecrets: {
        cardholderName: "Acme Corp",
        cardNumber: "4111111111111111",
        cardExpMonth: "11",
        cardExpYear: "2030",
        cardSecurityCode: "321",
      },
    },
  });

  const launchOpts = {
    headless: true,
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`],
  };
  if (process.env.OPENKEYLET_CHROME_EXECUTABLE) {
    launchOpts.executablePath = process.env.OPENKEYLET_CHROME_EXECUTABLE;
  } else {
    launchOpts.channel = process.env.OPENKEYLET_CHROME_CHANNEL || "chromium";
  }

  context = await chromium.launchPersistentContext(path.join(root, "profile"), launchOpts);
  const worker = context.serviceWorkers()[0] || await context.waitForEvent("serviceworker");
  await until(async () => (await worker.evaluate(async () => (await chrome.storage.local.get("bridgeStatus")).bridgeStatus)) === "connected", "extension pairing");

  mcp = new McpClient(openkeyletBin, path.join(root, "vault"));
  await mcp.initialize();

  // 1. Agent opens /login using browser_open (two-step login flow).
  const opened = await mcp.callTool("browser_open", { url: `${origin}/login` });
  const tabId = opened.tabId;
  assert.equal(opened.origin, origin);
  assert.match(opened.title, /Acme Cloud/);

  // Step 1: Fill email with stale account and submit -> transitions to password step.
  const step1 = await mcp.callTool("browser_fill_login", {
    item: "Acme Stale Login",
    tabId,
    submit: true,
  });
  assert.deepEqual(step1.filledFields, ["username"]);

  // Step 2: Fill WRONG password -> agent inspects and MUST see the visible error alert!
  await mcp.callTool("browser_fill_login", {
    item: "Acme Stale Login",
    tabId,
    submit: true,
  });
  const afterWrong = await mcp.callTool("browser_inspect", { tabId });
  assert.ok(
    afterWrong.alerts.some(a => a.includes("Invalid email or password")),
    `Agent must see readable login error alert, got: ${JSON.stringify(afterWrong.alerts)}`
  );
  assert.equal(JSON.stringify(afterWrong).includes(WRONG_PASS), false);

  // Step 3: Agent switches to "Acme Prod Login" and submits right password -> reaches /mfa.
  await mcp.callTool("browser_fill_login", {
    item: "Acme Prod Login",
    tabId,
    submit: true,
  });
  await until(async () => {
    const info = await mcp.callTool("browser_inspect", { tabId });
    return info.url.includes("/mfa");
  }, "navigation to /mfa");

  // Step 4: Fill split 6-box TOTP automatically (even without passing includeTotp explicitly on OTP-only page!).
  const totpBefore = totpSha1(TOTP_SECRET);
  const mfaRes = await mcp.callTool("browser_fill_login", {
    item: "Acme Prod Login",
    tabId,
    submit: true,
  });
  const totpAfter = totpSha1(TOTP_SECRET);
  assert.ok(mfaRes.filledFields.includes("totp"), `Expected totp filled: ${JSON.stringify(mfaRes)}`);
  assert.ok(totpBefore.length === 6 && totpAfter.length === 6);

  // Step 5: Lands on /dashboard?code=...&tab=keys#access_token=... -> path readable, query/fragment masked!
  let dashInspect;
  await until(async () => {
    dashInspect = await mcp.callTool("browser_inspect", { tabId });
    return dashInspect.url.includes("/dashboard");
  }, "navigation to /dashboard");
  assert.match(dashInspect.url, /\/dashboard\?code=…&tab=…#…/, `Unexpected masked URL: ${dashInspect.url}`);
  assert.equal(JSON.stringify(dashInspect).includes("oauth_one_time_code_999"), false);
  assert.equal(JSON.stringify(dashInspect).includes("frag_secret_888"), false);
  assert.match(dashInspect.title, /Developer Console/);
  assert.ok(dashInspect.buttons.some(b => b.text.includes("Generate API Key")));

  // 2. Agent clicks "Generate API Key" -> page echoes key in <code>, banner, title, AND URL!
  await mcp.callTool("browser_click", { tabId, text: "Generate API Key" });
  const keyInspect = await mcp.callTool("browser_inspect", { tabId });
  assert.equal(JSON.stringify(keyInspect).includes(ISSUED_WEB_KEY), false, "Issued web key must be scrubbed from inspect");
  assert.ok(keyInspect.keyCandidates?.length >= 1, `Expected keyCandidates: ${JSON.stringify(keyInspect)}`);

  // Unlock and save via browser_save_key -> immediately usable with http_send!
  await worker.evaluate(() => bridgeCall("unlock", { pin: "123456" }));
  const savedWebKey = await mcp.callTool("browser_save_key", {
    tabId,
    origin,
    selectorHint: keyInspect.keyCandidates[0].selectorHint,
    name: "Acme Issued Console Key",
  });
  assert.equal(JSON.stringify(savedWebKey).includes(ISSUED_WEB_KEY), false);

  // Normal http_send returns readable workspace & project list.
  const projRes = await mcp.callTool("http_send", {
    item: savedWebKey.itemId,
    url: "/api/projects",
  });
  assert.equal(projRes.status, 200);
  assert.match(projRes.body, /payments-api/);
  assert.match(projRes.body, /edge-worker/);

  // holdResponse + http_save_secret mints secondary CI key without repeating /api/mint.
  const mintReceipt = await mcp.callTool("http_send", {
    item: savedWebKey.itemId,
    url: "/api/mint",
    method: "POST",
    holdResponse: true,
  });
  assert.equal(mintReceipt.status, 201);
  assert.equal(JSON.stringify(mintReceipt).includes(ISSUED_API_KEY), false);
  const apiCandidate = mintReceipt.candidates.find(c => c.kind === "apiKey");
  assert.ok(apiCandidate, `Expected apiKey candidate: ${JSON.stringify(mintReceipt)}`);
  const mintedRefs = await mcp.callTool("http_save_secret", {
    responseId: mintReceipt.responseId,
    captureSecrets: { ciRunnerKey: `#${apiCandidate.slot}` },
  });
  const checkMinted = await mcp.callTool("http_send", {
    item: savedWebKey.itemId,
    url: "/api/check-minted",
    headers: { "X-Runner-Key": mintedRefs.ciRunnerKey },
  });
  assert.equal(checkMinted.status, 200);
  assert.match(checkMinted.body, /ap-northeast-1/);
  assert.equal(mintHits, 1, "Mint endpoint must only be invoked once");

  // 3. Checkout card autofill without leaking PAN/CVV.
  const cardRes = await mcp.callTool("browser_fill_personal", { item: "Acme Billing Card", tabId });
  assert.ok(cardRes.filled >= 4);
  assert.equal(JSON.stringify(cardRes).includes("4111111111111111"), false);
  assert.equal(JSON.stringify(cardRes).includes("321"), false);

  // 4. Passkey registration + cryptographic sign-in verification.
  await patchSettings({ browserAgentPasskey: true });
  const pkCreate = await mcp.callTool("browser_passkey", {
    operation: "create",
    triggerText: "Register Passkey",
    tabId,
  });
  const pkGet = await mcp.callTool("browser_passkey", {
    operation: "get",
    triggerText: "Sign in with Passkey",
    tabId,
  });
  assert.equal(pkGet.credentialId, pkCreate.credentialId);

  const page = context.pages().find(p => p.url().startsWith(origin));
  await until(async () => Boolean(await page.evaluate(() => window.__passkeyCreate && window.__passkeyGet)), "passkey DOM results");
  const { cRes, gRes } = await page.evaluate(() => ({ cRes: window.__passkeyCreate, gRes: window.__passkeyGet }));
  assert.equal(cRes.ok, true);
  assert.equal(gRes.ok, true);
  const pubKey = createPublicKey({ key: Buffer.from(cRes.json.response.publicKey, "base64url"), format: "der", type: "spki" });
  const auth = Buffer.from(gRes.json.response.authenticatorData, "base64url");
  const clientData = Buffer.from(gRes.json.response.clientDataJSON, "base64url");
  assert.ok(verify("sha256", Buffer.concat([auth, createHash("sha256").update(clientData).digest()]), pubKey, Buffer.from(gRes.json.response.signature, "base64url")));

  // 5. New service account submission -> browser_save_login -> immediate reuse on /login!
  await worker.evaluate(() => chrome.storage.local.set({ captureEnabled: true }));
  await until(() => worker.evaluate(async id => (await chrome.scripting.executeScript({
    target: { tabId: id }, func: () => captureSubmissionEnabled,
  }))[0].result, tabId), "capture enabled in tab");
  await page.locator("#new-user").fill("ci-bot@acme-cloud.test");
  await page.locator("#new-pass").fill(NEW_SIGNUP_PASS);
  await page.locator("#create-acct-btn").click();
  await page.waitForURL(`${origin}/account-created`);
  await until(() => worker.evaluate(id => Boolean(captureSummary(getLoginCapture(id))), tabId), "signup captured");

  await worker.evaluate(() => bridgeCall("lock"));
  const lockedSave = await mcp.request("tools/call", {
    name: "browser_save_login",
    arguments: { tabId, name: "Acme CI Bot" },
  });
  assert.equal(lockedSave.isError, true, "browser_save_login must require unlock");

  await worker.evaluate(() => bridgeCall("unlock", { pin: "123456" }));
  const savedSignup = await mcp.callTool("browser_save_login", { tabId, name: "Acme CI Bot" });
  assert.equal(JSON.stringify(savedSignup).includes(NEW_SIGNUP_PASS), false);

  // Immediately reuse the newly saved account on /login!
  await mcp.callTool("browser_open", { url: `${origin}/login`, tabId, newTab: false });
  const reuseStep1 = await mcp.callTool("browser_fill_login", { item: "Acme CI Bot", tabId, submit: true });
  assert.deepEqual(reuseStep1.filledFields, ["username"]);
  const reuseStep2 = await mcp.callTool("browser_fill_login", { item: "Acme CI Bot", tabId, submit: false });
  assert.deepEqual(reuseStep2.filledFields, ["password"]);
  assert.equal(await page.locator("#password").inputValue(), NEW_SIGNUP_PASS);

  console.log(JSON.stringify({
    ok: true,
    journey: [
      "two-step login wrong password -> readable error alert via browser_inspect",
      "retry with right password -> split 6-box TOTP auto-fill -> masked dashboard URL",
      "Generate API Key -> scrubbed title/banner/URL + browser_save_key -> normal http_send",
      "http_send(holdResponse) + http_save_secret -> one-time mint verified (hits=1)",
      "browser_fill_personal card autofill without secret leakage",
      "browser_passkey register + sign-in + ECDSA P-256 signature verification",
      "new service account signup -> browser_save_login (lock guard) -> immediate reuse",
    ],
  }, null, 2));
} finally {
  mcp?.close();
  await context?.close();
  await fs.writeFile(path.join(root, "stop"), "").catch(() => {});
  if (fixtureChild.exitCode === null) {
    await Promise.race([once(fixtureChild, "exit"), new Promise(r => setTimeout(r, 2000))]);
    if (fixtureChild.exitCode === null) fixtureChild.kill();
  }
  server.close();
}
