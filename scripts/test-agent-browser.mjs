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

const root = await fs.mkdtemp(path.join(os.tmpdir(), "openkeylet-browser-test-"));
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

const html = `<!doctype html>
<meta charset="utf-8">
<title>Agent Browser Fixture</title>
<form id="login-form">
  <label>Username <input id="username" autocomplete="username"></label>
  <label>Password <input id="password" type="password" autocomplete="current-password"></label>
  <div id="otp-boxes">
    <input class="otp-box" maxlength="1" inputmode="numeric" autocomplete="one-time-code" aria-label="OTP digit 1">
    <input class="otp-box" maxlength="1" inputmode="numeric" aria-label="OTP digit 2">
    <input class="otp-box" maxlength="1" inputmode="numeric" aria-label="OTP digit 3">
    <input class="otp-box" maxlength="1" inputmode="numeric" aria-label="OTP digit 4">
    <input class="otp-box" maxlength="1" inputmode="numeric" aria-label="OTP digit 5">
    <input class="otp-box" maxlength="1" inputmode="numeric" aria-label="OTP digit 6">
  </div>
  <button id="login-submit" type="submit">Sign in</button>
</form>
<div id="api-section">
  <label for="api-token-input">API Key</label>
  <input id="api-token-input" type="password" placeholder="Enter API key">
</div>
<form id="card-form">
  <input id="cardholder" autocomplete="cc-name">
  <input id="cardnumber" autocomplete="cc-number">
  <select id="cardmonth" autocomplete="cc-exp-month"><option value=""></option><option value="07">July</option></select>
  <input id="cardyear" autocomplete="cc-exp-year">
  <input id="cardcode" autocomplete="cc-csc">
</form>
<div>
  <button id="step-btn" type="button">Continue to Workspace</button>
  <button id="register-passkey-btn" type="button">Register Passkey</button>
  <button id="signin-passkey-btn" type="button">Sign in with Passkey</button>
</div>
<script>
  window.__loginSubmitted = 0;
  window.__stepClicked = 0;
  window.__passkeyCreateResult = null;
  window.__passkeyGetResult = null;
  document.getElementById("login-form").addEventListener("submit", (e) => {
    e.preventDefault();
    window.__loginSubmitted++;
  });
  document.getElementById("step-btn").addEventListener("click", () => {
    window.__stepClicked++;
  });
  document.getElementById("register-passkey-btn").addEventListener("click", async () => {
    try {
      const challenge = new Uint8Array(32).fill(11);
      const cred = await navigator.credentials.create({
        publicKey: {
          challenge,
          rp: { id: "localhost", name: "Agent Fixture" },
          user: { id: new Uint8Array([4, 5, 6]), name: "agent-user", displayName: "Agent User" },
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          authenticatorSelection: { residentKey: "required", userVerification: "required" },
          extensions: { credProps: true }
        }
      });
      window.__passkeyCreateResult = { ok: true, instance: cred instanceof PublicKeyCredential, json: cred.toJSON() };
    } catch (e) {
      window.__passkeyCreateResult = { ok: false, error: e.message, name: e.name };
    }
  });
  document.getElementById("signin-passkey-btn").addEventListener("click", async () => {
    try {
      const challenge = new Uint8Array(32).fill(12);
      const cred = await navigator.credentials.get({
        publicKey: {
          challenge,
          rpId: "localhost",
          userVerification: "required"
        }
      });
      window.__passkeyGetResult = { ok: true, instance: cred instanceof PublicKeyCredential, json: cred.toJSON() };
    } catch (e) {
      window.__passkeyGetResult = { ok: false, error: e.message, name: e.name };
    }
  });
</script>`;

const issuedWebKey = "new-key-from-the-test-issuer";
const issuedApiKey = "one-time-api-response-test-key";
let issues = 0;
const server = http.createServer((req, res) => {
  if (req.url === "/issue") {
    issues++;
    res.writeHead(req.headers.authorization === "Bearer " + issuedWebKey ? 201 : 401, {
      "Content-Type": "application/json", "X-Test-Note": issuedApiKey,
    });
    res.end(JSON.stringify({ unusualEnvelope: { access_token: issuedApiKey }, [issuedApiKey]: "ignored" }));
    return;
  }
  if (req.url === "/use") {
    res.writeHead(req.headers["x-issued"] === issuedApiKey ? 200 : 401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, records: ["example.com"] }));
    return;
  }
  res.setHeader("Content-Type", "text/html");
  res.end(html);
});
server.listen(0, "127.0.0.1");
await once(server, "listening");
const origin = `http://localhost:${server.address().port}`;

const portProbe = net.createServer();
portProbe.listen(0, "127.0.0.1");
await once(portProbe, "listening");
const port = portProbe.address().port;
await new Promise(r => portProbe.close(r));

await fs.cp(path.join(repo, "browser-extension"), extension, { recursive: true });
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
        reject(new Error(`MCP request ${method} timed out. stderr: ${this.stderr.slice(-1000)}`));
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
      clientInfo: { name: "Antigravity", version: "1.0.0" },
    });
    this.notify("notifications/initialized", {});
    return res;
  }

  async callTool(name, args = {}) {
    const res = await this.request("tools/call", { name, arguments: args });
    if (res.isError) {
      throw new Error(`Tool ${name} error: ${JSON.stringify(res.content)}`);
    }
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
  const totpSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  await seedItem({
    name: "Agent Login",
    itemType: "login",
    enabled: true,
    loginUris: [{ uri: origin, matchType: "host" }],
    modules: [
      { kind: "url", value: origin },
      { kind: "username" },
      { kind: "password" },
      { kind: "totp" },
      { kind: "apiCredential" },
    ],
    secrets: {
      password: "agent-secret-password-99",
      namedSecrets: {
        username: "agent-alice",
        totp: totpSecret,
        apiCredential: "ok_live_agent_secret_token_42",
      },
    },
  });
  await seedItem({
    name: "Agent Card",
    itemType: "card",
    enabled: true,
    modules: [
      { kind: "cardholderName" },
      { kind: "cardNumber" },
      { kind: "cardExpMonth" },
      { kind: "cardExpYear" },
      { kind: "cardSecurityCode" },
    ],
    secrets: {
      namedSecrets: {
        cardholderName: "Agent Cardholder",
        cardNumber: "4242424242424242",
        cardExpMonth: "07",
        cardExpYear: "2031",
        cardSecurityCode: "789",
      },
    },
  });

  context = await chromium.launchPersistentContext(path.join(root, "profile"), {
    channel: "chromium",
    headless: true,
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`],
  });
  const worker = context.serviceWorkers()[0] || await context.waitForEvent("serviceworker");
  await until(async () => (await worker.evaluate(async () => (await chrome.storage.local.get("bridgeStatus")).bridgeStatus)) === "connected", "extension pairing");

  const page = await context.newPage();
  await page.goto(origin);
  await page.bringToFront();

  mcp = new McpClient(openkeyletBin, path.join(root, "vault"));
  await mcp.initialize();

  const tools = await mcp.request("tools/list");
  const toolNames = tools.tools.map(t => t.name);
  for (const required of ["browser_inspect", "browser_fill_login", "browser_save_login", "browser_fill_personal", "browser_click", "browser_passkey", "credential_fill", "secret_write_file"]) {
    assert.ok(toolNames.includes(required), `Missing MCP tool: ${required}`);
  }

  // 0. secret_write_file writes rendered config file without returning plaintext
  const envOut = path.join(root, "rendered", ".env");
  const writeRes = await mcp.callTool("secret_write_file", {
    item: "Agent Login",
    path: envOut,
    content: "API_KEY={{openkeylet:apiCredential}}\n",
  });
  assert.equal(JSON.stringify(writeRes).includes("ok_live_agent_secret_token_42"), false);
  assert.equal(await fs.readFile(envOut, "utf8"), "API_KEY=ok_live_agent_secret_token_42\n");
  console.log("0/6 secret_write_file verified");

  // 1. Inspect page without leaking values
  await page.locator("#username").fill("preexisting-never-leak");
  await page.evaluate(() => document.activeElement?.blur());
  const inspected = await mcp.callTool("browser_inspect");
  assert.equal(inspected.origin, origin);
  assert.ok(inspected.loginForms.length >= 1);
  assert.ok(inspected.fields.length >= 4);
  assert.ok(inspected.buttons.some(b => b.text.includes("Register Passkey")));
  assert.ok(inspected.matchingItems.some(i => i.name === "Agent Login" && i.hasTotp));
  assert.equal(JSON.stringify(inspected).includes("preexisting-never-leak"), false, "browser_inspect must never expose input values");
  console.log("1/6 browser_inspect verified");

  // 2. Fill login + split 6-digit OTP + submit WITHOUT focusing any input
  const expectedTotpBefore = totpSha1(totpSecret);
  const loginRes = await mcp.callTool("browser_fill_login", {
    item: "Agent Login",
    includeTotp: true,
    submit: true,
  });
  const expectedTotpAfter = totpSha1(totpSecret);
  assert.deepEqual(loginRes.filledFields, ["username", "password", "totp"]);
  assert.equal(loginRes.submitted, true);
  assert.equal(JSON.stringify(loginRes).includes("agent-secret-password-99"), false, "secret leaked in loginRes");
  assert.equal(await page.locator("#username").inputValue(), "agent-alice");
  assert.equal(await page.locator("#password").inputValue(), "agent-secret-password-99");
  const otpFilled = await page.locator(".otp-box").evaluateAll(els => els.map(e => e.value).join(""));
  assert.ok([expectedTotpBefore, expectedTotpAfter].includes(otpFilled), `Unexpected OTP ${otpFilled}`);
  await until(async () => (await page.evaluate(() => window.__loginSubmitted)) === 1, "login form submitted");
  console.log("2/6 browser_fill_login + split OTP + submit verified");

  // 3. Targeted credential_fill by CSS selector without focus
  await page.evaluate(() => document.activeElement?.blur());
  const apiFill = await mcp.callTool("credential_fill", {
    item: "Agent Login",
    module: "apiCredential",
    target: "browser",
    selector: "#api-token-input",
  });
  assert.equal(apiFill.target, "browser");
  assert.equal(JSON.stringify(apiFill).includes("ok_live_agent_secret_token_42"), false);
  assert.equal(await page.locator("#api-token-input").inputValue(), "ok_live_agent_secret_token_42");
  console.log("3/6 targeted credential_fill verified");

  // 4. Personal card autofill via MCP without leaking card number/CVV
  const cardRes = await mcp.callTool("browser_fill_personal", { item: "Agent Card" });
  assert.equal(cardRes.itemType, "card");
  assert.ok(cardRes.filled >= 4);
  assert.equal(JSON.stringify(cardRes).includes("4242424242424242"), false);
  assert.equal(JSON.stringify(cardRes).includes("789"), false);
  assert.equal(await page.locator("#cardnumber").inputValue(), "4242424242424242");
  assert.equal(await page.locator("#cardmonth").inputValue(), "07");
  assert.equal(await page.locator("#cardcode").inputValue(), "789");
  console.log("4/6 browser_fill_personal verified");

  // 5. browser_click by visible text
  const clickRes = await mcp.callTool("browser_click", { text: "Continue to Workspace" });
  assert.equal(clickRes.clickedText, "Continue to Workspace");
  assert.equal(await page.evaluate(() => window.__stepClicked), 1);
  console.log("5/6 browser_click verified");

  // 6a-pre. Agent Passkey signing is OFF by default and must be explicitly enabled
  const deniedByDefault = await mcp.request("tools/call", {
    name: "browser_passkey",
    arguments: { operation: "create", triggerText: "Register Passkey" },
  });
  assert.equal(deniedByDefault.isError, true, "browser_passkey must fail while off by default");
  assert.match(JSON.stringify(deniedByDefault.content), /Agent Passkey signing is disabled/);

  await patchSettings({ browserAgentPasskey: true });

  // 6a. browser_passkey CREATE (atomic arm + triggerText click, no manual popup)
  const createRes = await mcp.callTool("browser_passkey", {
    operation: "create",
    triggerText: "Register Passkey",
  });
  assert.equal(createRes.operation, "create");
  assert.equal(createRes.rpId, "localhost");
  assert.equal(createRes.userName, "agent-user");
  await until(async () => Boolean(await page.evaluate(() => window.__passkeyCreateResult)), "passkey create result");
  const pageCreate = await page.evaluate(() => window.__passkeyCreateResult);
  assert.equal(pageCreate.ok, true, JSON.stringify(pageCreate));
  assert.equal(pageCreate.instance, true);
  assert.equal(context.pages().some(p => p.url().includes("request.html")), false, "Agent passkey create must not open manual popup");

  // Confirm newly created passkey appears in items_search
  const searchAfterCreate = await mcp.callTool("items_search", { query: "agent-user" });
  assert.ok(searchAfterCreate.items.some(i => i.actions.includes("browser_passkey") && i.passkeys.some(k => k.credentialId === createRes.credentialId)));

  // 6b. browser_passkey GET (atomic arm + triggerText click, cryptographic ECDSA verification)
  const getRes = await mcp.callTool("browser_passkey", {
    operation: "get",
    triggerText: "Sign in with Passkey",
  });
  assert.equal(getRes.operation, "get");
  assert.equal(getRes.credentialId, createRes.credentialId);
  await until(async () => Boolean(await page.evaluate(() => window.__passkeyGetResult)), "passkey get result");
  const pageGet = await page.evaluate(() => window.__passkeyGetResult);
  assert.equal(pageGet.ok, true, JSON.stringify(pageGet));
  assert.equal(pageGet.instance, true);
  assert.equal(context.pages().some(p => p.url().includes("request.html")), false, "Agent passkey get must not open manual popup");

  // Independently verify the P-256 ECDSA signature & UV+UP flags!
  const pubKey = createPublicKey({ key: Buffer.from(pageCreate.json.response.publicKey, "base64url"), format: "der", type: "spki" });
  const auth = Buffer.from(pageGet.json.response.authenticatorData, "base64url");
  const clientData = Buffer.from(pageGet.json.response.clientDataJSON, "base64url");
  assert.equal(JSON.parse(clientData).origin, origin);
  assert.equal(auth[32] & 0x05, 0x05, "UP and UV flags must both be set");
  assert.ok(verify("sha256", Buffer.concat([auth, createHash("sha256").update(clientData).digest()]), pubKey, Buffer.from(pageGet.json.response.signature, "base64url")));

  // 6c. Manual confirmation window isolation: agent MUST NOT take over a user-opened confirmation prompt
  await page.evaluate(() => { window.__passkeyGetResult = null; });
  const popupPromise = context.waitForEvent("page");
  await page.locator("#signin-passkey-btn").click();
  const promptPage = await popupPromise;
  await promptPage.waitForURL(/request\.html/);
  const inspectedPending = await mcp.callTool("browser_inspect");
  assert.equal(inspectedPending.pendingPasskeys.length, 1);
  assert.equal(inspectedPending.pendingPasskeys[0].agentManaged, false);
  const pendingReqId = inspectedPending.pendingPasskeys[0].requestId;

  const hijackById = await mcp.request("tools/call", {
    name: "browser_passkey",
    arguments: { requestId: pendingReqId },
  });
  assert.equal(hijackById.isError, true, "browser_passkey must refuse hijacking a manual confirmation by requestId");
  assert.match(JSON.stringify(hijackById.content), /Refused:.*manual Passkey confirmation/);

  const hijackImplicit = await mcp.request("tools/call", {
    name: "browser_passkey",
    arguments: { operation: "get" },
  });
  assert.equal(hijackImplicit.isError, true, "browser_passkey must refuse hijacking an open manual confirmation implicitly");
  assert.match(JSON.stringify(hijackImplicit.content), /Refused:.*manual Passkey confirmation/);

  assert.equal(context.pages().some(p => p.url().includes("request.html")), true, "Manual confirmation popup must stay open");
  assert.equal(await page.evaluate(() => window.__passkeyGetResult), null, "Manual request must not have been signed by agent");
  await promptPage.close();
  console.log("6/6 browser_passkey (default-off + create + get + ECDSA verify + manual prompt isolation) verified");

  await page.bringToFront();
  const tabId = inspected.tabId;
  await worker.evaluate(() => chrome.storage.local.set({ captureEnabled: true }));
  await until(() => worker.evaluate(async tabId => (await chrome.scripting.executeScript({
    target: { tabId }, func: () => captureSubmissionEnabled,
  }))[0].result, tabId), "login save suggestions enabled");
  const capturedPassword = "synthetic-agent-capture-password";
  await page.locator("#username").fill("new-browser-account");
  await page.locator("#password").fill(capturedPassword);
  await page.locator("#login-submit").click();
  await until(() => worker.evaluate(id => Boolean(captureSummary(getLoginCapture(id))), tabId), "submitted login captured");
  const argumentsToSave = { tabId, name: "Agent Saved Login" };
  const saveLogin = () => mcp.request("tools/call", { name: "browser_save_login", arguments: argumentsToSave });
  const lockedSave = await saveLogin();
  assert.equal(lockedSave.isError, true);
  assert.match(JSON.stringify(lockedSave), /Unlock OpenKeylet/);
  assert.equal(JSON.stringify(lockedSave).includes(capturedPassword), false);
  await worker.evaluate(() => bridgeCall("unlock", { pin: "123456" }));
  const savedLogin = await saveLogin();
  assert.equal(savedLogin.isError ?? false, false);
  assert.deepEqual(Object.keys(savedLogin.structuredContent).sort(), ["itemId", "origin"]);
  assert.equal(savedLogin.structuredContent.origin, origin);
  assert.equal(JSON.stringify(savedLogin).includes(capturedPassword), false);
  const loginArgs = { origin, id: savedLogin.structuredContent.itemId };
  const storedLogin = await worker.evaluate(args => bridgeCall("password.get", args), loginArgs);
  assert.equal(storedLogin.password, capturedPassword);
  const search = await mcp.callTool("items_search", { query: "Agent Saved Login" });
  assert.equal(search.items.length, 1);
  assert.equal(JSON.stringify(search).includes(capturedPassword), false);
  assert.equal((await saveLogin()).isError, true, "A saved capture is consumed");

  await page.evaluate(key => {
    document.title = key;
    const output = document.createElement("output");
    output.textContent = key;
    const heading = document.createElement("h2");
    heading.append(output);
    document.body.append(heading);
    history.replaceState(null, "", "/issued/" + key + "?" + key + "=1");
  }, issuedWebKey);
  const keyPage = await mcp.callTool("browser_inspect", { tabId });
  assert.ok(!JSON.stringify(keyPage).includes(issuedWebKey));
  const saveKey = { tabId, origin, selectorHint: keyPage.keyCandidates[0].selectorHint, name: "Issued Test API" };
  const mismatch = await mcp.request("tools/call", { name: "browser_save_key", arguments: { ...saveKey, origin: "https://other.example" } });
  assert.equal(mismatch.isError, true);
  await worker.evaluate(() => bridgeCall("lock"));
  const lockedKey = await mcp.request("tools/call", { name: "browser_save_key", arguments: saveKey });
  assert.equal(lockedKey.isError, true);
  await worker.evaluate(() => bridgeCall("unlock", { pin: "123456" }));
  const webKey = await mcp.callTool("browser_save_key", saveKey);
  assert.ok(webKey.reference.includes(webKey.itemId) && !JSON.stringify(webKey).includes(issuedWebKey));
  const receipt = await mcp.callTool("http_send", { item: webKey.itemId, url: "/issue", method: "POST", holdResponse: true });
  assert.equal(receipt.status, 201);
  assert.ok(!JSON.stringify(receipt).includes(issuedApiKey));
  const token = receipt.candidates.find(candidate => candidate.kind === "accessToken");
  const refs = await mcp.callTool("http_save_secret", { responseId: receipt.responseId, captureSecrets: { issuedKey: "#" + token.slot } });
  assert.ok(!JSON.stringify(refs).includes(issuedApiKey));
  const use = await mcp.callTool("http_send", { item: webKey.itemId, url: "/use", headers: { "X-Issued": refs.issuedKey } });
  assert.equal(use.status, 200);
  assert.ok(use.body.includes("example.com"), "Normal http_send returns readable response body");
  assert.equal(issues, 1);
  console.log(JSON.stringify({
    ok: true,
    checks: [
      "web and API issuance: inspect, save and use opaque references without reissuing",
      "mcp tools/list",
      "browser_inspect (zero value leakage + matchingItems)",
      "browser_fill_login (unfocused username + password + split 6-box TOTP + submit)",
      "credential_fill (targeted CSS selector without focus)",
      "browser_fill_personal (card autofill without secret leakage)",
      "browser_click (visible text match)",
      "browser_passkey default OFF guard",
      "browser_passkey create (atomic arm + trigger, zero manual popup)",
      "browser_passkey get (atomic arm + trigger, ECDSA P-256 + UV/UP verified)",
      "browser_passkey refuses takeover of manual confirmation window",
      "browser_save_login (requires unlock, consumes capture, no MCP plaintext)",
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
