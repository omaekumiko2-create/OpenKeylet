// Real-world Passkey (WebAuthn L3 optional extensions, empty pubKeyCredParams,
// UVPA availability, conditional mediation passthrough, InvalidStateError) &
// International/CJK Checkout Autofill (Card MM/YY, month selects, CJK full name,
// Country ISO2 <-> EN/ZH mapping, tel-national) verification in real Chromium.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import { once } from 'node:events';
import { chromium } from 'playwright';

const extDir = path.resolve(import.meta.dirname, '../browser-extension');
const webauthnMain = await fs.readFile(path.join(extDir, 'webauthn-main.js'), 'utf8');
const providerJs = await fs.readFile(path.join(extDir, 'provider.js'), 'utf8');

// Extract self-contained usePersonalForm from provider.js for direct DOM E2E execution
const startIdx = providerJs.indexOf('function usePersonalForm(');
const endIdx = providerJs.indexOf('function takeMatchingPasskeyWaiter(');
assert.ok(startIdx > 0 && endIdx > startIdx, 'Found usePersonalForm in provider.js');
const usePersonalFormSource = providerJs.slice(startIdx, endIdx);

const html = `<!doctype html>
<html><head><meta charset="utf-8"><title>Checkout & Passkey Real-World Test</title></head>
<body>
  <form id="card-form">
    <label for="c-name">持卡人姓名</label><input id="c-name" name="cardholder" />
    <label for="c-num">信用卡号</label><input id="c-num" name="cardnum" />
    <label for="c-exp">到期年月</label><input id="c-exp" name="mmyy" placeholder="MM / YY" />
    <select id="c-month-en" autocomplete="cc-exp-month">
      <option value="">Month</option>
      <option value="04 - April">04 - April</option>
      <option value="07 - July">07 - July</option>
    </select>
    <select id="c-month-zh" name="expmonth">
      <option value="">月份</option>
      <option value="m4">4月</option>
      <option value="m7">7月</option>
    </select>
    <input id="c-year" autocomplete="cc-exp-year" maxlength="2" />
    <input id="c-cvv" type="password" name="cvc" />
  </form>
  <form id="identity-form">
    <input id="i-full" autocomplete="name" />
    <input id="i-phone" autocomplete="tel-national" />
    <select id="i-country-iso" autocomplete="country">
      <option value="">Select</option>
      <option value="US">United States</option>
      <option value="CN">China</option>
      <option value="JP">Japan</option>
    </select>
    <select id="i-country-zh" name="country">
      <option value="">选择国家</option>
      <option value="us-opt">美国</option>
      <option value="cn-opt">中国</option>
    </select>
  </form>
</body></html>`;

const server = http.createServer((req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(html);
});
server.listen(0, 'localhost');
await once(server, 'listening');
const url = `http://localhost:${server.address().port}/`;

const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.goto(url);

  // 1. Test real-world WebAuthn provider behavior (webauthn-main.js)
  await page.evaluate((src) => {
    window.__nativeCalls = [];
    const fakeCreds = {
      create: async (opts) => { window.__nativeCalls.push({ op: 'create', opts }); return { native: true }; },
      get: async (opts) => { window.__nativeCalls.push({ op: 'get', opts }); return { native: true }; },
    };
    Object.defineProperty(navigator, 'credentials', { value: fakeCreds, configurable: true });
    // Run actual webauthn-main.js!
    eval(src);
    // Simulate content-script <-> service-worker responder
    window.__openkeyletCalls = [];
    window.addEventListener('message', (event) => {
      if (event.data?.type !== 'openkeylet-webauthn-call') return;
      window.__openkeyletCalls.push(event.data);
      const { requestId, operation, options } = event.data;
      if (options.excludeCredentials?.some(e => e.id === 'EXISTING_CRED')) {
        window.postMessage({ type: 'openkeylet-webauthn-result', requestId, result: { error: 'InvalidStateError: A matching passkey already exists', name: 'InvalidStateError' } }, location.origin);
        return;
      }
      const b64 = 'AQIDBA'; // unpadded base64url (tests padding fix!)
      window.postMessage({
        type: 'openkeylet-webauthn-result',
        requestId,
        result: {
          credential: operation === 'create'
            ? {
                id: 'NEW_CRED_1', rawId: b64, type: 'public-key', authenticatorAttachment: 'platform',
                response: { clientDataJSON: b64, attestationObject: b64, authenticatorData: b64, publicKey: b64, publicKeyAlgorithm: -7, transports: ['internal'] },
                clientExtensionResults: { credProps: { rk: true } },
              }
            : {
                id: 'NEW_CRED_1', rawId: b64, type: 'public-key', authenticatorAttachment: 'platform',
                response: { clientDataJSON: b64, authenticatorData: b64, signature: b64, userHandle: b64 },
                clientExtensionResults: {},
              },
        },
      }, location.origin);
    });
  }, webauthnMain);

  const webauthnChecks = await page.evaluate(async () => {
    const uvpa = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();

    // Real-world GitHub/Google/SimpleWebAuthn style create with prf + preferred largeBlob + empty pubKeyCredParams!
    const created = await navigator.credentials.create({
      publicKey: {
        challenge: new Uint8Array([1, 2, 3, 4]).subarray(1, 3), // non-zero byteOffset!
        rp: { id: 'localhost', name: 'Local' },
        user: { id: new Uint8Array([9, 8, 7]), name: 'alice', displayName: 'Alice' },
        pubKeyCredParams: [],
        extensions: { credProps: true, prf: {}, largeBlob: { support: 'preferred' } },
      },
    });
    const hasMethods = typeof created.response.getTransports === 'function'
      && typeof created.response.getPublicKey === 'function'
      && typeof created.response.getPublicKeyAlgorithm === 'function'
      && typeof created.response.getAuthenticatorData === 'function'
      && typeof created.toJSON === 'function';
    const transports = created.response.getTransports();
    const alg = created.response.getPublicKeyAlgorithm();
    const rawIdLen = created.rawId.byteLength;

    // InvalidStateError on excluded credential
    let excludeErr = '';
    try {
      await navigator.credentials.create({
        publicKey: {
          challenge: new Uint8Array([1, 2, 3]),
          rp: { id: 'localhost', name: 'Local' },
          user: { id: new Uint8Array([9]), name: 'alice', displayName: 'Alice' },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          excludeCredentials: [{ type: 'public-key', id: Uint8Array.from(atob('RVhJU1RJTkdfQ1JFRA=='), c => c.charCodeAt(0)) }],
        },
      });
    } catch (e) { excludeErr = e.name; }

    // Conditional mediation passes through to native browser (no intrusive popup!)
    const conditionalRes = await navigator.credentials.get({
      mediation: 'conditional',
      publicKey: { challenge: new Uint8Array([4, 5, 6]) },
    });

    // Required largeBlob falls back to native browser
    const requiredBlobRes = await navigator.credentials.create({
      publicKey: {
        challenge: new Uint8Array([4, 5, 6]),
        rp: { id: 'localhost', name: 'Local' },
        user: { id: new Uint8Array([9]), name: 'alice', displayName: 'Alice' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        extensions: { largeBlob: { support: 'required' } },
      },
    });

    return {
      uvpa,
      createdId: created.id,
      hasMethods,
      transports,
      alg,
      rawIdLen,
      openkeyletCallCount: window.__openkeyletCalls.length,
      nativeCallCount: window.__nativeCalls.length,
      conditionalNative: conditionalRes.native === true,
      requiredBlobNative: requiredBlobRes.native === true,
      challengeEncoded: window.__openkeyletCalls[0].options.challenge,
    };
  });

  assert.equal(webauthnChecks.uvpa, true, 'UVPA reports true so sites show Passkey UI even without Windows Hello/Touch ID');
  assert.equal(webauthnChecks.createdId, 'NEW_CRED_1', 'OpenKeylet handles create with prf + largeBlob:preferred + empty pubKeyCredParams');
  assert.equal(webauthnChecks.hasMethods, true, 'Synthetic PublicKeyCredential implements full WebAuthn L3 response methods + toJSON');
  assert.deepEqual(webauthnChecks.transports, ['internal']);
  assert.equal(webauthnChecks.alg, -7);
  assert.equal(webauthnChecks.rawIdLen, 4, 'Unpadded Base64URL decoded cleanly');
  assert.equal(webauthnChecks.challengeEncoded, 'AgM', 'Subarray Uint8Array respects byteOffset/byteLength');
  assert.equal(webauthnChecks.conditionalNative, true, 'Conditional mediation passes to browser native');
  assert.equal(webauthnChecks.requiredBlobNative, true, 'Required largeBlob falls back to browser native');
  assert.equal(webauthnChecks.nativeCallCount, 2);

  // 2. Test real-world international & Chinese checkout autofill (usePersonalForm)
  const fillResult = await page.evaluate((fnSrc) => {
    const usePersonalForm = eval(`(${fnSrc})`);
    const cardRes = usePersonalForm(location.origin, 'card', {
      cardholderName: '张三',
      cardNumber: '4111 1111 1111 1111',
      cardExpMonth: ' 7 ',
      cardExpYear: ' 2030 ',
      cardSecurityCode: '842',
    });
    const idRes1 = usePersonalForm(location.origin, 'identity', {
      firstName: '三',
      lastName: '张',
      phone: '13800138000',
      country: '中国',
    });
    const snap1 = {
      cardFilled: cardRes.filled,
      cName: document.getElementById('c-name').value,
      cNum: document.getElementById('c-num').value,
      cExp: document.getElementById('c-exp').value,
      cMonthEn: document.getElementById('c-month-en').value,
      cMonthZh: document.getElementById('c-month-zh').value,
      cYear: document.getElementById('c-year').value,
      cCvv: document.getElementById('c-cvv').value,
      idFilled: idRes1.filled,
      iFull: document.getElementById('i-full').value,
      iPhone: document.getElementById('i-phone').value,
      iCountryIso: document.getElementById('i-country-iso').value,
      iCountryZh: document.getElementById('i-country-zh').value,
    };
    // Also test US ISO2 -> Chinese select + English full name
    usePersonalForm(location.origin, 'identity', {
      firstName: 'Alice',
      lastName: 'Smith',
      country: 'US',
    });
    return {
      ...snap1,
      enFull: document.getElementById('i-full').value,
      usOnZhSelect: document.getElementById('i-country-zh').value,
    };
  }, usePersonalFormSource);

  assert.equal(fillResult.cardFilled, 7);
  assert.equal(fillResult.cName, '张三');
  assert.equal(fillResult.cNum, '4111 1111 1111 1111');
  assert.equal(fillResult.cExp, '07/30');
  assert.equal(fillResult.cMonthEn, '07 - July', 'Matches "07 - July" select option');
  assert.equal(fillResult.cMonthZh, 'm7', 'Matches "7月" Chinese month select option');
  assert.equal(fillResult.cYear, '30', 'Trims and formats 2-digit year');
  assert.equal(fillResult.cCvv, '842');
  assert.equal(fillResult.iFull, '张三', 'CJK full name formats as lastName+firstName without space');
  assert.equal(fillResult.iPhone, '13800138000', 'tel-national maps to phone');
  assert.equal(fillResult.iCountryIso, 'CN', '"中国" matches ISO2 "CN" select option');
  assert.equal(fillResult.iCountryZh, 'cn-opt', '"中国" matches Chinese select option');
  assert.equal(fillResult.enFull, 'Alice Smith', 'Latin full name joins with space');
  assert.equal(fillResult.usOnZhSelect, 'us-opt', '"US" matches "美国" select option');

  assert.deepEqual(errors, [], `Zero page errors: ${errors.join('; ')}`);
  console.log('REAL-WORLD PASSKEY & INTERNATIONAL AUTOFILL E2E PASSED');
} finally {
  await browser.close();
  server.close();
}
