import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import http from "node:http";
import net from "node:net";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createPublicKey, verify, createHash } from "node:crypto";
import { chromium } from "playwright";

const repo=path.resolve(import.meta.dirname,"..");
const root=await fs.mkdtemp(path.join(os.tmpdir(),"openkeylet-browser-test-"));
const extension=path.join(root,"extension");
const fixture=process.argv[2] || path.join(process.env.CARGO_TARGET_DIR || path.join(repo,"src-tauri/target"),"debug/examples",process.platform==="win32"?"browser_fixture.exe":"browser_fixture");
// Independent decoder for the definite-length CBOR used in WebAuthn attestation/COSE.
function readCbor(bytes, start=0) {
  let offset=start;
  function read() {
    const head=bytes[offset++], major=head>>5, ai=head&31;
    let n=ai;
    if(ai===24)n=bytes[offset++];
    else if(ai===25){n=bytes.readUInt16BE(offset);offset+=2;}
    else if(ai===26){n=bytes.readUInt32BE(offset);offset+=4;}
    else assert.ok(ai<24,"Unsupported CBOR length");
    if(major===0)return n;if(major===1)return -1-n;
    if(major===2 || major===3){const v=bytes.subarray(offset,offset+n);offset+=n;return major===2?v:v.toString("utf8");}
    if(major===4)return Array.from({length:n},read);
    if(major===5){const m=new Map();for(let i=0;i<n;i++)m.set(read(),read());return m;}
    throw new Error("Unsupported CBOR type");
  }
  return read();
}
const html='<!doctype html><meta charset="utf-8"><title>OpenKeylet fixture</title><form><label>Username <input id="username" autocomplete="username"></label><label>Password <input id="password" type="password" autocomplete="current-password"></label><button>Sign in</button></form><form><input id="cardholder" autocomplete="cc-name"><input id="cardnumber" autocomplete="cc-number"><select id="cardmonth" autocomplete="cc-exp-month"><option value=""></option><option value="7">July</option></select><input id="cardyear" autocomplete="cc-exp-year"><input id="cardcode" autocomplete="cc-csc"><input id="hidden-card" autocomplete="cc-number" type="hidden"></form><form><input id="full-name" autocomplete="name"><input id="identity-email" autocomplete="email"><input id="address" autocomplete="address-line1"></form>';
const server=http.createServer((req,res)=>{res.setHeader("Content-Type","text/html");res.end(html);});
server.listen(0,"127.0.0.1"); await once(server,"listening");
const origin=`http://localhost:${server.address().port}`;
const portProbe=net.createServer();portProbe.listen(0,"127.0.0.1");await once(portProbe,"listening");const port=portProbe.address().port;await new Promise(r=>portProbe.close(r));
await fs.cp(path.join(repo,"browser-extension"),extension,{recursive:true,dereference:true});
const swPath=path.join(extension,"service-worker.js");await fs.writeFile(swPath,(await fs.readFile(swPath,"utf8")).replaceAll("39272",String(port)));
const child=spawn(fixture,[root,String(port),origin],{windowsHide:true,stdio:["ignore","pipe","pipe"]});
let output="", context;
child.stdout.on("data",d=>{output+=d});child.stderr.on("data",d=>{output+=d});
async function until(fn,description,timeout=20000){const end=Date.now()+timeout;while(Date.now()<end){if(await fn())return;await new Promise(r=>setTimeout(r,100));}throw new Error(`Timed out: ${description}. ${output.slice(-1500)}`);}
try {
  await until(()=>output.includes("READY"),"fixture startup");
  console.log("Browser fixture ready");
  context=await chromium.launchPersistentContext(path.join(root,"profile"),{channel:"chromium",headless:true,locale:"en-US",args:["--lang=en-US",`--disable-extensions-except=${extension}`,`--load-extension=${extension}`]});
  const worker=context.serviceWorkers()[0] || await context.waitForEvent("serviceworker");
  const extensionId=new URL(worker.url()).host;
  assert.equal(extensionId,"knkjojeijgalhpdkfapohofobfomenmi");
  await until(async()=>await worker.evaluate(async()=> (await chrome.storage.local.get("bridgeStatus")).bridgeStatus === "connected"),"automatic pairing");
  console.log("Extension paired");
  const site=await context.newPage();await site.goto("chrome://extensions");await site.bringToFront();
  await worker.evaluate(async()=>{await chrome.tabs.create({url:chrome.runtime.getURL("popup.html"),active:false});});
  await until(()=>context.pages().some(p=>p.url().endsWith("popup.html")),"extension popup page");
  const popup=context.pages().find(p=>p.url().endsWith("popup.html"));
  await popup.setViewportSize({width:350,height:620});
  await popup.locator("#unlock-form").waitFor({state:"visible"});
  assert.match(await popup.locator("#status").textContent(),/CONNECTED/);
  assert.equal(await popup.locator("#error").textContent(),"");
  assert.equal(await popup.locator("#unlock-form").isHidden(),false);
  assert.equal(await popup.locator("#vault-panel").isHidden(),true);
  assert.equal(await popup.evaluate(()=>call("fill",{id:"anything"}).then(()=>false,()=>true)),true);
  await popup.screenshot({path:path.join(root,"browser-page-popup.png")});
  // A cached "connected" value must not mask an unavailable bridge.
  await worker.evaluate(()=>disposeSocket(socket,true));
  assert.equal(await worker.evaluate(async()=>(await chrome.storage.local.get("bridgeStatus")).bridgeStatus),"connected");
  await popup.evaluate(()=>refresh());
  await until(async()=>(await popup.locator("#status").textContent()).includes("UNAVAILABLE"),"actual bridge disconnect");
  assert.equal(await popup.locator("#offline-panel").isHidden(),false);
  await worker.evaluate(()=>requestConnect());
  await until(async()=>await worker.evaluate(async()=>(await chrome.storage.local.get("bridgeStatus")).bridgeStatus==="connected"),"bridge reconnect");
  await popup.evaluate(()=>refresh());
  await popup.locator("#unlock-form").waitFor({state:"visible"});
  assert.equal(await popup.locator("#error").textContent(),"");
  await popup.locator("#pin").fill("123456");await site.bringToFront();await popup.locator("#unlock-form button").click();
  await popup.locator("#page-hint").waitFor({state:"visible"});
  await site.goto(origin);await site.bringToFront();await popup.evaluate(()=>refresh());
  assert.equal(await popup.locator("#page-hint").isHidden(),true);
  console.log("Browser pages, live connection status and recovery verified");
  await popup.getByRole("button",{name:/Fixture login/}).waitFor();
  await site.bringToFront();await popup.getByRole("button",{name:/Fixture login/}).click();
  await until(async()=>await site.locator("#password").inputValue()==="fixture-initial-password","password autofill");
  console.log("Password filled");
  await site.locator("#password").fill("browser-update-secret");await site.bringToFront();await popup.locator("#read-form").click();
  await popup.locator("#save-form").waitFor({state:"visible"});
  await site.bringToFront();await popup.locator('#save-form button[type="submit"]').click();
  await until(async()=>await popup.locator("#save-form").isHidden(),"browser save");
  const items=await worker.evaluate(o=>bridgeCall("password.list",{origin:o}),origin);
  const login=items[0];
  assert.equal((await worker.evaluate(p=>bridgeCall("password.get",p),{id:login.id,origin})).password,"browser-update-secret");
  await fs.writeFile(path.join(root,"desktop-edit.json"),JSON.stringify({id:login.id,name:"Desktop renamed login",loginUris:[{uri:origin+"/",matchType:"exact"},{uri:origin+"/alternate",matchType:"exact"},{uri:origin+"/blocked",matchType:"never"}],modules:[{kind:"url",value:origin},{kind:"username"},{kind:"password"}],secrets:{password:"desktop-update-secret",namedSecrets:{username:"alice"}}}));
  await until(async()=>fs.access(path.join(root,"desktop-edited")).then(()=>true,()=>false),"desktop edit");
  await fs.rm(path.join(root, "desktop-edited"), { force: true });
  await popup.getByRole("button",{name:/Desktop renamed login/}).waitFor();
  await site.bringToFront();await popup.getByRole("button",{name:/Desktop renamed login/}).click();
  await until(async()=>await site.locator("#password").inputValue()==="desktop-update-secret","desktop-to-browser update");
  console.log("Browser and desktop edits synchronized");
  // Least-privilege check: full-vault CRUD RPCs belong exclusively to the desktop app.
  for (const blocked of ["vault.list", "vault.get", "vault.save", "vault.trash", "vault.purge", "personal.save"]) {
    assert.equal(
      await worker.evaluate(m => bridgeCall(m, {}).then(() => false, () => true), blocked),
      true,
      `${blocked} must be rejected by browser bridge`,
    );
  }
  await popup.locator("#agent-channel-card").waitFor({ state: "visible" });
  assert.equal(await popup.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  // Desktop-managed cards & identities are autofilled directly from the current-site quick autofill list.
  await fs.writeFile(path.join(root, "desktop-edit.json"), JSON.stringify({
    name: "Synthetic card",
    itemType: "card",
    modules: [{ kind: "cardholderName" }, { kind: "cardNumber" }, { kind: "cardExpMonth" }, { kind: "cardExpYear" }, { kind: "cardSecurityCode" }],
    secrets: { namedSecrets: { cardholderName: "Test Cardholder", cardNumber: "4111111111111111", cardExpMonth: "07", cardExpYear: "2030", cardSecurityCode: "987" } },
  }));
  await until(async () => fs.access(path.join(root, "desktop-edited")).then(() => true, () => false), "desktop card created");
  await fs.rm(path.join(root, "desktop-edited"), { force: true });
  await fs.writeFile(path.join(root, "desktop-edit.json"), JSON.stringify({
    name: "Synthetic identity",
    itemType: "identity",
    modules: [{ kind: "firstName" }, { kind: "lastName" }, { kind: "email" }, { kind: "address1" }],
    secrets: { namedSecrets: { firstName: "Alice", lastName: "Example", email: "alice@example.invalid", address1: "123 Example Street" } },
  }));
  await until(async () => fs.access(path.join(root, "desktop-edited")).then(() => true, () => false), "desktop identity created");
  await site.bringToFront();
  await popup.evaluate(() => refresh());
  const cardChip = popup.locator("#site-autofill-list .quick-fill-chip").filter({ hasText: "Synthetic card" });
  await cardChip.waitFor();
  assert.equal((await cardChip.textContent()).includes("4111111111111111"), false);
  assert.match(await cardChip.textContent(), /1111/);
  await site.bringToFront();
  await cardChip.click();
  await until(async () => await site.locator("#cardnumber").inputValue() === "4111111111111111", "card autofill");
  assert.equal(await site.locator("#cardmonth").inputValue(), "7");
  assert.equal(await site.locator("#hidden-card").inputValue(), "");
  const identityChip = popup.locator("#site-autofill-list .quick-fill-chip").filter({ hasText: "Synthetic identity" });
  await identityChip.waitFor();
  await site.bringToFront();
  await identityChip.click();
  await until(async () => await site.locator("#full-name").inputValue() === "Alice Example", "identity autofill");
  assert.equal(await site.locator("#identity-email").inputValue(), "alice@example.invalid");
  assert.equal(await site.locator("#address").inputValue(), "123 Example Street");
  const cards = await worker.evaluate(() => bridgeCall("personal.list"));
  const card = cards.find(c => c.name === "Synthetic card");
  await worker.evaluate(() => bridgeCall("lock"));
  await popup.evaluate(() => refresh());
  await popup.locator("#unlock-form").waitFor({ state: "visible" });
  await popup.locator("#pin").fill("123456");
  await site.bringToFront();
  await popup.locator("#unlock-form button").click();
  await popup.locator("#vault-panel").waitFor({ state: "visible" });
  await context.route("http://insecure.invalid/**", route => route.fulfill({ contentType: "text/html", body: html }));
  const insecure = await context.newPage();
  await insecure.goto("http://insecure.invalid/");
  await insecure.bringToFront();
  await popup.evaluate(() => refresh());
  await until(async () => await popup.evaluate(() => currentOrigin === "http://insecure.invalid"), "insecure target selected");
  const refused = await popup.evaluate(id => call("personal-fill", { id }).then(() => "", e => e.message), card.id);
  assert.match(refused, /HTTPS/);
  assert.equal(await insecure.locator("#cardnumber").inputValue(), "");
  await insecure.close();
  await site.bringToFront();
  await popup.evaluate(() => refresh());
  await until(async () => await popup.evaluate(o => currentOrigin === o, origin), "original target restored");
  // Insecure cross-origin iframe must never receive payment card autofill.
  await site.evaluate(url => { const iframe = document.createElement("iframe"); iframe.src = url; document.body.append(iframe); }, "http://insecure.invalid/");
  const insecureFrame = await (async () => { await until(() => site.frames().length === 2, "insecure cross-origin frame"); return site.frames()[1]; })();
  await insecureFrame.locator("#cardnumber").focus();
  await until(() => worker.evaluate(() => [...focusedFrameByTab.values()].some(id => id !== 0)), "insecure cross-origin field focused");
  await popup.evaluate(id => call("personal-fill", { id }).catch(() => null), card.id);
  assert.equal(await insecureFrame.locator("#cardnumber").inputValue(), "");
  await site.locator("#username").focus();
  await site.evaluate(() => document.querySelector("iframe").remove());
  // Cross-origin frame (even localhost vs 127.0.0.1) must always reject login credential fill.
  await site.evaluate(url => { const iframe = document.createElement("iframe"); iframe.src = url; document.body.append(iframe); }, `http://127.0.0.1:${server.address().port}`);
  const crossFrame = await (async () => { await until(() => site.frames().length === 2, "cross-origin frame"); return site.frames()[1]; })();
  await crossFrame.locator("#password").focus();
  await until(() => worker.evaluate(() => [...focusedFrameByTab.values()].some(id => id !== 0)), "cross-origin field focused");
  assert.equal(await popup.evaluate(id => call("fill", { id }).then(() => false, () => true), login.id), true);
  assert.equal(await crossFrame.locator("#password").inputValue(), "");
  await site.locator("#username").focus();
  await site.evaluate(() => document.querySelector("iframe").remove());
  console.log("Least-privilege bridge, cards, identities, and secure origin checks verified");
  const wrongOrigin=await worker.evaluate(async p=>{try{await bridgeCall("password.get",p);return false;}catch{return true;}},{id:login.id,origin:`http://127.0.0.1:${server.address().port}`});assert.equal(wrongOrigin,true);
  await site.goto(origin+"/alternate");await site.bringToFront();await popup.evaluate(()=>refresh());
  await popup.getByRole("button",{name:/Desktop renamed login/}).click();
  await until(async()=>await site.locator("#password").inputValue()==="desktop-update-secret","additional exact URL filled");
  await site.goto(origin+"/blocked");await site.bringToFront();await popup.evaluate(async()=>{while(loading)await new Promise(r=>setTimeout(r,20));await refresh();});
  assert.equal(await popup.getByRole("button",{name:/Desktop renamed login/}).count(),0,"Never rule must not list the login");
  assert.equal(await popup.evaluate(id=>call("fill",{id}).then(()=>false,()=>true),login.id),true,"Same origin with wrong path must reject fill");
  assert.equal(await site.locator("#password").inputValue(),"");
  await site.goto(origin);await site.bringToFront();
  await site.evaluate(url=>{const iframe=document.createElement("iframe");iframe.src=url;document.body.append(iframe);},origin+"/blocked");
  await until(()=>site.frames().length===2,"same-origin iframe");
  const pathFrame=site.frames()[1];await pathFrame.locator("#password").focus();
  await until(()=>worker.evaluate(()=>[...focusedFrameByTab.values()].some(id=>id!==0)),"same-origin frame focus");
  assert.equal(await popup.evaluate(id=>call("fill",{id}).then(()=>false,()=>true),login.id),true,"Exact rule must validate target frame URL");
  assert.equal(await pathFrame.locator("#password").inputValue(),"");
  await site.locator("#username").focus();await site.evaluate(()=>document.querySelector("iframe").remove());
  await popup.evaluate(()=>refresh());
  console.log("Multiple websites, never rules, exact paths and iframe URL isolation verified");
  await popup.screenshot({path:path.join(root,"password-popup.png")});
  await popup.close();await site.bringToFront();
  async function webauthn(operation,credentialId) {
    const nextPage=context.waitForEvent("page");
    const result=site.evaluate(async({operation,credentialId})=>{
      const challenge=new Uint8Array(32).fill(operation==="create"?9:10);
      const publicKey=operation==="create"?{challenge,rp:{id:"localhost",name:"Fixture"},user:{id:new Uint8Array([1,2,3]),name:"alice",displayName:"Alice"},pubKeyCredParams:[{type:"public-key",alg:-7}],authenticatorSelection:{residentKey:"required",userVerification:"required"},extensions:{credProps:true}}:{challenge,rpId:"localhost",userVerification:"required",allowCredentials:credentialId?[{type:"public-key",id:Uint8Array.from(atob(credentialId.replaceAll("-","+").replaceAll("_","/")),c=>c.charCodeAt(0))}]:[]};
      try {const credential=await navigator.credentials[operation]({publicKey});return {ok:true,instance:credential instanceof PublicKeyCredential,json:credential.toJSON()};}catch(e){return{ok:false,error:e.message,name:e.name};}
    },{operation,credentialId});
    const confirm=await nextPage;await confirm.waitForURL(/request.html/);await confirm.setViewportSize({width:400,height:600});await confirm.locator("#pin").fill("123456");
    assert.equal(await confirm.locator("#origin").textContent(),origin);
    await confirm.screenshot({path:path.join(root,`${operation}-passkey.png`)});
    await confirm.locator("#confirm").click();
    const credential=await result;assert.equal(credential.ok,true,JSON.stringify(credential));assert.equal(credential.instance,true);return credential.json;
  }
  const registration=await webauthn("create");
  console.log("Passkey registered");
  assert.equal(registration.clientExtensionResults.credProps.rk,true);
  const publicKey=createPublicKey({key:Buffer.from(registration.response.publicKey,"base64url"),format:"der",type:"spki"});
  const attestation=readCbor(Buffer.from(registration.response.attestationObject,"base64url"));
  assert.equal(attestation.get("fmt"),"none");
  const registeredAuth=attestation.get("authData");
  assert.deepEqual(registeredAuth,Buffer.from(registration.response.authenticatorData,"base64url"));
  const credentialLength=registeredAuth.readUInt16BE(53);
  assert.equal(registeredAuth.subarray(55,55+credentialLength).toString("base64url"),registration.id);
  const cose=readCbor(registeredAuth,55+credentialLength);
  assert.equal(cose.get(1),2);assert.equal(cose.get(3),-7);assert.equal(cose.get(-1),1);
  const registeredKey=createPublicKey({key:{kty:"EC",crv:"P-256",x:cose.get(-2).toString("base64url"),y:cose.get(-3).toString("base64url")},format:"jwk"});
  assert.deepEqual(registeredKey.export({format:"jwk"}),publicKey.export({format:"jwk"}));
  const assertion=await webauthn("get",registration.id);
  const auth=Buffer.from(assertion.response.authenticatorData,"base64url");
  const client=Buffer.from(assertion.response.clientDataJSON,"base64url");
  assert.equal(JSON.parse(client).origin,origin);assert.equal(auth[32]&5,5);
  assert.ok(verify("sha256",Buffer.concat([auth,createHash("sha256").update(client).digest()]),publicKey,Buffer.from(assertion.response.signature,"base64url")));
  assert.equal(JSON.parse(client).challenge,Buffer.alloc(32,10).toString("base64url"));
  assert.deepEqual(auth.subarray(0,32),createHash("sha256").update("localhost").digest());
  await webauthn("get"); // Discoverable login without allowCredentials.
  // Cancelling a real extension prompt must reject, rather than silently authenticating.
  const cancelPage=context.waitForEvent("page");
  const cancelled=site.evaluate(()=>navigator.credentials.get({publicKey:{challenge:new Uint8Array(32),rpId:"localhost"}}).then(()=>"unexpected",e=>e.name));
  const prompt=await cancelPage;await prompt.waitForURL(/request.html/);await prompt.locator("#cancel").click();assert.equal(await cancelled,"NotAllowedError");
  await worker.evaluate(()=>{
    const original=pageStillMatches;
    globalThis.abortProbeFinished=false;
    pageStillMatches=async(...args)=>{
      pageStillMatches=original;
      await new Promise(resolve=>setTimeout(resolve,100));
      try { return await original(...args); } finally { globalThis.abortProbeFinished=true; }
    };
  });
  const aborted=await site.evaluate(()=>{const c=new AbortController();const p=navigator.credentials.get({signal:c.signal,publicKey:{challenge:new Uint8Array(32),rpId:"localhost"}}).then(()=>"unexpected",e=>e.name);c.abort();return p;});
  assert.equal(aborted,"AbortError");
  await until(()=>worker.evaluate(()=>globalThis.abortProbeFinished && preparingCredentials.size===0 && credentialRequests.size===0),"abort during request preparation");
  await until(()=>!context.pages().some(p=>p.url().includes("request.html")),"aborted prompt dismissed");
  // Password RPCs are inaccessible to page-origin messages, even with a matching shape.
  await site.locator("#password").fill("page-isolation-sentinel");
  const isolation=await site.evaluate(()=>new Promise(resolve=>{window.postMessage({type:"vault-ui",action:"fill",id:"anything"},location.origin);setTimeout(()=>resolve(document.querySelector("#password").value),100);}));
  assert.equal(isolation,"page-isolation-sentinel");
  console.log(JSON.stringify({ok:true,checks:["pairing","browser page guidance","live bridge status","reconnect recovery","PIN unlock","password fill","browser save","desktop update","card create/edit/fill","identity create/fill","secure note round trip","lock clears open editors","hidden fields excluded","HTTPS enforcement","cross-origin iframe denied","password generator","origin isolation","passkey create","COSE public key","verified assertion","discoverable login","cancel","abort during preparation"],artifacts:root},null,2));
} catch(error) {
  console.error(`Browser test artifacts: ${root}`);
  for(const [index,page] of (context?.pages() || []).entries()) await page.screenshot({path:path.join(root,`failure-${index}.png`),timeout:2000}).catch(()=>{});
  throw error;
} finally {
  await context?.close(); await fs.writeFile(path.join(root,"stop"),"").catch(()=>{});
  if(child.exitCode===null){await Promise.race([once(child,"exit"),new Promise(r=>setTimeout(r,2000))]);if(child.exitCode===null)child.kill();}
  server.close();
}
