import assert from "node:assert/strict";
import { createHash as createDigest } from "node:crypto";
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
await fs.cp(path.join(repo,"browser-extension"),extension,{recursive:true});
const swPath=path.join(extension,"service-worker.js");
let swSource=(await fs.readFile(swPath,"utf8")).replaceAll("39272",String(port));
assert.ok(swSource.includes("const SYNTHETIC_HTTP_LOOPBACK_ALLOWED = false;"),"production extension must keep HTTP autofill disabled");
swSource=swSource.replace("const SYNTHETIC_HTTP_LOOPBACK_ALLOWED = false;","const SYNTHETIC_HTTP_LOOPBACK_ALLOWED = true;");
assert.ok(swSource.includes("const SYNTHETIC_HTTP_LOOPBACK_ALLOWED = true;"),"only the disposable test copy may enable loopback HTTP");
await fs.writeFile(swPath,swSource);
const child=spawn(fixture,[root,String(port),origin],{windowsHide:true,stdio:["pipe","pipe","pipe"]});
let output="", mcpBuffer="", context, worker;
let nextMcpId=1;
const pendingMcp=new Map();
child.stdout.on("data",chunk=>{
  mcpBuffer+=chunk.toString();
  for(;;){
    const newline=mcpBuffer.indexOf("\n");
    if(newline<0)break;
    const line=mcpBuffer.slice(0,newline).trim();mcpBuffer=mcpBuffer.slice(newline+1);
    if(!line)continue;
    try{
      const message=JSON.parse(line);
      if(message.id!==undefined&&pendingMcp.has(message.id)){
        const pending=pendingMcp.get(message.id);pendingMcp.delete(message.id);clearTimeout(pending.timer);pending.resolve(message);
      }
    }catch{output+=`\nstdout: ${line}`;}
  }
});
child.stderr.on("data",d=>{output+=d.toString()});
function mcpRequest(method,params={},timeoutMs=60000){
  const id=nextMcpId++;
  return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{pendingMcp.delete(id);reject(new Error(`MCP ${method} timed out`));},timeoutMs);
    pendingMcp.set(id,{resolve,reject,timer});
    child.stdin.write(JSON.stringify({jsonrpc:"2.0",id,method,params})+"\n",error=>{
      if(error){clearTimeout(timer);pendingMcp.delete(id);reject(error);}
    });
  });
}
function mcpNotify(method,params={}){child.stdin.write(JSON.stringify({jsonrpc:"2.0",method,params})+"\n");}
async function mcpTool(name,args){
  const response=await mcpRequest("tools/call",{name,arguments:args});
  if(response.error)throw new Error(response.error.message||JSON.stringify(response.error));
  return response.result;
}
function mcpToolPayload(result){
  if(result?.structuredContent)return result.structuredContent;
  const text=(result?.content||[]).filter(block=>block.type==="text").map(block=>block.text).join("\n");
  try{return JSON.parse(text);}catch{return text;}
}
async function until(fn,description,timeout=20000){const end=Date.now()+timeout;while(Date.now()<end){if(await fn())return;await new Promise(r=>setTimeout(r,100));}throw new Error(`Timed out: ${description}. ${output.slice(-1500)}`);}
try {
  await until(()=>output.includes("READY"),"fixture startup");
  console.log("Browser fixture ready");
  const initialized=await mcpRequest("initialize",{protocolVersion:"2025-11-25",capabilities:{},clientInfo:{name:"self-asserted-test-client",version:"1.0.0"}});
  assert.equal(initialized.error,undefined,JSON.stringify(initialized.error));
  assert.equal(initialized.result.protocolVersion,"2025-11-25");
  mcpNotify("notifications/initialized");
  const listedTools=await mcpRequest("tools/list",{});
  assert.equal(listedTools.error,undefined,JSON.stringify(listedTools.error));
  assert.ok(listedTools.result.tools.some(tool=>tool.name==="credential_fill"),"MCP credential_fill tool must be registered");
  context=await chromium.launchPersistentContext(path.join(root,"profile"),{channel:"chromium",headless:true,args:[`--disable-extensions-except=${extension}`,`--load-extension=${extension}`]});
  worker=context.serviceWorkers()[0] || await context.waitForEvent("serviceworker");
  const extensionId=new URL(worker.url()).host;
  assert.equal(extensionId,"knkjojeijgalhpdkfapohofobfomenmi");
  await until(async()=>await worker.evaluate(async()=> (await chrome.storage.local.get("bridgeStatus")).bridgeStatus === "connected"),"automatic pairing");
  console.log("Extension paired");
  const site=await context.newPage();await site.goto("chrome://extensions");await site.bringToFront();
  await worker.evaluate(async()=>{await chrome.tabs.create({url:chrome.runtime.getURL("popup.html"),active:false});});
  await until(()=>context.pages().some(p=>p.url().endsWith("popup.html")),"extension popup page");
  const popup=context.pages().find(p=>p.url().endsWith("popup.html"));
  await popup.setViewportSize({width:350,height:620});
  await popup.locator("#page-hint").waitFor({state:"visible"});
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
  assert.equal(await popup.locator("#page-hint").isHidden(),true);
  await worker.evaluate(()=>requestConnect());
  await until(async()=>await worker.evaluate(async()=>(await chrome.storage.local.get("bridgeStatus")).bridgeStatus==="connected"),"bridge reconnect");
  await popup.evaluate(()=>refresh());
  await popup.locator("#page-hint").waitFor({state:"visible"});
  assert.equal(await popup.locator("#error").textContent(),"");
  await site.goto(origin);await site.bringToFront();await popup.evaluate(()=>refresh());
  await popup.locator("#unlock-form").waitFor({state:"visible"});
  assert.equal(await popup.locator("#page-hint").isHidden(),true);
  console.log("Browser pages, live connection status and recovery verified");
  await popup.locator("#pin").fill("123456");await site.bringToFront();await popup.locator("#unlock-form button").click();
  await popup.getByRole("button",{name:/Fixture login/}).waitFor();
  await site.bringToFront();await popup.getByRole("button",{name:/Fixture login/}).click();
  await until(async()=>await site.locator("#password").inputValue()==="fixture-initial-password","password autofill");
  console.log("Password filled");

  // The MCP caller label is deliberately self-asserted; only the paired extension/vault connection authorizes delivery.
  async function trackFormSubmission(){
    await site.evaluate(()=>{
      window.__mcpFormSubmitted=false;
      document.querySelector("form").addEventListener("submit",event=>{window.__mcpFormSubmitted=true;event.preventDefault();});
    });
  }
  await trackFormSubmission();
  await site.locator("#password").fill("");
  const mcpPasswordFill=await mcpTool("credential_fill",{item:"Fixture login",module:"password",target:"browser"});
  const mcpPasswordPayload=mcpToolPayload(mcpPasswordFill);
  assert.notEqual(mcpPasswordFill.isError,true,JSON.stringify(mcpPasswordFill));
  assert.equal(mcpPasswordPayload.target,"browser");
  assert.equal(mcpPasswordPayload.module,"password");
  assert.equal(mcpPasswordPayload.origin,origin);
  assert.equal(typeof mcpPasswordPayload.operationId,"string");
  assert.equal(typeof mcpPasswordPayload.tabId,"number");
  assert.equal(typeof mcpPasswordPayload.documentId,"string");
  assert.equal(mcpPasswordPayload.delivered,true);
  assert.equal(mcpPasswordPayload.readback,true);
  assert.equal(mcpPasswordPayload.submitted,false,"MCP credential fill must never submit the form by default");
  for(const key of ["value","password","passwordHash","hash","secret"])assert.equal(Object.hasOwn(mcpPasswordPayload,key),false,`MCP result must not expose ${key}`);
  assert.equal(await site.locator("#password").inputValue(),"fixture-initial-password");
  assert.equal(await site.evaluate(()=>window.__mcpFormSubmitted),false);
  const mcpPasswordSerialized=JSON.stringify(mcpPasswordFill);
  assert.equal(mcpPasswordSerialized.includes("fixture-initial-password"),false,"MCP output must not disclose the credential");
  assert.equal(mcpPasswordSerialized.includes(createDigest("sha256").update("fixture-initial-password").digest("hex")),false,"MCP output must not disclose a password hash");
  await site.locator("#username").fill("");
  const mcpUsernameFill=await mcpTool("credential_fill",{item:"Fixture login",module:"username",target:"browser"});
  assert.notEqual(mcpUsernameFill.isError,true,JSON.stringify(mcpUsernameFill));
  assert.equal(mcpToolPayload(mcpUsernameFill).readback,true);
  assert.equal(await site.locator("#username").inputValue(),"alice");
  const mcpUsernameSerialized=JSON.stringify(mcpUsernameFill);
  assert.equal(mcpUsernameSerialized.includes("fixture-initial-password"),false,"username fill output must not disclose the password");
  assert.equal(mcpUsernameSerialized.includes(createDigest("sha256").update("fixture-initial-password").digest("hex")),false,"username fill output must not disclose the password hash");

  async function gatedCredentialFill(action){
    await worker.evaluate(()=>{
      const original=bridgeCall;
      globalThis.__credentialLookupOriginal=original;
      globalThis.__credentialLookupGate={enabled:true,ready:false,release:null};
      bridgeCall=async(method,params)=>{
        const result=await original(method,params);
        if(method==="password.get"&&globalThis.__credentialLookupGate?.enabled){
          const gate=globalThis.__credentialLookupGate;gate.ready=true;
          await new Promise(resolve=>gate.release=resolve);
        }
        return result;
      };
    });
    const pending=mcpTool("credential_fill",{item:"Fixture login",module:"password",target:"browser"});
    try{
      await until(()=>worker.evaluate(()=>globalThis.__credentialLookupGate?.ready===true),"credential lookup interlock");
      await action();
    }finally{
      await worker.evaluate(()=>{
        const gate=globalThis.__credentialLookupGate;
        if(gate){gate.enabled=false;gate.release?.();}
        if(globalThis.__credentialLookupOriginal)bridgeCall=globalThis.__credentialLookupOriginal;
        delete globalThis.__credentialLookupGate;delete globalThis.__credentialLookupOriginal;
      });
    }
    return pending;
  }

  await site.locator("#password").fill("");
  const wrongOriginPage=await context.newPage();
  await wrongOriginPage.goto(`http://127.0.0.1:${server.address().port}/`);
  await wrongOriginPage.locator("#password").focus();
  const wrongOriginFill=await mcpTool("credential_fill",{item:"Fixture login",module:"password",target:"browser"});
  assert.equal(wrongOriginFill.isError,true,"A credential must not cross its saved origin boundary");
  assert.equal(await wrongOriginPage.locator("#password").inputValue(),"");
  await wrongOriginPage.close();await site.bringToFront();

  await site.evaluate(url=>{const iframe=document.createElement("iframe");iframe.src=url;document.body.append(iframe);},`http://127.0.0.1:${server.address().port}/`);
  await until(()=>site.frames().length===2,"cross-origin MCP frame");
  const mcpCrossFrame=site.frames()[1];await mcpCrossFrame.locator("#password").focus();
  await until(()=>worker.evaluate(async()=>{
    const [active]=await chrome.tabs.query({active:true,lastFocusedWindow:true});
    return Boolean(active&&(focusedFrameByTab.get(active.id)??0)!==0);
  }),"cross-origin MCP frame focus");
  const crossOriginFill=await mcpTool("credential_fill",{item:"Fixture login",module:"password",target:"browser"});
  assert.equal(crossOriginFill.isError,true,"Cross-origin iframe credentials must be rejected");
  assert.equal(await mcpCrossFrame.locator("#password").inputValue(),"");
  await site.evaluate(()=>document.querySelector("iframe").remove());await site.locator("#password").focus();

  await site.locator("#password").fill("");
  const switchedTabFill=await gatedCredentialFill(async()=>{
    const other=await context.newPage();await other.goto(origin+"/other");await other.bringToFront();
    globalThis.__mcpOtherTab=other;
  });
  assert.equal(switchedTabFill.isError,true,"An active-tab switch during lookup must abort the fill");
  await site.bringToFront();assert.equal(await site.locator("#password").inputValue(),"");
  await context.pages().find(page=>page.url().endsWith("/other"))?.close();

  await site.locator("#password").fill("");
  const navigationFill=await gatedCredentialFill(async()=>{
    await site.reload();await site.locator("#password").waitFor();await site.locator("#password").focus();
    await trackFormSubmission();
  });
  assert.equal(navigationFill.isError,true,"A same-URL document replacement during lookup must abort the fill");
  assert.equal(await site.locator("#password").inputValue(),"");

  await site.locator("#password").focus();
  await site.evaluate(url=>{const iframe=document.createElement("iframe");iframe.src=url;document.body.append(iframe);},origin);
  await until(()=>site.frames().length===2,"same-origin MCP frame");
  const frameMismatchFill=await gatedCredentialFill(async()=>{await site.frames()[1].locator("#password").focus();});
  assert.equal(frameMismatchFill.isError,true,"A focused-frame switch during lookup must abort the fill");
  assert.equal(await site.locator("#password").inputValue(),"");
  await site.evaluate(()=>document.querySelector("iframe").remove());await site.locator("#password").focus();

  await site.locator("#password").fill("");
  const replacedFieldFill=await gatedCredentialFill(async()=>{
    await site.evaluate(()=>{const old=document.querySelector("#password");const replacement=old.cloneNode();old.replaceWith(replacement);replacement.focus();});
  });
  assert.equal(replacedFieldFill.isError,true,"A replaced target field must not inherit the prepared identity");
  assert.equal(await site.locator("#password").inputValue(),"");
  await site.locator("#password").focus();

  await site.locator("#password").fill("");
  const submitAttempt=await mcpTool("credential_fill",{item:"Fixture login",module:"password",target:"browser",submit:true});
  assert.equal(submitAttempt.isError,true,"MCP credential filling must reject requested form submission");
  assert.equal(await site.locator("#password").inputValue(),"");
  assert.equal(await site.evaluate(()=>window.__mcpFormSubmitted),false);
  console.log("Secure MCP autofill verified: origin, tab, navigation, frame/document, exact field, readback, non-submission and secret non-disclosure");

  // The checks above cleared the fixture form and reloaded it, so restore the saved login before the update flow.
  await site.bringToFront();await popup.getByRole("button",{name:/Fixture login/}).click();
  await until(async()=>await site.locator("#username").inputValue()==="alice","username autofill before save");
  await site.locator("#password").fill("browser-update-secret");await site.bringToFront();await popup.locator("#read-form").click();
  await popup.locator("#save-form").waitFor({state:"visible"});
  await site.bringToFront();await popup.locator('#save-form button[type="submit"]').click();
  await until(async()=>await popup.locator("#save-form").isHidden(),"browser save");
  const items=await worker.evaluate(o=>bridgeCall("password.list",{origin:o}),origin);
  const login=items[0];
  assert.equal((await worker.evaluate(p=>bridgeCall("password.get",p),{id:login.id,origin})).password,"browser-update-secret");
  await fs.writeFile(path.join(root,"desktop-edit.json"),JSON.stringify({id:login.id,name:"Desktop renamed login",loginUris:[{uri:origin+"/",matchType:"exact"},{uri:origin+"/alternate",matchType:"exact"},{uri:origin+"/blocked",matchType:"never"}],modules:[{kind:"url",value:origin},{kind:"username"},{kind:"password"}],secrets:{password:"desktop-update-secret",namedSecrets:{username:"alice"}}}));
  await until(async()=>fs.access(path.join(root,"desktop-edited")).then(()=>true,()=>false),"desktop edit");
  await popup.getByRole("button",{name:/Desktop renamed login/}).waitFor();
  await site.bringToFront();await popup.getByRole("button",{name:/Desktop renamed login/}).click();
  await until(async()=>await site.locator("#password").inputValue()==="desktop-update-secret","desktop-to-browser update");
  console.log("Browser and desktop edits synchronized");
  // Owner management is available even when the active tab has no website.
  await site.goto("chrome://extensions");await site.bringToFront();await popup.evaluate(()=>refresh());
  await popup.locator("#full-vault summary").click();
  await popup.locator("#vault-new").click();
  await popup.locator("#vault-item-name").fill("Managed login");
  await popup.locator("#vault-item-folder").fill("Personal");
  await popup.locator("#vault-item-favorite").check();
  await popup.locator('[data-vault-field="username"]').fill("managed-user");
  await popup.locator('[data-vault-field="password"]').fill("managed-before");
  await popup.locator("#vault-uri-add").click();
  await popup.locator("[data-uri]").fill("https://managed.example/login");
  await popup.locator("[data-match]").selectOption("exact");
  await popup.locator('#vault-editor button[type="submit"]').click();
  await popup.locator("#vault-editor").waitFor({state:"hidden"});
  const managed=(await worker.evaluate(()=>bridgeCall("vault.list"))).items.find(i=>i.name==="Managed login");
  assert.ok(managed);assert.equal(managed.folder,"Personal");assert.equal(managed.favorite,true);
  assert.equal(managed.loginUris[0].matchType,"exact");
  await popup.locator("#vault-search").fill("Managed login");
  await popup.locator("#vault-folder").selectOption("Personal");
  await popup.locator("#vault-favorites").check();
  const managedRow=popup.locator(`[data-vault-id="${managed.id}"]`);
  assert.equal(await popup.locator("#vault-all-items .vault-row").count(),1);
  await managedRow.locator("[data-vault-edit]").click();
  await popup.locator('[data-vault-field="password"]').fill("managed-after");
  await popup.locator('#vault-editor button[type="submit"]').click();
  await popup.locator("#vault-editor").waitFor({state:"hidden"});
  await managedRow.getByRole("button",{name:/History/}).click();
  assert.equal(await popup.locator("#vault-history-rows input").inputValue(),"managed-before");
  assert.equal(await popup.locator("#vault-history-rows input").getAttribute("type"),"password");
  await popup.screenshot({path:path.join(root,"vault-history.png")});
  await popup.locator("#vault-history-clear").click();
  await popup.locator("#vault-confirm-cancel").click();
  assert.equal((await worker.evaluate(id=>bridgeCall("vault.history",{id}),managed.id)).entries.length,1);
  await popup.locator("#vault-history-clear").click();
  await popup.locator("#vault-confirm-accept").click();
  await until(async()=>(await worker.evaluate(id=>bridgeCall("vault.history",{id}),managed.id)).entries.length===0,"history cleared");
  assert.equal((await worker.evaluate(id=>bridgeCall("vault.get",{id}),managed.id)).fields.find(f=>f.name==="password").value,"managed-after");
  await popup.locator("#vault-history-close").click();
  await managedRow.getByRole("button",{name:/Trash/}).click();
  await popup.locator("#vault-confirm-accept").click();
  await until(async()=>(await worker.evaluate(()=>bridgeCall("vault.list"))).trash.some(e=>e.item.id===managed.id),"trashed");
  assert.equal(await worker.evaluate(id=>bridgeCall("vault.get",{id}).then(()=>false,()=>true),managed.id),true);
  await popup.locator("#vault-view").selectOption("trash");
  await managedRow.getByRole("button",{name:/Restore/}).click();
  await until(async()=>(await worker.evaluate(()=>bridgeCall("vault.list"))).items.some(e=>e.id===managed.id),"restored");
  await popup.locator("#vault-view").selectOption("active");
  await managedRow.locator("[data-vault-edit]").click();
  await popup.locator('[data-vault-field="password"]').waitFor();
  await worker.evaluate(()=>bridgeCall("lock"));await popup.evaluate(()=>refresh());
  assert.equal(await popup.locator("[data-vault-field]").count(),0,"Lock removes owner secrets");
  await popup.locator("#pin").fill("123456");await popup.locator("#unlock-form button").click();
  await managedRow.getByRole("button",{name:/Trash/}).click();
  await popup.locator("#vault-confirm-accept").click();
  await popup.locator("#vault-view").selectOption("trash");
  await managedRow.getByRole("button",{name:/Delete forever/}).click();
  await popup.locator("#vault-confirm-cancel").click();
  assert.ok((await worker.evaluate(()=>bridgeCall("vault.list"))).trash.some(e=>e.item.id===managed.id));
  await managedRow.getByRole("button",{name:/Delete forever/}).click();
  await popup.locator("#vault-confirm-accept").click();
  await until(async()=>(await worker.evaluate(()=>bridgeCall("vault.list"))).trash.length===0,"permanent delete");
  await popup.locator("#vault-search").fill("");await popup.locator("#vault-view").selectOption("active");
  await popup.locator("#vault-folder").selectOption("");await popup.locator("#vault-favorites").uncheck();
  assert.equal(await popup.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  await popup.screenshot({path:path.join(root,"full-vault.png")});
  await popup.locator("#full-vault summary").click();
  await site.goto(origin);await site.bringToFront();await popup.evaluate(()=>refresh());
  console.log("Full vault editing, history, trash, restore, permanent deletion and lock verified");
  await popup.locator("#personal-vault-summary").click();
  await popup.locator("#add-card").click();
  await popup.locator("#personal-name").fill("Synthetic card");
  await popup.locator("#personal-cardholderName").fill("Test Cardholder");
  await popup.locator("#personal-cardNumber").fill("4111111111111111");
  await popup.locator("#personal-cardExpMonth").fill("07");
  await popup.locator("#personal-cardExpYear").fill("2030");
  await popup.locator("#personal-cardSecurityCode").fill("987");
  await popup.locator('#personal-form button[type="submit"]').click();
  await until(async()=>await popup.locator("#personal-form").isHidden(),"browser card saved");
  const cardRow=popup.locator(".personal-entry").filter({hasText:"Synthetic card"});
  await cardRow.waitFor();
  assert.equal((await cardRow.textContent()).includes("4111111111111111"),false);
  assert.match(await cardRow.textContent(),/1111/);
  await site.bringToFront();await cardRow.getByRole("button",{name:"填写 / Fill"}).click();
  await until(async()=>await site.locator("#cardnumber").inputValue()==="4111111111111111","card autofill");
  assert.equal(await site.locator("#cardmonth").inputValue(),"7");
  assert.equal(await site.locator("#hidden-card").inputValue(),"");
  await cardRow.getByRole("button",{name:"编辑 / Edit"}).click();
  await popup.locator("#personal-cardholderName").fill("Updated Cardholder");
  await popup.locator('#personal-form button[type="submit"]').click();
  await until(async()=>await popup.locator("#personal-form").isHidden(),"card edited");
  const cards=await worker.evaluate(()=>bridgeCall("personal.list"));
  const card=cards.find(c=>c.name==="Synthetic card");
  assert.equal((await worker.evaluate(id=>bridgeCall("personal.get",{id}),card.id)).fields.cardholderName,"Updated Cardholder");
  await popup.locator("#add-identity").click();
  await popup.locator("#personal-name").fill("Synthetic identity");
  await popup.locator("#personal-firstName").fill("Alice");
  await popup.locator("#personal-lastName").fill("Example");
  await popup.locator("#personal-email").fill("alice@example.invalid");
  await popup.locator("#personal-address1").fill("123 Example Street");
  await popup.locator('#personal-form button[type="submit"]').click();
  await until(async()=>await popup.locator("#personal-form").isHidden(),"identity saved");
  const identityRow=popup.locator(".personal-entry").filter({hasText:"Synthetic identity"});
  await identityRow.waitFor();await site.bringToFront();
  await identityRow.getByRole("button",{name:"填写 / Fill"}).click();
  await until(async()=>await site.locator("#full-name").inputValue()==="Alice Example","identity autofill");
  assert.equal(await site.locator("#identity-email").inputValue(),"alice@example.invalid");
  assert.equal(await site.locator("#address").inputValue(),"123 Example Street");
  await popup.locator("#add-note").click();
  await popup.locator("#personal-name").fill("Synthetic note");
  await popup.locator("#personal-secureNote").fill("Secret line one\nSecret line two");
  await popup.locator('#personal-form button[type="submit"]').click();
  await until(async()=>await popup.locator("#personal-form").isHidden(),"note saved");
  const noteRow = popup.locator(".personal-entry").filter({hasText:"Synthetic note"});
  await noteRow.waitFor();
  assert.equal(await noteRow.getByRole("button",{name:"填写 / Fill"}).count(),0);
  assert.equal((await noteRow.textContent()).includes("Secret line one"),false);
  await noteRow.getByRole("button",{name:"编辑 / Edit"}).click();
  assert.equal(await popup.locator("#personal-secureNote").inputValue(),"Secret line one\nSecret line two");
  await worker.evaluate(()=>bridgeCall("lock"));
  await popup.evaluate(()=>refresh());
  await popup.locator("#personal-form").waitFor({state:"hidden"});
  assert.equal(await popup.locator("[data-personal-field]").count(),0);
  await popup.locator("#pin").fill("123456");await site.bringToFront();
  await popup.locator("#unlock-form button").click();
  await popup.locator("#vault-panel").waitFor({state:"visible"});
  await context.route("http://insecure.invalid/**",route=>route.fulfill({contentType:"text/html",body:html}));
  const insecure = await context.newPage();await insecure.goto("http://insecure.invalid/");await insecure.bringToFront();
  await popup.evaluate(()=>refresh());
  await until(async()=>await popup.evaluate(()=>currentOrigin==="http://insecure.invalid"),"insecure target selected");
  const refused = await popup.evaluate(id=>call("personal-fill",{id}).then(()=>"",e=>e.message),card.id);
  assert.match(refused,/HTTPS/);
  assert.equal(await insecure.locator("#cardnumber").inputValue(),"");
  await insecure.close();await site.bringToFront();await popup.evaluate(()=>refresh());
  await until(async()=>await popup.evaluate(o=>currentOrigin===o,origin),"original target restored");
  await site.evaluate(url=>{const iframe=document.createElement("iframe");iframe.src=url;document.body.append(iframe);},`http://127.0.0.1:${server.address().port}`);
  const crossFrame = await (async()=>{await until(()=>site.frames().length===2,"cross-origin frame");return site.frames()[1];})();
  await crossFrame.locator("#cardnumber").focus();
  await until(()=>worker.evaluate(()=>[...focusedFrameByTab.values()].some(id=>id!==0)),"cross-origin field focused");
  assert.equal(await popup.evaluate(id=>call("personal-fill",{id}).then(()=>false,()=>true),card.id),true);
  assert.equal(await crossFrame.locator("#cardnumber").inputValue(),"");
  await site.locator("#username").focus();
  await site.evaluate(()=>document.querySelector("iframe").remove());
  await popup.locator(".personal-vault summary").filter({hasText:"Password generator"}).click();
  await popup.locator("#generate-password").click();
  await until(async()=>(await popup.locator("#generator-output").inputValue()).length===24,"password generation");
  console.log("Cards, identities, notes, secure origin checks and password generator verified");
  const wrongOrigin=await worker.evaluate(async p=>{try{await bridgeCall("password.get",p);return false;}catch{return true;}},{id:login.id,origin:`http://127.0.0.1:${server.address().port}`});assert.equal(wrongOrigin,true);
  await site.goto(origin+"/alternate");await site.bringToFront();await popup.evaluate(()=>refresh());
  await popup.getByRole("button",{name:/Desktop renamed login/}).click();
  await until(async()=>await site.locator("#password").inputValue()==="desktop-update-secret","additional exact URL filled");
  await site.goto(origin+"/blocked");await site.bringToFront();await popup.evaluate(()=>refresh());
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
  assert.ok(verify("sha256",Buffer.concat([auth,createDigest("sha256").update(client).digest()]),publicKey,Buffer.from(assertion.response.signature,"base64url")));
  assert.equal(JSON.parse(client).challenge,Buffer.alloc(32,10).toString("base64url"));
  assert.deepEqual(auth.subarray(0,32),createDigest("sha256").update("localhost").digest());
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
  if(child.exitCode===null){
    try{await mcpRequest("shutdown",{},3000);}catch{}
    mcpNotify("exit");
    child.stdin.end();
    await Promise.race([once(child,"exit"),new Promise(r=>setTimeout(r,5000))]);
    if(child.exitCode===null)child.kill();
  }
  server.close();
}
