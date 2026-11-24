#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const ENVELOPE_FORMAT = "openkeylet-update-v1";
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function fail(message) {
  console.error(`sign-release-manifest: ${message}`);
  process.exit(1);
}

function loadPrivateKey(rawInput) {
  const trimmed = String(rawInput || "").trim();
  if (!trimmed) {
    fail("OPENKEYLET_UPDATE_SIGNING_KEY is empty.");
  }
  if (trimmed.includes("BEGIN PRIVATE KEY")) {
    return crypto.createPrivateKey({ key: trimmed, format: "pem", type: "pkcs8" });
  }
  const der = Buffer.from(trimmed, "base64");
  if (der.length === 0) {
    fail("OPENKEYLET_UPDATE_SIGNING_KEY is not valid base64 PKCS#8 or PEM.");
  }
  return crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

function rawPublicKeyBase64(privateKey) {
  const pubKey = crypto.createPublicKey(privateKey);
  const spki = pubKey.export({ format: "der", type: "spki" });
  if (spki.length !== 44 || !spki.subarray(0, 12).equals(ED25519_SPKI_PREFIX)) {
    fail("Signing key is not an Ed25519 key.");
  }
  return spki.subarray(12).toString("base64");
}

function publicKeyFromRawBase64(pubB64) {
  const raw = Buffer.from(String(pubB64 || "").trim(), "base64");
  if (raw.length !== 32) {
    fail(`Expected 32-byte raw Ed25519 public key, got ${raw.length} bytes.`);
  }
  const spki = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
  return crypto.createPublicKey({ key: spki, format: "der", type: "spki" });
}

function parseFlags(args) {
  const flags = {};
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (!arg.startsWith("--")) continue;
    const key = arg.slice(2);
    const next = args[i + 1];
    if (!next || next.startsWith("--")) {
      flags[key] = "true";
    } else {
      flags[key] = next;
      i += 1;
    }
  }
  return flags;
}

function sha256File(filePath) {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(filePath));
  return hash.digest("hex");
}

function detectPlatform(fileName) {
  if (/^OpenKeylet_.*_windows-x64-portable\.zip$/i.test(fileName)) {
    return { key: "windows-x64", format: "zip" };
  }
  if (/^OpenKeylet_.*_windows-arm64-portable\.zip$/i.test(fileName)) {
    return { key: "windows-arm64", format: "zip" };
  }
  if (/^OpenKeylet_.*_macos-arm64-portable\.zip$/i.test(fileName)) {
    return { key: "macos-arm64", format: "zip" };
  }
  if (/^OpenKeylet_.*_macos-x64-portable\.zip$/i.test(fileName)) {
    return { key: "macos-x64", format: "zip" };
  }
  if (/^OpenKeylet_.*_linux-x64-portable\.tar\.gz$/i.test(fileName)) {
    return { key: "linux-x64-gui", format: "tar.gz" };
  }
  if (/^OpenKeylet_.*_linux-arm64-portable\.tar\.gz$/i.test(fileName)) {
    return { key: "linux-arm64-gui", format: "tar.gz" };
  }
  if (/^OpenKeylet_.*_linux-headless-x64\.tar\.gz$/i.test(fileName)) {
    return { key: "linux-x64-headless", format: "tar.gz" };
  }
  if (/^OpenKeylet_.*_linux-headless-arm64\.tar\.gz$/i.test(fileName)) {
    return { key: "linux-arm64-headless", format: "tar.gz" };
  }
  return null;
}

function cmdKeygen() {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const privDer = privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
  const pubB64 = rawPublicKeyBase64(privateKey);
  console.log("=== OpenKeylet Release Update Signing Keypair (Ed25519) ===");
  console.log("");
  console.log("1) Add this PRIVATE key to GitHub Repository Secrets as:");
  console.log("   Secret name: OPENKEYLET_UPDATE_SIGNING_KEY");
  console.log("");
  console.log(privDer);
  console.log("");
  console.log("2) Derived PUBLIC key (32-byte raw Ed25519, base64):");
  console.log("   (CI derives this automatically from OPENKEYLET_UPDATE_SIGNING_KEY at build time!)");
  console.log("");
  console.log(pubB64);
  console.log("");
  console.log("Keep the private key secret and never commit it to git.");
}

function cmdPubkey() {
  const privateKey = loadPrivateKey(process.env.OPENKEYLET_UPDATE_SIGNING_KEY);
  process.stdout.write(rawPublicKeyBase64(privateKey));
}

function cmdGenerate(flags) {
  const tag = String(flags.tag || "").trim();
  const repo = String(flags.repo || "").trim();
  const assetsDir = String(flags["assets-dir"] || "").trim();
  const outPath = String(flags.out || "").trim();
  const keyId = String(flags["key-id"] || "ok-release-1").trim();
  if (!tag || !repo || !assetsDir || !outPath) {
    fail("Usage: generate --tag <vX.Y.Z> --repo <owner/repo> --assets-dir <dir> --out <latest.json> [--notes-file <file>]");
  }
  const version = tag.replace(/^v/i, "");
  const privateKey = loadPrivateKey(process.env.OPENKEYLET_UPDATE_SIGNING_KEY);
  const publicKey = crypto.createPublicKey(privateKey);

  let notes = "";
  if (flags["notes-file"] && fs.existsSync(flags["notes-file"])) {
    notes = fs.readFileSync(flags["notes-file"], "utf8").trim();
  } else if (flags.notes) {
    notes = String(flags.notes).trim();
  }

  const entries = fs.readdirSync(assetsDir).sort();
  const platforms = {};
  for (const name of entries) {
    const match = detectPlatform(name);
    if (!match) continue;
    const fullPath = path.join(assetsDir, name);
    const stat = fs.statSync(fullPath);
    if (!stat.isFile()) continue;
    platforms[match.key] = {
      url: `https://github.com/${repo}/releases/download/${tag}/${name}`,
      sha256: sha256File(fullPath),
      size: stat.size,
      format: match.format,
    };
  }
  const platformKeys = Object.keys(platforms);
  if (platformKeys.length === 0) {
    fail(`No OpenKeylet release archives found in ${assetsDir}`);
  }

  const manifest = {
    schemaVersion: 1,
    version,
    tag,
    publishedAt: new Date().toISOString(),
    releaseUrl: `https://github.com/${repo}/releases/tag/${tag}`,
    notes,
    platforms,
  };
  const payload = JSON.stringify(manifest);
  const signingInput = Buffer.from(`${ENVELOPE_FORMAT}\n${payload}`, "utf8");
  const signature = crypto.sign(null, signingInput, privateKey);
  const ok = crypto.verify(null, signingInput, publicKey, signature);
  if (!ok) {
    fail("Self-verification of generated Ed25519 signature failed.");
  }

  const envelope = {
    format: ENVELOPE_FORMAT,
    keyId,
    payload,
    signature: signature.toString("base64"),
  };
  fs.writeFileSync(outPath, `${JSON.stringify(envelope, null, 2)}\n`, "utf8");
  console.log(`Generated signed update manifest at ${outPath} for ${tag} (${platformKeys.join(", ")})`);
}

function cmdVerify(flags) {
  const manifestPath = String(flags.manifest || "").trim();
  const pubB64 = String(flags.pubkey || process.env.OPENKEYLET_UPDATE_PUBLIC_KEY || "").trim();
  if (!manifestPath || !pubB64) {
    fail("Usage: verify --manifest <latest.json> --pubkey <base64>");
  }
  const envelope = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  if (envelope.format !== ENVELOPE_FORMAT) {
    fail(`Unexpected envelope format: ${envelope.format}`);
  }
  const publicKey = publicKeyFromRawBase64(pubB64);
  const signingInput = Buffer.from(`${ENVELOPE_FORMAT}\n${envelope.payload}`, "utf8");
  const sig = Buffer.from(envelope.signature, "base64");
  if (!crypto.verify(null, signingInput, publicKey, sig)) {
    fail("Ed25519 signature verification failed.");
  }
  const manifest = JSON.parse(envelope.payload);
  console.log(`Verified ${manifestPath}: version=${manifest.version}, platforms=${Object.keys(manifest.platforms || {}).join(",")}`);
}

const [command, ...rest] = process.argv.slice(2);
const flags = parseFlags(rest);

switch (command) {
  case "keygen":
    cmdKeygen();
    break;
  case "pubkey":
    cmdPubkey();
    break;
  case "generate":
    cmdGenerate(flags);
    break;
  case "verify":
    cmdVerify(flags);
    break;
  default:
    fail("Unknown command. Use one of: keygen | pubkey | generate | verify");
}
