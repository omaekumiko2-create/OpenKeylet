import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const files = {
  pkg: path.join(root, 'package.json'),
  cargo: path.join(root, 'src-tauri', 'Cargo.toml'),
  tauri: path.join(root, 'src-tauri', 'tauri.conf.json'),
  manifest: path.join(root, 'browser-extension', 'manifest.json'),
};

function readVersions() {
  const pkg = JSON.parse(fs.readFileSync(files.pkg, 'utf8')).version;
  const tauri = JSON.parse(fs.readFileSync(files.tauri, 'utf8')).version;
  const manifest = JSON.parse(fs.readFileSync(files.manifest, 'utf8')).version;
  const cargoText = fs.readFileSync(files.cargo, 'utf8');
  const cargoMatch = cargoText.match(/^version\s*=\s*"([^"]+)"/m);
  const cargo = cargoMatch ? cargoMatch[1] : null;
  return { pkg, cargo, tauri, manifest };
}

const nextVersion = process.argv[2]?.trim();
if (nextVersion) {
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(nextVersion)) {
    console.error(`Invalid semver version: ${nextVersion}`);
    process.exit(1);
  }
  const pkgJson = JSON.parse(fs.readFileSync(files.pkg, 'utf8'));
  pkgJson.version = nextVersion;
  fs.writeFileSync(files.pkg, `${JSON.stringify(pkgJson, null, 2)}\n`);

  const tauriJson = JSON.parse(fs.readFileSync(files.tauri, 'utf8'));
  tauriJson.version = nextVersion;
  fs.writeFileSync(files.tauri, `${JSON.stringify(tauriJson, null, 2)}\n`);

  const manifestJson = JSON.parse(fs.readFileSync(files.manifest, 'utf8'));
  manifestJson.version = nextVersion;
  fs.writeFileSync(files.manifest, `${JSON.stringify(manifestJson, null, 2)}\n`);

  const cargoText = fs.readFileSync(files.cargo, 'utf8');
  const updatedCargo = cargoText.replace(/^(version\s*=\s*)"[^"]+"/m, `$1"${nextVersion}"`);
  fs.writeFileSync(files.cargo, updatedCargo);

  console.log(`Synced all OpenKeylet manifests to v${nextVersion}`);
}

const versions = readVersions();
const unique = new Set(Object.values(versions));
if (unique.size !== 1 || !versions.cargo) {
  console.error('Version mismatch detected across OpenKeylet manifests:', versions);
  process.exit(1);
}
console.log(`All OpenKeylet versions aligned: v${versions.cargo}`, versions);
