import assert from "node:assert/strict";
import { existsSync, readdirSync } from "node:fs";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { listPackage } = require("@electron/asar");
const base = "release/win-unpacked/resources";
assert.ok(existsSync(`${base}/desktop/liteseal-desktop.exe`), "Missing Rust desktop executable");
const files = listPackage(`${base}/app.asar`).map(file => file.replaceAll("\\", "/"));
for (const file of ["/dist-electron/main.cjs", "/dist-electron/preload.cjs", "/ui/dist/index.html"]) {
  assert.ok(files.includes(file), `Missing packaged resource: ${file}`);
}
assert.ok(readdirSync("release").some(name => name.endsWith(".exe")), "Missing NSIS installer");
console.log("Windows package resources verified");
