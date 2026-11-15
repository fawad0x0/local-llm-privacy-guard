// Loads the extension's detection engine (same file order as manifest.json) into this test process.
// node --test runs every test file in its own process, so each file gets a fresh engine.
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.resolve(__dirname, "..", "..");
const ENGINE_FILES = [
  "src/settings.js",
  "src/engine/validators.js",
  "src/rules/pii.js",
  "src/rules/credentials.js",
  "src/rules/config.js",
  "src/rules/env.js",
  "src/rules/logs.js",
  "src/rules/network.js",
  "src/engine/classify.js",
  "src/engine/tokens.js",
  "src/engine/scan.js",
  "src/engine/files.js"
];

let loaded = false;

function loadContext() {
  if (!loaded) {
    for (const f of ENGINE_FILES) {
      vm.runInThisContext(fs.readFileSync(path.join(ROOT, f), "utf8"), { filename: path.join(ROOT, f) });
    }
    loaded = true;
  }
  return globalThis;
}

const loadEngine = () => loadContext().PrivacyGuard;

module.exports = { loadEngine, loadContext, ROOT, ENGINE_FILES };
