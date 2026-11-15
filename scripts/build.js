// Copies only the files the browser needs into dist/extension (load this folder with "Load unpacked").
// The project root also contains node_modules, which Chrome refuses to load (reserved "_" file names).
// Run: node scripts/build.js [outDir]
const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const FILES = [
  "manifest.json",
  "managed_schema.json",
  "background.js",
  "popup.html",
  "popup.css",
  "popup.js",
  "options.html",
  "options.css",
  "options.js",
  "src",
  "icons"
];

function copy(src, dst) {
  const st = fs.statSync(src);
  if (st.isDirectory()) {
    fs.mkdirSync(dst, { recursive: true });
    for (const f of fs.readdirSync(src)) copy(path.join(src, f), path.join(dst, f));
  } else {
    fs.copyFileSync(src, dst);
  }
}

function build(outDir = path.join(ROOT, "dist", "extension")) {
  fs.rmSync(outDir, { recursive: true, force: true });
  fs.mkdirSync(outDir, { recursive: true });
  for (const f of FILES) copy(path.join(ROOT, f), path.join(outDir, f));

  // Sanity check: every script referenced by the manifest exists.
  const manifest = JSON.parse(fs.readFileSync(path.join(outDir, "manifest.json"), "utf8"));
  const referenced = [
    ...manifest.content_scripts.flatMap(c => c.js),
    manifest.background.service_worker,
    ...(manifest.background.scripts || []),
    ...Object.values(manifest.icons)
  ];
  const missing = referenced.filter(f => !fs.existsSync(path.join(outDir, f)));
  if (missing.length) throw new Error("Missing files referenced by manifest: " + missing.join(", "));
  return outDir;
}

if (require.main === module) {
  const out = build(process.argv[2] ? path.resolve(process.argv[2]) : undefined);
  console.log("Extension built at", out);
}

module.exports = { build, FILES };
