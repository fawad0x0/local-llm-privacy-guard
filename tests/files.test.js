const test = require("node:test");
const assert = require("node:assert/strict");
const { loadEngine } = require("./helpers/load");
const PG = loadEngine();
const opts = { settings: PG.Settings.normalize({}) };

test("blocked file names", () => {
  for (const n of [
    ".env",
    ".env.production",
    "id_rsa",
    "server.pem",
    "cert.p12",
    "credentials",
    "terraform.tfstate",
    "prod.tfvars",
    ".npmrc",
    ".git-credentials",
    "service-account.json",
    "wp-config.php"
  ]) {
    assert.ok(PG.files.blockedReason(n), n);
  }
  for (const n of [".env.example", ".env.sample", "notes.txt", "id_rsa.pub", "photo.png"]) {
    assert.equal(PG.files.blockedReason(n), null, n);
  }
});

test("text files with secrets get a sanitized copy", async () => {
  const f = new File(["DB_PASSWORD=hunter2pass\nDB_HOST=db.internal\nPORT=3000\n"], ".env", { type: "" });
  const [entry] = await PG.files.analyze([f], opts);
  assert.equal(entry.blocked, "Environment file (.env)");
  assert.equal(entry.severity, "critical");
  assert.ok(entry.sanitizedFile);
  const text = await entry.sanitizedFile.text();
  assert.equal(text, "DB_PASSWORD=[PASSWORD_1]\nDB_HOST=[HOST_1]\nPORT=3000\n");
  assert.equal(PG.files.actionFor([entry], opts.settings.policy), "block");
});

test("clean files pass, binary files are not read", async () => {
  const clean = new File(["just some notes"], "notes.txt", { type: "text/plain" });
  const img = new File([new Uint8Array([137, 80, 78, 71, 0, 0])], "photo.png", { type: "image/png" });
  const [a, b] = await PG.files.analyze([clean, img], opts);
  assert.equal(a.flagged, false);
  assert.equal(b.skipped, "binary");
  assert.equal(b.flagged, false);
  assert.equal(PG.files.actionFor([a, b], opts.settings.policy), "off");
});

test("strict mode flags files that could not be scanned", async () => {
  const strict = { settings: PG.Settings.normalize({ strictMode: true }) };
  const img = new File([new Uint8Array([1, 2, 3])], "scan.pdf", { type: "application/pdf" });
  const [e] = await PG.files.analyze([img], strict);
  assert.equal(e.flagged, true);
  assert.equal(e.severity, "high");
});

test("private key files are never offered as sanitized stubs", async () => {
  const key = new File(["-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAB3NzaC1yc2EAAAADAQABAAABAQ\n"], "id_rsa", {
    type: ""
  });
  const [e] = await PG.files.analyze([key], opts);
  assert.equal(e.blocked, "SSH private key");
  assert.equal(e.sanitizedFile, null);
  assert.equal(e.severity, "critical");
});

test("blocked text file with no findings needs review, not a hard block", async () => {
  const f = new File(["PORT=3000\n"], ".env.local", { type: "" });
  const [e] = await PG.files.analyze([f], opts);
  assert.equal(e.severity, "high");
});
