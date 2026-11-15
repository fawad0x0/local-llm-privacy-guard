const test = require("node:test");
const assert = require("node:assert/strict");
const { loadEngine } = require("./helpers/load");
const PG = loadEngine();
const S = PG.Settings;

test("same value gets the same token, across scans that share a registry", () => {
  const registry = PG.tokens.createRegistry();
  const a = PG.scan("mail ali@acme.pk and ali@acme.pk and sara@acme.pk", { registry });
  assert.equal(a.text, "mail [EMAIL_1] and [EMAIL_1] and [EMAIL_2]");
  const b = PG.scan("again sara@acme.pk", { registry });
  assert.equal(b.text, "again [EMAIL_2]");
  assert.equal(registry.byToken.get("[EMAIL_2]"), "sara@acme.pk");
});

test("overlaps: most severe wins, no double counting", () => {
  const r = PG.scan("password=alice@company.io");
  assert.equal(r.findings.length, 1);
  assert.equal(r.text, "password=[PASSWORD_1]");
});

test("applyRedactions lets the user keep individual findings", () => {
  const r = PG.scan("ali@acme.pk 10.0.0.5");
  const keepIp = PG.applyRedactions(r.original, r.findings, f => f.label !== "IP");
  assert.equal(keepIp, "[EMAIL_1] 10.0.0.5");
});

test("allowlist, categories and custom rules", () => {
  const allow = S.normalize({ allowlist: ["support@acme.pk"] });
  assert.equal(PG.scan("write to support@acme.pk", { settings: allow }).findings.length, 0);

  const noNet = S.normalize({ categories: { network: false } });
  assert.equal(PG.scan("server 10.0.0.5", { settings: noNet }).findings.length, 0);

  const custom = S.normalize({
    customRules: [{ label: "employee id", severity: "critical", pattern: "\\bEMP-\\d{6}\\b", flags: "g" }],
    dictionary: ["Project Falcon"]
  });
  const r = PG.scan("EMP-123456 works on project falcon", { settings: custom });
  assert.equal(r.text, "[EMPLOYEE_ID_1] works on [CONFIDENTIAL_1]");
  assert.equal(r.maxSeverity, "critical");
});

test("invalid custom regex does not break scanning", () => {
  const s = S.normalize({ customRules: [{ label: "bad", severity: "high", pattern: "([", flags: "g" }] });
  assert.equal(PG.scan("ali@acme.pk", { settings: s }).text, "[EMAIL_1]");
});

test("local AI extras are merged as exact substrings", () => {
  const r = PG.scan("Meeting with Jane Doe from Contoso", {
    extra: [
      { value: "Jane Doe", label: "PERSON" },
      { value: "Contoso", label: "ORG" },
      { value: "not present", label: "ORG" }
    ]
  });
  assert.equal(r.text, "Meeting with [PERSON_1] from [ORG_1]");
  assert.ok(r.findings.every(f => f.category === "ai"));
});

test("policy actions", () => {
  const policy = S.DEFAULTS.policy;
  assert.equal(PG.actionFor(PG.scan("hello world"), policy), "off");
  assert.equal(PG.actionFor(PG.scan("ali@acme.pk"), policy), "review");
  assert.equal(PG.actionFor(PG.scan("postgres://a:Secr3tPw@h/db"), policy), "block");
  assert.equal(PG.actionFor(PG.scan("C:\\Users\\Wasim\\x"), policy), "note");
});

test("blocks: inherently secret files warn even without findings, others only with findings", () => {
  const k8s = PG.scan("kind: Secret\nmetadata:\n  name: x\n");
  assert.ok(k8s.blocks.find(b => b.id === "k8s_secret").active);
  assert.equal(k8s.maxSeverity, "critical");
  const env = PG.scan("A=1\nB=2\nC=3");
  assert.equal(env.blocks.find(b => b.id === "env_file").active, false);
  assert.equal(env.maxSeverity, null);
});

test("settings: migration and normalization", () => {
  const s = S.normalize({ policy: { high: "explode" }, dictionary: ["  x  ", ""], localAi: { timeoutMs: 5 } });
  assert.equal(s.policy.high, "review");
  assert.deepEqual(s.dictionary, ["x"]);
  assert.equal(s.localAi.timeoutMs, 1000);
});

test("v0.1 compatibility API (LocalPrivacySanitizer.sanitize) still works", () => {
  const ctx = require("./helpers/load").loadContext();
  const r = ctx.LocalPrivacySanitizer.sanitize("Email alice@acme.io and CNIC 35202-1234567-1");
  assert.equal(r.text, "Email [EMAIL_1] and CNIC [CNIC_1]");
  assert.deepEqual(
    r.findings.map(f => f.type),
    ["EMAIL", "CNIC"]
  );
});
