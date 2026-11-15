const test = require("node:test");
const assert = require("node:assert/strict");
const { loadEngine } = require("../helpers/load");
const PG = loadEngine();
const out = t => PG.scan(t).text;

test("usernames in paths", () => {
  assert.equal(out("C:\\Users\\Wasim\\app.py"), "C:\\Users\\[USER_1]\\app.py");
  assert.equal(out("C:\\Users\\Jane Doe\\Downloads"), "C:\\Users\\[USER_1]\\Downloads");
  assert.equal(out("/home/ayesha/project"), "/home/[USER_1]/project");
  assert.equal(out("/Users/bob/.ssh/config"), "/Users/[USER_1]/.ssh/config");
});

test("HTTP headers and query strings", () => {
  assert.equal(out("Cookie: session=8f3k2j1h5g6f7d8s9a0q"), "Cookie: [SESSION_1]");
  assert.equal(out("X-Api-Key: Zx9Kq2Lm8Np4Rt6V"), "X-Api-Key: [API_KEY_1]");
  assert.equal(out("X-Vault-Token: Zx9Kq2Lm8Np4Rt6V"), "X-Vault-Token: [TOKEN_1]");
  assert.equal(out("https://x.io/cb?code=4/0AbCdEf123&state=1"), "https://x.io/cb?code=[AUTH_CODE_1]&state=1");
  assert.equal(out("Authorization: Bearer <token>"), "Authorization: Bearer <token>");
});

test("database errors", () => {
  // An email inside the error keeps its more specific EMAIL label; other values become DB_VALUE.
  assert.equal(
    out("DETAIL:  Key (email)=(ali@acme.pk) already exists."),
    "DETAIL:  Key (email)=([EMAIL_1]) already exists."
  );
  assert.equal(
    out("DETAIL:  Key (full_name)=(Ahmed Raza) already exists."),
    "DETAIL:  Key (full_name)=([DB_VALUE_1]) already exists."
  );
  assert.equal(out("Duplicate entry 'ahmed@bank.pk' for key 'email'"), "Duplicate entry '[EMAIL_1]' for key 'email'");
  assert.equal(
    out("Duplicate entry 'INV-2024-0042' for key 'invoice_no'"),
    "Duplicate entry '[DB_VALUE_1]' for key 'invoice_no'"
  );
});

test("SQL literals are redacted only in logs/errors, enum words kept", () => {
  const err = "ERROR: insert failed\nERROR: INSERT INTO t (name, status) VALUES ('Ahmed Raza', 'active')";
  const r = PG.scan(err);
  assert.ok(!r.text.includes("Ahmed Raza"));
  assert.ok(r.text.includes("'active'"));
  const code = "INSERT INTO t (name) VALUES ('Ahmed Raza');";
  assert.equal(PG.scan(code).text, code);
});

test("stack trace and log classification", () => {
  const ids = t => PG.scan(t).blocks.map(b => b.id);
  assert.ok(ids('Traceback (most recent call last):\n  File "a.py", line 1').includes("stack_trace"));
  assert.ok(ids("panic: boom\n\ngoroutine 1 [running]:").includes("stack_trace"));
  assert.ok(ids("2024-01-01 10:00:00 INFO a\n2024-01-01 10:00:01 ERROR b").includes("log"));
  assert.ok(ids("GET /x HTTP/1.1\nHost: a").includes("http_dump"));
});

test("cloud account identifiers", () => {
  assert.match(out("arn:aws:iam::123456789012:role/x"), /::\[ACCOUNT_1\]:/);
  assert.match(out('"tenantId": "0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b"'), /\[ACCOUNT_1\]/);
});
