const test = require("node:test");
const assert = require("node:assert/strict");
const { loadEngine } = require("../helpers/load");
const PG = loadEngine();
const j = (...p) => p.join(""); // assembled so secret scanners do not flag these fake values
const first = t => PG.scan(t).findings.find(f => f.redact);

const CASES = [
  ["AWS_KEY", j("AK", "IA", "QWERTYUIOPASDFGH")],
  ["GITHUB_TOKEN", j("gh", "p_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8")],
  ["GITHUB_TOKEN", j("github", "_pat_", "11ABCDEFG0123456789_abcdefghijKLMNOP")],
  ["GITLAB_TOKEN", j("gl", "pat-", "a1B2c3D4e5F6g7H8i9J0")],
  ["OPENAI_KEY", j("sk-", "proj-", "a1B2c3D4e5F6g7H8i9J0k1L2")],
  ["ANTHROPIC_KEY", j("sk-", "ant-", "api03-", "a1B2c3D4e5F6g7H8i9J0k1L2")],
  ["STRIPE_KEY", j("sk_", "live_", "a1B2c3D4e5F6g7H8i9J0k1L2")],
  ["STRIPE_TEST_KEY", j("sk_", "test_", "a1B2c3D4e5F6g7H8i9J0k1L2")],
  ["SLACK_TOKEN", j("xo", "xb-", "1234567890-a1B2c3D4e5F6")],
  ["GOOGLE_KEY", j("AI", "za", "SyA1234567890abcdefghijklmnopqrstuv")],
  ["GOOGLE_SECRET", j("GOC", "SPX-", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4")],
  ["HF_TOKEN", j("hf", "_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6")],
  ["NPM_TOKEN", j("np", "m_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8")],
  ["DOCKER_TOKEN", j("dckr", "_pat_", "a1B2c3D4e5F6g7H8i9J0")],
  ["SHOPIFY_TOKEN", j("shp", "at_", "0123456789abcdef0123456789abcdef")],
  ["TELEGRAM_TOKEN", j("123456789", ":", "AAHa1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6")],
  ["WEBHOOK", j("https://hooks.", "slack.com/services/", "T000/B000/XXXXabc123")],
  ["JWT", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123def456ghi"],
  ["TOKEN", "Bearer a1B2c3D4e5F6g7H8i9J0k1L2"]
];

for (const [label, value] of CASES) {
  test(`detects ${label}: ${value.slice(0, 14)}...`, () => {
    const f = first(`here ${value} end`);
    assert.ok(f, "no finding");
    assert.equal(f.label, label);
  });
}

test("provider placeholders are ignored", () => {
  assert.equal(PG.scan(j("AK", "IAIOSFODNN7EXAMPLE")).findings.length, 0);
});

test("private keys: full and truncated, without swallowing following text", () => {
  const body = "MIIEowIBAAKCAQEAx1y2z3a4b5c6d7e8f9g0h1i2j3k4l5m6n7o8p9q0r1s2t3u4";
  const full = PG.scan(j("-----BEGIN ", "RSA PRIVATE KEY-----\n", body, "\n-----END ", "RSA PRIVATE KEY-----\nthanks"));
  assert.equal(full.findings[0].label, "PRIVATE_KEY");
  assert.ok(full.text.endsWith("\nthanks"));
  const partial = PG.scan(j("-----BEGIN ", "OPENSSH PRIVATE KEY-----\n", body, "\nThanks"));
  assert.ok(!partial.text.includes(body));
  assert.ok(partial.text.endsWith("Thanks"));
});

test("URL credentials redact only the password", () => {
  const r = PG.scan("postgres://admin:S3cretPw@db.example.org:5432/app");
  assert.equal(r.text, "postgres://admin:[PASSWORD_1]@db.example.org:5432/app");
});

test("high-entropy strings: high next to a keyword, kept by default otherwise", () => {
  const near = PG.scan("signing key Zq8xL2mN4pR6tV8yA1cE3gI5kM7oQ9sU").findings[0];
  assert.equal(near.severity, "high");
  const alone = PG.scan("commit Zq8xL2mN4pR6tV8yA1cE3gI5kM7oQ9sU merged").findings[0];
  assert.equal(alone.severity, "low");
  assert.equal(alone.redact, false);
});
