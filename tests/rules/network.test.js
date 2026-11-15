const test = require("node:test");
const assert = require("node:assert/strict");
const { loadEngine } = require("../helpers/load");
const PG = loadEngine();
const labels = t =>
  PG.scan(t)
    .findings.filter(f => f.redact)
    .map(f => f.label);

test("IPv4: private and public, not loopback or versions", () => {
  assert.deepEqual(labels("db at 10.0.3.7:5432"), ["IP"]);
  assert.deepEqual(labels("peer 203.0.113.25"), ["IP"]);
  assert.deepEqual(labels("127.0.0.1 and 0.0.0.0"), []);
  assert.deepEqual(labels("version 1.2.3.4"), []);
  assert.deepEqual(labels("999.1.1.1"), []);
});

test("IPv6 and MAC", () => {
  assert.deepEqual(labels("addr 2001:db8:85a3::8a2e:370:7334"), ["IP"]);
  assert.deepEqual(labels("time 10:30:45"), []);
  assert.deepEqual(labels("nic 00:1A:2B:3C:4D:5E"), ["MAC"]);
});

test("internal hostnames and custom internal domains", () => {
  assert.deepEqual(labels("connect db01.corp.local"), ["HOST"]);
  assert.deepEqual(labels("file .env.local"), []);
  const s = PG.Settings.normalize({ internalDomains: ["acme-internal.com"] });
  assert.equal(PG.scan("see wiki.acme-internal.com/page", { settings: s }).findings[0].label, "HOST");
});
