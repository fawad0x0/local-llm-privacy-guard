const test = require("node:test");
const assert = require("node:assert/strict");
const { loadEngine } = require("../helpers/load");
const PG = loadEngine();
const labels = t =>
  PG.scan(t)
    .findings.filter(f => f.redact)
    .map(f => f.label);

test("email", () => {
  assert.deepEqual(labels("mail alice@acme.io now"), ["EMAIL"]);
  assert.deepEqual(labels("user@example.com"), []);
  assert.deepEqual(labels("git@github.com:org/repo"), []);
});

test("phones: international, US, Pakistan", () => {
  assert.deepEqual(labels("Call +1 (415) 555-0198"), ["PHONE"]);
  assert.deepEqual(labels("call (415) 555-0198 today"), ["PHONE"]);
  assert.deepEqual(labels("my number 0300-1234567"), ["PHONE"]);
  assert.deepEqual(labels("on 2024-01-15"), []);
});

test("CNIC, SSN, NTN", () => {
  assert.deepEqual(labels("CNIC 35202-1234567-1"), ["CNIC"]);
  assert.deepEqual(labels("SSN 123-45-6789"), ["SSN"]);
  assert.deepEqual(labels("SSN 000-12-3456"), []);
  assert.deepEqual(labels("NTN: 1234567-8"), ["NTN"]);
});

test("payment cards need a valid Luhn checksum", () => {
  assert.deepEqual(labels("card 4111 1111 1111 1111"), ["CARD"]);
  assert.deepEqual(labels("card 4111 1111 1111 1112"), []);
});

test("IBAN needs a valid mod-97 checksum", () => {
  assert.deepEqual(labels("PK36SCBL0000001123456702"), ["IBAN"]);
  assert.deepEqual(labels("PK37SCBL0000001123456702"), []);
});

test("keyword-gated identifiers", () => {
  assert.deepEqual(labels("passport no AB1234567"), ["PASSPORT"]);
  assert.deepEqual(labels("DOB: 12/04/1990"), ["DOB"]);
  assert.deepEqual(labels("Address: House 12, Street 5, F-7/2 Islamabad"), ["ADDRESS"]);
  assert.deepEqual(labels("IP address: 8.8.8.8 is public"), ["IP"]);
});

test("country packs are opt-in", () => {
  const off = PG.Settings.normalize({});
  const on = PG.Settings.normalize({ packs: { uk: true, in: true, ae: true } });
  assert.equal(PG.scan("NI AB123456C", { settings: off }).findings.length, 0);
  assert.equal(PG.scan("NI AB123456C", { settings: on }).findings[0].label, "NI_NUMBER");
  assert.equal(PG.scan("aadhaar 2345 6789 0123", { settings: on }).findings[0].label, "AADHAAR");
  assert.equal(PG.scan("ID 784-1990-1234567-1", { settings: on }).findings[0].label, "EMIRATES_ID");
  const pkOff = PG.Settings.normalize({ packs: { pk: false } });
  assert.equal(PG.scan("CNIC 35202-1234567-1", { settings: pkOff }).findings.length, 0);
});
