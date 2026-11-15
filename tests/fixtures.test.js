// Detection-rate and false-positive gate over the fixture corpus. CI fails on any regression.
const test = require("node:test");
const assert = require("node:assert/strict");
const { loadEngine } = require("./helpers/load");
const positive = require("./fixtures/positive");
const negative = require("./fixtures/negative");

const PG = loadEngine();

test("positive fixtures: every sensitive value is redacted", async t => {
  let total = 0;
  let caught = 0;
  for (const c of positive) {
    await t.test(c.name, () => {
      const r = PG.scan(c.text);
      for (const v of c.mustRedact) {
        total++;
        if (!r.text.includes(v)) caught++;
        assert.ok(!r.text.includes(v), `not redacted: ${JSON.stringify(v.slice(0, 40))}`);
      }
      for (const v of c.mustKeep || []) assert.ok(r.text.includes(v), `context lost: ${v}`);
      const ids = r.blocks.map(b => b.id);
      for (const b of c.blocks || []) assert.ok(ids.includes(b), `block type not detected: ${b}`);
    });
  }
  t.diagnostic(`detection rate: ${caught}/${total}`);
});

test("negative fixtures: no false positives", async t => {
  for (const c of negative) {
    await t.test(c.name, () => {
      const r = PG.scan(c.text);
      const bad = r.findings.filter(f => f.redact).map(f => `${f.ruleId}: ${f.value}`);
      assert.deepEqual(bad, []);
      assert.equal(r.text, c.text);
    });
  }
});
