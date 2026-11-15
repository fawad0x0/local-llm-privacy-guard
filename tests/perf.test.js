// Performance budget and catastrophic-backtracking (ReDoS) guards.
const test = require("node:test");
const assert = require("node:assert/strict");
const { loadEngine } = require("./helpers/load");
const positive = require("./fixtures/positive");
const PG = loadEngine();

const BUDGET_100KB_MS = Number(process.env.PG_PERF_BUDGET_MS || 50);

function time(fn) {
  const t0 = process.hrtime.bigint();
  fn();
  return Number(process.hrtime.bigint() - t0) / 1e6;
}

test(`100 KB mixed paste scans within ${BUDGET_100KB_MS} ms`, () => {
  const prose = "Please review this function and suggest improvements for error handling and retries. ";
  let text = "";
  let i = 0;
  while (text.length < 100 * 1024) {
    text += i % 5 === 0 ? positive[i % positive.length].text + "\n" : prose.repeat(3) + "\n";
    i++;
  }
  PG.scan(text); // warm-up (regex compilation, JIT)
  // Best of 5: node --test runs files in parallel, so single runs include CPU contention noise.
  const best = Math.min(...Array.from({ length: 5 }, () => time(() => PG.scan(text))));
  assert.ok(best < BUDGET_100KB_MS, `best run ${best.toFixed(1)} ms exceeds budget`);
});

const PATHOLOGICAL = {
  "long word": "a".repeat(50000),
  "long digits": "1".repeat(50000),
  "digit groups": "1 ".repeat(25000),
  "equals chain": "a=".repeat(25000),
  "colon chain": "a:".repeat(25000),
  dots: "1.".repeat(25000),
  "hex colons": "ab:".repeat(20000),
  "at signs": "a@".repeat(25000),
  dashes: "-".repeat(50000),
  "begin key no end": "-----BEGIN RSA PRIVATE KEY-----\n" + "A".repeat(60000),
  quotes: '"'.repeat(50000),
  base64: "QUJD".repeat(15000),
  "url-ish": "http://a:b@".repeat(5000),
  backslashes: "C:\\Users\\".repeat(5000),
  newlines: "\n".repeat(50000),
  xml: "<a>".repeat(15000)
};

for (const [name, text] of Object.entries(PATHOLOGICAL)) {
  test(`no catastrophic backtracking: ${name}`, () => {
    const ms = time(() => PG.scan(text));
    assert.ok(ms < 1500, `${name} took ${ms.toFixed(0)} ms`);
  });
}
