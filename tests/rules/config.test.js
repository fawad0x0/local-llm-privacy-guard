const test = require("node:test");
const assert = require("node:assert/strict");
const { loadEngine } = require("../helpers/load");
const PG = loadEngine();
const out = t => PG.scan(t).text;

test(".env assignments keep the key and redact the value", () => {
  assert.equal(out("DB_PASSWORD=hunter2pass"), "DB_PASSWORD=[PASSWORD_1]");
  assert.equal(out('export API_TOKEN="Zx9Kq2Lm8Np4"'), 'export API_TOKEN="[TOKEN_1]"');
  assert.equal(out("set DB_PASS=Winter2024!"), "set DB_PASS=[PASSWORD_1]");
  assert.equal(out('$env:CLIENT_SECRET = "Zx9Kq2Lm8Np4Rt"'), '$env:CLIENT_SECRET = "[SECRET_1]"');
  assert.equal(out("ENV SECRET_KEY_BASE a8f9e7d6c5b4a3"), "ENV SECRET_KEY_BASE [SECRET_1]");
});

test("JSON / YAML / INI / XML forms", () => {
  assert.equal(out('{"password": "Pg-Pass-2024!"}'), '{"password": "[PASSWORD_1]"}');
  assert.equal(out("password: Pg-Pass-2024!"), "password: [PASSWORD_1]");
  assert.equal(out("[db]\npassword = Pg-Pass-2024!"), "[db]\npassword = [PASSWORD_1]");
  assert.equal(out("<password>Pg-Pass-2024!</password>"), "<password>[PASSWORD_1]</password>");
  assert.equal(out('<add key="ApiKey" value="Zx9Kq2Lm8Np4Rt6V" />'), '<add key="ApiKey" value="[API_KEY_1]" />');
});

test("connection strings", () => {
  assert.match(out("Server=sql01;User Id=sa;Password=Sql!Pass99;"), /Password=\[PASSWORD_1\];/);
  assert.equal(out("REDIS_URL=redis://localhost:6379"), "REDIS_URL=redis://localhost:6379");
});

test("key names that are not secrets", () => {
  for (const t of [
    "password_min_length: 12",
    "max_tokens: 4096",
    "token_limit=100",
    "AUTH_PROVIDER=google",
    "SSL_KEY_FILE=/etc/ssl/key.pem",
    "client_id: web-app"
  ]) {
    assert.equal(out(t), t, t);
  }
});

test("CLI secrets", () => {
  assert.match(out("mysql -u root -pR00tPass! shop"), /-p\[PASSWORD_1\]/);
  assert.match(out("curl -u deploy:Depl0y!Pass https://x"), /deploy:\[PASSWORD_1\]/);
  assert.match(out("deploy --token Zx9Kq2Lm8Np4Rt7Yu"), /--token \[SECRET_1\]/);
  assert.match(out("vault login s.Zx9Kq2Lm8Np4Rt7Yu1Io3Pa5Sd"), /login \[VAULT_TOKEN_1\]/);
});

test("Kubernetes Secret data values are redacted only inside a Secret", () => {
  const secret = "kind: Secret\ndata:\n  username: YWRtaW4=\n  config.json: eyJhIjoxfQ==\n";
  const r = PG.scan(secret);
  assert.ok(!r.text.includes("YWRtaW4=") && !r.text.includes("eyJhIjoxfQ=="));
  assert.ok(r.blocks.some(b => b.id === "k8s_secret" && b.active));
  const cm = "kind: ConfigMap\ndata:\n  username: YWRtaW4=\n";
  assert.equal(PG.scan(cm).text, cm);
});
