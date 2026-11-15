# Privacy Guard Improvement Plan

Goal: turn the MVP into an extension that reliably scans everything a user sends to an AI chat
(typed text, pasted text, dropped/uploaded files) and catches PII, system secrets, `.env` files,
configuration files, and error messages / logs / stack traces that contain real data.

All scanning stays 100% local. No network calls.

---

## Phase 0 - Fix the existing bugs (do first)

| #    | Bug                                                        | Fix                                                                                                                                                                                                                     |
| ---- | ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0.1  | "Always review" mode blocks sending forever                | After the user reviews, set a one-time `allowNextSend` flag bound to a hash of the current text. Next send of the same text passes.                                                                                     |
| 0.2  | No way to send after a false positive                      | Add **Send original anyway** button (logs nothing, just sets the allow flag).                                                                                                                                           |
| 0.3  | Rich editors (ProseMirror/Lexical) desync after replace    | Select all in the editor, then `document.execCommand("insertText", false, text)`; fall back to a synthetic `paste` event with `DataTransfer`. Re-read the editor afterwards; if the text does not match, warn the user. |
| 0.4  | Send-button click scans the first textbox on the page      | Resolve the editor via site adapter (Phase 3), or the nearest editable inside the same `form` / ancestor container of the button.                                                                                       |
| 0.5  | PHONE rule eats IPs, dates, card numbers, order IDs        | New engine with priority + overlap resolution (Phase 1). Stricter phone rule: `+` country code or phone-like grouping, 9-15 digits, never a date shape.                                                                 |
| 0.6  | `Bearer of bad news`, `secret: between us` false positives | Bearer needs a token of 20+ chars with no spaces. Keyword rules require the value to look like a secret (no spaces, length + entropy check).                                                                            |
| 0.7  | Rules re-match placeholders (double counting)              | Scan the original text once, collect all matches, then replace in a single pass.                                                                                                                                        |
| 0.8  | Runs on every website, badge on every page                 | Restrict `matches` to supported AI sites; other sites via `optional_host_permissions`. Badge only on active sites and only when enabled.                                                                                |
| 0.9  | Panel inherits page CSS                                    | Render the panel inside a closed Shadow DOM root; add Escape-to-close and a focus trap.                                                                                                                                 |
| 0.10 | Dead code (`pending`, unused `original` param)             | Remove.                                                                                                                                                                                                                 |

---

## Phase 1 - New detection engine

### 1.1 Rule format

Each rule becomes an object with metadata, split into files under `src/rules/`:

```js
{
  id: "aws_secret_key",
  category: "cloud_secret",        // pii | credential | cloud_secret | env | config | log | network
  severity: "critical",            // critical | high | medium | low
  re: /aws_secret_access_key\s*[=:]\s*([A-Za-z0-9/+=]{40})/gi,
  valueGroup: 1,                   // redact only the value, keep the key name visible
  validate: (value, ctx) => true,  // Luhn, entropy, IPv4 range, placeholder check, ...
  keywords: ["aws", "secret"]      // optional proximity boost
}
```

The output keeps context readable for the AI: `DB_PASSWORD=[SECRET_1]` instead of `[API_KEY_ASSIGNMENT_1]`.

### 1.2 Engine pipeline

1. **Block classifier**: detect what kind of text this is. Types are `.env` file, JSON/YAML/TOML/INI/XML config,
   stack trace, log lines, HTTP request/response dump, shell/curl command, source code, plain prose.
2. **Run rules** for all categories, plus stricter extra rules for the detected block type.
3. **Validators**: Luhn (cards), IBAN mod-97, IPv4/IPv6 ranges, CNIC/SSN shape, Shannon entropy, placeholder filter.
4. **Overlap resolution**: sort by severity, then length; drop matches inside an already chosen match.
5. **Consistent tokens**: the same value gets the same token everywhere (`alice@x.com` is always `[EMAIL_1]`).
6. **Single-pass replace** returning `{ text, findings[], blockTypes[], maxSeverity }`.

### 1.3 Placeholder / dummy filter (cuts false positives)

Do not flag values like `your_api_key_here`, `xxx`, `***`, `changeme`, `example`, `<TOKEN>`, `${VAR}`,
`$VAR`, `%VAR%`, `process.env.X`, `os.environ["X"]`, `{{ secret }}`, `null`, `true`/`false`, empty strings,
or secret values shorter than 6 chars.

### 1.4 Entropy check

For keyword-assigned values and generic long strings: flag when length >= 20 and Shannon entropy >= 3.5
bits/char **and** a secret keyword is within about 40 chars. Pure entropy without a keyword is `low` severity only.

---

## Phase 2 - New things to scan before sending

### 2.1 `.env` files and environment variables

- Treat a block as `.env` when 3+ lines match `^(export\s+)?[A-Z][A-Z0-9_]*=.*$`.
- When an env block is found: warn **"This looks like an .env file"** (high), and redact every value whose
  key contains `KEY, SECRET, TOKEN, PASS, PWD, AUTH, CREDENTIAL, PRIVATE, DSN, DATABASE_URL, CONN, SALT,
SIGNING, WEBHOOK, COOKIE, SESSION`. Key names stay visible.
- Single lines too: `export AWS_SECRET_ACCESS_KEY=...`, `set DB_PASS=...` (cmd), `$env:TOKEN="..."` (PowerShell),
  `ENV SECRET=...` / `ARG` in Dockerfiles, `--build-arg TOKEN=...`, `-e PASSWORD=...` in `docker run`.

### 2.2 System secrets and credentials (provider-specific)

| Provider / type             | Pattern idea                                                                               |
| --------------------------- | ------------------------------------------------------------------------------------------ |
| AWS access key              | `AKIA` / `ASIA` + 16 chars                                                                 |
| AWS secret key              | 40-char base64 after `aws_secret_access_key` / `AWS_SECRET`                                |
| AWS session token           | value after `aws_session_token`                                                            |
| Azure storage               | `AccountKey=...;`, `SharedAccessSignature`, SAS `sig=` in URLs                             |
| Azure / Entra client secret | after `client_secret`, `AZURE_CLIENT_SECRET`                                               |
| GCP service account JSON    | `"type": "service_account"` + `"private_key"` -> critical                                  |
| Google API key              | `AIza[0-9A-Za-z_-]{35}`                                                                    |
| Google OAuth secret         | `GOCSPX-...`                                                                               |
| OpenAI                      | `sk-proj-...`, `sk-...`                                                                    |
| Anthropic                   | `sk-ant-...`                                                                               |
| Hugging Face                | `hf_...`                                                                                   |
| GitHub                      | `ghp_ gho_ ghu_ ghs_ ghr_`, `github_pat_...`                                               |
| GitLab                      | `glpat-...`, `gldt-...`                                                                    |
| Slack                       | `xox[baprs]-...`, `hooks.slack.com/services/...`                                           |
| Discord                     | webhook URLs, bot tokens                                                                   |
| Telegram bot                | `\d{8,10}:[A-Za-z0-9_-]{35}`                                                               |
| Stripe                      | `sk_live_`, `rk_live_`, `whsec_` (`sk_test_` = medium)                                     |
| Twilio / SendGrid / Mailgun | `SK`/`AC` + 32 hex, `SG.xxx.yyy`, `key-...`                                                |
| npm / PyPI / Docker Hub     | `npm_...`, `pypi-...`, `dckr_pat_...`                                                      |
| Shopify                     | `shpat_ shpss_ shpca_`                                                                     |
| JWT                         | `eyJ...` `.` `eyJ...` `.` signature                                                        |
| Private keys                | RSA, EC, DSA, OPENSSH, **ENCRYPTED**, PGP `PRIVATE KEY BLOCK`, PuTTY `PuTTY-User-Key-File` |
| Password hashes             | bcrypt `$2a$`/`$2b$`, `$argon2`, `$6$` shadow lines, NTLM hashes                           |
| Basic-auth URLs             | `scheme://user:password@host`                                                              |
| Git credentials             | `https://x-access-token:...@github.com`, `.git-credentials` lines                          |
| SSH                         | `ssh-rsa AAAA... user@host` (low), `IdentityFile` paths                                    |

### 2.3 Configuration files

Detect JSON / YAML / TOML / INI / XML / `.properties` and redact secret values by key name.

- Generic keys: `password, passwd, pwd, secret, token, api_key, apikey, access_key, private_key,
client_secret, auth, credentials, connectionString, dsn, signing_key, encryption_key, salt`.
- JSON `"password": "..."`, YAML `password: ...`, INI/TOML `password = ...`,
  XML `<password>...</password>` and `<add key="ApiKey" value="..."/>` (web.config / app.config).
- Known files recognized by content:
  - `docker-compose.yml` `environment:` sections
  - Kubernetes `kind: Secret` with `data:` / `stringData:` (base64 values = critical)
  - kubeconfig `client-key-data`, `client-certificate-data`, `token:`
  - `~/.aws/credentials`, `.npmrc` `_authToken`, `.pypirc`, `.netrc` `password`, `.htpasswd`
  - Terraform `*.tfvars` and `terraform.tfstate`
  - Spring `application.properties` / `application.yml` (`spring.datasource.password`)
  - Laravel / Rails / Django settings (`APP_KEY`, `SECRET_KEY_BASE`, `SECRET_KEY`)
  - `wp-config.php` `define('DB_PASSWORD', '...')`
  - Ansible vault content, Helm `values.yaml` secrets
- Connection strings (critical): `postgres://`, `postgresql://`, `mysql://`, `mongodb(+srv)://`,
  `redis(s)://`, `amqp(s)://`, `mssql://`, `jdbc:...password=...`,
  ADO.NET `Server=...;User Id=...;Password=...;`.

### 2.4 Error messages, logs and stack traces with real data

Classify a block as `log` or `stack_trace`, warn **"This looks like log / error output"**, then redact:

| Leak                     | Example                                                                                   | Redacted as                        |
| ------------------------ | ----------------------------------------------------------------------------------------- | ---------------------------------- |
| User home paths          | `C:\Users\Wasim\...`, `/home/alice/`, `/Users/bob/`                                       | `C:\Users\[USER]\...`              |
| Internal hostnames       | `db01.corp.local`, `*.internal`, `*.lan`, `*.intranet`, custom company domains            | `[HOST_1]`                         |
| IPs, ports, MACs         | `10.0.3.7:5432`, IPv6, `00:1A:2B:3C:4D:5E`                                                | `[IP_1]`                           |
| DB errors with row data  | `Key (email)=(a@b.com) already exists`, `Duplicate entry 'x' for key`, `ORA-`, `SQLSTATE` | value redacted                     |
| SQL inside errors        | `INSERT ... VALUES ('Ali', '0300...')`                                                    | literal values redacted            |
| Connection errors        | `could not connect to postgres://admin:pw@10.0.0.5`                                       | DSN redacted                       |
| HTTP headers             | `Authorization:`, `Cookie:`, `Set-Cookie:`, `X-Api-Key:`, `X-Auth-Token:`                 | header value redacted              |
| URL query secrets        | `?token=`, `access_token=`, `api_key=`, `code=`, `sig=`, `session=`                       | value redacted                     |
| CLI commands             | `curl -u user:pass`, `-H "Authorization: ..."`, `mysql -pSecret`, `--password=`           | value redacted                     |
| Session / CSRF tokens    | session cookies, CSRF tokens                                                              | `[SESSION_1]`                      |
| User identifiers in logs | emails, phones, user IDs, account numbers                                                 | normal PII tokens                  |
| Source paths in traces   | `/srv/company-app/src/...`                                                                | username / org part redacted (low) |
| Cloud resource IDs       | AWS account IDs in `arn:`, ARNs, Azure subscription GUIDs                                 | `[ACCOUNT_1]` (medium)             |

Stack-trace signals: `Traceback (most recent call last)`, `at com.x.y(File.java:12)`,
`at fn (/path/file.js:10:5)`, `Exception in thread`, `panic:` + `goroutine`, PHP `Fatal error:`,
`System.NullReferenceException`, `#0 ...` frames.

### 2.5 More PII

Credit cards (Luhn), IBAN (mod-97), Pakistani mobile `03xx-xxxxxxx` / `+92`, NTN, passport numbers
(keyword-gated), dates of birth (keyword-gated: `DOB`, `born`), street addresses (keyword-gated),
optional country packs (UK NI, India Aadhaar / PAN, UAE Emirates ID).

---

## Phase 3 - Cover every way text leaves the page

1. **Typed text**: Enter, send button, form submit (existing, fixed via adapters).
2. **Paste scanning**: listen to `paste` in the capture phase. If pasted text has critical/high findings
   (typical for `.env`, logs, configs), show the panel right away with _Paste sanitized_ / _Paste original_ / _Cancel_.
   This is the most important new path, because people paste `.env` files and error logs.
3. **Drag and drop**: scan text from `drop` events the same way.
4. **File uploads**: intercept `drop` and `change` on `input[type=file]`.
   - Block by filename: `.env*`, `id_rsa`, `id_ed25519`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `credentials`,
     `*.tfstate`, `*.tfvars`, `kubeconfig`, `.npmrc`, `.netrc`, `.git-credentials`.
   - Read text files locally (`.txt .log .json .yaml .yml .toml .ini .xml .csv .md .js .py ...`, size-limited)
     with `File.text()` and scan them. If findings exist, clear the input and offer a sanitized copy to upload instead.
   - Limitation to document: some sites upload immediately on `change`. Strict mode warns when this cannot be prevented.
5. **Site adapters** in `src/adapters/`: ChatGPT, Claude, Gemini, Microsoft Copilot, Perplexity, DeepSeek,
   Mistral Le Chat, Grok, Poe, Meta AI. Each adapter defines the editor selector, send button selector,
   read/write text methods and file input selector. A generic fallback adapter is opt-in.
6. **Shadow DOM and iframes**: use `event.composedPath()` to find editors; `all_frames: true` for supported sites.
7. **Strict mode**: if the adapter cannot find or verify the editor, block sending and explain why.

---

## Phase 4 - User experience

- Preview with **highlighted findings** grouped by category, severity color and a keep/redact checkbox each.
  Show why something was flagged ("looks like an AWS secret key").
- Block-level banner: "This looks like an .env file / stack trace / Kubernetes Secret".
- Policy per severity: `critical` blocks until redacted (or typed-confirmation override), `high` needs review,
  `medium` review, `low` inline note only. Configurable.
- **Restore real values in AI replies**: per-tab, in-memory token -> original map (never written to disk),
  with a "Show real values" toggle on the AI's response.
- Options page: enable/disable categories, custom regex rules, custom dictionaries (client names, project
  codenames, internal domains like `*.mycompany.com`), value allowlist, per-site on/off.
- Popup: per-site toggle, count of items redacted this session (numbers only, no content).
- Dark mode, keyboard shortcuts, accessible dialog.

---

## Phase 5 - Optional local AI layer (makes the "Local LLM" name accurate)

- Use a small on-device model (transformers.js NER model, WebLLM, or an opt-in local Ollama server on
  `localhost`) to find names, addresses, organization names and confidential business text regex cannot catch.
- Run it after the regex scan, only on the text being sent, with a timeout. Regex results are always the baseline.

---

## Phase 6 - Testing and quality

- Use `node --test` (built in) or Vitest, one test file per rule category.
- **Positive fixtures** (fake but realistic): `.env` files, docker-compose, k8s Secret, kubeconfig, AWS credentials,
  GCP service-account JSON, web.config, Spring properties, Python / Java / Node / Go / .NET stack traces,
  Postgres / MySQL / Mongo errors, nginx / apache logs, curl commands, HTTP dumps.
- **Negative fixtures** (must NOT be flagged): `.env.example` with placeholders, docs with `your_api_key_here`,
  code reading `process.env.API_KEY`, dates, versions like `1.2.3.4`, order numbers, prose using "secret" / "bearer".
- Per-rule detection rate and false-positive rate; CI fails if either regresses.
- Performance: a 100 KB paste scans in under 50 ms; tests guard against catastrophic regex backtracking.
- End-to-end tests with Playwright loading the unpacked extension against a local mock chat page,
  plus a manual checklist per real site.
- ESLint, Prettier, GitHub Actions CI, `web-ext lint` for Firefox.

---

## Phase 7 - Release readiness

- Icons, options page, real Firefox add-on ID, version bump.
- Minimal permissions: `storage`, specific host permissions, `optional_host_permissions` for the rest.
- Privacy policy: no data leaves the device and nothing about prompts is stored.
- Enterprise: `storage.managed` schema so admins can force-enable rules and sites.

---

## Proposed file layout

```text
src/
  engine/
    scan.js          # pipeline: classify -> rules -> validate -> resolve -> replace
    classify.js      # env / config / log / stack trace / http / code / prose
    validators.js    # luhn, iban, ipv4/6, entropy, placeholder filter
    tokens.js        # consistent placeholder mapping
  rules/
    pii.js
    credentials.js   # provider-specific keys and tokens
    env.js
    config.js
    logs.js          # stack traces, paths, hosts, headers, sql errors
    network.js
  adapters/
    chatgpt.js claude.js gemini.js copilot.js perplexity.js deepseek.js generic.js
  ui/
    panel.js         # shadow-DOM review dialog
  content.js         # wiring: keydown, click, submit, paste, drop, file input
options.html / options.js
tests/
  fixtures/positive/*   fixtures/negative/*
  rules/*.test.js   engine.test.js   e2e/*.spec.js
```

## Order of work

1. Phase 0 bug fixes and the engine rewrite in Phase 1. This is the foundation.
2. `.env`, credential, config and log / stack-trace rules from Phase 2, with fixture tests from Phase 6 written alongside.
3. Paste scanning and file uploads (Phase 3, items 2-4). These matter most for `.env` files and logs.
4. Site adapters for the top 5 AI sites (Phase 3, item 5).
5. UX upgrades and the options page (Phase 4).
6. Release work (Phase 7), then the optional local AI layer (Phase 5).
