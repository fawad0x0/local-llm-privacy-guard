# Local LLM Privacy Guard

[![CI](https://github.com/fawad0x0/local-llm-privacy-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/fawad0x0/local-llm-privacy-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Manifest V3](https://img.shields.io/badge/Manifest-V3-4285F4)
![Chrome | Edge | Firefox 128+](https://img.shields.io/badge/browsers-Chrome%20%7C%20Edge%20%7C%20Firefox%20128%2B-informational)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

A free, open-source Chrome and Firefox extension that checks what you send to AI chat sites **before it leaves your browser**.
It finds secrets, `.env` files, configuration files, logs and stack traces with real data, and personal
information, then lets you send a sanitized version with placeholders like `[PASSWORD_1]`.

Everything runs locally. There is no server, no telemetry and no stored prompt text. See [PRIVACY.md](PRIVACY.md).

## Why

Developers paste error logs, config files and `.env` snippets into ChatGPT, Claude and Gemini every day to get help.
Those pastes often carry database passwords, API keys, internal hostnames, customer emails and IDs.
Privacy Guard sits between you and the chat box and catches that data before it is sent, while keeping the
message useful to the AI: key names, structure and context stay visible, only the sensitive values are replaced.

## Example

You paste this into a chat:

```text
My app crashes on startup:
DB_HOST=db-prod-01.corp.internal
DB_PASSWORD=Sup3r$ecretPa55
STRIPE_KEY=sk_live_********************
Error: connect ECONNREFUSED 10.20.4.17:5432 at C:\Users\ali\app\server.js:42
Contact: ali.khan@acme-corp.com
```

Privacy Guard shows a review panel and, if you accept, sends:

```text
My app crashes on startup:
DB_HOST=[HOST_1]
DB_PASSWORD=[PASSWORD_1]
STRIPE_KEY=[STRIPE_KEY_1]
Error: connect ECONNREFUSED [IP_1]:5432 at C:\Users\[USER_1]\app\server.js:42
Contact: [EMAIL_1]
```

The AI can still diagnose the problem. Afterwards, **Show real values** swaps the originals back into the page on your screen only.
(Exact placeholder names depend on the rule that matched.)

## What it scans

| Path                                 | What happens                                                                                    |
| ------------------------------------ | ----------------------------------------------------------------------------------------------- |
| Pressing Enter or clicking Send      | The message is scanned and reviewed before it is sent.                                          |
| Pasting or dropping text             | The text is reviewed before it reaches the message box.                                         |
| Attaching, pasting or dropping files | Text files are read locally. Secret files like `.env`, `id_rsa` or `*.pem` are flagged by name. |

## What it detects

- **`.env` files and environment variables.** `KEY=value`, `export`, `set`, PowerShell `$env:`, Dockerfile `ENV`/`ARG`, `docker run -e`.
  Key names stay visible: `DB_PASSWORD=[PASSWORD_1]`.
- **System secrets.** AWS, Azure, Google Cloud service accounts, OpenAI, Anthropic, Hugging Face, GitHub, GitLab, Slack, Discord,
  Telegram, Stripe, Twilio, SendGrid, Mailgun, npm, PyPI, Docker Hub, Shopify, HashiCorp Vault, JWTs, bearer tokens,
  all private-key formats, password hashes and passwords inside URLs.
- **Configuration files.** Secret values by key name in JSON, YAML, INI/TOML, `.properties`, XML and `web.config`, `wp-config.php`,
  docker-compose, Kubernetes Secrets, kubeconfig, AWS credentials, `.netrc`, `.htpasswd`, Ansible Vault and connection strings.
- **Logs, errors and stack traces.** Usernames in file paths, internal hostnames, IPs and MAC addresses, row values in database errors,
  SQL literals in error output, `Authorization` and `Cookie` headers, tokens in URLs, passwords in `curl`, `mysql` and `sshpass` commands,
  and cloud account or subscription IDs.
- **Personal data.** Emails, phone numbers, Luhn-checked cards, IBANs, dates of birth, passports and addresses.
  Country packs cover Pakistan (CNIC, NTN, mobile) and the US (on by default), plus the UK, India and UAE (opt-in).
- **Your own rules.** Custom regex rules, a confidential-terms dictionary, internal domains and an allowlist.
- **Optional local AI.** A model on your own computer (Ollama-compatible, localhost only) can flag names, companies, addresses
  and confidential business details that patterns miss.

Placeholders and templates are ignored. Values like `changeme`, `your_key_here`, `${VAR}` and `process.env.X` are not flagged.

## How a review works

Each finding has a severity. Your policy decides what happens, and you can change it in the options page.

| Severity                                        | Default action                                          |
| ----------------------------------------------- | ------------------------------------------------------- |
| Critical, such as private keys or live API keys | **Block.** You must redact, or type `SEND` to override. |
| High, such as passwords or tokens               | **Review.**                                             |
| Medium, such as emails, IPs or hostnames        | **Review.**                                             |
| Low, such as usernames in paths                 | **Note.** The message is sent with a short notice.      |

In the review panel you can uncheck findings that are safe, edit the text, or view the original with highlights.
After sending a sanitized message, **Show real values** puts the original values back into the page on your screen only.

## Supported sites

ChatGPT, Claude, Gemini, Microsoft Copilot, Perplexity, DeepSeek, Mistral Le Chat, Grok, Poe and Meta AI.
You can add any other site from the popup or the options page. That uses generic detection and asks for permission for that site only.

## Install

Get the code first:

```bash
git clone https://github.com/fawad0x0/local-llm-privacy-guard.git
cd local-llm-privacy-guard
```

### Chrome or Edge

1. Run `npm install` and then `npm run build`. This creates `dist/extension`.
   If you don't use Node, you can load the project folder directly as long as it has no `node_modules` folder.
2. Open `chrome://extensions` and enable **Developer mode**.
3. Click **Load unpacked** and select `dist/extension`.
4. Reload any open AI chat tabs.

### Firefox (128 or newer)

1. Run `npm run build`.
2. Open `about:debugging#/runtime/this-firefox`, click **Load Temporary Add-on…** and pick `dist/extension/manifest.json`.

Temporary add-ons are removed when Firefox restarts. For a permanent install, sign the package through addons.mozilla.org.
Change the add-on ID in `manifest.json` before the first submission, because the ID cannot be changed later.

### Local AI check (optional)

1. Install [Ollama](https://ollama.com) and pull a model, for example `ollama pull llama3.2`.
2. If the connection test fails, allow extensions to call Ollama by setting `OLLAMA_ORIGINS=chrome-extension://*,moz-extension://*`.
3. In the options page, turn on **Ask the local model before sending** and click **Test connection**.

### Organizations

Administrators can push settings through browser policy, using the schema in `managed_schema.json`.
Set `"locked": true` to stop users from changing them.

## Development

```bash
npm install
npm test              # unit tests, fixture gate, performance budget, ReDoS guards
npm run test:e2e      # loads the extension in Chromium against a mock chat page (needs: npx playwright install chromium)
npm run lint          # ESLint
npm run lint:firefox  # Mozilla add-on linter
npm run build         # dist/extension for "Load unpacked"
npm run zip           # dist/*.zip for store upload
npm run icons         # regenerate icons
```

Fake secrets in the tests are assembled from pieces at runtime, so repository secret scanners do not flag them.

### How it works

```text
 you type / paste / drop / attach
              │
              ▼
 src/content.js ── intercepts Enter, Send click, paste, drop and file inputs (site adapter finds the composer)
              │
              ▼
 src/engine/classify.js ── detects block types: .env, JSON/YAML/INI/XML config, stack trace, logs, HTTP dump, shell
              │
              ▼
 src/rules/* ── runs all rule packs, plus stricter rules for the detected block types
              │
              ▼
 src/engine/validators.js ── Luhn, IBAN mod-97, IP ranges, entropy, placeholder/dummy filter
              │
              ▼
 src/engine/scan.js ── overlap resolution, consistent tokens ([EMAIL_1] everywhere), single-pass replace
              │
              ▼
 (optional) local model on localhost via background.js
              │
              ▼
 src/ui/panel.js ── review dialog in a closed shadow DOM → send sanitized, edit, or override
```

The same value always gets the same placeholder, so the AI can follow references across a long log.
Placeholder mappings live only in the memory of the open tab.

### Project structure

```text
manifest.json            MV3 manifest for Chrome and Firefox
background.js            custom-site registration, local-AI proxy, session counters
popup.* / options.*      toolbar popup and settings page
managed_schema.json      enterprise policy schema
src/settings.js          shared settings model
src/engine/              validators, classifier, scan pipeline, tokens, file analysis
src/rules/               pii, credentials, config, env, logs, network
src/adapters/            composer detection per site plus a generic fallback
src/ui/panel.js          review dialog, toasts, badge (closed shadow DOM)
src/content.js           send, paste, drop, upload and reveal wiring
tests/                   unit, fixtures (positive/negative), perf, e2e
```

## Limitations

- Detection is heuristic. It reduces risk but cannot guarantee that nothing sensitive reaches an AI service.
- Chat sites change their markup often. If a site's adapter selectors stop matching, the generic detection takes over.
  Strict mode blocks sending when the message box cannot be inspected.
- Some sites upload a file as soon as it is chosen. Privacy Guard holds the file and re-attaches the approved version.
  If a site does not accept the re-attached file, you will be asked to attach it again.
- Binary files such as PDFs and images are not scanned. In strict mode they are flagged for review.
- Regex cannot understand meaning. Confidential business information needs the dictionary, custom rules or the local AI check.

See [PLAN.md](PLAN.md) for the design and roadmap.

## Contributing

Contributions are welcome: new detection rules, site adapters, country packs and false-positive fixes.
Read [CONTRIBUTING.md](CONTRIBUTING.md) to get set up. When reporting a miss or a false positive, use made-up data only.

## Security

Found a way for data to leak, or a bypass of the send check? Please report it privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © fawad0x0
