# Contributing

Thanks for helping make Local LLM Privacy Guard better. Bug reports, new detection rules, site adapters and
false-positive fixes are all welcome.

## Getting started

```bash
git clone https://github.com/fawad0x0/local-llm-privacy-guard.git
cd local-llm-privacy-guard
npm install
npm test
npm run build   # then load dist/extension as an unpacked extension
```

Node 22 or newer is recommended (the CI uses Node 22).

## Before opening a pull request

Run the same checks the CI runs:

```bash
npm run lint
npm run format:check
npm test
npm run lint:firefox
npm run test:e2e      # needs: npx playwright install chromium
```

## Adding or changing a detection rule

1. Rules live in `src/rules/` and are grouped by category (`pii`, `credentials`, `config`, `env`, `logs`, `network`).
   Each rule has an `id`, `category`, `severity`, a regex and, where useful, a `valueGroup` and a `validate` function.
2. Add at least one **positive** case to `tests/fixtures/positive.js` and one realistic **negative** case
   (something that looks similar but must not be flagged) to `tests/fixtures/negative.js`.
3. Add focused unit tests in `tests/rules/`.
4. Keep regexes linear. `tests/perf.test.js` checks the performance budget and catches catastrophic backtracking.

**Never commit real secrets.** Build fake keys from pieces at runtime, for example `"ghp_" + "a1B2..."`,
so repository secret scanners do not flag the test suite.

## Adding a chat site

Site adapters live in `src/adapters/sites.js`. An adapter tells the extension where the message box and send button are.
If you add a site to the defaults, also add it to `host_permissions` and `content_scripts.matches` in `manifest.json`.

## Reporting false positives or misses

Open an issue with a **made-up** example that reproduces the problem. Please do not paste real credentials or personal data.

## Code style

- Plain JavaScript, no bundler, no runtime dependencies.
- Prettier and ESLint configs are in the repo; run `npm run format` before committing.
- Keep everything local: the extension must not make network requests except to a user-enabled localhost model.

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
