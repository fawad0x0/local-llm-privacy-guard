# Security Policy

## Supported versions

Only the latest release on the `main` branch receives security fixes.

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report privately through GitHub:
**[Security → Report a vulnerability](https://github.com/fawad0x0/local-llm-privacy-guard/security/advisories/new)**.

Useful things to include:

- What the problem is and its impact (for example, data leaving the browser, a bypass of the send check, or a ReDoS pattern).
- Steps to reproduce, using made-up data only.
- Browser and extension version.

You should get a response within a few days. Once a fix is released, you will be credited unless you ask not to be.

## Scope

In scope:

- Any path where scanned text or files are sent anywhere other than a user-enabled `localhost` model.
- Ways for a web page to read placeholder mappings, settings, or the review panel's contents.
- Bypasses where a message is sent without being scanned on a supported site.
- Regular expressions with catastrophic backtracking.

Out of scope: secrets or personal data that the heuristics simply do not recognize. Please report those as normal issues.
