# Privacy Policy: Local LLM Privacy Guard

Last updated: 2026-10-12

## Summary

Privacy Guard scans text and files on your own device before you send them to an AI chat website.
It does not collect, store, sell or transmit your prompts, files or personal data.

## What the extension processes

- Text you type, paste or drop into the message box of supported AI chat sites, at the moment you send or paste it.
- Files you attach on those sites. Text files are read locally to look for secrets.

All of this happens inside your browser. Nothing is sent to the extension developer or any server.

## What the extension stores

- **Your settings**, in the browser's extension storage on this device.
- **Counts only** for the current browser session, such as how many items were redacted. No prompt text is ever stored.
- **Placeholder mappings** (for example `[EMAIL_1]` and the real value) are kept in the memory of the open tab only,
  so that "Show real values" can work. They disappear when the tab is closed or reloaded.

## Network access

The extension makes no network requests of its own, with one optional exception:
if you turn on **Local AI check**, the text being sent is passed to a model server on your own computer
(`localhost` or `127.0.0.1` only). Other addresses are rejected.

## Permissions

| Permission                           | Why                                     |
| ------------------------------------ | --------------------------------------- |
| Access to supported AI chat sites    | To scan what you send on those sites.   |
| `storage`                            | To save your settings on this device.   |
| `scripting` and optional site access | Only if you add another site yourself.  |
| `activeTab`                          | To show the current site in the popup.  |
| Optional `localhost` access          | Only if you turn on the local AI check. |

## Limitations

Detection is heuristic. It can miss sensitive data and cannot guarantee that nothing confidential reaches an AI service.

## Contact

Questions about this policy can be raised as an issue at
[github.com/fawad0x0/local-llm-privacy-guard](https://github.com/fawad0x0/local-llm-privacy-guard/issues).
The full source code is public, so you can verify these statements yourself.
