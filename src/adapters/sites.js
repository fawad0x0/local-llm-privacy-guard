/* Per-site adapters. Selectors are best-effort and should be re-checked when sites change their UI.
 * Every adapter falls back to generic editor/send-button detection when a selector stops matching. */
(() => {
  const PG = globalThis.PrivacyGuard;
  if (!PG || !PG.adapters || PG.adapters.list.length) return;
  const reg = PG.adapters.register;

  reg({
    id: "chatgpt",
    name: "ChatGPT",
    hosts: [/^(?:.+\.)?chatgpt\.com$/, /^chat\.openai\.com$/],
    editor: '#prompt-textarea, div.ProseMirror[contenteditable="true"], textarea[name="prompt-textarea"]',
    send: '[data-testid="send-button"], #composer-submit-button, button[aria-label="Send prompt"]'
  });
  reg({
    id: "claude",
    name: "Claude",
    hosts: [/^claude\.ai$/],
    editor: 'div.ProseMirror[contenteditable="true"], [data-testid="chat-input"] [contenteditable="true"]',
    send: 'button[aria-label="Send message"], button[aria-label="Send Message"], button[aria-label*="Send"]'
  });
  reg({
    id: "gemini",
    name: "Gemini",
    hosts: [/^gemini\.google\.com$/],
    editor: 'rich-textarea .ql-editor[contenteditable="true"], .ql-editor[contenteditable="true"]',
    send: 'button.send-button, button[aria-label*="Send message"], button[aria-label="Send"]'
  });
  reg({
    id: "copilot",
    name: "Microsoft Copilot",
    hosts: [/^copilot\.microsoft\.com$/],
    editor: "textarea#userInput, textarea[data-testid='composer-input'], textarea",
    send: '[data-testid="submit-button"], button[aria-label*="Submit"], button[title*="Submit"]'
  });
  reg({
    id: "perplexity",
    name: "Perplexity",
    hosts: [/^(?:www\.)?perplexity\.ai$/],
    editor: '#ask-input, [contenteditable="true"][role="textbox"], textarea',
    send: '[data-testid="submit-button"], button[aria-label="Submit"]'
  });
  reg({
    id: "deepseek",
    name: "DeepSeek",
    hosts: [/^chat\.deepseek\.com$/],
    editor: "textarea#chat-input, textarea"
  });
  reg({
    id: "mistral",
    name: "Mistral Le Chat",
    hosts: [/^chat\.mistral\.ai$/],
    editor: 'div.ProseMirror[contenteditable="true"], textarea',
    send: 'button[type="submit"], button[aria-label*="Send"]'
  });
  reg({
    id: "grok",
    name: "Grok",
    hosts: [/^grok\.com$/],
    editor: 'textarea, div.ProseMirror[contenteditable="true"]',
    send: 'button[type="submit"], button[aria-label="Submit"]'
  });
  reg({
    id: "poe",
    name: "Poe",
    hosts: [/^poe\.com$/],
    editor: 'textarea[class*="GrowingTextArea"], textarea',
    send: 'button[data-button-send], button[class*="sendButton"], button[aria-label="Send message"]'
  });
  reg({
    id: "meta",
    name: "Meta AI",
    hosts: [/^www\.meta\.ai$/],
    editor: '[contenteditable="true"][role="textbox"], textarea',
    send: '[aria-label="Send message"], [aria-label="Send"]'
  });
})();
