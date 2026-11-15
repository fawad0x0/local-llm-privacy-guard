/* Background: dynamic content scripts for user-added sites, local-AI proxy (localhost only), session counters.
 * Chrome runs this as a service worker, Firefox as an event page. */
if (typeof importScripts === "function" && !(globalThis.PrivacyGuard && globalThis.PrivacyGuard.Settings)) {
  importScripts("src/settings.js");
}

const api = globalThis.browser ?? globalThis.chrome;
const PGS = globalThis.PrivacyGuard.Settings;

const CONTENT_JS = [
  "src/settings.js",
  "src/engine/validators.js",
  "src/rules/pii.js",
  "src/rules/credentials.js",
  "src/rules/config.js",
  "src/rules/env.js",
  "src/rules/logs.js",
  "src/rules/network.js",
  "src/engine/classify.js",
  "src/engine/tokens.js",
  "src/engine/scan.js",
  "src/engine/files.js",
  "src/adapters/base.js",
  "src/adapters/sites.js",
  "src/ui/panel.js",
  "src/content.js"
];
const CUSTOM_ID = "pg-custom-sites";

// ---------- Custom sites ----------
async function syncCustomSites() {
  if (!api.scripting || !api.scripting.registerContentScripts) return;
  const { settings } = await PGS.load(api);
  try {
    await api.scripting.unregisterContentScripts({ ids: [CUSTOM_ID] });
  } catch {
    /* not registered yet */
  }
  const matches = [];
  for (const h of settings.customSites) {
    const origin = `*://${h}/*`;
    try {
      if (await api.permissions.contains({ origins: [origin] })) matches.push(origin);
    } catch {
      /* invalid host pattern */
    }
  }
  if (!matches.length) return;
  const script = { id: CUSTOM_ID, matches, js: CONTENT_JS, runAt: "document_start", allFrames: true };
  try {
    await api.scripting.registerContentScripts([{ ...script, persistAcrossSessions: true }]);
  } catch {
    await api.scripting.registerContentScripts([script]);
  }
}

api.runtime.onInstalled.addListener(() => syncCustomSites().catch(() => {}));
if (api.runtime.onStartup) api.runtime.onStartup.addListener(() => syncCustomSites().catch(() => {}));
api.permissions.onAdded.addListener(() => syncCustomSites().catch(() => {}));
api.permissions.onRemoved.addListener(() => syncCustomSites().catch(() => {}));
api.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.settings) {
    const before = JSON.stringify((changes.settings.oldValue || {}).customSites || []);
    const after = JSON.stringify((changes.settings.newValue || {}).customSites || []);
    if (before !== after) syncCustomSites().catch(() => {});
  }
});

// ---------- Session statistics (counts only, never content) ----------
async function count(msg) {
  const store = api.storage.session || api.storage.local;
  const key = "pgStats";
  const cur = (await store.get(key))[key] || { items: 0, events: {}, byHost: {} };
  cur.items += Number(msg.items) || 0;
  cur.events[msg.action] = (cur.events[msg.action] || 0) + 1;
  cur.byHost[msg.host] = (cur.byHost[msg.host] || 0) + (Number(msg.items) || 0);
  await store.set({ [key]: cur });
}

// ---------- Local AI (Ollama-compatible), localhost only ----------
function isLocalEndpoint(url) {
  try {
    const u = new URL(url);
    return (
      (u.protocol === "http:" || u.protocol === "https:") && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname)
    );
  } catch {
    return false;
  }
}

const AI_TYPES = new Set(["PERSON", "ORG", "ADDRESS", "CONFIDENTIAL"]);

async function aiDetect(text, cfg) {
  if (!isLocalEndpoint(cfg.endpoint)) return { ok: false, error: "endpoint must be on localhost" };
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), cfg.timeoutMs || 8000);
  const sample = String(text).slice(0, 8000);
  const prompt =
    "You are a data-loss-prevention detector. Find sensitive entities in TEXT that regular expressions miss: " +
    "person names, organization or customer names, physical addresses, and confidential business information " +
    "(unreleased products, internal project names, non-public financial figures). " +
    'Answer with JSON only: {"entities":[{"type":"PERSON|ORG|ADDRESS|CONFIDENTIAL","text":"exact substring of TEXT"}]}. ' +
    'Copy each "text" exactly as it appears. If nothing is sensitive answer {"entities":[]}.\n\nTEXT:\n"""\n' +
    sample +
    '\n"""';
  try {
    const res = await fetch(cfg.endpoint.replace(/\/+$/, "") + "/api/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model: cfg.model, prompt, stream: false, format: "json", options: { temperature: 0 } }),
      signal: ctrl.signal
    });
    if (!res.ok) return { ok: false, error: `model server returned HTTP ${res.status}` };
    const data = await res.json();
    let parsed;
    try {
      parsed = JSON.parse(data.response || "{}");
    } catch {
      return { ok: false, error: "model did not return JSON" };
    }
    const entities = (Array.isArray(parsed.entities) ? parsed.entities : [])
      .filter(
        e => e && typeof e.text === "string" && e.text.length >= 2 && e.text.length <= 200 && sample.includes(e.text)
      )
      .map(e => ({
        type: AI_TYPES.has(String(e.type).toUpperCase()) ? String(e.type).toUpperCase() : "SENSITIVE",
        text: e.text
      }));
    return { ok: true, entities };
  } catch (e) {
    return { ok: false, error: e && e.name === "AbortError" ? "timed out" : "model server not reachable" };
  } finally {
    clearTimeout(timer);
  }
}

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || typeof msg.type !== "string") return false;
  if (msg.type === "pg:count") {
    count(msg).catch(() => {});
    return false;
  }
  if (msg.type === "pg:ai" || msg.type === "pg:ai-test") {
    PGS.load(api)
      .then(({ settings }) => {
        const cfg = msg.type === "pg:ai-test" && msg.config ? { ...settings.localAi, ...msg.config } : settings.localAi;
        if (msg.type === "pg:ai" && !cfg.enabled) return { ok: false };
        return aiDetect(
          msg.type === "pg:ai-test"
            ? "Contact Jane Doe at Acme Corp, 221B Baker Street, about Project Falcon."
            : msg.text,
          cfg
        );
      })
      .then(sendResponse, () => sendResponse({ ok: false, error: "internal error" }));
    return true; // async response
  }
  return false;
});
