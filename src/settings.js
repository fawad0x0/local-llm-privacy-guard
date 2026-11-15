/* Shared settings model. Loaded by content scripts, popup, options page and background. */
(() => {
  const PG = (globalThis.PrivacyGuard = globalThis.PrivacyGuard || {});
  if (PG.Settings) return;

  const DEFAULTS = Object.freeze({
    version: 2,
    enabled: true,
    reviewAll: false,
    strictMode: false,
    scanPaste: true,
    scanFiles: true,
    showBadge: true,
    // Action per severity: block | review | note | off
    policy: { critical: "block", high: "review", medium: "review", low: "note" },
    categories: {
      pii: true,
      credential: true,
      cloud_secret: true,
      env: true,
      config: true,
      log: true,
      network: true,
      custom: true,
      ai: true
    },
    // Country-specific identifier packs
    packs: { pk: true, us: true, uk: false, in: false, ae: false },
    customRules: [], // [{ label, severity, pattern, flags }]
    dictionary: [], // confidential terms: client names, codenames
    internalDomains: [], // e.g. "mycompany.com"
    allowlist: [], // exact values never flagged
    disabledSites: [], // hostnames where protection is off
    customSites: [], // extra hostnames the user granted access to
    localAi: { enabled: false, endpoint: "http://localhost:11434", model: "llama3.2", timeoutMs: 8000 }
  });

  const SEVERITIES = ["critical", "high", "medium", "low"];
  const ACTIONS = ["block", "review", "note", "off"];

  function isPlainObject(v) {
    return v !== null && typeof v === "object" && !Array.isArray(v);
  }

  function clone(v) {
    return JSON.parse(JSON.stringify(v));
  }

  // Deep merge for plain objects. Arrays and primitives from `over` replace `base`.
  function merge(base, over) {
    const out = clone(base);
    if (!isPlainObject(over)) return out;
    for (const [k, v] of Object.entries(over)) {
      if (v === undefined) continue;
      if (isPlainObject(v) && isPlainObject(out[k])) out[k] = merge(out[k], v);
      else out[k] = clone(v);
    }
    return out;
  }

  // Keep only known keys with sane types so bad storage data cannot break scanning.
  function normalize(s) {
    const out = merge(DEFAULTS, s);
    for (const sev of SEVERITIES) if (!ACTIONS.includes(out.policy[sev])) out.policy[sev] = DEFAULTS.policy[sev];
    for (const key of ["customRules", "dictionary", "internalDomains", "allowlist", "disabledSites", "customSites"]) {
      if (!Array.isArray(out[key])) out[key] = [];
    }
    out.dictionary = out.dictionary
      .map(String)
      .map(x => x.trim())
      .filter(Boolean);
    out.internalDomains = out.internalDomains
      .map(x => String(x).trim().toLowerCase().replace(/^\*\./, ""))
      .filter(Boolean);
    out.allowlist = out.allowlist
      .map(String)
      .map(x => x.trim())
      .filter(Boolean);
    out.customRules = out.customRules.filter(r => r && typeof r.pattern === "string" && r.pattern);
    out.localAi.timeoutMs = Math.min(Math.max(Number(out.localAi.timeoutMs) || 8000, 1000), 60000);
    return out;
  }

  function api() {
    return globalThis.browser ?? globalThis.chrome;
  }

  // Migrates the v0.1 flat keys { enabled, review } into the v2 settings object.
  function migrate(local) {
    if (local.settings) return local.settings;
    const s = {};
    if (typeof local.enabled === "boolean") s.enabled = local.enabled;
    if (typeof local.review === "boolean") s.reviewAll = local.review;
    return s;
  }

  // Chrome never resolves storage.managed.get() in some contexts (seen in content scripts),
  // so managed policy is read with a timeout and can never block local settings.
  let managedCache = null;
  async function readManaged(a) {
    if (managedCache) return managedCache;
    try {
      if (!a.storage.managed) return {};
      const m = await Promise.race([
        a.storage.managed.get(null),
        new Promise(resolve => setTimeout(() => resolve(null), 500))
      ]);
      if (m === null) return {}; // timed out: retry on the next load
      managedCache = m || {};
      return managedCache;
    } catch {
      return {}; // No policy installed (normal for personal installs).
    }
  }

  // opts.managed === false skips organization policy (used for a fast first render).
  async function load(a = api(), opts = {}) {
    let local = {};
    try {
      local = (await a.storage.local.get(null)) || {};
    } catch {
      local = {};
    }
    const managedRaw = opts.managed === false ? managedCache || {} : await readManaged(a);
    const { locked, ...managedSettings } = managedRaw;
    const settings = normalize(merge(merge(DEFAULTS, migrate(local)), managedSettings));
    return {
      settings,
      managed: { locked: locked === true, keys: Object.keys(managedSettings) }
    };
  }

  async function save(settings, a = api()) {
    await a.storage.local.set({ settings: normalize(settings) });
  }

  PG.Settings = { DEFAULTS, SEVERITIES, ACTIONS, merge, normalize, load, save, api };
})();
