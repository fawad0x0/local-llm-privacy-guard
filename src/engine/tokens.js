/* Consistent placeholder tokens: the same value always maps to the same [LABEL_n] token. */
(() => {
  const PG = (globalThis.PrivacyGuard = globalThis.PrivacyGuard || {});
  if (PG.tokens) return;

  function createRegistry() {
    return { byKey: new Map(), byToken: new Map(), counts: Object.create(null) };
  }

  function assign(registry, label, value) {
    const key = label + "\u0000" + value;
    const existing = registry.byKey.get(key);
    if (existing) return existing;
    registry.counts[label] = (registry.counts[label] || 0) + 1;
    const token = `[${label}_${registry.counts[label]}]`;
    registry.byKey.set(key, token);
    registry.byToken.set(token, value);
    return token;
  }

  // Matches any token produced above.
  const TOKEN_RE = /\[[A-Z][A-Z0-9_]*_\d+\]/g;

  PG.tokens = { createRegistry, assign, TOKEN_RE };
})();
