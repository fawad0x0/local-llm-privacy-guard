/* Detection pipeline: classify -> run rules -> validate -> resolve overlaps -> tokenize -> replace. */
(() => {
  const PG = (globalThis.PrivacyGuard = globalThis.PrivacyGuard || {});
  if (PG.scan) return;
  const V = PG.validators;

  const RANK = { critical: 4, high: 3, medium: 2, low: 1 };
  const ACTION_RANK = { off: 0, note: 1, review: 2, block: 3 };
  const severityRank = s => RANK[s] || 0;
  const maxSeverity = list => list.reduce((best, s) => (severityRank(s) > severityRank(best) ? s : best), null);

  const escapeRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const safeLabel = s =>
    String(s || "CUSTOM")
      .toUpperCase()
      .replace(/[^A-Z0-9]+/g, "_")
      .replace(/^_+|_+$/g, "")
      .slice(0, 30) || "CUSTOM";

  function withFlags(re, extra) {
    const flags = new Set(re.flags.split(""));
    for (const f of extra) flags.add(f);
    flags.delete("y");
    return new RegExp(re.source, [...flags].join(""));
  }

  let cache = { key: null, rules: null };

  function compileRules(settings) {
    const s = settings || PG.Settings.DEFAULTS;
    const key = JSON.stringify([s.packs, s.customRules, s.dictionary, s.internalDomains, PG.rules.length]);
    if (cache.key === key) return cache.rules;

    const out = [];
    const add = r => out.push({ ...r, re: r.re ? withFlags(r.re, "gd") : null, priority: out.length });

    for (const r of PG.rules) {
      if (r.pack && !(s.packs || {})[r.pack]) continue;
      add(r);
    }
    for (const c of s.customRules || []) {
      try {
        const flags = String(c.flags || "gi").replace(/[^gimsuv]/g, "");
        add({
          id: "custom:" + safeLabel(c.label),
          label: safeLabel(c.label),
          category: "custom",
          severity: RANK[c.severity] ? c.severity : "high",
          reason: `Custom rule: ${c.label || "unnamed"}`,
          placeholder: "none",
          re: new RegExp(c.pattern, flags)
        });
      } catch {
        /* invalid user regex: ignored here, reported by the options page */
      }
    }
    const terms = (s.dictionary || []).filter(t => t.length >= 2);
    if (terms.length) {
      add({
        id: "dictionary",
        label: "CONFIDENTIAL",
        category: "custom",
        severity: "high",
        reason: "Term from your confidential dictionary",
        placeholder: "none",
        re: new RegExp(
          `(?<![\\w])(?:${terms
            .map(escapeRe)
            .sort((a, b) => b.length - a.length)
            .join("|")})(?![\\w])`,
          "gi"
        )
      });
    }
    const domains = (s.internalDomains || []).filter(Boolean);
    if (domains.length) {
      add({
        id: "internal_domain",
        label: "HOST",
        category: "network",
        severity: "medium",
        reason: "Internal company domain",
        placeholder: "none",
        re: new RegExp(`(?<![\\w.-])(?:[a-z0-9-]+\\.)*(?:${domains.map(escapeRe).join("|")})(?![\\w-])`, "gi")
      });
    }
    cache = { key, rules: out };
    return out;
  }

  // Remove surrounding quotes/whitespace from a span so tokens replace only the secret itself.
  function trimSpan(text, s, e) {
    while (s < e && /\s/.test(text[s])) s++;
    while (e > s && /\s/.test(text[e - 1])) e--;
    if (e - s >= 2 && /["'`]/.test(text[s]) && text[e - 1] === text[s]) {
      s++;
      e--;
    }
    return [s, e];
  }

  function scan(input, opts = {}) {
    const text = String(input ?? "");
    const settings = opts.settings || PG.Settings.DEFAULTS;
    const registry = opts.registry || PG.tokens.createRegistry();
    const categories = settings.categories || {};
    const blocks = PG.classify(text);
    const blockSet = new Set(blocks.map(b => b.id));
    const ctx = {
      text,
      blocks: blockSet,
      before: (i, n) => text.slice(Math.max(0, i - n), i),
      after: (i, n) => text.slice(i, i + n)
    };
    const allow = new Set((settings.allowlist || []).map(x => String(x).trim().toLowerCase()).filter(Boolean));
    const cands = [];

    function add(rule, s0, e0, m) {
      const [s, e] = trimSpan(text, s0, e0);
      if (e <= s) return;
      const value = text.slice(s, e);
      const info = { value, start: s, end: e, match: m, groups: (m && m.groups) || {}, ctx };
      let over = null;
      if (rule.validate) {
        const r = rule.validate(value, info);
        if (!r) return;
        if (typeof r === "object") over = r;
      }
      const mode = (over && over.placeholder) || rule.placeholder || "provider";
      if (mode === "strict" && V.isPlaceholder(value)) return;
      if (mode === "provider" && V.isProviderPlaceholder(value)) return;
      if (allow.has(value.toLowerCase())) return;
      const cand = {
        ruleId: rule.id,
        label: (over && over.label) || rule.label,
        category: (over && over.category) || rule.category,
        severity: (over && over.severity) || rule.severity,
        reason: (over && over.reason) || rule.reason,
        start: s,
        end: e,
        value,
        redact: ((over && over.defaultRedact) ?? rule.defaultRedact) !== false,
        priority: rule.priority
      };
      if (categories[cand.category] === false) return;
      cands.push(cand);
    }

    for (const rule of compileRules(settings)) {
      if (rule.when && !rule.when(ctx)) continue;
      if (rule.find) {
        for (const c of rule.find(text, ctx)) add(rule, c.start, c.end, null);
        continue;
      }
      for (const m of text.matchAll(rule.re)) {
        if (!m[0]) continue;
        const g = m.indices && m.indices.groups && m.indices.groups.v;
        if (g) add(rule, g[0], g[1], m);
        else add(rule, m.index, m.index + m[0].length, m);
      }
    }

    // Extra findings from the optional local AI layer: exact substrings.
    if (categories.ai !== false) {
      for (const x of opts.extra || []) {
        const needle = String(x.value || "");
        if (needle.length < 2 || allow.has(needle.toLowerCase())) continue;
        let i = text.indexOf(needle);
        while (i !== -1) {
          cands.push({
            ruleId: "local_ai",
            label: safeLabel(x.label || "SENSITIVE"),
            category: "ai",
            severity: RANK[x.severity] ? x.severity : "medium",
            reason: x.reason || "Flagged by local AI model",
            start: i,
            end: i + needle.length,
            value: needle,
            redact: true,
            priority: 1e6
          });
          i = text.indexOf(needle, i + needle.length);
        }
      }
    }

    // Overlap resolution: most severe first, then longest, then rule order.
    cands.sort(
      (a, b) =>
        severityRank(b.severity) - severityRank(a.severity) ||
        b.end - b.start - (a.end - a.start) ||
        a.priority - b.priority
    );
    const taken = new Uint8Array(text.length);
    const chosen = [];
    outer: for (const c of cands) {
      for (let i = c.start; i < c.end; i++) if (taken[i]) continue outer;
      taken.fill(1, c.start, c.end);
      chosen.push(c);
    }
    chosen.sort((a, b) => a.start - b.start);

    const findings = chosen.map((c, id) => {
      const { priority: _priority, ...rest } = c;
      return { id, ...rest, token: PG.tokens.assign(registry, c.label, c.value) };
    });

    const blockList = blocks.map(b => ({ ...b, active: !!b.severity && (b.alwaysWarn || findings.length > 0) }));
    const sev = maxSeverity([
      ...findings.map(f => f.severity),
      ...blockList.filter(b => b.active).map(b => b.severity)
    ]);

    return {
      original: text,
      text: applyRedactions(text, findings, f => f.redact),
      findings,
      blocks: blockList,
      maxSeverity: sev,
      registry
    };
  }

  function applyRedactions(text, findings, pick) {
    let out = "";
    let last = 0;
    for (const f of findings) {
      if (!pick(f)) continue;
      out += text.slice(last, f.start) + f.token;
      last = f.end;
    }
    return out + text.slice(last);
  }

  // Strongest policy action required by a scan result (or by a set of kept findings).
  function actionFor(result, policy, findings = result.findings) {
    let best = "off";
    const consider = sev => {
      const a = (policy && policy[sev]) || "review";
      if (ACTION_RANK[a] > ACTION_RANK[best]) best = a;
    };
    for (const f of findings) consider(f.severity);
    for (const b of result.blocks || []) if (b.active) consider(b.severity);
    return best;
  }

  PG.scan = scan;
  PG.applyRedactions = applyRedactions;
  PG.actionFor = actionFor;
  PG.severityRank = severityRank;
  PG.maxSeverity = maxSeverity;
  PG.compileRules = compileRules;

  // Backward-compatible API from v0.1.
  globalThis.LocalPrivacySanitizer = {
    sanitize(input, opts) {
      const r = scan(input, opts);
      return {
        text: r.text,
        findings: r.findings.filter(f => f.redact).map(f => ({ type: f.label, replacement: f.token }))
      };
    }
  };
})();
