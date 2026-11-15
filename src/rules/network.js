/* Network identifiers: IP addresses, MAC addresses, internal hostnames. */
(() => {
  const PG = (globalThis.PrivacyGuard = globalThis.PrivacyGuard || {});
  const V = PG.validators;
  const R = (PG.rules = PG.rules || []);
  if (R.some(r => r.id === "ipv4")) return;

  R.push(
    {
      id: "ipv4",
      label: "IP",
      category: "network",
      severity: "medium",
      reason: "IP address",
      placeholder: "none",
      re: /(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w]|\.\d)/g,
      validate(v, info) {
        if (!V.ipv4(v)) return false;
        const kind = V.ipv4Kind(v);
        if (kind === "loopback" || kind === "unspecified" || kind === "broadcast") return false;
        if (/(?:\bv|version|ver\.?|release|build|rev)\s*:?\s*$/i.test(info.ctx.before(info.start, 14))) return false;
        return { reason: kind === "public" ? "Public IP address" : "Private / internal IP address" };
      }
    },
    {
      id: "ipv6",
      label: "IP",
      category: "network",
      severity: "medium",
      reason: "IPv6 address",
      placeholder: "none",
      re: /(?<![\w:.])[0-9A-Fa-f:]{2,39}(?![\w:])/g,
      validate(v) {
        if ((v.match(/:/g) || []).length < 2) return false;
        if (!/[a-fA-F]/.test(v) && !v.includes("::")) return false;
        if (v === "::" || v === "::1") return false;
        return V.ipv6(v);
      }
    },
    {
      id: "mac",
      label: "MAC",
      category: "network",
      severity: "low",
      reason: "MAC address",
      placeholder: "none",
      re: /(?<![\w:-])[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![\w:-])/g,
      validate: v => !/^(?:00[:-]){5}00$/i.test(v) && !/^(?:ff[:-]){5}ff$/i.test(v)
    },
    {
      id: "internal_host",
      label: "HOST",
      category: "network",
      severity: "medium",
      reason: "Internal hostname",
      placeholder: "none",
      re: /(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:internal|local|lan|intranet|corp|localdomain|home\.arpa|private)(?![\w-]|\.[a-z])/gi
    }
  );
})();
