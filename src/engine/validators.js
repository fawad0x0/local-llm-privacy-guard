/* Validators and helpers used by detection rules. Pure functions, no DOM, no network. */
(() => {
  const PG = (globalThis.PrivacyGuard = globalThis.PrivacyGuard || {});
  if (PG.validators) return;

  function digits(s) {
    return String(s).replace(/\D/g, "");
  }

  function luhn(value) {
    const d = digits(value);
    if (d.length < 13 || d.length > 19) return false;
    let sum = 0;
    let alt = false;
    for (let i = d.length - 1; i >= 0; i--) {
      let n = d.charCodeAt(i) - 48;
      if (alt) {
        n *= 2;
        if (n > 9) n -= 9;
      }
      sum += n;
      alt = !alt;
    }
    return sum % 10 === 0;
  }

  function iban(value) {
    const s = String(value).replace(/\s+/g, "").toUpperCase();
    if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(s)) return false;
    const rearranged = s.slice(4) + s.slice(0, 4);
    let rem = 0;
    for (const ch of rearranged) {
      const code = ch >= "A" && ch <= "Z" ? String(ch.charCodeAt(0) - 55) : ch;
      for (const c of code) rem = (rem * 10 + (c.charCodeAt(0) - 48)) % 97;
    }
    return rem === 1;
  }

  function ipv4(value) {
    const parts = String(value).split(".");
    return parts.length === 4 && parts.every(p => /^\d{1,3}$/.test(p) && Number(p) <= 255 && String(Number(p)) === p);
  }

  function ipv4Kind(value) {
    const [a, b] = value.split(".").map(Number);
    if (a === 127) return "loopback";
    if (value === "0.0.0.0") return "unspecified";
    if (value === "255.255.255.255") return "broadcast";
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return "private";
    if (a === 169 && b === 254) return "link-local";
    if (a === 100 && b >= 64 && b <= 127) return "cgnat";
    return "public";
  }

  function ipv6(value) {
    if (!/:/.test(value) || (value.match(/:/g) || []).length < 2) return false;
    try {
      new URL(`http://[${value}]/`);
      return true;
    } catch {
      return false;
    }
  }

  function entropy(s) {
    if (!s) return 0;
    const counts = new Map();
    for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
    let h = 0;
    for (const n of counts.values()) {
      const p = n / s.length;
      h -= p * Math.log2(p);
    }
    return h;
  }

  function stripQuotes(v) {
    let s = String(v).trim();
    if (s.length >= 2 && /^["'`]/.test(s) && s[s.length - 1] === s[0]) s = s.slice(1, -1);
    return s.trim();
  }

  const PLACEHOLDER_WORDS =
    /^(?:secret|password|passwd|pass|pwd|token|key|apikey|api_key|value|none|null|nil|undefined|true|false|yes|no|on|off|empty|n\/a|na|tbd|required|optional|string|str|int|number|bool|boolean|object|any|test|demo|bearer|basic|digest|default|hidden|masked|redacted|unset|todo|fixme|\.\.\.|…)$/i;
  const PLACEHOLDER_PARTS =
    /(?:\b|_|-)(?:your|my)[_\-\s]?(?:api|secret|key|token|pass|password|own)|^(?:your|my)[_-]|[_-]here$|change[_\-]?me|placeholder|example|sample|dummy|redacted|replace[_\-]?(?:me|this|with)|insert[_\-]|enter[_\-]?your|xxxx|\*\*\*|•••|<[^>]*>|\{\{[^}]*\}\}|\$\{[^}]*\}/i;
  const CODE_REF =
    /(?:process\.env|import\.meta\.env|os\.environ|os\.getenv|getenv\(|System\.getenv|ENV\[|env\(|config\(|settings\.|secrets\.|vault:|ssm:|keyvault|Deno\.env)/i;

  // True when a value is obviously not a real secret (template, variable reference, our own token...).
  function isPlaceholder(value) {
    const v = stripQuotes(value);
    if (!v) return true;
    if (/^\[[A-Z][A-Z0-9_]*_\d+\]$/.test(v)) return true; // Privacy Guard token
    if (/^[<{[(].*[>}\])]$/.test(v)) return true; // <TOKEN>, {{x}}, [x], (x)
    if (/^\$\{?[A-Za-z_]\w*\}?$/.test(v) || /^%[A-Za-z_]\w*%$/.test(v)) return true; // $VAR ${VAR} %VAR%
    if (/^(.)\1*$/.test(v)) return true; // xxxx, ****, 0000
    if (PLACEHOLDER_WORDS.test(v)) return true;
    if (PLACEHOLDER_PARTS.test(v)) return true;
    if (CODE_REF.test(v)) return true;
    // req.body.password, config.db.pass: dotted identifiers whose parts read like names, not random tokens
    if (
      /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+(?:\(\))?$/.test(v) &&
      v.split(".").every(p => !(p.length >= 8 && /\d/.test(p) && /[A-Z]/.test(p) && /[a-z]/.test(p)))
    )
      return true;
    if (/^[\w$.]+\(/.test(v)) return true; // getPassword(
    if (/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(v)) return true; // API_KEY (reference to another var)
    return false;
  }

  // Lighter check for provider-shaped keys (AKIA..., sk-...).
  function isProviderPlaceholder(value) {
    const v = stripQuotes(value);
    if (!v) return true;
    if (/^(.)\1*$/.test(v)) return true;
    return /example|sample|dummy|placeholder|your[_-]|xxxxx|0{10,}|redacted/i.test(v);
  }

  function looksLikePath(value) {
    const v = stripQuotes(value);
    return /^(?:\.{0,2}\/|~\/|[A-Za-z]:[\\/]|\\\\)/.test(v) && !/\s/.test(v);
  }

  // Heuristic: does a value look like a machine-generated secret?
  function secretLike(value, minLen = 8) {
    const v = stripQuotes(value);
    if (v.length < minLen || /\s/.test(v)) return false;
    if (isPlaceholder(v) || looksLikePath(v)) return false;
    if (/^\d+$/.test(v) && v.length < 12) return false;
    const hasDigit = /\d/.test(v);
    const hasUpper = /[A-Z]/.test(v);
    const hasLower = /[a-z]/.test(v);
    const hasSymbol = /[^A-Za-z0-9]/.test(v);
    if (hasDigit && (hasUpper || hasLower)) return true;
    if (hasUpper && hasLower && v.length >= 12) return true;
    if (hasSymbol && (hasUpper || hasLower) && v.length >= 10) return true;
    return entropy(v) >= 3.2;
  }

  // ---- Key-name classification for assignments (KEY=value, key: value, <key>value</key>) ----
  function keyParts(k) {
    return String(k)
      .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
      .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter(Boolean);
  }

  const PASSWORD = new Set(["password", "passwd", "pass", "pwd", "passphrase", "passcode", "pswd"]);
  const TOKEN = new Set([
    "token",
    "tokens",
    "authtoken",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "bearer",
    "jwt",
    "pat"
  ]);
  const SECRET = new Set([
    "secret",
    "secrets",
    "clientsecret",
    "privatekey",
    "secretkey",
    "salt",
    "pepper",
    "credential",
    "credentials",
    "creds",
    "signingkey",
    "encryptionkey",
    "masterkey"
  ]);
  const SESSION = new Set([
    "cookie",
    "cookies",
    "session",
    "sessionid",
    "sid",
    "jsessionid",
    "phpsessid",
    "csrf",
    "xsrf",
    "csrftoken",
    "xsrftoken"
  ]);
  const APIKEY = new Set([
    "apikey",
    "accesskey",
    "appkey",
    "authkey",
    "clientkey",
    "serverkey",
    "licensekey",
    "privkey",
    "subscriptionkey"
  ]);
  const KEYQUAL = new Set([
    "api",
    "access",
    "private",
    "secret",
    "signing",
    "encryption",
    "encrypt",
    "master",
    "license",
    "licence",
    "app",
    "client",
    "service",
    "account",
    "ssh",
    "gpg",
    "pgp",
    "aes",
    "hmac",
    "jwt",
    "consumer",
    "subscription",
    "admin",
    "auth",
    "server",
    "session",
    "storage",
    "openai",
    "anthropic",
    "stripe",
    "google",
    "aws",
    "azure",
    "gcp",
    "github",
    "slack",
    "twilio",
    "sendgrid",
    "mailgun",
    "firebase",
    "supabase",
    "algolia",
    "mapbox",
    "webhook",
    "deploy",
    "root",
    "shared",
    "sas",
    "x"
  ]);
  const URLISH_SUFFIX = new Set([
    "url",
    "uri",
    "dsn",
    "connstr",
    "connectionstring",
    "conn",
    "connection",
    "connstring",
    "dburl"
  ]);
  const URLISH_PREFIX = new Set([
    "database",
    "db",
    "redis",
    "mongo",
    "mongodb",
    "postgres",
    "postgresql",
    "pg",
    "mysql",
    "mariadb",
    "mssql",
    "sql",
    "amqp",
    "rabbitmq",
    "broker",
    "sentry",
    "celery",
    "cache",
    "elastic",
    "elasticsearch",
    "kafka",
    "jdbc",
    "datasource"
  ]);
  const BENIGN_LAST = new Set([
    "length",
    "len",
    "min",
    "max",
    "limit",
    "policy",
    "required",
    "field",
    "fields",
    "label",
    "placeholder",
    "type",
    "name",
    "names",
    "hint",
    "prompt",
    "reset",
    "expiry",
    "expires",
    "expiration",
    "ttl",
    "timeout",
    "enabled",
    "enable",
    "disabled",
    "header",
    "headers",
    "param",
    "params",
    "path",
    "file",
    "filename",
    "dir",
    "url",
    "count",
    "size",
    "format",
    "regex",
    "pattern",
    "rule",
    "rules",
    "algorithm",
    "algo",
    "mode",
    "strength",
    "id",
    "ids",
    "version",
    "provider",
    "endpoint",
    "host",
    "port",
    "user",
    "username",
    "email",
    "lifetime",
    "duration",
    "age",
    "attempts",
    "rotation",
    "store",
    "location",
    "env",
    "var",
    "variable"
  ]);

  // Returns { label, kind } for keys whose values are secrets, or null.
  function classifyKey(key) {
    const parts = keyParts(key);
    if (!parts.length) return null;
    const joined = parts.join("");
    const last = parts[parts.length - 1];
    const prefixParts = parts.slice(0, -1);

    if (
      joined.includes("connectionstring") ||
      last === "dsn" ||
      (URLISH_SUFFIX.has(last) && prefixParts.some(p => URLISH_PREFIX.has(p)))
    ) {
      return { label: "CONNECTION_STRING", kind: "url" };
    }
    if (parts.length > 1 && BENIGN_LAST.has(last)) return null;
    if (parts.some(p => PASSWORD.has(p)) || joined.includes("password") || joined.includes("passwd")) {
      return { label: "PASSWORD", kind: "password" };
    }
    if (parts.some(p => SECRET.has(p)) || joined.includes("secret")) return { label: "SECRET", kind: "secret" };
    if (parts.some(p => TOKEN.has(p)) || /tokens?$/.test(joined)) return { label: "TOKEN", kind: "secret" };
    if (
      parts.some(p => APIKEY.has(p)) ||
      joined.includes("apikey") ||
      (parts.includes("key") && (parts.length === 1 || parts.some(p => KEYQUAL.has(p))))
    ) {
      return { label: "API_KEY", kind: "secret" };
    }
    if (parts.some(p => SESSION.has(p))) return { label: "SESSION", kind: "secret" };
    if (parts.includes("auth") || parts.includes("authorization")) return { label: "TOKEN", kind: "secret" };
    if (parts.includes("webhook") || parts.includes("hook")) return { label: "WEBHOOK", kind: "urlsecret" };
    if (parts.includes("pin") || parts.includes("cvv") || parts.includes("cvc")) return { label: "PIN", kind: "pin" };
    return null;
  }

  // 32-bit FNV-1a, used to remember "send this exact text once".
  function hash(str) {
    let h = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 0x01000193);
    }
    return (h >>> 0).toString(16) + ":" + str.length;
  }

  PG.validators = {
    digits,
    luhn,
    iban,
    ipv4,
    ipv4Kind,
    ipv6,
    entropy,
    stripQuotes,
    isPlaceholder,
    isProviderPlaceholder,
    looksLikePath,
    secretLike,
    keyParts,
    classifyKey,
    hash
  };
})();
