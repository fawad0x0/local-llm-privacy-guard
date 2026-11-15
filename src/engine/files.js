/* File analysis for uploads, drops and pasted files. Reads files locally with File.text(). */
(() => {
  const PG = (globalThis.PrivacyGuard = globalThis.PrivacyGuard || {});
  if (PG.files) return;

  const MAX_SCAN_BYTES = 2 * 1024 * 1024;

  const TEXT_EXT =
    /\.(?:txt|log|out|err|md|markdown|csv|tsv|json|jsonc|json5|ya?ml|toml|ini|cfg|conf|config|properties|env|xml|html?|js|mjs|cjs|ts|tsx|jsx|py|rb|php|java|kt|kts|go|rs|c|h|cc|cpp|hpp|cs|swift|sh|bash|zsh|fish|ps1|psm1|bat|cmd|sql|tf|tfvars|tfstate|hcl|gradle|dockerfile|pem|key|crt|cer|pub|rst|tex|vue|svelte|scala|r|pl|lua|dart|gitignore|npmrc|pypirc|netrc|htpasswd|pgpass|cnf|har|ipynb|lock|plist|reg)$/i;
  const TEXT_NAMES =
    /^(?:\.env.*|dockerfile|makefile|readme|license|credentials|config|kubeconfig|\.?git-credentials|\.npmrc|\.pypirc|\.netrc|_netrc|\.htpasswd|\.pgpass|\.my\.cnf|id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|known_hosts|authorized_keys)$/i;
  const TEXT_MIME = /^text\/|json|xml|yaml|javascript|x-sh|toml|x-python|x-php|sql/i;

  // Files that are secrets by their very name. binary: not read at all. removeOnly: never uploaded as a sanitized stub.
  const BLOCKED = [
    { re: /^\.env(?:\.(?!example$|sample$|template$|dist$|defaults$)[\w.-]+)?$/i, reason: "Environment file (.env)" },
    { re: /^id_(?:rsa|dsa|ecdsa|ed25519)$/i, reason: "SSH private key", removeOnly: true },
    { re: /\.(?:pem|key|p8)$/i, reason: "Private key file", removeOnly: true },
    { re: /\.(?:p12|pfx|jks|keystore|ppk|kdbx)$/i, reason: "Keystore / key container", binary: true },
    { re: /^credentials(?:\.json|\.csv)?$/i, reason: "Credentials file" },
    { re: /\.tfstate(?:\.backup)?$|\.tfvars(?:\.json)?$/i, reason: "Terraform state / variables" },
    { re: /^kubeconfig(?:\.ya?ml)?$/i, reason: "Kubernetes config" },
    {
      re: /^(?:\.npmrc|\.pypirc|\.netrc|_netrc|\.git-credentials|\.htpasswd|\.pgpass|\.my\.cnf)$/i,
      reason: "Credential config file"
    },
    { re: /^(?:service[-_]?account|secrets?)[\w.-]*\.(?:json|ya?ml)$/i, reason: "Secrets / service-account file" },
    { re: /^wp-config\.php$/i, reason: "WordPress config (database password)" }
  ];

  function blockedReason(name) {
    const base = String(name).split(/[\\/]/).pop();
    return BLOCKED.find(b => b.re.test(base)) || null;
  }

  function isTextFile(file) {
    const base = String(file.name || "")
      .split(/[\\/]/)
      .pop();
    return TEXT_EXT.test(base) || TEXT_NAMES.test(base) || TEXT_MIME.test(file.type || "");
  }

  async function analyzeOne(file, scanOpts) {
    const entry = {
      file,
      name: file.name || "(unnamed file)",
      size: file.size,
      blocked: null,
      result: null,
      sanitizedFile: null,
      skipped: null,
      severity: null
    };
    const b = blockedReason(entry.name);
    if (b) entry.blocked = b.reason;

    if (!isTextFile(file) || (b && b.binary)) entry.skipped = "binary";
    else if (file.size > MAX_SCAN_BYTES) entry.skipped = "too large to scan";
    else {
      try {
        const text = await file.text();
        if (text.slice(0, 2000).includes("\u0000")) entry.skipped = "binary";
        else {
          entry.result = PG.scan(text, scanOpts);
          if (entry.result.findings.some(f => f.redact) && !(b && b.removeOnly)) {
            entry.sanitizedFile = new File([entry.result.text], entry.name, {
              type: file.type || "text/plain",
              lastModified: Date.now()
            });
          }
        }
      } catch {
        entry.skipped = "could not be read";
      }
    }

    const sev = [];
    if (entry.blocked) {
      // A blocked text file that turned out clean is a review, not a hard block.
      const clean = entry.result && entry.result.findings.length === 0;
      sev.push(clean ? "high" : "critical");
    }
    if (entry.result && entry.result.maxSeverity) sev.push(entry.result.maxSeverity);
    if (entry.skipped && scanOpts && scanOpts.settings && scanOpts.settings.strictMode) sev.push("high");
    entry.severity = PG.maxSeverity(sev);
    entry.flagged = !!entry.severity;
    return entry;
  }

  async function analyze(files, scanOpts) {
    const list = [];
    for (const f of files) list.push(await analyzeOne(f, scanOpts));
    return list;
  }

  // Strongest policy action needed for a set of analyzed files.
  function actionFor(entries, policy) {
    const order = { off: 0, note: 1, review: 2, block: 3 };
    let best = "off";
    for (const e of entries) {
      if (!e.severity) continue;
      const a = (policy && policy[e.severity]) || "review";
      if (order[a] > order[best]) best = a;
    }
    return best;
  }

  PG.files = { analyze, actionFor, blockedReason, isTextFile, MAX_SCAN_BYTES };
})();
