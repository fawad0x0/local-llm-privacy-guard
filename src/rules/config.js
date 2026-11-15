/* Configuration files: KEY=value, key: value, XML, PHP, Kubernetes secrets, CLI flags. */
(() => {
  const PG = (globalThis.PrivacyGuard = globalThis.PrivacyGuard || {});
  const V = PG.validators;
  const R = (PG.rules = PG.rules || []);
  if (R.some(r => r.id === "assign_equals")) return;

  const CODE_LINE = /^\s*(?:const|let|var|val|final|private|public|protected|static|def|self\.|this\.|return\b|if\b|elif\b|while\b|for\b|func\b|fn\b)/;

  function lineAt(text, index) {
    const s = text.lastIndexOf("\n", index - 1) + 1;
    let e = text.indexOf("\n", index);
    if (e === -1) e = text.length;
    return text.slice(s, e);
  }

  // Decides whether `key = value` / `key: value` exposes a secret. Shared by env and config rules.
  function assignValidate(key, rawValue, info, opts = {}) {
    const kc = V.classifyKey(key);
    if (!kc) return false;
    const quoted = /^["'`]/.test(rawValue.trim());
    const value = V.stripQuotes(rawValue);
    if (V.isPlaceholder(value)) return false;
    if (kc.kind !== "url" && kc.kind !== "urlsecret" && V.looksLikePath(value)) return false;
    if (value.toLowerCase() === String(key).toLowerCase()) return false;

    // Unquoted identifiers in source code are usually variable references, not literals.
    if (!quoted && /^[A-Za-z_$][\w$]*$/.test(value) && info) {
      const line = lineAt(info.ctx.text, info.start);
      if (info.ctx.blocks.has("source_code") || CODE_LINE.test(line)) return false;
    }

    switch (kc.kind) {
      case "password":
        if (value.length < 4 || /\s/.test(value)) return false;
        break;
      case "pin":
        if (!/^\d{4,8}$/.test(value)) return false;
        break;
      case "secret":
        if (!V.secretLike(value, 8)) return false;
        break;
      case "url":
        if (!/@|pass(?:word)?=|pwd=/i.test(value)) return false;
        break;
      case "urlsecret":
        if (!/^https?:\/\/\S+\/\S{12,}/.test(value)) return false;
        break;
    }
    const category = opts.category || (/^[A-Z][A-Z0-9_]*$/.test(key) ? "env" : "config");
    const nice = kc.label.toLowerCase().replace(/_/g, " ");
    return {
      label: kc.label,
      category,
      severity: opts.severity || "high",
      reason: `${nice[0].toUpperCase()}${nice.slice(1)} assigned to "${String(key).slice(0, 60)}"`,
      placeholder: "none"
    };
  }
  PG.assignValidate = assignValidate;

  const assign = (id, reason, re, extra = {}) => ({
    id,
    label: "SECRET",
    category: "config",
    severity: "high",
    reason,
    re,
    placeholder: "none",
    validate: (v, info) => assignValidate(info.groups.k, v, info, extra.opts),
    ...extra
  });

  R.push(
    // KEY=value (env files, INI, TOML, properties, shell, query strings, ADO.NET, CLI --flag=value)
    assign("assign_equals", "Secret value in an assignment",
      /(?<![\w$.])(?<k>[A-Za-z_][\w.-]{0,80})[ \t]*(?::=|=>|=)(?!=)[ \t]*(?<v>"(?:[^"\\\n]|\\.){0,2000}"|'(?:[^'\\\n]|\\.){0,2000}'|`[^`\n]{0,2000}`|[^\s,;&"'`#)<>[\]]{1,2000})/g),

    // key: value (JSON, YAML, JS objects, HTTP-like prose "Password: x")
    assign("assign_colon", "Secret value in a key/value pair",
      /(?<![\w$.-])(?<q>["']?)(?<k>[A-Za-z_][\w.-]{0,80})\k<q>[ \t]*:(?!:)[ \t]*(?<v>"(?:[^"\\\n]|\\.){0,2000}"|'(?:[^'\\\n]|\\.){0,2000}'|`[^`\n]{0,2000}`|[^\s,;#{}[\]"'`|&][^\s,;{}[\]"'`]{0,2000})/g),

    // <password>value</password>
    assign("xml_element", "Secret value in an XML element",
      /<(?<k>[A-Za-z_][\w.:-]{0,80})(?:\s[^>]*)?>(?<v>[^<\n]{1,1000})<\/\k<k>\s*>/g),

    // <add key="ApiKey" value="..."/> (web.config / app.config)
    assign("xml_add_key", "Secret value in web.config appSettings",
      /<add\b[^>]*?\bkey\s*=\s*"(?<k>[^"]+)"[^>]*?\bvalue\s*=\s*"(?<v>[^"]*)"/gi),

    // define('DB_PASSWORD', '...') in wp-config.php
    assign("php_define", "Secret value in a PHP define()",
      /\bdefine\(\s*(?<q>['"])(?<k>\w+)\k<q>\s*,\s*(?<v>'[^'\n]*'|"[^"\n]*")/g),

    // .netrc
    {
      id: "netrc",
      label: "PASSWORD",
      category: "config",
      severity: "critical",
      reason: ".netrc machine password",
      placeholder: "strict",
      re: /\bmachine\s+\S+\s+login\s+\S+\s+password\s+(?<v>\S+)/g
    },
    // .htpasswd
    {
      id: "htpasswd",
      label: "PASSWORD_HASH",
      category: "config",
      severity: "high",
      reason: ".htpasswd password hash",
      placeholder: "none",
      re: /^[\w.-]+:(?<v>\$apr1\$\S+|\$2[aby]\$\S+|\{SHA\}\S+)$/gm
    },
    // Ansible vault payload
    {
      id: "ansible_vault",
      label: "VAULT_DATA",
      category: "config",
      severity: "medium",
      reason: "Ansible Vault encrypted payload",
      placeholder: "none",
      re: /\$ANSIBLE_VAULT;[\d.]+;AES256(?:;\w+)?[ \t]*(?<v>(?:\r?\n[0-9a-f]{10,})+)/g
    },
    // Kubernetes Secret data: / stringData: values
    {
      id: "k8s_secret_data",
      label: "K8S_SECRET",
      category: "config",
      severity: "critical",
      reason: "Value inside a Kubernetes Secret",
      placeholder: "strict",
      when: ctx => ctx.blocks.has("k8s_secret"),
      find(text) {
        const out = [];
        const lineRe = /[^\n]*\n?/g;
        let base = -1;
        let m;
        while ((m = lineRe.exec(text)) && m[0] !== "") {
          const line = m[0].replace(/\r?\n$/, "");
          const indent = line.match(/^\s*/)[0].length;
          const head = line.match(/^(\s*)(?:data|stringData):\s*$/);
          if (head) {
            base = head[1].length;
            continue;
          }
          if (base >= 0) {
            if (line.trim() && indent <= base) base = -1;
            else {
              const kv = line.match(/^(\s+[\w.-]+:\s*)(\S.*?)\s*$/);
              if (kv) out.push({ start: m.index + kv[1].length, end: m.index + kv[1].length + kv[2].length });
            }
          }
        }
        return out;
      }
    },

    // ---- CLI arguments ----
    {
      id: "cli_mysql_p",
      label: "PASSWORD",
      category: "config",
      severity: "high",
      reason: "Password passed to a database CLI",
      placeholder: "strict",
      re: /\b(?:mysql|mysqldump|mysqladmin|mariadb)\b[^\n]*?\s-p(?<v>[^\s-]\S*)/g
    },
    {
      id: "cli_curl_user",
      label: "PASSWORD",
      category: "config",
      severity: "critical",
      reason: "Password in curl -u",
      placeholder: "strict",
      re: /\bcurl\b[^\n]*?\s(?:-u|--user)\s*["']?[^:\s"']+:(?<v>[^\s"']+)/g
    },
    {
      id: "cli_sshpass",
      label: "PASSWORD",
      category: "config",
      severity: "high",
      reason: "Password passed to sshpass",
      placeholder: "strict",
      re: /\bsshpass\s+-p\s*(?<v>'[^'\n]*'|"[^"\n]*"|\S+)/g
    },
    {
      id: "cli_flag_space",
      label: "SECRET",
      category: "config",
      severity: "high",
      reason: "Secret passed as a command-line flag",
      placeholder: "strict",
      re: /--(?:password|passwd|pass|token|api-key|apikey|secret|client-secret|auth-token|access-token)[ \t]+(?<v>"[^"\n]*"|'[^'\n]*'|[^\s-]\S*)/gi
    }
  );
})();
