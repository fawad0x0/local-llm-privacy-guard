/* Error messages, logs, stack traces, HTTP dumps: data that leaks through diagnostics. */
(() => {
  const PG = (globalThis.PrivacyGuard = globalThis.PrivacyGuard || {});
  const V = PG.validators;
  const R = (PG.rules = PG.rules || []);
  if (R.some(r => r.id === "http_header_secret")) return;

  const GENERIC_USER = /^(?:public|default|default user|all users|shared|user|username|user ?name|your_?name|yourusername|you|me|runner|name|<[^>]+>|\$\w+|%\w+%|\*|\.\.\.|x+)$/i;
  const GENERIC_PROJECT = /^(?:app|apps|src|lib|bin|current|releases|shared|node_modules|venv|env|www|html|public|static|build|dist|code|data|tmp|cache|log|logs|site-packages)$/i;
  const ANY_LOG_BLOCK = ctx => ctx.blocks.has("log") || ctx.blocks.has("stack_trace") || ctx.blocks.has("sql_error");

  R.push(
    {
      id: "http_header_secret",
      label: "TOKEN",
      category: "log",
      severity: "high",
      reason: "Secret HTTP header",
      placeholder: "none",
      re: /(?<![\w-])(?<k>Authorization|Proxy-Authorization|Cookie|Set-Cookie|X-Api-Key|X-Auth-Token|X-Access-Token|X-Amz-Security-Token|X-CSRF-Token|X-XSRF-Token|Api-Key|Ocp-Apim-Subscription-Key|X-Goog-Api-Key|X-Shopify-Access-Token|PRIVATE-TOKEN|X-Vault-Token)[ \t]*:[ \t]*(?<v>[^\r\n"'\\]{4,})/gi,
      validate(v, info) {
        const rest = v.replace(/^(?:Bearer|Basic|Token|Digest|Negotiate)\s+/i, "").trim();
        if (rest.length < 8 || V.isPlaceholder(rest)) return false;
        const k = info.groups.k.toLowerCase();
        return k.includes("cookie")
          ? { label: "SESSION", reason: `${info.groups.k} header (session cookies)` }
          : { reason: `${info.groups.k} header value` };
      }
    },
    {
      id: "url_query_secret",
      label: "TOKEN",
      category: "log",
      severity: "high",
      reason: "Secret in a URL query parameter",
      placeholder: "strict",
      re: /[?&;#](?<k>token|access_token|refresh_token|id_token|auth_token|api_key|apikey|key|code|sig|signature|session|sessionid|sid|auth|password|pass|pwd|secret|client_secret|X-Amz-Signature|X-Amz-Credential|X-Amz-Security-Token|jwt)=(?<v>[^&#;\s"'<>]{6,})/gi,
      validate(v, info) {
        const k = info.groups.k.toLowerCase();
        if (k === "code") return { label: "AUTH_CODE", reason: "OAuth authorization code in URL" };
        if (k === "sig" || k === "signature" || k.startsWith("x-amz")) return { label: "SIGNATURE", reason: "Signed URL credential" };
        if (/pass|pwd/.test(k)) return { label: "PASSWORD", reason: "Password in URL query" };
        return true;
      }
    },
    {
      id: "user_path_windows",
      label: "USER",
      category: "log",
      severity: "low",
      reason: "Username inside a Windows path",
      placeholder: "none",
      re: /(?<![\w])[A-Za-z]:(?:\\{1,2}|\/)(?:Users|Documents and Settings)(?:\\{1,2}|\/)(?<v>[^\\/:*?"<>|\r\n]{1,64}?)(?=\\|\/)/gi,
      validate: v => !GENERIC_USER.test(v.trim())
    },
    {
      id: "user_path_windows_end",
      label: "USER",
      category: "log",
      severity: "low",
      reason: "Username inside a Windows path",
      placeholder: "none",
      re: /(?<![\w])[A-Za-z]:(?:\\{1,2}|\/)(?:Users|Documents and Settings)(?:\\{1,2}|\/)(?<v>[^\\/:*?"<>|\r\n\s]{1,64})(?![\\/\w])/gi,
      validate: v => !GENERIC_USER.test(v)
    },
    {
      id: "user_path_unix",
      label: "USER",
      category: "log",
      severity: "low",
      reason: "Username inside a home-directory path",
      placeholder: "none",
      re: /(?<![\w.])(?:\/home|\/Users)\/(?<v>[A-Za-z0-9._-]{1,64})(?=\/|\s|$|["':)])/gm,
      validate: v => !GENERIC_USER.test(v)
    },
    {
      id: "org_path",
      label: "PROJECT",
      category: "log",
      severity: "low",
      reason: "Project / organization name in a server path",
      placeholder: "none",
      when: ctx => ctx.blocks.has("stack_trace"),
      re: /(?<![\w.])\/(?:srv|opt|var\/www|app|apps|data|workspace|deploy)\/(?<v>[A-Za-z0-9._-]{2,64})(?=\/)/g,
      validate: v => !GENERIC_PROJECT.test(v)
    },
    {
      id: "pg_key_value",
      label: "DB_VALUE",
      category: "log",
      severity: "medium",
      reason: "Row value in a database error",
      placeholder: "none",
      re: /\bKey \((?<k>[^)\n]{1,100})\)=\((?<v>[^)\n]{1,500})\)/g
    },
    {
      id: "mysql_duplicate",
      label: "DB_VALUE",
      category: "log",
      severity: "medium",
      reason: "Row value in a database error",
      placeholder: "none",
      re: /\bDuplicate entry '(?<v>[^'\n]{1,500})' for key/g
    },
    {
      id: "sql_literal",
      label: "SQL_VALUE",
      category: "log",
      severity: "medium",
      reason: "Literal value in SQL from an error/log",
      placeholder: "none",
      when: ANY_LOG_BLOCK,
      find(text) {
        const out = [];
        const clause = /\b(?:VALUES\s*\((?<a>[^)\n]{1,4000})\)|WHERE\b(?<b>[^;\n]{1,1000}))/gid;
        for (const m of text.matchAll(clause)) {
          const span = m.indices.groups.a || m.indices.groups.b;
          if (!span) continue;
          const body = text.slice(span[0], span[1]);
          for (const lit of body.matchAll(/'((?:[^'\\]|\\.|''){1,500})'|(?<![\w.$])(\d{6,})(?![\w.])/g)) {
            const value = lit[1] ?? lit[2];
            if (!value || /^[a-z_]{1,12}$/.test(value)) continue; // enum-like words: 'active'
            const start = span[0] + lit.index + (lit[1] != null ? 1 : 0);
            out.push({ start, end: start + value.length });
          }
        }
        return out;
      }
    },
    {
      id: "aws_arn_account",
      label: "ACCOUNT",
      category: "log",
      severity: "medium",
      reason: "AWS account ID in an ARN",
      placeholder: "none",
      re: /\barn:aws[\w-]*:[\w-]+:[\w-]*:(?<v>\d{12}):/g
    },
    {
      id: "cloud_account_id",
      label: "ACCOUNT",
      category: "log",
      severity: "medium",
      reason: "Cloud account / subscription / tenant ID",
      placeholder: "none",
      re: /\b(?:aws[ _-]?account(?:[ _-]?id)?|account[ _-]?id|subscription[ _-]?id|tenant[ _-]?id)["']?\s*[:=]\s*["']?(?<v>\d{12}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b/gi
    },
    {
      id: "azure_subscription_path",
      label: "ACCOUNT",
      category: "log",
      severity: "medium",
      reason: "Azure subscription ID",
      placeholder: "none",
      re: /\/subscriptions\/(?<v>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/gi
    }
  );
})();
