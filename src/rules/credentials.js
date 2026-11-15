/* Credentials, provider API keys, private keys, password hashes. */
(() => {
  const PG = (globalThis.PrivacyGuard = globalThis.PrivacyGuard || {});
  const V = PG.validators;
  const R = (PG.rules = PG.rules || []);
  if (R.some(r => r.id === "private_key")) return;

  const cloud = (id, label, severity, reason, re, extra = {}) =>
    ({ id, label, category: "cloud_secret", severity, reason, re, placeholder: "provider", ...extra });
  const cred = (id, label, severity, reason, re, extra = {}) =>
    ({ id, label, category: "credential", severity, reason, re, placeholder: "provider", ...extra });

  const SECRET_KEYWORD = /(?:key|token|secret|passw|pwd|auth|credential|bearer|signature|session|cookie|private)/i;

  R.push(
    // ---- Private keys ----
    cred("private_key", "PRIVATE_KEY", "critical", "Private key block",
      /-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----[\s\S]*?-----END \1-----/g,
      { placeholder: "none" }),
    cred("private_key_partial", "PRIVATE_KEY", "critical", "Start of a private key (truncated)",
      /-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----(?:\r?\n(?:[A-Za-z0-9+/=]{16,}|[A-Za-z-]+: [^\r\n]*|(?=\r?\n[A-Za-z0-9+/=]{16,})))*/g,
      { placeholder: "none" }),
    cred("putty_key", "PRIVATE_KEY", "critical", "PuTTY private key file",
      /PuTTY-User-Key-File-\d+:[\s\S]*?Private-MAC: [0-9a-fA-F]+/g, { placeholder: "none" }),

    // ---- Cloud providers ----
    cloud("aws_access_key", "AWS_KEY", "critical", "AWS access key ID", /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g),
    cloud("aws_secret_key", "AWS_SECRET", "critical", "AWS secret access key",
      /\baws_?secret_?(?:access_?)?key(?:_id)?["']?\s*[:=]\s*["']?(?<v>[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gi),
    cloud("aws_session_token", "AWS_SESSION", "critical", "AWS session token",
      /\baws_?session_?token["']?\s*[:=]\s*["']?(?<v>[A-Za-z0-9/+=]{100,})/gi),
    cloud("azure_storage_key", "AZURE_KEY", "critical", "Azure storage / Service Bus key",
      /\b(?:AccountKey|SharedAccessKey)=(?<v>[A-Za-z0-9+/=]{20,})/g),
    cloud("azure_sas", "AZURE_SAS", "high", "Azure SAS signature",
      /[?&;](?:sig|SharedAccessSignature)=(?<v>[A-Za-z0-9%+/=]{20,})/g),
    cloud("gcp_private_key", "GCP_KEY", "critical", "Google Cloud service-account private key",
      /"private_key"\s*:\s*"(?<v>-----BEGIN[^"]+)"/g, { placeholder: "none" }),
    cloud("gcp_private_key_id", "GCP_KEY_ID", "high", "Google Cloud service-account key ID",
      /"private_key_id"\s*:\s*"(?<v>[a-f0-9]{40})"/g),
    cloud("google_api_key", "GOOGLE_KEY", "high", "Google API key", /\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/g),
    cloud("google_oauth_secret", "GOOGLE_SECRET", "critical", "Google OAuth client secret", /\bGOCSPX-[A-Za-z0-9_-]{20,}/g),

    // ---- AI providers ----
    cred("anthropic_key", "ANTHROPIC_KEY", "critical", "Anthropic API key", /\bsk-ant-[A-Za-z0-9_-]{20,}/g),
    cred("openai_key", "OPENAI_KEY", "critical", "OpenAI API key",
      /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/g),
    cred("huggingface", "HF_TOKEN", "high", "Hugging Face token", /\bhf_[A-Za-z0-9]{30,}\b/g),

    // ---- Code hosting / package registries ----
    cred("github_token", "GITHUB_TOKEN", "critical", "GitHub token", /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g),
    cred("github_pat", "GITHUB_TOKEN", "critical", "GitHub fine-grained token", /\bgithub_pat_[A-Za-z0-9_]{22,}/g),
    cred("gitlab_token", "GITLAB_TOKEN", "critical", "GitLab token",
      /\bgl(?:pat|dt|ptt|rt|cbt|imt|agent|oas|ffct|soat)-[A-Za-z0-9_-]{20,}/g),
    cred("npm_token", "NPM_TOKEN", "critical", "npm access token", /\bnpm_[A-Za-z0-9]{36}\b/g),
    cred("pypi_token", "PYPI_TOKEN", "critical", "PyPI API token", /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}/g),
    cred("docker_pat", "DOCKER_TOKEN", "critical", "Docker Hub token", /\bdckr_pat_[A-Za-z0-9_-]{20,}/g),
    cred("vault_token", "VAULT_TOKEN", "critical", "HashiCorp Vault token", /\b(?:hv[sbr]\.[A-Za-z0-9_-]{24,}|s\.[A-Za-z0-9]{24,})\b/g),

    // ---- Messaging / SaaS ----
    cred("slack_token", "SLACK_TOKEN", "critical", "Slack token", /\bxox[baprse]-[A-Za-z0-9-]{10,}/g),
    cred("slack_webhook", "WEBHOOK", "high", "Slack webhook URL",
      /https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9_/-]+/g),
    cred("discord_webhook", "WEBHOOK", "high", "Discord webhook URL",
      /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/g),
    cred("discord_bot", "DISCORD_TOKEN", "high", "Discord bot token",
      /\b[MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38}\b/g),
    cred("telegram_bot", "TELEGRAM_TOKEN", "high", "Telegram bot token", /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g),
    cred("stripe_live", "STRIPE_KEY", "critical", "Stripe live secret key", /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/g),
    cred("stripe_webhook", "STRIPE_KEY", "critical", "Stripe webhook secret", /\bwhsec_[A-Za-z0-9]{24,}\b/g),
    cred("stripe_test", "STRIPE_TEST_KEY", "medium", "Stripe test key", /\b(?:sk|rk)_test_[A-Za-z0-9]{20,}\b/g),
    cred("twilio_key", "TWILIO_KEY", "high", "Twilio API key", /\bSK[0-9a-fA-F]{32}\b/g),
    cred("twilio_sid", "TWILIO_SID", "medium", "Twilio account SID", /\bAC[0-9a-f]{32}\b/g),
    cred("sendgrid", "SENDGRID_KEY", "critical", "SendGrid API key", /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g),
    cred("mailgun", "MAILGUN_KEY", "high", "Mailgun API key", /\bkey-[0-9a-f]{32}\b/g),
    cred("shopify", "SHOPIFY_TOKEN", "critical", "Shopify access token", /\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b/g),

    // ---- Generic token formats ----
    cred("jwt", "JWT", "high", "JSON Web Token", /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g),
    cred("bearer", "TOKEN", "high", "Bearer token", /\bBearer\s+(?<v>[A-Za-z0-9\-._~+/]{20,}=*)/g),
    cred("url_credentials", "PASSWORD", "critical", "Password inside a URL / connection string",
      /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:@/]{1,100}:(?<v>[^\s@/]{1,200})@[^\s/]+/gi, { placeholder: "strict" }),

    // ---- Password hashes ----
    cred("bcrypt", "PASSWORD_HASH", "high", "bcrypt password hash", /\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}/g),
    cred("argon2", "PASSWORD_HASH", "high", "Argon2 password hash",
      /\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+/g),
    cred("crypt_hash", "PASSWORD_HASH", "high", "Unix crypt / shadow hash", /\$(?:1|5|6|y)\$[^\s$:]{1,}\$[./A-Za-z0-9]{20,}/g),
    cred("ntlm_hash", "PASSWORD_HASH", "high", "NTLM / LM hash pair", /\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b/g),

    // ---- High-entropy strings ----
    {
      id: "high_entropy",
      label: "HIGH_ENTROPY",
      category: "credential",
      severity: "low",
      reason: "Random-looking string (possible secret)",
      placeholder: "provider",
      re: /(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{20,}={0,2}(?![A-Za-z0-9+/=_-])/g,
      validate(v, info) {
        if (/^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(v)) return false; // UUID
        if (!/\d/.test(v) || !/[A-Za-z]/.test(v)) return false;
        if (/\/[a-z]{2,}\//.test(v)) return false; // path
        const words = v.match(/[a-z]{5,}/g) || [];
        if (words.join("").length / v.length >= 0.4) return false; // identifier like getUserAccountById2
        if (V.entropy(v) < 3.5) return false;
        if (SECRET_KEYWORD.test(info.ctx.before(info.start, 40))) {
          return { severity: "high", label: "SECRET", reason: "High-entropy string next to a secret keyword" };
        }
        return { defaultRedact: false };
      }
    }
  );
})();
