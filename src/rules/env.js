/* Environment-variable forms not covered by the generic KEY=value rule. */
(() => {
  const PG = (globalThis.PrivacyGuard = globalThis.PrivacyGuard || {});
  const R = (PG.rules = PG.rules || []);
  if (R.some(r => r.id === "env_powershell")) return;

  const envRule = (id, reason, re) => ({
    id,
    label: "SECRET",
    category: "env",
    severity: "high",
    reason,
    re,
    placeholder: "none",
    validate: (v, info) => PG.assignValidate(info.groups.k, v, info, { category: "env" })
  });

  R.push(
    // PowerShell: $env:API_TOKEN = "..."
    envRule("env_powershell", "Secret in a PowerShell environment variable",
      /\$env:(?<k>[A-Za-z_]\w*)\s*=\s*(?<v>"[^"\n]*"|'[^'\n]*'|\S+)/gi),
    // Dockerfile: ENV SECRET_KEY value   /   ARG TOKEN value
    envRule("env_dockerfile_space", "Secret in a Dockerfile ENV/ARG",
      /^[ \t]*(?:ENV|ARG)[ \t]+(?<k>[A-Za-z_]\w*)[ \t]+(?<v>"[^"\n]*"|'[^'\n]*'|[^\s=][^\n]*?)[ \t]*$/gm)
    // `export KEY=value`, `set KEY=value`, `docker run -e KEY=value`, `--build-arg KEY=value`
    // and plain .env lines are handled by the shared "assign_equals" rule in config.js.
  );
})();
