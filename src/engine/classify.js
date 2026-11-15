/* Block classifier: decides what kind of text is being sent (.env, config, log, stack trace...). */
(() => {
  const PG = (globalThis.PrivacyGuard = globalThis.PrivacyGuard || {});
  if (PG.classify) return;

  // severity: contribution to the overall risk. alwaysWarn: warn even when no finding matched.
  const BLOCKS = {
    env_file: { label: "This looks like an .env file", severity: "high" },
    k8s_secret: { label: "This looks like a Kubernetes Secret", severity: "critical", alwaysWarn: true },
    kubeconfig: { label: "This looks like a kubeconfig file", severity: "high", alwaysWarn: true },
    gcp_service_account: {
      label: "This looks like a Google Cloud service-account key",
      severity: "critical",
      alwaysWarn: true
    },
    aws_credentials: { label: "This looks like an AWS credentials file", severity: "critical", alwaysWarn: true },
    docker_compose: { label: "This looks like a docker-compose file", severity: "medium" },
    terraform: { label: "This looks like Terraform config/state", severity: "medium" },
    stack_trace: { label: "This looks like a stack trace / error output", severity: "medium" },
    log: { label: "This looks like log output", severity: "medium" },
    sql_error: { label: "This looks like a database error", severity: "medium" },
    http_dump: { label: "This looks like an HTTP request/response dump", severity: "medium" },
    json_config: { label: "This looks like a JSON configuration", severity: "low" },
    yaml_config: { label: "This looks like a YAML configuration", severity: "low" },
    ini_config: { label: "This looks like an INI/TOML configuration", severity: "low" },
    xml_config: { label: "This looks like an XML configuration", severity: "low" },
    properties_config: { label: "This looks like a .properties configuration", severity: "low" },
    shell: { label: "This looks like shell commands", severity: "low" },
    source_code: { label: "This looks like source code", severity: null }
  };

  const STACK_SIGNALS = [
    /Traceback \(most recent call last\)/,
    /Exception in thread "/,
    /PHP (?:Fatal|Parse) error|Fatal error: Uncaught/,
    /^panic: [\s\S]*goroutine \d+/m,
    /System\.\w*Exception/,
    /^[ \t]*at .+ in .+:line \d+[ \t]*$/m
  ];

  function classify(input) {
    const text = input.length > 500000 ? input.slice(0, 500000) : input;
    const lines = text.split(/\r?\n/);
    const content = lines.filter(l => l.trim() && !/^\s*(?:#|\/\/|;)/.test(l));
    const n = content.length || 1;
    const count = re => lines.reduce((c, l) => c + (re.test(l) ? 1 : 0), 0);
    const found = new Set();

    const envLines = count(/^\s*(?:export\s+)?[A-Z][A-Z0-9_]*\s?=/);
    if (envLines >= 3 && envLines >= n * 0.5) found.add("env_file");

    // Multiline regexes use [ \t] instead of \s so they cannot backtrack across many blank lines.
    if (/^[ \t]*kind:[ \t]*Secret\b/m.test(text)) found.add("k8s_secret");
    if (/^[ \t]*kind:[ \t]*Config\b/m.test(text) && /^[ \t]*clusters:/m.test(text)) found.add("kubeconfig");
    if (/"type"\s*:\s*"service_account"/.test(text)) found.add("gcp_service_account");
    if (/^[ \t]*\[[\w -]+\][ \t]*$/m.test(text) && /^[ \t]*aws_(?:access_key_id|secret_access_key)[ \t]*=/im.test(text))
      found.add("aws_credentials");
    if (/^services:[ \t]*$/m.test(text) && /^[ \t]+(?:image|build|environment|ports):/m.test(text))
      found.add("docker_compose");
    if (
      /\b(?:resource|provider|variable|module)\s+"[\w-]+"(?:\s+"[\w-]+")?\s*\{/.test(text) ||
      /"terraform_version"\s*:/.test(text)
    )
      found.add("terraform");

    const jsFrames = count(/^\s+at .+[(:]\d+(?::\d+)?\)?\s*$/);
    const pyFrames = count(/^\s+File ".*", line \d+/);
    if (STACK_SIGNALS.some(re => re.test(text)) || jsFrames >= 2 || pyFrames >= 2) found.add("stack_trace");

    const logLines =
      count(/^\s*\[?\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/) +
      count(/^\s*\[?(?:INFO|WARN(?:ING)?|ERROR|DEBUG|TRACE|FATAL|CRITICAL)\]?[\s:]/) +
      count(/^\S+ \S+ \S+ \[\d{2}\/\w{3}\/\d{4}:/);
    if (logLines >= 2) found.add("log");

    if (
      /SQLSTATE|ORA-\d{5}|ERROR:\s+duplicate key|Duplicate entry '|PG::\w+Error|SequelizeDatabaseError|sqlite3\.\w*Error|psycopg2\.\w+|MySQL server has gone away|violates (?:unique|foreign key|not-null) constraint/i.test(
        text
      )
    ) {
      found.add("sql_error");
    }
    if (
      /^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) \S+ HTTP\/\d/m.test(text) ||
      /^HTTP\/\d(?:\.\d)? \d{3}/m.test(text)
    )
      found.add("http_dump");

    const trimmed = text.trim();
    if (/^[{[]/.test(trimmed)) {
      let isJson = false;
      if (trimmed.length < 200000) {
        try {
          JSON.parse(trimmed);
          isJson = true;
        } catch {
          /* not strict JSON */
        }
      }
      if (isJson || (text.match(/"[\w.-]+"\s*:/g) || []).length >= 3) found.add("json_config");
    }
    const yamlLines = count(/^\s*-?\s*[\w.-]+:(?:\s|$)/);
    if (yamlLines >= 3 && yamlLines >= n * 0.5 && !found.has("log")) found.add("yaml_config");
    if (/^[ \t]*\[[^\]\n]+\][ \t]*$/m.test(text) && count(/^\s*[\w.-]+\s*=/) >= 2) found.add("ini_config");
    if (/<\?xml\b|<configuration>|<appSettings>|<connectionStrings>/i.test(text)) found.add("xml_config");
    if (count(/^\s*[a-z][\w-]*(?:\.[\w-]+)+\s*[=:]/) >= 2) found.add("properties_config");
    if (
      /^[ \t]*(?:\$|PS [A-Z]:\\[^>\n]*>)[ \t]*\S/m.test(text) ||
      /(?:^|[ \t])(?:curl|wget|mysql|psql|ssh|scp|docker|kubectl|aws|gcloud|az|sshpass|redis-cli|mongosh?)[ \t]+[-\w]/m.test(
        text
      )
    ) {
      found.add("shell");
    }
    const codeLines = count(
      /\b(?:function|def|class|import|const|let|var|public|private|return|package|func)\b|[;{}]\s*$/
    );
    if (codeLines >= 3 && codeLines >= n * 0.3) found.add("source_code");

    return [...found].map(id => ({ id, ...BLOCKS[id] }));
  }

  PG.classify = classify;
  PG.BLOCK_TYPES = BLOCKS;
})();
