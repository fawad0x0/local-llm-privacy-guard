const api = globalThis.browser ?? globalThis.chrome;
const PG = globalThis.PrivacyGuard;
const S = PG.Settings;
const $ = id => document.getElementById(id);

const CATEGORY_LABELS = {
  pii: "Personal data (emails, phones, IDs, cards, IBAN)",
  credential: "Credentials, tokens, private keys, password hashes",
  cloud_secret: "Cloud secrets (AWS, Azure, Google Cloud)",
  env: "Environment variables and .env files",
  config: "Configuration file secrets and connection strings",
  log: "Logs, stack traces, HTTP headers, database errors",
  network: "IP addresses, MAC addresses, internal hostnames",
  custom: "Your custom rules and dictionary",
  ai: "Local AI findings"
};
const PACK_LABELS = {
  pk: "Pakistan (CNIC, NTN, mobile)",
  us: "United States (SSN, phone, street)",
  uk: "United Kingdom (NI number)",
  in: "India (Aadhaar, PAN)",
  ae: "UAE (Emirates ID)"
};
const ACTION_LABELS = { block: "Block", review: "Review", note: "Note", off: "Off" };

let state = { settings: S.normalize({}), managed: { locked: false, keys: [] } };
let draft = null;

const lines = v =>
  v
    .split(/\r?\n/)
    .map(x => x.trim())
    .filter(Boolean);
const isManaged = key => state.managed.locked || state.managed.keys.includes(key);

function checkbox(container, label, checked, onChange, disabled) {
  const l = document.createElement("label");
  l.className = "toggle";
  const i = document.createElement("input");
  i.type = "checkbox";
  i.checked = checked;
  i.disabled = disabled;
  i.addEventListener("change", () => onChange(i.checked));
  l.append(i, document.createTextNode(" " + label));
  container.append(l);
}

function parseCustomRules(text) {
  const rules = [];
  const errors = [];
  lines(text).forEach((line, idx) => {
    const parts = line.split("|").map(x => x.trim());
    if (parts.length < 3) {
      errors.push(`Line ${idx + 1}: expected LABEL | severity | pattern`);
      return;
    }
    const [label, severity] = parts;
    let pattern = parts.slice(2).join("|");
    let flags = "gi";
    const lit = pattern.match(/^\/(.+)\/([a-z]*)$/);
    if (lit) {
      pattern = lit[1];
      flags = lit[2].includes("g") ? lit[2] : lit[2] + "g";
    }
    if (!S.SEVERITIES.includes(severity)) {
      errors.push(`Line ${idx + 1}: severity must be one of ${S.SEVERITIES.join(", ")}`);
      return;
    }
    try {
      new RegExp(pattern, flags.replace(/[^gimsuv]/g, ""));
    } catch (e) {
      errors.push(`Line ${idx + 1}: invalid regex (${e.message})`);
      return;
    }
    rules.push({ label, severity, pattern, flags });
  });
  return { rules, errors };
}

function formatCustomRules(rules) {
  return rules
    .map(r => `${r.label} | ${r.severity} | ${r.flags && r.flags !== "gi" ? `/${r.pattern}/${r.flags}` : r.pattern}`)
    .join("\n");
}

function renderSites() {
  const ul = $("customSites");
  ul.replaceChildren();
  for (const h of draft.customSites) {
    const li = document.createElement("li");
    const span = document.createElement("span");
    span.textContent = h;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = "Remove";
    btn.disabled = isManaged("customSites");
    btn.addEventListener("click", async () => {
      draft.customSites = draft.customSites.filter(x => x !== h);
      try {
        await api.permissions.remove({ origins: [`*://${h}/*`] });
      } catch {
        /* already removed */
      }
      await persist("Site removed.");
    });
    li.append(span, btn);
    ul.append(li);
  }
}

function render() {
  draft = S.normalize(state.settings);
  $("managed").hidden = !(state.managed.locked || state.managed.keys.length);

  for (const input of document.querySelectorAll("input[data-key]")) {
    input.checked = !!draft[input.dataset.key];
    input.disabled = isManaged(input.dataset.key);
    input.onchange = () => (draft[input.dataset.key] = input.checked);
  }

  const policy = $("policy");
  policy.replaceChildren();
  for (const sev of S.SEVERITIES) {
    const l = document.createElement("label");
    l.className = "lbl";
    l.textContent = sev[0].toUpperCase() + sev.slice(1);
    const sel = document.createElement("select");
    sel.disabled = isManaged("policy");
    for (const a of S.ACTIONS) {
      const o = document.createElement("option");
      o.value = a;
      o.textContent = ACTION_LABELS[a];
      sel.append(o);
    }
    sel.value = draft.policy[sev];
    sel.addEventListener("change", () => (draft.policy[sev] = sel.value));
    l.append(sel);
    policy.append(l);
  }

  $("categories").replaceChildren();
  for (const [k, label] of Object.entries(CATEGORY_LABELS)) {
    checkbox(
      $("categories"),
      label,
      draft.categories[k] !== false,
      v => (draft.categories[k] = v),
      isManaged("categories")
    );
  }
  $("packs").replaceChildren();
  for (const [k, label] of Object.entries(PACK_LABELS)) {
    checkbox($("packs"), label, !!draft.packs[k], v => (draft.packs[k] = v), isManaged("packs"));
  }

  $("customRules").value = formatCustomRules(draft.customRules);
  $("dictionary").value = draft.dictionary.join("\n");
  $("internalDomains").value = draft.internalDomains.join("\n");
  $("allowlist").value = draft.allowlist.join("\n");
  $("disabledSites").value = draft.disabledSites.join("\n");
  for (const id of ["customRules", "dictionary", "internalDomains", "allowlist", "disabledSites"])
    $(id).disabled = isManaged(id);

  $("aiEnabled").checked = draft.localAi.enabled;
  $("aiEndpoint").value = draft.localAi.endpoint;
  $("aiModel").value = draft.localAi.model;
  $("aiTimeout").value = draft.localAi.timeoutMs;
  for (const id of ["aiEnabled", "aiEndpoint", "aiModel", "aiTimeout", "aiTest"]) $(id).disabled = isManaged("localAi");
  $("save").disabled = state.managed.locked;
  $("reset").disabled = state.managed.locked;
  $("addSite").disabled = isManaged("customSites");

  renderSites();
  runTry();
}

function collect() {
  const { rules, errors } = parseCustomRules($("customRules").value);
  $("customRulesError").textContent = errors.join("\n");
  if (errors.length) return null;
  draft.customRules = rules;
  draft.dictionary = lines($("dictionary").value);
  draft.internalDomains = lines($("internalDomains").value).map(x =>
    x
      .toLowerCase()
      .replace(/^\*\./, "")
      .replace(/^https?:\/\//, "")
      .replace(/\/.*$/, "")
  );
  draft.allowlist = lines($("allowlist").value);
  draft.disabledSites = lines($("disabledSites").value).map(x => x.toLowerCase());
  draft.localAi = {
    enabled: $("aiEnabled").checked,
    endpoint: $("aiEndpoint").value.trim() || "http://localhost:11434",
    model: $("aiModel").value.trim() || "llama3.2",
    timeoutMs: Number($("aiTimeout").value) || 8000
  };
  return draft;
}

function isLocal(url) {
  try {
    return ["localhost", "127.0.0.1", "[::1]"].includes(new URL(url).hostname);
  } catch {
    return false;
  }
}

async function persist(message = "Settings saved.") {
  await S.save(draft, api);
  state = await S.load(api);
  render();
  $("saveStatus").textContent = message;
}

$("save").addEventListener("click", async () => {
  const s = collect();
  if (!s) {
    $("saveStatus").textContent = "Fix the errors above before saving.";
    return;
  }
  if (s.localAi.enabled) {
    if (!isLocal(s.localAi.endpoint)) {
      $("saveStatus").textContent = "The local AI endpoint must be on localhost.";
      return;
    }
    let granted = false;
    try {
      granted = await api.permissions.request({ origins: ["http://localhost/*", "http://127.0.0.1/*"] });
    } catch {
      granted = false;
    }
    if (!granted) {
      s.localAi.enabled = false;
      $("aiEnabled").checked = false;
      $("aiStatus").textContent = "Permission to reach localhost was not granted, so the local AI check stays off.";
    }
  }
  await persist();
});

$("reset").addEventListener("click", async () => {
  if (!confirm("Restore all Privacy Guard settings to their defaults?")) return;
  draft = S.normalize({ customSites: draft.customSites });
  await persist("Defaults restored.");
});

$("addSite").addEventListener("click", async () => {
  const raw = $("newSite").value.trim().toLowerCase();
  const hostName = raw.replace(/^https?:\/\//, "").replace(/[/:].*$/, "");
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(hostName)) {
    $("saveStatus").textContent = "Enter a hostname like chat.example.com.";
    return;
  }
  let granted = false;
  try {
    granted = await api.permissions.request({ origins: [`*://${hostName}/*`] });
  } catch {
    granted = false;
  }
  if (!granted) {
    $("saveStatus").textContent = "Permission was not granted for " + hostName + ".";
    return;
  }
  collect();
  draft.customSites = [...new Set([...draft.customSites, hostName])];
  $("newSite").value = "";
  await persist(`Added ${hostName}. Reload its tabs to start protection.`);
});

$("aiTest").addEventListener("click", async () => {
  const endpoint = $("aiEndpoint").value.trim() || "http://localhost:11434";
  if (!isLocal(endpoint)) {
    $("aiStatus").textContent = "Endpoint must be on localhost.";
    return;
  }
  let granted = false;
  try {
    granted = await api.permissions.request({ origins: ["http://localhost/*", "http://127.0.0.1/*"] });
  } catch {
    granted = false;
  }
  if (!granted) {
    $("aiStatus").textContent = "Permission to reach localhost is needed for the test.";
    return;
  }
  $("aiStatus").textContent = "Testing…";
  const res = await api.runtime.sendMessage({
    type: "pg:ai-test",
    config: {
      endpoint,
      model: $("aiModel").value.trim() || "llama3.2",
      timeoutMs: Number($("aiTimeout").value) || 8000
    }
  });
  $("aiStatus").textContent =
    res && res.ok
      ? `Connected. The model found ${res.entities.length} entities in a sample sentence.`
      : `Failed: ${(res && res.error) || "no response"}. If Ollama is running, set OLLAMA_ORIGINS to allow extensions.`;
});

// ---- Live scanner preview ----
let tryTimer = null;
function runTry() {
  clearTimeout(tryTimer);
  tryTimer = setTimeout(() => {
    const text = $("tryInput").value;
    const settings = collect() || draft;
    const out = $("tryOutput");
    const list = $("tryFindings");
    const blocks = $("tryBlocks");
    list.replaceChildren();
    blocks.replaceChildren();
    if (!text.trim()) {
      out.textContent = "";
      return;
    }
    const r = PG.scan(text, { settings });
    out.textContent = r.text;
    for (const b of r.blocks.filter(x => x.active)) {
      const d = document.createElement("div");
      d.className = "banner";
      d.textContent = b.label;
      blocks.append(d);
    }
    for (const f of r.findings) {
      const li = document.createElement("li");
      const sev = document.createElement("span");
      sev.className = "sev sev-" + f.severity;
      sev.textContent = f.severity;
      li.append(sev, document.createTextNode(`${f.token} ${f.reason}${f.redact ? "" : " (kept by default)"}`));
      list.append(li);
    }
    if (!r.findings.length) {
      const li = document.createElement("li");
      li.textContent = "Nothing flagged.";
      list.append(li);
    }
  }, 150);
}
$("tryInput").addEventListener("input", runTry);

(async () => {
  try {
    state = await S.load(api, { managed: false }); // fast first paint
    render();
    state = await S.load(api); // then apply organization policy, if any
  } catch {
    $("saveStatus").textContent = "Could not load settings.";
  }
  render();
})();
