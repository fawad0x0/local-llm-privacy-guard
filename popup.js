const api = globalThis.browser ?? globalThis.chrome;
const S = globalThis.PrivacyGuard.Settings;
const $ = id => document.getElementById(id);

const SUPPORTED = [
  /^(?:.+\.)?chatgpt\.com$/,
  /^chat\.openai\.com$/,
  /^claude\.ai$/,
  /^gemini\.google\.com$/,
  /^copilot\.microsoft\.com$/,
  /^(?:www\.)?perplexity\.ai$/,
  /^chat\.deepseek\.com$/,
  /^chat\.mistral\.ai$/,
  /^grok\.com$/,
  /^poe\.com$/,
  /^www\.meta\.ai$/
];

let state = { settings: S.normalize({}), managed: { locked: false } };
let host = null;

function setStatus(text, error = false) {
  $("status").textContent = text;
  $("status").classList.toggle("error", error);
}

async function currentHost() {
  try {
    const [tab] = await api.tabs.query({ active: true, currentWindow: true });
    const u = new URL(tab.url);
    return /^https?:$/.test(u.protocol) ? u.hostname : null;
  } catch {
    return null;
  }
}

function render() {
  const s = state.settings;
  $("enabled").checked = s.enabled;
  $("reviewAll").checked = s.reviewAll;
  $("strictMode").checked = s.strictMode;
  const locked = state.managed.locked;
  for (const id of ["enabled", "reviewAll", "strictMode", "siteEnabled"]) $(id).disabled = locked;

  const supported = host && SUPPORTED.some(re => re.test(host));
  const custom = host && s.customSites.includes(host);
  $("siteName").textContent = host || "This page cannot be protected";
  if (!host) {
    $("siteEnabled").disabled = true;
    $("siteEnabled").checked = false;
    $("siteHint").textContent = "";
  } else if (supported || custom) {
    $("siteEnabled").checked = !s.disabledSites.includes(host);
    $("siteHint").textContent = supported ? "Supported AI site." : "Added by you.";
  } else {
    $("siteEnabled").checked = false;
    $("siteHint").textContent = "Not protected. Turn on to grant access to this site (reload the tab afterwards).";
  }
  if (locked) setStatus("Settings are managed by your organization.");
}

async function renderStats() {
  try {
    const store = api.storage.session || api.storage.local;
    const st = (await store.get("pgStats")).pgStats || { items: 0, events: {} };
    $("statItems").textContent = st.items || 0;
    const ev = st.events || {};
    $("statReviews").textContent = (ev.redacted || 0) + (ev.cancelled || 0) + (ev.overridden || 0) + (ev.removed || 0);
    $("statOverrides").textContent = ev.overridden || 0;
  } catch {
    /* session storage unavailable */
  }
}

async function save(mutate, message = "Settings saved locally.") {
  const next = S.normalize(state.settings);
  mutate(next);
  await S.save(next, api);
  state.settings = next;
  render();
  setStatus(message);
}

$("enabled").addEventListener("change", e => save(s => (s.enabled = e.target.checked)));
$("reviewAll").addEventListener("change", e => save(s => (s.reviewAll = e.target.checked)));
$("strictMode").addEventListener("change", e => save(s => (s.strictMode = e.target.checked)));

$("siteEnabled").addEventListener("change", async e => {
  if (!host) return;
  const on = e.target.checked;
  const supported = SUPPORTED.some(re => re.test(host));
  if (on && !supported && !state.settings.customSites.includes(host)) {
    // Must be requested directly from the click handler (user gesture).
    let granted = false;
    try {
      granted = await api.permissions.request({ origins: [`*://${host}/*`] });
    } catch {
      granted = false;
    }
    if (!granted) {
      e.target.checked = false;
      setStatus("Permission was not granted.", true);
      return;
    }
    await save(s => {
      s.customSites = [...new Set([...s.customSites, host])];
      s.disabledSites = s.disabledSites.filter(h => h !== host);
    }, "Site added. Reload the tab to start protection.");
    return;
  }
  await save(
    s => {
      s.disabledSites = on ? s.disabledSites.filter(h => h !== host) : [...new Set([...s.disabledSites, host])];
    },
    on ? "Protection on for this site." : "Protection off for this site."
  );
});

$("openOptions").addEventListener("click", () => api.runtime.openOptionsPage());

(async () => {
  host = await currentHost();
  try {
    state = await S.load(api, { managed: false }); // fast first paint
    render();
    renderStats();
    state = await S.load(api); // then apply organization policy, if any
  } catch {
    setStatus("Could not load settings.", true);
  }
  render();
})();
