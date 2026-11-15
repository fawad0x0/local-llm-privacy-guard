/* Review dialog, toasts, badge and reveal button. All UI lives in closed shadow roots so page CSS
 * cannot restyle or hide it, and page scripts cannot read it. Text is inserted with textContent only. */
(() => {
  const PG = (globalThis.PrivacyGuard = globalThis.PrivacyGuard || {});
  if (PG.ui) return;

  const hosts = new WeakSet();
  const SEV_ORDER = ["critical", "high", "medium", "low"];
  const CATEGORY_NAMES = {
    pii: "Personal data",
    credential: "Credentials & tokens",
    cloud_secret: "Cloud secrets",
    env: "Environment variables",
    config: "Configuration secrets",
    log: "Logs & error details",
    network: "Network identifiers",
    custom: "Your custom rules",
    ai: "Local AI findings"
  };

  const CSS = `
    :host { all: initial; }
    * { box-sizing: border-box; }
    .wrap { --bg:#ffffff; --fg:#17202a; --muted:#5f6b76; --line:#d6dde4; --soft:#f3f6f8; --accent:#176b55; --accent-fg:#fff;
      --crit:#b42318; --high:#c4320a; --med:#a15c07; --low:#4b5563; --mark:#fde68a; --banner:#fff4e5; --banner-fg:#7a4100;
      font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--fg); }
    @media (prefers-color-scheme: dark) {
      .wrap { --bg:#1b2026; --fg:#e6ebf0; --muted:#a3adb8; --line:#36404a; --soft:#242b33; --accent:#3fb38f; --accent-fg:#0b1a14;
        --crit:#ff6b5e; --high:#ff8a4c; --med:#f0b44c; --low:#a3adb8; --mark:#7a5d00; --banner:#3a2a10; --banner-fg:#ffd59a; }
    }
    .backdrop { position: fixed; inset: 0; background: rgba(0,0,0,.35); z-index: 2147483646; }
    .dialog { position: fixed; z-index: 2147483647; right: 16px; bottom: 16px; width: min(560px, calc(100vw - 32px));
      max-height: min(86vh, 900px); display: flex; flex-direction: column; background: var(--bg); color: var(--fg);
      border: 1px solid var(--line); border-radius: 12px; box-shadow: 0 16px 48px rgba(0,0,0,.3); }
    header { padding: 14px 16px 8px; display: flex; gap: 10px; align-items: center; }
    h2 { margin: 0; font-size: 15px; font-weight: 650; flex: 1; }
    .body { padding: 0 16px; overflow: auto; flex: 1; }
    footer { padding: 12px 16px 14px; display: flex; flex-wrap: wrap; gap: 8px; justify-content: flex-end; border-top: 1px solid var(--line); }
    .pill { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; padding: 2px 8px; border-radius: 999px; color: #fff; }
    .sev-critical { background: var(--crit); } .sev-high { background: var(--high); } .sev-medium { background: var(--med); } .sev-low { background: var(--low); }
    .banner { background: var(--banner); color: var(--banner-fg); border-radius: 8px; padding: 8px 10px; margin: 6px 0; font-weight: 600; }
    .muted { color: var(--muted); font-size: 12.5px; margin: 6px 0; }
    .group { margin: 10px 0 4px; font-size: 12px; font-weight: 700; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
    .row { display: flex; align-items: flex-start; gap: 8px; padding: 6px 8px; border-radius: 8px; }
    .row:hover { background: var(--soft); }
    .row input { margin-top: 3px; accent-color: var(--accent); }
    .dot { width: 9px; height: 9px; border-radius: 50%; margin-top: 6px; flex: none; }
    .row .what { flex: 1; min-width: 0; }
    .row .label { font-weight: 600; }
    .row .reason { color: var(--muted); font-size: 12.5px; }
    .row code { font: 12px ui-monospace, Consolas, monospace; background: var(--soft); padding: 1px 5px; border-radius: 4px; word-break: break-all; }
    details { margin: 10px 0; }
    summary { cursor: pointer; color: var(--muted); font-size: 12.5px; }
    pre { white-space: pre-wrap; word-break: break-word; font: 12px/1.5 ui-monospace, Consolas, monospace; background: var(--soft);
      border: 1px solid var(--line); border-radius: 8px; padding: 8px; max-height: 180px; overflow: auto; margin: 6px 0 0; }
    mark { background: var(--mark); color: inherit; border-radius: 3px; padding: 0 1px; }
    textarea { width: 100%; min-height: 120px; max-height: 260px; resize: vertical; font: 12.5px/1.5 ui-monospace, Consolas, monospace;
      color: var(--fg); background: var(--bg); border: 1px solid var(--line); border-radius: 8px; padding: 8px; }
    label.lbl { display: block; font-size: 12px; font-weight: 600; color: var(--muted); margin: 10px 0 4px; }
    .confirm { display: none; margin: 10px 0 0; gap: 8px; align-items: center; flex-wrap: wrap; }
    .confirm.show { display: flex; }
    .confirm input { font: inherit; padding: 6px 8px; border: 1px solid var(--line); border-radius: 6px; width: 120px; background: var(--bg); color: var(--fg); }
    .warn { color: var(--crit); font-size: 12.5px; font-weight: 600; }
    button { font: inherit; font-size: 13px; cursor: pointer; border-radius: 8px; padding: 8px 12px; border: 1px solid var(--line);
      background: var(--bg); color: var(--fg); }
    button:hover { background: var(--soft); }
    button.primary { background: var(--accent); color: var(--accent-fg); border-color: var(--accent); font-weight: 650; }
    button.primary:hover { filter: brightness(1.05); }
    button:disabled { opacity: .45; cursor: not-allowed; }
    button:focus-visible, input:focus-visible, textarea:focus-visible, summary:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .file { padding: 8px; border: 1px solid var(--line); border-radius: 8px; margin: 6px 0; }
    .file .name { font-weight: 600; word-break: break-all; }
    .toast { position: fixed; right: 16px; bottom: 16px; z-index: 2147483647; max-width: min(420px, calc(100vw - 32px));
      background: var(--bg); color: var(--fg); border: 1px solid var(--line); border-left: 4px solid var(--accent); border-radius: 8px;
      padding: 10px 14px; box-shadow: 0 6px 24px rgba(0,0,0,.2); font-size: 13px; }
    .toast.error { border-left-color: var(--crit); } .toast.warn { border-left-color: var(--med); }
    .badge { position: fixed; left: 8px; bottom: 8px; z-index: 2147483000; background: #17202a; color: #fff; padding: 4px 8px;
      border-radius: 6px; font-size: 11px; opacity: .8; pointer-events: none; }
    .reveal { position: fixed; right: 16px; top: 72px; z-index: 2147483000; font-size: 12px; padding: 6px 10px; box-shadow: 0 4px 16px rgba(0,0,0,.15); }
  `;

  function el(tag, props = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (v == null || v === false) continue;
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
      else if (k in node && typeof v !== "string") node[k] = v;
      else node.setAttribute(k, v === true ? "" : v);
    }
    for (const c of children.flat())
      if (c != null) node.append(c instanceof Node ? c : document.createTextNode(String(c)));
    return node;
  }

  function mount(kind) {
    const host = document.createElement("privacy-guard-ui");
    host.setAttribute("data-privacy-guard", kind || "ui");
    const root = host.attachShadow({ mode: "closed" });
    root.append(el("style", { text: CSS }));
    const wrap = el("div", { class: "wrap" });
    root.append(wrap);
    // Keep keystrokes typed in our UI away from page shortcuts.
    for (const t of ["keydown", "keyup", "keypress", "input", "beforeinput", "paste", "copy", "cut"]) {
      host.addEventListener(t, e => e.stopPropagation());
    }
    (document.body || document.documentElement).append(host);
    hosts.add(host);
    return { host, root, wrap };
  }

  function isOwnEvent(event) {
    const path = event.composedPath ? event.composedPath() : [event.target];
    return path.some(n => hosts.has(n));
  }

  function mask(v) {
    const s = String(v).replace(/\s+/g, " ");
    if (s.length <= 6) return "•".repeat(Math.max(3, s.length));
    return s.slice(0, 3) + "•".repeat(Math.min(10, s.length - 5)) + s.slice(-2);
  }

  function highlighted(text, findings) {
    const pre = el("pre");
    let last = 0;
    const MAX = 20000;
    for (const f of findings) {
      if (f.start >= MAX) break;
      pre.append(text.slice(last, f.start));
      pre.append(el("mark", { title: f.reason, text: text.slice(f.start, f.end) }));
      last = f.end;
    }
    pre.append(text.slice(last, MAX));
    if (text.length > MAX) pre.append("\n… (truncated)");
    return pre;
  }

  function focusTrap(root, dialog, onEscape) {
    dialog.addEventListener("keydown", e => {
      if (e.key === "Escape") {
        e.preventDefault();
        onEscape();
        return;
      }
      if (e.key !== "Tab") return;
      const items = [...dialog.querySelectorAll("button, input, textarea, summary, [tabindex]")].filter(
        x => !x.disabled && x.offsetParent !== null
      );
      if (!items.length) return;
      const first = items[0];
      const last = items[items.length - 1];
      const active = root.activeElement;
      if (e.shiftKey && active === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && active === last) {
        e.preventDefault();
        first.focus();
      }
    });
  }

  function findingRows(findings, selected, onChange) {
    const frag = document.createDocumentFragment();
    const byCat = new Map();
    for (const f of findings) {
      if (!byCat.has(f.category)) byCat.set(f.category, []);
      byCat.get(f.category).push(f);
    }
    const cats = [...byCat.keys()].sort((a, b) => {
      const sa = Math.min(...byCat.get(a).map(f => SEV_ORDER.indexOf(f.severity)));
      const sb = Math.min(...byCat.get(b).map(f => SEV_ORDER.indexOf(f.severity)));
      return sa - sb;
    });
    for (const cat of cats) {
      frag.append(el("div", { class: "group", text: CATEGORY_NAMES[cat] || cat }));
      for (const f of byCat.get(cat)) {
        const id = "pg-f-" + f.id;
        const box = el("input", { type: "checkbox", id, checked: selected.has(f.id) });
        box.addEventListener("change", () => {
          if (box.checked) selected.add(f.id);
          else selected.delete(f.id);
          onChange();
        });
        frag.append(
          el(
            "label",
            { class: "row", for: id },
            box,
            el("span", { class: "dot sev-" + f.severity, title: f.severity }),
            el(
              "span",
              { class: "what" },
              el("span", { class: "label", text: f.label.replace(/_/g, " ") + " " }),
              el("code", { text: mask(f.value) }),
              el("div", { class: "reason", text: `${f.reason} · ${f.severity}${selected.has(f.id) ? "" : ""}` })
            )
          )
        );
      }
    }
    return frag;
  }

  let open = null;

  /**
   * Show the review dialog.
   * opts.mode: "send" | "paste" | "file"
   * opts.result: scan result (send/paste); opts.files: analyzed files (file)
   * opts.policy: settings.policy; opts.rescan(text) -> scan result for manually edited text
   * Resolves { action: "sanitized"|"original"|"remove"|"cancel", text? }
   */
  function review(opts) {
    if (open) open.close({ action: "cancel" });
    return new Promise(resolve => {
      const { host, root, wrap } = mount("dialog");
      const previousFocus = document.activeElement;
      let done = false;
      const close = value => {
        if (done) return;
        done = true;
        host.remove();
        open = null;
        try {
          previousFocus && previousFocus.focus && previousFocus.focus();
        } catch {
          /* element gone */
        }
        resolve(value);
      };
      open = { close };

      const dialog = el("section", {
        class: "dialog",
        role: "dialog",
        "aria-modal": "true",
        "aria-labelledby": "pg-title"
      });
      const backdrop = el("div", { class: "backdrop", onclick: () => close({ action: "cancel" }) });
      wrap.append(backdrop, dialog);
      focusTrap(root, dialog, () => close({ action: "cancel" }));

      if (opts.mode === "file") buildFileDialog(dialog, opts, close);
      else buildTextDialog(dialog, opts, close);

      const primary = dialog.querySelector("button.primary:not([disabled])") || dialog.querySelector("button");
      setTimeout(() => primary && primary.focus(), 0);
    });
  }

  function buildTextDialog(dialog, opts, close) {
    const { result, policy, mode } = opts;
    const findings = result.findings;
    const selected = new Set(findings.filter(f => f.redact).map(f => f.id));
    const sev = result.maxSeverity;
    const n = findings.length;

    const title = n
      ? `Privacy Guard found ${n} sensitive item${n === 1 ? "" : "s"}`
      : mode === "paste"
        ? "Review pasted text"
        : "Review before sending";
    dialog.append(
      el(
        "header",
        {},
        el("h2", { id: "pg-title", text: title }),
        sev ? el("span", { class: "pill sev-" + sev, text: sev }) : null
      )
    );

    const body = el("div", { class: "body" });
    dialog.append(body);
    for (const b of result.blocks.filter(x => x.active)) body.append(el("div", { class: "banner", text: b.label }));
    if (!n)
      body.append(el("p", { class: "muted", text: "No known pattern matched. That does not prove the text is safe." }));
    else
      body.append(
        el("p", {
          class: "muted",
          text: "Checked items will be replaced with placeholders. Uncheck anything that is safe to share."
        })
      );

    const preview = el("textarea", { "aria-label": "Sanitized text preview", spellcheck: "false" });
    let edited = false;
    preview.value = result.text;
    preview.addEventListener("input", () => {
      edited = true;
      updateState();
    });

    if (n) {
      body.append(
        findingRows(findings, selected, () => {
          preview.value = PG.applyRedactions(result.original, findings, f => selected.has(f.id));
          edited = false;
          updateState();
        })
      );
      const det = el("details", {}, el("summary", { text: "Show original with highlights" }));
      det.addEventListener(
        "toggle",
        () => {
          if (det.open && !det.querySelector("pre")) det.append(highlighted(result.original, findings));
        },
        { once: false }
      );
      body.append(det);
    }
    body.append(
      el("label", { class: "lbl", text: mode === "paste" ? "Text that will be pasted" : "Text that will be sent" }),
      preview
    );

    const warn = el("div", { class: "warn" });
    const confirmInput = el("input", {
      type: "text",
      "aria-label": "Type SEND to confirm",
      placeholder: "SEND",
      autocomplete: "off"
    });
    const confirmRow = el(
      "div",
      { class: "confirm" },
      el("span", { class: "warn", text: "This includes items your policy blocks. Type SEND to override:" }),
      confirmInput
    );
    body.append(
      warn,
      confirmRow,
      el("p", { class: "muted", text: "Scanning is local and heuristic. It can miss sensitive data." })
    );

    const verb = mode === "paste" ? "Paste" : "Send";
    const btnCancel = el("button", { text: "Cancel", onclick: () => close({ action: "cancel" }) });
    const btnOriginal = el("button", { text: n ? `${verb} original anyway` : verb });
    const btnSanitized = el("button", { class: "primary", text: `${verb} sanitized` });
    const footer = el("footer", {}, btnCancel, btnOriginal);
    if (n) footer.append(btnSanitized);
    else btnOriginal.className = "primary";
    dialog.append(footer);

    const kept = () => findings.filter(f => !selected.has(f.id));
    const confirmed = () => confirmInput.value.trim().toUpperCase() === "SEND";
    let editedResult = null;

    function needsConfirmFor(which) {
      if (which === "original") return PG.actionFor(result, policy, findings) === "block";
      if (edited) {
        editedResult = opts.rescan ? opts.rescan(preview.value) : null;
        return !!editedResult && PG.actionFor(editedResult, policy) === "block";
      }
      return kept().length > 0 && PG.actionFor({ blocks: [] }, policy, kept()) === "block";
    }

    function updateState() {
      const origNeeds = needsConfirmFor("original");
      const sanNeeds = n ? needsConfirmFor("sanitized") : false;
      confirmRow.classList.toggle("show", (origNeeds || sanNeeds) && true);
      btnOriginal.disabled = origNeeds && !confirmed();
      btnSanitized.disabled = sanNeeds && !confirmed();
      warn.textContent = edited && sanNeeds ? "Your edited text still contains blocked items." : "";
    }
    confirmInput.addEventListener("input", updateState);
    btnOriginal.addEventListener("click", () => close({ action: "original", text: result.original }));
    btnSanitized.addEventListener("click", () => close({ action: "sanitized", text: preview.value }));
    updateState();
  }

  function buildFileDialog(dialog, opts, close) {
    const { files, policy } = opts;
    const flagged = files.filter(f => f.flagged);
    const sev = PG.maxSeverity(files.map(f => f.severity));
    dialog.append(
      el(
        "header",
        {},
        el("h2", {
          id: "pg-title",
          text: `Privacy Guard: ${flagged.length} of ${files.length} file${files.length === 1 ? "" : "s"} need review`
        }),
        sev ? el("span", { class: "pill sev-" + sev, text: sev }) : null
      )
    );
    const body = el("div", { class: "body" });
    dialog.append(body);
    for (const f of files) {
      const lines = [];
      if (f.blocked) lines.push(`Blocked file type: ${f.blocked}`);
      if (f.result) {
        for (const b of f.result.blocks.filter(x => x.active)) lines.push(b.label);
        if (f.result.findings.length) {
          const labels = [...new Set(f.result.findings.map(x => x.label.replace(/_/g, " ")))].slice(0, 8).join(", ");
          lines.push(`${f.result.findings.length} finding(s): ${labels}`);
        } else lines.push("No sensitive patterns found in contents");
      }
      if (f.skipped) lines.push(`Contents not scanned (${f.skipped})`);
      body.append(
        el(
          "div",
          { class: "file" },
          el(
            "div",
            {},
            f.severity ? el("span", { class: "pill sev-" + f.severity, text: f.severity }) : null,
            " ",
            el("span", { class: "name", text: f.name })
          ),
          ...lines.map(t => el("div", { class: "reason muted", text: t }))
        )
      );
    }
    const canSanitize = flagged.some(f => f.sanitizedFile);
    body.append(
      el("p", {
        class: "muted",
        text: canSanitize
          ? '"Upload sanitized copies" replaces secrets inside text files with placeholders and leaves out private-key and keystore files.'
          : "Flagged files cannot be sanitized automatically. You can remove them or upload anyway."
      })
    );

    const confirmInput = el("input", {
      type: "text",
      "aria-label": "Type SEND to confirm",
      placeholder: "SEND",
      autocomplete: "off"
    });
    const needsConfirm = PG.files.actionFor(files, policy) === "block";
    const confirmRow = el(
      "div",
      { class: "confirm" + (needsConfirm ? " show" : "") },
      el("span", { class: "warn", text: "Your policy blocks these files. Type SEND to upload them anyway:" }),
      confirmInput
    );
    body.append(confirmRow);

    const btnCancel = el("button", { text: "Cancel upload", onclick: () => close({ action: "cancel" }) });
    const btnOriginal = el("button", { text: "Upload anyway", disabled: needsConfirm });
    const btnRemove = el("button", { text: "Remove flagged files", onclick: () => close({ action: "remove" }) });
    const btnSanitized = el("button", {
      class: "primary",
      text: "Upload sanitized copies",
      onclick: () => close({ action: "sanitized" })
    });
    confirmInput.addEventListener("input", () => {
      btnOriginal.disabled = needsConfirm && confirmInput.value.trim().toUpperCase() !== "SEND";
    });
    btnOriginal.addEventListener("click", () => close({ action: "original" }));
    const footer = el("footer", {}, btnCancel, btnOriginal, btnRemove);
    if (canSanitize) footer.append(btnSanitized);
    else btnRemove.className = "primary";
    dialog.append(footer);
  }

  let toastTimer = null;
  let toastHost = null;
  function toast(message, kind = "info", ms = 5000) {
    if (toastHost) toastHost.host.remove();
    clearTimeout(toastTimer);
    toastHost = mount("toast");
    toastHost.wrap.append(el("div", { class: "toast " + kind, role: "status", text: message }));
    const h = toastHost;
    toastTimer = setTimeout(() => {
      h.host.remove();
      if (toastHost === h) toastHost = null;
    }, ms);
  }

  let badgeHost = null;
  function badge(show, text = "Privacy Guard: local scanning") {
    if (!show) {
      if (badgeHost) badgeHost.host.remove();
      badgeHost = null;
      return;
    }
    if (badgeHost) return;
    badgeHost = mount("badge");
    badgeHost.wrap.append(el("div", { class: "badge", text }));
  }

  let revealHost = null;
  function revealButton(state) {
    if (!state) {
      if (revealHost) revealHost.host.remove();
      revealHost = null;
      return;
    }
    if (!revealHost) revealHost = mount("reveal");
    revealHost.wrap.replaceChildren(
      el("button", {
        class: "reveal",
        text: state.on ? "Hide real values" : `Show real values (${state.count})`,
        title: "Replaces Privacy Guard placeholders in this page with the original values. Only on your screen.",
        onclick: state.onToggle
      })
    );
  }

  PG.ui = { review, toast, badge, revealButton, isOwnEvent, mask };
})();
