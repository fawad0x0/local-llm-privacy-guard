/* Content script: intercepts every way text/files leave the composer and routes them through the scanner. */
(() => {
  const PG = globalThis.PrivacyGuard;
  if (!PG || PG.__contentLoaded) return;
  PG.__contentLoaded = true;

  const api = globalThis.browser ?? globalThis.chrome;
  const V = PG.validators;
  const host = location.hostname;
  const isTop = window === window.top;
  const adapter = PG.adapters.forHost(host);
  const registry = PG.tokens.createRegistry(); // token -> real value, memory only, this page only

  let settings = PG.Settings.normalize({});
  let allowOnce = null; // { hash, until } lets one reviewed text through
  let busy = false;
  const pendingFileInputs = new WeakSet();

  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const active = () => settings.enabled && !settings.disabledSites.includes(host);
  const scanOpts = () => ({ settings, registry });
  const bypassing = () => PG.adapters.bypass > 0;

  function stop(e) {
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();
  }

  function allow(text, ms = 4000) {
    allowOnce = { hash: V.hash(text), until: Date.now() + ms };
  }

  function isAllowed(text) {
    return !!allowOnce && allowOnce.hash === V.hash(text) && Date.now() < allowOnce.until;
  }

  function report(result, action) {
    const n = result ? result.findings.filter(f => f.redact).length : 0;
    try {
      const p = api.runtime.sendMessage({ type: "pg:count", host, items: n, action });
      if (p && p.catch) p.catch(() => {});
    } catch {
      /* extension reloaded */
    }
  }

  function noteToast(result) {
    const labels = [...new Set(result.findings.map(f => f.label.replace(/_/g, " ").toLowerCase()))]
      .slice(0, 4)
      .join(", ");
    PG.ui.toast(
      `Privacy Guard noted ${result.findings.length} low-risk item(s): ${labels}. Sent unchanged.`,
      "info",
      4000
    );
  }

  let settingsLoaded = false;
  function renderBadge() {
    if (!isTop || !settingsLoaded || document.readyState === "loading") return;
    PG.ui.badge(
      active() && settings.showBadge,
      `Privacy Guard: ${adapter.generic ? "local scanning" : adapter.name + " protected"}`
    );
  }

  async function refreshSettings() {
    try {
      // Local settings first so protection is configured immediately, then organization policy.
      settings = (await PG.Settings.load(api, { managed: false })).settings;
      settingsLoaded = true;
      renderBadge();
      settings = (await PG.Settings.load(api)).settings;
    } catch {
      /* keep previous settings */
    }
    settingsLoaded = true;
    renderBadge();
  }

  // ---------------- Local AI (optional, opt-in, localhost only) ----------------
  async function aiExtra(text) {
    if (!settings.localAi.enabled) return [];
    try {
      const res = await api.runtime.sendMessage({ type: "pg:ai", text });
      if (!res || !res.ok) {
        if (res && res.error) PG.ui.toast(`Local AI check skipped: ${res.error}`, "warn", 4000);
        return [];
      }
      return res.entities.map(e => ({
        value: e.text,
        label: e.type,
        severity: "medium",
        reason: `Local AI: possible ${String(e.type).toLowerCase()}`
      }));
    } catch {
      return [];
    }
  }

  // ---------------- Sending ----------------
  async function triggerSend(editor, info) {
    await sleep(80);
    if (info.kind === "submit" && info.form && info.form.isConnected) {
      if (info.form.requestSubmit) info.form.requestSubmit();
      else info.form.submit();
      return true;
    }
    for (let i = 0; i < 12; i++) {
      const btn = info.button && info.button.isConnected ? info.button : adapter.findSendButton(editor);
      if (btn && !btn.disabled && btn.getAttribute("aria-disabled") !== "true") {
        btn.click();
        return true;
      }
      await sleep(80);
    }
    if (editor && editor.isConnected) {
      editor.focus();
      editor.dispatchEvent(
        new KeyboardEvent("keydown", {
          key: "Enter",
          code: "Enter",
          keyCode: 13,
          which: 13,
          bubbles: true,
          cancelable: true,
          composed: true
        })
      );
      await sleep(400);
      if ((adapter.readText(editor) || "").trim()) PG.ui.toast("Reviewed. Press Send to submit your message.", "info");
    }
    return false;
  }

  async function copyFallback(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      return false;
    }
  }

  async function reviewSend(result, editor, info) {
    busy = true;
    let decision;
    try {
      decision = await PG.ui.review({
        mode: "send",
        result,
        policy: settings.policy,
        rescan: t => PG.scan(t, scanOpts())
      });
    } finally {
      busy = false;
    }
    if (decision.action === "cancel") {
      report(result, "cancelled");
      editor.focus();
      return;
    }
    if (decision.action === "original") {
      report(result, "overridden");
      allow(result.original);
      await triggerSend(editor, info);
      return;
    }
    const ok = await adapter.writeText(editor, decision.text);
    if (!ok) {
      const copied = await copyFallback(decision.text);
      PG.ui.toast(
        settings.strictMode
          ? "Strict mode: the message box could not be updated safely, so nothing was sent." +
              (copied ? " The sanitized text is on your clipboard." : "")
          : "Could not update the message box safely." +
              (copied ? " The sanitized text is on your clipboard: paste it and send." : " Please edit it manually."),
        "error",
        8000
      );
      return;
    }
    report(result, "redacted");
    allow(adapter.readText(editor) || decision.text);
    updateReveal();
    await triggerSend(editor, info);
  }

  async function handleSend(event, editor, info) {
    if (!active() || bypassing()) return;
    if (!editor) {
      if (settings.strictMode && info.kind === "click") {
        stop(event);
        PG.ui.toast("Strict mode: Privacy Guard could not find the message box, so sending was blocked.", "error");
      }
      return;
    }
    const text = adapter.readText(editor);
    if (text == null) {
      if (settings.strictMode) {
        stop(event);
        PG.ui.toast("Strict mode: the message box could not be inspected, so sending was blocked.", "error");
      }
      return;
    }
    if (!text.trim()) return;
    if (isAllowed(text)) return;
    if (busy) {
      stop(event);
      return;
    }

    const result = PG.scan(text, scanOpts());
    if (settings.localAi.enabled) {
      // The model is async, so hold this attempt and resend once the check finishes.
      stop(event);
      busy = true;
      PG.ui.toast("Privacy Guard: checking with your local AI model…", "info", 2500);
      let final = result;
      try {
        const extra = await aiExtra(text);
        if (extra.length) final = PG.scan(text, { ...scanOpts(), extra });
      } finally {
        busy = false;
      }
      const action = PG.actionFor(final, settings.policy);
      if ((action === "off" || action === "note") && !settings.reviewAll) {
        if (action === "note") noteToast(final);
        allow(text);
        await triggerSend(editor, info);
        return;
      }
      await reviewSend(final, editor, info);
      return;
    }

    const action = PG.actionFor(result, settings.policy);
    if (!settings.reviewAll) {
      if (action === "off") return;
      if (action === "note") {
        noteToast(result);
        report(result, "noted");
        return;
      }
    }
    stop(event);
    await reviewSend(result, editor, info);
  }

  // Enter (and Ctrl/Cmd+Enter) in a composer.
  window.addEventListener(
    "keydown",
    event => {
      if (event.key !== "Enter" || event.shiftKey || event.isComposing || event.altKey) return;
      if (PG.ui.isOwnEvent(event)) return;
      const editor = adapter.editorFromEvent(event);
      if (!editor) return;
      // Generic sites: a plain textarea Enter is usually a newline, not a send.
      if (adapter.generic && editor instanceof HTMLTextAreaElement && !event.ctrlKey && !event.metaKey) return;
      handleSend(event, editor, { kind: "enter" });
    },
    true
  );

  // Send-button clicks.
  window.addEventListener(
    "click",
    event => {
      if (PG.ui.isOwnEvent(event)) return;
      const button = adapter.buttonFromEvent(event);
      if (!button || !adapter.isSendButton(button)) return;
      handleSend(event, adapter.findEditor(button), { kind: "click", button });
    },
    true
  );

  // Form submissions.
  window.addEventListener(
    "submit",
    event => {
      const form = event.target;
      if (!(form instanceof HTMLFormElement)) return;
      const editors = [...form.querySelectorAll(PG.adapters.EDITABLE)].filter(adapter.isEditable);
      const editor = editors.find(e => (adapter.readText(e) || "").trim()) || null;
      if (editor) handleSend(event, editor, { kind: "submit", form });
    },
    true
  );

  // ---------------- Paste / drop of text ----------------
  async function reviewInsert(event, editor, text) {
    const result = PG.scan(text, scanOpts());
    const action = PG.actionFor(result, settings.policy);
    if (action === "off") return;
    if (action === "note") {
      noteToast(result);
      return;
    }
    stop(event);
    const saved = adapter.saveSelection(editor);
    busy = true;
    let decision;
    try {
      decision = await PG.ui.review({
        mode: "paste",
        result,
        policy: settings.policy,
        rescan: t => PG.scan(t, scanOpts())
      });
    } finally {
      busy = false;
    }
    if (decision.action === "cancel") {
      report(result, "cancelled");
      return;
    }
    adapter.restoreSelection(editor, saved);
    adapter.insertText(editor, decision.action === "original" ? text : decision.text);
    report(result, decision.action === "original" ? "overridden" : "redacted");
    if (decision.action === "sanitized") updateReveal();
  }

  window.addEventListener(
    "paste",
    event => {
      if (!active() || bypassing() || PG.ui.isOwnEvent(event)) return;
      const editor = adapter.editorFromEvent(event);
      if (!editor || !event.clipboardData) return;
      const files = [...(event.clipboardData.files || [])];
      if (files.length) {
        if (settings.scanFiles) interceptFiles(event, files, { kind: "paste", target: event.target });
        return;
      }
      if (!settings.scanPaste) return;
      const text = event.clipboardData.getData("text/plain");
      if (text && text.trim()) reviewInsert(event, editor, text);
    },
    true
  );

  window.addEventListener(
    "drop",
    event => {
      if (!active() || bypassing() || PG.ui.isOwnEvent(event) || !event.dataTransfer) return;
      const files = [...(event.dataTransfer.files || [])];
      if (files.length) {
        if (settings.scanFiles)
          interceptFiles(event, files, { kind: "drop", target: event.target, x: event.clientX, y: event.clientY });
        return;
      }
      if (!settings.scanPaste) return;
      const editor = adapter.editorFromEvent(event);
      const text = event.dataTransfer.getData("text/plain");
      if (editor && text && text.trim()) reviewInsert(event, editor, text);
    },
    true
  );

  // ---------------- Files ----------------
  function deliverFiles(files, ctx) {
    const dt = new DataTransfer();
    for (const f of files) dt.items.add(f);
    PG.adapters.bypass++;
    try {
      if (ctx.kind === "change") {
        ctx.input.files = dt.files;
        ctx.input.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
        ctx.input.dispatchEvent(new Event("change", { bubbles: true }));
        return;
      }
      let handled = false;
      if (ctx.target && ctx.target.isConnected) {
        if (ctx.kind === "drop") {
          for (const type of ["dragenter", "dragover", "drop"]) {
            const ev = new DragEvent(type, {
              bubbles: true,
              cancelable: true,
              composed: true,
              dataTransfer: dt,
              clientX: ctx.x,
              clientY: ctx.y
            });
            ctx.target.dispatchEvent(ev);
            if (type === "drop") handled = ev.defaultPrevented;
          }
        } else {
          const ev = new ClipboardEvent("paste", {
            bubbles: true,
            cancelable: true,
            composed: true,
            clipboardData: dt
          });
          ctx.target.dispatchEvent(ev);
          handled = ev.defaultPrevented;
        }
      }
      if (!handled) {
        const input = adapter.findFileInput();
        if (input) {
          input.files = dt.files;
          input.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
          input.dispatchEvent(new Event("change", { bubbles: true }));
        } else {
          PG.ui.toast(
            "Files were checked, but this site did not accept them automatically. Please attach them again.",
            "warn"
          );
        }
      }
    } finally {
      PG.adapters.bypass--;
    }
  }

  function clearInput(ctx) {
    if (ctx.kind === "change" && ctx.input) ctx.input.value = "";
  }

  async function interceptFiles(event, files, ctx) {
    stop(event);
    if (busy) return;
    busy = true;
    let analysis;
    try {
      analysis = await PG.files.analyze(files, scanOpts());
    } catch {
      busy = false;
      PG.ui.toast("Privacy Guard could not check these files, so they were not attached.", "error");
      clearInput(ctx);
      return;
    }
    const action = PG.files.actionFor(analysis, settings.policy);
    if (action === "off" || action === "note") {
      busy = false;
      if (action === "note") PG.ui.toast("Privacy Guard noted low-risk items in the attached file(s).", "info", 3500);
      if (ctx.input) pendingFileInputs.delete(ctx.input);
      deliverFiles(files, ctx);
      return;
    }
    let decision;
    try {
      decision = await PG.ui.review({ mode: "file", files: analysis, policy: settings.policy });
    } finally {
      busy = false;
      if (ctx.input) pendingFileInputs.delete(ctx.input);
    }
    const fake = { findings: analysis.flatMap(a => (a.result ? a.result.findings : [])) };
    if (decision.action === "cancel") {
      clearInput(ctx);
      report(fake, "cancelled");
      return;
    }
    let out = files;
    if (decision.action === "sanitized") {
      out = analysis
        .map(a => (a.sanitizedFile ? a.sanitizedFile : a.flagged && a.blocked ? null : a.file))
        .filter(Boolean);
      report(fake, "redacted");
      updateReveal();
    } else if (decision.action === "remove") {
      out = analysis.filter(a => !a.flagged).map(a => a.file);
      report(fake, "removed");
    } else report(fake, "overridden");
    if (!out.length) {
      clearInput(ctx);
      PG.ui.toast("No files were attached.", "info", 3000);
      return;
    }
    deliverFiles(out, ctx);
  }

  function onFileInput(event) {
    const input = event.target;
    if (!(input instanceof HTMLInputElement) || input.type !== "file") return;
    if (bypassing() || !active() || !settings.scanFiles) return;
    if (pendingFileInputs.has(input)) {
      stop(event);
      return;
    }
    const files = [...(input.files || [])];
    if (!files.length) return;
    pendingFileInputs.add(input);
    interceptFiles(event, files, { kind: "change", input });
  }
  window.addEventListener("input", onFileInput, true);
  window.addEventListener("change", onFileInput, true);

  // ---------------- Reveal real values in AI replies (this screen only) ----------------
  let revealOn = false;
  let revealed = [];
  let observer = null;
  const TOKEN_TEST = /\[[A-Z][A-Z0-9_]*_\d+\]/;

  function revealIn(root) {
    if (!root) return;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode(n) {
        if (!TOKEN_TEST.test(n.nodeValue)) return NodeFilter.FILTER_REJECT;
        const p = n.parentElement;
        if (!p || p.closest("[contenteditable], textarea, input, script, style, [data-privacy-guard]"))
          return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      }
    });
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    for (const n of nodes) {
      const original = n.nodeValue;
      const next = original.replace(PG.tokens.TOKEN_RE, t => registry.byToken.get(t) ?? t);
      if (next !== original) {
        n.nodeValue = next;
        revealed.push({ node: n, original, next });
      }
    }
  }

  function setReveal(on) {
    revealOn = on;
    if (on) {
      revealIn(document.body);
      observer = new MutationObserver(muts => {
        for (const m of muts) {
          if (m.type === "characterData") revealIn(m.target.parentNode);
          for (const n of m.addedNodes) revealIn(n.nodeType === 3 ? n.parentNode : n);
        }
      });
      observer.observe(document.body, { childList: true, subtree: true, characterData: true });
    } else {
      if (observer) observer.disconnect();
      observer = null;
      for (const r of revealed) if (r.node.isConnected && r.node.nodeValue === r.next) r.node.nodeValue = r.original;
      revealed = [];
    }
    updateReveal();
  }

  function updateReveal() {
    if (!isTop) return;
    const count = registry.byToken.size;
    PG.ui.revealButton(count ? { count, on: revealOn, onToggle: () => setReveal(!revealOn) } : null);
  }

  // ---------------- Init ----------------
  document.addEventListener(
    "focusin",
    e => {
      const ed = adapter.editorFromEvent(e);
      if (ed) adapter.lastEditor = ed;
    },
    true
  );

  api.storage.onChanged.addListener((changes, area) => {
    if (area === "local" || area === "managed") refreshSettings();
  });
  refreshSettings();
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", renderBadge, { once: true });
})();
