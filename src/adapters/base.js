/* Adapter base: finding, reading and writing chat composers. Site files only supply selectors. */
(() => {
  const PG = (globalThis.PrivacyGuard = globalThis.PrivacyGuard || {});
  if (PG.adapters) return;

  const EDITABLE =
    'textarea, input[type="text"], input[type="search"], input:not([type]), [contenteditable=""], [contenteditable="true"], [contenteditable="plaintext-only"], [role="textbox"]';
  const BUTTON = 'button, [role="button"], input[type="submit"], input[type="button"]';

  const isField = el =>
    el instanceof HTMLTextAreaElement || (el instanceof HTMLInputElement && /^(?:text|search|)$/.test(el.type));

  function isEditable(el) {
    if (!(el instanceof Element)) return false;
    if (el.closest("[data-privacy-guard]")) return false;
    if (isField(el)) return !el.readOnly && !el.disabled;
    return el.isContentEditable || el.getAttribute("role") === "textbox";
  }

  // Climb to the outermost contenteditable so we read/write the whole editor.
  function editorRoot(el) {
    let root = el;
    while (root.parentElement && root.parentElement.isContentEditable) root = root.parentElement;
    return root;
  }

  function editorFromEvent(event) {
    for (const n of event.composedPath ? event.composedPath() : [event.target]) {
      if (n instanceof Element && n.hasAttribute && n.hasAttribute("data-privacy-guard")) return null;
      if (n instanceof Element && isEditable(n)) return editorRoot(n);
    }
    return null;
  }

  function buttonFromEvent(event) {
    for (const n of event.composedPath ? event.composedPath() : [event.target]) {
      if (!(n instanceof Element)) continue;
      if (n.hasAttribute("data-privacy-guard")) return null;
      if (n.matches(BUTTON)) return n;
    }
    return null;
  }

  // querySelectorAll that also walks open shadow roots.
  function queryAllDeep(selector, root = document) {
    const out = [...root.querySelectorAll(selector)];
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
    let node = walker.currentNode;
    while (node) {
      if (node.shadowRoot) out.push(...queryAllDeep(selector, node.shadowRoot));
      node = walker.nextNode();
    }
    return out;
  }

  function visible(el) {
    if (!el || !el.isConnected) return false;
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  }

  function deepActiveElement() {
    let a = document.activeElement;
    while (a && a.shadowRoot && a.shadowRoot.activeElement) a = a.shadowRoot.activeElement;
    return a;
  }

  // Number of hops between two nodes through their closest common ancestor.
  function domDistance(a, b) {
    const chain = new Map();
    let n = a;
    let d = 0;
    while (n) {
      chain.set(n, d++);
      n = n.parentNode || n.host;
    }
    n = b;
    d = 0;
    while (n) {
      if (chain.has(n)) return chain.get(n) + d;
      n = n.parentNode || n.host;
      d++;
    }
    return Infinity;
  }

  function nearest(list, ref) {
    if (!ref) return list[0] || null;
    let best = null;
    let bestD = Infinity;
    for (const el of list) {
      const d = domDistance(el, ref);
      if (d < bestD) {
        best = el;
        bestD = d;
      }
    }
    return best;
  }

  function readText(el) {
    if (!el) return null;
    if (isField(el)) return el.value;
    if (el.isContentEditable || el.getAttribute("role") === "textbox") return el.innerText ?? el.textContent ?? "";
    return null;
  }

  const normalize = s =>
    String(s || "")
      .replace(/\r/g, "")
      .replace(/\u00a0/g, " ")
      .replace(/\n{2,}/g, "\n")
      .trim();

  function selectAll(el) {
    if (isField(el)) {
      el.select();
      return;
    }
    const range = document.createRange();
    range.selectNodeContents(el);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }

  // Insert text at the current caret/selection in a way rich editors (ProseMirror, Lexical,
  // Quill, React-controlled fields) observe, so their internal state stays in sync.
  function insertText(el, text) {
    el.focus();
    if (isField(el)) {
      const ok = document.execCommand && document.execCommand("insertText", false, text);
      if (!ok) {
        const s = el.selectionStart ?? el.value.length;
        const e = el.selectionEnd ?? el.value.length;
        const next = el.value.slice(0, s) + text + el.value.slice(e);
        const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), "value")?.set;
        if (setter) setter.call(el, next);
        else el.value = next;
        el.dispatchEvent(
          new InputEvent("input", { bubbles: true, composed: true, inputType: "insertText", data: text })
        );
      }
      return;
    }
    // 1) Synthetic paste: rich editors handle it and preventDefault.
    let handled = false;
    try {
      const dt = new DataTransfer();
      dt.setData("text/plain", text);
      const ev = new ClipboardEvent("paste", { clipboardData: dt, bubbles: true, cancelable: true, composed: true });
      PG.adapters.bypass++;
      try {
        el.dispatchEvent(ev);
      } finally {
        PG.adapters.bypass--;
      }
      handled = ev.defaultPrevented;
    } catch {
      handled = false;
    }
    if (handled) return;
    // 2) execCommand insertText (fires beforeinput/input).
    if (document.execCommand && document.execCommand("insertText", false, text)) return;
    // 3) Last resort: DOM insertion of a text node.
    const sel = window.getSelection();
    if (sel && sel.rangeCount) {
      const range = sel.getRangeAt(0);
      range.deleteContents();
      range.insertNode(document.createTextNode(text));
      range.collapse(false);
    } else {
      el.append(document.createTextNode(text));
    }
    el.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType: "insertText", data: text }));
  }

  // Replace the whole composer content and verify it actually changed.
  async function writeText(el, text) {
    if (!el || !el.isConnected) return false;
    if (isField(el)) {
      const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), "value")?.set;
      el.focus();
      if (setter) setter.call(el, text);
      else el.value = text;
      el.dispatchEvent(
        new InputEvent("input", { bubbles: true, composed: true, inputType: "insertReplacementText", data: text })
      );
      el.dispatchEvent(new Event("change", { bubbles: true }));
    } else {
      el.focus();
      selectAll(el);
      insertText(el, text);
    }
    await new Promise(r => setTimeout(r, 60));
    return normalize(readText(el)) === normalize(text);
  }

  function saveSelection(el) {
    if (isField(el)) return { field: true, start: el.selectionStart, end: el.selectionEnd };
    const sel = window.getSelection();
    return sel && sel.rangeCount ? { range: sel.getRangeAt(0).cloneRange() } : null;
  }

  function restoreSelection(el, saved) {
    el.focus();
    if (!saved) return;
    if (saved.field) {
      try {
        el.setSelectionRange(saved.start, saved.end);
      } catch {
        /* input type without selection support */
      }
      return;
    }
    if (saved.range) {
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(saved.range);
    }
  }

  function labelOf(btn) {
    return [
      btn.getAttribute("aria-label"),
      btn.getAttribute("title"),
      btn.getAttribute("data-testid"),
      btn.getAttribute("name"),
      btn.value,
      (btn.innerText || "").slice(0, 40)
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
  }

  const SEND_WORD = /\b(?:send|submit)\b/;
  const NOT_SEND = /\b(?:feedback|report|invite|share|e-?mail|code|verification|unsend|resend|cancel|stop)\b/;

  function makeAdapter(def) {
    const editorSel = def.editor || EDITABLE;
    const a = {
      id: def.id,
      name: def.name,
      hosts: def.hosts || [],
      generic: !!def.generic,
      matchesHost: host => a.hosts.some(re => re.test(host)),
      editorFromEvent,
      buttonFromEvent,
      readText,
      writeText,
      insertText,
      saveSelection,
      restoreSelection,
      isEditable,
      lastEditor: null,

      findEditor(near) {
        const active = deepActiveElement();
        if (active && isEditable(active) && (!def.editor || editorRoot(active).matches(def.editor)))
          return editorRoot(active);
        let list = queryAllDeep(editorSel).filter(visible).filter(isEditable);
        if (!list.length && def.editor) list = queryAllDeep(EDITABLE).filter(visible).filter(isEditable);
        if (!list.length) return null;
        if (near) return editorRoot(nearest(list, near));
        if (a.lastEditor && list.includes(a.lastEditor)) return a.lastEditor;
        return editorRoot(list[0]);
      },

      isSendButton(btn) {
        if (!btn) return false;
        if (def.send && btn.matches(def.send)) return true;
        const label = labelOf(btn);
        if (SEND_WORD.test(label) && !NOT_SEND.test(label)) return true;
        // Icon-only submit button inside the composer's form.
        const form = btn.closest("form");
        return !!(form && btn.type === "submit" && form.querySelector(EDITABLE));
      },

      findSendButton(editor) {
        let list = def.send ? queryAllDeep(def.send).filter(visible) : [];
        if (!list.length) {
          const scope =
            (editor && (editor.closest("form") || editor.parentElement?.parentElement?.parentElement)) || document;
          list = [...scope.querySelectorAll(BUTTON)].filter(visible).filter(b => a.isSendButton(b));
        }
        return nearest(list, editor);
      },

      findFileInput() {
        const sel = def.fileInput || 'input[type="file"]';
        return queryAllDeep(sel)[0] || null;
      }
    };
    return a;
  }

  const list = [];
  PG.adapters = {
    list,
    bypass: 0,
    EDITABLE,
    register: def => list.push(makeAdapter(def)),
    forHost(host) {
      return (
        list.find(a => !a.generic && a.matchesHost(host)) ||
        makeAdapter({ id: "generic", name: "Generic site", generic: true })
      );
    },
    normalize
  };
})();
