"use strict";
/* Komponen UI bersama. Semua teks dari lalu lintas disisipkan via textContent (anti-XSS). */
EX.ui = (() => {
  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else if (k === "value") el.value = v;
      else if (k === "checked") el.checked = !!v;
      else if (k === "dataset") Object.assign(el.dataset, v);
      else if (k === "style") Object.assign(el.style, v);
      else el.setAttribute(k, v === true ? "" : v);
    }
    for (const kid of kids.flat()) {
      if (kid === null || kid === undefined || kid === false) continue;
      el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
  const icon = (n) => EX.icons.svg(n);
  function btn(label, opts = {}) {
    const b = h("button", { class: "btn " + (opts.cls || ""), type: "button", title: opts.title, onclick: opts.onclick, disabled: opts.disabled });
    if (opts.icon) b.append(icon(opts.icon));
    if (label) b.append(document.createTextNode(label));
    return b;
  }
  function toast(msg, type = "") {
    const box = $("#toasts");
    const t = h("div", { class: "toast " + type, role: "status", text: msg });
    box.append(t);
    setTimeout(() => t.remove(), type === "err" ? 7000 : 3500);
  }
  const fail = (e) => toast(e && e.message ? e.message : String(e), "err");
  const debounce = (fn, ms = 250) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
  function bytes(n) {
    if (n === null || n === undefined) return "";
    if (n < 1024) return n + " B";
    if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
    return (n / 1048576).toFixed(2) + " MB";
  }
  const pad = (n) => String(n).padStart(2, "0");
  function time(ts, full) {
    const d = new Date(ts * 1000);
    const t = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    return full ? `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${t}` : t;
  }
  const ms = (v) => (v === null || v === undefined ? "" : v < 1000 ? Math.round(v) + " ms" : (v / 1000).toFixed(2) + " s");
  const sclass = (s) => "s" + (s ? Math.floor(s / 100) : 0) + "xx".slice(s ? 0 : 3);
  const statusEl = (s) => h("span", { class: s ? "s" + Math.floor(s / 100) + "xx" : "s0", text: s || "ERR" });
  function sev(s) { return h("span", { class: "sev " + s, text: s }); }
  async function copy(text) {
    try { await navigator.clipboard.writeText(text); toast("Disalin ke clipboard"); }
    catch (e) {
      const ta = h("textarea", { style: { position: "fixed", opacity: "0" } }); ta.value = text;
      document.body.append(ta); ta.select();
      try { document.execCommand("copy"); toast("Disalin ke clipboard"); } catch (e2) { toast("Gagal menyalin", "err"); }
      ta.remove();
    }
  }
  function saveText(text, name, type = "text/plain") {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const a = h("a", { href: url, download: name }); document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }
  /* dialog modal berbasis <dialog>; fields: [{name,label,type,value,options,placeholder,hint}] */
  function modal(title, fields, okLabel = "OK") {
    return new Promise((resolve) => {
      const inputs = {};
      const body = h("div", { class: "dbody" });
      for (const f of fields) {
        let inp;
        if (f.type === "select") inp = h("select", {}, f.options.map((o) => h("option", { value: o.value ?? o, text: o.label ?? o })));
        else if (f.type === "textarea") inp = h("textarea", { rows: f.rows || 5, placeholder: f.placeholder });
        else if (f.type === "checkbox") inp = h("input", { type: "checkbox" });
        else inp = h("input", { type: f.type || "text", placeholder: f.placeholder, autocomplete: "off" });
        if (f.type === "checkbox") inp.checked = !!f.value; else if (f.value !== undefined) inp.value = f.value;
        inputs[f.name] = inp;
        body.append(h("label", {}, f.type === "checkbox" ? [inp, f.label] : [f.label, inp, f.hint ? h("span", { class: "muted small", text: f.hint }) : null]));
      }
      const dlg = h("dialog", {});
      const done = (v) => { dlg.close(); dlg.remove(); resolve(v); };
      const form = h("form", { method: "dialog", onsubmit: (e) => {
        e.preventDefault();
        const out = {};
        for (const [k, el] of Object.entries(inputs)) out[k] = el.type === "checkbox" ? el.checked : el.value;
        done(out);
      } }, h("h3", { text: title }), body,
      h("div", { class: "dfoot" }, btn("Batal", { onclick: () => done(null) }), h("button", { class: "btn primary", type: "submit", text: okLabel })));
      dlg.append(form); dlg.addEventListener("cancel", () => done(null));
      document.body.append(dlg); dlg.showModal();
      const first = Object.values(inputs)[0]; if (first) first.focus();
    });
  }
  const confirmBox = async (msg, ok = "Ya") => !!(await modal(msg, [], ok));
  /* menu konteks */
  function ctxMenu(ev, items) {
    ev.preventDefault();
    const old = $("#ctxmenu"); if (old) old.remove();
    const m = h("div", { id: "ctxmenu", role: "menu" });
    for (const it of items) {
      if (it === "-") { m.append(h("hr")); continue; }
      m.append(h("button", { role: "menuitem", text: it.label, onclick: () => { m.remove(); it.run(); } }));
    }
    document.body.append(m);
    const r = m.getBoundingClientRect();
    m.style.left = Math.min(ev.clientX, innerWidth - r.width - 8) + "px";
    m.style.top = Math.min(ev.clientY, innerHeight - r.height - 8) + "px";
    const close = () => { m.remove(); removeEventListener("click", close); removeEventListener("keydown", esc); };
    const esc = (e) => { if (e.key === "Escape") close(); };
    setTimeout(() => { addEventListener("click", close); addEventListener("keydown", esc); }, 0);
  }
  /* panel terpisah yang dapat diubah ukurannya */
  function split(dir, a, b, initial = 50, key) {
    const saved = key && Number(localStorage.getItem("exv.split." + key));
    const root = h("div", { class: "split " + dir });
    root.style.setProperty("--a", (saved || initial) + "%");
    const g = h("div", { class: "gutter", role: "separator", tabindex: "0", "aria-orientation": dir === "h" ? "vertical" : "horizontal" });
    root.append(h("div", { class: "pane" }, a), g, h("div", { class: "pane" }, b));
    const set = (pct) => { pct = Math.max(12, Math.min(88, pct)); root.style.setProperty("--a", pct + "%"); if (key) { try { localStorage.setItem("exv.split." + key, pct.toFixed(1)); } catch (e) { /* noop */ } } };
    g.addEventListener("pointerdown", (e) => {
      g.setPointerCapture(e.pointerId); g.classList.add("drag");
      const vertical = dir === "v" || matchMedia("(max-width:760px)").matches;
      const move = (ev) => { const r = root.getBoundingClientRect(); set(vertical ? ((ev.clientY - r.top) / r.height) * 100 : ((ev.clientX - r.left) / r.width) * 100); };
      const up = () => { g.classList.remove("drag"); g.removeEventListener("pointermove", move); g.removeEventListener("pointerup", up); };
      g.addEventListener("pointermove", move); g.addEventListener("pointerup", up);
    });
    g.addEventListener("keydown", (e) => {
      const cur = parseFloat(root.style.getPropertyValue("--a")) || initial;
      const d = { ArrowLeft: -3, ArrowUp: -3, ArrowRight: 3, ArrowDown: 3 }[e.key]; if (d) { e.preventDefault(); set(cur + d); }
    });
    return root;
  }
  /* tab sederhana: items [{id,label,render()}] */
  function tabs(items, onChange, active) {
    const bar = h("div", { class: "tabs", role: "tablist" });
    const body = h("div", { class: "pane-body", style: { overflow: "hidden", display: "flex", flexDirection: "column" } });
    const wrap = h("div", { class: "reqbox" }, bar, body);
    let cur = active || items[0].id;
    const show = (id) => {
      cur = id;
      $$(".tab", bar).forEach((t) => { const on = t.dataset.id === id; t.classList.toggle("active", on); t.setAttribute("aria-selected", on); });
      body.replaceChildren(items.find((i) => i.id === id).render());
      if (onChange) onChange(id);
    };
    items.forEach((i) => bar.append(h("button", { class: "tab", role: "tab", dataset: { id: i.id }, text: i.label, onclick: () => show(i.id) })));
    show(cur);
    return { el: wrap, show, current: () => cur };
  }
  /* tabel data; columns [{key,label,width,render(row),cls,sort}] */
  function table(columns, opts = {}) {
    const wrap = h("div", { class: "tbl-wrap" });
    const t = h("table", { class: "tbl" });
    const thead = h("thead"), tbody = h("tbody");
    const tr = h("tr");
    let sort = opts.sort || { key: null, dir: "desc" };
    columns.forEach((c) => {
      const th = h("th", { class: c.sort ? "sortable" : "", text: c.label, scope: "col" });
      if (c.width) th.style.width = c.width;
      if (c.sort) th.addEventListener("click", () => { sort = { key: c.sort, dir: sort.key === c.sort && sort.dir === "desc" ? "asc" : "desc" }; mark(); if (opts.onSort) opts.onSort(sort); });
      th.dataset.sort = c.sort || ""; tr.append(th);
    });
    function mark() { [...tr.children].forEach((th) => { th.textContent = th.textContent.replace(/ [▲▼]$/, ""); if (th.dataset.sort && th.dataset.sort === sort.key) th.textContent += sort.dir === "asc" ? " ▲" : " ▼"; }); }
    thead.append(tr); t.append(thead, tbody); wrap.append(t);
    let rows = [], selected = new Set(), last = null;
    const keyOf = opts.key || ((r) => r.id);
    function rowEl(r) {
      const el = h("tr", { dataset: { k: keyOf(r) }, tabindex: "-1" });
      columns.forEach((c) => {
        const v = c.render ? c.render(r) : r[c.key];
        const td = h("td", { class: (c.cls || "") }, v === null || v === undefined ? "" : v);
        if (!c.render && v !== null && v !== undefined) td.title = String(v);
        el.append(td);
      });
      if (selected.has(keyOf(r))) el.classList.add("sel");
      return el;
    }
    function render(newRows) {
      if (newRows) rows = newRows;
      tbody.replaceChildren(...rows.map(rowEl));
      if (!rows.length && opts.empty) { tbody.append(h("tr", {}, h("td", { colspan: columns.length, class: "muted", style: { padding: "24px", textAlign: "center" }, text: opts.empty }))); }
    }
    tbody.addEventListener("click", (e) => {
      const tr2 = e.target.closest("tr[data-k]"); if (!tr2) return;
      const k = tr2.dataset.k, row = rows.find((r) => String(keyOf(r)) === k); if (!row) return;
      if (opts.multi && (e.ctrlKey || e.metaKey)) { selected.has(keyOf(row)) ? selected.delete(keyOf(row)) : selected.add(keyOf(row)); }
      else if (opts.multi && e.shiftKey && last !== null) {
        const a = rows.findIndex((r) => keyOf(r) === last), b = rows.indexOf(row);
        selected = new Set(rows.slice(Math.min(a, b), Math.max(a, b) + 1).map(keyOf));
      } else { selected = new Set([keyOf(row)]); }
      last = keyOf(row);
      [...tbody.children].forEach((x) => x.classList.toggle("sel", selected.has(isNaN(x.dataset.k) ? x.dataset.k : Number(x.dataset.k))));
      if (opts.onSelect) opts.onSelect(row, [...selected]);
    });
    if (opts.onContext) tbody.addEventListener("contextmenu", (e) => {
      const tr2 = e.target.closest("tr[data-k]"); if (!tr2) return;
      const row = rows.find((r) => String(keyOf(r)) === tr2.dataset.k); if (!row) return;
      if (!selected.has(keyOf(row))) { selected = new Set([keyOf(row)]); [...tbody.children].forEach((x) => x.classList.toggle("sel", x === tr2)); if (opts.onSelect) opts.onSelect(row, [...selected]); }
      opts.onContext(e, row, [...selected]);
    });
    mark();
    return { el: wrap, render, selected: () => [...selected], clearSel: () => { selected = new Set(); }, rows: () => rows, sort: () => sort, prepend(r) { rows.unshift(r); render(); }, tbody };
  }
  function highlight(preEl, text, term) {
    preEl.textContent = "";
    if (!term) { preEl.textContent = text; return 0; }
    const lc = text.toLowerCase(), t = term.toLowerCase();
    let i = 0, n = 0, at;
    while ((at = lc.indexOf(t, i)) !== -1 && n < 2000) {
      preEl.append(document.createTextNode(text.slice(i, at)), h("mark", { text: text.slice(at, at + t.length) }));
      i = at + t.length; n++;
    }
    preEl.append(document.createTextNode(text.slice(i)));
    return n;
  }
  /* viewer teks dengan pencarian, salin, ekspor */
  function codeView(getText, opts = {}) {
    const pre = h("pre", { class: "viewer" });
    const term = h("input", { type: "search", placeholder: "Cari…", "aria-label": "Cari dalam tampilan", style: { width: "130px" } });
    const cnt = h("span", { class: "muted small" });
    const wrap = h("div", { class: "reqbox" });
    let text = "";
    const draw = () => { const n = highlight(pre, text, term.value); cnt.textContent = term.value ? n + " cocok" : ""; };
    term.addEventListener("input", debounce(draw, 120));
    const head = h("div", { class: "pane-head" }, opts.title ? h("h3", { text: opts.title }) : null,
      h("div", { class: "code-tools" }, cnt, term,
        btn("", { cls: "sm", icon: "copy", title: "Salin", onclick: () => copy(text) }),
        btn("", { cls: "sm", icon: "download", title: "Ekspor", onclick: () => saveText(text, (opts.filename || "exvolt") + ".txt") })));
    wrap.append(head, h("div", { class: "pane-body", style: { overflow: "hidden" } }, pre));
    return { el: wrap, set(t) { text = t || ""; draw(); }, get: () => text, pre };
  }
  return { h, $, $$, icon, btn, toast, fail, debounce, bytes, time, ms, statusEl, sev, copy, saveText, modal, confirmBox, ctxMenu, split, tabs, table, highlight, codeView, sclass };
})();
