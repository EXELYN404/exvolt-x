"use strict";
(() => {
  const { h, btn, fail, toast, ms, bytes, time, statusEl, modal, confirmBox } = EX.ui;
  const KEY = "exv.repeater.v1";
  let tabs = [], active = 0, uid = 0, pending = null;

  const blank = (n) => ({ id: ++uid, name: n || "Tab " + uid, method: "GET", url: "https://", raw: "GET / HTTP/1.1\r\nHost: \r\nUser-Agent: EXVOLT-X\r\nAccept: */*\r\nConnection: close\r\n\r\n", follow: false, timeout: 30, resp: null });
  function persist() { try { localStorage.setItem(KEY, JSON.stringify(tabs.map((t) => ({ ...t, resp: null })))); } catch (e) { /* penuh/diblokir */ } }
  function restore() {
    try { const s = JSON.parse(localStorage.getItem(KEY) || "[]"); if (Array.isArray(s) && s.length) { tabs = s; uid = Math.max(...s.map((t) => t.id)); return; } } catch (e) { /* abaikan */ }
    tabs = [blank()];
  }
  function parseUrl(u) { try { const x = new URL(u); return x.protocol === "http:" || x.protocol === "https:" ? x : null; } catch (e) { return null; } }
  function fromRaw(t) {
    const first = t.raw.split(/\r?\n/)[0].trim().split(/\s+/);
    if (first.length >= 2) { t.method = first[0].toUpperCase(); const u = parseUrl(t.url); if (u && first[1].startsWith("/")) { u.pathname = ""; u.search = ""; t.url = u.origin + first[1]; } }
  }
  function applyUrl(t) {
    const u = parseUrl(t.url); if (!u) return;
    const path = (u.pathname || "/") + u.search;
    const lines = t.raw.split(/\r?\n/);
    lines[0] = `${t.method} ${path} HTTP/1.1`;
    let idx = lines.findIndex((l, i) => i > 0 && /^host\s*:/i.test(l));
    const hostLine = "Host: " + u.host;
    if (idx === -1) lines.splice(1, 0, hostLine); else lines[idx] = hostLine;
    t.raw = lines.join("\r\n");
  }

  function mount(root, arg) {
    if (!tabs.length) restore();
    if (arg && arg.raw) {
      const t = blank(arg.label ? "Repeater " + arg.label : undefined);
      t.raw = arg.raw.replace(/\r?\n/g, "\r\n");
      const def = arg.scheme === "https" ? 443 : 80;
      t.url = `${arg.scheme}://${arg.host}${arg.port && arg.port !== def ? ":" + arg.port : ""}/`;
      fromRaw(t); tabs.push(t); active = tabs.length - 1; persist();
    }
    const tabBar = h("div", { class: "tabs", role: "tablist" });
    const methodSel = h("select", { "aria-label": "Metode" }, ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"].map((m) => h("option", { value: m, text: m })));
    const urlIn = h("input", { type: "text", "aria-label": "URL target", placeholder: "https://target.example/path", style: { flex: "1", minWidth: "220px" } });
    const followChk = h("input", { type: "checkbox" });
    const timeoutIn = h("input", { type: "number", min: "1", max: "600", style: { width: "64px" }, "aria-label": "Timeout (detik)" });
    const sendBtn = btn("Kirim", { cls: "primary", icon: "send" });
    const editor = h("textarea", { class: "editor", spellcheck: "false", "aria-label": "Editor request mentah", wrap: "off" });
    const respInfo = h("div", { class: "pane-head small muted", text: "Belum ada respons." });
    const respView = EX.viewer.message("Response");
    const banner = h("div", { class: "hidden" });
    const cur = () => tabs[active];

    function drawTabs() {
      tabBar.replaceChildren(...tabs.map((t, i) => h("button", { class: "tab" + (i === active ? " active" : ""), role: "tab", onclick: () => { active = i; load(); }, ondblclick: async () => { const r = await modal("Ubah nama tab", [{ name: "n", label: "Nama", value: t.name }]); if (r && r.n.trim()) { t.name = r.n.trim().slice(0, 40); persist(); drawTabs(); } } },
        h("span", { text: t.name }), tabs.length > 1 ? h("button", { class: "x", title: "Tutup tab", "aria-label": "Tutup tab", text: "×", onclick: (e) => { e.stopPropagation(); tabs.splice(i, 1); active = Math.min(active, tabs.length - 1); persist(); load(); } }) : null)),
      h("button", { class: "tab", title: "Tab baru", "aria-label": "Tab baru", onclick: () => { tabs.push(blank()); active = tabs.length - 1; persist(); load(); } }, "+"));
    }
    function load() {
      const t = cur(); drawTabs();
      methodSel.value = t.method; urlIn.value = t.url; followChk.checked = t.follow; timeoutIn.value = t.timeout; editor.value = t.raw;
      showResp(t.resp);
    }
    function showResp(r) {
      banner.className = "hidden";
      if (!r) { respInfo.textContent = "Belum ada respons."; respView.clear(); return; }
      if (r.error) { respInfo.textContent = ""; respView.show({ head: "", body: r.error }); banner.className = "errbox"; banner.textContent = r.error; return; }
      const bits = [`${r.status} ${r.reason}`, ms(r.duration_ms) + ` (TTFB ${ms(r.ttfb_ms)})`, bytes(r.size)];
      if (r.tls) bits.push(`${r.tls.version} ${r.tls.cipher || ""}`);
      if (r.redirects && r.redirects.length) bits.push(`${r.redirects.length} redirect diikuti`);
      if (r.truncated) bits.push("DIPOTONG");
      if (r.decode_note) bits.push("encoding: " + r.decode_note);
      bits.push(`riwayat #${r.history_id}`);
      respInfo.textContent = bits.join("  ·  ");
      respView.show({ head: r.raw_head, body: r.body, pretty: r.body_pretty });
      if (r.redirect_blocked) { banner.className = "warnbox"; banner.textContent = r.redirect_blocked; }
    }
    editor.addEventListener("input", () => { const t = cur(); t.raw = editor.value; fromRaw(t); methodSel.value = t.method; urlIn.value = t.url; persist(); });
    methodSel.addEventListener("change", () => { const t = cur(); t.method = methodSel.value; applyUrl(t); editor.value = t.raw; persist(); });
    urlIn.addEventListener("change", () => { const t = cur(); t.url = urlIn.value.trim(); applyUrl(t); editor.value = t.raw; persist(); });
    followChk.addEventListener("change", () => { cur().follow = followChk.checked; persist(); });
    timeoutIn.addEventListener("change", () => { cur().timeout = Number(timeoutIn.value) || 30; persist(); });

    async function send() {
      const t = cur(); t.url = urlIn.value.trim();
      const u = parseUrl(t.url); if (!u) return toast("URL tidak valid (harus http:// atau https://)", "err");
      sendBtn.disabled = true; sendBtn.lastChild.textContent = "Mengirim…";
      try {
        const r = await EX.api.post("/api/repeater/send", { raw: editor.value.replace(/\r?\n/g, "\r\n"), scheme: u.protocol.slice(0, -1), host: u.hostname, port: u.port ? Number(u.port) : null, follow_redirects: followChk.checked, timeout: Number(timeoutIn.value) || 30 });
        t.resp = r;
      } catch (e) { t.resp = { error: e.message }; }
      sendBtn.disabled = false; sendBtn.lastChild.textContent = "Kirim";
      if (cur() === t) showResp(t.resp);
    }
    sendBtn.onclick = send;
    editor.addEventListener("keydown", (e) => { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); send(); } });

    const dup = () => { const t = { ...cur(), id: ++uid, name: cur().name + " (salinan)", resp: null }; tabs.splice(active + 1, 0, t); active++; persist(); load(); };
    async function save() {
      const r = await modal("Simpan request", [{ name: "n", label: "Nama", value: cur().name }], "Simpan"); if (!r || !r.n.trim()) return;
      try { const t = cur(); await EX.api.post("/api/repeater/saved", { name: r.n.trim(), data: { raw: t.raw, url: t.url, method: t.method, follow: t.follow, timeout: t.timeout } }); toast("Request tersimpan"); } catch (e) { fail(e); }
    }
    async function openSaved() {
      try {
        const [s, l] = await Promise.all([EX.api.get("/api/repeater/saved"), EX.api.get("/api/repeater/log")]);
        const dlg = h("dialog", { style: { width: "min(92vw,720px)" } });
        const closeIt = () => { dlg.close(); dlg.remove(); };
        const body = h("div", { class: "dbody", style: { maxHeight: "60vh", overflow: "auto" } },
          h("b", { text: "Request tersimpan" }),
          ...(s.items.length ? s.items.map((it) => h("div", { class: "row" }, h("span", { style: { flex: "1" }, text: `${it.name} — ${it.data.method} ${it.data.url}` }),
            btn("Muat", { cls: "sm", onclick: () => { const t = { ...blank(it.name), ...it.data }; tabs.push(t); active = tabs.length - 1; persist(); closeIt(); load(); } }),
            btn("", { cls: "sm danger", icon: "trash", onclick: async () => { try { await EX.api.del("/api/repeater/saved/" + it.id); closeIt(); openSaved(); } catch (e) { fail(e); } } }))) : [h("span", { class: "muted", text: "Belum ada." })]),
          h("b", { style: { marginTop: "10px" }, text: "Riwayat pengiriman" }),
          ...(l.items.length ? l.items.slice(0, 100).map((it) => h("div", { class: "small mono muted", text: `${time(it.ts)}  ${it.method} ${it.url}  →  ${it.status || it.error}${it.history_id ? "  (#" + it.history_id + ")" : ""}` })) : [h("span", { class: "muted", text: "Belum ada." })]));
        dlg.append(h("h3", { text: "Muat request / riwayat" }), body, h("div", { class: "dfoot" }, btn("Tutup", { onclick: closeIt })));
        dlg.addEventListener("cancel", closeIt); document.body.append(dlg); dlg.showModal();
      } catch (e) { fail(e); }
    }
    const left = h("div", { class: "reqbox" }, h("div", { class: "pane-head" }, h("h3", { text: "Request" }), h("span", { class: "muted small", text: "Ctrl+Enter untuk kirim" })), h("div", { class: "pane-body", style: { overflow: "hidden" } }, editor));
    const right = h("div", { class: "reqbox" }, respInfo, banner, h("div", { style: { flex: "1", minHeight: "0", display: "flex" } }, respView.el));
    respView.el.style.flex = "1";
    root.append(tabBar,
      h("div", { class: "toolbar" }, methodSel, urlIn, h("label", { class: "chk" }, followChk, "Ikuti redirect"), h("label", { class: "chk" }, "Timeout", timeoutIn), sendBtn,
        btn("Duplikat", { cls: "sm", onclick: dup }), btn("Simpan", { cls: "sm", icon: "save", onclick: save }), btn("Muat / Riwayat", { cls: "sm", onclick: openSaved })),
      EX.ui.split("h", left, right, 48, "repeater"));
    root.lastChild.style.flex = "1";
    load();
  }
  EX.modules.repeater = { title: "Repeater", mount };
})();
