"use strict";
(() => {
  const { h, btn, fail, toast, time, bytes, ms, statusEl, modal } = EX.ui;
  let timers = [];

  async function mount(root) {
    const p = EX.state.proxy;
    const addr = h("input", { type: "text", value: "127.0.0.1", "aria-label": "Alamat listen", style: { width: "130px" } });
    const port = h("input", { type: "number", value: "8081", min: "0", max: "65535", "aria-label": "Port listen", style: { width: "80px" } });
    const startBtn = btn("Mulai Proxy", { cls: "primary", icon: "play" });
    const stopBtn = btn("Hentikan", { cls: "danger", icon: "stop" });
    const stat = h("span", { class: "muted small" });
    const queueBody = h("div", { class: "pane-body" });
    const queueList = EX.ui.table([
      { label: "#", key: "id", width: "50px" }, { label: "Waktu", width: "80px", render: (r) => time(r.ts), cls: "mono" },
      { label: "Host", render: (r) => `${r.host}:${r.port}` }, { label: "Request", render: (r) => r.raw.split("\n")[0].slice(0, 120), cls: "mono" },
    ], { empty: "Antrean kosong. Aktifkan Intercept untuk menahan request.", onSelect: (row) => select(row) });
    let current = null;
    const editor = h("textarea", { class: "editor", spellcheck: "false", "aria-label": "Editor request", disabled: true, placeholder: "Pilih item antrean untuk mengedit request mentah…" });
    const fwd = btn("Forward", { cls: "primary", icon: "forward", disabled: true, onclick: () => decide("forward", true) });
    const fwdRaw = btn("Forward (tanpa edit)", { cls: "", disabled: true, onclick: () => decide("forward", false) });
    const drop = btn("Drop", { cls: "danger", icon: "x", disabled: true, onclick: () => decide("drop") });
    const fwdAll = btn("Forward semua", { cls: "sm", onclick: async () => { for (const r of queueList.rows()) { try { await EX.api.post(`/api/proxy/queue/${r.id}/forward`); } catch (e) { /* sudah diproses */ } } loadQueue(); } });
    const dropAll = btn("Drop semua", { cls: "sm danger", onclick: async () => { for (const r of queueList.rows()) { try { await EX.api.post(`/api/proxy/queue/${r.id}/drop`); } catch (e) { /* noop */ } } loadQueue(); } });

    function select(row) {
      current = row; editor.disabled = false; editor.value = row.raw; [fwd, fwdRaw, drop].forEach((b) => (b.disabled = false));
    }
    async function decide(action, withEdit) {
      if (!current) return;
      try {
        await EX.api.post(`/api/proxy/queue/${current.id}/${action}`, action === "forward" && withEdit ? { raw: editor.value } : {});
        current = null; editor.value = ""; editor.disabled = true; [fwd, fwdRaw, drop].forEach((b) => (b.disabled = true)); loadQueue();
      } catch (e) { fail(e); loadQueue(); }
    }
    async function loadQueue() {
      try {
        const r = await EX.api.get("/api/proxy/queue");
        queueList.render(r.items);
        if (current && !r.items.find((i) => i.id === current.id)) { current = null; editor.value = ""; editor.disabled = true; [fwd, fwdRaw, drop].forEach((b) => (b.disabled = true)); }
        else if (!current && r.items.length) { /* biarkan pengguna memilih */ }
      } catch (e) { fail(e); }
    }
    // riwayat live
    const live = EX.ui.table([
      { label: "#", key: "id", width: "56px", cls: "num mono" }, { label: "Waktu", width: "76px", render: (r) => time(r.ts), cls: "mono" },
      { label: "Metode", key: "method", width: "64px", cls: "mono" }, { label: "URL", key: "url" }, { label: "Status", width: "60px", render: (r) => statusEl(r.status) },
      { label: "Ukuran", width: "76px", cls: "num", render: (r) => bytes(r.resp_size) }, { label: "Durasi", width: "76px", cls: "num", render: (r) => ms(r.duration_ms) },
    ], { empty: "Menunggu lalu lintas proxy…", onSelect: async (row) => { try { viewer.show(await EX.api.get("/api/history/" + row.id)); } catch (e) { fail(e); } } });
    const viewer = EX.viewer.exchange();
    const logBox = h("div", { class: "pane-body" });
    const helpBox = h("div", { class: "help pane-body", style: { padding: "12px 16px" } });

    async function refresh() {
      const s = await EX.api.get("/api/proxy/status"); EX.applyProxy(s);
      startBtn.disabled = s.running; stopBtn.disabled = !s.running; addr.disabled = port.disabled = s.running;
      if (s.running) { addr.value = s.host; port.value = s.port; }
      stat.textContent = s.running ? `${s.stats.connections} koneksi · ${s.stats.requests} request · ${s.stats.errors} error` : "Proxy tidak berjalan";
      helpBox.replaceChildren(
        h("b", { text: "Konfigurasi browser" }),
        h("ol", {}, h("li", {}, "Atur proxy HTTP dan HTTPS browser ke ", h("code", { text: `${s.running ? s.host : addr.value}:${s.running ? s.port : port.value}` }), "."),
          h("li", {}, "Unduh sertifikat CA EXVOLT X: ", h("a", { class: "em", href: "/api/proxy/ca", text: "PEM" }), " · ", h("a", { class: "em", href: "/api/proxy/ca?format=der", text: "DER" }), " (atau buka ", h("code", { text: `http://${s.running ? s.host : "127.0.0.1"}:${s.running ? s.port : "8081"}/ca.pem` }), " lewat proxy)."),
          h("li", {}, "Impor sebagai Authority/Otoritas tepercaya (Firefox: Settings → Certificates → Authorities; Chrome/Chromium Linux: Settings → Privacy → Manage certificates → Authorities)."),
          h("li", {}, "Telusuri situs: request muncul di riwayat dan antrean intercept secara langsung.")),
        h("p", { class: "muted small", text: `CA: ${s.ca.subject} · sha256 ${s.ca.sha256.slice(0, 32)}… · berlaku sampai ${s.ca.not_after.slice(0, 10)}` }),
        h("div", { class: "warnbox", text: "Hanya uji target yang Anda miliki atau berwenang untuk diuji. Instal CA ini hanya pada profil browser khusus pengujian dan hapus setelah selesai." }));
    }
    startBtn.onclick = async () => { try { const s = await EX.api.post("/api/proxy/start", { host: addr.value.trim(), port: Number(port.value) }); EX.applyProxy(s); await refresh(); toast(`Proxy berjalan di ${s.host}:${s.port}`); } catch (e) { fail(e); } };
    stopBtn.onclick = async () => { try { EX.applyProxy(await EX.api.post("/api/proxy/stop")); await refresh(); } catch (e) { fail(e); } };

    const tabsApi = EX.ui.tabs([
      { id: "intercept", label: "Intercept", render: () => EX.ui.split("v", h("div", { class: "reqbox" }, h("div", { class: "pane-head" }, h("h3", { text: "Antrean intercept" }), h("span", { class: "grow" }), fwdAll, dropAll), queueList.el),
        h("div", { class: "reqbox" }, h("div", { class: "pane-head" }, h("h3", { text: "Request (dapat diedit)" }), h("span", { class: "grow" }), fwd, fwdRaw, drop), h("div", { class: "pane-body", style: { overflow: "hidden" } }, editor)), 38, "intercept") },
      { id: "live", label: "Lalu lintas live", render: () => EX.ui.split("v", h("div", { class: "reqbox" }, live.el), viewer.el, 45, "proxylive") },
      { id: "log", label: "Log proxy", render: () => logBox },
      { id: "conn", label: "Koneksi & CA", render: () => helpBox },
    ], (id) => { if (id === "log") loadLogs(); }, "intercept");
    for (const el of [tabsApi.el]) el.style.flex = "1";

    root.append(h("div", { class: "toolbar" }, h("span", { class: "muted small", text: "Listen" }), addr, port, startBtn, stopBtn, h("span", { class: "grow" }), stat,
      h("label", { class: "chk" }, h("button", { class: "switch", role: "switch", id: "sw-intercept2", "aria-checked": String(!!p.intercept), "aria-label": "Intercept", onclick: async (e) => { try { EX.applyProxy(await EX.api.post("/api/proxy/intercept", { enabled: !EX.state.proxy.intercept })); e.target.setAttribute("aria-checked", String(EX.state.proxy.intercept)); } catch (x) { fail(x); } } }), "Intercept aktif")), tabsApi.el);
    mod.onProxy = (s) => { const sw = document.getElementById("sw-intercept2"); if (sw) sw.setAttribute("aria-checked", String(!!s.intercept)); };

    async function loadLogs() {
      try { const r = await EX.api.get("/api/proxy/logs"); logBox.replaceChildren(...(r.logs.length ? r.logs.map((l) => h("div", { class: "logline " + l.level, text: `${time(l.ts)}  [${l.level}] ${l.msg}` })) : [h("div", { class: "empty", text: "Belum ada log." })])); logBox.scrollTop = logBox.scrollHeight; } catch (e) { fail(e); }
    }
    mod.onEvent = (ev) => {
      if (ev.type === "history" && ev.data.source !== "repeater") { const r = ev.data; live.rows().unshift(r); if (live.rows().length > 300) live.rows().pop(); if (tabsApi.current() === "live") live.render(); }
      else if (ev.type === "intercept") loadQueue();
      else if (ev.type === "proxy_log" && tabsApi.current() === "log") { logBox.append(h("div", { class: "logline " + ev.data.level, text: `${time(ev.data.ts)}  [${ev.data.level}] ${ev.data.msg}` })); }
      else if (ev.type === "proxy_status") refresh().catch(() => {});
    };
    timers.push(setInterval(() => { refresh().catch(() => {}); }, 4000));
    try { const r = await EX.api.get("/api/history", { source: "proxy", page_size: 100 }); live.render(r.items); } catch (e) { /* noop */ }
    refresh().catch(fail); loadQueue();
  }
  const mod = { title: "Proxy", mount, unmount() { timers.forEach(clearInterval); timers = []; } };
  EX.modules.proxy = mod;
})();
