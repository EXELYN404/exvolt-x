"use strict";
(() => {
  const { h, btn, fail, toast, ms, statusEl, modal, saveText } = EX.ui;
  const MARK = "§";
  const DEFAULT = "GET /search?q=§test§ HTTP/1.1\r\nHost: localhost:8000\r\nUser-Agent: EXVOLT-X\r\nConnection: close\r\n\r\n";
  let timer = null, saved = null;

  function mount(root) {
    const st = saved || { template: DEFAULT, scheme: "http", host: "localhost", port: "8000", mode: "sniper", conc: 2, rps: 5, timeout: 15, lists: [""] };
    saved = st;
    const tpl = h("textarea", { class: "editor", spellcheck: "false", wrap: "off", "aria-label": "Template request" });
    tpl.value = st.template;
    const scheme = h("select", { "aria-label": "Skema" }, ["http", "https"].map((s) => h("option", { value: s, text: s })));
    const host = h("input", { type: "text", placeholder: "host", "aria-label": "Host target", style: { width: "180px" } });
    const port = h("input", { type: "number", placeholder: "port", "aria-label": "Port", style: { width: "74px" } });
    const mode = h("select", { "aria-label": "Mode serangan" }, [["sniper", "Sniper"], ["battering_ram", "Battering ram"], ["pitchfork", "Pitchfork"], ["cluster_bomb", "Cluster bomb"]].map(([v, t]) => h("option", { value: v, text: t })));
    const conc = h("input", { type: "number", min: "1", max: "100", style: { width: "64px" }, "aria-label": "Concurrency" });
    const rps = h("input", { type: "number", min: "1", step: "1", style: { width: "70px" }, "aria-label": "Request per detik" });
    const tout = h("input", { type: "number", min: "1", max: "120", style: { width: "64px" }, "aria-label": "Timeout" });
    const confirm = h("input", { type: "text", placeholder: "ketik persis host:port untuk konfirmasi", "aria-label": "Konfirmasi target", autocomplete: "off", style: { width: "260px" } });
    const listsBox = h("div", { class: "col", style: { padding: "8px", overflow: "auto", height: "100%" } });
    const info = h("div", { class: "muted small" });
    const prog = h("div", { class: "bar", style: { width: "180px" } }, h("i", {}));
    const startBtn = btn("Mulai serangan", { cls: "primary", icon: "play" }), stopBtn = btn("Stop", { cls: "danger", icon: "stop", disabled: true });
    const warn = h("div", { class: "warnbox", text: "Gunakan hanya pada target yang Anda miliki/berwenang uji. Target harus ada di Scope (include), dikonfirmasi manual, dan dibatasi concurrency/rate." });
    scheme.value = st.scheme; host.value = st.host; port.value = st.port; mode.value = st.mode; conc.value = st.conc; rps.value = st.rps; tout.value = st.timeout;
    let attackId = null, results = [], lastSort = { key: "n", dir: "asc" };

    const res = EX.ui.table([
      { label: "#", key: "n", sort: "n", width: "56px", cls: "num mono" }, { label: "Payload", key: "payload", cls: "mono" },
      { label: "Status", sort: "status", width: "70px", render: (r) => (r.status ? statusEl(r.status) : "ERR") },
      { label: "Ukuran", key: "length", sort: "length", width: "80px", cls: "num" }, { label: "Durasi", sort: "duration_ms", width: "80px", cls: "num", render: (r) => ms(r.duration_ms) },
      { label: "Error / cuplikan", render: (r) => r.error || (r.snippet || "").replace(/\s+/g, " ").slice(0, 80), cls: "mono muted" },
    ], { key: (r) => r.n, empty: "Belum ada hasil.", sort: { key: "n", dir: "asc" }, onSort: (s) => { lastSort = s; paintRows(); } });
    function paintRows() {
      const k = lastSort.key === "ms" ? "duration_ms" : lastSort.key, d = lastSort.dir === "asc" ? 1 : -1;
      res.render([...results].sort((a, b) => ((a[k] ?? -1) > (b[k] ?? -1) ? 1 : (a[k] ?? -1) < (b[k] ?? -1) ? -1 : 0) * d));
    }

    const positions = () => Math.floor((tpl.value.split(MARK).length - 1) / 2);
    function drawLists() {
      const n = positions(), m = mode.value, need = m === "sniper" || m === "battering_ram" ? 1 : Math.max(1, n);
      while (st.lists.length < need) st.lists.push("");
      listsBox.replaceChildren(h("div", { class: "muted small", text: `${n} posisi payload terdeteksi (${MARK}…${MARK}). ${m === "sniper" ? "Sniper: satu daftar, tiap posisi diuji bergantian." : m === "battering_ram" ? "Battering ram: payload sama pada semua posisi." : m === "pitchfork" ? "Pitchfork: satu daftar per posisi, dijalankan paralel (zip)." : "Cluster bomb: semua kombinasi antar daftar."}` }),
        ...Array.from({ length: need }, (_, i) => {
          const ta = h("textarea", { rows: 7, spellcheck: "false", "aria-label": `Daftar payload ${i + 1}`, placeholder: "satu payload per baris", style: { width: "100%" } });
          ta.value = st.lists[i]; ta.addEventListener("input", () => { st.lists[i] = ta.value; count(); });
          const num = btn("1..N", { cls: "sm", title: "Isi dengan rentang angka", onclick: async () => { const r = await modal("Rentang angka", [{ name: "a", label: "Mulai", type: "number", value: 1 }, { name: "b", label: "Sampai", type: "number", value: 100 }]); if (!r) return; const a = Number(r.a), b = Number(r.b); if (!(b >= a) || b - a > 100000) return toast("Rentang tidak valid (maks 100.000)", "err"); ta.value = Array.from({ length: b - a + 1 }, (_, k) => a + k).join("\n"); st.lists[i] = ta.value; count(); } });
          const file = h("input", { type: "file", accept: ".txt,text/plain", "aria-label": "Muat dari berkas", onchange: async (e) => { const f = e.target.files[0]; if (!f) return; if (f.size > 5e6) return toast("Berkas > 5 MB", "err"); ta.value = await f.text(); st.lists[i] = ta.value; count(); } });
          return h("div", { class: "col" }, h("div", { class: "row" }, h("b", { class: "small", text: `Daftar ${i + 1}` }), num, file), ta);
        }));
      count();
    }
    function listsArr() { const m = mode.value, n = positions(); const need = m === "sniper" || m === "battering_ram" ? 1 : Math.max(1, n); return st.lists.slice(0, need).map((t) => t.split(/\r?\n/).filter((x) => x !== "")); }
    function count() {
      const n = positions(), L = listsArr().map((l) => l.length), m = mode.value; let t = 0;
      if (m === "sniper") t = n * (L[0] || 0); else if (m === "battering_ram") t = L[0] || 0; else if (m === "pitchfork") t = Math.min(...L); else t = L.reduce((a, b) => a * b, 1);
      info.textContent = n ? `Perkiraan request: ${t.toLocaleString("id-ID")}` : `Tandai posisi payload dengan ${MARK}…${MARK} pada template.`;
    }
    mode.addEventListener("change", () => { st.mode = mode.value; drawLists(); });
    tpl.addEventListener("input", () => { st.template = tpl.value; drawLists(); });
    for (const [el, k] of [[scheme, "scheme"], [host, "host"], [port, "port"], [conc, "conc"], [rps, "rps"], [tout, "timeout"]]) el.addEventListener("input", () => { st[k] = el.value; });
    const markBtn = btn("Tambah §", { cls: "sm", title: "Bungkus teks terpilih dengan §", onclick: () => { const a = tpl.selectionStart, b = tpl.selectionEnd; tpl.value = tpl.value.slice(0, a) + MARK + tpl.value.slice(a, b) + MARK + tpl.value.slice(b); st.template = tpl.value; drawLists(); } });
    const clearMark = btn("Hapus §", { cls: "sm", onclick: () => { tpl.value = tpl.value.split(MARK).join(""); st.template = tpl.value; drawLists(); } });

    async function poll() {
      if (attackId === null) return;
      try {
        const a = await EX.api.get("/api/intruder/" + attackId, { offset: 0 });
        results = a.results;
        paintRows();
        prog.firstChild.style.width = (a.total ? (a.done / a.total) * 100 : 0) + "%";
        info.textContent = `${a.state}: ${a.done}/${a.total} selesai · ${a.errors} error`;
        const running = a.state === "running";
        startBtn.disabled = running; stopBtn.disabled = !running;
        if (!running) { clearInterval(timer); timer = null; }
      } catch (e) { clearInterval(timer); fail(e); }
    }
    startBtn.onclick = async () => {
      try {
        const a = await EX.api.post("/api/intruder/start", { template: tpl.value.replace(/\r?\n/g, "\r\n"), scheme: scheme.value, host: host.value.trim(), port: port.value ? Number(port.value) : null,
          mode: mode.value, payloads: listsArr(), concurrency: Number(conc.value), rps: Number(rps.value), timeout: Number(tout.value), confirm_target: confirm.value });
        attackId = a.id; results = []; res.render([]); startBtn.disabled = true; stopBtn.disabled = false;
        clearInterval(timer); timer = setInterval(poll, 700); poll();
      } catch (e) { fail(e); }
    };
    stopBtn.onclick = async () => { try { await EX.api.post(`/api/intruder/${attackId}/stop`); toast("Permintaan stop dikirim; request berjalan dibatalkan"); poll(); } catch (e) { fail(e); } };
    const exp = (fmt) => attackId === null ? toast("Belum ada serangan", "warn") : EX.api.download("GET", `/api/intruder/${attackId}/export?format=${fmt}`).catch(fail);

    const top = h("div", { class: "reqbox" }, h("div", { class: "pane-head" }, h("h3", { text: "Template request" }), markBtn, clearMark, h("span", { class: "muted small", text: `Posisi ditandai dengan ${MARK}…${MARK}` })), h("div", { class: "pane-body", style: { overflow: "hidden" } }, tpl));
    const cfg = h("div", { class: "reqbox" }, h("div", { class: "pane-head" }, h("h3", { text: "Payload" })), h("div", { class: "pane-body" }, listsBox));
    const resPane = h("div", { class: "reqbox" }, h("div", { class: "toolbar" }, h("b", { class: "small", text: "Hasil" }), prog, info, h("span", { class: "grow" }),
      btn("CSV", { cls: "sm", icon: "download", onclick: () => exp("csv") }), btn("JSON", { cls: "sm", onclick: () => exp("json") })), res.el);
    root.append(h("div", { class: "toolbar" }, scheme, host, port, mode, h("label", { class: "chk" }, "Concurrency", conc), h("label", { class: "chk" }, "Req/detik", rps), h("label", { class: "chk" }, "Timeout", tout)),
      h("div", { class: "toolbar" }, confirm, startBtn, stopBtn, h("span", { class: "grow" }), warn),
      EX.ui.split("v", EX.ui.split("h", top, cfg, 55, "intr-top"), resPane, 48, "intr"));
    root.lastChild.style.flex = "1";
    drawLists();
    EX.api.get("/api/intruder").then((r) => { const last = r.attacks[r.attacks.length - 1]; if (last) { attackId = last.id; poll(); if (last.state === "running") timer = setInterval(poll, 700); } }).catch(() => {});
  }
  EX.modules.intruder = { title: "Intruder", mount, unmount() { clearInterval(timer); timer = null; } };
})();
