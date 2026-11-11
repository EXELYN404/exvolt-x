"use strict";
(() => {
  const { h, btn, fail, toast, time, bytes, debounce, confirmBox } = EX.ui;

  function mount(root) {
    let conn = "";
    const q = h("input", { type: "search", placeholder: "Cari payload…", "aria-label": "Cari payload", style: { width: "200px" } });
    const dir = h("select", { "aria-label": "Arah" }, [["", "Semua arah"], ["out", "Keluar (klien→server)"], ["in", "Masuk (server→klien)"]].map(([v, t]) => h("option", { value: v, text: t })));
    const kind = h("select", { "aria-label": "Jenis" }, [["", "Semua jenis"], ["text", "text"], ["binary", "binary"], ["ping", "ping"], ["pong", "pong"], ["close", "close"]].map(([v, t]) => h("option", { value: v, text: t })));
    const info = h("span", { class: "muted small" });
    const payload = EX.ui.codeView(() => "", { title: "Payload" });
    const conns = EX.ui.table([{ label: "Conn", key: "conn_id", width: "56px" }, { label: "Host", key: "host" }, { label: "Pesan", key: "n", width: "60px", cls: "num" }, { label: "Keluar/Masuk", width: "100px", render: (r) => `${r.out_n}/${r.in_n}` }],
      { key: (r) => r.conn_id, empty: "Belum ada koneksi WebSocket tertangkap. Telusuri situs ber-WebSocket melalui proxy.", onSelect: (r) => { conn = String(r.conn_id); loadMsgs(); } });
    const msgs = EX.ui.table([{ label: "#", key: "id", width: "60px", cls: "num mono" }, { label: "Waktu", width: "76px", cls: "mono", render: (r) => time(r.ts) },
      { label: "Arah", width: "50px", render: (r) => (r.direction === "out" ? "→ keluar" : "← masuk") }, { label: "Jenis", key: "kind", width: "60px" }, { label: "Ukuran", width: "70px", cls: "num", render: (r) => bytes(r.length) },
      { label: "Payload", cls: "mono", render: (r) => (r.payload || "").replace(/\s+/g, " ").slice(0, 160) }],
      { empty: "Tidak ada pesan.", onSelect: (r) => payload.set(`${r.direction === "out" ? "→ keluar" : "← masuk"} · ${r.kind} · ${r.length} byte\n\n${r.payload}`) });
    async function loadConns() { try { const r = await EX.api.get("/api/websocket/connections"); conns.render(r.items); } catch (e) { fail(e); } }
    async function loadMsgs() {
      try { const r = await EX.api.get("/api/websocket/messages", { conn_id: conn, direction: dir.value, kind: kind.value, q: q.value.trim() }); msgs.render(r.items); info.textContent = `${r.total} pesan`; } catch (e) { fail(e); }
    }
    q.addEventListener("input", debounce(loadMsgs, 300)); dir.addEventListener("change", loadMsgs); kind.addEventListener("change", loadMsgs);
    const soft = debounce(() => { loadConns(); loadMsgs(); }, 400);
    mod.onEvent = (ev) => { if (ev.type === "ws_message") soft(); };
    root.append(h("div", { class: "toolbar" }, q, dir, kind, btn("Semua koneksi", { cls: "sm", onclick: () => { conn = ""; loadMsgs(); } }), info, h("span", { class: "grow" }),
      btn("Ekspor", { cls: "sm", icon: "download", onclick: () => EX.api.download("GET", "/api/websocket/export").catch(fail) }),
      btn("Kosongkan", { cls: "sm danger", icon: "trash", onclick: async () => { if (await confirmBox("Hapus semua pesan WebSocket?", "Hapus")) { try { await EX.api.del("/api/websocket/messages"); loadConns(); loadMsgs(); } catch (e) { fail(e); } } } })),
    EX.ui.split("h", h("div", { class: "reqbox" }, h("div", { class: "pane-head" }, h("h3", { text: "Koneksi" })), conns.el),
      EX.ui.split("v", h("div", { class: "reqbox" }, h("div", { class: "pane-head" }, h("h3", { text: "Pesan" })), msgs.el), payload.el, 58, "ws-v"), 28, "ws"));
    root.lastChild.style.flex = "1";
    loadConns(); loadMsgs();
  }
  const mod = { title: "WebSocket", mount };
  EX.modules.websocket = mod;
})();
