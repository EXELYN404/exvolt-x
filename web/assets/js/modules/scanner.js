"use strict";
(() => {
  const { h, btn, fail, toast, sev, time, modal, confirmBox } = EX.ui;
  const SEVS = ["critical", "high", "medium", "low", "info"];

  function mount(root) {
    const sevSel = h("select", { "aria-label": "Severity" }, [["", "Semua severity"], ...SEVS.map((s) => [s, s])].map(([v, t]) => h("option", { value: v, text: t })));
    const scopeChk = h("input", { type: "checkbox" });
    const info = h("span", { class: "muted small" });
    const detail = h("div", { class: "pane-body", style: { padding: "14px 16px" } }, h("div", { class: "empty", text: "Pilih temuan untuk melihat bukti dan perbaikan." }));
    const tbl = EX.ui.table([
      { label: "Severity", width: "90px", render: (r) => sev(r.severity) }, { label: "Temuan", key: "name" }, { label: "Keyakinan", key: "confidence", width: "90px" },
      { label: "Host", key: "host", width: "170px" }, { label: "Terdeteksi", width: "80px", cls: "mono", render: (r) => time(r.ts) },
    ], { empty: "Belum ada temuan. Temuan pasif muncul dari lalu lintas yang tertangkap proxy; gunakan 'Pindai ulang riwayat' untuk menganalisis riwayat yang sudah ada.", onSelect: showDetail });
    function showDetail(f) {
      detail.replaceChildren(h("div", { class: "row wrap" }, sev(f.severity), h("h3", { style: { margin: "0" }, text: f.name })),
        h("dl", { class: "kv", style: { margin: "12px 0" } }, h("dt", { text: "Keyakinan" }), h("dd", { text: f.confidence }), h("dt", { text: "URL terdampak" }), h("dd", { class: "mono", text: f.url }),
          h("dt", { text: "Terdeteksi" }), h("dd", { text: time(f.ts, true) }), h("dt", { text: "Transaksi" }), h("dd", {}, f.history_id ? h("a", { class: "em", href: "#/history", text: `riwayat #${f.history_id}`, onclick: () => { EX.state.pendingOpen = f.history_id; } }) : "probe langsung")),
        h("b", { text: "Deskripsi" }), h("p", { text: f.description }), h("b", { text: "Bukti" }), h("pre", { class: "viewer", style: { height: "auto", maxHeight: "200px", borderRadius: "6px" }, text: f.evidence }),
        h("b", { text: "Perbaikan" }), h("p", { text: f.remediation }),
        h("div", { class: "row" }, btn("Ekspor bukti", { cls: "sm", icon: "download", onclick: () => EX.api.download("GET", `/api/evidence/${f.id}`).catch(fail) }),
          btn("Hapus temuan", { cls: "sm danger", icon: "trash", onclick: async () => { try { await EX.api.del("/api/scanner/findings/" + f.id); load(); detail.replaceChildren(); } catch (e) { fail(e); } } })));
    }
    async function load() {
      try { const r = await EX.api.get("/api/scanner/findings", { severity: sevSel.value, in_scope: scopeChk.checked }); tbl.render(r.items); info.textContent = `${r.total} temuan`; } catch (e) { fail(e); }
    }
    sevSel.addEventListener("change", load); scopeChk.addEventListener("change", load);
    const probeOut = h("div", { class: "hidden" });
    async function probe() {
      const r = await modal("Probe TLS (handshake nyata)", [{ name: "host", label: "Host", placeholder: "localhost" }, { name: "port", label: "Port", type: "number", value: 443 }], "Probe");
      if (!r || !r.host.trim()) return;
      try {
        const p = await EX.api.post("/api/scanner/tls", { host: r.host.trim(), port: Number(r.port) });
        probeOut.className = "okbox"; probeOut.textContent = `${p.host}:${p.port} · ${p.version} · ${p.cipher} · kunci ${p.key} · ${p.sig_hash} · berlaku s/d ${p.not_after.slice(0, 10)} · TLS1.0: ${p.legacy_protocols["TLSv1.0"]} · TLS1.1: ${p.legacy_protocols["TLSv1.1"]} · ${p.new_findings} temuan baru`;
        load();
      } catch (e) { probeOut.className = "errbox"; probeOut.textContent = e.message; }
    }
    root.append(h("div", { class: "toolbar" }, sevSel, h("label", { class: "chk" }, scopeChk, "Hanya scope"), info, h("span", { class: "grow" }),
      btn("Pindai ulang riwayat", { cls: "sm", icon: "refresh", onclick: async () => { try { const r = await EX.api.post("/api/scanner/rescan"); toast(`${r.new_findings} temuan baru`); load(); } catch (e) { fail(e); } } }),
      btn("Probe TLS", { cls: "sm", icon: "shield", onclick: probe }),
      btn("Hapus semua", { cls: "sm danger", onclick: async () => { if (await confirmBox("Hapus semua temuan?", "Hapus")) { try { await EX.api.del("/api/scanner/findings"); load(); } catch (e) { fail(e); } } } })),
    probeOut, EX.ui.split("h", h("div", { class: "reqbox" }, tbl.el), h("div", { class: "reqbox" }, h("div", { class: "pane-head" }, h("h3", { text: "Detail temuan" })), detail), 56, "scanner"));
    root.lastChild.style.flex = "1";
    load();
    mod.onEvent = (ev) => { if (ev.type === "finding") load(); };
  }
  const mod = { title: "Scanner Pasif", mount };
  EX.modules.scanner = mod;
})();
