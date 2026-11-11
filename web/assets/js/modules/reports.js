"use strict";
(() => {
  const { h, btn, fail, toast, modal, confirmBox, time } = EX.ui;

  function mount(root) {
    const tbl = EX.ui.table([
      { label: "#", key: "id", width: "50px" }, { label: "Judul", key: "title" }, { label: "Dibuat", width: "150px", cls: "mono", render: (r) => time(r.ts, true) },
      { label: "Temuan", width: "70px", cls: "num", render: (r) => r.summary.findings ?? 0 }, { label: "Request", width: "80px", cls: "num", render: (r) => r.summary.requests_captured ?? 0 },
      { label: "Aksi", width: "240px", render: (r) => h("div", { class: "row" }, btn("HTML", { cls: "sm", icon: "download", onclick: () => EX.api.download("GET", `/api/reports/${r.id}/html`).catch(fail) }),
        btn("JSON", { cls: "sm", icon: "download", onclick: () => EX.api.download("GET", `/api/reports/${r.id}/json`).catch(fail) }),
        btn("", { cls: "sm danger", icon: "trash", title: "Hapus", onclick: async () => { if (await confirmBox(`Hapus laporan #${r.id}?`, "Hapus")) { try { await EX.api.del("/api/reports/" + r.id); load(); } catch (e) { fail(e); } } } })) },
    ], { empty: "Belum ada laporan. Laporan dibuat dari temuan nyata yang tercatat." });
    async function load() { try { tbl.render((await EX.api.get("/api/reports")).items); } catch (e) { fail(e); } }
    async function create() {
      const r = await modal("Buat laporan", [{ name: "title", label: "Judul", value: "Laporan Pengujian EXVOLT X" },
        { name: "min", label: "Severity minimum", type: "select", options: [{ value: "info", label: "Semua (info ke atas)" }, { value: "low", label: "Low ke atas" }, { value: "medium", label: "Medium ke atas" }, { value: "high", label: "High ke atas" }] },
        { name: "scope", label: "Hanya temuan di dalam scope", type: "checkbox", value: false }], "Buat");
      if (!r) return;
      const order = ["info", "low", "medium", "high", "critical"], sev = order.slice(order.indexOf(r.min));
      try { const rep = await EX.api.post("/api/reports", { title: r.title, severities: sev, in_scope_only: r.scope }); toast(`Laporan #${rep.id} dibuat dengan ${rep.summary.findings} temuan`); load(); } catch (e) { fail(e); }
    }
    root.append(h("div", { class: "toolbar" }, btn("Buat laporan", { cls: "primary", icon: "plus", onclick: create }), h("span", { class: "grow" }),
      btn("Ekspor semua riwayat (HAR)", { cls: "sm", onclick: () => EX.api.download("POST", "/api/history/export", { all: true, format: "har" }).catch(fail) }),
      btn("Ekspor semua riwayat (JSON)", { cls: "sm", onclick: () => EX.api.download("POST", "/api/history/export", { all: true, format: "json" }).catch(fail) })), tbl.el);
    load();
  }
  EX.modules.reports = { title: "Laporan", mount };
})();
