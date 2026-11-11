"use strict";
(() => {
  const { h, btn, fail, toast, time, bytes, ms, statusEl, debounce, ctxMenu, modal, confirmBox } = EX.ui;
  let ui = null;

  function toRepeater(d) {
    EX.go("repeater", { raw: d.request.raw, scheme: d.scheme, host: d.host, port: d.port, label: `#${d.id}` });
  }

  EX.sendToComparer = (side, spec) => { EX.state.cmp = EX.state.cmp || {}; EX.state.cmp[side] = spec; toast(`Dikirim ke Comparer (${side === "left" ? "kiri" : "kanan"})`); };

  async function ctxActions(ev, row, ids) {
    const get = async () => EX.api.get("/api/history/" + row.id);
    ctxMenu(ev, [
      { label: "Kirim ke Repeater", run: async () => { try { toRepeater(await get()); } catch (e) { fail(e); } } },
      { label: "Comparer: respons → kiri", run: () => EX.sendToComparer("left", { history_id: row.id, part: "response", label: `#${row.id} respons` }) },
      { label: "Comparer: respons → kanan", run: () => EX.sendToComparer("right", { history_id: row.id, part: "response", label: `#${row.id} respons` }) },
      { label: "Comparer: request → kiri", run: () => EX.sendToComparer("left", { history_id: row.id, part: "request", label: `#${row.id} request` }) },
      { label: "Comparer: request → kanan", run: () => EX.sendToComparer("right", { history_id: row.id, part: "request", label: `#${row.id} request` }) },
      "-",
      { label: "Ekstrak token ke Sequencer…", run: () => EX.go("sequencer", { fromHistory: ids }) },
      { label: "Tambah host ke scope (include)", run: async () => { try { await EX.api.post("/api/scope", { action: "include", type: "domain", value: row.host }); await EX.api.post("/api/scope/recompute"); toast("Host ditambahkan ke scope"); EX.refreshStatus(); ui && ui.load(); } catch (e) { fail(e); } } },
      { label: "Salin URL", run: () => EX.ui.copy(row.url) },
      "-",
      { label: `Hapus ${ids.length} entri`, run: () => del(ids) },
    ]);
  }

  async function del(ids) {
    if (!ids.length || !(await confirmBox(`Hapus ${ids.length} entri riwayat?`, "Hapus"))) return;
    try { const r = await EX.api.post("/api/history/delete", { ids }); toast(`${r.deleted} entri dihapus`); ui.load(); } catch (e) { fail(e); }
  }

  function mount(root, arg) {
    const f = { q: (arg && arg.q) || "", methods: "", status_class: "", host: "", in_scope: false, body: false, page: 1, sort: "id", dir: "desc", page_size: 100, source: "" };
    const search = h("input", { type: "search", placeholder: "Cari host / URL / metode / status…", "aria-label": "Cari", value: f.q, style: { width: "240px" } });
    const mSel = h("select", { "aria-label": "Metode" }, [["", "Semua metode"], ["GET", "GET"], ["POST", "POST"], ["PUT", "PUT"], ["DELETE", "DELETE"], ["PATCH", "PATCH"], ["OPTIONS", "OPTIONS"], ["HEAD", "HEAD"]].map(([v, t]) => h("option", { value: v, text: t })));
    const sSel = h("select", { "aria-label": "Status" }, [["", "Semua status"], ["2", "2xx"], ["3", "3xx"], ["4", "4xx"], ["5", "5xx"], ["0", "Error/Drop"]].map(([v, t]) => h("option", { value: v, text: t })));
    const srcSel = h("select", { "aria-label": "Sumber" }, [["", "Semua sumber"], ["proxy", "Proxy"], ["repeater", "Repeater"]].map(([v, t]) => h("option", { value: v, text: t })));
    const hostSel = h("select", { "aria-label": "Host", style: { maxWidth: "200px" } }, h("option", { value: "", text: "Semua host" }));
    const scopeChk = h("input", { type: "checkbox" }), bodyChk = h("input", { type: "checkbox" });
    const info = h("span", { class: "muted small" });
    const pager = h("span", { class: "row" });
    const detail = EX.viewer.exchange();

    const tbl = EX.ui.table([
      { label: "#", key: "id", sort: "id", width: "60px", cls: "num mono" },
      { label: "Waktu", sort: "ts", width: "80px", render: (r) => time(r.ts), cls: "mono" },
      { label: "Host", key: "host", sort: "host", width: "170px" },
      { label: "Metode", key: "method", sort: "method", width: "70px", cls: "mono" },
      { label: "URL", key: "url", sort: "url" },
      { label: "Status", sort: "status", width: "64px", render: (r) => statusEl(r.status) },
      { label: "Tipe", key: "content_type", sort: "content_type", width: "140px", render: (r) => (r.content_type || "").split(";")[0] },
      { label: "Ukuran", sort: "resp_size", width: "80px", cls: "num", render: (r) => bytes(r.resp_size) },
      { label: "Durasi", sort: "duration_ms", width: "80px", cls: "num", render: (r) => ms(r.duration_ms) },
      { label: "Scope", width: "56px", render: (r) => (r.in_scope ? "✓" : "") },
    ], {
      multi: true, empty: "Belum ada riwayat. Jalankan proxy dan telusuri situs, atau kirim request dari Repeater.",
      sort: { key: "id", dir: "desc" }, onSort: (s) => { f.sort = s.key; f.dir = s.dir; f.page = 1; load(); },
      onSelect: async (row) => { try { detail.show(await EX.api.get("/api/history/" + row.id)); } catch (e) { fail(e); } },
      onContext: (e, row, ids) => ctxActions(e, row, ids),
    });

    async function load() {
      const q = { q: search.value.trim(), methods: mSel.value, status_class: sSel.value, host: hostSel.value, in_scope: scopeChk.checked, body: bodyChk.checked, source: srcSel.value, page: f.page, page_size: f.page_size, sort: f.sort, dir: f.dir };
      try {
        const r = await EX.api.get("/api/history", q);
        tbl.render(r.items);
        const pages = Math.max(1, Math.ceil(r.total / f.page_size));
        info.textContent = `${r.total.toLocaleString("id-ID")} entri · halaman ${f.page}/${pages}`;
        pager.replaceChildren(btn("", { cls: "sm", icon: "forward", title: "Sebelumnya", disabled: f.page <= 1, onclick: () => { f.page--; load(); } }),
          btn("", { cls: "sm", icon: "forward", title: "Berikutnya", disabled: f.page >= pages, onclick: () => { f.page++; load(); } }));
        pager.firstChild.style.transform = "scaleX(-1)";
      } catch (e) { fail(e); }
    }
    async function loadHosts() { try { const r = await EX.api.get("/api/history/hosts"); const cur = hostSel.value; hostSel.replaceChildren(h("option", { value: "", text: "Semua host" }), ...r.hosts.map((x) => h("option", { value: x, text: x }))); hostSel.value = cur; } catch (e) { /* noop */ } }
    const reload = () => { f.page = 1; load(); };
    const reloadSoft = debounce(load, 150);
    search.addEventListener("input", debounce(reload, 300));
    [mSel, sSel, srcSel, hostSel, scopeChk, bodyChk].forEach((el) => el.addEventListener("change", reload));

    const exportSel = async (fmt) => {
      const ids = tbl.selected(); if (!ids.length) return toast("Pilih entri terlebih dahulu (Ctrl/Shift untuk banyak)", "warn");
      try { await EX.api.download("POST", "/api/history/export", { ids, format: fmt }); } catch (e) { fail(e); }
    };
    const bar = h("div", { class: "toolbar" }, search, mSel, sSel, srcSel, hostSel,
      h("label", { class: "chk" }, scopeChk, "Hanya scope"), h("label", { class: "chk", title: "Cari juga di body request/respons" }, bodyChk, "Cari body"),
      h("span", { class: "grow" }), info, pager,
      btn("Ekspor JSON", { cls: "sm", icon: "download", onclick: () => exportSel("json") }), btn("Ekspor HAR", { cls: "sm", onclick: () => exportSel("har") }),
      btn("Hapus terpilih", { cls: "sm danger", icon: "trash", onclick: () => del(tbl.selected()) }),
      btn("Hapus semua", { cls: "sm danger", onclick: async () => { if (await confirmBox("Hapus SELURUH riwayat HTTP? Tindakan ini tidak dapat dibatalkan.", "Hapus semua")) { try { await EX.api.post("/api/history/delete", { all: true }); tbl.clearSel(); detail.clear(); load(); } catch (e) { fail(e); } } } }),
      btn("", { cls: "sm", icon: "refresh", title: "Muat ulang", onclick: () => { load(); loadHosts(); } }));
    root.append(bar, EX.ui.split("v", h("div", { class: "reqbox" }, tbl.el), detail.el, 48, "history"));
    root.lastChild.style.flex = "1";
    ui = { load, loadHosts };
    load(); loadHosts();
    if (EX.state.pendingOpen) { const id = EX.state.pendingOpen; EX.state.pendingOpen = null; EX.api.get("/api/history/" + id).then((d) => detail.show(d)).catch(fail); }
    mod.onEvent = (ev) => { if (ev.type === "history" && f.page === 1 && f.sort === "id" && f.dir === "desc") reloadSoft(); };
  }
  const mod = { title: "Riwayat HTTP", mount, unmount() { ui = null; } };
  EX.modules.history = mod;
})();
