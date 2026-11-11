"use strict";
(() => {
  const { h, btn, fail, toast, confirmBox } = EX.ui;
  const HINT = { domain: "contoh: example.com atau *.example.com", ip: "contoh: 127.0.0.1 atau 10.0.0.0/24", port: "contoh: 8080", url: "awalan URL (https://x.test/app) atau regex dengan awalan re:" };

  function mount(root) {
    const action = h("select", { "aria-label": "Aksi" }, [["include", "Include"], ["exclude", "Exclude"]].map(([v, t]) => h("option", { value: v, text: t })));
    const type = h("select", { "aria-label": "Tipe" }, [["domain", "Domain"], ["ip", "IP / CIDR"], ["port", "Port"], ["url", "URL"]].map(([v, t]) => h("option", { value: v, text: t })));
    const value = h("input", { type: "text", placeholder: HINT.domain, "aria-label": "Nilai aturan", style: { flex: "1", minWidth: "220px" } });
    const note = h("input", { type: "text", placeholder: "catatan (opsional)", "aria-label": "Catatan", style: { width: "180px" } });
    type.addEventListener("change", () => { value.placeholder = HINT[type.value]; });
    const banner = h("div", { class: "hidden" });
    const test = h("input", { type: "text", placeholder: "https://target/path — uji apakah diizinkan", "aria-label": "Uji URL", style: { flex: "1", minWidth: "240px" } });
    const testOut = h("span", { class: "small" });
    const tbl = EX.ui.table([
      { label: "Aktif", width: "56px", render: (r) => h("input", { type: "checkbox", checked: !!r.enabled, "aria-label": "Aktif", onchange: async (e) => { try { await EX.api.patch("/api/scope/" + r.id, { enabled: e.target.checked }); await EX.api.post("/api/scope/recompute"); load(); EX.refreshStatus(); } catch (x) { fail(x); } } }) },
      { label: "Aksi", width: "80px", render: (r) => h("span", { class: r.action === "include" ? "em" : "s5xx", text: r.action }) }, { label: "Tipe", key: "type", width: "70px" },
      { label: "Nilai", key: "value", cls: "mono" }, { label: "Catatan", key: "note" },
      { label: "", width: "40px", render: (r) => btn("", { cls: "sm danger", icon: "trash", title: "Hapus aturan", onclick: async () => { try { await EX.api.del("/api/scope/" + r.id); await EX.api.post("/api/scope/recompute"); load(); EX.refreshStatus(); } catch (x) { fail(x); } } }) },
    ], { empty: "Scope kosong. Tanpa aturan include, semua aksi aktif (Repeater, Intruder, probe TLS) diblokir." });
    async function load() {
      try {
        const r = await EX.api.get("/api/scope"); tbl.render(r.rules);
        const inc = r.rules.filter((x) => x.enabled && x.action === "include").length;
        banner.className = inc ? "okbox" : "warnbox";
        banner.textContent = (inc ? `${inc} aturan include aktif.` : "Belum ada aturan include aktif: tidak ada target yang dianggap berwenang.") + (r.enforce ? " Penegakan scope: AKTIF." : " Penegakan scope: NONAKTIF (Pengaturan → Jaringan).");
      } catch (e) { fail(e); }
    }
    async function add() {
      try { await EX.api.post("/api/scope", { action: action.value, type: type.value, value: value.value.trim(), note: note.value.trim() }); await EX.api.post("/api/scope/recompute"); value.value = ""; note.value = ""; load(); EX.refreshStatus(); } catch (e) { fail(e); }
    }
    value.addEventListener("keydown", (e) => { if (e.key === "Enter") add(); });
    async function check() {
      try { const r = await EX.api.post("/api/scope/check", { url: test.value.trim() }); testOut.className = "small " + (r.allowed ? "em" : "s5xx"); testOut.textContent = (r.allowed ? "DIIZINKAN — " : "DITOLAK — ") + r.reason; } catch (e) { testOut.className = "small s5xx"; testOut.textContent = e.message; }
    }
    const file = h("input", { type: "file", accept: ".json,application/json", class: "hidden", onchange: async (e) => {
      const f = e.target.files[0]; if (!f) return;
      try { const data = JSON.parse(await f.text()); const replace = await confirmBox("Ganti seluruh scope yang ada dengan berkas ini? (Batal = tambahkan saja)", "Ganti"); const r = await EX.api.post("/api/scope/import", { data, replace }); toast(`${r.imported} aturan diimpor`); await EX.api.post("/api/scope/recompute"); load(); EX.refreshStatus(); } catch (x) { fail(x); }
      e.target.value = "";
    } });
    root.append(h("div", { class: "toolbar" }, action, type, value, note, btn("Tambah", { cls: "primary", icon: "plus", onclick: add })),
      h("div", { style: { padding: "8px 12px" } }, banner),
      h("div", { class: "toolbar" }, test, btn("Uji", { cls: "sm", onclick: check }), testOut, h("span", { class: "grow" }),
        btn("Ekspor", { cls: "sm", icon: "download", onclick: () => EX.api.download("GET", "/api/scope/export").catch(fail) }), btn("Impor", { cls: "sm", icon: "upload", onclick: () => file.click() }), file),
      tbl.el);
    load();
  }
  EX.modules.scope = { title: "Scope", mount };
})();
