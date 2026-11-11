"use strict";
(() => {
  const { h, btn, fail, toast, modal, confirmBox, time, bytes } = EX.ui;
  const SPEC = [
    ["Proxy", [
      ["proxy.host", "Alamat listen proxy", "text", "Gunakan 127.0.0.1. Alamat non-loopback butuh proxy.allow_remote."],
      ["proxy.port", "Port proxy", "number"], ["proxy.allow_remote", "Izinkan bind non-localhost", "bool", "BERISIKO: proxy tidak punya autentikasi."],
      ["proxy.autostart", "Mulai proxy otomatis", "bool"], ["proxy.mitm_https", "Intersepsi HTTPS (MITM)", "bool", "Jika mati, HTTPS dilewatkan sebagai tunnel tanpa inspeksi."],
      ["proxy.verify_upstream", "Verifikasi sertifikat server tujuan", "bool"], ["proxy.intercept_only_in_scope", "Intercept hanya request dalam scope", "bool"],
      ["proxy.only_in_scope_history", "Simpan riwayat hanya untuk scope", "bool"], ["proxy.intercept_timeout", "Timeout intercept (detik)", "number", "Item yang tidak diputuskan akan di-drop."],
      ["proxy.upstream_timeout", "Timeout upstream (detik)", "number"], ["proxy.max_body_bytes", "Maks body disimpan per pesan (byte)", "number"],
      ["proxy.ignore_hosts", "Host tanpa intersepsi (satu per baris, wildcard)", "list", "Mis. *.bank.example — TLS dilewatkan tanpa dibongkar."]]],
    ["Riwayat", [["history.max_entries", "Maks entri riwayat", "number", "Entri terlama dihapus otomatis."]]],
    ["Jaringan (Repeater/Intruder/Scanner)", [
      ["network.enforce_scope", "Wajibkan scope untuk aksi aktif", "bool", "Sangat disarankan tetap aktif."], ["network.request_timeout", "Timeout request (detik)", "number"],
      ["network.max_response_bytes", "Maks ukuran respons (byte)", "number"], ["network.blocked_hosts", "Host diblokir (wildcard, satu per baris)", "list"]]],
    ["Intruder", [["intruder.max_requests", "Maks request per serangan", "number"], ["intruder.max_concurrency", "Maks concurrency", "number"], ["intruder.max_rps", "Maks request/detik", "number"]]],
    ["Scanner", [["scanner.passive_enabled", "Analisis pasif otomatis", "bool"]]],
    ["Sesi", [["session.autosave", "Autosave", "bool"], ["session.autosave_minutes", "Interval autosave (menit)", "number"]]],
    ["Server UI", [["server.host", "Alamat bind UI", "text", "Perlu restart. Non-localhost wajib token."], ["server.port", "Port UI", "number", "Perlu restart."], ["server.auth_token", "Token autentikasi (min. 16 karakter)", "password", "Kosongkan = tanpa autentikasi (hanya aman di localhost)."]]],
  ];
  const getp = (o, p) => p.split(".").reduce((a, k) => (a ? a[k] : undefined), o);

  async function mount(root) {
    let cfg, paths;
    try { const r = await EX.api.get("/api/settings"); cfg = r.settings; paths = r.paths; } catch (e) { return fail(e); }
    const inputs = {};
    const form = h("div", { class: "form" });
    for (const [title, fields] of SPEC) {
      form.append(h("h4", { text: title }));
      for (const [key, label, type, hint] of fields) {
        const v = getp(cfg, key); let el;
        if (type === "bool") { el = h("button", { class: "switch", type: "button", role: "switch", "aria-checked": String(!!v), "aria-label": label, onclick: (e) => e.target.setAttribute("aria-checked", String(e.target.getAttribute("aria-checked") !== "true")) }); }
        else if (type === "list") { el = h("textarea", { rows: 3, "aria-label": label, style: { width: "100%" } }); el.value = (v || []).join("\n"); }
        else { el = h("input", { type, "aria-label": label, autocomplete: "off", style: { width: type === "number" ? "140px" : "280px" } }); el.value = v ?? ""; }
        inputs[key] = { el, type };
        form.append(h("label", { text: label, for: "" }), el);
        if (hint) form.append(h("div", { class: "hint", text: hint }));
      }
    }
    async function save() {
      const patch = {};
      for (const [key, { el, type }] of Object.entries(inputs)) {
        const [s, k] = key.split("."); patch[s] = patch[s] || {};
        patch[s][k] = type === "bool" ? el.getAttribute("aria-checked") === "true" : type === "number" ? Number(el.value) : type === "list" ? el.value.split(/\r?\n/).map((x) => x.trim()).filter(Boolean) : el.value;
      }
      try {
        const r = await EX.api.put("/api/settings", patch);
        toast(r.restart_required ? "Tersimpan. Restart aplikasi agar alamat/port UI berlaku." : "Pengaturan tersimpan", r.restart_required ? "warn" : ""); EX.refreshStatus();
      } catch (e) { fail(e); }
    }
    // sesi
    const sessBox = h("div", { class: "col" });
    async function loadSessions() {
      try {
        const r = await EX.api.get("/api/sessions");
        sessBox.replaceChildren(
          h("div", { class: "small muted", text: r.current.name ? `Sesi aktif: ${r.current.name}` : "Belum ada sesi bernama disimpan." }),
          ...r.items.map((s) => h("div", { class: "row small" }, h("span", { style: { flex: "1" }, text: `${s.name} · ${bytes(s.size)} · ${time(s.modified, true)}` }),
            btn("Muat", { cls: "sm", onclick: async () => { if (await confirmBox(`Muat sesi "${s.name}"? Data saat ini akan diganti.`, "Muat")) { try { const x = await EX.api.post("/api/sessions/load", { name: s.name }); toast(`Sesi dimuat (${x.loaded.history} request)`); loadSessions(); } catch (e) { fail(e); } } } }),
            btn("", { cls: "sm danger", icon: "trash", onclick: async () => { try { await EX.api.del("/api/sessions/" + encodeURIComponent(s.name)); loadSessions(); } catch (e) { fail(e); } } }))),
          h("b", { class: "small", style: { marginTop: "8px" }, text: "Autosave / pemulihan" }),
          ...(r.autosaves.length ? r.autosaves.map((s) => h("div", { class: "row small" }, h("span", { style: { flex: "1" }, text: `${s.name} · ${bytes(s.size)}` }),
            btn("Pulihkan", { cls: "sm", onclick: async () => { if (await confirmBox(`Pulihkan dari ${s.name}? Data saat ini akan diganti.`, "Pulihkan")) { try { await EX.api.post("/api/sessions/recover", { name: s.name }); toast("Data dipulihkan"); } catch (e) { fail(e); } } } }))) : [h("span", { class: "muted small", text: "Belum ada autosave." })]));
      } catch (e) { fail(e); }
    }
    const file = h("input", { type: "file", accept: ".exvolt,application/gzip", class: "hidden", onchange: async (e) => {
      const f = e.target.files[0]; if (!f) return;
      try { const merge = !(await confirmBox("Ganti seluruh data dengan sesi ini? (Batal = gabungkan ke data yang ada)", "Ganti")); const r = await fetch("/api/sessions/import" + (merge ? "?replace=0" : ""), { method: "POST", headers: { "X-Requested-With": "exvolt", "Content-Type": "application/octet-stream" }, body: await f.arrayBuffer(), credentials: "same-origin" }); const j = await r.json(); if (!r.ok) throw new Error(j.error); toast(`Sesi diimpor (${j.imported.history} request)`); loadSessions(); } catch (x) { fail(x); }
      e.target.value = "";
    } });
    const ca = h("div", { class: "small muted" });
    EX.api.get("/api/proxy/status").then((s) => { ca.textContent = `CA: ${s.ca.subject} · sha256 ${s.ca.sha256.slice(0, 24)}… · lokasi ${s.ca.path}`; }).catch(() => {});
    root.append(h("div", { class: "page" }, h("div", { class: "col", style: { maxWidth: "800px", gap: "20px" } },
      form, h("div", { class: "row" }, btn("Simpan pengaturan", { cls: "primary", icon: "save", onclick: save })),
      h("div", { class: "panel" }, h("header", { text: "Sesi" }), h("div", { class: "body col" }, h("div", { class: "row wrap" },
        btn("Simpan sesi…", { cls: "sm", icon: "save", onclick: async () => { const r = await modal("Simpan sesi", [{ name: "n", label: "Nama sesi", value: "sesi-" + new Date().toISOString().slice(0, 10) }], "Simpan"); if (r && r.n.trim()) { try { await EX.api.post("/api/sessions/save", { name: r.n.trim() }); toast("Sesi tersimpan"); loadSessions(); } catch (e) { fail(e); } } } }),
        btn("Ekspor sesi", { cls: "sm", icon: "download", onclick: () => EX.api.download("GET", "/api/sessions/export").catch(fail) }), btn("Impor sesi", { cls: "sm", icon: "upload", onclick: () => file.click() }), file,
        btn("Autosave sekarang", { cls: "sm", onclick: async () => { try { await EX.api.post("/api/sessions/autosave"); toast("Autosave dibuat"); loadSessions(); } catch (e) { fail(e); } } })), sessBox)),
      h("div", { class: "panel" }, h("header", { text: "Sertifikat CA & penyimpanan" }), h("div", { class: "body col" }, ca,
        h("div", { class: "small muted", text: `Data: ${paths.data} · Sertifikat: ${paths.certificates}` }),
        h("div", { class: "row" }, btn("Unduh CA (PEM)", { cls: "sm", icon: "download", onclick: () => EX.api.download("GET", "/api/proxy/ca").catch(fail) }),
          btn("Buat ulang CA", { cls: "sm danger", onclick: async () => { if (await confirmBox("Buat ulang CA? Sertifikat lama berhenti berlaku dan CA baru harus diinstal ulang di browser.", "Buat ulang")) { try { await EX.api.post("/api/proxy/ca/regenerate", { confirm: true }); toast("CA baru dibuat", "warn"); } catch (e) { fail(e); } } } })))),
      h("div", { class: "small muted", text: "EXVOLT X 1.0.0 · MIT · Dipublikasikan oleh EXELYN404 · tanpa telemetri, tanpa unggahan otomatis." }))));
    loadSessions();
  }
  EX.modules.settings = { title: "Pengaturan", mount };
})();
