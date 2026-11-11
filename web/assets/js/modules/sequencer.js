"use strict";
(() => {
  const { h, btn, fail, toast, modal, confirmBox, time } = EX.ui;

  function mount(root, arg) {
    let selected = null;
    const out = h("div", { class: "pane-body", style: { padding: "14px 16px" } }, h("div", { class: "empty", text: "Pilih set token lalu klik Analisis." }));
    const live = h("div", { class: "small muted" });
    const tbl = EX.ui.table([{ label: "Set", key: "name" }, { label: "Sumber", key: "source" }, { label: "Token", key: "count", width: "70px", cls: "num" }, { label: "Dibuat", width: "70px", render: (r) => time(r.created), cls: "mono" }],
      { key: (r) => r.name, empty: "Belum ada set token.", onSelect: (r) => { selected = r.name; analyze(); } });
    const kindFields = [{ name: "kind", label: "Sumber token", type: "select", options: [{ value: "cookie", label: "Cookie (Set-Cookie)" }, { value: "header", label: "Header respons" }, { value: "body_regex", label: "Regex pada body (grup 1)" }] },
      { name: "extract", label: "Nama cookie / header / regex", placeholder: "mis. PHPSESSID" }];
    async function load() {
      try { const r = await EX.api.get("/api/sequencer/sets"); tbl.render(r.sets); const l = Object.entries(r.live); live.textContent = l.length ? "Penangkapan live aktif: " + l.map(([k, v]) => `${k} (${v.kind}:${v.extract})`).join(", ") : "Tidak ada penangkapan live."; } catch (e) { fail(e); }
    }
    function metric(label, value) { return h("div", { class: "panel stat" }, h("small", { text: label }), h("b", { style: { fontSize: "20px" }, text: String(value) })); }
    async function analyze() {
      if (!selected) return;
      try {
        const a = await EX.api.get(`/api/sequencer/${encodeURIComponent(selected)}/analyze`);
        const kids = [h("h3", { style: { margin: "0 0 8px" }, text: `Analisis: ${a.set}` }),
          h("div", { class: "grid", style: { gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))" } }, metric("Jumlah token", a.count), metric("Unik", a.unique), metric("Duplikat", a.duplicates),
            metric("Panjang (min/rata/maks)", `${a.length.min}/${a.length.mean}/${a.length.max}`), metric("Ukuran charset", a.charset_size), metric("Entropi/karakter (bit)", a.entropy_per_char_bits), metric("Estimasi entropi total (bit)", a.entropy_total_est_bits))];
        if (a.bit_test) kids.push(h("p", { class: "mono small", text: `Uji bit: ${a.bit_test.bits} bit · rasio 1 = ${a.bit_test.ones_ratio} · monobit p=${a.bit_test.monobit_p}${a.bit_test.runs_p !== undefined ? " · runs p=" + a.bit_test.runs_p : ""}` }));
        if (a.numeric) kids.push(h("p", { class: "mono small", text: `Numerik: monotonik naik=${a.numeric.monotonic_increasing} · selisih dominan=${a.numeric.common_delta} (${(a.numeric.common_delta_share * 100).toFixed(0)}%)` }));
        if (a.position_entropy) { const ch = h("div", { class: "seq-chart", role: "img", "aria-label": "Entropi per posisi karakter" }); const mx = Math.max(...a.position_entropy, 1); a.position_entropy.forEach((v, i) => { const b = h("i", { title: `posisi ${i + 1}: ${v} bit` }); b.style.height = (v / mx) * 100 + "%"; ch.append(b); }); kids.push(h("b", { text: "Entropi per posisi" }), ch); }
        kids.push(h("p", { class: "mono small", text: `Charset: ${a.charset}` }), h("p", { class: "mono small", text: `Awalan bersama: ${a.common_prefix || "(tidak ada)"}` }),
          h("b", { text: "Observasi" }), h("ul", {}, a.observations.map((o) => h("li", { text: o }))));
        out.replaceChildren(...kids);
      } catch (e) { out.replaceChildren(h("div", { class: "errbox", text: e.message })); }
    }
    async function liveStart() {
      const r = await modal("Tangkap token dari lalu lintas proxy", [{ name: "name", label: "Nama set", value: "sesi" }, ...kindFields], "Mulai tangkap"); if (!r) return;
      try { await EX.api.post("/api/sequencer/live", { name: r.name, kind: r.kind, extract: r.extract }); toast("Penangkapan live aktif: token baru dari proxy akan dikumpulkan"); load(); } catch (e) { fail(e); }
    }
    async function fromHistory(ids) {
      const r = await modal(`Ekstrak token dari ${ids.length} entri riwayat`, [{ name: "name", label: "Nama set", value: "riwayat" }, ...kindFields], "Ekstrak"); if (!r) return;
      try { const x = await EX.api.post("/api/sequencer/from-history", { name: r.name, kind: r.kind, extract: r.extract, ids }); toast(`${x.added} token ditambahkan`); load(); } catch (e) { fail(e); }
    }
    async function manual() {
      const r = await modal("Tempel token manual", [{ name: "name", label: "Nama set", value: "manual" }, { name: "text", label: "Token (satu per baris)", type: "textarea", rows: 8 }], "Simpan"); if (!r) return;
      try { const x = await EX.api.post("/api/sequencer/manual", { name: r.name, text: r.text }); toast(`${x.added} token disimpan`); load(); } catch (e) { fail(e); }
    }
    root.append(h("div", { class: "toolbar" }, btn("Tangkap live", { cls: "sm primary", icon: "play", onclick: liveStart }),
      btn("Hentikan live", { cls: "sm", icon: "stop", onclick: async () => { try { const r = await EX.api.get("/api/sequencer/sets"); for (const k of Object.keys(r.live)) await EX.api.post("/api/sequencer/live", { action: "stop", name: k }); load(); } catch (e) { fail(e); } } }),
      btn("Tempel manual", { cls: "sm", onclick: manual }), btn("Analisis", { cls: "sm", onclick: analyze }),
      btn("Ekspor", { cls: "sm", icon: "download", onclick: () => selected ? EX.api.download("GET", `/api/sequencer/${encodeURIComponent(selected)}/export`).catch(fail) : toast("Pilih set", "warn") }),
      btn("Hapus set", { cls: "sm danger", icon: "trash", onclick: async () => { if (selected && await confirmBox(`Hapus set "${selected}"?`, "Hapus")) { try { await EX.api.del("/api/sequencer/" + encodeURIComponent(selected)); selected = null; load(); } catch (e) { fail(e); } } } }),
      h("span", { class: "grow" }), live),
    EX.ui.split("h", h("div", { class: "reqbox" }, tbl.el), h("div", { class: "reqbox" }, h("div", { class: "pane-head" }, h("h3", { text: "Hasil analisis" })), out), 38, "seq"));
    root.lastChild.style.flex = "1";
    load();
    mod.onEvent = (ev) => { if (ev.type === "sequencer") { load(); if (selected === ev.data.set) analyze(); } };
    if (arg && arg.fromHistory) fromHistory(arg.fromHistory);
  }
  const mod = { title: "Sequencer", mount };
  EX.modules.sequencer = mod;
})();
