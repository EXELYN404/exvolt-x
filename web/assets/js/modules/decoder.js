"use strict";
(() => {
  const { h, btn, fail, toast, copy, time } = EX.ui;
  const LABELS = { url: "URL", base64: "Base64", base64url: "Base64 URL-safe", hex: "Hex", html: "Entitas HTML", unicode: "Unicode (\\uXXXX)", json: "JSON (minify / pretty)", jwt: "JWT (inspeksi)", sha256: "SHA-256", sha512: "SHA-512", sha1: "SHA-1", md5: "MD5 (legacy)" };
  let hist = [];

  async function mount(root) {
    let types = {};
    try { types = (await EX.api.get("/api/decoder/types")).types; } catch (e) { return fail(e); }
    const sel = h("select", { "aria-label": "Jenis transformasi" }, Object.keys(types).map((k) => h("option", { value: k, text: LABELS[k] || k })));
    const input = h("textarea", { class: "editor", spellcheck: "false", "aria-label": "Input", placeholder: "Input…", wrap: "soft" });
    const output = h("textarea", { class: "editor", spellcheck: "false", "aria-label": "Output", placeholder: "Output…", readonly: true, wrap: "soft" });
    const encBtn = btn("Encode", { cls: "primary" }), decBtn = btn("Decode", { cls: "primary" });
    const note = h("span", { class: "muted small" });
    const histBox = h("div", { class: "pane-body" });
    const sync = () => { const t = types[sel.value]; encBtn.disabled = !t.includes("encode"); decBtn.disabled = !t.includes("decode"); note.textContent = encBtn.disabled ? "Hanya decode/inspeksi" : decBtn.disabled ? "Hash satu arah (hanya encode)" : ""; };
    sel.addEventListener("change", sync); sync();
    async function run(dir) {
      try {
        const r = await EX.api.post("/api/decoder/" + dir, { type: sel.value, text: input.value });
        output.value = r.output;
        hist.unshift({ ts: Date.now() / 1000, type: sel.value, dir, input: input.value, output: r.output }); hist = hist.slice(0, 50); drawHist();
      } catch (e) { output.value = ""; fail(e); }
    }
    encBtn.onclick = () => run("encode"); decBtn.onclick = () => run("decode");
    function drawHist() {
      histBox.replaceChildren(...(hist.length ? hist.map((x) => h("div", { class: "row small", style: { padding: "5px 10px", borderBottom: "1px solid var(--line)", cursor: "pointer" }, title: "Klik untuk memuat input", onclick: () => { input.value = x.input; output.value = x.output; sel.value = x.type; sync(); } },
        h("span", { class: "mono muted", text: time(x.ts) }), h("span", { class: "em", text: `${x.dir} ${x.type}` }), h("span", { class: "mono muted", style: { overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }, text: x.input.slice(0, 60) }))) : [h("div", { class: "empty", text: "Riwayat transformasi kosong." })]));
    }
    drawHist();
    root.append(h("div", { class: "toolbar" }, sel, encBtn, decBtn,
      btn("Swap", { cls: "sm", icon: "swap", title: "Tukar input dan output", onclick: () => { const a = input.value; input.value = output.value; output.value = a; } }),
      btn("Salin output", { cls: "sm", icon: "copy", onclick: () => copy(output.value) }), btn("Bersihkan", { cls: "sm", onclick: () => { input.value = ""; output.value = ""; } }), note),
    EX.ui.split("v", EX.ui.split("h", h("div", { class: "reqbox" }, h("div", { class: "pane-head" }, h("h3", { text: "Input" })), h("div", { class: "pane-body", style: { overflow: "hidden" } }, input)),
      h("div", { class: "reqbox" }, h("div", { class: "pane-head" }, h("h3", { text: "Output" })), h("div", { class: "pane-body", style: { overflow: "hidden" } }, output)), 50, "dec-io"),
    h("div", { class: "reqbox" }, h("div", { class: "pane-head" }, h("h3", { text: "Riwayat transformasi" }), h("span", { class: "grow" }), btn("Kosongkan", { cls: "sm", onclick: () => { hist = []; drawHist(); } })), histBox), 72, "dec"));
    root.lastChild.style.flex = "1";
  }
  EX.modules.decoder = { title: "Decoder", mount };
})();
