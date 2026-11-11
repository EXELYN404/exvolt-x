"use strict";
(() => {
  const { h, btn, fail, toast } = EX.ui;

  function mount(root) {
    const sides = {};
    const mkSide = (key, title) => {
      const ta = h("textarea", { class: "editor", spellcheck: "false", wrap: "off", "aria-label": `Teks ${title}`, placeholder: "Tempel teks, atau muat dari riwayat HTTP…" });
      const idIn = h("input", { type: "number", min: "1", placeholder: "ID riwayat", "aria-label": `ID riwayat ${title}`, style: { width: "100px" } });
      const part = h("select", { "aria-label": "Bagian" }, [["response", "Response"], ["request", "Request"]].map(([v, t]) => h("option", { value: v, text: t })));
      const label = h("span", { class: "muted small" });
      const loadH = async (id, p) => { try { const d = await EX.api.get("/api/history/" + id); ta.value = p === "request" ? d.request.raw : d.response.raw_head + d.response.body; label.textContent = `#${id} ${p}`; } catch (e) { fail(e); } };
      sides[key] = { ta };
      const el = h("div", { class: "reqbox" }, h("div", { class: "pane-head" }, h("h3", { text: title }), idIn, part, btn("Muat", { cls: "sm", onclick: () => idIn.value && loadH(idIn.value, part.value) }), label), h("div", { class: "pane-body", style: { overflow: "hidden" } }, ta));
      const pend = EX.state.cmp && EX.state.cmp[key];
      if (pend) { idIn.value = pend.history_id; part.value = pend.part; loadH(pend.history_id, pend.part); }
      return el;
    };
    const mode = h("select", { "aria-label": "Mode" }, [["text", "Teks (per baris)"], ["json", "JSON (struktural)"]].map(([v, t]) => h("option", { value: v, text: t })));
    const ws = h("input", { type: "checkbox" }), cs = h("input", { type: "checkbox" });
    const result = h("div", { class: "pane-body" }, h("div", { class: "empty", text: "Tekan Bandingkan untuk melihat perbedaan." }));
    const sum = h("span", { class: "muted small" });
    let last = null;
    const payload = () => ({ left: { text: sides.left.ta.value }, right: { text: sides.right.ta.value }, mode: mode.value, ignore_whitespace: ws.checked, ignore_case: cs.checked });
    async function compare() {
      try {
        const r = await EX.api.post("/api/comparer/compare", payload()); last = r;
        sum.textContent = r.identical ? "Identik" : `${r.changes} perbedaan`;
        if (r.mode === "text") {
          result.replaceChildren(h("div", {}, ...r.rows.map((x) => h("div", { class: "diff-row " + x.op }, h("span", { class: "ln", text: x.ln ?? "" }), h("span", { text: x.l ?? "" }), h("span", { class: "ln", text: x.rn ?? "" }), h("span", { text: x.r ?? "" })))));
        } else {
          result.replaceChildren(r.diffs.length ? h("div", {}, ...r.diffs.map((d) => h("div", { class: "diff-row " + d.op, style: { gridTemplateColumns: "1fr 1fr 1fr" } }, h("span", { class: "em", text: d.path }), h("span", { text: JSON.stringify(d.l) ?? "" }), h("span", { text: JSON.stringify(d.r) ?? "" })))) : h("div", { class: "empty", text: "JSON identik secara struktural." }));
        }
      } catch (e) { fail(e); }
    }
    const exp = (fmt) => EX.api.download("POST", "/api/comparer/export", { ...payload(), format: fmt }).catch(fail);
    const swap = () => { const a = sides.left.ta.value; sides.left.ta.value = sides.right.ta.value; sides.right.ta.value = a; };
    root.append(h("div", { class: "toolbar" }, mode, h("label", { class: "chk" }, ws, "Abaikan whitespace"), h("label", { class: "chk" }, cs, "Abaikan huruf besar/kecil"),
      btn("Bandingkan", { cls: "primary", onclick: compare }), btn("Tukar", { cls: "sm", icon: "swap", onclick: swap }), sum, h("span", { class: "grow" }),
      btn("Ekspor HTML", { cls: "sm", icon: "download", onclick: () => exp("html") }), btn("Ekspor JSON", { cls: "sm", onclick: () => exp("json") })),
    EX.ui.split("v", EX.ui.split("h", mkSide("left", "Kiri"), mkSide("right", "Kanan"), 50, "cmp-io"), h("div", { class: "reqbox" }, h("div", { class: "pane-head" }, h("h3", { text: "Perbedaan" })), result), 45, "cmp"));
    root.lastChild.style.flex = "1";
    EX.state.cmp = {};
  }
  EX.modules.comparer = { title: "Comparer", mount };
})();
