"use strict";
/* Penampil pesan HTTP: Raw / Pretty / Header / Body */
EX.viewer = (() => {
  const { h, codeView } = EX.ui;
  const MODES = [["raw", "Raw"], ["pretty", "Pretty"], ["headers", "Header"], ["body", "Body"]];
  function message(title) {
    const cv = codeView(() => "", { title });
    let mode = "raw", msg = null;
    const bar = h("div", { class: "tabs", role: "tablist" });
    MODES.forEach(([id, label]) => bar.append(h("button", { class: "tab" + (id === mode ? " active" : ""), role: "tab", dataset: { id }, text: label, onclick: () => { mode = id; paint(); } })));
    function text() {
      if (!msg) return "";
      const head = msg.head || "";
      if (mode === "raw") return head + (msg.body || "");
      if (mode === "pretty") return head + (msg.pretty ?? msg.body ?? "");
      if (mode === "headers") return head.trim() || "(tidak ada header)";
      return msg.pretty ?? msg.body ?? "";
    }
    function paint() {
      [...bar.children].forEach((b) => { const on = b.dataset.id === mode; b.classList.toggle("active", on); b.setAttribute("aria-selected", on); });
      cv.set(text());
    }
    const el = h("div", { class: "reqbox" }, bar, cv.el);
    cv.el.style.flex = "1"; cv.el.style.minHeight = "0";
    return { el, show(m) { msg = m; paint(); }, clear() { msg = null; paint(); } };
  }
  /* pasangan request/response dari detail riwayat */
  function exchange() {
    const req = message("Request"), res = message("Response");
    const info = h("div", { class: "pane-head small muted", text: "Pilih entri untuk melihat detail." });
    const root = h("div", { class: "reqbox" }, info, EX.ui.split("h", req.el, res.el, 50, "exchange"));
    root.lastChild.style.flex = "1";
    return {
      el: root,
      show(d) {
        const reqHead = d.request.raw.split(/\r?\n\r?\n/)[0] + "\r\n\r\n";
        req.show({ head: reqHead, body: d.request.body, pretty: d.request.body_pretty });
        res.show({ head: d.response.raw_head, body: d.response.body, pretty: d.response.body_pretty });
        const bits = [`#${d.id}`, `${d.method} ${d.url}`, d.status ? `status ${d.status}` : "tanpa respons", EX.ui.ms(d.duration_ms), EX.ui.bytes(d.response.size)];
        if (d.tls) bits.push(`${d.tls.version} ${d.tls.cipher || ""}`);
        if (d.error) bits.push("ERROR: " + d.error);
        if (d.truncated) bits.push("body dipotong (melebihi batas simpan)");
        if (d.response.decode_note) bits.push("encoding: " + d.response.decode_note);
        info.textContent = bits.join("  ·  ");
      },
      clear() { req.clear(); res.clear(); info.textContent = "Pilih entri untuk melihat detail."; },
    };
  }
  return { message, exchange };
})();
