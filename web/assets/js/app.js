"use strict";
(() => {
  const { h, $, icon, btn, toast, fail } = EX.ui;
  const NAV = [
    ["overview", "Ringkasan"], ["proxy", "Proxy"], ["history", "Riwayat HTTP"], ["repeater", "Repeater"], ["intruder", "Intruder"],
    ["scanner", "Scanner"], ["sequencer", "Sequencer"], ["decoder", "Decoder"], ["comparer", "Comparer"], ["websocket", "WebSocket"],
    ["scope", "Scope"], ["reports", "Laporan"], ["settings", "Pengaturan"],
  ];
  const state = EX.state;
  state.proxy = { running: false, intercept: false, queue: 0, stats: {} };
  state.counts = { requests: 0 };
  let current = null, pendingArg = null, mounted = null;

  EX.go = (id, arg) => { pendingArg = arg; if (location.hash === "#/" + id) route(); else location.hash = "#/" + id; };

  function buildShell() {
    const app = $("#app");
    const side = h("nav", { id: "sidebar", "aria-label": "Navigasi utama" });
    side.append(h("div", { class: "brand" }, h("span", {}), h("div", {}, h("b", { text: "EXVOLT X" }), h("small", { text: "EXELYN404" }))));
    side.firstChild.firstChild.innerHTML = EX.icons.logo;
    NAV.forEach(([id, label], i) => {
      if (id === "scope") side.append(h("div", { class: "nav-sep" }));
      const a = h("a", { class: "nav", href: "#/" + id, dataset: { id }, title: label }, icon(id), h("span", { text: label }));
      if (id === "proxy") a.append(h("span", { class: "badge hidden", id: "nav-queue" }));
      side.append(a);
    });
    side.append(h("div", { class: "sp" }), h("div", { class: "small muted", style: { padding: "8px" }, text: "v1.0.0 · MIT" }));
    const top = h("header", { id: "topbar" },
      h("h1", { id: "page-title" }),
      h("div", { class: "sp" }),
      h("form", { class: "search", role: "search", onsubmit: (e) => { e.preventDefault(); const v = e.target.q.value.trim(); EX.go("history", { q: v }); } },
        icon("search"), h("input", { name: "q", type: "search", placeholder: "Cari riwayat (host, URL, metode)…", "aria-label": "Cari riwayat" })),
      h("span", { class: "pill", id: "pill-proxy" }, h("span", { class: "dot" }), h("span", { id: "pill-proxy-txt", text: "Proxy mati" })),
      h("label", { class: "chk", title: "Intercept request proxy" }, h("button", { class: "switch", id: "sw-intercept", role: "switch", "aria-checked": "false", "aria-label": "Intercept", onclick: toggleIntercept }), "Intercept"));
    const status = h("footer", { id: "statusbar" }, h("span", { id: "st-proxy", text: "proxy: mati" }), h("span", { id: "st-req", text: "request: 0" }),
      h("span", { id: "st-ws", text: "live: terputus" }), h("span", { id: "st-scope" }), h("span", { class: "sp" }), h("span", { text: "EXVOLT X · EXELYN404" }));
    app.replaceChildren(side, top, h("main", { id: "main" }), status);
  }

  async function toggleIntercept() {
    try { const s = await EX.api.post("/api/proxy/intercept", { enabled: !state.proxy.intercept }); applyProxy(s); } catch (e) { fail(e); }
  }

  function applyProxy(s) {
    Object.assign(state.proxy, s);
    const p = state.proxy;
    $("#pill-proxy .dot").className = "dot " + (p.running ? "on" : "");
    $("#pill-proxy-txt").textContent = p.running ? `Proxy ${p.host}:${p.port}` : "Proxy mati";
    $("#sw-intercept").setAttribute("aria-checked", String(!!p.intercept));
    $("#st-proxy").textContent = p.running ? `proxy: ${p.host}:${p.port}${p.intercept ? " · intercept ON" : ""}` : "proxy: mati";
    const q = $("#nav-queue"); q.textContent = p.queue || ""; q.classList.toggle("hidden", !p.queue);
    if (mounted && mounted.onProxy) mounted.onProxy(p);
  }
  EX.applyProxy = applyProxy;

  async function refreshStatus() {
    try {
      const [p, sc] = await Promise.all([EX.api.get("/api/proxy/status"), EX.api.get("/api/scope")]);
      applyProxy(p);
      const n = sc.rules.filter((r) => r.enabled && r.action === "include").length;
      $("#st-scope").textContent = n ? `scope: ${n} aturan include` : "scope: KOSONG (aksi aktif diblokir)";
    } catch (e) { /* ditangani onUnauthorized */ }
  }
  EX.refreshStatus = refreshStatus;

  function route() {
    const id = (location.hash.replace(/^#\//, "") || "overview").split("?")[0];
    const mod = EX.modules[id] || EX.modules.overview;
    const mid = EX.modules[id] ? id : "overview";
    if (mounted && mounted.unmount) mounted.unmount();
    const main = $("#main");
    const root = h("section", { class: "module", "aria-label": mod.title });
    main.replaceChildren(root);
    current = mid;
    document.querySelectorAll("#sidebar .nav").forEach((a) => { const on = a.dataset.id === mid; a.classList.toggle("active", on); if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current"); });
    $("#page-title").textContent = mod.title;
    document.title = `${mod.title} · EXVOLT X`;
    const arg = pendingArg; pendingArg = null;
    mounted = mod;
    try { mod.mount(root, arg); } catch (e) { console.error(e); root.append(h("div", { class: "empty" }, h("b", { text: "Modul gagal dimuat" }), e.message)); }
  }

  function onEvent(ev) {
    if (ev.type === "_conn") { $("#st-ws").textContent = "live: " + (ev.data ? "terhubung" : "terputus"); if (ev.data) refreshStatus(); return; }
    if (ev.type === "proxy_status") applyProxy(ev.data);
    else if (ev.type === "intercept") { state.proxy.queue = ev.data.queue; const q = $("#nav-queue"); q.textContent = ev.data.queue || ""; q.classList.toggle("hidden", !ev.data.queue); }
    else if (ev.type === "history") { state.counts.requests++; $("#st-req").textContent = "request (sesi ini): " + state.counts.requests; }
    if (mounted && mounted.onEvent) mounted.onEvent(ev);
  }

  function showLogin() {
    if ($("#login")) return;
    const err = h("div", { class: "errbox hidden" });
    const form = h("form", { onsubmit: async (e) => {
      e.preventDefault();
      try { await EX.api.post("/api/login", { token: e.target.token.value }); location.reload(); }
      catch (x) { err.textContent = x.message; err.classList.remove("hidden"); }
    } }, h("div", { class: "brand" }, h("span", {}), h("div", {}, h("b", { text: "EXVOLT X" }), h("small", { text: "AUTENTIKASI DIPERLUKAN" }))),
    h("input", { name: "token", type: "password", placeholder: "Token akses", autocomplete: "current-password", "aria-label": "Token akses" }), err,
    h("button", { class: "btn primary", type: "submit", text: "Masuk" }));
    form.firstChild.firstChild.innerHTML = EX.icons.logo;
    document.body.append(h("div", { id: "login" }, form));
    form.token.focus();
  }
  EX.onUnauthorized = showLogin;

  async function boot() {
    document.documentElement.lang = "id";
    try {
      const a = await EX.api.get("/api/auth/status");
      if (a.auth_required && !a.authenticated) return showLogin();
      EX.live.setMode(a.realtime);
    } catch (e) { document.body.textContent = "Tidak dapat menghubungi server EXVOLT X."; return; }
    buildShell();
    document.body.append(h("div", { id: "toasts", "aria-live": "polite" }));
    addEventListener("hashchange", route);
    EX.live.on(onEvent); EX.live.connect();
    await refreshStatus();
    route();
  }
  document.addEventListener("DOMContentLoaded", boot);
})();
