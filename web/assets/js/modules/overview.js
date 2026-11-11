"use strict";
(() => {
  const { h, icon, bytes, time, sev } = EX.ui;
  const SEVS = ["critical", "high", "medium", "low", "info"];
  let timer = null, raf = null, data = null;

  function hash(s) { let x = 2166136261; for (let i = 0; i < s.length; i++) { x ^= s.charCodeAt(i); x = Math.imul(x, 16777619); } return x >>> 0; }
  const DOTS = (() => { const n = 1100, out = [], g = Math.PI * (3 - Math.sqrt(5)); for (let i = 0; i < n; i++) { const y = 1 - (i / (n - 1)) * 2, r = Math.sqrt(1 - y * y), t = g * i; out.push([Math.cos(t) * r, y, Math.sin(t) * r]); } return out; })();

  function stat(label, value, accent) { return h("div", { class: "panel stat" + (accent ? " accent" : "") }, h("small", { text: label }), h("b", { text: value })); }

  function gaugeSvg(total, risky) {
    const ratio = total ? risky / total : 0, len = 251.3;
    const d = document.createElement("div"); d.className = "gauge";
    d.innerHTML = `<svg viewBox="0 0 200 110" role="img" aria-label="Rasio temuan menengah ke atas"><path d="M20 100 A80 80 0 0 1 180 100" fill="none" stroke="#1c2824" stroke-width="10" stroke-linecap="round"/><path d="M20 100 A80 80 0 0 1 180 100" fill="none" stroke="#10d9a0" stroke-width="10" stroke-linecap="round" stroke-dasharray="${(len * ratio).toFixed(1)} ${len}"/></svg>`;
    d.append(h("div", { class: "num", text: String(total) }), h("div", { class: "cap", text: "Temuan tercatat" }));
    return d;
  }

  function mount(root) {
    const left = h("div", { class: "left" }), right = h("div", { class: "right" });
    const canvas = h("canvas", { "aria-label": "Topologi host yang tertangkap" });
    const hero = h("div", { class: "panel hero" }, canvas,
      h("div", { class: "title" }, h("h2", { text: "Ruang Kerja Keamanan" }), h("p", { text: "Topologi host dari lalu lintas yang benar-benar tertangkap" })),
      h("div", { class: "legend", id: "ov-legend" }));
    const stats = h("div", { class: "stats" });
    root.append(h("div", { class: "ov" }, left, hero, right, stats));
    const emptyNote = h("div", { class: "empty", style: { position: "absolute", inset: "0", zIndex: "1", pointerEvents: "none" } });

    function paintSide() {
      const d = data, sevc = d.severity, total = d.totals.findings;
      const risky = (sevc.critical || 0) + (sevc.high || 0) + (sevc.medium || 0);
      const tl = d.timeline, max = Math.max(1, ...tl);
      const spark = h("div", { class: "spark", role: "img", "aria-label": "Request per menit, 60 menit terakhir" });
      tl.forEach((v, i) => { const b = h("i", { class: v ? "" : "z", title: `${v} request` }); b.style.height = Math.max(3, (v / max) * 100) + "%"; spark.append(b); });
      left.replaceChildren(
        h("div", { class: "panel" }, h("header", { text: "Aktivitas Request · 60 menit" }), h("div", { class: "body" }, spark,
          h("div", { class: "row small muted", style: { justifyContent: "space-between", marginTop: "6px" } }, h("span", { text: "−60m" }), h("span", { text: `puncak ${max} / menit` }), h("span", { text: "sekarang" })))),
        h("div", { class: "panel" }, h("header", { text: "Distribusi Status" }), h("div", { class: "body" },
          ...["2", "3", "4", "5", "0"].map((k) => {
            const v = d.status_classes[k] || 0, tot = Math.max(1, d.totals.requests);
            const bar = h("div", { class: "bar" }, h("i", {})); bar.firstChild.style.width = (v / tot) * 100 + "%";
            return h("div", { class: "hrow" }, h("span", { text: k === "0" ? "Error/Drop" : k + "xx" }), bar, h("span", { text: v }));
          }))),
        h("div", { class: "panel" }, h("header", { text: "Metode HTTP" }), h("div", { class: "body" },
          ...(Object.entries(d.methods).length ? Object.entries(d.methods).map(([m, n]) => {
            const bar = h("div", { class: "bar" }, h("i", {})); bar.firstChild.style.width = (n / Math.max(1, d.totals.requests)) * 100 + "%";
            return h("div", { class: "hrow" }, h("span", { class: "mono", text: m }), bar, h("span", { text: n }));
          }) : [h("div", { class: "muted small", text: "Belum ada data." })]))));
      right.replaceChildren(
        h("div", { class: "panel" }, h("header", { text: "Temuan Scanner Pasif" }), h("div", { class: "body" }, gaugeSvg(total, risky),
          h("div", { class: "cap small muted", style: { textAlign: "center" }, text: total ? `${risky} berseverity menengah ke atas` : "Belum ada temuan" }))),
        h("div", { class: "panel" }, h("header", { text: "Berdasarkan Severity" }), h("div", { class: "body" },
          ...SEVS.map((s) => {
            const v = sevc[s] || 0, bar = h("div", { class: "bar sev-" + s }, h("i", {})); bar.firstChild.style.width = (v / Math.max(1, total)) * 100 + "%";
            return h("div", { class: "hrow" }, h("span", { text: s }), bar, h("span", { text: v }));
          }))),
        h("div", { class: "panel" }, h("header", { text: "Temuan Terbaru" }), h("div", { class: "body" },
          ...(d.recent_findings.length ? d.recent_findings.map((f) => h("div", { class: "row small", style: { margin: "5px 0", alignItems: "flex-start" } }, sev(f.severity), h("span", { style: { flex: "1", minWidth: "0", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }, title: f.name, text: f.name })))
            : [h("div", { class: "muted small", text: "Belum ada temuan." })]))));
      const t = d.totals;
      stats.replaceChildren(stat("Request tersimpan", t.requests.toLocaleString("id-ID"), true), stat("Host unik", t.hosts), stat("Dalam scope", t.in_scope),
        stat("Error koneksi", t.errors), stat("Pesan WebSocket", t.ws_messages), stat("Data respons", bytes(t.bytes)), stat("Aturan scope aktif", t.scope_rules));
      const lg = document.getElementById("ov-legend");
      if (lg) lg.replaceChildren(h("span", { text: `${d.top_hosts.length} host ditampilkan` }), h("span", { text: d.proxy.running ? `Proxy aktif · ${d.proxy.host}:${d.proxy.port}` : "Proxy tidak aktif" }));
      hero.querySelectorAll(".empty").forEach((e) => e.remove());
      if (!d.top_hosts.length) {
        emptyNote.replaceChildren(h("b", { text: d.proxy.running ? "Menunggu lalu lintas" : "Belum ada lalu lintas tertangkap" }),
          h("span", { text: d.proxy.running ? `Arahkan browser ke ${d.proxy.host}:${d.proxy.port}.` : "Buka modul Proxy, mulai listener, lalu arahkan browser ke proxy." }),
          h("a", { class: "btn primary", href: "#/proxy", style: { pointerEvents: "auto", textDecoration: "none", marginTop: "8px" }, text: "Buka Proxy" }));
        hero.append(emptyNote);
      }
    }

    async function load() {
      try { data = await EX.api.get("/api/overview"); paintSide(); } catch (e) { /* offline */ }
    }

    mounted._load = load;
    const ctx = canvas.getContext("2d");
    const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
    let angle = 0, last = 0;
    function draw(ts) {
      raf = null;
      if (!canvas.isConnected) return;
      if (ts - last >= 42 || !last) {
        last = ts;
        const dpr = Math.min(devicePixelRatio || 1, 2), w = canvas.clientWidth, hh = canvas.clientHeight;
        if (canvas.width !== w * dpr || canvas.height !== hh * dpr) { canvas.width = w * dpr; canvas.height = hh * dpr; }
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, w, hh);
        const R = Math.min(w * 0.34, hh * 0.36), cx = w / 2, cy = hh * 0.52;
        const ca = Math.cos(angle), sa = Math.sin(angle), tilt = 0.35, ct = Math.cos(tilt), st = Math.sin(tilt);
        const proj = (x, y, z) => { const x1 = x * ca + z * sa, z1 = -x * sa + z * ca; const y2 = y * ct - z1 * st, z2 = y * st + z1 * ct; return [cx + x1 * R, cy - y2 * R, z2]; };
        const g = ctx.createRadialGradient(cx, cy, R * 0.2, cx, cy, R * 1.25); g.addColorStop(0, "rgba(16,217,160,.10)"); g.addColorStop(1, "rgba(16,217,160,0)");
        ctx.fillStyle = g; ctx.beginPath(); ctx.arc(cx, cy, R * 1.25, 0, 7); ctx.fill();
        ctx.strokeStyle = "rgba(52,232,180,.22)"; ctx.lineWidth = 1; ctx.beginPath(); ctx.arc(cx, cy, R, 0, 7); ctx.stroke();
        for (const [x, y, z] of DOTS) { const [px, py, pz] = proj(x, y, z); ctx.fillStyle = pz > 0 ? `rgba(52,232,180,${0.12 + pz * 0.55})` : "rgba(52,232,180,.05)"; ctx.fillRect(px, py, pz > 0 ? 1.6 : 1, pz > 0 ? 1.6 : 1); }
        if (data) {
          const hosts = data.top_hosts, max = Math.max(1, ...hosts.map((x) => x.n));
          const nodes = hosts.map((hst) => { const hv = hash(hst.host), lat = ((hv % 1000) / 1000) * 2 - 1, lon = (((hv >>> 10) % 1000) / 1000) * Math.PI * 2, r = Math.sqrt(1 - lat * lat); const [px, py, pz] = proj(Math.cos(lon) * r, lat, Math.sin(lon) * r); return { hst, px, py, pz }; });
          const [ox, oy] = proj(0, 0, 1.0);
          for (const n of nodes) { if (n.pz <= 0) continue; ctx.strokeStyle = `rgba(52,232,180,${0.18 + n.pz * 0.3})`; ctx.lineWidth = 1; ctx.beginPath(); ctx.moveTo(cx, cy); ctx.quadraticCurveTo((cx + n.px) / 2, Math.min(cy, n.py) - R * 0.25, n.px, n.py); ctx.stroke(); }
          ctx.fillStyle = "#10d9a0"; ctx.beginPath(); ctx.arc(cx, cy, 5, 0, 7); ctx.fill(); ctx.strokeStyle = "rgba(16,217,160,.4)"; ctx.beginPath(); ctx.arc(cx, cy, 11, 0, 7); ctx.stroke();
          ctx.font = "11px ui-monospace,monospace"; ctx.textAlign = "left";
          ctx.fillStyle = "#7d9189"; ctx.fillText("EXVOLT X", cx + 14, cy + 4);
          nodes.sort((a, b) => a.pz - b.pz);
          nodes.forEach((n, i) => {
            const front = n.pz > 0, rad = 2.5 + (n.hst.n / max) * 4.5;
            ctx.globalAlpha = front ? 1 : 0.25;
            ctx.fillStyle = n.hst.errors ? "#ff5d6c" : n.hst.in_scope ? "#34e8b4" : "#8aa0aa";
            ctx.beginPath(); ctx.arc(n.px, n.py, rad, 0, 7); ctx.fill();
            if (front) { ctx.strokeStyle = "rgba(230,239,235,.25)"; ctx.beginPath(); ctx.arc(n.px, n.py, rad + 3, 0, 7); ctx.stroke(); }
            if (front && i >= nodes.length - 8) { ctx.fillStyle = "#e6efeb"; ctx.fillText(`${n.hst.host} · ${n.hst.n}`, n.px + rad + 6, n.py + 4); }
            ctx.globalAlpha = 1;
          });
        }
        if (!reduce) angle += 0.0045;
      }
      if (!reduce && !document.hidden) raf = requestAnimationFrame(draw);
    }
    const start = () => { if (!raf) raf = requestAnimationFrame(draw); };
    document.addEventListener("visibilitychange", start);
    mounted.cleanup = () => document.removeEventListener("visibilitychange", start);
    load().then(() => { start(); if (reduce) draw(performance.now() + 100); });
    timer = setInterval(load, 5000);
    new ResizeObserver(() => { last = 0; if (reduce) draw(performance.now() + 100); }).observe(canvas);
  }
  const mounted = { title: "Ringkasan", mount,
    unmount() { clearInterval(timer); if (raf) cancelAnimationFrame(raf); raf = null; if (mounted.cleanup) mounted.cleanup(); },
    onEvent(ev) { if (ev.type === "history" || ev.type === "finding" || ev.type === "proxy_status") { clearTimeout(mounted._t); mounted._t = setTimeout(() => mounted._load && mounted._load(), 800); } } };
  EX.modules.overview = mounted;
})();
