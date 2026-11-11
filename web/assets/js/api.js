"use strict";
window.EX = window.EX || { modules: {}, state: {} };

EX.api = (() => {
  class ApiError extends Error {
    constructor(msg, status) { super(msg); this.status = status; }
  }
  async function call(method, path, body, opts = {}) {
    const init = { method, headers: { "X-Requested-With": "exvolt" }, credentials: "same-origin" };
    if (body !== undefined) {
      if (opts.raw) { init.body = body; init.headers["Content-Type"] = "application/octet-stream"; }
      else { init.body = JSON.stringify(body); init.headers["Content-Type"] = "application/json"; }
    }
    let res;
    try { res = await fetch(path, init); }
    catch (e) { throw new ApiError("Tidak dapat menghubungi server EXVOLT X", 0); }
    if (res.status === 401 && EX.onUnauthorized) EX.onUnauthorized();
    if (opts.blob && res.ok) {
      const cd = res.headers.get("content-disposition") || "";
      const m = /filename="([^"]+)"/.exec(cd);
      return { blob: await res.blob(), name: m ? m[1] : "export" };
    }
    let data = null;
    const text = await res.text();
    if (text) { try { data = JSON.parse(text); } catch (e) { data = { error: text.slice(0, 200) }; } }
    if (!res.ok) throw new ApiError((data && data.error) || `HTTP ${res.status}`, res.status);
    return data;
  }
  const qs = (o) => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(o || {})) if (v !== undefined && v !== null && v !== "" && v !== false) p.set(k, v === true ? "1" : v);
    const s = p.toString();
    return s ? "?" + s : "";
  };
  async function download(method, path, body) {
    const { blob, name } = await call(method, path, body, { blob: true });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    return name;
  }
  return {
    ApiError, qs, download,
    get: (p, q) => call("GET", p + qs(q)),
    post: (p, b) => call("POST", p, b === undefined ? {} : b),
    put: (p, b) => call("PUT", p, b),
    patch: (p, b) => call("PATCH", p, b),
    del: (p, b) => call("DELETE", p, b),
    upload: (p, buf) => call("POST", p, buf, { raw: true }),
  };
})();
