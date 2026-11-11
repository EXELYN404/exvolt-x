"use strict";
/* Kanal real-time: WebSocket native; fallback otomatis ke Server-Sent Events bila WS tidak tersedia di server. */
EX.live = (() => {
  let ws = null, es = null, retry = 1000, timer = null, failsBeforeOpen = 0, useSse = false;
  const listeners = new Set();
  const state = { connected: false, transport: "ws" };
  function emit(ev) { listeners.forEach((fn) => { try { fn(ev); } catch (e) { console.error(e); } }); }
  function up() { state.connected = true; retry = 1000; emit({ type: "_conn", data: true }); }
  function down() { if (state.connected) { state.connected = false; emit({ type: "_conn", data: false }); } }
  function connectSse() {
    state.transport = "sse";
    es = new EventSource("/api/events");
    es.onopen = up;
    es.onmessage = (m) => { try { emit(JSON.parse(m.data)); } catch (e) { /* abaikan */ } };
    es.onerror = () => { down(); /* EventSource menyambung ulang otomatis */ };
  }
  function connect() {
    clearTimeout(timer);
    if (useSse) return connectSse();
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    let opened = false;
    ws = new WebSocket(`${proto}//${location.host}/api/ws`);
    ws.onopen = () => { opened = true; failsBeforeOpen = 0; up(); };
    ws.onmessage = (m) => { try { emit(JSON.parse(m.data)); } catch (e) { /* abaikan frame rusak */ } };
    ws.onclose = () => {
      down();
      if (!opened && ++failsBeforeOpen >= 2) { useSse = true; return connect(); }
      timer = setTimeout(connect, retry); retry = Math.min(retry * 2, 15000);
    };
    ws.onerror = () => { try { ws.close(); } catch (e) { /* noop */ } };
  }
  return { state, connect, setMode: (m) => { useSse = m === "sse"; }, on: (fn) => { listeners.add(fn); return () => listeners.delete(fn); } };
})();
