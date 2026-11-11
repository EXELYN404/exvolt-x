import asyncio, ssl, json
import pytest

async def start(c):
    await c.proxy.start("127.0.0.1", 0)
    return c.proxy.port

async def raw_get(pport, tport, path="/echo", extra=""):
    r, w = await asyncio.open_connection("127.0.0.1", pport)
    w.write(f"GET http://127.0.0.1:{tport}{path} HTTP/1.1\r\nHost: 127.0.0.1:{tport}\r\nConnection: close\r\n{extra}\r\n".encode()); await w.drain()
    data = await asyncio.wait_for(r.read(), 10); w.close(); return data

def test_http_capture_and_history(services, target):
    async def go():
        c = services; c.bus.bind_loop(asyncio.get_running_loop())
        p = await start(c)
        out = await raw_get(p, target, "/echo?x=1")
        assert b"200 OK" in out and b"echo /echo?x=1" in out
        await asyncio.sleep(0.2)
        rows = c.db.q("SELECT * FROM history")
        assert len(rows) == 1 and rows[0]["method"] == "GET" and rows[0]["status"] == 200 and rows[0]["resp_body"] == b"echo /echo?x=1"
        await c.proxy.stop()
    asyncio.run(go())

def test_https_interception_with_local_ca(services, target):
    import http.server, threading
    from tests.conftest import Target
    async def go():
        c = services; c.bus.bind_loop(asyncio.get_running_loop())
        ctx = c.certs.server_context("127.0.0.1")
        hs = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Target); hs.socket = ctx.wrap_socket(hs.socket, server_side=True)
        threading.Thread(target=hs.serve_forever, daemon=True).start()
        p = await start(c)
        r, w = await asyncio.open_connection("127.0.0.1", p)
        w.write(f"CONNECT 127.0.0.1:{hs.server_address[1]} HTTP/1.1\r\nHost: x\r\n\r\n".encode()); await w.drain()
        assert b"200 Connection Established" in await r.readuntil(b"\r\n\r\n")
        await w.start_tls(ssl.create_default_context(cafile=str(c.certs.ca_pem_path)), server_hostname="127.0.0.1")  # klien memverifikasi CA EXVOLT
        w.write(b"POST /p HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4\r\n\r\nbody"); await w.drain()
        assert b"body" in await asyncio.wait_for(r.readuntil(b"body"), 10)
        w.close(); await asyncio.sleep(0.2)
        row = c.db.q("SELECT * FROM history")[0]
        assert row["scheme"] == "https" and row["method"] == "POST" and row["req_body"] == b"body" and json.loads(row["tls"])["version"].startswith("TLS")
        hs.shutdown(); await c.proxy.stop()
    asyncio.run(go())

def test_intercept_forward_edit_and_drop(services, target):
    async def go():
        c = services; c.bus.bind_loop(asyncio.get_running_loop())
        p = await start(c); c.proxy.set_intercept(True)
        t1 = asyncio.create_task(raw_get(p, target, "/echo?orig"))
        for _ in range(50):
            if c.proxy.queue: break
            await asyncio.sleep(0.05)
        item = c.proxy.queue_list()[0]
        assert "GET /echo?orig" in item["raw"]
        c.proxy.decide(item["id"], "forward", item["raw"].replace("orig", "edited"))
        assert b"echo /echo?edited" in await t1                      # modifikasi benar-benar sampai ke target
        t2 = asyncio.create_task(raw_get(p, target, "/echo?drop"))
        for _ in range(50):
            if c.proxy.queue: break
            await asyncio.sleep(0.05)
        c.proxy.decide(c.proxy.queue_list()[0]["id"], "drop")
        assert b"403" in await t2
        await asyncio.sleep(0.2)
        assert c.db.one("SELECT COUNT(*) c FROM history WHERE error LIKE '%drop%'")["c"] == 1
        # intercept dimatikan -> antrean diteruskan
        t3 = asyncio.create_task(raw_get(p, target, "/echo?flush"))
        for _ in range(50):
            if c.proxy.queue: break
            await asyncio.sleep(0.05)
        c.proxy.set_intercept(False)
        assert b"echo /echo?flush" in await t3
        await c.proxy.stop()
    asyncio.run(go())

def test_remote_bind_refused_and_port_conflict(services):
    from exvolt.core.proxy_engine import ProxyError
    async def go():
        c = services
        with pytest.raises(ProxyError): await c.proxy.start("0.0.0.0", 0)
        await c.proxy.start("127.0.0.1", 0)
        with pytest.raises(ProxyError): await c.proxy.start("127.0.0.1", 0)  # sudah berjalan
        await c.proxy.stop()
    asyncio.run(go())

def test_upstream_failure_returns_502_and_logs(services):
    async def go():
        c = services; c.bus.bind_loop(asyncio.get_running_loop()); p = await start(c)
        out = await raw_get(p, 1, "/x")      # port 1: tidak ada listener
        assert b"502" in out
        await asyncio.sleep(0.2)
        assert c.db.one("SELECT error FROM history")["error"]
        await c.proxy.stop()
    asyncio.run(go())

def test_ws_frame_parser():
    from exvolt.core.proxy_engine import WsParser
    import os
    p = WsParser(); mk = os.urandom(4); msg = b"hello"
    frame = bytes([0x81, 0x80 | len(msg)]) + mk + bytes(c ^ mk[i % 4] for i, c in enumerate(msg))
    assert p.feed(frame[:3]) == [] and p.feed(frame[3:]) == [(1, b"hello")]
