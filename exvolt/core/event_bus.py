"""Event bus ringan untuk pembaruan real-time (WebSocket / SSE)."""
from __future__ import annotations

import asyncio
import collections
import time


class EventBus:
    def __init__(self):
        self.loop = None
        self.subs: set[asyncio.Queue] = set()
        self.logs = collections.deque(maxlen=500)

    def bind_loop(self, loop):
        self.loop = loop

    def subscribe(self):
        q = asyncio.Queue(maxsize=2000)
        self.subs.add(q)
        return q

    def unsubscribe(self, q):
        self.subs.discard(q)

    def publish(self, type_, data=None):
        ev = {"type": type_, "data": data, "ts": time.time()}
        if self.loop is None:
            return
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self.loop:
            self._push(ev)
        else:
            try:
                self.loop.call_soon_threadsafe(self._push, ev)
            except RuntimeError:  # loop sudah ditutup saat shutdown
                pass

    def _push(self, ev):
        for q in list(self.subs):
            if q.full():  # klien lambat: buang yang tertua, jangan blokir
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            q.put_nowait(ev)

    def log(self, level, msg):
        item = {"ts": time.time(), "level": level, "msg": msg}
        self.logs.append(item)
        self.publish("proxy_log", item)
