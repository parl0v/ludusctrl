# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Josip Parlov (@parl0v). See NOTICE for the attribution terms.
"""Tests for the browser bridge (webbridge.py), with a stub pad: needs neither
ViGEmBus nor a controller, and never touches the real certificate a phone
already trusts (every server here uses a throwaway certificate directory).

Covers: the page and its security headers, the token and Origin checks, the
single-driver rule, arbitration with the UDP app, the watchdog evicting a
silent driver and the phone getting back in, WebSocket close handling and
malformed frames, a connection that never speaks not blocking anyone, prompt
shutdown, pad switching, and the certificate profile.

    python test_webbridge.py
"""

from __future__ import annotations

import base64
import datetime
import os
import re
import shutil
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

CERT_TMP = tempfile.mkdtemp(prefix="ludusctrl-test-cert-")
os.environ["LUDUSCTRL_CERT_DIR"] = CERT_TMP

import webbridge  # noqa: E402
from webbridge import (OP_BINARY, OP_CLOSE, OP_PING, OP_PONG, OP_TEXT,  # noqa: E402
                       PACKET, ws_accept)

FAILURES: list[str] = []


def check(name: str, ok, detail: str = "") -> None:
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail else ""))
    if not ok:
        FAILURES.append(name)


CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def pkt(seq=1, buttons=0x1000, lx=-12345, ly=6000, rx=300, ry=-400, lt=128, rt=255,
        flags=0x01, layout=1) -> bytes:
    return PACKET.pack(0xD5, 1, seq, buttons, lx, ly, rx, ry, lt, rt, flags, layout)


class StubPad:
    def __init__(self, kind="x360"):
        self.kind = kind
        self.last = None
        self.released = 0

    def apply(self, *a):
        self.last = a

    def release(self):
        self.released += 1
        self.last = None


class Server:
    """A bridge on a free port, torn down by stop()."""

    def __init__(self, pad=None, **kw):
        self.pad = pad if pad is not None else (None if "pad_getter" in kw else StubPad())
        self.states = []
        kw.setdefault("on_state", self.states.append)
        self.server, self.bridge = webbridge.serve(self.pad, port=0, host="127.0.0.1",
                                                   cert_directory=CERT_TMP, **kw)
        self.port = self.server.port
        self.token = self.bridge.token

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


class Client:
    """A minimal WebSocket client that speaks exactly what the page speaks."""

    def __init__(self, port, token=None, origin="auto", path="/ws", auth=True, upgrade=True):
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.s = CTX.wrap_socket(raw, server_hostname="127.0.0.1")
        self.buf = b""
        self.status = None
        # A real page sends a packet every frame. While `feeding`, this client
        # does the same (every 100 ms) whenever it is waiting on a read, so the
        # watchdog does not evict it in the middle of a test.
        self.feeding = False
        self.feed_state: dict = {}
        self._feed_seq = 1000
        self._next_feed = 0.0
        if not upgrade:
            return
        host = f"127.0.0.1:{port}"
        key = base64.b64encode(os.urandom(16)).decode()
        head = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
                f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                "Sec-WebSocket-Version: 13\r\n")
        if origin == "auto":
            origin = f"https://{host}"
        if origin:
            head += f"Origin: {origin}\r\n"
        self.s.sendall((head + "\r\n").encode())
        while b"\r\n\r\n" not in self.buf:
            chunk = self.s.recv(4096)
            if not chunk:
                break
            self.buf += chunk
        header, _, self.buf = self.buf.partition(b"\r\n\r\n")
        self.header = header.decode("latin-1")
        self.status = int(self.header.split(" ")[1]) if self.header else 0
        self.accept_ok = ws_accept(key) in self.header
        if auth and self.status == 101 and token is not None:
            self.text("auth:" + token)

    def send(self, opcode, payload=b"", mask=True, fin=True):
        head = bytes([(0x80 if fin else 0) | opcode])
        n = len(payload)
        mbit = 0x80 if mask else 0
        if n < 126:
            head += bytes([mbit | n])
        else:
            head += bytes([mbit | 126]) + struct.pack(">H", n)
        if mask:
            m = os.urandom(4)
            payload = m + bytes(b ^ m[i % 4] for i, b in enumerate(payload))
        self.s.sendall(head + payload)

    def text(self, s):
        self.send(OP_TEXT, s.encode())

    def packet(self, **kw):
        self.feed_state = {k: v for k, v in kw.items() if k != "seq"}
        self.send(OP_BINARY, pkt(**kw))

    def _feed(self):
        if self.feeding and time.monotonic() >= self._next_feed:
            self._next_feed = time.monotonic() + 0.1
            self._feed_seq += 1
            self.send(OP_BINARY, pkt(seq=self._feed_seq, **self.feed_state))

    def pump(self, seconds):
        """Wait, reading (and feeding, if on) without losing the connection."""
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            f = self.frame(min(0.1, max(0.01, deadline - time.monotonic())))
            if f is None:
                return

    def _fill(self, need, deadline):
        while len(self.buf) < need:
            try:
                self._feed()
            except OSError:
                return None
            left = deadline - time.monotonic()
            if left <= 0:
                return False
            self.s.settimeout(min(0.05, left) if self.feeding else left)
            try:
                chunk = self.s.recv(4096)
            except (socket.timeout, TimeoutError):
                continue
            except (OSError, ssl.SSLError):
                return None
            if not chunk:
                return None
            self.buf += chunk
        return True

    def frame(self, timeout=2.0):
        """(opcode, payload), None on EOF, or "timeout"."""
        deadline = time.monotonic() + timeout
        r = self._fill(2, deadline)
        if r is not True:
            return None if r is None else "timeout"
        n = self.buf[1] & 0x7F
        hlen = 2 + (2 if n == 126 else 8 if n == 127 else 0)
        r = self._fill(hlen, deadline)
        if r is not True:
            return None if r is None else "timeout"
        if n == 126:
            n = struct.unpack(">H", self.buf[2:4])[0]
        elif n == 127:
            n = struct.unpack(">Q", self.buf[2:10])[0]
        r = self._fill(hlen + n, deadline)
        if r is not True:
            return None if r is None else "timeout"
        op, payload = self.buf[0] & 0x0F, self.buf[hlen:hlen + n]
        self.buf = self.buf[hlen + n:]
        return op, payload

    def texts_until(self, pred, timeout=2.0):
        """Collect text frames until pred(text) is true. Returns (texts, hit, close)."""
        deadline = time.monotonic() + timeout
        texts, close = [], None
        while time.monotonic() < deadline:
            f = self.frame(max(0.01, deadline - time.monotonic()))
            if f is None or f == "timeout":
                break
            op, payload = f
            if op == OP_TEXT:
                t = payload.decode()
                texts.append(t)
                if pred(t):
                    return texts, True, close
            elif op == OP_CLOSE:
                close = struct.unpack(">H", payload[:2])[0] if len(payload) >= 2 else 0
                return texts, False, close
        return texts, False, close

    def until_closed(self, timeout=3.0):
        """Read until EOF. Returns (texts, close code or None, closed?)."""
        deadline = time.monotonic() + timeout
        texts, close = [], None
        while time.monotonic() < deadline:
            f = self.frame(max(0.01, deadline - time.monotonic()))
            if f is None:
                return texts, close, True
            if f == "timeout":
                break
            op, payload = f
            if op == OP_TEXT:
                texts.append(payload.decode())
            elif op == OP_CLOSE:
                close = struct.unpack(">H", payload[:2])[0] if len(payload) >= 2 else 0
                # Answer it, as a browser does, so the server need not wait
                # out its linger.
                try:
                    self.send(OP_CLOSE, payload[:2])
                except OSError:
                    pass
        return texts, close, False

    def ready(self):
        texts, hit, _ = self.texts_until(lambda t: t.startswith("padkind:"))
        return "ready" in texts and hit

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def http_get(port, path="/"):
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    s = CTX.wrap_socket(raw, server_hostname="127.0.0.1")
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode())
    data = b""
    while True:
        try:
            c = s.recv(65536)
        except (socket.timeout, OSError):
            break
        if not c:
            break
        data += c
    s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    return head.decode("latin-1"), body


def wait_for(pred, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.02)
    return pred()


# ---------------------------------------------------------------------------

def test_page():
    print("\n--- page and headers ---")
    srv = Server()
    try:
        head, body = http_get(srv.port)
        check("page served over HTTPS", head.startswith("HTTP/1.1 200"), head.split("\r\n")[0])
        check("page is the gamepad client", b"getGamepads" in body)
        check("version filled in", webbridge.APP_VERSION.encode() in body
              and webbridge.VERSION_PLACEHOLDER.encode() not in body)
        check("token not in the page", srv.token.encode() not in body)
        csp = re.search(r"Content-Security-Policy: (.*)", head)
        check("CSP sent", bool(csp))
        script = re.search(rb"<script>(.*?)</script>", body, re.S).group(1)
        import hashlib
        digest = base64.b64encode(hashlib.sha256(script).digest()).decode()
        check("CSP pins the served script by hash", csp and f"'sha256-{digest}'" in csp.group(1))
        check("CSP forbids framing", csp and "frame-ancestors 'none'" in csp.group(1))
        check("CSP allows wss to self only", csp and "connect-src 'self' wss:" in csp.group(1))
        for h in ("X-Content-Type-Options: nosniff", "Referrer-Policy: no-referrer",
                  "Cache-Control: no-store"):
            check(f"header {h.split(':')[0]}", h in head)
        head404, _ = http_get(srv.port, "/nope")
        check("unknown path 404s with headers", head404.startswith("HTTP/1.1 404")
              and "X-Content-Type-Options: nosniff" in head404)
        urls = webbridge.browser_urls(srv.port, srv.token)
        check("links carry the token in the fragment",
              all(u["url"].endswith(f":{srv.port}/#t={srv.token}") for u in urls),
              urls[0]["url"] if urls else "no LAN address on this machine")
        check("token is 128 bits", len(base64.urlsafe_b64decode(srv.token + "==")) == 16)
    finally:
        srv.stop()


def test_auth_and_origin():
    print("\n--- token and Origin ---")
    srv = Server()
    try:
        c = Client(srv.port, token="wrong-token")
        texts, close, closed = c.until_closed()
        check("wrong token refused with 'denied'", "denied" in texts, repr(texts))
        check("wrong token closes 1008", close == 1008, str(close))
        check("wrong token does not claim", srv.bridge.driver is None)
        c.close()

        c = Client(srv.port, token=None)          # no auth message at all
        c.packet()
        texts, close, _ = c.until_closed()
        check("packet before token refused", "denied" in texts and close == 1008)
        check("packet before token not applied", srv.pad.last is None)
        c.close()

        old = webbridge.WS_READ_TIMEOUT
        webbridge.WS_READ_TIMEOUT = 0.8
        try:
            c = Client(srv.port, token=None)
            t0 = time.monotonic()
            texts, close, closed = c.until_closed(timeout=3)
            check("silent socket without a token is closed", closed and close == 1008,
                  f"close={close} after {time.monotonic() - t0:.1f}s")
            c.close()
        finally:
            webbridge.WS_READ_TIMEOUT = old

        c = Client(srv.port, token=srv.token, origin="https://evil.example")
        check("foreign Origin refused before upgrade", c.status == 403, str(c.status))
        c.close()

        c = Client(srv.port, token=srv.token, origin=f"http://127.0.0.1:{srv.port}")
        check("plain-http Origin refused", c.status == 403, str(c.status))
        c.close()

        c = Client(srv.port, token=srv.token)     # Origin = https://Host
        check("own Origin upgrades", c.status == 101 and c.accept_ok)
        check("right token claims", c.ready())
        c.close()
    finally:
        srv.stop()


def test_session():
    print("\n--- packets, acks, single driver ---")
    srv = Server()
    try:
        c = Client(srv.port, token=srv.token)
        check("ready + padkind on connect", c.ready())
        c.packet(seq=7)
        texts, hit, _ = c.texts_until(lambda t: t.startswith("ack:"))
        check("pad applied", wait_for(lambda: srv.pad.last == (0x1000, -12345, 6000, 300, -400, 128, 255)),
              str(srv.pad.last))
        check("ack says applied", hit and texts[-1] == "ack:7:1:1", repr(texts[-1:]))

        before = srv.pad.last
        c.send(OP_BINARY, pkt(seq=8) + b"\x00")     # 21 bytes
        c.send(OP_BINARY, pkt(seq=9)[:19])          # 19 bytes
        c.send(OP_BINARY, b"\x00" * 20)             # bad magic
        time.sleep(0.3)
        check("only exactly-20-byte packets apply", srv.pad.last == before
              and srv.bridge.packets == 1, str(srv.bridge.packets))

        c.text("ping:abc")
        texts, hit, _ = c.texts_until(lambda t: t.startswith("pong:"))
        check("ping echoed", hit and texts[-1] == "pong:abc")
        c.send(OP_PING, b"hi")
        f = c.frame()
        check("control ping answered", f != "timeout" and f and f[0] == OP_PONG and f[1] == b"hi")

        c.feeding = True                    # from here on, behave like a live page
        c.pump(0.2)
        released = srv.pad.released
        c2 = Client(srv.port, token=srv.token)
        texts, close, _ = c2.until_closed()
        check("second browser refused 'busy'", "busy" in texts, repr(texts))
        c2.close()
        c.pump(0.3)
        check("refused browser leaving does not release the driver's pad",
              srv.pad.released == released and srv.pad.last == before)
        check("driver still driving", srv.bridge.driver is not None)

        c.close()
        check("driver leaving releases the pad", wait_for(lambda: srv.pad.released > released))
    finally:
        srv.stop()


def test_arbitration():
    print("\n--- arbitration with the Android app ---")
    linked = {"v": True}
    srv = Server(link_getter=lambda: linked["v"])
    try:
        c = Client(srv.port, token=srv.token)
        texts, close, _ = c.until_closed()
        check("browser refused while UDP is linked", "busy:app" in texts, repr(texts))
        check("nothing claimed", srv.bridge.driver is None and not srv.bridge.driving())
        c.close()

        linked["v"] = False
        c = Client(srv.port, token=srv.token)
        check("browser claims once UDP is gone", c.ready())
        check("driving() reports it (blocks UDP)", srv.bridge.driving())
        c.close()
        check("driving() clears on disconnect", wait_for(lambda: not srv.bridge.driving()))
    finally:
        srv.stop()


def test_watchdog_evict():
    print("\n--- watchdog: silent driver evicted, phone gets back in ---")
    srv = Server()
    try:
        c = Client(srv.port, token=srv.token)
        c.ready()
        c.packet(seq=1)
        wait_for(lambda: srv.pad.last is not None)
        released = srv.pad.released
        time.sleep(webbridge.WATCHDOG_TIMEOUT + 0.6)   # socket open, nothing sent
        check("silent driver's pad released", srv.pad.released > released and srv.pad.last is None)
        check("claim dropped", srv.bridge.driver is None)

        c.packet(seq=2)                                # the phone wakes up
        texts, close, closed = c.until_closed()
        check("stale session told 'evicted'", "evicted" in texts, repr(texts))
        check("stale session closed", closed or close is not None)
        check("its late packet not applied", srv.pad.last is None)
        c.close()

        c = Client(srv.port, token=srv.token)          # the page's reconnect path
        check("reconnect claims again", c.ready())
        c.packet(seq=1, buttons=0x2000)
        check("input applies again", wait_for(lambda: srv.pad.last and srv.pad.last[0] == 0x2000))
        c.close()
    finally:
        srv.stop()


def test_close_and_bad_frames():
    print("\n--- close handshake and malformed frames ---")
    srv = Server()
    try:
        c = Client(srv.port, token=srv.token)
        c.ready()
        c.send(OP_CLOSE, struct.pack(">H", 1000))
        f = c.frame()
        check("close echoed", f not in (None, "timeout") and f[0] == OP_CLOSE
              and f[1][:2] == struct.pack(">H", 1000), repr(f))
        try:
            c.s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            rest = c.until_closed(timeout=1.5)
        except OSError:
            rest = ([], None, True)
        check("no HTTP after close", b"HTTP/1.1" not in c.buf and rest[2])
        c.close()

        cases = [
            ("oversize frame", 1009,
             lambda c: c.s.sendall(bytes([0x82, 0x80 | 126]) + struct.pack(">H", 5000) + b"\0\0\0\0"
                                   + b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")),
            ("unmasked frame", 1002, lambda c: c.send(OP_BINARY, pkt(), mask=False)),
            ("fragmented frame", 1002, lambda c: c.send(OP_BINARY, pkt(), fin=False)),
        ]
        for name, code, act in cases:
            c = Client(srv.port, token=srv.token)
            c.ready()
            act(c)
            texts, close, closed = c.until_closed()
            check(f"{name} closes {code}", close == code, str(close))
            check(f"{name}: tail never parsed as HTTP", b"HTTP/1.1" not in c.buf)
            c.close()
            wait_for(lambda: srv.bridge.driver is None)
    finally:
        srv.stop()


def test_idle_connections_and_shutdown():
    print("\n--- idle connections cannot block anyone; shutdown is prompt ---")
    srv = Server()
    idle_tcp = socket.create_connection(("127.0.0.1", srv.port), timeout=5)   # never says hello
    idle_tls = CTX.wrap_socket(socket.create_connection(("127.0.0.1", srv.port), timeout=5),
                               server_hostname="127.0.0.1")                  # TLS up, no request
    try:
        t0 = time.monotonic()
        head, body = http_get(srv.port)
        took = time.monotonic() - t0
        check("page loads past an idle TCP and an idle TLS connection",
              head.startswith("HTTP/1.1 200") and took < 2.0, f"{took:.2f}s")
        c = Client(srv.port, token=srv.token)
        check("a real client still gets the pad", c.ready())

        t0 = time.monotonic()
        srv.stop()
        took = time.monotonic() - t0
        check("shutdown returns promptly with idle and live connections open", took < 2.0,
              f"{took:.2f}s")
        texts, close, closed = c.until_closed(timeout=2)
        check("live session dropped on shutdown", closed)
        check("pad released on shutdown", wait_for(lambda: srv.pad.released > 0))
        c.close()
    finally:
        idle_tcp.close()
        idle_tls.close()


def test_switching():
    print("\n--- pad switching: driver only, rate limited, teardown order ---")
    made, released = [], []

    class KindPad(StubPad):
        def release(self):
            super().release()
            released.append(self.kind)

    real_create = webbridge.create_gamepad

    def fake_create(kind="x360"):
        made.append(kind)
        return KindPad(kind)

    webbridge.create_gamepad = fake_create
    first = StubPad()
    srv = Server(pad=first)
    try:
        ok, msg = srv.bridge.request_switch(object(), "ds4")
        check("non-driver cannot switch", not ok and "driving" in msg, msg)

        c = Client(srv.port, token=srv.token)
        c.ready()
        c.packet(seq=1)
        c.feeding = True
        c.text("pad:ds4")
        texts, hit, _ = c.texts_until(lambda t: t.startswith(("padkind:", "paderr:")))
        check("driver switches to ds4", hit and texts[-1] == "padkind:ds4", repr(texts))
        check("old pad released before the new one was made",
              first.released > 0 and made == ["ds4"], f"made={made}")

        c.text("pad:x360")
        texts, hit, _ = c.texts_until(lambda t: t.startswith(("padkind:", "paderr:")))
        check("a second switch within 2 s is refused", hit and texts[-1].startswith("paderr:"),
              repr(texts[-1:]))
        check("... and nothing was rebuilt", made == ["ds4"])

        c.pump(webbridge.PAD_SWITCH_INTERVAL + 0.1)
        c.text("pad:x360")
        texts, hit, _ = c.texts_until(lambda t: t.startswith(("padkind:", "paderr:")))
        check("switch back after the interval", hit and texts[-1] == "padkind:x360")
        check("ds4 released, then x360 made", released == ["ds4"] and made == ["ds4", "x360"],
              f"released={released} made={made}")

        c.pump(webbridge.PAD_SWITCH_INTERVAL + 0.1)
        c.text("pad:nonsense")
        texts, hit, _ = c.texts_until(lambda t: t.startswith(("padkind:", "paderr:")))
        check("unknown kind refused", hit and texts[-1].startswith("paderr:"))
        c.close()
    finally:
        srv.stop()
        webbridge.create_gamepad = real_create


def test_hosted_and_isolation():
    print("\n--- hosted mode, and two servers in one process ---")

    class FakeService:
        def __init__(self):
            self.gamepad = StubPad()

    svc = FakeService()
    calls = []

    def host_switch(kind):
        calls.append(kind)
        svc.gamepad = StubPad(kind)          # the app rebuilds it, as switch_pad does
        return True, kind

    a = Server(pad_getter=lambda: svc.gamepad, pad_switcher=host_switch,
               kind_getter=lambda: "ds4")
    b = Server()
    try:
        check("hosted bridge owns no pad", a.bridge.gamepad is None)
        check("kind comes from the host", a.bridge.pad_kind == "ds4")

        c = Client(a.port, token=a.token)
        c.ready()
        c.packet(seq=1, buttons=0x0002, lx=111, ly=222, rx=333, ry=444, lt=9, rt=8, layout=2)
        c.feeding = True
        check("host's pad driven", wait_for(lambda: svc.gamepad.last == (0x0002, 111, 222, 333, 444, 9, 8)))
        check("the other server's pad untouched", b.pad.last is None)
        check("the other server's token does not open this one",
              a.token != b.token)

        c.text("pad:x360")
        c.texts_until(lambda t: t.startswith(("padkind:", "paderr:")))
        rebuilt = svc.gamepad
        c.packet(seq=2, buttons=0x0004, lx=1, ly=2, rx=3, ry=4, lt=5, rt=6, layout=2)
        check("switch went through the host", calls == ["x360"], str(calls))
        check("bridge drives the rebuilt pad", wait_for(lambda: rebuilt.last == (0x0004, 1, 2, 3, 4, 5, 6)))

        svc.gamepad = None                    # host mid-rebuild
        c.packet(seq=3)
        texts, hit, _ = c.texts_until(lambda t: t.startswith("ack:") and t.endswith(":0"), timeout=1.5)
        check("ack reports 'not applied' while the host has no pad", hit, repr(texts[-1:]))
        c.close()
    finally:
        a.stop()
        b.stop()


def test_certificate():
    print("\n--- certificate profile ---")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    d = tempfile.mkdtemp(prefix="ludusctrl-test-cert2-")
    real_lan = webbridge.lan_addresses
    try:
        cert_p, key_p = webbridge.ensure_cert(d)
        cert = x509.load_pem_x509_certificate(cert_p.read_bytes())
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        check("end-entity: ca=False", bc.value.ca is False)
        check("basic constraints critical", bc.critical)
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        check("EKU serverAuth", ExtendedKeyUsageOID.SERVER_AUTH in eku)
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        check("key usage digitalSignature + keyEncipherment",
              ku.digital_signature and ku.key_encipherment and not ku.key_cert_sign)
        days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
        check("validity <= 825 days", days <= 825, f"{days} days")
        sans = {str(i) for i in cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress)}
        check("127.0.0.1 in SANs", "127.0.0.1" in sans)

        key_bytes, cert_bytes = key_p.read_bytes(), cert_p.read_bytes()
        webbridge.ensure_cert(d)
        check("no reissue when nothing changed", cert_p.read_bytes() == cert_bytes)

        # A new primary address (the laptop moved networks): reissue, same key.
        webbridge.lan_addresses = lambda: [("10.99.88.77", "Wi-Fi")]
        webbridge.ensure_cert(d)
        new = x509.load_pem_x509_certificate(cert_p.read_bytes())
        new_sans = {str(i) for i in new.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress)}
        check("reissued for an uncovered primary address", "10.99.88.77" in new_sans)
        check("earlier addresses carried forward", sans <= new_sans)
        check("key stable across reissue", key_p.read_bytes() == key_bytes)
        webbridge.lan_addresses = real_lan

        # The upgrade path: an old CA-flagged, 10-year certificate on disk.
        key = serialization.load_pem_private_key(key_bytes, password=None)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LudusCtrl")])
        now = datetime.datetime.now(datetime.timezone.utc)
        old = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(now + datetime.timedelta(days=3650))
               .add_extension(x509.SubjectAlternativeName(
                   [x509.IPAddress(__import__("ipaddress").ip_address(ip)) for ip in new_sans]),
                   critical=False)
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
               .sign(key, hashes.SHA256()))
        cert_p.write_bytes(old.public_bytes(serialization.Encoding.PEM))
        (cert_p.parent / "web-cert.ips").write_text("legacy", encoding="utf-8")
        webbridge.ensure_cert(d)
        up = x509.load_pem_x509_certificate(cert_p.read_bytes())
        check("old CA-style certificate replaced once",
              up.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False)
        check("... keeping the key", key_p.read_bytes() == key_bytes)
        check("legacy .ips file removed", not (cert_p.parent / "web-cert.ips").exists())
        again = cert_p.read_bytes()
        webbridge.ensure_cert(d)
        check("... and only once", cert_p.read_bytes() == again)
    finally:
        webbridge.lan_addresses = real_lan
        shutil.rmtree(d, ignore_errors=True)


def main() -> int:
    tests = [test_page, test_auth_and_origin, test_session, test_arbitration,
             test_watchdog_evict, test_close_and_bad_frames,
             test_idle_connections_and_shutdown, test_switching,
             test_hosted_and_isolation, test_certificate]
    try:
        for t in tests:
            try:
                t()
            except Exception as exc:
                import traceback
                traceback.print_exc()
                check(f"{t.__name__} ran without error", False, repr(exc))
    finally:
        shutil.rmtree(CERT_TMP, ignore_errors=True)
    live = [t.name for t in threading.enumerate() if t.name.startswith("webbridge-")]
    check("no bridge threads left running", not live, str(live))

    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s): " + ", ".join(FAILURES))
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
