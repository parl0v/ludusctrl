# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Josip Parlov (@parl0v). See NOTICE for the attribution terms.
"""The desktop app's wiring between the UDP receiver and the browser bridge.

test_webbridge.py proves the bridge obeys a link_getter, and the receiver's own
tests prove it obeys blocked_by. This proves app.py connects the two the right
way round, with the real ReceiverService and the real bridge, and that the
app's own locking and error paths hold:

  - a browser is refused ("busy:app") while the Android app is linked,
  - a driving browser blocks UDP input, which resumes when it leaves,
  - the status readout follows whoever holds the pad,
  - concurrent pad switches leave exactly one live pad,
  - an unexpected exception while starting the pad fails cleanly.

A stub pad stands in for ViGEm, so no driver is needed.

    python test_app_arbitration.py
"""

from __future__ import annotations

import os
import shutil
import socket
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# Pairings, settings and certificates all stay in a throwaway directory.
TMP = tempfile.mkdtemp(prefix="ludusctrl-test-app-")
os.environ["LUDUSCTRL_DATA_DIR"] = TMP
os.environ.pop("LUDUSCTRL_TEST_AUTO_ALLOW", None)

import dualsense_link as dsl  # noqa: E402
import app as appmod  # noqa: E402
import test_webbridge as tw  # noqa: E402  (its WebSocket client; main() not run)
from fake_phone import FakePhone  # noqa: E402

FAILURES: list[str] = []


def check(name: str, ok, detail: str = "") -> None:
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail else ""))
    if not ok:
        FAILURES.append(name)


made: list = []


class FakePad:
    def __init__(self, kind):
        self.kind = {"x360": "Xbox 360", "ds4": "DualShock 4"}.get(kind, kind)
        self.last = None
        self.released = 0
        made.append(self)

    def apply(self, *a):
        self.last = a

    def release(self):
        self.released += 1
        self.last = None


class Udp(threading.Thread):
    """The Android app, as far as the receiver can tell: a paired phone
    starting a new link (session) and streaming authenticated packets."""

    def __init__(self, port, buttons, phone):
        super().__init__(daemon=True)
        self.port, self.buttons, self.phone = port, buttons, phone
        self.stop = threading.Event()
        phone.start_session()

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while not self.stop.is_set():
            s.sendto(self.phone.packet(buttons=self.buttons, lx=7, ly=7, rx=7, ry=7,
                                       lt=7, rt=7, flags=1, layout=2),
                     ("127.0.0.1", self.port))
            time.sleep(0.01)
        s.close()


def wait_for(pred, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.02)
    return pred()


def main() -> int:
    real_create = dsl.create_gamepad
    dsl.create_gamepad = FakePad
    tmp = TMP
    a = appmod.App(0, dsl.DEFAULT_BEACON_PORT, False, "x360", web_port=0,
                   settings_path=os.path.join(tmp, "settings.json"),
                   cert_directory=os.path.join(tmp, "cert"),
                   data_directory=os.path.join(tmp, "data"))
    phone = FakePhone(name="Arbitration phone")
    phone.adopt(a.pairing.store)
    udp = None
    try:
        check("the app keeps pairings in the directory it was given",
              str(a.pairing.store.dir) == os.path.join(tmp, "data"))
        a.start_service()
        check("service up on a stub pad", a.service is not None and a.port > 0)
        check("started the browser client", a.start_web())
        wport, token = a.web_server.port, a.web_bridge.token
        pad = a._pad

        print("\n--- Android app first ---")
        udp = Udp(a.port, 0x1000, phone)
        udp.start()
        check("UDP linked and driving", wait_for(lambda: a.service.receiver.linked
                                                 and pad().last and pad().last[0] == 0x1000))
        c = tw.Client(wport, token=token)
        texts, close, _ = c.until_closed()
        check("browser refused with busy:app", "busy:app" in texts, repr(texts))
        c.close()
        check("status shows the phone app", a._stats()["label"] == "LIVE"
              and a._stats()["client"] == "127.0.0.1", str(a._stats()))

        print("\n--- then the browser ---")
        udp.stop.set()
        udp.join()
        check("UDP link times out", wait_for(lambda: not a.service.receiver.linked, 4))
        c = tw.Client(wport, token=token)
        check("browser claims once UDP is gone", c.ready())
        c.packet(seq=1, buttons=0x2000)
        c.feeding = True
        c.pump(0.3)
        check("browser drives the pad", pad().last is not None and pad().last[0] == 0x2000,
              str(pad().last))

        udp = Udp(a.port, 0x4000, phone)       # the Android app comes back meanwhile
        udp.start()
        c.pump(0.6)
        r = a.service.receiver
        check("UDP input blocked while the browser drives",
              getattr(r, "blocked", None) is True and pad().last[0] == 0x2000,
              f"blocked={getattr(r, 'blocked', None)} last={pad().last}")
        st = a._stats()
        check("status follows the browser", st["client"] == "browser" and st["label"] == "LIVE",
              str(st))

        c.close()
        check("UDP takes over when the browser leaves",
              wait_for(lambda: pad().last is not None and pad().last[0] == 0x4000, 4),
              str(pad().last))
        check("receiver no longer blocked", getattr(a.service.receiver, "blocked", False) is False)
        udp.stop.set()
        udp.join()
        udp = None

        print("\n--- locking and error paths ---")
        before = len(made)
        api = appmod.Api(a)
        check("unknown pad kind refused", api.set_pad("bogus") is False and len(made) == before)
        threads = [threading.Thread(target=a.switch_pad, args=(k,))
                   for k in ("ds4", "x360", "ds4", "x360", "ds4", "x360")]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        current = a._pad()
        leaked = [p for p in made if p is not current and p.released == 0]
        check("concurrent switches leave one live pad", current is not None and not leaked,
              f"{len(leaked)} pad(s) never released")
        check("pad kind matches the service", a.service.pad_kind == a.pad_kind)

        r = a.service.receiver
        r.linked, r.peer = True, None      # the watchdog's half-written state
        try:
            a._stats()
            ok = True
        except Exception as exc:
            ok = repr(exc)
        check("status readout survives a half-cleared peer", ok is True, str(ok))

        def broken(kind="x360"):
            raise Exception("simulated: ViGEmBus not found")   # what vgamepad raises
        dsl.create_gamepad = broken
        a.pad_kind = "x360"
        try:
            a.switch_pad("ds4")
            raised = None
        except Exception as exc:
            raised = repr(exc)
        check("bare Exception from the pad is contained", raised is None and a.service is None,
              str(raised))
        dsl.create_gamepad = FakePad
        check("the app recovers on the next switch", a.switch_pad("x360") and a.service is not None)
    finally:
        if udp:
            udp.stop.set()
        a.shutdown()
        dsl.create_gamepad = real_create
        shutil.rmtree(tmp, ignore_errors=True)
        shutil.rmtree(tw.CERT_TMP, ignore_errors=True)

    check("shutdown stopped the bridge and the service", a.web_server is None and a.service is None)
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s): " + ", ".join(FAILURES))
        return 1
    print("all app arbitration checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
