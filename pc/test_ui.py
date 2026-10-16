# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Josip Parlov (@parl0v). See NOTICE for the attribution terms.
"""Smoke test for the desktop app: does the window come up and actually run?

Starts the real app, feeds it synthetic pad packets, and reads state back out
of the page. Checks the canvas renders at display rate, since the whole reason
for the web front end was that Tk could not.

Also covers the browser client from the window's side: started at launch
because the (temporary) settings file says so, its link, QR sheet and switch,
and the instrument front end showing the same. Settings and certificate live
in a throwaway directory, never the real %LOCALAPPDATA%\\LudusCtrl.

    python test_ui.py
"""

from __future__ import annotations

import json
import math
import os
import shutil
import socket
import ssl
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Settings, pairings and the certificate all live in a throwaway directory,
# never the real one. Set before app is imported.
TMP = tempfile.mkdtemp(prefix="ludusctrl-test-ui-")
os.environ["LUDUSCTRL_DATA_DIR"] = TMP
os.environ.pop("LUDUSCTRL_TEST_AUTO_ALLOW", None)

import app as appmod  # noqa: E402
import dualsense_link as dsl  # noqa: E402
import pairing  # noqa: E402
from fake_phone import FakePhone  # noqa: E402

PORT = 45986
FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail else ""))
    if not ok:
        FAILURES.append(name)


def fetch_page(port: int):
    """GET / from the app's own bridge. True if the phone page came back."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5),
                             server_hostname="127.0.0.1") as s:
            s.sendall(f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode())
            data = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
        return data.startswith(b"HTTP/1.1 200") and b"getGamepads" in data
    except OSError as exc:
        return repr(exc)


def feed(stop: threading.Event, phone: FakePhone) -> None:
    """Sweep the sticks and cycle buttons so the UI has something to draw,
    as a paired phone on a new link."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    phone.start_session()
    t0 = time.time()
    bits = [0x1000, 0x2000, 0x4000, 0x8000, 0x0040, 0x0080, 0x0400, 0x0001]
    while not stop.is_set():
        t = time.time() - t0
        a = t * 2.2
        s.sendto(phone.packet(
            buttons=bits[int(t * 2) % len(bits)],
            lx=int(26000 * math.cos(a)), ly=int(26000 * math.sin(a)),
            rx=int(17000 * math.sin(a)), ry=int(17000 * math.cos(a)),
            lt=int(127 + 127 * math.sin(t * 1.7)), rt=int(127 + 127 * math.cos(t * 1.3)),
            flags=1, layout=0), ("127.0.0.1", PORT))
        time.sleep(0.008)


def wait_js(js, expr: str, timeout: float = 10.0):
    """Poll a page expression until it is truthy; returns its last value."""
    deadline = time.monotonic() + timeout
    value = None
    while time.monotonic() < deadline:
        try:
            value = js(expr)
        except Exception:
            value = None
        if value:
            return value
        time.sleep(0.1)
    return value


def pair_in_background(phone: FakePhone, results: dict, key: str) -> threading.Thread:
    """Run the phone's side of pairing over loopback, as the app would."""
    t = threading.Thread(target=lambda: results.__setitem__(
        key, phone.pair("127.0.0.1", PORT, timeout=25)), daemon=True)
    t.start()
    return t


def main() -> int:
    if sys.platform != "win32":
        return print("Desktop app is Windows only.") or 1

    # Nothing here may touch the real settings or the certificate a phone
    # already trusts, so both live in a throwaway directory.
    tmp = TMP
    settings = os.path.join(tmp, "settings.json")
    with open(settings, "w", encoding="utf-8") as fh:
        json.dump({"web": True}, fh)       # remembered as on: the startup branch
    a = appmod.App(PORT, dsl.DEFAULT_BEACON_PORT, False, "x360", web_port=0,
                   settings_path=settings, cert_directory=os.path.join(tmp, "cert"),
                   data_directory=os.path.join(tmp, "data"))
    streamer = FakePhone(name="Streaming phone")
    streamer.adopt(a.pairing.store)
    stop = threading.Event()
    results: dict = {}
    js = lambda code: a.window.evaluate_js(code)  # noqa: E731

    def probe() -> None:
        try:
            a._on_ready()
            time.sleep(2.5)
            threading.Thread(target=feed, args=(stop, streamer), daemon=True).start()
            time.sleep(3.0)

            results["service"] = a.service is not None
            results["pad"] = a.service.gamepad.kind if a.service else None
            results["packets"] = a.service.receiver.packets if a.service else 0
            results["linked"] = a.service.receiver.linked if a.service else False

            # Let the page settle, then sample the render loop.
            time.sleep(1.5)
            results["fps"] = js("window.__fps")
            results["title"] = js("document.title")
            results["glow"] = js("typeof glowAmt === 'object' && 'l3' in glowAmt")
            results["cards"] = js("getComputedStyle(document.querySelector('.card')).borderRadius")
            results["padkind"] = js("document.getElementById('btnX360').classList.contains('on')")
            results["pressed"] = js("document.getElementById('btnX360').getAttribute('aria-pressed')")
            results["version"] = js("document.getElementById('ver').textContent")

            # Browser client, started at launch because settings said so.
            results["web_started"] = a.web_server is not None
            token = a.web_bridge.token if a.web_bridge else "?"
            results["web_url"] = js("document.getElementById('webUrl').textContent")
            results["web_token"] = token
            results["web_switch"] = js("document.getElementById('webToggle').getAttribute('aria-checked')")
            if a.web_server:
                results["web_page"] = fetch_page(a.web_server.port)
            js("document.getElementById('webQr').click()")
            time.sleep(0.4)
            results["qr"] = js("JSON.stringify({open: !document.getElementById('qrSheet').hidden,"
                               " w: document.getElementById('qrCanvas').width})")
            js("document.dispatchEvent(new KeyboardEvent('keydown', {key: 'Escape'}))")
            time.sleep(0.2)
            results["qr_closed"] = js("document.getElementById('qrSheet').hidden")

            # Responsive, with the browser-client card open (the tallest the
            # page gets): at every size the window can be dragged to, the page
            # must fit rather than clip. Measured, not eyeballed.
            overflow = {}
            for w, h in ((560, 800), (430, 540), (880, 640), (420, 520)):
                a.window.resize(w, h)
                time.sleep(0.8)
                overflow[f"{w}x{h}"] = js(
                    "JSON.stringify({"
                    " ox: document.documentElement.scrollWidth - document.documentElement.clientWidth,"
                    " oy: document.documentElement.scrollHeight - document.documentElement.clientHeight,"
                    " clip: Math.max(0, ...[...document.getElementById('app').children]"
                    "   .filter(e => e.offsetParent !== null)"
                    "   .map(e => e.getBoundingClientRect().bottom - innerHeight)),"
                    " pad: document.querySelector('canvas').getBoundingClientRect().width|0"
                    "})")
            results["overflow"] = overflow

            # The switch, clicked like a user would: off, then on again.
            js("document.getElementById('webToggle').click()")
            time.sleep(1.5)
            results["web_off"] = (a.web_server is None,
                                  appmod.load_settings(appmod.Path(settings)).get("web"),
                                  js("document.getElementById('webToggle').getAttribute('aria-checked')"))
            js("document.getElementById('webToggle').click()")
            time.sleep(2.0)
            results["web_on"] = (a.web_server is not None,
                                 appmod.load_settings(appmod.Path(settings)).get("web"),
                                 a.web_bridge is not None and a.web_bridge.token != token)

            # Pairing, as a user would do it: a phone asks, the prompt shows
            # the phone's own code, Allow is clicked.
            newcomer = FakePhone(name="Pixel 8")
            pairer = pair_in_background(newcomer, results, "pair_state")
            results["pair_shown"] = wait_js(js, "!document.getElementById('pairSheet').hidden")
            results["pair_armed_late"] = js("document.getElementById('pairAllow').disabled")
            results["pair_code"] = js("document.getElementById('pairCode').textContent")
            results["pair_name"] = js("document.getElementById('pairName').textContent")
            results["pair_count"] = js("document.getElementById('pairCount').textContent")
            results["phone_code"] = newcomer.code
            time.sleep(1.2)                  # Allow arms after a second
            js("document.getElementById('pairAllow').click()")
            pairer.join(30)
            results["pair_closed"] = wait_js(js, "document.getElementById('pairSheet').hidden")
            results["paired"] = a.pairing.store.get(newcomer.id) is not None
            results["phones_btn"] = wait_js(
                js, "document.getElementById('phonesBtn').textContent.includes('(2)')"
                " && document.getElementById('phonesBtn').textContent")

            # Deny.
            time.sleep(1.1)                  # the per-address pairing rate limit
            refused = FakePhone(name="Stranger")
            pairer = pair_in_background(refused, results, "deny_state")
            wait_js(js, "!document.getElementById('pairSheet').hidden")
            js("document.getElementById('pairDeny').click()")
            pairer.join(30)
            results["deny_stored"] = a.pairing.store.get(refused.id) is not None

            # Remove, from the list: two clicks, the second confirms.
            js("document.getElementById('phonesBtn').click()")
            time.sleep(0.3)
            results["phones_open"] = js("!document.getElementById('phonesSheet').hidden")
            results["phones_rows"] = js("document.getElementById('phonesList').childElementCount")
            remove = ("[...document.querySelectorAll('#phonesList li')].find(li => "
                      "li.querySelector('.who').textContent === 'Pixel 8').querySelector('button')")
            js(remove + ".click()")
            time.sleep(0.3)
            results["removed_early"] = a.pairing.store.get(newcomer.id) is None
            js(remove + ".click()")
            time.sleep(0.8)
            results["removed"] = a.pairing.store.get(newcomer.id) is None
            results["phones_rows_after"] = js(
                "document.getElementById('phonesList').childElementCount")
            js("document.dispatchEvent(new KeyboardEvent('keydown', {key: 'Escape'}))")
            time.sleep(0.2)
            results["phones_closed"] = js("document.getElementById('phonesSheet').hidden")
            results["note"] = js("document.getElementById('phonesNote').textContent")

            # The UI log is capped.
            js("for (let i = 0; i < 450; i++) appendLog('line ' + i)")
            results["log_rows"] = js("document.getElementById('log').childElementCount")

            # The instrument front end speaks the same contract.
            # As a file:// URI: a bare path is resolved by pywebview's own
            # server, which is rooted at the first page's folder.
            a.window.load_url(appmod.Path(appmod.resource("webui-instrument", "index.html")).as_uri())
            time.sleep(2.0)
            a._push_web()
            a._sent_stats = None
            time.sleep(0.5)
            results["inst"] = js("JSON.stringify({qr: typeof QR, url: document.getElementById('webUrl').textContent,"
                                 " on: document.getElementById('webToggle').getAttribute('aria-checked')})")
            a._pairing_dirty = True
            time.sleep(1.2)
            other = FakePhone(name="Instrument phone")
            pairer = pair_in_background(other, results, "inst_pair_state")
            results["inst_prompt"] = wait_js(
                js, "!document.getElementById('pairSheet').hidden"
                " && document.getElementById('pairCode').textContent")
            results["inst_code"] = other.code
            time.sleep(1.2)
            js("document.getElementById('pairAllow').click()")
            pairer.join(30)
            results["inst_phones"] = wait_js(
                js, "document.getElementById('phonesBtn').textContent.includes('(2)')"
                " && document.getElementById('phonesBtn').textContent")
        except Exception as exc:
            import traceback
            results["error"] = traceback.format_exc()
        finally:
            stop.set()
            try:
                a.window.destroy()
            except Exception:
                pass

    a.window = appmod.webview.create_window(
        "LudusCtrl", appmod.resource("webui", "index.html"),
        js_api=appmod.Api(a), width=560, height=800,
        background_color="#0B0E14", frameless=True, easy_drag=False,
    )
    appmod.webview.start(probe, private_mode=True)
    a.shutdown()

    if "error" in results:
        print("harness error:", results["error"])
        return 1

    check("receiver service started", results.get("service"))
    check("virtual pad created", results.get("pad") == "Xbox 360", str(results.get("pad")))
    check("page loaded", results.get("title") == "LudusCtrl", str(results.get("title")))
    check("packets reached the app", results.get("packets", 0) > 100,
          str(results.get("packets")))
    check("link registered as live", results.get("linked"))
    check("cards are rounded", results.get("cards", "0px") not in ("0px", "", None),
          str(results.get("cards")))
    check("L3/R3 glow state exists", results.get("glow") is True)
    check("pad-type control reflects x360", results.get("padkind") is True)

    check("pad-type control exposes aria-pressed", results.get("pressed") == "true")
    check("version shown", results.get("version") == appmod.APP_VERSION,
          repr(results.get("version")))

    fps = results.get("fps") or 0
    check("canvas renders at display rate while input moves", fps >= 50, f"{fps} fps")

    for size, raw in (results.get("overflow") or {}).items():
        m = json.loads(raw)
        check(f"fits at {size}", m["ox"] <= 1 and m["oy"] <= 1 and m["clip"] <= 1,
              f"overflow {m['ox']}x{m['oy']}px, clipped {m['clip']:.0f}px, pad {m['pad']}px wide")
        check(f"pad still drawn at {size}", m["pad"] > 80, f"{m['pad']}px")

    print()
    check("browser client started from remembered setting", results.get("web_started"))
    check("switch shows on", results.get("web_switch") == "true")
    url = results.get("web_url") or ""
    check("full link with token shown", url.startswith("https://")
          and url.endswith("/#t=" + str(results.get("web_token"))), url)
    check("phone page served by the running bridge", results.get("web_page") is True,
          str(results.get("web_page")))
    qr = json.loads(results.get("qr") or "{}")
    check("QR sheet opens with a code drawn", qr.get("open") and qr.get("w", 0) > 100, str(qr))
    check("Escape closes the QR sheet", results.get("qr_closed") is True)
    off = results.get("web_off") or (None, None, None)
    check("switch off stops the bridge and is remembered",
          off[0] is True and off[1] is False and off[2] == "false", str(off))
    on = results.get("web_on") or (None, None, None)
    check("switch on starts it again with a new token", on == (True, True, True), str(on))
    check("UI log capped at 400 rows", results.get("log_rows") == 400, str(results.get("log_rows")))

    print()
    check("a pairing request shows the prompt", results.get("pair_shown") is True)
    check("Allow is not armed the instant the prompt appears",
          results.get("pair_armed_late") is True)
    check("the prompt shows the phone's own code",
          results.get("pair_code") == pairing.format_code(results.get("phone_code") or 0),
          f"{results.get('pair_code')} vs phone {results.get('phone_code')}")
    check("the prompt names the device", "Pixel 8" in (results.get("pair_name") or ""),
          str(results.get("pair_name")))
    check("the prompt counts down from 60 s",
          (results.get("pair_count") or "").endswith("s left")
          and int((results.get("pair_count") or "0").split()[0]) >= 55,
          str(results.get("pair_count")))
    check("clicking Allow pairs the phone", results.get("pair_state") == pairing.STATE_ACCEPTED
          and results.get("paired"), str(results.get("pair_state")))
    check("the prompt closes after Allow", results.get("pair_closed") is True)
    check("the phones button counts both phones", results.get("phones_btn") == "Paired phones (2)",
          str(results.get("phones_btn")))
    check("clicking Deny refuses the phone", results.get("deny_state") == pairing.STATE_DENIED
          and results.get("deny_stored") is False, str(results.get("deny_state")))
    check("the paired phones list opens", results.get("phones_open") is True
          and results.get("phones_rows") == 2, str(results.get("phones_rows")))
    check("one click on Remove does not remove", results.get("removed_early") is False)
    check("the second click does", results.get("removed") is True
          and results.get("phones_rows_after") == 1)
    check("Escape closes the list", results.get("phones_closed") is True)
    check("status note says what it is waiting for",
          results.get("note") in ("Linked: Streaming phone", "Waiting for a paired phone"),
          str(results.get("note")))
    inst = json.loads(results.get("inst") or "{}")
    check("instrument front end shows the link", inst.get("qr") == "object"
          and "#t=" in (inst.get("url") or "") and inst.get("on") == "true", str(inst))
    check("instrument front end shows the pairing prompt with the code",
          results.get("inst_prompt") == pairing.format_code(results.get("inst_code") or 0),
          f"{results.get('inst_prompt')} vs {results.get('inst_code')}")
    check("and pairs through it", results.get("inst_pair_state") == pairing.STATE_ACCEPTED
          and results.get("inst_phones") == "Paired phones (2)", str(results.get("inst_phones")))
    check("app stopped the bridge on shutdown", a.web_server is None)
    shutil.rmtree(tmp, ignore_errors=True)

    print()
    if FAILURES:
        print("FAILED: " + ", ".join(FAILURES))
        return 1
    print("all desktop app checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
