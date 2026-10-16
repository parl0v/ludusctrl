# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Josip Parlov (@parl0v). See NOTICE for the attribution terms.
"""LudusCtrl — desktop app.

Runs the receiver and presents it in a native window backed by Edge WebView2,
which ships with Windows 10 and 11. The UI is `webui/index.html`; this module
only owns the window, the service, and the traffic between them.

The web front end exists because Tk could not draw the app the phone draws:
no rounded corners, no alpha (so no glow on a pressed L3/R3), and a Tcl round
trip per canvas item per frame, which is where the frame rate went. The
receiver core was never the bottleneck and is untouched.

    python app.py

The terminal receiver is still there: python dualsense_link.py
"""

from __future__ import annotations

import base64
import html
import json
import logging
import logging.handlers
import os
import queue
import sys
import threading
import time
import traceback
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dualsense_link as dsl  # noqa: E402
import pairing  # noqa: E402
import webbridge  # noqa: E402
from version import VERSION as APP_VERSION  # noqa: E402

try:
    import webview
except ImportError:
    sys.exit("pywebview is required:\n  python -m pip install pywebview")

PAD_KINDS = ("x360", "ds4")

log = logging.getLogger("ludusctrl")


def resource(*parts: str) -> str:
    """Path to a bundled file, whether running from source or PyInstaller."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, *parts)


def state_dir() -> Path:
    """%LOCALAPPDATA%\\LudusCtrl: settings, the log, the web certificate and
    the paired phones. LUDUSCTRL_DATA_DIR moves all of it (the tests do)."""
    return pairing.data_dir()


# --- Log file ------------------------------------------------------------------

class _LogStream:
    """Stands in for stdout/stderr in the windowed build.

    A PyInstaller --windowed exe starts with sys.stdout and sys.stderr set to
    None, so every print was dropped and every traceback vanished: a crash
    left nothing behind to diagnose. This sends them to the log file instead.
    """

    encoding = "utf-8"

    def __init__(self, level: int) -> None:
        self.level = level
        self._buf = ""

    def write(self, text: str) -> int:
        # The console receiver redraws one line with "\r"; only whole lines
        # are worth keeping.
        self._buf += text.replace("\r", "\n")
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            if line.strip():
                log.log(self.level, line)
        return len(text)

    def flush(self) -> None:
        pass

    def isatty(self) -> bool:
        return False


def setup_logging() -> Path:
    """Rotating log at %LOCALAPPDATA%\\LudusCtrl\\ludusctrl.log, 1 MB x 3.

    Also routes every unhandled exception, on any thread, into it. The
    receiver and the web bridge each run threads of their own, and an
    exception there used to end the thread without a trace.
    """
    path = state_dir() / "ludusctrl.log"
    handler = logging.handlers.RotatingFileHandler(
        path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-7s %(threadName)s: %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.INFO)

    if getattr(sys, "frozen", False) or sys.stdout is None or sys.stderr is None:
        sys.stdout = _LogStream(logging.INFO)   # type: ignore[assignment]
        sys.stderr = _LogStream(logging.ERROR)  # type: ignore[assignment]

    def on_exception(kind, value, tb):
        log.critical("unhandled exception:\n%s",
                     "".join(traceback.format_exception(kind, value, tb)))

    def on_thread_exception(args):
        if args.exc_type is SystemExit:
            return
        log.critical("unhandled exception in thread %s:\n%s",
                     args.thread.name if args.thread else "?",
                     "".join(traceback.format_exception(
                         args.exc_type, args.exc_value, args.exc_traceback)))

    sys.excepthook = on_exception
    threading.excepthook = on_thread_exception
    log.info("LudusCtrl %s starting (%s)", APP_VERSION,
             "packaged" if getattr(sys, "frozen", False) else "source")
    return path


# --- Settings ------------------------------------------------------------------

def load_settings(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_settings(path: Path, settings: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(settings, indent=2), encoding="utf-8")
        os.replace(tmp, path)
    except OSError as exc:
        log.warning("could not save settings: %s", exc)


class Api:
    """Exposed to JavaScript as window.pywebview.api.

    Every stored attribute is underscore-prefixed on purpose. pywebview walks
    the public attributes of this object to build the JS bridge, so holding a
    plain reference to App makes it recurse through App -> window -> the native
    WebView2 control and blow the stack.

    pywebview runs each call on a thread of its own, so everything here must be
    safe to call concurrently; App does the locking.
    """

    def __init__(self, app: "App") -> None:
        self._app = app

    def set_pad(self, kind: str) -> bool:
        if kind not in PAD_KINDS:
            return False
        return self._app.switch_pad(kind)

    def set_web(self, on: bool) -> dict:
        """Turn the browser client on or off. Remembered for the next start."""
        return self._app.set_web(bool(on))

    def pair_answer(self, prompt_id: str, allow: bool) -> bool:
        """Allow or Deny the pairing prompt with this id. False if that prompt
        is no longer the open one, so a late click approves nothing."""
        return self._app.pairing.answer(str(prompt_id), bool(allow))

    def phones(self) -> list:
        return self._app.phones_state()

    def remove_phone(self, phone_id: str) -> list:
        """Unpair a phone. It has to pair again before it can connect."""
        self._app.remove_phone(str(phone_id))
        return self._app.phones_state()

    def open_log_folder(self) -> bool:
        try:
            os.startfile(str(state_dir()))  # type: ignore[attr-defined]
            return True
        except OSError:
            return False


class App:
    # Push at most this often. The pad itself is eased in JS at display rate,
    # so a higher push rate would cost bridge calls and buy nothing visible.
    PUSH_HZ = 60

    def __init__(self, port: int, beacon_port: int, use_beacon: bool, pad_kind: str,
                 ui: str = "webui", web: bool = False,
                 web_port: int = webbridge.DEFAULT_WEB_PORT,
                 settings_path: str | os.PathLike | None = None,
                 cert_directory: str | os.PathLike | None = None,
                 data_directory: str | os.PathLike | None = None) -> None:
        self.ui = ui
        self.port = port
        self.beacon_port = beacon_port
        self.use_beacon = use_beacon
        self.pad_kind = pad_kind if pad_kind in PAD_KINDS else "x360"
        self.web_port = web_port
        self.cert_directory = cert_directory

        # --web still forces the browser client on for one run without
        # changing what is remembered; the switch in the window is what the
        # installed app uses, since it has no command line.
        self.settings_path = (Path(settings_path) if settings_path
                              else Path(data_directory or state_dir()) / "settings.json")
        self.settings = load_settings(self.settings_path)
        self.web = bool(web or self.settings.get("web", False))

        self.service: dsl.ReceiverService | None = None
        self.web_server = None
        self.web_bridge: webbridge.WebBridge | None = None
        self.web_error: str | None = None
        self.window: webview.Window | None = None

        # One lock for everything that creates or destroys the virtual pad.
        # pywebview runs each JS call on a new thread and the browser bridge
        # switches from its handler thread, so two switches used to be able
        # to interleave and leave a second ReceiverService (and a second
        # virtual controller) behind. Reentrant because switch_pad restarts
        # the service through start_service.
        self._svc_lock = threading.RLock()
        # Separate, and never held while waiting on the service lock, so
        # stopping the bridge cannot wait on a switch the bridge started.
        self._web_lock = threading.Lock()

        self._events: queue.Queue = queue.Queue()

        # Pairing outlives any one ReceiverService: switching the pad type
        # restarts the service, and must not drop an open prompt or reload
        # the store.
        self.pairing = pairing.PairingManager(
            pairing.PairingStore(data_directory, on_status=self._events.put),
            on_change=self._on_pairing)
        self._pairing_dirty = True

        self._latest: dsl.PadState | None = None
        self._sent_state = None
        self._sent_stats = None
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._pump_error_at = 0.0

        self._last_count = 0
        self._last_sample = 0.0
        self._rate = 0.0

        self._web_count = 0
        self._web_sample = 0.0
        self._web_bps = 0.0

    # --- window ------------------------------------------------------------

    def run(self) -> int:
        self.window = webview.create_window(
            "LudusCtrl",
            resource(self.ui, "index.html"),
            js_api=Api(self),
            width=560, height=800, min_size=(420, 520),
            background_color="#0B0E14",
            # Native frame on purpose. pywebview's WinForms backend sets
            # FormBorderStyle.None for frameless windows and implements no
            # WM_NCHITTEST, so a frameless window cannot be resized at all.
            # Keeping the frame buys dragging, all eight resize edges, Aero
            # Snap and double-click maximise for free; the title bar is then
            # darkened below so it still matches the page.
            frameless=False, resizable=True,
        )
        # private_mode keeps WebView2 on an ephemeral profile. A shared
        # persistent profile directory gets locked by any still-running
        # instance and the next launch comes up as an empty window.
        webview.start(self._on_ready, private_mode=True)
        self.shutdown()
        return 0

    def _dark_titlebar(self) -> None:
        """Ask DWM for a dark title bar so the frame matches the page."""
        try:
            import ctypes
            hwnd = int(self.window.native.Handle)
            for attr in (20, 19):   # DWMWA_USE_IMMERSIVE_DARK_MODE, 20 then legacy 19
                if ctypes.windll.dwmapi.DwmSetWindowAttribute(
                        hwnd, attr, ctypes.byref(ctypes.c_int(1)),
                        ctypes.sizeof(ctypes.c_int)) == 0:
                    break
        except Exception:
            pass  # cosmetic only, and Windows-version dependent

    def _on_ready(self) -> None:
        """Runs once the DOM is live; safe to start pushing from here."""
        self._dark_titlebar()
        self._ready.set()
        # The pump first, so whatever goes wrong below still reaches the log
        # panel instead of leaving a window that never fills in.
        threading.Thread(target=self._pump, name="dslink-ui", daemon=True).start()
        try:
            self.start_service()
        except Exception as exc:   # start_service reports its own; belt and braces
            log.exception("service start failed")
            self._fail(f"Could not start the receiver: {exc}")
        try:
            if self.web:
                self.start_web()
            else:
                self._push_web()
        except Exception as exc:
            log.exception("browser client start failed")
            self._log(f"browser client unavailable: {exc}")

    def shutdown(self) -> None:
        self._stop.set()
        self.stop_web()
        with self._svc_lock:
            if self.service:
                self.service.stop()
                self.service = None
        self.pairing.store.close()

    # --- service -----------------------------------------------------------

    def _pad(self):
        """The live virtual pad, or None. Read once: another thread may be
        tearing the service down between a check and a use."""
        svc = self.service
        return svc.gamepad if svc is not None else None

    def _browser_driving(self) -> bool:
        """blocked_by for the UDP receiver: a browser holds the pad."""
        bridge = self.web_bridge
        return bridge is not None and bridge.driving()

    def _udp_linked(self) -> bool:
        """link_getter for the bridge: the Android app is linked over UDP."""
        svc = self.service
        receiver = svc.receiver if svc is not None else None
        return bool(receiver is not None and receiver.linked)

    def _make_service(self) -> dsl.ReceiverService:
        kwargs = dict(port=self.port, beacon_port=self.beacon_port, beacon=self.use_beacon,
                      verbose=False, pad_kind=self.pad_kind,
                      on_state=self._on_state,
                      on_status=lambda msg: self._events.put(msg),
                      pairing=self.pairing)
        # Only one source may drive the pad; the receiver asks this for every
        # packet. Passed to the constructor so every Receiver the service
        # builds (switch_pad makes a new one) carries it. A receiver from
        # before arbitration existed does not take the argument; it still
        # starts, just without the block.
        try:
            svc = dsl.ReceiverService(blocked_by=self._browser_driving, **kwargs)
        except TypeError:
            svc = dsl.ReceiverService(**kwargs)
            svc.blocked_by = self._browser_driving
        return svc

    def start_service(self) -> None:
        with self._svc_lock:
            svc = self._make_service()
            try:
                svc.start()
            except dsl.PadUnavailable as exc:
                self._abandon(svc)
                self._fail(str(exc))
                return
            except OSError as exc:
                self._abandon(svc)
                self._fail(f"Cannot listen on UDP {self.port}: {exc}\n"
                           "Another copy of the receiver is probably already running.")
                return
            except Exception as exc:
                # vgamepad raises a bare Exception at import time when the
                # ViGEmBus driver is missing, and that used to escape both
                # handlers above, abort _on_ready and leave a blank window.
                log.exception("receiver failed to start")
                self._abandon(svc)
                self._fail(f"Could not create the virtual pad: {exc}\n"
                           "The ViGEmBus driver is probably missing or not working. "
                           "Install it from https://github.com/nefarius/ViGEmBus/releases "
                           "and restart LudusCtrl.")
                return

            receiver = getattr(svc, "receiver", None)
            if receiver is not None and getattr(receiver, "blocked_by", None) is None:
                receiver.blocked_by = self._browser_driving
            self.service = svc
            self.port = getattr(svc, "port", self.port)
            kind_name = svc.gamepad.kind if svc.gamepad else self.pad_kind

        lan = webbridge.lan_addresses()
        primary = lan[0][0] if lan else "no network"
        hint = "Type this into the app if it does not fill in by itself."
        if len(lan) > 1:
            # Addresses only: machines with Hyper-V or VMware have many, and
            # names here pushed the pad view off the window. The browser
            # client's QR sheet lists them with their adapter names.
            others = ", ".join(html.escape(ip) for ip, _ in lan[1:])
            hint += "<br><code>other adapters: " + others + "</code>"

        self._js("setInfo", {
            "sub": f"listening on udp/{self.port} · {kind_name} pad ready",
            "address": primary,
            "hint": hint,
            "kind": self.pad_kind,
            "version": APP_VERSION,
        })
        self._log(f"listening on udp/{self.port}")
        if self.use_beacon:
            self._log(f"broadcasting discovery on udp/{self.beacon_port}")
        self._log(f"virtual pad: {kind_name}")

    @staticmethod
    def _abandon(svc) -> None:
        """Release whatever a half-started service created (its pad above
        all), so a failed start cannot leave a controller plugged in."""
        try:
            svc.stop()
        except Exception:
            pass

    # --- browser client ------------------------------------------------------

    def set_web(self, on: bool) -> dict:
        self.settings["web"] = on
        save_settings(self.settings_path, self.settings)
        if on:
            self.start_web()
        else:
            self.stop_web()
        return self.web_state()

    def start_web(self) -> bool:
        """Serve the browser client, sharing this app's single virtual pad.

        The bridge is given getters rather than a pad. Handing it one would
        make it create nothing but hold a reference, and any second virtual
        pad shows up in Windows as a second controller -- games take the first
        and look dead while the browser drives the second. Getters also mean
        the bridge survives switch_pad(), which destroys and rebuilds the pad
        underneath it.
        """
        with self._web_lock:
            self.web = True
            if self.web_server is not None:
                return True
            self.web_error = None
            try:
                server, bridge = webbridge.serve(
                    port=self.web_port,
                    on_state=self._on_state,
                    pad_getter=self._pad,
                    pad_switcher=self._web_switch_pad,
                    kind_getter=lambda: self.pad_kind,
                    link_getter=self._udp_linked,
                    cert_directory=self.cert_directory,
                )
            except SystemExit as exc:
                # webbridge raises SystemExit for a busy port or a missing
                # certificate library. Neither should take the whole app down
                # when the UDP receiver is running fine without it.
                lines = [ln.strip() for ln in str(exc).splitlines() if ln.strip()]
                self.web_error = lines[0] if lines else "could not start"
            except Exception as exc:
                log.exception("browser client failed to start")
                self.web_error = str(exc) or type(exc).__name__
            else:
                self.web_server, self.web_bridge = server, bridge

        if self.web_error:
            self._log("browser client unavailable: " + self.web_error)
            self._push_web()
            return False

        for u in self.web_state()["urls"]:
            # The token is in the fragment; it goes to the on-screen log so it
            # can be copied from there too, but never into the log file.
            self._js("appendLog", f"browser client: {u['url']}"
                     + (f"  ({u['name']})" if u["name"] else ""))
        log.info("browser client listening on tcp/%s", self.web_server.port
                 if self.web_server else self.web_port)
        self._log("  self-signed certificate — the phone warns once, that is expected")
        self._push_web()
        return True

    def stop_web(self) -> None:
        with self._web_lock:
            self.web = False
            server, self.web_server, self.web_bridge = self.web_server, None, None
        if server is not None:
            # The bridge reference is dropped first so the UDP receiver stops
            # being blocked the moment the browser client goes away.
            server.shutdown()
            server.server_close()
            self._log("browser client stopped")
        self._push_web()

    def web_state(self) -> dict:
        server, bridge = self.web_server, self.web_bridge
        urls = (webbridge.browser_urls(server.port, bridge.token)
                if server is not None and bridge is not None else [])
        return {
            "on": server is not None,
            "wanted": self.web,
            "port": server.port if server is not None else self.web_port,
            "urls": urls,
            "error": self.web_error,
        }

    def _push_web(self) -> None:
        self._js("setWeb", self.web_state())

    def _web_switch_pad(self, kind: str) -> tuple[bool, str]:
        """Pad switching requested from the browser, done the app's way.

        Letting the bridge do it itself would rebuild the pad while the UDP
        receiver still pointed at the released one.
        """
        if kind not in PAD_KINDS:
            return False, "unknown pad kind"
        if self.switch_pad(kind):
            return True, kind
        return False, f"could not create the {kind} pad"

    def switch_pad(self, kind: str) -> bool:
        """Tear the service down and bring it back on the other pad type.

        A ViGEm target cannot change kind in place, so this is a full restart.
        """
        if kind not in PAD_KINDS:
            return False
        with self._svc_lock:
            if kind == self.pad_kind and self.service:
                return True
            self.pad_kind = kind
            svc, self.service = self.service, None
            if svc:
                svc.stop()
            # Leave nothing lit from the old pad.
            self._latest = dsl.PadState(0, 0, 0, 0, 0, 0, 0, False)
            self._last_count = 0
            self._last_sample = 0.0
            self._rate = 0.0

            self._web_count = 0
            self._web_sample = 0.0
            self._web_bps = 0.0
            self.start_service()
            return self.service is not None

    # --- pairing -------------------------------------------------------------

    def _on_pairing(self, kind: str, prompt) -> None:
        """PairingManager's observer. Called from the receive thread or a JS
        call's thread, so it only records; the pump pushes to the page."""
        if kind == "open":
            self._events.put(f"pairing request from {prompt.name}, code "
                             f"{pairing.format_code(prompt.code)}")
        elif kind == "allowed":
            self._events.put(f"paired {prompt.name}")
        elif kind == "denied":
            self._events.put(f"denied pairing to {prompt.name}")
        elif kind == "timeout":
            self._events.put(f"pairing request from {prompt.name} timed out")
        self._pairing_dirty = True

    def phones_state(self) -> list:
        return [ph.public() for ph in self.pairing.store.phones()]

    def remove_phone(self, phone_id: str) -> bool:
        try:
            raw = base64.b64decode(phone_id, validate=True)
        except ValueError:
            return False
        phone = self.pairing.store.get(raw)
        if phone is None or not self.pairing.remove(raw):
            return False
        # Its next packet is answered "not paired", so the phone drops the
        # link and offers to pair again; the watchdog lets go of the pad.
        self._events.put(f"removed {phone.name}; it has to pair again to connect")
        return True

    def _push_pairing(self) -> None:
        self._pairing_dirty = False
        prompt = self.pairing.prompt
        self._js("setPairing", prompt.public(self.pairing.clock()) if prompt else None)
        self._js("setPhones", self.phones_state())

    def _fail(self, message: str) -> None:
        log.error("%s", message)
        self._js("setInfo", {
            "sub": "not running", "address": "—", "hint": "", "kind": self.pad_kind,
            "version": APP_VERSION,
        })
        self._js("setStats", {"client": "—", "packets": "—", "rate": "—",
                              "level": "err", "label": "ERROR"})
        for line in message.splitlines():
            if line.strip():
                self._js("appendLog", line.strip())

    # --- bridge ------------------------------------------------------------

    def _on_state(self, state: dsl.PadState) -> None:
        # Called from the receive thread at up to 500 Hz. Keep only the newest;
        # the UI thread will pick it up on its next tick.
        self._latest = state

    def _js(self, fn: str, payload) -> None:
        if not self._ready.is_set() or not self.window:
            return
        try:
            self.window.evaluate_js(f"window.{fn} && window.{fn}({json.dumps(payload)})")
        except Exception:
            pass  # window closing

    def _log(self, line: str) -> None:
        log.info("%s", line)
        self._js("appendLog", line)

    def _pump(self) -> None:
        interval = 1.0 / self.PUSH_HZ
        while not self._stop.is_set():
            start = time.monotonic()
            try:
                self._pump_once()
            except Exception:
                # One bad tick must not freeze the window for the rest of the
                # session, which is what an exception here used to do. Logged
                # at most every few seconds so a persistent fault cannot flood
                # the log file.
                now = time.monotonic()
                if now - self._pump_error_at > 5.0:
                    self._pump_error_at = now
                    log.exception("UI update failed")
            time.sleep(max(0.0, interval - (time.monotonic() - start)))

    def _pump_once(self) -> None:
        while True:
            try:
                self._log(self._events.get_nowait())
            except queue.Empty:
                break

        if self._pairing_dirty:
            self._push_pairing()

        state = self._latest
        if state is not None and state != self._sent_state:
            self._sent_state = state
            self._js("setPad", {
                "buttons": state.buttons,
                "lx": state.left_x, "ly": state.left_y,
                "rx": state.right_x, "ry": state.right_y,
                "lt": state.left_trigger, "rt": state.right_trigger,
                "connected": state.connected,
                # 0 unknown, 1 PlayStation, 2 Xbox, 3 Nintendo. Chooses the
                # glyphs and body shape only; the mask is vendor-neutral.
                "layout": state.layout,
            })

        stats = self._stats()
        if stats != self._sent_stats:
            self._sent_stats = stats
            self._js("setStats", stats)

    def _web_rate(self, packets: int) -> str:
        """Measured, not assumed: the browser sends at its display rate, which
        is 60 Hz on most phones but not on all of them."""
        now = time.monotonic()
        if not self._web_sample:
            self._web_count, self._web_sample = packets, now
        elif now - self._web_sample >= 0.5:
            sample = (packets - self._web_count) * dsl.PACKET_SIZE / (now - self._web_sample)
            self._web_bps = self._web_bps * 0.5 + sample * 0.5
            self._web_count, self._web_sample = packets, now
        return (f"{self._web_bps:.0f} B/s" if self._web_bps < 1024
                else f"{self._web_bps / 1024:.1f} KB/s")

    def _stats(self) -> dict:
        # Every shared value is read into a local exactly once. The receive
        # thread and the watchdogs replace these underneath this thread; a
        # check-then-use (`r.peer and r.peer[0]`) raced a watchdog setting
        # peer to None, and the TypeError killed this loop for good.
        svc = self.service
        r = svc.receiver if svc is not None else None
        if r is None:
            return {"client": "—", "packets": "—", "rate": "—",
                    "level": "err", "label": "OFFLINE", "note": "Receiver not running"}

        # A browser drives the same virtual pad over a different transport,
        # and while it does the UDP path is blocked, so the readout follows
        # whichever source actually holds the pad.
        b = self.web_bridge
        if b is not None and b.driving():
            with b.lock:
                web_live = (b.driver is not None and b.last_packet_at
                            and time.monotonic() - b.last_packet_at < webbridge.WATCHDOG_TIMEOUT)
                web_packets = b.packets
            if web_live:
                return {
                    "note": "Browser client driving",
                    "client": "browser",
                    "packets": f"{web_packets:,}".replace(",", " "),
                    "rate": self._web_rate(web_packets),
                    "level": "live", "label": "LIVE",
                }

        packets = r.packets
        peer = r.peer
        linked = r.linked
        # A blocked receiver stays linked (it keeps acking the phone), but it
        # is not the one driving the pad, so it must not read LIVE.
        blocked = bool(getattr(r, "blocked", False))

        now = time.monotonic()
        if not self._last_sample:
            self._last_count, self._last_sample = packets, now
        elif now - self._last_sample >= 0.5:
            delta = packets - self._last_count
            sample = delta * dsl.PACKET_V2_SIZE / (now - self._last_sample)
            self._rate = self._rate * 0.5 + sample * 0.5
            self._last_count, self._last_sample = packets, now

        live = bool(linked and peer and not blocked)
        if linked and peer:
            note = f"Linked: {r.peer_name}" if r.peer_name else "Linked"
        elif self.pairing.store.phones():
            note = "Waiting for a paired phone"
        else:
            note = "No phone paired yet. Press Start link in the phone app to pair it."
        return {
            "note": note,
            "client": peer[0] if (linked and peer) else "—",
            "packets": f"{packets:,}".replace(",", " "),
            "rate": (f"{self._rate:.0f} B/s" if self._rate < 1024
                     else f"{self._rate / 1024:.1f} KB/s"),
            "level": "live" if live else "wait",
            "label": "LIVE" if live else ("BLOCKED" if linked and blocked else "WAITING"),
        }


def main() -> int:
    import argparse
    p = argparse.ArgumentParser(description="LudusCtrl receiver (desktop app).")
    p.add_argument("--port", type=int, default=dsl.DEFAULT_INPUT_PORT)
    p.add_argument("--beacon-port", type=int, default=dsl.DEFAULT_BEACON_PORT)
    p.add_argument("--no-beacon", action="store_true")
    p.add_argument("--pad", choices=PAD_KINDS, default="x360")
    # Two front ends live side by side. Both speak the same setPad/setStats/
    # setInfo/setWeb/appendLog contract, so this only swaps the folder.
    p.add_argument("--ui", default="webui",
                   help="front end folder: webui (default) or webui-instrument")
    # Off by default: it opens an HTTPS listener on the LAN, which is not
    # something the UDP receiver needs and not something to turn on for
    # someone without asking. The window has a switch for it that is
    # remembered; this flag turns it on for one run regardless.
    p.add_argument("--web", action="store_true",
                   help="also serve the browser client, for phones with no app (iPhone)")
    p.add_argument("--web-port", type=int, default=webbridge.DEFAULT_WEB_PORT)
    args = p.parse_args()

    try:
        setup_logging()
    except OSError:
        pass   # a read-only profile must not stop the receiver

    if sys.platform != "win32":
        print("This receiver needs Windows and ViGEmBus.")
        return 1

    return App(args.port, args.beacon_port, not args.no_beacon, args.pad, args.ui,
               web=args.web, web_port=args.web_port).run()


if __name__ == "__main__":
    raise SystemExit(main())
