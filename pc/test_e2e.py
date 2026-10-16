# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Josip Parlov (@parl0v). See NOTICE for the attribution terms.
"""End-to-end test: UDP packet in, real XInput state out.

Starts the receiver as a subprocess, pairs with it over loopback the way the
phone does, sends authenticated DSLINK v2 packets at it, and reads the
resulting pad state back out of Windows through XInput. That closes the loop
through ViGEmBus rather than trusting our own report object, so a passing run
means a game would see the same thing.

Nobody is there to click Allow, so the receiver runs with the test-only
LUDUSCTRL_TEST_AUTO_ALLOW=1, which a packaged build refuses. Its pairings go
to a throwaway LUDUSCTRL_DATA_DIR, never the real one.

    python test_e2e.py

Requires vgamepad and ViGEmBus. Does not require an Android device.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import dualsense_link as d  # noqa: E402
import pairing as p  # noqa: E402
from fake_phone import FakePhone  # noqa: E402

PORT = 45999  # off the default so a real receiver can be running alongside
HOST = "127.0.0.1"


# --- XInput ------------------------------------------------------------------

class XINPUT_GAMEPAD(ctypes.Structure):
    _fields_ = [
        ("wButtons", ctypes.c_ushort),
        ("bLeftTrigger", ctypes.c_ubyte),
        ("bRightTrigger", ctypes.c_ubyte),
        ("sThumbLX", ctypes.c_short),
        ("sThumbLY", ctypes.c_short),
        ("sThumbRX", ctypes.c_short),
        ("sThumbRY", ctypes.c_short),
    ]


class XINPUT_STATE(ctypes.Structure):
    _fields_ = [("dwPacketNumber", ctypes.c_ulong), ("Gamepad", XINPUT_GAMEPAD)]


def load_xinput():
    for name in ("XInput1_4.dll", "XInput1_3.dll", "xinput9_1_0.dll"):
        try:
            return ctypes.windll.LoadLibrary(name)
        except OSError:
            continue
    raise SystemExit("No XInput DLL found; this test needs Windows.")


XINPUT = load_xinput()
ERROR_SUCCESS = 0


def connected_slots() -> set[int]:
    state = XINPUT_STATE()
    return {i for i in range(4)
            if XINPUT.XInputGetState(i, ctypes.byref(state)) == ERROR_SUCCESS}


def read_slot(slot: int) -> XINPUT_GAMEPAD | None:
    state = XINPUT_STATE()
    if XINPUT.XInputGetState(slot, ctypes.byref(state)) != ERROR_SUCCESS:
        return None
    return state.Gamepad


# --- harness -----------------------------------------------------------------

class Results:
    def __init__(self) -> None:
        self.failures: list[str] = []

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail else ""))
        if not ok:
            self.failures.append(name)


PHONE = FakePhone(name="e2e phone")


def send(sock: socket.socket, seq: int, **kw) -> None:
    f = dict(buttons=0, lx=0, ly=0, rx=0, ry=0, lt=0, rt=0, flags=1)
    f.update(kw)
    sock.sendto(PHONE.packet(seq, **f), (HOST, PORT))


def drain(sock: socket.socket) -> None:
    sock.setblocking(False)
    try:
        while True:
            sock.recvfrom(64)
    except (BlockingIOError, socket.timeout, OSError):
        pass
    sock.setblocking(True)
    sock.settimeout(2.0)


def ack_for(sock: socket.socket, want_seq: int, timeout: float = 2.0):
    """The first ack echoing want_seq, as FakePhone.read_ack reads it."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            data, _ = sock.recvfrom(64)
        except (socket.timeout, ConnectionResetError):
            continue
        ack = PHONE.read_ack(data)
        if ack is not None and ack[0] == want_seq:
            return ack, data
    return None, None


def settle(slot: int, predicate, timeout: float = 2.0):
    """Poll the real pad until it matches, so the test is not timing-fragile."""
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = read_slot(slot)
        if last is not None and predicate(last):
            return last, True
        time.sleep(0.02)
    return last, False


def main() -> int:
    r = Results()

    before = connected_slots()
    print(f"XInput slots in use before start: {sorted(before) or 'none'}")

    data_dir = tempfile.mkdtemp(prefix="ludusctrl-test-e2e-")
    env = dict(os.environ, LUDUSCTRL_DATA_DIR=data_dir, LUDUSCTRL_TEST_AUTO_ALLOW="1")

    # Its own process group, so Ctrl+Break can be sent to the receiver alone
    # and it shuts down the way a user's Ctrl+C would, through its finally.
    proc = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "dualsense_link.py"),
         "--port", str(PORT), "--no-beacon", "-q"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
        text=True, env=env, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )
    graceful = False
    output = ""
    try:
        # Wait for the virtual pad to show up as a brand new XInput slot.
        slot = None
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                print(proc.stdout.read())
                return print("Receiver exited during startup.") or 1
            new = connected_slots() - before
            if new:
                slot = sorted(new)[0]
                break
            time.sleep(0.1)

        r.check("virtual pad appears in XInput", slot is not None,
                f"slot {slot}" if slot is not None else "no new slot within 15 s")
        if slot is None:
            return 1

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)

        # --- an unpaired phone is told so, and moves nothing ---
        stranger = FakePhone(name="stranger")
        stranger.key = os.urandom(32)
        stranger.kid = p.key_id(stranger.key)
        stranger.start_session()
        sock.sendto(stranger.packet(5, buttons=0x1000), (HOST, PORT))
        got = None
        deadline = time.monotonic() + 2.0
        while got is None and time.monotonic() < deadline:
            try:
                data, _ = sock.recvfrom(64)
            except (socket.timeout, ConnectionResetError):
                continue
            got = stranger.read_ack(data)
        r.check("unpaired phone gets the not-paired ack",
                got is not None and not got[3] and got[2] == d.ACK_NOT_PAIRED, str(got))
        r.check("and moves nothing", read_slot(slot).wButtons == 0)

        # --- pair over loopback, exactly as the phone does ---
        state = PHONE.pair(HOST, PORT, timeout=10, sock=sock)
        sock.settimeout(2.0)
        r.check("pairs over UDP (test auto-allow)", state == p.STATE_ACCEPTED
                and PHONE.key is not None, f"state {state}")
        if state != p.STATE_ACCEPTED:
            return 1
        PHONE.start_session()
        seq = 1

        # --- a forged packet under the right key id does nothing ---
        sock.sendto(PHONE.packet(seq := seq + 1, buttons=0x2000, key=os.urandom(32)),
                    (HOST, PORT))
        time.sleep(0.3)
        r.check("a packet with a bad MAC moves nothing", read_slot(slot).wButtons == 0)

        # --- buttons ---
        send(sock, seq := seq + 1, buttons=0x1000)  # A / cross
        pad, ok = settle(slot, lambda g: g.wButtons == 0x1000)
        r.check("cross reaches XInput as A", ok, f"wButtons=0x{pad.wButtons:04X}")

        send(sock, seq := seq + 1, buttons=0x8000 | 0x0100)  # triangle + L1
        pad, ok = settle(slot, lambda g: g.wButtons == 0x8100)
        r.check("triangle+L1 combine correctly", ok, f"wButtons=0x{pad.wButtons:04X}")

        send(sock, seq := seq + 1, buttons=0)
        pad, ok = settle(slot, lambda g: g.wButtons == 0)
        r.check("buttons release", ok, f"wButtons=0x{pad.wButtons:04X}")

        # --- sticks, including the int16 extremes ---
        send(sock, seq := seq + 1, lx=-32768, ly=32767, rx=12345, ry=-9876)
        pad, ok = settle(slot, lambda g: g.sThumbLX == -32768 and g.sThumbLY == 32767)
        r.check("left stick full deflection survives", ok,
                f"LX={pad.sThumbLX} LY={pad.sThumbLY}")
        r.check("right stick arbitrary values survive",
                pad.sThumbRX == 12345 and pad.sThumbRY == -9876,
                f"RX={pad.sThumbRX} RY={pad.sThumbRY}")

        # --- analog triggers ---
        send(sock, seq := seq + 1, lt=255, rt=128)
        pad, ok = settle(slot, lambda g: g.bLeftTrigger == 255 and g.bRightTrigger == 128)
        r.check("analog triggers survive", ok,
                f"LT={pad.bLeftTrigger} RT={pad.bRightTrigger}")

        # --- ack / round trip ---
        # The receiver acks the very first packet it sees and then rate limits,
        # so drain that queued one before asking a fresh question.
        drain(sock)
        time.sleep(d.ACK_INTERVAL + 0.05)  # make the next packet ack-eligible
        send(sock, seq := seq + 1, buttons=0x0010)
        got_ack, raw = ack_for(sock, seq)
        r.check("receiver acknowledges the client", got_ack is not None, str(got_ack))
        if got_ack:
            r.check("ack is 20 bytes, version 2, with a valid MAC",
                    len(raw) == 20 and raw[0] == d.ACK_MAGIC and raw[1] == 2 and got_ack[3])
            r.check("ack echoes our sequence number", got_ack[0] == seq,
                    f"sent {seq}, echoed {got_ack[0]}")
            r.check("ack reports the pad live", got_ack[2] & 1 == 1)

        # --- a v1 client is told to update, and moves nothing ---
        sock.sendto(d.PACKET.pack(d.MAGIC, 1, 77, 0x1000, 0, 0, 0, 0,
                                  0, 0, 1, 0), (HOST, PORT))
        mismatch, raw = ack_for(sock, 77)
        r.check("v1 packet is acked with bit1, version 2, unauthenticated",
                mismatch is not None and not mismatch[3] and raw[1] == 2
                and mismatch[2] & d.ACK_VERSION_MISMATCH
                and not mismatch[2] & d.ACK_PAD_LIVE, str(mismatch))
        pad = read_slot(slot)
        r.check("v1 packet leaves the pad alone", pad.wButtons == 0x0010,
                f"wButtons=0x{pad.wButtons:04X}")

        # --- datagrams that used to kill the receive thread ---
        sock.sendto(b"\xd5" * 4000, (HOST, PORT))  # WSAEMSGSIZE on Windows
        sock.sendto(b"not a packet", (HOST, PORT))
        send(sock, seq := seq + 1, buttons=0x0020)
        pad, ok = settle(slot, lambda g: g.wButtons == 0x0020)
        r.check("oversized and garbage datagrams do not stop the receiver", ok,
                f"wButtons=0x{pad.wButtons:04X}")
        send(sock, seq := seq + 1, buttons=0x0010)
        settle(slot, lambda g: g.wButtons == 0x0010)

        # --- stale and replayed packets must not rewrite state ---
        send(sock, 1, buttons=0xF0F0)  # ancient seq
        time.sleep(0.3)
        pad = read_slot(slot)
        r.check("stale sequence is ignored", pad.wButtons == 0x0010,
                f"wButtons=0x{pad.wButtons:04X}")
        old = PHONE.packet(seq := seq + 1, buttons=0x8000)
        PHONE.start_session()                  # a new link, as Start does
        seq = 0
        send(sock, seq := seq + 1, buttons=0x0020)
        settle(slot, lambda g: g.wButtons == 0x0020)
        sock.sendto(old, (HOST, PORT))         # the previous link, replayed
        time.sleep(0.3)
        pad = read_slot(slot)
        r.check("a new session restarts seq, and the old one cannot be replayed",
                pad.wButtons == 0x0020, f"wButtons=0x{pad.wButtons:04X}")
        send(sock, seq := seq + 1, buttons=0x0010)
        settle(slot, lambda g: g.wButtons == 0x0010)

        # --- watchdog releases a stuck button ---
        send(sock, seq := seq + 1, buttons=0x1000)
        settle(slot, lambda g: g.wButtons == 0x1000)
        print(f"      holding cross, waiting {d.WATCHDOG_TIMEOUT}s for the watchdog...")
        pad, ok = settle(slot, lambda g: g.wButtons == 0,
                         timeout=d.WATCHDOG_TIMEOUT + 2.0)
        r.check("watchdog releases a held button", ok,
                f"wButtons=0x{pad.wButtons:04X}")

        sock.close()

    finally:
        if proc.poll() is None:
            proc.send_signal(signal.CTRL_BREAK_EVENT)
            try:
                proc.wait(timeout=5)
                graceful = proc.returncode == 0
            except subprocess.TimeoutExpired:
                # Fallback only: TerminateProcess skips the receiver's own
                # cleanup, so a pass after this proves the driver's handle
                # cleanup rather than ours, and graceful stays False.
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        try:
            output = proc.stdout.read()
        except (OSError, ValueError):
            pass

    r.check("receiver stops cleanly on Ctrl+Break", graceful,
            f"exit code {proc.returncode}")
    r.check("shutdown ran the receiver's own cleanup",
            "stopping" in output and "packets " in output,
            output.strip().splitlines()[-1] if output.strip() else "no output")

    # The virtual pad must disappear when the receiver stops, or a stale device
    # would linger in every game's controller list.
    _, gone = (None, False)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if slot not in connected_slots():
            gone = True
            break
        time.sleep(0.1)
    r.check("virtual pad is removed on shutdown", gone)
    if not graceful:
        print("      (after a forced kill, so this proves the driver's cleanup, not ours)")
    r.check("the receiver said it was in test mode", "TEST MODE" in output)
    stored = p.PairingStore(data_dir).get(PHONE.id)
    r.check("the pairing and the last session were saved",
            stored is not None and stored.key == PHONE.key
            and stored.highest_session == PHONE.session,
            f"{stored.highest_session if stored else None} vs {PHONE.session}")
    shutil.rmtree(data_dir, ignore_errors=True)

    print()
    if r.failures:
        print("FAILED: " + ", ".join(r.failures))
        return 1
    print("all end-to-end checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
