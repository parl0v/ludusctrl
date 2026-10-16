# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Josip Parlov (@parl0v). See NOTICE for the attribution terms.
"""Unit tests for the receiver's packet handling, against a fake ViGEm pad.

No driver, no Android device: this exercises pairing, authentication, replay
protection, ordering, the peer lock, the source filter, acking, the watchdog,
the beacon and the receive loop in isolation (the loop over real loopback
UDP). See test_e2e.py for the full loop out through Windows and back.

Pairings live in throwaway directories, never the real %LOCALAPPDATA%.

    python test_receiver.py
"""

from __future__ import annotations

import base64
import builtins
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Before anything can reach for the real data directory.
TMP_ROOT = tempfile.mkdtemp(prefix="ludusctrl-test-receiver-")
os.environ["LUDUSCTRL_DATA_DIR"] = os.path.join(TMP_ROOT, "default")
os.environ.pop("LUDUSCTRL_TEST_AUTO_ALLOW", None)

# Stub vgamepad so these tests run anywhere, including CI without ViGEmBus.
_fake = types.ModuleType("vgamepad")
_fake.VX360Gamepad = object
_fake.VDS4Gamepad = object
sys.modules.setdefault("vgamepad", _fake)

import dualsense_link as d  # noqa: E402
import pairing as p  # noqa: E402
from fake_phone import FakePhone  # noqa: E402


class _Report:
    def __init__(self):
        self.wButtons = 0
        self.sThumbLX = self.sThumbLY = self.sThumbRX = self.sThumbRY = 0
        self.bLeftTrigger = self.bRightTrigger = 0


class _Pad(d.VirtualPad):
    """Stands in for a ViGEm target and records what was applied."""

    kind = "test"

    def __init__(self):
        super().__init__()
        self.report = _Report()
        self.applies = 0
        self.releases = 0
        self.fail_apply = 0      # raise on the next N applies
        self.fail_release = 0

    def _apply(self, buttons, lx, ly, rx, ry, lt, rt):
        if self.fail_apply:
            self.fail_apply -= 1
            raise Exception("VIGEM_ERROR_BUS_ACCESS_FAILED")  # what vgamepad raises
        self.applies += 1
        r = self.report
        r.wButtons = buttons
        r.sThumbLX, r.sThumbLY = lx, ly
        r.sThumbRX, r.sThumbRY = rx, ry
        r.bLeftTrigger, r.bRightTrigger = lt, rt

    def _release(self):
        if self.fail_release:
            self.fail_release -= 1
            raise Exception("VIGEM_ERROR_BUS_ACCESS_FAILED")
        self.releases += 1
        self.report = _Report()


class _Sock:
    """Captures whatever the receiver tries to send back to the client."""

    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append((data, addr))


FAILURES: list[str] = []
PASSES = 0


def check(name: str, ok, detail: str = "") -> None:
    global PASSES
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail else ""))
    if ok:
        PASSES += 1
    else:
        FAILURES.append(name)


def tmpdir() -> str:
    return tempfile.mkdtemp(dir=TMP_ROOT)


class _Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def acks_to(sock: _Sock, addr, phone: FakePhone) -> list[tuple]:
    """(seq, received, flags, authenticated) for every ack sent to addr."""
    out = []
    for data, to in sock.sent:
        if to == addr:
            ack = phone.read_ack(data)
            if ack is not None:
                out.append(ack)
    return out


def fresh(phones=1, **kw):
    """A receiver with a fake pad and `phones` phones already paired, each
    on its first session. Returns (receiver, pad, sock, log, [phones])."""
    pad, sock, log = _Pad(), _Sock(), []
    store = p.PairingStore(tmpdir())
    manager = p.PairingManager(store, auto_allow=False)
    r = d.Receiver(pad, sock, verbose=False, on_status=log.append, pairing=manager, **kw)
    made = []
    for i in range(phones):
        ph = FakePhone(name=f"Phone {'AB'[i]}")
        ph.adopt(store)
        ph.start_session()
        made.append(ph)
    return r, pad, sock, log, made


PHONE = ("192.168.1.5", 5000)
PHONE_RESTARTED = ("192.168.1.5", 5001)
OTHER = ("192.168.1.9", 6000)


# --- golden bytes -------------------------------------------------------------
# Fixed vectors for the wire format, so a change to either side's packing
# shows up as a hex diff rather than as a mysteriously dead pad.

GOLDEN_PACKETS = [
    # neutral keepalive, seq 1, pad connected, unknown layout
    ((d.MAGIC, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0),
     "d501010000000000000000000000000000000100"),
    # every defined button, int16 extremes, triggers, Xbox layout, seq near wrap
    ((d.MAGIC, 1, 0xFFFFFFFE, 0xF7FF, -32768, 32767, 12345, -9876, 255, 128, 1, 2),
     "d501fefffffffff70080ff7f39306cd9ff800102"),
    # cross only, LY -1, RX +1, no physical pad, PlayStation layout
    ((d.MAGIC, 1, 0x12345678, 0x1000, 0, -1, 1, 0, 0, 0, 0, 1),
     "d5017856341200100000ffff0100000000000001"),
]

GOLDEN_ACKS = [
    # unauthenticated: protocol version mismatch
    ((d.ACK_MAGIC, 2, 0x12345678, 0, d.ACK_VERSION_MISMATCH, 0), "d60278563412000000000200"),
    # unauthenticated: this PC does not know the phone
    ((d.ACK_MAGIC, 2, 7, 0, d.ACK_NOT_PAIRED, 0), "d60207000000000000000400"),
]

# Protocol v2 cross-language vectors. The Android app's tests assert the very
# same numbers, so the phone and this receiver agree byte for byte.
V2_PHONE_SCALAR = int("11" * 32, 16)
V2_PC_SCALAR = int("22" * 32, 16)
V2_PHONE_ID = bytes.fromhex("0102030405060708")
V2_PC_ID = bytes.fromhex("a1a2a3a4a5a6a7a8")
V2_NONCE = bytes(range(16))
V2 = {
    "phone_pub": "040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed"
                 "194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794",
    "pc_pub": "04d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf3"
              "50185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c91285",
    "z": "ccfc261f58193c98ca4ad4a53bbac6f0ee29bc4d48438090446908622ca79af6",
    "k": "78fb82829c51a3cc9762af1ca02bd7749f797d182d18971b695bb78c28ab7a24",
    "kid": "10253095",
    "code": 260329,
    "commit": "d06ad9ddcb46f53c44d669f7d08fd932",
    # seq 0x12345678, cross, LX -32768, LY 32767, RX 12345, RY -9876,
    # LT 255, RT 128, pad connected, Xbox layout, session 7
    "input": "d5027856341200100080ff7f39306cd9ff8001020700000010253095bee0eb8534c2d722",
    # seq 0x12345678, 1000 received, pad live
    "ack": "d60278563412e80300000100099521f0c16e1df7",
    "resp": "d802a1a2a3a4a5a6a7a804d65a93977caa3d1b081852ff57a79e465f1660577304ba"
            "ead505dd3a48589cf350185e895372df6221ea3a137557e473fddb6755f05bd507c3"
            "c533fce9c9128501f1980601122fd826",
    "req_commit": "d7020102030405060708040217e617f0b6443928278f96999e69a23a4f2c152b"
                  "df6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc75859"
                  "9652f2897c65306e579407506978656c2038000000000000000000000000000000"
                  "0000000000000000000000d06ad9ddcb46f53c44d669f7d08fd932000000",
    "req_reveal": "d7020102030405060708040217e617f0b6443928278f96999e69a23a4f2c152b"
                  "df6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc75859"
                  "9652f2897c65306e579407506978656c2038000000000000000000000000000000"
                  "0000000000000000000001000102030405060708090a0b0c0d0e0f000000",
}


def test_golden() -> None:
    check("v1 input packet is 20 bytes", d.PACKET.size == 20, str(d.PACKET.size))
    check("v2 input packet is 36 bytes", d.PACKET_V2.size == 36, str(d.PACKET_V2.size))
    check("unauthenticated ack is 12 bytes", d.ACK.size == 12, str(d.ACK.size))
    check("authenticated ack is 20 bytes", d.ACK_V2.size == 20, str(d.ACK_V2.size))
    check("beacon is 16 bytes", d.BEACON_WITH_ID.size == 16, str(d.BEACON_WITH_ID.size))
    check("PAIR_REQ is 128 bytes, PAIR_RESP 84",
          p.PAIR_REQ.size == 128 and p.PAIR_RESP_SIZE == 84)
    for fields, hexed in GOLDEN_PACKETS:
        raw = d.PACKET.pack(*fields)
        check(f"v1 packet (browser client) packs to {hexed}", raw.hex() == hexed, raw.hex())
    for fields, hexed in GOLDEN_ACKS:
        raw = d.ACK.pack(*fields)
        check(f"unauthenticated ack packs to {hexed}", raw.hex() == hexed, raw.hex())
    check("ack flag bits", (d.ACK_PAD_LIVE, d.ACK_VERSION_MISMATCH, d.ACK_NOT_PAIRED)
          == (0x01, 0x02, 0x04))
    beacon = d.BEACON_WITH_ID.pack(d.BEACON_MAGIC, 1, d.DEFAULT_INPUT_PORT, 0, V2_PC_ID)
    check("beacon golden", beacon.hex() == "44534c4b01a5b300a1a2a3a4a5a6a7a8", beacon.hex())
    check("beacon's first 8 bytes are what 1.1 apps read",
          beacon[:8].hex() == "44534c4b01a5b300")


def test_crypto_vectors() -> None:
    phone = p.private_key_from_scalar(V2_PHONE_SCALAR)
    pc = p.private_key_from_scalar(V2_PC_SCALAR)
    phone_pub, pc_pub = p.public_bytes(phone), p.public_bytes(pc)
    check("phone public key", phone_pub.hex() == V2["phone_pub"], phone_pub.hex())
    check("PC public key", pc_pub.hex() == V2["pc_pub"], pc_pub.hex())
    z = p.shared_secret(phone, pc_pub)
    check("Z", z.hex() == V2["z"], z.hex())
    check("ECDH agrees both ways", p.shared_secret(pc, phone_pub) == z)
    k, kid, code = p.derive(z, phone_pub, pc_pub, V2_NONCE)
    check("K", k.hex() == V2["k"], k.hex())
    check("KID", kid.hex() == V2["kid"], kid.hex())
    check("confirmation code", code == V2["code"], str(code))
    check("code shown as two groups", p.format_code(code) == "260 329"
          and p.format_code(42) == "000 042")
    check("commitment", p.commitment(V2_NONCE).hex() == V2["commit"])

    ph = FakePhone(name="Pixel 8", phone_id=V2_PHONE_ID, private=phone, nonce=V2_NONCE)
    check("PAIR_REQ commit bytes", ph.pair_request(p.PHASE_COMMIT).hex() == V2["req_commit"])
    check("PAIR_REQ reveal bytes", ph.pair_request(p.PHASE_REVEAL).hex() == V2["req_reveal"])
    ph.key, ph.kid = k, kid
    raw = ph.packet(seq=0x12345678, buttons=0x1000, lx=-32768, ly=32767, rx=12345,
                    ry=-9876, lt=255, rt=128, flags=1, layout=2, session=7)
    check("v2 input packet and MAC", raw.hex() == V2["input"], raw.hex())
    head = d.ACK.pack(d.ACK_MAGIC, 2, 0x12345678, 1000, d.ACK_PAD_LIVE, 0)
    check("v2 ack and MAC", (head + p.mac(k, head)).hex() == V2["ack"])
    resp = p.PAIR_RESP_HEAD.pack(p.PAIR_RESP_MAGIC, 2, V2_PC_ID, pc_pub, p.STATE_ACCEPTED)
    check("PAIR_RESP state 1 and MAC", (resp + p.mac(k, resp)).hex() == V2["resp"])

    # What the receiver emits for that packet, byte for byte.
    r, pad, sock, _, _ = fresh(phones=0)
    r.pairing.store._phones[V2_PHONE_ID] = p.PairedPhone(V2_PHONE_ID, "Pixel 8", k, kid, "", 6)
    r.packets = 999
    r.handle(bytes.fromhex(V2["input"]), PHONE)
    check("receiver accepts the golden packet", pad.report.wButtons == 0x1000
          and pad.report.sThumbRY == -9876)
    check("receiver's ack is the golden ack",
          sock.sent and sock.sent[0][0].hex() == V2["ack"],
          sock.sent[0][0].hex() if sock.sent else "none")

    bad = [
        ("wrong length", bytes(64)),
        ("compressed point", b"\x02" + bytes.fromhex(V2["pc_pub"])[1:33] + bytes(32)),
        ("point off the curve", bytes.fromhex(V2["pc_pub"])[:-1] + b"\x00"),
        ("all zero", b"\x04" + bytes(64)),
    ]
    for label, raw_key in bad:
        try:
            p.load_public(raw_key)
            ok = False
        except ValueError:
            ok = True
        check(f"public key refused: {label}", ok)
    check("device name cleaned of controls and bidi overrides",
          p.clean_name("Pix‮el\x00 8\n".encode()) == "Pixel 8"
          and p.clean_name(b"\xff\xfe") != "" and p.clean_name(b"") == "Unnamed phone")


# --- the basics, now authenticated -------------------------------------------

def test_basics() -> None:
    r, pad, sock, _, (ph,) = fresh()
    addr = PHONE

    r.handle(ph.packet(1, buttons=0x1000, lx=-32768, ly=32767, lt=255), addr)
    check("full-scale values reach the report",
          pad.report.wButtons == 0x1000 and pad.report.sThumbLX == -32768
          and pad.report.sThumbLY == 32767 and pad.report.bLeftTrigger == 255)
    check("packet counted", r.packets == 1)

    before = r.packets
    r.handle(ph.packet(2)[:35], addr)
    check("short packet ignored", r.packets == before)
    r.handle(ph.packet(2) + b"\x00", addr)
    check("long packet ignored", r.packets == before)
    raw = bytearray(ph.packet(2))
    raw[0] = 0x00
    r.handle(bytes(raw), addr)
    check("bad magic ignored", r.packets == before)
    r.handle(b"", addr)
    r.handle(b"\xd5", addr)
    check("empty and 1-byte datagrams ignored", r.packets == before)

    r.handle(ph.packet(5), addr)
    r.handle(ph.packet(3), addr)
    check("stale seq dropped", r.dropped == 1 and r.last_seq == 5)
    r.handle(ph.packet(6), addr)
    check("newer seq accepted", r.last_seq == 6)

    r._seq[ph.id] = (ph.session, 0xFFFFFFFE)
    r.handle(ph.packet(1), addr)
    check("u32 seq wraparound accepted", r.last_seq == 1)

    r.handle(ph.packet(2, buttons=0xF0F0, lx=20000, flags=0), addr)
    check("disconnected pad resets the report",
          pad.report.wButtons == 0 and pad.report.sThumbLX == 0)

    sock.sent.clear()
    r._last_ack_at.clear()
    r.handle(ph.packet(3, buttons=0x2000), addr)
    check("ack sent to the client", len(sock.sent) == 1)
    if sock.sent:
        data, to = sock.sent[0]
        check("ack is 20 bytes and authenticated", len(data) == 20
              and ph.read_ack(data) is not None and ph.read_ack(data)[3])
        magic, ver, ack_seq, received, flags, _ = d.ACK.unpack(data[:12])
        check("ack is well formed",
              magic == d.ACK_MAGIC and ver == 2 and flags & 1 == 1)
        check("ack echoes the sequence", ack_seq == 3, str(ack_seq))
        check("ack counts accepted packets", received == r.packets, f"{received}")
        check("ack goes back to the sender", to == addr)
        forged = bytearray(data)
        forged[10] ^= 0x01
        check("a flipped ack bit fails the phone's MAC check", ph.read_ack(bytes(forged)) is None)

    sock.sent.clear()
    r.handle(ph.packet(4), addr)
    check("acks are rate limited", len(sock.sent) == 0)

    r.handle(ph.packet(5, buttons=0x2000), addr)
    check("linked while packets flow", r.linked)
    check("watchdog is 1.5 s", d.WATCHDOG_TIMEOUT == 1.5)
    r.last_packet_at = time.monotonic() - (d.WATCHDOG_TIMEOUT - 0.2)
    r.tick_watchdog()
    check("watchdog waits out its full timeout", r.linked)
    r.last_packet_at = time.monotonic() - (d.WATCHDOG_TIMEOUT + 0.1)
    r.tick_watchdog()
    check("watchdog unlinks and releases",
          not r.linked and pad.report.wButtons == 0 and r.last_seq is None
          and r.peer is None and r.peer_id is None)
    r.handle(ph.packet(4, buttons=0x1000), addr)
    check("after the watchdog, the same session's old seq is still refused",
          pad.report.wButtons == 0 and not r.linked)
    r.handle(ph.packet(6, buttons=0x1000), addr)
    check("and a newer one resumes the link", pad.report.wButtons == 0x1000 and r.linked)

    check("button decode", d.describe_buttons(0x1000 | 0x0100) == "L1+cross")
    check("empty button decode", d.describe_buttons(0) == "-")


# --- authentication and replay -------------------------------------------------

def test_authentication() -> None:
    r, pad, sock, log, (ph,) = fresh()

    stranger = FakePhone(name="Stranger")
    stranger.key = os.urandom(32)
    stranger.kid = p.key_id(stranger.key)
    stranger.start_session()
    r.handle(stranger.packet(1, buttons=0x1000), PHONE)
    acks = acks_to(sock, PHONE, stranger)
    check("unknown KID is not applied", pad.applies == 0 and not r.linked)
    check("unknown KID gets a 12-byte not-paired ack",
          len(acks) == 1 and not acks[0][3] and acks[0][2] == d.ACK_NOT_PAIRED
          and acks[0][0] == 1, str(acks))
    check("the not-paired ack is version 2", sock.sent[-1][0][1] == 2)
    for i in range(20):
        r.handle(stranger.packet(i + 2), PHONE)
    check("not-paired acks are rate limited", len(acks_to(sock, PHONE, stranger)) == 1)
    check("a new source port is answered on its own",
          (r.handle(stranger.packet(40), PHONE_RESTARTED) or True)
          and len(acks_to(sock, PHONE_RESTARTED, stranger)) == 1)

    sock.sent.clear()
    forged = ph.packet(1, buttons=0x1000, key=os.urandom(32))
    r.handle(forged, PHONE)
    check("bad MAC with a known KID is dropped", pad.applies == 0 and not r.linked)
    check("bad MAC gets no ack at all", not sock.sent)
    good = bytearray(ph.packet(2, buttons=0x1000))
    good[8] ^= 0x40        # flip a bit in LX after signing
    r.handle(bytes(good), PHONE)
    check("tampered payload fails the MAC", pad.applies == 0 and not sock.sent)
    for _ in range(30):
        r.handle(forged, PHONE)
    check("MAC failures logged at most once per interval",
          sum("fail authentication" in m for m in log) == 1, str(log))
    check("MAC failures counted", r.unauthenticated >= 32, str(r.unauthenticated))

    r.handle(ph.packet(3, buttons=0x2000), PHONE)
    check("the real phone is unaffected", pad.report.wButtons == 0x2000)

    # Replay of an older session: record session 1, move to session 2.
    recorded = [ph.packet(10 + i, buttons=0x4000) for i in range(3)]
    for raw in recorded:
        r.handle(raw, PHONE)
    ph.start_session()
    r.handle(ph.packet(20, buttons=0x8000), PHONE)
    check("new session accepted", pad.report.wButtons == 0x8000
          and r.pairing.store.get(ph.id).highest_session == 2)
    dropped = r.dropped
    for raw in recorded:
        r.handle(raw, PHONE)
    check("replayed packets of an old session are dropped",
          pad.report.wButtons == 0x8000 and r.dropped == dropped + 3)

    # A new session resets seq: the phone's counter need not be higher.
    ph.start_session()
    r.handle(ph.packet(5, buttons=0x0100), PHONE)
    check("new session with a lower seq is accepted and resets seq",
          pad.report.wButtons == 0x0100 and r._seq[ph.id] == (3, 5), str(r._seq[ph.id]))
    r.handle(ph.packet(4, buttons=0x0200), PHONE)
    check("within it, seq must still move forward", pad.report.wButtons == 0x0100)

    # v1 has no way in any more.
    sock.sent.clear()
    v1 = d.PACKET.pack(d.MAGIC, 1, 77, 0x1000, 0, 0, 0, 0, 0, 0, 1, 0)
    r.handle(v1, OTHER)
    acks = acks_to(sock, OTHER, ph)
    check("v1 packet is not applied", pad.report.wButtons == 0x0100)
    check("v1 packet gets a 12-byte bit1 ack, version 2",
          len(acks) == 1 and not acks[0][3] and acks[0][2] == d.ACK_VERSION_MISMATCH
          and acks[0][0] == 77 and sock.sent[-1][0][1] == 2, str(acks))
    for i in range(20):
        r.handle(d.PACKET.pack(d.MAGIC, 1, i, 0x1000, 0, 0, 0, 0, 0, 0, 1, 0), OTHER)
    check("mismatch replies are rate limited", len(acks_to(sock, OTHER, ph)) == 1)
    check("mismatch logged once", sum("protocol v1" in m for m in log) == 1)
    r.handle(b"\xd5\x01\x00", OTHER)
    check("tiny mismatched datagram gets no (amplified) reply",
          len(acks_to(sock, OTHER, ph)) == 1)
    r.handle(v1, ("8.8.8.8", 1))
    check("public sender gets no mismatch reply", not acks_to(sock, ("8.8.8.8", 1), ph))
    r.handle(ph.packet(6, version=3), ("192.168.1.77", 1))
    check("a future version is told too", len(acks_to(sock, ("192.168.1.77", 1), ph)) == 1)

    # No pairing manager at all: everything is "not paired".
    r2 = d.Receiver(_Pad(), _Sock(), verbose=False, on_status=lambda m: None)
    r2.handle(ph.packet(99, buttons=0x1000), PHONE)
    check("a receiver without pairing applies nothing",
          r2.gamepad.applies == 0 and r2.sock.sent
          and r2.sock.sent[0][0][10] == d.ACK_NOT_PAIRED)


def test_restart_and_persistence() -> None:
    directory = tmpdir()
    store = p.PairingStore(directory)
    ph = FakePhone(name="Pixel 8")
    ph.adopt(store)
    pc_id = store.pc_id
    r = d.Receiver(_Pad(), _Sock(), verbose=False, on_status=lambda m: None,
                   pairing=p.PairingManager(store, auto_allow=False))
    ph.start_session()
    ph.start_session()
    ph.start_session()          # session 3
    recorded = [ph.packet(i, buttons=0x1000) for i in range(1, 4)]
    r.handle(recorded[0], PHONE)
    check("session 3 accepted", r.gamepad.report.wButtons == 0x1000)
    store.close()               # what stopping the service does
    saved = json.loads((store.path).read_text(encoding="utf-8"))
    check("highest_session persisted", saved["phones"][0]["highest_session"] == 3,
          str(saved["phones"][0]))
    check("pc_id and key stored as base64",
          base64.b64decode(saved["pc_id"]) == pc_id
          and base64.b64decode(saved["phones"][0]["key"]) == ph.key)

    # A restart: new store object from the same file, new receiver.
    store2 = p.PairingStore(directory)
    check("pc_id survives a restart", store2.pc_id == pc_id)
    got = store2.get(ph.id)
    check("storage round trip", got is not None and got.key == ph.key and got.kid == ph.kid
          and got.name == "Pixel 8" and got.highest_session == 3 and got.paired_at)
    pad = _Pad()
    r2 = d.Receiver(pad, _Sock(), verbose=False, on_status=lambda m: None,
                    pairing=p.PairingManager(store2, auto_allow=False))
    for raw in recorded[1:]:
        r2.handle(raw, PHONE)
    check("after a restart, the current session cannot be replayed", pad.applies == 0)
    ph.start_session()
    r2.handle(ph.packet(1, buttons=0x2000), PHONE)
    check("the phone's next session is accepted", pad.report.wButtons == 0x2000)
    for raw in recorded:
        r2.handle(raw, PHONE)
    check("and the old one still is not", pad.report.wButtons == 0x2000)
    store2.close()

    # A damaged file is set aside, not trusted and not silently overwritten.
    bad_dir = tmpdir()
    with open(os.path.join(bad_dir, "pairing.json"), "w", encoding="utf-8") as fh:
        fh.write("{not json")
    msgs = []
    store3 = p.PairingStore(bad_dir, on_status=msgs.append)
    kept = [f for f in os.listdir(bad_dir) if f.startswith("pairing.corrupt-")]
    check("corrupt pairing.json is moved aside", kept and not store3.phones()
          and len(store3.pc_id) == 8 and any("unreadable" in m for m in msgs), str(msgs))

    # Removal is written at once.
    store4 = p.PairingStore(directory)
    store4.remove(ph.id)
    check("remove is persisted", not p.PairingStore(directory).phones())
    check("no temp file is left behind",
          not [f for f in os.listdir(directory) if f.endswith(".tmp")])


# --- H1: source filter --------------------------------------------------------

def test_source_filter() -> None:
    allowed = ["127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.254",
               "192.168.43.1", "169.254.10.20", "::1", "fe80::1", "fe80::1%3",
               "fd12:3456::1", "::ffff:192.168.1.5"]
    refused = ["8.8.8.8", "100.64.0.1", "100.127.255.254", "172.32.0.1",
               "172.15.255.255", "192.169.0.1", "1.1.1.1", "2001:4860::8888",
               "::ffff:8.8.8.8", "255.255.255.255", "0.0.0.0", "not-an-ip", ""]
    bad_allow = [a for a in allowed if not d.allowed_source(a)]
    bad_refuse = [a for a in refused if d.allowed_source(a)]
    check("private, link-local and loopback sources accepted", not bad_allow, str(bad_allow))
    check("public and CGNAT sources refused", not bad_refuse, str(bad_refuse))

    r, pad, sock, log, (ph,) = fresh()
    for i in range(50):
        r.handle(ph.packet(i + 1, buttons=0x1000), ("8.8.8.8", 4000 + i))
    check("public sender cannot drive the pad, even with a valid packet",
          pad.applies == 0 and not r.linked and r.packets == 0)
    check("public sender gets no ack", not sock.sent)
    check("public sender counted as rejected", r.rejected == 50, str(r.rejected))
    check("refused sources logged at most once per interval",
          sum("not a local network" in m for m in log) == 1, str(log))
    r.handle(FakePhone().pair_request(), ("8.8.8.8", 1))
    check("public sender cannot open a pairing prompt",
          r.pairing.prompt is None and r.pairing.requests == 0 and not sock.sent)


# --- the single-peer lock, between paired phones ------------------------------

def test_peer_lock() -> None:
    r, pad, sock, log, (a, b) = fresh(phones=2)

    r.handle(a.packet(1000, buttons=0x1000), PHONE)
    check("first phone links", r.linked and r.peer == PHONE and r.peer_id == a.id)

    r.handle(b.packet(1, buttons=0x2000), OTHER)
    check("a second phone's new session takes over at once",
          r.peer_id == b.id and pad.report.wButtons == 0x2000)

    sock.sent.clear()
    r._last_ack_at.clear()
    r.handle(a.packet(1001, buttons=0x1000), PHONE)
    check("the first phone carrying on its old link is refused",
          r.peer_id == b.id and pad.report.wButtons == 0x2000 and r.rejected == 1)
    acks = acks_to(sock, PHONE, a)
    check("and told so with an authenticated pad-live-0 ack",
          len(acks) == 1 and acks[0][3] and acks[0][2] == 0, str(acks))

    r.last_packet_at = time.monotonic() - (d.PEER_SWITCH_SILENCE - 0.1)
    r.handle(a.packet(1002, buttons=0x1000), PHONE)
    check("still refused before the silence window", r.peer_id == b.id)
    r.last_packet_at = time.monotonic() - (d.PEER_SWITCH_SILENCE + 0.01)
    r.handle(a.packet(1003, buttons=0x4000), PHONE)
    check("the first phone gets the pad back after 300 ms of silence",
          r.peer_id == a.id and pad.report.wButtons == 0x4000)

    # The same phone from a new source port (restarted socket), same session.
    r.handle(a.packet(1004, buttons=0x8000), PHONE_RESTARTED)
    check("same phone, new port, same link: followed",
          r.peer == PHONE_RESTARTED and pad.report.wButtons == 0x8000)
    r._last_ack_at.clear()
    r.handle(a.packet(1005), PHONE_RESTARTED)
    check("its acks now go to the new port", acks_to(sock, PHONE_RESTARTED, a))

    # A flood of forged packets must not starve the phone of acks or fill
    # the log.
    r, pad, sock, log, (a,) = fresh()
    r.handle(a.packet(1), PHONE)
    sock.sent.clear()
    log.clear()
    forger = FakePhone()
    forger.key, forger.kid = os.urandom(32), a.kid    # right KID, wrong key
    forger.start_session()
    for i in range(500):
        r.last_packet_at = time.monotonic()  # the phone is still streaming
        r.handle(forger.packet(i + 2, buttons=0x1000, session=99),
                 (OTHER[0], OTHER[1] + (i % 3)))
    check("forged flood gets no acks", not [s for s in sock.sent if s[1][0] == OTHER[0]])
    check("forged flood cannot drive the pad", pad.report.wButtons == 0)
    check("forged flood logged once per interval",
          sum("authentication" in m for m in log) == 1, f"{len(log)} lines")
    r._last_ack_at.clear()
    r.handle(a.packet(2), PHONE)
    check("phone still gets its ack during a flood", len(acks_to(sock, PHONE, a)) == 1)
    check("a forged session number does not move highest_session",
          r.pairing.store.get(a.id).highest_session == 1)


# --- ack flags -----------------------------------------------------------------

def test_ack_flags() -> None:
    r, pad, sock, log, (ph,) = fresh()
    r.handle(ph.packet(1), PHONE)
    check("pad-live bit set when the pad works", acks_to(sock, PHONE, ph)[-1][2] == 1)
    pad.fail_apply = 1
    r._last_ack_at.clear()
    r.handle(ph.packet(2, buttons=0x1000), PHONE)
    check("pad-live bit clear when the driver refuses a write",
          acks_to(sock, PHONE, ph)[-1][2] == 0)
    r._last_ack_at.clear()
    r.handle(ph.packet(3, buttons=0x1000), PHONE)
    check("pad-live bit returns when writes succeed again",
          acks_to(sock, PHONE, ph)[-1][2] == 1 and pad.report.wButtons == 0x1000)

    r.gamepad = None
    r._last_ack_at.clear()
    r.handle(ph.packet(4), PHONE)
    check("pad-live bit clear with no pad at all", acks_to(sock, PHONE, ph)[-1][2] == 0)


# --- contract 3: arbitration hook ---------------------------------------------

def test_blocked_by() -> None:
    check("Receiver has a blocked_by hook defaulting to None",
          d.Receiver.blocked_by is None and fresh()[0].blocked_by is None)

    blocked = [False]
    r, pad, sock, log, (ph,) = fresh()
    states = []
    r.on_state = states.append
    r.blocked_by = lambda: blocked[0]

    r.handle(ph.packet(1, buttons=0x1000), PHONE)
    check("unblocked receiver drives the pad", pad.report.wButtons == 0x1000 and r.driving)

    blocked[0] = True
    releases = pad.releases
    n_states = len(states)
    r._last_ack_at.clear()
    r.handle(ph.packet(2, buttons=0x2000), PHONE)
    check("blocked input is not applied", pad.report.wButtons == 0 and pad.applies == 1)
    check("pad released once when blocking takes it from us",
          pad.releases == releases + 1 and not r.driving)
    check("blocked receiver still acks, with pad-live 0",
          acks_to(sock, PHONE, ph)[-1][2] == 0)
    check("blocked receiver stays linked", r.linked and r.peer == PHONE)
    check("blocked input is not shown", len(states) == n_states)

    # The browser now owns the pad; nothing we do may touch it.
    pad.apply(0x0001, 0, 0, 0, 0, 0, 0)
    r.handle(ph.packet(3, buttons=0x2000), PHONE)
    check("while blocked the pad is left alone",
          pad.report.wButtons == 0x0001 and pad.releases == releases + 1)
    r.last_packet_at = time.monotonic() - (d.WATCHDOG_TIMEOUT + 0.1)
    r.tick_watchdog()
    check("watchdog does not release a pad someone else is driving",
          pad.report.wButtons == 0x0001 and not r.linked)

    blocked[0] = False
    r.handle(ph.packet(4, buttons=0x4000), PHONE)
    check("unblocking hands the pad back", pad.report.wButtons == 0x4000 and r.driving)

    r2, pad2, _, log2, (ph2,) = fresh(blocked_by=lambda: 1 / 0)
    r2.handle(ph2.packet(1, buttons=0x1000), PHONE)
    check("a broken arbiter fails towards the phone",
          pad2.report.wButtons == 0x1000 and any("arbitration" in m for m in log2))


# --- C1: nothing a packet does can kill the loop ------------------------------

def test_faults() -> None:
    r, pad, sock, log, (ph,) = fresh()
    r.handle(ph.packet(1, buttons=0x1000), PHONE)

    def boom(_state):
        raise RuntimeError("observer bug")
    r.on_state = boom
    try:
        r.process(ph.packet(2, buttons=0x2000), PHONE)
        ok = True
    except Exception:
        ok = False
    check("process() contains an exception from handle()", ok)
    check("a handling error releases the pad", pad.report.wButtons == 0)
    check("a handling error is logged", any("observer bug" in m for m in log), str(log))
    r.on_state = None
    r.process(ph.packet(3, buttons=0x4000), PHONE)
    check("the next packet applies normally", pad.report.wButtons == 0x4000)

    pad.fail_apply = 1
    pad.fail_release = 1
    r.process(ph.packet(4, buttons=0x8000), PHONE)
    check("apply and release both failing still does not raise", True)
    r.process(ph.packet(5, buttons=0x1000), PHONE)
    check("pad recovers after a driver hiccup", pad.report.wButtons == 0x1000 and r.pad_ok)

    pad.fail_release = 1
    r.last_packet_at = time.monotonic() - (d.WATCHDOG_TIMEOUT + 0.1)
    try:
        r.tick()
        ok = True
    except Exception:
        ok = False
    check("tick() contains a release failure", ok and not r.linked)

    def bad_pairing_request(*_a, **_k):
        raise RuntimeError("pairing bug")
    r.pairing.handle_request = bad_pairing_request
    r.process(FakePhone().pair_request(), PHONE)
    r.process(ph.packet(6, buttons=0x2000), PHONE)
    check("an error while pairing does not stop input", pad.report.wButtons == 0x2000)


# --- the pairing exchange --------------------------------------------------------

def _exchange(m: p.PairingManager, phone: FakePhone, addr, clock: _Clock):
    """Commit, then reveal, a second apart. Returns the two states."""
    s1 = phone.on_response(m.handle_request(phone.pair_request(), addr) or b"")
    clock.t += 1.0
    s2 = phone.on_response(m.handle_request(phone.pair_request(), addr) or b"")
    return s1, s2


def test_pairing() -> None:
    clock = _Clock()
    events = []
    store = p.PairingStore(tmpdir())
    m = p.PairingManager(store, on_change=lambda k, pr: events.append((k, pr)),
                         auto_allow=False, clock=clock)
    phone = FakePhone(name="Pixel 8")

    s1, s2 = _exchange(m, phone, PHONE, clock)
    check("commit is answered with state 0 and the PC's key",
          s1 == p.STATE_WAITING and phone.pc_pub is not None)
    check("the prompt opens only once the nonce is revealed",
          s2 == p.STATE_WAITING and m.prompt is not None and events[-1][0] == "open")
    prompt = m.prompt
    check("both sides show the same code", prompt.code == phone.code,
          f"PC {prompt.code} phone {phone.code}")
    check("the prompt carries the device name", prompt.name == "Pixel 8")
    check("the prompt lasts 60 s",
          prompt.public(clock.t)["seconds"] == 60 and prompt.public(clock.t)["code"]
          == p.format_code(phone.code))
    check("nothing is stored before Allow", store.get(phone.id) is None)

    # Rate limit: a second request from the same address within a second.
    check("a second request within 1 s is ignored",
          m.handle_request(phone.pair_request(), PHONE, now=clock.t + 0.5) is None
          and m.rate_limited == 1)
    check("from a new port too",
          m.handle_request(phone.pair_request(), PHONE_RESTARTED, now=clock.t + 0.6) is None)

    # Busy: another phone while the prompt is open.
    other = FakePhone(name="Other")
    clock.t += 1.0
    reply = m.handle_request(other.pair_request(), OTHER)
    check("a second phone gets state 3 with no key",
          reply is not None and reply[75] == p.STATE_BUSY
          and reply[10:75] == p.ZERO_PUBLIC and reply[76:] == p.ZERO_MAC)
    check("one prompt at a time", m.prompt is prompt)
    # The same phone with a fresh key (Stop then Start) is another attempt.
    again = FakePhone(name="Pixel 8", phone_id=phone.id)
    reply = m.handle_request(again.pair_request(), ("192.168.1.6", 1))
    check("a new attempt from the same phone is busy too; the prompt never changes code",
          reply is not None and reply[75] == p.STATE_BUSY and m.prompt is prompt)

    check("a stale prompt id approves nothing", not m.answer("not-the-id", True)
          and store.get(phone.id) is None)
    check("Allow", m.answer(prompt.id, True) and events[-1][0] == "allowed")
    stored = store.get(phone.id)
    check("Allow stores the phone with the same key",
          stored is not None and stored.key == phone.key and stored.name == "Pixel 8"
          and stored.highest_session == 0)
    check("the prompt is gone", m.prompt is None)
    check("answering twice does nothing", not m.answer(prompt.id, False))
    clock.t += 1.0
    reply = m.handle_request(phone.pair_request(), PHONE)
    check("the phone's next resend gets state 1 with a valid MAC",
          phone.on_response(reply) == p.STATE_ACCEPTED and phone.pc_id == store.pc_id)
    bad = bytearray(reply)
    bad[-1] ^= 1
    twin = FakePhone(phone_id=phone.id, private=phone.private, nonce=phone.nonce)
    twin.on_response(m.handle_request(twin.pair_request(), ("192.168.1.99", 1)))
    check("a state 1 with a bad MAC is refused by the phone",
          twin.key == phone.key and twin.on_response(bytes(bad)) is None
          and twin.on_response(reply) == p.STATE_ACCEPTED)
    fresh_phone = FakePhone()
    fresh_phone.pc_pub = reply[10:75]
    fresh_phone.key = os.urandom(32)
    check("a phone with another key rejects that MAC",
          fresh_phone.on_response(reply) is None)

    # Deny.
    clock.t += 5
    denied = FakePhone(name="Nope")
    _exchange(m, denied, OTHER, clock)
    check("a new prompt opens once the slot is free", m.prompt is not None
          and m.prompt.name == "Nope")
    check("Deny", m.answer(m.prompt.id, False) and events[-1][0] == "denied")
    clock.t += 1.0
    check("the phone hears state 2",
          denied.on_response(m.handle_request(denied.pair_request(), OTHER))
          == p.STATE_DENIED)
    check("nothing stored on Deny", store.get(denied.id) is None)

    # Timeout.
    clock.t += 5
    slow = FakePhone(name="Slow")
    _exchange(m, slow, ("192.168.1.30", 1), clock)
    check("prompt open", m.prompt is not None and m.prompt.name == "Slow")
    pid = m.prompt.id
    clock.t += 59.0
    m.tick()
    check("still open at 59 s", m.prompt is not None)
    clock.t += 1.5
    m.tick()
    check("closed after 60 s", m.prompt is None and events[-1][0] == "timeout")
    check("a late Allow does nothing", not m.answer(pid, True) and store.get(slow.id) is None)
    clock.t += 1.0
    check("the phone hears state 2 after the timeout",
          slow.on_response(m.handle_request(slow.pair_request(), ("192.168.1.30", 1)))
          == p.STATE_DENIED)

    # A request that never reveals frees the slot on its own.
    clock.t += 5
    ghost = FakePhone(name="Ghost")
    m.handle_request(ghost.pair_request(), ("192.168.1.40", 1))
    clock.t += 1.0
    blocked = m.handle_request(FakePhone().pair_request(), ("192.168.1.41", 1))
    check("an unrevealed request holds the slot", blocked[75] == p.STATE_BUSY)
    clock.t += m.REVEAL_TIMEOUT + 0.5
    m.tick()
    late = FakePhone(name="Late")
    reply = m.handle_request(late.pair_request(), ("192.168.1.42", 1))
    check("and gives it up after the reveal timeout",
          reply is not None and reply[75] == p.STATE_WAITING)
    check("no prompt was ever shown for it",
          not any(pr is not None and pr.name == "Ghost" for _, pr in events))
    clock.t += 20
    m.tick()

    # A wrong reveal is ignored, not fatal.
    clock.t += 5
    victim = FakePhone(name="Victim")
    victim.on_response(m.handle_request(victim.pair_request(), ("192.168.1.50", 1)))
    liar = FakePhone(name="Victim", phone_id=victim.id, private=victim.private,
                     nonce=os.urandom(16))
    liar.pc_pub = victim.pc_pub
    clock.t += 1.0
    m.handle_request(liar.pair_request(p.PHASE_REVEAL), ("192.168.1.51", 1))
    check("a reveal that does not match the commitment opens nothing", m.prompt is None)
    clock.t += 1.0
    victim.on_response(m.handle_request(victim.pair_request(), ("192.168.1.50", 1)))
    check("the real phone's reveal still does", m.prompt is not None
          and m.prompt.code == victim.code)
    m.answer(m.prompt.id, False)

    # Replacing a pairing only happens on a new Allow.
    clock.t += 5
    repair = FakePhone(name="Pixel 8 again", phone_id=phone.id)
    _exchange(m, repair, PHONE, clock)
    check("an already paired phone keeps its key while asking again",
          store.get(phone.id).key == phone.key)
    m.answer(m.prompt.id, False)
    check("Deny leaves the old pairing intact", store.get(phone.id).key == phone.key)
    clock.t += 5
    repair = FakePhone(name="Pixel 8 again", phone_id=phone.id)
    _exchange(m, repair, PHONE, clock)
    m.answer(m.prompt.id, True)
    check("Allow replaces it", store.get(phone.id).key == repair.key
          and store.get(phone.id).name == "Pixel 8 again" and len(store.phones()) == 1)

    # Malformed requests.
    clock.t += 5
    req = bytearray(FakePhone().pair_request())
    for label, mutate in (("wrong version", lambda b: b.__setitem__(1, 1)),
                          ("name too long", lambda b: b.__setitem__(75, 33)),
                          ("bad phase", lambda b: b.__setitem__(108, 7)),
                          ("key not on the curve", lambda b: b.__setitem__(74, b[74] ^ 1))):
        b = bytearray(req)
        mutate(b)
        clock.t += 1.1
        check(f"malformed PAIR_REQ ignored: {label}",
              m.handle_request(bytes(b), ("192.168.1.60", 1)) is None and m.prompt is None)
    clock.t += 1.1
    check("a short PAIR_REQ is ignored",
          m.handle_request(bytes(req[:127]), ("192.168.1.61", 1)) is None)

    check("remove", m.remove(phone.id) and store.get(phone.id) is None
          and events[-1][0] == "removed")

    # The test hook cannot be switched on in a packaged build.
    os.environ[p.TEST_AUTO_ALLOW_ENV] = "1"
    try:
        check("auto-allow on from source with the env var", p.test_auto_allow_enabled())
        sys.frozen = True
        check("auto-allow refused when frozen", not p.test_auto_allow_enabled()
              and not p.PairingManager(store).auto_allow
              and not p.PairingManager(store, auto_allow=True).auto_allow)
    finally:
        del sys.frozen
        del os.environ[p.TEST_AUTO_ALLOW_ENV]
    check("auto-allow off by default", not p.PairingManager(store).auto_allow)

    auto = p.PairingManager(p.PairingStore(tmpdir()), auto_allow=True, clock=clock)
    fast = FakePhone(name="Auto")
    clock.t += 5
    s1, s2 = _exchange(auto, fast, PHONE, clock)
    check("auto-allow answers the reveal with state 1", (s1, s2) == (0, 1)
          and auto.store.get(fast.id) is not None)


def test_pairing_over_receiver() -> None:
    """PAIR_REQ through Receiver.handle, then input with the new key."""
    r, pad, sock, log, _ = fresh(phones=0)
    phone = FakePhone(name="Pixel 8")
    r.handle(phone.pair_request(), PHONE)
    reply = sock.sent[-1][0] if sock.sent else b""
    check("the receiver answers PAIR_REQ with PAIR_RESP",
          len(reply) == 84 and phone.on_response(reply) == p.STATE_WAITING)
    r.pairing._last_by_source.clear()
    r.handle(phone.pair_request(), PHONE)
    check("the reveal opens a prompt", r.pairing.prompt is not None
          and r.pairing.prompt.code == phone.code)
    r.pairing.answer(r.pairing.prompt.id, True)
    r.pairing._last_by_source.clear()
    r.handle(phone.pair_request(), PHONE)
    check("the phone learns it is paired", phone.on_response(sock.sent[-1][0]) == 1)
    phone.start_session()
    r.handle(phone.packet(1, buttons=0x1000), PHONE)
    check("and its input drives the pad", pad.report.wButtons == 0x1000)
    r.tick()   # the prompt timeout runs from the receive loop's tick


# --- L7 / contract 4: the pad wrappers ----------------------------------------

class _LockedReport:
    """A report that complains if touched without the pad's lock held."""

    def __init__(self, owner):
        object.__setattr__(self, "_owner", owner)
        object.__setattr__(self, "unlocked_writes", 0)

    def __setattr__(self, name, value):
        if not self._owner.lock_held():
            object.__setattr__(self, "unlocked_writes", self.unlocked_writes + 1)
        object.__setattr__(self, name, value)


class _FakeVX360:
    """Mimics vgamepad.VX360Gamepad: reset() swaps in a new report object."""

    def __init__(self):
        self.wrapper = None
        self.report = None
        self.updates = 0
        self.stale_updates = 0
        self.issued = []

    def lock_held(self):
        return self.wrapper is not None and self.wrapper._lock.locked()

    def reset(self):
        self.report = _LockedReport(self)
        self.issued.append(self.report)

    def update(self):
        if not self.lock_held():
            self.stale_updates += 1
        self.updates += 1


def test_pad_wrappers() -> None:
    vg = types.SimpleNamespace()
    made = []

    def make():
        g = _FakeVX360()
        g.reset()
        made.append(g)
        return g
    vg.VX360Gamepad = make

    pad = d.Xbox360Pad(vg)
    raw = made[0]
    raw.wrapper = pad
    raw.stale_updates = 0  # the constructor's release ran before we could watch
    pad.apply(0xFFFF, 1, 2, 3, 4, 5, 6)
    check("unused bit 0x0800 never reaches XInput",
          raw.report.wButtons == 0xF7FF, f"{raw.report.wButtons:#06x}")
    check("defined-button mask is 0xF7FF", d.DEFINED_BUTTONS == 0xF7FF)

    stop = threading.Event()
    errors = []

    def hammer(fn):
        try:
            while not stop.is_set():
                fn()
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=hammer, args=(lambda: pad.apply(0x1000, 1, 1, 1, 1, 1, 1),)),
               threading.Thread(target=hammer, args=(pad.release,)),
               threading.Thread(target=hammer, args=(lambda: pad.apply(0x2000, 2, 2, 2, 2, 2, 2),))]
    for t in threads:
        t.start()
    time.sleep(0.4)
    stop.set()
    for t in threads:
        t.join()
    unlocked = sum(rep.unlocked_writes for rep in raw.issued)
    check("apply/release from three threads raise nothing", not errors, str(errors[:1]))
    check("every report write happens under the pad lock", unlocked == 0, str(unlocked))
    check("every update happens under the pad lock",
          raw.stale_updates == 0 and raw.updates > 100, f"{raw.updates} updates")

    axis = d.DualShock4Pad._axis
    check("DS4 axis endpoints exact",
          (axis(-32768), axis(0), axis(32767)) == (0, 128, 255)
          and (axis(-32768, True), axis(0, True), axis(32767, True)) == (255, 128, 0))
    seq_x = [axis(v) for v in range(-32768, 32768, 7)]
    seq_y = [axis(v, True) for v in range(-32768, 32768, 7)]
    check("DS4 axis monotonic both ways",
          seq_x == sorted(seq_x) and seq_y == sorted(seq_y, reverse=True))


# --- H2: import-time driver failure -------------------------------------------

def test_create_gamepad_errors() -> None:
    real_import = builtins.__import__

    def failing(exc):
        def imp(name, *a, **kw):
            if name == "vgamepad" or name.startswith("vgamepad."):
                raise exc
            return real_import(name, *a, **kw)
        return imp

    for exc, expect, label in (
        (Exception("VIGEM_ERROR_BUS_NOT_FOUND"), "ViGEmBus", "bare Exception at import"),
        (Exception("VIGEM_ERROR_BUS_VERSION_MISMATCH"), "outdated", "bus version mismatch"),
        (OSError("ViGEmClient.dll could not be loaded"), "ViGEmBus", "DLL load failure"),
        (ImportError("No module named 'vgamepad'"), "install_vgamepad.py", "not installed"),
    ):
        builtins.__import__ = failing(exc)
        try:
            d.create_gamepad("x360")
            got = None
        except d.PadUnavailable as e:
            got = str(e)
        except Exception as e:
            got = f"LEAKED {type(e).__name__}: {e}"
        finally:
            builtins.__import__ = real_import
        check(f"{label} becomes PadUnavailable",
              got is not None and not got.startswith("LEAKED") and expect in got,
              (got or "no exception").splitlines()[0])


# --- L1 / L2: beacon ----------------------------------------------------------

class _BeaconSock:
    def __init__(self, fail=None):
        self.fail = fail
        self.sent = 0
        self.payloads = []
        self.closed = False

    def sendto(self, data, addr):
        if self.fail:
            raise self.fail
        self.sent += 1
        self.payloads.append(data)

    def close(self):
        self.closed = True


def test_beacon() -> None:
    log = []
    linked = [False]
    b = d.Beacon(45989, 45990, on_status=log.append, paused=lambda: linked[0],
                 pc_id=V2_PC_ID)
    denied = OSError(13, "An attempt was made to access a socket in a way forbidden")
    denied.winerror = 10013
    socks = [("10.0.0.2", _BeaconSock(denied)), ("192.168.1.2", _BeaconSock()),
             ("172.20.0.1", _BeaconSock(OSError(10065, "no route to host")))]
    b._open_sockets = lambda: list(socks)

    t = 1000.0
    try:
        b.step(t)
        ok = True
    except OSError:
        ok = False
    check("one interface refusing broadcast does not stop the others",
          ok and socks[1][1].sent == 1, f"sent={socks[1][1].sent}")
    check("partial failure is not reported", not log)
    check("the beacon carries pc_id",
          socks[1][1].payloads[0].hex() == "44534c4b01a5b300a1a2a3a4a5a6a7a8")

    b.step(t + 0.5)
    check("beacon respects its interval", socks[1][1].sent == 1)
    b.step(t + d.BEACON_INTERVAL)
    check("beacon sends again after its interval", socks[1][1].sent == 2)

    linked[0] = True
    b.step(t + 10)
    check("beacon pauses while a client is linked", socks[1][1].sent == 2 and b.paused)
    linked[0] = False
    b.step(t + 10.1)
    check("beacon resumes at once when the link drops",
          socks[1][1].sent == 3 and not b.paused)

    socks[1][1].fail = OSError(10050, "network is down")
    now = t + 12
    for i in range(int(b.FAIL_REPORT_AFTER / d.BEACON_INTERVAL) + 3):
        b.step(now + i * d.BEACON_INTERVAL)
    check("all interfaces failing is reported once",
          sum("not reaching any network" in m for m in log) == 1, str(log))
    socks[1][1].fail = None
    b.step(now + 100)
    check("recovery is reported", any("broadcasting again" in m for m in log), str(log))

    # The thread itself survives anything step() throws.
    b2 = d.Beacon(45989, 45990, on_status=log.append)
    calls = [0]

    def bad_step(now):
        calls[0] += 1
        raise RuntimeError("enumeration blew up")
    b2.step = bad_step
    b2.TICK = 0.01
    b2.start()
    time.sleep(0.15)
    alive = b2.is_alive()
    b2.stop()
    b2.join(1)
    check("beacon thread survives errors", alive and calls[0] > 3, f"{calls[0]} steps")


# --- C1 / L3: the real receive loop over loopback -----------------------------

def test_service_loop() -> None:
    pads: list[_Pad] = []

    def factory(kind):
        pad = _Pad()
        pads.append(pad)
        return pad

    log = []
    store = p.PairingStore(tmpdir())
    manager = p.PairingManager(store, auto_allow=True)
    svc = d.ReceiverService(port=0, beacon=False, pad_factory=factory,
                            on_status=log.append, pairing=manager)
    svc.start()
    target = ("127.0.0.1", svc.port)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(1.0)
    pad = pads[0]
    phone = FakePhone(name="Loopback phone")

    def wait_for(pred, timeout=1.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if pred():
                return True
            time.sleep(0.01)
        return False

    try:
        state = phone.pair("127.0.0.1", svc.port, timeout=8, sock=client)
        check("pairs over loopback UDP", state == p.STATE_ACCEPTED
              and phone.pc_id == store.pc_id, str(state))
        check("test mode is announced", any("TEST MODE" in m for m in log))
        phone.start_session()
        client.settimeout(1.0)

        client.sendto(phone.packet(buttons=0x1000), target)
        check("loop applies a packet over UDP",
              wait_for(lambda: pad.report.wButtons == 0x1000))

        client.sendto(b"\xd5" * 4000, target)   # WSAEMSGSIZE on Windows
        client.sendto(os.urandom(36), target)
        client.sendto(b"garbage", target)
        client.sendto(phone.packet(buttons=0x2000), target)
        check("oversized and garbage datagrams do not stop the loop",
              wait_for(lambda: pad.report.wButtons == 0x2000)
              and svc._thread.is_alive())

        pad.fail_apply = 1
        client.sendto(phone.packet(buttons=0x4000), target)
        check("a driver error releases the pad",
              wait_for(lambda: pad.releases >= 1 and pad.report.wButtons == 0))
        client.sendto(phone.packet(buttons=0x8000), target)
        check("loop keeps going after a driver error",
              wait_for(lambda: pad.report.wButtons == 0x8000) and svc._thread.is_alive())

        def explode(_state):
            raise RuntimeError("observer bug")
        svc.receiver.on_state = explode
        client.sendto(phone.packet(buttons=0x1000), target)
        wait_for(lambda: svc.receiver.last_seq == phone.seq)
        svc.receiver.on_state = None
        client.sendto(phone.packet(buttons=0x0100), target)
        check("loop survives handle() raising",
              wait_for(lambda: pad.report.wButtons == 0x0100) and svc._thread.is_alive())

        # Drain acks, then check one arrives, authenticated, with the live bit.
        time.sleep(d.ACK_INTERVAL + 0.02)
        client.setblocking(False)
        try:
            while True:
                client.recvfrom(64)
        except OSError:
            pass
        client.settimeout(1.0)
        client.sendto(phone.packet(buttons=0x0100), target)
        try:
            data, _ = client.recvfrom(64)
            ack = phone.read_ack(data)
        except OSError:
            ack = None
        check("ack over UDP is authenticated and reports the pad live",
              ack is not None and ack[3] and ack[2] == d.ACK_PAD_LIVE
              and ack[0] == phone.seq, str(ack))

        t0 = time.monotonic()
        check("watchdog still fires after all that",
              wait_for(lambda: not svc.receiver.linked and pad.report.wButtons == 0,
                       timeout=d.WATCHDOG_TIMEOUT + 1.0),
              f"{time.monotonic() - t0:.2f} s")
    finally:
        client.close()
        svc.stop()
    check("stop releases the pad and ends the thread",
          svc._thread is None and svc.gamepad is None)
    check("a service does not close a pairing manager it was given",
          svc.pairing is manager and not store._closed)
    store.close()
    check("the new session was persisted",
          p.PairingStore(store.dir).get(phone.id).highest_session == 1)

    # A service with no manager of its own makes one in the data directory.
    svc = d.ReceiverService(port=0, beacon=False, pad_factory=factory)
    svc.start()
    made_store = svc.pairing.store
    check("the default store lives in LUDUSCTRL_DATA_DIR",
          str(made_store.dir) == os.environ["LUDUSCTRL_DATA_DIR"])
    svc.stop()
    check("and is closed with the service", made_store._closed and svc.pairing is None)

    # L3: a busy port must fail before any pad exists.
    blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    blocker.bind(("0.0.0.0", 0))
    busy = blocker.getsockname()[1]
    made_before = len(pads)
    svc = d.ReceiverService(port=busy, beacon=False, pad_factory=factory)
    try:
        svc.start()
        raised = False
    except OSError:
        raised = True
    blocker.close()
    check("busy port raises OSError", raised)
    check("busy port creates no virtual pad", len(pads) == made_before)

    def no_pad(kind):
        raise d.PadUnavailable("no driver")
    svc = d.ReceiverService(port=0, beacon=False, pad_factory=no_pad)
    try:
        svc.start()
        raised = False
    except d.PadUnavailable:
        raised = True
    check("missing pad raises PadUnavailable and leaves no socket",
          raised and svc.sock is None and svc._thread is None)


def main() -> int:
    try:
        for test in (test_golden, test_crypto_vectors, test_basics, test_authentication,
                     test_restart_and_persistence, test_source_filter, test_peer_lock,
                     test_ack_flags, test_blocked_by, test_faults, test_pairing,
                     test_pairing_over_receiver, test_pad_wrappers,
                     test_create_gamepad_errors, test_beacon, test_service_loop):
            print(f"\n--- {test.__name__[5:].replace('_', ' ')} ---")
            test()
    finally:
        shutil.rmtree(TMP_ROOT, ignore_errors=True)

    print()
    if FAILURES:
        print(f"{PASSES} passed, {len(FAILURES)} failed")
        print("FAILED: " + ", ".join(FAILURES))
        return 1
    print(f"all {PASSES} unit checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
