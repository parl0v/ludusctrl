# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Josip Parlov (@parl0v). See NOTICE for the attribution terms.
"""DSLINK receiver.

Listens for DSLINK input packets from the Android client and replays them into
a virtual Xbox 360 pad via ViGEmBus, so Windows and every game on it see an
ordinary wired controller.

Protocol v2: a phone pairs with this PC once (pairing.py), and every input
packet and ack after that carries a MAC under that phone's key. Nothing
unauthenticated reaches the pad any more.

See ../docs/PROTOCOL.md for the wire format.
"""

from __future__ import annotations

import argparse
import gc
import ipaddress
import signal
import socket
import struct
import sys
import threading
import time
import traceback
from typing import Callable, NamedTuple

import pairing
from pairing import (
    PAIR_REQ_MAGIC,
    PROTOCOL_VERSION,
    PairingManager,
    PairingStore,
)

# The 20-byte v1 input packet. UDP stopped accepting it in 1.2: anyone on the
# LAN could send one. The browser client still speaks it, in-process, behind
# its own per-session token and TLS, which is why webbridge imports these.
MAGIC = 0xD5
VERSION = 1
PACKET_SIZE = 20
PACKET = struct.Struct("<BBIHhhhhBBBB")

# The 36-byte v2 input packet: v1's first 20 bytes with version 2, then the
# session number, the key id and a MAC over everything before it.
PACKET_V2 = struct.Struct("<BBIHhhhhBBBBI4s8s")
PACKET_V2_SIZE = PACKET_V2.size
PACKET_V2_SIGNED = PACKET_V2_SIZE - pairing.MAC_SIZE   # bytes the MAC covers

ACK_MAGIC = 0xD6
# Unauthenticated, 12 bytes: only ever "wrong version" or "not paired", which
# an attacker gains nothing by forging beyond making a phone pair again.
ACK = struct.Struct("<BBIIBB")
# Authenticated, 20 bytes: the same 12, then a MAC over them.
ACK_V2 = struct.Struct("<BBIIBB8s")
# Often enough for a responsive status readout, rare enough to be free.
ACK_INTERVAL = 0.2
# Ack flags byte (offset 10).
ACK_PAD_LIVE = 0x01          # the virtual pad exists and this client is driving it
ACK_VERSION_MISMATCH = 0x02  # the client speaks a protocol version we do not
ACK_NOT_PAIRED = 0x04        # this PC has no key for the packet's key id
# A client on the wrong protocol version only needs telling now and then; it
# is not going to fix itself between two packets. The same goes for a phone
# this PC does not know.
MISMATCH_ACK_INTERVAL = 1.0

BEACON_MAGIC = b"DSLK"
# The beacon keeps its own format version, separate from the input protocol:
# 1.1 apps read the first 8 bytes and ignore the pc_id appended after them.
BEACON_VERSION = 1
BEACON = struct.Struct("<4sBHB")
BEACON_WITH_ID = struct.Struct("<4sBHB8s")

DEFAULT_INPUT_PORT = 45989
DEFAULT_BEACON_PORT = 45990
BEACON_INTERVAL = 2.0

# Release everything if the client goes quiet, so nothing sticks down in a game.
# The client sends a keepalive every 500 ms, so this tolerates two lost in a
# row and still bounds how long a dead phone can hold a button.
WATCHDOG_TIMEOUT = 1.5

# The receiver locks onto one paired phone at a time. Another phone continuing
# an existing session only gets the pad once the current one has been silent
# this long: long enough that two phones cannot interleave packet by packet.
# A phone starting a new session (pressing Start link) takes over at once;
# that is authenticated, and it is what the person holding it asked for.
PEER_SWITCH_SILENCE = 0.3

# Repeating log lines (a second phone, a stranger on the network, a flaky
# driver) are shown at most this often, so a flood cannot bury the log or
# make the UI thread do nothing but append to it.
NOTICE_INTERVAL = 5.0

# Big enough for any sane datagram. Anything larger is garbage by definition,
# and on Windows a datagram that does not fit raises WSAEMSGSIZE rather than
# being truncated, so the size only has to be comfortably above PACKET_SIZE.
RECV_BUFFER = 2048

WSAEMSGSIZE = 10040
WSAECONNRESET = 10054

# Half of the u32 sequence space. A gap larger than this reads as wraparound
# rather than as a late packet.
SEQ_HALF = 1 << 31

# Pad layout, carried in byte 19 of the input packet. Cosmetic only: the button
# mask is positional and identical across vendors, because Android reports the
# bottom face button as KEYCODE_BUTTON_A on every pad.
LAYOUT_UNKNOWN, LAYOUT_PLAYSTATION, LAYOUT_XBOX, LAYOUT_NINTENDO = 0, 1, 2, 3

# Same bits throughout; only the names differ. Order matches the bit order so
# describe_buttons() reads left to right.
_BITS = [0x0001, 0x0002, 0x0004, 0x0008, 0x0010, 0x0020, 0x0040, 0x0080,
         0x0100, 0x0200, 0x0400, 0x1000, 0x2000, 0x4000, 0x8000]

_NAMES = {
    LAYOUT_PLAYSTATION: ["up", "down", "left", "right", "options", "create",
                         "L3", "R3", "L1", "R1", "PS",
                         "cross", "circle", "square", "triangle"],
    LAYOUT_XBOX:        ["up", "down", "left", "right", "menu", "view",
                         "LS", "RS", "LB", "RB", "guide",
                         "A", "B", "X", "Y"],
    LAYOUT_NINTENDO:    ["up", "down", "left", "right", "plus", "minus",
                         "L3", "R3", "L", "R", "home",
                         "B", "A", "Y", "X"],
}
# An unknown pad gets neutral, position-based names rather than a guess.
_NAMES[LAYOUT_UNKNOWN] = ["up", "down", "left", "right", "start", "select",
                          "L3", "R3", "L1", "R1", "guide",
                          "south", "east", "west", "north"]

BUTTON_NAMES = list(zip(_BITS, _NAMES[LAYOUT_PLAYSTATION]))

# Every bit the protocol defines (0xF7FF). 0x0800 is unused on the wire, and
# XInput has nothing there either, so a client that sets it must not be able
# to push an undefined bit into the virtual pad.
DEFINED_BUTTONS = 0
for _bit in _BITS:
    DEFINED_BUTTONS |= _bit
del _bit


class PadState(NamedTuple):
    """One instant of pad state, as handed to an observer such as the GUI."""

    buttons: int
    left_x: int
    left_y: int
    right_x: int
    right_y: int
    left_trigger: int
    right_trigger: int
    connected: bool
    layout: int = LAYOUT_UNKNOWN


def describe_buttons(mask: int, layout: int = LAYOUT_PLAYSTATION) -> str:
    names = _NAMES.get(layout, _NAMES[LAYOUT_UNKNOWN])
    hit = [n for bit, n in zip(_BITS, names) if mask & bit]
    return "+".join(hit) if hit else "-"


# Where input and pairing requests are accepted from. Pairing and the MAC are
# what authenticate a phone now; this stays as a second wall, so nobody who
# can merely route a packet to this PC (and could otherwise open a pairing
# prompt on it) gets that far. Loopback is here for tests and local tools;
# link-local covers a phone and PC joined by a bare cable or a hotspot that
# hands out no DHCP.
#
# 100.64.0.0/10 (carrier-grade NAT, also Tailscale) is deliberately absent:
# it is shared with strangers on the carrier's side, which is exactly who
# this filter exists to keep out.
_ALLOWED_SOURCES = [ipaddress.ip_network(n) for n in (
    "127.0.0.0/8",      # loopback
    "10.0.0.0/8",       # RFC 1918
    "172.16.0.0/12",    # RFC 1918 (also Hyper-V / WSL NAT)
    "192.168.0.0/16",   # RFC 1918
    "169.254.0.0/16",   # IPv4 link-local
    "::1/128",          # IPv6 loopback
    "fe80::/10",        # IPv6 link-local
    "fc00::/7",         # IPv6 unique local, the v6 counterpart of RFC 1918
)]


def allowed_source(host: str) -> bool:
    """True when `host` is on a private, link-local or loopback network."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return any(ip in net for net in _ALLOWED_SOURCES)


def primary_ip() -> str | None:
    """The address on the default route, i.e. the one facing the real LAN.

    Nothing is transmitted; connect() on a UDP socket only picks a route.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 80))
        return probe.getsockname()[0]
    except OSError:
        return None
    finally:
        probe.close()


def local_ips() -> list[str]:
    """Every IPv4 address on this host, primary first.

    Machines with Hyper-V, WSL, VMware or VirtualBox routinely have a dozen,
    and the beacon has to go out all of them because there is no reliable way
    to know in advance which one the phone is on.
    """
    found: list[str] = []
    primary = primary_ip()
    if primary:
        found.append(primary)
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127.") and ip not in found:
                found.append(ip)
    except OSError:  # gaierror included; a hostname lookup is never fatal
        pass
    return found


class Beacon(threading.Thread):
    """Broadcasts our presence so the client can autofill the host address.

    A single unbound socket sending to 255.255.255.255 leaves the choice of
    interface to the routing table, which picks exactly one. On a machine with
    Hyper-V, WSL, VMware or VirtualBox installed that is very often a virtual
    adapter, and the broadcast never reaches the phone. So bind one socket per
    local address and send from all of them; binding the source address is what
    pins each datagram to its interface.

    The beacon advertises this PC to everyone on the network, so it only runs
    while it is needed: `paused` is polled, and while it returns True (a
    client is linked) nothing is broadcast. It resumes the moment the link
    drops. It carries pc_id, so a paired phone can follow this PC when its
    address changes; pc_id is no secret, only a name.
    """

    daemon = True

    # Adapters come and go (VPNs, docks, VMs starting), so rebuild periodically.
    REFRESH_EVERY = 15.0
    # How long every interface may fail before it is worth telling the user.
    # Shorter would report a laptop briefly between networks as broken.
    FAIL_REPORT_AFTER = 10.0
    # Loop granularity. Sends still happen every BEACON_INTERVAL; this only
    # decides how quickly a resume or a stop is noticed.
    TICK = 0.25

    def __init__(self, input_port: int, beacon_port: int,
                 on_status: Callable[[str], None] | None = None,
                 paused: Callable[[], bool] | None = None,
                 pc_id: bytes = bytes(8)) -> None:
        super().__init__(name="dslink-beacon")
        self.input_port = input_port
        self.beacon_port = beacon_port
        self.on_status = on_status
        self.paused_by = paused
        self._stop = threading.Event()
        self.interfaces = 0
        self.paused = False
        self.payload = BEACON_WITH_ID.pack(BEACON_MAGIC, BEACON_VERSION, input_port, 0,
                                           pc_id)
        self._socks: list[tuple[str, socket.socket]] = []
        self._last_refresh = float("-inf")
        self._last_sent = float("-inf")
        self._failing_since: float | None = None
        self._reported_failure = False
        self._last_error_at = float("-inf")

    def _open_sockets(self) -> list[tuple[str, socket.socket]]:
        made = []
        for ip in local_ips():
            s = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((ip, 0))
                made.append((ip, s))
            except OSError:
                if s is not None:
                    s.close()
                continue  # interface vanished between enumeration and bind
        return made

    def _close_sockets(self) -> None:
        for _, s in self._socks:
            try:
                s.close()
            except OSError:
                pass
        self._socks = []

    def _status(self, message: str) -> None:
        if self.on_status:
            try:
                self.on_status(message)
            except Exception:
                pass  # an observer's bug must not stop discovery

    def step(self, now: float) -> None:
        """One pass of the loop: maybe rebuild, maybe send. Never raises OSError."""
        if self.paused_by is not None and self.paused_by():
            self.paused = True
            return
        resumed, self.paused = self.paused, False

        if now - self._last_refresh >= self.REFRESH_EVERY:
            self._close_sockets()
            self._socks = self._open_sockets()
            self.interfaces = len(self._socks)
            self._last_refresh = now

        # Send straight away on resume, so a phone that lost the link finds
        # the PC again without waiting out a full interval.
        if not resumed and now - self._last_sent < BEACON_INTERVAL:
            return
        self._last_sent = now

        sent, reason = 0, "no usable network interface"
        for ip, s in self._socks:
            try:
                s.sendto(self.payload, ("255.255.255.255", self.beacon_port))
                sent += 1
            except OSError as exc:
                # One interface going down, refusing broadcast (WSAEACCES
                # 10013), or losing its route (10050, 10065) is routine and
                # says nothing about the others, so carry on with the rest.
                reason = f"{ip}: {exc}"

        if sent:
            if self._reported_failure:
                self._status(f"[beacon] broadcasting again on {sent} interface(s)")
            self._failing_since = None
            self._reported_failure = False
            return

        if self._failing_since is None:
            self._failing_since = now
        elif (not self._reported_failure
              and now - self._failing_since >= self.FAIL_REPORT_AFTER):
            self._reported_failure = True
            self._status(f"[beacon] discovery is not reaching any network ({reason}); "
                         "type the PC address into the app instead")

    def run(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    self.step(time.monotonic())
                except Exception as exc:
                    # Discovery is a convenience. Whatever went wrong, keep the
                    # thread alive so it recovers when the network does.
                    now = time.monotonic()
                    if now - self._last_error_at >= NOTICE_INTERVAL:
                        self._last_error_at = now
                        self._status(f"[beacon] error: {exc}")
                self._stop.wait(self.TICK)
        finally:
            self._close_sockets()

    def stop(self) -> None:
        self._stop.set()


class Receiver:
    """Turns input datagrams into virtual pad state.

    Owns no thread and no socket lifetime; ReceiverService feeds it. Every
    public counter and flag here is read from other threads (the GUI), so each
    is a plain attribute that is only ever replaced whole.
    """

    # Arbitration hook. When set and returning True, another input source
    # (the browser bridge) owns the pad: packets are still accepted and acked,
    # but not applied, and the pad-live ack bit reads 0. Called on the
    # receive thread.
    blocked_by: Callable[[], bool] | None = None

    def __init__(self, gamepad, sock: socket.socket, verbose: bool,
                 on_state=None, on_status=None,
                 blocked_by: Callable[[], bool] | None = None,
                 pairing: PairingManager | None = None) -> None:
        self.gamepad = gamepad
        self.sock = sock
        self.verbose = verbose
        # Optional observers, used by the GUI. Both are called from the
        # receive thread, so anything touching a toolkit must marshal.
        self.on_state = on_state
        self.on_status = on_status
        self.blocked_by = blocked_by
        # None means nobody is paired and nobody can pair: every input
        # packet is answered "not paired". Only tests construct it that way.
        self.pairing = pairing
        self.last_seq: int | None = None
        self.last_packet_at = 0.0
        # True while a client is sending valid packets within the watchdog
        # window. It does not mean that client is driving the pad; see
        # `driving` and `blocked` for that.
        self.linked = False
        # Who holds the pad: the phone's id and name, and where its packets
        # come from (which is where its acks go).
        self.peer_id: bytes | None = None
        self.peer_name = ""
        self.peer: tuple[str, int] | None = None
        self.packets = 0
        self.dropped = 0
        self.rejected = 0
        self.unauthenticated = 0
        self.acks = 0
        # Whether this receiver wrote the pad last, so it knows whether a
        # timeout or a block is its release to make.
        self.driving = False
        self.blocked = False
        # False after the driver refused a write, until one succeeds again.
        self.pad_ok = True
        # Per phone: (session, newest seq) of its current session. Kept across
        # the watchdog and across phones taking turns, so a stretch of silence
        # never reopens the window for replaying that session's packets. Not
        # persisted, on purpose; see _accept.
        self._seq: dict[bytes, tuple[int, int]] = {}
        # Per phone, so no other phone can use up the driving phone's acks.
        self._last_ack_at: dict[bytes, float] = {}
        self._mismatch_ack_at: dict[tuple, float] = {}
        self._unpaired_ack_at: dict[tuple, float] = {}
        self._notice_at: dict[str, float] = {}
        self._last_state = None
        self._last_width = 0

    # --- bookkeeping ---------------------------------------------------------

    @property
    def pad_live(self) -> bool:
        """What ack flag bit 0 reports: a pad exists, works, and is ours."""
        return self.gamepad is not None and self.pad_ok and not self.blocked

    @staticmethod
    def newer(last: int | None, seq: int) -> bool:
        if last is None:
            return True
        # Unsigned distance forward from last; small means genuinely newer.
        return 0 < ((seq - last) & 0xFFFFFFFF) < SEQ_HALF

    def notice(self, key: str, message: str) -> None:
        """status(), but at most once per NOTICE_INTERVAL for each key."""
        now = time.monotonic()
        if now - self._notice_at.get(key, float("-inf")) < NOTICE_INTERVAL:
            return
        self._notice_at[key] = now
        self.status(message)

    def _is_blocked(self) -> bool:
        check = self.blocked_by
        if check is None:
            return False
        try:
            return bool(check())
        except Exception as exc:
            # A broken arbiter should not silently kill the primary client,
            # so fail towards letting the phone drive.
            self.notice("blocked_by", f"[error] input arbitration failed: {exc}")
            return False

    @staticmethod
    def _limit(table: dict, key, now: float, interval: float) -> bool:
        """True if `key` may be answered now, and records that it was."""
        if now - table.get(key, float("-inf")) < interval:
            return False
        if len(table) > 64:
            # Bounded, so a sender cycling source ports cannot grow it forever.
            table.clear()
        table[key] = now
        return True

    # --- packets -------------------------------------------------------------

    def process(self, data: bytes, addr: tuple[str, int]) -> None:
        """handle(), guaranteed not to raise. The receive loop calls this."""
        try:
            self.handle(data, addr)
        except Exception as exc:
            self.fault("packet handling", exc)

    def handle(self, data: bytes, addr: tuple[str, int]) -> None:
        if not allowed_source(addr[0]):
            self.rejected += 1
            self.notice("source", f"[link] ignoring {addr[0]}: not a local network "
                                  "address")
            return

        if not data:
            return
        if data[0] == PAIR_REQ_MAGIC:
            self.pair_request(data, addr)
            return
        if len(data) < 2 or data[0] != MAGIC:
            return
        if data[1] != PROTOCOL_VERSION:
            # Includes every v1 packet: there is no unauthenticated input
            # path any more, only an answer saying which side to update.
            self.version_mismatch(data, addr)
            return
        if len(data) != PACKET_V2_SIZE:
            return
        (_, _, seq, buttons, lx, ly, rx, ry, lt, rt, flags, layout,
         session, kid, tag) = PACKET_V2.unpack(data)

        phone = self._authenticate(data, kid, tag, seq, addr)
        if phone is None:
            return

        now = time.monotonic()
        fresh = self._accept(phone, session, seq)
        if fresh is None:
            return

        if phone.id != self.peer_id:
            if (not fresh and self.linked
                    and now - self.last_packet_at < PEER_SWITCH_SILENCE):
                # Another paired phone has the pad and this one is only
                # carrying on with an older link. Tell it so (pad-live 0)
                # rather than leave it guessing, but leave the pad alone.
                self.rejected += 1
                self.notice("peer", f"[link] {phone.name} is linked too, but "
                                    f"{self.peer_name} has the pad")
                self._ack(phone, seq, addr, now, live=False)
                return
            was_linked = self.linked
            self.peer_id = phone.id
            self.peer_name = phone.name
            self.peer = addr
            self._last_ack_at.pop(phone.id, None)
            message = f"[link] {phone.name} ({addr[0]}:{addr[1]})"
            if was_linked:
                # Two phones that each pause often enough could otherwise
                # trade the lock back and forth and flood the log.
                self.notice("switch", message + " took over")
            else:
                self.status(message)
        elif addr != self.peer:
            # The same phone from a new source port or address (Wi-Fi
            # roaming). Authenticated and seq-checked, so follow it.
            self.peer = addr

        self.last_seq = seq
        self.last_packet_at = now
        self.packets += 1
        self.linked = True

        pad_connected = bool(flags & 0x01)
        self.blocked = self._is_blocked()
        if self.blocked:
            if self.driving:
                self._release_pad()
        elif pad_connected:
            self._write_pad(buttons, lx, ly, rx, ry, lt, rt)
        else:
            self._write_pad(None)

        self._ack(phone, seq, addr, now, live=self.pad_live)

        if self.blocked:
            return  # the UI shows whichever source owns the pad, not us
        if self.on_state:
            self.on_state(
                PadState(buttons, lx, ly, rx, ry, lt, rt, pad_connected, layout))
        if self.verbose:
            self.render(buttons, lx, ly, rx, ry, lt, rt, pad_connected, layout)

    def _authenticate(self, data: bytes, kid: bytes, tag: bytes, seq: int,
                      addr: tuple[str, int]):
        """The paired phone that sent this, or None (answered or dropped)."""
        candidates = self.pairing.store.by_kid(kid) if self.pairing else []
        if not candidates:
            # The PC forgot this phone, or the phone is talking to another PC
            # that took over this address. Say so, so it can offer to pair
            # again. Unauthenticated by necessity: there is no key to sign
            # with. Forging it costs the user a re-pair and nothing more.
            self.unauthenticated += 1
            if self._limit(self._unpaired_ack_at, addr, time.monotonic(),
                           MISMATCH_ACK_INTERVAL):
                self.notice("unpaired", f"[link] {addr[0]} is not paired with this PC; "
                                        "it has to pair again")
                self._send(ACK.pack(ACK_MAGIC, PROTOCOL_VERSION, seq, 0, ACK_NOT_PAIRED, 0),
                           addr)
            return None
        signed = data[:PACKET_V2_SIGNED]
        for phone in candidates:
            if pairing.mac_ok(phone.key, signed, tag):
                return phone
        # Forged, corrupted, or under a replaced key. No ack: an answer here
        # would tell whoever is guessing which of their guesses got further.
        self.unauthenticated += 1
        self.notice("mac", f"[link] dropping packets from {addr[0]} that fail "
                           "authentication")
        return None

    def _accept(self, phone, session: int, seq: int) -> bool | None:
        """Replay protection. None to drop; True for the first packet of a new
        session, False for a newer packet of the current one. Records it.

        A phone numbers its links (sessions) upwards and never reuses one.
        The highest seen is persisted, so nothing recorded from an earlier
        link is accepted again, even after this PC restarts. Within the
        current session the u32 seq must move forward.

        After a restart the newest seq of the current session is unknown, so
        its packets are refused until the phone starts a new session, which it
        does by itself once acks stop. Accepting them would let a recording of
        that session be replayed into the first moments after a restart.
        """
        highest = phone.highest_session
        if session > highest:
            if self.pairing is not None:
                self.pairing.store.note_session(phone.id, session)
            self._seq[phone.id] = (session, seq)
            return True
        if session < highest:
            self.dropped += 1
            self.notice("replay", f"[link] dropped a replayed packet for {phone.name}")
            return None
        current = self._seq.get(phone.id)
        if current is None or current[0] != session:
            self.dropped += 1
            self.notice("stale", f"[link] {phone.name} is on a link from before a "
                                 "restart; waiting for it to start a new one")
            return None
        if not self.newer(current[1], seq):
            self.dropped += 1
            return None
        self._seq[phone.id] = (session, seq)
        return False

    def pair_request(self, data: bytes, addr: tuple[str, int]) -> None:
        manager = self.pairing
        if manager is None:
            return
        reply = manager.handle_request(data, addr)
        if reply is not None:
            self._send(reply, addr)

    def version_mismatch(self, data: bytes, addr: tuple[str, int]) -> None:
        """Tell a client on another protocol version why nothing is happening.

        Silently dropping it looks exactly like a firewall to the client. The
        reply carries our own version plus the mismatch bit, so the app can
        say which side needs updating.
        """
        # A reply larger than the request would make this a (small) traffic
        # amplifier, so only answer datagrams at least as big as the ack.
        if len(data) < ACK.size:
            return
        if not self._limit(self._mismatch_ack_at, addr, time.monotonic(),
                           MISMATCH_ACK_INTERVAL):
            return
        seq = struct.unpack_from("<I", data, 2)[0]
        self.notice("version", f"[link] {addr[0]} speaks protocol v{data[1]}, this "
                               f"receiver speaks v{PROTOCOL_VERSION}; update whichever "
                               "is older")
        self._send(ACK.pack(ACK_MAGIC, PROTOCOL_VERSION, seq, 0, ACK_VERSION_MISMATCH, 0),
                   addr)

    def _ack(self, phone, seq: int, addr: tuple[str, int], now: float, live: bool) -> None:
        """Tell the phone we exist, so it can show a real link state and RTT.

        Authenticated, so a phone can trust LIVE. Each phone has its own
        limiter, so no other sender can use up the driving phone's acks.
        """
        if not self._limit(self._last_ack_at, phone.id, now, ACK_INTERVAL):
            return
        flags = ACK_PAD_LIVE if live else 0
        head = ACK.pack(ACK_MAGIC, PROTOCOL_VERSION, seq, self.packets & 0xFFFFFFFF, flags, 0)
        if self._send(head + pairing.mac(phone.key, head), addr):
            self.acks += 1

    def _send(self, payload: bytes, addr: tuple[str, int]) -> bool:
        try:
            self.sock.sendto(payload, addr)
            return True
        except OSError:
            # Acks are advisory; input must never stall waiting on one.
            return False

    # --- the pad -------------------------------------------------------------

    def _write_pad(self, *state) -> None:
        """Apply `state`, or release when it is (None,). Driver errors are
        contained here so the ack can still go out and say the pad is dead."""
        pad = self.gamepad
        if pad is None:
            return
        try:
            if state == (None,):
                pad.release()
            else:
                pad.apply(*state)
            self.driving = True
            self.pad_ok = True
        except Exception as exc:
            self.fault("virtual pad", exc)

    def _release_pad(self) -> bool:
        pad = self.gamepad
        self.driving = False
        if pad is None:
            return True
        try:
            pad.release()
            self.pad_ok = True
            return True
        except Exception:
            self.pad_ok = False
            return False

    def fault(self, where: str, exc: BaseException) -> None:
        """Something threw. Let go of the pad, say so (rarely), keep going.

        A stuck button is worse than a dropped frame: if the state we were
        writing is in doubt, neutral is the only safe thing to leave behind.
        """
        released = self._release_pad()
        if where == "virtual pad" or not released:
            self.pad_ok = False
        detail = "".join(traceback.format_exception_only(type(exc), exc)).strip()
        self.notice("fault:" + where, f"[error] {where}: {detail}; pad released")

    def apply(self, buttons, lx, ly, rx, ry, lt, rt) -> None:
        self.gamepad.apply(buttons, lx, ly, rx, ry, lt, rt)

    def neutral(self) -> None:
        self.gamepad.release()

    # --- output --------------------------------------------------------------

    def render(self, buttons, lx, ly, rx, ry, lt, rt, connected,
               layout=LAYOUT_PLAYSTATION) -> None:
        state = (buttons, lx // 2048, ly // 2048, rx // 2048, ry // 2048,
                 lt // 16, rt // 16, layout)
        if state == self._last_state:
            return
        self._last_state = state

        pad = "pad" if connected else "NO PAD"
        lname, rname = ("LT", "RT") if layout == LAYOUT_XBOX else ("L2", "R2")
        line = (f"[{pad}] L({lx:+6d},{ly:+6d}) R({rx:+6d},{ry:+6d}) "
                f"{lname}{lt:3d} {rname}{rt:3d} {describe_buttons(buttons, layout)}")

        # \r only moves the cursor; it does not erase. Without padding out to
        # the previous line's width, a longer line (many buttons held) leaves
        # its tail on screen when the next one is shorter.
        pad_to = max(0, self._last_width - len(line))
        self._last_width = len(line)

        sys.stdout.write("\r" + line + " " * pad_to)
        sys.stdout.flush()

    def status(self, message: str) -> None:
        """Report a status line without leaving fragments of the live readout."""
        if self.on_status:
            self.on_status(message)
        if self._last_width and sys.stdout:
            sys.stdout.write("\r" + " " * self._last_width + "\r")
            self._last_width = 0
            self._last_state = None
        print(message)

    # --- watchdog ------------------------------------------------------------

    def tick(self) -> None:
        """tick_watchdog() and the pairing prompt's timeout, guaranteed not
        to raise."""
        try:
            self.tick_watchdog()
        except Exception as exc:
            self.fault("watchdog", exc)
        manager = self.pairing
        if manager is not None:
            try:
                manager.tick()
            except Exception as exc:
                self.notice("pairing", f"[error] pairing: {exc}")

    def tick_watchdog(self) -> None:
        if not self.linked:
            return
        if time.monotonic() - self.last_packet_at > WATCHDOG_TIMEOUT:
            self.linked = False
            self.peer = None
            self.peer_id = None
            self.last_seq = None
            # The phone's own session and seq (self._seq) are deliberately
            # kept: it may come back on the same link after a Wi-Fi stall,
            # and nothing recorded before the stall may be replayed.
            # Only undo what we did. If the browser owns the pad, releasing it
            # here would drop whatever the browser is holding.
            was_driving = self.driving
            if was_driving:
                self._release_pad()
            self.blocked = False
            if was_driving and self.on_state:
                self.on_state(PadState(0, 0, 0, 0, 0, 0, 0, False, LAYOUT_UNKNOWN))
            who = self.peer_name or "client"
            self.status(f"[link] {who} timed out, pad released" if was_driving
                        else f"[link] {who} timed out")


class PadUnavailable(RuntimeError):
    """vgamepad or the ViGEmBus driver is missing or unusable."""


class VirtualPad:
    """Wraps a ViGEm target so the receiver does not care which kind it is.

    apply() and release() may be called from different threads (the UDP
    receiver and the browser bridge share one pad), so both run under a lock.
    That matters more than it looks: vgamepad's reset() swaps in a brand new
    report object, and an apply() racing it would write the old one and then
    update() the new, losing the input or resurrecting a released button.
    """

    kind = "?"

    def __init__(self) -> None:
        self._lock = threading.Lock()

    def apply(self, buttons, lx, ly, rx, ry, lt, rt) -> None:
        with self._lock:
            self._apply(buttons & DEFINED_BUTTONS, lx, ly, rx, ry, lt, rt)

    def release(self) -> None:
        with self._lock:
            self._release()

    def _apply(self, buttons, lx, ly, rx, ry, lt, rt) -> None:
        raise NotImplementedError

    def _release(self) -> None:
        raise NotImplementedError


class Xbox360Pad(VirtualPad):
    """XInput target. Universally supported; games show Xbox prompts."""

    kind = "Xbox 360"

    def __init__(self, vg):
        super().__init__()
        self.pad = vg.VX360Gamepad()
        self.release()

    def _apply(self, buttons, lx, ly, rx, ry, lt, rt) -> None:
        # The wire bitmask is already XInput's wButtons layout, so this is a
        # straight copy rather than a per-button translation. Read the report
        # here, under the lock, never before it: release() replaces it.
        r = self.pad.report
        r.wButtons = buttons
        r.sThumbLX, r.sThumbLY = lx, ly
        r.sThumbRX, r.sThumbRY = rx, ry
        r.bLeftTrigger, r.bRightTrigger = lt, rt
        self.pad.update()

    def _release(self) -> None:
        self.pad.reset()
        self.pad.update()


class DualShock4Pad(VirtualPad):
    """HID target. Games show PlayStation prompts, but XInput-only titles
    will not see it at all, which is why Xbox 360 stays the default."""

    kind = "DualShock 4"

    # (up, down, left, right) -> hat direction
    _HAT = {
        (0, 0, 0, 0): "NONE",
        (1, 0, 0, 0): "NORTH",  (1, 0, 0, 1): "NORTHEAST",
        (0, 0, 0, 1): "EAST",   (0, 1, 0, 1): "SOUTHEAST",
        (0, 1, 0, 0): "SOUTH",  (0, 1, 1, 0): "SOUTHWEST",
        (0, 0, 1, 0): "WEST",   (1, 0, 1, 0): "NORTHWEST",
    }

    def __init__(self, vg):
        super().__init__()
        self.vg = vg
        self.pad = vg.VDS4Gamepad()
        B = vg.DS4_BUTTONS
        # XInput bit -> DS4 button, in the wire bitmask's order (docs/PROTOCOL.md).
        self.button_map = [
            (0x0010, B.DS4_BUTTON_OPTIONS),
            (0x0020, B.DS4_BUTTON_SHARE),           # Create
            (0x0040, B.DS4_BUTTON_THUMB_LEFT),
            (0x0080, B.DS4_BUTTON_THUMB_RIGHT),
            (0x0100, B.DS4_BUTTON_SHOULDER_LEFT),
            (0x0200, B.DS4_BUTTON_SHOULDER_RIGHT),
            (0x1000, B.DS4_BUTTON_CROSS),
            (0x2000, B.DS4_BUTTON_CIRCLE),
            (0x4000, B.DS4_BUTTON_SQUARE),
            (0x8000, B.DS4_BUTTON_TRIANGLE),
        ]
        self.hat = {name: getattr(vg.DS4_DPAD_DIRECTIONS, f"DS4_BUTTON_DPAD_{name}")
                    for name in set(self._HAT.values())}
        self.release()

    @staticmethod
    def _axis(v: int, invert: bool = False) -> int:
        """int16 (XInput, positive-up) -> uint8 (DS4 HID, positive-down).

        Each half of the int16 range is scaled onto its own half of the byte,
        because the two halves are not the same size (-32768..-1 has one more
        value than 1..32767, and 0..127 one fewer than 129..255). A plain
        shift gets the centre right but leaves an inverted full deflection one
        short of the rail. This way -32768 / 0 / 32767 land on exactly
        0 / 128 / 255, or 255 / 128 / 0 inverted.

        A real DualShock 4 reports 8 bits per axis, so this is accurate
        emulation rather than a loss of resolution.
        """
        v = max(-32768, min(32767, int(v)))
        if invert:
            if v >= 0:
                u = 128 - (v * 128 + 16383) // 32767
            else:
                u = 128 + (-v * 127 + 16384) // 32768
        else:
            if v >= 0:
                u = 128 + (v * 127 + 16383) // 32767
            else:
                u = 128 - (-v * 128 + 16384) // 32768
        return max(0, min(255, u))

    def _apply(self, buttons, lx, ly, rx, ry, lt, rt) -> None:
        pad = self.pad
        for bit, btn in self.button_map:
            if buttons & bit:
                pad.press_button(button=btn)
            else:
                pad.release_button(button=btn)

        # L2/R2 are analog, but DS4 also carries a digital bit that games use
        # to detect a press at all; mirror the analog value into it.
        B = self.vg.DS4_BUTTONS
        for value, btn in ((lt, B.DS4_BUTTON_TRIGGER_LEFT),
                           (rt, B.DS4_BUTTON_TRIGGER_RIGHT)):
            if value > 0:
                pad.press_button(button=btn)
            else:
                pad.release_button(button=btn)

        if buttons & 0x0400:
            pad.press_special_button(
                special_button=self.vg.DS4_SPECIAL_BUTTONS.DS4_SPECIAL_BUTTON_PS)
        else:
            pad.release_special_button(
                special_button=self.vg.DS4_SPECIAL_BUTTONS.DS4_SPECIAL_BUTTON_PS)

        # The d-pad is a hat on DS4, not four independent bits.
        key = (1 if buttons & 0x0001 else 0, 1 if buttons & 0x0002 else 0,
               1 if buttons & 0x0004 else 0, 1 if buttons & 0x0008 else 0)
        pad.directional_pad(direction=self.hat[self._HAT.get(key, "NONE")])

        pad.left_joystick(x_value=self._axis(lx), y_value=self._axis(ly, invert=True))
        pad.right_joystick(x_value=self._axis(rx), y_value=self._axis(ry, invert=True))
        pad.left_trigger(value=lt)
        pad.right_trigger(value=rt)
        pad.update()

    def _release(self) -> None:
        self.pad.reset()
        self.pad.update()


DRIVER_URL = "https://github.com/nefarius/ViGEmBus/releases"


def create_gamepad(kind: str = "x360") -> VirtualPad:
    """Create the virtual pad, or raise PadUnavailable with a usable message."""
    try:
        import vgamepad
    except ImportError:
        raise PadUnavailable(
            "vgamepad is not installed.\n\n"
            "Run:  python install_vgamepad.py"
        ) from None
    except Exception as exc:
        # vgamepad connects to the bus while it is being imported, and reports
        # failure with a bare Exception named after the ViGEm error code, e.g.
        # VIGEM_ERROR_BUS_NOT_FOUND (no driver) or
        # VIGEM_ERROR_BUS_VERSION_MISMATCH (driver too old for the client DLL).
        raise PadUnavailable(
            f"vgamepad is installed but cannot reach the ViGEmBus driver ({exc}).\n\n"
            "The driver is missing, stopped or outdated. Install the latest\n"
            f"ViGEmBus from {DRIVER_URL}\n"
            "then restart this program (a reboot may be needed after installing)."
        ) from exc
    try:
        return DualShock4Pad(vgamepad) if kind == "ds4" else Xbox360Pad(vgamepad)
    except Exception as exc:  # vgamepad raises bare Exception when the bus is absent
        raise PadUnavailable(
            f"Could not create the virtual pad: {exc}\n\n"
            "The ViGEmBus driver is probably missing. Install it from\n"
            f"{DRIVER_URL} and try again."
        ) from exc


def require_vgamepad(kind: str = "x360"):
    """CLI wrapper: same as create_gamepad, but exits with the message."""
    try:
        return create_gamepad(kind)
    except PadUnavailable as exc:
        sys.exit(str(exc))


class ReceiverService:
    """Owns the socket, beacon and receive loop so callers need not.

    Both the console entry point and the GUI drive this; keeping the loop in
    one place is what stops the two front ends drifting apart.
    """

    def __init__(self, port: int = DEFAULT_INPUT_PORT,
                 beacon_port: int = DEFAULT_BEACON_PORT,
                 beacon: bool = True, verbose: bool = False,
                 pad_kind: str = "x360",
                 on_state=None, on_status=None,
                 blocked_by: Callable[[], bool] | None = None,
                 pad_factory: Callable[[str], VirtualPad] | None = None,
                 pairing: PairingManager | None = None) -> None:
        self.pad_kind = pad_kind
        self.port = port
        self.beacon_port = beacon_port
        self.use_beacon = beacon
        self.verbose = verbose
        self.on_state = on_state
        self.on_status = on_status
        self.blocked_by = blocked_by
        # Tests swap in a fake; everything else gets the real ViGEm pad.
        self.pad_factory = pad_factory or create_gamepad
        # The desktop app passes its own, which outlives this service (a pad
        # switch restarts the service, and must not drop an open prompt).
        # Otherwise the service keeps one for its lifetime, stored in the
        # data directory like the app's.
        self.pairing = pairing
        self._owns_pairing = False

        self.gamepad = None
        self.sock: socket.socket | None = None
        self.beacon: Beacon | None = None
        self.receiver: Receiver | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        """Raises PadUnavailable or OSError if the pad or port is unavailable.

        On failure nothing is left behind: no socket, no pad, no thread.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Deliberately no SO_REUSEADDR. On Windows it lets a second process
            # bind the same UDP port; both then report success while the
            # datagrams reach only one of them. Failing loudly on the second
            # instance is far better than a receiver that looks healthy and
            # receives nothing.
            #
            # 0.0.0.0 rather than one address: the PC's LAN address changes
            # with DHCP and docks, multi-homed machines may reach the phone
            # through any adapter, and loopback has to work for tests. Who may
            # send is decided per packet by allowed_source() instead.
            sock.bind(("0.0.0.0", self.port))
            sock.settimeout(0.25)
        except BaseException:
            sock.close()
            raise
        # Port 0 asks the OS for a free one; report the one we really got.
        self.port = sock.getsockname()[1]
        self.sock = sock

        # Only now create the pad. The other order meant a second instance
        # plugged in a second virtual controller before discovering the port
        # was taken, and games briefly saw two pads.
        try:
            if self.pairing is None:
                self.pairing = PairingManager(PairingStore(on_status=self.on_status))
                self._owns_pairing = True

            self.gamepad = self.pad_factory(self.pad_kind)

            self.receiver = Receiver(self.gamepad, sock, verbose=self.verbose,
                                     on_state=self.on_state, on_status=self.on_status,
                                     blocked_by=self.blocked_by, pairing=self.pairing)
            if self.pairing.auto_allow:
                self.receiver.status("[pair] TEST MODE: every pairing request is allowed "
                                     f"automatically ({pairing.TEST_AUTO_ALLOW_ENV}=1)")

            if self.use_beacon:
                self.beacon = Beacon(self.port, self.beacon_port,
                                     on_status=self._beacon_status,
                                     paused=self._linked,
                                     pc_id=self.pairing.store.pc_id)
                self.beacon.start()

            self._stop.clear()
            self._thread = threading.Thread(target=self._run, name="dslink-recv",
                                            daemon=True)
            self._thread.start()
        except BaseException:
            self.stop()
            raise

    def _linked(self) -> bool:
        receiver = self.receiver
        return bool(receiver and receiver.linked)

    def _beacon_status(self, message: str) -> None:
        receiver = self.receiver
        if receiver:
            receiver.status(message)
        elif self.on_status:
            self.on_status(message)

    def _run(self) -> None:
        """The receive loop. Must never die while the service is running.

        When it did, the watchdog died with it: held inputs stayed pressed in
        the game forever and the UI kept showing LIVE, with nothing on screen
        to say why (the windowed build has no console for a traceback).
        """
        sock, receiver = self.sock, self.receiver
        while not self._stop.is_set():
            try:
                try:
                    data, addr = sock.recvfrom(RECV_BUFFER)
                except socket.timeout:
                    data = None
                except OSError as exc:
                    if self._stop.is_set():
                        break
                    code = getattr(exc, "winerror", None)
                    # WSAECONNRESET: a prior ack was refused by the peer
                    # (ICMP port unreachable). WSAEMSGSIZE: a datagram larger
                    # than the buffer, which Windows reports as an error and
                    # discards. Both are about one datagram, not the socket.
                    if code not in (WSAECONNRESET, WSAEMSGSIZE):
                        receiver.notice("recv", f"[error] receive failed: {exc}")
                        # Whatever this is, do not spin a core on it.
                        self._stop.wait(0.1)
                    data = None
                if data is not None:
                    receiver.process(data, addr)
                receiver.tick()
            except Exception as exc:
                # process() and tick() already contain their own errors; this
                # is the last line for anything else (an observer's print on a
                # closed console, say).
                try:
                    receiver.fault("receive loop", exc)
                except Exception:
                    pass
                self._stop.wait(0.1)

    def stop(self) -> None:
        self._stop.set()
        if self.beacon:
            self.beacon.stop()
            self.beacon = None
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

        if self.gamepad:
            try:
                self.gamepad.release()
            except Exception:
                pass  # the driver is already gone; nothing left to release
            self.gamepad = None
        # vgamepad only calls vigem_target_remove from __del__, so the virtual
        # device survives until the last reference is collected. The receiver
        # holds one too; leaving it alive is what used to strand an Xbox pad on
        # the system after switching to DualShock 4, so games saw both and
        # picked the wrong one. Drop every reference, then collect now rather
        # than whenever GC feels like it.
        if self.receiver:
            self.receiver.gamepad = None
            self.receiver = None
        gc.collect()

        if self.sock:
            self.sock.close()
            self.sock = None

        if self._owns_pairing and self.pairing is not None:
            # Writes a pending highest_session before the process can exit.
            self.pairing.store.close()
            self.pairing = None
            self._owns_pairing = False


class ConsolePairing:
    """Pairing prompts on the terminal: print the code, read y/n from stdin.

    There is only ever one prompt open, so one reader thread and one "current
    prompt" are all it takes. The answer is tied to the prompt it was typed
    for; a y that arrives after that prompt closed approves nothing.
    """

    def __init__(self) -> None:
        self.manager: PairingManager | None = None
        self.say: Callable[[str], None] = print
        self._prompt = None
        self._lock = threading.Lock()

    def on_change(self, kind: str, prompt) -> None:
        if kind == "open":
            with self._lock:
                self._prompt = prompt
            self.say(f"[pair] {prompt.name} wants to pair with this PC.")
            self.say(f"[pair] Check the phone shows   {pairing.format_code(prompt.code)}")
            self.say(f"[pair] Type y and Enter to allow, anything else to deny "
                     f"({int(PairingManager.PROMPT_TIMEOUT)} s)")
            return
        with self._lock:
            if prompt is not None and self._prompt is not None \
                    and self._prompt.id == prompt.id:
                self._prompt = None
        if kind == "allowed":
            self.say(f"[pair] paired {prompt.name}")
        elif kind == "denied":
            self.say(f"[pair] denied {prompt.name}")
        elif kind == "timeout":
            self.say(f"[pair] nobody answered the request from {prompt.name}; denied")

    def read_answers(self) -> None:
        stream = sys.stdin
        if stream is None:
            return
        while True:
            try:
                line = stream.readline()
            except (OSError, ValueError):
                return
            if not line:
                return   # EOF: nobody to ask, so every prompt times out
            with self._lock:
                prompt = self._prompt
            if prompt is None or self.manager is None:
                continue
            self.manager.answer(prompt.id, line.strip().lower() in ("y", "yes"))


def _list_phones(store: PairingStore) -> list:
    phones = store.phones()
    if not phones:
        print("No phones are paired with this PC.")
    for i, p in enumerate(phones, 1):
        print(f"  {i}. {p.name}   paired {p.paired_at}")
    return phones


def main() -> int:
    parser = argparse.ArgumentParser(description="DSLINK receiver: Android gamepad to virtual Xbox pad.")
    parser.add_argument("--port", type=int, default=DEFAULT_INPUT_PORT,
                        help=f"UDP port to listen on (default {DEFAULT_INPUT_PORT})")
    parser.add_argument("--beacon-port", type=int, default=DEFAULT_BEACON_PORT,
                        help=f"UDP port to broadcast discovery on (default {DEFAULT_BEACON_PORT})")
    parser.add_argument("--no-beacon", action="store_true",
                        help="do not broadcast; type the host IP into the client manually")
    parser.add_argument("--pad", choices=("x360", "ds4"), default="x360",
                        help="virtual pad type: x360 (XInput, works everywhere) "
                             "or ds4 (PlayStation prompts, HID only)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="do not print the live input readout")
    parser.add_argument("--phones", action="store_true",
                        help="list the phones paired with this PC and exit")
    parser.add_argument("--forget", metavar="N",
                        help="unpair phone number N from --phones (or 'all') and exit")
    args = parser.parse_args()

    if args.phones or args.forget:
        store = PairingStore(on_status=print)
        phones = _list_phones(store)
        if args.forget:
            if args.forget == "all":
                chosen = phones
            elif args.forget.isdigit() and 1 <= int(args.forget) <= len(phones):
                chosen = [phones[int(args.forget) - 1]]
            else:
                return print(f"No phone number {args.forget}.") or 1
            for p in chosen:
                store.remove(p.id)
                print(f"Forgot {p.name}. It has to pair again to connect.")
        return 0

    if sys.platform != "win32":
        return print("This receiver needs Windows and ViGEmBus.") or 1

    try:
        from version import VERSION as app_version
    except ImportError:
        app_version = ""

    console = ConsolePairing()
    try:
        store = PairingStore(on_status=print)
    except OSError as exc:
        print(f"Cannot open the pairing store in {pairing.data_dir()}: {exc}")
        return 1
    manager = PairingManager(store, on_change=console.on_change)
    console.manager = manager

    service = ReceiverService(port=args.port, beacon_port=args.beacon_port,
                              beacon=not args.no_beacon, verbose=not args.quiet,
                              pad_kind=args.pad, pairing=manager)
    try:
        service.start()
    except PadUnavailable as exc:
        print(exc)
        return 1
    except OSError as exc:
        print(f"Cannot listen on UDP {args.port}: {exc}")
        print("Another copy of the receiver is probably already running.")
        return 1
    # Through the receiver, so a prompt wipes the live readout line first.
    console.say = service.receiver.status

    # Ctrl+C arrives as KeyboardInterrupt. Ctrl+Break (and the CTRL_BREAK_EVENT
    # a parent process can send) arrives as SIGBREAK, whose default is to kill
    # the process on the spot; catching it lets the finally below release the
    # pad and remove the virtual device properly.
    stop = threading.Event()
    for name in ("SIGBREAK", "SIGTERM"):
        sig = getattr(signal, name, None)
        if sig is not None:
            signal.signal(sig, lambda *_: stop.set())

    print(f"DSLINK receiver {app_version}".rstrip() + f" (protocol v{PROTOCOL_VERSION})")
    print("LudusCtrl by Josip Parlov (@parl0v). GNU AGPL 3.0 or later, no warranty; "
          "see LICENSE and NOTICE.")
    print(f"  listening    udp/{service.port}")

    ips = local_ips()
    primary = ips[0] if ips else None
    if primary:
        print(f"  PC address   {primary}   <-- type this into the app if it does not autofill")
    others = ips[1:]
    if others:
        # Usually Hyper-V/WSL/VMware/VirtualBox. Listed, but not as the answer.
        print(f"  other NICs   {', '.join(others)}")

    if args.no_beacon:
        print("  discovery    off, enter the address in the app manually")
    else:
        print(f"  discovery    broadcasting on udp/{args.beacon_port} "
              f"from every interface while no client is linked")
    print(f"  virtual pad  ready ({service.gamepad.kind})")
    print(f"  pairing      {len(store.phones())} phone(s) paired; a new phone asks here "
          "and you answer y to allow it")
    print("\nWaiting for a paired phone. Ctrl+C to stop.\n", flush=True)

    threading.Thread(target=console.read_answers, name="dslink-stdin", daemon=True).start()

    receiver = service.receiver
    try:
        # A short wait rather than a blocking one, so Ctrl+C is seen promptly.
        while not stop.wait(0.25):
            pass
    except KeyboardInterrupt:
        pass
    finally:
        print("\nstopping")
        service.stop()
        store.close()
        print(f"packets {receiver.packets}, acks {receiver.acks}, "
              f"out-of-order dropped {receiver.dropped}, "
              f"rejected {receiver.rejected}, "
              f"unauthenticated {receiver.unauthenticated}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
