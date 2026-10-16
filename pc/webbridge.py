# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Josip Parlov (@parl0v). See NOTICE for the attribution terms.
"""Browser bridge: a phone with no app installed acts as the Bluetooth source.

Why this exists: an iPhone cannot run the Android client, so an iPhone owner
has to borrow somebody else's phone for the whole session. The browser's
Gamepad API works on iOS Safari, so a page served off the PC closes that gap
with no install, no App Store and no developer account.

Four constraints shape the design.

1.  **The Gamepad API requires a secure context.** On plain HTTP,
    `navigator.getGamepads()` returns an empty array -- that is the spec, not
    a quirk, and Chrome and Firefox both enforce it. So the page has to be
    served over HTTPS even though it never leaves the LAN. No certificate
    authority will sign a private IP, so this generates a self-signed
    certificate and the phone is told to trust it once, by hand. There is no
    way around that step; it is the price of the API being locked down.

2.  **No new packages in the receive path.** `pc/` ships through PyInstaller
    into a 16 MB installer, so the WebSocket server here is stdlib only. The
    handshake is one SHA-1 and the framing is about sixty lines, which is
    cheaper than the download weight of a library. `cryptography` is imported
    only to mint the certificate, and only when one has to be issued.

3.  **One input body.** The browser sends the 20-byte v1 DSLINK body. The
    Android client wraps the same fields in a signed 36-byte v2 packet, so
    the button, stick and trigger decoding stays shared. The browser needs
    no MAC: TLS and the per-start token already authenticate it. See
    ../docs/PROTOCOL.md.

4.  **Anything on the LAN can reach the port.** A listener on 0.0.0.0 that
    drives a game controller is worth attacking from a shared Wi-Fi or from a
    web page open on some other device. So every server start mints a random
    token; the URL the PC shows carries it in the fragment (which browsers
    never send over the wire), the page hands it over as its first WebSocket
    message, and nothing is claimed without it. Cross-origin WebSocket
    upgrades are refused outright.

A side effect worth knowing: the browser normalises pads to the W3C "standard
gamepad" layout itself, using its own vendor tables. That sidesteps the class
of bug where an Android device ships no key layout for a pad and hands the app
shifted keycodes -- the browser path cannot inherit it, because it never sees
Android's mapping. Pads the browser cannot normalise are refused by the page.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import gc
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import socket
import socketserver
import ssl
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from dualsense_link import (
    ACK_INTERVAL,
    MAGIC,
    PACKET,
    PACKET_SIZE,
    VERSION,
    WATCHDOG_TIMEOUT,
    LAYOUT_UNKNOWN,
    PadState,
    PadUnavailable,
    create_gamepad,
    local_ips,
)
from pairing import data_dir, restrict_to_current_user

try:
    from version import VERSION as APP_VERSION
except ImportError:  # pragma: no cover - only if version.py was left out of a build
    APP_VERSION = "dev"

DEFAULT_WEB_PORT = 45991

# WATCHDOG_TIMEOUT is the receiver's, imported above, so both paths agree:
# release everything if the browser goes quiet, so no button can stick down
# inside a game when a phone sleeps or walks out of range.

# Every blocking step on a connection has a deadline. Without them one idle
# TCP connection (a port scanner, `nc`, a phone that suspended mid-handshake)
# used to hold the single accept thread forever: nobody else could connect and
# closing the app hung. The client pings once a second and sends a packet
# every frame, so five seconds of silence on a WebSocket means it is gone.
HANDSHAKE_TIMEOUT = 5.0
HTTP_TIMEOUT = 10.0
WS_READ_TIMEOUT = 5.0

# Plenty for one phone loading the page (browsers open up to six connections)
# plus its WebSocket, and a hard ceiling on threads for anything hostile.
MAX_CONNECTIONS = 16

# A switch destroys and recreates the virtual pad, which a running game sees
# as the controller being unplugged. Repeating that faster than this is never
# what anybody meant.
PAD_SWITCH_INTERVAL = 2.0

# Payloads here are a 20-byte packet or a short text command. Anything bigger
# is not one of ours.
MAX_FRAME = 4096

# RFC 6455. Concatenated with the client key, hashed, and echoed back; this is
# the whole of the WebSocket handshake.
WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_CONT, OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA

CLOSE_NORMAL, CLOSE_GOING_AWAY, CLOSE_PROTOCOL = 1000, 1001, 1002
CLOSE_POLICY, CLOSE_TOO_BIG = 1008, 1009

# _MEIPASS when frozen: PyInstaller unpacks bundled data to a temp directory,
# so __file__ points at the source tree only when running from source.
HERE = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
PAGE_DIR = HERE / "webui-mobile"

# Replaced in the served page, so the phone can say which PC build it talks to.
VERSION_PLACEHOLDER = "__LUDUSCTRL_VERSION__"


# --- Addresses ---------------------------------------------------------------

def _adapter_addresses() -> list[tuple[str, str, bool, bool]] | None:
    """(ip, adapter name, has a gateway, is Wi-Fi/Ethernet) for every IPv4
    address on an adapter that is up, or None where this cannot be asked.

    Windows only, through GetAdaptersAddresses. It is the one place that knows
    which adapter an address belongs to, and that is what separates the Wi-Fi
    the phone is on from a VPN tunnel, which is what the default route (and so
    `primary_ip()`) points at whenever a VPN is connected.
    """
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    class SOCKET_ADDRESS(ctypes.Structure):
        _fields_ = [("lpSockaddr", ctypes.c_void_p), ("iSockaddrLength", ctypes.c_int)]

    class UNICAST(ctypes.Structure):
        pass

    UNICAST._fields_ = [("Length", wintypes.ULONG), ("Flags", wintypes.DWORD),
                        ("Next", ctypes.POINTER(UNICAST)), ("Address", SOCKET_ADDRESS)]

    class GATEWAY(ctypes.Structure):
        pass

    GATEWAY._fields_ = [("Length", wintypes.ULONG), ("Reserved", wintypes.DWORD),
                        ("Next", ctypes.POINTER(GATEWAY)), ("Address", SOCKET_ADDRESS)]

    class ADAPTER(ctypes.Structure):
        pass

    ADAPTER._fields_ = [
        ("Length", wintypes.ULONG), ("IfIndex", wintypes.DWORD),
        ("Next", ctypes.POINTER(ADAPTER)),
        ("AdapterName", ctypes.c_char_p),
        ("FirstUnicastAddress", ctypes.POINTER(UNICAST)),
        ("FirstAnycastAddress", ctypes.c_void_p),
        ("FirstMulticastAddress", ctypes.c_void_p),
        ("FirstDnsServerAddress", ctypes.c_void_p),
        ("DnsSuffix", ctypes.c_wchar_p),
        ("Description", ctypes.c_wchar_p),
        ("FriendlyName", ctypes.c_wchar_p),
        ("PhysicalAddress", ctypes.c_ubyte * 8),
        ("PhysicalAddressLength", wintypes.ULONG),
        ("Flags", wintypes.ULONG),
        ("Mtu", wintypes.ULONG),
        ("IfType", wintypes.ULONG),
        ("OperStatus", ctypes.c_int),
        ("Ipv6IfIndex", wintypes.DWORD),
        ("ZoneIndices", wintypes.ULONG * 16),
        ("FirstPrefix", ctypes.c_void_p),
        ("TransmitLinkSpeed", ctypes.c_uint64),
        ("ReceiveLinkSpeed", ctypes.c_uint64),
        ("FirstWinsServerAddress", ctypes.c_void_p),
        ("FirstGatewayAddress", ctypes.POINTER(GATEWAY)),
    ]

    AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, ERROR_BUFFER_OVERFLOW = 2, 0x0080, 111
    IF_OPER_UP, IF_TYPE_ETHERNET, IF_TYPE_WIFI = 1, 6, 71

    try:
        fn = ctypes.windll.iphlpapi.GetAdaptersAddresses
    except (AttributeError, OSError):
        return None
    size = wintypes.ULONG(16 * 1024)
    for _ in range(3):
        buf = ctypes.create_string_buffer(size.value)
        rc = fn(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, None, buf, ctypes.byref(size))
        if rc != ERROR_BUFFER_OVERFLOW:
            break
    if rc != 0:
        return None

    out = []
    node = ctypes.cast(buf, ctypes.POINTER(ADAPTER))
    while node:
        a = node.contents
        if a.OperStatus == IF_OPER_UP:
            has_gateway = bool(a.FirstGatewayAddress)
            physical = a.IfType in (IF_TYPE_ETHERNET, IF_TYPE_WIFI)
            name = a.FriendlyName or ""
            u = a.FirstUnicastAddress
            while u:
                sa = u.contents.Address
                if sa.lpSockaddr and sa.iSockaddrLength >= 8:
                    raw = ctypes.string_at(sa.lpSockaddr, 8)
                    if struct.unpack_from("<H", raw, 0)[0] == AF_INET:
                        out.append((socket.inet_ntoa(raw[4:8]), name, has_gateway, physical))
                u = u.contents.Next
        node = a.Next
    return out


def _reachable(ip: str) -> bool:
    """A private IPv4 address, i.e. one a phone on the same LAN could dial."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and a.is_private and not (a.is_loopback or a.is_link_local)


def lan_addresses() -> list[tuple[str, str]]:
    """(ip, adapter name) for every private address, most likely LAN first.

    `local_ips()[0]` is the address on the default route, and with a VPN up
    that is the tunnel, which the phone cannot reach. Printing only that one is
    how a tester ends up staring at a page that never loads. So every candidate
    is listed, ranked: an adapter with a gateway that is real Wi-Fi or
    Ethernet first (the home network), then anything else with a gateway, then
    the rest (Hyper-V, WSL, VirtualBox host-only and most VPN tunnels). The
    adapter name goes alongside so the user can see which one is their Wi-Fi.
    """
    try:
        adapters = _adapter_addresses()
    except Exception:
        adapters = None

    if adapters:
        ranked = []
        for order, (ip, name, gateway, physical) in enumerate(adapters):
            if not _reachable(ip):
                continue
            rank = 0 if (gateway and physical) else 1 if gateway else 2
            ranked.append((rank, order, ip, name))
        ranked.sort()
        seen: set[str] = set()
        out = []
        for _, _, ip, name in ranked:
            if ip not in seen:
                seen.add(ip)
                out.append((ip, name))
        if out:
            return out

    # No adapter table: fall back to the address ranges home routers hand out,
    # which at least puts 192.168.x ahead of the 10.x and 172.16.x that VPNs
    # and Hyper-V favour.
    def rank(ip: str) -> int:
        return 0 if ip.startswith("192.168.") else 1 if ip.startswith("10.") else 2

    ips = [ip for ip in local_ips() if _reachable(ip)]
    return [(ip, "") for ip in sorted(ips, key=lambda ip: (rank(ip), ips.index(ip)))]


def browser_urls(port: int, token: str) -> list[dict]:
    """What to show the user: one full link per reachable address, best first."""
    return [{"ip": ip, "name": name, "url": f"https://{ip}:{port}/#t={token}"}
            for ip, name in lan_addresses()]


# --- Certificate -------------------------------------------------------------

CERT_DAYS = 825          # the most Apple platforms accept for a TLS server cert
RENEW_WITHIN_DAYS = 30
MAX_SAN_IPS = 32


def cert_dir(override: str | os.PathLike | None = None) -> Path:
    """Where the self-signed pair lives, next to the app's other state.

    LUDUSCTRL_CERT_DIR (or an explicit argument) points it elsewhere, which is
    what keeps the tests away from the real certificate a phone already trusts.
    Otherwise it follows the shared data directory (LUDUSCTRL_DATA_DIR).
    """
    if override is None:
        override = os.environ.get("LUDUSCTRL_CERT_DIR")
    if override:
        d = Path(override)
        d.mkdir(parents=True, exist_ok=True)
        return d
    return data_dir()


# Shared with the pairing store, which keeps its keys the same way.
_restrict_to_current_user = restrict_to_current_user


def _need_cryptography():
    try:
        import cryptography  # noqa: F401
    except ImportError:
        # "pip install" is useless advice inside a packaged build, so say what
        # is actually true for whichever way this is running.
        fix = ("This build was packaged without it. Rebuild with "
               "tools/build_exe.py, which no longer excludes it."
               if getattr(sys, "frozen", False)
               else "Run:  pip install cryptography")
        raise SystemExit(
            "The browser client needs `cryptography` to mint its HTTPS "
            "certificate.\n\n" + fix + "\n\n"
            "It is needed once; the certificate is cached afterwards. "
            "Everything else, including the UDP receiver, works without it."
        )


def _reissue_reason(cert, key, primary: str | None) -> str | None:
    """Why the certificate on disk must be replaced, or None to keep it.

    Deliberately conservative. Every new certificate is a new warning the user
    has to click through on every phone, so a VPN coming up or a Hyper-V
    switch appearing is not a reason by itself; only the address a phone is
    actually told to use not being covered is.
    """
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID

    if cert.public_key().public_numbers() != key.public_key().public_numbers():
        return "key does not match"
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if bc.ca:
            # The first releases issued a CA-flagged leaf. iOS treats that as
            # a root to be installed, not a site certificate, so replace it
            # once, on the upgrade.
            return "old CA-style certificate"
    except x509.ExtensionNotFound:
        return "no basic constraints"
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
            return "not a server certificate"
    except x509.ExtensionNotFound:
        return "not a server certificate"

    start, end = cert.not_valid_before_utc, cert.not_valid_after_utc
    if (end - start).days > CERT_DAYS + 1:
        return "validity too long for Apple platforms"
    if end - datetime.datetime.now(datetime.timezone.utc) < datetime.timedelta(days=RENEW_WITHIN_DAYS):
        return "expiring"

    if primary:
        try:
            sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            covered = {str(ip) for ip in sans.get_values_for_type(x509.IPAddress)}
        except x509.ExtensionNotFound:
            covered = set()
        if primary not in covered:
            return f"{primary} not covered"
    return None


def ensure_cert(directory: str | os.PathLike | None = None) -> tuple[Path, Path]:
    """Return (cert, key), issuing a certificate only when one is needed.

    The key is kept across reissues. The certificate carries the LAN
    addresses as SANs, because the phone connects by address and iOS validates
    the SAN rather than the CN; addresses from earlier certificates are carried
    forward, so a laptop moving between two networks settles on one
    certificate instead of alternating.
    """
    _need_cryptography()
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    d = cert_dir(directory)
    cert_path, key_path = d / "web-cert.pem", d / "web-key.pem"

    lan = [ip for ip, _ in lan_addresses()]
    primary = lan[0] if lan else None

    key = None
    if key_path.exists():
        try:
            key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
                key = None
        except (ValueError, TypeError, OSError):
            key = None

    old = None
    if key is not None and cert_path.exists():
        try:
            old = x509.load_pem_x509_certificate(cert_path.read_bytes())
        except (ValueError, OSError):
            old = None
        if old is not None and _reissue_reason(old, key, primary) is None:
            return cert_path, key_path

    new_key = key is None
    if new_key:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    ips: list[str] = []
    for ip in [*lan, *local_ips(), "127.0.0.1"]:
        if ip not in ips:
            ips.append(ip)
    if old is not None:
        try:
            sans = old.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            for ip in sans.get_values_for_type(x509.IPAddress):
                if str(ip) not in ips:
                    ips.append(str(ip))
        except x509.ExtensionNotFound:
            pass
    ips = ips[:MAX_SAN_IPS]

    san: list[x509.GeneralName] = [x509.DNSName("localhost")]
    for ip in ips:
        try:
            san.append(x509.IPAddress(ipaddress.ip_address(ip)))
        except ValueError:
            continue

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LudusCtrl")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now - datetime.timedelta(days=1) + datetime.timedelta(days=CERT_DAYS))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        # An end-entity certificate for a TLS server, and nothing else. A
        # CA-flagged leaf is what iOS offers to install as a profile instead of
        # simply letting the user proceed past the warning.
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=True, content_commitment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .sign(key, hashes.SHA256())
    )

    if new_key:
        tmp = key_path.with_suffix(".tmp")
        tmp.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        os.replace(tmp, key_path)
        _restrict_to_current_user(key_path)

    tmp = cert_path.with_suffix(".tmp")
    tmp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    os.replace(tmp, cert_path)

    # Left over from the first releases, which reissued whenever this changed.
    try:
        (d / "web-cert.ips").unlink()
    except OSError:
        pass

    return cert_path, key_path


# --- WebSocket framing -------------------------------------------------------

class FrameError(Exception):
    """A frame this server will not accept. Carries the RFC 6455 close code."""

    def __init__(self, code: int, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


def ws_accept(key: str) -> str:
    digest = hashlib.sha1(key.encode("ascii") + WS_GUID).digest()
    return base64.b64encode(digest).decode("ascii")


def read_exact(rfile, n: int) -> bytes | None:
    """Read exactly n bytes, or None if the peer closed mid-frame."""
    buf = b""
    while len(buf) < n:
        chunk = rfile.read(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def read_frame(rfile) -> tuple[int, bytes] | None:
    """Return (opcode, payload), or None when the connection ends.

    Raises FrameError for anything that is not a well-formed, masked, single
    frame of sane size. The caller must then close the connection: the
    payload of a refused frame is never read, so whatever follows on the
    socket is not a frame boundary any more.

    Continuation frames are not reassembled: every payload here is a single
    20-byte packet or a short command that cannot be fragmented in practice,
    and pretending to support fragmentation without testing it would be worse
    than refusing it.
    """
    head = read_exact(rfile, 2)
    if head is None:
        return None
    fin = bool(head[0] & 0x80)
    opcode = head[0] & 0x0F
    masked = bool(head[1] & 0x80)
    length = head[1] & 0x7F

    if head[0] & 0x70:
        raise FrameError(CLOSE_PROTOCOL, "reserved bits set")
    if opcode not in (OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG) or not fin:
        raise FrameError(CLOSE_PROTOCOL, "fragmented or unknown frame")
    if opcode >= OP_CLOSE and length > 125:
        raise FrameError(CLOSE_PROTOCOL, "oversized control frame")

    if length == 126:
        ext = read_exact(rfile, 2)
        if ext is None:
            return None
        length = struct.unpack(">H", ext)[0]
    elif length == 127:
        ext = read_exact(rfile, 8)
        if ext is None:
            return None
        length = struct.unpack(">Q", ext)[0]

    # A browser always masks; a frame that is not masked is not a browser, and
    # RFC 6455 says the server must close rather than guess.
    if not masked:
        raise FrameError(CLOSE_PROTOCOL, "unmasked frame")
    if length > MAX_FRAME:
        raise FrameError(CLOSE_TOO_BIG, "frame too large")

    mask = read_exact(rfile, 4)
    if mask is None:
        return None
    payload = read_exact(rfile, length)
    if payload is None:
        return None

    return opcode, bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


def write_frame(wfile, opcode: int, payload: bytes = b"") -> None:
    """Server frames are never masked, per RFC 6455."""
    head = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        head += bytes([n])
    elif n < (1 << 16):
        head += bytes([126]) + struct.pack(">H", n)
    else:
        head += bytes([127]) + struct.pack(">Q", n)
    wfile.write(head + payload)
    wfile.flush()


class Conn:
    """One browser session. Doubles as the identity the bridge compares.

    Only the connection's own handler thread ever writes to it, because an
    OpenSSL connection must not be read and written from two threads at once;
    the watchdog therefore never touches a socket, it only drops the claim,
    and the handler notices and says so on its next read.
    """

    def __init__(self, wfile) -> None:
        self.wfile = wfile
        self.closed = False

    def send(self, opcode: int, payload: bytes = b"") -> bool:
        if self.closed:
            return False
        try:
            write_frame(self.wfile, opcode, payload)
            return True
        except (OSError, ValueError):
            self.closed = True
            return False

    def text(self, message: str) -> bool:
        return self.send(OP_TEXT, message.encode("utf-8"))

    def close(self, code: int = CLOSE_NORMAL, reason: str = "") -> None:
        self.send(OP_CLOSE, struct.pack(">H", code) + reason.encode("utf-8")[:120])
        self.closed = True


# --- Bridge ------------------------------------------------------------------

class WebBridge:
    """Owns the virtual pad and the state shared across browser sessions."""

    def __init__(self, gamepad=None, verbose: bool = False, on_state=None,
                 pad_kind: str = "x360", pad_getter=None, pad_switcher=None,
                 kind_getter=None, link_getter=None, token: str | None = None) -> None:
        """Either owns a virtual pad, or borrows the host application's.

        Standalone (`gamepad` given) it creates and destroys its own pad. When
        the desktop app hosts it, that app already owns one, and a second would
        show up in Windows as a second controller -- games default to the first
        and appear dead. So the app passes getters instead: the bridge never
        holds a reference of its own, which also means it cannot strand a
        device when the app rebuilds the pad underneath it.

        `link_getter`, when given, reports whether the Android app is linked
        over UDP right now; while it is, no browser may take the pad.
        """
        self.gamepad = gamepad
        self._pad_kind = pad_kind
        self.pad_getter = pad_getter
        self.pad_switcher = pad_switcher
        self.kind_getter = kind_getter
        self.link_getter = link_getter
        self.verbose = verbose
        self.on_state = on_state

        # 128 bits, fresh on every start. Anyone holding the URL the PC shows
        # can drive the pad; anyone else on the network cannot.
        self.token = token or secrets.token_urlsafe(16)

        self.lock = threading.Lock()
        self.packets = 0
        self.last_packet_at = 0.0
        self.pad_live = False
        self.evictions = 0
        self._last_switch_at = 0.0

        # Only one browser may drive the pad. A second tab silently fighting
        # the first for the sticks would be impossible to diagnose from the
        # phone, so later arrivals are refused with a message they can read.
        self.driver: object | None = None

    @property
    def pad_kind(self) -> str:
        return self.kind_getter() if self.kind_getter else self._pad_kind

    def current_pad(self):
        """The pad to drive right now, or None while the host is rebuilding it."""
        return self.pad_getter() if self.pad_getter else self.gamepad

    def check_token(self, offered: bytes) -> bool:
        # Constant time, so the token cannot be recovered a byte at a time
        # from response timing.
        return hmac.compare_digest(offered, self.token.encode("ascii"))

    def driving(self) -> bool:
        """True while a browser holds the pad. Lock-free on purpose: the UDP
        receive thread asks this for every packet, at up to 500 Hz."""
        return self.driver is not None

    def is_driver(self, who: object) -> bool:
        return self.driver is who

    def claim(self, who: object) -> str | None:
        """Take the pad for `who`. Returns None, or the refusal to send them."""
        with self.lock:
            if self.driver is who:
                return None
            # The Android app got there first. Two sources on one pad would
            # fight frame by frame, so the second one is told why it is idle.
            if self.link_getter is not None:
                try:
                    if self.link_getter():
                        return "busy:app"
                except Exception:
                    pass
            stale = (
                self.driver is not None
                and time.monotonic() - self.last_packet_at > WATCHDOG_TIMEOUT
            )
            if self.driver is None or stale:
                self.driver = who
                self.last_packet_at = time.monotonic()
                return None
            return "busy"

    def release(self, who: object) -> None:
        """Let go of the pad, but only if `who` was holding it.

        A refused second browser, or a session the watchdog already evicted,
        disconnecting must not zero the pad under whoever is driving it now.
        """
        with self.lock:
            if self.driver is not who:
                return
            self.driver = None
            self.pad_live = False
        self._neutral()

    def handle(self, who: object, data: bytes) -> tuple[int, bool] | None:
        """Apply one packet. Returns (seq, applied), or None if it was refused.

        `applied` is False when the packet was valid but no pad exists to take
        it (the host is mid-rebuild, or a switch failed); the phone is told, so
        its LIVE lamp means input is reaching Windows rather than merely that a
        socket is open.
        """
        # Exactly 20, as on UDP. A longer frame is not a newer client, it is
        # not a client of this protocol at all.
        if len(data) != PACKET_SIZE:
            return None
        magic, version, seq, buttons, lx, ly, rx, ry, lt, rt, flags, layout = \
            PACKET.unpack(data)
        if magic != MAGIC or version != VERSION:
            return None
        pad_connected = bool(flags & 0x01)
        with self.lock:
            if self.driver is not who:
                return None
            self.packets += 1
            self.last_packet_at = time.monotonic()
            self.pad_live = pad_connected

        # Fetched per packet rather than cached, so a pad rebuilt underneath
        # this bridge is picked up on the very next one. None means the host is
        # mid-rebuild, or a switch failed; drop input rather than raise.
        pad = self.current_pad()
        if pad is None:
            return seq, False
        if pad_connected:
            pad.apply(buttons, lx, ly, rx, ry, lt, rt)
        else:
            # Same as UDP: no controller on the phone means nothing held here.
            pad.release()
        self._publish(PadState(buttons, lx, ly, rx, ry, lt, rt, pad_connected, layout))
        return seq, True

    def request_switch(self, who: object, kind: str) -> tuple[bool, str]:
        """A browser asking for the other pad type. Returns (ok, message)."""
        with self.lock:
            if self.driver is not who:
                return False, "only the phone driving the pad can switch it"
            now = time.monotonic()
            if now - self._last_switch_at < PAD_SWITCH_INTERVAL:
                return False, "wait a moment before switching again"
            self._last_switch_at = now
        ok, msg = self.switch_pad(kind)
        with self.lock:
            # The switch can take a while; that is not the phone going quiet.
            if self.driver is who:
                self.last_packet_at = time.monotonic()
        return ok, msg

    def switch_pad(self, kind: str) -> tuple[bool, str]:
        """Replace the virtual pad with the other kind. Returns (ok, message).

        A ViGEm target cannot change kind in place, so the old one has to be
        destroyed before the new one is made -- and destroyed properly.
        `vgamepad` only calls vigem_target_remove from __del__, so the device
        survives until the last reference is collected. Leaving one alive is
        what used to strand an Xbox pad on the system after switching to
        DualShock 4, so games saw both and picked the wrong one.

        The consequence of that ordering is that a failed create leaves no pad
        at all. That is reported rather than papered over; the user can switch
        back, and `handle` drops input meanwhile instead of raising.
        """
        if kind not in ("x360", "ds4"):
            return False, "unknown pad kind"

        # The host owns the pad and knows how to rebuild it (it has a UDP
        # receiver wired to the same device). Doing it here as well would
        # leave that receiver pointing at a released pad.
        if self.pad_switcher is not None:
            return self.pad_switcher(kind)

        with self.lock:
            if kind == self._pad_kind and self.gamepad is not None:
                return True, self.pad_kind
            old, self.gamepad = self.gamepad, None

        if old is not None:
            try:
                old.release()
            except Exception:
                pass
        del old
        gc.collect()   # now, rather than whenever GC feels like it

        try:
            pad = create_gamepad(kind)
        except PadUnavailable as exc:
            return False, str(exc).splitlines()[0]

        with self.lock:
            self.gamepad = pad
            self._pad_kind = kind
        return True, kind

    def tick_watchdog(self) -> None:
        """Drop the claim of a driver that stopped sending.

        The session itself is closed by its own handler thread, which sees it
        is no longer the driver on its next read (or its read deadline) and
        tells the phone "evicted", so the phone reconnects and claims afresh
        instead of showing LIVE over a link that is being ignored.
        """
        with self.lock:
            if self.driver is None or self.last_packet_at == 0.0:
                return
            if time.monotonic() - self.last_packet_at <= WATCHDOG_TIMEOUT:
                return
            self.driver = None
            self.pad_live = False
            self.evictions += 1
        self._neutral()

    def _neutral(self) -> None:
        pad = self.current_pad()
        if pad is not None:
            try:
                pad.release()
            except Exception:
                pass
        self._publish(PadState(0, 0, 0, 0, 0, 0, 0, False, LAYOUT_UNKNOWN))

    def _publish(self, state: PadState) -> None:
        if self.on_state is not None:
            try:
                self.on_state(state)
            except Exception:
                # An observer must never be able to stall the input path.
                pass


# --- HTTP / WebSocket server ---------------------------------------------------

_INLINE = re.compile(r"<(script|style)>(.*?)</\1>", re.S)


def render_page(path: Path) -> tuple[bytes, str]:
    """The phone page with the version filled in, and a CSP to serve it with.

    The CSP pins the page's own inline script and style by hash, computed here
    from exactly what is sent, so nothing injected into the page could run
    even if something were. Newlines are normalised first because the HTML
    parser does that before hashing, and a Windows checkout has CRLF.
    """
    html = path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
    html = html.replace(VERSION_PLACEHOLDER, APP_VERSION)
    hashes = {"script": [], "style": []}
    for kind, body in _INLINE.findall(html):
        digest = base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode()
        hashes[kind].append(f"'sha256-{digest}'")
    csp = "; ".join([
        "default-src 'self'",
        "connect-src 'self' wss:",
        "img-src 'self' data:",
        "script-src " + (" ".join(hashes["script"]) or "'none'"),
        "style-src " + (" ".join(hashes["style"]) or "'none'"),
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
    ])
    return html.encode("utf-8"), csp


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = HTTP_TIMEOUT
    server_version = "LudusCtrl"
    sys_version = ""

    _csp = "default-src 'none'; frame-ancestors 'none'"

    def setup(self):
        # The TLS handshake runs here, on this connection's own thread and
        # under a deadline. Done in accept() it ran on the one thread that
        # serves everybody, with no deadline at all.
        self.request.settimeout(HANDSHAKE_TIMEOUT)
        self.request.do_handshake()
        super().setup()

    def log_message(self, fmt, *args):
        if self.server.verbose:  # type: ignore[attr-defined]
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def end_headers(self):
        # On every response, errors included.
        self.send_header("Content-Security-Policy", self._csp)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        # The page is the app; a stale cached copy after an update would be
        # indistinguishable from a bug.
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/ws":
            self.serve_ws()
            return
        # One request per connection. A phone loading the page keeps idle
        # keep-alive sockets open otherwise, each holding a connection slot.
        self.close_connection = True
        if path in ("/", "/index.html"):
            self.serve_page()
        else:
            self.send_error(404)

    def send_error(self, code, message=None, explain=None):
        self.close_connection = True
        super().send_error(code, message, explain)

    def serve_page(self) -> None:
        try:
            body, csp = render_page(PAGE_DIR / "index.html")
        except OSError:
            self.send_error(404)
            return
        self._csp = csp
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    # --- WebSocket ---------------------------------------------------------

    def serve_ws(self) -> None:
        # Whatever happens from here on, this socket never goes back to being
        # parsed as HTTP. Falling through used to let the tail of a refused
        # frame be read as a fresh request.
        self.close_connection = True
        bridge: WebBridge = self.server.bridge  # type: ignore[attr-defined]

        key = self.headers.get("Sec-WebSocket-Key")
        if not key or "websocket" not in self.headers.get("Upgrade", "").lower():
            self.send_error(400)
            return

        # Browsers always send Origin on a WebSocket upgrade, and a page from
        # any other site (or another device's port) would carry its own. Only
        # our own page may connect. A missing Origin is not a browser; it
        # still has to present the token.
        origin = self.headers.get("Origin")
        host = self.headers.get("Host", "")
        if origin is not None and origin.lower() != f"https://{host}".lower():
            self.send_error(403, "Cross-origin WebSocket refused")
            return

        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", ws_accept(key))
        self.end_headers()
        self.wfile.flush()

        conn = Conn(self.wfile)
        self.connection.settimeout(WS_READ_TIMEOUT)
        try:
            if not self._authenticate(conn, bridge):
                return
            refusal = bridge.claim(conn)
            if refusal is not None:
                conn.text(refusal)
                conn.close(CLOSE_NORMAL, refusal)
                self._linger()
                return
            try:
                self._session(conn, bridge)
            finally:
                # Whatever happened, the pad must not be left holding anything.
                bridge.release(conn)
        except (OSError, ssl.SSLError):
            pass

    def _authenticate(self, conn: Conn, bridge: WebBridge) -> bool:
        """The first message must be `auth:<token>`, within the read deadline."""
        try:
            frame = read_frame(self.rfile)
        except FrameError as exc:
            conn.close(exc.code, exc.reason)
            return False
        except TimeoutError:
            conn.close(CLOSE_POLICY, "no token")
            return False
        if frame is None:
            return False
        opcode, payload = frame
        if opcode == OP_TEXT and payload.startswith(b"auth:") and bridge.check_token(payload[5:]):
            return True
        # Tell the page, so it can say "open the link the PC shows" instead of
        # retrying forever with a token from a previous run.
        conn.text("denied")
        conn.close(CLOSE_POLICY, "bad token")
        self._linger()
        return False

    def _session(self, conn: Conn, bridge: WebBridge) -> None:
        conn.text("ready")
        conn.text("padkind:" + bridge.pad_kind)
        kind_sent = bridge.pad_kind
        last_ack = 0.0

        while True:
            try:
                frame = read_frame(self.rfile)
            except FrameError as exc:
                conn.close(exc.code, exc.reason)
                self._linger()
                return
            except TimeoutError:
                # Five seconds of nothing, not even a ping. The watchdog has
                # long since dropped the claim.
                if not bridge.is_driver(conn):
                    conn.text("evicted")
                conn.close(CLOSE_GOING_AWAY, "idle")
                return
            if frame is None:
                return

            if not bridge.is_driver(conn):
                # Evicted by the watchdog (or a stale claim was taken over)
                # while this socket stayed open. Say so and close, so the page
                # runs its reconnect path and claims again instead of
                # showing LIVE over a link that is being ignored.
                conn.text("evicted")
                conn.close(CLOSE_NORMAL, "evicted")
                self._linger()
                return

            opcode, payload = frame
            if opcode == OP_BINARY:
                result = bridge.handle(conn, payload)
                now = time.monotonic()
                if result is not None and now - last_ack >= ACK_INTERVAL:
                    # Mirrors the UDP ack: the seq just applied, the total
                    # accepted, and whether it actually reached a pad.
                    last_ack = now
                    seq, applied = result
                    conn.text(f"ack:{seq}:{bridge.packets}:{1 if applied else 0}")
                    # The desktop window can switch the pad too; keep the
                    # phone's control honest without it having to ask.
                    kind = bridge.pad_kind
                    if kind != kind_sent:
                        kind_sent = kind
                        conn.text("padkind:" + kind)
            elif opcode == OP_TEXT and payload.startswith(b"pad:"):
                ok, msg = bridge.request_switch(conn, payload[4:].decode("ascii", "replace"))
                if ok:
                    kind_sent = msg
                conn.text(("padkind:" if ok else "paderr:") + msg)
            elif opcode == OP_TEXT and payload.startswith(b"ping:"):
                # Application-level echo, because browsers do not expose
                # WebSocket ping/pong to JavaScript. The client times the
                # round trip itself; the token is opaque here.
                conn.send(OP_TEXT, b"pong:" + payload[5:64])
            elif opcode == OP_PING:
                conn.send(OP_PONG, payload)
            elif opcode == OP_CLOSE:
                # Echo the status code, as RFC 6455 asks. Without the echo the
                # browser waits out its own close timeout before onclose fires.
                conn.send(OP_CLOSE, payload[:2])
                return

    def _linger(self) -> None:
        """After our close frame, read briefly until the peer's close arrives.

        Closing a TCP socket with unread input makes Windows send a reset,
        and a reset can destroy the text frame just sent (the "busy" or
        "denied" that tells the phone why) before the phone reads it.
        """
        try:
            self.connection.settimeout(1.0)
            deadline = time.monotonic() + 1.0
            while time.monotonic() < deadline:
                frame = read_frame(self.rfile)
                if frame is None or frame[0] == OP_CLOSE:
                    return
        except (FrameError, OSError, ValueError):
            pass


class BridgeServer(ThreadingHTTPServer):
    daemon_threads = True
    verbose = False
    bridge: WebBridge

    # server_close() would otherwise join every handler thread. One of them
    # can be inside the host's pad switch, waiting on a lock the host holds
    # while it closes this server, and that join would never return. Sessions
    # are unblocked by closing their sockets instead; see server_close.
    block_on_close = False

    # ThreadingHTTPServer sets this to 1, which on Windows means SO_REUSEADDR
    # lets a SECOND bridge bind a port the first one is already listening on.
    # Both then accept connections, the phone reaches whichever wins the race,
    # and input appears to half-work with nothing in any log to explain it.
    # Failing the bind is the only honest outcome.
    allow_reuse_address = False

    def __init__(self, *args, **kwargs) -> None:
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self._active: set = set()
        self._active_lock = threading.Lock()
        self.closing = threading.Event()
        super().__init__(*args, **kwargs)

    def server_bind(self):
        # HTTPServer.server_bind does a reverse DNS lookup of the bind address
        # purely to fill in server_name, which nothing here uses and which can
        # stall for seconds on a network with a slow resolver.
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name, self.server_port = host, port

    @property
    def port(self) -> int:
        return self.server_address[1]

    def process_request(self, request, client_address):
        # Past the cap, refuse at once rather than queue: a flood of idle
        # connections must not be able to spawn unbounded threads.
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        with self._active_lock:
            self._active.add(request)
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._active_lock:
                self._active.discard(request)
            self._slots.release()

    def server_close(self):
        """Stop listening and drop every open session, so the phone sees the
        link end at once and the pad is released on the way out."""
        self.closing.set()
        with self._active_lock:
            active = list(self._active)
        for sock in active:
            try:
                # The OS-level call only, not SSLSocket.shutdown, which would
                # tear the TLS state out from under the thread reading it.
                socket.socket.shutdown(sock, socket.SHUT_RDWR)
            except OSError:
                pass
        super().server_close()

    def handle_error(self, request, client_address):
        """Stay quiet when a phone simply goes away.

        A tab closing, a screen locking or a walk out of Wi-Fi range all
        surface as a reset or a truncated TLS record, and a port scan as a
        failed handshake. socketserver's default prints a full traceback for
        each, which would bury the pad readout in stack traces during ordinary
        use. Anything else is still reported.
        """
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionError, TimeoutError, ssl.SSLError)):
            return
        super().handle_error(request, client_address)


def serve(gamepad=None, port: int = DEFAULT_WEB_PORT, verbose: bool = False,
          on_state=None, pad_kind: str = "x360", pad_getter=None,
          pad_switcher=None, kind_getter=None, link_getter=None,
          token: str | None = None, cert_directory=None,
          host: str = "0.0.0.0") -> tuple[BridgeServer, WebBridge]:
    """Start the HTTPS + WebSocket server. Returns (server, bridge).

    Pass `gamepad` to have the bridge own a pad, or the three getters to have
    it borrow the host application's. See WebBridge.__init__ for why a host
    must not hand over a plain reference. Port 0 picks a free one; read it
    back from `server.port`. Stop with server.shutdown() then server_close().
    """
    cert, key = ensure_cert(cert_directory)

    bridge = WebBridge(gamepad, verbose=verbose, on_state=on_state,
                       pad_kind=pad_kind, pad_getter=pad_getter,
                       pad_switcher=pad_switcher, kind_getter=kind_getter,
                       link_getter=link_getter, token=token)

    try:
        server = BridgeServer((host, port), Handler)
    except OSError as exc:
        raise SystemExit(
            f"Could not listen on port {port}: {exc}\n\n"
            "The bridge is probably already running. Close the other copy, or\n"
            "start this one with --port on a free port."
        )
    server.verbose = verbose
    # Per server, not per class: a second bridge in the same process must not
    # redirect the first one's connections to itself.
    server.bridge = bridge

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    # Handshake deferred to the connection's own thread; see Handler.setup.
    server.socket = ctx.wrap_socket(server.socket, server_side=True,
                                    do_handshake_on_connect=False)

    threading.Thread(target=server.serve_forever, name="webbridge-accept",
                     daemon=True).start()

    def watchdog():
        while not server.closing.wait(0.25):
            bridge.tick_watchdog()

    threading.Thread(target=watchdog, name="webbridge-watchdog", daemon=True).start()
    return server, bridge


def main() -> int:
    ap = argparse.ArgumentParser(description="LudusCtrl browser bridge")
    ap.add_argument("--port", type=int, default=DEFAULT_WEB_PORT)
    ap.add_argument("--pad", choices=["x360", "ds4"], default="x360")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    try:
        gamepad = create_gamepad(args.pad)
    except PadUnavailable as exc:
        sys.exit(str(exc))

    last = {"line": ""}

    def show(state: PadState) -> None:
        from dualsense_link import describe_buttons
        line = (f"[{'pad' if state.connected else 'NO PAD'}] "
                f"L({state.left_x:+6d},{state.left_y:+6d}) "
                f"R({state.right_x:+6d},{state.right_y:+6d}) "
                f"LT{state.left_trigger:3d} RT{state.right_trigger:3d} "
                f"{describe_buttons(state.buttons, state.layout)}")
        if line == last["line"]:
            return
        pad_to = max(0, len(last["line"]) - len(line))
        last["line"] = line
        sys.stdout.write("\r" + line + " " * pad_to)
        sys.stdout.flush()

    server, bridge = serve(gamepad, port=args.port, verbose=args.verbose,
                           on_state=show, pad_kind=args.pad)

    print(f"LudusCtrl browser bridge {APP_VERSION}")
    print()
    urls = browser_urls(server.port, bridge.token)
    if urls:
        print("  On the phone, open the link for the network the phone is on:")
        for u in urls:
            print(f"    {u['url']}" + (f"   ({u['name']})" if u["name"] else ""))
    else:
        print("  No LAN address found. Connect this PC to the phone's Wi-Fi.")
    print()
    print("  The link carries a one-time code and changes every time this starts.")
    print("  The certificate is self-signed, so the browser will warn once.")
    print("  On iOS: tap Show Details, then 'visit this website'.")
    print("  This is expected -- no authority will sign a private IP address.")
    print()
    print("Ctrl-C to stop.")
    print()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print()
        return 0
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
