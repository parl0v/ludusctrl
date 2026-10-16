# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Josip Parlov (@parl0v). See NOTICE for the attribution terms.
"""Protocol v2 pairing: the crypto, the PC's store of paired phones, and the
PAIR_REQ / PAIR_RESP state machine.

v1 accepted any 20-byte datagram with the right magic, so anything on the LAN
could drive the virtual pad, Guide button included, and nothing stopped a
replay. v2 pairs a phone with this PC once, over ECDH with a six-digit code
the user compares on both screens, and every input packet and ack after that
carries a MAC under the per-phone key that pairing produced.

The Android app implements the same derivations; the golden vectors in
test_receiver.py, which the app's own tests assert too, pin both to the same
bytes. See ../docs/PROTOCOL.md for the wire format.

Nothing here owns a socket or a thread of its own except the store's writer,
so the receive loop stays the only place datagrams are read.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
import subprocess
import sys
import threading
import time
import unicodedata
from pathlib import Path
from typing import Callable, NamedTuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTOCOL_VERSION = 2

# --- wire formats --------------------------------------------------------------

PAIR_REQ_MAGIC = 0xD7
PAIR_RESP_MAGIC = 0xD8

# PAIR_REQ, phone -> PC, 128 bytes:
#   magic, version, phone_id, phone ephemeral public key, name length, name,
#   phase (0 = commit, 1 = reveal), commitment or nonce (16), reserved (3)
PAIR_REQ = struct.Struct("<BB8s65sB32sB16s3s")
# PAIR_RESP, PC -> phone, 84 bytes: this 76-byte head, then an 8-byte MAC.
PAIR_RESP_HEAD = struct.Struct("<BB8s65sB")
PAIR_RESP_SIZE = PAIR_RESP_HEAD.size + 8

PHASE_COMMIT = 0
PHASE_REVEAL = 1

STATE_WAITING = 0   # the prompt is up (or about to be); keep resending
STATE_ACCEPTED = 1  # MAC valid: the PC derived the same key
STATE_DENIED = 2    # Deny, or nobody answered within PROMPT_TIMEOUT
STATE_BUSY = 3      # another phone's request holds the one prompt

PUBLIC_KEY_SIZE = 65
NAME_MAX = 32
NONCE_SIZE = 16
ID_SIZE = 8
KEY_SIZE = 32
KID_SIZE = 4
MAC_SIZE = 8

ZERO_PUBLIC = bytes(PUBLIC_KEY_SIZE)
ZERO_MAC = bytes(MAC_SIZE)

LINK_KEY_INFO = b"LudusCtrl v2 link key"
CONFIRM_INFO = b"LudusCtrl v2 confirm"
COMMIT_LABEL = b"LudusCtrl v2 commit"


# --- crypto --------------------------------------------------------------------

def new_private_key() -> ec.EllipticCurvePrivateKey:
    """A fresh P-256 key. Every pairing attempt gets its own and drops it after."""
    return ec.generate_private_key(ec.SECP256R1())


def private_key_from_scalar(scalar: int) -> ec.EllipticCurvePrivateKey:
    """Only the golden-vector tests need a key with a chosen scalar."""
    return ec.derive_private_key(scalar, ec.SECP256R1())


def public_bytes(key) -> bytes:
    """X9.62 uncompressed point, 0x04 || X || Y, 65 bytes."""
    if isinstance(key, ec.EllipticCurvePrivateKey):
        key = key.public_key()
    return key.public_bytes(serialization.Encoding.X962,
                            serialization.PublicFormat.UncompressedPoint)


def load_public(raw: bytes) -> ec.EllipticCurvePublicKey:
    """Parse an uncompressed point. Raises ValueError for anything else,
    including a point that is not on the curve (from_encoded_point checks),
    which is what stops an invalid-curve attack on our ephemeral key."""
    if len(raw) != PUBLIC_KEY_SIZE or raw[0] != 0x04:
        raise ValueError("not an uncompressed P-256 point")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(raw))


def shared_secret(private: ec.EllipticCurvePrivateKey, peer_public: bytes) -> bytes:
    """Z, the 32-byte ECDH x-coordinate."""
    return private.exchange(ec.ECDH(), load_public(peer_public))


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def commitment(nonce: bytes) -> bytes:
    """What the phone sends before it has seen the PC's key; see PairingManager."""
    return hashlib.sha256(COMMIT_LABEL + nonce).digest()[:16]


class Derived(NamedTuple):
    key: bytes   # K, the link key
    kid: bytes   # first 4 bytes of SHA-256(K); a lookup hint, not a secret
    code: int    # 0..999999, shown on both screens


def derive(z: bytes, phone_pub: bytes, pc_pub: bytes, nonce: bytes) -> Derived:
    """K, KID and the confirmation code from one ECDH result.

    The code also covers the phone's nonce, which the phone committed to
    before it saw the PC's key. Without that, whoever sends the second key
    could try keys offline until the two codes collide; see PairingManager.
    """
    salt = phone_pub + pc_pub
    key = hkdf(z, salt, LINK_KEY_INFO, KEY_SIZE)
    code = int.from_bytes(hkdf(z, salt + nonce, CONFIRM_INFO, 4), "big") % 1_000_000
    return Derived(key, key_id(key), code)


def key_id(key: bytes) -> bytes:
    return hashlib.sha256(key).digest()[:KID_SIZE]


def mac(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256 truncated to 8 bytes. 64 bits is plenty against online
    forgery: every guess costs a datagram and the receiver gives no oracle."""
    return hmac.new(key, data, hashlib.sha256).digest()[:MAC_SIZE]


def mac_ok(key: bytes, data: bytes, tag: bytes) -> bool:
    return hmac.compare_digest(mac(key, data), tag)


def format_code(code: int) -> str:
    """"123 456": two groups read back more reliably than six digits."""
    digits = f"{code:06d}"
    return f"{digits[:3]} {digits[3:]}"


def clean_name(raw: bytes) -> str:
    """The device name as it may be shown on the PC.

    It comes off the network, so anything could be in it. Control and format
    characters go, bidi overrides included: those could make the prompt read
    as something it is not.
    """
    text = raw.decode("utf-8", errors="replace")
    text = "".join(ch for ch in text if not unicodedata.category(ch).startswith("C"))
    text = re.sub(r"\s+", " ", text).strip()
    return text or "Unnamed phone"


# --- where state lives ---------------------------------------------------------

DATA_DIR_ENV = "LUDUSCTRL_DATA_DIR"


def data_dir() -> Path:
    """%LOCALAPPDATA%\\LudusCtrl: settings, the log, the certificate, pairings.

    LUDUSCTRL_DATA_DIR moves all of it, which is how the tests stay away from
    the real pairings (and the real certificate) of whoever runs them.
    """
    override = os.environ.get(DATA_DIR_ENV)
    if override:
        d = Path(override)
    else:
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        d = Path(base) / "LudusCtrl"
    d.mkdir(parents=True, exist_ok=True)
    return d


_sid_cache: list[str | None] = []


def _current_sid() -> str | None:
    if _sid_cache:
        return _sid_cache[0]
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    sid = None
    try:
        who = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"],
                             capture_output=True, text=True, timeout=5,
                             stdin=subprocess.DEVNULL, creationflags=flags)
        m = re.search(r"S-1-[\d-]+", who.stdout or "")
        if who.returncode == 0 and m:
            sid = m.group(0)
    except (OSError, subprocess.SubprocessError):
        pass
    _sid_cache.append(sid)
    return sid


def restrict_to_current_user(path: Path) -> None:
    """Best effort: make a secret file readable by this Windows user only.

    os.chmod(0o600) does nothing useful on Windows, where it only toggles the
    read-only attribute; files under %LOCALAPPDATA% inherit an ACL that already
    excludes other standard users, but an administrator-created or roaming
    profile may not. icacls with the user's SID (not their name, which can be
    ambiguous across domains) drops inheritance and grants only them. Failure
    is not fatal. The SID is looked up once per process, since the pairing
    store writes more often than the certificate ever did.
    """
    if sys.platform != "win32":
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return
    sid = _current_sid()
    if not sid:
        return
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"*{sid}:F"],
                       capture_output=True, timeout=5,
                       stdin=subprocess.DEVNULL, creationflags=flags)
    except (OSError, subprocess.SubprocessError):
        pass


# --- the store -----------------------------------------------------------------

class PairedPhone(NamedTuple):
    id: bytes
    name: str
    key: bytes
    kid: bytes
    paired_at: str
    highest_session: int

    def public(self) -> dict:
        """What the UI may see. Never the key."""
        return {"id": base64.b64encode(self.id).decode(), "name": self.name,
                "paired_at": self.paired_at}


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text, size: int) -> bytes:
    raw = base64.b64decode(str(text), validate=True)
    if len(raw) != size:
        raise ValueError("wrong length")
    return raw


class PairingStore:
    """pairing.json: this PC's id and the phones paired with it.

    Read from the receive thread (every packet looks its key up) and written
    from the UI thread (Allow, Remove), so everything goes through one lock
    and readers get immutable PairedPhone tuples.

    Writes are atomic (temp file, restrict, replace), so a crash mid-write
    leaves the previous file rather than half of one. A new session number
    from a phone is persisted on a writer thread, because the ACL step spawns
    icacls and the receive thread must not stall on it; pairing and removal
    are written before they return.
    """

    FILENAME = "pairing.json"

    def __init__(self, directory: str | os.PathLike | None = None,
                 on_status: Callable[[str], None] | None = None) -> None:
        self.dir = Path(directory) if directory is not None else data_dir()
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / self.FILENAME
        self.on_status = on_status
        self._lock = threading.Lock()
        self._io_lock = threading.Lock()
        self._phones: dict[bytes, PairedPhone] = {}
        self.pc_id = b""
        self._dirty = False
        self._wake = threading.Event()
        self._closed = False
        self._readonly = False
        self._writer: threading.Thread | None = None
        self._load()

    # --- file ----------------------------------------------------------------

    def _status(self, message: str) -> None:
        if self.on_status:
            try:
                self.on_status(message)
            except Exception:
                pass

    def _load(self) -> None:
        try:
            text = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            text = None
        except OSError as exc:
            # Unreadable is not the same as absent: starting over here would
            # overwrite every pairing on the next save. Run without saving.
            self._status(f"[pair] cannot read {self.path}: {exc}; "
                         "pairings made now will not be saved")
            self.pc_id = secrets.token_bytes(ID_SIZE)
            self._readonly = True
            return

        if text is not None:
            try:
                data = json.loads(text)
                pc_id = _unb64(data["pc_id"], ID_SIZE)
                phones = {}
                for p in data.get("phones", []):
                    key = _unb64(p["key"], KEY_SIZE)
                    pid = _unb64(p["id"], ID_SIZE)
                    session = int(p.get("highest_session", 0))
                    if not 0 <= session <= 0xFFFFFFFF:
                        raise ValueError("session out of range")
                    phones[pid] = PairedPhone(pid, str(p.get("name", ""))[:64], key,
                                              key_id(key), str(p.get("paired_at", "")),
                                              session)
                self.pc_id, self._phones = pc_id, phones
                return
            except (ValueError, KeyError, TypeError, AttributeError) as exc:
                # Keep the damaged file for whoever wants to look at it, and
                # start clean: every phone will have to pair again, which is
                # annoying but safe.
                aside = self.path.with_name(f"pairing.corrupt-{int(time.time())}.json")
                try:
                    os.replace(self.path, aside)
                except OSError:
                    pass
                self._status(f"[pair] {self.path.name} was unreadable ({exc}); "
                             f"moved to {aside.name}, phones must pair again")

        self.pc_id = secrets.token_bytes(ID_SIZE)
        self._phones = {}
        # Now, not later: the beacon advertises pc_id, and a phone that
        # follows this PC by it needs the same one after a restart.
        self.flush()

    def _snapshot(self) -> dict:
        with self._lock:
            self._dirty = False
            return {
                "pc_id": _b64(self.pc_id),
                "phones": [{"id": _b64(p.id), "name": p.name, "key": _b64(p.key),
                            "paired_at": p.paired_at,
                            "highest_session": p.highest_session}
                           for p in self._phones.values()],
            }

    def flush(self) -> bool:
        """Write the current state now. Returns False if it could not be."""
        if self._readonly:
            return False
        with self._io_lock:
            data = self._snapshot()
            tmp = self.path.with_name(self.FILENAME + ".tmp")
            try:
                tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
                # Before the replace, so the file is never readable by anyone
                # else even for an instant. A replaced file keeps the ACL of
                # the temp file it came from.
                restrict_to_current_user(tmp)
                for attempt in range(5):
                    try:
                        os.replace(tmp, self.path)
                        break
                    except PermissionError:
                        # Something (an indexer, antivirus) has the old file
                        # open for a moment. It lets go quickly.
                        if attempt == 4:
                            raise
                        time.sleep(0.05)
                return True
            except OSError as exc:
                self._status(f"[pair] could not save {self.path.name}: {exc}")
                return False

    def _save_later(self) -> None:
        with self._lock:
            self._dirty = True
            if self._writer is None:
                self._writer = threading.Thread(target=self._write_loop,
                                                name="dslink-pairing-store", daemon=True)
                self._writer.start()
        self._wake.set()

    def _write_loop(self) -> None:
        while True:
            self._wake.wait()
            self._wake.clear()
            if self._dirty:
                self.flush()
            if self._closed:
                return

    def close(self) -> None:
        """Write anything pending and stop the writer."""
        writer = self._writer
        self._closed = True
        self._wake.set()
        if writer is not None:
            writer.join(timeout=5)
        if self._dirty:
            self.flush()

    # --- phones --------------------------------------------------------------

    def phones(self) -> list[PairedPhone]:
        with self._lock:
            return sorted(self._phones.values(), key=lambda p: p.paired_at)

    def get(self, phone_id: bytes) -> PairedPhone | None:
        with self._lock:
            return self._phones.get(phone_id)

    def by_kid(self, kid: bytes) -> list[PairedPhone]:
        """Usually zero or one; a 32-bit KID can collide, so all of them."""
        with self._lock:
            return [p for p in self._phones.values() if p.kid == kid]

    def add(self, phone_id: bytes, name: str, key: bytes) -> PairedPhone:
        """Pair a phone, replacing any earlier pairing of the same phone_id.

        The session counter starts again at 0: the phone numbers sessions per
        pairing, and anything from the old pairing fails its MAC under the new
        key anyway, so nothing old can be replayed.
        """
        paired_at = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
        phone = PairedPhone(phone_id, name, key, key_id(key), paired_at, 0)
        with self._lock:
            self._phones[phone_id] = phone
        self.flush()
        return phone

    def remove(self, phone_id: bytes) -> bool:
        with self._lock:
            gone = self._phones.pop(phone_id, None) is not None
        if gone:
            self.flush()
        return gone

    def note_session(self, phone_id: bytes, session: int) -> bool:
        """Raise a phone's highest_session. Only ever upwards; True if it moved."""
        with self._lock:
            phone = self._phones.get(phone_id)
            if phone is None or session <= phone.highest_session:
                return False
            self._phones[phone_id] = phone._replace(highest_session=session)
        # Written before the session is accepted, not later on the writer
        # thread: if the PC died in between, a recording of this session
        # would pass as new after a restart. Sessions start once per link,
        # so the cost is one small write per Start.
        self.flush()
        return True


# --- the pairing exchange ------------------------------------------------------

TEST_AUTO_ALLOW_ENV = "LUDUSCTRL_TEST_AUTO_ALLOW"


def test_auto_allow_enabled() -> bool:
    """The end-to-end tests pair over loopback with nobody to click Allow.

    Only honoured from source, never from a packaged build: a frozen exe
    refuses it whatever the environment says, so no setting on a user's
    machine can turn pairing into "anyone on the LAN may pair".
    """
    if getattr(sys, "frozen", False):
        return False
    return os.environ.get(TEST_AUTO_ALLOW_ENV) == "1"


class PairingPrompt(NamedTuple):
    """One open request, as the UI shows it."""

    id: str
    phone_id: bytes
    name: str
    code: int
    expires_at: float   # on the manager's clock

    def public(self, now: float) -> dict:
        return {"id": self.id, "name": self.name, "code": format_code(self.code),
                "seconds": max(0, int(round(self.expires_at - now)))}


class _Attempt:
    __slots__ = ("key", "phone_id", "name", "phone_pub", "commit", "pc_private",
                 "pc_pub", "created", "prompt", "link_key")

    def __init__(self, key, phone_id, name, phone_pub, commit, now):
        self.key = key
        self.phone_id = phone_id
        self.name = name
        self.phone_pub = phone_pub
        self.commit = commit
        self.pc_private = new_private_key()
        self.pc_pub = public_bytes(self.pc_private)
        self.created = now
        self.prompt: PairingPrompt | None = None
        self.link_key: bytes | None = None


class PairingManager:
    """Answers PAIR_REQ and owns the one pairing prompt.

    The exchange, as implemented:

      1. The phone sends PAIR_REQ with its ephemeral key and a commitment to a
         random 16-byte nonce, and repeats it every second.
      2. The PC answers state 0 with its own ephemeral key.
      3. The phone's next PAIR_REQ reveals the nonce. Only now can either side
         compute the code, and the PC opens the prompt.
      4. Allow: state 1 with a MAC under K. Deny or 60 s: state 2.

    Step 1's commitment is not in the original design. Without it, an active
    attacker between the two could pick its key for the phone after seeing the
    PC's, trying keys offline until the phone's code matched the PC's (a
    million tries is seconds of work), and both screens would agree. With it,
    the phone's code depends on a nonce the attacker cannot see until its own
    key is fixed, so one guess is all it gets: one in a million.

    Called from the receive thread (requests, tick) and from UI threads
    (answer, remove), so all state is under one lock. on_change is called
    outside it.
    """

    PROMPT_TIMEOUT = 60.0
    # The phone reveals on its next resend, one second after our answer.
    # A request that never does holds the prompt slot this long at most.
    REVEAL_TIMEOUT = 10.0
    # How long a finished attempt keeps answering its phone's resends.
    FINISHED_KEEP = 90.0
    PER_SOURCE_INTERVAL = 1.0

    def __init__(self, store: PairingStore,
                 on_change: Callable[[str, PairingPrompt | None], None] | None = None,
                 auto_allow: bool | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.store = store
        self.on_change = on_change
        self.clock = clock
        # Refused in a packaged build even if a caller asks for it.
        self.auto_allow = (test_auto_allow_enabled() if auto_allow is None else auto_allow) \
            and not getattr(sys, "frozen", False)
        self._lock = threading.Lock()
        self._current: _Attempt | None = None
        self._finished: dict[tuple, tuple[int, bytes, bytes | None, float]] = {}
        self._last_by_source: dict[str, float] = {}
        self.requests = 0
        self.rate_limited = 0

    # --- queries ---------------------------------------------------------------

    @property
    def prompt(self) -> PairingPrompt | None:
        cur = self._current
        return cur.prompt if cur is not None else None

    def _emit(self, events) -> None:
        if not self.on_change:
            return
        for kind, prompt in events:
            try:
                self.on_change(kind, prompt)
            except Exception:
                pass  # a UI bug must not break pairing

    # --- the exchange ------------------------------------------------------------

    def _response(self, state: int, pc_pub: bytes, key: bytes | None) -> bytes:
        head = PAIR_RESP_HEAD.pack(PAIR_RESP_MAGIC, PROTOCOL_VERSION, self.store.pc_id,
                                   pc_pub, state)
        tag = mac(key, head) if state == STATE_ACCEPTED and key else ZERO_MAC
        return head + tag

    def handle_request(self, data: bytes, addr: tuple, now: float | None = None) -> bytes | None:
        """One PAIR_REQ in; the PAIR_RESP to send back, or None for silence."""
        if len(data) != PAIR_REQ.size or data[0] != PAIR_REQ_MAGIC \
                or data[1] != PROTOCOL_VERSION:
            return None
        now = self.clock() if now is None else now
        events = []
        with self._lock:
            # Per source address, not per port: a sender cycling ports must
            # not get a fresh allowance each time.
            source = addr[0]
            if now - self._last_by_source.get(source, float("-inf")) < self.PER_SOURCE_INTERVAL:
                self.rate_limited += 1
                return None
            if len(self._last_by_source) > 256:
                self._last_by_source = {s: t for s, t in self._last_by_source.items()
                                        if now - t < self.PER_SOURCE_INTERVAL}
            self._last_by_source[source] = now
            self.requests += 1

            _, _, phone_id, phone_pub, name_len, name_raw, phase, field, reserved = \
                PAIR_REQ.unpack(data)
            if name_len > NAME_MAX or phase not in (PHASE_COMMIT, PHASE_REVEAL) \
                    or phone_pub[0] != 0x04:
                return None
            key = (phone_id, phone_pub)

            self._expire(now, events)

            done = self._finished.get(key)
            if done is not None:
                state, pc_pub, link_key, _ = done
                reply = self._response(state, pc_pub, link_key)
            elif self._current is not None and self._current.key == key:
                reply = self._continue(self._current, phase, field, now, events)
            elif self._current is not None:
                reply = self._response(STATE_BUSY, ZERO_PUBLIC, None)
            elif phase != PHASE_COMMIT:
                # A reveal for an attempt we never saw (we restarted, or it
                # expired). Silence; the phone times out and says so.
                reply = None
            else:
                try:
                    load_public(phone_pub)
                except ValueError:
                    return None
                self._current = _Attempt(key, phone_id, clean_name(name_raw[:name_len]),
                                         phone_pub, bytes(field), now)
                reply = self._response(STATE_WAITING, self._current.pc_pub, None)
        self._emit(events)
        if self.auto_allow and events and events[-1][0] == "open":
            prompt = events[-1][1]
            if self.answer(prompt.id, True):
                # Answer the reveal that opened the prompt with the result
                # at once, as a fast human would have.
                with self._lock:
                    done = self._finished.get(key)
                if done is not None:
                    reply = self._response(done[0], done[1], done[2])
        return reply

    def _continue(self, cur: _Attempt, phase: int, field: bytes, now: float, events) -> bytes:
        if cur.prompt is None and phase == PHASE_REVEAL:
            # A wrong reveal is ignored rather than fatal: anyone who saw the
            # phone's first request could send one, and failing the attempt
            # on it would hand them a way to block pairing.
            if hmac.compare_digest(commitment(bytes(field)), cur.commit):
                z = shared_secret(cur.pc_private, cur.phone_pub)
                d = derive(z, cur.phone_pub, cur.pc_pub, bytes(field))
                cur.link_key = d.key
                cur.pc_private = None   # done with it; nothing else needs Z
                cur.prompt = PairingPrompt(secrets.token_hex(8), cur.phone_id, cur.name,
                                           d.code, now + self.PROMPT_TIMEOUT)
                events.append(("open", cur.prompt))
        return self._response(STATE_WAITING, cur.pc_pub, None)

    def _finish(self, cur: _Attempt, state: int, now: float) -> None:
        self._finished[cur.key] = (state, cur.pc_pub,
                                   cur.link_key if state == STATE_ACCEPTED else None, now)
        if len(self._finished) > 32:
            oldest = min(self._finished, key=lambda k: self._finished[k][3])
            del self._finished[oldest]
        self._current = None

    def _expire(self, now: float, events) -> None:
        for k in [k for k, v in self._finished.items() if now - v[3] > self.FINISHED_KEEP]:
            del self._finished[k]
        cur = self._current
        if cur is None:
            return
        if cur.prompt is None and now - cur.created > self.REVEAL_TIMEOUT:
            self._finish(cur, STATE_DENIED, now)
        elif cur.prompt is not None and now >= cur.prompt.expires_at:
            prompt = cur.prompt
            self._finish(cur, STATE_DENIED, now)
            events.append(("timeout", prompt))

    def tick(self, now: float | None = None) -> None:
        """Time out a prompt nobody answered. The receive loop calls this."""
        now = self.clock() if now is None else now
        events = []
        with self._lock:
            self._expire(now, events)
        self._emit(events)

    # --- the user's side -----------------------------------------------------

    def answer(self, prompt_id: str, allow: bool) -> bool:
        """Allow or Deny the prompt with this id. False if it is not the open
        one any more (answered elsewhere, timed out, replaced): a click meant
        for one request must never approve another."""
        now = self.clock()
        events = []
        with self._lock:
            cur = self._current
            if cur is None or cur.prompt is None or cur.prompt.id != prompt_id:
                return False
            prompt = cur.prompt
            if now >= prompt.expires_at:
                self._expire(now, events)
                allowed = None
            else:
                allowed = allow
                if allow:
                    # Stored before the phone can hear state 1, so its first
                    # input packet already finds a key.
                    self.store.add(cur.phone_id, cur.name, cur.link_key)
                self._finish(cur, STATE_ACCEPTED if allow else STATE_DENIED, now)
                events.append(("allowed" if allow else "denied", prompt))
        self._emit(events)
        return allowed is not None

    def remove(self, phone_id: bytes) -> bool:
        gone = self.store.remove(phone_id)
        if gone:
            self._emit([("removed", None)])
        return gone
