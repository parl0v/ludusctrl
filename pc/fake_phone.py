# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Josip Parlov (@parl0v). See NOTICE for the attribution terms.
"""The phone's half of protocol v2, in Python, for tests.

Pairs over UDP exactly as the Android app does (PAIR_REQ commit, then reveal),
builds authenticated input packets and checks the PC's acks. The tests use it
to stand in for a phone, since none is attached to the machine that runs them.
Not imported by the app; nothing here ships.
"""

from __future__ import annotations

import secrets
import socket
import time

import dualsense_link as d
import pairing as p


class FakePhone:
    def __init__(self, name: str = "Test phone", phone_id: bytes | None = None,
                 private=None, nonce: bytes | None = None) -> None:
        self.name = name
        self.id = phone_id or secrets.token_bytes(p.ID_SIZE)
        self.private = private or p.new_private_key()
        self.pub = p.public_bytes(self.private)
        self.nonce = nonce or secrets.token_bytes(p.NONCE_SIZE)
        self.pc_pub: bytes | None = None
        self.pc_id: bytes | None = None
        self.key: bytes | None = None
        self.kid: bytes | None = None
        self.code: int | None = None
        self.session = 0
        self.seq = 0
        self.states: list[int] = []

    # --- pairing -----------------------------------------------------------------

    def pair_request(self, phase: int | None = None) -> bytes:
        """Commit until the PC's key is known, then reveal (as the app does)."""
        if phase is None:
            phase = p.PHASE_REVEAL if self.pc_pub else p.PHASE_COMMIT
        field = self.nonce if phase == p.PHASE_REVEAL else p.commitment(self.nonce)
        name = self.name.encode("utf-8")[:p.NAME_MAX]
        return p.PAIR_REQ.pack(p.PAIR_REQ_MAGIC, p.PROTOCOL_VERSION, self.id, self.pub,
                               len(name), name, phase, field, bytes(3))

    def on_response(self, data: bytes) -> int | None:
        """Feed one PAIR_RESP. Returns its state, or None if it was ignored."""
        if len(data) != p.PAIR_RESP_SIZE or data[0] != p.PAIR_RESP_MAGIC \
                or data[1] != p.PROTOCOL_VERSION:
            return None
        head, tag = data[:p.PAIR_RESP_HEAD.size], data[p.PAIR_RESP_HEAD.size:]
        _, _, pc_id, pc_pub, state = p.PAIR_RESP_HEAD.unpack(head)
        if state in (p.STATE_WAITING, p.STATE_ACCEPTED) and pc_pub != p.ZERO_PUBLIC:
            if self.pc_pub is None:
                # The first key heard is the one the code is computed from.
                self.pc_pub = pc_pub
                z = p.shared_secret(self.private, pc_pub)
                derived = p.derive(z, self.pub, pc_pub, self.nonce)
                self.key, self.kid, self.code = derived
            elif pc_pub != self.pc_pub:
                return None
        if state == p.STATE_ACCEPTED:
            if self.key is None or not p.mac_ok(self.key, head, tag):
                return None
            self.pc_id = pc_id
        self.states.append(state)
        return state

    def pair(self, host: str, port: int, timeout: float = 15.0,
             sock: socket.socket | None = None, interval: float = 1.05) -> int | None:
        """The whole exchange over UDP. Returns the final state (1 accepted,
        2 denied), or None on timeout."""
        own = sock is None
        s = sock or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        deadline = time.monotonic() + timeout
        next_send = 0.0
        try:
            while time.monotonic() < deadline:
                now = time.monotonic()
                if now >= next_send:
                    s.sendto(self.pair_request(), (host, port))
                    next_send = now + interval
                try:
                    data, _ = s.recvfrom(256)
                except (socket.timeout, ConnectionResetError):
                    continue
                state = self.on_response(data)
                if state in (p.STATE_ACCEPTED, p.STATE_DENIED):
                    return state
            return None
        finally:
            if own:
                s.close()

    def adopt(self, store: p.PairingStore) -> None:
        """Skip the exchange: pair straight into a store, as if Allow had
        been clicked. For tests about what comes after pairing."""
        self.key = secrets.token_bytes(p.KEY_SIZE)
        self.kid = p.key_id(self.key)
        self.pc_id = store.pc_id
        store.add(self.id, self.name, self.key)

    # --- the link ---------------------------------------------------------------

    def start_session(self) -> int:
        self.session += 1
        return self.session

    def packet(self, seq: int | None = None, buttons: int = 0, lx: int = 0, ly: int = 0,
               rx: int = 0, ry: int = 0, lt: int = 0, rt: int = 0, flags: int = 1,
               layout: int = 0, session: int | None = None, key: bytes | None = None,
               kid: bytes | None = None, version: int = p.PROTOCOL_VERSION) -> bytes:
        if seq is None:
            self.seq = (self.seq + 1) & 0xFFFFFFFF
            seq = self.seq
        body = d.PACKET_V2.pack(d.MAGIC, version, seq, buttons, lx, ly, rx, ry, lt, rt,
                                flags, layout, self.session if session is None else session,
                                self.kid if kid is None else kid, bytes(8))
        signed = body[:d.PACKET_V2_SIGNED]
        return signed + p.mac(self.key if key is None else key, signed)

    def read_ack(self, data: bytes):
        """(seq, received, flags, authenticated) or None if it is not an ack
        or its MAC is wrong."""
        if len(data) == d.ACK_V2.size and data[0] == d.ACK_MAGIC:
            head, tag = data[:d.ACK.size], data[d.ACK.size:]
            if not p.mac_ok(self.key, head, tag):
                return None
            _, _, seq, received, flags, _ = d.ACK.unpack(head)
            return seq, received, flags, True
        if len(data) == d.ACK.size and data[0] == d.ACK_MAGIC:
            _, version, seq, received, flags, _ = d.ACK.unpack(data)
            return seq, received, flags, False
        return None
