# DSLINK wire protocol, v2

This is the wire format between the LudusCtrl Android app, the browser client
and the PC receiver. The receiver side is implemented in
`pc/dualsense_link.py`, `pc/pairing.py`, `pc/webbridge.py` and
`pc/webui-mobile/index.html`; the Android app implements the phone side. The
code is authoritative. The golden vectors at the end are asserted by
`pc/test_receiver.py` and by the Android app's unit tests, so any change shows
up in both as a hex diff.

## Overview

| Channel | Transport | Default port | Direction |
| --- | --- | --- | --- |
| Pairing, input, acks | UDP | 45989 | phone to PC; the PC answers to the datagram's source address and port |
| Discovery beacon | UDP broadcast | 45990 | PC to `255.255.255.255` |
| Browser client | TCP, HTTPS + WebSocket | 45991 | browser to PC |

The ports are configurable (`--port`, `--beacon-port`, `--web-port` on the PC;
the port field in the app). The beacon advertises the input port, so the phone
follows whatever the PC listens on.

All multi-byte integers are little-endian unless stated otherwise. The
exceptions are the EC point coordinates (big-endian, per X9.62), the HKDF
output that becomes the confirmation code (read big-endian) and WebSocket frame
lengths (big-endian, per RFC 6455).

| Magic | Packet | Size |
| --- | --- | --- |
| `0xD5` | input | 36 bytes (v2, UDP); 20 bytes (v1 body, browser path only) |
| `0xD6` | ack | 20 bytes signed, 12 bytes unsigned |
| `0xD7` | PAIR_REQ | 128 bytes |
| `0xD8` | PAIR_RESP | 84 bytes |
| `DSLK` | beacon | 16 bytes (8 from a 1.1 PC) |

Versions:

- **Input protocol version 2.** Byte 1 of every `0xD5`, `0xD6`, `0xD7` and
  `0xD8` packet on UDP. Version 1 input is no longer accepted over UDP.
- **Beacon format version 1.** A separate constant that did not change when
  the input protocol went to 2; the pc_id was appended without changing what
  the first 8 bytes mean.
- **Browser path: v1 body.** The browser still sends the 20-byte version 1
  packet, but only inside an authenticated TLS WebSocket, never over UDP.

## Beacon

Broadcast by the PC so the app can fill in the host address and follow a paired
PC whose address changes.

| Offset | Size | Type | Field | Notes |
| --- | --- | --- | --- | --- |
| 0 | 4 | ascii | magic | `DSLK` |
| 4 | 1 | u8 | version | `0x01` (beacon format, not the input protocol) |
| 5 | 2 | u16 | input_port | the UDP port the receiver listens on |
| 7 | 1 | u8 | reserved | 0 |
| 8 | 8 | bytes | pc_id | this PC's id from `pairing.json`; not a secret |

PC behaviour:

- One socket per local IPv4 address (loopback excluded), each bound to that
  address, sending to `255.255.255.255:45990` every 2 s. Binding the source
  address is what gets the broadcast out of every adapter rather than the one
  the routing table picks. The socket set is rebuilt every 15 s.
- **Paused while linked.** While the receiver has a linked phone (a valid,
  authenticated packet within the watchdog window) nothing is broadcast. It
  resumes when the link drops, and sends immediately on resume rather than
  waiting out the interval. A browser client holding the pad does not pause it.
- The body carries no address. The phone takes the host from the datagram's
  source IP, which is correct on multi-homed hosts and through NAT.

Phone behaviour (`Protocol.decodeBeacon`, `BeaconListener`):

- Accepts a datagram of at least 8 bytes with magic `DSLK`, version byte 1 and
  a non-zero port. The 8-byte beacon of a 1.1 PC is accepted with no pc_id; a
  datagram of 16 bytes or more yields the pc_id (bytes 8..15, kept as hex).
- Reports are throttled: one per source (host, port) per second, four per
  second overall, sixteen tracked sources at most.
- A paired PC is identified by pc_id, not by address. A beacon naming a known
  pc_id from a new address moves that pairing's stored endpoint there, but only
  once the old address has been silent for a while, so a PC beaconing from
  several adapters does not flip between them.

## Crypto primitives

Both sides implement the same derivations byte for byte (`pairing.py` with
`cryptography`, the Android app with `java.security` / `javax.crypto`).

| Item | Definition |
| --- | --- |
| Curve | NIST P-256 (secp256r1), ECDH |
| Public key encoding | X9.62 uncompressed point, 65 bytes: `0x04 \|\| X \|\| Y`, coordinates 32-byte big-endian |
| Key pairs | fresh ephemeral pair per pairing attempt on both sides, discarded afterwards |
| Point validation | PC: `EllipticCurvePublicKey.from_encoded_point` (rejects off-curve points). Phone: checked by hand (`x, y < p` and `y^2 = x^3 + ax + b mod p`) before `KeyAgreement`. Anything but a 65-byte `0x04` point is refused, including all-zero and compressed forms |
| Z | ECDH shared secret, the 32-byte x-coordinate |
| HKDF | HKDF-SHA256, RFC 5869 extract-then-expand (hand-rolled on Android and checked against RFC 5869 test case A.1) |
| salt | `phone_pub (65) \|\| pc_pub (65)`, 130 bytes |
| K (link key) | `HKDF(ikm = Z, salt = salt, info = "LudusCtrl v2 link key", L = 32)` |
| Confirmation code | `HKDF(ikm = Z, salt = salt \|\| nonce (16), info = "LudusCtrl v2 confirm", L = 4)`, read as a big-endian u32, `mod 1_000_000`, shown as two groups of three digits (`"260 329"`, `"000 042"`) |
| Commitment | first 16 bytes of `SHA-256("LudusCtrl v2 commit" \|\| nonce)` |
| KID | first 4 bytes of `SHA-256(K)`. A lookup hint, not a secret |
| MAC | HMAC-SHA256 under K, truncated to the first 8 bytes |
| Comparison | constant time: `hmac.compare_digest` on the PC, `MessageDigest.isEqual` on the phone |

The info strings and the commitment label are ASCII with no terminator. The
nonce is 16 random bytes chosen by the phone per attempt.

Identities:

- **pc_id**: 8 random bytes, created on the PC's first start and persisted in
  `pairing.json` straight away (the beacon advertises it, so it must survive a
  restart).
- **phone_id**: 8 random bytes, created once per app install and kept in the
  phone's SharedPreferences.

## Pairing exchange

Pairing runs over UDP to the PC's input port. It pairs one phone with one PC,
once; the result is the per-phone link key K that signs every input packet and
ack afterwards.

### Sequence

1. The phone sends PAIR_REQ in the **commit** phase: its ephemeral public key
   and a commitment to a random nonce. It repeats the current request every
   1 s.
2. The PC creates an attempt with a fresh ephemeral key pair and answers state
   0 (waiting) with its public key.
3. The phone fixes the first PC key it hears, derives K and the code, shows the
   code, and from then on sends PAIR_REQ in the **reveal** phase, carrying the
   nonce itself.
4. The PC checks the nonce against the commitment. On a match it derives K and
   the code and opens the prompt ("<device name> wants to pair", the code, 60 s
   countdown, Allow / Deny). It keeps answering state 0.
5. **Allow**: the PC stores the phone, then answers state 1 with a MAC under K.
   The phone verifies the MAC, stores the pairing and starts the link.
   **Deny**, or 60 s with no answer: state 2.

### PAIR_REQ (phone to PC, 128 bytes)

| Offset | Size | Type | Field | Notes |
| --- | --- | --- | --- | --- |
| 0 | 1 | u8 | magic | `0xD7` |
| 1 | 1 | u8 | version | `0x02` |
| 2 | 8 | bytes | phone_id | |
| 10 | 65 | bytes | phone_pub | ephemeral key, X9.62 uncompressed |
| 75 | 1 | u8 | name_len | 0..32 |
| 76 | 32 | bytes | name | UTF-8, zero-padded; the phone cuts it at a character boundary so it fits in 32 bytes |
| 108 | 1 | u8 | phase | 0 = commit, 1 = reveal |
| 109 | 16 | bytes | field | phase 0: commitment; phase 1: nonce |
| 125 | 3 | bytes | reserved | sent as 0; the PC does not check them |

The phone sends the commit phase until it knows the PC's key and the reveal
phase from then on. The device name is `"<Manufacturer> <Model>"` (or the
model alone when it already starts with the manufacturer). No MAC: nothing is
shared yet.

PC-side validation, in order (anything failing is dropped with no reply):

1. Length exactly 128, magic `0xD7`, version 2.
2. Rate limit: at most one PAIR_REQ per source **IP address** per second
   (strictly less than 1.0 s since the last accepted one is dropped). Keyed by
   IP, not port, so cycling ports gains nothing. The table is pruned past 256
   entries.
3. `name_len <= 32`, `phase` is 0 or 1, `phone_pub[0] == 0x04`.
4. For a new attempt (commit phase), the full point check of `phone_pub`.

The name shown on the PC is decoded as UTF-8 with replacement, stripped of
every Unicode control and format character (bidi overrides included), with
whitespace collapsed; an empty result becomes "Unnamed phone".

### PAIR_RESP (PC to phone, 84 bytes)

| Offset | Size | Type | Field | Notes |
| --- | --- | --- | --- | --- |
| 0 | 1 | u8 | magic | `0xD8` |
| 1 | 1 | u8 | version | `0x02` |
| 2 | 8 | bytes | pc_id | |
| 10 | 65 | bytes | pc_pub | the attempt's ephemeral key; all zero in state 3 |
| 75 | 1 | u8 | state | see below |
| 76 | 8 | bytes | mac | state 1: MAC over bytes 0..75 under K. Otherwise zero |

| State | Name | Meaning | pc_pub | MAC |
| --- | --- | --- | --- | --- |
| 0 | waiting | the attempt exists; the prompt is up or will be once the nonce is revealed. Keep resending | the attempt's key | zero |
| 1 | accepted | the user clicked Allow and the PC stored K | the attempt's key | valid, under K |
| 2 | denied | Deny, the 60 s prompt ran out, or no valid reveal arrived within 10 s of the commit | the attempt's key | zero |
| 3 | busy | another attempt holds the PC's one pairing slot | zero | zero |

### PC state machine (`PairingManager`)

The PC keeps at most one current attempt, keyed by `(phone_id, phone_pub)`,
plus a table of finished attempts. For each valid PAIR_REQ:

1. If the key matches a **finished** attempt (kept 90 s after it finished, at
   most 32 of them): answer with its final state (1 with the MAC, or 2). This is
   how resends that cross the Allow click still get the result.
2. Else if it matches the **current** attempt:
   - no prompt yet and phase 1: if `commitment(nonce)` equals the stored
     commitment (constant-time), derive K and the code, drop the ephemeral
     private key and open the prompt. A wrong reveal is ignored, not fatal, so
     a third party who saw the commit cannot use it to cancel the attempt.
   - answer state 0.
3. Else if a current attempt exists: answer state 3. This includes the same
   phone_id arriving with a new key. **The open prompt never changes**: a new
   request never replaces the current attempt; it only ends by Allow, Deny,
   timeout or the reveal timeout.
4. Else if phase is 1 (a reveal for an attempt this PC never saw, for example
   after a restart): no reply. The phone reports that nothing answered.
5. Else (phase 0, nothing current): validate the point, create the attempt with
   a fresh PC key pair and answer state 0.

Timers on the PC:

| Timer | Value | Effect |
| --- | --- | --- |
| Prompt | 60 s from the reveal | unanswered: attempt finishes as state 2 |
| Reveal-less hold | 10 s from the commit | no valid reveal: attempt finishes as state 2, freeing the slot |
| Finished answers | 90 s | a finished attempt keeps answering its phone's resends |
| Rate limit | 1 PAIR_REQ/s per IP | excess dropped silently |

An Allow or Deny is bound to the prompt's random id. A click meant for a prompt
that has since closed approves nothing. On Allow the phone is written to
`pairing.json` before state 1 can go out, so the phone's first input packet
already finds its key; an existing pairing with the same phone_id is replaced
and its highest_session reset to 0. Nothing is stored on Deny.

`LUDUSCTRL_TEST_AUTO_ALLOW=1` makes the PC allow every prompt at once, for the
end-to-end tests. It is honoured only when running from source; a packaged
build refuses it whatever the environment says.

### Phone behaviour (`PairingAttempt`, `Pairer`)

- A response is considered only if it is exactly 84 bytes, magic `0xD8`,
  version 2, and comes from the port the request was sent to.
- **First key wins.** State 0 or 1 with a non-zero pc_pub: if no PC key is
  known yet, the point is validated, Z, K, KID and the code are derived and
  that key is fixed for the rest of the attempt. A response carrying any other
  key afterwards is ignored. An invalid point is ignored without fixing
  anything. A zero pc_pub in state 0 or 1 is ignored.
- State 0: show the code (the status line updates only when it changes).
- State 1: accepted only if the MAC over bytes 0..75 verifies under K. The
  phone then stores `pc_id -> K, KID, host, port` with its session counter at 0
  and starts the link.
- State 2: ends the attempt as declined, unless a PC key is already fixed and
  this response carries a different one.
- State 3: shown as "busy" and the phone keeps asking, but only while no PC key
  is fixed; after that it is ignored.

| Timer | Value | Effect |
| --- | --- | --- |
| Resend | 1 s | the current PAIR_REQ (commit or reveal) is sent again |
| No reply | 5 s | nothing heard (no state 0 or 3): show a "no reply, is the PC app updated?" notice and keep trying |
| Give up | 62 s | end the attempt as timed out (the PC's prompt lasts 60 s, plus the first round trip) |
| Send failures | 10 in a row | end the attempt as "lost the route" |

### Why commit-then-reveal

Without the commitment, an active attacker between phone and PC could answer
the phone with its own key after seeing the PC's, and try keys offline until
the code the phone shows equals the code the PC shows. A million candidates is
seconds of work, and both screens would then agree on a man-in-the-middle.

With it, the code also covers the nonce, and the phone commits to the nonce
before it sees any PC key. The attacker must send its key to the phone before
the phone reveals the nonce, and the phone keeps the first key it hears, so the
phone-side code is fixed by a value the attacker could not see when it chose.
On the PC side the attacker's key and commitment are fixed before the PC's
fresh key is generated. The two codes therefore match by chance only: about one
guess per attempt, with probability 1 in 1,000,000, and the user still has to
click Allow on it. Attempts are limited by the one-prompt-at-a-time rule, the
rate limit of one PAIR_REQ per second per IP, the 10 s reveal hold, and the
phone's 62 s window, after which the user has to start a new attempt by hand.

What an attacker on the LAN can still do is deny service: forge state 2 or 3
before the phone has fixed a key, hold the PC's one slot with its own request
(for 10 s without a reveal, or 60 s with one, with a prompt the user can Deny),
or forge a "not paired" ack (see Acks). None of these yields a key or input.

## Input packet v2 (36 bytes)

Sent by the Android app over UDP to the paired PC.

| Offset | Size | Type | Field | Notes |
| --- | --- | --- | --- | --- |
| 0 | 1 | u8 | magic | `0xD5` |
| 1 | 1 | u8 | version | `0x02` |
| 2 | 4 | u32 | seq | process-wide counter on the phone, starts at 0 when the app process starts, wraps |
| 6 | 2 | u16 | buttons | XInput `wButtons` layout, see below |
| 8 | 2 | i16 | left_x | -32768..32767 |
| 10 | 2 | i16 | left_y | -32768..32767, **positive = up** |
| 12 | 2 | i16 | right_x | |
| 14 | 2 | i16 | right_y | positive = up |
| 16 | 1 | u8 | left_trigger | 0..255 |
| 17 | 1 | u8 | right_trigger | 0..255 |
| 18 | 1 | u8 | flags | bit 0 = a physical pad is connected to the phone; bits 1..7 reserved, sent 0, ignored |
| 19 | 1 | u8 | layout | 0 unknown, 1 PlayStation, 2 Xbox, 3 Nintendo |
| 20 | 4 | u32 | session | this link's session number, see below |
| 24 | 4 | bytes | kid | KID of the link key |
| 28 | 8 | bytes | mac | MAC over bytes 0..27 under K |

Bytes 0..19 are the v1 packet with the version byte set to 2.

### Sticks and triggers

A stick axis in -1.0..1.0 is scaled by 32768 when negative and by 32767 when
positive and rounded, so both rails are reachable. Android and the Gamepad API
report Y positive-down; the **client** negates both Y axes before encoding, so
the PC is a straight pipe into XInput. Triggers are 0.0..1.0 scaled by 255 and
rounded. L2 and R2 travel only in the trigger bytes, never in the bitmask.

### Button bitmask

Identical to XInput's `wButtons`, so the Xbox 360 target assigns it with no
translation.

| Bit | Value | Button | DualSense |
| --- | --- | --- | --- |
| 0 | `0x0001` | DPAD_UP | D-pad up |
| 1 | `0x0002` | DPAD_DOWN | D-pad down |
| 2 | `0x0004` | DPAD_LEFT | D-pad left |
| 3 | `0x0008` | DPAD_RIGHT | D-pad right |
| 4 | `0x0010` | START | Options |
| 5 | `0x0020` | BACK | Create |
| 6 | `0x0040` | LEFT_THUMB | L3 |
| 7 | `0x0080` | RIGHT_THUMB | R3 |
| 8 | `0x0100` | LEFT_SHOULDER | L1 |
| 9 | `0x0200` | RIGHT_SHOULDER | R1 |
| 10 | `0x0400` | GUIDE | PS button (often swallowed by Android) |
| 11 | `0x0800` | reserved | never set; the PC masks it off |
| 12 | `0x1000` | A | Cross |
| 13 | `0x2000` | B | Circle |
| 14 | `0x4000` | X | Square |
| 15 | `0x8000` | Y | Triangle |

The PC applies `buttons & 0xF7FF`, so a client setting bit 11 cannot push an
undefined bit into the virtual pad.

### Layout byte

Cosmetic only: it picks the glyphs and body shape the PC draws, and never
changes the meaning of a bit. The mask is positional and identical across
vendors, because Android reports the bottom face button as `KEYCODE_BUTTON_A`
on every pad: bit `0x1000` is cross on a DualSense, A on an Xbox pad and B on a
Nintendo one. The phone picks the value from `InputDevice.getVendorId()` (Sony
`0x054C`, Microsoft `0x045E`, Nintendo `0x057E`), falling back to a device-name
match for third-party pads. An unknown value is drawn with neutral,
position-based names.

### Sending

- A packet goes out as soon as pad state changes, at least 2 ms apart (500 Hz
  ceiling), and as a keepalive every 500 ms when nothing changes.
- Every packet is a complete snapshot, never a delta, so a lost packet is
  corrected by the next one.
- A press and release that both land between two sends are not lost: the
  press goes out in the next packet and the release immediately after.
- When the link stops, the phone sends one final neutral packet (all zero,
  flags 0) so the PC releases everything without waiting for the watchdog.

### Sessions

- The phone keeps a counter per paired PC (`pc.<id>.session`). Each new link
  takes `stored + 1`, persists it, and sends it as a u32. It restarts at 0 only
  with a new pairing, on both sides.
- The phone starts a new session at the start of every link, and again whenever
  3 s pass with no authenticated ack (measured from the later of the last ack
  and the session's start), unless the PC has reported a version mismatch. A
  new session is what a PC that restarted, or a PC whose pad is held by another
  phone, will accept.
- The PC persists each phone's `highest_session`. It keeps the newest
  `(session, seq)` of each phone's current session **in memory only**, per
  phone, across the watchdog and across phones taking turns, so a stretch of
  silence never reopens a window for replaying that session.

### Receiver acceptance order

For every datagram on the input port:

1. **Source filter.** The source must be loopback, RFC 1918 (`10/8`,
   `172.16/12`, `192.168/16`), IPv4 link-local (`169.254/16`), or on IPv6 `::1`,
   `fe80::/10`, `fc00::/7` (IPv4-mapped addresses are unwrapped). Carrier-grade
   NAT (`100.64/10`, also Tailscale) is deliberately excluded. Anything else is
   dropped.
2. Empty: dropped. First byte `0xD7`: handled as PAIR_REQ (above).
3. Shorter than 2 bytes or magic not `0xD5`: dropped.
4. **Version.** Not 2 (every v1 packet included): answered with an unsigned
   version-mismatch ack if the datagram is at least 12 bytes, at most once per
   second per source (IP, port). Nothing is applied.
5. **Length** not exactly 36: dropped.
6. **KID lookup.** No paired phone has this KID: answered with an unsigned
   not-paired ack, at most once per second per source (IP, port). A 32-bit KID
   can collide, so every paired phone with that KID is a candidate.
7. **MAC** over bytes 0..27, tried against each candidate's key, constant time.
   No match: dropped silently, **no ack**, so a forger learns nothing about how
   far a guess got.
8. **Session**, against the phone's persisted `highest_session`:
   - `session > highest`: a new session. `highest_session` is raised and
     written to disk before the packet is accepted, and the phone's in-memory state becomes
     `(session, seq)`. Accepted.
   - `session < highest`: a replay of an old session. Dropped.
   - `session == highest`: accepted only if the in-memory state is for this
     same session and `seq` is newer than the newest seen:
     `0 < (seq - newest) mod 2^32 < 2^31` (u32 half-window, so wraparound
     works). If there is no in-memory state for it (the PC restarted since the
     session began), it is dropped: after a restart the newest seq of that
     session is unknown, and accepting it would let a recording of the session
     be replayed. The phone recovers on its own by rotating to a new session
     after 3 s without acks.
   The session and seq are recorded here, before the peer lock below.
9. **Single-peer lock.** One paired phone holds the pad at a time.
   - Packet from the holder: accepted. If it arrives from a new address or port
     (Wi-Fi roaming), the PC follows it; acks go to the new address.
   - Packet from another phone that continues an existing session, while the
     receiver is linked and the holder's last packet is less than 0.3 s old:
     not applied. The phone gets a signed ack with pad-live 0.
   - Packet from another phone that starts a **new session** (it just pressed
     Start link), or continues one after the holder has been silent for 0.3 s
     or more: it **takes over** at once. That is authenticated, and it is what
     the person holding it asked for.
10. **Apply.**
    - If another input source owns the pad (a browser client is driving it),
      the packet is authenticated and acked but not applied, the ack's pad-live
      bit is 0, and if this receiver was driving it releases its own input.
    - Else if flags bit 0 is set: buttons (masked with `0xF7FF`), sticks and
      triggers are written to the virtual pad.
    - Else (no physical pad on the phone): the virtual pad is released to
      neutral.
    - The layout byte only feeds the PC's display.
11. **Ack**, rate-limited per phone (see below).

### Watchdog

`WATCHDOG_TIMEOUT` is 1.5 s. The receive loop checks it at least every 0.25 s,
so a silent phone is timed out between 1.5 s and about 1.75 s after its last
accepted packet. On timeout the receiver:

- releases every button and recentres both sticks, but only if it was the one
  driving the pad (a browser holding the pad is left alone),
- drops the peer lock, so the next phone to send takes the pad,
- keeps every phone's in-memory `(session, seq)`, so the same session may carry
  on after a Wi-Fi stall but nothing recorded before the stall can be replayed,
- resumes the beacon.

If a write to the virtual pad throws, the receiver releases the pad and reports
pad-live 0 until a write succeeds again.

## Acks

Sent by the PC to the source address and port of the input packet that
triggered them.

| Offset | Size | Type | Field | Notes |
| --- | --- | --- | --- | --- |
| 0 | 1 | u8 | magic | `0xD6` |
| 1 | 1 | u8 | version | the **PC's** protocol version, 2 |
| 2 | 4 | u32 | ack_seq | seq of the input packet that triggered this ack |
| 6 | 4 | u32 | received | signed form: the receiver's count of accepted packets from whichever phone held the pad, mod 2^32 (packets from a phone refused by the peer lock are not counted). Unsigned form: 0 |
| 10 | 1 | u8 | flags | see below |
| 11 | 1 | u8 | reserved | 0 |
| 12 | 8 | bytes | mac | **signed form only**: MAC over bytes 0..11 under the phone's K |

| Flag | Value | Meaning | Carried by |
| --- | --- | --- | --- |
| bit 0 | `0x01` | pad live: a virtual pad exists, its last write succeeded, this phone holds it and no browser owns it | signed ack only |
| bit 1 | `0x02` | version mismatch: the packet's protocol version is not the PC's | unsigned ack |
| bit 2 | `0x04` | not paired: this PC has no key for the packet's KID | unsigned ack |
| bits 3..7 | | reserved, 0 | |

**Signed ack, 20 bytes.** Sent for every authenticated, accepted packet,
including those from a phone that does not hold the pad (pad-live 0), at most
once per 200 ms **per phone**, so no other sender can use up the driving
phone's acks.

**Unsigned ack, 12 bytes.** Only ever "version mismatch" or "not paired". There
is no key to sign with in either case; forging one costs the user at most a
confusing status line or a re-pair, never input. Each kind is limited to one
per second per source (IP, port); the limiter tables are cleared when they grow
past 64 entries. The mismatch ack is only sent in answer to a datagram of at
least 12 bytes, so it is never larger than the request.

**No ack at all** for: a source outside the allowed ranges, an unknown magic, a
v2 packet of the wrong length, a bad MAC, a replayed or pre-restart session, a
seq that is not newer, or anything over the rate limits.

Phone behaviour (`Protocol.decodeAck`, `UdpSender`):

- Ignored unless it is at least 12 bytes with magic `0xD6` and comes from the
  port the phone sends to. The source IP is deliberately not checked: a docked
  laptop with Wi-Fi and Ethernet on one LAN often answers from the other
  address.
- **Version byte not 2** (for example a future PC): read as a version mismatch
  and counted as "heard"; the app shows the mismatch state.
- The ack's seq must be one of the last 256 seqs this sender sent, or it is
  ignored.
- **20 bytes, version 2**: the MAC must verify under K, otherwise the datagram
  is ignored entirely. Then the ack's seq must match the send-time ring slot
  exactly; the phone updates its round-trip time (smoothed 0.7 old / 0.3 new),
  sets its mismatch state from bit 1 and marks the link as answered for 1.5 s.
  Bit 0 decides what the app shows: set reads LIVE, clear reads PC BUSY (the
  PC answers but is not applying this phone's input).
- **12 bytes, version 2, bit 2 set**: the link ends with "not paired", the
  phone forgets its pairing for that PC, and the next Start link pairs again.
- **12 bytes, version 2, bit 1 set**: mismatch state, counted as heard.
- Any other unsigned ack: ignored. Pad-live is never believed without a MAC.
- While the phone is in the mismatch state it does not rotate sessions.

Acks are advisory. Input never waits on one; losing them only degrades the
status display.

## Storage

### PC: `pairing.json`

In the data directory: `%LOCALAPPDATA%\LudusCtrl` (falling back to the home
directory), or `LUDUSCTRL_DATA_DIR` if set. The browser client's certificate
(`web-cert.pem`, `web-key.pem`) lives in the same directory unless
`LUDUSCTRL_CERT_DIR` points it elsewhere.

```json
{
  "pc_id": "<base64 of 8 bytes>",
  "phones": [
    {
      "id": "<base64 of the 8-byte phone_id>",
      "name": "Google Pixel 8",
      "key": "<base64 of the 32-byte K>",
      "paired_at": "2026-09-23T14:05:12+02:00",
      "highest_session": 7
    }
  ]
}
```

- `paired_at` is local time, ISO 8601 with offset, to the second. KID is not
  stored; it is recomputed from the key on load. Names are cut to 64
  characters on load.
- **Atomic write**: the JSON goes to `pairing.json.tmp`, that file's ACL is
  restricted to the current user (`icacls /inheritance:r /grant:r *<SID>:F`,
  using the SID rather than the name; `chmod 600` off Windows; best effort),
  then it replaces `pairing.json` (retried up to 5 times if something briefly
  holds the old file). The replaced file keeps the temp file's ACL, so it is
  never readable by anyone else, even for an instant.
- Pairing, removal and a raised `highest_session` are all written before
  they take effect. For a session that means the first packet of each link
  waits for one small write; if the PC died before the write, a recording of
  that session would otherwise pass as new after a restart.
- A file that fails to parse (bad base64, wrong key or id length, a session
  outside u32) is moved aside to `pairing.corrupt-<unix time>.json` and the PC
  starts clean with a new pc_id: every phone must pair again. A file that
  exists but cannot be read is left alone, and the PC runs for that session
  with a random pc_id and saves nothing, rather than overwrite it.

### Phone: SharedPreferences `pairing`

Excluded from backup and device transfer (`allowBackup` is off), so a key never
leaves the phone. All byte values are lowercase hex.

| Key | Type | Content |
| --- | --- | --- |
| `phoneId` | string | this install's 8-byte phone_id |
| `pcs` | string set | the pc_ids (hex) of every paired PC |
| `pc.<id>.key` | string | K, 32 bytes |
| `pc.<id>.kid` | string | KID, 4 bytes |
| `pc.<id>.host` | string | where the PC was last reached; emptied when another PC takes that address |
| `pc.<id>.port` | int | its input port |
| `pc.<id>.pairedAt` | long | `System.currentTimeMillis()` at pairing |
| `pc.<id>.session` | long | the last session number used; reset to 0 by a new pairing |

An address belongs to one PC at a time: storing or moving a pairing to an
address clears the host of any other PC recorded there. A damaged entry reads
as not paired. The separate `dslink` preferences hold UI state (last host and
port, the autofilled address) and nothing protocol-related.

## Compatibility

| | PC 1.1 (protocol 1) | PC 1.2 (protocol 2) |
| --- | --- | --- |
| **App 1.1** | v1: unauthenticated 20-byte input, 12-byte acks | The 1.2 beacon is accepted (the app reads the first 8 bytes). Its v1 input is not applied; the PC answers with an unsigned 12-byte ack, version 2, bit 1 set, once per second. The 1.1 app discards acks whose version is not 1, so it shows NO REPLY. Update the app. |
| **App 1.2** | The 8-byte beacon is accepted with no pc_id. The 1.1 PC ignores PAIR_REQ (it accepts only exact 20-byte v1 packets), so pairing shows the "no reply" notice after 5 s and times out at 62 s. Update the PC. | v2: pairing, then signed input and acks |

The browser client is served by the PC it talks to, so page and server always
match.

## Browser client (HTTPS and WebSocket)

For phones that cannot run the app (iPhones). The Gamepad API needs a secure
context, so the page is served over HTTPS; the PC mints a self-signed
certificate (RSA 2048, 825 days, SANs for its LAN addresses, `localhost` and
`127.0.0.1`), which the user accepts once per phone.

### Server

- TCP 45991 on all interfaces, TLS 1.2 minimum. The TLS handshake runs on the
  connection's own thread with a 5 s deadline.
- `GET /` or `/index.html`: the page, with a Content-Security-Policy that pins
  its inline script and style by hash. Any other path: 404. `GET /ws`: the
  WebSocket. One HTTP request per connection.
- At most 16 concurrent connections; one past that is closed immediately.
- HTTP requests time out after 10 s.

### Token

- 16 random bytes, URL-safe base64 (22 characters), new every time the server
  starts.
- The PC shows `https://<pc-ip>:45991/#t=<token>` (one link per LAN address,
  most likely first) and a QR code of it. The token is in the URL fragment, so
  the browser never sends it in a request and it appears in no server log.
- The page reads `t=` from the fragment, keeps it in `sessionStorage` for the
  tab, and removes it from the address bar.

### Handshake

1. The upgrade request needs `Sec-WebSocket-Key` and `Upgrade: websocket`,
   otherwise 400.
2. **Origin check**: if an `Origin` header is present it must equal
   `https://` + the request's `Host` header (case-insensitive), otherwise 403.
   A request with no Origin is not a browser and is let through to the token
   check.
3. 101 Switching Protocols, then a 5 s read deadline applies to every frame.
4. **Authentication**: the first frame must be the text `auth:<token>`,
   compared in constant time. A wrong or missing token gets the text `denied`
   and close 1008 "bad token". No frame within 5 s: close 1008 "no token".
5. **Claim**: only one source drives the pad.
   - The Android app is linked over UDP: text `busy:app`, then close 1000.
   - Another browser holds the pad and sent a packet within the last 1.5 s:
     text `busy`, then close 1000. A holder silent for longer counts as stale
     and is taken over.
6. Success: the server sends `ready`, then `padkind:<kind>`.

After sending its own close frame the server reads for up to 1 s so the
peer's close arrives before the socket closes; otherwise Windows would send a
reset that can destroy the explanatory text frame.

### Frames

Only single, unfragmented, masked frames of at most 4096 bytes are accepted.

Browser to PC:

| Frame | Content | PC response |
| --- | --- | --- |
| text | `auth:<token>` | first frame only, see Handshake |
| binary | 20-byte v1 input packet | applied if it is exactly 20 bytes with magic `0xD5` and version 1 and this connection holds the pad; anything else is ignored with no reply. Acked as below |
| text | `ping:<id>` | `pong:<id>`, echoing at most 59 bytes of `<id>`. Application-level, because browsers do not expose WebSocket ping to scripts. The page sends one per second and times the round trip |
| text | `pad:<kind>` | switch the virtual pad to `x360` or `ds4`: `padkind:<kind>` on success, `paderr:<message>` on failure |
| ping | any | pong with the same payload |
| close | code | the code is echoed back and the session ends |
| other text | | ignored |

PC to browser:

| Text | Meaning |
| --- | --- |
| `ready` | authenticated and holding the pad; start sending |
| `padkind:<kind>` | the virtual pad's type, `x360` or `ds4`. Sent after `ready`, after a successful switch, and after an ack whenever the type changed (the desktop window can switch it too) |
| `paderr:<message>` | a switch failed: `unknown pad kind`, `wait a moment before switching again` (one switch per 2 s), or why the new pad could not be created. A failed switch can leave no pad at all |
| `ack:<seq>:<received>:<applied>` | after a valid packet, at most once per 200 ms per connection: the packet's seq (decimal u32), the bridge's total accepted packets, and `1` if it reached a virtual pad or `0` if none exists right now |
| `pong:<id>` | answer to `ping:<id>` |
| `busy` | another browser holds the pad; the connection closes |
| `busy:app` | the Android app holds the pad; the connection closes |
| `denied` | wrong or missing token; the connection closes |
| `evicted` | this connection no longer holds the pad (the bridge watchdog dropped it); the connection closes and the page reconnects and claims again |

### Close codes

| Code | When |
| --- | --- |
| 1000 | after `busy`, `busy:app` or `evicted` |
| 1001 | no frame at all for 5 s ("idle"); preceded by `evicted` if the claim was already dropped |
| 1002 | reserved bits set, a fragmented, continuation or unknown frame, a control frame over 125 bytes, or an unmasked frame |
| 1008 | bad token ("bad token") or no token within 5 s ("no token") |
| 1009 | a frame over 4096 bytes |

### Input and timing

- The 20-byte body is exactly the v1 layout: bytes 0..19 of the v2 table with
  version 1. The page sends one every animation frame (about 60 Hz) while
  connected, skipping a frame when more than 40 bytes are still buffered, so a
  Wi-Fi stall does not flush seconds of stale snapshots into the game. Its seq
  starts at 0 on Start link and is not reset on reconnect.
- Only pads the browser maps to the W3C standard layout are used; any other pad
  is sent as neutral with flags 0. Flags bit 0 clear releases the virtual pad,
  as on UDP.
- **Bridge watchdog**: checked every 0.25 s. A holder with no valid packet for
  more than 1.5 s (the same `WATCHDOG_TIMEOUT` as UDP) loses the pad, which is
  released to neutral. The connection learns this as `evicted` on its next
  frame or read deadline.
- **Arbitration with UDP**: while a browser holds the pad, UDP packets from a
  paired phone are still authenticated and acked but not applied (pad-live 0).
  While a phone is linked over UDP, a browser's claim is refused with
  `busy:app`.
- The page reconnects 800 ms after an unexpected close while it is running and
  visible, and reads an ack older than 1 s as NO REPLY.

## Timers and limits at a glance

| Where | Name | Value |
| --- | --- | --- |
| PC | beacon interval | 2 s (paused while a phone is linked) |
| PC | input watchdog | 1.5 s |
| PC | peer switch silence | 0.3 s |
| PC | signed ack interval | 200 ms per phone |
| PC | unsigned ack interval | 1 s per source (IP, port) |
| PC | PAIR_REQ rate | 1 per second per source IP |
| PC | pairing prompt | 60 s |
| PC | reveal-less hold | 10 s |
| PC | finished attempt answers | 90 s, 32 attempts |
| Phone | send floor / keepalive | 2 ms / 500 ms |
| Phone | link shown LIVE | 1.5 s after the last authenticated ack |
| Phone | session rotation | 3 s without an authenticated ack |
| Phone | ack seq window | last 256 seqs |
| Phone | pairing resend / no-reply notice / give up | 1 s / 5 s / 62 s |
| Browser | WebSocket read deadline | 5 s |
| Browser | ack interval | 200 ms per connection |
| Browser | pad switch interval | 2 s |
| Browser | max frame / max connections | 4096 bytes / 16 |

## Golden vectors

### Fixed inputs

| Input | Value |
| --- | --- |
| phone private scalar | `11` repeated 32 times (`0x1111...11`) |
| PC private scalar | `22` repeated 32 times (`0x2222...22`) |
| phone_id | `0102030405060708` |
| pc_id | `a1a2a3a4a5a6a7a8` |
| nonce | `000102030405060708090a0b0c0d0e0f` |
| device name | `Pixel 8` |

### Keys and derivations

| Value | Hex |
| --- | --- |
| phone_pub | `040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794` |
| pc_pub | `04d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf350185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c91285` |
| Z | `ccfc261f58193c98ca4ad4a53bbac6f0ee29bc4d48438090446908622ca79af6` |
| K | `78fb82829c51a3cc9762af1ca02bd7749f797d182d18971b695bb78c28ab7a24` |
| KID | `10253095` |
| code | `260329`, shown as `260 329` |
| commitment | `d06ad9ddcb46f53c44d669f7d08fd932` |

`format_code(42)` is `000 042`. The hand-rolled HKDF on Android is also checked
against RFC 5869 test case A.1.

### PAIR_REQ, commit phase (128 bytes)

```
d7020102030405060708040217e617f0b6443928278f96999e69a23a4f2c152b
df6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc75859
9652f2897c65306e579407506978656c2038000000000000000000000000000000
0000000000000000000000d06ad9ddcb46f53c44d669f7d08fd932000000
```

### PAIR_REQ, reveal phase (128 bytes)

```
d7020102030405060708040217e617f0b6443928278f96999e69a23a4f2c152b
df6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc75859
9652f2897c65306e579407506978656c2038000000000000000000000000000000
0000000000000000000001000102030405060708090a0b0c0d0e0f000000
```

### PAIR_RESP

State 1 (accepted), with the MAC under K (asserted on both sides):

```
d802a1a2a3a4a5a6a7a804d65a93977caa3d1b081852ff57a79e465f1660577304ba
ead505dd3a48589cf350185e895372df6221ea3a137557e473fddb6755f05bd507c3
c533fce9c9128501f1980601122fd826
```

State 0 (waiting), as `PairingTest` builds it: the same head with state 0 and
a zero MAC.

```
d802a1a2a3a4a5a6a7a804d65a93977caa3d1b081852ff57a79e465f1660577304ba
ead505dd3a48589cf350185e895372df6221ea3a137557e473fddb6755f05bd507c3
c533fce9c91285000000000000000000
```

### Input packet v2 (36 bytes)

seq `0x12345678`, buttons `0x1000` (cross), LX -32768, LY 32767, RX 12345,
RY -9876, LT 255, RT 128, flags 1, layout 2 (Xbox), session 7, KID and MAC
under the K above:

```
d5027856341200100080ff7f39306cd9ff8001020700000010253095bee0eb8534c2d722
```

Bodies (bytes 0..19), shared with the Android app's tests:

| Case | Bytes 0..19 |
| --- | --- |
| seq 0, neutral, no pad, unknown layout | `d502000000000000000000000000000000000000` |
| seq 1, cross + d-pad up, LX 32767, LY -32768, RX 0, RY -1, LT 255, RT 0, pad, PlayStation | `d502010000000110ff7f00800000ffffff000101` |
| seq `0x12345678`, buttons `0xF7FF`, LX 1234, LY -1234, RX -16384, RY 16384, LT 128, RT 64, pad, Xbox | `d50278563412fff7d2042efb00c0004080400102` |
| seq `0xFFFFFFFF`, triangle, RT 255, no pad, Nintendo | `d502ffffffff0080000000000000000000ff0003` |

Session -1 as an Int encodes as `ffffffff` at bytes 20..23 (unsigned u32).

### Acks

Signed, seq `0x12345678`, received 1000, pad live, MAC under K. The receiver
emits exactly these bytes for the input packet above when its counter stood at
999:

```
d60278563412e80300000100099521f0c16e1df7
```

Unsigned:

| Case | Bytes |
| --- | --- |
| version mismatch, seq `0x12345678` | `d60278563412000000000200` |
| not paired, seq 7 | `d60207000000000000000400` |

### Beacon

Port 45989, pc_id `a1a2a3a4a5a6a7a8`:

```
44534c4b01a5b300a1a2a3a4a5a6a7a8
```

The first 8 bytes, `44534c4b01a5b300`, are all a 1.1 app reads and all a 1.1
PC sends.

### v1 bodies (browser path)

| Case | Bytes |
| --- | --- |
| neutral keepalive, seq 1, pad connected, unknown layout | `d501010000000000000000000000000000000100` |
| every defined button (`0xF7FF`), LX -32768, LY 32767, RX 12345, RY -9876, LT 255, RT 128, pad, Xbox, seq `0xFFFFFFFE` | `d501fefffffffff70080ff7f39306cd9ff800102` |
| cross only, LY -1, RX 1, no pad, PlayStation, seq `0x12345678` | `d5017856341200100000ffff0100000000000001` |
