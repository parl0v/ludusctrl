# Security

The receiver turns network packets into a game controller and installs a
kernel driver, so security reports are taken seriously.

## Reporting a vulnerability

Email **josipparlov@protonmail.com** with "LudusCtrl security" in the subject.
Please do not open a public issue for it.

Include what you found, the version (`pc/version.py`, or Properties > Details
on `LudusCtrl.exe`), and the steps or packets that reproduce it. You will get a
reply within a week, and credit in the release notes if you want it.

## In scope

- Anything that lets a device on the network drive or disturb the virtual pad
  without being paired: forged or replayed packets, pairing bypasses, code
  confusion, crashes from malformed input.
- The browser client: token or Origin bypass, TLS handling, the WebSocket
  framing.
- Local issues: `pairing.json` or the certificate key readable by other
  accounts, the installer's firewall rules opening more than they should.

## Out of scope

- Someone on the network seeing pad input. The link is authenticated, not
  encrypted, by design (see [README](README.md#security-model)).
- Malware already running on the PC or the phone.
- Issues in ViGEmBus, vgamepad or other third-party components; report those
  upstream.

The protocol, including every check the receiver makes and in what order, is
documented in [docs/PROTOCOL.md](docs/PROTOCOL.md).
