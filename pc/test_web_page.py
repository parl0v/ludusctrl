# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Josip Parlov (@parl0v). See NOTICE for the attribution terms.
"""Checks on the browser-facing pages that need a JavaScript engine.

1. The phone page's encode() must produce byte-for-byte what the receiver's
   PACKET.pack produces, and sample() must refuse a pad the browser could not
   map to the standard layout. The page's real script is run under node with
   a stub DOM, so this tests the shipped code, not a copy of it.
2. The QR encoder embedded in both desktop front ends must produce codes an
   independent decoder (OpenCV) reads back exactly.
3. The phone page must stay compatible with its Content-Security-Policy: no
   inline style or event-handler attributes, which the hash-pinned CSP blocks.

Skips (and says so) when node or OpenCV is not installed.

    python test_web_page.py
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import dualsense_link as dsl  # noqa: E402

FAILURES: list[str] = []


def check(name: str, ok, detail: str = "") -> None:
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail else ""))
    if not ok:
        FAILURES.append(name)


def read(*parts: str) -> str:
    with open(os.path.join(HERE, *parts), encoding="utf-8") as fh:
        return fh.read()


def node(code: str) -> str | None:
    exe = shutil.which("node")
    if not exe:
        return None
    # Over stdin: the page script is far past Windows' command-line limit.
    out = subprocess.run([exe, "-"], input=code, capture_output=True, text=True,
                         encoding="utf-8", timeout=60)
    if out.returncode != 0:
        raise RuntimeError(out.stderr)
    return out.stdout


# A DOM that absorbs everything: every property is another stub, every call
# returns one. Enough for the page's top-level wiring to run without a browser.
STUB = r"""
const vm = require('vm');
function stub() {
  return new Proxy(function () {}, {
    get: (t, k) => k === Symbol.toPrimitive ? () => 0 : (k === 'then' ? undefined : stub()),
    set: () => true, apply: () => stub(), construct: () => stub(),
  });
}
let pads = [];
const ctx = {
  document: stub(), window: null, history: stub(), sessionStorage: stub(),
  location: { hash: '', pathname: '/', search: '', protocol: 'https:',
              host: 'pc:45991', hostname: 'pc', port: '45991' },
  navigator: { getGamepads: () => pads },
  performance, TextEncoder, console,
  requestAnimationFrame: () => 0, setInterval: () => 0, setTimeout: () => 0,
  clearTimeout: () => {}, WebSocket: stub(),
};
ctx.window = new Proxy(ctx, { get: (t, k) => k in t ? t[k] : stub(), set: (t, k, v) => { t[k] = v; return true; } });
ctx.window.addEventListener = () => {};
ctx.window.isSecureContext = true;
ctx.window.devicePixelRatio = 1;
vm.createContext(ctx);
"""


def test_encode() -> None:
    print("--- phone page: encode() matches the receiver's PACKET ---")
    html = read("webui-mobile", "index.html")
    script = re.search(r"<script>(.*?)</script>", html, re.S).group(1)
    snapshots = [
        dict(seq=0, buttons=0, lx=0, ly=0, rx=0, ry=0, lt=0, rt=0, connected=False, layout=0),
        dict(seq=7, buttons=0x1000, lx=-12345, ly=6000, rx=300, ry=-400, lt=128, rt=255,
             connected=True, layout=1),
        dict(seq=0xFFFFFFFF, buttons=0xF7FF, lx=-32768, ly=32767, rx=32767, ry=-32768,
             lt=255, rt=1, connected=True, layout=3),
        dict(seq=123456, buttons=0x0001 | 0x0400, lx=1, ly=-1, rx=-2, ry=2, lt=3, rt=4,
             connected=True, layout=2),
    ]
    code = STUB + "vm.runInContext(" + json.dumps(
        script + "\n;globalThis.__t = { encode, buf, sample, setSeq: v => { seq = v; } };") + ", ctx);\n" + r"""
const t = ctx.__t, out = { encoded: [], samples: {} };
for (const s of """ + json.dumps(snapshots) + r""") {
  t.setSeq(s.seq); t.encode(s);
  out.encoded.push(Buffer.from(t.buf).toString('hex'));
}
const mk = (mapping) => ({
  connected: true, index: 0, id: '054c-0ce6-Wireless Controller', mapping,
  buttons: Array.from({ length: 17 }, (_, i) => ({
    pressed: i === 0 || i === 12, value: i === 6 ? 0.5 : (i === 0 || i === 12 ? 1 : 0) })),
  axes: [1, 0, 0, -1],
});
pads = [mk('standard')];
const a = t.sample(); delete a.pad; out.samples.standard = a;
pads = [mk('')];
const b = t.sample(); delete b.pad; out.samples.unmapped = b;
console.log(JSON.stringify(out));
"""
    raw = node(code)
    if raw is None:
        print("SKIP  node is not installed; encode() not checked")
        return
    out = json.loads(raw)
    for s, got in zip(snapshots, out["encoded"]):
        want = dsl.PACKET.pack(dsl.MAGIC, dsl.VERSION, s["seq"], s["buttons"], s["lx"], s["ly"],
                               s["rx"], s["ry"], s["lt"], s["rt"], 1 if s["connected"] else 0,
                               s["layout"]).hex()
        check(f"encode seq={s['seq']:#x}", got == want, "" if got == want else f"{got} != {want}")

    std = out["samples"]["standard"]
    check("standard pad: buttons read by W3C index", std["buttons"] == 0x1000 | 0x0001, hex(std["buttons"]))
    check("standard pad: sticks, Y flipped to positive-up",
          (std["lx"], std["ly"], std["rx"], std["ry"]) == (32767, 0, 0, 32767),
          str((std["lx"], std["ly"], std["rx"], std["ry"])))
    check("standard pad: analog trigger", std["lt"] == 128 and std["rt"] == 0)
    check("standard pad: connected, PlayStation layout", std["connected"] and std["layout"] == 1)
    un = out["samples"]["unmapped"]
    check("non-standard mapping reported, not guessed", un["unsupported"] is True)
    check("non-standard mapping sent as neutral and disconnected",
          not un["connected"] and un["buttons"] == 0
          and (un["lx"], un["ly"], un["rx"], un["ry"], un["lt"], un["rt"]) == (0, 0, 0, 0, 0, 0))


def test_qr() -> None:
    print("\n--- desktop front ends: embedded QR encoder ---")
    blocks = []
    for ui in ("webui", "webui-instrument"):
        m = re.search(r"/\* QR:BEGIN \*/(.*?)/\* QR:END \*/", read(ui, "index.html"), re.S)
        check(f"{ui} embeds the QR encoder", bool(m))
        if m:
            blocks.append(m.group(1))
    if len(blocks) == 2:
        check("both front ends carry the same encoder", blocks[0] == blocks[1])
    if not blocks:
        return
    try:
        import cv2
        import numpy as np
    except ImportError:
        print("SKIP  OpenCV is not installed; QR output not decoded")
        return

    texts = [f"https://192.168.{i}.{i * 7 % 250 + 2}:45991/#t={secrets.token_urlsafe(16)}"
             for i in range(8)]
    texts += ["a", "x" * 40, "y" * 100, "z" * 170, "w" * 210]   # versions 1 to 10
    raw = node(blocks[0] + "\nconsole.log(JSON.stringify(" + json.dumps(texts) +
               ".map(t => QR.encode(t).map(r => r.map(v => v ? 1 : 0).join('')))));")
    if raw is None:
        print("SKIP  node is not installed; QR output not decoded")
        return
    # OpenCV's classic detector misses a few percent of perfectly sharp
    # synthetic codes at some pixel scales (a detection quirk; over 400 random
    # links every one decoded under some setting and none ever decoded wrong).
    # So each code gets both detectors and a few renderings, and must decode
    # to exactly the input in at least one, and to nothing else in any.
    detectors = [cv2.QRCodeDetector()]
    if hasattr(cv2, "QRCodeDetectorAruco"):
        detectors.append(cv2.QRCodeDetectorAruco())

    def render(rows, cell, blur):
        n = len(rows)
        img = np.full(((n + 8) * cell, (n + 8) * cell), 255, np.uint8)
        for y, row in enumerate(rows):
            for x, c in enumerate(row):
                if c == "1":
                    img[(y + 4) * cell:(y + 5) * cell, (x + 4) * cell:(x + 5) * cell] = 0
        return cv2.GaussianBlur(img, (3, 3), 0) if blur else img

    for text, rows in zip(texts, json.loads(raw)):
        n = len(rows)
        decoded = set()
        for det in detectors:
            for cell in (4, 6, 8, 10):
                for blur in (False, True):
                    got, _, _ = det.detectAndDecode(render(rows, cell, blur))
                    if got:
                        decoded.add(got)
        check(f"QR version {(n - 17) // 4:2d}, {len(text):3d} bytes decodes exactly",
              decoded == {text}, "" if decoded == {text} else repr(decoded))


def test_csp_compat() -> None:
    print("\n--- phone page stays inside its CSP ---")
    html = read("webui-mobile", "index.html")
    body = re.sub(r"<(script|style)>.*?</\1>", "", html, flags=re.S)
    check("no inline style attributes", " style=" not in body)
    check("no inline event handlers", not re.search(r"\son[a-z]+=", body))
    check("exactly one inline script and one style block",
          len(re.findall(r"<script>", html)) == 1 and len(re.findall(r"<style>", html)) == 1)
    check("no external resources", not re.search(r"(src|href)=\"https?:", html))


def test_pairing_block() -> None:
    print("\n--- desktop front ends: pairing prompt and paired phones ---")
    blocks = []
    for ui in ("webui", "webui-instrument"):
        html = read(ui, "index.html")
        m = re.search(r"/\* PAIRING:BEGIN \*/(.*?)/\* PAIRING:END \*/", html, re.S)
        check(f"{ui} carries the pairing block", bool(m))
        if m:
            blocks.append(m.group(1))
        ids = ["pairSheet", "pairName", "pairCode", "pairCount", "pairAllow", "pairDeny",
               "phonesSheet", "phonesList", "phonesEmpty", "phonesClose", "phonesBtn",
               "phonesNote"]
        missing = [i for i in ids if f'id="{i}"' not in html]
        check(f"{ui} has every element the block uses", not missing, str(missing))
        # Names come off the network: never through innerHTML.
        check(f"{ui} writes phone names as text only",
              m and "innerHTML" not in m.group(1))
    if len(blocks) == 2:
        check("both front ends carry the same pairing code", blocks[0] == blocks[1])


def main() -> int:
    for t in (test_encode, test_qr, test_pairing_block, test_csp_compat):
        try:
            t()
        except Exception as exc:
            check(f"{t.__name__} ran without error", False, repr(exc)[:400])
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s): " + ", ".join(FAILURES))
        return 1
    print("all web page checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
