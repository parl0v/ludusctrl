# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Josip Parlov (@parl0v). See NOTICE for the attribution terms.
"""Pad-layout tables must agree across all four implementations.

The glyphs and control positions are declared five times: Kotlin (PadView),
the two desktop front ends, the phone page, and Python (console names). Nothing at runtime
forces them to match, so they can drift silently -- and since none of this can
be checked without owning an Xbox or Switch pad, the cross-check is the only
thing standing in for hardware.

    python test_layouts.py
"""

from __future__ import annotations

import math
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

sys.path.insert(0, HERE)
import dualsense_link as d  # noqa: E402

# The glyphs are non-ASCII and the Windows console is cp1252 by default, which
# would raise rather than print them.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass

failures = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global failures
    print(f"{'PASS' if ok else 'FAIL'}  {label}" + (f"   {detail}" if detail else ""))
    if not ok:
        failures += 1


def read(*parts: str) -> str:
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


def js_layouts(src: str) -> dict[int, dict]:
    """Pull the LAYOUTS object out of a front end without running it."""
    body = src[src.index("const LAYOUTS = {"):]
    body = body[:body.index("\n};")]
    # Brace-depth scan rather than a regex: each entry contains a nested
    # face:{...}, which a lazy regex would stop at.
    blocks: list[tuple[str, str]] = []
    i = 0
    while True:
        m = re.compile(r"(\d)\s*:\s*\{").search(body, i)
        if not m:
            break
        depth, j = 1, m.end()
        while depth and j < len(body):
            depth += {"{": 1, "}": -1}.get(body[j], 0)
            j += 1
        blocks.append((m.group(1), body[m.end():j - 1]))
        i = j

    out: dict[int, dict] = {}
    for num, block in blocks:
        entry: dict = {}
        face = re.search(r"face:\s*\{(.*?)\}", block, re.S)
        if face:
            entry["face"] = dict(re.findall(r"(\w+)\s*:\s*'([^']*)'", face.group(1)))
        for key in ("sh", "tr"):
            m = re.search(key + r":\s*\['([^']*)','([^']*)'\]", block)
            if m:
                entry[key] = [m.group(1), m.group(2)]
        for key in ("ls", "rs", "dpad", "faceAt", "guideAt", "pillL", "pillR"):
            m = re.search(key + r":\s*\[(\d+),\s*(\d+)\]", block)
            if m:
                entry[key] = (int(m.group(1)), int(m.group(2)))
        m = re.search(r"guide:\s*'([^']*)'", block)
        if m:
            entry["guide"] = m.group(1)
        m = re.search(r"body:\s*'(\w+)'", block)
        if m:
            entry["body"] = m.group(1)
        m = re.search(r"touchpad:\s*(true|false)", block)
        if m:
            entry["touchpad"] = m.group(1) == "true"
        out[int(num)] = entry
    return out


def kt_layouts(src: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for name in ("layoutGeneric", "layoutPlaystation", "layoutXbox", "layoutNintendo"):
        block = src[src.index(f"private val {name} = Layout("):]
        block = block[:block.index("\n    )")]
        strs = re.findall(r'"((?:[^"\\]|\\.)*)"', block)
        entry = {
            "face": {"n": strs[0], "e": strs[1], "s": strs[2], "w": strs[3]},
            "sh": [strs[4], strs[5]],
            "tr": [strs[6], strs[7]],
            "guide": strs[8],
        }
        for key in ("lsX", "lsY", "rsX", "rsY", "dpadX", "dpadY", "faceX", "faceY",
                    "guideX", "guideY", "pillLX", "pillLY", "pillRX", "pillRY"):
            entry[key] = float(re.search(key + r"\s*=\s*([\d.]+)f", block).group(1))
        entry["body"] = re.search(r'bodyStyle = "(\w+)"', block).group(1)
        entry["touchpad"] = "touchpad = true" in block
        # Both sources store the real characters, so nothing is decoded here.
        # An encode/unicode_escape round trip would corrupt exactly the
        # non-ASCII glyphs this test exists to compare.
        out[name] = entry
    return out


def mobile_layouts(src: str) -> dict[int, dict]:
    """The phone page's table, in the shape js_layouts returns.

    It uses PadView's field names and builds Nintendo and the unknown pad by
    Object.assign over Xbox, so the overrides are merged here the way the page
    merges them at runtime.
    """
    ids = {k: int(v) for k, v in re.findall(
        r"(\w+):\s*(\d)", re.search(r"const LAYOUT = \{(.*?)\}", src).group(1))}
    raw: dict[str, dict] = {}
    entry = re.compile(r"LAYOUTS\[LAYOUT\.(\w+)\] = "
                       r"(?:Object\.assign\(\{\}, LAYOUTS\[LAYOUT\.(\w+)\], )?\{(.*?)\n\}", re.S)
    for m in entry.finditer(src):
        name, base, block = m.groups()
        fields: dict = dict(re.findall(r'(\w+):\s*"([^"]*)"', block))
        fields.update({k: float(v) for k, v in re.findall(r"(\w+):\s*(\d+(?:\.\d+)?)\b", block)})
        fields.update({k: v == "true" for k, v in re.findall(r"(\w+):\s*(true|false)", block)})
        raw[name] = {**raw[base], **fields} if base else fields

    def at(f: dict, key: str) -> tuple[int, int]:
        return int(f[key + "X"]), int(f[key + "Y"])

    out: dict[int, dict] = {}
    for name, f in raw.items():
        out[ids[name]] = {
            "face": {"n": f["faceN"], "e": f["faceE"], "s": f["faceS"], "w": f["faceW"]},
            "sh": [f["shoulderL"], f["shoulderR"]],
            "tr": [f["triggerL"], f["triggerR"]],
            "guide": f["guide"],
            "body": f["bodyStyle"],
            "touchpad": f["touchpad"],
            "ls": at(f, "ls"), "rs": at(f, "rs"), "dpad": at(f, "dpad"),
            "faceAt": at(f, "face"), "guideAt": at(f, "guide"),
            "pillL": at(f, "pillL"), "pillR": at(f, "pillR"),
        }
    return out


def function_body(src: str, name: str) -> str:
    """Source of a top-level JS function, up to its closing brace in column 0."""
    start = src.index(f"function {name}")
    return src[start:src.index("\n}", start) + 2]


def outlines(src: str) -> dict[str, list[tuple[float, float]]]:
    """Each bodyPath branch flattened to a polygon, keyed by body style."""
    fn = function_body(src, "bodyPath")
    branches = re.findall(r"style === '(\w+)'\) \{(.*?)\n  \}", fn, re.S)
    branches.append(("ps", re.search(r"\} else \{(.*?)\n  \}", fn, re.S).group(1)))
    out: dict[str, list[tuple[float, float]]] = {}
    for style, code in branches:
        pts: list[tuple[float, float]] = []
        for op, args in re.findall(r"g\.(moveTo|lineTo|bezierCurveTo)\(([^)]*)\)", code):
            n = [float(v) for v in args.split(",")]
            if op != "bezierCurveTo":
                pts.append((n[0], n[1]))
                continue
            (x0, y0), (x1, y1, x2, y2, x3, y3) = pts[-1], n
            for i in range(1, 25):
                t = i / 24
                u = 1 - t
                pts.append((u**3 * x0 + 3 * u * u * t * x1 + 3 * u * t * t * x2 + t**3 * x3,
                            u**3 * y0 + 3 * u * u * t * y1 + 3 * u * t * t * y2 + t**3 * y3))
        out[style] = pts
    return out


def inset(poly: list[tuple[float, float]], x: float, y: float) -> float:
    """Distance from (x, y) to the outline, negative when the point is outside."""
    inside, best = False, float("inf")
    for (ax, ay), (bx, by) in zip(poly, poly[1:] + poly[:1]):
        if (ay > y) != (by > y) and x < ax + (y - ay) * (bx - ax) / (by - ay):
            inside = not inside
        dx, dy = bx - ax, by - ay
        t = max(0.0, min(1.0, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy or 1)))
        best = min(best, math.hypot(x - ax - t * dx, y - ay - t * dy))
    return best if inside else -best


def reach(L: dict) -> list[tuple[str, float, float, float]]:
    """Every control as a disc (name, x, y, radius) covering what gets drawn."""
    fx, fy = L["faceAt"]
    return [("left stick", *L["ls"], 26), ("right stick", *L["rs"], 26),
            ("d-pad", *L["dpad"], math.hypot(16, 6.5)),
            ("face N", fx, fy - 23, 11), ("face E", fx + 23, fy, 11),
            ("face S", fx, fy + 23, 11), ("face W", fx - 23, fy, 11),
            ("guide", *L["guideAt"], 9),
            ("left pill", *L["pillL"], math.hypot(8, 7)),
            ("right pill", *L["pillR"], math.hypot(8, 7))]


def main() -> int:
    web_src = read("pc", "webui", "index.html")
    mobile_src = read("pc", "webui-mobile", "index.html")
    # The Android app is not part of the published receiver, so its checks
    # run only in a checkout that has it.
    kt_path = os.path.join(ROOT, "android", "app", "src", "main", "java", "com",
                           "parlov", "ludusctrl", "PadView.kt")
    kt_src = read(kt_path) if os.path.isfile(kt_path) else None
    web = js_layouts(web_src)
    inst = js_layouts(read("pc", "webui-instrument", "index.html"))
    mob = mobile_layouts(mobile_src)
    kt = kt_layouts(kt_src) if kt_src else None

    print("--- the two desktop front ends agree ---")
    check("every layout id has its own entry", sorted(web) == [0, 1, 2, 3], str(sorted(web)))
    check("same layout ids defined", sorted(web) == sorted(inst),
          f"{sorted(web)} vs {sorted(inst)}")
    for num in sorted(set(web) & set(inst)):
        check(f"layout {num} identical", web[num] == inst[num])

    print("\n--- the phone page agrees with the desktop tables ---")
    check("same layout ids defined", sorted(mob) == sorted(web),
          f"{sorted(mob)} vs {sorted(web)}")
    for num in sorted(set(mob) & set(web)):
        diff = sorted(k for k in web[num] if mob[num].get(k) != web[num][k])
        check(f"layout {num} identical", not diff, f"differs in {diff}")

    if kt is None:
        print("\n--- Kotlin checks skipped: android/ is not in this checkout ---")
    else:
        print("\n--- Kotlin agrees with the desktop tables ---")
        pairs = [("layoutGeneric", 0), ("layoutPlaystation", 1), ("layoutXbox", 2),
                 ("layoutNintendo", 3)]
        for name, num in pairs:
            k, w = kt[name], web[num]
            check(f"{name} face glyphs", k["face"] == w["face"], f"{k['face']} vs {w['face']}")
            check(f"{name} shoulders", k["sh"] == w["sh"], f"{k['sh']} vs {w['sh']}")
            check(f"{name} triggers", k["tr"] == w["tr"], f"{k['tr']} vs {w['tr']}")
            check(f"{name} guide", k["guide"] == w["guide"], f"{k['guide']!r} vs {w['guide']!r}")
            check(f"{name} touchpad", k["touchpad"] == w["touchpad"])
            check(f"{name} body style", k["body"] == w["body"], f"{k['body']} vs {w['body']}")
            for kkey, wkey, idx in [("lsX", "ls", 0), ("lsY", "ls", 1),
                                    ("rsX", "rs", 0), ("rsY", "rs", 1),
                                    ("dpadX", "dpad", 0), ("dpadY", "dpad", 1),
                                    ("faceX", "faceAt", 0), ("faceY", "faceAt", 1),
                                    ("guideX", "guideAt", 0), ("guideY", "guideAt", 1),
                                    ("pillLX", "pillL", 0), ("pillLY", "pillL", 1),
                                    ("pillRX", "pillR", 0), ("pillRY", "pillR", 1)]:
                check(f"{name} {kkey}", k[kkey] == w[wkey][idx],
                      f"{k[kkey]} vs {w[wkey][idx]}")

    print("\n--- an unrecognised pad is not drawn as a DualSense ---")
    # Feedback #6: layout 0 used to alias PlayStation, so a generic Bluetooth
    # pad got a touchpad and shape-glyphs it does not have.
    if kt_src:
        layout_for = kt_src[kt_src.index("private fun layoutFor"):]
        layout_for = layout_for[:layout_for.index("\n    }")]
        check("Kotlin falls back to the generic layout",
              "else -> layoutGeneric" in layout_for
              and "Protocol.LAYOUT_PLAYSTATION -> layoutPlaystation" in layout_for)
    check("desktop front ends no longer alias layout 0 to PlayStation",
          "LAYOUTS[0] = LAYOUTS[1]" not in web_src
          and "LAYOUTS[0] = LAYOUTS[1]" not in read("pc", "webui-instrument", "index.html"))
    check("phone page falls back to the unknown layout",
          "LAYOUTS[s.layout] || LAYOUTS[LAYOUT.UNKNOWN]" in mobile_src
          and "LAYOUTS[LAYOUT.UNKNOWN] = LAYOUTS[LAYOUT.PLAYSTATION]" not in mobile_src)
    check("unknown pad has no touchpad", not web[0]["touchpad"])
    check("unknown pad draws the generic body", web[0]["body"] == "generic", web[0]["body"])
    check("unknown pad letters the bottom button A, as Android names it",
          web[0]["face"] == {"n": "Y", "e": "B", "s": "A", "w": "X"}, str(web[0]["face"]))
    check("unknown pad uses Android's L1/L2 naming",
          web[0]["sh"] == ["L1", "R1"] and web[0]["tr"] == ["L2", "R2"])
    check("unknown pad sits its controls where Xbox does",
          all(web[0][k] == web[2][k]
              for k in ("ls", "rs", "dpad", "faceAt", "guideAt", "pillL", "pillR")))

    print("\n--- the layouts say what they should ---")
    check("only PlayStation has a touchpad",
          [n for n in range(4) if web[n]["touchpad"]] == [1],
          str([n for n in range(4) if web[n]["touchpad"]]))
    check("Xbox letters the bottom button A", web[2]["face"]["s"] == "A")
    check("Nintendo letters the bottom button B", web[3]["face"]["s"] == "B")
    check("Nintendo swaps A and B against Xbox",
          web[2]["face"]["s"] == web[3]["face"]["e"] == "A"
          and web[2]["face"]["e"] == web[3]["face"]["s"] == "B")
    check("Xbox uses bumper/trigger naming",
          web[2]["sh"] == ["LB", "RB"] and web[2]["tr"] == ["LT", "RT"])
    check("PlayStation keeps L1/L2 naming",
          web[1]["sh"] == ["L1", "R1"] and web[1]["tr"] == ["L2", "R2"])

    print("\n--- Xbox really is a different body, not a relabel ---")
    check("Xbox moves the left stick off the PlayStation position",
          web[2]["ls"] != web[1]["ls"], f"{web[2]['ls']} vs {web[1]['ls']}")
    # The exact coordinates are tuned to the Xbox shell, so assert the
    # arrangement rather than pinning numbers that legitimately move.
    check("Xbox left stick is upper-left, above its d-pad",
          web[2]["ls"][1] < web[2]["dpad"][1] and web[2]["ls"][0] < 200,
          f"ls={web[2]['ls']} dpad={web[2]['dpad']}")
    check("Xbox d-pad drops to the lower row",
          web[2]["dpad"][1] > web[2]["ls"][1])
    check("Xbox face buttons stay upper-right",
          web[2]["faceAt"][0] > 250 and web[2]["faceAt"][1] < web[2]["rs"][1],
          f"face={web[2]['faceAt']} rs={web[2]['rs']}")
    check("Xbox mirrors its two rows",
          web[2]["ls"][1] == web[2]["faceAt"][1]
          and web[2]["dpad"][1] == web[2]["rs"][1])
    check("Xbox d-pad is left of its right stick",
          web[2]["dpad"][0] < web[2]["rs"][0])
    check("each family draws its own shell",
          [web[n]["body"] for n in range(4)] == ["generic", "ps", "xbox", "nintendo"],
          " / ".join(web[n]["body"] for n in range(4)))
    check("Xbox guide sits at the top, PlayStation between the sticks",
          web[2]["guideAt"][1] < web[2]["faceAt"][1] < web[1]["guideAt"][1],
          f"xbox y={web[2]['guideAt'][1]}, ps y={web[1]['guideAt'][1]}")
    check("centre pills straddle the midline",
          web[2]["pillL"][0] < 200 < web[2]["pillR"][0]
          and web[1]["pillL"][0] < 200 < web[1]["pillR"][0])
    check("no control hangs below the Xbox waist (y=174)",
          max(web[2]["ls"][1], web[2]["rs"][1], web[2]["dpad"][1]) + 26 <= 176,
          f"lowest reach {max(web[2]['ls'][1], web[2]['rs'][1], web[2]['dpad'][1]) + 26}")

    print("\n--- the shells hold their controls ---")
    # The DualSense wells deliberately straddle its notch, so only the shells
    # drawn around the Xbox arrangement are held to containment.
    shells = outlines(web_src)
    for num in (0, 2, 3):
        body = web[num]["body"]
        worst = min((inset(shells[body], x, y) - r, what) for what, x, y, r in reach(web[num]))
        need = 0 if body == "xbox" else 6
        check(f"layout {num} ({body}) keeps every control {need}+ units inside its outline",
              worst[0] >= need, f"tightest: {worst[1]} at {worst[0]:.1f}")
    for body, poly in shells.items():
        xs = [x for x, _ in poly]
        check(f"{body} outline is mirrored about x=200",
              abs((min(xs) + max(xs)) / 2 - 200) < 0.5, f"{min(xs):.1f}..{max(xs):.1f}")
        check(f"{body} outline stays in the 400x250 design space",
              all(0 <= x <= 400 and 0 <= y <= 250 for x, y in poly))

    print("\n--- each front end actually uses its table ---")
    # Comparing the tables alone once passed while the instrument UI still drew
    # a hardcoded DualSense outline, so check the call sites too.
    styles = {e["body"] for e in web.values()}
    for label, src in (("main UI", web_src),
                       ("instrument UI", read("pc", "webui-instrument", "index.html"))):
        check(f"{label} draws the layout's body", "bodyPath(g, L.body)" in src)
        check(f"{label} places the guide from the layout", "L.guideAt[0]" in src)
        check(f"{label} places the centre pills from the layout", "L.pillL[0]" in src)
        check(f"{label} places the sticks from the layout", "L.ls[0]" in src)
        check(f"{label} places the d-pad from the layout", "L.dpad[0]" in src)
        path = function_body(src, "bodyPath")
        missing = [s for s in styles - {"ps"} if f"style === '{s}'" not in path]
        check(f"{label} has a branch for every body style", not missing, f"missing {missing}")
        check(f"{label} draws the same outlines as the main UI",
              path == function_body(web_src, "bodyPath"))
        # The only legitimate DualSense outline is the one inside bodyPath's
        # else branch; anywhere else means a hardcoded shell got left behind.
        outside = src.replace(path, "")
        check(f"{label} has no hardcoded outline outside bodyPath",
              "g.moveTo(72, 50)" not in outside)

    # The phone page and Kotlin spell the same paths with their own API, so
    # compare the numbers: every coordinate list must match the main UI's.
    def numbers(code: str) -> list[str]:
        return re.findall(r"\d+(?:\.\d+)?", code)

    web_fn = function_body(web_src, "bodyPath")
    mobile_fn = function_body(mobile_src, "drawBody")
    for s in styles - {"ps"}:
        check(f"phone page draws the {s} body", f'style === "{s}"' in mobile_fn)
        if kt_src:
            check(f"Kotlin draws the {s} body", f'"{s}" ->' in kt_src)

    def branch(fn: str, quote: str, style: str) -> str:
        if style == "ps":
            return re.search(r"\} else \{(.*?)\n  \}", fn, re.S).group(1)
        return re.search(rf"style === {quote}{style}{quote}\) \{{(.*?)\n  \}}", fn, re.S).group(1)

    kt_bodies = {"ps": "bodyPlaystation", "xbox": "bodyXbox",
                 "nintendo": "bodyNintendo", "generic": "bodyGeneric"}
    for s in sorted(styles):
        want = numbers(re.sub(r"//.*", "", branch(web_fn, "'", s)))
        got_m = numbers(re.sub(r"//.*", "", branch(mobile_fn, '"', s)))
        check(f"phone page {s} outline matches", got_m == want)
        if kt_src:
            kt_block = kt_src[kt_src.index(f"private val {kt_bodies[s]} = Path()"):]
            got_k = numbers(re.sub(r"//.*", "", kt_block[:kt_block.index("\n    }")]))
            check(f"Kotlin {s} outline matches", got_k == want)

    print("\n--- Python console names line up with the glyphs ---")
    check("Xbox console names", d.describe_buttons(0x1000 | 0x0100, d.LAYOUT_XBOX) == "LB+A")
    check("PlayStation console names",
          d.describe_buttons(0x1000 | 0x0100, d.LAYOUT_PLAYSTATION) == "L1+cross")
    check("Nintendo console names", d.describe_buttons(0x1000, d.LAYOUT_NINTENDO) == "B")
    check("unknown pad stays vendor-neutral",
          d.describe_buttons(0x1000, d.LAYOUT_UNKNOWN) == "south")
    check("every layout names all 15 bits",
          all(len(v) == len(d._BITS) for v in d._NAMES.values()))

    print("\n--- the wire format did not grow ---")
    check("packet is still 20 bytes", d.PACKET.size == 20, str(d.PACKET.size))
    raw = d.PACKET.pack(0xD5, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, d.LAYOUT_XBOX)
    check("layout rides in byte 19", raw[19] == d.LAYOUT_XBOX, str(raw[19]))
    check("a pre-layout client still parses",
          d.PACKET.unpack(bytes(raw[:19]) + b"\x00")[11] == d.LAYOUT_UNKNOWN)

    print()
    if failures:
        print(f"FAILED: {failures} check(s)")
        return 1
    print("all layout checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
