# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Josip Parlov (@parl0v). See NOTICE for the attribution terms.
"""Checks the DualShock 4 target is what Windows actually sees.

Creates a DS4 virtual pad and confirms the OS enumerates it with Sony's real
hardware id, then exercises the conversions that differ from XInput: unsigned
byte axes with an inverted Y, and the d-pad collapsing to an 8-way hat.

    python test_ds4.py

Requires vgamepad and ViGEmBus. Does not require an Android device.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# The services below keep a pairing store; it goes to a throwaway directory,
# never the real one.
DATA_TMP = tempfile.mkdtemp(prefix="ludusctrl-test-ds4-")
os.environ["LUDUSCTRL_DATA_DIR"] = DATA_TMP

import dualsense_link as d  # noqa: E402

FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail else ""))
    if not ok:
        FAILURES.append(name)


def sony_hid() -> set[str]:
    """PNP ids of every Sony-vendor HID device currently present."""
    out = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "Get-CimInstance Win32_PnPEntity | "
         "Where-Object { $_.PNPDeviceID -like '*VID_054C*' } | "
         "Select-Object -ExpandProperty PNPDeviceID"],
        capture_output=True, text=True).stdout
    return {line.strip() for line in out.splitlines() if line.strip()}


def main() -> int:
    if sys.platform != "win32":
        return print("DualShock 4 emulation needs Windows and ViGEmBus.") or 1

    before = sony_hid()

    try:
        pad = d.create_gamepad("ds4")
    except d.PadUnavailable as exc:
        return print(exc) or 1

    check("DS4 target created", pad.kind == "DualShock 4", pad.kind)

    time.sleep(3)
    new = sony_hid() - before
    check("Windows enumerates a Sony HID device", bool(new), f"{len(new)} new")
    # 054C:05C4 is a real DualShock 4 v1. Games key off this to pick prompts.
    check("hardware id is DualShock 4 (VID_054C / PID_05C4)",
          any("VID_054C" in x.upper() and "PID_05C4" in x.upper() for x in new),
          next(iter(new), "none"))

    pad.apply(0x1000 | 0x0001, -32768, 32767, 0, 0, 200, 0)
    time.sleep(0.3)
    check("apply() with buttons, axes and triggers succeeds", True)

    # int16 (XInput, positive-up) -> uint8 (DS4 HID, positive-down). Exact
    # endpoints, not "close to": full deflection one step short of the rail
    # reads as a stick that never quite reaches the edge in some games.
    axis = d.DualShock4Pad._axis
    check("centre maps exactly to 128", axis(0) == 128, str(axis(0)))
    check("X extremes hit the rails exactly",
          axis(-32768) == 0 and axis(32767) == 255,
          f"{axis(-32768)}..{axis(32767)}")
    check("Y full up is exactly 0 and full down exactly 255",
          axis(32767, invert=True) == 0 and axis(-32768, invert=True) == 255,
          f"up={axis(32767, invert=True)} down={axis(-32768, invert=True)}")
    check("Y centre is also 128", axis(0, invert=True) == 128)
    check("one step either side of centre stays at 128",
          {axis(v, inv) for v in (-1, 1) for inv in (False, True)} == {128})
    xs = [axis(v) for v in range(-32768, 32768, 3)]
    ys = [axis(v, invert=True) for v in range(-32768, 32768, 3)]
    check("X rises and Y falls monotonically",
          xs == sorted(xs) and ys == sorted(ys, reverse=True))
    check("apply() masks the unused 0x0800 bit without complaint",
          pad.apply(0xFFFF, 0, 0, 0, 0, 0, 0) is None)
    pad.release()

    # DS4 has no independent d-pad bits; it reports one of eight directions.
    hat = d.DualShock4Pad._HAT
    for combo, expected in (
        ((1, 0, 0, 0), "NORTH"),
        ((0, 0, 0, 1), "EAST"),
        ((1, 0, 0, 1), "NORTHEAST"),
        ((0, 1, 1, 0), "SOUTHWEST"),
        ((0, 0, 0, 0), "NONE"),
    ):
        check(f"d-pad {combo} -> {expected}", hat.get(combo) == expected,
              str(hat.get(combo)))

    pad.release()
    del pad
    time.sleep(2)
    check("device disappears once released", not (sony_hid() & new))

    # Switching pad type used to strand the old virtual device on the system,
    # because vgamepad only removes it from __del__ and the receiver kept a
    # live reference. Games then saw both pads and picked the Xbox one.
    print()
    print("--- switching pad type leaves nothing behind ---")

    def counts():
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_PnPEntity | Where-Object { "
             "$_.PNPDeviceID -like '*VID_045E&PID_028E*' -or "
             "$_.PNPDeviceID -like '*VID_054C&PID_05C4*' } | "
             "Select-Object -ExpandProperty PNPDeviceID"],
            capture_output=True, text=True).stdout.upper()
        return (sum("045E" in l for l in out.splitlines()),
                sum("054C" in l for l in out.splitlines()))

    port = 45991
    svc = d.ReceiverService(port=port, beacon=False, pad_kind="x360")
    svc.start()
    time.sleep(3.5)
    xbox, ds4 = counts()
    check("x360 mode presents only an Xbox pad", xbox >= 1 and ds4 == 0,
          f"xbox={xbox} ds4={ds4}")

    svc.stop()
    time.sleep(1.5)
    svc = d.ReceiverService(port=port, beacon=False, pad_kind="ds4")
    svc.start()
    time.sleep(3.5)
    xbox, ds4 = counts()
    check("switching removes the Xbox pad", xbox == 0, f"xbox={xbox}")
    check("switching creates the DualShock pad", ds4 >= 1, f"ds4={ds4}")

    svc.stop()
    time.sleep(2)
    xbox, ds4 = counts()
    check("nothing stranded after stop", xbox == 0 and ds4 == 0,
          f"xbox={xbox} ds4={ds4}")
    check("its pairing store stayed in the test directory",
          os.path.exists(os.path.join(DATA_TMP, "pairing.json")))
    shutil.rmtree(DATA_TMP, ignore_errors=True)

    print()
    if FAILURES:
        print("FAILED: " + ", ".join(FAILURES))
        return 1
    print("all DualShock 4 checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
