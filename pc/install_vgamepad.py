# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Josip Parlov (@parl0v). See NOTICE for the attribution terms.
"""Install vgamepad on a machine that already has ViGEmBus.

Why this exists
---------------
`pip install vgamepad` hangs on many systems. vgamepad 0.1.0 detects the driver
by searching the registry for the string

    nefarius virtual gamepad emulation bus driver

which was the installer's product name before ViGEmBus 1.19. Every release
since registers as `ViGEm Bus Driver`, so detection returns "not installed"
even when it plainly is, and setup.py shells out to

    msiexec /i ViGEmBusSetup_x64.msi

with no /quiet flag. Because the driver is already present, that MSI opens a
Repair/Remove wizard and waits for a click that never comes. pip blocks
forever behind it.

`pip download` does not help: modern pip calls the PEP 517 hook
`prepare_metadata_for_build_wheel`, which runs setup.py with `dist_info`, and
vgamepad only guards against `egg_info` and `sdist`.

So this script fetches the sdist straight from PyPI, removes the msiexec call,
and installs from the patched tree. It refuses to run unless ViGEmBus is
actually installed, so it can never be a way to skip a driver you need.

It installs exactly vgamepad 0.1.0 and checks the archive's SHA-256 before
running a line of it. setup.py runs with this user's rights, so "whatever PyPI
happens to list as latest" is not good enough, and the patch below targets
0.1.0's setup.py specifically anyway. Moving to a newer vgamepad means changing
VGAMEPAD_VERSION, SDIST_NAME and SDIST_SHA256 together, deliberately.

    python install_vgamepad.py
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

VGAMEPAD_VERSION = "0.1.0"
# From https://pypi.org/pypi/vgamepad/0.1.0/json; the release's only file.
SDIST_NAME = "vgamepad-0.1.0.tar.gz"
SDIST_SHA256 = "57f6bd01aec0c172947517fb782d150ef9b285f7f4d524c317374fa5c24a89de"
PYPI = f"https://pypi.org/pypi/vgamepad/{VGAMEPAD_VERSION}/json"
DRIVER_URL = "https://github.com/nefarius/ViGEmBus/releases"


class InstallError(Exception):
    """A step failed; the message says which one and what to do about it."""


def driver_installed() -> tuple[bool, str]:
    """True when the ViGEmBus kernel service exists and is running."""
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "$s = Get-Service ViGEmBus -ErrorAction SilentlyContinue; "
             "if ($s) { $s.Status } else { 'MISSING' }"],
            capture_output=True, text=True, timeout=30,
        ).stdout.strip()
    except Exception as exc:
        return False, f"could not query the service ({exc})"
    return out == "Running", out or "MISSING"


def verify_sdist(raw: bytes, expected: str = SDIST_SHA256) -> None:
    """Refuse the archive unless it is byte for byte the pinned release."""
    digest = hashlib.sha256(raw).hexdigest()
    if digest != expected:
        raise InstallError(
            f"{SDIST_NAME} failed its integrity check.\n"
            f"  expected sha256 {expected}\n"
            f"  got      sha256 {digest}\n"
            "Nothing was installed. The download was corrupted or tampered with;\n"
            "try again, ideally on another network."
        )


def fetch_sdist(dest: str) -> str:
    try:
        meta = json.load(urllib.request.urlopen(PYPI, timeout=60))
        sdists = [u for u in meta["urls"]
                  if u["packagetype"] == "sdist" and u["filename"] == SDIST_NAME]
        if not sdists:
            raise InstallError(f"PyPI no longer lists {SDIST_NAME}.")
        url = sdists[0]
        print(f"  downloading {url['filename']}")
        raw = urllib.request.urlopen(url["url"], timeout=120).read()
    except InstallError:
        raise
    except (OSError, ValueError, KeyError) as exc:  # URLError is an OSError
        raise InstallError(
            f"Could not download vgamepad {VGAMEPAD_VERSION} from PyPI: {exc}\n"
            "Check the internet connection (and any proxy or firewall), then try again."
        ) from exc

    # Before extracting, not after: a tampered archive must not get as far
    # as writing files, let alone running setup.py.
    verify_sdist(raw)
    print("  sha256 verified")

    tar = tarfile.open(fileobj=io.BytesIO(raw))
    # Python 3.14 makes this the default; ask for it explicitly so the
    # behaviour is the same on older interpreters.
    try:
        tar.extractall(dest, filter="data")
    except TypeError:
        tar.extractall(dest)

    entries = [e for e in os.listdir(dest) if os.path.isdir(os.path.join(dest, e))]
    if len(entries) != 1:
        raise InstallError(f"Unexpected archive layout: {entries}")
    return os.path.join(dest, entries[0])


def patch_setup(root: str) -> None:
    path = os.path.join(root, "setup.py")
    with open(path, encoding="utf-8") as fh:
        source = fh.read()

    needle = "subprocess.call(['msiexec', '/i', '%s' % str(pathMsi)], shell=True)"
    if needle not in source:
        # Cannot happen with the verified archive. If it somehow does, stop
        # rather than install something unexpected.
        raise InstallError(
            "setup.py does not contain the msiexec call this script patches."
        )

    replacement = (
        "pass  # patched by install_vgamepad.py: ViGEmBus is already installed"
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(source.replace(needle, replacement))
    print("  patched setup.py: removed the blocking msiexec call")


def already_installed() -> tuple[bool, str | None]:
    """(installed, problem).

    Importing vgamepad also connects to the bus, and a missing or outdated
    driver surfaces as a bare Exception rather than an ImportError. That case
    means the package is fine and the driver is not, and reinstalling the
    package would not help, so it has to be told apart from "not installed".
    """
    try:
        import vgamepad  # noqa: F401
        return True, None
    except ImportError:
        return False, None
    except Exception as exc:
        return True, str(exc) or type(exc).__name__


def install() -> int:
    print("Checking for the ViGEmBus driver...")
    ok, state = driver_installed()
    if not ok:
        print(f"  ViGEmBus service: {state}\n")
        print("This script only bypasses vgamepad's broken driver detection; it")
        print("cannot install the driver for you. Install ViGEmBus first:")
        print(f"  {DRIVER_URL}")
        print("then run this again.")
        return 1
    print("  ViGEmBus service: Running\n")

    with tempfile.TemporaryDirectory(prefix="vgamepad-") as tmp:
        print(f"Fetching vgamepad {VGAMEPAD_VERSION} from PyPI...")
        root = fetch_sdist(tmp)
        patch_setup(root)

        print("\nInstalling...")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", root, "--no-build-isolation"]
        )
        if result.returncode != 0:
            print("\npip could not install vgamepad; its own error is above.")
            print("If it mentions setuptools, run:  python -m pip install setuptools")
            return result.returncode

    print("\nVerifying...")
    check = subprocess.run(
        [sys.executable, "-c",
         "import vgamepad as vg; g = vg.VX360Gamepad(); g.reset(); g.update(); "
         "print('virtual Xbox 360 pad created')"],
        capture_output=True, text=True,
    )
    lines = (check.stdout or check.stderr).strip().splitlines()
    print("  " + (lines[-1] if lines else "(no output)"))
    if check.returncode != 0:
        print("\nvgamepad is installed, but it could not create a virtual pad.")
        print("The ViGEmBus driver is running but unusable; usually it is too old.")
        print(f"Install the latest from {DRIVER_URL}, reboot, and try again.")
        return check.returncode

    print("\nDone. Start the receiver with:  python dualsense_link.py")
    return 0


def main() -> int:
    if sys.platform != "win32":
        return print("vgamepad and ViGEmBus are Windows only.") or 1

    # Plain ASCII: Windows consoles default to cp1252 and mangle anything else.
    print("LudusCtrl - vgamepad installer\n")

    installed, problem = already_installed()
    if installed and problem is None:
        print("vgamepad is already installed. Nothing to do.")
        return 0
    if installed:
        print("vgamepad is installed, but it cannot reach the ViGEmBus driver:")
        print(f"  {problem}\n")
        print("The driver is missing, stopped or outdated. Install the latest from")
        print(f"  {DRIVER_URL}")
        print("then reboot and start LudusCtrl again.")
        return 1

    try:
        return install()
    except InstallError as exc:
        print(f"\n{exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
