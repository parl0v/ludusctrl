# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Josip Parlov (@parl0v). See NOTICE for the attribution terms.
"""Build the Windows installer for the LudusCtrl receiver.

Runs build_exe.py first so the installer can never ship a stale payload, then
compiles installer/ludusctrl.iss with Inno Setup.

The result is a single setup.exe that installs the onedir payload and, when
the driver is missing, installs ViGEmBus in the same run. That matters more
than it looks: without it every user has to find a kernel driver on GitHub and
install it by hand, which is where most of them give up.

    python tools/build_installer.py
    python tools/build_installer.py --skip-app    # reuse the existing dist/

Requires Inno Setup 6:  winget install JRSoftware.InnoSetup

The version comes from pc/version.py and is passed to ISCC as /DAppVersion, so
the .iss never declares it and the two cannot drift. The output is
pc/dist/LudusCtrl-<version>-setup.exe.

Signing: when LUDUSCTRL_SIGN_CMD is set (see tools/build_exe.py for the
format), ISCC is given it as a SignTool and signs both the setup and the
uninstaller it embeds. Unset, the installer is built unsigned with a note.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ISS = os.path.join(ROOT, "installer", "ludusctrl.iss")
PAYLOAD = os.path.join(ROOT, "pc", "dist", "LudusCtrl")
VERSION_PY = os.path.join(ROOT, "pc", "version.py")
SIGN_ENV = "LUDUSCTRL_SIGN_CMD"

# Pinned so a swapped or truncated download cannot be shipped silently. This is
# v1.22.0, the final release before ViGEmBus went end-of-life in Nov 2023, so
# the hash is not expected to change.
VIGEM = "ViGEmBus_1.22.0_x64_x86_arm64.exe"
VIGEM_SHA256 = "89220a7865076b342892f98865f3499fb7c4cfd673159e89d352c360fd014c6a"

# winget installs Inno Setup per-user by default, so LOCALAPPDATA has to be
# checked as well as the machine-wide locations.
ISCC_CANDIDATES = [
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Inno Setup 6", "ISCC.exe"),
    os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                 "Inno Setup 6", "ISCC.exe"),
    os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"),
                 "Inno Setup 6", "ISCC.exe"),
]


def find_iscc() -> str:
    for path in ISCC_CANDIDATES:
        if os.path.isfile(path):
            return path
    from shutil import which
    found = which("iscc")
    if found:
        return found
    sys.exit(
        "Inno Setup 6 not found. Install it with:\n"
        "    winget install JRSoftware.InnoSetup"
    )


def check_vigem() -> None:
    path = os.path.join(ROOT, "installer", "vendor", VIGEM)
    if not os.path.isfile(path):
        sys.exit(
            "Missing %s\n"
            "Download it from:\n"
            "    https://github.com/nefarius/ViGEmBus/releases/tag/v1.22.0\n"
            "and put it in installer/vendor/" % VIGEM
        )
    with open(path, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    if digest != VIGEM_SHA256:
        sys.exit(
            "%s does not match the pinned hash.\n"
            "  expected %s\n"
            "  got      %s\n"
            "Refusing to bundle an unverified kernel driver."
            % (VIGEM, VIGEM_SHA256, digest)
        )
    print("ViGEmBus %s verified against its pinned hash" % VIGEM)


def app_version() -> str:
    """VERSION from pc/version.py, the single source of the PC version.

    It used to be declared in the .iss and hardcoded again here, and the two
    drifted the moment the installer was bumped: ISCC wrote the new filename
    while this still looked for the old one and silently reported nothing.
    Now it is read once, here, and handed to ISCC.
    """
    with open(VERSION_PY, encoding="utf-8") as fh:
        m = re.search(r'^VERSION\s*=\s*["\']([^"\']+)["\']', fh.read(), re.M)
    if not m:
        sys.exit("Could not read VERSION from %s" % VERSION_PY)
    return m.group(1)


def sign_args() -> list:
    """ISCC arguments that turn signing on, or none when it is not configured.

    ISCC wants the command registered as a named SignTool, with $f where the
    quoted file name goes; LUDUSCTRL_SIGN_CMD uses {file} for the same thing.
    The .iss only sets SignTool= when Sign is defined, so an unsigned build
    needs no edits anywhere.
    """
    template = os.environ.get(SIGN_ENV, "").strip()
    if not template:
        print("The installer will not be signed (%s is not set)." % SIGN_ENV)
        return []
    if "{file}" not in template:
        sys.exit("%s must contain {file} where the path goes." % SIGN_ENV)
    return ["/DSign", "/Sludusctrl=" + template.replace("{file}", "$f")]


def main() -> int:
    if sys.platform != "win32":
        return print("The installer is Windows only.") or 1

    if "--skip-app" not in sys.argv:
        print("Building the receiver...\n")
        result = subprocess.run(
            [sys.executable, os.path.join(HERE, "build_exe.py")]
        )
        if result.returncode != 0:
            return result.returncode
        print()

    if not os.path.isdir(PAYLOAD):
        sys.exit("No payload at %s. Run without --skip-app." % PAYLOAD)

    check_vigem()

    version = app_version()
    iscc = find_iscc()
    print("Compiling the %s installer with %s...\n" % (version, iscc))
    result = subprocess.run([iscc, "/DAppVersion=" + version] + sign_args() + [ISS])
    if result.returncode != 0:
        return result.returncode

    out = os.path.join(ROOT, "pc", "dist", "LudusCtrl-%s-setup.exe" % version)
    if os.path.isfile(out):
        size = os.path.getsize(out) / 1048576.0
        print("\n  %s\n  %.1f MB" % (out, size))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
