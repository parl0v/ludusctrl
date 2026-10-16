@echo off
REM SPDX-License-Identifier: AGPL-3.0-or-later
REM Copyright (C) 2026 Josip Parlov (@parl0v). See NOTICE for the attribution terms.
REM LudusCtrl launcher with the browser client switched on for this run.
REM
REM Same app as run.bat, plus an HTTPS page a phone can open with no app
REM installed -- which is the only way an iPhone can drive the pad. The
REM window shows the link (with a QR code) in its "Browser client" card. The
REM link carries a one-time code and changes every time the app starts.
REM
REM The installed app does not need this script: the "Browser client" switch
REM in its window does the same and is remembered.
REM
REM The certificate is self-signed, because no authority will sign a private
REM IP address, so the phone warns once. On iOS: Show Details -> visit this
REM website. That is expected, not a fault.
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo Python was not found on PATH.
    echo Install Python 3 from https://www.python.org/downloads/ and tick
    echo "Add python.exe to PATH" in the installer, then run this again.
    goto :pause
)

REM find_spec checks vgamepad is installed without importing it. Importing also
REM connects to ViGEmBus, so a missing driver would look like a missing package
REM and send us off to reinstall something that is fine. The app itself
REM explains a driver problem properly.
python -c "import importlib.util, sys; sys.exit(importlib.util.find_spec('vgamepad') is None)"
if errorlevel 1 (
    REM Not `pip install`: vgamepad's setup.py blocks forever on an MSI dialog
    REM when ViGEmBus is already present. See install_vgamepad.py.
    echo Installing vgamepad...
    python install_vgamepad.py
    if errorlevel 1 (
        echo.
        echo vgamepad was not installed. The reason is printed above.
        goto :pause
    )
)

python -c "import importlib.util, sys; sys.exit(importlib.util.find_spec('webview') is None)"
if errorlevel 1 (
    echo Installing pywebview...
    python -m pip install "pywebview>=5.0"
    if errorlevel 1 (
        echo.
        echo pip could not install pywebview. Its error is printed above;
        echo usually that means no internet connection or a blocking proxy.
        goto :pause
    )
)

REM Pairing needs this (every phone packet is authenticated with it), and the
REM browser client uses it to issue its HTTPS certificate.
python -c "import importlib.util, sys; sys.exit(importlib.util.find_spec('cryptography') is None)"
if errorlevel 1 (
    echo Installing cryptography...
    python -m pip install "cryptography>=42"
    if errorlevel 1 (
        echo.
        echo pip could not install cryptography. Its error is printed above.
        echo The receiver cannot pair with a phone without it.
        goto :pause
    )
)

REM Anything passed to this script is forwarded, so --pad ds4, --web-port and
REM the rest still work.
python app.py --web %*
if errorlevel 1 (
    echo.
    echo LudusCtrl exited with an error. The details are printed above and in
    echo %LOCALAPPDATA%\LudusCtrl\ludusctrl.log
    goto :pause
)
goto :eof

:pause
pause
exit /b 1
