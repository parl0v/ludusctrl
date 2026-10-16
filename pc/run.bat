@echo off
REM SPDX-License-Identifier: AGPL-3.0-or-later
REM Copyright (C) 2026 Josip Parlov (@parl0v). See NOTICE for the attribution terms.
REM LudusCtrl launcher. First run installs the Python dependencies.
REM The terminal receiver is dualsense_link.py if you want that instead.
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

python -c "import webview" 2>nul
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

REM Pairing needs this: every phone packet is authenticated with it.
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

python app.py %*
if errorlevel 1 (
    echo.
    echo LudusCtrl exited with an error. The details are printed above.
    goto :pause
)
goto :eof

:pause
pause
exit /b 1
