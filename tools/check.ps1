# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Josip Parlov (@parl0v). See NOTICE for the attribution terms.
<#
    Local equivalent of .github/workflows/ci.yml.

    Runs the same checks on this machine:

        .\tools\check.ps1                 Python tests, plus the Android tests,
                                         lint and builds when android\ exists
        .\tools\check.ps1 -SkipAndroid    Python tests only (seconds)
        .\tools\check.ps1 -SkipPython     Android only

    Python: test_receiver.py, test_layouts.py and test_webbridge.py. They stub
    or avoid vgamepad, so they need neither ViGEmBus nor a controller;
    test_webbridge.py needs `cryptography` and binds TCP 45991 on 127.0.0.1,
    so close LudusCtrl first if its browser client is on. The tests that do
    need the driver (test_e2e.py, test_ds4.py, test_ui.py) are not run here or
    in CI; run them by hand on a PC with ViGEmBus.

    Android: the same Gradle invocation as CI, with the private toolchain from
    android\bootstrap.ps1. bundleRelease is debug-signed through
    -PallowDebugSigning=true, so its output is NOT uploadable to Play; it only
    proves the release variant builds.
#>

param(
    [switch]$SkipPython,
    [switch]$SkipAndroid
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = Split-Path -Parent $PSScriptRoot
$failed = @()

function Step($name) {
    Write-Host ""
    Write-Host "== $name" -ForegroundColor Cyan
}

if (-not $SkipPython) {
    $python = (Get-Command python -ErrorAction SilentlyContinue)
    if (-not $python) { throw "python is not on PATH." }

    # Windows PowerShell turns redirected native stderr into an error record,
    # so relax Stop just for this probe and judge it by exit code alone.
    $ErrorActionPreference = "Continue"
    & python -c "import cryptography" 2>$null
    $probe = $LASTEXITCODE
    $ErrorActionPreference = "Stop"
    if ($probe -ne 0) {
        throw "test_webbridge.py needs cryptography:  python -m pip install -r pc\requirements-build.txt"
    }

    # test_webbridge.py resolves webbridge from the working directory, so all
    # three run from pc\, the way CI runs them.
    Push-Location (Join-Path $Root "pc")
    try {
        foreach ($test in "test_receiver.py", "test_layouts.py", "test_webbridge.py") {
            Step "python $test"
            & python $test
            if ($LASTEXITCODE -ne 0) { $failed += $test }
        }
    } finally {
        Pop-Location
    }
}

if (-not $SkipAndroid -and (Test-Path (Join-Path $Root "android"))) {
    $android = Join-Path $Root "android"
    $jdk = Join-Path $android ".toolchain\jdk"
    $sdk = Join-Path $android ".toolchain\sdk"

    # Prefer the private toolchain; fall back to whatever JAVA_HOME and
    # ANDROID_HOME already say, which is how CI provides them.
    if (Test-Path $jdk) { $env:JAVA_HOME = $jdk }
    if (Test-Path $sdk) {
        $env:ANDROID_HOME = $sdk
        $env:ANDROID_SDK_ROOT = $sdk
    }
    if (-not $env:JAVA_HOME) {
        throw "No JDK. Run android\bootstrap.ps1 first, or set JAVA_HOME to a JDK 21."
    }

    Step "gradlew testDebugUnitTest lintRelease assembleDebug bundleRelease"
    Push-Location $android
    try {
        & .\gradlew.bat testDebugUnitTest lintRelease assembleDebug bundleRelease `
            -PallowDebugSigning=true --no-daemon
        if ($LASTEXITCODE -ne 0) { $failed += "android" }
    } finally {
        Pop-Location
    }
}

Write-Host ""
if ($failed.Count -gt 0) {
    Write-Host ("FAILED: " + ($failed -join ", ")) -ForegroundColor Red
    exit 1
}
Write-Host "All checks passed." -ForegroundColor Green
