; SPDX-License-Identifier: AGPL-3.0-or-later
; Copyright (C) 2026 Josip Parlov (@parl0v). See NOTICE for the attribution terms.
;
; Inno Setup script for the LudusCtrl PC receiver.
;
; Build with:
;     python tools/build_installer.py
;
; That script reads the version from pc/version.py and passes it in as
; /DAppVersion=<v>, so the version is declared in exactly one place. Compiling
; this file directly in the Inno Setup IDE still works, but produces a "0.0"
; installer; that is deliberate, so a hand build can never pass for a release.
;
; Why an installer rather than a single --onefile exe:
;
;   PyInstaller's onefile bootloader runs the real process as a child of a
;   parent stub. Killing the parent (Task Manager "End task") orphans the
;   child, which keeps an open ViGEmBus handle and leaves a phantom controller
;   visible to every game. The onedir payload here runs as one process and
;   cannot do that, while the installer still gives users a single download.
;
;   It also lets us install ViGEmBus in the same run. Without that, every user
;   has to find a kernel driver on GitHub and install it by hand, which is
;   where most of them would give up.

#ifndef AppVersion
  #define AppVersion "0.0"
  #pragma message "AppVersion was not passed in; building as 0.0. Use tools/build_installer.py for a release."
#endif

#define AppName        "LudusCtrl"
#define AppPublisher   "Josip Parlov"
#define AppURL         "https://parl0v.github.io/ludusctrl/"
#define AppExe         "LudusCtrl.exe"
#define ViGEmInstaller "ViGEmBus_1.22.0_x64_x86_arm64.exe"
; What the bundled installer puts on disk, for the "is the installed driver
; older?" check. Compared on major.minor only. The bundled installer's payload
; is encrypted, so the exact file version of its ViGEmBus.sys could not be read
; from the repo; comparing build numbers against a guess could make every
; LudusCtrl install re-run the driver installer. Machines on 1.21.x and older
; get the update; 1.22.anything counts as current.
#define ViGEmBundledLabel "1.22.0"
#define ViGEmBundledMajor 1
#define ViGEmBundledMinor 22

; Ports the receiver listens on. docs/PROTOCOL.md is the reference.
#define InputPort 45989
#define WebPort   45991
#define FwInputRule "LudusCtrl controller input (UDP 45989)"
#define FwWebRule   "LudusCtrl browser client (TCP 45991)"

[Setup]
AppId={{7C4A1E6B-9D2F-4B85-A3E1-5F8C0D6B21A4}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppCopyright=(c) 2026 {#AppPublisher}. All rights reserved.
VersionInfoVersion={#AppVersion}
VersionInfoProductName={#AppName}
VersionInfoCompany={#AppPublisher}
VersionInfoCopyright=(c) 2026 {#AppPublisher}. All rights reserved.
VersionInfoDescription={#AppName} {#AppVersion} setup
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
; Shown before anything is installed, so the licence terms are agreed to up
; front. The third-party notices are too long for a wizard page; they are
; installed next to the exe instead and the finish page says where.
LicenseFile=..\LICENSE
; The author attribution and the additional licence terms, shown first.
InfoBeforeFile=..\NOTICE
OutputDir=..\pc\dist
OutputBaseFilename=LudusCtrl-{#AppVersion}-setup
SetupIconFile=..\pc\icon.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName} {#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Windows 10 or later. The desktop window needs WebView2 and the receiver has
; never been tested on anything older.
MinVersion=10.0
; The receiver is x64 only, matching the ViGEmClient.dll that ships with it.
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Needed to install the ViGEmBus kernel driver and the firewall rules.
PrivilegesRequired=admin
; The receiver binds UDP 45989 and cannot run twice, so offer to close a
; running copy instead of writing files underneath it.
CloseApplications=yes
RestartApplications=no

; Code signing. There is no certificate yet, so this is off by default.
;
; tools/build_installer.py turns it on when LUDUSCTRL_SIGN_CMD is set: it
; passes /DSign plus /Sludusctrl=<command> to ISCC, and ISCC then signs both
; setup.exe and the uninstaller it embeds. To sign from the IDE instead, add a
; sign tool named "ludusctrl" under Tools > Configure Sign Tools, e.g.
;     signtool sign /fd sha256 /tr http://timestamp.digicert.com /td sha256 /a $f
; and compile with /DSign, or uncomment the two lines after the #endif.
#ifdef Sign
SignTool=ludusctrl
SignedUninstaller=yes
#endif
;SignTool=ludusctrl
;SignedUninstaller=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
FinishedLabel=Setup has finished installing [name] on your computer.%n%nThe licence for LudusCtrl, and the licences of the third-party components it includes, are in the installation folder: LICENSE.txt, NOTICE.txt and THIRD-PARTY-NOTICES.txt.
FinishedLabelNoIcons=Setup has finished installing [name] on your computer.%n%nThe licence for LudusCtrl, and the licences of the third-party components it includes, are in the installation folder: LICENSE.txt, NOTICE.txt and THIRD-PARTY-NOTICES.txt.
; ViGEmBus is shared: other controller tools (DS4Windows, BetterJoy and so on)
; depend on the same driver, so removing it with LudusCtrl could break them.
; Say so, rather than leave it behind without a word.
UninstalledAll=%1 was removed from your computer.%n%nThe ViGEmBus controller driver was left installed, because other programs may use it too. To remove it as well, uninstall "ViGEm Bus Driver" in Settings > Apps.

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"
; Offered only when the driver is missing or older than the bundled one, and
; checked by default, because LudusCtrl cannot create a controller without it.
; Unchecking it asks for confirmation; see NextButtonClick below.
Name: "vigembus"; \
  Description: "Install the ViGEmBus {#ViGEmBundledLabel} controller driver (a third-party kernel driver by Nefarius Software Solutions e.U., BSD-3-Clause)"; \
  GroupDescription: "Controller driver:"; \
  Check: NeedsViGEmBus

[Files]
; The whole PyInstaller onedir payload.
Source: "..\pc\dist\{#AppName}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; Bundled so users are not sent off to find a kernel driver themselves.
; BSD-3-Clause; see THIRD-PARTY-NOTICES. Only extracted when it will be used.
Source: "vendor\{#ViGEmInstaller}"; DestDir: "{tmp}"; Flags: deleteafterinstall; Tasks: vigembus
; .txt so a double-click opens them in Notepad.
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion
Source: "..\NOTICE"; DestDir: "{app}"; DestName: "NOTICE.txt"; Flags: ignoreversion
Source: "..\THIRD-PARTY-NOTICES"; DestDir: "{app}"; DestName: "THIRD-PARTY-NOTICES.txt"; Flags: ignoreversion

[InstallDelete]
; 1.1 installed the notices without an extension.
Type: files; Name: "{app}\THIRD-PARTY-NOTICES"

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
; Same app with the browser client switched on, for a phone with no app
; installed (an iPhone, typically). The window shows the address to open.
Name: "{group}\{#AppName} (phone browser mode)"; Filename: "{app}\{#AppExe}"; \
  Parameters: "--web"; \
  Comment: "Start LudusCtrl with the browser client, for phones without the app"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
; Firewall. Without an inbound rule Windows either shows its "allow access"
; prompt on first run, which is easy to dismiss and then silently drops every
; packet, or, if the prompt was cancelled once, keeps a BLOCK rule for the exe
; that overrides any allow rule added later. So: clear everything that points
; at this exe first, then add exactly what the receiver needs.
;
; Scope, deliberately narrow:
;   program=     only LudusCtrl.exe can receive on these ports, not anything
;                else that happens to bind them.
;   private      the input channel has no authentication (anything that can
;                reach the port can press buttons), so it is never opened on
;                networks Windows treats as public (cafes, hotels, campus).
;                The catch: Windows sometimes files a home network as Public;
;                the README says how to switch it to Private.
;   localsubnet  the phone is always on the same LAN; nothing beyond it needs
;                to reach the receiver.
;
; The discovery beacon (UDP 45990) needs no rule: the PC only sends it.
;
; "DSLINK" is the name the README used to tell people to create by hand. That
; rule was not scoped to a profile, subnet or program, so it is removed too.
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=all program=""{app}\{#AppExe}"""; \
  Flags: runhidden; StatusMsg: "Configuring Windows Firewall..."
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""LudusCtrl"""; Flags: runhidden
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""DSLINK"""; Flags: runhidden
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#FwInputRule}"""; Flags: runhidden
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#FwWebRule}"""; Flags: runhidden
Filename: "{sys}\netsh.exe"; \
  Parameters: "advfirewall firewall add rule name=""{#FwInputRule}"" dir=in action=allow program=""{app}\{#AppExe}"" protocol=UDP localport={#InputPort} profile=private remoteip=localsubnet description=""Controller input from the LudusCtrl Android app on this network."""; \
  Flags: runhidden
Filename: "{sys}\netsh.exe"; \
  Parameters: "advfirewall firewall add rule name=""{#FwWebRule}"" dir=in action=allow program=""{app}\{#AppExe}"" protocol=TCP localport={#WebPort} profile=private remoteip=localsubnet description=""Browser client page for phones without the app. LudusCtrl only listens on it while the browser client is switched on."""; \
  Flags: runhidden

; ViGEmBus is handled in [Code] instead, so the silent attempt can be checked
; and retried visibly rather than failing quietly.
; Not offered when WebView2 is missing: the window would open blank.
Filename: "{app}\{#AppExe}"; \
  Description: "Start {#AppName}"; \
  Flags: nowait postinstall skipifsilent; \
  Check: HasWebView2

[UninstallRun]
; Remove the rules this installer created, plus anything else keyed to the exe
; (such as a rule Windows made from its own prompt), so nothing is left open.
; ViGEmBus is deliberately NOT uninstalled; see UninstalledAll above.
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#FwInputRule}"""; \
  Flags: runhidden; RunOnceId: "DelFwInput"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#FwWebRule}"""; \
  Flags: runhidden; RunOnceId: "DelFwWeb"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=all program=""{app}\{#AppExe}"""; \
  Flags: runhidden; RunOnceId: "DelFwProgram"

[Code]

const
  ViGEmReleasesURL = 'https://github.com/nefarius/ViGEmBus/releases';
  WebView2URL = 'https://developer.microsoft.com/microsoft-edge/webview2/';
  { The WebView2 Runtime's EdgeUpdate client id, as documented by Microsoft
    for detecting an installed runtime. }
  WebView2ClientKey = 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}';

var
  RestartNeeded: Boolean;

function ViGEmBusSys: String;
begin
  Result := ExpandConstant('{sys}\drivers\ViGEmBus.sys');
end;

{ Whether the ViGEmBus driver is actually present.

  Deliberately tests for the driver file rather than the service registry key.
  Uninstalling ViGEmBus routinely leaves its Services key behind, so a key check
  reports "already installed" on a machine that no longer has the driver and the
  install gets skipped. The .sys file is the honest signal. }
function ViGEmBusPresent: Boolean;
begin
  Result := FileExists(ViGEmBusSys);
end;

{ The installed driver's version for display, or an empty string. }
function InstalledViGEmVersion: String;
begin
  if not GetVersionNumbersString(ViGEmBusSys, Result) then
    Result := '';
end;

{ True when the installed driver is older than the bundled one, by
  major.minor. An unreadable version counts as current: better to leave a
  working driver alone than to reinstall it on a guess. }
function ViGEmBusOutdated: Boolean;
var
  MS, LS: Cardinal;
begin
  Result := False;
  if not ViGEmBusPresent then
    Exit;
  if not GetVersionNumbers(ViGEmBusSys, MS, LS) then
    Exit;
  Result := MS < (({#ViGEmBundledMajor} shl 16) or {#ViGEmBundledMinor});
end;

function NeedsViGEmBus: Boolean;
begin
  Result := (not ViGEmBusPresent) or ViGEmBusOutdated;
end;

function WebView2Registered(RootKey: Integer): Boolean;
var
  Version: String;
begin
  Result := RegQueryStringValue(RootKey, WebView2ClientKey, 'pv', Version)
    and (Version <> '') and (Version <> '0.0.0.0');
end;

{ The Evergreen WebView2 Runtime registers per machine (under the 32-bit view
  on 64-bit Windows) or per user. Windows 11 always has it; some Windows 10
  installs, LTSC and N editions and offline machines in particular, do not. }
function HasWebView2: Boolean;
begin
  Result := WebView2Registered(HKLM32) or WebView2Registered(HKLM64)
    or WebView2Registered(HKCU);
end;

{ Called by Setup at the end; asks to restart when the driver needs it. }
function NeedRestart: Boolean;
begin
  Result := RestartNeeded;
end;

{ Unchecking the driver is allowed, but not by accident. }
function NextButtonClick(CurPageID: Integer): Boolean;
var
  Msg: String;
begin
  Result := True;
  if (CurPageID <> wpSelectTasks) or (not NeedsViGEmBus)
    or WizardIsTaskSelected('vigembus') then
    Exit;

  if ViGEmBusPresent then
    Msg := 'ViGEmBus ' + InstalledViGEmVersion + ' is installed, which is older than'
      + ' the bundled {#ViGEmBundledLabel}.' + #13#10#13#10
      + 'LudusCtrl will use the installed version. It will probably work, but'
      + ' LudusCtrl is tested with {#ViGEmBundledLabel}.' + #13#10#13#10
      + 'Continue without updating the driver?'
  else
    Msg := 'Without the ViGEmBus driver, LudusCtrl cannot create a virtual'
      + ' controller, so games will not see your gamepad.' + #13#10#13#10
      + 'You can install it yourself later from ' + ViGEmReleasesURL + '.'
      + #13#10#13#10
      + 'Continue without installing the driver?';

  Result := MsgBox(Msg, mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;
end;

{ The Ready page lists tasks by their short description. The driver deserves
  a plain sentence about what it is and what happens to it later. }
function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo,
  MemoTypeInfo, MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
var
  S: String;
begin
  S := '';
  if MemoDirInfo <> '' then S := S + MemoDirInfo + NewLine + NewLine;
  if MemoGroupInfo <> '' then S := S + MemoGroupInfo + NewLine + NewLine;
  if MemoTasksInfo <> '' then S := S + MemoTasksInfo + NewLine + NewLine;

  S := S + 'Controller driver:' + NewLine;
  if WizardIsTaskSelected('vigembus') then
    S := S + Space + 'ViGEmBus {#ViGEmBundledLabel} will be installed. It is a third-party'
      + NewLine + Space + 'kernel-mode driver by Nefarius Software Solutions e.U.'
      + NewLine + Space + '(BSD-3-Clause) that lets LudusCtrl create a virtual gamepad.'
      + NewLine + Space + 'Uninstalling LudusCtrl leaves it in place, because other'
      + NewLine + Space + 'programs may use it too.'
  else if ViGEmBusPresent then
    S := S + Space + 'ViGEmBus ' + InstalledViGEmVersion + ' is already installed and will not be changed.'
  else
    S := S + Space + 'Not installed. LudusCtrl cannot create a controller until it is.';

  if not HasWebView2 then
    S := S + NewLine + NewLine + 'Microsoft Edge WebView2 Runtime:' + NewLine
      + Space + 'Not found. The LudusCtrl window needs it; setup will say where'
      + NewLine + Space + 'to get it once installation finishes.';

  Result := S;
end;

{ What a ViGEmBus installer exit code means, in words a user can act on. The
  bundled installer is an Advanced Installer bootstrapper around an MSI, so
  these are Windows Installer codes. }
function ViGEmExitMeaning(Code: Integer): String;
begin
  case Code of
    1602, 1223:
      Result := 'the driver installation was cancelled.';
    1618:
      Result := 'another installation was already running. Let it finish, then'
        + ' run this setup again.';
    1625, 1643:
      Result := 'a system policy on this PC blocked the installation.';
    1638:
      Result := 'a different version of ViGEmBus is registered with Windows'
        + ' Installer. Uninstall "ViGEm Bus Driver" in Settings > Apps, then run'
        + ' this setup again.';
  else
    Result := Format('the driver installer stopped with error %d.', [Code]);
  end;
end;

{ Run the bundled installer once. Returns True when it reports success and
  the driver file is on disk. Cancelled is set when the user backed out, so
  the caller does not ask the same question twice. }
function RunViGEmInstaller(const Setup, Params: String; Show: Integer;
  var Detail: String; var Cancelled: Boolean): Boolean;
var
  ResultCode: Integer;
begin
  Result := False;
  Cancelled := False;
  if not Exec(Setup, Params, '', Show, ewWaitUntilTerminated, ResultCode) then
  begin
    { Exec could not start it at all; ResultCode is a Windows error here. }
    Detail := 'the driver installer could not be started ('
      + SysErrorMessage(ResultCode) + ').';
    Exit;
  end;

  case ResultCode of
    0:
      Result := True;
    3010, 1641:
      begin
        { Installed, but Windows has to restart before the driver loads. }
        RestartNeeded := True;
        Result := True;
      end;
    1602, 1223:
      begin
        Cancelled := True;
        Detail := ViGEmExitMeaning(ResultCode);
      end;
  else
    Detail := ViGEmExitMeaning(ResultCode);
  end;

  if Result and not ViGEmBusPresent then
  begin
    Result := False;
    Detail := 'the driver installer reported success, but ViGEmBus.sys is not'
      + ' on the system.';
  end;
end;

{ Install the driver, confirm it took, and fall back to a visible install rather
  than leaving the user with an app that cannot create a controller.

  The bundled installer is built with Advanced Installer, whose bootstrapper
  wants /exenoui /qn. Plain /qn is msiexec syntax and does not silence it. }
procedure InstallViGEmBus;
var
  Setup, Detail, Msg: String;
  WasPresent, Cancelled: Boolean;
begin
  if not WizardIsTaskSelected('vigembus') then
    Exit;

  WasPresent := ViGEmBusPresent;
  Setup := ExpandConstant('{tmp}\{#ViGEmInstaller}');
  if not FileExists(Setup) then
  begin
    SuppressibleMsgBox('The bundled ViGEmBus installer is missing, so the controller'
      + ' driver could not be installed.' + #13#10#13#10
      + 'Install it from ' + ViGEmReleasesURL + ', then start LudusCtrl again.',
      mbError, MB_OK, IDOK);
    Exit;
  end;

  WizardForm.StatusLabel.Caption := 'Installing the ViGEmBus controller driver...';
  if RunViGEmInstaller(Setup, '/exenoui /qn /norestart', SW_HIDE, Detail, Cancelled) then
    Exit;

  { The silent attempt did not take, so show it and let the user finish it.
    Not in a silent install, where nobody is there to click through it. }
  if (not WizardSilent) and (not Cancelled) then
    if RunViGEmInstaller(Setup, '/norestart', SW_SHOW, Detail, Cancelled) then
      Exit;

  if WasPresent then
    Msg := 'The ViGEmBus driver could not be updated: ' + Detail + #13#10#13#10
      + 'The installed version (' + InstalledViGEmVersion + ') is still there,'
      + ' and LudusCtrl will use it.'
  else
    Msg := 'LudusCtrl needs the ViGEmBus driver, and it was not installed: '
      + Detail + #13#10#13#10
      + 'LudusCtrl itself is installed and will start, but it cannot create a'
      + ' controller until the driver is present. Install it from '
      + ViGEmReleasesURL + ' and start LudusCtrl again.';
  SuppressibleMsgBox(Msg, mbError, MB_OK, IDOK);
end;

{ Not bundled: it is Microsoft's to distribute, it updates itself, and most
  PCs already have it. Point at the official page instead. }
procedure CheckWebView2;
var
  ErrorCode: Integer;
begin
  if HasWebView2 then
    Exit;
  if SuppressibleMsgBox('The LudusCtrl window needs the Microsoft Edge WebView2 Runtime,'
      + ' and it is not installed on this PC. Without it the window stays blank.'
      + #13#10#13#10
      + 'Download the Evergreen Runtime from Microsoft:' + #13#10
      + WebView2URL + #13#10#13#10
      + 'Open that page now?', mbInformation, MB_YESNO, IDNO) = IDYES then
    ShellExecAsOriginalUser('open', WebView2URL, '', '', SW_SHOWNORMAL,
      ewNoWait, ErrorCode);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    InstallViGEmBus;
    CheckWebView2;
  end;
end;
