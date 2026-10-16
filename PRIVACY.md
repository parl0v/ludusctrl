# Privacy Policy — LudusCtrl

**Last updated: 16 October 2026**

LudusCtrl is developed by Josip Parlov. This policy covers the LudusCtrl
Android app and the LudusCtrl receiver for Windows, and explains what they do
and do not do with your data. It is short because they collect nothing.

## Summary

**LudusCtrl does not collect, transmit, or share any personal data.**

There are no accounts, no analytics, no advertising, no crash reporting, no
tracking, and no third-party SDKs of any kind. The only way anything reaches
the developer is if you choose to send a problem report by email, described
below.

## What the Android app does

LudusCtrl forwards input from a gamepad paired to your device over Bluetooth to
a computer on your own local network. To do this it:

- Reads button and stick input from a gamepad you have paired, using Android's
  standard input APIs.
- Sends that input as UDP packets to an IP address on your local network, either
  discovered automatically or typed in by you.
- Listens for a discovery broadcast from the receiver program running on your
  computer.
- The first time it links to a computer, pairs with it: the two exchange keys
  so that only your phone can control that computer, and the app sends your
  device's maker and model (for example "Google Pixel 8") so the computer can
  show which phone is asking. You confirm the pairing on the computer.

All of this traffic stays on your local network. Nothing is sent to the
developer, and nothing is sent to any internet server.

## Data stored on your device

The app saves the last receiver address and port you used, and whether you
enabled dim-screen mode, so you do not have to set them again. For each
computer you pair with, it also keeps a random ID for your phone, the
computer's random ID, address and port, the key created during pairing, the
date you paired, and a link counter. You can remove a computer with **Paired
PCs** > **Forget**. All of this is stored only in the app's private storage on
your device. It is **not** included in
Android's cloud or device-to-device backups (the app turns backup off), it is
removed when you uninstall the app, and it is never transmitted anywhere.

## Reporting a problem

If you tap **Report a problem**, the app opens your own email app with a
pre-filled message to **josipparlov@protonmail.com**. The message contains:

- the app version;
- your device's manufacturer and model, and its Android version;
- the connected controller's name, its vendor and product IDs, and the button
  layout the app detected;
- the connection status and the measured round-trip time;
- the receiver address you are connecting to, which is an address on your
  local network (for example `192.168.1.20:45989`).

You can read and change the message before sending it. **Nothing is sent
unless you send it yourself** from your email app. If your device has no email
app, the report is copied to the clipboard instead, and again goes nowhere
unless you paste and send it.

A report you send is used only to look into the problem and reply to you, and
is not shared with anyone. You can ask for it to be deleted at the same
address.

## The Windows receiver

The receiver runs on your computer and accepts controller input only from your
local network. It sends nothing to the developer or to any internet server.

It keeps its files in `%LOCALAPPDATA%\LudusCtrl` on your PC:

- **Settings** (`settings.json`), such as whether the browser client is on.
- **A log file** (`ludusctrl.log`, kept to a few megabytes). It records what
  the receiver did, such as starting up, connections and errors, and can
  include the local network addresses of devices that connected. It exists so
  a problem can be diagnosed after the fact. It never leaves your PC; if you
  want to include it in a problem report, attaching it is up to you.
- **Paired phones** (`pairing.json`): a random ID for the computer and, for
  each phone you allowed, its random ID, maker and model, the key created
  during pairing, the date you paired and a link counter. The file is readable
  only by your Windows account. Remove a phone in the receiver's window
  (**Paired phones** > **Remove**) or with `--forget`.
- **The browser client's certificate**, described next.

## The browser client

The receiver can optionally serve a web page on your local network, so a phone
without the app (an iPhone, for example) can send controller input from its
browser. It is off unless you turn it on.

- The page is served over HTTPS with a **self-signed certificate that is
  created on your PC** the first time the browser client is used and stored in
  the folder above. No certificate authority or other outside service is
  involved.
- Each session uses a **random access token**, part of the address the
  receiver shows you. Only a browser that has that address can send input.
- The page loads nothing from the internet and sends controller input only to
  your PC.

## Permissions (Android)

| Permission | Why it is needed |
|---|---|
| `INTERNET` | Opens a UDP socket to send input to your PC on the local network. Despite the name, Android requires this for any network socket, including local-only ones. |
| `ACCESS_NETWORK_STATE` | Watches the Wi-Fi network so the connection can be tied to it and stop cleanly when it drops. |
| `CHANGE_WIFI_MULTICAST_STATE` | Holds a multicast lock so discovery broadcasts are not dropped while the Wi-Fi radio is in power-save mode. |
| `WAKE_LOCK` | Keeps Wi-Fi in its low-latency mode while a connection is running. |

The app requests no location, contacts, storage, camera, or microphone
permissions.

## Children

The app is not directed at children and collects no data from anyone,
regardless of age.

## Third parties

None. Neither the app nor the receiver contains third-party analytics,
advertising, or tracking libraries. A problem report you choose to send passes
through your own email provider and the developer's (Proton), as any email
does.

## Changes to this policy

If this policy changes, the updated version will be published at this same
address, and in the receiver's source repository at
<https://github.com/parl0v/ludusctrl/blob/main/PRIVACY.md>, with a revised
date above. Any future version that introduces data
collection will say so explicitly.

## Contact

Questions about this policy: **josipparlov@protonmail.com**
