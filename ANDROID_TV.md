# Android TV

## Why the TV case shapes the whole design

A television sitting on a shelf with a dead panel is the target this was
designed around. If the server needs somebody to see the screen, press a
button, dismiss a dialog or grant a permission through a visible prompt, it
does not work on that device.

So:

- the server is started by the application object, not by a button
- it is owned by a foreground service, so it survives the launcher going away
- it restarts after a reboot
- the status screen has no controls at all, which also means there is nothing
  a D-pad has to reach
- the setup code is written to the notification and the log as well as the
  screen, so it can be read over `adb logcat` if the panel is dead

## Launcher entry

The manifest declares `android.hardware.touchscreen` and
`android.software.leanback` as not required, and the launcher activity carries
both `LAUNCHER` and `LEANBACK_LAUNCHER` categories, with a banner. One APK
therefore installs and appears on phones, tablets, Android TV and Google TV.

## Multicast

mDNS needs multicast, and Android Wi-Fi drops multicast packets unless a
multicast lock is held. The lock is held for as long as the server runs. On
some TV boxes multicast is filtered by the access point rather than the
device; if discovery fails there, the fault is usually the network, not the
app.

## Status

Declared and implemented. **Not yet verified on real TV hardware.** See
[STATUS.md](STATUS.md).
