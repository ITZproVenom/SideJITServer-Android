# SideJITServer for Android

A SideJITServer that runs on an Android phone, tablet or TV box and provides
JIT to a physical iPhone or iPad over Wi-Fi. No USB, no PC, no Mac, no Linux
box, no Termux, no Python, no cloud server, no pairing file to import.

> **Read [STATUS.md](STATUS.md) first.** This is an in-progress
> implementation. Wireless pairing with an iPhone works, and so does opening a
> CoreDevice tunnel to it: on real hardware the server finds the paired device,
> verifies against it, obtains a tunnel listener and completes the TLS-PSK and
> CDTunnel handshakes. It does **not** yet enable JIT. The first step inside
> the tunnel, a TCP connection to the device's RSD port, currently gets no
> reply. Nothing in this repository returns a fake success, and STATUS.md says
> exactly which layers a real device has and has not exercised.

## What it is meant to be

```
iPhone / iPad  (iOS 27+, Developer Mode on)
      |
      |  Wi-Fi only
      v
Android phone / tablet / TV
      |
      v
SideJITServer  -->  SideStore, LiveContainer
```

The Android device advertises itself on the local network as a pairable
developer host. The iPhone connects to it and drives the pairing. Once paired,
the Android device opens a CoreDevice tunnel to the iPhone, discovers the
developer services, attaches a debugger to the target application long enough
for the kernel to grant it JIT, and detaches.

## Why pairing and tunnelling run in opposite directions

Up to and including iOS 26, wireless developer pairing worked one way only:
the iOS device advertised `_remotepairing._tcp` and a computer found it and
connected. That flow needs the computer to already hold a pairing record,
which in practice meant a USB cable at least once.

iOS 27 added the reverse. A host advertises
`_remotepairing-pairable-host._tcp`, the iOS device finds it, connects to it,
and the *host* acts as the SRP accessory while the device drives the exchange.
The user reads a code off the host and types it into the iPhone. That is what
makes a cable-free, PC-free server possible at all.

But that direction alone is not enough. Because the iPhone opened the
connection, the Android box is the accessory on it, and iOS refuses to create
a tunnel listener there. Everything JIT needs hangs off a connection the
*host* opened. So once a pairing record exists, this server browses for the
iPhone's own `_remotepairing._tcp` service, dials it, verifies as the
initiator, and asks for the tunnel on that connection.

Both halves are implemented here. See [PROTOCOL.md](PROTOCOL.md).

## Diagnostics

The server answers on port 8080. `GET /status` reports what it has managed to
do, and `GET /diag` returns a plain text trace of the last few hundred packets
on the tunnel. Both are worth including in a bug report.

## Requirements

- Android 7.0 (API 24) or newer: phone, tablet, Android TV or Google TV
- An iPhone or iPad on iOS/iPadOS 27 or newer with Developer Mode enabled
- Both on the same Wi-Fi network, with client isolation off

## Installing

Take the APK from the [releases](../../releases) page and sideload it, or build
it yourself: see [BUILD.md](BUILD.md).

## Documentation

- [STATUS.md](STATUS.md) — what actually works
- [CHANGELOG.md](CHANGELOG.md) — what changed in each build
- [ARCHITECTURE.md](ARCHITECTURE.md) — module layout and why
- [PROTOCOL.md](PROTOCOL.md) — the Apple protocols, as understood so far
- [BUILD.md](BUILD.md) — building and testing locally
- [TESTING.md](TESTING.md) — what is covered and what has to be done by hand
- [ANDROID_TV.md](ANDROID_TV.md) — running on a TV, including one with a dead screen
- [SECURITY.md](SECURITY.md) — what is stored, where, and what is never logged

## Credit where it is due

The protocol behaviour implemented here was understood by reading the public
work of others, in particular:

- [idevice](https://github.com/jkcoxson/idevice) by Jackson Coxson, which
  documents the iOS 27 pairable-host flow
- [pymobiledevice3](https://github.com/doronz88/pymobiledevice3) by doronz88
- [SideJITServer](https://github.com/nythepegasus/SideJITServer) by nythepegasus
- StikDebug and StikPair

None of their code is used here. This is an independent Kotlin implementation
of the same protocols.

## Licence

MIT. See [LICENSE](LICENSE).
