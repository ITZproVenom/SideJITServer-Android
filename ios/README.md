# SideJIT Control (iOS companion)

An optional remote control for the Android server. Nothing here is required: the Android app
pairs, tunnels and grants JIT entirely on its own, including headless on Android TV. This app
exists for people who would rather drive it from the phone than from the TV.

## What it does

- Points at the Android device by address and remembers it.
- Shows `/status`: pairing, device name and identifier, tunnel state, last JIT result.
- Asks for JIT by bundle identifier, over the same route SideStore uses.
- Shows the server's `/diag` log.

## What it does not do

- It does not enable JIT by itself. Every button is an HTTP request to the Android server.
- It cannot list the apps installed on the device; the server does not implement that yet.
- There is no Bonjour discovery yet, so the address is typed in by hand. The Info.plist already
  declares `_sidejit._tcp` so discovery can be added once the server advertises it.

## Installing

CI builds an unsigned IPA and attaches it to an `ios-build-<number>` release. This project has no
Apple Developer membership, so the IPA is unsigned: sideload it with SideStore or AltStore, which
sign it with your own account.

## Building locally

Needs a Mac with Xcode and [XcodeGen](https://github.com/yonaskolb/XcodeGen):

    cd ios
    xcodegen generate
    open SideJITControl.xcodeproj
