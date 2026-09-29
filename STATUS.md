# Status

This file is the only place that says what works. Everything else in the
documentation describes intent and design; this describes reality. It is
updated in the same commit as the code it describes.

Legend:

- **IMPLEMENTED + TESTED** — code exists, automated tests cover it, and it has
  been exercised against something real.
- **IMPLEMENTED + UNTESTED** — code exists and compiles, no real counterpart
  has confirmed it.
- **PARTIAL** — some of it exists; the gap is named.
- **NOT IMPLEMENTED** — nothing exists. No stub pretending otherwise.

## Current overall state

**The application does not yet pair with an iOS device and does not yet
provide JIT.** It builds, installs and runs on phones, tablets and Android TV,
and starts its own background service. That is all it does today.

## Build and packaging

| Item | State |
| --- | --- |
| Gradle multi-module project, Android SDK 35, minSdk 24 | IMPLEMENTED + TESTED (builds locally and in CI) |
| Debug APK | IMPLEMENTED + TESTED (installable, 12.7 MB) |
| Release APK | IMPLEMENTED + UNTESTED (unsigned; needs your own key) |
| Phone / tablet compatibility | IMPLEMENTED + UNTESTED on hardware |
| Android TV / Google TV launcher entry | IMPLEMENTED + UNTESTED on hardware |
| GitHub Actions: tests, lint, debug + release APK, artifacts | IMPLEMENTED |

## Runtime

| Item | State |
| --- | --- |
| Structured logging with per-layer tags | IMPLEMENTED + TESTED (unit tests) |
| Secret redaction on every log line | IMPLEMENTED + TESTED (unit tests) |
| Foreground service, survives the UI being closed | IMPLEMENTED + UNTESTED on hardware |
| Start on boot | IMPLEMENTED + UNTESTED on hardware |
| Status screen, read-only, no controls needed | IMPLEMENTED + UNTESTED on hardware |

## Networking

| Item | State |
| --- | --- |
| Interface and address enumeration | NOT IMPLEMENTED |
| Network change handling and re-registration | NOT IMPLEMENTED |
| Multicast lock | NOT IMPLEMENTED |

## mDNS

| Item | State |
| --- | --- |
| DNS record encode/decode | NOT IMPLEMENTED |
| `_remotepairing-pairable-host._tcp` advertisement | NOT IMPLEMENTED |
| Service discovery for SideStore / LiveContainer | NOT IMPLEMENTED |

## Cryptography

| Item | State |
| --- | --- |
| X25519, Ed25519, ChaCha20-Poly1305, HKDF, HMAC, SHA-512 | NOT IMPLEMENTED |
| SRP-6a (3072-bit, SHA-512) accessory side | NOT IMPLEMENTED |
| OPACK encode/decode | NOT IMPLEMENTED |
| TLV8 encode/decode | NOT IMPLEMENTED |

## Pairing

| Item | State |
| --- | --- |
| RPPairing framing and state machine | NOT IMPLEMENTED |
| Pair setup (device-initiated, host as accessory) | NOT IMPLEMENTED |
| Pair verify | NOT IMPLEMENTED |
| Keystore-backed pairing storage | NOT IMPLEMENTED |

## CoreDevice and above

| Item | State |
| --- | --- |
| TLS-PSK tunnel | NOT IMPLEMENTED |
| Userspace TCP over the tunnel | NOT IMPLEMENTED |
| RSD | NOT IMPLEMENTED |
| RemoteXPC / HTTP/2 | NOT IMPLEMENTED |
| DVT, ProcessControl | NOT IMPLEMENTED |
| debugproxy | NOT IMPLEMENTED |
| GDB remote protocol | NOT IMPLEMENTED |
| JIT | NOT IMPLEMENTED |
| Local HTTP API | NOT IMPLEMENTED |

## Physical validation

None. No iPhone, iPad or Android TV has been used against this code. Nothing
above marked TESTED means "tested against Apple hardware"; it means covered by
automated tests that run on a build machine.
