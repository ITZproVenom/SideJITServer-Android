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

**Pair-setup, pair-verify, GDB packet codec, CDTunnel framing, createListener
JSON, and RSD handshake parsing exist and are unit-tested. Nothing has been
run against a real iPhone. JIT is not available.**

On start the app generates a stable host identity, advertises
`_remotepairing-pairable-host._tcp`, accepts device-initiated pair-setup (six
digit code), stores the pairing, and can run pair-verify when a record exists.
CDTunnel frame codec and tunnel parameter parsing are ready for a TLS-PSK
transport that is still missing.

## Build and packaging

| Item | State |
| --- | --- |
| Gradle multi-module, SDK 35, minSdk 24 | IMPLEMENTED + TESTED |
| Debug APK on GitHub Releases (pre-release) | IMPLEMENTED + TESTED |
| Phone / tablet / Android TV single APK | IMPLEMENTED + UNTESTED on hardware |
| CI: test + assembleDebug + gh release | IMPLEMENTED |

## Pairing

| Item | State |
| --- | --- |
| RPPairing framing | IMPLEMENTED + TESTED |
| Pair setup (device-initiated) | IMPLEMENTED + TESTED (stand-in only) |
| Pair verify | IMPLEMENTED + UNTESTED vs iPhone |
| SessionKeys after verify | IMPLEMENTED + UNTESTED |
| Keystore pairing storage | IMPLEMENTED + UNTESTED on hardware |
| Browse `_remotepairing._tcp` | NOT IMPLEMENTED |

## CoreDevice and above

| Item | State |
| --- | --- |
| CDTunnel frame encode/decode | IMPLEMENTED + TESTED (unit tests) |
| createListener request (TCP-PSK) | IMPLEMENTED + TESTED (JSON shape only) |
| Tunnel parameter parse (handshake response) | IMPLEMENTED + TESTED |
| TLS 1.2 PSK transport | NOT IMPLEMENTED |
| Userspace TCP/IPv6 over tunnel | NOT IMPLEMENTED |
| RSD Handshake parse | IMPLEMENTED + TESTED |
| Live RSD connect | NOT IMPLEMENTED |
| RemoteXPC / HTTP/2 | NOT IMPLEMENTED |
| DVT / ProcessControl | NOT IMPLEMENTED |
| debugproxy transport | NOT IMPLEMENTED |
| GDB remote packet codec + JIT sequence | IMPLEMENTED + TESTED (unit tests) |
| End-to-end JIT | NOT IMPLEMENTED |
| Local HTTP API | NOT IMPLEMENTED |

## Physical validation

None. No iPhone, iPad or Android TV has been used against this code.
