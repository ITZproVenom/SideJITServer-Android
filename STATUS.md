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

**The application can run device-initiated pair-setup and has a pair-verify
state machine plus a GDB remote codec. It has never been run against a real
iPhone or iPad, and it still does not provide JIT.** On start it generates a
stable host identity, listens for a device-initiated pairing on a TCP port,
advertises `_remotepairing-pairable-host._tcp` over multicast DNS, shows a six
digit setup code on screen, completes SRP pair setup and stores the resulting
pairing encrypted on the device. Pair-verify (reconnect) is implemented in
code against the stored record. Everything above that layer — the encrypted
tunnel, RSD, RemoteXPC, the developer services, end-to-end JIT and the local
HTTP API — does not exist yet.

## Build and packaging

| Item | State |
| --- | --- |
| Gradle multi-module project, Android SDK 35, minSdk 24 | IMPLEMENTED + TESTED (builds locally and in CI) |
| Debug APK | IMPLEMENTED + TESTED (installable, ~12 MB) |
| Release APK | IMPLEMENTED + UNTESTED (unsigned; needs your own key) |
| Phone / tablet compatibility | IMPLEMENTED + UNTESTED on hardware |
| Android TV / Google TV launcher entry | IMPLEMENTED + UNTESTED on hardware |
| GitHub Actions: tests, lint, debug APK, Releases upload | IMPLEMENTED |

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
| Interface and address enumeration | IMPLEMENTED + TESTED (unit tests) |
| Network change handling and re-registration | IMPLEMENTED + UNTESTED on hardware |
| Multicast lock and partial wake lock | IMPLEMENTED + UNTESTED on hardware |

## mDNS

| Item | State |
| --- | --- |
| DNS record encode/decode, with name compression | IMPLEMENTED + TESTED (unit tests) |
| Question to answer logic, known-answer suppression | IMPLEMENTED + TESTED (unit tests) |
| Multicast responder sockets (IPv4 and IPv6) | IMPLEMENTED + UNTESTED (no test harness sends real multicast yet) |
| `_remotepairing-pairable-host._tcp` advertisement | IMPLEMENTED + UNTESTED on hardware (published on the real pairing port, with `authTag`) |
| Service discovery for SideStore / LiveContainer | NOT IMPLEMENTED |

## Cryptography

| Item | State |
| --- | --- |
| SipHash-2-4 and the mDNS `authTag` | IMPLEMENTED + TESTED |
| JSON reader and writer | IMPLEMENTED + TESTED |
| SHA-256 / SHA-512, HMAC, HKDF | IMPLEMENTED + TESTED |
| X25519 | IMPLEMENTED + TESTED |
| Ed25519 | IMPLEMENTED + TESTED |
| ChaCha20-Poly1305 | IMPLEMENTED + TESTED |
| SRP-6a (3072-bit, SHA-512) accessory side | IMPLEMENTED + TESTED (stand-in only; never vs iPhone) |
| OPACK encode/decode | IMPLEMENTED + TESTED |
| TLV8 encode/decode | IMPLEMENTED + TESTED |
| Byte readers and writers | IMPLEMENTED + TESTED |

## Pairing

| Item | State |
| --- | --- |
| `RPPairing` framing and JSON envelopes | IMPLEMENTED + TESTED (unit tests) |
| Pair setup (device-initiated, host as accessory) | IMPLEMENTED + TESTED against a stand-in; **never against an iPhone** |
| Setup code shown on screen, wrong code rejected | IMPLEMENTED + TESTED (unit tests) |
| Host identity, stable across restarts | IMPLEMENTED + UNTESTED on hardware |
| Keystore-backed encrypted pairing storage | IMPLEMENTED + UNTESTED on hardware |
| Pair verify (reconnect with stored record) | IMPLEMENTED + UNTESTED (code + unit path; never vs iPhone) |
| SessionKeys after verify (Control-Read/Write) | IMPLEMENTED + UNTESTED |
| `_remotepairing._tcp` browsing for a paired device | NOT IMPLEMENTED |

## CoreDevice and above

| Item | State |
| --- | --- |
| TLS-PSK tunnel | NOT IMPLEMENTED (explicit failure, no fake success) |
| Userspace TCP over the tunnel | NOT IMPLEMENTED |
| RSD | NOT IMPLEMENTED |
| RemoteXPC / HTTP/2 | NOT IMPLEMENTED |
| DVT, ProcessControl | NOT IMPLEMENTED |
| debugproxy transport | NOT IMPLEMENTED |
| GDB remote protocol (packet codec + JIT attach sequence) | IMPLEMENTED + TESTED (unit tests only; no live debugproxy) |
| JIT end-to-end | NOT IMPLEMENTED |
| Local HTTP API | NOT IMPLEMENTED |

## Physical validation

None. No iPhone, iPad or Android TV has been used against this code. Nothing
above marked TESTED means "tested against Apple hardware"; it means covered by
automated tests that run on a build machine.
