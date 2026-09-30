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

**The application can now run the full device-initiated pairing conversation,
but it has never been run against a real iPhone or iPad, and it still does not
provide JIT.** On start it generates a stable host identity, listens for a
device-initiated pairing on a TCP port, advertises
`_remotepairing-pairable-host._tcp` over multicast DNS, shows a six digit setup
code on screen, completes SRP pair setup and stores the resulting pairing
encrypted on the device. Everything above that layer - the encrypted tunnel,
RSD, RemoteXPC, the developer services, JIT itself and the local HTTP API -
does not exist yet.

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
| SipHash-2-4 and the mDNS `authTag` | IMPLEMENTED + TESTED (paper vectors and a captured advertisement) |
| JSON reader and writer | IMPLEMENTED + TESTED (unit tests) |
| SHA-256 / SHA-512, HMAC, HKDF | IMPLEMENTED + TESTED (RFC 4231 and RFC 5869 vectors) |
| X25519 | IMPLEMENTED + TESTED (RFC 7748 section 6.1 vectors) |
| Ed25519 | IMPLEMENTED + TESTED (RFC 8032 section 7.1 vectors) |
| ChaCha20-Poly1305 | IMPLEMENTED + TESTED (RFC 8439 section 2.8.2 vector) |
| SRP-6a (3072-bit, SHA-512) accessory side | IMPLEMENTED + TESTED (round trip against an independent test client; never run against an iPhone) |
| OPACK encode/decode | IMPLEMENTED + TESTED (unit tests, including back references) |
| TLV8 encode/decode | IMPLEMENTED + TESTED (unit tests, including 255-byte fragmentation) |
| Byte readers and writers | IMPLEMENTED + TESTED (unit tests) |

## Pairing

| Item | State |
| --- | --- |
| `RPPairing` framing and JSON envelopes | IMPLEMENTED + TESTED (unit tests) |
| Pair setup (device-initiated, host as accessory) | IMPLEMENTED + TESTED against a stand-in device over a real socket; **never against an iPhone** |
| Setup code shown on screen, wrong code rejected | IMPLEMENTED + TESTED (unit tests) |
| Host identity, stable across restarts | IMPLEMENTED + UNTESTED on hardware |
| Keystore-backed encrypted pairing storage | IMPLEMENTED + UNTESTED on hardware |
| Pair verify (reconnecting to a device already paired) | NOT IMPLEMENTED |
| `_remotepairing._tcp` browsing for a paired device | NOT IMPLEMENTED |

## CoreDevice and above

| Item | State |
| --- | --- |
| TLS-PSK tunnel | NOT IMPLEMENTED |
| Userspace TCP over the tunnel | NOT IMPLEMENTED |
| RSD | NOT IMPLEMENTED |
| HTTP/2 framing for RemoteXPC | NOT IMPLEMENTED |
| DVT / DTX messages, NSKeyedArchive, ProcessControl, process list | NOT IMPLEMENTED |
| debugproxy service connection (opening the socket through the tunnel) | NOT IMPLEMENTED |
| JIT end to end | NOT IMPLEMENTED (every layer below the orchestrator is missing) |
| Local HTTP API (`/health`, `/status`, `/jit/<bundle>`; local-network clients only) | IMPLEMENTED + TESTED (unit tests over a real socket). Route names are this project's own and have not been checked against a SideStore release. `/jit/...` currently always answers 503 with the missing stage |
| GDB remote protocol (framing, escaping, run-length decoding, no-ack mode) | IMPLEMENTED + TESTED (unit tests against a stub server); never run against debugserver |
| Attach-then-detach sequence (`vAttach`, `D`) | IMPLEMENTED + TESTED against a stub server only |
| JIT orchestration (bundle id -> pid -> debugserver -> attach -> detach, per-stage failures) | IMPLEMENTED + TESTED with stand-ins; the real process resolver (DVT) and connector (tunnel) do not exist, so it can only fail, and says where |
| RemoteXPC message codec (wrapper, body, all object types) | IMPLEMENTED + TESTED (round trips and byte layout); written from public descriptions, never seen against a device |

## Physical validation

None. No iPhone, iPad or Android TV has been used against this code. Nothing
above marked TESTED means "tested against Apple hardware"; it means covered by
automated tests that run on a build machine.
