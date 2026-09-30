# Status

This file is the only place that says what works. Updated with the code it describes.

## Current overall state

**Protocol stack code is largely in place: pair-setup/verify, TLS-PSK client,
CDTunnel, tunnel data-plane helpers, RSD parse, HTTP/2 frames, ProcessControl
payloads, GDB attach sequence, local HTTP API, JIT orchestration.**

**Nothing has been validated against a physical iPhone/iPad. End-to-end JIT is
not claimed.** `JitEngine.enable(bundleId)` returns a structured failure naming
the missing live path. Partial paths (GDB on open streams, tunnel open when
host/port/psk are known) exist for integration.

## Implemented (unit-tested codecs / local logic)

| Layer | State |
| --- | --- |
| Pair setup / verify / SessionKeys | IMPLEMENTED |
| TLS-PSK client (BC, TLS_PSK_WITH_AES_256_GCM_SHA384) | IMPLEMENTED (no live device) |
| CDTunnel framing + handshake parse | IMPLEMENTED |
| Tunnel IPv6 helpers / length-prefixed packets | IMPLEMENTED |
| RSD Handshake parse | IMPLEMENTED |
| HTTP/2 frame codec (RemoteXPC transport) | IMPLEMENTED |
| ProcessControl launch payload | IMPLEMENTED |
| GDB remote JIT sequence | IMPLEMENTED |
| Local HTTP API (/status, /launch) | IMPLEMENTED |
| JIT orchestration | IMPLEMENTED (fails without live device) |

## Not validated on hardware

- Pairing against real iOS 27+
- createListener + TLS-PSK to a real listener port
- Userspace TCP across the tunnel to RSD
- Full RemoteXPC method dispatch / NSKeyedArchive DVT
- Actual JIT grant

## Physical validation

None.
