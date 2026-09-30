# Status

This file is the only place that says what works. Updated with the code it describes.

## Current overall state

**Protocol stack code is in place through userspace TCP, RSD, NSKeyedArchive,
DVT ProcessControl archive send, and GDB attach sequence.**

**Local HTTP API is started by ServerRuntime (port 8080) for SideStore-style clients.**

**Nothing has been validated against a physical iPhone/iPad. End-to-end JIT is
not claimed.** `JitEngine.enable(...)` returns a structured failure naming the
step that could not complete without a live device.

## Implemented (unit-tested codecs / local logic)

| Layer | State |
| --- | --- |
| Pair setup / verify / SessionKeys | IMPLEMENTED |
| TLS-PSK client (BC, TLS_PSK_WITH_AES_256_GCM_SHA384) | IMPLEMENTED (no live device) |
| CDTunnel framing + handshake parse | IMPLEMENTED |
| Tunnel IPv6 helpers / length-prefixed packets | IMPLEMENTED |
| Userspace TCP client (SYN/ACK, seq, checksum, stream) | IMPLEMENTED |
| RSD Handshake parse + RsdClient | IMPLEMENTED |
| HTTP/2 frame codec (RemoteXPC transport) | IMPLEMENTED |
| NSKeyedArchive encoder (bplist00, DVT method calls) | IMPLEMENTED |
| ProcessControl launch archive + JSON | IMPLEMENTED |
| DvtClient (preface + archive send + best-effort PID scrape) | IMPLEMENTED |
| GDB remote JIT sequence | IMPLEMENTED |
| Local HTTP API (/status, /launch, /re) | IMPLEMENTED (started by ServerRuntime on :8080) |
| JIT orchestration | IMPLEMENTED (fails without live device) |

## Not validated on hardware

- Pairing against real iOS 27+
- createListener + TLS-PSK to a real listener port
- Userspace TCP across a real tunnel
- Live RSD / DVT reply parsing (heuristic PID scrape only; unvalidated)
- Actual JIT grant via debugproxy

## Physical validation

None.
