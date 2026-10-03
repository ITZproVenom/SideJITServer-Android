# Status

This file is the only place that says what works. Updated with the code it describes.

## Current overall state

**Protocol stack code is in place through userspace TCP, RSD, NSKeyedArchive,
DVT ProcessControl archive send, and GDB attach sequence.**

**Local HTTP API is started by ServerRuntime (port 8080) for SideStore-style clients.**

**Both directions of remote pairing now exist.** A device pairs by dialling into our
advertised pairable host service, which leaves us as the accessory; iOS will not create a
tunnel listener on that connection. So once a pairing record exists, `DeviceLink` browses for
the device's own `_remotepairing._tcp` service, dials it, verifies as the initiator, and asks
for the listener on that socket, holding it open for as long as the tunnel is wanted.

**Nothing has been validated against a physical iPhone/iPad. End-to-end JIT is
not claimed.** `JitEngine.enable(...)` returns a structured failure naming the
step that could not complete without a live device.

## Implemented (unit-tested codecs / local logic)

| Layer | State |
| --- | --- |
| Pair setup / verify / SessionKeys (accessory side) | IMPLEMENTED |
| mDNS browser (one shot, unicast reply, keeps IPv6 scope) | VALIDATED on an iPhone |
| authTag match of an advertisement to a stored record | IMPLEMENTED |
| Host initiated pair verify (initiator side) | VALIDATED on an iPhone |
| Outbound control channel + createListener | VALIDATED on an iPhone (returns a port) |
| DeviceLink reconnect loop | VALIDATED on an iPhone (browse, verify, createListener) |
| TLS-PSK client (BC, TLS_PSK_WITH_AES_256_CBC_SHA384 then AES_128_CBC_SHA) | IMPLEMENTED (no live device) |
| CDTunnel framing + handshake parse | IMPLEMENTED |
| Tunnel IPv6 helpers / length-prefixed packets | IMPLEMENTED |
| Userspace TCP client (SYN/ACK, seq, checksum, stream) | IMPLEMENTED |
| RSD Handshake parse + RsdClient | IMPLEMENTED |
| HTTP/2 frame codec (RemoteXPC transport) | IMPLEMENTED |
| NSKeyedArchive encoder and binary plist decoder (DVT replies) | IMPLEMENTED |
| DTX framing, channel request, method invocation, PID decode | IMPLEMENTED (no live device) |
| ProcessControl launch archive + JSON | IMPLEMENTED |
| GDB remote JIT sequence | IMPLEMENTED |
| Local HTTP API, SideJITServer route shape | IMPLEMENTED (started by ServerRuntime on :8080) |
| JIT orchestration | IMPLEMENTED (fails without live device) |

## HTTP API

Served on :8080. The route shape is SideJITServer's, because that is what SideStore and
LiveContainer already speak. Trailing slashes are optional.

| Route | Behaviour |
| --- | --- |
| `GET /`, `GET /status` | server state as JSON |
| `GET /ver/`, `GET /version` | version |
| `GET /re/` | answers, but nothing is cached to refresh |
| `GET /<udid>/<bundle id>/` | enable JIT; what SideStore calls |
| `GET /<bundle id>/` | enable JIT on the only paired device |
| `GET /<udid>/` | 501, listing installed apps is NOT IMPLEMENTED |
| `GET\|POST /launch?bundleId=` | the same launch by query parameter |

A launch answers 503 with the stage that could not complete unless JIT was really granted.

## Not validated on hardware

- TLS-PSK and CDTunnel handshake against a real listener
- Userspace TCP across a real tunnel
- Live RSD / DVT reply parsing. The PID comes from decoding the keyed archive in the DTX
  reply, not from guessing, but no real reply has ever been decoded.
- Actual JIT grant via debugproxy

## Physical validation

An iPhone running iOS 27, paired wirelessly, on the same Wi-Fi as an Android host:

- the browse found the device's `_remotepairing._tcp` service
- host initiated pair verify succeeded against it
- `createListener` returned a TCP port

The listener turned out to be short lived. Requesting a port and keeping it for later gave
ECONNREFUSED on connect, so the tunnel data plane is now connected the instant the port is
issued and held open. Whether the TLS-PSK and CDTunnel handshake succeed against a real
listener is the next unknown.
