# Protocol notes

What is written here is the current understanding from public research. Where
something is a guess, it says so. Where something is confirmed only by reading
another implementation and not by observing a device, it says that too.

## The distinction that matters

**Old (lockdown/usbmux) pairing** ran over USB or over `_apple-mobdev2._tcp`,
used TLS with a device certificate, and produced a pairing record `.plist`.
It is not what this project uses, and code written against it will not work on
iOS 27.

**RPPairing** is the modern remote-pairing protocol behind CoreDevice. It
carries OPACK-encoded messages over its own framing, authenticates with SRP-6a
and then Ed25519 long-term keys, and yields a session from which an encrypted
tunnel is built.

Within RPPairing there are two directions:

| Direction | mDNS service | Who advertises | Available |
| --- | --- | --- | --- |
| Host finds device | `_remotepairing._tcp` | the iOS device | iOS 17+ |
| Device finds host | `_remotepairing-pairable-host._tcp` | the host | iOS 27+ |

This project uses the **second** one. It is the only variant that lets an
Android device become the host without ever having had a cable attached,
because the host does not need a pre-existing pairing record to be found — the
device initiates, and the host proves itself with a setup code the user reads
off the Android screen (or, on a TV with no screen, a code the Android device
chooses and shows in its own log and notification).

In that flow the roles invert relative to the older one:

- the **Android host** is the SRP **server** (the "accessory" role in Apple's
  HomeKit-derived terminology)
- the **iOS device** is the SRP **client** and drives the state machine

## Layers, once pairing is done

```
RPPairing session
      v
encrypted tunnel (TLS-PSK from the pairing session key)
      v
userspace TCP over the tunnel  (an Android app cannot create a tun
                                interface without VpnService, and taking
                                over the whole device's VPN slot to reach
                                one iPhone is the wrong trade, so the TCP
                                stack is implemented in userspace)
      v
RSD  - service discovery: names, ports, properties
      v
RemoteXPC over HTTP/2 - request/response and async events
      v
developer services
      v
DVT -> ProcessControl -> debugproxy -> GDB remote protocol
      v
attach, let the kernel grant JIT, detach
```

## Cryptography expected

- SRP-6a, 3072-bit group, SHA-512, for the setup exchange
- Ed25519 long-term identity keys for both sides, exchanged during setup and
  used for every later verification
- X25519 for the per-session key agreement
- HKDF-SHA-512 for key derivation, with Apple's salt/info strings
- ChaCha20-Poly1305 for the encrypted portions of setup and verify

## Serialisation

- **OPACK**, Apple's compact binary object format, for RPPairing message
  bodies
- **TLV8**, type-length-value triplets, for the setup and verify sub-messages
- **Property lists**, binary and XML, for RSD and some developer services

## What is still unknown

- The exact iOS 27 framing header fields and their ordering. iOS 27 is newer
  than every reference implementation consulted, so the framing is
  implemented from the iOS 17-26 description plus the pairable-host additions,
  and must be validated against a real device.
- Whether iOS 27 requires a personalised Developer Disk Image for the
  debugging services, or whether the on-device developer components suffice.
  This is deliberately not implemented until it can be observed, because
  guessing produces exactly the sort of fake that this project refuses to
  ship.
- The TXT record keys the iOS device requires in the pairable-host
  advertisement for it to be offered to the user at all.

## Device-initiated remote pairing, as implemented here

This is the part that makes a server with no cable and no computer possible, so
it is worth writing down precisely.

Older remote pairing has the *device* advertise `_remotepairing._tcp` and the
host connect to it. That flow needs a pairing record to already exist, which is
exactly what a fresh Android install does not have, and it is why every other
tool asks for a pairing file produced on a Mac, a PC or with a cable.

iOS 26 and later can also go the other way. The host advertises

```
_remotepairing-pairable-host._tcp.local.
```

and the phone connects to it. The host then plays the *accessory*: it chooses a
six digit setup code, displays it, and acts as the SRP server while the person
types the code into the phone.

### The advertisement

- Instance name: the host identifier, a UUID.
- Host name: `idevice-<first eight characters of the identifier, lower case>.local.`
- TXT entries: `name`, `identifier`, `authTag`, `model`, `flags=1`, `ver=26`,
  `minVer=17`.
- `authTag` is `SipHash-2-4` keyed with the host's 16 byte `altIRK` over the
  identifier, taken as eight little endian bytes, reversed, first six bytes,
  base64 encoded. A device that has paired before uses it to recognise the host.

### The control channel

Frames are the literal ASCII `RPPairing`, a big endian 16 bit length, then a
JSON envelope:

```json
{"message":{"plain":{"_0": ...}},"originatedBy":"device","sequenceNumber":0}
```

`originatedBy` is `device` on the accessory side and `host` on the initiating
side; the responder here is the accessory, so it sends `device`. Once a session
key exists the envelope becomes `{"streamEncrypted":{"_0":"<base64>"}}`.

### The conversation

1. The phone sends `request._0.handshake._0`. If `hostOptions.attemptPairVerify`
   is set it wants to reuse an existing pairing, which this side cannot do yet.
2. The host replies with its wire protocol version, its device options and a
   `peerDeviceInfo` dictionary.
3. Pair setup runs as TLV8 inside
   `event._0.pairingData._0.data`, base64 encoded, `kind` `setupManualPairing`.
   States 1 to 6 are the familiar accessory pair setup:
   M1 start, M2 salt and `B`, M3 `A` and the device proof, M4 the host proof,
   M5 the device identity sealed under `PS-Msg05`, M6 the host identity sealed
   under `PS-Msg06`.

SRP-6a uses the RFC 5054 3072 bit group with SHA-512 and the user name
`Pair-Setup`. Two details do not match the letter of the RFC and must be
followed exactly or the proofs will not agree:

- `u = H(A | B)` over the *unpadded* big endian values,
- `M1 = H(H(N) xor H(g) | H(I) | s | A | B | K)` with `A` and `B` *padded* to
  384 bytes.

`B` is also expected to be exactly 384 bytes, so the private exponent is
regenerated until it is.

Keys are derived from the SRP session key with HKDF-SHA512:

| Purpose | Salt | Info |
| --- | --- | --- |
| M5 and M6 encryption | `Pair-Setup-Encrypt-Salt` | `Pair-Setup-Encrypt-Info` |
| Host signature input | `Pair-Setup-Accessory-Sign-Salt` | `Pair-Setup-Accessory-Sign-Info` |
| Device signature input | `Pair-Setup-Controller-Sign-Salt` | `Pair-Setup-Controller-Sign-Info` |

The host signs `accessoryX | identifier | longTermPublicKey` with Ed25519 and
sends that, its identifier and its public key in M6, along with an OPACK
dictionary holding `altIRK`, `accountID`, `remotepairing_udid`, `model` and
`name`. The device sends the same shape in M5.
