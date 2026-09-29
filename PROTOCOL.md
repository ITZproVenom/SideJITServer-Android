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
